#!/usr/bin/env python3
"""Repository-local fail-closed Agent Work Governor gate."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, NamedTuple

import toolchain_catalog
import validate_policy
from contract_blocks import (
    contract_diagnostic,
    enforcement_token_is_present,
    parsed_contracts,
    resolve_contract_reference,
)

# LLM-CONTRACT
# id: agent-work-governor.repository-gate
# state: POLICY_UNREAD -> REPOSITORY_OBSERVED -> PASS | FAIL
# preconditions: canonical policy helpers and Git metadata are available
# invariant: owner mutations require canonical policy, current-SHA review, and pinned evidence
# failure: emit machine-readable errors and return a non-zero process status
# source: bundle:knowledge/policies/work-governor.md
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: main
# test: bundle:tests/test_repo_bundle.py

COMMENTABLE_EXTENSIONS = {
    ".bash",
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".css",
    ".go",
    ".graphql",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".jsx",
    ".lean",
    ".mjs",
    ".nix",
    ".py",
    ".rs",
    ".sh",
    ".sol",
    ".swift",
    ".toml",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
    ".zsh",
}
SIDECAR_EXTENSIONS = {".json"}
EXECUTABLE_CONFIG_NAMES = {"Dockerfile", "Justfile", "Makefile"}


class GitTreeEntry(NamedTuple):
    mode: str
    object_type: str
    object_id: str


def finding(code: str, message: str, **evidence: object) -> dict[str, Any]:
    return {"code": code, "message": message, "evidence": evidence}


def run_git(root: Path, *args: str) -> tuple[bool, str]:
    try:
        process = subprocess.run(
            ["git", "-C", str(root), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exception:
        return False, str(exception)
    output = process.stdout.strip() or process.stderr.strip()
    return process.returncode == 0, output


def run_git_paths_z(root: Path, *args: str) -> tuple[list[Path], str | None]:
    # LLM-CONTRACT
    # id: agent-work-governor.git-path-stream
    # state: GIT_PATH_STREAM -> NUL_RECORDS -> ROOTED_PATHS | PATH_STREAM_REJECTED
    # preconditions: the Git command emits repository-relative paths with -z
    # invariant: quoting, newlines, and undecodable bytes cannot split or escape a path
    # failure: return no paths and a stable error before contract inspection
    # source: https://github.com/git/git/blob/13c7afec212fc97ce257d15601659314c6673d6c/Documentation/diff-options.adoc
    # knowledge: bundle:knowledge/policies/work-governor.md
    # enforced_by: run_git_paths_z
    # test: bundle:tests/test_repo_bundle.py
    try:
        process = subprocess.run(
            ["git", "-C", str(root), *args],
            check=False,
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exception:
        return [], str(exception)
    if process.returncode != 0:
        return [], os.fsdecode(process.stderr).strip()
    if process.stdout and not process.stdout.endswith(b"\0"):
        return [], "Git path stream is not NUL-terminated"

    root = root.resolve()
    paths: list[Path] = []
    records = process.stdout[:-1].split(b"\0") if process.stdout else []
    for record in records:
        components = record.split(b"/")
        if (
            not record
            or record.startswith(b"/")
            or any(component in {b"", b".", b".."} for component in components)
        ):
            return [], "Git returned an unsafe repository-relative path"
        relative = Path(os.fsdecode(record))
        candidate = root / relative
        if relative.is_absolute() or not candidate.resolve(strict=False).is_relative_to(
            root
        ):
            return [], "Git path escapes the repository root"
        paths.append(candidate)
    return paths, None


def git_tree_entries(
    root: Path,
    treeish: str,
) -> tuple[dict[Path, GitTreeEntry], str | None]:
    # LLM-CONTRACT
    # id: agent-work-governor.git-tree-entries
    # state: TREEISH -> EXACT_TREE_RECORDS -> PATH_BOUND_BLOBS | TREE_REJECTED
    # preconditions: treeish names the immutable candidate commit under validation
    # invariant: paths, object modes, and object ids come from one exact Git tree
    # failure: reject malformed, unsafe, or non-NUL-terminated tree output
    # source: https://github.com/git/git/blob/13c7afec212fc97ce257d15601659314c6673d6c/Documentation/git-ls-tree.adoc
    # knowledge: bundle:knowledge/policies/work-governor.md
    # enforced_by: changed_code_files
    # test: bundle:tests/test_repo_bundle.py
    try:
        process = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "ls-tree",
                "-r",
                "-z",
                "--full-tree",
                treeish,
            ],
            check=False,
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exception:
        return {}, str(exception)
    if process.returncode != 0:
        return {}, os.fsdecode(process.stderr).strip()
    if process.stdout and not process.stdout.endswith(b"\0"):
        return {}, "Git tree stream is not NUL-terminated"

    root = root.resolve()
    entries: dict[Path, GitTreeEntry] = {}
    records = process.stdout[:-1].split(b"\0") if process.stdout else []
    for record in records:
        metadata, separator, raw_path = record.partition(b"\t")
        fields = metadata.split(b" ")
        components = raw_path.split(b"/")
        if (
            separator != b"\t"
            or len(fields) != 3
            or not raw_path
            or raw_path.startswith(b"/")
            or any(component in {b"", b".", b".."} for component in components)
        ):
            return {}, "Git returned an unsafe or malformed tree record"
        try:
            mode, object_type, object_id = (
                field.decode("ascii", errors="strict") for field in fields
            )
        except UnicodeDecodeError:
            return {}, "Git returned non-ASCII tree metadata"
        if (
            re.fullmatch(r"[0-7]{6}", mode) is None
            or object_type not in {"blob", "commit", "tree"}
            or re.fullmatch(r"[0-9a-f]{40,64}", object_id) is None
        ):
            return {}, "Git returned invalid tree metadata"
        relative = Path(os.fsdecode(raw_path))
        if relative.is_absolute():
            return {}, "Git path escapes the repository root"
        candidate = root / relative
        if candidate in entries:
            return {}, "Git returned a duplicate tree path"
        entries[candidate] = GitTreeEntry(mode, object_type, object_id)
    return entries, None


def git_tree_text(
    root: Path,
    entries: dict[Path, GitTreeEntry],
    path: Path,
) -> tuple[str | None, str | None]:
    # LLM-CONTRACT
    # id: agent-work-governor.git-tree-text
    # state: PATH_BOUND_ENTRY -> EXACT_BLOB_BYTES -> UTF8_TEXT | SOURCE_REJECTED
    # preconditions: entries came from the candidate tree named by the gate
    # invariant: ambient files, index entries, and symlinks cannot replace committed bytes
    # failure: reject missing, non-regular, unreadable, or non-UTF-8 Git objects
    # source: https://github.com/git/git/blob/13c7afec212fc97ce257d15601659314c6673d6c/Documentation/git-cat-file.adoc
    # knowledge: bundle:knowledge/policies/work-governor.md
    # enforced_by: main
    # test: bundle:tests/test_repo_bundle.py
    entry = entries.get(path)
    relative_name = path.relative_to(root.resolve()).as_posix()
    if entry is None:
        return None, f"{relative_name}: path is absent from the candidate Git tree"
    if entry.object_type != "blob" or entry.mode not in {"100644", "100755"}:
        return None, f"{relative_name}: contract source is not a regular Git blob"
    try:
        process = subprocess.run(
            ["git", "-C", str(root), "cat-file", "blob", entry.object_id],
            check=False,
            capture_output=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exception:
        return None, f"{relative_name}: {exception}"
    if process.returncode != 0:
        detail = os.fsdecode(process.stderr).strip() or "Git blob is unavailable"
        return None, f"{relative_name}: {detail}"
    try:
        return process.stdout.decode("utf-8", errors="strict"), None
    except UnicodeDecodeError as exception:
        return None, f"{relative_name}: {exception}"


def load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exception:
        return None, str(exception)
    if not isinstance(value, dict):
        return None, "JSON root must be an object"
    return value, None


def canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_python_runtime(
    pins: dict[str, dict[str, object]],
    actual_version: tuple[int, int, int],
) -> list[dict[str, Any]]:
    # LLM-CONTRACT
    # id: agent-work-governor.repository-gate-python-runtime
    # state: VALIDATED_CATALOG -> EXACT_PYTHON_RUNTIME | RUNTIME_REJECTED
    # preconditions: the unified catalog contains the required python identity
    # invariant: repository policy never executes under an uncatalogued Python version
    # failure: emit TOOLCHAIN_PYTHON_VERSION_MISMATCH before repository acceptance
    # source: https://github.com/python/cpython/blob/c63aec69bd59c55314c06c23f4c22c03de76fe45/Doc/library/sys.rst
    # knowledge: bundle:knowledge/policies/work-governor.md
    # enforced_by: validate_toolchain
    # test: bundle:tests/test_repo_bundle.py
    python_pin = pins.get("python")
    expected = python_pin.get("version") if python_pin is not None else None
    actual = ".".join(str(component) for component in actual_version)
    if not isinstance(expected, str) or actual != expected:
        return [
            finding(
                "TOOLCHAIN_PYTHON_VERSION_MISMATCH",
                "repository gate must run with the catalogued Python version",
                actual=actual,
                expected=expected,
            )
        ]
    return []


def validate_toolchain(
    root: Path,
    environment: dict[str, Any],
) -> list[dict[str, Any]]:
    relative = environment.get("toolchain_lock")
    required = environment.get("required_tools")
    if (
        not isinstance(relative, str)
        or not isinstance(required, list)
        or not all(isinstance(tool, str) for tool in required)
    ):
        return [
            finding(
                "TOOLCHAIN_POLICY_INVALID",
                "canonical policy validation should require a lock path and tool list",
            )
        ]

    lock_path = root / relative
    pins, catalog_findings = toolchain_catalog.validate_catalog(
        lock_path,
        sorted({*required, "python"}),
    )
    errors = [
        finding(
            item["code"],
            "unified toolchain catalog rejected",
            field=item["field"],
            path=str(lock_path),
            tool=item["tool_id"],
        )
        for item in catalog_findings
    ]
    if catalog_findings:
        return errors

    actual_version = (
        sys.version_info.major,
        sys.version_info.minor,
        sys.version_info.micro,
    )
    return validate_python_runtime(pins, actual_version)


def is_contract_sidecar(path: Path) -> bool:
    return path.name == "LLM-CONTRACT.md" or path.name.endswith(".LLM-CONTRACT.md")


def is_governed_source(path: Path) -> bool:
    return (
        path.suffix.lower() in COMMENTABLE_EXTENSIONS | SIDECAR_EXTENSIONS
        or path.name in EXECUTABLE_CONFIG_NAMES
        or is_contract_sidecar(path)
    )


def contract_source_path(path: Path) -> Path:
    """Resolve a local sidecar for inspection, never for Git-tree authority."""
    if path.suffix.lower() not in SIDECAR_EXTENSIONS:
        return path
    candidates = (
        path.with_suffix(".LLM-CONTRACT.md"),
        path.parent / "LLM-CONTRACT.md",
    )
    return next((candidate for candidate in candidates if candidate.is_file()), path)


def tracked_contract_source_path(path: Path, tracked_paths: set[Path]) -> Path:
    # LLM-CONTRACT
    # id: agent-work-governor.tracked-contract-source
    # state: HEAD_TREE_PATH -> TRACKED_SIDECAR | SOURCE_REQUIRES_INLINE_CONTRACT
    # preconditions: tracked_paths comes from the exact candidate Git tree
    # invariant: ambient or untracked files never satisfy committed contract evidence
    # failure: return the governed source so missing inline evidence fails validation
    # source: https://github.com/git/git/blob/13c7afec212fc97ce257d15601659314c6673d6c/Documentation/git-ls-tree.adoc
    # knowledge: bundle:knowledge/policies/work-governor.md
    # enforced_by: changed_code_files
    # test: bundle:tests/test_repo_bundle.py
    if path.suffix.lower() not in SIDECAR_EXTENSIONS:
        return path
    candidates = (
        path.with_suffix(".LLM-CONTRACT.md"),
        path.parent / "LLM-CONTRACT.md",
    )
    return next(
        (candidate for candidate in candidates if candidate in tracked_paths), path
    )


def changed_code_files(
    root: Path,
    branch_base: str,
    head_ref: str,
) -> tuple[list[Path], str | None]:
    changed_paths, error = run_git_paths_z(
        root,
        "diff",
        "--name-only",
        "--diff-filter=ACMRT",
        "-z",
        f"{branch_base}...{head_ref}",
    )
    if error is not None:
        return [], error

    root = root.resolve()
    tree_entries, error = git_tree_entries(root, head_ref)
    if error is not None:
        return [], error
    tracked_paths = list(tree_entries)
    tracked_path_set = set(tracked_paths)
    deleted_paths, error = run_git_paths_z(
        root,
        "diff",
        "--name-only",
        "--no-renames",
        "--diff-filter=D",
        "-z",
        f"{branch_base}...{head_ref}",
    )
    if error is not None:
        return [], error
    deleted_sidecars = {path for path in deleted_paths if is_contract_sidecar(path)}
    if deleted_sidecars:
        required_sidecars: set[Path] = set()
        for source in tracked_paths:
            if (
                source.suffix.lower() in SIDECAR_EXTENSIONS
                and tracked_contract_source_path(source, tracked_path_set) == source
            ):
                required_sidecars.update(
                    (
                        source.with_suffix(".LLM-CONTRACT.md"),
                        source.parent / "LLM-CONTRACT.md",
                    )
                )
        if missing_sidecars := sorted(deleted_sidecars & required_sidecars):
            relative = missing_sidecars[0].relative_to(root).as_posix()
            return (
                [],
                f"{relative}: required JSON contract sidecar was deleted",
            )

    paths: set[Path] = set()
    for path in changed_paths:
        if not is_governed_source(path):
            continue
        contract_path = tracked_contract_source_path(path, tracked_path_set)
        _, source_error = git_tree_text(root, tree_entries, contract_path)
        if source_error is not None:
            return [], source_error
        paths.add(contract_path)
    return sorted(paths), None


def repository_contract_index(
    root: Path,
    head_ref: str,
) -> tuple[dict[str, list[str]], str | None]:
    tree_entries, error = git_tree_entries(root, head_ref)
    if error is not None:
        return {}, error

    contract_sources: set[Path] = set()
    tracked_paths = list(tree_entries)
    tracked_path_set = set(tracked_paths)
    root = root.resolve()
    for path in tracked_paths:
        if not is_governed_source(path):
            continue
        contract_path = tracked_contract_source_path(path, tracked_path_set)
        contract_sources.add(contract_path)

    index: dict[str, list[str]] = {}
    for path in sorted(contract_sources):
        relative_name = str(path.relative_to(root))
        source, source_error = git_tree_text(root, tree_entries, path)
        if source_error is not None or source is None:
            return {}, source_error or f"{relative_name}: Git blob is unavailable"
        for contract in parsed_contracts(source):
            identifier = contract.get("id")
            if identifier:
                index.setdefault(identifier, []).append(relative_name)
    return index, None


def repository_contract_id_errors(
    contract_index: dict[str, list[str]],
) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    for identifier, occurrences in sorted(contract_index.items()):
        if len(occurrences) < 2:
            continue
        errors.append(
            finding(
                "LLM_CONTRACT_ID_DUPLICATE",
                "contract id must be repository-unique",
                contract_id=identifier,
                collision_paths=sorted(set(occurrences)),
                occurrence_count=len(occurrences),
            )
        )
    return errors


def contract_reference_errors(
    root: Path,
    bundle_root: Path,
    source_path: Path,
    source_text: str,
) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    for contract in parsed_contracts(source_text):
        identifier = contract["id"]

        source_ref = contract["source"]
        _, source_error = resolve_contract_reference(
            source_ref,
            repo_root=root,
            bundle_root=bundle_root,
            allow_external=True,
        )
        if source_error is not None:
            errors.append(
                finding(
                    "LLM_CONTRACT_SOURCE_INVALID",
                    source_error,
                    contract_id=identifier,
                    source=source_ref,
                )
            )

        for field in ("knowledge", "test"):
            reference = contract[field]
            target, reference_error = resolve_contract_reference(
                reference,
                repo_root=root,
                bundle_root=bundle_root,
                allow_external=False,
            )
            if reference_error is not None or target is None:
                errors.append(
                    finding(
                        f"LLM_CONTRACT_{field.upper()}_INVALID",
                        reference_error or f"{field} reference could not be resolved",
                        contract_id=identifier,
                        reference=reference,
                    )
                )
                continue
            if field == "knowledge":
                try:
                    knowledge = target.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError) as exception:
                    errors.append(
                        finding(
                            "LLM_CONTRACT_KNOWLEDGE_UNREADABLE",
                            str(exception),
                            contract_id=identifier,
                            reference=reference,
                        )
                    )
                else:
                    if re.search(
                        r'(?im)^\s*(?:status\s*:\s*|["\']status["\']\s*:\s*["\'])'
                        r"deprecated\b",
                        knowledge,
                    ):
                        errors.append(
                            finding(
                                "LLM_CONTRACT_KNOWLEDGE_DEPRECATED",
                                "knowledge reference is deprecated",
                                contract_id=identifier,
                                reference=reference,
                            )
                        )

        symbol = contract["enforced_by"]
        if not enforcement_token_is_present(source_text, symbol):
            errors.append(
                finding(
                    "LLM_CONTRACT_ENFORCEMENT_MISSING",
                    "enforced_by token is absent outside standalone comment metadata",
                    contract_id=identifier,
                    symbol=symbol,
                )
            )
    return errors


def validate_pre_pr_receipt(
    root: Path,
    receipts: dict[str, Any],
    branch_base: str,
    policy_path: Path,
    quality: dict[str, Any],
) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    directory = receipts.get("directory")
    if not isinstance(directory, str):
        return [finding("RECEIPT_POLICY_INVALID", "receipt directory is unavailable")]
    receipt_path = root / directory / "pre-pr.json"
    receipt, parse_error = load_json(receipt_path)
    if receipt is None:
        return [
            finding(
                "PRE_PR_RECEIPT_UNREADABLE",
                parse_error or "unknown parse error",
                path=str(receipt_path),
            )
        ]

    common_strings = (
        "receipt_id",
        "session_id",
        "input_digest",
        "output_digest",
        "policy_bundle_digest",
        "environment_digest",
        "actor",
        "replay_ref",
        "started_at",
        "finished_at",
        "reason_code",
    )
    malformed_common = (
        receipt.get("action_kind") != "code-review"
        or receipt.get("verdict") != "PASS"
        or any(
            not isinstance(receipt.get(field), str) or not receipt[field].strip()
            for field in common_strings
        )
        or not isinstance(receipt.get("trace_span_ids"), list)
        or not receipt["trace_span_ids"]
        or not isinstance(receipt.get("attester"), dict)
        or not isinstance(receipt["attester"].get("id"), str)
        or receipt["attester"].get("source_digest")
        != quality.get("code_review_skill_sha256")
    )
    if malformed_common:
        errors.append(
            finding(
                "REVIEW_RECEIPT_COMMON_INVALID",
                "candidate receipt must carry ReceiptCommon fields and pinned attester source",
            )
        )

    success, observed_head = run_git(root, "rev-parse", "HEAD")
    current_head = os.environ.get("GOVERNOR_HEAD_SHA") or observed_head
    reviewed_head = receipt.get("head_sha")
    if not success or reviewed_head != current_head:
        errors.append(
            finding(
                "REVIEW_SHA_MISMATCH",
                "reviewed SHA must equal the current work-branch SHA",
                current=current_head,
                reviewed=reviewed_head,
            )
        )

    success, observed_base = run_git(root, "rev-parse", branch_base)
    if not success or receipt.get("branch_base_sha") != observed_base:
        errors.append(
            finding(
                "BRANCH_RECEIPT_MISMATCH",
                "pre-PR receipt must bind the fetched branch base",
                expected=observed_base,
                actual=receipt.get("branch_base_sha"),
            )
        )

    if not isinstance(receipt.get("task_id"), str) or not receipt["task_id"].strip():
        errors.append(
            finding("TASK_ID_MISSING", "one PR requires one explicit task id")
        )
    if receipt.get("one_task") is not True:
        errors.append(finding("ONE_TASK_UNPROVEN", "receipt must assert one_task=true"))

    expected_input_digest = canonical_digest(
        {
            "head_sha": receipt.get("head_sha"),
            "branch_base_sha": receipt.get("branch_base_sha"),
            "task_id": receipt.get("task_id"),
        }
    )
    if receipt.get("input_digest") != expected_input_digest:
        errors.append(
            finding(
                "REVIEW_INPUT_DIGEST_MISMATCH",
                "input_digest must bind head, branch base, and task",
                expected=expected_input_digest,
                actual=receipt.get("input_digest"),
            )
        )

    expected_policy_digest = (
        validate_policy.sha256_file(policy_path) if policy_path.is_file() else None
    )
    if receipt.get("policy_bundle_digest") != expected_policy_digest:
        errors.append(
            finding(
                "REVIEW_POLICY_DIGEST_MISMATCH",
                "candidate review must bind the current policy",
                expected=expected_policy_digest,
                actual=receipt.get("policy_bundle_digest"),
            )
        )

    artifact_ref = receipt.get("review_artifact")
    if not isinstance(artifact_ref, str):
        errors.append(
            finding(
                "REVIEW_ARTIFACT_MISSING",
                "candidate receipt must reference its review artifact",
            )
        )
    else:
        artifact_path = (root / artifact_ref).resolve()
        if (
            not artifact_path.is_relative_to(receipt_path.parent.resolve())
            or not artifact_path.is_file()
        ):
            errors.append(
                finding(
                    "REVIEW_ARTIFACT_UNSAFE",
                    "review artifact must be an existing runtime-receipt file",
                    reference=artifact_ref,
                )
            )
        elif receipt.get("output_digest") != validate_policy.sha256_file(artifact_path):
            errors.append(
                finding(
                    "REVIEW_OUTPUT_DIGEST_MISMATCH",
                    "output_digest must bind the review artifact bytes",
                    reference=artifact_ref,
                )
            )

    review = receipt.get("code_review")
    if (
        not isinstance(review, dict)
        or review.get("skill") != "code-review"
        or review.get("artifact_sha") != reviewed_head
        or review.get("standards") != "PASS"
        or review.get("spec") != "PASS"
    ):
        errors.append(
            finding(
                "CODE_REVIEW_RECEIPT_INVALID",
                "current-SHA Standards and Spec review evidence is required",
            )
        )

    sources = receipt.get("primary_sources")
    if (
        not isinstance(sources, list)
        or not sources
        or any(not isinstance(source, str) or not source.strip() for source in sources)
    ):
        errors.append(
            finding(
                "PRIMARY_SOURCES_MISSING",
                "pre-PR receipt must identify primary sources",
            )
        )
    errors.append(
        finding(
            "CODE_REVIEW_ATTESTATION_UNTRUSTED",
            "PR-controlled JSON is candidate evidence only; configure a trusted Review Adapter",
            path=str(receipt_path),
        )
    )
    return errors


def main() -> int:
    root = Path.cwd().resolve()
    policy_path = root / ".agent-work-governor" / "policy.toml"
    errors: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    policy, parse_findings = validate_policy.load_policy(policy_path)
    if policy is None:
        errors.extend(parse_findings)
    else:
        errors.extend(validate_policy.validate_document(policy))

    scope = policy.get("repository_scope") if policy else None
    if scope == "unknown" or scope is None:
        errors.append(
            finding("SCOPE_UNRESOLVED", "declare repository_scope before enabling CI")
        )

    if policy and scope == "owner_original":
        for relative in ("AGENTS.md", "flake.nix", "flake.lock"):
            if not (root / relative).is_file():
                errors.append(finding("OWNER_FILE_MISSING", relative))
        gitignore = root / ".gitignore"
        try:
            ignored = gitignore.read_text(encoding="utf-8").splitlines()
        except OSError as exception:
            errors.append(
                finding("GOVERNANCE_IGNORE_MISSING", str(exception), path=".gitignore")
            )
        else:
            if ".governance/" not in {line.strip() for line in ignored}:
                errors.append(
                    finding(
                        "GOVERNANCE_RUNTIME_TRACKED",
                        ".gitignore must contain .governance/",
                    )
                )

        github = policy.get("github")
        environment = policy.get("environment")
        receipts = policy.get("receipts")
        if (
            not isinstance(github, dict)
            or not isinstance(environment, dict)
            or not isinstance(receipts, dict)
        ):
            errors.append(
                finding(
                    "OWNER_POLICY_INVALID",
                    "canonical owner policy tables are required",
                )
            )
        else:
            branch_base = github.get("branch_base")
            if not isinstance(branch_base, str):
                errors.append(finding("BRANCH_BASE_INVALID", "branch base is required"))
            else:
                base_ref = os.environ.get("GITHUB_BASE_REF")
                default_branch = policy.get("default_branch")
                if base_ref and base_ref != default_branch:
                    errors.append(
                        finding(
                            "PR_BASE_MISMATCH",
                            "pull request base differs from policy",
                            expected=default_branch,
                            actual=base_ref,
                        )
                    )
                head_ref = os.environ.get("GITHUB_HEAD_REF")
                if head_ref and head_ref == default_branch:
                    errors.append(
                        finding(
                            "WORK_BRANCH_REQUIRED",
                            "work must run on a branch distinct from the default branch",
                        )
                    )

                head_ref = os.environ.get("GOVERNOR_HEAD_SHA") or "HEAD"
                code_files, diff_error = changed_code_files(root, branch_base, head_ref)
                if diff_error:
                    errors.append(
                        finding(
                            "DIFF_UNAVAILABLE",
                            "cannot inspect branch-base diff",
                            detail=diff_error,
                        )
                    )
                else:
                    tree_entries, tree_error = git_tree_entries(root, head_ref)
                    if tree_error is not None:
                        errors.append(
                            finding(
                                "LLM_CONTRACT_TREE_UNAVAILABLE",
                                "cannot read the candidate Git tree",
                                detail=tree_error,
                            )
                        )
                        tree_entries = {}
                    contract_index, index_error = repository_contract_index(
                        root, head_ref
                    )
                    if index_error is not None:
                        errors.append(
                            finding(
                                "LLM_CONTRACT_INDEX_UNAVAILABLE",
                                "cannot build the repository-wide contract id index",
                                detail=index_error,
                            )
                        )
                    else:
                        errors.extend(repository_contract_id_errors(contract_index))
                    bundle_root = Path(__file__).resolve().parent
                    for path in code_files:
                        source, source_error = git_tree_text(root, tree_entries, path)
                        if source_error is not None or source is None:
                            errors.append(
                                finding(
                                    "CODE_UNREADABLE",
                                    source_error or "Git blob is unavailable",
                                    path=str(path),
                                )
                            )
                            continue
                        contract_error = contract_diagnostic(source)
                        if contract_error is not None:
                            errors.append(
                                finding(
                                    "LLM_CONTRACT_INVALID",
                                    contract_error,
                                    path=str(path.relative_to(root)),
                                )
                            )
                            continue
                        errors.extend(
                            contract_reference_errors(
                                root,
                                bundle_root,
                                path,
                                source,
                            )
                        )
                    if code_files:
                        errors.append(
                            finding(
                                "LLM_CONTRACT_AST_ATTESTATION_REQUIRED",
                                "shape/reference checks are not symbol mapping; configure the pinned AST Adapter",
                                changed_code_files=len(code_files),
                            )
                        )

                quality = policy.get("quality")
                if isinstance(quality, dict):
                    errors.extend(
                        validate_pre_pr_receipt(
                            root,
                            receipts,
                            branch_base,
                            policy_path,
                            quality,
                        )
                    )
                else:
                    errors.append(
                        finding(
                            "QUALITY_POLICY_INVALID",
                            "owner quality policy is unavailable",
                        )
                    )
            errors.extend(validate_toolchain(root, environment))

        warnings.append(
            finding(
                "REVIEW_CLOSEOUT_EXTERNAL",
                "merged-thread closeout and bug-Issue linkage need GitHub Adapter evidence",
            )
        )

    report = {
        "status": "FAIL" if errors else "PASS",
        "policy": str(policy_path),
        "errors": errors,
        "warnings": warnings,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
