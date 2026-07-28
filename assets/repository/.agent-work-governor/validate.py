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
from typing import Any

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


def validate_toolchain(
    root: Path,
    environment: dict[str, Any],
) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    relative = environment.get("toolchain_lock")
    required = environment.get("required_tools")
    if not isinstance(relative, str) or not isinstance(required, list):
        return [
            finding(
                "TOOLCHAIN_POLICY_INVALID",
                "canonical policy validation should require a lock path and tool list",
            )
        ]

    lock_path = root / relative
    lock, parse_error = load_json(lock_path)
    if lock is None:
        return [
            finding(
                "TOOLCHAIN_LOCK_UNREADABLE",
                parse_error or "unknown parse error",
                path=str(lock_path),
            )
        ]
    if lock.get("schema_version") != "0.1":
        errors.append(
            finding(
                "TOOLCHAIN_SCHEMA_MISMATCH",
                "toolchain lock schema_version must be 0.1",
                path=str(lock_path),
            )
        )
    for tool in required:
        entry = lock.get(tool)
        if (
            not isinstance(tool, str)
            or not isinstance(entry, dict)
            or not isinstance(entry.get("version"), str)
            or not isinstance(entry.get("source"), str)
            or not entry["source"].startswith("https://")
            or not isinstance(entry.get("source_digest"), str)
            or re.fullmatch(r"git:[0-9a-f]{40}", entry["source_digest"]) is None
            or not isinstance(entry.get("purpose"), str)
            or not isinstance(entry.get("command"), str)
        ):
            errors.append(
                finding(
                    "REQUIRED_TOOL_NOT_LOCKED",
                    "required tool needs version, source digest, purpose, and command",
                    tool=tool,
                    path=str(lock_path),
                )
            )
    return errors


def is_contract_sidecar(path: Path) -> bool:
    return path.name == "LLM-CONTRACT.md" or path.name.endswith(".LLM-CONTRACT.md")


def is_governed_source(path: Path) -> bool:
    return (
        path.suffix.lower() in COMMENTABLE_EXTENSIONS | SIDECAR_EXTENSIONS
        or path.name in EXECUTABLE_CONFIG_NAMES
        or is_contract_sidecar(path)
    )


def contract_source_path(path: Path) -> Path:
    if path.suffix.lower() not in SIDECAR_EXTENSIONS:
        return path
    candidates = (
        path.with_suffix(".LLM-CONTRACT.md"),
        path.parent / "LLM-CONTRACT.md",
    )
    return next((candidate for candidate in candidates if candidate.is_file()), path)


def changed_code_files(
    root: Path,
    branch_base: str,
    head_ref: str,
) -> tuple[list[Path], str | None]:
    changed_paths, error = run_git_paths_z(
        root,
        "diff",
        "--name-only",
        "--diff-filter=ACMR",
        "-z",
        f"{branch_base}...{head_ref}",
    )
    if error is not None:
        return [], error

    root = root.resolve()
    paths: set[Path] = set()
    for path in changed_paths:
        if not is_governed_source(path):
            continue
        contract_path = contract_source_path(path)
        if not contract_path.resolve(strict=False).is_relative_to(root):
            return [], "LLM contract sidecar escapes the repository root"
        paths.add(contract_path)
    return sorted(paths), None


def repository_contract_index(
    root: Path,
) -> tuple[dict[str, list[str]], str | None]:
    tracked_paths, error = run_git_paths_z(root, "ls-files", "-z")
    if error is not None:
        return {}, error

    contract_sources: set[Path] = set()
    root = root.resolve()
    for path in tracked_paths:
        if not is_governed_source(path):
            continue
        contract_path = contract_source_path(path)
        if not contract_path.resolve(strict=False).is_relative_to(root):
            return {}, "LLM contract sidecar escapes the repository root"
        contract_sources.add(contract_path)

    index: dict[str, list[str]] = {}
    for path in sorted(contract_sources):
        relative_name = str(path.relative_to(root))
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exception:
            return {}, f"{relative_name}: {exception}"
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
                    contract_index, index_error = repository_contract_index(root)
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
                        try:
                            source = path.read_text(encoding="utf-8")
                        except (OSError, UnicodeDecodeError) as exception:
                            errors.append(
                                finding(
                                    "CODE_UNREADABLE",
                                    str(exception),
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
