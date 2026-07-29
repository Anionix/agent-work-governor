#!/usr/bin/env python3
"""Run a read-only Agent Work Governor plugin and repository audit."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import rust_dispatch
import toolchain_catalog
import validate_canonical
import validate_okf
import validate_policy

# LLM-CONTRACT
# id: agent-work-governor.read-only-doctor
# state: UNINSPECTED -> OBSERVED -> PASS | WARN | FAIL | INCONCLUSIVE
# preconditions: repository and plugin paths are readable or reported inaccessible
# invariant: this process performs no mutation and only PASS or WARN exits zero
# failure: inaccessible evidence is INCONCLUSIVE with exit 2 rather than PASS
# source: bundle:knowledge/policies/work-governor.md
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: audit
# test: bundle:tests/test_contracts.py


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_git(repo: Path, *args: str) -> tuple[bool, str]:
    try:
        process = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return False, str(error)
    output = process.stdout.strip() or process.stderr.strip()
    return process.returncode == 0, output


def normalize_validator_status(status: object) -> str:
    if status == "valid":
        return "PASS"
    if status == "inconclusive":
        return "INCONCLUSIVE"
    return "FAIL"


def audit_exit_code(overall: object) -> int:
    if overall in {"PASS", "WARN"}:
        return 0
    if overall == "FAIL":
        return 1
    return 2


def rust_evidence(invocation: rust_dispatch.RustInvocation) -> str:
    report = (
        json.dumps(invocation.report, sort_keys=True)
        if invocation.report is not None
        else invocation.stderr.strip() or invocation.stdout.strip()
    )
    return report[:2000] or f"Rust binary exited {invocation.exit_code}"


def rust_check(
    selection: rust_dispatch.BinarySelection,
    arguments: list[str],
) -> tuple[str, str, dict[str, Any] | None]:
    try:
        invocation = rust_dispatch.invoke(selection, arguments)
    except rust_dispatch.IntegrityError as error:
        return "FAIL", str(error), None
    except rust_dispatch.InvocationError as error:
        return "INCONCLUSIVE", str(error), None
    return (
        rust_dispatch.invocation_status(invocation),
        rust_evidence(invocation),
        invocation.report,
    )


def canonical_validator(
    *,
    validator: Path,
    expected_sha256: str,
    target: Path,
    runtime: validate_canonical.RuntimeSnapshot,
) -> tuple[str, str]:
    try:
        process = validate_canonical.run_validator(
            validator,
            expected_sha256,
            runtime,
            target,
        )
    except validate_canonical.CanonicalRuntimeError as error:
        return "INCONCLUSIVE" if error.inconclusive else "FAIL", error.code
    except validate_canonical.CanonicalValidationError as error:
        return "FAIL", str(error)
    except (OSError, subprocess.SubprocessError) as error:
        return "INCONCLUSIVE", str(error)
    evidence = (process.stdout.strip() or process.stderr.strip())[:2000]
    if process.returncode == 0:
        return "PASS", evidence or str(validator)
    return "FAIL", evidence or f"validator exited {process.returncode}"


def inspect_toolchain_catalog(path: Path, required: list[str]) -> tuple[str, str]:
    pins, findings = toolchain_catalog.validate_catalog(path, required)
    if findings:
        return "FAIL", json.dumps(findings, sort_keys=True)
    return "PASS", json.dumps(
        {"path": str(path), "tools": len(pins)},
        sort_keys=True,
    )


def audit(repo: Path) -> dict[str, Any]:
    plugin_root = Path(__file__).resolve().parent.parent
    findings: list[dict[str, str]] = []

    def add(status: str, check: str, evidence: str) -> None:
        findings.append({"status": status, "check": check, "evidence": evidence})

    manifest_path = plugin_root / ".codex-plugin" / "plugin.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        required = ("name", "version", "description", "author", "interface")
        missing = [key for key in required if not manifest.get(key)]
        add(
            "PASS" if not missing else "FAIL",
            "plugin_manifest_parse_smoke",
            str(manifest_path) if not missing else f"missing: {', '.join(missing)}",
        )
    except (OSError, json.JSONDecodeError) as error:
        add("FAIL", "plugin_manifest_parse_smoke", str(error))

    skill_paths: list[Path] = []
    try:
        validator_lock = validate_canonical.load_lock(plugin_root)
        skill_paths = sorted(
            path for path in (plugin_root / "skills").iterdir() if path.is_dir()
        )
        runtime = validate_canonical.load_runtime(plugin_root, validator_lock)
    except validate_canonical.CanonicalRuntimeError as error:
        status = "INCONCLUSIVE" if error.inconclusive else "FAIL"
        add(status, "canonical_validator_runtime", error.code)
        add(status, "plugin_manifest_canonical", f"not executed: {error.code}")
        for skill_path in skill_paths:
            add(
                status,
                f"skill_canonical:{skill_path.name}",
                f"not executed: {error.code}",
            )
    except (
        OSError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        validate_canonical.CanonicalValidationError,
    ) as error:
        add("FAIL", "canonical_validator_lock", str(error))
    else:
        add(
            "PASS",
            "canonical_validator_runtime",
            f"{runtime.relative_path}: {runtime.sha256}",
        )
        plugin_validator_lock = validator_lock["plugin_validator"]
        skill_validator_lock = validator_lock["skill_validator"]
        plugin_validator = Path.home() / plugin_validator_lock["path"]
        skill_validator = Path.home() / skill_validator_lock["path"]
        status, evidence = canonical_validator(
            validator=plugin_validator,
            expected_sha256=plugin_validator_lock["sha256"],
            target=plugin_root,
            runtime=runtime,
        )
        add(status, "plugin_manifest_canonical", evidence)

        for skill_path in skill_paths:
            status, evidence = canonical_validator(
                validator=skill_validator,
                expected_sha256=skill_validator_lock["sha256"],
                target=skill_path,
                runtime=runtime,
            )
            add(status, f"skill_canonical:{skill_path.name}", evidence)

    status, evidence = inspect_toolchain_catalog(
        plugin_root / "toolchain.lock.json",
        ["uv", "ruff", "ty", "pip-audit"],
    )
    add(status, "plugin_toolchain_lock", evidence)

    rust_selection: rust_dispatch.BinarySelection | None = None
    rust_unavailable_status = "INCONCLUSIVE"
    rust_unavailable_evidence = "Rust runtime was not inspected"
    try:
        rust_selection = rust_dispatch.resolve_binary(plugin_root)
        add(
            "PASS",
            "rust_core_artifact",
            json.dumps(
                {
                    "path": str(rust_selection.path),
                    "sha256": rust_selection.sha256,
                    "size": rust_selection.size,
                    "target": rust_selection.target,
                },
                sort_keys=True,
            ),
        )
    except rust_dispatch.UnsupportedHostError as error:
        rust_unavailable_evidence = str(error)
        add("INCONCLUSIVE", "rust_core_artifact", rust_unavailable_evidence)
    except (OSError, rust_dispatch.IntegrityError) as error:
        rust_unavailable_status = "FAIL"
        rust_unavailable_evidence = str(error)
        add("FAIL", "rust_core_artifact", rust_unavailable_evidence)

    okf = validate_okf.validate_bundle(plugin_root / "knowledge")
    add(
        normalize_validator_status(okf["okf_core"]["status"]),
        "okf_core",
        json.dumps(okf["okf_core"], sort_keys=True),
    )
    add(
        normalize_validator_status(okf["governor_profile"]["status"]),
        "governor_okf_profile",
        json.dumps(okf["governor_profile"], sort_keys=True),
    )
    if rust_selection is None:
        add(
            rust_unavailable_status,
            "rust_okf_core",
            f"not executed: {rust_unavailable_evidence}",
        )
        add(
            rust_unavailable_status,
            "okf_runtime_differential",
            f"not compared: {rust_unavailable_evidence}",
        )
    else:
        rust_status, evidence, rust_okf = rust_check(
            rust_selection,
            ["okf", str(plugin_root / "knowledge")],
        )
        add(rust_status, "rust_okf_core", evidence)
        if rust_okf is None:
            add("INCONCLUSIVE", "okf_runtime_differential", evidence)
        else:
            python_statuses = (
                okf["okf_core"]["status"],
                okf["governor_profile"]["status"],
            )
            rust_statuses = (
                rust_okf.get("okf_core", {}).get("status"),
                rust_okf.get("governor_profile", {}).get("status"),
            )
            add(
                "PASS" if python_statuses == rust_statuses else "FAIL",
                "okf_runtime_differential",
                f"python={python_statuses}; rust={rust_statuses}",
            )

    lock_path = plugin_root / "references" / "ask-matt.lock.json"
    adapter_path = plugin_root / "adapters" / "ask-matt-routes.json"
    locked_digest: str | None = None
    try:
        source_lock = json.loads(lock_path.read_text(encoding="utf-8"))
        adapter = json.loads(adapter_path.read_text(encoding="utf-8"))
        locked_digest = source_lock["sha256"]
        adapter_digest = adapter["source"]["sha256"]
        if locked_digest != adapter_digest:
            add(
                "FAIL",
                "ask_matt_adapter_lock",
                "Adapter and source lock digests differ",
            )
        else:
            add("PASS", "ask_matt_adapter_lock", locked_digest)

        candidates = (
            Path.home() / ".codex" / "skills" / "ask-matt" / "SKILL.md",
            Path.home() / ".agents" / "skills" / "ask-matt" / "SKILL.md",
        )
        installed = next((path for path in candidates if path.is_file()), None)
        if installed is None:
            add(
                "INCONCLUSIVE",
                "ask_matt_installed_source",
                "installed SKILL.md not found",
            )
        else:
            installed_digest = digest(installed)
            add(
                "PASS" if installed_digest == locked_digest else "FAIL",
                "ask_matt_installed_source",
                f"{installed}: {installed_digest}",
            )
    except (OSError, KeyError, json.JSONDecodeError) as error:
        add("FAIL", "ask_matt_source_lock", str(error))

    repo = repo.resolve()
    policy_path = repo / ".agent-work-governor" / "policy.toml"
    policy_document: dict[str, Any] | None = None
    if policy_path.is_file():
        receipt = validate_policy.build_receipt(policy_path)
        add(
            "PASS" if receipt["valid"] else "FAIL",
            "repository_policy",
            json.dumps(receipt, sort_keys=True),
        )
        try:
            with policy_path.open("rb") as handle:
                policy_document = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError):
            policy_document = None
        if rust_selection is None:
            add(
                rust_unavailable_status,
                "rust_repository_policy",
                f"not executed: {rust_unavailable_evidence}",
            )
            add(
                rust_unavailable_status,
                "policy_runtime_differential",
                f"not compared: {rust_unavailable_evidence}",
            )
        else:
            rust_status, evidence, rust_policy = rust_check(
                rust_selection,
                ["policy", str(policy_path)],
            )
            add(rust_status, "rust_repository_policy", evidence)
            if rust_policy is None:
                add("INCONCLUSIVE", "policy_runtime_differential", evidence)
            else:
                python_codes = sorted(item["code"] for item in receipt["findings"])
                rust_codes = sorted(
                    item.get("code")
                    for item in rust_policy.get("findings", [])
                    if isinstance(item, dict) and isinstance(item.get("code"), str)
                )
                agrees = (
                    receipt["valid"] == rust_policy.get("valid")
                    and python_codes == rust_codes
                )
                add(
                    "PASS" if agrees else "FAIL",
                    "policy_runtime_differential",
                    f"python={python_codes}; rust={rust_codes}",
                )
    else:
        add(
            "WARN",
            "repository_policy",
            f"{policy_path} missing; effective repository authority is read-only",
        )
        add(
            "WARN",
            "rust_repository_policy",
            "not executed because repository policy is missing",
        )

    is_git, git_evidence = run_git(repo, "rev-parse", "--show-toplevel")
    add("PASS" if is_git else "WARN", "git_repository", git_evidence or str(repo))

    receipt_directory = (
        policy_document.get("receipts", {}).get("directory")
        if policy_document and isinstance(policy_document.get("receipts"), dict)
        else ".governance/receipts"
    )
    if not isinstance(receipt_directory, str):
        receipt_directory = ".governance/receipts"
    setup_receipt = repo / receipt_directory / "setup-matt-pocock-skills.json"
    setup_files = (
        repo / "docs" / "agents" / "issue-tracker.md",
        repo / "docs" / "agents" / "domain.md",
        setup_receipt,
    )
    missing_setup = [str(path) for path in setup_files if not path.is_file()]
    invalid_setup: str | None = None
    if not missing_setup:
        try:
            setup = json.loads(setup_receipt.read_text(encoding="utf-8"))
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
            if (
                not isinstance(setup, dict)
                or setup.get("action_kind") != "setup-matt-pocock-skills"
                or setup.get("verdict") != "PASS"
                or setup.get("repository") != str(repo)
                or setup.get("ask_matt_sha256") != locked_digest
                or any(
                    not isinstance(setup.get(field), str) or not setup[field].strip()
                    for field in common_strings
                )
                or not isinstance(setup.get("trace_span_ids"), list)
                or not setup["trace_span_ids"]
                or not isinstance(setup.get("attester"), dict)
                or not isinstance(setup["attester"].get("id"), str)
                or not isinstance(setup["attester"].get("source_digest"), str)
            ):
                invalid_setup = "candidate receipt is malformed or bound elsewhere"
        except (OSError, json.JSONDecodeError) as error:
            invalid_setup = str(error)
    mutating_policy = bool(
        policy_document
        and isinstance(policy_document.get("authority"), dict)
        and policy_document["authority"].get("repository_write") is True
    )
    setup_problem = (
        f"missing: {', '.join(missing_setup)}" if missing_setup else invalid_setup
    )
    add(
        "PASS"
        if setup_problem is None and not mutating_policy
        else "INCONCLUSIVE"
        if setup_problem is None
        else "FAIL"
        if mutating_policy
        else "WARN",
        "matt_setup",
        (
            "candidate artifacts present; trusted runtime attestation is still required"
            if setup_problem is None and mutating_policy
            else "configured"
            if setup_problem is None
            else setup_problem
        ),
    )

    if policy_document and policy_document.get("repository_scope") == "owner_original":
        owner_files = (repo / "AGENTS.md", repo / "flake.nix", repo / "flake.lock")
        missing_owner = [str(path) for path in owner_files if not path.is_file()]
        add(
            "PASS" if not missing_owner else "FAIL",
            "owner_original_files",
            "present" if not missing_owner else f"missing: {', '.join(missing_owner)}",
        )
        environment = policy_document.get("environment")
        if isinstance(environment, dict):
            lock_relative = environment.get("toolchain_lock")
            required_tools = environment.get("required_tools")
        else:
            lock_relative = None
            required_tools = None
        if isinstance(lock_relative, str) and isinstance(required_tools, list):
            status, evidence = inspect_toolchain_catalog(
                repo / lock_relative,
                [tool for tool in required_tools if isinstance(tool, str)],
            )
        else:
            status, evidence = "FAIL", "owner toolchain policy is incomplete"
        add(status, "owner_toolchain_lock", evidence)
        add(
            "INCONCLUSIVE",
            "github_review_closeout",
            "requires a GitHub Adapter receipt; static repository audit cannot prove it",
        )
        add(
            "INCONCLUSIVE",
            "trusted_code_review_attestation",
            "repository-local JSON cannot prove reviewer identity",
        )
        add(
            "INCONCLUSIVE",
            "llm_contract_ast_mapping",
            "shape checks do not replace a pinned AST-to-symbol Adapter receipt",
        )

    statuses = {item["status"] for item in findings}
    overall = (
        "FAIL"
        if "FAIL" in statuses
        else "INCONCLUSIVE"
        if "INCONCLUSIVE" in statuses
        else "WARN"
        if "WARN" in statuses
        else "PASS"
    )
    return {
        "overall": overall,
        "repository": str(repo),
        "mutation_count": 0,
        "findings": findings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)

    report = audit(args.repo)
    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(report["overall"])
        for item in report["findings"]:
            print(f"{item['status']}: {item['check']}: {item['evidence']}")
        print("No files changed.")
    return audit_exit_code(report["overall"])


if __name__ == "__main__":
    sys.exit(main())
