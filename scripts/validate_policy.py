#!/usr/bin/env python3
"""Validate one Agent Work Governor repository policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

# LLM-CONTRACT
# id: agent-work-governor.policy-validation
# state: UNREAD -> PARSED -> VALID | INVALID
# preconditions: policy path or decoded mapping is explicit
# invariant: unknown scope never grants write or external side-effect authority
# failure: emit a structured finding and return a non-zero process status
# source: bundle:knowledge/policies/work-governor.md
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: validate_document
# test: bundle:tests/test_repo_bundle.py

SCHEMA_VERSION = "0.1"
ASK_MATT_SHA256 = "b1a134ada29cbfded84bc9a7f93356ab7a3d7f800edf1f541a2a964118ad45a7"
ALLOWED_SCOPES = {
    "unknown",
    "owner_original",
    "authorized_external",
    "external_read_only",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OWNER_GITHUB_GATES = (
    "one_pr_one_task",
    "require_review_closeout",
    "require_bug_issue_for_merged_finding",
)
OWNER_QUALITY_GATES = (
    "require_llm_contract",
    "require_primary_sources",
    "require_code_review_skill",
    "require_type_check",
    "require_security_check",
)
OWNER_ENVIRONMENT_GATES = (
    "require_nix_flake",
    "require_nix_lock",
    "require_pinned_toolchain",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def finding(code: str, field: str, message: str) -> dict[str, str]:
    return {"severity": "error", "code": code, "field": field, "message": message}


def _table(
    document: dict[str, Any],
    key: str,
    findings: list[dict[str, str]],
) -> dict[str, Any]:
    value = document.get(key)
    if not isinstance(value, dict):
        findings.append(finding("MISSING_TABLE", key, f"{key} must be a TOML table"))
        return {}
    return value


def _require_bool(
    table: dict[str, Any],
    key: str,
    field: str,
    findings: list[dict[str, str]],
    *,
    expected: bool | None = None,
) -> bool | None:
    value = table.get(key)
    if not isinstance(value, bool):
        findings.append(finding("INVALID_BOOLEAN", field, f"{field} must be boolean"))
        return None
    if expected is not None and value is not expected:
        findings.append(
            finding("UNSAFE_VALUE", field, f"{field} must be {str(expected).lower()}")
        )
    return value


def _require_non_negative_int(
    table: dict[str, Any],
    key: str,
    field: str,
    findings: list[dict[str, str]],
    *,
    minimum: int,
) -> int | None:
    value = table.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        findings.append(
            finding("INVALID_BUDGET", field, f"{field} must be an integer >= {minimum}")
        )
        return None
    return value


def _require_non_empty_string(
    table: dict[str, Any],
    key: str,
    field: str,
    findings: list[dict[str, str]],
) -> str | None:
    value = table.get(key)
    if not isinstance(value, str) or not value.strip():
        findings.append(finding("INVALID_STRING", field, f"{field} must be non-empty"))
        return None
    return value


def _require_string_list(
    table: dict[str, Any],
    key: str,
    field: str,
    findings: list[dict[str, str]],
) -> list[str] | None:
    value = table.get(key)
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item.strip() for item in value)
        or len(value) != len(set(value))
    ):
        findings.append(
            finding(
                "INVALID_STRING_LIST",
                field,
                f"{field} must be a non-empty list of unique strings",
            )
        )
        return None
    return value


def _is_safe_relative_path(value: str) -> bool:
    path = Path(value)
    return not path.is_absolute() and ".." not in path.parts


def validate_document(document: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    if document.get("schema_version") != SCHEMA_VERSION:
        findings.append(
            finding(
                "SCHEMA_VERSION_MISMATCH",
                "schema_version",
                f"schema_version must be {SCHEMA_VERSION}",
            )
        )

    policy_id = document.get("policy_id")
    if not isinstance(policy_id, str) or not policy_id.strip():
        findings.append(
            finding("MISSING_POLICY_ID", "policy_id", "policy_id is required")
        )

    scope = document.get("repository_scope")
    if scope not in ALLOWED_SCOPES:
        findings.append(
            finding(
                "INVALID_SCOPE",
                "repository_scope",
                f"repository_scope must be one of {sorted(ALLOWED_SCOPES)}",
            )
        )

    authority = _table(document, "authority", findings)
    repository_write = _require_bool(
        authority, "repository_write", "authority.repository_write", findings
    )
    external_side_effects = _require_bool(
        authority, "external_side_effects", "authority.external_side_effects", findings
    )
    _require_bool(
        authority,
        "destructive_actions",
        "authority.destructive_actions",
        findings,
        expected=False,
    )
    if scope in {"unknown", "external_read_only"}:
        if repository_write:
            findings.append(
                finding(
                    "SCOPE_AUTHORITY_CONFLICT",
                    "authority.repository_write",
                    f"{scope} scope cannot grant repository writes",
                )
            )
        if external_side_effects:
            findings.append(
                finding(
                    "SCOPE_AUTHORITY_CONFLICT",
                    "authority.external_side_effects",
                    f"{scope} scope cannot grant external side effects",
                )
            )
    if scope == "authorized_external":
        external_authority = _table(document, "external_authority", findings)
        for key in ("authority_receipt", "upstream_policy"):
            _require_non_empty_string(
                external_authority,
                key,
                f"external_authority.{key}",
                findings,
            )
        for key in ("authority_receipt_sha256", "upstream_policy_sha256"):
            value = external_authority.get(key)
            if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
                findings.append(
                    finding(
                        "INVALID_AUTHORITY_DIGEST",
                        f"external_authority.{key}",
                        f"external_authority.{key} must be a lower-case SHA-256 digest",
                    )
                )
        if repository_write or external_side_effects:
            findings.append(
                finding(
                    "EXTERNAL_WRITE_ADAPTER_UNAVAILABLE",
                    "repository_scope",
                    "this static slice cannot establish an external trust root; use read-only authority",
                )
            )

    budget = _table(document, "budget", findings)
    _require_non_negative_int(
        budget, "max_in_flight", "budget.max_in_flight", findings, minimum=1
    )
    _require_non_negative_int(
        budget,
        "max_delegation_depth",
        "budget.max_delegation_depth",
        findings,
        minimum=0,
    )
    _require_non_negative_int(
        budget,
        "max_repair_rounds",
        "budget.max_repair_rounds",
        findings,
        minimum=0,
    )

    routing = _table(document, "routing", findings)
    if routing.get("authority") != "ask-matt-or-explicit-user-selection":
        findings.append(
            finding(
                "INVALID_ROUTING_AUTHORITY",
                "routing.authority",
                "routing authority must remain ask-matt-or-explicit-user-selection",
            )
        )
    _require_bool(
        routing,
        "require_explicit_route",
        "routing.require_explicit_route",
        findings,
        expected=True,
    )
    _require_bool(
        routing,
        "allow_route_substitution",
        "routing.allow_route_substitution",
        findings,
        expected=False,
    )
    _require_bool(
        routing,
        "implicit_ask_matt_invocation",
        "routing.implicit_ask_matt_invocation",
        findings,
        expected=False,
    )
    source_digest = routing.get("ask_matt_sha256")
    if not isinstance(source_digest, str) or not SHA256_RE.fullmatch(source_digest):
        findings.append(
            finding(
                "INVALID_SOURCE_DIGEST",
                "routing.ask_matt_sha256",
                "routing.ask_matt_sha256 must be a lower-case SHA-256 digest",
            )
        )
    elif source_digest != ASK_MATT_SHA256:
        findings.append(
            finding(
                "ROUTER_SOURCE_MISMATCH",
                "routing.ask_matt_sha256",
                "routing.ask_matt_sha256 must match the bundled ask-matt Adapter",
            )
        )

    completion = _table(document, "completion", findings)
    for key in (
        "require_terminal_evidence",
        "require_satisfied_postcondition",
        "require_current_artifact_review",
    ):
        _require_bool(
            completion,
            key,
            f"completion.{key}",
            findings,
            expected=True,
        )

    knowledge = _table(document, "knowledge", findings)
    if knowledge.get("okf_version") != "0.2":
        findings.append(
            finding(
                "INVALID_OKF_VERSION",
                "knowledge.okf_version",
                "knowledge.okf_version must be 0.2",
            )
        )
    bundle = knowledge.get("bundle")
    if not isinstance(bundle, str) or not bundle.strip():
        findings.append(
            finding(
                "MISSING_BUNDLE", "knowledge.bundle", "knowledge.bundle is required"
            )
        )

    receipts = _table(document, "receipts", findings)
    _require_bool(
        receipts,
        "include_in_okf_bundle",
        "receipts.include_in_okf_bundle",
        findings,
        expected=False,
    )
    directory = receipts.get("directory")
    if not isinstance(directory, str) or not directory.strip():
        findings.append(
            finding(
                "MISSING_RECEIPT_DIRECTORY",
                "receipts.directory",
                "receipts.directory is required",
            )
        )
    elif not _is_safe_relative_path(directory):
        findings.append(
            finding(
                "UNSAFE_RECEIPT_DIRECTORY",
                "receipts.directory",
                "receipts.directory must be a repository-relative path without '..'",
            )
        )

    if scope == "owner_original":
        default_branch = _require_non_empty_string(
            document,
            "default_branch",
            "default_branch",
            findings,
        )

        github = _table(document, "github", findings)
        branch_base = _require_non_empty_string(
            github, "branch_base", "github.branch_base", findings
        )
        if default_branch and branch_base != f"origin/{default_branch}":
            findings.append(
                finding(
                    "INVALID_BRANCH_BASE",
                    "github.branch_base",
                    "github.branch_base must equal origin/<default_branch>",
                )
            )
        for key in OWNER_GITHUB_GATES:
            _require_bool(github, key, f"github.{key}", findings, expected=True)
        _require_non_negative_int(
            github,
            "product_diff_soft_target",
            "github.product_diff_soft_target",
            findings,
            minimum=1,
        )

        quality = _table(document, "quality", findings)
        for key in OWNER_QUALITY_GATES:
            _require_bool(quality, key, f"quality.{key}", findings, expected=True)
        review_digest = quality.get("code_review_skill_sha256")
        if not isinstance(review_digest, str) or not SHA256_RE.fullmatch(review_digest):
            findings.append(
                finding(
                    "INVALID_REVIEW_SKILL_DIGEST",
                    "quality.code_review_skill_sha256",
                    "quality.code_review_skill_sha256 must be a lower-case SHA-256",
                )
            )

        environment = _table(document, "environment", findings)
        for key in OWNER_ENVIRONMENT_GATES:
            _require_bool(
                environment, key, f"environment.{key}", findings, expected=True
            )
        lock_path = _require_non_empty_string(
            environment,
            "toolchain_lock",
            "environment.toolchain_lock",
            findings,
        )
        if lock_path and not _is_safe_relative_path(lock_path):
            findings.append(
                finding(
                    "UNSAFE_TOOLCHAIN_LOCK_PATH",
                    "environment.toolchain_lock",
                    "environment.toolchain_lock must be repository-relative without '..'",
                )
            )
        _require_string_list(
            environment,
            "required_tools",
            "environment.required_tools",
            findings,
        )

    return sorted(
        findings, key=lambda item: (item["code"], item["field"], item["message"])
    )


def load_policy(path: Path) -> tuple[dict[str, Any] | None, list[dict[str, str]]]:
    try:
        with path.open("rb") as handle:
            document = tomllib.load(handle)
    except FileNotFoundError:
        return None, [
            finding("POLICY_NOT_FOUND", str(path), "policy file does not exist")
        ]
    except (OSError, tomllib.TOMLDecodeError) as error:
        return None, [finding("POLICY_PARSE_ERROR", str(path), str(error))]
    if not isinstance(document, dict):
        return None, [
            finding("INVALID_POLICY_ROOT", str(path), "policy root must be a table")
        ]
    return document, []


def build_receipt(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    document, parse_findings = load_policy(resolved)
    findings = parse_findings if document is None else validate_document(document)
    policy_digest = sha256_file(resolved) if resolved.is_file() else None
    validator_path = Path(__file__).resolve()
    return {
        "policy_path": str(resolved),
        "policy_sha256": policy_digest,
        "validator_sha256": sha256_file(validator_path),
        "schema_version": SCHEMA_VERSION,
        "valid": not findings,
        "findings": findings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("policy", type=Path)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)

    receipt = build_receipt(args.policy)
    if args.as_json:
        print(json.dumps(receipt, indent=2, sort_keys=True))
    else:
        print("PASS" if receipt["valid"] else "FAIL")
        for item in receipt["findings"]:
            print(f"{item['code']}: {item['field']}: {item['message']}")
    return 0 if receipt["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
