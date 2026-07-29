#!/usr/bin/env python3
"""Validate and query the unified, provenance-bearing toolchain catalog."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Final, TypedDict, cast

# LLM-CONTRACT
# id: agent-work-governor.toolchain-catalog
# state: CATALOG_BYTES -> UNIQUE_TYPED_CONSISTENT_PINS -> VALIDATED_CATALOG | LOCK_REJECTED
# preconditions: the caller supplies one explicit catalog and required-ID set
# invariant: no duplicate, unsupported, floating, or contradictory component identity resolves
# failure: return sorted stable findings without executing any catalogued tool
# source: https://github.com/python/cpython/blob/c63aec69bd59c55314c06c23f4c22c03de76fe45/Doc/library/json.rst
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: validate_catalog
# test: bundle:tests/test_repo_bundle.py

LANGUAGES = frozenset({"github_actions", "nix", "python", "rust"})
SYSTEMS = frozenset({"aarch64-darwin", "aarch64-linux", "x86_64-linux"})
ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9./-]*")
VERSION_PATTERN = re.compile(
    r"(?:v?\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.]+)?|[0-9a-f]{40})"
)
DIGEST_PATTERN = re.compile(r"(?:git:[0-9a-f]{40}|sha256:[0-9a-f]{64})")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
PIN_FIELDS = frozenset({"id", "language", "version", "source", "source_digest"})
FLOATING_VERSIONS = frozenset({"head", "latest", "main", "master", "nightly", "stable"})
CANONICAL_GIT_REPOSITORIES: Final[dict[str, str]] = {
    "cachix/install-nix-action": "https://github.com/cachix/install-nix-action",
    "cargo": "https://github.com/rust-lang/cargo",
    "clippy": "https://github.com/rust-lang/rust",
    "ruff": "https://github.com/astral-sh/ruff",
    "rust": "https://github.com/rust-lang/rust",
    "rustfmt": "https://github.com/rust-lang/rust",
    "ty": "https://github.com/astral-sh/ty",
    "uv": "https://github.com/astral-sh/uv",
}


class Finding(TypedDict):
    """One stable fail-closed catalog diagnostic."""

    code: str
    tool_id: str
    field: str


class DuplicateJsonKey(ValueError):
    """Raised before JSON object keys can overwrite one another."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKey(key)
        result[key] = value
    return result


def _finding(code: str, tool_id: str = "", field: str = "") -> Finding:
    return {"code": code, "tool_id": tool_id, "field": field}


# LLM-CONTRACT
# id: agent-work-governor.canonical-git-tool-source
# state: TOOL_ID + DECLARED_IDENTITY + SOURCE_URL -> CANONICAL_GIT_SOURCE | SOURCE_REJECTED
# preconditions: generic catalog shape and exact digest validation have passed
# invariant: validator-owned Git tools retain both Git identity kind and repository identity
# failure: emit one stable source finding before any catalogued tool executes
# source: https://github.com/git/git/blob/13c7afec212fc97ce257d15601659314c6673d6c/Documentation/gitrepository-layout.adoc
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: _git_source_repository_finding
# test: bundle:tests/test_repo_bundle.py
def _git_source_repository_finding(
    tool_id: str,
    source: str,
    digest: str,
) -> Finding | None:
    repository = CANONICAL_GIT_REPOSITORIES.get(tool_id)
    if repository is None:
        if digest.startswith("git:"):
            return _finding(
                "TOOLCHAIN_SOURCE_REPOSITORY_MISMATCH",
                tool_id,
                "source",
            )
        return None
    if not digest.startswith("git:"):
        return _finding(
            "TOOLCHAIN_SOURCE_REPOSITORY_MISMATCH",
            tool_id,
            "source_digest",
        )
    expected = f"{repository}/commit/{digest[4:]}"
    if source != expected:
        return _finding("TOOLCHAIN_SOURCE_REPOSITORY_MISMATCH", tool_id, "source")
    return None


def _rust_component_findings(pins: dict[str, dict[str, Any]]) -> list[Finding]:
    # LLM-CONTRACT
    # id: agent-work-governor.rust-component-catalog
    # state: INDIVIDUAL_RUST_PINS -> CONSISTENT_COMPONENT_SET | COMPONENT_REJECTED
    # preconditions: generic catalog shape and exact-pin checks have run
    # invariant: present Rust components share the release identities consumed by Nix
    # failure: emit stable component/field evidence without executing the toolchain
    # source: https://github.com/rust-lang/rust/blob/8bab26f4f68e0e26f0bb7960be334d5b520ea452/src/tools/build-manifest/src/main.rs
    # knowledge: bundle:knowledge/policies/work-governor.md
    # enforced_by: validate_catalog
    # test: bundle:tests/test_repo_bundle.py
    rust = pins.get("rust")
    if rust is None:
        return []

    findings: list[Finding] = []
    components = {
        tool_id: pins[tool_id]
        for tool_id in ("cargo", "clippy", "rust", "rustfmt")
        if tool_id in pins
    }
    for tool_id, pin in components.items():
        if pin.get("language") != "rust":
            findings.append(
                _finding("TOOLCHAIN_RUST_COMPONENT_MISMATCH", tool_id, "language")
            )

    cargo = components.get("cargo")
    if cargo is not None and cargo.get("version") != rust.get("version"):
        findings.append(
            _finding("TOOLCHAIN_RUST_COMPONENT_MISMATCH", "cargo", "version")
        )
    for tool_id in ("clippy", "rustfmt"):
        pin = components.get(tool_id)
        if pin is None:
            continue
        for field in ("source", "source_digest"):
            if pin.get(field) != rust.get(field):
                findings.append(
                    _finding("TOOLCHAIN_RUST_COMPONENT_MISMATCH", tool_id, field)
                )
    return findings


def _valid_artifacts(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != SYSTEMS:
        return False
    artifacts = cast(dict[str, object], value)
    for artifact_value in artifacts.values():
        if not isinstance(artifact_value, dict):
            return False
        artifact = cast(dict[str, object], artifact_value)
        url = artifact.get("url")
        sha256 = artifact.get("sha256")
        if (
            set(artifact) != {"url", "sha256"}
            or not isinstance(url, str)
            or not url.startswith("https://")
            or not isinstance(sha256, str)
            or SHA256_PATTERN.fullmatch(sha256) is None
        ):
            return False
    return True


def validate_catalog(
    path: Path,
    required: Iterable[str] = (),
) -> tuple[dict[str, dict[str, Any]], list[Finding]]:
    """Return unique pins and deterministic findings without running tools."""
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
        )
    except DuplicateJsonKey as error:
        return {}, [_finding("TOOLCHAIN_DUPLICATE_JSON_KEY", field=str(error))]
    except (OSError, json.JSONDecodeError):
        return {}, [_finding("TOOLCHAIN_LOCK_UNREADABLE")]

    if not isinstance(document, dict) or document.get("schema_version") != "0.2":
        return {}, [_finding("TOOLCHAIN_SCHEMA_MISMATCH")]
    declared_required = document.get("required")
    tools = document.get("tools")
    if (
        set(document) != {"locked_at", "required", "schema_version", "tools"}
        or not isinstance(document.get("locked_at"), str)
        or re.fullmatch(r"\d{4}-\d{2}-\d{2}", document["locked_at"]) is None
        or not isinstance(declared_required, list)
        or not isinstance(tools, list)
    ):
        return {}, [_finding("TOOLCHAIN_ENTRY_INVALID", field="<catalog>")]

    findings: list[Finding] = []
    caller_required = list(required)
    declared_strings = [value for value in declared_required if isinstance(value, str)]
    caller_strings = [value for value in caller_required if isinstance(value, str)]
    if (
        len(declared_strings) != len(declared_required)
        or declared_strings != sorted(declared_strings)
        or any(ID_PATTERN.fullmatch(value) is None for value in declared_strings)
        or len(caller_strings) != len(caller_required)
        or any(ID_PATTERN.fullmatch(value) is None for value in caller_strings)
    ):
        findings.append(_finding("TOOLCHAIN_ENTRY_INVALID", field="required"))
    if len(set(declared_strings)) != len(declared_strings) or len(
        set(caller_strings)
    ) != len(caller_strings):
        findings.append(_finding("TOOLCHAIN_DUPLICATE_ID", field="required"))
    required_ids = set(declared_strings) | set(caller_strings)

    pins: dict[str, dict[str, Any]] = {}
    observed_ids: list[str] = []
    for index, value in enumerate(tools):
        fallback_id = f"index:{index}"
        if not isinstance(value, dict):
            findings.append(_finding("TOOLCHAIN_ENTRY_INVALID", fallback_id))
            continue
        entry = cast(dict[str, Any], value)
        tool_id = entry.get("id")
        tool_id = tool_id if isinstance(tool_id, str) else fallback_id
        observed_ids.append(tool_id)
        allowed_fields = PIN_FIELDS | {"artifacts"}
        if set(entry) - allowed_fields or PIN_FIELDS - set(entry):
            findings.append(_finding("TOOLCHAIN_ENTRY_INVALID", tool_id))
            continue
        language = entry["language"]
        if not isinstance(language, str) or language not in LANGUAGES:
            findings.append(
                _finding("TOOLCHAIN_LANGUAGE_UNSUPPORTED", tool_id, "language")
            )
        version = entry["version"]
        source = entry["source"]
        digest = entry["source_digest"]
        if (
            ID_PATTERN.fullmatch(tool_id) is None
            or not isinstance(version, str)
            or VERSION_PATTERN.fullmatch(version) is None
            or version.lower() in FLOATING_VERSIONS
            or not isinstance(source, str)
            or not source.startswith("https://")
            or not isinstance(digest, str)
            or DIGEST_PATTERN.fullmatch(digest) is None
            or (digest.startswith("git:") and digest[4:] not in source)
            or ("artifacts" in entry and not _valid_artifacts(entry["artifacts"]))
        ):
            findings.append(_finding("TOOLCHAIN_ENTRY_INVALID", tool_id))
        elif git_source_finding := _git_source_repository_finding(
            tool_id,
            source,
            digest,
        ):
            findings.append(git_source_finding)
        if tool_id in pins:
            findings.append(_finding("TOOLCHAIN_DUPLICATE_ID", tool_id))
        else:
            pins[tool_id] = entry

    if observed_ids != sorted(observed_ids):
        findings.append(_finding("TOOLCHAIN_ENTRY_INVALID", field="tools-order"))
    for language in ("python", "rust"):
        if not any(pin.get("language") == language for pin in pins.values()):
            findings.append(_finding("TOOLCHAIN_LANGUAGE_REQUIRED", field=language))
    for tool_id in sorted(required_ids):
        if tool_id not in pins:
            findings.append(_finding("REQUIRED_TOOL_NOT_LOCKED", tool_id))
    findings.extend(_rust_component_findings(pins))

    findings.sort(key=lambda item: (item["code"], item["tool_id"], item["field"]))
    return ({}, findings) if findings else (pins, [])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catalog", type=Path)
    parser.add_argument("--require", action="append", default=[])
    query = parser.add_mutually_exclusive_group()
    query.add_argument("--tool-version", metavar="TOOL_ID")
    query.add_argument("--tool-source", metavar="TOOL_ID")
    arguments = parser.parse_args(argv)
    required = [*arguments.require]
    query_tool = arguments.tool_version or arguments.tool_source
    if query_tool:
        required.append(query_tool)
    pins, findings = validate_catalog(arguments.catalog, required)
    if findings:
        print(json.dumps({"findings": findings, "status": "FAIL"}, sort_keys=True))
        return 1
    if arguments.tool_version:
        print(pins[arguments.tool_version]["version"])
    elif arguments.tool_source:
        pin = pins[arguments.tool_source]
        print(f"{pin['source']}\t{pin['source_digest']}")
    else:
        print(json.dumps({"status": "PASS", "tools": len(pins)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
