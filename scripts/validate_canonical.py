#!/usr/bin/env python3
"""Run digest-pinned canonical Codex Plugin and Skill validators."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any

# LLM-CONTRACT
# id: agent-work-governor.canonical-validator-runner
# state: LOCKED_VALIDATORS -> VERIFIED_BYTES -> CANONICAL_PASS | CLOSED_FAILURE
# preconditions: the lock identifies installed paths and immutable OpenAI Codex source URLs
# invariant: missing, redirected, oversized, or digest-mismatched validator bytes never execute
# failure: validation reports the exact failed boundary and exits non-zero
# source: bundle:references/canonical-validators.lock.json
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: main
# test: bundle:tests/test_contracts.py
# Primary source: https://github.com/openai/codex

VALIDATOR_KEYS = ("plugin_validator", "skill_validator")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_VALIDATOR_BYTES = 1_000_000
SOURCE_REPOSITORY = "https://github.com/openai/codex"
RAW_PREFIX = "https://raw.githubusercontent.com/openai/codex"


class CanonicalValidationError(RuntimeError):
    """A fail-closed canonical-validator boundary error."""


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fetch-missing",
        action="store_true",
        help="fetch a missing validator from its immutable locked source",
    )
    parser.add_argument("plugin_root", nargs="?", default=".")
    return parser.parse_args(argv)


def require_string(entry: dict[str, Any], field: str, key: str) -> str:
    value = entry.get(field)
    if not isinstance(value, str) or not value:
        raise CanonicalValidationError(f"{key}.{field} must be a non-empty string")
    return value


def load_lock(plugin_root: Path) -> dict[str, dict[str, str]]:
    lock_path = plugin_root / "references/canonical-validators.lock.json"
    document = json.loads(lock_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("schema_version") != "0.1":
        raise CanonicalValidationError("canonical validator lock schema is invalid")

    entries: dict[str, dict[str, str]] = {}
    for key in VALIDATOR_KEYS:
        raw_entry = document.get(key)
        if not isinstance(raw_entry, dict):
            raise CanonicalValidationError(f"{key} lock entry is missing")
        entry = {
            field: require_string(raw_entry, field, key)
            for field in (
                "path",
                "source_repository",
                "source_commit",
                "source_path",
                "source_url",
                "sha256",
            )
        }
        installed_path = PurePosixPath(entry["path"])
        source_path = PurePosixPath(entry["source_path"])
        if installed_path.is_absolute() or ".." in installed_path.parts:
            raise CanonicalValidationError(f"{key}.path must stay below the user home")
        if source_path.is_absolute() or ".." in source_path.parts:
            raise CanonicalValidationError(
                f"{key}.source_path must be repository-relative"
            )
        if entry["source_repository"] != SOURCE_REPOSITORY:
            raise CanonicalValidationError(f"{key}.source_repository is not canonical")
        if COMMIT_RE.fullmatch(entry["source_commit"]) is None:
            raise CanonicalValidationError(f"{key}.source_commit is not immutable")
        expected_url = f"{RAW_PREFIX}/{entry['source_commit']}/{entry['source_path']}"
        if entry["source_url"] != expected_url:
            raise CanonicalValidationError(
                f"{key}.source_url contradicts its source lock"
            )
        if SHA256_RE.fullmatch(entry["sha256"]) is None:
            raise CanonicalValidationError(f"{key}.sha256 is invalid")
        entries[key] = entry
    return entries


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def verified_installed_validator(entry: dict[str, str]) -> Path | None:
    candidate = Path.home() / entry["path"]
    if not candidate.is_file():
        return None
    observed = hashlib.sha256(candidate.read_bytes()).hexdigest()
    if observed != entry["sha256"]:
        raise CanonicalValidationError(
            f"installed canonical validator digest mismatch: {candidate}"
        )
    return candidate


def fetch_verified_validator(
    entry: dict[str, str],
    destination: Path,
) -> Path:
    request = urllib.request.Request(
        entry["source_url"],
        headers={"User-Agent": "agent-work-governor/0.1"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.geturl() != entry["source_url"]:
            raise CanonicalValidationError("canonical validator download redirected")
        payload = response.read(MAX_VALIDATOR_BYTES + 1)
    if len(payload) > MAX_VALIDATOR_BYTES:
        raise CanonicalValidationError("canonical validator exceeds the size limit")
    if sha256_bytes(payload) != entry["sha256"]:
        raise CanonicalValidationError("downloaded canonical validator digest mismatch")
    destination.write_bytes(payload)
    return destination


def resolve_validator(
    key: str,
    entry: dict[str, str],
    temporary_root: Path,
    *,
    fetch_missing: bool,
) -> Path:
    installed = verified_installed_validator(entry)
    if installed is not None:
        return installed
    if not fetch_missing:
        raise CanonicalValidationError(f"canonical validator is unavailable: {key}")
    return fetch_verified_validator(entry, temporary_root / f"{key}.py")


def run_validator(validator: Path, target: Path) -> None:
    process = subprocess.run(
        [sys.executable, "-I", str(validator), str(target)],
        check=False,
        text=True,
        capture_output=True,
        timeout=30,
    )
    evidence = process.stdout.strip() or process.stderr.strip()
    if evidence:
        print(evidence)
    if process.returncode != 0:
        raise CanonicalValidationError(
            f"{validator.name} rejected {target}: exit {process.returncode}"
        )


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(sys.argv[1:] if argv is None else argv)
    plugin_root = Path(arguments.plugin_root).resolve()
    try:
        entries = load_lock(plugin_root)
        with tempfile.TemporaryDirectory(
            prefix="agent-work-governor-validators-"
        ) as raw:
            temporary_root = Path(raw)
            plugin_validator = resolve_validator(
                "plugin_validator",
                entries["plugin_validator"],
                temporary_root,
                fetch_missing=arguments.fetch_missing,
            )
            skill_validator = resolve_validator(
                "skill_validator",
                entries["skill_validator"],
                temporary_root,
                fetch_missing=arguments.fetch_missing,
            )
            run_validator(plugin_validator, plugin_root)
            skills_root = plugin_root / "skills"
            skill_paths = sorted(
                path
                for path in skills_root.iterdir()
                if path.is_dir() and (path / "SKILL.md").is_file()
            )
            if not skill_paths:
                raise CanonicalValidationError("plugin contains no canonical Skill")
            for skill_path in skill_paths:
                run_validator(skill_validator, skill_path)
    except (
        CanonicalValidationError,
        json.JSONDecodeError,
        OSError,
        subprocess.SubprocessError,
        TimeoutError,
        urllib.error.URLError,
    ) as error:
        print(f"canonical validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
