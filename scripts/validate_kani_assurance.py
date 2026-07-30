#!/usr/bin/env python3
"""Validate bounded Kani shadow evidence and emit a non-authoritative receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tomllib
from pathlib import Path
from typing import Any, cast

# LLM-CONTRACT
# id: agent-work-governor.kani-assurance-validator
# state: MANIFEST + SOURCE + KANI_LOG -> SHADOW_RECEIPT | EVIDENCE_REJECTED
# preconditions: the caller supplies bounded regular files below one repository root
# invariant: source digests, harness set, bounds, verification, and every cover agree exactly
# failure: malformed, stale, missing, duplicate, or non-SATISFIED evidence exits non-zero
# source: https://github.com/model-checking/kani/blob/4feaaad1d6a2378a6ff6caa3b4fc5d6999c7bb5d/kani-driver/src/cbmc_output_parser.rs
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: validate
# test: bundle:tests/test_kani_assurance.py

MAX_MANIFEST = 32 * 1024
MAX_SOURCE = 64 * 1024
MAX_LOG = 1024 * 1024
EXPECTED_KEYS = {
    "bounds",
    "claims",
    "excluded",
    "expected_covers",
    "harness_sha256",
    "invocation",
    "mode",
    "negative_canary",
    "non_vacuity",
    "positive_harnesses",
    "schema_version",
    "source_path",
    "source_sha256",
    "subject",
    "tool_id",
    "tool_version",
}
EXPECTED_BOUNDS = {
    "authority_bits": 6,
    "binding_mask_bits": 8,
    "timestamp_bits": 64,
    "unwind": 1,
}
EXPECTED_INVOCATION = (
    "cargo kani --manifest-path rust/Cargo.toml --lib --harness <positive_harness>"
)
ANSI = re.compile(r"\x1b\[[0-9;]*m")
RESULT = re.compile(
    r'Status:[ \t]+([A-Z]+)[ \t]*\r?\n[ \t]*(?:-\s*)?Description:\s+"([^"\r\n]+)"'
)


class AssuranceError(ValueError):
    """Raised when Kani evidence cannot establish the bounded shadow claim."""


def _read_regular(path: Path, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise AssuranceError(f"invalid evidence file: {path}")
    return path.read_bytes()


def _below(root: Path, path: Path) -> Path:
    resolved = path.resolve()
    if not resolved.is_relative_to(root):
        raise AssuranceError(f"evidence path escapes repository: {path}")
    return resolved


def _strings(value: object, field: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        raise AssuranceError(f"invalid string set: {field}")
    return cast(list[str], value)


def validate(
    root: Path, manifest_path: Path, log_path: Path, kani_version: str
) -> dict[str, Any]:
    """Return a shadow receipt or raise on any incomplete assurance evidence."""
    root = root.resolve(strict=True)
    manifest = tomllib.loads(
        _read_regular(_below(root, root / manifest_path), MAX_MANIFEST).decode()
    )
    if (
        set(manifest) != EXPECTED_KEYS
        or manifest.get("schema_version") != "0.1"
        or manifest.get("mode") != "shadow"
        or manifest.get("tool_id") != "kani"
        or manifest.get("tool_version") != kani_version
        or manifest.get("bounds") != EXPECTED_BOUNDS
        or manifest.get("invocation") != EXPECTED_INVOCATION
    ):
        raise AssuranceError("manifest identity or bounds mismatch")
    source_relative = manifest.get("source_path")
    for field in ("subject", "negative_canary", "non_vacuity"):
        if not isinstance(manifest.get(field), str) or not manifest[field]:
            raise AssuranceError(f"invalid string: {field}")
    _strings(manifest.get("claims"), "claims")
    _strings(manifest.get("excluded"), "excluded")
    if not isinstance(source_relative, str) or not source_relative:
        raise AssuranceError("source_path is invalid")
    source = _read_regular(_below(root, root / source_relative), MAX_SOURCE)
    source_digest = hashlib.sha256(source).hexdigest()
    if (
        manifest.get("source_sha256") != source_digest
        or manifest.get("harness_sha256") != source_digest
    ):
        raise AssuranceError("source or harness digest mismatch")
    harnesses = _strings(manifest.get("positive_harnesses"), "positive_harnesses")
    covers = _strings(manifest.get("expected_covers"), "expected_covers")
    log = ANSI.sub("", _read_regular(log_path.resolve(strict=True), MAX_LOG).decode())
    if log.count("VERIFICATION:- SUCCESSFUL") != len(harnesses) or re.search(
        r"Status:\s+(?:UNDETERMINED|UNKNOWN|UNREACHABLE|UNSATISFIABLE)", log
    ):
        raise AssuranceError("verification or reachability is incomplete")
    observed: dict[str, list[str]] = {}
    for status, description in RESULT.findall(log):
        observed.setdefault(description, []).append(status)
    for description in covers:
        if observed.get(description) != ["SATISFIED"]:
            raise AssuranceError(f"cover is not uniquely satisfied: {description}")
    return {
        "authority": "none",
        "bounds": EXPECTED_BOUNDS,
        "covers": covers,
        "harnesses": harnesses,
        "source_sha256": source_digest,
        "status": "PASS",
        "tool": f"kani-{kani_version}",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--kani-version", required=True)
    arguments = parser.parse_args()
    try:
        receipt = validate(
            arguments.root, arguments.manifest, arguments.log, arguments.kani_version
        )
    except (AssuranceError, OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        print(json.dumps({"reason": str(error), "status": "FAIL"}, sort_keys=True))
        return 1
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
