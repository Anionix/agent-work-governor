#!/usr/bin/env python3
"""Project the canonical toolchain byte digest into exact JSON fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Final

from toolchain_catalog import (
    SHA256_PATTERN,
    unique_json_object,
    validate_catalog,
)

# LLM-CONTRACT
# id: agent-work-governor.toolchain-digest-projection
# state: TOOLCHAIN_LOCK_BYTES + DECLARED_JSON_POINTERS -> BYTE_EXACT_PROJECTIONS | PROJECTION_REJECTED
# preconditions: one repository root contains the canonical lock and two declared regular-file fixtures
# invariant: only bindings.toolchain_sha256 changes; duplicate, malformed, stale, or partial projections never pass check mode
# failure: check mode never writes; failed writes attempt bounded rollback and emit one stable TOOLCHAIN_PROJECTION_* code
# source: https://github.com/python/cpython/blob/c63aec69bd59c55314c06c23f4c22c03de76fe45/Doc/library/json.rst
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: synchronize
# test: bundle:tests/test_toolchain_projection.py

PROJECTIONS: Final = (
    Path("rust/tests/fixtures/rejected-plan-report.json"),
    Path("rust/tests/fixtures/rust-plan-report.json"),
)
FIELD = re.compile(r'("toolchain_sha256"\s*:\s*")[0-9a-f]{64}(")')
MAX_INPUT_BYTES = 2_000_000


class ProjectionError(ValueError):
    """One stable fail-closed projection error."""

    def __init__(self, code: str, paths: tuple[str, ...] = ()) -> None:
        super().__init__(code)
        self.code = code
        self.paths = paths


def _reject_json_constant(value: str) -> None:
    raise ValueError(value)


def _read_regular(path: Path) -> bytes:
    try:
        if path.is_symlink() or not path.is_file():
            raise OSError
        payload = path.read_bytes()
    except OSError as error:
        raise ProjectionError("TOOLCHAIN_PROJECTION_INPUT_INVALID") from error
    if not payload or len(payload) > MAX_INPUT_BYTES:
        raise ProjectionError("TOOLCHAIN_PROJECTION_INPUT_INVALID")
    return payload


def _render(path: Path, digest: str) -> bytes:
    payload = _read_regular(path)
    try:
        text = payload.decode("utf-8")
        document = json.loads(
            text,
            object_pairs_hook=unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise ProjectionError(
            "TOOLCHAIN_PROJECTION_INVALID",
            (path.name,),
        ) from error
    if (
        not isinstance(document, dict)
        or not isinstance(document.get("bindings"), dict)
        or not isinstance(document["bindings"].get("toolchain_sha256"), str)
        or SHA256_PATTERN.fullmatch(document["bindings"]["toolchain_sha256"]) is None
        or text.count('"toolchain_sha256"') != 1
    ):
        raise ProjectionError("TOOLCHAIN_PROJECTION_INVALID", (path.name,))
    rendered, count = FIELD.subn(
        lambda match: f"{match.group(1)}{digest}{match.group(2)}",
        text,
    )
    if count != 1:
        raise ProjectionError("TOOLCHAIN_PROJECTION_INVALID", (path.name,))
    return rendered.encode("utf-8")


def _expected(root: Path) -> tuple[str, dict[Path, bytes]]:
    catalog = root / "toolchain.lock.json"
    before = _read_regular(catalog)
    _, findings = validate_catalog(catalog)
    if findings or _read_regular(catalog) != before:
        raise ProjectionError("TOOLCHAIN_PROJECTION_CATALOG_INVALID")
    digest = hashlib.sha256(before).hexdigest()
    return digest, {
        root / relative: _render(root / relative, digest) for relative in PROJECTIONS
    }


def synchronize(root: Path, *, write: bool) -> dict[str, object]:
    """Check or update every declared projection as one bounded operation."""
    root = root.resolve()
    digest, expected = _expected(root)
    stale = tuple(
        path for path, projected in expected.items() if _read_regular(path) != projected
    )
    relative = tuple(str(path.relative_to(root)) for path in stale)
    report: dict[str, object] = {
        "digest": digest,
        "projections": len(expected),
        "status": "PASS",
        "updated": list(relative),
    }
    if not stale:
        return report
    if not write:
        raise ProjectionError("TOOLCHAIN_PROJECTION_STALE", relative)
    originals = {path: _read_regular(path) for path in stale}
    try:
        for path in stale:
            path.write_bytes(expected[path])
        _, confirmed = _expected(root)
        if any(
            _read_regular(path) != projected for path, projected in confirmed.items()
        ):
            raise OSError
    except (OSError, ProjectionError) as error:
        try:
            for path, payload in originals.items():
                path.write_bytes(payload)
        except OSError:
            pass
        raise ProjectionError("TOOLCHAIN_PROJECTION_WRITE_FAILED", relative) from error
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        report = synchronize(arguments.root, write=arguments.write)
    except ProjectionError as error:
        print(
            json.dumps(
                {"code": error.code, "paths": error.paths, "status": "FAIL"},
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
