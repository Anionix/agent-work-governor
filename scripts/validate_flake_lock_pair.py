#!/usr/bin/env python3
"""Validate an isolated flake-lock regeneration against committed bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Final

# LLM-CONTRACT
# id: agent-work-governor.flake-lock-pair
# state: CANDIDATE_FLAKE_PAIR -> CLEAN_REGENERATION -> BYTE_EQUIVALENT | STALE_LOCK | REGENERATION_INCONCLUSIVE
# preconditions: Nix writes the regenerated lock outside the repository
# invariant: only byte-identical regular-file locks pass under the reviewed head and pinned Nix identity
# failure: mismatch exits 1; unreadable input or invalid execution identity exits 2
# source: https://github.com/NixOS/nix/blob/2c6d06e9387cf58167cb5a7ab91cee7333d8d17c/src/nix/flake-lock.md
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: validate_pair
# test: bundle:tests/test_flake_lock_pair.py

HEAD_SHA_PATTERN: Final = re.compile(r"[0-9a-f]{40}")
PINNED_NIX_IDENTITY: Final = "nix (Nix) 2.34.7"
MAX_INPUT_BYTES: Final = 4 * 1024 * 1024


def _read_regular(path: Path) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_INPUT_BYTES:
            raise OSError(f"not a regular file: {path}")
        chunks: list[bytes] = []
        observed = 0
        while chunk := os.read(descriptor, min(1024 * 1024, MAX_INPUT_BYTES + 1)):
            observed += len(chunk)
            if observed > MAX_INPUT_BYTES:
                raise OSError(f"input exceeds byte limit: {path}")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _digest(path: Path) -> tuple[bytes | None, str | None]:
    try:
        content = _read_regular(path)
    except OSError:
        return None, None
    return content, hashlib.sha256(content).hexdigest()


def validate_pair(
    *,
    flake_nix: Path,
    committed_lock: Path,
    regenerated_lock: Path,
    head_sha: str,
    nix_version: str,
) -> tuple[dict[str, str | None], int]:
    """Return deterministic evidence and the fail-closed process exit."""
    flake_bytes, flake_digest = _digest(flake_nix)
    committed_bytes, committed_digest = _digest(committed_lock)
    regenerated_bytes, regenerated_digest = _digest(regenerated_lock)
    evidence: dict[str, str | None] = {
        "code": "",
        "committed_lock_sha256": committed_digest,
        "flake_nix_sha256": flake_digest,
        "head_sha": head_sha,
        "nix_version": nix_version,
        "regenerated_lock_sha256": regenerated_digest,
        "state": "",
        "status": "",
    }

    if (
        HEAD_SHA_PATTERN.fullmatch(head_sha) is None
        or nix_version != PINNED_NIX_IDENTITY
    ):
        evidence.update(
            code="FLAKE_LOCK_EXECUTION_IDENTITY_INVALID",
            state="REGENERATION_INCONCLUSIVE",
            status="INCONCLUSIVE",
        )
        return evidence, 2
    if flake_bytes is None or committed_bytes is None or regenerated_bytes is None:
        evidence.update(
            code="FLAKE_LOCK_PAIR_UNREADABLE",
            state="REGENERATION_INCONCLUSIVE",
            status="INCONCLUSIVE",
        )
        return evidence, 2
    if committed_bytes != regenerated_bytes:
        evidence.update(
            code="FLAKE_LOCK_PAIR_MISMATCH",
            state="STALE_LOCK",
            status="FAIL",
        )
        return evidence, 1

    evidence.update(
        code="FLAKE_LOCK_PAIR_MATCH",
        state="BYTE_EQUIVALENT",
        status="PASS",
    )
    return evidence, 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--flake-nix", type=Path, required=True)
    parser.add_argument("--committed-lock", type=Path, required=True)
    parser.add_argument("--regenerated-lock", type=Path, required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--nix-version", required=True)
    arguments = parser.parse_args()
    evidence, exit_code = validate_pair(
        flake_nix=arguments.flake_nix,
        committed_lock=arguments.committed_lock,
        regenerated_lock=arguments.regenerated_lock,
        head_sha=arguments.head_sha,
        nix_version=arguments.nix_version,
    )
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
