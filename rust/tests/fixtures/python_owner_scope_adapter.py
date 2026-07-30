"""Exercise the real Python dispatcher with one Cargo-built test binary."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))

import rust_dispatch

# LLM-CONTRACT
# id: agent-work-governor.owner-scope-python-adapter-test
# state: EXACT_TEST_BINARY + CLI_BYTES -> DISPATCHED_REPORT | TYPED_ROUTE_FAILURE
# preconditions: the Rust integration harness supplies CARGO_BIN_EXE and bounded arguments
# invariant: the helper replaces artifact selection only; parsing, forwarding, and exit mapping remain the production dispatcher
# failure: missing binary, timeout, non-JSON output, or adapter drift fails the differential test
# source: repo:scripts/rust_dispatch.py
# knowledge: repo:knowledge/policies/work-governor.md
# enforced_by: rust_dispatch.main
# test: repo:rust/tests/owner_scope.rs


def main() -> int:
    binary = Path(sys.argv[1]).resolve(strict=True)
    binary_sha256 = rust_dispatch.sha256_file(binary)
    selection = rust_dispatch.BinarySelection(
        plugin_root=Path(__file__).resolve().parents[3],
        target="test-only",
        path=binary,
        sha256=binary_sha256,
        size=binary.stat().st_size,
        component_version=f"sha256:{binary_sha256}",
        rustc_version="test-only",
    )
    with patch.object(rust_dispatch, "resolve_binary", return_value=selection):
        return rust_dispatch.main(sys.argv[2:])


if __name__ == "__main__":
    raise SystemExit(main())
