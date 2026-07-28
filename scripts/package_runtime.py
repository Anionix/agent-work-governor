#!/usr/bin/env python3
"""Write a deterministic manifest for a finalized Nix package runtime."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import rust_dispatch

# LLM-CONTRACT
# id: agent-work-governor.package-runtime-manifest
# state: FINALIZED_BINARY + SOURCE_TREE -> BOUND_MANIFEST | PACKAGE_REJECTED
# preconditions: the Nix fixup phase supplies one supported target and finalized binary
# invariant: manifest digests bind the packaged binary and every dispatcher source input
# failure: refuse overwrite or invalid evidence and return a non-zero process status
# source: bundle:flake.nix
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: main
# test: bundle:tests/test_contracts.py


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin-root", type=Path, required=True)
    parser.add_argument("--relative-binary", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--component-version", required=True)
    parser.add_argument("--rustc-version", required=True)
    args = parser.parse_args(argv)

    manifest_path = args.plugin_root / rust_dispatch.MANIFEST
    if manifest_path.exists():
        print(f"runtime manifest already exists: {manifest_path}", file=sys.stderr)
        return 1
    try:
        document = rust_dispatch.build_manifest(
            args.plugin_root,
            args.relative_binary,
            target=args.target,
            component_version=args.component_version,
            rustc_version=args.rustc_version,
        )
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, rust_dispatch.RustRuntimeError) as error:
        print(f"runtime package rejected: {error}", file=sys.stderr)
        return 1
    print(manifest_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
