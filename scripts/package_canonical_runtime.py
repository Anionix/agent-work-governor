#!/usr/bin/env python3
"""Build the deterministic pure-Python YAML runtime used by locked validators."""

from __future__ import annotations

import argparse
import hashlib
import io
import re
import sys
import tarfile
import zipfile
from pathlib import Path

# LLM-CONTRACT
# id: agent-work-governor.canonical-runtime-package
# state: PINNED_PYYAML_SOURCE -> CANONICAL_ZIP_BYTES -> HASH_BOUND_RUNTIME | REJECTED
# preconditions: Nix supplies the uv.lock-derived version and source SHA-256
# invariant: selected source bytes, names, metadata, ordering, and output bytes are deterministic
# failure: reject source/archive drift or unsafe members before writing output
# source: bundle:uv.lock
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: build_archive
# test: bundle:tests/test_contracts.py

MODULE_NAMES = """
__init__.py composer.py constructor.py dumper.py emitter.py error.py events.py
loader.py nodes.py parser.py reader.py representer.py resolver.py scanner.py
serializer.py tokens.py
"""
MODULES = MODULE_NAMES.split()
ARCHIVE_MEMBERS = tuple(
    sorted(["PyYAML-LICENSE", *(f"yaml/{name}" for name in MODULES)])
)
FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}$")
MAX_SOURCE_BYTES = 2_000_000


def build_archive(
    payload: bytes,
    source_sha256: str,
    source_size: int,
    version: str,
) -> bytes:
    if not SHA256_RE.fullmatch(source_sha256):
        raise ValueError("invalid PyYAML source digest")
    if not VERSION_RE.fullmatch(version):
        raise ValueError("invalid PyYAML version")
    if isinstance(source_size, bool) or not 0 < source_size <= MAX_SOURCE_BYTES:
        raise ValueError("invalid PyYAML source size")
    if len(payload) != source_size:
        raise ValueError("PyYAML source size mismatch")
    if hashlib.sha256(payload).hexdigest() != source_sha256:
        raise ValueError("PyYAML source digest mismatch")
    source_root = f"pyyaml-{version}"
    source_names = {
        output_name: (
            f"{source_root}/LICENSE"
            if output_name == "PyYAML-LICENSE"
            else f"{source_root}/lib/{output_name}"
        )
        for output_name in ARCHIVE_MEMBERS
    }
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as source:
        entries: dict[str, bytes] = {}
        required = {name: output for output, name in source_names.items()}
        selected: dict[str, tarfile.TarInfo] = {}
        for member in source.getmembers():
            if member.name not in required:
                continue
            if member.name in selected:
                raise ValueError(f"duplicate source member: {member.name}")
            selected[member.name] = member
        if selected.keys() != required.keys():
            raise ValueError("required PyYAML source members are missing")
        for source_name, output_name in required.items():
            member = selected[source_name]
            if not member.isfile() or member.size > 512_000:
                raise ValueError(f"unsafe source member: {source_name}")
            handle = source.extractfile(member)
            if handle is None:
                raise ValueError(f"unreadable source member: {source_name}")
            entries[output_name] = handle.read()
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_STORED) as archive:
        for name in ARCHIVE_MEMBERS:
            info = zipfile.ZipInfo(name, FIXED_TIMESTAMP)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, entries[name])
    return output.getvalue()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--source-size", type=int, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        payload = build_archive(
            args.source.read_bytes(),
            args.source_sha256,
            args.source_size,
            args.version,
        )
        observed = hashlib.sha256(payload).hexdigest()
        if observed != args.expected_sha256:
            raise ValueError(
                f"canonical runtime digest mismatch: expected "
                f"{args.expected_sha256}, observed {observed}"
            )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(payload)
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"canonical runtime packaging failed: {error}", file=sys.stderr)
        return 1
    print(observed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
