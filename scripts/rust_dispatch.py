#!/usr/bin/env python3
"""Select and invoke the bundled, integrity-checked Rust Governor binary."""

from __future__ import annotations

import hashlib
import json
import platform
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# LLM-CONTRACT
# id: agent-work-governor.rust-dispatch
# state: HOST + BUNDLE -> VERIFIED_ARTIFACT -> TYPED_REPORT | CLOSED_FAILURE
# preconditions: plugin_root names the installed or source Governor bundle
# invariant: no binary runs before target, path, size, source, lock, and SHA-256 checks pass
# failure: unsupported hosts are INCONCLUSIVE and bundle-integrity faults are FAIL
# source: bundle:knowledge/policies/work-governor.md
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: resolve_binary
# test: bundle:tests/test_contracts.py

MANIFEST = Path("bin/manifest.json")
SOURCE_INPUTS = (
    Path("flake.lock"),
    Path("flake.nix"),
    Path("pyproject.toml"),
    Path("toolchain.lock.json"),
    Path("uv.lock"),
    Path("rust/Cargo.lock"),
    Path("rust/Cargo.toml"),
    Path("rust/clippy.toml"),
    Path("rust/deny.toml"),
    Path("rust/rust-toolchain.toml"),
    Path("rust/rustfmt.toml"),
    Path("rust/tests/fixtures/owner-scope-differential.json"),
    Path("rust/tests/fixtures/python_owner_scope_adapter.py"),
    Path("scripts/canonical_runtime_runner.py"),
    Path("scripts/bounded_harness.py"),
    Path("scripts/doctor.py"),
    Path("scripts/package_canonical_runtime.py"),
    Path("scripts/validate_canonical.py"),
    Path("references/canonical-runtime.lock.json"),
    Path("references/canonical-validators.lock.json"),
    Path("vendor/pyyaml-6.0.3.zip"),
)
SUPPORTED_TARGETS = frozenset(
    {
        "aarch64-apple-darwin",
        "aarch64-unknown-linux-gnu",
        "x86_64-unknown-linux-gnu",
    }
)


class RustRuntimeError(RuntimeError):
    """Base error at the bundled Rust runtime boundary."""


class UnsupportedHostError(RustRuntimeError):
    """The bundle does not declare a binary for this host."""


class IntegrityError(RustRuntimeError):
    """The selected bundle artifact does not match its manifest."""


class InvocationError(RustRuntimeError):
    """The verified binary could not complete a bounded invocation."""


@dataclass(frozen=True)
class BinarySelection:
    """A verified binary and its build provenance."""

    plugin_root: Path
    target: str
    path: Path
    sha256: str
    size: int
    component_version: str
    rustc_version: str


@dataclass(frozen=True)
class RustInvocation:
    """One bounded Rust CLI result."""

    selection: BinarySelection
    exit_code: int
    report: dict[str, Any] | None
    stdout: str
    stderr: str


def host_target(
    system: str | None = None,
    machine: str | None = None,
) -> str:
    """Map a supported kernel and machine pair to one Rust target triple."""

    host_system = (system or platform.system()).lower()
    host_machine = (machine or platform.machine()).lower()
    targets = {
        ("darwin", "arm64"): "aarch64-apple-darwin",
        ("darwin", "aarch64"): "aarch64-apple-darwin",
        ("linux", "aarch64"): "aarch64-unknown-linux-gnu",
        ("linux", "arm64"): "aarch64-unknown-linux-gnu",
        ("linux", "x86_64"): "x86_64-unknown-linux-gnu",
        ("linux", "amd64"): "x86_64-unknown-linux-gnu",
    }
    try:
        return targets[(host_system, host_machine)]
    except KeyError as error:
        raise UnsupportedHostError(
            f"unsupported host: {host_system}/{host_machine}"
        ) from error


def sha256_file(path: Path) -> str:
    """Hash a file without loading the artifact into memory."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_digest(plugin_root: Path) -> str:
    """Bind a release artifact to its deterministic Rust and Nix inputs."""

    root = plugin_root.resolve(strict=True)
    inputs = list(SOURCE_INPUTS)
    for relative_root in (Path("rust/src"), Path("rust/tests")):
        source_root = root / relative_root
        if not source_root.is_dir():
            raise IntegrityError(f"Rust source directory missing: {source_root}")
        inputs.extend(
            path.relative_to(root)
            for path in sorted(source_root.rglob("*.rs"))
            if path.is_file()
        )
    digest = hashlib.sha256()
    for relative in sorted(inputs):
        path = _regular_file(root, relative)
        encoded = relative.as_posix().encode("utf-8")
        payload = path.read_bytes()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _regular_file(root: Path, relative: Path) -> Path:
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise IntegrityError(f"unsafe bundle-relative path: {relative}")
    candidate = root
    for part in relative.parts:
        candidate = candidate / part
        try:
            metadata = candidate.lstat()
        except OSError as error:
            raise IntegrityError(
                f"bundle file inaccessible: {candidate}: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            raise IntegrityError(f"bundle symlink rejected: {candidate}")
    # Every non-empty relative path executes the loop; Pyrefly 1.1.1 cannot
    # derive that fact from the guard above.
    # Primary source: https://github.com/facebook/pyrefly/blob/b87de05834c401898c79fd9686b806c051dd3667/website/docs/error-suppressions.mdx
    # pyrefly: ignore[unbound-name]
    if not stat.S_ISREG(metadata.st_mode):
        raise IntegrityError(f"bundle path is not a regular file: {candidate}")
    return candidate


def _required_string(document: dict[str, Any], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise IntegrityError(f"manifest field {key!r} must be a non-empty string")
    return value


def build_manifest(
    plugin_root: Path,
    relative_binary: Path,
    *,
    target: str,
    component_version: str,
    rustc_version: str,
) -> dict[str, Any]:
    """Describe one finalized package binary and its exact source inputs."""

    root = plugin_root.resolve(strict=True)
    if target not in SUPPORTED_TARGETS:
        raise UnsupportedHostError(f"unsupported manifest target: {target}")
    if not component_version or not rustc_version:
        raise IntegrityError("manifest versions must be non-empty")
    binary = _regular_file(root, relative_binary)
    metadata = binary.stat()
    if metadata.st_size <= 0 or metadata.st_mode & 0o111 == 0:
        raise IntegrityError("packaged binary must be non-empty and executable")
    return {
        "schema_version": "0.1",
        "plugin_base_version": component_version,
        "integrity_scope": "nix-package-runtime-bundle",
        "publisher_signature": None,
        "artifacts": [
            {
                "target": target,
                "relative_path": relative_binary.as_posix(),
                "sha256": sha256_file(binary),
                "size": metadata.st_size,
                "rustc_version": rustc_version,
                "source_sha256": source_digest(root),
                "cargo_lock_sha256": sha256_file(
                    _regular_file(root, Path("rust/Cargo.lock"))
                ),
                "flake_lock_sha256": sha256_file(
                    _regular_file(root, Path("flake.lock"))
                ),
            }
        ],
    }


def resolve_binary(
    plugin_root: Path,
    *,
    target: str | None = None,
) -> BinarySelection:
    """Select and fully verify the declared binary for one host target."""

    root = plugin_root.resolve(strict=True)
    manifest_path = _regular_file(root, MANIFEST)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise IntegrityError(f"runtime manifest is invalid: {error}") from error
    if not isinstance(manifest, dict) or manifest.get("schema_version") != "0.1":
        raise IntegrityError("runtime manifest root or schema_version is invalid")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise IntegrityError("runtime manifest artifacts must be a list")

    selected_target = target or host_target()
    matching = [
        item
        for item in artifacts
        if isinstance(item, dict) and item.get("target") == selected_target
    ]
    if len(matching) != 1:
        raise UnsupportedHostError(
            f"exactly one artifact required for {selected_target}; found {len(matching)}"
        )
    artifact = matching[0]
    relative_path = Path(_required_string(artifact, "relative_path"))
    expected_sha256 = _required_string(artifact, "sha256")
    expected_source = _required_string(artifact, "source_sha256")
    expected_cargo_lock = _required_string(artifact, "cargo_lock_sha256")
    expected_flake_lock = _required_string(artifact, "flake_lock_sha256")
    if any(
        len(value) != 64
        or value.lower() != value
        or any(c not in "0123456789abcdef" for c in value)
        for value in (
            expected_sha256,
            expected_source,
            expected_cargo_lock,
            expected_flake_lock,
        )
    ):
        raise IntegrityError("runtime manifest contains a malformed SHA-256 digest")
    expected_size = artifact.get("size")
    if (
        not isinstance(expected_size, int)
        or isinstance(expected_size, bool)
        or expected_size <= 0
    ):
        raise IntegrityError("runtime manifest size must be a positive integer")

    binary = _regular_file(root, relative_path)
    metadata = binary.stat()
    if metadata.st_size != expected_size:
        raise IntegrityError(
            f"binary size mismatch: expected {expected_size}, observed {metadata.st_size}"
        )
    if metadata.st_mode & 0o111 == 0:
        raise IntegrityError(f"binary is not executable: {binary}")
    observed_sha256 = sha256_file(binary)
    if observed_sha256 != expected_sha256:
        raise IntegrityError(
            f"binary digest mismatch: expected {expected_sha256}, observed {observed_sha256}"
        )
    observed_inputs = {
        "source_sha256": source_digest(root),
        "cargo_lock_sha256": sha256_file(_regular_file(root, Path("rust/Cargo.lock"))),
        "flake_lock_sha256": sha256_file(_regular_file(root, Path("flake.lock"))),
    }
    expected_inputs = {
        "source_sha256": expected_source,
        "cargo_lock_sha256": expected_cargo_lock,
        "flake_lock_sha256": expected_flake_lock,
    }
    for key, observed in observed_inputs.items():
        if observed != expected_inputs[key]:
            raise IntegrityError(
                f"{key} mismatch: expected {expected_inputs[key]}, observed {observed}"
            )
    return BinarySelection(
        plugin_root=root,
        target=selected_target,
        path=binary,
        sha256=observed_sha256,
        size=metadata.st_size,
        component_version=_required_string(manifest, "plugin_base_version"),
        rustc_version=_required_string(artifact, "rustc_version"),
    )


def invoke(
    selection: BinarySelection,
    arguments: list[str],
    *,
    timeout_seconds: int = 30,
) -> RustInvocation:
    """Invoke a verified selection without a shell and decode its JSON report."""

    if not arguments:
        raise InvocationError("a Rust subcommand is required")
    current = resolve_binary(selection.plugin_root, target=selection.target)
    if current != selection:
        raise IntegrityError("runtime selection changed after verification")
    try:
        process = subprocess.run(
            [str(current.path), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise InvocationError(str(error)) from error
    try:
        decoded = json.loads(process.stdout)
        report = decoded if isinstance(decoded, dict) else None
    except json.JSONDecodeError:
        report = None
    return RustInvocation(
        selection=current,
        exit_code=process.returncode,
        report=report,
        stdout=process.stdout,
        stderr=process.stderr,
    )


def run_rust(
    arguments: list[str],
    *,
    plugin_root: Path,
    timeout_seconds: int = 30,
) -> RustInvocation:
    """Resolve, verify, and invoke the current host binary."""

    return invoke(
        resolve_binary(plugin_root),
        arguments,
        timeout_seconds=timeout_seconds,
    )


def invocation_status(invocation: RustInvocation) -> str:
    """Classify trusted Rust reports without promoting infrastructure faults."""

    if invocation.report is None or invocation.exit_code not in (0, 1):
        return "INCONCLUSIVE"
    return "PASS" if invocation.exit_code == 0 else "FAIL"


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    plugin_root = Path(__file__).resolve().parent.parent
    try:
        invocation = run_rust(arguments, plugin_root=plugin_root)
    except UnsupportedHostError as error:
        print(json.dumps({"status": "INCONCLUSIVE", "error": str(error)}))
        return 70
    except IntegrityError as error:
        print(json.dumps({"status": "FAIL", "error": str(error)}))
        return 70
    except InvocationError as error:
        print(json.dumps({"status": "INCONCLUSIVE", "error": str(error)}))
        return 70
    if invocation.report is None:
        print(
            json.dumps(
                {
                    "status": "INCONCLUSIVE",
                    "error": "verified Rust binary returned invalid JSON",
                }
            ),
            file=sys.stderr,
        )
        return 70
    sys.stdout.write(invocation.stdout)
    sys.stderr.write(invocation.stderr)
    return invocation.exit_code


if __name__ == "__main__":
    sys.exit(main())
