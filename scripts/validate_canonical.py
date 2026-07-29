#!/usr/bin/env python3
"""Run digest-pinned canonical Codex Plugin and Skill validators."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass
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
MAX_RUNTIME_BYTES = 512_000
SOURCE_REPOSITORY = "https://github.com/openai/codex"
RAW_PREFIX = "https://raw.githubusercontent.com/openai/codex"
RUNTIME_RELATIVE_PATH = "vendor/pyyaml-6.0.3.zip"
RUNTIME_BUILDER_PATH = "scripts/package_canonical_runtime.py"
RUNTIME_RUNNER_PATH = "scripts/canonical_runtime_runner.py"
RUNTIME_DEPENDENCY = {
    "name": "pyyaml",
    "group": "runtime-build",
    "lock_path": "uv.lock",
}
RUNTIME_FIELDS = {
    "builder_path",
    "builder_sha256",
    "compatible_validator_sha256",
    "dependency_identity_sha256",
    "distribution",
    "license",
    "license_member",
    "relative_path",
    "runner_path",
    "runner_sha256",
    "sha256",
    "size",
}


class CanonicalValidationError(RuntimeError):
    """A fail-closed canonical-validator boundary error."""


class CanonicalRuntimeError(CanonicalValidationError):
    """A typed runtime admission failure."""

    def __init__(self, code: str, *, inconclusive: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.inconclusive = inconclusive


@dataclass(frozen=True)
class RuntimeSnapshot:
    """Verified immutable dependency bytes for one validator run."""

    payload: bytes
    runner: bytes
    sha256: str
    relative_path: str


@dataclass(frozen=True)
class RuntimeContract:
    """Validated runtime artifact identities."""

    sha256: str
    size: int
    builder_sha256: str
    runner_sha256: str


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
    try:
        document = json.loads(
            regular_file_bytes(
                lock_path,
                maximum=64_000,
                missing_code="CANONICAL_VALIDATOR_LOCK_MISSING",
                invalid_code="CANONICAL_VALIDATOR_LOCK_INVALID",
            )
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CanonicalValidationError(
            "canonical validator lock JSON is invalid"
        ) from error
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


def regular_file_bytes(
    path: Path,
    *,
    maximum: int,
    missing_code: str,
    invalid_code: str,
) -> bytes:
    # Primary source: https://pubs.opengroup.org/onlinepubs/9799919799/functions/open.html
    # O_NONBLOCK prevents a FIFO open from waiting for a writer before fstat rejects it.
    nonblocking = getattr(os, "O_NONBLOCK", None)
    if not isinstance(nonblocking, int):
        raise CanonicalRuntimeError(f"{invalid_code}: O_NONBLOCK unavailable")
    flags = os.O_RDONLY | nonblocking | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as error:
        raise CanonicalRuntimeError(missing_code, inconclusive=True) from error
    except OSError as error:
        raise CanonicalRuntimeError(f"{invalid_code}: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise CanonicalRuntimeError(invalid_code)
        payload = bytearray()
        while chunk := os.read(descriptor, min(65_536, maximum + 1 - len(payload))):
            payload.extend(chunk)
            if len(payload) > maximum:
                raise CanonicalRuntimeError(invalid_code)
        if len(payload) != metadata.st_size:
            raise CanonicalRuntimeError(invalid_code)
        return bytes(payload)
    finally:
        os.close(descriptor)


# LLM-CONTRACT
# id: agent-work-governor.pyyaml-dependency-identity
# state: UV_LOCK_BYTES -> VALIDATED_SOURCE_IDENTITY -> CANONICAL_DIGEST | CLOSED_FAILURE
# preconditions: uv.lock contains one project root and one PyYAML source package
# invariant: version, registry, sdist, and runtime-build requirement have one stable digest
# failure: reject malformed, duplicate, or contradictory lock state before runtime admission
# source: bundle:uv.lock
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: pyyaml_identity_sha256
# test: bundle:tests/test_contracts.py
def pyyaml_identity_sha256(plugin_root: Path) -> str:
    try:
        lock = tomllib.loads(
            regular_file_bytes(
                plugin_root / RUNTIME_DEPENDENCY["lock_path"],
                maximum=2_000_000,
                missing_code="VALIDATOR_RUNTIME_DEPENDENCY_LOCK_MISSING",
                invalid_code="VALIDATOR_RUNTIME_DEPENDENCY_LOCK_INVALID",
            ).decode()
        )
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise CanonicalRuntimeError(
            "VALIDATOR_RUNTIME_DEPENDENCY_LOCK_INVALID"
        ) from error
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise CanonicalRuntimeError("VALIDATOR_RUNTIME_DEPENDENCY_LOCK_INVALID")
    roots = [
        entry
        for entry in packages
        if isinstance(entry, dict)
        and entry.get("name") == "agent-work-governor"
        and entry.get("source") == {"virtual": "."}
    ]
    dependencies = [
        entry
        for entry in packages
        if isinstance(entry, dict) and entry.get("name") == RUNTIME_DEPENDENCY["name"]
    ]
    if len(roots) != 1 or len(dependencies) != 1:
        raise CanonicalRuntimeError("VALIDATOR_RUNTIME_DEPENDENCY_LOCK_INVALID")
    dependency = dependencies[0]
    version = dependency.get("version")
    sdist = dependency.get("sdist")
    if (
        not isinstance(version, str)
        or not isinstance(sdist, dict)
        or dependency.get("source") != {"registry": "https://pypi.org/simple"}
    ):
        raise CanonicalRuntimeError("VALIDATOR_RUNTIME_DEPENDENCY_LOCK_INVALID")
    expected_group = [{"name": RUNTIME_DEPENDENCY["name"]}]
    expected_requirement = [
        {"name": RUNTIME_DEPENDENCY["name"], "specifier": f"=={version}"}
    ]
    root = roots[0]
    groups = root.get("dev-dependencies")
    metadata = root.get("metadata")
    requirements = metadata.get("requires-dev") if isinstance(metadata, dict) else None
    if (
        not isinstance(groups, dict)
        or groups.get(RUNTIME_DEPENDENCY["group"]) != expected_group
        or not isinstance(requirements, dict)
        or requirements.get(RUNTIME_DEPENDENCY["group"]) != expected_requirement
    ):
        raise CanonicalRuntimeError("VALIDATOR_RUNTIME_DEPENDENCY_LOCK_INVALID")
    source_url = sdist.get("url")
    source_hash = sdist.get("hash")
    source_size = sdist.get("size")
    if (
        not isinstance(source_url, str)
        or not source_url.startswith("https://files.pythonhosted.org/packages/")
        or not source_url.endswith(f"/pyyaml-{version}.tar.gz")
        or not isinstance(source_hash, str)
        or not source_hash.startswith("sha256:")
        or SHA256_RE.fullmatch(source_hash.removeprefix("sha256:")) is None
        or not isinstance(source_size, int)
        or isinstance(source_size, bool)
        or not 0 < source_size <= 2_000_000
    ):
        raise CanonicalRuntimeError("VALIDATOR_RUNTIME_DEPENDENCY_LOCK_INVALID")
    identity = {
        "group": RUNTIME_DEPENDENCY["group"],
        "name": RUNTIME_DEPENDENCY["name"],
        "registry": "https://pypi.org/simple",
        "sdist": {
            "hash": source_hash,
            "size": source_size,
            "url": source_url,
        },
        "version": version,
    }
    return sha256_bytes(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    )


def load_runtime_contract(
    plugin_root: Path,
    validator_entries: dict[str, dict[str, str]],
) -> RuntimeContract:
    try:
        document = json.loads(
            regular_file_bytes(
                plugin_root / "references/canonical-runtime.lock.json",
                maximum=64_000,
                missing_code="VALIDATOR_RUNTIME_LOCK_MISSING",
                invalid_code="VALIDATOR_RUNTIME_LOCK_INVALID",
            )
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CanonicalRuntimeError("VALIDATOR_RUNTIME_LOCK_INVALID") from error
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "dependency", "runtime"}
        or document.get("schema_version") != "0.2"
        or document.get("dependency") != RUNTIME_DEPENDENCY
        or not isinstance(document.get("runtime"), dict)
    ):
        raise CanonicalRuntimeError("VALIDATOR_RUNTIME_LOCK_INVALID")
    runtime = document["runtime"]
    compatible = sorted(entry["sha256"] for entry in validator_entries.values())
    if (
        set(runtime) != RUNTIME_FIELDS
        or runtime.get("distribution") != "PyYAML"
        or runtime.get("license") != "MIT"
        or runtime.get("license_member") != "PyYAML-LICENSE"
        or runtime.get("relative_path") != RUNTIME_RELATIVE_PATH
        or runtime.get("builder_path") != RUNTIME_BUILDER_PATH
        or runtime.get("runner_path") != RUNTIME_RUNNER_PATH
        or runtime.get("compatible_validator_sha256") != compatible
    ):
        raise CanonicalRuntimeError("VALIDATOR_RUNTIME_LOCK_INVALID")
    for field in (
        "sha256",
        "builder_sha256",
        "runner_sha256",
        "dependency_identity_sha256",
    ):
        value = runtime.get(field)
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise CanonicalRuntimeError("VALIDATOR_RUNTIME_LOCK_INVALID")
    size = runtime.get("size")
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or not 0 < size <= MAX_RUNTIME_BYTES
    ):
        raise CanonicalRuntimeError("VALIDATOR_RUNTIME_LOCK_INVALID")
    dependency_identity = pyyaml_identity_sha256(plugin_root)
    if runtime["dependency_identity_sha256"] != dependency_identity:
        raise CanonicalRuntimeError("VALIDATOR_RUNTIME_DEPENDENCY_IDENTITY_MISMATCH")
    return RuntimeContract(
        sha256=runtime["sha256"],
        size=runtime["size"],
        builder_sha256=runtime["builder_sha256"],
        runner_sha256=runtime["runner_sha256"],
    )


# LLM-CONTRACT
# id: agent-work-governor.canonical-validator-runtime
# state: DEPENDENCY_LOCK + RUNTIME_LOCK -> VERIFIED_SNAPSHOTS -> ISOLATED_IMPORT | CLOSED_BLOCKER
# preconditions: the bundle contains uv-locked provenance plus builder, runner, and archive bytes
# invariant: non-regular, missing, symlinked, or digest-mismatched bytes never execute or block
# failure: raise a typed fail-closed CanonicalRuntimeError before validator execution
# source: bundle:references/canonical-runtime.lock.json
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: load_runtime
# test: bundle:tests/test_contracts.py
def load_runtime(
    plugin_root: Path,
    validator_entries: dict[str, dict[str, str]],
) -> RuntimeSnapshot:
    runtime = load_runtime_contract(plugin_root, validator_entries)

    builder = regular_file_bytes(
        plugin_root / RUNTIME_BUILDER_PATH,
        maximum=128_000,
        missing_code="VALIDATOR_RUNTIME_BUILDER_MISSING",
        invalid_code="VALIDATOR_RUNTIME_BUILDER_INVALID",
    )
    if sha256_bytes(builder) != runtime.builder_sha256:
        raise CanonicalRuntimeError("VALIDATOR_RUNTIME_BUILDER_DIGEST_MISMATCH")

    runner = regular_file_bytes(
        plugin_root / RUNTIME_RUNNER_PATH,
        maximum=128_000,
        missing_code="VALIDATOR_RUNTIME_RUNNER_MISSING",
        invalid_code="VALIDATOR_RUNTIME_RUNNER_INVALID",
    )
    if sha256_bytes(runner) != runtime.runner_sha256:
        raise CanonicalRuntimeError("VALIDATOR_RUNTIME_RUNNER_DIGEST_MISMATCH")

    payload = regular_file_bytes(
        plugin_root / RUNTIME_RELATIVE_PATH,
        maximum=MAX_RUNTIME_BYTES,
        missing_code="VALIDATOR_RUNTIME_MISSING",
        invalid_code="VALIDATOR_RUNTIME_INVALID",
    )
    observed = sha256_bytes(payload)
    if len(payload) != runtime.size or observed != runtime.sha256:
        raise CanonicalRuntimeError("VALIDATOR_RUNTIME_DIGEST_MISMATCH")
    return RuntimeSnapshot(payload, runner, observed, RUNTIME_RELATIVE_PATH)


def verified_installed_validator(entry: dict[str, str]) -> Path | None:
    candidate = Path.home() / entry["path"]
    try:
        payload = regular_file_bytes(
            candidate,
            maximum=MAX_VALIDATOR_BYTES,
            missing_code="CANONICAL_VALIDATOR_MISSING",
            invalid_code="CANONICAL_VALIDATOR_INVALID",
        )
    except CanonicalRuntimeError as error:
        if error.inconclusive:
            return None
        raise CanonicalValidationError(error.code) from error
    observed = sha256_bytes(payload)
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


def run_validator(
    validator: Path,
    expected_sha256: str,
    runtime: RuntimeSnapshot,
    target: Path,
) -> subprocess.CompletedProcess[str]:
    validator_payload = regular_file_bytes(
        validator,
        maximum=MAX_VALIDATOR_BYTES,
        missing_code="CANONICAL_VALIDATOR_MISSING",
        invalid_code="CANONICAL_VALIDATOR_INVALID",
    )
    if sha256_bytes(validator_payload) != expected_sha256:
        raise CanonicalValidationError("canonical validator snapshot digest mismatch")
    with tempfile.TemporaryDirectory(prefix="agent-work-governor-runtime-") as raw:
        private_root = Path(raw)
        private_root.chmod(0o700)
        runner_path = private_root / "runner.py"
        runtime_path = private_root / "runtime.zip"
        validator_path = private_root / "validator.py"
        runner_path.write_bytes(runtime.runner)
        runtime_path.write_bytes(runtime.payload)
        validator_path.write_bytes(validator_payload)
        runner_path.chmod(0o500)
        runtime_path.chmod(0o600)
        validator_path.chmod(0o600)
        process = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                str(runner_path),
                str(runtime_path),
                str(validator_path),
                str(target),
                runtime.sha256,
                expected_sha256,
            ],
            check=False,
            text=True,
            capture_output=True,
            timeout=30,
        )
    if process.returncode == 86:
        raise CanonicalRuntimeError(
            process.stderr.strip() or "VALIDATOR_RUNTIME_EXECUTION_MISMATCH"
        )
    return process


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(sys.argv[1:] if argv is None else argv)
    plugin_root = Path(arguments.plugin_root).resolve()
    try:
        entries = load_lock(plugin_root)
        runtime = load_runtime(plugin_root, entries)
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
            checks = [
                (
                    plugin_validator,
                    entries["plugin_validator"]["sha256"],
                    plugin_root,
                )
            ]
            skill_paths = sorted(
                path
                for path in (plugin_root / "skills").iterdir()
                if path.is_dir() and (path / "SKILL.md").is_file()
            )
            if not skill_paths:
                raise CanonicalValidationError("plugin contains no canonical Skill")
            checks.extend(
                (
                    skill_validator,
                    entries["skill_validator"]["sha256"],
                    skill_path,
                )
                for skill_path in skill_paths
            )
            for validator, digest, target in checks:
                process = run_validator(validator, digest, runtime, target)
                evidence = process.stdout.strip() or process.stderr.strip()
                if evidence:
                    print(evidence)
                if process.returncode != 0:
                    raise CanonicalValidationError(
                        f"canonical validator rejected {target}: "
                        f"exit {process.returncode}"
                    )
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
