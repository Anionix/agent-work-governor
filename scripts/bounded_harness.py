#!/usr/bin/env python3
"""Run one canonical plan without interpreting policy or assigning a verdict."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import pwd
import re
import signal
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, cast

# LLM-CONTRACT
# id: agent-work-governor.bounded-harness
# state: VALID_EXECUTION_PLAN + DISTINCT_UID -> WRITE_ISOLATED_RUN -> AGGREGATE_RUN_RECEIPT | HARNESS_FAULT
# preconditions: a root harness binds one plan, repository, invocation, and dedicated identity
# invariant: only plan argv executes; candidate checks cannot write receipt/evidence or PASS
# failure: malformed, partial, unbounded, interrupted, or unsafe runs emit a typed sibling fault
# source: https://github.com/python/cpython/blob/c63aec69bd59c55314c06c23f4c22c03de76fe45/Doc/library/asyncio-subprocess.rst
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: execute
# test: bundle:tests/test_bounded_harness.py

MAX_OUTPUT = MAX_PLAN = 1_048_576
TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
NIX_WRAPPER_TARGET = re.compile(
    r"^NIX_(?:CC|BINTOOLS)_WRAPPER_TARGET_(?:BUILD|HOST)_[A-Za-z0-9_]+$"
)
REPORT_FIELDS = {
    "bindings",
    "execution_plan",
    "execution_plan_sha256",
    "findings",
    "mutation_count",
    "status",
}
CHECK_FIELDS = {
    "argv",
    "dependencies",
    "identifier",
    "input_artifacts",
    "kind",
    "language",
    "output_artifacts",
    "path",
    "timeout_seconds",
    "tool",
}


class HarnessError(RuntimeError):
    def __init__(self, code: str, failed: str | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.failed = [failed] if failed else []
        self.completed: list[str] = []
        self.running: list[str] = []
        self.not_started: list[str] = []


class CheckPhase(StrEnum):
    NOT_STARTED = "not_started"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class RunIdentity:
    """Unprivileged operating-system identity for candidate checks."""

    uid: int
    gid: int


@dataclass(frozen=True)
class RuntimePaths:
    """Harness-owned paths that candidate checks cannot replace."""

    receipt: Path
    evidence: Path
    artifacts: Path


SAFE_ENVIRONMENT = frozenset(
    {
        "AR",
        "AR_FOR_BUILD",
        "AS",
        "AS_FOR_BUILD",
        "CC",
        "CC_FOR_BUILD",
        "CONFIG_SHELL",
        "CPATH",
        "CXX",
        "CXX_FOR_BUILD",
        "DETERMINISTIC_BUILD",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LD",
        "LD_DYLD_PATH",
        "LD_FOR_BUILD",
        "LIBRARY_PATH",
        "MACOSX_DEPLOYMENT_TARGET",
        "NIX_BINTOOLS",
        "NIX_BINTOOLS_FOR_BUILD",
        "NIX_BUILD_CORES",
        "NIX_CC",
        "NIX_CC_FOR_BUILD",
        "NIX_CFLAGS_COMPILE",
        "NIX_CFLAGS_COMPILE_FOR_BUILD",
        "NIX_DONT_SET_RPATH",
        "NIX_DONT_SET_RPATH_FOR_BUILD",
        "NIX_ENFORCE_NO_NATIVE",
        "NIX_HARDENING_ENABLE",
        "NIX_IGNORE_LD_THROUGH_GCC",
        "NIX_LDFLAGS",
        "NIX_LDFLAGS_FOR_BUILD",
        "NIX_NO_SELF_RPATH",
        "NIX_SSL_CERT_FILE",
        "NM",
        "NM_FOR_BUILD",
        "NO_COLOR",
        "OBJCOPY",
        "OBJCOPY_FOR_BUILD",
        "OBJDUMP",
        "OBJDUMP_FOR_BUILD",
        "PATH",
        "PYTHONHASHSEED",
        "PYTHONNOUSERSITE",
        "PYTHONPATH",
        "RANLIB",
        "RANLIB_FOR_BUILD",
        "SDKROOT",
        "SIZE",
        "SIZE_FOR_BUILD",
        "SOURCE_DATE_EPOCH",
        "SSL_CERT_FILE",
        "STRINGS",
        "STRINGS_FOR_BUILD",
        "STRIP",
        "STRIP_FOR_BUILD",
        "TERM",
        "TERMINFO_DIRS",
        "XDG_CONFIG_DIRS",
        "XDG_DATA_DIRS",
        "ZERO_AR_DATE",
    }
)


def _json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require(condition: bool, code: str = "HARNESS_PLAN_INVALID") -> None:
    if not condition:
        raise HarnessError(code)


def _object(value: object, fields: set[str]) -> dict[str, Any]:
    _require(isinstance(value, dict) and set(value) == fields)
    return cast(dict[str, Any], value)


def _token(value: object) -> str:
    _require(isinstance(value, str) and TOKEN.fullmatch(value) is not None)
    return cast(str, value)


def load_plan(
    path: Path, expected: str
) -> tuple[dict[str, Any], list[dict[str, Any]], str, str]:
    _require(
        DIGEST.fullmatch(expected) is not None, "HARNESS_EXPECTED_PLAN_DIGEST_INVALID"
    )
    try:
        _require(path.stat().st_size <= MAX_PLAN, "HARNESS_PLAN_SIZE_EXCEEDED")
        report = _object(json.loads(path.read_bytes()), REPORT_FIELDS)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise HarnessError("HARNESS_PLAN_UNREADABLE") from error
    bindings = _object(
        report["bindings"],
        {
            "environment_sha256",
            "policy_sha256",
            "repository_sha256",
            "revision_sha256",
            "toolchain_sha256",
        },
    )
    _require(
        all(
            isinstance(value, str) and DIGEST.fullmatch(value)
            for value in bindings.values()
        )
    )
    plan = _object(report["execution_plan"], {"checks", "schema_version"})
    _require(
        report["status"] == "PLANNED"
        and report["findings"] == []
        and report["mutation_count"] == 0
        and plan["schema_version"] == "0.1"
        and isinstance(plan["checks"], list)
        and 0 < len(plan["checks"]) <= 128
    )
    digest = _sha(_json(plan))
    _require(
        report["execution_plan_sha256"] == digest == expected,
        "HARNESS_PLAN_DIGEST_MISMATCH",
    )
    checks = [_check(value) for value in plan["checks"]]
    identifiers = [check["identifier"] for check in checks]
    _require(len(set(identifiers)) == len(identifiers))
    known, done = set(identifiers), set()
    while len(done) < len(checks):
        ready = [
            check["identifier"]
            for check in checks
            if check["identifier"] not in done and set(check["dependencies"]) <= done
        ]
        _require(
            bool(ready)
            and all(dep in known for check in checks for dep in check["dependencies"])
        )
        done.update(ready)
    return dict(bindings), checks, digest, _sha(_json(identifiers))


def _check(value: object) -> dict[str, Any]:
    check = _object(value, CHECK_FIELDS)
    identifier = _token(check["identifier"])
    dependencies = check["dependencies"]
    groups = check["input_artifacts"], check["output_artifacts"]
    _require(
        isinstance(check["argv"], list)
        and bool(check["argv"])
        and isinstance(dependencies, list)
        and all(isinstance(item, str) for item in dependencies)
        and len(set(dependencies)) == len(dependencies)
        and all(isinstance(group, list) for group in groups)
        and isinstance(check["path"], str)
        and isinstance(check["timeout_seconds"], int)
        and 0 < check["timeout_seconds"] <= 3600
        and isinstance(check["kind"], str)
        and isinstance(check["language"], str)
    )
    _object(check["tool"], {"identity", "version"})
    declared = {_token(item) for group in groups for item in group}
    for atom in check["argv"]:
        if isinstance(atom, str) and atom:
            continue
        _require(_token(_object(atom, {"artifact"})["artifact"]) in declared)
    check["identifier"] = identifier
    return check


def _inside(root: Path, relative: str) -> Path:
    try:
        path = (root / relative).resolve(strict=True)
        path.relative_to(root)
    except (OSError, ValueError) as error:
        raise HarnessError("HARNESS_PATH_UNSAFE") from error
    _require(path.is_dir(), "HARNESS_PATH_UNSAFE")
    return path


def _atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def _kill(process: asyncio.subprocess.Process) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        if process.returncode is None:
            try:
                process.kill()
            except OSError as error:
                raise HarnessError("HARNESS_CONTAINMENT_FAILED") from error
    except OSError as error:
        raise HarnessError("HARNESS_CONTAINMENT_FAILED") from error


def _isolation_identity() -> RunIdentity:
    # LLM contract: root harness + distinct non-root identity -> isolated check
    # or typed refusal; candidate code never shares receipt-writer authority.
    # Primary source: https://github.com/python/cpython/blob/c63aec69bd59c55314c06c23f4c22c03de76fe45/Doc/library/subprocess.rst
    try:
        account = pwd.getpwnam("nobody")
    except KeyError as error:
        raise HarnessError("HARNESS_IDENTITY_UNSAFE") from error
    uid = account.pw_uid % (1 << 32)
    gid = account.pw_gid % (1 << 32)
    invoking = os.environ.get("SUDO_UID", "")
    _require(not invoking or invoking.isdecimal(), "HARNESS_IDENTITY_UNSAFE")
    invoking_uid = int(invoking) if invoking else -1
    _require(
        os.geteuid() == 0
        and uid not in (0, (1 << 32) - 1)
        and gid not in (0, (1 << 32) - 1)
        and uid != invoking_uid,
        "HARNESS_PRIVILEGE_ISOLATION_REQUIRED",
    )
    return RunIdentity(uid, gid)


def _candidate_environment(
    artifacts: Path, cargo_home: Path | None = None
) -> dict[str, str]:
    # LLM contract: trusted Nix shell + wrapper target marker -> preserved
    # compiler semantics; malformed or non-unit ambient markers are discarded.
    # Primary sources:
    # https://github.com/NixOS/nixpkgs/blob/624af665418d3c65d544145b4d34ad696439570e/pkgs/build-support/setup-hooks/role.bash#L52-L61
    # https://github.com/NixOS/nixpkgs/blob/624af665418d3c65d544145b4d34ad696439570e/pkgs/build-support/cc-wrapper/default.nix#L141-L148
    # https://github.com/NixOS/nixpkgs/blob/624af665418d3c65d544145b4d34ad696439570e/pkgs/build-support/bintools-wrapper/default.nix#L107-L110
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in SAFE_ENVIRONMENT
        or (NIX_WRAPPER_TARGET.fullmatch(key) is not None and value == "1")
    }
    environment.update(
        {
            "CARGO_HOME": str(cargo_home or artifacts),
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TARGET_DIR": str(artifacts / "cargo-target"),
            "HOME": str(artifacts),
            "PIP_CACHE_DIR": str(artifacts / "pip-cache"),
            "RUFF_CACHE_DIR": str(artifacts / "ruff-cache"),
            "TMPDIR": str(artifacts),
            "UV_CACHE_DIR": str(artifacts / "uv-cache"),
            "XDG_CACHE_HOME": str(artifacts),
        }
    )
    if cargo_home is not None:
        # LLM contract: one pinned advisory repository -> one protected Git
        # trust exception; candidate/global Git configuration remains absent.
        # Primary source: https://git-scm.com/docs/git-config/2.55.0#Documentation/git-config.txt-safedirectory
        environment.update(
            {
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "safe.directory",
                "GIT_CONFIG_VALUE_0": str(
                    (cargo_home / "advisory-db").resolve(strict=True)
                ),
            }
        )
    return environment


async def _spawn(
    argv: list[str],
    cwd: Path,
    artifacts: Path,
    cargo_home: Path | None,
    identity: RunIdentity | None,
) -> asyncio.subprocess.Process:
    if identity is None:
        return await asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )
    return await asyncio.create_subprocess_exec(
        *argv,
        cwd=cwd,
        env=_candidate_environment(artifacts, cargo_home),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        start_new_session=True,
        extra_groups=(),
        group=identity.gid,
        user=identity.uid,
    )


async def _execute_check(
    check: dict[str, Any],
    repository: Path,
    evidence_root: Path,
    artifacts: Path,
    events: dict[str, asyncio.Event],
    semaphore: asyncio.Semaphore,
    state: dict[str, CheckPhase],
    cargo_home: Path | None,
    identity: RunIdentity | None,
) -> dict[str, object]:
    identifier = check["identifier"]
    await asyncio.gather(*(events[item].wait() for item in check["dependencies"]))
    async with semaphore:
        state[identifier] = CheckPhase.RUNNING
        try:
            argv = [
                atom
                if isinstance(atom, str)
                else _artifact(
                    atom["artifact"], set(check["input_artifacts"]), artifacts
                )
                for atom in check["argv"]
            ]
            process = await _spawn(
                argv,
                _inside(repository, check["path"]),
                artifacts,
                cargo_home,
                identity,
            )
        except HarnessError as error:
            state[identifier] = CheckPhase.FAILED
            error.failed = [identifier]
            raise
        except (OSError, ValueError) as error:
            state[identifier] = CheckPhase.FAILED
            raise HarnessError("HARNESS_SPAWN_FAILED", identifier) from error
        output = bytearray()

        async def drain() -> None:
            assert process.stdout is not None
            while chunk := await process.stdout.read(65_536):
                _require(
                    len(output) + len(chunk) <= MAX_OUTPUT,
                    "HARNESS_OUTPUT_LIMIT_EXCEEDED",
                )
                output.extend(chunk)

        timed_out = False
        try:

            async def complete() -> None:
                await drain()
                await process.wait()

            await asyncio.wait_for(complete(), check["timeout_seconds"])
            _kill(process)
            await process.wait()
        except TimeoutError:
            timed_out = True
            _kill(process)
            await process.wait()
        except (HarnessError, asyncio.CancelledError) as error:
            _kill(process)
            await process.wait()
            if isinstance(error, HarnessError):
                state[identifier] = CheckPhase.FAILED
                error.failed = [identifier]
            raise
        evidence = bytes(output)
        relative = f".governance/receipts/evidence/{identifier}.log"
        try:
            _atomic(evidence_root / f"{identifier}.log", evidence)
        except OSError as error:
            state[identifier] = CheckPhase.FAILED
            raise HarnessError("HARNESS_EVIDENCE_WRITE_FAILED", identifier) from error
        state[identifier] = CheckPhase.COMPLETED
        events[identifier].set()
        return {
            "evidence_path": relative,
            "identifier": identifier,
            "outcome": "TIMED_OUT"
            if timed_out
            else {"EXITED": {"exit_code": process.returncode}},
            "output_bytes": len(evidence),
            "output_sha256": _sha(evidence),
        }


def _artifact(name: str, inputs: set[str], root: Path) -> str:
    path = root / name
    if name in inputs:
        _require(path.is_file() and not path.is_symlink(), "HARNESS_ARTIFACT_MISSING")
    else:
        _require(not path.exists() and not path.is_symlink(), "HARNESS_ARTIFACT_STALE")
    return str(path)


def _runtime_dir(root: Path, name: str) -> Path:
    path = root / name
    path.mkdir(parents=True, exist_ok=True)
    path = path.resolve(strict=True)
    _require(path.is_dir() and path.is_relative_to(root), "HARNESS_RECEIPT_PATH_UNSAFE")
    return path


def _candidate_can_write(paths: list[Path], identity: RunIdentity) -> bool:
    # LLM contract: stat-safe subject + candidate identity -> no effective write
    # access, including ACL grants, or typed refusal before candidate execution.
    # Primary source: https://pubs.opengroup.org/onlinepubs/9799919799/functions/access.html
    process = os.fork()
    if process == 0:
        result = 2
        try:
            os.setgroups([])
            os.setgid(identity.gid)
            os.setuid(identity.uid)
            result = int(
                any(not path.exists() or os.access(path, os.W_OK) for path in paths)
            )
        finally:
            os._exit(result)
    _, status = os.waitpid(process, 0)
    _require(
        os.WIFEXITED(status) and os.WEXITSTATUS(status) in (0, 1),
        "HARNESS_SUBJECT_ACCESS_UNVERIFIED",
    )
    return os.WEXITSTATUS(status) == 1


def _validate_subject(repository: Path, identity: RunIdentity) -> None:
    paths: list[Path] = []
    for current, directories, files in os.walk(repository, followlinks=False):
        for name in [".", *directories, *files]:
            path = Path(current) if name == "." else Path(current) / name
            metadata = path.lstat()
            writable = (
                (
                    metadata.st_uid == identity.uid
                    and metadata.st_mode & stat.S_IWUSR != 0
                )
                or (
                    metadata.st_gid == identity.gid
                    and metadata.st_mode & stat.S_IWGRP != 0
                )
                or metadata.st_mode & stat.S_IWOTH != 0
            )
            _require(
                not writable
                and not stat.S_ISLNK(metadata.st_mode)
                and (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)),
                "HARNESS_SUBJECT_WRITABLE",
            )
            paths.append(path)
            _require(len(paths) <= 100_000, "HARNESS_SUBJECT_TOO_WIDE")
    _require(
        not _candidate_can_write(paths, identity),
        "HARNESS_SUBJECT_WRITABLE",
    )


def _trusted_nix_store_path(path: Path) -> bool:
    # LLM contract: resolved Nix-store path + root-owned immutable mode ->
    # trusted runtime input, or rejection before candidate execution.
    # Primary source: https://github.com/NixOS/nix/blob/2c6d06e9387cf58167cb5a7ab91cee7333d8d17c/src/nix/store-api.md
    try:
        path.relative_to(Path("/nix/store"))
        metadata = path.stat()
    except (OSError, ValueError):
        return False
    return (
        path.is_dir()
        and metadata.st_uid == 0
        and metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH) == 0
    )


def _prepare_rust_inputs(
    source: Path | None,
    repository: Path,
    checks: list[dict[str, Any]],
    runtime: RuntimePaths,
    identity: RunIdentity,
) -> Path | None:
    # LLM contract: immutable Nix inputs + matching candidate Cargo.lock ->
    # root-owned Cargo home; mismatch or candidate config closes before spawn.
    # Primary source: https://github.com/rust-lang/cargo/blob/c980f4866141969fab6254a680546a277789d6f0/src/doc/src/reference/config.md
    rust_paths = {check["path"] for check in checks if check["language"] == "rust"}
    if not rust_paths:
        return None
    if source is None:
        raise HarnessError("HARNESS_RUST_INPUTS_REQUIRED")
    try:
        source = source.resolve(strict=True)
        _require(
            _trusted_nix_store_path(source),
            "HARNESS_RUST_INPUTS_UNTRUSTED",
        )
        raw_manifest = json.loads((source / "manifest.json").read_bytes())
        _require(
            isinstance(raw_manifest, dict)
            and set(raw_manifest)
            == {"cargo_lock_sha256", "rustsec_revision", "schema_version"},
            "HARNESS_RUST_INPUTS_UNTRUSTED",
        )
        manifest = cast(dict[str, Any], raw_manifest)
        _require(
            manifest["schema_version"] == "0.1"
            and isinstance(manifest["rustsec_revision"], str)
            and re.fullmatch(r"[0-9a-f]{40}", manifest["rustsec_revision"]) is not None
            and isinstance(manifest["cargo_lock_sha256"], str)
            and DIGEST.fullmatch(manifest["cargo_lock_sha256"]) is not None
            and (source / "config.toml").is_file()
            and (source / "advisory-db/.git").is_dir(),
            "HARNESS_RUST_INPUTS_UNTRUSTED",
        )
        _require(len(rust_paths) == 1, "HARNESS_RUST_LAYOUT_UNSUPPORTED")
        rust_root = _inside(repository, next(iter(rust_paths)))
        for ancestor in (repository, rust_root):
            for name in ("config", "config.toml"):
                _require(
                    not (ancestor / ".cargo" / name).exists()
                    and not (ancestor / ".cargo" / name).is_symlink(),
                    "HARNESS_CARGO_CONFIG_UNTRUSTED",
                )
        cargo_lock = rust_root / "Cargo.lock"
        _require(
            cargo_lock.is_file()
            and cargo_lock.stat().st_size <= MAX_PLAN
            and _sha(cargo_lock.read_bytes()) == manifest["cargo_lock_sha256"],
            "HARNESS_CARGO_LOCK_DIVERGED",
        )
        cargo_home = runtime.receipt.parent / "cargo-home"
        cargo_home.mkdir(mode=0o755)
        cargo_home.chmod(0o755)
        (cargo_home / "config.toml").symlink_to(source / "config.toml")
        (cargo_home / "advisory-db").symlink_to(source / "advisory-db")
        advisory_root = cargo_home / "advisory-dbs"
        advisory_root.mkdir(mode=0o755)
        advisory_root.chmod(0o755)
        (advisory_root / "advisory-db-3157b0e258782691").symlink_to(
            source / "advisory-db"
        )
        for lock in (cargo_home / ".package-cache", advisory_root / "db.lock"):
            lock.touch(mode=0o600)
            os.chown(lock, identity.uid, identity.gid)
        return cargo_home
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise HarnessError("HARNESS_RUST_INPUTS_UNTRUSTED") from error


def _prepare_runtime(
    repository: Path,
    receipt: Path,
    runtime_root: Path,
    identity: RunIdentity | None,
) -> tuple[Path, RuntimePaths]:
    try:
        repository = repository.resolve(strict=True)
        if identity is None:
            receipts = repository / ".governance" / "receipts"
            receipts.mkdir(parents=True, exist_ok=True)
            receipts = receipts.resolve(strict=True)
            receipt.resolve().relative_to(receipts)
            _require(receipts.is_relative_to(repository), "HARNESS_RECEIPT_PATH_UNSAFE")
            evidence = _runtime_dir(receipts, "evidence")
            artifacts = _runtime_dir(receipts, "artifacts")
        else:
            _validate_subject(repository, identity)
            _require(
                runtime_root.is_absolute()
                and receipt.is_absolute()
                and receipt.parent == runtime_root,
                "HARNESS_RUNTIME_ROOT_UNSAFE",
            )
            parent = runtime_root.parent.resolve(strict=True)
            metadata = parent.stat()
            _require(
                metadata.st_uid == 0
                and stat.S_ISDIR(metadata.st_mode)
                and metadata.st_mode & stat.S_ISVTX != 0,
                "HARNESS_RUNTIME_ROOT_UNSAFE",
            )
            runtime_root = parent / runtime_root.name
            runtime_root.mkdir(mode=0o711)
            metadata = runtime_root.lstat()
            _require(
                metadata.st_uid == 0
                and stat.S_ISDIR(metadata.st_mode)
                and stat.S_IMODE(metadata.st_mode) == 0o711,
                "HARNESS_RUNTIME_ROOT_UNSAFE",
            )
            receipt = runtime_root / receipt.name
            evidence = _runtime_dir(runtime_root, "evidence")
            evidence.chmod(0o700)
            artifacts = _runtime_dir(runtime_root, "artifacts")
            os.chown(artifacts, identity.uid, identity.gid)
            artifacts.chmod(0o700)
        receipt.unlink(missing_ok=True)
        receipt.with_name(f"{receipt.name}.fault.json").unlink(missing_ok=True)
    except (OSError, ValueError) as error:
        raise HarnessError("HARNESS_RUNTIME_PREPARATION_FAILED") from error
    return repository, RuntimePaths(receipt, evidence, artifacts)


async def execute(
    bindings: dict[str, Any],
    checks: list[dict[str, Any]],
    plan_sha256: str,
    coverage_sha256: str,
    repository: Path,
    receipt: Path,
    invocation_sha256: str,
    workers: int,
    runtime: RuntimePaths,
    identity: RunIdentity | None,
    cargo_home: Path | None = None,
) -> None:
    _require(
        DIGEST.fullmatch(invocation_sha256) is not None and 0 < workers <= 8,
        "HARNESS_INVOCATION_INVALID",
    )
    receipt = runtime.receipt
    evidence_root = runtime.evidence
    artifacts = runtime.artifacts
    order = [check["identifier"] for check in checks]
    state = dict.fromkeys(order, CheckPhase.NOT_STARTED)
    events = {identifier: asyncio.Event() for identifier in order}
    semaphore = asyncio.Semaphore(workers)
    tasks = [
        asyncio.create_task(
            _execute_check(
                check,
                repository,
                evidence_root,
                artifacts,
                events,
                semaphore,
                state,
                cargo_home,
                identity,
            )
        )
        for check in checks
    ]
    try:
        results = await asyncio.gather(*tasks)
    except (HarnessError, asyncio.CancelledError, KeyboardInterrupt) as error:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        fault = (
            error
            if isinstance(error, HarnessError)
            else HarnessError("HARNESS_INTERRUPTED")
        )
        fault.completed = [
            item for item in order if state[item] == CheckPhase.COMPLETED
        ]
        fault.running = [item for item in order if state[item] == CheckPhase.RUNNING]
        fault.not_started = [
            item for item in order if state[item] == CheckPhase.NOT_STARTED
        ]
        fault.failed = [item for item in order if state[item] == CheckPhase.FAILED]
        raise fault
    document = {
        "bindings": bindings,
        "checks": results,
        "coverage_sha256": coverage_sha256,
        "execution_plan_sha256": plan_sha256,
        "harness_sha256": _sha(Path(__file__).read_bytes()),
        "invocation_sha256": invocation_sha256,
        "schema_version": "0.1",
    }
    try:
        _atomic(receipt, _json(document))
    except OSError as error:
        fault = HarnessError("HARNESS_RECEIPT_WRITE_FAILED")
        fault.completed = order
        raise fault from error


def _fault(receipt: Path, error: HarnessError) -> None:
    try:
        _atomic(
            receipt.with_name(f"{receipt.name}.fault.json"),
            _json(
                {
                    "code": error.code,
                    "completed": error.completed,
                    "failed": error.failed,
                    "not_started": error.not_started,
                    "running": error.running,
                    "schema_version": "0.1",
                    "state": "HARNESS_FAULT",
                }
            ),
        )
    except OSError:
        return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan-report", type=Path, required=True)
    parser.add_argument("--expected-plan-sha256", required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--invocation-sha256", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--trusted-rust-inputs", type=Path)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args(argv)
    runtime: RuntimePaths | None = None
    try:
        identity = _isolation_identity()
        repository, runtime = _prepare_runtime(
            args.repository, args.receipt, args.runtime_root, identity
        )
        bindings, checks, plan_sha256, coverage_sha256 = load_plan(
            args.plan_report, args.expected_plan_sha256
        )
        cargo_home = _prepare_rust_inputs(
            args.trusted_rust_inputs, repository, checks, runtime, identity
        )
        asyncio.run(
            execute(
                bindings,
                checks,
                plan_sha256,
                coverage_sha256,
                repository,
                runtime.receipt,
                args.invocation_sha256,
                args.workers,
                runtime,
                identity,
                cargo_home,
            )
        )
    except KeyboardInterrupt:
        error = HarnessError("HARNESS_INTERRUPTED")
        if runtime is not None:
            _fault(runtime.receipt, error)
        return 130
    except HarnessError as error:
        if runtime is not None:
            _fault(runtime.receipt, error)
        if error.code == "HARNESS_INTERRUPTED":
            return 130
        return 2 if "PLAN" in error.code else 1
    print(
        _json(
            {"receipt": str(runtime.receipt), "state": "AGGREGATE_RUN_RECEIPT"}
        ).decode()
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
