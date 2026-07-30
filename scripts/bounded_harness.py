#!/usr/bin/env python3
"""Run one canonical plan without interpreting policy or assigning a verdict."""

from __future__ import annotations

import argparse
import asyncio
import errno
import hashlib
import ipaddress
import json
import os
import platform
import pwd
import re
import shutil
import signal
import socket
import stat
import struct
import sys
from contextlib import ExitStack
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Literal, cast

# LLM-CONTRACT
# id: agent-work-governor.bounded-harness
# state: VALID_EXECUTION_PLAN + DISTINCT_UID -> OS_NETWORK_SANDBOX_VERIFIED -> WRITE_ISOLATED_RUN -> AGGREGATE_RUN_RECEIPT | HARNESS_FAULT
# preconditions: a root harness binds one plan, repository, invocation, and dedicated identity
# invariant: only plan argv executes; candidates have no IP sockets and cannot write receipt/evidence or PASS
# failure: malformed, partial, unbounded, interrupted, unsafe, or unverified isolation emits a typed sibling fault
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
NETWORK_FAULTS = frozenset(
    {
        "HARNESS_NETWORK_SANDBOX_UNAVAILABLE",
        "HARNESS_NETWORK_SANDBOX_SETUP_FAILED",
        "HARNESS_NETWORK_SANDBOX_BYPASS_DETECTED",
        "HARNESS_NETWORK_SANDBOX_POLICY_UNSUPPORTED",
    }
)
NETWORK_BYPASS_EXIT = 81
NETWORK_SETUP_EXIT = 82
FAULT_SCHEMA_VERSION = "0.2"
SANDBOX_READY = b"\x01"
# LLM contract: OS_SANDBOX_ENTERED -> STDOUT_READY_BYTE -> CANDIDATE_EXEC;
# the fixed prefix crosses each launcher on its existing output channel, while
# missing readiness proves setup failure before candidate outcome evaluation.
# Primary sources: https://docs.python.org/3.14/library/os.html#os.execvpe and
# https://docs.python.org/3.14/library/asyncio-subprocess.html#asyncio.subprocess.Process.stdout
CANDIDATE_EXEC = (
    "import os,sys;os.write(1,b'\\x01');os.execvpe(sys.argv[1],sys.argv[1:],os.environ)"
)


class HarnessError(RuntimeError):
    def __init__(
        self,
        code: str,
        failed: str | None = None,
        *,
        stage: NetworkStage | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.failed = [failed] if failed else []
        self.stage = stage
        self.completed: list[str] = []
        self.running: list[str] = []
        self.not_started: list[str] = []


class CheckPhase(StrEnum):
    NOT_STARTED = "not_started"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class NetworkSandbox(StrEnum):
    LINUX = "linux"
    MACOS = "macos"


# LLM contract: PRECHECK_TRANSITION -> FIXED_STAGE_TOKEN | NO_DIAGNOSTIC;
# candidate output can never select or alter a fault stage.
class NetworkStage(StrEnum):
    SANDBOX_SELECT = "network-sandbox-select"
    HOST_CANARIES = "network-host-canaries"
    CANDIDATE_START = "network-candidate-start"
    CANDIDATE_CREATE = "network-candidate-create"
    CANDIDATE_READY_EOF = "network-candidate-ready-eof"
    CANDIDATE_READY_OUTPUT = "network-candidate-ready-output"
    CANDIDATE_READY_TIMEOUT = "network-candidate-ready-timeout"
    CANDIDATE_RESULT = "network-candidate-result"
    TRUSTED_START = "network-trusted-start"
    TRUSTED_CREATE = "network-trusted-create"
    TRUSTED_READY_EOF = "network-trusted-ready-eof"
    TRUSTED_READY_OUTPUT = "network-trusted-ready-output"
    TRUSTED_READY_TIMEOUT = "network-trusted-ready-timeout"
    TRUSTED_RESULT = "network-trusted-result"


def _startup_stage(
    stage: NetworkStage | None,
    reason: Literal["create", "ready-eof", "ready-output", "ready-timeout"],
) -> NetworkStage | None:
    # LLM contract: fixed start phase + trusted observation -> fixed stage;
    # launcher output is never copied into evidence or allowed to select a token.
    # Primary source: https://docs.python.org/3.14/library/asyncio-subprocess.html
    if stage not in {NetworkStage.CANDIDATE_START, NetworkStage.TRUSTED_START}:
        return stage
    return NetworkStage(f"{stage.value.removesuffix('-start')}-{reason}")


@dataclass(frozen=True)
class RunIdentity:
    """Unprivileged operating-system identity for candidate checks."""

    uid: int
    gid: int


@dataclass(frozen=True)
class RuntimePaths:
    """Protected evidence paths plus one candidate-owned temporary workspace."""

    receipt: Path
    evidence: Path
    artifacts: Path
    temporary: Path


def _sandbox_host_identity(identity: RunIdentity) -> RunIdentity:
    # LLM contract: Linux root launcher + user namespace -> sandbox nobody is
    # mapped to host root; macOS keeps the real nobody identity.
    # Primary source: https://github.com/containers/bubblewrap/blob/1b80120ef26a28e065e67f89bfef873f13bdd317/bubblewrap.c#L970-L1003
    return RunIdentity(0, 0) if sys.platform == "linux" else identity


def _cargo_lock_paths(cargo_home: Path) -> tuple[Path, Path]:
    return (
        cargo_home / ".package-cache",
        cargo_home / "advisory-dbs/db.lock",
    )


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
    artifacts: Path, temporary: Path, cargo_home: Path | None = None
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
            "TMPDIR": str(temporary),
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


def _trusted_executable(raw: str | None) -> Path:
    try:
        path = Path(raw or "").resolve(strict=True)
        metadata = path.stat()
    except OSError as error:
        raise HarnessError("HARNESS_NETWORK_SANDBOX_UNAVAILABLE") from error
    _require(
        path.is_file()
        and metadata.st_uid == 0
        and metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH) == 0,
        "HARNESS_NETWORK_SANDBOX_UNAVAILABLE",
    )
    return path


def _network_sandbox(identity: RunIdentity | None) -> NetworkSandbox | None:
    if identity is None:
        return None
    if sys.platform == "linux":
        executable = _trusted_executable(shutil.which("bwrap"))
        try:
            executable.relative_to(Path("/nix/store"))
        except ValueError as error:
            raise HarnessError("HARNESS_NETWORK_SANDBOX_UNAVAILABLE") from error
        return NetworkSandbox.LINUX
    if sys.platform == "darwin":
        _trusted_executable("/usr/bin/sandbox-exec")
        return NetworkSandbox.MACOS
    raise HarnessError("HARNESS_NETWORK_SANDBOX_POLICY_UNSUPPORTED")


def _macos_profile(
    runtime: RuntimePaths,
    cargo_home: Path | None,
    cwd: Path,
    *,
    allow_loopback: bool = False,
) -> str:
    # LLM contract: TRUSTED_PREFLIGHT -> EXPLICIT_LOOPBACK_CAPABILITY;
    # CANDIDATE -> NO_NETWORK_RULES. Host-shared loopback is never exposed to
    # candidate bytes because an ambient localhost broker could relay egress.
    # Primary sources: Apple-shipped sandbox-exec(1),
    # /System/Library/Sandbox/Profiles/dyld-support.sb (process bootstrap),
    # /usr/share/sandbox/com.apple.CommCenter.sb (remote localhost filter), and
    # /usr/share/sandbox/mds_stores.sb (file-read subpath filter).
    # https://github.com/apple-oss-distributions/dyld/blob/fd8d0c4d52320ebf64db34f3cb280310d905c5ae/dyld/DyldProcessConfig.cpp#L1107-L1125
    # https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/security/mac_socket.c#L147-L164
    readable = [
        Path("/nix/store"),
        Path("/System/Library"),
        Path("/usr/lib"),
        Path("/private/etc"),
        Path("/private/var/db/timezone"),
        cwd,
        runtime.artifacts,
        runtime.temporary,
    ]
    writable = [runtime.artifacts, runtime.temporary]
    if cargo_home is not None:
        readable.append(cargo_home)
        writable.append(cargo_home)
    _require(
        all(path.is_absolute() and path != Path("/") for path in readable),
        "HARNESS_NETWORK_SANDBOX_SETUP_FAILED",
    )
    reads = "\n".join(
        f"(allow file-read* (subpath {json.dumps(str(path))}))"
        for path in dict.fromkeys(readable)
    )
    writes = "\n".join(
        f"(allow file-write* (subpath {json.dumps(str(path))}))" for path in writable
    )
    loopback = ""
    if allow_loopback:
        loopback = """
(allow network-bind (local ip "localhost:*"))
(allow network-inbound (local ip "localhost:*"))
(allow network-outbound (remote ip "localhost:*"))
"""
    # deny-default also blocks AF_UNIX, AppleEvents, LaunchServices, and
    # unlisted Mach brokers that could proxy candidate network requests.
    return f"""
(version 1)
(deny default)
(import "dyld-support.sb")
(allow process-exec process-fork)
(allow process-info* (target same-sandbox))
(allow signal (target same-sandbox))
(allow mach-priv-task-port (target same-sandbox))
{reads}
(allow file-read* (literal "/dev/null") (literal "/dev/random") (literal "/dev/urandom"))
{writes}
(allow file-write-data file-ioctl (literal "/dev/null"))
(allow sysctl-read user-preference-read ipc-posix-shm ipc-posix-sem)
{loopback}
"""


def _linux_seccomp_program(
    machine: str | None = None, *, allow_loopback: bool = False
) -> bytes:
    # LLM contract: PINNED_LINUX_ABI -> ARCH_BOUND_SOCKET_ALLOWLIST;
    # unexpected ABI, x32, io_uring socket creation, or nonlocal socket domain
    # transitions to policy denial before candidate-controlled network access.
    # Primary sources:
    # https://github.com/torvalds/linux/blob/fc02acf6ac0ccde0c805c2daa9148683cdd01ba8/include/uapi/linux/seccomp.h
    # https://github.com/torvalds/linux/blob/fc02acf6ac0ccde0c805c2daa9148683cdd01ba8/include/uapi/linux/io_uring.h
    # https://github.com/torvalds/linux/blob/fc02acf6ac0ccde0c805c2daa9148683cdd01ba8/arch/x86/entry/syscalls/syscall_64.tbl
    # https://github.com/torvalds/linux/blob/fc02acf6ac0ccde0c805c2daa9148683cdd01ba8/include/uapi/asm-generic/unistd.h
    specifications = {
        "x86_64": (0xC000003E, 41, 53, 0x40000000),
        "aarch64": (0xC00000B7, 198, 199, 0),
        "arm64": (0xC00000B7, 198, 199, 0),
    }
    specification = specifications.get((machine or platform.machine()).lower())
    _require(
        specification is not None and sys.byteorder == "little",
        "HARNESS_NETWORK_SANDBOX_POLICY_UNSUPPORTED",
    )
    assert specification is not None
    arch, socket_call, socketpair_call, x32_bit = specification
    deny = 0x00050000 | errno.EPERM
    instructions = [
        (0x20, 0, 0, 4),  # seccomp_data.arch
        (0x15, 1, 0, arch),
        (0x06, 0, 0, 0x80000000),  # SECCOMP_RET_KILL_PROCESS
        (0x20, 0, 0, 0),  # seccomp_data.nr
    ]
    if x32_bit:
        instructions += [(0x45, 0, 1, x32_bit), (0x06, 0, 0, deny)]
    domains = [int(socket.AF_UNIX)]
    if allow_loopback:
        domains += [int(socket.AF_INET), int(socket.AF_INET6)]
    instructions += [
        (0x15, 0, 1, 425),  # io_uring_setup
        (0x06, 0, 0, deny),
        (0x15, 2, 0, socket_call),
        (0x15, 1, 0, socketpair_call),
        (0x06, 0, 0, 0x7FFF0000),  # SECCOMP_RET_ALLOW
        (0x20, 0, 0, 16),  # seccomp_data.args[0]
        *[
            (0x15, len(domains) - index, 0, domain)
            for index, domain in enumerate(domains)
        ],
        (0x06, 0, 0, deny),
        (0x06, 0, 0, 0x7FFF0000),
    ]
    return b"".join(struct.pack("=HBBI", *instruction) for instruction in instructions)


def _linux_seccomp_fd(*, allow_loopback: bool = False) -> int:
    # LLM contract: VERIFIED_FILTER_BYTES -> INHERITED_BWRAP_FD | SETUP_FAILED.
    program = _linux_seccomp_program(allow_loopback=allow_loopback)
    try:
        read_fd, write_fd = os.pipe()
    except OSError as error:
        raise HarnessError("HARNESS_NETWORK_SANDBOX_SETUP_FAILED") from error
    try:
        _require(
            os.write(write_fd, program) == len(program),
            "HARNESS_NETWORK_SANDBOX_SETUP_FAILED",
        )
    except (HarnessError, OSError) as error:
        os.close(read_fd)
        raise HarnessError("HARNESS_NETWORK_SANDBOX_SETUP_FAILED") from error
    finally:
        os.close(write_fd)
    return read_fd


def _sandboxed_argv(
    sandbox: NetworkSandbox,
    identity: RunIdentity,
    argv: list[str],
    cwd: Path,
    runtime: RuntimePaths,
    cargo_home: Path | None,
    *,
    allow_loopback: bool = False,
    seccomp_fd: int | None = None,
) -> list[str]:
    # LLM contract: verified OS sandbox + fixed identity -> one inherited
    # network boundary; unsupported policy refuses before candidate execution.
    # Primary sources:
    # https://github.com/torvalds/linux/blob/fc02acf6ac0ccde0c805c2daa9148683cdd01ba8/include/uapi/linux/sched.h
    # https://github.com/containers/bubblewrap/blob/1b80120ef26a28e065e67f89bfef873f13bdd317/bubblewrap.c#L2447-L2464
    # https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/security/mac_socket.c#L147-L164
    if sandbox == NetworkSandbox.MACOS:
        _require(seccomp_fd is None, "HARNESS_NETWORK_SANDBOX_SETUP_FAILED")
        return [
            "/usr/bin/sandbox-exec",
            "-p",
            _macos_profile(
                runtime,
                cargo_home,
                cwd,
                allow_loopback=allow_loopback,
            ),
            *argv,
        ]
    _require(
        isinstance(seccomp_fd, int) and seccomp_fd >= 3,
        "HARNESS_NETWORK_SANDBOX_SETUP_FAILED",
    )
    command = [
        str(_trusted_executable(shutil.which("bwrap"))),
        "--add-seccomp-fd",
        str(seccomp_fd),
        "--unshare-net",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent",
        "--disable-userns",
        "--cap-drop",
        "ALL",
        "--uid",
        str(identity.uid),
        "--gid",
        str(identity.gid),
        "--ro-bind",
        "/nix/store",
        "/nix/store",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--dir",
        str(runtime.receipt.parent),
        "--bind",
        str(runtime.artifacts),
        str(runtime.artifacts),
        "--dir",
        str(runtime.temporary.parent),
        "--bind",
        str(runtime.temporary),
        str(runtime.temporary),
    ]
    if cargo_home is not None:
        command += ["--ro-bind", str(cargo_home), str(cargo_home)]
        for lock in _cargo_lock_paths(cargo_home):
            command += ["--bind", str(lock), str(lock)]
    if not cwd.is_relative_to(Path("/nix/store")) and not cwd.is_relative_to(
        runtime.artifacts
    ):
        command += ["--ro-bind", str(cwd), str(cwd)]
    return [*command, "--chdir", str(cwd), *argv]


def _loopback_fixture(family: socket.AddressFamily, host: str) -> bool:
    try:
        with (
            socket.socket(family, socket.SOCK_STREAM) as server,
            socket.socket(family, socket.SOCK_STREAM) as client,
        ):
            server.settimeout(1)
            client.settimeout(1)
            server.bind((host, 0))
            server.listen(1)
            return client.connect_ex(server.getsockname()) == 0
    except OSError:
        return False


def _native_ipv6_listener(stack: ExitStack) -> tuple[str, int, int] | None:
    # LLM contract: HOST_NATIVE_IPV6_ROUTE -> REACHABLE_HOST_BOUND_CANARY |
    # CAPABILITY_ABSENT. Absence never proves sandbox policy; the independent
    # candidate-profile probe remains mandatory before candidate execution.
    # Primary source:
    # https://github.com/python/cpython/blob/c63aec69bd59c55314c06c23f4c22c03de76fe45/Doc/library/socket.rst
    route = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        route.connect(("2001:db8::1", 9))
    except OSError as error:
        route.close()
        if error.errno in {
            errno.EACCES,
            errno.EADDRNOTAVAIL,
            errno.EAFNOSUPPORT,
            errno.EHOSTUNREACH,
            errno.ENETUNREACH,
            errno.ENODEV,
            errno.EPERM,
            errno.EPROTONOSUPPORT,
        }:
            return None
        raise HarnessError("HARNESS_NETWORK_SANDBOX_SETUP_FAILED") from error
    stack.enter_context(route)
    selected = route.getsockname()
    address = ipaddress.ip_address(selected[0])
    if not (
        isinstance(address, ipaddress.IPv6Address)
        and not address.is_loopback
        and not address.is_unspecified
        and address.ipv4_mapped is None
    ):
        return None
    listener = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_STREAM))
    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    listener.bind((str(address), 0, 0, selected[3]))
    listener.listen(8)
    bound = listener.getsockname()
    return str(bound[0]), int(bound[1]), int(bound[3])


def _socket_domain_filter_enforced() -> bool:
    # LLM contract: AF_VSOCK_PROBE -> POLICY_EPERM | UNPROVEN_BOUNDARY.
    # Primary source: https://www.kernel.org/doc/html/v7.1/admin-guide/sysctl/net.html#vsock-sockets
    family = getattr(socket, "AF_VSOCK", None)
    if not isinstance(family, int):
        return False
    try:
        probe = socket.socket(family, socket.SOCK_STREAM)
    except OSError as error:
        return error.errno == errno.EPERM
    probe.close()
    return False


def _candidate_ip_policy_once() -> int:
    # LLM contract: CANDIDATE_PROFILE + IP_FAMILY -> EPERM | UNPROVEN_POLICY.
    # Route errors are host evidence, not sandbox evidence; only EPERM proves
    # that the OS policy intercepted both IPv4 and IPv6 socket use.
    # Primary sources:
    # https://github.com/torvalds/linux/blob/fc02acf6ac0ccde0c805c2daa9148683cdd01ba8/include/uapi/linux/seccomp.h
    # https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/security/mac_socket.c#L147-L179
    # https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/security/mac_socket.c#L230-L247
    targets: tuple[tuple[socket.AddressFamily, Any], ...] = (
        (socket.AF_INET, ("127.0.0.1", 9)),
        (socket.AF_INET6, ("::1", 9)),
    )
    for family, target in targets:
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            try:
                client = socket.socket(family, kind)
            except OSError as error:
                if error.errno == errno.EPERM:
                    continue
                return NETWORK_SETUP_EXIT
            try:
                with client:
                    if kind == socket.SOCK_DGRAM:
                        client.sendto(b"x", target)
                        return NETWORK_BYPASS_EXIT
                    result = client.connect_ex(target)
            except OSError as error:
                if error.errno == errno.EPERM:
                    continue
                return NETWORK_SETUP_EXIT
            if result == errno.EPERM:
                continue
            if result in {0, errno.ECONNREFUSED}:
                return NETWORK_BYPASS_EXIT
            return NETWORK_SETUP_EXIT
    return 0


def _candidate_ip_policy_probe() -> int:
    direct = _candidate_ip_policy_once()
    if direct != 0:
        return direct
    child = os.fork()
    if child == 0:
        os._exit(_candidate_ip_policy_once())
    _, status = os.waitpid(child, 0)
    if not os.WIFEXITED(status):
        return NETWORK_SETUP_EXIT
    return os.WEXITSTATUS(status)


def _egress_blocked(
    host: str,
    tcp_port: int,
    native_ipv6: tuple[str, int, int] | None,
    udp_port: int,
    unix_path: str,
) -> bool:
    if sys.platform == "linux" and not _socket_domain_filter_enforced():
        return False
    targets: list[tuple[socket.AddressFamily, Any]] = [
        (socket.AF_INET, (host, tcp_port)),
        (socket.AF_INET6, (f"::ffff:{host}", tcp_port)),
    ]
    if native_ipv6 is not None:
        ipv6_host, ipv6_port, ipv6_scope = native_ipv6
        targets.append((socket.AF_INET6, (ipv6_host, ipv6_port, 0, ipv6_scope)))
    for family, target in targets:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as client:
                client.settimeout(1)
                if client.connect_ex(target) == 0:
                    return False
        except OSError:
            pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
            datagram.sendto(b"dns", (host, udp_port))
    except OSError:
        pass
    else:
        return False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as local:
            return local.connect_ex(unix_path) != 0
    except OSError:
        return True


def _descendant_egress_blocked(
    host: str,
    tcp_port: int,
    native_ipv6: tuple[str, int, int] | None,
    udp_port: int,
    unix_path: str,
) -> bool:
    child = os.fork()
    if child == 0:
        grandchild = os.fork()
        if grandchild == 0:
            os._exit(
                int(
                    not _egress_blocked(
                        host,
                        tcp_port,
                        native_ipv6,
                        udp_port,
                        unix_path,
                    )
                )
            )
        _, status = os.waitpid(grandchild, 0)
        os._exit(int(not (os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0)))
    _, status = os.waitpid(child, 0)
    return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0


def _network_probe(argv: list[str]) -> int:
    try:
        _require(len(argv) == 8 and all(atom for atom in argv))
        (
            host,
            tcp_port,
            ipv6_host,
            ipv6_port,
            ipv6_scope,
            udp_port,
            unix_path,
            write_canary,
        ) = (
            argv[0],
            int(argv[1]),
            argv[2],
            int(argv[3]),
            int(argv[4]),
            int(argv[5]),
            argv[6],
            Path(argv[7]),
        )
        native_ipv6 = None
        if ipv6_host == "-":
            _require(ipv6_port == 0 and ipv6_scope == 0)
        else:
            ipv6_address = ipaddress.ip_address(ipv6_host)
            _require(
                isinstance(ipv6_address, ipaddress.IPv6Address)
                and not ipv6_address.is_loopback
                and not ipv6_address.is_unspecified
                and ipv6_address.ipv4_mapped is None
                and 0 < ipv6_port <= 65_535
                and ipv6_scope >= 0
            )
            native_ipv6 = (ipv6_host, ipv6_port, ipv6_scope)
        _require(
            not ipaddress.ip_address(host).is_loopback
            and 0 < tcp_port <= 65_535
            and 0 < udp_port <= 65_535
            and write_canary.is_absolute()
        )
        write_canary.write_bytes(b"network-sandbox-write-ok")
        if not (
            _loopback_fixture(socket.AF_INET, "127.0.0.1")
            and _loopback_fixture(socket.AF_INET6, "::1")
        ):
            return NETWORK_SETUP_EXIT
        if not (
            _egress_blocked(host, tcp_port, native_ipv6, udp_port, unix_path)
            and _descendant_egress_blocked(
                host,
                tcp_port,
                native_ipv6,
                udp_port,
                unix_path,
            )
        ):
            return NETWORK_BYPASS_EXIT
        return 0
    except (HarnessError, OSError, ValueError):
        return NETWORK_SETUP_EXIT


async def _spawn(
    argv: list[str],
    cwd: Path,
    runtime: RuntimePaths,
    cargo_home: Path | None,
    identity: RunIdentity | None,
    sandbox: NetworkSandbox | None,
    *,
    allow_loopback: bool = False,
    startup_failure: NetworkStage | None = None,
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
    _require(sandbox is not None, "HARNESS_NETWORK_SANDBOX_SETUP_FAILED")
    assert sandbox is not None
    seccomp_fd = (
        _linux_seccomp_fd(allow_loopback=allow_loopback)
        if sandbox == NetworkSandbox.LINUX
        else None
    )
    process: asyncio.subprocess.Process | None = None
    try:
        wrapped = [
            sys.executable,
            "-I",
            "-B",
            "-c",
            CANDIDATE_EXEC,
            *argv,
        ]
        command = _sandboxed_argv(
            sandbox,
            identity,
            wrapped,
            cwd,
            runtime,
            cargo_home,
            allow_loopback=allow_loopback,
            seccomp_fd=seccomp_fd,
        )
        macos = sandbox == NetworkSandbox.MACOS
        inherited = () if seccomp_fd is None else (seccomp_fd,)
        # LLM contract: LAUNCHER_SETSID -> SANDBOX_INHERITS_DETACHED_SESSION;
        # a second Bubblewrap setsid would fail closed before READY because the
        # launcher is already the process-group leader.
        # Primary sources:
        # https://docs.python.org/3.14/library/subprocess.html#popen-constructor
        # https://github.com/containers/bubblewrap/blob/1b80120ef26a28e065e67f89bfef873f13bdd317/bubblewrap.c#L3563-L3565
        # https://pubs.opengroup.org/onlinepubs/9799919799/functions/setsid.html
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                cwd=cwd if macos else "/",
                env=_candidate_environment(
                    runtime.artifacts, runtime.temporary, cargo_home
                ),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,
                pass_fds=inherited,
                extra_groups=() if macos else None,
                group=identity.gid if macos else None,
                user=identity.uid if macos else None,
            )
        except OSError as error:
            raise HarnessError(
                "HARNESS_NETWORK_SANDBOX_SETUP_FAILED",
                stage=_startup_stage(startup_failure, "create"),
            ) from error
        assert process.stdout is not None
        try:
            ready = await asyncio.wait_for(process.stdout.read(1), 2)
        except TimeoutError as error:
            raise HarnessError(
                "HARNESS_NETWORK_SANDBOX_SETUP_FAILED",
                stage=_startup_stage(startup_failure, "ready-timeout"),
            ) from error
        if ready != SANDBOX_READY:
            raise HarnessError(
                "HARNESS_NETWORK_SANDBOX_SETUP_FAILED",
                stage=_startup_stage(
                    startup_failure,
                    "ready-eof" if ready == b"" else "ready-output",
                ),
            )
        return process
    except asyncio.CancelledError:
        if process is not None and process.returncode is None:
            _kill(process)
            await process.wait()
        raise
    except (HarnessError, OSError, TimeoutError) as error:
        if process is not None and process.returncode is None:
            _kill(process)
            await process.wait()
        if isinstance(error, HarnessError):
            if startup_failure is not None and error.stage is None:
                error.stage = startup_failure
            raise
        raise HarnessError(
            "HARNESS_NETWORK_SANDBOX_SETUP_FAILED",
            stage=startup_failure,
        ) from error
    finally:
        if seccomp_fd is not None:
            os.close(seccomp_fd)


async def _verify_network_sandbox(
    identity: RunIdentity | None,
    runtime: RuntimePaths,
) -> NetworkSandbox | None:
    # LLM contract: HOST_CAPABILITY_PROBED -> CANDIDATE_POLICY_PROVED ->
    # TRUSTED_LOOPBACK_PROVED | TYPED_NETWORK_FAULT. An unavailable native
    # IPv6 route only removes that host canary; it never authorizes candidates.
    stage = NetworkStage.SANDBOX_SELECT
    sandbox: NetworkSandbox | None = None
    process: asyncio.subprocess.Process | None = None
    unix_path = runtime.receipt.parent / ".network-canary.sock"
    unix_path.unlink(missing_ok=True)
    try:
        sandbox = _network_sandbox(identity)
        if sandbox is None:
            return None
        stage = NetworkStage.HOST_CANARIES
        with ExitStack() as stack:
            route = stack.enter_context(
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            )
            route.connect(("192.0.2.1", 9))
            host = route.getsockname()[0]
            _require(
                isinstance(ipaddress.ip_address(host), ipaddress.IPv4Address)
                and not ipaddress.ip_address(host).is_loopback,
                "HARNESS_NETWORK_SANDBOX_SETUP_FAILED",
            )
            listener = stack.enter_context(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            )
            datagram = stack.enter_context(
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            )
            listener.bind((host, 0))
            listener.listen(8)
            datagram.bind((host, 0))
            tcp_port = listener.getsockname()[1]
            udp_port = datagram.getsockname()[1]
            native_ipv6 = _native_ipv6_listener(stack)
            unix_listener = stack.enter_context(
                socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            )
            unix_listener.bind(str(unix_path))
            stack.callback(unix_path.unlink, missing_ok=True)
            unix_listener.listen(2)
            write_canary = runtime.artifacts / ".network-write-canary"
            write_canary.unlink(missing_ok=True)
            stack.callback(write_canary.unlink, missing_ok=True)
            reachable_targets: list[tuple[socket.AddressFamily, Any]] = [
                (socket.AF_INET, (host, tcp_port)),
                (socket.AF_INET6, (f"::ffff:{host}", tcp_port)),
                (socket.AF_UNIX, str(unix_path)),
            ]
            if native_ipv6 is not None:
                ipv6_host, ipv6_port, ipv6_scope = native_ipv6
                reachable_targets.append(
                    (socket.AF_INET6, (ipv6_host, ipv6_port, 0, ipv6_scope))
                )
            for family, target in reachable_targets:
                with socket.socket(family, socket.SOCK_STREAM) as client:
                    _require(
                        client.connect_ex(target) == 0,
                        "HARNESS_NETWORK_SANDBOX_POLICY_UNSUPPORTED",
                    )
            harness = Path(__file__).resolve(strict=True)
            stage = NetworkStage.CANDIDATE_START
            process = await _spawn(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(harness),
                    "--candidate-ip-policy-probe",
                ],
                harness.parent,
                runtime,
                None,
                identity,
                sandbox,
                startup_failure=stage,
            )
            stage = NetworkStage.CANDIDATE_RESULT
            output, _ = await asyncio.wait_for(process.communicate(), 5)
            _require(len(output) <= 4096, "HARNESS_NETWORK_SANDBOX_SETUP_FAILED")
            if process.returncode == NETWORK_BYPASS_EXIT:
                raise HarnessError("HARNESS_NETWORK_SANDBOX_BYPASS_DETECTED")
            if process.returncode != 0:
                raise HarnessError("HARNESS_NETWORK_SANDBOX_POLICY_UNSUPPORTED")
            native_arguments = (
                [native_ipv6[0], str(native_ipv6[1]), str(native_ipv6[2])]
                if native_ipv6 is not None
                else ["-", "0", "0"]
            )
            stage = NetworkStage.TRUSTED_START
            process = await _spawn(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(harness),
                    "--network-probe",
                    host,
                    str(tcp_port),
                    *native_arguments,
                    str(udp_port),
                    str(unix_path),
                    str(write_canary),
                ],
                harness.parent,
                runtime,
                None,
                identity,
                sandbox,
                allow_loopback=True,
                startup_failure=stage,
            )
            stage = NetworkStage.TRUSTED_RESULT
            output, _ = await asyncio.wait_for(process.communicate(), 5)
            _require(len(output) <= 4096, "HARNESS_NETWORK_SANDBOX_SETUP_FAILED")
            _require(
                write_canary.read_bytes() == b"network-sandbox-write-ok",
                "HARNESS_NETWORK_SANDBOX_SETUP_FAILED",
            )
    except HarnessError as error:
        if error.code in NETWORK_FAULTS and error.stage is None:
            error.stage = stage
        raise
    except (OSError, TimeoutError, ValueError) as error:
        if process is not None and process.returncode is None:
            _kill(process)
            await process.wait()
        raise HarnessError(
            "HARNESS_NETWORK_SANDBOX_SETUP_FAILED",
            stage=stage,
        ) from error
    if process.returncode == NETWORK_BYPASS_EXIT:
        raise HarnessError(
            "HARNESS_NETWORK_SANDBOX_BYPASS_DETECTED",
            stage=NetworkStage.TRUSTED_RESULT,
        )
    if process.returncode != 0:
        raise HarnessError(
            "HARNESS_NETWORK_SANDBOX_SETUP_FAILED",
            stage=NetworkStage.TRUSTED_RESULT,
        )
    return sandbox


async def _execute_check(
    check: dict[str, Any],
    repository: Path,
    runtime: RuntimePaths,
    events: dict[str, asyncio.Event],
    semaphore: asyncio.Semaphore,
    state: dict[str, CheckPhase],
    cargo_home: Path | None,
    identity: RunIdentity | None,
    sandbox: NetworkSandbox | None,
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
                    atom["artifact"],
                    set(check["input_artifacts"]),
                    runtime.artifacts,
                )
                for atom in check["argv"]
            ]
            process = await _spawn(
                argv,
                _inside(repository, check["path"]),
                runtime,
                cargo_home,
                identity,
                sandbox,
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
            _atomic(runtime.evidence / f"{identifier}.log", evidence)
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
        owner = _sandbox_host_identity(identity)
        for lock in _cargo_lock_paths(cargo_home):
            lock.touch(mode=0o600)
            os.chown(lock, owner.uid, owner.gid)
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
            temporary = artifacts
        else:
            _validate_subject(repository, identity)
            owner = _sandbox_host_identity(identity)
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
            os.chown(artifacts, owner.uid, owner.gid)
            artifacts.chmod(0o700)
            # LLM contract: protected 0711 runtime + root-owned readable anchor
            # -> candidate-only temporary workspace | typed preparation failure.
            # Primary source: https://pubs.opengroup.org/onlinepubs/9799919799/functions/open.html
            temporary_anchor = parent / f"{runtime_root.name}-candidate"
            temporary_anchor.mkdir(mode=0o755)
            metadata = temporary_anchor.lstat()
            _require(
                metadata.st_uid == 0
                and stat.S_ISDIR(metadata.st_mode)
                and stat.S_IMODE(metadata.st_mode) == 0o755,
                "HARNESS_RUNTIME_ROOT_UNSAFE",
            )
            temporary = _runtime_dir(temporary_anchor, "tmp")
            os.chown(temporary, owner.uid, owner.gid)
            temporary.chmod(0o700)
            metadata = temporary.lstat()
            _require(
                metadata.st_uid == owner.uid
                and stat.S_ISDIR(metadata.st_mode)
                and stat.S_IMODE(metadata.st_mode) == 0o700,
                "HARNESS_RUNTIME_ROOT_UNSAFE",
            )
        receipt.unlink(missing_ok=True)
        receipt.with_name(f"{receipt.name}.fault.json").unlink(missing_ok=True)
    except (OSError, ValueError) as error:
        raise HarnessError("HARNESS_RUNTIME_PREPARATION_FAILED") from error
    return repository, RuntimePaths(receipt, evidence, artifacts, temporary)


async def execute(
    bindings: dict[str, Any],
    checks: list[dict[str, Any]],
    plan_sha256: str,
    coverage_sha256: str,
    repository: Path,
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
    sandbox = await _verify_network_sandbox(identity, runtime)
    order = [check["identifier"] for check in checks]
    state = dict.fromkeys(order, CheckPhase.NOT_STARTED)
    events = {identifier: asyncio.Event() for identifier in order}
    semaphore = asyncio.Semaphore(workers)
    tasks = [
        asyncio.create_task(
            _execute_check(
                check,
                repository,
                runtime,
                events,
                semaphore,
                state,
                cargo_home,
                identity,
                sandbox,
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
                    "schema_version": FAULT_SCHEMA_VERSION,
                    "stage": error.stage.value if error.stage is not None else None,
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
        if error.code in NETWORK_FAULTS:
            return 70
        return 2 if "PLAN" in error.code else 1
    print(
        _json(
            {"receipt": str(runtime.receipt), "state": "AGGREGATE_RUN_RECEIPT"}
        ).decode()
    )
    return 0


if __name__ == "__main__":
    arguments = sys.argv[1:]
    if arguments and arguments[0] == "--network-probe":
        raise SystemExit(_network_probe(arguments[1:]))
    if arguments == ["--candidate-ip-policy-probe"]:
        raise SystemExit(_candidate_ip_policy_probe())
    raise SystemExit(main(arguments))
