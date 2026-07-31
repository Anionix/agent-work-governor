from __future__ import annotations

import asyncio
import errno
import hashlib
import io
import json
import os
import pwd
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Self
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import bounded_harness as harness

# LLM-CONTRACT
# id: agent-work-governor.bounded-harness-tests
# state: PLAN_FIXTURE + TEST_IDENTITY -> BOUNDED_EXECUTION -> RECEIPT_OR_TYPED_FAULT | TEST_FAILURE
# preconditions: fixtures use temporary roots; the root-only test drops to the system nobody user
# invariant: tests cover argv, bounds, timeout, path, UID/network isolation, and atomic replacement
# failure: unittest exposes the violated fail-closed transition
# source: https://github.com/python/cpython/blob/c63aec69bd59c55314c06c23f4c22c03de76fe45/Doc/library/unittest.rst
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: BoundedHarnessTests
# test: bundle:tests/test_bounded_harness.py

SHA = "a" * 64
NOBODY = pwd.getpwnam("nobody")


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def seccomp_verdict(program: bytes, arch: int, syscall: int, argument: int = 0) -> int:
    """Evaluate the small cBPF subset emitted by the harness."""
    data = bytearray(64)
    struct.pack_into("=IIQ", data, 0, syscall & 0xFFFFFFFF, arch, 0)
    struct.pack_into("=Q", data, 16, argument)
    instructions = [
        struct.unpack_from("=HBBI", program, offset)
        for offset in range(0, len(program), 8)
    ]
    accumulator = position = 0
    while True:
        code, jump_true, jump_false, constant = instructions[position]
        if code == 0x20:
            accumulator = struct.unpack_from("=I", data, constant)[0]
            position += 1
        elif code == 0x15:
            position += 1 + (jump_true if accumulator == constant else jump_false)
        elif code == 0x45:
            position += 1 + (jump_true if accumulator & constant else jump_false)
        elif code == 0x06:
            return constant
        else:
            raise AssertionError(f"unsupported test instruction: {code:#x}")


class BoundedHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.plan_path = self.root / "plan.json"
        self.receipt = self.root / ".governance/receipts/run.json"
        self.runtime_root = self.root / "runtime"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def check(
        self,
        identifier: str,
        code: str,
        *arguments: str,
        dependencies: tuple[str, ...] = (),
        timeout: int = 5,
        path: str = ".",
    ) -> dict[str, object]:
        return {
            "argv": [sys.executable, "-c", code, *arguments],
            "dependencies": list(dependencies),
            "identifier": identifier,
            "input_artifacts": [],
            "kind": "test",
            "language": "python",
            "output_artifacts": [],
            "path": path,
            "timeout_seconds": timeout,
            "tool": {"identity": "python", "version": "3.14.6"},
        }

    def plan(self, checks: list[dict[str, object]]) -> str:
        plan = {"checks": checks, "schema_version": "0.1"}
        digest = hashlib.sha256(encoded(plan)).hexdigest()
        self.plan_path.write_bytes(
            encoded(
                {
                    "bindings": {
                        "environment_sha256": SHA,
                        "policy_sha256": SHA,
                        "repository_sha256": SHA,
                        "revision_sha256": SHA,
                        "toolchain_sha256": SHA,
                    },
                    "execution_plan": plan,
                    "execution_plan_sha256": digest,
                    "findings": [],
                    "mutation_count": 0,
                    "status": "PLANNED",
                }
            )
        )
        return digest

    def invoke(self, digest: str, workers: int = 2) -> int:
        with (
            redirect_stdout(io.StringIO()),
            mock.patch.object(harness, "_isolation_identity", return_value=None),
        ):
            return harness.main(
                [
                    "--plan-report",
                    str(self.plan_path),
                    "--expected-plan-sha256",
                    digest,
                    "--repository",
                    str(self.root),
                    "--invocation-sha256",
                    "b" * 64,
                    "--receipt",
                    str(self.receipt),
                    "--runtime-root",
                    str(self.runtime_root),
                    "--workers",
                    str(workers),
                ]
            )

    def result(self) -> dict[str, Any]:
        return json.loads(self.receipt.read_text())

    def assert_harness_pass(self, result: int, receipt: Path) -> None:
        fault_path = receipt.with_name(f"{receipt.name}.fault.json")
        fault = fault_path.read_text() if fault_path.exists() else "fault missing"
        self.assertEqual(0, result, fault)

    def test_exact_argv_nonzero_and_deterministic_receipt(self) -> None:
        sentinel = self.root / "must-not-exist"
        atom = f"x;touch {sentinel}"
        digest = self.plan(
            [
                self.check("python.literal", "import sys;print(sys.argv[1])", atom),
                self.check("python.nonzero", "raise SystemExit(7)"),
            ]
        )
        self.assertEqual(0, self.invoke(digest))
        first, result = self.receipt.read_bytes(), self.result()
        self.assertEqual(
            ["python.literal", "python.nonzero"],
            [item["identifier"] for item in result["checks"]],
        )
        self.assertEqual({"EXITED": {"exit_code": 7}}, result["checks"][1]["outcome"])
        self.assertEqual(
            f"{atom}\n",
            (self.root / result["checks"][0]["evidence_path"]).read_text(),
        )
        self.assertFalse(sentinel.exists())
        self.assertEqual(0, self.invoke(digest))
        self.assertEqual(first, self.receipt.read_bytes())
        self.assertNotIn("verdict", result)
        self.assertNotIn("status", result)

    def test_dependency_timeout_still_produces_a_complete_receipt(self) -> None:
        marker = self.root / "ready"
        leak = self.root / "descendant-leaked"
        descendant = (
            "import time;from pathlib import Path;time.sleep(1.1);"
            f"Path({str(leak)!r}).write_text('bad')"
        )
        digest = self.plan(
            [
                self.check(
                    "python.timeout-close",
                    "import os,time;os.close(1);os.close(2);time.sleep(2)",
                    timeout=1,
                ),
                self.check(
                    "python.timeout-descendant",
                    f"import subprocess,sys;subprocess.Popen("
                    f"[sys.executable,'-c',{descendant!r}])",
                    dependencies=("python.timeout-close",),
                    timeout=1,
                ),
                self.check(
                    "python.dependent",
                    f"from pathlib import Path;Path({str(marker)!r}).write_text('yes')",
                    dependencies=("python.timeout-descendant",),
                ),
            ]
        )
        self.assertEqual(0, self.invoke(digest, workers=1))
        self.assertEqual(
            ["TIMED_OUT", "TIMED_OUT"],
            [item["outcome"] for item in self.result()["checks"][:2]],
        )
        self.assertEqual("yes", marker.read_text())
        time.sleep(0.3)
        self.assertFalse(leak.exists())

    def test_one_shared_semaphore_bounds_concurrency(self) -> None:
        digest = self.plan(
            [
                self.check(f"python.{index}", "import time;time.sleep(.05)")
                for index in range(3)
            ]
        )
        real = asyncio.Semaphore

        class TrackingSemaphore:
            active = maximum = 0

            def __init__(self, value: int) -> None:
                self.inner = real(value)

            async def __aenter__(self) -> None:
                await self.inner.acquire()
                type(self).active += 1
                type(self).maximum = max(type(self).maximum, type(self).active)

            async def __aexit__(self, *_: object) -> None:
                type(self).active -= 1
                self.inner.release()

        with mock.patch.object(harness.asyncio, "Semaphore", TrackingSemaphore):
            self.assertEqual(0, self.invoke(digest, workers=2))
        self.assertEqual(2, TrackingSemaphore.maximum)

    def test_nominal_exit_kills_same_session_descendants(self) -> None:
        leak = self.root / "nominal-descendant-leaked"
        descendant = (
            "import os,time;from pathlib import Path;"
            "os.close(1);os.close(2);time.sleep(.4);"
            f"Path({str(leak)!r}).write_text('bad')"
        )
        digest = self.plan(
            [
                self.check(
                    "python.nominal-descendant",
                    "import subprocess,sys;"
                    f"subprocess.Popen([sys.executable,'-c',{descendant!r}])",
                )
            ]
        )
        self.assertEqual(0, self.invoke(digest, workers=1))
        time.sleep(0.5)
        self.assertFalse(leak.exists())

    def test_fixed_identity_and_kill_failures_are_fail_closed(self) -> None:
        with (
            mock.patch.object(harness.os, "geteuid", return_value=0),
            mock.patch.dict(harness.os.environ, {"SUDO_UID": "501"}),
        ):
            self.assertEqual(
                harness.RunIdentity(
                    NOBODY.pw_uid % (1 << 32),
                    NOBODY.pw_gid % (1 << 32),
                ),
                harness._isolation_identity(),
            )
        with (
            mock.patch.object(harness.os, "geteuid", return_value=0),
            mock.patch.object(
                harness.pwd,
                "getpwnam",
                return_value=SimpleNamespace(pw_uid=-2, pw_gid=-2),
            ),
            mock.patch.dict(harness.os.environ, {}, clear=True),
        ):
            self.assertEqual(
                harness.RunIdentity((1 << 32) - 2, (1 << 32) - 2),
                harness._isolation_identity(),
            )
        with mock.patch.dict(
            harness.os.environ,
            {
                "AWS_ACCESS_KEY_ID": "secret",
                "BASH_ENV": "/tmp/inject",
                "GITHUB_ENV": "/tmp/github-env",
                "LD_PRELOAD": "/tmp/inject.so",
                "NIX_CFLAGS_COMPILE": "-isystem /nix/store/include",
                "NIX_CC_WRAPPER_TARGET_HOST_x86_64_unknown_linux_gnu": "1",
                "NIX_CC_WRAPPER_TARGET_HOST_injected": "0",
                "NIX_CC_WRAPPER_TARGET_HOST_bad-name": "1",
                "NIX_REMOTE": "ssh://root@host",
                "NIX_SECRET_TOKEN": "secret",
                "NIX_USER_CONF_FILES": "/tmp/nix.conf",
                "PATH": "/trusted/bin",
                "PKG_CONFIG_ATTACK": "secret",
                "PYTHONPATH": "/trusted/python",
                "RUST_TOKEN": "secret",
            },
            clear=True,
        ):
            environment = harness._candidate_environment(self.root, self.root)
        self.assertEqual("/trusted/bin", environment["PATH"])
        self.assertEqual("/trusted/python", environment["PYTHONPATH"])
        self.assertEqual("true", environment["CARGO_NET_OFFLINE"])
        self.assertEqual(str(self.root), environment["TMPDIR"])
        self.assertEqual(
            "-isystem /nix/store/include",
            environment["NIX_CFLAGS_COMPILE"],
        )
        self.assertEqual(
            "1",
            environment["NIX_CC_WRAPPER_TARGET_HOST_x86_64_unknown_linux_gnu"],
        )
        for denied in (
            "AWS_ACCESS_KEY_ID",
            "BASH_ENV",
            "GITHUB_ENV",
            "LD_PRELOAD",
            "NIX_REMOTE",
            "NIX_SECRET_TOKEN",
            "NIX_USER_CONF_FILES",
            "NIX_CC_WRAPPER_TARGET_HOST_injected",
            "NIX_CC_WRAPPER_TARGET_HOST_bad-name",
            "PKG_CONFIG_ATTACK",
            "RUST_TOKEN",
        ):
            self.assertNotIn(denied, environment)
        with (
            mock.patch.object(
                harness,
                "_candidate_can_write",
                return_value=True,
            ),
            self.assertRaises(harness.HarnessError) as raised,
        ):
            harness._validate_subject(
                self.root,
                harness.RunIdentity((1 << 32) - 2, (1 << 32) - 2),
            )
        self.assertEqual("HARNESS_SUBJECT_WRITABLE", raised.exception.code)
        digest = self.plan([self.check("python.kill-fault", "print('done')")])
        with mock.patch.object(
            harness.os, "killpg", side_effect=PermissionError("injected")
        ):
            self.assertEqual(1, self.invoke(digest, workers=1))
        fault = json.loads(self.receipt.with_name("run.json.fault.json").read_text())
        self.assertEqual("HARNESS_CONTAINMENT_FAILED", fault["code"])

    def test_trusted_rust_inputs_bind_lock_and_read_only_cargo_home(self) -> None:
        rust = self.root / "rust"
        rust.mkdir()
        cargo_lock = rust / "Cargo.lock"
        cargo_lock.write_bytes(b"locked")
        source = self.root / "trusted-rust-inputs"
        (source / "advisory-db/.git").mkdir(parents=True)
        (source / "config.toml").write_text("[net]\noffline = true\n")
        (source / "manifest.json").write_bytes(
            encoded(
                {
                    "cargo_lock_sha256": hashlib.sha256(b"locked").hexdigest(),
                    "rustsec_revision": "b" * 40,
                    "schema_version": "0.1",
                }
            )
        )
        repository, runtime = harness._prepare_runtime(
            self.root, self.receipt, self.runtime_root, None
        )
        identity = harness.RunIdentity(NOBODY.pw_uid, NOBODY.pw_gid)
        checks = [{"language": "rust", "path": "rust"}]
        cargo_config = self.root / ".cargo/config.toml"
        cargo_config.parent.mkdir()
        cargo_config.write_text("[net]\noffline = false\n")
        with (
            mock.patch.object(harness, "_trusted_nix_store_path", return_value=True),
            self.assertRaises(harness.HarnessError) as raised,
        ):
            harness._prepare_rust_inputs(source, repository, checks, runtime, identity)
        self.assertEqual("HARNESS_CARGO_CONFIG_UNTRUSTED", raised.exception.code)
        cargo_config.unlink()
        with (
            mock.patch.object(harness, "_trusted_nix_store_path", return_value=True),
            mock.patch.object(harness.os, "chown"),
        ):
            cargo_home = harness._prepare_rust_inputs(
                source, repository, checks, runtime, identity
            )
        assert cargo_home is not None
        self.assertEqual(source / "config.toml", (cargo_home / "config.toml").resolve())
        environment = harness._candidate_environment(
            runtime.artifacts, runtime.temporary, cargo_home
        )
        self.assertEqual(str(cargo_home), environment["CARGO_HOME"])
        self.assertEqual(str(source / "advisory-db"), environment["GIT_CONFIG_VALUE_0"])
        cargo_lock.write_bytes(b"changed")
        with (
            mock.patch.object(harness, "_trusted_nix_store_path", return_value=True),
            self.assertRaises(harness.HarnessError) as raised,
        ):
            harness._prepare_rust_inputs(source, repository, checks, runtime, identity)
        self.assertEqual("HARNESS_CARGO_LOCK_DIVERGED", raised.exception.code)

    def test_invalid_digest_and_escaped_cwd_spawn_nothing(self) -> None:
        digest = self.plan([self.check("python.safe", "print('x')")])
        self.receipt.parent.mkdir(parents=True)
        self.receipt.write_bytes(b"stale")
        with mock.patch.object(harness.asyncio, "create_subprocess_exec") as spawn:
            self.assertEqual(2, self.invoke("0" * 64))
            spawn.assert_not_called()
        self.assertFalse(self.receipt.exists())
        outside = self.root.parent / f"{self.root.name}-outside"
        outside.mkdir()
        try:
            (self.root / "escape").symlink_to(outside, target_is_directory=True)
            digest = self.plan(
                [self.check("python.escape", "print('x')", path="escape")]
            )
            with mock.patch.object(harness.asyncio, "create_subprocess_exec") as spawn:
                self.assertEqual(1, self.invoke(digest))
                spawn.assert_not_called()
        finally:
            outside.rmdir()

    def test_network_sandbox_faults_are_inconclusive_before_candidate(self) -> None:
        marker = self.root / "candidate-ran"
        digest = self.plan(
            [
                self.check(
                    "python.network",
                    f"from pathlib import Path;Path({str(marker)!r}).touch()",
                )
            ]
        )
        codes = (
            "HARNESS_NETWORK_SANDBOX_UNAVAILABLE",
            "HARNESS_NETWORK_SANDBOX_SETUP_FAILED",
            "HARNESS_NETWORK_SANDBOX_BYPASS_DETECTED",
            "HARNESS_NETWORK_SANDBOX_POLICY_UNSUPPORTED",
        )
        for code in codes:
            with (
                self.subTest(code=code),
                mock.patch.object(
                    harness,
                    "_verify_network_sandbox",
                    side_effect=harness.HarnessError(code),
                ),
                mock.patch.object(harness.asyncio, "create_subprocess_exec") as spawn,
            ):
                self.assertEqual(70, self.invoke(digest, workers=1))
                fault = json.loads(
                    self.receipt.with_name("run.json.fault.json").read_text()
                )
                self.assertEqual(code, fault["code"])
                self.assertFalse(marker.exists())
                spawn.assert_not_called()

    def test_network_probe_rejects_parent_or_descendant_egress(self) -> None:
        arguments = [
            "10.0.0.1",
            "1234",
            "fd00::1",
            "4321",
            "0",
            "1235",
            "/tmp/canary.sock",
            str(self.root / "write-canary"),
        ]
        with (
            mock.patch.object(harness, "_loopback_fixture", return_value=True),
            mock.patch.object(harness, "_egress_blocked", return_value=True) as parent,
            mock.patch.object(
                harness, "_descendant_egress_blocked", return_value=True
            ) as descendant,
        ):
            self.assertEqual(0, harness._network_probe(arguments))
        native_ipv6 = ("fd00::1", 4321, 0)
        parent.assert_called_once_with(
            "10.0.0.1", 1234, native_ipv6, 1235, "/tmp/canary.sock"
        )
        descendant.assert_called_once_with(
            "10.0.0.1", 1234, native_ipv6, 1235, "/tmp/canary.sock"
        )
        arguments[2:5] = ["-", "0", "0"]
        with (
            mock.patch.object(harness, "_loopback_fixture", return_value=True),
            mock.patch.object(harness, "_egress_blocked", return_value=True) as parent,
            mock.patch.object(
                harness, "_descendant_egress_blocked", return_value=True
            ) as descendant,
        ):
            self.assertEqual(0, harness._network_probe(arguments))
        parent.assert_called_once_with("10.0.0.1", 1234, None, 1235, "/tmp/canary.sock")
        descendant.assert_called_once_with(
            "10.0.0.1", 1234, None, 1235, "/tmp/canary.sock"
        )
        arguments[2:5] = ["fd00::1", "4321", "0"]
        for parent, descendant in ((False, True), (True, False)):
            with (
                self.subTest(parent=parent, descendant=descendant),
                mock.patch.object(harness, "_loopback_fixture", return_value=True),
                mock.patch.object(harness, "_egress_blocked", return_value=parent),
                mock.patch.object(
                    harness,
                    "_descendant_egress_blocked",
                    return_value=descendant,
                ),
            ):
                self.assertEqual(
                    harness.NETWORK_BYPASS_EXIT,
                    harness._network_probe(arguments),
                )

    def test_network_probe_requires_explicit_ipv4_loopback(self) -> None:
        arguments = [
            "10.0.0.1",
            "1234",
            "-",
            "0",
            "0",
            "1235",
            "/tmp/canary.sock",
            str(self.root / "write-canary"),
        ]
        with (
            mock.patch.object(
                harness, "_loopback_fixture", return_value=True
            ) as loopback,
            mock.patch.object(harness, "_egress_blocked", return_value=True),
            mock.patch.object(harness, "_descendant_egress_blocked", return_value=True),
        ):
            self.assertEqual(0, harness._network_probe(arguments))
        loopback.assert_called_once_with(socket.AF_INET, "127.0.0.1")
        with mock.patch.object(harness, "_loopback_fixture", return_value=False):
            self.assertEqual(
                harness.NETWORK_SETUP_EXIT,
                harness._network_probe(arguments),
            )

    def test_egress_probe_rejects_reachable_native_ipv6_canary(self) -> None:
        targets: list[tuple[str, int]] = []

        class ProbeSocket:
            def __enter__(self) -> Self:
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def settimeout(self, _: int) -> None:
                return None

            def connect_ex(self, target: tuple[Any, ...]) -> int:
                pair = (str(target[0]), int(target[1]))
                targets.append(pair)
                return int(pair != ("fd00::1", 4321))

        with (
            mock.patch.object(
                harness,
                "_socket_domain_filter_enforced",
                return_value=True,
            ),
            mock.patch.object(harness.socket, "socket", return_value=ProbeSocket()),
        ):
            self.assertFalse(
                harness._egress_blocked(
                    "192.0.2.1",
                    9,
                    ("fd00::1", 4321, 0),
                    9,
                    "/tmp/missing-network-canary.sock",
                )
            )
        self.assertIn(("fd00::1", 4321), targets)

    def test_vsock_canary_requires_policy_eperm(self) -> None:
        with (
            mock.patch.object(harness.socket, "AF_VSOCK", 40, create=True),
            mock.patch.object(
                harness.socket,
                "socket",
                side_effect=OSError(errno.EPERM, "policy"),
            ),
        ):
            self.assertTrue(harness._socket_domain_filter_enforced())
        with (
            mock.patch.object(harness.socket, "AF_VSOCK", 40, create=True),
            mock.patch.object(
                harness.socket,
                "socket",
                side_effect=OSError(errno.EAFNOSUPPORT, "host"),
            ),
        ):
            self.assertFalse(harness._socket_domain_filter_enforced())
        available = mock.Mock()
        with (
            mock.patch.object(harness.socket, "AF_VSOCK", 40, create=True),
            mock.patch.object(harness.socket, "socket", return_value=available),
        ):
            self.assertFalse(harness._socket_domain_filter_enforced())
        available.close.assert_called_once_with()

    def test_linux_seccomp_denies_nonlocal_socket_paths(self) -> None:
        denied = 0x00050000 | errno.EPERM
        allowed = 0x7FFF0000
        killed = 0x80000000
        for machine, arch, socket_call, socketpair_call, clone, unshare, setns in (
            ("x86_64", 0xC000003E, 41, 53, 56, 272, 308),
            ("aarch64", 0xC00000B7, 198, 199, 220, 97, 268),
        ):
            with self.subTest(machine=machine):
                candidate = harness._linux_seccomp_program(machine)
                probe = harness._linux_seccomp_program(machine, allow_loopback=True)
                self.assertEqual(0, len(candidate) % 8)
                self.assertEqual(killed, seccomp_verdict(candidate, 0, socket_call, 2))
                self.assertEqual(allowed, seccomp_verdict(candidate, arch, 1))
                self.assertEqual(denied, seccomp_verdict(candidate, arch, 425))
                self.assertEqual(
                    0x00050000 | errno.ENOSYS,
                    seccomp_verdict(candidate, arch, 435),
                )
                self.assertEqual(denied, seccomp_verdict(candidate, arch, setns))
                for call in (clone, unshare):
                    self.assertEqual(
                        allowed,
                        seccomp_verdict(candidate, arch, call),
                    )
                    self.assertEqual(
                        denied,
                        seccomp_verdict(candidate, arch, call, 0x10000000),
                    )
                for family in (socket.AF_INET, socket.AF_INET6):
                    for call in (socket_call, socketpair_call):
                        self.assertEqual(
                            denied,
                            seccomp_verdict(candidate, arch, call, family),
                        )
                        self.assertEqual(
                            allowed,
                            seccomp_verdict(probe, arch, call, family),
                        )
                for call in (socket_call, socketpair_call):
                    self.assertEqual(
                        allowed,
                        seccomp_verdict(candidate, arch, call, socket.AF_UNIX),
                    )
                for call in (socket_call, socketpair_call):
                    for family in (40, 17):  # AF_VSOCK, AF_PACKET
                        self.assertEqual(
                            denied,
                            seccomp_verdict(candidate, arch, call, family),
                        )
        program = harness._linux_seccomp_program("x86_64")
        self.assertEqual(
            denied,
            seccomp_verdict(program, 0xC000003E, 0x40000000 | 41, socket.AF_INET),
        )
        with self.assertRaises(harness.HarnessError) as raised:
            harness._linux_seccomp_program("riscv64")
        self.assertEqual(
            "HARNESS_NETWORK_SANDBOX_POLICY_UNSUPPORTED",
            raised.exception.code,
        )

    def test_candidate_ip_policy_probe_requires_eperm_for_both_families(
        self,
    ) -> None:
        denied: list[socket.AddressFamily] = []

        def deny(family: socket.AddressFamily, _: socket.SocketKind) -> socket.socket:
            denied.append(family)
            raise OSError(errno.EPERM, "policy")

        with (
            mock.patch.object(harness.socket, "socket", side_effect=deny),
            mock.patch.object(harness.os, "fork") as fork,
        ):
            self.assertEqual(0, harness._candidate_ip_policy_once())
        fork.assert_not_called()
        self.assertEqual(
            [
                socket.AF_INET,
                socket.AF_INET,
                socket.AF_INET6,
                socket.AF_INET6,
            ],
            denied,
        )

        with mock.patch.object(
            harness.socket,
            "socket",
            side_effect=OSError(errno.EAFNOSUPPORT, "host"),
        ):
            self.assertEqual(
                harness.NETWORK_POLICY_SOCKET_CREATE_EXIT,
                harness._candidate_ip_policy_once(),
            )

        class DatagramAllowed:
            def __init__(self, kind: socket.SocketKind) -> None:
                self.kind = kind

            def __enter__(self) -> Self:
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def connect_ex(self, _: tuple[str, int]) -> int:
                return errno.EPERM

            def sendto(self, _: bytes, target: tuple[str, int]) -> int:
                return 1

        with mock.patch.object(
            harness.socket,
            "socket",
            side_effect=lambda _family, kind: DatagramAllowed(kind),
        ):
            self.assertEqual(
                harness.NETWORK_BYPASS_EXIT,
                harness._candidate_ip_policy_once(),
            )

    def test_candidate_ip_policy_stage_separates_failure_boundaries(
        self,
    ) -> None:
        class OperationUnsupported:
            def __enter__(self) -> Self:
                return self

            def __exit__(self, *_: object) -> None:
                return None

            def connect_ex(self, _: tuple[str, int]) -> int:
                return errno.ENETUNREACH

        with mock.patch.object(
            harness.socket,
            "socket",
            return_value=OperationUnsupported(),
        ):
            self.assertEqual(
                harness.NETWORK_POLICY_SOCKET_OPERATION_EXIT,
                harness._candidate_ip_policy_once(),
            )

        for returncode, stage in (
            (
                harness.NETWORK_POLICY_SOCKET_CREATE_EXIT,
                harness.NetworkStage.CANDIDATE_SOCKET_CREATE_UNEXPECTED,
            ),
            (
                harness.NETWORK_POLICY_SOCKET_OPERATION_EXIT,
                harness.NetworkStage.CANDIDATE_SOCKET_OPERATION_UNEXPECTED,
            ),
            (1, harness.NetworkStage.CANDIDATE_PROCESS_EXIT_UNEXPECTED),
        ):
            with self.subTest(returncode=returncode):
                self.assertEqual(
                    stage,
                    harness._candidate_policy_stage(returncode),
                )

    def test_missing_native_ipv6_route_is_not_used_as_policy_proof(self) -> None:
        class NoRouteSocket:
            def connect(self, _: tuple[str, int]) -> None:
                raise OSError(errno.ENETUNREACH, "no route")

            def close(self) -> None:
                return None

        with (
            ExitStack() as stack,
            mock.patch.object(
                harness.socket,
                "socket",
                return_value=NoRouteSocket(),
            ),
        ):
            self.assertIsNone(harness._native_ipv6_listener(stack))

    def test_macos_candidate_profile_denies_loopback_brokers(self) -> None:
        runtime = harness.RuntimePaths(
            self.root / "run.json",
            self.root / "evidence",
            self.root / "artifacts",
            self.root / "tmp",
        )
        identity = harness.RunIdentity(NOBODY.pw_uid, NOBODY.pw_gid)
        candidate = harness._sandboxed_argv(
            harness.NetworkSandbox.MACOS,
            identity,
            ["/nix/store/python", "-c", "pass"],
            self.root,
            runtime,
            None,
        )
        probe = harness._sandboxed_argv(
            harness.NetworkSandbox.MACOS,
            identity,
            ["/nix/store/python", "-c", "pass"],
            self.root,
            runtime,
            None,
            allow_loopback=True,
        )
        self.assertNotIn("(allow network-", candidate[2])
        self.assertIn("(deny network* (with errno EPERM))", candidate[2])
        self.assertIn('(import "dyld-support.sb")', candidate[2])
        self.assertNotIn("\n(allow file-read*)\n", candidate[2])
        self.assertIn(f'(subpath "{self.root}")', candidate[2])
        self.assertIn('(subpath "/nix/store")', candidate[2])
        self.assertNotIn("(deny network*", probe[2])
        self.assertIn('(allow network-outbound (remote ip "localhost:*"))', probe[2])

    def test_linux_sandbox_binds_trusted_launcher_outside_candidate_cwd(self) -> None:
        script = Path(harness.__file__).resolve()
        candidate_cwd = self.root / "candidate"
        candidate_cwd.mkdir()
        runtime = harness.RuntimePaths(
            self.root / "run.json",
            self.root / "evidence",
            self.root / "artifacts",
            self.root / "tmp",
        )
        cargo_home = self.root / "cargo-home"
        identity = harness.RunIdentity(NOBODY.pw_uid, NOBODY.pw_gid)
        with mock.patch.object(
            harness,
            "_trusted_executable",
            return_value=Path("/nix/store/pinned-bwrap"),
        ):
            command = harness._sandboxed_argv(
                harness.NetworkSandbox.LINUX,
                identity,
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(script),
                    "--network-probe-entry",
                    str(NOBODY.pw_uid),
                    str(NOBODY.pw_gid),
                    "10.0.0.1",
                    "1234",
                    "-",
                    "0",
                    "0",
                    "1235",
                    "/tmp/canary.sock",
                    "/tmp/write-canary",
                ],
                candidate_cwd,
                runtime,
                cargo_home,
                allow_loopback=True,
                seccomp_fd=9,
                trusted_launcher=script,
                privileged_probe=harness.FIXED_PROBES["network"],
            )
        self.assertNotIn("--unshare-user", command)
        self.assertNotIn("--disable-userns", command)
        self.assertNotIn("--new-session", command)
        self.assertNotIn("--uid", command)
        self.assertNotIn("--gid", command)
        self.assertIn(
            ["--cap-add", "CAP_SETGID"],
            [command[index : index + 2] for index in range(len(command))],
        )
        self.assertIn(
            ["--cap-add", "CAP_SETUID"],
            [command[index : index + 2] for index in range(len(command))],
        )
        self.assertIn(
            ["--add-seccomp-fd", "9"],
            [command[index : index + 2] for index in range(len(command))],
        )
        anchor = command.index(str(script))
        self.assertEqual(
            ["--ro-bind", str(script), str(script)],
            command[anchor - 1 : anchor + 2],
        )
        cwd_anchor = command.index(str(candidate_cwd))
        self.assertEqual(
            ["--ro-bind", str(candidate_cwd), str(candidate_cwd)],
            command[cwd_anchor - 1 : cwd_anchor + 2],
        )
        cargo_anchor = command.index(str(cargo_home))
        self.assertEqual(
            ["--ro-bind", str(cargo_home), str(cargo_home)],
            command[cargo_anchor - 1 : cargo_anchor + 2],
        )
        for lock in harness._cargo_lock_paths(cargo_home):
            lock_anchor = command.index(str(lock))
            self.assertEqual(
                ["--bind", str(lock), str(lock)],
                command[lock_anchor - 1 : lock_anchor + 2],
            )

    def test_linux_privileged_probe_rejects_unbound_spec_or_entry(self) -> None:
        script = Path(harness.__file__).resolve()
        runtime = harness.RuntimePaths(
            self.root / "run.json",
            self.root / "evidence",
            self.root / "artifacts",
            self.root / "tmp",
        )
        identity = harness.RunIdentity(NOBODY.pw_uid, NOBODY.pw_gid)
        argv = [
            sys.executable,
            "-I",
            "-B",
            str(script),
            "--policy-probe-entry",
            str(identity.uid),
            str(identity.gid),
        ]
        equal_but_unbound = harness.FixedProbeSpec(
            "--candidate-ip-policy-probe", "--policy-probe-entry", False, 5
        )
        for probe, candidate in (
            (equal_but_unbound, argv),
            (
                harness.FIXED_PROBES["policy"],
                [*argv[:4], "--network-probe-entry", *argv[5:]],
            ),
        ):
            with self.assertRaises(harness.HarnessError):
                harness._sandboxed_argv(
                    harness.NetworkSandbox.LINUX,
                    identity,
                    candidate,
                    self.root,
                    runtime,
                    None,
                    seccomp_fd=9,
                    trusted_launcher=script,
                    privileged_probe=probe,
                )

    def test_linux_candidate_uses_root_launcher_and_no_user_namespace(self) -> None:
        script = self.root / "trusted-source/scripts/bounded_harness.py"
        script.parent.mkdir(parents=True)
        script.write_text("# trusted launcher\n", encoding="utf-8")
        runtime = harness.RuntimePaths(
            self.root / "run.json",
            self.root / "evidence",
            self.root / "artifacts",
            self.root / "tmp",
        )
        with mock.patch.object(
            harness,
            "_trusted_executable",
            return_value=Path("/nix/store/pinned-bwrap"),
        ):
            command = harness._sandboxed_argv(
                harness.NetworkSandbox.LINUX,
                harness.RunIdentity(NOBODY.pw_uid, NOBODY.pw_gid),
                [str(script), "--linux-candidate-exec"],
                self.root,
                runtime,
                None,
                seccomp_fd=9,
                trusted_launcher=script,
            )
        self.assertNotIn("--unshare-user", command)
        self.assertNotIn("--disable-userns", command)
        self.assertIn("CAP_SETGID", command)
        self.assertIn("CAP_SETUID", command)
        anchor = command.index(str(script))
        self.assertEqual(
            ["--ro-bind", str(script), str(script)],
            command[anchor - 1 : anchor + 2],
        )

    def test_linux_spawn_passes_then_closes_seccomp_fd(self) -> None:
        runtime = harness.RuntimePaths(
            self.root / "run.json",
            self.root / "evidence",
            self.root / "artifacts",
            self.root / "tmp",
        )
        stdout = mock.AsyncMock()
        stdout.read.return_value = harness.SANDBOX_READY
        process = SimpleNamespace(stdout=stdout)
        with (
            mock.patch.object(harness, "_linux_seccomp_fd", return_value=9),
            mock.patch.object(
                harness, "_sandboxed_argv", return_value=["bwrap"]
            ) as sandboxed,
            mock.patch.object(
                harness.asyncio,
                "create_subprocess_exec",
                return_value=process,
            ) as spawn,
            mock.patch.object(harness.os, "close") as close,
        ):
            result = asyncio.run(
                harness._spawn(
                    ["candidate"],
                    self.root,
                    runtime,
                    None,
                    harness.RunIdentity(NOBODY.pw_uid, NOBODY.pw_gid),
                    harness.NetworkSandbox.LINUX,
                )
            )
        self.assertIs(process, result)
        await_args = spawn.await_args
        assert await_args is not None
        self.assertEqual((9,), await_args.kwargs["pass_fds"])
        self.assertIs(True, await_args.kwargs["start_new_session"])
        self.assertIsNone(await_args.kwargs["extra_groups"])
        self.assertIsNone(await_args.kwargs["group"])
        self.assertIsNone(await_args.kwargs["user"])
        stdout.read.assert_awaited_once_with(1)
        self.assertEqual(1, close.call_args_list.count(mock.call(9)))
        wrapped = sandboxed.call_args.args[2]
        self.assertEqual(
            Path(harness.__file__).resolve(),
            sandboxed.call_args.kwargs["trusted_launcher"],
        )
        self.assertIsNone(sandboxed.call_args.kwargs["privileged_probe"])
        self.assertEqual(
            [
                "--linux-candidate-exec",
                str(NOBODY.pw_uid),
                str(NOBODY.pw_gid),
                "candidate",
            ],
            wrapped[4:],
        )

    def test_fixed_probes_have_no_post_ready_exec_boundary(self) -> None:
        runtime = harness.RuntimePaths(
            self.root / "run.json",
            self.root / "evidence",
            self.root / "artifacts",
            self.root / "tmp",
        )
        script = Path(harness.__file__).resolve()
        network_arguments = [
            "10.0.0.1",
            "1234",
            "-",
            "0",
            "0",
            "1235",
            "/tmp/canary.sock",
            str(self.root / "write-canary"),
        ]
        cases = (
            ("policy", "--candidate-ip-policy-probe", [], False),
            ("network", "--network-probe", network_arguments, True),
        )
        for fixed_probe, marker, arguments, allow_loopback in cases:
            argv = [sys.executable, "-I", "-B", str(script), marker, *arguments]
            for sandbox in (
                harness.NetworkSandbox.LINUX,
                harness.NetworkSandbox.MACOS,
            ):
                with self.subTest(fixed_probe=fixed_probe, sandbox=sandbox):
                    stdout = mock.AsyncMock()
                    stdout.read.return_value = harness.SANDBOX_READY
                    process = SimpleNamespace(stdout=stdout)
                    with (
                        mock.patch.object(harness, "_linux_seccomp_fd", return_value=9),
                        mock.patch.object(
                            harness, "_sandboxed_argv", return_value=["sandbox"]
                        ) as sandboxed,
                        mock.patch.object(
                            harness.asyncio,
                            "create_subprocess_exec",
                            return_value=process,
                        ) as spawn,
                        mock.patch.object(harness.os, "close"),
                    ):
                        result = asyncio.run(
                            harness._spawn(
                                argv,
                                script.parent,
                                runtime,
                                None,
                                harness.RunIdentity(NOBODY.pw_uid, NOBODY.pw_gid),
                                sandbox,
                                allow_loopback=allow_loopback,
                                fixed_probe=fixed_probe,
                            )
                        )
                self.assertIs(process, result)
                self.assertEqual(
                    [
                        f"--{fixed_probe}-probe-entry",
                        str(NOBODY.pw_uid),
                        str(NOBODY.pw_gid),
                        *arguments,
                    ],
                    sandboxed.call_args.args[2][4:],
                )
                self.assertEqual(
                    script if sandbox == harness.NetworkSandbox.LINUX else None,
                    sandboxed.call_args.kwargs["trusted_launcher"],
                )
                self.assertIs(
                    harness.FIXED_PROBES[fixed_probe]
                    if sandbox == harness.NetworkSandbox.LINUX
                    else None,
                    sandboxed.call_args.kwargs["privileged_probe"],
                )
                await_args = spawn.await_args
                assert await_args is not None
                if sandbox == harness.NetworkSandbox.MACOS:
                    self.assertEqual(NOBODY.pw_uid, await_args.kwargs["user"])
                    self.assertEqual(NOBODY.pw_gid, await_args.kwargs["group"])
                    self.assertEqual((), await_args.kwargs["extra_groups"])
                else:
                    self.assertIsNone(await_args.kwargs["user"])
                    self.assertIsNone(await_args.kwargs["group"])
                    self.assertIsNone(await_args.kwargs["extra_groups"])

    def test_candidate_policy_probe_emits_ready_from_proving_process(self) -> None:
        with (
            mock.patch.object(
                harness.os,
                "write",
                return_value=len(harness.SANDBOX_READY),
            ) as write,
            mock.patch.object(
                harness,
                "_candidate_ip_policy_once",
                return_value=0,
            ) as prove,
        ):
            self.assertEqual(0, harness._candidate_ip_policy_probe())
        write.assert_called_once_with(1, harness.SANDBOX_READY)
        prove.assert_called_once_with()

    def test_policy_probe_entry_drops_identity_without_exec(self) -> None:
        with (
            mock.patch.object(harness.sys, "platform", "linux"),
            mock.patch.object(
                harness,
                "_drop_candidate_identity",
                return_value=[],
            ) as drop,
            mock.patch.object(
                harness,
                "_candidate_ip_policy_probe",
                return_value=0,
            ) as prove,
            mock.patch.object(harness.os, "execvpe") as execute,
        ):
            self.assertEqual(
                0,
                harness._candidate_policy_probe_entry(
                    [str(NOBODY.pw_uid), str(NOBODY.pw_gid)]
                ),
            )
        drop.assert_called_once_with([str(NOBODY.pw_uid), str(NOBODY.pw_gid)])
        prove.assert_called_once_with()
        execute.assert_not_called()

    def test_trusted_probe_entry_drops_identity_without_exec(self) -> None:
        arguments = ["host", "1", "-", "0", "0", "2", "unix", "write"]
        with (
            mock.patch.object(harness.sys, "platform", "linux"),
            mock.patch.object(
                harness,
                "_drop_candidate_identity",
                return_value=arguments,
            ) as drop,
            mock.patch.object(harness.os, "write", return_value=1) as write,
            mock.patch.object(harness, "_network_probe", return_value=0) as prove,
            mock.patch.object(harness.os, "execvpe") as execute,
        ):
            self.assertEqual(
                0,
                harness._trusted_network_probe_entry(
                    [str(NOBODY.pw_uid), str(NOBODY.pw_gid), *arguments]
                ),
            )
        drop.assert_called_once()
        write.assert_called_once_with(1, harness.SANDBOX_READY)
        prove.assert_called_once_with(arguments)
        execute.assert_not_called()

    def test_macos_fixed_probe_verifies_parent_dropped_identity(self) -> None:
        with (
            mock.patch.object(harness.sys, "platform", "darwin"),
            mock.patch.object(harness.os, "geteuid", return_value=NOBODY.pw_uid),
            mock.patch.object(harness.os, "getegid", return_value=NOBODY.pw_gid),
            mock.patch.object(harness.os, "getgroups", return_value=[]),
            mock.patch.object(
                harness,
                "_candidate_ip_policy_probe",
                return_value=0,
            ) as prove,
            mock.patch.object(harness.os, "execvpe") as execute,
        ):
            self.assertEqual(
                0,
                harness._candidate_policy_probe_entry(
                    [str(NOBODY.pw_uid), str(NOBODY.pw_gid)]
                ),
            )
        prove.assert_called_once_with()
        execute.assert_not_called()

    def test_linux_candidate_exec_verifies_identity_before_ready(self) -> None:
        writes: list[tuple[int, bytes]] = []
        with (
            mock.patch.object(
                harness,
                "_drop_candidate_identity",
                return_value=["/nix/store/candidate", "argument"],
            ) as drop,
            mock.patch.object(
                harness.os,
                "write",
                side_effect=lambda fd, value: writes.append((fd, value)) or len(value),
            ),
            mock.patch.object(
                harness.os,
                "execvpe",
                side_effect=OSError(errno.ENOENT, "injected"),
            ) as execute,
        ):
            result = harness._linux_candidate_exec(
                [
                    str(NOBODY.pw_uid),
                    str(NOBODY.pw_gid),
                    "/nix/store/candidate",
                    "argument",
                ]
            )
        self.assertEqual(harness.NETWORK_SETUP_EXIT, result)
        drop.assert_called_once()
        self.assertEqual([(1, harness.SANDBOX_READY)], writes)
        execute.assert_called_once_with(
            "/nix/store/candidate",
            ["/nix/store/candidate", "argument"],
            mock.ANY,
        )

    def test_linux_candidate_exec_fails_before_ready_on_identity_mismatch(self) -> None:
        with (
            mock.patch.object(
                harness,
                "_drop_candidate_identity",
                side_effect=harness.HarnessError("HARNESS_IDENTITY_UNSAFE"),
            ),
            mock.patch.object(harness.os, "write") as write,
        ):
            self.assertEqual(
                harness.NETWORK_SETUP_EXIT,
                harness._linux_candidate_exec(
                    [str(NOBODY.pw_uid), str(NOBODY.pw_gid), "candidate"]
                ),
            )
        write.assert_not_called()

    def test_candidate_exec_prefixes_output_with_readiness(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                harness.CANDIDATE_EXEC,
                sys.executable,
                "-I",
                "-B",
                "-c",
                "import os;os.write(1,b'candidate-output')",
            ],
            check=False,
            capture_output=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(
            harness.SANDBOX_READY + b"candidate-output",
            result.stdout,
        )

    def test_sandbox_startup_failure_is_typed(self) -> None:
        runtime = harness.RuntimePaths(
            self.root / "run.json",
            self.root / "evidence",
            self.root / "artifacts",
            self.root / "tmp",
        )
        known_digest = hashlib.sha256(
            harness.BWRAP_LOOPBACK_RTM_NEWADDR_EPERM
        ).hexdigest()
        cases = (
            (
                "create",
                OSError(),
                harness.NetworkStage.CANDIDATE_CREATE,
                None,
                harness.NetworkStage.CANDIDATE_START,
            ),
            (
                "ready-eof",
                b"",
                harness.NetworkStage.CANDIDATE_READY_EOF,
                None,
                harness.NetworkStage.CANDIDATE_START,
            ),
            (
                "first-byte-newline",
                b"\n",
                harness.NetworkStage.CANDIDATE_READY_OUTPUT,
                hashlib.sha256(b"").hexdigest(),
                harness.NetworkStage.CANDIDATE_START,
            ),
            (
                "oversized",
                tuple(bytes((byte,)) for byte in b"x" * 256),
                harness.NetworkStage.CANDIDATE_READY_OUTPUT,
                None,
                harness.NetworkStage.CANDIDATE_START,
            ),
            (
                "generic-newline",
                tuple(bytes((byte,)) for byte in b"generic\n"),
                harness.NetworkStage.CANDIDATE_READY_OUTPUT,
                hashlib.sha256(b"generic").hexdigest(),
                harness.NetworkStage.CANDIDATE_START,
            ),
            (
                "macos-newline",
                tuple(bytes((byte,)) for byte in b"macos\n"),
                harness.NetworkStage.CANDIDATE_READY_OUTPUT,
                hashlib.sha256(b"macos").hexdigest(),
                harness.NetworkStage.CANDIDATE_START,
            ),
            (
                "generic-eof-partial",
                (*tuple(bytes((byte,)) for byte in b"generic"), b""),
                harness.NetworkStage.CANDIDATE_READY_OUTPUT,
                None,
                harness.NetworkStage.CANDIDATE_START,
            ),
            (
                "bounded-eof-partial",
                (*tuple(bytes((byte,)) for byte in b"x" * 255), b""),
                harness.NetworkStage.CANDIDATE_READY_OUTPUT,
                None,
                harness.NetworkStage.CANDIDATE_START,
            ),
            (
                "linux-loopback-rtnetlink-eperm",
                tuple(
                    bytes((byte,))
                    for byte in harness.BWRAP_LOOPBACK_RTM_NEWADDR_EPERM + b"\n"
                ),
                harness.NetworkStage.CANDIDATE_LINUX_LOOPBACK_RTMNETLINK_EPERM,
                known_digest,
                harness.NetworkStage.CANDIDATE_START,
            ),
            (
                "ready-timeout",
                TimeoutError(),
                harness.NetworkStage.CANDIDATE_READY_TIMEOUT,
                None,
                harness.NetworkStage.CANDIDATE_START,
            ),
            (
                "ordinary-complete",
                tuple(bytes((byte,)) for byte in b"candidate-derived\n"),
                None,
                None,
                None,
            ),
        )
        for name, observed, expected_stage, expected_digest, startup_failure in cases:
            with self.subTest(name=name):
                stdout = mock.AsyncMock()
                process = SimpleNamespace(returncode=1, stdout=stdout)
                spawn = mock.AsyncMock()
                if name == "create":
                    spawn.side_effect = observed
                else:
                    spawn.return_value = process
                    if isinstance(observed, tuple):
                        stdout.read.side_effect = observed
                    elif isinstance(observed, bytes):
                        stdout.read.return_value = observed
                    else:
                        stdout.read.side_effect = observed
                with (
                    mock.patch.object(harness, "_linux_seccomp_fd", return_value=9),
                    mock.patch.object(
                        harness, "_sandboxed_argv", return_value=["bwrap"]
                    ),
                    mock.patch.object(
                        harness.asyncio, "create_subprocess_exec", new=spawn
                    ),
                    mock.patch.object(harness.os, "close"),
                    self.assertRaises(harness.HarnessError) as raised,
                ):
                    asyncio.run(
                        harness._spawn(
                            ["candidate"],
                            self.root,
                            runtime,
                            None,
                            harness.RunIdentity(NOBODY.pw_uid, NOBODY.pw_gid),
                            (
                                harness.NetworkSandbox.MACOS
                                if name == "macos-newline"
                                else harness.NetworkSandbox.LINUX
                            ),
                            startup_failure=startup_failure,
                        )
                    )
                self.assertEqual(
                    "HARNESS_NETWORK_SANDBOX_SETUP_FAILED",
                    raised.exception.code,
                )
                self.assertEqual(expected_stage, raised.exception.stage)
                self.assertEqual([], raised.exception.failed)
                self.assertEqual(
                    expected_digest,
                    raised.exception.launcher_diagnostic_sha256,
                )
                if name == "first-byte-newline":
                    self.assertEqual(1, stdout.read.await_count)

        known_reason, observed_digest = harness._startup_observation(
            harness.NetworkSandbox.LINUX,
            harness.BWRAP_LOOPBACK_RTM_NEWADDR_EPERM + b"\n",
            line_complete=True,
        )
        self.assertEqual(
            harness.NetworkStage.TRUSTED_READY_EOF,
            harness._startup_stage(harness.NetworkStage.TRUSTED_START, "ready-eof"),
        )
        self.assertEqual(
            harness.NetworkStage.CANDIDATE_LINUX_LOOPBACK_RTMNETLINK_EPERM,
            harness._startup_stage(
                harness.NetworkStage.CANDIDATE_START,
                known_reason,
            ),
        )
        self.assertEqual(
            known_digest,
            observed_digest,
        )
        self.assertEqual(
            (
                "ready-output",
                hashlib.sha256(b"untrusted").hexdigest(),
            ),
            harness._startup_observation(
                harness.NetworkSandbox.MACOS,
                b"untrusted",
                line_complete=True,
            ),
        )
        self.assertEqual(
            (
                "ready-output",
                hashlib.sha256(
                    harness.BWRAP_LOOPBACK_RTM_NEWADDR_EPERM + b"-candidate"
                ).hexdigest(),
            ),
            harness._startup_observation(
                harness.NetworkSandbox.LINUX,
                harness.BWRAP_LOOPBACK_RTM_NEWADDR_EPERM + b"-candidate\n",
                line_complete=True,
            ),
        )
        self.assertEqual(
            ("ready-output", None),
            harness._startup_observation(
                harness.NetworkSandbox.LINUX,
                harness.BWRAP_LOOPBACK_RTM_NEWADDR_EPERM,
                line_complete=False,
            ),
        )

    def test_network_fault_names_the_preflight_stage(self) -> None:
        runtime = harness.RuntimePaths(
            self.root / "run.json",
            self.root / "evidence",
            self.root / "artifacts",
            self.root / "tmp",
        )
        for code in sorted(harness.NETWORK_FAULTS):
            with (
                self.subTest(code=code),
                mock.patch.object(
                    harness,
                    "_network_sandbox",
                    side_effect=harness.HarnessError(code),
                ),
                self.assertRaises(harness.HarnessError) as raised,
            ):
                asyncio.run(
                    harness._verify_network_sandbox(
                        harness.RunIdentity(NOBODY.pw_uid, NOBODY.pw_gid),
                        runtime,
                    )
                )
            self.assertEqual(
                harness.NetworkStage.SANDBOX_SELECT, raised.exception.stage
            )
            self.assertEqual([], raised.exception.failed)
            harness._fault(runtime.receipt, raised.exception)
            fault = json.loads(
                runtime.receipt.with_name("run.json.fault.json").read_text()
            )
            self.assertEqual(
                {
                    "code",
                    "completed",
                    "failed",
                    "launcher_diagnostic_sha256",
                    "not_started",
                    "running",
                    "schema_version",
                    "stage",
                    "state",
                },
                set(fault),
            )
            self.assertEqual(harness.FAULT_SCHEMA_VERSION, fault["schema_version"])
            self.assertEqual(harness.NetworkStage.SANDBOX_SELECT.value, fault["stage"])
            self.assertEqual([], fault["failed"])
            self.assertIsNone(fault["launcher_diagnostic_sha256"])

    def test_output_overflow_is_an_explicit_partial_fault(self) -> None:
        self.receipt.parent.mkdir(parents=True)
        self.receipt.write_bytes(b"old")
        digest = self.plan(
            [self.check("python.overflow", f"print('x'*{harness.MAX_OUTPUT})")]
        )
        self.assertEqual(1, self.invoke(digest, workers=1))
        self.assertFalse(self.receipt.exists())
        fault = json.loads(self.receipt.with_name("run.json.fault.json").read_text())
        self.assertEqual("HARNESS_OUTPUT_LIMIT_EXCEEDED", fault["code"])
        self.assertEqual(["python.overflow"], fault["failed"])
        self.assertIsNone(fault["stage"])
        self.assertEqual("HARNESS_FAULT", fault["state"])

    def test_interruption_is_typed_without_an_aggregate_receipt(self) -> None:
        marker = self.root / "started"
        digest = self.plan(
            [
                self.check(
                    "python.interrupted",
                    f"from pathlib import Path;import time;"
                    f"Path({str(marker)!r}).write_text('yes');time.sleep(30)",
                )
            ]
        )
        bindings, checks, plan_sha, coverage = harness.load_plan(self.plan_path, digest)
        repository, runtime = harness._prepare_runtime(
            self.root, self.receipt, self.runtime_root, None
        )

        async def interrupt() -> harness.HarnessError:
            task = asyncio.create_task(
                harness.execute(
                    bindings,
                    checks,
                    plan_sha,
                    coverage,
                    repository,
                    SHA,
                    1,
                    runtime,
                    None,
                )
            )
            async with asyncio.timeout(5):
                while not marker.exists():
                    await asyncio.sleep(0.01)
            task.cancel()
            with self.assertRaises(harness.HarnessError) as raised:
                await task
            return raised.exception

        error = asyncio.run(interrupt())
        harness._fault(self.receipt, error)
        self.assertFalse(self.receipt.exists())
        fault = json.loads(self.receipt.with_name("run.json.fault.json").read_text())
        self.assertEqual("HARNESS_INTERRUPTED", fault["code"])
        self.assertEqual(["python.interrupted"], fault["running"])

    def test_atomic_replace_failure_preserves_old_bytes(self) -> None:
        target = self.root / "atomic.json"
        target.write_bytes(b"old")
        with (
            mock.patch.object(harness.os, "replace", side_effect=OSError("injected")),
            self.assertRaises(OSError),
        ):
            harness._atomic(target, b"new")
        self.assertEqual(b"old", target.read_bytes())

    @unittest.skipUnless(
        os.geteuid() == 0,
        "requires a disposable root harness",
    )
    def test_distinct_uid_temp_root_supports_component_walk(self) -> None:
        self.root.chmod(0o755)
        runtime_root = (
            Path(tempfile.gettempdir()).resolve()
            / f"agent-work-governor-temp-{uuid.uuid4().hex}"
        )
        temporary_anchor = runtime_root.with_name(f"{runtime_root.name}-candidate")
        receipt = runtime_root / "run.json"
        self.addCleanup(shutil.rmtree, runtime_root, True)
        self.addCleanup(shutil.rmtree, temporary_anchor, True)
        code = """
import os
import sys
import tempfile
from pathlib import Path

try:
    Path(sys.argv[1]).read_bytes()
except (FileNotFoundError, PermissionError):
    pass
else:
    raise SystemExit("protected receipt became readable")
temporary = Path(tempfile.mkdtemp())
descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
try:
    for component in temporary.parts[1:]:
        child = os.open(
            component,
            os.O_RDONLY | os.O_DIRECTORY,
            dir_fd=descriptor,
        )
        os.close(descriptor)
        descriptor = child
finally:
    os.close(descriptor)
"""
        digest = self.plan([self.check("python.temp-walk", code, str(receipt))])
        with redirect_stdout(io.StringIO()):
            result = harness.main(
                [
                    "--plan-report",
                    str(self.plan_path),
                    "--expected-plan-sha256",
                    digest,
                    "--repository",
                    str(self.root),
                    "--invocation-sha256",
                    "b" * 64,
                    "--receipt",
                    str(receipt),
                    "--runtime-root",
                    str(runtime_root),
                    "--workers",
                    "1",
                ]
            )
        self.assert_harness_pass(result, receipt)
        self.assertEqual(
            {"EXITED": {"exit_code": 0}},
            json.loads(receipt.read_text())["checks"][0]["outcome"],
        )
        identity = harness._isolation_identity()
        self.assertEqual(0o711, stat.S_IMODE(runtime_root.stat().st_mode))
        self.assertEqual(0o755, stat.S_IMODE(temporary_anchor.stat().st_mode))
        self.assertEqual(
            identity.uid,
            (temporary_anchor / "tmp").stat().st_uid,
        )
        self.assertEqual(
            0o700,
            stat.S_IMODE((temporary_anchor / "tmp").stat().st_mode),
        )

    @unittest.skipUnless(
        os.geteuid() == 0,
        "requires a disposable root harness",
    )
    def test_distinct_uid_blocks_new_session_receipt_rewrite(self) -> None:
        self.root.chmod(0o755)
        runtime_root = (
            Path(tempfile.gettempdir()).resolve()
            / f"agent-work-governor-isolation-{uuid.uuid4().hex}"
        )
        self.addCleanup(shutil.rmtree, runtime_root, True)
        self.addCleanup(
            shutil.rmtree,
            runtime_root.with_name(f"{runtime_root.name}-candidate"),
            True,
        )
        receipt = runtime_root / "run.json"
        blocked = runtime_root / "artifacts/overwrite-blocked"
        source = self.root / "source.py"
        source.write_text("original")
        source.chmod(0o444)
        escaped = (
            "import os,time;from pathlib import Path;"
            "os.setsid();os.close(1);os.close(2);time.sleep(.2);"
            f"\ntry: Path({str(receipt)!r}).write_text('forged')"
            f"\nexcept PermissionError: pass"
            f"\ntry: Path({str(source)!r}).write_text('forged')"
            f"\nexcept PermissionError: Path({str(blocked)!r}).write_text('yes')"
        )
        digest = self.plan(
            [
                self.check(
                    "python.new-session",
                    "import subprocess,sys;"
                    f"subprocess.Popen([sys.executable,'-c',{escaped!r}])",
                )
            ]
        )
        with redirect_stdout(io.StringIO()):
            result = harness.main(
                [
                    "--plan-report",
                    str(self.plan_path),
                    "--expected-plan-sha256",
                    digest,
                    "--repository",
                    str(self.root),
                    "--invocation-sha256",
                    "b" * 64,
                    "--receipt",
                    str(receipt),
                    "--runtime-root",
                    str(runtime_root),
                    "--workers",
                    "1",
                ]
            )
        self.assert_harness_pass(result, receipt)
        time.sleep(0.4)
        self.assertEqual("yes", blocked.read_text())
        self.assertNotEqual(b"forged", receipt.read_bytes())
        self.assertEqual("original", source.read_text())
        acl_command: list[str] | None = None
        if sys.platform == "darwin":
            acl_command = ["/bin/chmod", "+a", "nobody allow write", str(source)]
        elif setfacl := shutil.which("setfacl"):
            acl_command = [
                setfacl,
                "-m",
                f"u:{NOBODY.pw_uid}:rw",
                str(source),
            ]
        if acl_command is not None:
            subprocess.run(acl_command, check=True)
            with self.assertRaises(harness.HarnessError) as raised:
                harness._validate_subject(
                    self.root,
                    harness._isolation_identity(),
                )
            self.assertEqual("HARNESS_SUBJECT_WRITABLE", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
