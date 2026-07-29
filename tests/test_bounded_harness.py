from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import bounded_harness as harness

# LLM-CONTRACT
# id: agent-work-governor.bounded-harness-tests
# state: PLAN_FIXTURE + TEST_IDENTITY -> BOUNDED_EXECUTION -> RECEIPT_OR_TYPED_FAULT | TEST_FAILURE
# preconditions: fixtures use temporary roots; the root-only test drops to the system nobody user
# invariant: tests cover argv, bounds, timeout, path and UID isolation, and atomic replacement
# failure: unittest exposes the violated fail-closed transition
# source: https://github.com/python/cpython/blob/c63aec69bd59c55314c06c23f4c22c03de76fe45/Doc/library/unittest.rst
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: BoundedHarnessTests
# test: bundle:tests/test_bounded_harness.py

SHA = "a" * 64
NOBODY = pwd.getpwnam("nobody")


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


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
            environment = harness._candidate_environment(self.root)
        self.assertEqual("/trusted/bin", environment["PATH"])
        self.assertEqual("/trusted/python", environment["PYTHONPATH"])
        self.assertEqual("true", environment["CARGO_NET_OFFLINE"])
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
        environment = harness._candidate_environment(runtime.artifacts, cargo_home)
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
                    runtime.receipt,
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
    def test_distinct_uid_blocks_new_session_receipt_rewrite(self) -> None:
        self.root.chmod(0o755)
        runtime_root = (
            Path(tempfile.gettempdir()).resolve()
            / f"agent-work-governor-isolation-{uuid.uuid4().hex}"
        )
        self.addCleanup(shutil.rmtree, runtime_root, True)
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
        self.assertEqual(0, result)
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
