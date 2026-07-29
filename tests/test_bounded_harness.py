from __future__ import annotations

import asyncio
import hashlib
import io
import json
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import bounded_harness as harness

# LLM-CONTRACT
# id: agent-work-governor.bounded-harness-tests
# state: PLAN_FIXTURE -> BOUNDED_EXECUTION -> RECEIPT_OR_TYPED_FAULT | TEST_FAILURE
# preconditions: every subprocess and output remains inside one temporary repository
# invariant: tests cover exact argv, bounds, timeout, path containment, and atomic replacement
# failure: unittest exposes the violated fail-closed transition
# source: https://github.com/python/cpython/blob/c63aec69bd59c55314c06c23f4c22c03de76fe45/Doc/library/unittest.rst
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: BoundedHarnessTests
# test: bundle:tests/test_bounded_harness.py

SHA = "a" * 64


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class BoundedHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.plan_path = self.root / "plan.json"
        self.receipt = self.root / ".governance/receipts/run.json"

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
        with redirect_stdout(io.StringIO()):
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

        async def interrupt() -> harness.HarnessError:
            task = asyncio.create_task(
                harness.execute(
                    bindings,
                    checks,
                    plan_sha,
                    coverage,
                    self.root,
                    self.receipt,
                    SHA,
                    1,
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
        harness._fault(self.root, self.receipt, error)
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


if __name__ == "__main__":
    unittest.main()
