#!/usr/bin/env python3
"""Run one canonical plan without interpreting policy or assigning a verdict."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import signal
from enum import StrEnum
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, cast

# LLM-CONTRACT
# id: agent-work-governor.bounded-harness
# state: VALID_EXECUTION_PLAN -> BOUNDED_RUN -> AGGREGATE_RUN_RECEIPT | HARNESS_FAULT
# preconditions: the caller binds one PLANNED report, repository, invocation, and plan digest
# invariant: only plan argv executes without a shell; this module never infers or writes PASS
# failure: malformed, partial, unbounded, interrupted, or unsafe runs emit a typed sibling fault
# source: https://github.com/python/cpython/blob/c63aec69bd59c55314c06c23f4c22c03de76fe45/Doc/library/asyncio-subprocess.rst
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: execute
# test: bundle:tests/test_bounded_harness.py

MAX_OUTPUT = MAX_PLAN = 1_048_576
TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
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
            process.kill()


async def _execute_check(
    check: dict[str, Any],
    repository: Path,
    evidence_root: Path,
    artifacts: Path,
    events: dict[str, asyncio.Event],
    semaphore: asyncio.Semaphore,
    state: dict[str, CheckPhase],
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
            process = await asyncio.create_subprocess_exec(
                *argv,
                cwd=_inside(repository, check["path"]),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,
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


def _invalidate(repository: Path, receipt: Path) -> tuple[Path, Path]:
    try:
        repository = repository.resolve(strict=True)
        receipts = repository / ".governance" / "receipts"
        receipts.mkdir(parents=True, exist_ok=True)
        receipts = receipts.resolve(strict=True)
        receipt.resolve().relative_to(receipts)
        _require(receipts.is_relative_to(repository), "HARNESS_RECEIPT_PATH_UNSAFE")
        receipt.unlink(missing_ok=True)
        receipt.with_name(f"{receipt.name}.fault.json").unlink(missing_ok=True)
    except (OSError, ValueError) as error:
        raise HarnessError("HARNESS_RECEIPT_INVALIDATION_FAILED") from error
    return repository, receipts


async def execute(
    bindings: dict[str, Any],
    checks: list[dict[str, Any]],
    plan_sha256: str,
    coverage_sha256: str,
    repository: Path,
    receipt: Path,
    invocation_sha256: str,
    workers: int,
) -> None:
    _require(
        DIGEST.fullmatch(invocation_sha256) is not None and 0 < workers <= 8,
        "HARNESS_INVOCATION_INVALID",
    )
    repository, receipts = _invalidate(repository, receipt)
    evidence_root = _runtime_dir(receipts, "evidence")
    artifacts = _runtime_dir(receipts, "artifacts")
    order = [check["identifier"] for check in checks]
    state = dict.fromkeys(order, CheckPhase.NOT_STARTED)
    events = {identifier: asyncio.Event() for identifier in order}
    semaphore = asyncio.Semaphore(workers)
    tasks = [
        asyncio.create_task(
            _execute_check(
                check, repository, evidence_root, artifacts, events, semaphore, state
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


def _fault(repository: Path, receipt: Path, error: HarnessError) -> None:
    try:
        root = repository.resolve(strict=True) / ".governance" / "receipts"
        receipt.resolve().relative_to(root)
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
    except (OSError, ValueError):
        return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan-report", type=Path, required=True)
    parser.add_argument("--expected-plan-sha256", required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--invocation-sha256", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args(argv)
    receipt = (
        args.receipt if args.receipt.is_absolute() else args.repository / args.receipt
    )
    try:
        _invalidate(args.repository, receipt)
        bindings, checks, plan_sha256, coverage_sha256 = load_plan(
            args.plan_report, args.expected_plan_sha256
        )
        asyncio.run(
            execute(
                bindings,
                checks,
                plan_sha256,
                coverage_sha256,
                args.repository,
                receipt,
                args.invocation_sha256,
                args.workers,
            )
        )
    except KeyboardInterrupt:
        error = HarnessError("HARNESS_INTERRUPTED")
        _fault(args.repository, receipt, error)
        return 130
    except HarnessError as error:
        _fault(args.repository, receipt, error)
        if error.code == "HARNESS_INTERRUPTED":
            return 130
        return 2 if "PLAN" in error.code else 1
    print(_json({"receipt": str(receipt), "state": "AGGREGATE_RUN_RECEIPT"}).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
