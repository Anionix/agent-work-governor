#!/usr/bin/env python3
"""Run one CI command and preserve code-versus-infrastructure failure identity."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence

# LLM-CONTRACT
# id: agent-work-governor.typed-ci-command
# state: COMMAND -> PASS | CODE_FAIL | INFRA_INCONCLUSIVE
# preconditions: the caller supplies one explicit argv, stable evidence codes, and a trusted probe
# invariant: child output cannot select infrastructure identity; explicit exit 2 or the probe does
# failure: command faults exit 1; recognized infrastructure faults exit 2
# source: https://github.com/python/cpython/blob/c63aec69bd59c55314c06c23f4c22c03de76fe45/Doc/library/subprocess.rst
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: run_typed_command
# test: bundle:tests/test_typed_ci.py

EVIDENCE_CODE = re.compile(r"[A-Z][A-Z0-9_]*")
GATE = re.compile(r"[a-z0-9][a-z0-9-]*")
PROBE_HOSTS = ("api.github.com", "cache.nixos.org", "github.com")
SERVICE_PROBES = (
    "https://api.github.com/rate_limit",
    "https://cache.nixos.org/nix-cache-info",
)


def _emit(
    *,
    classification: str,
    code: str,
    duration_seconds: float,
    gate: str,
    status: str,
) -> None:
    print(
        json.dumps(
            {
                "classification": classification,
                "code": code,
                "duration_seconds": round(duration_seconds, 3),
                "gate": gate,
                "status": status,
            },
            sort_keys=True,
        )
    )


def infrastructure_unavailable() -> bool:
    """Probe trusted DNS and the local Nix daemon after a command failure."""
    # Primary source: https://github.com/python/cpython/blob/c63aec69bd59c55314c06c23f4c22c03de76fe45/Doc/library/urllib.request.rst
    try:
        for host in PROBE_HOSTS:
            socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        nix = shutil.which("nix")
        if nix is not None:
            ping = subprocess.run(
                [nix, "store", "ping", "--store", "daemon"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if ping.returncode != 0:
                return True
        for url in SERVICE_PROBES:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "agent-work-governor-ci-probe"},
            )
            try:
                with urllib.request.urlopen(request, timeout=3) as response:
                    if response.status == 429 or response.status >= 500:
                        return True
            except urllib.error.HTTPError as error:
                if error.code in {403, 429} or error.code >= 500:
                    return True
            except (OSError, TimeoutError, urllib.error.URLError):
                return True
    except OSError:
        return True
    return False


def run_typed_command(
    command: Sequence[str],
    *,
    code: str,
    gate: str,
    infra_code: str,
    probe: Callable[[], bool] | None = None,
) -> int:
    """Stream one command and map its terminal state to the stable CI exit algebra."""
    if not command:
        raise ValueError("command must not be empty")
    if EVIDENCE_CODE.fullmatch(code) is None:
        raise ValueError("invalid code evidence")
    if EVIDENCE_CODE.fullmatch(infra_code) is None:
        raise ValueError("invalid infrastructure evidence")
    if GATE.fullmatch(gate) is None:
        raise ValueError("invalid gate")

    started = time.monotonic()
    try:
        with subprocess.Popen(
            list(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        ) as process:
            if process.stdout is None:
                raise RuntimeError("combined command output is unavailable")
            for line in process.stdout:
                print(line, end="")
            return_code = process.wait()
    except OSError as error:
        print(f"{type(error).__name__}: {error}")
        return_code = 1

    duration = time.monotonic() - started
    if return_code == 0:
        _emit(
            classification="CODE_OK",
            code=code,
            duration_seconds=duration,
            gate=gate,
            status="PASS",
        )
        return 0
    if return_code == 2 or (probe or infrastructure_unavailable)():
        _emit(
            classification="INFRA_INCONCLUSIVE",
            code=infra_code,
            duration_seconds=duration,
            gate=gate,
            status="INCONCLUSIVE",
        )
        return 2
    _emit(
        classification="CODE_FAIL",
        code=code,
        duration_seconds=duration,
        gate=gate,
        status="FAIL",
    )
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--code", required=True)
    parser.add_argument("--gate", required=True)
    parser.add_argument("--infra-code", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args(argv)
    command = arguments.command
    if command[:1] == ["--"]:
        command = command[1:]
    return run_typed_command(
        command,
        code=arguments.code,
        gate=arguments.gate,
        infra_code=arguments.infra_code,
    )


if __name__ == "__main__":
    raise SystemExit(main())
