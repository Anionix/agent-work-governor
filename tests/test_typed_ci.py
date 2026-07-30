from __future__ import annotations

import contextlib
import email.message
import io
import json
import sys
import unittest
import urllib.error
from unittest import mock

from scripts.run_typed_ci import infrastructure_unavailable, run_typed_command

# LLM-CONTRACT
# id: agent-work-governor.typed-ci-command-tests
# state: FIXTURE_COMMAND -> TYPED_RESULT -> EXPECTED_CLASSIFICATION | TEST_FAILURE
# preconditions: the stdlib Python interpreter can execute bounded local fixtures
# invariant: PASS, code failure, and infrastructure failure remain distinct
# failure: any exit or classification mismatch fails the test suite
# source: bundle:scripts/run_typed_ci.py
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: TypedCiCommandTests
# test: bundle:tests/test_typed_ci.py


class TypedCiCommandTests(unittest.TestCase):
    def run_fixture(self, body: str) -> tuple[int, dict[str, object]]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = run_typed_command(
                [sys.executable, "-c", body],
                code="FIXTURE_FAILED",
                gate="fixture",
                infra_code="FIXTURE_INFRA",
                probe=lambda: False,
            )
        evidence = json.loads(output.getvalue().splitlines()[-1])
        return status, evidence

    def test_success_is_code_ok(self) -> None:
        status, evidence = self.run_fixture("print('ok')")
        self.assertEqual(0, status)
        self.assertEqual("CODE_OK", evidence["classification"])

    def test_ordinary_failure_is_code_fail(self) -> None:
        status, evidence = self.run_fixture("raise SystemExit(9)")
        self.assertEqual(1, status)
        self.assertEqual("CODE_FAIL", evidence["classification"])

    def test_explicit_exit_two_remains_inconclusive(self) -> None:
        status, evidence = self.run_fixture("raise SystemExit(2)")
        self.assertEqual(2, status)
        self.assertEqual("INFRA_INCONCLUSIVE", evidence["classification"])

    def test_failed_trusted_probe_is_inconclusive(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = run_typed_command(
                [sys.executable, "-c", "raise SystemExit(1)"],
                code="FIXTURE_FAILED",
                gate="fixture",
                infra_code="FIXTURE_INFRA",
                probe=lambda: True,
            )
        evidence = json.loads(output.getvalue().splitlines()[-1])
        self.assertEqual(2, status)
        self.assertEqual("INFRA_INCONCLUSIVE", evidence["classification"])

    def test_candidate_diagnostic_cannot_forge_infrastructure(self) -> None:
        status, evidence = self.run_fixture(
            "print('failed to fetch api.github.com'); raise SystemExit(1)"
        )
        self.assertEqual(1, status)
        self.assertEqual("CODE_FAIL", evidence["classification"])

    def test_dns_failure_is_detected_by_trusted_probe(self) -> None:
        with mock.patch(
            "scripts.run_typed_ci.socket.getaddrinfo",
            side_effect=OSError("dns unavailable"),
        ):
            self.assertTrue(infrastructure_unavailable())

    def test_nix_daemon_failure_is_detected_by_trusted_probe(self) -> None:
        with (
            mock.patch(
                "scripts.run_typed_ci.socket.getaddrinfo",
                return_value=[],
            ),
            mock.patch(
                "scripts.run_typed_ci.shutil.which",
                return_value="/nix/bin/nix",
            ),
            mock.patch(
                "scripts.run_typed_ci.subprocess.run",
                return_value=mock.Mock(returncode=1),
            ),
        ):
            self.assertTrue(infrastructure_unavailable())

    def test_api_failure_is_detected_after_healthy_dns(self) -> None:
        error = urllib.error.HTTPError(
            "https://api.github.com/rate_limit",
            503,
            "service unavailable",
            email.message.Message(),
            None,
        )
        with (
            mock.patch(
                "scripts.run_typed_ci.socket.getaddrinfo",
                return_value=[],
            ),
            mock.patch(
                "scripts.run_typed_ci.shutil.which",
                return_value=None,
            ),
            mock.patch(
                "scripts.run_typed_ci.urllib.request.urlopen",
                side_effect=error,
            ),
        ):
            self.assertTrue(infrastructure_unavailable())


if __name__ == "__main__":
    unittest.main()
