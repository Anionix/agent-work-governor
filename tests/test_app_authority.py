from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import cast

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))

import publish_app_authority
from validate_pr_authority import Result

# LLM-CONTRACT
# id: agent-work-governor.external-app-authority-tests
# state: FAKE_APP_API + AUTHORITY_RESULT -> APP_BOUND_CHECK | EXPECTED_CLOSED_FAILURE
# preconditions: requester is isolated and every response carries explicit App identity
# invariant: no credential, network request, repository mutation, or candidate execution occurs
# failure: unittest exposes identity, idempotency, or conclusion-mapping drift
# source: https://github.com/github/docs/blob/72ef2d329866e5d0d52829f105f853da9bcf4260/content/rest/checks/runs.md
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: AppAuthorityTests
# test: bundle:tests/test_app_authority.py


class FakeRequester:
    def __init__(self, app_id: int = 91) -> None:
        self.app_id = app_id
        self.calls: list[tuple[str, str, str, dict[str, object] | None]] = []
        self.runs: list[dict[str, object]] = []
        self.next_id = 500
        self.total_override: int | None = None
        self.readback_conclusion: str | None = None

    def __call__(
        self,
        url: str,
        method: str,
        token: str,
        document: dict[str, object] | None,
    ) -> object:
        self.calls.append((url, method, token, document))
        if method == "GET" and "check-runs?" in url:
            return {
                "total_count": (
                    len(self.runs)
                    if self.total_override is None
                    else self.total_override
                ),
                "check_runs": [dict(run) for run in self.runs],
            }
        if method == "GET":
            run_id = int(url.rsplit("/", 1)[1])
            run = dict(next(run for run in self.runs if run["id"] == run_id))
            if self.readback_conclusion is not None:
                run["conclusion"] = self.readback_conclusion
            return run
        if method == "POST":
            if document is None:
                raise AssertionError("POST requires a document")
            self.next_id += 1
            run = {
                **document,
                "id": self.next_id,
                "app": {"id": self.app_id},
            }
            self.runs.append(run)
            return dict(run)
        if method == "PATCH":
            if document is None:
                raise AssertionError("PATCH requires a document")
            run_id = int(url.rsplit("/", 1)[1])
            run = next(run for run in self.runs if run["id"] == run_id)
            run.update(document)
            return dict(run)
        raise AssertionError(f"unexpected request: {method} {url}")


class AppAuthorityTests(unittest.TestCase):
    def target(
        self,
        *,
        app_id: int = 91,
        external_id: str = "awg:42:33:" + "a" * 40,
    ) -> publish_app_authority.CheckTarget:
        return publish_app_authority.CheckTarget(
            repository="Anionix/agent-work-governor",
            head_sha="a" * 40,
            app_id=app_id,
            external_id=external_id,
            details_url=(
                "https://github.com/Anionix/agent-work-governor/actions/runs/700"
            ),
        )

    def test_pass_is_app_bound_but_shadow_neutral(self) -> None:
        requester = FakeRequester()
        publisher = publish_app_authority.Publisher(
            self.target(),
            "installation-token",
            requester=requester,
        )

        run_id = publisher.start()
        publisher.finish(
            run_id,
            Result(
                "PASS",
                "AUTHORITY_VERIFIED",
                pull_number=33,
                head_sha="a" * 40,
                issue_number=33,
            ),
        )

        self.assertEqual(
            ["GET", "POST", "GET", "PATCH", "GET"],
            [call[1] for call in requester.calls],
        )
        self.assertIn("app_id=91", requester.calls[0][0])
        self.assertEqual("installation-token", requester.calls[1][2])
        self.assertEqual(
            publish_app_authority.CHECK_NAME,
            requester.runs[0]["name"],
        )
        self.assertEqual({"id": 91}, requester.runs[0]["app"])
        self.assertEqual("completed", requester.runs[0]["status"])
        self.assertEqual("neutral", requester.runs[0]["conclusion"])

    def test_fail_and_inconclusive_never_conclude_success(self) -> None:
        for status, code in (
            ("FAIL", "AUTHORITY_HEAD_MISMATCH"),
            ("INCONCLUSIVE", "AUTHORITY_API_ERROR"),
        ):
            with self.subTest(status=status):
                requester = FakeRequester()
                publisher = publish_app_authority.Publisher(
                    self.target(external_id=f"case-{status}"),
                    "installation-token",
                    requester=requester,
                )
                run_id = publisher.start()
                publisher.finish(run_id, Result(status, code))
                self.assertEqual("failure", requester.runs[0]["conclusion"])

    def test_neutral_completion_requires_independent_readback(self) -> None:
        requester = FakeRequester()
        requester.readback_conclusion = "failure"
        publisher = publish_app_authority.Publisher(
            self.target(),
            "installation-token",
            requester=requester,
        )
        run_id = publisher.start()
        with self.assertRaisesRegex(
            publish_app_authority.PublishError,
            "APP_CHECK_COMPLETION_MISMATCH",
        ):
            publisher.finish(run_id, Result("PASS", "AUTHORITY_VERIFIED"))
        self.assertEqual("neutral", requester.runs[0]["conclusion"])

    def test_retry_reuses_one_matching_external_id(self) -> None:
        requester = FakeRequester()
        target = self.target()
        requester.runs.append(
            {
                "id": 123,
                "name": publish_app_authority.CHECK_NAME,
                "head_sha": target.head_sha,
                "external_id": target.external_id,
                "app": {"id": target.app_id},
                "status": "in_progress",
            }
        )
        publisher = publish_app_authority.Publisher(
            target,
            "installation-token",
            requester=requester,
        )

        self.assertEqual(123, publisher.start())
        self.assertEqual(["GET", "PATCH"], [call[1] for call in requester.calls])
        self.assertEqual(1, len(requester.runs))

    def test_stale_identity_is_demoted_before_current_creation(self) -> None:
        requester = FakeRequester()
        target = self.target()
        requester.runs.append(
            {
                "id": 123,
                "name": publish_app_authority.CHECK_NAME,
                "head_sha": target.head_sha,
                "external_id": "stale",
                "app": {"id": target.app_id},
                "status": "completed",
                "conclusion": "success",
            }
        )

        current_id = publish_app_authority.Publisher(
            target,
            "installation-token",
            requester=requester,
        ).start()

        self.assertEqual("failure", requester.runs[0]["conclusion"])
        self.assertNotEqual(123, current_id)
        self.assertEqual(target.external_id, requester.runs[1]["external_id"])
        self.assertEqual(
            ["GET", "PATCH", "POST"],
            [call[1] for call in requester.calls],
        )

    def test_failed_stale_check_demotion_is_not_suppressed(self) -> None:
        requester = FakeRequester()
        target = self.target()
        requester.runs.append(
            {
                "id": 123,
                "name": publish_app_authority.CHECK_NAME,
                "head_sha": target.head_sha,
                "external_id": "stale",
                "app": {"id": target.app_id},
                "status": "completed",
                "conclusion": "success",
            }
        )

        def unavailable_demotion(
            url: str,
            method: str,
            token: str,
            document: dict[str, object] | None,
        ) -> object:
            if method == "PATCH":
                raise publish_app_authority.PublishError("APP_CHECK_API_ERROR")
            return requester(url, method, token, document)

        with self.assertRaisesRegex(
            publish_app_authority.PublishError,
            "APP_CHECK_DEMOTION_FAILED",
        ):
            publish_app_authority.Publisher(
                target,
                "installation-token",
                requester=unavailable_demotion,
            ).start()

    def test_duplicate_or_incomplete_list_fails_closed(self) -> None:
        target = self.target()
        matching: dict[str, object] = {
            "id": 123,
            "name": publish_app_authority.CHECK_NAME,
            "head_sha": target.head_sha,
            "external_id": target.external_id,
            "app": {"id": target.app_id},
        }
        duplicate = FakeRequester()
        duplicate.runs = [matching, {**matching, "id": 124}]
        duplicate_publisher = publish_app_authority.Publisher(
            target,
            "installation-token",
            requester=duplicate,
        )
        with self.assertRaisesRegex(
            publish_app_authority.PublishError,
            "APP_CHECK_DUPLICATE",
        ):
            duplicate_publisher.start()
        self.assertEqual(
            ["failure", "failure"],
            [run["conclusion"] for run in duplicate.runs],
        )
        with self.assertRaisesRegex(
            publish_app_authority.PublishError,
            "APP_CHECK_DUPLICATE",
        ):
            duplicate_publisher.start()
        self.assertEqual(2, len(duplicate.runs))

        incomplete = FakeRequester()
        incomplete.total_override = 101
        with self.assertRaisesRegex(
            publish_app_authority.PublishError,
            "APP_CHECK_LIST_INVALID",
        ):
            publish_app_authority.Publisher(
                target,
                "installation-token",
                requester=incomplete,
            ).start()

    def test_response_from_wrong_app_is_rejected(self) -> None:
        requester = FakeRequester(app_id=92)
        publisher = publish_app_authority.Publisher(
            self.target(app_id=91),
            "installation-token",
            requester=requester,
        )
        with self.assertRaisesRegex(
            publish_app_authority.PublishError,
            "APP_CHECK_IDENTITY_MISMATCH",
        ):
            publisher.start()

    def test_candidate_check_with_same_name_cannot_be_reused(self) -> None:
        requester = FakeRequester(app_id=91)
        target = self.target()
        requester.runs.append(
            {
                "id": 400,
                "name": publish_app_authority.CHECK_NAME,
                "head_sha": target.head_sha,
                "external_id": target.external_id,
                "app": {"id": 15368},
                "status": "completed",
                "conclusion": "success",
            }
        )

        run_id = publish_app_authority.Publisher(
            target,
            "installation-token",
            requester=requester,
        ).start()

        self.assertNotEqual(400, run_id)
        self.assertEqual(["GET", "POST"], [call[1] for call in requester.calls])
        self.assertEqual({"id": 91}, requester.runs[-1]["app"])

    def test_response_for_wrong_head_is_rejected(self) -> None:
        requester = FakeRequester()

        def wrong_head(
            url: str,
            method: str,
            token: str,
            document: dict[str, object] | None,
        ) -> object:
            response = requester(url, method, token, document)
            if method == "POST":
                assert isinstance(response, dict)
                cast(dict[str, object], response)["head_sha"] = "b" * 40
            return response

        publisher = publish_app_authority.Publisher(
            self.target(),
            "installation-token",
            requester=wrong_head,
        )
        with self.assertRaisesRegex(
            publish_app_authority.PublishError,
            "APP_CHECK_IDENTITY_MISMATCH",
        ):
            publisher.start()

    def test_target_is_stable_across_workflow_retries(self) -> None:
        event = {
            "repository": {
                "id": 42,
                "full_name": "Anionix/agent-work-governor",
            },
            "pull_request": {
                "number": 33,
                "head": {"sha": "a" * 40},
                "base": {"sha": "b" * 40},
            },
        }
        environment = {
            "GITHUB_REPOSITORY": "Anionix/agent-work-governor",
            "AWG_AUTHORITY_APP_ID": "91",
            "GITHUB_RUN_ID": "700",
            "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_SERVER_URL": "https://github.com",
        }

        target = publish_app_authority._target(event, environment)
        environment["GITHUB_RUN_ATTEMPT"] = "99"
        retry_target = publish_app_authority._target(event, environment)

        self.assertEqual("a" * 40, target.head_sha)
        self.assertEqual(91, target.app_id)
        self.assertEqual(
            "awg:42:33:" + "a" * 40,
            target.external_id,
        )
        self.assertEqual(target.external_id, retry_target.external_id)


if __name__ == "__main__":
    unittest.main()
