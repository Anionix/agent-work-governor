from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from http.client import HTTPException, HTTPMessage, IncompleteRead
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))

import validate_pr_authority

# LLM-CONTRACT
# id: agent-work-governor.live-pr-authority-tests
# state: AUTHORITY_FIXTURE -> TWO_LIVE_SNAPSHOTS -> COMMIT_TRAILER -> BODY_EVIDENCE -> REPOSITORY_ISSUE -> EXPECTED_VERDICT
# preconditions: transport is isolated and every requested page is explicit
# invariant: tests never use a credential or mutate repository and GitHub state
# failure: unittest exposes the exact fail-closed classification drift
# source: https://github.com/github/docs/blob/72ef2d329866e5d0d52829f105f853da9bcf4260/content/rest/issues/issues.md
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: AuthorityTests
# test: bundle:tests/test_pr_authority.py


class AuthorityTests(unittest.TestCase):
    repository = "Anionix/agent-work-governor"
    repository_id = 42
    api = "https://api.github.com"
    head_sha = "a" * 40
    base_sha = "b" * 40

    def event(self) -> dict[str, object]:
        return {
            "repository": {
                "id": self.repository_id,
                "full_name": self.repository,
            },
            "pull_request": {
                "number": 33,
                "body": "stale event body is never authority",
                "head": {"sha": self.head_sha},
                "base": {"sha": self.base_sha},
            },
        }

    def pull(
        self,
        *,
        number: int = 33,
        state: str = "open",
        head_sha: str | None = None,
        base_sha: str | None = None,
        body: str = "Issue/spec: #33",
        repository_id: int | None = None,
        head_repository: str | None = None,
        base_ref: str = "main",
    ) -> dict[str, object]:
        return {
            "number": number,
            "state": state,
            "body": body,
            "head": {
                "sha": head_sha or self.head_sha,
                "repo": {"full_name": head_repository or self.repository},
            },
            "base": {
                "sha": base_sha or self.base_sha,
                "ref": base_ref,
                "repo": {
                    "id": repository_id or self.repository_id,
                    "full_name": self.repository,
                },
            },
        }

    def repository_issue(
        self,
        *,
        number: int = 33,
        state: str = "open",
    ) -> dict[str, object]:
        repository_url = f"{self.api}/repos/{self.repository}"
        return {
            "id": 3300,
            "number": number,
            "state": state,
            "url": f"{repository_url}/issues/33",
            "repository_url": repository_url,
        }

    def validate(
        self,
        *,
        event: object | None = None,
        live: object | None = None,
        pages: dict[int, object] | None = None,
        second_pages: dict[int, object] | None = None,
        page_links: dict[int, str | None] | None = None,
        second_page_links: dict[int, str | None] | None = None,
        error: BaseException | None = None,
        commit_error: BaseException | None = None,
        issue_error: BaseException | None = None,
        second_live: object | None = None,
        commit: object | None = None,
        issue: object | None = None,
        commit_repository: str | None = None,
        require_body: bool = True,
    ) -> validate_pr_authority.Result:
        pull_url = f"{self.api}/repos/{self.repository}/pulls/33"
        commit_url = (
            f"{self.api}/repos/{commit_repository or self.repository}"
            f"/commits/{self.head_sha}"
        )
        issue_url = f"{self.api}/repos/{self.repository}/issues/33"
        calls = 0
        first_live = self.pull() if live is None else live
        live_documents = [
            first_live,
            first_live if second_live is None else second_live,
        ]
        page_documents = pages or {1: [self.pull()]}
        second_page_documents = second_pages or page_documents
        first_links = page_links or {}
        later_links = second_page_links or first_links

        def fetch(url: str, token: str) -> validate_pr_authority.ApiResponse:
            nonlocal calls
            self.assertEqual("secret-token", token)
            if error is not None:
                raise error
            if url == pull_url:
                index = min(calls, 1)
                calls += 1
                return validate_pr_authority.ApiResponse(live_documents[index])
            if url == commit_url:
                if commit_error is not None:
                    raise commit_error
                document = (
                    {
                        "sha": self.head_sha,
                        "commit": {"message": "fix: bind authority\n\nIssue-Spec: #33"},
                    }
                    if commit is None
                    else commit
                )
                return validate_pr_authority.ApiResponse(document)
            if url == issue_url:
                if issue_error is not None:
                    raise issue_error
                document = self.repository_issue() if issue is None else issue
                return validate_pr_authority.ApiResponse(document)
            selected_pages = page_documents if calls == 1 else second_page_documents
            selected_links = first_links if calls == 1 else later_links
            for page, document in selected_pages.items():
                if url.endswith(f"&page={page}"):
                    next_link = (
                        f'<{self.list_url(page + 1)}>; rel="next"'
                        if page + 1 in selected_pages
                        else None
                    )
                    return validate_pr_authority.ApiResponse(
                        document,
                        selected_links.get(page, next_link),
                    )
            self.fail(f"unexpected URL: {url}")

        validator = (
            validate_pr_authority.validate_pr_authority
            if require_body
            else validate_pr_authority.validate_immutable_pr_authority
        )
        return validator(
            self.event() if event is None else event,
            self.repository,
            "secret-token",
            self.api,
            fetcher=fetch,
        )

    def list_url(self, page: int) -> str:
        repository_url = f"{self.api}/repos/{self.repository}"
        return validate_pr_authority._pull_list_url(repository_url, page)

    def test_pass_uses_live_body_after_two_stable_snapshots(self) -> None:
        result = self.validate()
        self.assertEqual(
            (
                "PASS",
                "AUTHORITY_VERIFIED",
                33,
                self.head_sha,
                33,
                "Issue/spec: #33",
            ),
            (
                result.status,
                result.code,
                result.pull_number,
                result.head_sha,
                result.issue_number,
                result.body,
            ),
        )

    def test_immutable_app_authority_ignores_mutable_body_evidence(self) -> None:
        result = self.validate(
            live=self.pull(body="Issue/spec: #999"),
            second_live=self.pull(body="body changed during evaluation"),
            require_body=False,
        )
        self.assertEqual(
            ("PASS", "IMMUTABLE_AUTHORITY_VERIFIED", 33),
            (result.status, result.code, result.issue_number),
        )

    def test_deterministic_identity_mismatches_fail(self) -> None:
        cases = (
            (self.pull(state="closed"), "AUTHORITY_PR_NOT_OPEN"),
            (self.pull(number=34), "AUTHORITY_PULL_NUMBER_MISMATCH"),
            (self.pull(head_sha="c" * 40), "AUTHORITY_HEAD_MISMATCH"),
            (self.pull(base_sha="d" * 40), "AUTHORITY_BASE_MISMATCH"),
            (
                self.pull(repository_id=self.repository_id + 1),
                "AUTHORITY_BASE_REPOSITORY_MISMATCH",
            ),
        )
        for live, code in cases:
            with self.subTest(code=code):
                result = self.validate(live=live)
                self.assertEqual(("FAIL", code), (result.status, result.code))

        event = self.event()
        event["repository"] = {
            "id": self.repository_id,
            "full_name": "attacker/repository",
        }
        result = self.validate(event=event)
        self.assertEqual(
            ("FAIL", "AUTHORITY_REPOSITORY_MISMATCH"),
            (result.status, result.code),
        )

    def test_open_head_must_belong_to_exactly_the_locator(self) -> None:
        cases: tuple[tuple[dict[int, object], str], ...] = (
            ({1: []}, "AUTHORITY_OPEN_HEAD_NOT_UNIQUE"),
            (
                {1: [self.pull(), self.pull(number=34)]},
                "AUTHORITY_OPEN_HEAD_NOT_UNIQUE",
            ),
            (
                {1: [self.pull(number=34)]},
                "AUTHORITY_OPEN_HEAD_NOT_UNIQUE",
            ),
            (
                {
                    1: [
                        self.pull(),
                        self.pull(
                            number=34,
                            head_repository="contributor/agent-work-governor",
                        ),
                    ]
                },
                "AUTHORITY_OPEN_HEAD_NOT_UNIQUE",
            ),
            (
                {1: [self.pull(), self.pull(number=34, base_ref="release")]},
                "AUTHORITY_OPEN_HEAD_NOT_UNIQUE",
            ),
        )
        for pages, code in cases:
            with self.subTest(pages=pages):
                result = self.validate(pages=pages)
                self.assertEqual(("FAIL", code), (result.status, result.code))

    def test_unrelated_open_pulls_do_not_create_ambiguity(self) -> None:
        unrelated = self.pull(number=34, head_sha="c" * 40)
        result = self.validate(pages={1: [unrelated, self.pull()]})
        self.assertEqual("PASS", result.status)

    def test_fork_head_uses_the_live_head_repository_commit(self) -> None:
        head_repository = "contributor/agent-work-governor"
        live = self.pull(head_repository=head_repository)
        result = self.validate(
            live=live,
            pages={1: [live]},
            commit_repository=head_repository,
        )
        self.assertEqual("PASS", result.status)

    def test_state_drift_between_snapshots_fails(self) -> None:
        result = self.validate(second_live=self.pull(body="changed live body"))
        self.assertEqual(
            ("FAIL", "AUTHORITY_STATE_CHANGED"), (result.status, result.code)
        )

        changed_listing = [self.pull(), self.pull(number=34, head_sha="c" * 40)]
        result = self.validate(second_pages={1: changed_listing})
        self.assertEqual(
            ("FAIL", "AUTHORITY_STATE_CHANGED"), (result.status, result.code)
        )

    def test_issue_authority_is_bound_to_the_head_commit_trailer(self) -> None:
        cases = (
            ("fix: missing trailer", "AUTHORITY_ISSUE_TRAILER_INVALID"),
            ("fix: malformed\n\nIssue-Spec #33", "AUTHORITY_ISSUE_TRAILER_INVALID"),
            ("", "AUTHORITY_ISSUE_TRAILER_INVALID"),
            (
                "Issue-Spec: #33\nIssue-Spec: #33",
                "AUTHORITY_ISSUE_TRAILER_INVALID",
            ),
            (
                "Issue-Spec: #33\n\nfix: trailer is not final",
                "AUTHORITY_ISSUE_TRAILER_INVALID",
            ),
            ("fix: zero\n\nIssue-Spec: #0", "AUTHORITY_ISSUE_TRAILER_INVALID"),
            (
                "Issue-Spec: #33\n  Issue-Spec: #33",
                "AUTHORITY_ISSUE_TRAILER_INVALID",
            ),
            (
                "fix: oversized\n\nIssue-Spec: #9999999999",
                "AUTHORITY_ISSUE_TRAILER_INVALID",
            ),
        )
        for message, code in cases:
            with self.subTest(message=message):
                result = self.validate(
                    commit={"sha": self.head_sha, "commit": {"message": message}}
                )
                self.assertEqual(("FAIL", code), (result.status, result.code))

        result = self.validate(
            commit={
                "sha": self.head_sha,
                "commit": {"message": "fix: valid\n\nIssue-Spec: #33\n \n"},
            }
        )
        self.assertEqual("PASS", result.status)

        result = self.validate(
            commit={
                "sha": "c" * 40,
                "commit": {"message": "fix: mismatch\n\nIssue-Spec: #33"},
            }
        )
        self.assertEqual(
            ("INCONCLUSIVE", "AUTHORITY_COMMIT_RESPONSE_INVALID"),
            (result.status, result.code),
        )

    def test_body_issue_evidence_is_exact_and_matches_the_trailer(self) -> None:
        invalid_bodies = (
            "",
            "Issue/spec: none",
            "Issue/spec: other/repository#33",
            "Issue/spec: #0",
            "Issue/spec: #9999999999",
            "Issue/spec: #33 #34",
            "Issue/spec: #33\nIssue/spec: #33",
            "Issue/spec: #33\n  Issue/spec: #33",
        )
        for body in invalid_bodies:
            with self.subTest(body=body):
                result = self.validate(live=self.pull(body=body))
                self.assertEqual(
                    ("FAIL", "AUTHORITY_BODY_ISSUE_INVALID"),
                    (result.status, result.code),
                )

        result = self.validate(live=self.pull(body="Issue/spec: #24"))
        self.assertEqual(
            ("FAIL", "AUTHORITY_BODY_ISSUE_MISMATCH"),
            (result.status, result.code),
        )

    def test_body_issue_evidence_must_be_reader_visible_markdown(self) -> None:
        invalid_bodies = (
            "<!-- Issue/spec: #33 -->",
            "<!--\nIssue/spec: #33\n-->",
            "<!--\nIssue/spec: #33",
            "<!--\n```\nIssue/spec: #33\n```\n-->",
            "```\nIssue/spec: #33\n```",
            "~~~\nIssue/spec: #33\n~~~",
            " ````python\nIssue/spec: #33\n```",
            "   ~~~~\nIssue/spec: #33\n```\n~~~~",
            "```\n<!--\nIssue/spec: #33\n-->\n```",
            "<!-- Issue/spec: #33 -->\nIssue/spec: #33",
            "```\nIssue/spec: #33\n```\nIssue/spec: #33",
            "Issue/spec: #33\n<!--",
            "Issue/spec: #33\n~~~",
            "<script>\nIssue/spec: #33\n</script>",
            "<STYLE>\nIssue/spec: #33\n</PRE>",
            "<pre>Issue/spec: #33</pre>",
            "<?governor\nIssue/spec: #33\n?>",
            "<!DECLARATION\nIssue/spec: #33\n>",
            "<![CDATA[\nIssue/spec: #33\n]]>",
            "<div>\nIssue/spec: #33\n\n",
            "<custom-tag>\nIssue/spec: #33\n\n",
            "<script>\nIssue/spec: #33",
            "<div>\nIssue/spec: #33\n\nIssue/spec: #33",
            "<!-- note -->\n<custom-tag>\nIssue/spec: #33",
            "<script>\r\nIssue/spec: #33\r\n</script>",
            "# Heading\n<custom-tag>\nIssue/spec: #33\n\n",
            "***\n<custom-tag>\nIssue/spec: #33\n\n",
            "    code\n<custom-tag>\nIssue/spec: #33\n\n",
            "<div>\n\u00a0\nIssue/spec: #33\n\n",
            "<div>\n\f\nIssue/spec: #33\n\n",
            "<script\f>\nIssue/spec: #33\n</script>",
            "<script\v>\nIssue/spec: #33\n</script>",
            "[x]: /url\n<custom-tag>\nIssue/spec: #33\n\n",
        )
        for body in invalid_bodies:
            with self.subTest(body=body):
                result = self.validate(live=self.pull(body=body))
                self.assertEqual(
                    ("FAIL", "AUTHORITY_BODY_ISSUE_INVALID"),
                    (result.status, result.code),
                )

        valid_bodies = (
            "<!-- note -->\n```\nexample\n```\nIssue/spec: #33",
            "    ```\nIssue/spec: #33",
            "Introduction\r\nIssue/spec: #33\r\n",
            "<div>example</div>\n\nIssue/spec: #33",
            "<custom-tag>  \nexample\n\nIssue/spec: #33",
            "<script>example</script>\nIssue/spec: #33",
            "<?governor?>\nIssue/spec: #33",
            "<![CDATA[example]]>\nIssue/spec: #33",
        )
        for body in valid_bodies:
            with self.subTest(body=body):
                result = self.validate(live=self.pull(body=body))
                self.assertEqual("PASS", result.status)

    def test_issue_must_exist_in_the_repository_and_not_be_a_pull_request(
        self,
    ) -> None:
        pull_request = self.repository_issue()
        pull_request["pull_request"] = {
            "url": f"{self.api}/repos/{self.repository}/pulls/33"
        }
        result = self.validate(issue=pull_request)
        self.assertEqual(
            ("FAIL", "AUTHORITY_ISSUE_IS_PULL_REQUEST"),
            (result.status, result.code),
        )

        result = self.validate(issue=self.repository_issue(number=34))
        self.assertEqual(
            ("INCONCLUSIVE", "AUTHORITY_ISSUE_RESPONSE_INVALID"),
            (result.status, result.code),
        )

        result = self.validate(issue=self.repository_issue(state="future"))
        self.assertEqual(
            ("INCONCLUSIVE", "AUTHORITY_ISSUE_RESPONSE_INVALID"),
            (result.status, result.code),
        )

        result = self.validate(issue=self.repository_issue(state="closed"))
        self.assertEqual("PASS", result.status)

        malformed_issue = self.repository_issue()
        malformed_issue.pop("repository_url")
        result = self.validate(issue=malformed_issue)
        self.assertEqual(
            ("INCONCLUSIVE", "AUTHORITY_ISSUE_RESPONSE_INVALID"),
            (result.status, result.code),
        )

        for field in ("url", "repository_url"):
            contradictory = self.repository_issue()
            contradictory[field] = f"{self.api}/repos/other/repository"
            with self.subTest(field=field):
                result = self.validate(issue=contradictory)
                self.assertEqual(
                    ("INCONCLUSIVE", "AUTHORITY_ISSUE_RESPONSE_INVALID"),
                    (result.status, result.code),
                )

        malformed_markers: tuple[object, ...] = (
            None,
            "pull request",
            {},
            {"url": f"{self.api}/repos/other/repository/pulls/33"},
        )
        for marker in malformed_markers:
            malformed_pull = self.repository_issue()
            malformed_pull["pull_request"] = marker
            with self.subTest(marker=marker):
                result = self.validate(issue=malformed_pull)
                self.assertEqual(
                    ("INCONCLUSIVE", "AUTHORITY_ISSUE_RESPONSE_INVALID"),
                    (result.status, result.code),
                )

        for code in (404, 410):
            error = HTTPError(self.api, code, "fixture", HTTPMessage(), None)
            result = self.validate(issue_error=error)
            self.assertEqual(
                ("FAIL", "AUTHORITY_ISSUE_NOT_FOUND"),
                (result.status, result.code),
            )

        for code in (301, 403, 429, 500):
            error = HTTPError(self.api, code, "fixture", HTTPMessage(), None)
            result = self.validate(issue_error=error)
            self.assertEqual(
                ("INCONCLUSIVE", "AUTHORITY_API_ERROR"),
                (result.status, result.code),
            )

    def test_absence_fails_but_transport_uncertainty_is_inconclusive(self) -> None:
        for code in (404, 410):
            error = HTTPError(self.api, code, "fixture", HTTPMessage(), None)
            result = self.validate(error=error)
            self.assertEqual(
                ("FAIL", "AUTHORITY_PR_NOT_FOUND"),
                (result.status, result.code),
            )

        for code in (404, 410):
            error = HTTPError(self.api, code, "fixture", HTTPMessage(), None)
            result = self.validate(commit_error=error)
            self.assertEqual(
                ("FAIL", "AUTHORITY_COMMIT_NOT_FOUND"),
                (result.status, result.code),
            )

        uncertain: tuple[BaseException, ...] = (
            *(
                HTTPError(self.api, code, "fixture", HTTPMessage(), None)
                for code in (302, 403, 429, 500)
            ),
            TimeoutError(),
            URLError("offline"),
            IncompleteRead(b"partial"),
            HTTPException("broken protocol"),
            json.JSONDecodeError("malformed", "{", 0),
        )
        for error in uncertain:
            with self.subTest(error=type(error).__name__):
                result = self.validate(error=error)
                self.assertEqual(
                    ("INCONCLUSIVE", "AUTHORITY_API_ERROR"),
                    (result.status, result.code),
                )

    def test_malformed_live_list_and_commit_schemas_are_inconclusive(self) -> None:
        oversized_page = [self.pull()] + [
            self.pull(number=1_000 + index, head_sha=f"{index + 1:040x}")
            for index in range(validate_pr_authority.PAGE_SIZE)
        ]
        cases = (
            self.validate(live=[]),
            self.validate(live=self.pull(state="future")),
            self.validate(pages={1: {}}),
            self.validate(pages={1: oversized_page}),
            self.validate(pages={1: [self.pull(head_sha="not-a-sha")]}),
            self.validate(pages={1: [self.pull(), self.pull()]}),
            self.validate(commit={"sha": self.head_sha, "commit": {"message": 33}}),
        )
        self.assertEqual(
            [
                ("INCONCLUSIVE", "AUTHORITY_PR_RESPONSE_INVALID"),
                ("INCONCLUSIVE", "AUTHORITY_PR_RESPONSE_INVALID"),
                ("INCONCLUSIVE", "AUTHORITY_PULL_LIST_INVALID"),
                ("INCONCLUSIVE", "AUTHORITY_PULL_LIST_INVALID"),
                ("INCONCLUSIVE", "AUTHORITY_PULL_LIST_INVALID"),
                ("INCONCLUSIVE", "AUTHORITY_PULL_LIST_UNSTABLE"),
                ("INCONCLUSIVE", "AUTHORITY_COMMIT_RESPONSE_INVALID"),
            ],
            [(result.status, result.code) for result in cases],
        )

    def test_pagination_must_prove_completion(self) -> None:
        incomplete: dict[int, object] = {}
        first_page: list[dict[str, object]] = []
        for page in range(1, validate_pr_authority.MAX_PAGES + 1):
            offset = page * validate_pr_authority.PAGE_SIZE
            page_pulls = [
                self.pull(number=offset + index, head_sha=f"{offset + index:040x}")
                for index in range(validate_pr_authority.PAGE_SIZE)
            ]
            if page == 1:
                page_pulls[0] = self.pull()
                first_page = page_pulls
            incomplete[page] = page_pulls
        result = self.validate(
            pages=incomplete,
            page_links={
                validate_pr_authority.MAX_PAGES: (
                    f"<{self.list_url(validate_pr_authority.MAX_PAGES + 1)}>"
                    '; rel="next"'
                )
            },
        )
        self.assertEqual(
            ("INCONCLUSIVE", "AUTHORITY_PAGINATION_INCOMPLETE"),
            (result.status, result.code),
        )

        completed: dict[int, object] = {1: first_page, 2: []}
        result = self.validate(pages=completed)
        self.assertEqual("PASS", result.status)

        numeric_next = self.list_url(2).replace(
            f"/repos/{self.repository}/pulls",
            f"/repositories/{self.repository_id}/pulls",
        )
        result = self.validate(
            pages={1: [self.pull()], 2: [self.pull(number=34, head_sha="c" * 40)]},
            page_links={1: f'<{numeric_next}>; rel="next"'},
        )
        self.assertEqual("PASS", result.status)

    def test_pagination_link_must_be_one_canonical_next_page(self) -> None:
        invalid_links = (
            '<https://attacker.example/pulls?page=2>; rel="next"',
            f'<{self.list_url(3)}>; rel="next"',
            f'<{self.list_url(2)}>; rel="next", <{self.list_url(2)}>; rel="next"',
            '<https://[invalid/pulls?page=2>; rel="next"',
            "malformed",
        )
        pages: dict[int, object] = {1: [self.pull()], 2: []}
        for link in invalid_links:
            with self.subTest(link=link):
                result = self.validate(pages=pages, page_links={1: link})
                self.assertEqual(
                    ("INCONCLUSIVE", "AUTHORITY_LINK_INVALID"),
                    (result.status, result.code),
                )

    def test_pagination_relations_prove_no_same_head_page_is_hidden(self) -> None:
        hidden_duplicate: dict[int, object] = {
            1: [self.pull()],
            2: [self.pull(number=34, head_sha=self.head_sha)],
        }
        last_without_next = f'<{self.list_url(2)}>; rel="last"'
        result = self.validate(
            pages=hidden_duplicate,
            page_links={1: last_without_next},
        )
        self.assertEqual(
            ("INCONCLUSIVE", "AUTHORITY_LINK_INVALID"),
            (result.status, result.code),
        )

        contradictory = (
            f'<{self.list_url(2)}>; rel="next", <{self.list_url(1)}>; rel="last"'
        )
        result = self.validate(
            pages={1: [self.pull()], 2: []},
            page_links={1: contradictory},
        )
        self.assertEqual(
            ("INCONCLUSIVE", "AUTHORITY_LINK_INVALID"),
            (result.status, result.code),
        )

        promised_last = (
            f'<{self.list_url(2)}>; rel="next", <{self.list_url(3)}>; rel="last"'
        )
        shortened_last = f'<{self.list_url(2)}>; rel="last"'
        cross_page_cases: tuple[dict[int, str | None], ...] = (
            {1: promised_last, 2: shortened_last},
            {1: promised_last, 2: None},
        )
        pages_with_hidden_duplicate: dict[int, object] = {
            1: [self.pull()],
            2: [self.pull(number=34, head_sha="c" * 40)],
            3: [self.pull(number=35, head_sha=self.head_sha)],
        }
        for links in cross_page_cases:
            with self.subTest(links=links):
                result = self.validate(
                    pages=pages_with_hidden_duplicate,
                    page_links=links,
                )
                self.assertEqual(
                    ("INCONCLUSIVE", "AUTHORITY_LINK_INVALID"),
                    (result.status, result.code),
                )

    def test_canonical_first_middle_and_final_links_complete(self) -> None:
        links: dict[int, str | None] = {
            1: (f'<{self.list_url(2)}>; rel="next", <{self.list_url(3)}>; rel="last"'),
            2: (
                f'<{self.list_url(1)}>; rel="prev", '
                f'<{self.list_url(3)}>; rel="next", '
                f'<{self.list_url(1)}>; rel="first"'
            ),
            3: (
                f'<{self.list_url(2)}>; rel="prev", '
                f'<{self.list_url(3)}>; rel="last", '
                f'<{self.list_url(1)}>; rel="first"'
            ),
        }
        result = self.validate(
            pages={
                1: [self.pull()],
                2: [self.pull(number=34, head_sha="c" * 40)],
                3: [],
            },
            page_links=links,
        )
        self.assertEqual("PASS", result.status)

    def test_all_pagination_relations_are_unique_canonical_and_bounded(self) -> None:
        invalid_links = (
            (
                f'<{self.list_url(2)}>; rel="next", '
                f'<{self.list_url(2)}>; rel="last", '
                f'<{self.list_url(2)}>; rel="last"'
            ),
            '<https://attacker.example/pulls?page=2>; rel="last"',
            f'<{self.list_url(2)}&page=2>; rel="last"',
            f'<{self.list_url(2)}>; rel="unknown"',
        )
        for link in invalid_links:
            with self.subTest(link=link):
                result = self.validate(
                    pages={1: [self.pull()], 2: []},
                    page_links={1: link},
                )
                self.assertEqual(
                    ("INCONCLUSIVE", "AUTHORITY_LINK_INVALID"),
                    (result.status, result.code),
                )

        overflow = f'<{self.list_url(validate_pr_authority.MAX_PAGES + 1)}>; rel="last"'
        result = self.validate(
            pages={1: [self.pull()]},
            page_links={1: overflow},
        )
        self.assertEqual(
            ("INCONCLUSIVE", "AUTHORITY_PAGINATION_INCOMPLETE"),
            (result.status, result.code),
        )

    def test_invalid_inputs_never_fetch(self) -> None:
        for repository, token, api_url in (
            ("../repo", "secret", self.api),
            (self.repository, "", self.api),
            (self.repository, "secret", "https://attacker.example"),
        ):
            fetch_called = False

            def fetch(_url: str, _token: str) -> validate_pr_authority.ApiResponse:
                nonlocal fetch_called
                fetch_called = True
                return validate_pr_authority.ApiResponse({})

            result = validate_pr_authority.validate_pr_authority(
                self.event(),
                repository,
                token,
                api_url,
                fetcher=fetch,
            )
            self.assertEqual("INCONCLUSIVE", result.status)
            self.assertFalse(fetch_called)

    def test_json_integer_conversion_is_bounded(self) -> None:
        maximum = b"9" * validate_pr_authority.MAX_INTEGER_DIGITS
        self.assertEqual(
            int(maximum),
            validate_pr_authority._loads_json(maximum),
        )
        with self.assertRaisesRegex(ValueError, "integer exceeds"):
            validate_pr_authority._loads_json(maximum + b"9")
        with self.assertRaisesRegex(ValueError, "duplicate key"):
            validate_pr_authority._loads_json(b'{"id": 1, "id": 2}')
        with self.assertRaisesRegex(ValueError, "invalid constant"):
            validate_pr_authority._loads_json(b'{"id": NaN}')
        with self.assertRaisesRegex(ValueError, "nesting exceeds"):
            validate_pr_authority._loads_json(b"[" * 300_000 + b"]" * 300_000)

    def test_deep_event_json_keeps_the_machine_exit_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "event.json"
            event_path.write_bytes(b"[" * 300_000 + b"]" * 300_000)
            output = io.StringIO()
            with (
                patch.dict(os.environ, {"GITHUB_EVENT_PATH": str(event_path)}),
                redirect_stdout(output),
            ):
                exit_code = validate_pr_authority.main()
        self.assertEqual(2, exit_code)
        self.assertEqual("INCONCLUSIVE", json.loads(output.getvalue())["status"])

    def test_workflow_is_trusted_and_check_name_is_unique(self) -> None:
        authority_path = PLUGIN_ROOT / ".github/workflows/governor-authority.yml"
        authority = authority_path.read_text(encoding="utf-8")
        for evidence in (
            "pull_request_target:",
            "branches: [main]",
            "contents: read",
            "issues: read",
            "pull-requests: read",
            "governor / authority",
            "runs-on: ubuntu-24.04",
            "TRUSTED_SHA: ${{ github.sha }}",
            'git remote add origin "https://github.com/${TRUSTED_REPOSITORY}.git"',
            'git -c protocol.version=2 fetch --quiet --no-tags --depth=1 origin "$TRUSTED_SHA"',
            '[[ "$(git rev-parse HEAD)" == "$TRUSTED_SHA" ]]',
            "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
            "permission-checks: write",
            "permission-contents: read",
            "permission-issues: read",
            "permission-pull-requests: read",
            "AWG_AUTHORITY_APP_ID: ${{ vars.AWG_AUTHORITY_APP_ID }}",
            "AWG_AUTHORITY_TOKEN: ${{ steps.app-token.outputs.token }}",
            "cancel-in-progress: false",
            "GITHUB_TOKEN: ${{ github.token }}",
            "python3 -B scripts/validate_pr_authority.py",
            "python3 -B scripts/publish_app_authority.py",
        ):
            self.assertIn(evidence, authority)
        permission_block = authority.split("permissions:\n", 1)[1].split("\n\n", 1)[0]
        self.assertEqual(
            "  contents: read\n  issues: read\n  pull-requests: read",
            permission_block,
        )
        for forbidden in (
            "pull_request.head",
            "refs/pull/",
            "download-artifact",
            "issues: write",
            "pull-requests: write",
            "pull_request.body",
            "actions/checkout@",
        ):
            self.assertNotIn(forbidden, authority)
        self.assertEqual(1, authority.count("permissions:"))
        self.assertEqual(1, authority.count("GITHUB_TOKEN:"))
        legacy_gate = authority.split(
            "      - name: Validate live pull request authority\n", 1
        )[1].split("      - name: Publish immutable App authority\n", 1)[0]
        self.assertNotIn("        if:", legacy_gate)
        self.assertIn(
            "        run: python3 -B scripts/validate_pr_authority.py",
            legacy_gate,
        )
        contexts = 0
        workflows = PLUGIN_ROOT / ".github/workflows"
        for workflow in (*workflows.glob("*.yml"), *workflows.glob("*.yaml")):
            contexts += workflow.read_text(encoding="utf-8").count(
                "name: governor / authority"
            )
        self.assertEqual(1, contexts)


if __name__ == "__main__":
    unittest.main()
