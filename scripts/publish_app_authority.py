#!/usr/bin/env python3
"""Publish immutable PR authority as a GitHub App-owned check run."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import cast
from urllib.parse import urlencode

from validate_pr_authority import (
    CANONICAL_API_URL,
    MAX_GITHUB_ID,
    REPOSITORY_RE,
    SHA_RE,
    Result,
    _event_identity,
    _load_event,
    _Reject,
    _Uncertain,
    validate_immutable_pr_authority,
)
from validate_pr_authority import github_request_json as _request_json

# LLM-CONTRACT
# id: agent-work-governor.external-app-authority-check
# state: APP_TOKEN + IMMUTABLE_HEAD -> APP_BOUND_IN_PROGRESS -> VERIFIED_RESULT -> APP_BOUND_COMPLETION
# preconditions: protected-base code supplies a repository-scoped installation token
# invariant: only the expected App id may publish the unique authoritative check name
# failure: missing, duplicate, redirected, oversized, or mismatched evidence never concludes success
# source: https://github.com/github/docs/blob/72ef2d329866e5d0d52829f105f853da9bcf4260/content/rest/checks/runs.md
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: Publisher
# test: bundle:tests/test_app_authority.py

CHECK_NAME = "agent-work-governor / authoritative"
MAX_CHECK_RUNS = 100
POSITIVE_INTEGER_RE = re.compile(r"[1-9][0-9]{0,18}")

JsonObject = dict[str, object]
Requester = Callable[[str, str, str, JsonObject | None], object]


@dataclass(frozen=True)
class CheckTarget:
    repository: str
    head_sha: str
    app_id: int
    external_id: str
    details_url: str


class PublishError(RuntimeError):
    """A check run could not be bound to the expected GitHub App."""


def _mapping(value: object) -> JsonObject:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise PublishError("APP_CHECK_RESPONSE_INVALID")
    return cast(JsonObject, value)


def _positive_integer(value: object) -> int:
    if type(value) is not int or not 0 < value <= MAX_GITHUB_ID:
        raise PublishError("APP_CHECK_RESPONSE_INVALID")
    return value


class Publisher:
    def __init__(
        self,
        target: CheckTarget,
        token: str,
        *,
        requester: Requester = _request_json,
    ) -> None:
        if not token:
            raise PublishError("APP_CHECK_INPUT_INVALID")
        self.target = target
        self.token = token
        self.requester = requester
        self.repository_url = f"{CANONICAL_API_URL}/repos/{target.repository}"

    def _call(
        self,
        url: str,
        method: str,
        document: JsonObject | None = None,
    ) -> object:
        try:
            response = self.requester(url, self.token, method, document)
            return getattr(response, "document", response)
        except PublishError:
            raise
        except ValueError as error:
            code = str(error).replace("GITHUB_API", "APP_CHECK", 1)
            if code not in {"APP_CHECK_REDIRECTED", "APP_CHECK_RESPONSE_OVERSIZED"}:
                code = "APP_CHECK_API_ERROR"
            raise PublishError(code) from error
        except Exception as error:
            raise PublishError("APP_CHECK_API_ERROR") from error

    def _run_id(self, document: object) -> int:
        run = _mapping(document)
        app = _mapping(run.get("app"))
        if (
            run.get("name") != CHECK_NAME
            or run.get("head_sha") != self.target.head_sha
            or run.get("external_id") != self.target.external_id
            or _positive_integer(app.get("id")) != self.target.app_id
        ):
            raise PublishError("APP_CHECK_IDENTITY_MISMATCH")
        return _positive_integer(run.get("id"))

    def _demote(self, run_ids: list[int], reason: str) -> None:
        failed = False
        for run_id in run_ids:
            try:
                response = self._call(
                    f"{self.repository_url}/check-runs/{run_id}",
                    "PATCH",
                    {
                        "status": "completed",
                        "conclusion": "failure",
                        "details_url": self.target.details_url,
                        "output": {
                            "title": "Authority identity rejected",
                            "summary": reason,
                        },
                    },
                )
                run = _mapping(response)
                if (
                    _positive_integer(run.get("id")) != run_id
                    or run.get("status") != "completed"
                    or run.get("conclusion") != "failure"
                ):
                    raise PublishError("APP_CHECK_DEMOTION_FAILED")
            except PublishError:
                failed = True
        if failed:
            raise PublishError("APP_CHECK_DEMOTION_FAILED")

    def _existing(self) -> int | None:
        query = urlencode(
            {
                "app_id": str(self.target.app_id),
                "check_name": CHECK_NAME,
                "filter": "all",
                "per_page": str(MAX_CHECK_RUNS),
            }
        )
        document = _mapping(
            self._call(
                f"{self.repository_url}/commits/{self.target.head_sha}"
                f"/check-runs?{query}",
                "GET",
            )
        )
        runs = document.get("check_runs")
        total = document.get("total_count")
        if (
            not isinstance(runs, list)
            or type(total) is not int
            or total != len(runs)
            or total > MAX_CHECK_RUNS
        ):
            raise PublishError("APP_CHECK_LIST_INVALID")
        matches: list[int] = []
        admissive: list[int] = []
        stale: list[int] = []
        for document in runs:
            run = _mapping(document)
            app = _mapping(run.get("app"))
            if (
                run.get("name") != CHECK_NAME
                or run.get("head_sha") != self.target.head_sha
            ):
                raise PublishError("APP_CHECK_LIST_INVALID")
            if _positive_integer(app.get("id")) != self.target.app_id:
                continue
            run_id = _positive_integer(run.get("id"))
            if run.get("external_id") == self.target.external_id:
                matches.append(self._run_id(run))
                if not (
                    run.get("status") == "completed"
                    and run.get("conclusion") == "failure"
                ):
                    admissive.append(run_id)
            elif (
                run.get("status") == "completed" and run.get("conclusion") == "failure"
            ):
                continue
            else:
                stale.append(run_id)
        if stale:
            self._demote(stale, "Stale external identity cannot satisfy authority.")
        if len(matches) > 1:
            if admissive:
                self._demote(admissive, "Duplicate authoritative checks are ambiguous.")
            raise PublishError("APP_CHECK_DUPLICATE")
        if admissive:
            return admissive[0]
        return matches[0] if matches else None

    def start(self) -> int:
        document: JsonObject = {
            "name": CHECK_NAME,
            "head_sha": self.target.head_sha,
            "status": "in_progress",
            "external_id": self.target.external_id,
            "details_url": self.target.details_url,
            "output": {
                "title": "Authority evaluation started",
                "summary": "Protected-base validator is evaluating immutable PR authority.",
            },
        }
        existing = self._existing()
        if existing is None:
            response = self._call(
                f"{self.repository_url}/check-runs",
                "POST",
                document,
            )
        else:
            document.pop("name")
            document.pop("head_sha")
            response = self._call(
                f"{self.repository_url}/check-runs/{existing}",
                "PATCH",
                document,
            )
        return self._run_id(response)

    def finish(self, run_id: int, result: Result) -> None:
        conclusion = "neutral" if result.status == "PASS" else "failure"
        run_url = f"{self.repository_url}/check-runs/{run_id}"
        if self._existing() != run_id:
            raise PublishError("APP_CHECK_IDENTITY_MISMATCH")
        response = self._call(
            run_url,
            "PATCH",
            {
                "status": "completed",
                "conclusion": conclusion,
                "details_url": self.target.details_url,
                "output": {
                    "title": f"Authority {result.status.lower()}",
                    "summary": (
                        f"status={result.status} code={result.code} "
                        f"head={result.head_sha or self.target.head_sha} "
                        f"issue={result.issue_number or 'unknown'}"
                    ),
                },
            },
        )
        self._require_completion(response, run_id, conclusion)
        self._require_completion(
            self._call(run_url, "GET"),
            run_id,
            conclusion,
        )

    def _require_completion(
        self,
        document: object,
        run_id: int,
        conclusion: str,
    ) -> None:
        run = _mapping(document)
        if (
            self._run_id(run) != run_id
            or run.get("status") != "completed"
            or run.get("conclusion") != conclusion
        ):
            raise PublishError("APP_CHECK_COMPLETION_MISMATCH")


def _target(event: object, environment: dict[str, str]) -> CheckTarget:
    repository = environment.get("GITHUB_REPOSITORY", "")
    identity = _event_identity(event, repository)
    app_id_text = environment.get("AWG_AUTHORITY_APP_ID", "")
    run_id = environment.get("GITHUB_RUN_ID", "")
    server_url = environment.get("GITHUB_SERVER_URL", "")
    if (
        REPOSITORY_RE.fullmatch(repository) is None
        or SHA_RE.fullmatch(identity.head_sha) is None
        or POSITIVE_INTEGER_RE.fullmatch(app_id_text) is None
        or POSITIVE_INTEGER_RE.fullmatch(run_id) is None
        or server_url != "https://github.com"
    ):
        raise PublishError("APP_CHECK_INPUT_INVALID")
    app_id = int(app_id_text)
    if app_id > MAX_GITHUB_ID:
        raise PublishError("APP_CHECK_INPUT_INVALID")
    return CheckTarget(
        repository=repository,
        head_sha=identity.head_sha,
        app_id=app_id,
        external_id=(
            f"awg:{identity.repository_id}:{identity.pull_number}:{identity.head_sha}"
        ),
        details_url=f"{server_url}/{repository}/actions/runs/{run_id}",
    )


def _print(result: Result) -> None:
    public = asdict(result)
    public.pop("body")
    print(json.dumps(public, sort_keys=True))


def main() -> int:
    environment = dict(os.environ)
    try:
        event = _load_event(Path(environment.get("GITHUB_EVENT_PATH", "")))
        target = _target(event, environment)
        token = environment.get("AWG_AUTHORITY_TOKEN", "")
        publisher = Publisher(target, token)
        run_id = publisher.start()
    except (OSError, ValueError, PublishError, _Reject, _Uncertain):
        result = Result("INCONCLUSIVE", "APP_CHECK_START_FAILED")
        _print(result)
        return 2

    result = validate_immutable_pr_authority(
        event,
        target.repository,
        token,
        environment.get("GITHUB_API_URL", CANONICAL_API_URL),
    )
    try:
        publisher.finish(run_id, result)
    except PublishError:
        result = Result("INCONCLUSIVE", "APP_CHECK_COMPLETION_FAILED")
    _print(result)
    return {"PASS": 0, "FAIL": 1, "INCONCLUSIVE": 2}[result.status]


if __name__ == "__main__":
    raise SystemExit(main())
