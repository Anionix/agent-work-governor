#!/usr/bin/env python3
"""Bind one live pull request to an immutable, resolvable Issue authority."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass
from http.client import HTTPException, HTTPMessage, IncompleteRead
from pathlib import Path
from typing import IO, Literal, cast
from urllib.error import HTTPError
from urllib.parse import parse_qsl, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

# LLM-CONTRACT
# id: agent-work-governor.live-pr-authority
# state: EVENT_LOCATOR -> LIVE_PR -> UNIQUE_OPEN_HEAD -> COMMIT_AUTHORITY -> STABLE_RECHECK -> BODY_EVIDENCE -> REPOSITORY_ISSUE -> PASS
# preconditions: the protected-base workflow supplies its repository and read-only token
# invariant: body/trailer drift, redirects, partial pages, non-unique head, and non-Issues never admit
# failure: deterministic mismatch is FAIL=1; uncertain API evidence is INCONCLUSIVE=2
# source: https://github.com/github/docs/blob/72ef2d329866e5d0d52829f105f853da9bcf4260/content/rest/pulls/pulls.md
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: validate_pr_authority
# test: bundle:tests/test_pr_authority.py

API_VERSION = "2026-03-10"
CANONICAL_API_URL = "https://api.github.com"
MAX_EVENT_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 8_388_608
MAX_LINK_CHARS = 16_384
PAGE_SIZE = 100
MAX_PAGES = 10
MAX_PR_NUMBER = 2_147_483_647
MAX_GITHUB_ID = 9_223_372_036_854_775_807
MAX_INTEGER_DIGITS = len(str(MAX_GITHUB_ID))
REPOSITORY_RE = re.compile(r"(?=.{3,201}\Z)[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
SHA_RE = re.compile(r"[0-9a-f]{40}")
ISSUE_TRAILER_RE = re.compile(r"Issue-Spec: #(?P<number>[1-9][0-9]{0,9})")
BODY_ISSUE_RE = re.compile(r"Issue/spec:[ \t]+#(?P<number>[1-9][0-9]{0,9})[ \t]*")
LINK_RE = re.compile(r'\s*<(?P<url>[^<>\s]+)>;\s*rel="(?P<rel>[a-z]+)"\s*')


@dataclass(frozen=True)
class Result:
    status: Literal["PASS", "FAIL", "INCONCLUSIVE"]
    code: str
    pull_number: int | None = None
    head_sha: str | None = None
    issue_number: int | None = None
    body: str | None = None


@dataclass(frozen=True)
class ApiResponse:
    document: object
    link: str | None = None


Fetcher = Callable[[str, str], ApiResponse]


@dataclass(frozen=True)
class EventIdentity:
    repository: str
    repository_id: int
    pull_number: int
    head_sha: str
    base_sha: str


@dataclass(frozen=True)
class Snapshot:
    pull_number: int
    head_sha: str
    base_sha: str
    base_ref: str
    head_repository: str
    body: str
    open_pulls: tuple[tuple[int, str], ...]


class _Reject(RuntimeError):
    pass


class _Uncertain(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> Request | None:
        return None


def _bounded_json_integer(value: str) -> int:
    digits = value.removeprefix("-")
    if len(digits) > MAX_INTEGER_DIGITS:
        raise ValueError("JSON integer exceeds the bounded input")
    return int(value)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON object contains a duplicate key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"JSON contains invalid constant: {value}")


def _loads_json(payload: bytes) -> object:
    try:
        return json.loads(
            payload,
            parse_int=_bounded_json_integer,
            parse_constant=_reject_json_constant,
            object_pairs_hook=_unique_json_object,
        )
    except RecursionError as error:
        raise ValueError("JSON nesting exceeds the bounded input") from error


def _fetch_json(url: str, token: str) -> ApiResponse:
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "agent-work-governor/0.1",
            "X-GitHub-Api-Version": API_VERSION,
        },
    )
    with build_opener(_NoRedirect).open(request, timeout=10.0) as response:
        if response.geturl() != url:
            raise ValueError("GitHub API redirected")
        payload = response.read(MAX_RESPONSE_BYTES + 1)
        link = response.headers.get("Link")
    if len(payload) > MAX_RESPONSE_BYTES:
        raise ValueError("GitHub response exceeds the bounded input")
    return ApiResponse(_loads_json(payload), link)


def _mapping(value: object, code: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise _Uncertain(code)
    return cast(dict[str, object], value)


def _at(value: object, code: str, *keys: str) -> object:
    for key in keys:
        value = _mapping(value, code).get(key)
    return value


def _integer(value: object, code: str, maximum: int = MAX_GITHUB_ID) -> int:
    if type(value) is not int or not 0 < value <= maximum:
        raise _Uncertain(code)
    return value


def _string(value: object, code: str) -> str:
    if not isinstance(value, str) or not value:
        raise _Uncertain(code)
    return value


def _valid_repository(repository: str) -> bool:
    return REPOSITORY_RE.fullmatch(repository) is not None and all(
        part not in {".", ".."} for part in repository.split("/")
    )


def _event_identity(event: object, repository: str) -> EventIdentity:
    code = "AUTHORITY_EVENT_INVALID"
    observed_repository = _string(_at(event, code, "repository", "full_name"), code)
    if observed_repository.casefold() != repository.casefold():
        raise _Reject("AUTHORITY_REPOSITORY_MISMATCH")
    return EventIdentity(
        repository=repository,
        repository_id=_integer(_at(event, code, "repository", "id"), code),
        pull_number=_integer(
            _at(event, code, "pull_request", "number"), code, MAX_PR_NUMBER
        ),
        head_sha=_string(_at(event, code, "pull_request", "head", "sha"), code),
        base_sha=_string(_at(event, code, "pull_request", "base", "sha"), code),
    )


def _call(
    url: str,
    token: str,
    fetcher: Fetcher,
    *,
    absence_code: str | None = None,
) -> ApiResponse:
    try:
        return fetcher(url, token)
    except HTTPError as error:
        status = error.code
        error.close()
        if absence_code is not None and status in {404, 410}:
            raise _Reject(absence_code) from error
        raise _Uncertain("AUTHORITY_API_ERROR") from error
    except (HTTPException, IncompleteRead, OSError, TimeoutError, ValueError) as error:
        raise _Uncertain("AUTHORITY_API_ERROR") from error


def _pull_list_url(repository_url: str, page: int) -> str:
    return (
        f"{repository_url}/pulls?state=open&sort=created&direction=asc"
        f"&per_page={PAGE_SIZE}&page={page}"
    )


def _next_page(
    link: str | None,
    identity: EventIdentity,
    current_page: int,
    expected_last: int | None,
) -> tuple[int | None, int | None]:
    # LLM-CONTRACT
    # id: agent-work-governor.pagination-completeness
    # state: LINK_HEADER -> UNIQUE_RELATIONS -> CANONICAL_PAGES -> NEXT_PAGE | COMPLETE
    # preconditions: current_page and expected_last describe the bounded traversal
    # invariant: last cannot advertise or later hide unseen pages without exact next
    # failure: malformed, duplicate, contradictory, or over-bound relations are inconclusive
    # source: https://github.com/github/docs/blob/72ef2d329866e5d0d52829f105f853da9bcf4260/content/rest/using-the-rest-api/using-pagination-in-the-rest-api.md
    # knowledge: bundle:knowledge/policies/work-governor.md
    # enforced_by: _live_snapshot
    # test: bundle:tests/test_pr_authority.py
    if link is None:
        if expected_last is not None and current_page != expected_last:
            raise _Uncertain("AUTHORITY_LINK_INVALID")
        return None, expected_last
    if not isinstance(link, str) or not link or len(link) > MAX_LINK_CHARS:
        raise _Uncertain("AUTHORITY_LINK_INVALID")

    relations: dict[str, str] = {}
    for entry in link.split(","):
        match = LINK_RE.fullmatch(entry)
        if match is None:
            raise _Uncertain("AUTHORITY_LINK_INVALID")
        relation = match.group("rel")
        if relation not in {"first", "prev", "next", "last"} or relation in relations:
            raise _Uncertain("AUTHORITY_LINK_INVALID")
        relations[relation] = match.group("url")

    allowed_paths = {
        f"/repos/{identity.repository}/pulls",
        f"/repositories/{identity.repository_id}/pulls",
    }
    expected_query = {
        "state": "open",
        "sort": "created",
        "direction": "asc",
        "per_page": str(PAGE_SIZE),
    }
    pages: dict[str, int] = {}
    for relation, url in relations.items():
        try:
            target = urlsplit(url)
            query = parse_qsl(
                target.query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=8,
            )
        except ValueError as error:
            raise _Uncertain("AUTHORITY_LINK_INVALID") from error
        query_values = dict(query)
        page_value = query_values.pop("page", None)
        if (
            target.scheme != "https"
            or target.netloc != "api.github.com"
            or target.path not in allowed_paths
            or target.fragment
            or len(query) != len(expected_query) + 1
            or query_values != expected_query
            or not isinstance(page_value, str)
            or re.fullmatch(r"[1-9][0-9]{0,9}", page_value) is None
        ):
            raise _Uncertain("AUTHORITY_LINK_INVALID")
        pages[relation] = int(page_value)

    if pages.get("first", 1) != 1:
        raise _Uncertain("AUTHORITY_LINK_INVALID")
    if "prev" in pages and (current_page == 1 or pages["prev"] != current_page - 1):
        raise _Uncertain("AUTHORITY_LINK_INVALID")
    if "next" in pages and pages["next"] != current_page + 1:
        raise _Uncertain("AUTHORITY_LINK_INVALID")

    last_page = pages.get("last")
    next_page = pages.get("next")
    if last_page is not None:
        if last_page > MAX_PAGES:
            raise _Uncertain("AUTHORITY_PAGINATION_INCOMPLETE")
        if last_page < current_page or (
            expected_last is not None and last_page != expected_last
        ):
            raise _Uncertain("AUTHORITY_LINK_INVALID")
        expected_last = last_page
    if expected_last is not None and (
        (expected_last > current_page and next_page is None)
        or (next_page is not None and next_page > expected_last)
    ):
        raise _Uncertain("AUTHORITY_LINK_INVALID")
    return next_page, expected_last


def _live_snapshot(
    identity: EventIdentity,
    token: str,
    fetcher: Fetcher,
) -> Snapshot:
    code = "AUTHORITY_PR_RESPONSE_INVALID"
    repository_url = f"{CANONICAL_API_URL}/repos/{identity.repository}"
    pull_url = f"{repository_url}/pulls/{identity.pull_number}"
    pull = _mapping(
        _call(
            pull_url,
            token,
            fetcher,
            absence_code="AUTHORITY_PR_NOT_FOUND",
        ).document,
        code,
    )
    head_full_name = _string(_at(pull, code, "head", "repo", "full_name"), code)
    base_full_name = _string(_at(pull, code, "base", "repo", "full_name"), code)
    number = _integer(pull.get("number"), code, MAX_PR_NUMBER)
    head_sha = _string(_at(pull, code, "head", "sha"), code)
    base_sha = _string(_at(pull, code, "base", "sha"), code)
    base_ref = _string(_at(pull, code, "base", "ref"), code)
    state = _string(pull.get("state"), code)
    body_value = pull.get("body")
    if body_value is not None and not isinstance(body_value, str):
        raise _Uncertain(code)
    body = body_value or ""

    if state == "closed":
        raise _Reject("AUTHORITY_PR_NOT_OPEN")
    if state != "open":
        raise _Uncertain("AUTHORITY_PR_RESPONSE_INVALID")
    if number != identity.pull_number:
        raise _Reject("AUTHORITY_PULL_NUMBER_MISMATCH")
    if head_sha != identity.head_sha:
        raise _Reject("AUTHORITY_HEAD_MISMATCH")
    if base_sha != identity.base_sha:
        raise _Reject("AUTHORITY_BASE_MISMATCH")
    if (
        _integer(_at(pull, code, "base", "repo", "id"), code) != identity.repository_id
        or base_full_name.casefold() != identity.repository.casefold()
    ):
        raise _Reject("AUTHORITY_BASE_REPOSITORY_MISMATCH")
    if not _valid_repository(head_full_name):
        raise _Uncertain("AUTHORITY_PR_RESPONSE_INVALID")

    candidates: list[int] = []
    listed_pulls: list[tuple[int, str]] = []
    seen_numbers: set[int] = set()
    page = 1
    expected_last: int | None = None
    for _ in range(MAX_PAGES):
        response = _call(_pull_list_url(repository_url, page), token, fetcher)
        document = response.document
        if not isinstance(document, list) or len(document) > PAGE_SIZE:
            raise _Uncertain("AUTHORITY_PULL_LIST_INVALID")
        for raw_candidate in document:
            list_code = "AUTHORITY_PULL_LIST_INVALID"
            candidate = _mapping(raw_candidate, list_code)
            candidate_sha = _string(_at(candidate, list_code, "head", "sha"), list_code)
            candidate_number = _integer(
                candidate.get("number"),
                list_code,
                MAX_PR_NUMBER,
            )
            candidate_state = _string(candidate.get("state"), list_code)
            candidate_repo_id = _integer(
                _at(candidate, list_code, "base", "repo", "id"), list_code
            )
            if candidate_state != "open":
                raise _Uncertain("AUTHORITY_PULL_LIST_INVALID")
            if (
                candidate_repo_id != identity.repository_id
                or SHA_RE.fullmatch(candidate_sha) is None
            ):
                raise _Uncertain("AUTHORITY_PULL_LIST_INVALID")
            if candidate_number in seen_numbers:
                raise _Uncertain("AUTHORITY_PULL_LIST_UNSTABLE")
            seen_numbers.add(candidate_number)
            listed_pulls.append((candidate_number, candidate_sha))
            if candidate_sha == head_sha:
                candidates.append(candidate_number)
        next_page, expected_last = _next_page(
            response.link,
            identity,
            page,
            expected_last,
        )
        if next_page is None:
            break
        page = next_page
    else:
        raise _Uncertain("AUTHORITY_PAGINATION_INCOMPLETE")

    if candidates != [identity.pull_number]:
        raise _Reject("AUTHORITY_OPEN_HEAD_NOT_UNIQUE")
    return Snapshot(
        number,
        head_sha,
        base_sha,
        base_ref,
        head_full_name,
        body,
        tuple(listed_pulls),
    )


# Primary source: https://github.com/github/docs/blob/72ef2d329866e5d0d52829f105f853da9bcf4260/content/rest/commits/commits.md
def _commit_issue_number(
    snapshot: Snapshot,
    token: str,
    fetcher: Fetcher,
) -> int:
    commit_url = (
        f"{CANONICAL_API_URL}/repos/{snapshot.head_repository}"
        f"/commits/{snapshot.head_sha}"
    )
    document = _mapping(
        _call(
            commit_url,
            token,
            fetcher,
            absence_code="AUTHORITY_COMMIT_NOT_FOUND",
        ).document,
        "AUTHORITY_COMMIT_RESPONSE_INVALID",
    )
    if document.get("sha") != snapshot.head_sha:
        raise _Uncertain("AUTHORITY_COMMIT_RESPONSE_INVALID")
    message = _at(
        document,
        "AUTHORITY_COMMIT_RESPONSE_INVALID",
        "commit",
        "message",
    )
    if not isinstance(message, str):
        raise _Uncertain("AUTHORITY_COMMIT_RESPONSE_INVALID")
    lines = message.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    while lines and not lines[-1].strip():
        lines.pop()
    trailer_lines = [
        line for line in lines if line.lstrip().casefold().startswith("issue-spec:")
    ]
    if len(trailer_lines) != 1 or trailer_lines[0] != lines[-1]:
        raise _Reject("AUTHORITY_ISSUE_TRAILER_INVALID")
    match = ISSUE_TRAILER_RE.fullmatch(trailer_lines[0])
    if match is None:
        raise _Reject("AUTHORITY_ISSUE_TRAILER_INVALID")
    number = int(match.group("number"))
    if number > MAX_PR_NUMBER:
        raise _Reject("AUTHORITY_ISSUE_TRAILER_INVALID")
    return number


def _body_issue_number(body: str) -> int:
    # LLM-CONTRACT
    # id: agent-work-governor.visible-body-issue
    # state: LIVE_BODY -> VISIBLE | HTML_COMMENT | FENCE -> ONE_VISIBLE_FIELD
    # preconditions: body is the bounded live PR body from both stable snapshots
    # invariant: hidden, mixed, or structurally incomplete Issue/spec evidence never authorizes
    # failure: reject hidden markers, unclosed contexts, or non-canonical visible fields
    # source: https://github.com/github/cmark-gfm/blob/499789b49373bfa045d0e7547e5ee63444c77bca/test/spec.txt
    # knowledge: bundle:knowledge/policies/work-governor.md
    # enforced_by: validate_pr_authority
    # test: bundle:tests/test_pr_authority.py
    lines = body.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    authority_lines: list[str] = []
    fence_character: str | None = None
    fence_length = 0
    in_comment = False
    hidden_marker = False

    for line in lines:
        folded = line.casefold()
        content = line.lstrip(" ")
        indentation = len(line) - len(content)

        if fence_character is not None:
            hidden_marker |= "issue/spec:" in folded
            run_length = len(content) - len(content.lstrip(fence_character))
            if (
                indentation <= 3
                and run_length >= fence_length
                and not content[run_length:].strip(" ")
            ):
                fence_character = None
                fence_length = 0
            continue

        if not in_comment and indentation <= 3 and content[:1] in {"`", "~"}:
            candidate = content[0]
            run_length = len(content) - len(content.lstrip(candidate))
            info = content[run_length:]
            if run_length >= 3 and (candidate == "~" or "`" not in info):
                hidden_marker |= "issue/spec:" in folded
                fence_character = candidate
                fence_length = run_length
                continue

        starts_visible = not in_comment
        position = 0
        while position < len(line):
            if in_comment:
                end = line.find("-->", position)
                nested = line.find("<!--", position)
                boundary = len(line) if end < 0 else end
                hidden_marker |= "issue/spec:" in line[position:boundary].casefold()
                if nested >= 0 and (end < 0 or nested < end):
                    raise _Reject("AUTHORITY_BODY_ISSUE_INVALID")
                if end < 0:
                    break
                in_comment = False
                position = end + 3
                continue
            start = line.find("<!--", position)
            if start < 0:
                break
            in_comment = True
            position = start + 4

        if starts_visible and line.lstrip().casefold().startswith("issue/spec:"):
            authority_lines.append(line)

    if (
        in_comment
        or fence_character is not None
        or hidden_marker
        or len(authority_lines) != 1
    ):
        raise _Reject("AUTHORITY_BODY_ISSUE_INVALID")
    match = BODY_ISSUE_RE.fullmatch(authority_lines[0])
    if match is None:
        raise _Reject("AUTHORITY_BODY_ISSUE_INVALID")
    number = int(match.group("number"))
    if number > MAX_PR_NUMBER:
        raise _Reject("AUTHORITY_BODY_ISSUE_INVALID")
    return number


# LLM contract: stable body + immutable trailer -> SAME_REPOSITORY_ISSUE or fail closed.
# A redirect can represent an Issue transfer, so the no-redirect transport never
# silently changes repository authority.
# Primary source: https://github.com/github/docs/blob/72ef2d329866e5d0d52829f105f853da9bcf4260/content/rest/issues/issues.md
def _require_repository_issue(
    repository: str,
    issue_number: int,
    token: str,
    fetcher: Fetcher,
) -> None:
    code = "AUTHORITY_ISSUE_RESPONSE_INVALID"
    repository_url = f"{CANONICAL_API_URL}/repos/{repository}"
    issue_url = f"{repository_url}/issues/{issue_number}"
    issue = _mapping(
        _call(
            issue_url,
            token,
            fetcher,
            absence_code="AUTHORITY_ISSUE_NOT_FOUND",
        ).document,
        code,
    )
    _integer(issue.get("id"), code)
    if (
        _integer(issue.get("number"), code, MAX_PR_NUMBER) != issue_number
        or _string(issue.get("state"), code) not in {"open", "closed"}
        or _string(issue.get("url"), code).casefold() != issue_url.casefold()
        or _string(issue.get("repository_url"), code).casefold()
        != repository_url.casefold()
    ):
        raise _Uncertain(code)
    if "pull_request" in issue:
        pull_request = _mapping(issue["pull_request"], code)
        pull_url = f"{repository_url}/pulls/{issue_number}"
        if _string(pull_request.get("url"), code).casefold() != pull_url.casefold():
            raise _Uncertain(code)
        raise _Reject("AUTHORITY_ISSUE_IS_PULL_REQUEST")


def validate_pr_authority(
    event: object,
    repository: str,
    token: str,
    api_url: str,
    *,
    fetcher: Fetcher = _fetch_json,
) -> Result:
    if not _valid_repository(repository) or not token or api_url != CANONICAL_API_URL:
        return Result("INCONCLUSIVE", "AUTHORITY_INPUT_INVALID")
    try:
        identity = _event_identity(event, repository)
        if (
            SHA_RE.fullmatch(identity.head_sha) is None
            or SHA_RE.fullmatch(identity.base_sha) is None
        ):
            raise _Uncertain("AUTHORITY_EVENT_INVALID")
        first = _live_snapshot(identity, token, fetcher)
        issue_number = _commit_issue_number(first, token, fetcher)
        second = _live_snapshot(identity, token, fetcher)
        if first != second:
            raise _Reject("AUTHORITY_STATE_CHANGED")
        if _body_issue_number(second.body) != issue_number:
            raise _Reject("AUTHORITY_BODY_ISSUE_MISMATCH")
        _require_repository_issue(
            identity.repository,
            issue_number,
            token,
            fetcher,
        )
    except _Reject as error:
        return Result("FAIL", str(error))
    except _Uncertain as error:
        return Result("INCONCLUSIVE", str(error))
    return Result(
        "PASS",
        "AUTHORITY_VERIFIED",
        pull_number=second.pull_number,
        head_sha=second.head_sha,
        issue_number=issue_number,
        body=second.body,
    )


def _load_event(path: Path) -> object:
    if not path.is_file():
        raise ValueError("event payload is missing or oversized")
    with path.open("rb") as stream:
        payload = stream.read(MAX_EVENT_BYTES + 1)
    if len(payload) > MAX_EVENT_BYTES:
        raise ValueError("event payload is missing or oversized")
    return _loads_json(payload)


def main() -> int:
    try:
        event = _load_event(Path(os.environ.get("GITHUB_EVENT_PATH", "")))
    except (OSError, ValueError):
        result = Result("INCONCLUSIVE", "AUTHORITY_EVENT_INVALID")
    else:
        result = validate_pr_authority(
            event,
            os.environ.get("GITHUB_REPOSITORY", ""),
            os.environ.get("GITHUB_TOKEN", ""),
            os.environ.get("GITHUB_API_URL", CANONICAL_API_URL),
        )
    public = asdict(result)
    public.pop("body")
    print(json.dumps(public, sort_keys=True))
    return {"PASS": 0, "FAIL": 1, "INCONCLUSIVE": 2}[result.status]


if __name__ == "__main__":
    raise SystemExit(main())
