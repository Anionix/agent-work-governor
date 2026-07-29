"""Validate compact LLM state-transition contract comment blocks."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlparse

# LLM-CONTRACT
# id: agent-work-governor.contract-block-parser
# state: SOURCE -> COMMENT_BLOCKS -> VALID | INVALID
# preconditions: UTF-8 source text with language comment syntax
# invariant: a marker alone never proves a state-transition contract
# failure: return a stable diagnostic string without changing source text
# source: bundle:knowledge/policies/work-governor.md
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: contract_diagnostic
# test: bundle:tests/test_repo_bundle.py

COMMENT_RE = re.compile(r"^\s*(?:#|//+|--|/\*+|\*+)\s*(.*?)\s*(?:\*/)?\s*$")
REQUIRED_FIELDS = {
    "id",
    "state",
    "preconditions",
    "invariant",
    "failure",
    "source",
    "knowledge",
    "enforced_by",
    "test",
}
FIELD_RE = re.compile(
    r"^(id|state|preconditions|invariant|failure|source|knowledge|enforced_by|test)"
    r"\s*:\s*(.+)$",
    re.IGNORECASE,
)


def parsed_contracts(source: str) -> list[dict[str, str]]:
    lines = source.splitlines()
    contracts: list[dict[str, str]] = []
    for marker_index, line in enumerate(lines):
        marker = COMMENT_RE.match(line)
        if marker is None or marker.group(1).strip().upper() != "LLM-CONTRACT":
            continue
        fields: dict[str, str] = {}
        for candidate in lines[marker_index + 1 : marker_index + 17]:
            comment = COMMENT_RE.match(candidate)
            if comment is None:
                if fields:
                    break
                continue
            field = FIELD_RE.match(comment.group(1).strip())
            if field:
                fields[field.group(1).lower()] = field.group(2).strip()
        contracts.append(fields)
    return contracts


def contract_diagnostic(source: str) -> str | None:
    contracts = parsed_contracts(source)
    if not contracts:
        return "missing LLM-CONTRACT comment marker"

    missing_sets: list[set[str]] = []
    identifiers: set[str] = set()
    for fields in contracts:
        missing = REQUIRED_FIELDS - fields.keys()
        if missing:
            missing_sets.append(missing)
            continue
        if "->" not in fields["state"]:
            return "state field must contain a transition arrow (->)"
        identifier = fields["id"]
        if identifier in identifiers:
            return f"contract id must be unique within the file: {identifier}"
        identifiers.add(identifier)
    if missing_sets:
        names = ", ".join(sorted(min(missing_sets, key=len)))
        return f"contract block is missing required fields: {names}"
    return None


def has_valid_contract(source: str) -> bool:
    return contract_diagnostic(source) is None


def _safe_relative_path(raw_path: str) -> PurePosixPath | None:
    decoded = unquote(raw_path)
    if not decoded or "\x00" in decoded or "\\" in decoded or decoded.startswith("/"):
        return None
    parts = decoded.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return None
    return PurePosixPath(*parts)


def _immutable_external_source(reference: str) -> bool:
    if reference.startswith("doi:"):
        return bool(re.fullmatch(r"doi:10\.\d{4,9}/\S+", reference))
    if reference.startswith("arxiv:"):
        return bool(
            re.fullmatch(
                r"arxiv:(?:\d{4}\.\d{4,5}|[a-z-]+/\d{7})v[1-9]\d*",
                reference,
                re.IGNORECASE,
            )
        )
    parsed = urlparse(reference)
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        return False
    return bool(re.search(r"/blob/[0-9a-f]{40}/", parsed.path, re.IGNORECASE))


def resolve_contract_reference(
    reference: str,
    *,
    repo_root: Path,
    bundle_root: Path,
    allow_external: bool,
) -> tuple[Path | None, str | None]:
    """Resolve an explicit contract URI without relying on cwd or file location."""
    if allow_external and _immutable_external_source(reference):
        return None, None

    scheme, separator, raw_path = reference.partition(":")
    roots = {"repo": repo_root.resolve(), "bundle": bundle_root.resolve()}
    if not separator or scheme not in roots:
        if allow_external and (reference.startswith(("https:", "doi:", "arxiv:"))):
            return None, "external source locator must be immutable"
        return None, "reference must use the bundle: or repo: scheme"

    relative = _safe_relative_path(raw_path)
    if relative is None:
        return None, "reference contains an unsafe path"
    base = roots[scheme]
    target = (base / Path(*relative.parts)).resolve()
    if not target.is_relative_to(base):
        return None, "reference escapes its declared root"
    if not target.is_file():
        return None, "reference does not name an existing regular file"
    return target, None


def source_without_standalone_comments(source: str) -> str:
    """Mask standalone comments while preserving line boundaries."""
    return "\n".join(
        "" if COMMENT_RE.match(line) is not None else line
        for line in source.splitlines()
    )


def enforcement_token_is_present(source: str, symbol: str) -> bool:
    """Check only that a token occurs outside standalone contract metadata."""
    executable_text = source_without_standalone_comments(source)
    return re.search(rf"\b{re.escape(symbol)}\b", executable_text) is not None
