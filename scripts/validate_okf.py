#!/usr/bin/env python3
"""Validate this plugin's JSON-compatible OKF v0.2 Bundle and strict profile."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any

# LLM-CONTRACT
# id: agent-work-governor.okf-validation
# state: DISCOVERED -> PARSED -> CORE_VERDICT + PROFILE_VERDICT
# preconditions: bundle is an explicit directory
# invariant: Governor profile errors never masquerade as OKF core-conformance errors
# failure: unsupported general YAML is INCONCLUSIVE, never a false OKF rejection
# source: https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/3fcbb9f828c2f23d109c855ee403c3a4c81f3a96/okf/SPEC.md
# knowledge: bundle:knowledge/references/okf-v0.2.md
# enforced_by: validate_bundle
# test: bundle:tests/test_contracts.py

ACTOR_RE = re.compile(
    r"^(?:human:[^\s]+|process:[^\s]+|[A-Za-z0-9_.-]+/[A-Za-z0-9_.:+-]+)$"
)
DATE_HEADING_RE = re.compile(r"^## (\d{4}-\d{2}-\d{2})$")
LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
RESERVED = {"index.md", "log.md"}


def issue(code: str, path: Path, message: str) -> dict[str, str]:
    return {"code": code, "path": str(path), "message": message}


def split_frontmatter(text: str) -> tuple[str | None, str]:
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        return None, text
    try:
        end = lines.index("---", 1)
    except ValueError:
        return None, text
    return "\n".join(lines[1:end]).strip(), "\n".join(lines[end + 1 :])


def parse_frontmatter(
    raw: str | None,
    path: Path,
) -> tuple[dict[str, Any] | None, dict[str, str] | None]:
    if raw is None:
        return None, issue("MISSING_FRONTMATTER", path, "frontmatter is required")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return None, issue(
            "YAML_PARSE_INCONCLUSIVE",
            path,
            "v0.1 validator proves only the JSON-compatible YAML profile",
        )
    if not isinstance(value, dict):
        return None, issue(
            "INVALID_FRONTMATTER_ROOT", path, "frontmatter must be a mapping"
        )
    return value, None


def valid_date(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        dt.date.fromisoformat(value)
    except ValueError:
        return False
    return True


def valid_datetime(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        # Normalize Z explicitly so Python 3.11-3.14 and the Rust validator agree.
        dt.datetime.fromisoformat(value.replace("Z", "+00:00"))  # noqa: FURB162
    except ValueError:
        return False
    return True


def valid_actor(value: Any) -> bool:
    return isinstance(value, str) and bool(ACTOR_RE.fullmatch(value))


def _profile_common(
    metadata: dict[str, Any],
    path: Path,
    errors: list[dict[str, str]],
) -> None:
    generated = metadata.get("generated")
    if not isinstance(generated, dict):
        errors.append(
            issue("PROFILE_GENERATED_REQUIRED", path, "generated mapping is required")
        )
    elif not valid_actor(generated.get("by")) or not valid_datetime(
        generated.get("at")
    ):
        errors.append(
            issue(
                "PROFILE_GENERATED_INVALID",
                path,
                "generated requires a valid actor and ISO 8601 datetime",
            )
        )

    status = metadata.get("status")
    if status not in {"draft", "stable", "deprecated"}:
        errors.append(
            issue(
                "PROFILE_STATUS_INVALID",
                path,
                "status must be draft, stable, or deprecated",
            )
        )

    if not valid_date(metadata.get("stale_after")):
        errors.append(
            issue(
                "PROFILE_STALE_AFTER_REQUIRED",
                path,
                "stale_after must be an absolute ISO date",
            )
        )

    sources = metadata.get("sources")
    if not isinstance(sources, list) or not sources:
        errors.append(
            issue("PROFILE_SOURCES_REQUIRED", path, "sources must be non-empty")
        )
    else:
        for index, source in enumerate(sources):
            if not isinstance(source, dict) or not isinstance(
                source.get("resource"), str
            ):
                errors.append(
                    issue(
                        "PROFILE_SOURCE_INVALID",
                        path,
                        f"sources[{index}].resource is required",
                    )
                )
                continue
            author = source.get("author")
            if author is not None and not valid_actor(author):
                errors.append(
                    issue(
                        "PROFILE_SOURCE_AUTHOR_INVALID",
                        path,
                        f"sources[{index}].author must follow the OKF actor convention",
                    )
                )
            last_modified = source.get("last_modified")
            if last_modified is not None and not valid_date(last_modified):
                errors.append(
                    issue(
                        "PROFILE_SOURCE_DATE_INVALID",
                        path,
                        f"sources[{index}].last_modified must be an ISO date",
                    )
                )

    verified = metadata.get("verified")
    if verified is not None:
        events = [verified] if isinstance(verified, dict) else verified
        if not isinstance(events, list) or not events:
            errors.append(
                issue(
                    "PROFILE_VERIFIED_INVALID",
                    path,
                    "verified must be a mapping or list",
                )
            )
        else:
            for index, event in enumerate(events):
                if (
                    not isinstance(event, dict)
                    or not valid_actor(event.get("by"))
                    or not valid_datetime(event.get("at"))
                ):
                    errors.append(
                        issue(
                            "PROFILE_VERIFIED_INVALID",
                            path,
                            f"verified[{index}] requires a valid actor and datetime",
                        )
                    )


def _profile_computation(
    metadata: dict[str, Any],
    body: str,
    path: Path,
    bundle: Path,
    errors: list[dict[str, str]],
) -> None:
    if not isinstance(metadata.get("runtime"), str) or not metadata["runtime"].strip():
        errors.append(
            issue("COMPUTATION_RUNTIME_REQUIRED", path, "runtime is required")
        )

    parameters = metadata.get("parameters", [])
    if not isinstance(parameters, list):
        errors.append(
            issue("COMPUTATION_PARAMETERS_INVALID", path, "parameters must be a list")
        )
    else:
        for index, parameter in enumerate(parameters):
            if not isinstance(parameter, dict):
                errors.append(
                    issue(
                        "COMPUTATION_PARAMETER_INVALID",
                        path,
                        f"parameters[{index}] must be a mapping",
                    )
                )
                continue
            if not isinstance(parameter.get("name"), str) or not isinstance(
                parameter.get("type"), str
            ):
                errors.append(
                    issue(
                        "COMPUTATION_PARAMETER_INVALID",
                        path,
                        f"parameters[{index}] requires name and type",
                    )
                )
            if not isinstance(parameter.get("required"), bool):
                errors.append(
                    issue(
                        "COMPUTATION_PARAMETER_INVALID",
                        path,
                        f"parameters[{index}].required must be boolean",
                    )
                )

    computation_path = metadata.get("computation")
    if computation_path is not None and not isinstance(computation_path, str):
        errors.append(
            issue(
                "COMPUTATION_PATH_INVALID",
                path,
                "computation must be a path string when present",
            )
        )
    has_inline = "# Computation" in body and "```" in body
    has_file = isinstance(computation_path, str) and bool(computation_path)
    if has_file == has_inline:
        errors.append(
            issue(
                "COMPUTATION_SOURCE_AMBIGUOUS",
                path,
                "provide exactly one computation path or inline computation fence",
            )
        )
    # has_file already proves the string predicate at runtime; Pyrefly 1.1.1
    # does not propagate narrowing through the named boolean.
    # Primary source: https://github.com/facebook/pyrefly/blob/b87de05834c401898c79fd9686b806c051dd3667/website/docs/error-suppressions.mdx
    # pyrefly: ignore[bad-argument-type]
    elif has_file and not _resource_exists(computation_path, path, bundle):
        errors.append(
            issue(
                "COMPUTATION_PATH_MISSING",
                path,
                f"computation path does not exist: {computation_path}",
            )
        )

    executor = metadata.get("executor")
    if (
        not isinstance(executor, dict)
        or not isinstance(executor.get("resource"), str)
        or not isinstance(executor.get("receipt"), list)
        or not executor["receipt"]
        or any(not isinstance(field, str) or not field for field in executor["receipt"])
    ):
        errors.append(
            issue(
                "COMPUTATION_EXECUTOR_INVALID",
                path,
                "executor requires resource and a non-empty receipt field list",
            )
        )
    elif not _resource_exists(executor["resource"], path, bundle):
        errors.append(
            issue(
                "COMPUTATION_EXECUTOR_MISSING",
                path,
                f"executor resource does not exist: {executor['resource']}",
            )
        )

    attester = metadata.get("attester")
    if not isinstance(attester, dict) or not isinstance(attester.get("resource"), str):
        errors.append(
            issue(
                "COMPUTATION_ATTESTER_INVALID",
                path,
                "attester.resource is required",
            )
        )
    elif not _resource_exists(attester["resource"], path, bundle):
        errors.append(
            issue(
                "COMPUTATION_ATTESTER_MISSING",
                path,
                f"attester resource does not exist: {attester['resource']}",
            )
        )


def _resource_exists(resource: str, path: Path, bundle: Path) -> bool:
    if "://" in resource:
        return True
    target = (
        bundle / resource.lstrip("/")
        if resource.startswith("/")
        else path.parent / resource
    )
    return target.resolve().exists()


def _link_warnings(body: str, path: Path, bundle: Path) -> list[dict[str, str]]:
    warnings: list[dict[str, str]] = []
    for raw_target in LINK_RE.findall(body):
        target = raw_target.split("#", 1)[0]
        if not target or "://" in target or target.startswith("mailto:"):
            continue
        resolved = (
            bundle / target.lstrip("/")
            if target.startswith("/")
            else path.parent / target
        )
        if target.endswith("/"):
            resolved /= "index.md"
        if not resolved.resolve().exists():
            warnings.append(
                issue(
                    "BROKEN_LINK_ALLOWED_BY_OKF", path, f"unresolved link: {raw_target}"
                )
            )
    return warnings


def validate_bundle(bundle: Path) -> dict[str, Any]:
    bundle = bundle.resolve()
    core_errors: list[dict[str, str]] = []
    core_inconclusive: list[dict[str, str]] = []
    profile_errors: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []

    if not bundle.is_dir():
        core_errors.append(
            issue("BUNDLE_NOT_FOUND", bundle, "bundle directory does not exist")
        )
    else:
        root_index = bundle / "index.md"
        if not root_index.is_file():
            profile_errors.append(
                issue(
                    "PROFILE_INDEX_REQUIRED",
                    root_index,
                    "Governor profile requires index.md",
                )
            )

        for path in sorted(bundle.rglob("*.md")):
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as error:
                core_errors.append(issue("DOCUMENT_READ_ERROR", path, str(error)))
                continue

            raw, body = split_frontmatter(text)
            if path.name == "index.md":
                if path == root_index:
                    if raw is None:
                        profile_errors.append(
                            issue(
                                "PROFILE_OKF_VERSION",
                                path,
                                'root index must declare okf_version "0.2"',
                            )
                        )
                    else:
                        metadata, parse_issue = parse_frontmatter(raw, path)
                        if parse_issue:
                            core_inconclusive.append(parse_issue)
                        elif (
                            metadata is not None
                            and metadata.get("okf_version") != "0.2"
                        ):
                            profile_errors.append(
                                issue(
                                    "PROFILE_OKF_VERSION",
                                    path,
                                    'root index must declare okf_version "0.2"',
                                )
                            )
                elif raw is not None:
                    core_errors.append(
                        issue(
                            "RESERVED_FRONTMATTER",
                            path,
                            "only bundle-root index.md may contain frontmatter",
                        )
                    )
                warnings.extend(_link_warnings(body, path, bundle))
                continue

            if path.name == "log.md":
                if raw is not None:
                    core_errors.append(
                        issue(
                            "RESERVED_FRONTMATTER",
                            path,
                            "log.md must not have frontmatter",
                        )
                    )
                dates: list[dt.date] = []
                for line in body.splitlines():
                    match = DATE_HEADING_RE.fullmatch(line)
                    if match:
                        try:
                            dates.append(dt.date.fromisoformat(match.group(1)))
                        except ValueError:
                            core_errors.append(
                                issue(
                                    "LOG_DATE_INVALID",
                                    path,
                                    f"invalid date heading: {line}",
                                )
                            )
                if dates != sorted(dates, reverse=True):
                    core_errors.append(
                        issue(
                            "LOG_ORDER_INVALID", path, "log dates must be newest first"
                        )
                    )
                continue

            metadata, parse_issue = parse_frontmatter(raw, path)
            if parse_issue:
                if parse_issue["code"] == "YAML_PARSE_INCONCLUSIVE":
                    core_inconclusive.append(parse_issue)
                else:
                    core_errors.append(parse_issue)
                continue

            assert metadata is not None
            concept_type = metadata.get("type")
            if not isinstance(concept_type, str) or not concept_type.strip():
                core_errors.append(
                    issue("TYPE_REQUIRED", path, "type must be a non-empty string")
                )
                continue

            _profile_common(metadata, path, profile_errors)
            if concept_type == "Attested Computation":
                _profile_computation(metadata, body, path, bundle, profile_errors)
            warnings.extend(_link_warnings(body, path, bundle))

    core_status = (
        "invalid" if core_errors else "inconclusive" if core_inconclusive else "valid"
    )
    profile_status = (
        "valid"
        if core_status == "valid" and not profile_errors
        else "inconclusive"
        if core_status == "inconclusive" and not core_errors
        else "invalid"
    )
    return {
        "bundle": str(bundle),
        "parser_profile": "JSON-compatible YAML",
        "okf_core": {
            "status": core_status,
            "errors": core_errors,
            "inconclusive": core_inconclusive,
        },
        "governor_profile": {
            "status": profile_status,
            "errors": profile_errors,
        },
        "warnings": warnings,
    }


def main(argv: list[str] | None = None) -> int:
    plugin_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "bundle", type=Path, nargs="?", default=plugin_root / "knowledge"
    )
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--core-only", action="store_true")
    args = parser.parse_args(argv)

    report = validate_bundle(args.bundle)
    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"OKF core: {report['okf_core']['status'].upper()}")
        print(f"Governor profile: {report['governor_profile']['status'].upper()}")
        for category in ("errors", "inconclusive"):
            for item in report["okf_core"][category]:
                print(f"{item['code']}: {item['path']}: {item['message']}")
        for item in report["governor_profile"]["errors"]:
            print(f"{item['code']}: {item['path']}: {item['message']}")

    core_valid = report["okf_core"]["status"] == "valid"
    profile_valid = report["governor_profile"]["status"] == "valid"
    return 0 if core_valid and (args.core_only or profile_valid) else 1


if __name__ == "__main__":
    sys.exit(main())
