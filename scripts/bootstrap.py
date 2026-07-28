#!/usr/bin/env python3
"""Plan repository-local Agent Work Governor templates without changing files."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Literal, TypedDict

# LLM-CONTRACT
# id: agent-work-governor.bootstrap-plan
# state: DISCOVERED -> PLANNED -> DRY_RUN | CONFLICT
# preconditions: target repository path and preset are explicit
# invariant: this slice never writes; a later authorized harness must bind a CapabilityLease
# failure: report every conflicting target and return non-zero without mutation
# source: bundle:knowledge/policies/work-governor.md
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: build_plan
# test: bundle:tests/test_contracts.py


class PlanItem(TypedDict):
    source: str
    target: str
    action: Literal["conflict", "unchanged", "would_create"]


def build_plan(repo: Path, preset: str) -> tuple[list[PlanItem], list[str]]:
    repo = repo.resolve()
    plugin_root = Path(__file__).resolve().parent.parent
    source_root = plugin_root / "assets" / "repository"
    policy_override = (
        plugin_root / "assets" / "presets" / "owner-original.toml"
        if preset == "owner-original"
        else None
    )
    source_mappings = [
        (source, source.relative_to(source_root))
        for source in sorted(path for path in source_root.rglob("*") if path.is_file())
    ]
    source_mappings.extend(
        (
            (
                plugin_root / "scripts" / "validate_policy.py",
                Path(".agent-work-governor/validate_policy.py"),
            ),
            (
                plugin_root / "scripts" / "contract_blocks.py",
                Path(".agent-work-governor/contract_blocks.py"),
            ),
            (
                plugin_root / "scripts" / "toolchain_catalog.py",
                Path(".agent-work-governor/toolchain_catalog.py"),
            ),
            (
                plugin_root / "toolchain.lock.json",
                Path(".agent-work-governor/toolchain.lock.json"),
            ),
            (
                plugin_root / "knowledge" / "policies" / "work-governor.md",
                Path(".agent-work-governor/knowledge/policies/work-governor.md"),
            ),
            (
                plugin_root / "tests" / "test_repo_bundle.py",
                Path(".agent-work-governor/tests/test_repo_bundle.py"),
            ),
        )
    )

    plan: list[PlanItem] = []
    conflicts: list[str] = []

    for source, relative in source_mappings:
        actual_source = (
            policy_override
            if policy_override is not None
            and relative == Path(".agent-work-governor/policy.toml")
            else source
        )
        target = repo / relative
        parent_escapes = not target.parent.resolve().is_relative_to(repo)
        if target.is_symlink() or parent_escapes:
            action = "conflict"
            conflicts.append(str(target))
        elif target.exists():
            if (
                not target.is_file()
                or target.read_bytes() != actual_source.read_bytes()
            ):
                action = "conflict"
                conflicts.append(str(target))
            else:
                action = "unchanged"
        else:
            action = "would_create"
        plan.append(
            {
                "source": str(actual_source),
                "target": str(target),
                "action": action,
            }
        )
    return plan, conflicts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--preset", choices=("safe", "owner-original"), default="safe")
    parser.add_argument("--allow-non-git", action="store_true")
    args = parser.parse_args(argv)

    repo = args.repo.resolve()
    if not repo.is_dir():
        print(json.dumps({"status": "FAIL", "error": "repository directory not found"}))
        return 1
    if not args.allow_non_git and not (repo / ".git").exists():
        print(
            json.dumps(
                {
                    "status": "FAIL",
                    "error": "target is not a Git repository; use --allow-non-git explicitly",
                }
            )
        )
        return 1

    plan, conflicts = build_plan(repo, args.preset)
    if conflicts:
        print(
            json.dumps(
                {"status": "CONFLICT", "conflicts": conflicts, "plan": plan},
                indent=2,
                sort_keys=True,
            )
        )
        return 1

    print(
        json.dumps(
            {"status": "DRY_RUN", "mutation_count": 0, "plan": plan},
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
