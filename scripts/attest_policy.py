#!/usr/bin/env python3
"""Attest a policy-validation receipt against the current policy and validator."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import validate_policy

# LLM-CONTRACT
# id: agent-work-governor.policy-attestation
# state: RECEIPT_UNREAD -> RECOMPUTED -> PASS | FAIL
# preconditions: receipt and policy paths are explicit inputs
# invariant: a PASS binds the exact policy bytes, validator bytes, schema, and findings
# failure: emit FAIL with mismatched fields and return a non-zero process status
# source: bundle:knowledge/policies/work-governor.md
# knowledge: bundle:knowledge/computations/policy-validation.md
# enforced_by: attest
# test: bundle:tests/test_contracts.py


def load_receipt(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise TypeError("receipt root must be an object")
    return value


def attest(receipt: dict[str, Any], policy: Path) -> dict[str, Any]:
    expected = validate_policy.build_receipt(policy)
    fields = (
        "policy_path",
        "policy_sha256",
        "validator_sha256",
        "schema_version",
        "valid",
        "findings",
    )
    mismatches = [
        field for field in fields if receipt.get(field) != expected.get(field)
    ]
    if receipt.get("valid") is not True:
        mismatches.append("valid")
    mismatches = sorted(set(mismatches))
    return {
        "verdict": "PASS" if not mismatches else "FAIL",
        "mismatched_fields": mismatches,
        "policy_sha256": expected["policy_sha256"],
        "validator_sha256": expected["validator_sha256"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("policy", type=Path)
    args = parser.parse_args(argv)

    try:
        result = attest(load_receipt(args.receipt), args.policy)
    except (OSError, TypeError, json.JSONDecodeError) as error:
        result = {
            "verdict": "FAIL",
            "mismatched_fields": ["receipt"],
            "error": str(error),
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
