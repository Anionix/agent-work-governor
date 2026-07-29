#!/usr/bin/env python3
"""Execute one verified validator with one private pure-Python YAML snapshot."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

# LLM-CONTRACT
# id: agent-work-governor.canonical-runtime-runner
# state: PRIVATE_SNAPSHOTS -> VERIFIED_ISOLATED_IMPORT -> VALIDATOR_EXIT | CLOSED_FAILURE
# preconditions: the parent created private runner, runtime, and validator snapshots
# invariant: only matching bytes and pure-Python YAML from the runtime snapshot may execute
# failure: exit 86 for runtime failure or 87 for validator snapshot drift
# source: bundle:references/canonical-runtime.lock.json
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: main
# test: bundle:tests/test_contracts.py

RUNTIME_FAILURE = 86
VALIDATOR_FAILURE = 87


def main(argv: list[str]) -> int:
    if len(argv) != 6:
        return RUNTIME_FAILURE
    runtime, validator, target, runtime_sha, validator_sha = argv[1:]
    runtime_bytes = Path(runtime).read_bytes()
    validator_bytes = Path(validator).read_bytes()
    if hashlib.sha256(runtime_bytes).hexdigest() != runtime_sha:
        print("VALIDATOR_RUNTIME_SNAPSHOT_MISMATCH", file=sys.stderr)
        return RUNTIME_FAILURE
    if hashlib.sha256(validator_bytes).hexdigest() != validator_sha:
        print("VALIDATOR_SNAPSHOT_MISMATCH", file=sys.stderr)
        return VALIDATOR_FAILURE

    sys.path.insert(0, runtime)
    try:
        import yaml

        origin = getattr(yaml, "__file__", None)
        isolated = (
            isinstance(origin, str)
            and origin.startswith(runtime + "/yaml/")
            and getattr(yaml, "__with_libyaml__", None) is False
        )
    except Exception as error:  # noqa: BLE001 - normalize locked runtime failures
        print(
            f"VALIDATOR_RUNTIME_IMPORT_FAILED:{type(error).__name__}",
            file=sys.stderr,
        )
        return RUNTIME_FAILURE
    if not isolated:
        print("VALIDATOR_RUNTIME_ISOLATION_BREACH", file=sys.stderr)
        return RUNTIME_FAILURE

    sys.argv = [validator, target]
    namespace = {"__name__": "__main__", "__file__": validator}
    exec(  # noqa: S102 - executes the digest-verified locked validator snapshot
        compile(validator_bytes, validator, "exec"),
        namespace,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
