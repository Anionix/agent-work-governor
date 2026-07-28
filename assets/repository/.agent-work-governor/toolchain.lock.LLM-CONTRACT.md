# LLM-CONTRACT
# id: agent-work-governor.bootstrap-toolchain-lock
# state: TOOL_REQUIREMENT -> IMMUTABLE_PIN -> CHECKED_COMMAND | LOCK_REJECTED
# preconditions: each required tool has a version, immutable source digest, purpose, and command
# invariant: only lock-consistent tools contribute evidence to the repository gate
# failure: report REQUIRED_TOOL_NOT_LOCKED and return a non-zero process status
# source: bundle:toolchain.lock.json
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: validate_toolchain
# test: bundle:tests/test_repo_bundle.py

The repository gate calls `validate_toolchain` before it accepts owner-repository evidence.
