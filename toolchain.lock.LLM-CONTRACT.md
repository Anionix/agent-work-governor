# LLM-CONTRACT
# id: agent-work-governor.repository-toolchain-lock
# state: TOOL_REQUIREMENT -> IMMUTABLE_PIN -> CHECKED_COMMAND | LOCK_REJECTED
# preconditions: each quality and CI tool has a version, source, digest, and command
# invariant: only lock-consistent tools contribute evidence to the required check
# failure: toolchain validation or a locked command returns a non-zero process status
# source: repo:toolchain.lock.json
# knowledge: repo:knowledge/policies/work-governor.md
# enforced_by: inspect_toolchain_lock
# test: repo:tests/test_contracts.py

The repository doctor calls `inspect_toolchain_lock` before accepting toolchain evidence.
