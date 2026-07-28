# LLM-CONTRACT
# id: agent-work-governor.active-toolchain-lock
# state: POLICY_SELECTION -> PINNED_TOOLCHAIN -> REPRODUCIBLE_CHECKS | LOCK_REJECTED
# preconditions: versions, immutable sources, digests, and validation commands are present
# invariant: an unpinned or contradictory tool definition cannot authorize repository work
# failure: policy or clean-checkout validation returns a non-zero process status
# source: repo:.agent-work-governor/toolchain.lock.json
# knowledge: repo:knowledge/policies/work-governor.md
# enforced_by: inspect_toolchain_lock
# test: repo:tests/test_contracts.py

The repository doctor calls `inspect_toolchain_lock` before accepting toolchain evidence.
