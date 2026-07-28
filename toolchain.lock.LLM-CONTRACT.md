# LLM-CONTRACT
# id: agent-work-governor.repository-toolchain-lock
# state: TOOL_REQUIREMENTS -> UNIQUE_TYPED_CONSISTENT_PINS -> VALIDATED_CATALOG | LOCK_REJECTED
# preconditions: the schema version and complete required-ID set are explicit
# invariant: duplicate, unsupported, floating, or contradictory component pins never validate
# failure: catalog validation emits sorted stable findings and returns non-zero
# source: repo:toolchain.lock.json
# knowledge: repo:knowledge/policies/work-governor.md
# enforced_by: validate_catalog
# test: repo:tests/test_repo_bundle.py

The repository doctor calls `validate_catalog` before accepting toolchain evidence.
