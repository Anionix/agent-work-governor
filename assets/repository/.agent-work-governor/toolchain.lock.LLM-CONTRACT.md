# LLM-CONTRACT
# id: agent-work-governor.bootstrap-toolchain-lock
# state: TOOL_REQUIREMENTS -> UNIQUE_TYPED_PINS -> VALIDATED_CATALOG | LOCK_REJECTED
# preconditions: the schema version and complete required-ID set are explicit
# invariant: duplicate, unsupported, range-versioned, or mutable pins never validate
# failure: catalog validation emits sorted stable findings and returns non-zero
# source: bundle:toolchain.lock.json
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: validate_catalog
# test: bundle:tests/test_repo_bundle.py

The repository gate calls `validate_catalog` before it accepts toolchain evidence.
