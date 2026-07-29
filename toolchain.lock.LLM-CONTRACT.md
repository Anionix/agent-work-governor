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
Rust analyzer components are release-bound by the
[Rust 1.97.1 channel manifest](https://static.rust-lang.org/dist/2026-07-16/channel-rust-1.97.1.toml);
Pyrefly uses the [1.1.1 release](https://github.com/facebook/pyrefly/releases/tag/1.1.1)
and exact wheel hashes published by PyPI.
