# LLM-CONTRACT
# id: agent-work-governor.plan-golden-fixtures
# state: TYPED_PLAN_REPORT -> EXACT_GOLDEN_JSON | SERIALIZATION_DRIFT
# preconditions: fixture bindings are fixed and the toolchain digest is projected from canonical lock bytes
# invariant: the public library and CLI serialize byte-identical plan reports
# failure: the Rust integration test rejects any field, ordering, or plan digest drift
# source: repo:AGENTS.md
# knowledge: repo:knowledge/policies/work-governor.md
# enforced_by: plan_library_and_cli_match_the_golden_report
# test: repo:rust/tests/interface.rs

The success `rust-plan-report.json` and failure `rejected-plan-report.json`
files are the canonical public wire fixtures for Issue #7.
`plan_library_and_cli_match_the_golden_report` binds both public adapters to
these exact bytes. `project_toolchain_digest.py` is the only writer for each
`bindings.toolchain_sha256` field.
