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

# LLM-CONTRACT
# id: agent-work-governor.owner-scope-differential-corpus
# state: VERSIONED_CASE_BYTES -> RUST_ROUTE + PYTHON_ADAPTER_ROUTE -> EXACT_PARITY | CLOSED_FAILURE
# preconditions: the test harness materializes one shared evidence snapshot per declared case
# invariant: neither route may widen policy, signed receipt, or runtime authority
# failure: unknown schema, omitted case, malformed output, route failure, or any mismatch fails the test
# source: doi:10.17487/RFC8785
# knowledge: repo:knowledge/policies/work-governor.md
# enforced_by: owner_scope_differential_acceptance
# test: repo:rust/tests/owner_scope.rs

`owner-scope-differential.json` is the Issue #107 corpus. Expected values are
reader-visible evidence only; both executable routes must independently match
them from the same materialized policy, receipt, public-key, and argument bytes.
The `owner_scope_differential_acceptance` test rejects schema drift or omitted
cases and emits one identity-bound success record only after both routes agree.
