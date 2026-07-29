# LLM-CONTRACT
# id: agent-work-governor.python-check-recipes
# state: VERSIONED_RECIPE_BYTES -> DIGEST_BOUND_PYTHON_RECIPE_DAG | RECIPE_CATALOG_REJECTED
# preconditions: schema, language, check IDs, tool IDs, typed argv atoms, artifact flow, dependencies, workdir, and timeout are explicit
# invariant: consumer text never enters argv; artifact paths are late-bound to a harness-owned run; command-free GovernanceIR remains authoritative
# failure: the Rust adapter rejects the entire catalog without returning a partial check set
# source: repo:adapters/check-recipes.v1.json
# knowledge: repo:knowledge/policies/work-governor.md
# enforced_by: parse_recipe_catalog
# test: repo:rust/src/python_adapter.rs

The catalog follows Pytra's mapping-data seam and keeps executable recipes out
of emitters. Rust `parse_recipe_catalog` validates its exact digest, closed
identifiers, and typed artifact flow before any check set can resolve. Command
semantics are bound to these immutable primary sources:

- uv export: https://github.com/astral-sh/uv/blob/fece32fc54b0e6fb6a031d3c80397cc4afb25737/docs/concepts/projects/export.md
- uv `--all-packages` workspace semantics: https://github.com/astral-sh/uv/blob/fece32fc54b0e6fb6a031d3c80397cc4afb25737/crates/uv-cli/src/lib.rs#L4735-L4743
- uv lock: https://github.com/astral-sh/uv/blob/fece32fc54b0e6fb6a031d3c80397cc4afb25737/docs/concepts/projects/sync.md
- Ruff: https://github.com/astral-sh/ruff/blob/a2635fd8f39e1d34ce8074cb486809426148f3e9/docs/configuration.md
- ty: https://github.com/astral-sh/ty/blob/5e64a131b436a4e1f40e6317c526f4fc73fab38b/docs/reference/cli.md
- unittest: https://github.com/python/cpython/blob/c63aec69bd59c55314c06c23f4c22c03de76fe45/Doc/library/unittest.rst
- pip-audit: https://github.com/pypa/pip-audit/blob/8894eb8cee033531a1fbd9f2fb160892531c14e3/README.md
