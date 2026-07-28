# LLM-CONTRACT
# id: agent-work-governor.rust-check-recipes
# state: VERSIONED_RECIPE_BYTES -> DIGEST_BOUND_RUST_RECIPE_SET | RECIPE_CATALOG_REJECTED
# preconditions: schema, language, closed check and tool IDs, argv, dependencies, workdir, and timeout are explicit
# invariant: repository text never enters argv; every resolution flag and lint severity is catalog-owned; GovernanceIR remains command-free
# failure: parse_rust_recipe_catalog rejects the entire catalog without returning a partial check set
# source: repo:adapters/rust-check-recipes.v1.json
# knowledge: repo:knowledge/policies/work-governor.md
# enforced_by: parse_rust_recipe_catalog
# test: repo:rust/src/rust_adapter.rs

The catalog follows Pytra's mapping-data seam: the adapter maps typed project
facts to closed recipes, while a later harness owns execution. Exact command
semantics are accepted only by `parse_rust_recipe_catalog` and are bound to
immutable primary sources:

- rustfmt: https://github.com/rust-lang/rust/blob/8bab26f4f68e0e26f0bb7960be334d5b520ea452/src/tools/rustfmt/README.md
- Clippy CI: https://github.com/rust-lang/rust/blob/8bab26f4f68e0e26f0bb7960be334d5b520ea452/src/tools/clippy/book/src/continuous_integration/README.md
- Cargo test: https://github.com/rust-lang/cargo/blob/c980f4866141969fab6254a680546a277789d6f0/src/doc/src/commands/cargo-test.md
- cargo-audit: https://github.com/rustsec/rustsec/blob/281452c35cf0870969042374110f099a411bc185/cargo-audit/src/commands/audit.rs
- cargo-deny check: https://github.com/EmbarkStudios/cargo-deny/blob/bca0dde53651ee946720e4540b5ce2610bec8f06/docs/src/cli/check.md
- cargo-deny common flags: https://github.com/EmbarkStudios/cargo-deny/blob/bca0dde53651ee946720e4540b5ce2610bec8f06/docs/src/cli/common.md

Network access is disabled in every dependency-resolving recipe. The later
bounded harness must supply a digest-bound advisory database and isolated Cargo
home before executing `cargo-audit` or `cargo-deny`; execution is outside this
adapter's authority.
