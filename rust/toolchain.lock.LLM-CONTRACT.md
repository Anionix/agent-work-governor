# LLM-CONTRACT
# id: agent-work-governor.rust-toolchain-lock
# state: RUST_POLICY -> PINNED_COMPONENTS -> CHECKED_TOOLCHAIN | LOCK_REJECTED
# preconditions: Rust, Nix, cargo-audit, and cargo-deny entries are immutable
# invariant: unavailable or digest-mismatched tooling cannot produce a passing receipt
# failure: the Rust dispatcher or repository checks return a non-zero process status
# source: repo:rust/toolchain.lock.json
# knowledge: repo:knowledge/policies/work-governor.md
# enforced_by: resolve_binary
# test: repo:rust/tests/interface.rs

The Rust dispatcher calls `resolve_binary` before it executes a bundled release artifact.
