# Agent Work Governor — Rust

This crate is the read-only Rust implementation of the plugin's static checks. Its public
Interface is one method:

```rust
Governor.check(CheckRequest) -> Result<CheckReport, GovernorError>
```

The CLI keeps the common path short:

```console
agent-work-governor check --repo .
```

Focused diagnostics are also available:

```console
agent-work-governor policy ../assets/presets/owner-original.toml
agent-work-governor okf ../knowledge
agent-work-governor contract src/lib.rs --repo-root .. --bundle-root ..
agent-work-governor bootstrap --repo /path/to/repo --plugin-root .. --preset owner-original
```

The crate never accepts `--trust-receipt`, `--skip-review`, `--skip-ast`, or caller-supplied
authority. Owner-repository checks remain fail-closed until trusted Review and AST Adapters exist.
The Rust version does not reinterpret OKF `verified` metadata or repository-local JSON as runtime
authorization.

## Bundled runtime

Installed Skills call `scripts/doctor.py`, which selects the current-host artifact through
`scripts/rust_dispatch.py`. The dispatcher rejects unsupported targets, symlinks, non-executable
files, size or SHA-256 drift, and Rust/Nix source or lock drift before execution. It never falls
back to a development artifact under `rust/target`.

The Rust binary is normative for static policy and OKF checks. Python retains the wider
plugin/GitHub/ask-matt diagnostic matrix and compares its overlapping results with Rust. The
manifest digest is an integrity binding inside the trusted plugin bundle; it is not an external
publisher signature.

Validation:

```console
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --locked
cargo audit
cargo deny --locked --all-features check advisories bans licenses sources
nix flake check .. --no-update-lock-file --no-write-lock-file
```

The Nix flake lives at the plugin root so its package includes the policy,
knowledge, script, and toolchain data consumed by the Rust binary.
It evaluates on `aarch64-darwin`, `aarch64-linux`, and `x86_64-linux`;
the pinned Nixpkgs 26.11 line no longer supports `x86_64-darwin`.
