# Repository agent contract

These rules apply to this owner-original repository.

## State and evidence

- Hand-written code and executable config require an LLM contract comment:
  allowed state transition plus fail-closed outcome.
- Schema-constrained JSON uses an adjacent `LLM-CONTRACT.md` because JSON has
  no comment syntax; tests bind every declared sidecar to its JSON file.
- GitHub Issues are task specifications; the linked Project is only a view.
- Cite primary sources. Generated lockfiles evidence environment resolution.
- Make invalid states unrepresentable. Kani covers Rust behavior; Lean covers
  the abstract model.

## Pull requests

- Branch from current `origin/main`; do not stack.
- Keep one task per PR and target about 200 product-diff lines. Contract comments
  and the one-time source-only baseline import are excluded from this target.
- Before opening a PR, run checks and the code-review skill on the final commit;
  bind both commit and skill digest in ignored `.governance/receipts/`.
- Resolve or obsolete every review conversation before merge.
- Post-merge valid findings become linked `bug` + `review-fallout` Issues.

## Repository controls

- Fail closed on missing, stale, duplicate, or contradictory evidence.
- Pin Actions to full SHAs and record release sources.
- Update `flake.nix` and `flake.lock` together.
- Do not track build/cache/venv output, receipts, `.governance/`,
  `rust/target/`, or `bin/`.
- Squash merge, keep linear history, and delete merged topic branches.
