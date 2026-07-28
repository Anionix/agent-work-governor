## Agent Work Governor

- Use `ask-matt` or an explicit user-selected Skill to choose a route.
- Apply `govern-agent-work` after route selection; it may deny a route but must not substitute one.
- Require repository-bound Matt setup evidence before admitting a Matt engineering flow.
- Treat missing repository policy as read-only authority.
- Repository rules may narrow authority, budget, and concurrency but must not widen upstream grants.
- Keep OKF knowledge separate from runtime receipts and authorization.
- Merge `.agent-work-governor/gitignore.snippet` into `.gitignore`; never commit `.governance/`.
- Require current-artifact review and terminal postcondition evidence before completion.
- For owner-original work, keep the toolchain, Nix checks, branch base, one-task receipt, and
  review evidence pinned to the reviewed artifact.
- Treat built-in LLM Contract parsing as a shape/reference precheck only; `READY_FOR_PR` still
  requires the repository's pinned AST-to-symbol and test/proof attestation Adapter.

Merge this block into the repository's existing `AGENTS.md` after human review. Do not replace
existing repository instructions.
