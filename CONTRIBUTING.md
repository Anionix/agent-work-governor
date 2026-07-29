# Contributing

GitHub Issues are the work specification. Pick an Issue marked
`ready-for-agent`; blocked Issues are not implementation-ready.

1. Update local `main`, then create one branch from `origin/main`.
2. Implement only the selected task and bind it in the final commit trailer as
   `Issue-Spec: #N`.
3. Add an LLM contract comment—transition and fail-closed result—to code and
   executable configuration.
4. Run `nix flake check --no-update-lock-file --no-write-lock-file` and
   task-specific checks.
   If `flake.nix` or `flake.lock` changes, also regenerate the candidate lock
   into a temporary `--output-lock-file` with registries disabled and require
   byte equality. Commit a lock diff only when regeneration changes its bytes.
5. Review the final commit with the code-review skill and write its ignored
   receipt under `.governance/receipts/`.
6. Open one squash-merge PR, targeting roughly 200 product-diff lines.

PRs identify the task, primary sources, transition, reviewed commit, and checks.
The immutable head-commit trailer is the authority source; PR body text is
reader-facing evidence.
Resolve or obsolete all review conversations; post-merge valid findings become
linked `bug` + `review-fallout` Issues.

Issue #1 may exceed the diff target once, but remains a mechanical source-only
import gated by secret, Nix, Rust, Python, and plugin-bundle validation.
