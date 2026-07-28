---
name: check-governor-policy
description: Audit Agent Work Governor policy, OKF knowledge, ask-matt adapter drift, and repository prerequisites without changing files. Use when the user asks to check, diagnose, score, or validate governance setup, before enabling repository mutations, or after updating the plugin, router, policy, or knowledge bundle.
---

# Check Governor Policy

Perform a bounded, read-only audit. Never install, initialize, repair, or rewrite repository
configuration while this skill is active.

## Run the checks

1. Read [checks.md](references/checks.md).
2. Resolve `<plugin-root>` as two directories above this `SKILL.md`, then run:

   ```bash
   python3 <plugin-root>/scripts/doctor.py --repo <repository-path> --json
   ```

   The doctor auto-selects the bundled Rust binary for the current host, verifies its source,
   lockfile, size, and SHA-256 bindings, and uses it as the normative policy/OKF core. Python
   checks remain supplemental; they must never turn a missing or corrupt Rust core into `PASS`.
   Never run a binary from `rust/target`.
   Exit `0` means `PASS` or non-blocking `WARN`, exit `1` means `FAIL`, and exit `2` means
   `INCONCLUSIVE`. Treat every nonzero exit as non-admission.

3. Keep these verdicts separate:
   - Codex Plugin manifest validity;
   - bundled Rust artifact integrity and host support;
   - Rust policy/OKF core validity and Python/Rust differential status;
   - OKF v0.2 structural validity;
   - Governor OKF profile validity;
   - repository policy validity;
   - `ask-matt` source-lock status;
   - repository setup readiness.
4. Treat inaccessible data as `INCONCLUSIVE`, not `PASS`.
5. Report the smallest safe next action. Do not run that action.

## Never conflate these signals

- OKF `verified` is a knowledge trust signal, not authorization.
- An OKF `executor.receipt` field declares a receipt shape; it is not a runtime receipt.
- A valid policy document does not prove that a run followed the policy.
- A passing agent review does not replace deterministic verification.
- A missing `index.md`, unknown OKF `type`, unknown key, or broken link is not by itself an OKF
  core-conformance failure.

## Return the audit

Return a compact matrix with `PASS`, `FAIL`, `WARN`, or `INCONCLUSIVE`, followed by evidence
paths and recommended next actions. State explicitly that no files were changed.
