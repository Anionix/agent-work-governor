# Shadow Plan/Verify

`governor-shadow` observes the Plan → bounded harness → Verify path after the
legacy `governor` workflow succeeds. It runs on Linux x86-64, Linux ARM64, and
macOS ARM64. The legacy check remains the only merge authority.

Each job separates two trees:

- `control/` is checked out at the default-branch workflow SHA. Only its locked
  Nix environment, packaged Governor binary, dispatcher, harness, policy, and
  toolchain run as trusted code.
- `subject/` is checked out from the observed repository at the exact event head
  SHA, copied into the root-owned read-only Nix store, and executed only as
  `nobody` through the trusted harness. Its Nix, scripts, Actions, manifests, and
  receipts never establish trust.

Rust checks use a separate `shadow-inputs` Nix output containing the exact
control `Cargo.lock` vendor closure and pinned RustSec database. The harness
rejects candidate lock drift and Cargo configuration before execution; only the
Cargo target and coordination lock files are writable by `nobody`.

Each matrix job emits one sorted schema-`0.2` JSON object to its log and job
summary:

- `PARITY_EVIDENCE`: Plan, bounded execution, and Rust Verify all completed
  successfully.
- `SHADOW_REGRESSION`: any observed stage rejected or failed.
- `SHADOW_INCONCLUSIVE`: trusted infrastructure or artifact verification could
  not produce a decision.

The JSON binds the control and candidate SHA, candidate repository, candidate
archive and store digests, packaged manifest digest, runner, workflow-run ID and
attempt, legacy conclusion, trusted Rust-input digest, all stage exits,
structured reason codes, the nullable trusted network-preflight stage, and the
plan, receipt, evidence-set, and Verify-report digests. Runtime receipts remain
outside OKF.

Schema `0.2` adds `network_preflight_stage`; schema `0.1` shadow evidence did
not contain that field.

## Promotion criteria

Promotion requires a separate Issue and protection-rule change after all three
targets show reproducible parity across at least 30 consecutive successful
legacy runs, with no unresolved security review or unexplained divergence.
Promotion must keep event identity outside repository-local JSON and must never
replace the legacy gate in the same pull request.

Primary sources:

- [GitHub `workflow_run` security boundary](https://github.com/github/docs/blob/ee27de73e024106c5cf1f3938cf00bb477252862/content/actions/reference/workflows-and-actions/events-that-trigger-workflows.md)
- [GitHub-hosted runner labels](https://github.com/github/docs/blob/ee27de73e024106c5cf1f3938cf00bb477252862/content/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job.md)
- [SLSA verification model](https://github.com/slsa-framework/slsa/blob/ae7fc76215004e8fae250c877eff8919bf048e3b/spec/verifying-artifacts.md)
- [Cargo source replacement](https://github.com/rust-lang/cargo/blob/c980f4866141969fab6254a680546a277789d6f0/src/doc/src/reference/source-replacement.md)
- [Pinned RustSec advisory database](https://github.com/RustSec/advisory-db/commit/7c7ccac53056b87f69ac677f15ea2d9a98a6f8e2)
