# CI lanes

The repository separates merge identity from fast candidate feedback and slow
assurance. Check names consumed by current branch protection are unchanged.

| Lane | Trusted context | Trigger | Cancellation | Result evidence |
| --- | --- | --- | --- | --- |
| `authority-fast` | protected default-branch code | PR authority events | serialized per PR, never cancelled | `CODE_OK`, `CODE_FAIL`, or `INFRA_INCONCLUSIVE` |
| `shadow-fast` | candidate code, no App authority | PR, push, merge queue | stale runs cancelled | focused unit, Ruff, Pyrefly, and ty evidence |
| `proof-slow-nix` | candidate proof input | relevant input selected inside every PR/push; merge queue, manual, nightly always select it | stale code/base runs cancelled; metadata edits preserve running proof and inherit any replaced pending obligation | full locked Nix with duration and cold/warm state |
| `proof-slow-kani` | candidate proof input | Rust/assurance paths, merge queue, manual, nightly | stale branch runs cancelled | bounded Kani assurance; no authority |

`governor / authority` remains the protected-base authority job.
It validates the immutable Issue trailer plus a unique, reader-visible review
card bound to the live head SHA and pinned review-skill digest. Body edits rerun
this required check without executing candidate code. HTML comments are
handled fail closed; raw HTML elements are rejected instead of reproducing
GitHub's sanitizer inside the authority boundary. Review sources use raw HTTPS;
Markdown link/reference syntax is rejected.
`governor / validate` remains the legacy required name until the external App
cutover. It passes without a proof claim for irrelevant changes and otherwise
fails closed unless `proof-slow / nix` passes. `shadow-fast / validate` is
advisory. No candidate or proof lane can emit the reserved external App identity.
Repository required files, tracked ignored output, Action SHA pins, and diff
validity share one validator that runs in both the early shadow lane and the
required proof job on every new head; only expensive Nix remains path-selected.
Metadata-only PR edits keep the same required name without rerunning Nix. They
queue behind any proof already running, then use the GitHub Checks API to require
an earlier successful `governor / validate` from GitHub Actions on the identical
head SHA. Malformed or unreadable evidence fails closed; successful reconciliation
emits `proof_claim: preserved-head`. If no prior success exists,
the metadata run inherits the pending obligation and performs the normal
path-selected proof instead; malformed or unreadable API evidence remains
inconclusive.

GitHub leaves a path-filtered required workflow pending. Therefore the Nix
workflow itself is unfiltered: a small selector gates the proof job, and an
unfiltered aggregator preserves the required check. Documentation-only changes
emit `proof_claim: none` without building Nix. Kani remains path-filtered and
advisory. Merge-queue, manual, and nightly events always select the proof jobs.

Transport and daemon failures emit `INFRA_INCONCLUSIVE` and exit 2 where the
workflow can classify them. Candidate source, contract, lint, type, test, or
proof failures emit `CODE_FAIL` and exit 1. A cache hit may reduce latency but
never changes a check command or verdict.

## Timing evidence

The pre-split GitHub baseline is PR
[#110](https://github.com/Anionix/agent-work-governor/pull/110): `governor /
authority` took 5 seconds, `governor / validate` took 199 seconds, and `kani /
shadow` took 55 seconds from GitHub's job timestamps. The legacy jobs did not
emit cache state.

Each replacement lane emits `duration_seconds` and `cache_state`
(`not-applicable` for authority). The Issue #106 closeout must read these fields
and GitHub job timestamps back from the post-change PR before merge; missing
post-change timing evidence leaves the Issue incomplete.

Post-split evidence from PR
[#111](https://github.com/Anionix/agent-work-governor/pull/111) at
`7307efc794a05e6ea592e5aa05d10dbcb086414f`: authority 5 seconds,
shadow-fast 21 seconds, Kani 52 seconds, full Nix 3 minutes 32 seconds, and the
stable aggregator completed after a 1 minute 50 second queue/run interval.

Primary sources:

- [GitHub merge-group events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#merge_group)
- [GitHub path filters](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#onpushpull_requestpull_request_targetpathspaths-ignore)
- [GitHub concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)
- [GitHub CLI in workflows](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-github-cli)
