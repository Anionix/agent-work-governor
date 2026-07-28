# Pre-PR Receipt

For an `owner_original` repository, write this **candidate receipt** only after the selected
implementation flow and its owned code-review step finish. PR-controlled JSON is evidence, not
authority, and the repository gate deliberately rejects it as a final attestation.

Store it at `<receipts.directory>/pre-pr.json`. The `.governance/` runtime directory is
Git-ignored; never commit the receipt to the reviewed branch:

```json
{
  "receipt_id": "<stable receipt id>",
  "session_id": "<review session id>",
  "action_kind": "code-review",
  "input_digest": "<sha256 of head_sha, branch_base_sha, and task_id>",
  "output_digest": "<sha256 of review_artifact bytes>",
  "policy_bundle_digest": "<sha256 of repository policy>",
  "capability_lease_digest": "<sha256 or null>",
  "change_intent_digest": "<sha256 or null>",
  "environment_digest": "<sha256>",
  "actor": "<OKF actor>",
  "trace_span_ids": ["<trace span id>"],
  "replay_ref": "<replayable fixed-point review reference>",
  "attester": {
    "id": "<review attester id>",
    "source_digest": "<pinned code-review Skill sha256>"
  },
  "started_at": "<ISO 8601>",
  "finished_at": "<ISO 8601>",
  "verdict": "PASS",
  "reason_code": "TWO_AXIS_REVIEW_PASSED",
  "head_sha": "<reviewed product SHA>",
  "branch_base_sha": "<fetched origin/main SHA>",
  "task_id": "<one issue or task identifier>",
  "one_task": true,
  "review_artifact": ".governance/receipts/code-review.md",
  "primary_sources": ["<primary source URI>"],
  "code_review": {
    "skill": "code-review",
    "artifact_sha": "<same reviewed work-branch SHA>",
    "standards": "PASS",
    "spec": "PASS"
  }
}
```

Create the receipt after the current product SHA has been reviewed. Any commit or worktree
change that alters the reviewed artifact invalidates it and requires a new review.

A trusted Review Adapter must independently bind the current SHA, review artifact digest,
reviewer or attester identity, review-skill source revision, and replay reference. Until that
Adapter is configured, the deterministic gate returns `CODE_REVIEW_ATTESTATION_UNTRUSTED`;
neither this file nor a model's `PASS` string can authorize `READY_FOR_PR`.
