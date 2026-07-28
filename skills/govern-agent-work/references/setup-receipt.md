# Matt Setup Receipt

After `/setup-matt-pocock-skills` completes, write candidate evidence to
`<receipts.directory>/setup-matt-pocock-skills.json`:

```json
{
  "receipt_id": "<stable receipt id>",
  "session_id": "<setup session id>",
  "action_kind": "setup-matt-pocock-skills",
  "input_digest": "<sha256 of setup inputs>",
  "output_digest": "<sha256 of configured artifacts>",
  "policy_bundle_digest": "<sha256>",
  "capability_lease_digest": "<sha256 or null>",
  "change_intent_digest": "<sha256 or null>",
  "environment_digest": "<sha256>",
  "actor": "<OKF actor>",
  "trace_span_ids": ["<trace span id>"],
  "replay_ref": "<replayable setup evidence>",
  "attester": {
    "id": "<trusted attester id>",
    "source_digest": "<sha256>"
  },
  "started_at": "<ISO 8601>",
  "finished_at": "<ISO 8601>",
  "verdict": "PASS",
  "reason_code": "SETUP_POSTCONDITION_SATISFIED",
  "repository": "<absolute canonical repository path>",
  "ask_matt_sha256": "<digest from the bundled Adapter>"
}
```

The file does not grant write authority and cannot attest itself. A trusted runtime Adapter must
verify the input/output digests, actor, attester revision, and replay reference before the
Governor may treat the setup precondition as satisfied. The static doctor can only report the
file and setup artifacts as candidate evidence.
