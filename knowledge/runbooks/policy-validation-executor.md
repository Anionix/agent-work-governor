---
{
  "type": "Playbook",
  "title": "Policy Validation Executor",
  "description": "Run the locked policy validator and return its machine-readable receipt.",
  "tags": ["policy", "executor", "receipt"],
  "status": "draft",
  "generated": {"by": "agent-work-governor/0.1.0", "at": "2026-07-28T00:00:00+09:00"},
  "stale_after": "2026-10-28",
  "sources": [
    {
      "id": "okf-attestation",
      "resource": "https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/3fcbb9f828c2f23d109c855ee403c3a4c81f3a96/okf/SPEC.md#10-attested-computations-concept",
      "title": "OKF attested computations",
      "last_modified": "2026-07-24"
    }
  ]
}
---
# Steps

1. Run `python3 scripts/validate_policy.py POLICY --json`.
2. Save stdout as the runtime receipt outside `knowledge/`.
3. Run `python3 scripts/attest_policy.py RECEIPT POLICY`.
4. Treat only a `PASS` verdict as successful policy attestation.

The runtime receipt is deliberately not stored in this OKF Bundle.[^okf-attestation]

[^okf-attestation]: OKF attested computations
