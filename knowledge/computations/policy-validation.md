---
{
  "type": "Attested Computation",
  "title": "Agent Work Governor Policy Validation",
  "description": "Validate one repository policy with the locked deterministic Python validator.",
  "tags": ["policy", "validation", "attestation"],
  "status": "draft",
  "runtime": "python",
  "parameters": [
    {"name": "policy_path", "type": "path", "required": true}
  ],
  "computation": "../../scripts/validate_policy.py",
  "executor": {
    "resource": "../runbooks/policy-validation-executor.md",
    "receipt": [
      "policy_path",
      "policy_sha256",
      "validator_sha256",
      "schema_version",
      "valid",
      "findings"
    ]
  },
  "attester": {"resource": "../../scripts/attest_policy.py"},
  "generated": {"by": "agent-work-governor/0.1.0", "at": "2026-07-28T00:00:00+09:00"},
  "stale_after": "2026-10-28",
  "sources": [
    {
      "id": "okf-contract",
      "resource": "https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/3fcbb9f828c2f23d109c855ee403c3a4c81f3a96/okf/SPEC.md#102-contract-fields",
      "title": "OKF computation contract fields",
      "last_modified": "2026-07-24"
    }
  ]
}
---
# Contract

Bind only the declared `policy_path`. The executor returns content and validator digests. The
deterministic attester recomputes both and compares the complete validation result.[^okf-contract]

[^okf-contract]: OKF computation contract fields
