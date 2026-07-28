---
{
  "type": "Policy",
  "title": "Agent Work Governor Policy",
  "description": "Non-overridable boundaries for governing an explicitly selected agent workflow.",
  "tags": ["agent", "governance", "policy"],
  "status": "draft",
  "generated": {"by": "agent-work-governor/0.1.0", "at": "2026-07-28T00:00:00+09:00"},
  "stale_after": "2026-10-28",
  "sources": [
    {
      "id": "okf-v02",
      "resource": "https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/3fcbb9f828c2f23d109c855ee403c3a4c81f3a96/okf/SPEC.md",
      "title": "Open Knowledge Format v0.2",
      "last_modified": "2026-07-24"
    },
    {
      "id": "ask-matt",
      "resource": "https://github.com/mattpocock/skills/blob/7d694b7ae981ca221a8f759b15273fe7b5dc393e/skills/engineering/ask-matt/SKILL.md",
      "title": "ask-matt",
      "author": "human:mattpocock",
      "last_modified": "2026-07-13"
    }
  ]
}
---
# Invariants

1. Accept an exact user-selected or router-selected flow; never infer a route from ambiguous prose.
2. Let routing policy select work and let the Governor admit, constrain, and verify it.
3. Compute effective authority by intersection and effective budgets by minimum.
4. Permit narrower repository policy but never let it widen upstream authority.
5. Keep knowledge trust, runtime authorization, and run attestation separate.
6. Require terminal evidence before declaring completion.
7. Require Matt setup evidence before admitting one of its repository engineering flows.
8. Keep external repositories read-only until a trusted external-authority Adapter verifies both
   an authority receipt and the upstream policy.
9. Require a source- and lock-bound Rust artifact for normative static checks; a Python diagnostic
   fallback must not promote a missing, unsupported, or corrupt Rust core to `PASS`.

The knowledge/runtime separation follows OKF v0.2.[^okf-v02] The routing boundary preserves
`ask-matt` as an orienting router that performs no downstream work.[^ask-matt]

[^okf-v02]: Open Knowledge Format v0.2
[^ask-matt]: ask-matt routing documentation
