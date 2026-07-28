---
{
  "type": "Playbook",
  "title": "ask-matt Bridge",
  "description": "Admit and govern a Matt Pocock flow without replacing its routing policy.",
  "tags": ["ask-matt", "adapter", "routing"],
  "status": "draft",
  "generated": {"by": "agent-work-governor/0.1.0", "at": "2026-07-28T00:00:00+09:00"},
  "stale_after": "2026-08-28",
  "sources": [
    {
      "id": "ask-matt-source",
      "resource": "https://github.com/mattpocock/skills/blob/7d694b7ae981ca221a8f759b15273fe7b5dc393e/skills/engineering/ask-matt/SKILL.md",
      "title": "ask-matt SKILL.md",
      "author": "human:mattpocock",
      "last_modified": "2026-07-13"
    }
  ]
}
---
# Trigger

Use this bridge only after the user has explicitly selected a route or invoked `ask-matt` and then
selected the returned flow. Do not invoke `ask-matt` implicitly.

# Steps

1. Compare the installed `ask-matt` digest with the locked Adapter digest.
2. Require exactly one explicit route. Include every flow-changing branch decision, such as
   `multi_session: true|false`, in the route identity.
3. Require a current `/setup-matt-pocock-skills` receipt before an engineering flow can mutate
   the repository.
4. Convert the route into a typed route stimulus.
5. Apply Governor authority, budget, context, and evidence gates.
6. Let each downstream Skill own its work.
7. Inspect returned receipts without re-running nested Skills.

# Context

- Keep `grill-with-docs`, `to-spec`, and `to-tickets` in one context.
- Start each `/implement` ticket in a fresh context.
- Treat `/handoff` as a new session and revoke the old write lease.
- Treat `/compact` as the same session.

These constraints preserve the source flow rather than reconstructing it.[^ask-matt-source]

[^ask-matt-source]: ask-matt SKILL.md
