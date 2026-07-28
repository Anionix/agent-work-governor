# Audit Checks

## Plugin

- Validate `.codex-plugin/plugin.json`.
- Reject placeholders and paths to missing components.
- Validate each Skill independently.
- Execute canonical validators only when their installed bytes match
  `references/canonical-validators.lock.json`, using isolated Python. Otherwise report
  `INCONCLUSIVE`.

## OKF

- Report OKF core and Governor profile separately.
- Restrict the Bundle root to `knowledge/`.
- Treat unsupported YAML parsing as `INCONCLUSIVE`.
- Do not reject optional-family omissions or unknown concept types as OKF core failures.

## Router

- Hash the installed `ask-matt/SKILL.md`.
- Compare it with `references/ask-matt.lock.json` and the Adapter digest.
- Report missing source as `INCONCLUSIVE`.
- Report digest drift as `ROUTER_CONTRACT_STALE`.
- Never rewrite the Adapter automatically.

## Repository

- Inspect `.agent-work-governor/policy.toml`.
- Treat missing policy as read-only authority.
- Check Matt setup artifacts without running setup.
- Apply owner-only GitHub, Nix, and toolchain checks only when scope is explicitly
  `owner_original`.

## Evidence

Include exact paths, digests, and validator results. Do not claim production readiness from static
validation alone.
