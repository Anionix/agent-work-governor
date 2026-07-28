---
name: govern-agent-work
description: Apply bounded authority, budget, context, and terminal-evidence gates after the user or an explicit router has selected an agent skill or flow. Use for non-trivial repository work, multi-step implementation, delegated work, review closeout, or any run needing auditable admission and completion. Do not use this skill to choose a route or replace ask-matt, implement, tdd, code-review, research, handoff, or other domain skills.
---

# Govern Agent Work

Govern an already selected workflow. Keep routing authority, execution authority, and
verification evidence separate.

## Load the contract

Read [runtime-contract.md](references/runtime-contract.md) before admitting a mutating run.
When the selected route comes from Matt Pocock's flow, also read the
[ask-matt bridge](../../knowledge/runbooks/ask-matt-bridge.md). When producing or consuming
knowledge, read [okf-boundary.md](references/okf-boundary.md).

## Govern the selected route

1. Observe before mutating.
   - Locate the nearest `.agent-work-governor/policy.toml`.
   - Resolve repository scope from signed or human-authored configuration; never infer owner
     authority from a remote URL alone.
   - Treat a missing policy as read-only authority.
2. Require one explicit route.
   - Accept an exact selected skill or flow plus its source receipt. For a branched route,
     require the branch decision (for example `multi_session: true|false`) as part of the route
     identity.
   - Do not parse free-form `ask-matt` prose into a route.
   - If there is no route, return `ROUTE_DECISION_REQUIRED`, recommend that the user invoke
     `/ask-matt`, and emit no effect.
   - If there are multiple routes, return `AMBIGUOUS_ROUTE` and emit no effect.
3. Enforce route preconditions.
   - Before any Matt engineering flow mutates a repository, require a current trusted
     `/setup-matt-pocock-skills` receipt bound to that repository, using
     [setup-receipt.md](references/setup-receipt.md).
   - Never promote the repository-local candidate JSON to trusted evidence without its runtime
     Adapter and deterministic attester.
   - If it is missing or stale, return `SETUP_REQUIRED` and emit no effect.
4. Admit the run.
   - Intersect requested authority with global, repository, task, and runtime grants.
   - Take the minimum of their budgets.
   - Deny by default when scope, route, source digest, or required grant is unknown.
   - Permit repository writes only after an admitted `CapabilityLease`.
5. Preserve the selected flow.
   - Let the selected domain skill perform its own work.
   - Never substitute a denied route with another route.
   - Never invoke `/tdd` or `/code-review` a second time when `/implement` already owns them.
   - Treat subagent output as evidence, never as authority.
6. Apply the route's context contract.
   - Keep `grill-with-docs -> to-spec -> to-tickets` in one context lease.
   - Start each unblocked `/implement` ticket in a fresh context.
   - Treat `/handoff` as a new session that revokes the old write lease.
   - Treat `/compact` as the same session with a new context revision.
7. Verify before completion.
   - Require deterministic predicates and current-artifact evidence.
   - Require the selected flow's own TDD and code-review receipts when applicable.
   - Require a terminal transition receipt and satisfied postcondition evidence.
   - Do not call a compensated or unknown external effect successful.
   - For an owner-original pre-PR transition, follow
     [pre-pr-receipt.md](references/pre-pr-receipt.md) and bind the receipt to the reviewed SHA.

## Stop conditions

Stop without side effects when any of these is true:

- `ROUTE_DECISION_REQUIRED`
- `AMBIGUOUS_ROUTE`
- `ROUTER_CONTRACT_STALE`
- `SETUP_REQUIRED`
- `POLICY_INVALID`
- `AUTHORITY_DENIED`
- `BUDGET_EXHAUSTED`
- `COORDINATION_UNAVAILABLE`
- `POSTCONDITION_UNKNOWN`

Report the blocking predicate, the evidence inspected, and the smallest user action that can
unblock it. Do not silently relax policy.

## Return a bounded result

Return only:

- selected route and source digest;
- effective authority and budget;
- current state;
- effects performed or denied;
- evidence and receipt references;
- terminal verdict or one blocking condition;
- the smallest safe `unblock_action`, or `null` at a terminal verdict.
