# Runtime Contract

## Admission

```text
requested route
  + source receipt
  + requested effects
  + policy digests
  + runtime grants
  -> ADMITTED | DENIED | AWAITING_INPUT
```

Compute effective authority as an intersection and effective budgets as minima. A repository
policy may narrow an upstream grant but may not widen it.

## States

```text
ACTIVE
  | BLOCKED { blocker }
  | AWAITING_INPUT { request }
  | TERMINAL { verdict, transition_receipt }
```

Treat policy denial as a terminal run with a denial receipt. Treat missing route selection as
`AWAITING_INPUT`, because the user can select a route without changing policy.

## Effects

Require an operation registry entry for every effect. Classify each operation as `read_only` or
`side_effecting`. Dispatch a side effect only when it is provider-idempotent or has deterministic
reconciliation. Block an unknown external outcome.

## Completion

Completion requires all of:

- the selected flow reached its own terminal condition;
- required deterministic predicates pass;
- current-artifact review evidence exists;
- every requested postcondition is `Satisfied`;
- the terminal state and transition receipt were committed together.

An owner-original `READY_FOR_PR` transition additionally requires the current-SHA receipt
defined in [pre-pr-receipt.md](pre-pr-receipt.md).

`Reverted` and `Unknown` postconditions are not successful completion.

## Result

```text
GovernedResult {
  route
  source_digest
  effective_authority
  effective_budget
  state
  effect_receipts
  evidence
  verdict_or_blocker
  unblock_action
}
```

For `ROUTE_DECISION_REQUIRED`, serialize the bounded result with these exact null and zero
defaults:

```json
{
  "route": null,
  "source_digest": null,
  "effective_authority": "read_only",
  "effective_budget": {
    "side_effecting_operations": 0,
    "delegations": 0,
    "repair_rounds": 0
  },
  "state": "AWAITING_INPUT",
  "effect_receipts": [],
  "evidence": ["No explicit route or source receipt was provided."],
  "verdict_or_blocker": "ROUTE_DECISION_REQUIRED",
  "unblock_action": "Invoke /ask-matt and explicitly select one route."
}
```

For any later blocker, preserve every already-established field: in particular, retain the
selected route and source digest for `SETUP_REQUIRED`, `POLICY_INVALID`, `AUTHORITY_DENIED`, and
budget or coordination blockers. Set only unavailable fields to `null` or zero. `evidence` must
be a non-empty list of observations actually inspected; the example sentence is not a
placeholder to copy for other blockers.
