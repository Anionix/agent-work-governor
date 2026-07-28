# OKF and Runtime Boundary

Use OKF v0.2 for durable knowledge:

- policy definitions;
- runbooks;
- research findings;
- provenance, trust, lifecycle, and freshness metadata;
- attested-computation contracts.

Keep per-run events, authority grants, effect receipts, transition receipts, and attestation
verdicts outside the OKF Bundle in the runtime Receipt Ledger.

Never infer runtime authorization from OKF `verified`. Never set `verified` merely because a
runtime execution succeeded. A successful attestation proves one execution; it does not prove the
knowledge definition is still correct.

Use the plugin's [knowledge index](../../../knowledge/index.md) for progressive disclosure.
