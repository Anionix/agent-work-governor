# LLM-CONTRACT
# id: agent-work-governor.ask-matt-adapter
# state: LOCKED_ROUTER -> TYPED_ROUTE_MAP -> EXACT_ROUTE | CLOSED_FAILURE
# preconditions: the installed ask-matt digest equals the locked source digest
# invariant: the Adapter may describe routes but never select, substitute, or authorize one
# failure: digest or route-shape drift returns ROUTER_CONTRACT_STALE
# source: repo:adapters/ask-matt-routes.json
# knowledge: repo:knowledge/runbooks/ask-matt-bridge.md
# enforced_by: audit
# test: repo:tests/test_contracts.py

The repository doctor uses `audit` to bind the Adapter bytes to the locked ask-matt source.
