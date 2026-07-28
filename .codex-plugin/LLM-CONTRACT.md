# LLM-CONTRACT
# id: agent-work-governor.plugin-manifest
# state: PLUGIN_TREE -> CANONICAL_MANIFEST -> LOADABLE | REJECTED
# preconditions: every declared Skill path exists and the manifest uses accepted fields
# invariant: malformed or unsupported manifest data never becomes an installed plugin
# failure: the pinned canonical plugin validator returns a non-zero process status
# source: repo:.codex-plugin/plugin.json
# knowledge: repo:knowledge/policies/work-governor.md
# enforced_by: validate_canonical
# test: repo:tests/test_contracts.py

The clean-checkout workflow runs `validate_canonical` before accepting the plugin manifest.
