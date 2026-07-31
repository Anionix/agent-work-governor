# LLM-CONTRACT
# id: agent-work-governor.buck2-shadow-contract
# state: DECLARED_INPUTS -> BYTE_STABLE_SHADOW_OUTPUT | BUILD_FAILURE
# preconditions: the bundled prelude exposes genrule
# invariant: every consumed repository byte is an action input and the output has no authority
# failure: the target exits non-zero and produces no accepted receipt
# source: https://buck2.build/docs/prelude/rules/core/genrule/
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: shadow_contract
# test: bundle:tests/test_contracts.py

genrule(
    name = "shadow_contract",
    srcs = glob(
        [
            ".agent-work-governor/**", ".github/**", "assets/**", "knowledge/**",
            "references/**", "rust/**", "scripts/**", "skills/**",
            "tests/**", "vendor/**", "*.json", "*.lock", "*.md", "*.toml",
            "flake.lock", "flake.nix",
        ],
        exclude = [
            "buck-out/**",
            "knowledge/references/buck2-shadow-pilot.md",
            "rust/target/**",
        ],
    ),
    out = "shadow-contract.json",
    bash = "bash $SRCDIR/scripts/buck2_shadow_probe.sh $OUT",
)
