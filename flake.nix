{
  description = "Reproducible governance bootstrap for Agent Work Governor";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-darwin"
        "x86_64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      # LLM contract: pinned repository source -> checked derivation; a missing
      # governance file makes the derivation fail instead of producing output.
      # Sources: https://github.com/NixOS/nix and
      # https://github.com/rhysd/actionlint
      checks = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          governance =
            pkgs.runCommand "agent-work-governor-bootstrap"
              {
                src = self;
                nativeBuildInputs = [ pkgs.actionlint ];
              }
              ''
                test -f "$src/AGENTS.md"
                test -f "$src/CONTRIBUTING.md"
                test -f "$src/SECURITY.md"
                actionlint "$src/.github/workflows/governor.yml"
                touch "$out"
              '';
        }
      );

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixfmt);
    };
}
