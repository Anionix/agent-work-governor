{
  description = "Reproducible Agent Work Governor Rust validator";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      forAllSystems =
        function:
        nixpkgs.lib.genAttrs systems (
          system:
          function (
            import nixpkgs {
              inherit system;
              overlays = [ rust-overlay.overlays.default ];
            }
          )
        );
    in
    {
      packages = forAllSystems (
        pkgs:
        let
          rust = pkgs.rust-bin.stable."1.97.1".default.override {
            extensions = [
              "clippy"
              "rustfmt"
            ];
          };
          rustPlatform = pkgs.makeRustPlatform {
            cargo = rust;
            rustc = rust;
          };
          python = pkgs.python3.withPackages (packages: [ packages.pyyaml ]);
        in
        {
          default = rustPlatform.buildRustPackage {
            pname = "agent-work-governor";
            version = "0.1.0";
            src = self;
            cargoRoot = "rust";
            buildAndTestSubdir = "rust";
            cargoLock.lockFile = ./rust/Cargo.lock;
            doCheck = true;
            nativeCheckInputs = [
              python
              pkgs.actionlint
              pkgs.gitMinimal
              pkgs.gitleaks
              pkgs.ruff
              pkgs.ty
            ];
            preCheck = ''
              cd rust
              cargo fmt --check
              cargo clippy --all-targets --all-features --offline -- -D warnings
              cd ..
              python -B -m unittest discover -s tests
              python -B scripts/validate_okf.py knowledge --json
              python -B scripts/validate_policy.py \
                assets/presets/owner-original.toml --json
              ruff format --check .
              ruff check .
              ty check
              actionlint .github/workflows/governor.yml \
                assets/repository/.github/workflows/agent-work-governor.yml
              gitleaks dir . --no-banner --redact --exit-code 1
            '';
            postInstall = ''
              bundle="$out/share/agent-work-governor"
              mkdir -p "$bundle"
              cp -R "$src/." "$bundle/"
            '';
            postFixup = ''
              bundle="$out/share/agent-work-governor"
              target="${pkgs.stdenv.hostPlatform.rust.rustcTarget}"
              relative_binary="bin/$target/agent-work-governor"
              install -Dm755 "$out/bin/agent-work-governor" "$bundle/$relative_binary"
              python -B "$bundle/scripts/package_runtime.py" \
                --plugin-root "$bundle" \
                --relative-binary "$relative_binary" \
                --target "$target" \
                --component-version "0.1.0" \
                --rustc-version "rustc ${rust.version}"
              PYTHONDONTWRITEBYTECODE=1 python -B -m unittest discover \
                -s "$bundle/tests"
              test ! -e "$bundle/rust/target"
              test ! -e "$bundle/.governance"
              test ! -e "$bundle/.venv"
            '';
          };
        }
      );

      checks = forAllSystems (pkgs: {
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      });

      devShells = forAllSystems (
        pkgs:
        let
          rust = pkgs.rust-bin.stable."1.97.1".default.override {
            extensions = [
              "clippy"
              "rustfmt"
            ];
          };
          python = pkgs.python3.withPackages (packages: [ packages.pyyaml ]);
        in
        {
          default = pkgs.mkShellNoCC {
            packages = [
              rust
              python
              pkgs.actionlint
              pkgs.cargo-audit
              pkgs.cargo-deny
              pkgs.gitMinimal
              pkgs.gitleaks
              pkgs.nixfmt-tree
              pkgs.pip-audit
              pkgs.ruff
              pkgs.ty
              pkgs.uv
            ];
          };
        }
      );

      formatter = forAllSystems (pkgs: pkgs.nixfmt-tree);
    };
}

# LLM-CONTRACT
# id: agent-work-governor.rust-nix-environment
# state: LOCKED_INPUTS -> REPRODUCIBLE_SHELL -> CHECKED_PACKAGE | BUILD_FAILURE
# preconditions: flake.lock and Cargo.lock are present
# invariant: Rust, Python, plugin, secret, format, type, and dependency checks use pinned inputs
# failure: Nix reports evaluation, dependency, build, or test failure
# source: bundle:knowledge/policies/work-governor.md
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: checks
# test: bundle:rust/tests/interface.rs
