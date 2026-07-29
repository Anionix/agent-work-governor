{
  description = "Reproducible Agent Work Governor Rust validator";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/624af665418d3c65d544145b4d34ad696439570e";
    rust-overlay.url = "github:oxalica/rust-overlay/8ec8a5a41f8d8244e672829c9cd705416139d3f0";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      fail = code: detail: throw "${code}${if detail == "" then "" else ":${detail}"}";
      catalogResult = builtins.tryEval (builtins.fromJSON (builtins.readFile ./toolchain.lock.json));
      catalog =
        if
          catalogResult.success
          && builtins.isAttrs catalogResult.value
          && (catalogResult.value.schema_version or null) == "0.2"
        then
          catalogResult.value
        else
          fail "TOOLCHAIN_SCHEMA_MISMATCH" "";
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      rawTools = catalog.tools or null;
      typedTools =
        if
          builtins.isList rawTools
          && builtins.all (
            entry:
            builtins.isAttrs entry
            && builtins.isString (entry.id or null)
            && builtins.isString (entry.language or null)
            && builtins.isString (entry.version or null)
            && builtins.isString (entry.source or null)
            && builtins.isString (entry.source_digest or null)
          ) rawTools
        then
          rawTools
        else
          fail "TOOLCHAIN_ENTRY_INVALID" "<catalog>";
      toolIds = map (entry: entry.id) typedTools;
      requiredIds =
        if
          builtins.isList (catalog.required or null) && builtins.all builtins.isString catalog.required
        then
          catalog.required
        else
          fail "TOOLCHAIN_ENTRY_INVALID" "required";
      hasDuplicates =
        values:
        if values == [ ] then
          false
        else
          builtins.elem (builtins.head values) (builtins.tail values) || hasDuplicates (builtins.tail values);
      unsupported = builtins.filter (
        entry:
        !builtins.elem entry.language [
          "github_actions"
          "nix"
          "python"
          "rust"
        ]
      ) typedTools;
      # LLM contract: tool ID + declared identity -> canonical kind/repository or evaluation failure.
      canonicalGitRepositories = {
        "cachix/install-nix-action" = "https://github.com/cachix/install-nix-action";
        cargo = "https://github.com/rust-lang/cargo";
        clippy = "https://github.com/rust-lang/rust";
        ruff = "https://github.com/astral-sh/ruff";
        rust = "https://github.com/rust-lang/rust";
        rustfmt = "https://github.com/rust-lang/rust";
        ty = "https://github.com/astral-sh/ty";
        uv = "https://github.com/astral-sh/uv";
      };
      validPin =
        entry:
        let
          gitDigest = builtins.match "git:([0-9a-f]{40})" entry.source_digest;
          shaDigest = builtins.match "sha256:[0-9a-f]{64}" entry.source_digest;
          gitCommit = if gitDigest == null then "" else builtins.head gitDigest;
          gitRepository =
            if builtins.hasAttr entry.id canonicalGitRepositories then
              builtins.getAttr entry.id canonicalGitRepositories
            else
              null;
        in
        builtins.match "(v?[0-9]+(\\.[0-9]+){1,3}([-+][A-Za-z0-9.]+)?|[0-9a-f]{40})" entry.version != null
        && builtins.match "https://.+" entry.source != null
        && (
          if gitRepository != null then
            gitDigest != null && entry.source == "${gitRepository}/commit/${gitCommit}"
          else
            shaDigest != null
        );
      gitRepositoryBindingSelfTest =
        let
          commit = "0000000000000000000000000000000000000000";
          rejectsRepository = !validPin {
            id = "cachix/install-nix-action";
            version = "v1.0.0";
            source = "https://github.com/unrelated/repository/commit/${commit}";
            source_digest = "git:${commit}";
          };
          rejectsDigestDowngrade = !validPin {
            id = "cachix/install-nix-action";
            version = "v1.0.0";
            source = "https://github.com/cachix/install-nix-action/commit/${commit}";
            source_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
          };
        in
        if rejectsRepository && rejectsDigestDowngrade then
          true
        else
          fail "TOOLCHAIN_GIT_REPOSITORY_SELF_TEST_FAILED" "cachix/install-nix-action";
      invalidPins = builtins.filter (entry: !validPin entry) typedTools;
      missingRequired = builtins.filter (toolId: !builtins.elem toolId toolIds) requiredIds;
      checkedTools = builtins.seq gitRepositoryBindingSelfTest (
        if hasDuplicates toolIds || hasDuplicates requiredIds then
          fail "TOOLCHAIN_DUPLICATE_ID" ""
        else if invalidPins != [ ] then
          fail "TOOLCHAIN_ENTRY_INVALID" (builtins.head invalidPins).id
        else if unsupported != [ ] then
          fail "TOOLCHAIN_LANGUAGE_UNSUPPORTED" (builtins.head unsupported).id
        else if missingRequired != [ ] then
          fail "REQUIRED_TOOL_NOT_LOCKED" (builtins.head missingRequired)
        else
          typedTools
      );
      pin =
        toolId:
        let
          matches = builtins.filter (entry: entry.id == toolId) checkedTools;
        in
        if builtins.length matches == 1 then
          builtins.head matches
        else if matches == [ ] then
          fail "REQUIRED_TOOL_NOT_LOCKED" toolId
        else
          fail "TOOLCHAIN_DUPLICATE_ID" toolId;
      pinFor =
        language: toolId:
        let
          entry = pin toolId;
        in
        if entry.language == language then entry else fail "TOOLCHAIN_LANGUAGE_MISMATCH" toolId;
      validateRustComponents =
        rustPin: cargoPin: clippyPin: rustfmtPin:
        # LLM contract: individually valid component pins -> one consistent Rust release or failure.
        # Source: https://github.com/rust-lang/rust/blob/8bab26f4f68e0e26f0bb7960be334d5b520ea452/src/tools/build-manifest/src/main.rs
        if
          cargoPin.version == rustPin.version
          && clippyPin.source == rustPin.source
          && clippyPin.source_digest == rustPin.source_digest
          && rustfmtPin.source == rustPin.source
          && rustfmtPin.source_digest == rustPin.source_digest
        then
          true
        else
          fail "TOOLCHAIN_RUST_COMPONENT_MISMATCH" "";
      gitCommit =
        language: toolId:
        let
          digest = (pinFor language toolId).source_digest;
        in
        if builtins.match "git:[0-9a-f]{40}" digest != null then
          builtins.substring 4 40 digest
        else
          fail "TOOLCHAIN_SOURCE_DIGEST_INVALID" toolId;
      hashHex =
        failureCode: toolId: hash: hashAlgo:
        let
          converted = builtins.tryEval (
            builtins.convertHash (
              {
                inherit hash;
                toHashFormat = "base16";
              }
              // (
                if hashAlgo == null then
                  { }
                else
                  {
                    inherit hashAlgo;
                  }
              )
            )
          );
        in
        if builtins.isString hash && converted.success then converted.value else fail failureCode toolId;
      bindInputIdentity =
        toolId: owner: repository: expected: input:
        let
          revision = input.rev or "";
          expectedSource = "https://github.com/${owner}/${repository}/commit/${revision}";
          narHash = input.narHash or null;
          actualDigest = "sha256:${hashHex "TOOLCHAIN_INPUT_NAR_HASH_MISSING" toolId narHash null}";
        in
        if expected.version != revision then
          fail "TOOLCHAIN_INPUT_REVISION_MISMATCH" toolId
        else if expected.source != expectedSource then
          fail "TOOLCHAIN_INPUT_SOURCE_MISMATCH" toolId
        else if expected.source_digest != actualDigest then
          fail "TOOLCHAIN_INPUT_NAR_HASH_MISMATCH" toolId
        else
          input;
      bindInput =
        toolId: owner: repository: input:
        bindInputIdentity toolId owner repository (pinFor "nix" toolId) input;
      inputProvenanceSelfTest =
        let
          expected = pinFor "nix" "nixpkgs";
          rejects =
            candidate:
            !(builtins.tryEval (
              builtins.seq (bindInputIdentity "nixpkgs" "NixOS" "nixpkgs" candidate nixpkgs) true
            )).success;
        in
        if
          rejects (
            expected
            // {
              source = "https://github.com/example/nixpkgs/commit/${expected.version}";
            }
          )
          && rejects (
            expected
            // {
              source_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
            }
          )
        then
          true
        else
          fail "TOOLCHAIN_INPUT_PROVENANCE_SELF_TEST_FAILED" "nixpkgs";
      lockedNixpkgs = builtins.seq inputProvenanceSelfTest (
        bindInput "nixpkgs" "NixOS" "nixpkgs" nixpkgs
      );
      lockedRustOverlay = bindInput "rust-overlay" "oxalica" "rust-overlay" rust-overlay;
      bindPackage =
        language: toolId: expectedPname: package:
        let
          expected = pinFor language toolId;
        in
        if (package.pname or "") != expectedPname then
          fail "TOOLCHAIN_PACKAGE_ID_MISMATCH" toolId
        else if (package.version or "") != expected.version then
          fail "TOOLCHAIN_PACKAGE_VERSION_MISMATCH" toolId
        else
          package;
      packageSource =
        toolId: package:
        let
          source = package.src or null;
        in
        if builtins.isAttrs source then source else fail "TOOLCHAIN_PACKAGE_SOURCE_MISSING" toolId;
      sourceHashHex =
        toolId: package:
        let
          source = packageSource toolId package;
          outputHash = source.outputHash or null;
          outputHashAlgo = source.outputHashAlgo or null;
        in
        hashHex "TOOLCHAIN_PACKAGE_SOURCE_HASH_MISSING" toolId outputHash outputHashAlgo;
      sourceUrls =
        toolId: package:
        let
          source = packageSource toolId package;
          urls = source.urls or [ (source.url or "") ];
        in
        if builtins.isList urls && builtins.all builtins.isString urls then
          urls
        else
          fail "TOOLCHAIN_PACKAGE_SOURCE_URL_MISSING" toolId;
      bindNixPackageIdentity =
        toolId: expected: checked:
        let
          actualDigest = "sha256:${sourceHashHex toolId checked}";
        in
        if !builtins.elem expected.source (sourceUrls toolId checked) then
          fail "TOOLCHAIN_PACKAGE_SOURCE_URL_MISMATCH" toolId
        else if expected.source_digest != actualDigest then
          fail "TOOLCHAIN_PACKAGE_SOURCE_DIGEST_MISMATCH" toolId
        else
          checked;
      bindNixPackage =
        language: toolId: expectedPname: package:
        bindNixPackageIdentity toolId (pinFor language toolId) (
          bindPackage language toolId expectedPname package
        );
      mkWheelTool =
        pkgs: toolId:
        let
          expected = pinFor "python" toolId;
          rawArtifacts = expected.artifacts or null;
          artifacts =
            if builtins.isAttrs rawArtifacts && builtins.attrNames rawArtifacts == systems then
              rawArtifacts
            else
              fail "TOOLCHAIN_ARTIFACT_SET_INVALID" toolId;
          artifact = artifacts.${pkgs.stdenv.hostPlatform.system};
          validArtifact =
            builtins.isAttrs artifact
            && builtins.isString (artifact.url or null)
            && builtins.match "https://.+" artifact.url != null
            && builtins.isString (artifact.sha256 or null)
            && builtins.match "[0-9a-f]{64}" artifact.sha256 != null;
          wheelName = builtins.baseNameOf artifact.url;
        in
        if !validArtifact then
          fail "TOOLCHAIN_ARTIFACT_INVALID" "${toolId}:${pkgs.stdenv.hostPlatform.system}"
        else
          bindPackage "python" toolId toolId (
            pkgs.python3Packages.buildPythonApplication {
              pname = toolId;
              version = expected.version;
              format = "wheel";
              src = pkgs.fetchurl {
                name = wheelName;
                inherit (artifact) url sha256;
              };
              # LLM contract: manylinux wheel -> Nix-native ELF or build failure.
              # Primary source: pinned nixpkgs python/manylinux/default.nix.
              nativeBuildInputs = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
                pkgs.autoPatchelfHook
              ];
              buildInputs = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux (
                pkgs.pythonManylinuxPackages.manylinux2014
              );
              doCheck = false;
            }
          );
      mkToolchain =
        pkgs:
        let
          rustPin = pinFor "rust" "rust";
          cargoPin = pinFor "rust" "cargo";
          clippyPin = pinFor "rust" "clippy";
          rustfmtPin = pinFor "rust" "rustfmt";
          rustComponentSelfTest =
            let
              rejects =
                cargoCandidate: clippyCandidate: rustfmtCandidate:
                !(builtins.tryEval (validateRustComponents rustPin cargoCandidate clippyCandidate rustfmtCandidate))
                .success;
            in
            if
              rejects (cargoPin // { version = "0.0.0"; }) clippyPin rustfmtPin
              && rejects cargoPin (clippyPin // { source = "https://example.invalid/clippy"; }) rustfmtPin
              && rejects cargoPin clippyPin (rustfmtPin // { source = "https://example.invalid/rustfmt"; })
            then
              true
            else
              fail "TOOLCHAIN_RUST_COMPONENT_SELF_TEST_FAILED" "";
          rustComponentsValid = builtins.seq rustComponentSelfTest (
            validateRustComponents rustPin cargoPin clippyPin rustfmtPin
          );
          rustRelease =
            if builtins.hasAttr rustPin.version pkgs.rust-bin.stable then
              pkgs.rust-bin.stable.${rustPin.version}
            else
              fail "TOOLCHAIN_PACKAGE_NOT_FOUND" "rust";
          rust = builtins.seq rustComponentsValid (
            bindPackage "rust" "rust" "rust-default" (
              rustRelease.default.override {
                extensions = [
                  "clippy"
                  "rustfmt"
                ];
              }
            )
          );
          pythonBase = bindNixPackage "python" "python" "python3" pkgs.python3;
          nixfmt = bindNixPackage "nix" "nixfmt" "nixfmt" pkgs.nixfmt;
          treefmt = bindNixPackage "nix" "treefmt" "treefmt" pkgs.treefmt;
          provenanceBindingSelfTest =
            let
              expected = pinFor "nix" "git";
              package = bindPackage "nix" "git" "git-minimal" pkgs.gitMinimal;
              rejects =
                candidate:
                !(builtins.tryEval (builtins.seq (bindNixPackageIdentity "git" candidate package) true)).success;
            in
            if
              rejects (
                expected
                // {
                  source = "https://example.invalid/git.tar.xz";
                }
              )
              && rejects (
                expected
                // {
                  source_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
                }
              )
            then
              true
            else
              fail "TOOLCHAIN_PROVENANCE_SELF_TEST_FAILED" "git";
        in
        {
          inherit rust;
          rustVersion = rustPin.version;
          cargoVersion = cargoPin.version;
          clippyVersion = clippyPin.version;
          rustfmtVersion = rustfmtPin.version;
          rustCommit = gitCommit "rust" "rust";
          cargoCommit = gitCommit "rust" "cargo";
          python = pythonBase.withPackages (packages: [ packages.pyyaml ]);
          actionlint = bindNixPackage "nix" "actionlint" "actionlint" pkgs.actionlint;
          cargoAudit = bindNixPackage "rust" "cargo-audit" "cargo-audit" pkgs.cargo-audit;
          cargoDeny = bindNixPackage "rust" "cargo-deny" "cargo-deny" pkgs.cargo-deny;
          git = builtins.seq provenanceBindingSelfTest (
            bindNixPackage "nix" "git" "git-minimal" pkgs.gitMinimal
          );
          gitleaks = bindNixPackage "nix" "gitleaks" "gitleaks" pkgs.gitleaks;
          pipAudit = bindNixPackage "python" "pip-audit" "pip-audit" pkgs.pip-audit;
          ruff = mkWheelTool pkgs "ruff";
          ty = mkWheelTool pkgs "ty";
          uv = mkWheelTool pkgs "uv";
          formatter = builtins.seq nixfmt (builtins.seq treefmt pkgs.nixfmt-tree);
        };
      forAllSystems =
        function:
        nixpkgs.lib.genAttrs systems (
          system:
          function (
            import lockedNixpkgs {
              inherit system;
              overlays = [ lockedRustOverlay.overlays.default ];
            }
          )
        );
    in
    {
      packages = forAllSystems (
        pkgs:
        let
          toolchain = mkToolchain pkgs;
          rustPlatform = pkgs.makeRustPlatform {
            cargo = toolchain.rust;
            rustc = toolchain.rust;
          };
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
              toolchain.python
              toolchain.actionlint
              toolchain.git
              toolchain.gitleaks
              toolchain.ruff
              toolchain.ty
              toolchain.uv
            ];
            preCheck = ''
              assert_locked_identity() {
                if [ "$2" != "$3" ]; then
                  echo "TOOLCHAIN_BINARY_IDENTITY_MISMATCH:$1" >&2
                  return 1
                fi
              }
              assert_locked_identity rust \
                "$(rustc --version | awk '{print $2}')" \
                "${toolchain.rustVersion}"
              assert_locked_identity rust-commit \
                "$(rustc --version --verbose | awk '/commit-hash:/ {print $2}')" \
                "${toolchain.rustCommit}"
              assert_locked_identity cargo \
                "$(cargo --version | awk '{print $2}')" \
                "${toolchain.cargoVersion}"
              assert_locked_identity cargo-commit \
                "$(cargo --version --verbose | awk '/commit-hash:/ {print $2}')" \
                "${toolchain.cargoCommit}"
              assert_locked_identity clippy \
                "$(cargo-clippy --version | awk '{print $2}')" \
                "${toolchain.clippyVersion}"
              assert_locked_identity clippy-commit \
                "$(cargo-clippy --version | awk '{gsub(/[()]/, "", $3); print $3}')" \
                "${builtins.substring 0 10 toolchain.rustCommit}"
              assert_locked_identity rustfmt \
                "$(rustfmt --version | awk '{split($2, parts, "-"); print parts[1]}')" \
                "${toolchain.rustfmtVersion}"
              assert_locked_identity rustfmt-commit \
                "$(rustfmt --version | awk '{gsub(/[()]/, "", $3); print $3}')" \
                "${builtins.substring 0 10 toolchain.rustCommit}"
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
                --rustc-version "rustc ${toolchain.rust.version}"
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
          toolchain = mkToolchain pkgs;
        in
        {
          default = pkgs.mkShellNoCC {
            packages = [
              toolchain.rust
              toolchain.python
              toolchain.actionlint
              toolchain.cargoAudit
              toolchain.cargoDeny
              toolchain.git
              toolchain.gitleaks
              toolchain.formatter
              toolchain.pipAudit
              toolchain.ruff
              toolchain.ty
              toolchain.uv
            ];
            shellHook = ''
              # LLM contract: inherited tool state -> REPO_LOCAL_CACHE, so host
              # plugins and incompatible caches cannot affect locked evidence.
              export CARGO_HOME="$PWD/.governance/cache/cargo"
              export UV_CACHE_DIR="$PWD/.governance/cache/uv"
              export UV_TOOL_DIR="$PWD/.governance/cache/uv-tools"
              export XDG_CACHE_HOME="$PWD/.governance/cache/xdg"
              mkdir -p "$CARGO_HOME" "$UV_CACHE_DIR" "$UV_TOOL_DIR" "$XDG_CACHE_HOME"
            '';
          };
        }
      );

      formatter = forAllSystems (pkgs: (mkToolchain pkgs).formatter);
    };
}

# LLM-CONTRACT
# id: agent-work-governor.unified-nix-environment
# state: CATALOG_BYTES -> VALIDATED_IDENTITIES -> REPRODUCIBLE_SHELL | TOOLCHAIN_LOCK_REJECTED | BUILD_FAILURE
# preconditions: toolchain.lock.json, flake.lock, and Cargo.lock are present
# invariant: every catalogued Nix package, Rust release, and wheel artifact matches one exact identity
# failure: stable TOOLCHAIN_* evaluation error or a Nix dependency, build, or test failure
# source: https://github.com/NixOS/nix/blob/2c6d06e9387cf58167cb5a7ab91cee7333d8d17c/src/nix/flake.md
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: checks
# test: bundle:tests/test_contracts.py
# Cargo lock primary source: https://github.com/rust-lang/cargo/blob/c980f4866141969fab6254a680546a277789d6f0/src/doc/src/guide/cargo-toml-vs-cargo-lock.md
