from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, Protocol, cast

BUNDLE_ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = BUNDLE_ROOT / "scripts"
if not MODULE_ROOT.is_dir():
    MODULE_ROOT = BUNDLE_ROOT
sys.path.insert(0, str(MODULE_ROOT))

import contract_blocks
import toolchain_catalog
import validate_policy

# LLM-CONTRACT
# id: agent-work-governor.repo-bundle-tests
# state: BUNDLE -> PORTABLE_CHECKS -> PASS | FAIL
# preconditions: the plugin or repository-local Governor bundle is readable
# invariant: the same explicit bundle references resolve in both layouts
# failure: unittest reports the exact broken portable contract
# source: bundle:knowledge/policies/work-governor.md
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: unittest.main
# test: bundle:tests/test_repo_bundle.py


class RepositoryGate(Protocol):
    def validate_python_runtime(
        self,
        pins: dict[str, dict[str, object]],
        actual_version: tuple[int, int, int],
    ) -> list[dict[str, Any]]: ...

    def validate_toolchain(
        self,
        root: Path,
        environment: dict[str, object],
    ) -> list[dict[str, Any]]: ...

    def is_governed_source(self, path: Path) -> bool: ...

    def contract_source_path(self, path: Path) -> Path: ...

    def changed_code_files(
        self,
        root: Path,
        branch_base: str,
        head_ref: str,
    ) -> tuple[list[Path], str | None]: ...

    def contract_reference_errors(
        self,
        root: Path,
        bundle_root: Path,
        source_path: Path,
        source_text: str,
    ) -> list[dict[str, object]]: ...


def gate_path() -> Path:
    source_path = BUNDLE_ROOT / "assets/repository/.agent-work-governor/validate.py"
    return source_path if source_path.is_file() else BUNDLE_ROOT / "validate.py"


def safe_policy_path() -> Path:
    source_path = BUNDLE_ROOT / "assets/repository/.agent-work-governor/policy.toml"
    return source_path if source_path.is_file() else BUNDLE_ROOT / "policy.toml"


def toolchain_contract_path() -> Path:
    source_path = (
        BUNDLE_ROOT
        / "assets/repository/.agent-work-governor/toolchain.lock.LLM-CONTRACT.md"
    )
    return (
        source_path
        if source_path.is_file()
        else BUNDLE_ROOT / "toolchain.lock.LLM-CONTRACT.md"
    )


def toolchain_catalog_path() -> Path:
    return BUNDLE_ROOT / "toolchain.lock.json"


def repository_workflow_path() -> Path:
    source_path = (
        BUNDLE_ROOT / "assets/repository/.github/workflows/agent-work-governor.yml"
    )
    return (
        source_path
        if source_path.is_file()
        else BUNDLE_ROOT.parent / ".github/workflows/agent-work-governor.yml"
    )


def load_gate() -> RepositoryGate:
    specification = importlib.util.spec_from_file_location(
        "agent_work_governor_repo_gate",
        gate_path(),
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("repository gate module is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return cast(RepositoryGate, module)


class PortableBundleTests(unittest.TestCase):
    @staticmethod
    def minimal_catalog() -> dict[str, object]:
        python_sha = "a" * 40
        rust_sha = "b" * 40
        return {
            "locked_at": "2026-07-29",
            "required": ["python", "rust"],
            "schema_version": "0.2",
            "tools": [
                {
                    "id": "python",
                    "language": "python",
                    "version": "3.14.6",
                    "source": f"https://github.com/python/cpython/commit/{python_sha}",
                    "source_digest": f"git:{python_sha}",
                },
                {
                    "id": "rust",
                    "language": "rust",
                    "version": "1.97.1",
                    "source": f"https://github.com/rust-lang/rust/commit/{rust_sha}",
                    "source_digest": f"git:{rust_sha}",
                },
            ],
        }

    @classmethod
    def rust_component_catalog(cls) -> dict[str, object]:
        document = cls.minimal_catalog()
        tools = cls.catalog_tools(document)
        rust = next(tool for tool in tools if tool["id"] == "rust")
        cargo_sha = "c" * 40
        tools.extend(
            (
                {
                    "id": "cargo",
                    "language": "rust",
                    "version": rust["version"],
                    "source": f"https://github.com/rust-lang/cargo/commit/{cargo_sha}",
                    "source_digest": f"git:{cargo_sha}",
                },
                {
                    "id": "clippy",
                    "language": "rust",
                    "version": "0.1.97",
                    "source": rust["source"],
                    "source_digest": rust["source_digest"],
                },
                {
                    "id": "rustfmt",
                    "language": "rust",
                    "version": "1.9.0",
                    "source": rust["source"],
                    "source_digest": rust["source_digest"],
                },
            )
        )
        tools.sort(key=lambda tool: cast(str, tool["id"]))
        document["required"] = sorted(cast(str, tool["id"]) for tool in tools)
        return document

    @staticmethod
    def catalog_tools(
        document: dict[str, object],
    ) -> list[dict[str, object]]:
        tools = document["tools"]
        if not isinstance(tools, list) or not all(
            isinstance(tool, dict) for tool in tools
        ):
            raise AssertionError("catalog fixture tools must be objects")
        return cast(list[dict[str, object]], tools)

    def validate_catalog_fixture(
        self,
        document: dict[str, object],
        required: tuple[str, ...] = (),
    ) -> tuple[dict[str, dict[str, object]], list[toolchain_catalog.Finding]]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "toolchain.lock.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            return toolchain_catalog.validate_catalog(path, required)

    def finding_codes(self, document: dict[str, object]) -> set[str]:
        pins, findings = self.validate_catalog_fixture(document)
        self.assertEqual({}, pins)
        return {finding["code"] for finding in findings}

    def test_executable_config_and_json_sidecars_are_governed(self) -> None:
        gate = load_gate()
        for relative in (
            "flake.nix",
            "Cargo.toml",
            "policy.yaml",
            "workflow.yml",
            "check.sh",
            "manifest.json",
            "Dockerfile",
        ):
            self.assertTrue(gate.is_governed_source(Path(relative)), relative)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = root / "manifest.json"
            manifest.write_text("{}\n", encoding="utf-8")
            sidecar = root / "LLM-CONTRACT.md"
            sidecar.write_text("# contract\n", encoding="utf-8")
            self.assertEqual(sidecar, gate.contract_source_path(manifest))

    def test_policy_and_contract_helpers_are_live(self) -> None:
        self.assertTrue(validate_policy.build_receipt(safe_policy_path())["valid"])
        self.assertIsNone(
            contract_blocks.contract_diagnostic(
                Path(__file__).read_text(encoding="utf-8")
            )
        )

    def test_bundled_toolchain_sidecar_is_machine_valid(self) -> None:
        gate = load_gate()
        sidecar = toolchain_contract_path()
        source = sidecar.read_text(encoding="utf-8")
        self.assertIsNone(contract_blocks.contract_diagnostic(source))
        self.assertEqual(
            [],
            gate.contract_reference_errors(
                BUNDLE_ROOT,
                BUNDLE_ROOT,
                sidecar,
                source,
            ),
        )

    def test_bundled_catalog_has_required_python_and_rust_pins(self) -> None:
        pins, findings = toolchain_catalog.validate_catalog(
            toolchain_catalog_path(),
            ("python", "rust"),
        )
        self.assertEqual([], findings)
        self.assertEqual("python", pins["python"]["language"])
        self.assertEqual("rust", pins["rust"]["language"])

    def test_repository_gate_requires_exact_python_runtime_and_pin(self) -> None:
        gate = load_gate()
        document = self.minimal_catalog()
        pins, catalog_findings = self.validate_catalog_fixture(
            document,
            ("python", "rust"),
        )
        self.assertEqual([], catalog_findings)
        self.assertEqual([], gate.validate_python_runtime(pins, (3, 14, 6)))
        runtime_findings = gate.validate_python_runtime(pins, (3, 14, 5))
        self.assertEqual(
            ["TOOLCHAIN_PYTHON_VERSION_MISMATCH"],
            [finding["code"] for finding in runtime_findings],
        )
        self.assertEqual("3.14.6", runtime_findings[0]["evidence"]["expected"])
        self.assertEqual("3.14.5", runtime_findings[0]["evidence"]["actual"])

        tools = self.catalog_tools(document)
        python_pin = next(tool for tool in tools if tool["id"] == "python")
        python_pin["id"] = "ruff"
        document["required"] = ["ruff", "rust"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock_path = root / "toolchain.lock.json"
            lock_path.write_text(json.dumps(document), encoding="utf-8")
            findings = gate.validate_toolchain(
                root,
                {
                    "toolchain_lock": "toolchain.lock.json",
                    "required_tools": ["rust"],
                },
            )

        self.assertIn("REQUIRED_TOOL_NOT_LOCKED", {item["code"] for item in findings})

    def test_repository_workflow_uses_nix_python_for_policy_gate(self) -> None:
        workflow = repository_workflow_path().read_text(encoding="utf-8")

        self.assertLess(
            workflow.index("Validate Nix bootstrap identity"),
            workflow.index("uses: cachix/install-nix-action@"),
        )
        self.assertLess(
            workflow.index("uses: cachix/install-nix-action@"),
            workflow.index("python .agent-work-governor/validate.py"),
        )
        for evidence in (
            "--tool-source nix",
            "--tool-source cachix/install-nix-action",
            "TOOLCHAIN_ACTION_IDENTITY_MISMATCH",
            "TOOLCHAIN_NIX_PREINSTALLED",
            "sha256sum --check --strict",
            "install_url: file://${{ runner.temp }}/nix-install",
            "TOOLCHAIN_VERSION_MISMATCH::nix",
            "nix develop --no-update-lock-file --no-write-lock-file --command",
        ):
            self.assertIn(evidence, workflow)
        self.assertNotIn("run: python3 .agent-work-governor/validate.py", workflow)

    def test_catalog_accepts_valid_python_rust_and_artifacts(self) -> None:
        document = self.minimal_catalog()
        artifacts = {
            system: {
                "url": f"https://example.invalid/python-{system}.whl",
                "sha256": character * 64,
            }
            for system, character in (
                ("aarch64-darwin", "1"),
                ("aarch64-linux", "2"),
                ("x86_64-linux", "3"),
            )
        }
        tools = self.catalog_tools(document)
        tools[0]["artifacts"] = artifacts

        pins, findings = self.validate_catalog_fixture(
            document,
            ("python", "rust"),
        )

        self.assertEqual([], findings)
        self.assertEqual(artifacts, pins["python"]["artifacts"])

    def test_catalog_cli_exposes_exact_source_identity(self) -> None:
        document = self.minimal_catalog()
        tools = self.catalog_tools(document)
        expected = f"{tools[0]['source']}\t{tools[0]['source_digest']}\n"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "toolchain.lock.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                result = toolchain_catalog.main([str(path), "--tool-source", "python"])

        self.assertEqual(0, result)
        self.assertEqual(expected, output.getvalue())

    def test_catalog_rejects_duplicate_raw_json_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "toolchain.lock.json"
            path.write_text(
                '{"schema_version":"0.2","schema_version":"0.2"}',
                encoding="utf-8",
            )
            pins, findings = toolchain_catalog.validate_catalog(path)

        self.assertEqual({}, pins)
        self.assertEqual(
            ["TOOLCHAIN_DUPLICATE_JSON_KEY"],
            [finding["code"] for finding in findings],
        )

    def test_catalog_rejects_duplicate_unknown_and_missing_tools(self) -> None:
        duplicate = self.minimal_catalog()
        duplicate_tools = self.catalog_tools(duplicate)
        duplicate_tools.append(dict(duplicate_tools[-1]))

        unknown = self.minimal_catalog()
        unknown_tools = self.catalog_tools(unknown)
        unknown_tools[0]["language"] = "javascript"

        missing = self.minimal_catalog()
        missing["required"] = ["cargo-deny", "python", "rust"]

        for document, code in (
            (duplicate, "TOOLCHAIN_DUPLICATE_ID"),
            (unknown, "TOOLCHAIN_LANGUAGE_UNSUPPORTED"),
            (missing, "REQUIRED_TOOL_NOT_LOCKED"),
        ):
            with self.subTest(code=code):
                self.assertIn(code, self.finding_codes(document))

    def test_catalog_rejects_non_exact_versions(self) -> None:
        for version in ("", "latest", ">=3.11", "1.*", "1.x", "^1.2.3", "1 || 2"):
            document = self.minimal_catalog()
            tools = self.catalog_tools(document)
            tools[0]["version"] = version
            with self.subTest(version=version):
                self.assertIn(
                    "TOOLCHAIN_ENTRY_INVALID",
                    self.finding_codes(document),
                )

    def test_catalog_rejects_inconsistent_rust_components(self) -> None:
        valid = self.rust_component_catalog()
        pins, findings = self.validate_catalog_fixture(valid)
        self.assertEqual([], findings)
        self.assertEqual("1.97.1", pins["cargo"]["version"])

        cases = (
            ("cargo", "version"),
            ("clippy", "source_identity"),
            ("rustfmt", "source_identity"),
            ("cargo", "language"),
        )
        for tool_id, mutation in cases:
            with self.subTest(tool=tool_id, mutation=mutation):
                document = cast(
                    dict[str, object],
                    json.loads(json.dumps(valid)),
                )
                tool = next(
                    item
                    for item in self.catalog_tools(document)
                    if item["id"] == tool_id
                )
                if mutation == "version":
                    tool["version"] = "1.96.0"
                elif mutation == "language":
                    tool["language"] = "python"
                else:
                    other_sha = "d" * 40
                    tool["source"] = (
                        f"https://github.com/rust-lang/rust/commit/{other_sha}"
                    )
                    tool["source_digest"] = f"git:{other_sha}"

                _, rejected = self.validate_catalog_fixture(document)

                self.assertIn(
                    ("TOOLCHAIN_RUST_COMPONENT_MISMATCH", tool_id),
                    {(item["code"], item["tool_id"]) for item in rejected},
                )

    def test_catalog_rejects_mutable_or_malformed_provenance(self) -> None:
        sha = "a" * 40
        cases = (
            ("source", "http://github.com/python/cpython/commit/" + sha),
            ("source", "https://github.com/python/cpython/releases/latest"),
            ("source_digest", "git:main"),
            ("source_digest", "git:" + "b" * 40),
            ("source_digest", "sha256:" + "0" * 63),
        )
        for field, value in cases:
            document = self.minimal_catalog()
            tools = self.catalog_tools(document)
            tools[0][field] = value
            with self.subTest(field=field, value=value):
                self.assertIn(
                    "TOOLCHAIN_ENTRY_INVALID",
                    self.finding_codes(document),
                )

    def test_catalog_rejects_incomplete_or_malformed_artifacts(self) -> None:
        valid = {
            system: {
                "url": f"https://example.invalid/python-{system}.whl",
                "sha256": character * 64,
            }
            for system, character in (
                ("aarch64-darwin", "1"),
                ("aarch64-linux", "2"),
                ("x86_64-linux", "3"),
            )
        }
        invalid_artifacts = (
            {key: value for key, value in valid.items() if key != "aarch64-darwin"},
            {
                **valid,
                "aarch64-darwin": {
                    "url": "http://example.invalid/python.whl",
                    "sha256": "1" * 64,
                },
            },
            {
                **valid,
                "aarch64-linux": {
                    "url": "https://example.invalid/python.whl",
                    "sha256": "not-a-digest",
                },
            },
        )
        for artifacts in invalid_artifacts:
            document = self.minimal_catalog()
            tools = self.catalog_tools(document)
            tools[0]["artifacts"] = artifacts
            with self.subTest(artifacts=artifacts):
                self.assertIn(
                    "TOOLCHAIN_ENTRY_INVALID",
                    self.finding_codes(document),
                )

    def test_changed_code_files_preserve_newlines(self) -> None:
        gate = load_gate()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*arguments: str) -> None:
                subprocess.run(
                    [
                        "git",
                        "-c",
                        "commit.gpgsign=false",
                        "-C",
                        str(root),
                        *arguments,
                    ],
                    check=True,
                    capture_output=True,
                )

            git("init", "-b", "main")
            git("config", "user.name", "Contract Test")
            git("config", "user.email", "contract@example.invalid")
            (root / "README.md").write_text("baseline\n", encoding="utf-8")
            git("add", "README.md")
            git("commit", "-m", "baseline")
            git("update-ref", "refs/remotes/origin/main", "HEAD")
            git("switch", "-c", "work/path-boundary")
            changed = root / "line\nbreak.py"
            changed.write_text("VALUE = 1\n", encoding="utf-8")
            git("add", str(changed.relative_to(root)))
            invalid_bytes = b"invalid-\xff.py"
            invalid = root / os.fsdecode(invalid_bytes)
            if sys.platform.startswith("linux"):
                invalid.write_text("VALUE = 2\n", encoding="utf-8")
                git("add", str(invalid.relative_to(root)))
            git("commit", "-m", "add governed path")

            paths, error = gate.changed_code_files(root, "origin/main", "HEAD")

        self.assertIsNone(error)
        self.assertIn(changed.resolve(), paths)
        if sys.platform.startswith("linux"):
            self.assertIn(invalid.resolve(), paths)
            self.assertIn(invalid_bytes, {os.fsencode(path.name) for path in paths})

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_changed_code_files_reject_root_escape(self) -> None:
        gate = load_gate()
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            root = workspace / "repo"
            root.mkdir()

            def git(*arguments: str) -> None:
                subprocess.run(
                    [
                        "git",
                        "-c",
                        "commit.gpgsign=false",
                        "-C",
                        str(root),
                        *arguments,
                    ],
                    check=True,
                    capture_output=True,
                )

            git("init", "-b", "main")
            git("config", "user.name", "Contract Test")
            git("config", "user.email", "contract@example.invalid")
            (root / "README.md").write_text("baseline\n", encoding="utf-8")
            git("add", "README.md")
            git("commit", "-m", "baseline")
            git("update-ref", "refs/remotes/origin/main", "HEAD")
            git("switch", "-c", "work/path-escape")
            outside = workspace / "outside.py"
            outside.write_text("VALUE = 1\n", encoding="utf-8")
            (root / "escape.py").symlink_to(outside)
            git("add", "escape.py")
            git("commit", "-m", "add escaping path")

            paths, error = gate.changed_code_files(root, "origin/main", "HEAD")

        self.assertEqual([], paths)
        self.assertEqual("Git path escapes the repository root", error)

    def test_bundle_reference_is_explicit_and_bounded(self) -> None:
        resolved, error = contract_blocks.resolve_contract_reference(
            "bundle:knowledge/policies/work-governor.md",
            repo_root=BUNDLE_ROOT,
            bundle_root=BUNDLE_ROOT,
            allow_external=False,
        )
        self.assertIsNone(error)
        self.assertEqual(
            BUNDLE_ROOT / "knowledge/policies/work-governor.md",
            resolved,
        )
        for unsafe in ("../escape", "bundle:../escape", "bundle:%2e%2e/escape"):
            with self.subTest(reference=unsafe):
                _, error = contract_blocks.resolve_contract_reference(
                    unsafe,
                    repo_root=BUNDLE_ROOT,
                    bundle_root=BUNDLE_ROOT,
                    allow_external=False,
                )
                self.assertIsNotNone(error)

    def test_enforcement_token_ignores_contract_metadata(self) -> None:
        source = "# enforced_by: ghost_symbol\n"
        self.assertFalse(
            contract_blocks.enforcement_token_is_present(source, "ghost_symbol")
        )
        self.assertTrue(
            contract_blocks.enforcement_token_is_present(
                source + "def ghost_symbol():\n    return None\n",
                "ghost_symbol",
            )
        )

    def test_bundle_reference_rejects_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "bundle"
            outside = root / "outside"
            bundle.mkdir()
            outside.mkdir()
            (outside / "evidence.md").write_text("outside\n", encoding="utf-8")
            (bundle / "escape.md").symlink_to(outside / "evidence.md")
            _, error = contract_blocks.resolve_contract_reference(
                "bundle:escape.md",
                repo_root=bundle,
                bundle_root=bundle,
                allow_external=False,
            )
        self.assertEqual("reference escapes its declared root", error)

    def test_repository_gate_contract_references_resolve(self) -> None:
        gate = load_gate()
        source_path = gate_path()
        source = source_path.read_text(encoding="utf-8")
        errors = gate.contract_reference_errors(
            BUNDLE_ROOT,
            BUNDLE_ROOT,
            source_path,
            source,
        )
        self.assertEqual([], errors)


if __name__ == "__main__":
    unittest.main()
