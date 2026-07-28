from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Protocol, cast

BUNDLE_ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = BUNDLE_ROOT / "scripts"
if not MODULE_ROOT.is_dir():
    MODULE_ROOT = BUNDLE_ROOT
sys.path.insert(0, str(MODULE_ROOT))

import contract_blocks
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
