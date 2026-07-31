from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import tomllib
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest import mock

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = PLUGIN_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import attest_policy
import bootstrap
import contract_blocks
import doctor
import package_canonical_runtime
import package_runtime
import project_toolchain_digest
import rust_dispatch
import toolchain_catalog
import validate_canonical
import validate_okf
import validate_policy

# LLM-CONTRACT
# id: agent-work-governor.contract-tests
# state: FIXTURE -> EXERCISED -> EXPECTED_VERDICT | TEST_FAILURE
# preconditions: fixtures are isolated from user repositories
# invariant: tests operate only on plugin source or temporary directories
# failure: unittest reports the exact violated contract
# source: bundle:knowledge/policies/work-governor.md
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: unittest.main
# test: bundle:tests/test_contracts.py


def json_frontmatter(metadata: dict[str, object], body: str = "# Body\n") -> str:
    return f"---\n{json.dumps(metadata)}\n---\n{body}"


def profile_metadata(concept_type: str = "Reference") -> dict[str, object]:
    return {
        "type": concept_type,
        "status": "draft",
        "generated": {
            "by": "process:contract-test",
            "at": "2026-07-28T00:00:00+09:00",
        },
        "stale_after": "2026-10-28",
        "sources": [{"resource": "https://example.invalid/primary"}],
    }


def copy_mutable_fixture(source: Path, target: Path) -> None:
    # LLM-CONTRACT
    # id: agent-work-governor.mutable-test-fixture
    # state: READ_ONLY_SOURCE -> CONTENT_COPY -> MUTABLE_FIXTURE
    # preconditions: source is a regular repository fixture
    # invariant: source metadata never removes write access from the temporary copy
    # failure: copyfile raises and the test fails before exercising a false fixture
    # source: https://github.com/python/cpython/blob/c63aec69bd59c55314c06c23f4c22c03de76fe45/Doc/library/shutil.rst
    # knowledge: bundle:knowledge/policies/work-governor.md
    # enforced_by: DoctorTests
    # test: bundle:tests/test_contracts.py
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)


def bundled_runtime_or_skip(
    test_case: unittest.TestCase,
) -> rust_dispatch.BinarySelection:
    """Return a verified release binary when this is an installed bundle."""

    if not (PLUGIN_ROOT / rust_dispatch.MANIFEST).is_file():
        baseline = tomllib.loads(
            (PLUGIN_ROOT / "SOURCE_BASELINE.toml").read_text(encoding="utf-8")
        )
        test_case.assertEqual("0.1", baseline["schema_version"])
        test_case.assertRegex(baseline["source_bundle_sha256"], r"^[0-9a-f]{64}$")
        test_case.skipTest(
            "source-only checkout intentionally excludes compiled release artifacts"
        )
    return rust_dispatch.resolve_binary(PLUGIN_ROOT)


def workflow_run_block(workflow: str, step_name: str) -> str:
    """Extract one literal GitHub Actions run block without a YAML dependency."""

    lines = workflow.splitlines()
    marker = f"      - name: {step_name}"
    step_index = lines.index(marker)
    run_index = next(
        index
        for index in range(step_index + 1, len(lines))
        if lines[index] == "        run: |"
    )
    body: list[str] = []
    for line in lines[run_index + 1 :]:
        if line.startswith("          "):
            body.append(line[10:])
        elif not line:
            body.append("")
        else:
            break
    if not body:
        raise AssertionError(f"workflow step has no run block: {step_name}")
    return "\n".join(body) + "\n"


def run_metadata_proof_fixture(
    payload: dict[str, object],
) -> subprocess.CompletedProcess[str]:
    """Run metadata reconciliation against one isolated Actions response."""

    jq = shutil.which("jq")
    bash = shutil.which("bash")
    if jq is None or bash is None:
        raise unittest.SkipTest("bash and jq are required")
    workflow = (PLUGIN_ROOT / ".github/workflows/proof-slow.yml").read_text(
        encoding="utf-8"
    )
    step = workflow_run_block(workflow, "Reconcile metadata-only proof")
    head_sha = "a" * 40
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        fixture = root / "workflow-runs.json"
        fixture.write_text(json.dumps(payload), encoding="utf-8")
        output = root / "github-output"
        fake_bin = root / "bin"
        fake_bin.mkdir()
        fake_gh = fake_bin / "gh"
        fake_gh.write_text(
            (
                f"#!{sys.executable}\n"
                "import os, subprocess, sys\n"
                "required = {\n"
                "  'repos/Anionix/agent-work-governor/actions/workflows/"
                "proof-slow.yml/runs',\n"
                "  'head_sha=' + 'a' * 40,\n"
                "  'event=pull_request', 'status=success', 'per_page=100',\n"
                "}\n"
                "if sys.argv[1] != 'api' or not required.issubset(set(sys.argv[2:])):\n"
                "  raise SystemExit(64)\n"
                "query = sys.argv[sys.argv.index('--jq') + 1]\n"
                "result = subprocess.run(\n"
                "  [os.environ['AWG_FIXTURE_JQ'], '-r', query,\n"
                "   os.environ['AWG_FIXTURE_JSON']],\n"
                "  check=False, capture_output=True, text=True,\n"
                ")\n"
                "sys.stdout.write(result.stdout)\n"
                "sys.stderr.write(result.stderr)\n"
                "raise SystemExit(result.returncode)\n"
            ),
            encoding="utf-8",
        )
        fake_gh.chmod(0o755)
        return subprocess.run(
            [bash, "-c", step],
            cwd=root,
            env={
                "AWG_FIXTURE_JQ": jq,
                "AWG_FIXTURE_JSON": str(fixture),
                "GH_API_URL": "https://api.github.com",
                "GH_REPOSITORY": "Anionix/agent-work-governor",
                "GH_TOKEN": "fixture",
                "GITHUB_OUTPUT": str(output),
                "PATH": f"{fake_bin}:/usr/bin:/bin",
                "PR_HEAD_SHA": head_sha,
            },
            check=False,
            capture_output=True,
            text=True,
        )


def workflow_event_paths(workflow: str, event: str) -> tuple[str, ...]:
    """Extract one event's quoted path filters without a YAML dependency."""

    lines = workflow.splitlines()
    event_index = lines.index(f"  {event}:")
    event_end = next(
        (
            index
            for index in range(event_index + 1, len(lines))
            if lines[index].startswith("  ") and not lines[index].startswith("    ")
        ),
        len(lines),
    )
    try:
        paths_index = lines.index("    paths:", event_index, event_end)
    except ValueError:
        return ()
    paths: list[str] = []
    for line in lines[paths_index + 1 :]:
        if line.startswith('      - "') and line.endswith('"'):
            paths.append(line[9:-1])
        elif line.startswith("  ") and not line.startswith("    "):
            break
    return tuple(paths)


def run_nix_bootstrap_fixture(
    *,
    downloaded_installer: bytes | None = None,
    source_mismatch: bool = False,
    action_mismatch: bool = False,
    preinstalled_nix: bool = False,
    repository_template: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run the real pre-Nix workflow script with isolated fake transport."""

    expected_installer = b"verified nix installer\n"
    downloaded_installer = downloaded_installer or expected_installer
    workflow_source = PLUGIN_ROOT / (
        "assets/repository/.github/workflows/agent-work-governor.yml"
        if repository_template
        else ".github/workflows/proof-slow.yml"
    )
    workflow = workflow_source.read_text(encoding="utf-8")
    catalog = json.loads(
        (PLUGIN_ROOT / "toolchain.lock.json").read_text(encoding="utf-8")
    )
    nix_pin = next(tool for tool in catalog["tools"] if tool["id"] == "nix")
    nix_pin["source_digest"] = (
        f"sha256:{hashlib.sha256(expected_installer).hexdigest()}"
    )
    if source_mismatch:
        nix_pin["source"] = "https://example.invalid/nix-install"
    if action_mismatch:
        workflow = workflow.replace(
            "uses: cachix/install-nix-action@630ae543ea3a38a9a4166f03376c02c50f408342",
            f"uses: cachix/install-nix-action@{'0' * 40}",
        )

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        workflow_relative = Path(
            ".github/workflows/agent-work-governor.yml"
            if repository_template
            else ".github/workflows/proof-slow.yml"
        )
        query_relative = Path(
            ".agent-work-governor/toolchain_catalog.py"
            if repository_template
            else "scripts/toolchain_catalog.py"
        )
        catalog_relative = Path(
            ".agent-work-governor/toolchain.lock.json"
            if repository_template
            else "toolchain.lock.json"
        )
        workflow_path = root / workflow_relative
        workflow_path.parent.mkdir(parents=True)
        workflow_path.write_text(workflow, encoding="utf-8")
        query_path = root / query_relative
        query_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PLUGIN_ROOT / "scripts/toolchain_catalog.py", query_path)
        catalog_path = root / catalog_relative
        catalog_path.write_text(
            json.dumps(catalog),
            encoding="utf-8",
        )
        if not repository_template:
            shutil.copy2(
                PLUGIN_ROOT / "scripts/project_toolchain_digest.py",
                root / "scripts/project_toolchain_digest.py",
            )
            for relative in project_toolchain_digest.PROJECTIONS:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(PLUGIN_ROOT / relative, target)
            project_toolchain_digest.synchronize(root, write=True)
        runner_temp = root / "runner"
        runner_temp.mkdir()
        fake_bin = root / "bin"
        fake_bin.mkdir()
        fake_curl = fake_bin / "curl"
        fake_curl.write_text(
            (
                f"#!{sys.executable}\n"
                "import pathlib, sys\n"
                "output = sys.argv[sys.argv.index('--output') + 1]\n"
                f"pathlib.Path(output).write_bytes(bytes.fromhex("
                f"'{downloaded_installer.hex()}'))\n"
            ),
            encoding="utf-8",
        )
        fake_curl.chmod(0o755)
        for name, source in (
            ("python3", Path(sys.executable)),
            ("sed", Path(shutil.which("sed") or "")),
            ("sha256sum", Path(shutil.which("sha256sum") or "")),
        ):
            if not source.is_file():
                raise unittest.SkipTest(f"{name} is unavailable")
            (fake_bin / name).symlink_to(source)
        if preinstalled_nix:
            fake_nix = fake_bin / "nix"
            fake_nix.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_nix.chmod(0o755)
        step = workflow_run_block(
            workflow,
            (
                "Validate Nix bootstrap identity"
                if repository_template
                else "Validate unified toolchain catalog"
            ),
        )
        bash = shutil.which("bash")
        if bash is None:
            raise unittest.SkipTest("bash is unavailable")
        return subprocess.run(
            [bash, "-c", step],
            cwd=root,
            env={
                "PATH": str(fake_bin),
                "PYTHONDONTWRITEBYTECODE": "1",
                "RUNNER_TEMP": str(runner_temp),
            },
            check=False,
            capture_output=True,
            text=True,
        )


def run_repository_controls_fixture(
    *,
    action: str | None = None,
    composite_action: str | None = None,
    docker_action_image: str | None = None,
    ignored_output: bool = False,
    invalid_diff: bool = False,
    contract_kind: str = "regular",
    template_action: str | None = None,
    tracked_output: str | None = None,
    uses_input: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run required repository controls against one isolated candidate tree."""

    with tempfile.TemporaryDirectory() as directory:
        if contract_kind not in {
            "regular",
            "ignored",
            "missing",
            "symlink",
            "submodule",
            "unreadable",
        }:
            raise ValueError(f"unsupported contract kind: {contract_kind}")
        root = Path(directory)
        workflow = root / ".github/workflows/fixture.yml"
        workflow.parent.mkdir(parents=True)
        action = action or f"uses: owner/action@{'a' * 40}"
        uses_input_block = (
            "\n        with:\n          uses: ordinary-input" if uses_input else ""
        )
        workflow.write_text(
            "name: fixture\non:\n  workflow_dispatch:\njobs:\n"
            "  fixture:\n    runs-on: ubuntu-24.04\n    steps:\n"
            f"      - {action}{uses_input_block}\n",
            encoding="utf-8",
        )
        if composite_action or docker_action_image:
            manifest = root / ".github/actions/local/action.yml"
            manifest.parent.mkdir(parents=True)
            manifest_source = (
                "name: fixture\ndescription: fixture\nruns:\n"
                "  using: composite\n  steps:\n"
                f"    - uses: {composite_action}\n"
                if composite_action
                else "name: fixture\ndescription: fixture\nruns:\n"
                f"  using: docker\n  image: {docker_action_image}\n"
            )
            manifest.write_text(manifest_source, encoding="utf-8")
        if template_action:
            template = root / "assets/repository/.github/workflows/template.yml"
            template.parent.mkdir(parents=True)
            template.write_text(
                "name: template\non:\n  workflow_dispatch:\njobs:\n"
                "  fixture:\n    runs-on: ubuntu-24.04\n    steps:\n"
                f"      - uses: {template_action}\n",
                encoding="utf-8",
            )
        required = "AGENTS.md CONTRIBUTING.md SECURITY.md flake.nix flake.lock"
        for name in required.split():
            if not (contract_kind == "missing" and name == "SECURITY.md"):
                (root / name).write_text("", encoding="utf-8")
        if contract_kind == "symlink":
            (root / "SECURITY.md").unlink()
            (root / "SECURITY.md").symlink_to("AGENTS.md")
        (root / ".gitignore").write_text("runtime/\n", encoding="utf-8")
        output_path = "runtime/cache" if ignored_output else tracked_output
        if output_path:
            output = root / output_path
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text("runtime\n", encoding="utf-8")

        def git(*arguments: str) -> str:
            return subprocess.check_output(
                ["git", *arguments], cwd=root, text=True
            ).strip()

        git("init", "-q")
        git("config", "user.name", "Fixture")
        git("config", "user.email", "fixture@example.invalid")
        git("config", "commit.gpgsign", "false")
        git("add", ".")
        if ignored_output:
            git("add", "-f", "runtime/cache")
        git("commit", "-qm", "fixture")
        base = git("rev-parse", "HEAD")
        if contract_kind == "ignored":
            (root / ".gitignore").write_text(
                "runtime/\nSECURITY.md\n", encoding="utf-8"
            )
            git("add", ".gitignore")
            git("commit", "-qm", "ignore tracked contract")
        elif contract_kind == "submodule":
            git(
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{base},SECURITY.md",
            )
            git("commit", "-qm", "replace contract with gitlink")
        elif contract_kind == "unreadable":
            object_id = git("rev-parse", "HEAD:SECURITY.md")
            loose_object = root / ".git/objects" / object_id[:2] / object_id[2:]
            loose_object.chmod(0o600)
            loose_object.write_bytes(zlib.compress(b"blob 100\0"))
        if invalid_diff:
            invalid = root / "docs/invalid.md"
            invalid.parent.mkdir()
            invalid.write_text("trailing whitespace  \n", encoding="utf-8")
            git("add", "docs/invalid.md")
            git("commit", "-qm", "invalid diff")
        head = git("rev-parse", "HEAD")
        return subprocess.run(
            [
                shutil.which("bash") or "bash",
                str(PLUGIN_ROOT / "scripts/validate_repository_controls.sh"),
                base,
                head,
            ],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )


class PolicyTests(unittest.TestCase):
    def test_safe_and_owner_presets_validate(self) -> None:
        policies = (
            PLUGIN_ROOT / "assets/repository/.agent-work-governor/policy.toml",
            PLUGIN_ROOT / "assets/presets/owner-original.toml",
        )
        for path in policies:
            with self.subTest(path=path):
                self.assertTrue(validate_policy.build_receipt(path)["valid"])

    def test_unknown_scope_cannot_grant_write(self) -> None:
        policy = {
            "schema_version": "0.1",
            "policy_id": "unsafe",
            "repository_scope": "unknown",
            "authority": {
                "repository_write": True,
                "external_side_effects": False,
                "destructive_actions": False,
            },
            "budget": {
                "max_in_flight": 1,
                "max_delegation_depth": 0,
                "max_repair_rounds": 0,
            },
            "routing": {
                "authority": "ask-matt-or-explicit-user-selection",
                "require_explicit_route": True,
                "allow_route_substitution": False,
                "implicit_ask_matt_invocation": False,
                "ask_matt_sha256": "0" * 64,
            },
            "completion": {
                "require_terminal_evidence": True,
                "require_satisfied_postcondition": True,
                "require_current_artifact_review": True,
            },
            "knowledge": {"okf_version": "0.2", "bundle": "knowledge"},
            "receipts": {
                "directory": ".governance/receipts",
                "include_in_okf_bundle": False,
            },
        }
        codes = {item["code"] for item in validate_policy.validate_document(policy)}
        self.assertIn("SCOPE_AUTHORITY_CONFLICT", codes)

    def test_external_repository_cannot_self_authorize_write(self) -> None:
        policy = {
            "schema_version": "0.1",
            "policy_id": "self-authored-external",
            "repository_scope": "authorized_external",
            "authority": {
                "repository_write": True,
                "external_side_effects": True,
                "destructive_actions": False,
            },
            "external_authority": {
                "authority_receipt": "repo://self-authored-receipt",
                "authority_receipt_sha256": "0" * 64,
                "upstream_policy": "repo://self-authored-policy",
                "upstream_policy_sha256": "1" * 64,
            },
            "budget": {
                "max_in_flight": 1,
                "max_delegation_depth": 0,
                "max_repair_rounds": 0,
            },
            "routing": {
                "authority": "ask-matt-or-explicit-user-selection",
                "require_explicit_route": True,
                "allow_route_substitution": False,
                "implicit_ask_matt_invocation": False,
                "ask_matt_sha256": validate_policy.ASK_MATT_SHA256,
            },
            "completion": {
                "require_terminal_evidence": True,
                "require_satisfied_postcondition": True,
                "require_current_artifact_review": True,
            },
            "knowledge": {"okf_version": "0.2", "bundle": "knowledge"},
            "receipts": {
                "directory": ".governance/receipts",
                "include_in_okf_bundle": False,
            },
        }
        codes = {item["code"] for item in validate_policy.validate_document(policy)}
        self.assertIn("EXTERNAL_WRITE_ADAPTER_UNAVAILABLE", codes)

    def test_owner_rules_are_enforced_not_decorative(self) -> None:
        path = PLUGIN_ROOT / "assets/presets/owner-original.toml"
        policy, parse_findings = validate_policy.load_policy(path)
        self.assertEqual([], parse_findings)
        self.assertIsNotNone(policy)
        assert policy is not None
        policy["github"]["one_pr_one_task"] = False
        policy["quality"]["require_code_review_skill"] = False
        policy["environment"]["require_nix_flake"] = False
        codes = {item["code"] for item in validate_policy.validate_document(policy)}
        self.assertIn("UNSAFE_VALUE", codes)

    def test_receipt_attestation_binds_policy_and_validator(self) -> None:
        policy = PLUGIN_ROOT / "assets/repository/.agent-work-governor/policy.toml"
        receipt = validate_policy.build_receipt(policy)
        self.assertEqual("PASS", attest_policy.attest(receipt, policy)["verdict"])
        mutated = dict(receipt)
        mutated["policy_sha256"] = "0" * 64
        self.assertEqual("FAIL", attest_policy.attest(mutated, policy)["verdict"])


class ContractBlockTests(unittest.TestCase):
    def test_marker_alone_is_invalid(self) -> None:
        self.assertFalse(contract_blocks.has_valid_contract("# LLM-CONTRACT\n"))

    def test_state_requires_transition_arrow(self) -> None:
        source = (
            "# LLM-CONTRACT\n"
            "# id: example.invalid-state\n"
            "# state: ONLY_ONE_STATE\n"
            "# preconditions: input exists\n"
            "# invariant: bounded\n"
            "# failure: fail closed\n"
            "# source: https://example.invalid/source\n"
            "# knowledge: AGENTS.md\n"
            "# enforced_by: example\n"
            "# test: tests/test_example.py\n"
        )
        self.assertEqual(
            "state field must contain a transition arrow (->)",
            contract_blocks.contract_diagnostic(source),
        )

    def test_complete_contract_is_valid(self) -> None:
        source = (
            "// LLM-CONTRACT\n"
            "// id: example.complete\n"
            "// state: INPUT -> OUTPUT\n"
            "// preconditions: input exists\n"
            "// invariant: output is bounded\n"
            "// failure: return a typed error\n"
            "// source: https://example.invalid/source\n"
            "// knowledge: AGENTS.md\n"
            "// enforced_by: example\n"
            "// test: tests/test_example.py\n"
        )
        self.assertTrue(contract_blocks.has_valid_contract(source))


class OkfTests(unittest.TestCase):
    def test_plugin_bundle_passes_both_layers(self) -> None:
        report = validate_okf.validate_bundle(PLUGIN_ROOT / "knowledge")
        self.assertEqual("valid", report["okf_core"]["status"])
        self.assertEqual("valid", report["governor_profile"]["status"])

    def test_missing_index_is_profile_only_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            (bundle / "concept.md").write_text(
                json_frontmatter(profile_metadata()),
                encoding="utf-8",
            )
            report = validate_okf.validate_bundle(bundle)
        self.assertEqual("valid", report["okf_core"]["status"])
        self.assertEqual("invalid", report["governor_profile"]["status"])

    def test_root_index_without_version_is_profile_only_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            (bundle / "index.md").write_text("# Index\n", encoding="utf-8")
            (bundle / "concept.md").write_text(
                json_frontmatter(profile_metadata()),
                encoding="utf-8",
            )
            report = validate_okf.validate_bundle(bundle)
        self.assertEqual("valid", report["okf_core"]["status"])
        self.assertEqual("invalid", report["governor_profile"]["status"])

    def test_unknown_type_key_and_broken_link_are_not_core_failures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            (bundle / "index.md").write_text(
                '---\n{"okf_version":"0.2"}\n---\n# Index\n',
                encoding="utf-8",
            )
            metadata = profile_metadata("Future Concept")
            metadata["unknown_extension"] = {"safe": True}
            (bundle / "concept.md").write_text(
                json_frontmatter(metadata, "[Missing](not-yet-written.md)\n"),
                encoding="utf-8",
            )
            report = validate_okf.validate_bundle(bundle)
        self.assertEqual("valid", report["okf_core"]["status"])
        self.assertEqual("valid", report["governor_profile"]["status"])
        self.assertEqual("BROKEN_LINK_ALLOWED_BY_OKF", report["warnings"][0]["code"])

    def test_missing_type_is_core_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            metadata = profile_metadata()
            metadata.pop("type")
            (bundle / "concept.md").write_text(
                json_frontmatter(metadata),
                encoding="utf-8",
            )
            report = validate_okf.validate_bundle(bundle)
        self.assertEqual("invalid", report["okf_core"]["status"])

    def test_general_yaml_without_parser_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            (bundle / "concept.md").write_text(
                "---\ntype: Reference\n---\n# Body\n",
                encoding="utf-8",
            )
            report = validate_okf.validate_bundle(bundle)
        self.assertEqual("inconclusive", report["okf_core"]["status"])

    def test_invalid_source_actor_is_profile_failure_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            (bundle / "index.md").write_text(
                '---\n{"okf_version":"0.2"}\n---\n# Index\n',
                encoding="utf-8",
            )
            metadata = profile_metadata()
            metadata["sources"] = [
                {
                    "resource": "https://example.invalid/source",
                    "author": "team:not-an-okf-actor",
                    "last_modified": "2026-07-24",
                }
            ]
            (bundle / "concept.md").write_text(
                json_frontmatter(metadata),
                encoding="utf-8",
            )
            report = validate_okf.validate_bundle(bundle)
        self.assertEqual("valid", report["okf_core"]["status"])
        self.assertEqual("invalid", report["governor_profile"]["status"])
        codes = {item["code"] for item in report["governor_profile"]["errors"]}
        self.assertIn("PROFILE_SOURCE_AUTHOR_INVALID", codes)


class DoctorTests(unittest.TestCase):
    def test_mutable_fixture_copy_drops_read_only_source_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.lock"
            target = root / "fixture/target.lock"
            source.write_text("locked\n", encoding="utf-8")
            source.chmod(0o444)
            copy_mutable_fixture(source, target)
            target.write_text("mutated\n", encoding="utf-8")
            self.assertEqual("mutated\n", target.read_text(encoding="utf-8"))
            self.assertEqual(0, source.stat().st_mode & 0o222)

    def test_unknown_okf_status_fails_closed(self) -> None:
        self.assertEqual("PASS", doctor.normalize_validator_status("valid"))
        self.assertEqual(
            "INCONCLUSIVE", doctor.normalize_validator_status("inconclusive")
        )
        self.assertEqual("FAIL", doctor.normalize_validator_status("invalid"))
        self.assertEqual("FAIL", doctor.normalize_validator_status("future-status"))

    def test_audit_exit_codes_do_not_admit_inconclusive(self) -> None:
        expected = {"PASS": 0, "WARN": 0, "FAIL": 1, "INCONCLUSIVE": 2, "future": 2}
        for status, exit_code in expected.items():
            with self.subTest(status=status):
                self.assertEqual(exit_code, doctor.audit_exit_code(status))

    def test_doctor_marks_corrupt_rust_as_fail(self) -> None:
        with mock.patch.object(
            rust_dispatch,
            "resolve_binary",
            side_effect=rust_dispatch.IntegrityError("fixture digest mismatch"),
        ):
            report = doctor.audit(PLUGIN_ROOT)
        findings = {item["check"]: item["status"] for item in report["findings"]}
        self.assertEqual("FAIL", findings["rust_core_artifact"])
        self.assertEqual("FAIL", findings["rust_okf_core"])
        self.assertEqual("FAIL", report["overall"])

    def test_doctor_marks_unsupported_rust_as_inconclusive(self) -> None:
        with mock.patch.object(
            rust_dispatch,
            "resolve_binary",
            side_effect=rust_dispatch.UnsupportedHostError("fixture host"),
        ):
            report = doctor.audit(PLUGIN_ROOT)
        findings = {item["check"]: item["status"] for item in report["findings"]}
        self.assertEqual("INCONCLUSIVE", findings["rust_core_artifact"])
        self.assertEqual("INCONCLUSIVE", findings["rust_okf_core"])
        self.assertNotEqual("PASS", report["overall"])

    def test_main_preserves_machine_readable_exit_contract(self) -> None:
        for status, expected in (("PASS", 0), ("FAIL", 1), ("INCONCLUSIVE", 2)):
            report = {"overall": status, "findings": [], "mutation_count": 0}
            with (
                self.subTest(status=status),
                mock.patch.object(doctor, "audit", return_value=report),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(
                    expected,
                    doctor.main(["--repo", str(PLUGIN_ROOT), "--json"]),
                )

    def test_runtime_drift_during_doctor_check_is_structured_fail(self) -> None:
        selection = bundled_runtime_or_skip(self)
        with mock.patch.object(
            rust_dispatch,
            "invoke",
            side_effect=rust_dispatch.IntegrityError("fixture concurrent drift"),
        ):
            status, evidence, report = doctor.rust_check(selection, ["okf", "fixture"])
        self.assertEqual("FAIL", status)
        self.assertIn("concurrent drift", evidence)
        self.assertIsNone(report)

    def test_canonical_runtime_is_deterministic_and_isolated(self) -> None:
        entries = validate_canonical.load_lock(PLUGIN_ROOT)
        runtime = validate_canonical.load_runtime(PLUGIN_ROOT, entries)
        self.assertEqual(
            hashlib.sha256(runtime.payload).hexdigest(),
            runtime.sha256,
        )
        with zipfile.ZipFile(io.BytesIO(runtime.payload)) as packaged:
            self.assertEqual(
                list(package_canonical_runtime.ARCHIVE_MEMBERS),
                packaged.namelist(),
            )
            self.assertNotIn("yaml/cyaml.py", packaged.namelist())
            self.assertTrue(packaged.read("PyYAML-LICENSE").startswith(b"Copyright"))
            self.assertTrue(
                all(
                    item.compress_type == zipfile.ZIP_STORED
                    for item in packaged.infolist()
                )
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target space ü"
            target.mkdir()
            (target / "input.txt").write_text("unchanged\n", encoding="utf-8")
            poison = root / "poison"
            poison.mkdir()
            (poison / "yaml.py").write_text(
                "raise RuntimeError('ambient yaml imported')\n",
                encoding="utf-8",
            )
            validator = root / "validator.py"
            validator.write_text(
                "import sys, yaml\n"
                "assert yaml.safe_load('enabled: true') == {'enabled': True}\n"
                "print(sys.flags.isolated, sys.flags.no_site, "
                "int(yaml.__with_libyaml__))\n",
                encoding="utf-8",
            )
            before = {
                path.relative_to(target): (path.read_bytes(), path.stat().st_mode)
                for path in target.rglob("*")
                if path.is_file()
            }
            with (
                mock.patch.dict(os.environ, {"PYTHONPATH": str(poison)}),
                mock.patch.object(
                    validate_canonical.urllib.request,
                    "urlopen",
                    side_effect=AssertionError("doctor must not use the network"),
                ),
            ):
                validator_status, validator_evidence = doctor.canonical_validator(
                    validator=validator,
                    expected_sha256=hashlib.sha256(validator.read_bytes()).hexdigest(),
                    target=target,
                    runtime=runtime,
                )
            after = {
                path.relative_to(target): (path.read_bytes(), path.stat().st_mode)
                for path in target.rglob("*")
                if path.is_file()
            }
        self.assertEqual(("PASS", "1 1 0"), (validator_status, validator_evidence))
        self.assertEqual(before, after)

        with tempfile.TemporaryDirectory() as directory:
            validator = Path(directory) / "validator.py"
            validator.write_text("import missing_validator_module\n", encoding="utf-8")
            rejected_status, rejected_evidence = doctor.canonical_validator(
                validator=validator,
                expected_sha256=hashlib.sha256(validator.read_bytes()).hexdigest(),
                target=Path(directory),
                runtime=runtime,
            )
        self.assertEqual("FAIL", rejected_status)
        self.assertIn("ModuleNotFoundError", rejected_evidence)
        self.assertNotIn("VALIDATOR_RUNTIME", rejected_evidence)

        poisoned = io.BytesIO()
        with zipfile.ZipFile(poisoned, "w") as archive:
            archive.writestr("yaml/__init__.py", "raise RuntimeError('poisoned')\n")
        poisoned_payload = poisoned.getvalue()
        poisoned_runtime = validate_canonical.RuntimeSnapshot(
            poisoned_payload,
            runtime.runner,
            hashlib.sha256(poisoned_payload).hexdigest(),
            "fixture",
        )
        with tempfile.TemporaryDirectory() as directory:
            validator = Path(directory) / "validator.py"
            validator.write_text("import yaml\n", encoding="utf-8")
            with self.assertRaises(validate_canonical.CanonicalRuntimeError) as blocked:
                validate_canonical.run_validator(
                    validator,
                    hashlib.sha256(validator.read_bytes()).hexdigest(),
                    poisoned_runtime,
                    Path(directory),
                )
        self.assertEqual(
            "VALIDATOR_RUNTIME_IMPORT_FAILED:RuntimeError",
            blocked.exception.code,
        )

    def test_canonical_runtime_rebuild_rejects_lock_drift(self) -> None:
        source = io.BytesIO()
        with tarfile.open(fileobj=source, mode="w:gz") as archive:
            for output_name in package_canonical_runtime.ARCHIVE_MEMBERS:
                source_name = (
                    "pyyaml-6.0.3/LICENSE"
                    if output_name == "PyYAML-LICENSE"
                    else f"pyyaml-6.0.3/lib/{output_name}"
                )
                payload = f"# {output_name}\n".encode()
                member = tarfile.TarInfo(source_name)
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        source_bytes = source.getvalue()
        source_sha256 = hashlib.sha256(source_bytes).hexdigest()

        with self.assertRaisesRegex(ValueError, "source size mismatch"):
            package_canonical_runtime.build_archive(
                source_bytes,
                source_sha256,
                len(source_bytes) + 1,
                "6.0.3",
            )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_path = root / "pyyaml.tar.gz"
            output_path = root / "runtime.zip"
            source_path.write_bytes(source_bytes)
            with contextlib.redirect_stderr(io.StringIO()):
                result = package_canonical_runtime.main(
                    [
                        "--source",
                        str(source_path),
                        "--source-sha256",
                        source_sha256,
                        "--source-size",
                        str(len(source_bytes)),
                        "--version",
                        "6.0.3",
                        "--output",
                        str(output_path),
                        "--expected-sha256",
                        "0" * 64,
                    ]
                )
            self.assertEqual(1, result)
            self.assertFalse(output_path.exists())

    def test_canonical_runtime_faults_are_typed_and_fail_closed(self) -> None:
        entries = validate_canonical.load_lock(PLUGIN_ROOT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock_target = root / "references/canonical-runtime.lock.json"
            copy_mutable_fixture(
                PLUGIN_ROOT / "references/canonical-runtime.lock.json",
                lock_target,
            )
            dependency_lock_target = root / "uv.lock"
            copy_mutable_fixture(PLUGIN_ROOT / "uv.lock", dependency_lock_target)
            builder_target = root / "scripts/package_canonical_runtime.py"
            builder_target.parent.mkdir()
            shutil.copy2(
                PLUGIN_ROOT / "scripts/package_canonical_runtime.py",
                builder_target,
            )
            runner_target = root / "scripts/canonical_runtime_runner.py"
            shutil.copy2(
                PLUGIN_ROOT / "scripts/canonical_runtime_runner.py",
                runner_target,
            )

            fifo_probe = """
import importlib.util
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("validate_canonical_probe", sys.argv[1])
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
operation = sys.argv[2]
expected = sys.argv[3]
try:
    if operation == "lock":
        module.load_lock(Path(sys.argv[4]))
    elif operation == "runtime":
        entries = module.load_lock(Path(sys.argv[4]))
        module.load_runtime(Path(sys.argv[5]), entries)
    else:
        raise SystemExit(4)
except module.CanonicalRuntimeError as error:
    print(error.code)
    raise SystemExit(0 if error.code == expected else 2)
raise SystemExit(3)
"""

            def run_fifo_probe(*arguments: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-S",
                        "-c",
                        fifo_probe,
                        str(PLUGIN_ROOT / "scripts/validate_canonical.py"),
                        *arguments,
                    ],
                    capture_output=True,
                    check=False,
                    text=True,
                    timeout=2,
                )

            validator_lock_target = root / "references/canonical-validators.lock.json"
            os.mkfifo(validator_lock_target)
            validator_lock_result = run_fifo_probe(
                "lock",
                "CANONICAL_VALIDATOR_LOCK_INVALID",
                str(root),
            )
            self.assertEqual(
                0,
                validator_lock_result.returncode,
                validator_lock_result.stderr,
            )
            self.assertEqual(
                "CANONICAL_VALIDATOR_LOCK_INVALID",
                validator_lock_result.stdout.strip(),
            )
            validator_lock_target.unlink()

            with self.assertRaises(validate_canonical.CanonicalRuntimeError) as missing:
                validate_canonical.load_runtime(root, entries)
            self.assertEqual("VALIDATOR_RUNTIME_MISSING", missing.exception.code)
            self.assertTrue(missing.exception.inconclusive)

            runtime_target = root / "vendor/pyyaml-6.0.3.zip"
            runtime_target.parent.mkdir()
            runtime_target.write_bytes(b"corrupt")
            with self.assertRaises(
                validate_canonical.CanonicalRuntimeError
            ) as mismatch:
                validate_canonical.load_runtime(root, entries)
            self.assertEqual(
                "VALIDATOR_RUNTIME_DIGEST_MISMATCH",
                mismatch.exception.code,
            )
            self.assertFalse(mismatch.exception.inconclusive)

            runtime_target.unlink()
            runtime_target.symlink_to(PLUGIN_ROOT / "vendor/pyyaml-6.0.3.zip")
            with self.assertRaises(validate_canonical.CanonicalRuntimeError) as symlink:
                validate_canonical.load_runtime(root, entries)
            self.assertTrue(
                symlink.exception.code.startswith("VALIDATOR_RUNTIME_INVALID")
            )

            runtime_target.unlink()
            runtime_target.mkdir()
            with self.assertRaises(
                validate_canonical.CanonicalRuntimeError
            ) as directory_error:
                validate_canonical.load_runtime(root, entries)
            self.assertEqual(
                "VALIDATOR_RUNTIME_INVALID",
                directory_error.exception.code,
            )

            runtime_target.rmdir()
            os.mkfifo(runtime_target)
            fifo_result = run_fifo_probe(
                "runtime",
                "VALIDATOR_RUNTIME_INVALID",
                str(PLUGIN_ROOT),
                str(root),
            )
            self.assertEqual(0, fifo_result.returncode, fifo_result.stderr)
            self.assertEqual(
                "VALIDATOR_RUNTIME_INVALID",
                fifo_result.stdout.strip(),
            )

            runtime_target.unlink()
            dependency_lock_target.write_text(
                'version = 1\n[[package]]\nname = "agent-work-governor"\n',
                encoding="utf-8",
            )
            with self.assertRaises(
                validate_canonical.CanonicalRuntimeError
            ) as dependency_lock:
                validate_canonical.load_runtime(root, entries)
            self.assertEqual(
                "VALIDATOR_RUNTIME_DEPENDENCY_LOCK_INVALID",
                dependency_lock.exception.code,
            )
            copy_mutable_fixture(PLUGIN_ROOT / "uv.lock", dependency_lock_target)
            coherent_drift = dependency_lock_target.read_text(encoding="utf-8").replace(
                'runtime-build = [{ name = "pyyaml", specifier = "==6.0.3" }]',
                'runtime-build = [{ name = "pyyaml", specifier = "==6.0.4" }]',
                1,
            )
            coherent_drift = coherent_drift.replace(
                'name = "pyyaml"\nversion = "6.0.3"',
                'name = "pyyaml"\nversion = "6.0.4"',
                1,
            )
            coherent_drift = coherent_drift.replace(
                "/pyyaml-6.0.3.tar.gz",
                "/pyyaml-6.0.4.tar.gz",
                1,
            )
            dependency_lock_target.write_text(
                coherent_drift,
                encoding="utf-8",
            )
            with self.assertRaises(
                validate_canonical.CanonicalRuntimeError
            ) as identity_drift:
                validate_canonical.load_runtime(root, entries)
            self.assertEqual(
                "VALIDATOR_RUNTIME_DEPENDENCY_IDENTITY_MISMATCH",
                identity_drift.exception.code,
            )
            copy_mutable_fixture(PLUGIN_ROOT / "uv.lock", dependency_lock_target)
            lock_target.write_text("{}\n", encoding="utf-8")
            with self.assertRaises(
                validate_canonical.CanonicalRuntimeError
            ) as invalid_lock:
                validate_canonical.load_runtime(root, entries)
            self.assertEqual(
                "VALIDATOR_RUNTIME_LOCK_INVALID",
                invalid_lock.exception.code,
            )

    def test_canonical_runtime_snapshot_survives_source_replacement(self) -> None:
        entries = validate_canonical.load_lock(PLUGIN_ROOT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in (
                Path("references/canonical-runtime.lock.json"),
                Path("scripts/canonical_runtime_runner.py"),
                Path("scripts/package_canonical_runtime.py"),
                Path("uv.lock"),
                Path("vendor/pyyaml-6.0.3.zip"),
            ):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                if relative == Path("vendor/pyyaml-6.0.3.zip"):
                    copy_mutable_fixture(PLUGIN_ROOT / relative, target)
                else:
                    shutil.copy2(PLUGIN_ROOT / relative, target)
            runtime = validate_canonical.load_runtime(root, entries)
            validator_path = root / "validator.py"
            validator_path.write_text(
                "import yaml\nprint(yaml.safe_load('value: 7')['value'])\n",
                encoding="utf-8",
            )
            validator_sha = hashlib.sha256(validator_path.read_bytes()).hexdigest()
            real_run = subprocess.run

            def replace_sources(*args, **kwargs):
                (root / "vendor/pyyaml-6.0.3.zip").write_bytes(b"replaced")
                validator_path.write_text(
                    "raise RuntimeError('replaced')\n",
                    encoding="utf-8",
                )
                return real_run(*args, **kwargs)

            with mock.patch.object(
                validate_canonical.subprocess,
                "run",
                side_effect=replace_sources,
            ):
                process = validate_canonical.run_validator(
                    validator_path,
                    validator_sha,
                    runtime,
                    root,
                )
        self.assertEqual(0, process.returncode, process.stderr)
        self.assertEqual("7", process.stdout.strip())

    def test_packaged_doctor_runtime_checks_pass(self) -> None:
        bundled_runtime_or_skip(self)
        report = doctor.audit(PLUGIN_ROOT)
        states = {item["check"]: item["status"] for item in report["findings"]}
        self.assertEqual("PASS", states["rust_core_artifact"])
        self.assertEqual("PASS", states["rust_okf_core"])
        self.assertEqual("PASS", states["okf_runtime_differential"])

    def test_canonical_validator_locks_match_installed_sources(self) -> None:
        lock = validate_canonical.load_lock(PLUGIN_ROOT)
        runtime = validate_canonical.load_runtime(PLUGIN_ROOT, lock)
        targets = {
            "plugin_validator": PLUGIN_ROOT,
            "skill_validator": PLUGIN_ROOT / "skills/check-governor-policy",
        }
        for key in ("plugin_validator", "skill_validator"):
            path = Path.home() / lock[key]["path"]
            self.assertEqual(
                (
                    "https://raw.githubusercontent.com/openai/codex/"
                    f"{lock[key]['source_commit']}/{lock[key]['source_path']}"
                ),
                lock[key]["source_url"],
            )
            if path.is_file():
                self.assertEqual(
                    lock[key]["sha256"],
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )
                validator = validate_canonical.verified_installed_validator(lock[key])
                assert validator is not None
                process = validate_canonical.run_validator(
                    validator,
                    lock[key]["sha256"],
                    runtime,
                    targets[key],
                )
                self.assertEqual(0, process.returncode, process.stderr)

    def test_code_review_source_lock_matches_installed_source(self) -> None:
        lock = json.loads(
            (PLUGIN_ROOT / "references/code-review.lock.json").read_text(
                encoding="utf-8"
            )
        )
        path = Path.home() / ".codex/skills/code-review/SKILL.md"
        if not path.is_file():
            self.skipTest("code-review Skill is not installed")
        self.assertEqual(lock["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())


class RustDispatchTests(unittest.TestCase):
    @staticmethod
    def runtime_bundle(
        root: Path,
        *,
        stdout: str = '{"status":"PASS","mutation_count":0}',
        exit_code: int = 0,
        delay_seconds: float = 0,
    ) -> Path:
        for relative in rust_dispatch.SOURCE_INPUTS:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"fixture:{relative}\n", encoding="utf-8")
        source = root / "rust/src/main.rs"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("// fixture\n", encoding="utf-8")
        test_source = root / "rust/tests/fixture.rs"
        test_source.parent.mkdir(parents=True, exist_ok=True)
        test_source.write_text("// fixture\n", encoding="utf-8")
        target = rust_dispatch.host_target()
        binary = root / f"bin/{target}/agent-work-governor"
        binary.parent.mkdir(parents=True, exist_ok=True)
        delay = f"sleep {delay_seconds}\n" if delay_seconds else ""
        binary.write_text(
            f"#!/bin/sh\n{delay}printf '%s' '{stdout}'\nexit {exit_code}\n",
            encoding="utf-8",
        )
        binary.chmod(0o755)
        manifest = rust_dispatch.build_manifest(
            root,
            binary.relative_to(root),
            target=target,
            component_version="0.1.0",
            rustc_version="rustc fixture",
        )
        (root / "bin/manifest.json").write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )
        return binary

    def test_host_mapping_is_explicit(self) -> None:
        self.assertEqual(
            "aarch64-apple-darwin",
            rust_dispatch.host_target("Darwin", "arm64"),
        )
        self.assertEqual(
            "x86_64-unknown-linux-gnu",
            rust_dispatch.host_target("Linux", "amd64"),
        )
        with self.assertRaises(rust_dispatch.UnsupportedHostError):
            rust_dispatch.host_target("Plan9", "mips")

    def test_verified_fixture_runs_without_a_shell_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.runtime_bundle(root)
            selection = rust_dispatch.resolve_binary(root)
            invocation = rust_dispatch.invoke(selection, ["okf", "fixture"])
        self.assertEqual("PASS", rust_dispatch.invocation_status(invocation))
        self.assertIsNotNone(invocation.report)
        assert invocation.report is not None
        self.assertEqual(0, invocation.report["mutation_count"])

    def test_package_runtime_writes_resolvable_manifest_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = self.runtime_bundle(root)
            (root / rust_dispatch.MANIFEST).unlink()
            arguments = [
                "--plugin-root",
                str(root),
                "--relative-binary",
                str(binary.relative_to(root)),
                "--target",
                rust_dispatch.host_target(),
                "--component-version",
                "0.1.0",
                "--rustc-version",
                "rustc fixture",
            ]
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(0, package_runtime.main(arguments))
            self.assertEqual(binary.resolve(), rust_dispatch.resolve_binary(root).path)
            with contextlib.redirect_stderr(output):
                self.assertEqual(1, package_runtime.main(arguments))

    def test_digest_drift_and_symlinks_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = self.runtime_bundle(root)
            binary.write_bytes(binary.read_bytes() + b"drift")
            with self.assertRaises(rust_dispatch.IntegrityError):
                rust_dispatch.resolve_binary(root)

            self.runtime_bundle(root)
            catalog = root / "toolchain.lock.json"
            catalog.write_bytes(catalog.read_bytes() + b"drift")
            with self.assertRaises(rust_dispatch.IntegrityError):
                rust_dispatch.resolve_binary(root)

            binary = self.runtime_bundle(root)
            outside = root / "outside"
            shutil.copy2(binary, outside)
            binary.unlink()
            binary.symlink_to(outside)
            with self.assertRaises(rust_dispatch.IntegrityError):
                rust_dispatch.resolve_binary(root)

    def test_invalid_json_and_usage_exit_are_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.runtime_bundle(root, stdout="not-json")
            invocation = rust_dispatch.run_rust(["okf"], plugin_root=root)
            self.assertEqual(
                "INCONCLUSIVE",
                rust_dispatch.invocation_status(invocation),
            )

    def test_timeout_is_a_typed_inconclusive_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.runtime_bundle(root, delay_seconds=1)
            selection = rust_dispatch.resolve_binary(root)
            with self.assertRaises(rust_dispatch.InvocationError):
                rust_dispatch.invoke(selection, ["okf"], timeout_seconds=0)

            self.runtime_bundle(root, exit_code=64)
            invocation = rust_dispatch.run_rust(["okf"], plugin_root=root)
            self.assertEqual(
                "INCONCLUSIVE",
                rust_dispatch.invocation_status(invocation),
            )

    def test_bundled_release_matches_manifest_and_component_version(self) -> None:
        selection = bundled_runtime_or_skip(self)
        process = subprocess.run(
            [str(selection.path), "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(0, process.returncode, process.stderr)
        self.assertEqual(
            f"agent-work-governor {selection.component_version}",
            process.stdout.strip(),
        )

    def test_policy_and_okf_overlap_matches_rust(self) -> None:
        selection = bundled_runtime_or_skip(self)
        policy_path = PLUGIN_ROOT / "assets/presets/owner-original.toml"
        policy = rust_dispatch.invoke(selection, ["policy", str(policy_path)])
        self.assertEqual("PASS", rust_dispatch.invocation_status(policy))
        self.assertIsNotNone(policy.report)
        assert policy.report is not None
        python_policy = validate_policy.build_receipt(policy_path)
        self.assertEqual(python_policy["valid"], policy.report["valid"])
        self.assertEqual(
            [item["code"] for item in python_policy["findings"]],
            [item["code"] for item in policy.report["findings"]],
        )

        okf = rust_dispatch.invoke(
            selection,
            ["okf", str(PLUGIN_ROOT / "knowledge")],
        )
        self.assertEqual("PASS", rust_dispatch.invocation_status(okf))
        self.assertIsNotNone(okf.report)
        assert okf.report is not None
        python_okf = validate_okf.validate_bundle(PLUGIN_ROOT / "knowledge")
        self.assertEqual(
            python_okf["okf_core"]["status"],
            okf.report["okf_core"]["status"],
        )
        self.assertEqual(
            python_okf["governor_profile"]["status"],
            okf.report["governor_profile"]["status"],
        )


class RouterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = json.loads(
            (PLUGIN_ROOT / "adapters/ask-matt-routes.json").read_text(encoding="utf-8")
        )
        self.source_lock = json.loads(
            (PLUGIN_ROOT / "references/ask-matt.lock.json").read_text(encoding="utf-8")
        )

    def test_adapter_and_source_lock_are_identical(self) -> None:
        self.assertEqual(self.source_lock["commit"], self.adapter["source"]["commit"])
        self.assertEqual(self.source_lock["sha256"], self.adapter["source"]["sha256"])

    def test_adapter_cannot_route_or_substitute(self) -> None:
        authority = self.adapter["authority"]
        self.assertFalse(authority["route_substitution"])
        self.assertFalse(authority["implicit_ask_matt_invocation"])
        self.assertEqual(
            "ROUTE_DECISION_REQUIRED", self.adapter["missing_route_result"]
        )
        self.assertEqual(
            "SETUP_REQUIRED",
            self.adapter["preconditions"]["engineering_flow"]["missing_result"],
        )

    def test_route_ids_are_unique(self) -> None:
        route_ids = [route["route_id"] for route in self.adapter["routes"]]
        self.assertEqual(len(route_ids), len(set(route_ids)))

    def test_main_flow_preserves_single_and_multi_session_branches(self) -> None:
        main_routes = {
            route["selection_receipt"]["multi_session"]: route["selected_flow"]
            for route in self.adapter["routes"]
            if route["route_id"].startswith("idea-to-ship-codebase-")
        }
        self.assertEqual(
            {
                False: ["grill-with-docs", "implement"],
                True: [
                    "grill-with-docs",
                    "to-spec",
                    "to-tickets",
                    "implement",
                ],
            },
            main_routes,
        )

    def test_adapter_covers_every_ask_matt_standalone_route(self) -> None:
        selected = {
            skill
            for route in self.adapter["routes"]
            for skill in route["selected_flow"]
        }
        expected = {
            "code-review",
            "codebase-design",
            "compact",
            "domain-modeling",
            "grill-me",
            "handoff",
            "implement",
            "prototype",
            "research",
            "setup-matt-pocock-skills",
            "tdd",
            "teach",
            "writing-great-skills",
        }
        self.assertLessEqual(expected, selected)

    def test_wayfinder_preserves_small_and_mapped_outcomes(self) -> None:
        outcomes = {
            route["selection_receipt"]["wayfinder_outcome"]: route["selected_flow"]
            for route in self.adapter["routes"]
            if route["route_id"].startswith("huge-foggy-effort-")
        }
        self.assertEqual(
            {
                "genuinely-small": ["wayfinder", "implement"],
                "multi-session-map": [
                    "wayfinder",
                    "to-spec",
                    "to-tickets",
                    "implement",
                ],
            },
            outcomes,
        )

    def test_installed_source_matches_when_present(self) -> None:
        source = Path.home() / ".codex/skills/ask-matt/SKILL.md"
        if not source.is_file():
            self.skipTest("ask-matt is not installed")
        actual = hashlib.sha256(source.read_bytes()).hexdigest()
        self.assertEqual(self.source_lock["sha256"], actual)


class BootstrapTests(unittest.TestCase):
    def test_dry_run_does_not_write_and_reports_existing_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / ".git").mkdir()
            plan, conflicts = bootstrap.build_plan(repo, "safe")
            self.assertFalse(conflicts)
            self.assertTrue(plan)
            self.assertFalse((repo / ".agent-work-governor").exists())

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = bootstrap.main(["--repo", str(repo)])
            self.assertEqual(0, result)
            policy = repo / ".agent-work-governor/policy.toml"
            self.assertFalse(policy.exists())
            report = json.loads(output.getvalue())
            self.assertEqual("DRY_RUN", report["status"])
            self.assertEqual(0, report["mutation_count"])

            policy.parent.mkdir()
            policy.write_text("conflict = true\n", encoding="utf-8")
            _, conflicts = bootstrap.build_plan(repo, "safe")
            self.assertIn(
                str(repo.resolve() / ".agent-work-governor/policy.toml"),
                conflicts,
            )

    def test_symbolic_link_parent_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            outside = root / "outside"
            repo.mkdir()
            outside.mkdir()
            (repo / ".git").mkdir()
            (repo / ".github").symlink_to(outside, target_is_directory=True)
            _, conflicts = bootstrap.build_plan(repo, "safe")
        self.assertIn(
            str(repo.resolve() / ".github/workflows/agent-work-governor.yml"),
            conflicts,
        )

    def test_plan_installs_the_unified_catalog_and_validator(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory).resolve()
            (repo / ".git").mkdir()
            plan, conflicts = bootstrap.build_plan(repo, "safe")

        self.assertEqual([], conflicts)
        sources_by_target = {
            Path(item["target"]).relative_to(repo): Path(item["source"]).resolve()
            for item in plan
        }
        self.assertEqual(
            (PLUGIN_ROOT / "toolchain.lock.json").resolve(),
            sources_by_target[Path(".agent-work-governor/toolchain.lock.json")],
        )
        self.assertEqual(
            (PLUGIN_ROOT / "scripts/toolchain_catalog.py").resolve(),
            sources_by_target[Path(".agent-work-governor/toolchain_catalog.py")],
        )
        stale_rust_lock = Path("rust") / ("toolchain" + ".lock.json")
        self.assertNotIn(stale_rust_lock, sources_by_target)
        self.assertNotIn(
            (PLUGIN_ROOT / stale_rust_lock).resolve(),
            set(sources_by_target.values()),
        )

    def test_planned_bundle_is_portable_when_materialized_by_a_harness(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / ".git").mkdir()
            plan, conflicts = bootstrap.build_plan(repo, "safe")
            self.assertEqual([], conflicts)
            for item in plan:
                target = Path(item["target"])
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item["source"], target)

            test_file = repo / ".agent-work-governor/tests/test_repo_bundle.py"
            environment = dict(os.environ)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            process = subprocess.run(
                [sys.executable, str(test_file)],
                cwd=repo,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(0, process.returncode, process.stderr)


class RepositoryGateTests(unittest.TestCase):
    def git(self, repo: Path, *args: str) -> str:
        process = subprocess.run(
            ["git", "-c", "commit.gpgsign=false", "-C", str(repo), *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return process.stdout.strip()

    def test_owner_gate_rejects_self_attestation_and_current_sha_drift(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            self.git(repo, "init", "-b", "main")
            self.git(repo, "config", "user.name", "Contract Test")
            self.git(repo, "config", "user.email", "contract@example.invalid")

            gate = repo / ".agent-work-governor"
            gate.mkdir()
            shutil.copy2(
                PLUGIN_ROOT / "assets/presets/owner-original.toml",
                gate / "policy.toml",
            )
            shutil.copy2(
                PLUGIN_ROOT / "scripts/validate_policy.py",
                gate / "validate_policy.py",
            )
            shutil.copy2(
                PLUGIN_ROOT / "scripts/contract_blocks.py",
                gate / "contract_blocks.py",
            )
            shutil.copy2(
                PLUGIN_ROOT / "assets/repository/.agent-work-governor/validate.py",
                gate / "validate.py",
            )
            shutil.copy2(
                PLUGIN_ROOT / "scripts/toolchain_catalog.py",
                gate / "toolchain_catalog.py",
            )
            shutil.copy2(
                PLUGIN_ROOT / "toolchain.lock.json",
                gate / "toolchain.lock.json",
            )
            (repo / "AGENTS.md").write_text("# Agents\n", encoding="utf-8")
            (repo / ".gitignore").write_text(".governance/\n", encoding="utf-8")
            (repo / "flake.nix").write_text("{}\n", encoding="utf-8")
            (repo / "flake.lock").write_text("{}\n", encoding="utf-8")
            (repo / "existing.py").write_text(
                "# LLM-CONTRACT\n"
                "# id: fixture.module\n"
                "# state: INPUT -> OUTPUT\n"
                "# preconditions: input exists\n"
                "# invariant: output remains bounded\n"
                "# failure: raise a typed error\n"
                "# source: repo:AGENTS.md\n"
                "# knowledge: repo:AGENTS.md\n"
                "# enforced_by: EXISTING\n"
                "# test: repo:existing.py\n"
                "EXISTING = 1\n",
                encoding="utf-8",
            )
            self.git(repo, "add", ".")
            self.git(repo, "commit", "-m", "baseline")
            base = self.git(repo, "rev-parse", "HEAD")
            self.git(repo, "update-ref", "refs/remotes/origin/main", base)

            self.git(repo, "switch", "-c", "work/task-1")
            (repo / "module.py").write_text(
                "# LLM-CONTRACT\n"
                "# id: fixture.module\n"
                "# state: INPUT -> OUTPUT\n"
                "# preconditions: input exists\n"
                "# invariant: output is derived from input\n"
                "# failure: raise a typed error\n"
                "# source: repo:AGENTS.md\n"
                "# knowledge: repo:AGENTS.md\n"
                "# enforced_by: VALUE\n"
                "# test: repo:tests/test_module.py\n"
                "VALUE = 1\n",
                encoding="utf-8",
            )
            test_path = repo / "tests/test_module.py"
            test_path.parent.mkdir()
            test_path.write_text(
                "# LLM-CONTRACT\n"
                "# id: fixture.test-module\n"
                "# state: CASE -> PASS | FAIL\n"
                "# preconditions: module is importable\n"
                "# invariant: VALUE remains one\n"
                "# failure: unittest reports the mismatch\n"
                "# source: repo:AGENTS.md\n"
                "# knowledge: repo:AGENTS.md\n"
                "# enforced_by: test_value\n"
                "# test: repo:tests/test_module.py\n"
                "def test_value():\n"
                "    assert True\n",
                encoding="utf-8",
            )
            self.git(repo, "add", "module.py", "tests/test_module.py")
            self.git(repo, "commit", "-m", "feat: add module")
            reviewed = self.git(repo, "rev-parse", "HEAD")

            receipt_path = repo / ".governance/receipts/pre-pr.json"
            receipt_path.parent.mkdir(parents=True)
            review_artifact = receipt_path.parent / "code-review.md"
            review_artifact.write_text(
                "# Two-axis review\n\nStandards: PASS\n\nSpec: PASS\n",
                encoding="utf-8",
            )
            input_digest = hashlib.sha256(
                json.dumps(
                    {
                        "head_sha": reviewed,
                        "branch_base_sha": base,
                        "task_id": "task-1",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            receipt_path.write_text(
                json.dumps(
                    {
                        "receipt_id": "review-task-1",
                        "session_id": "session-task-1",
                        "action_kind": "code-review",
                        "input_digest": input_digest,
                        "output_digest": hashlib.sha256(
                            review_artifact.read_bytes()
                        ).hexdigest(),
                        "policy_bundle_digest": hashlib.sha256(
                            (gate / "policy.toml").read_bytes()
                        ).hexdigest(),
                        "capability_lease_digest": None,
                        "change_intent_digest": None,
                        "environment_digest": "2" * 64,
                        "actor": "code-review/1",
                        "trace_span_ids": ["standards", "spec"],
                        "replay_ref": f"git:{base}...{reviewed}",
                        "attester": {
                            "id": "two-axis-review",
                            "source_digest": (
                                "6a65cc61114f96db07ec41e3920e67c9"
                                "c5bf70dd6e0901eb9460ebcb2bdc209f"
                            ),
                        },
                        "started_at": "2026-07-28T00:00:00Z",
                        "finished_at": "2026-07-28T00:01:00Z",
                        "verdict": "PASS",
                        "reason_code": "TWO_AXIS_REVIEW_PASSED",
                        "head_sha": reviewed,
                        "branch_base_sha": base,
                        "task_id": "task-1",
                        "one_task": True,
                        "review_artifact": ".governance/receipts/code-review.md",
                        "primary_sources": ["https://example.invalid/primary"],
                        "code_review": {
                            "skill": "code-review",
                            "artifact_sha": reviewed,
                            "standards": "PASS",
                            "spec": "PASS",
                        },
                    }
                ),
                encoding="utf-8",
            )
            current = reviewed

            environment = dict(os.environ)
            environment.update(
                {
                    "GITHUB_BASE_REF": "main",
                    "GITHUB_HEAD_REF": "work/task-1",
                    "GOVERNOR_HEAD_SHA": current,
                    "PYTHONDONTWRITEBYTECODE": "1",
                }
            )
            process = subprocess.run(
                [sys.executable, str(gate / "validate.py")],
                cwd=repo,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(1, process.returncode)
            codes = {item["code"] for item in json.loads(process.stdout)["errors"]}
            self.assertIn("CODE_REVIEW_ATTESTATION_UNTRUSTED", codes)
            self.assertIn("LLM_CONTRACT_AST_ATTESTATION_REQUIRED", codes)
            self.assertIn("LLM_CONTRACT_ID_DUPLICATE", codes)

            (repo / "module.py").write_text(
                (repo / "module.py").read_text(encoding="utf-8") + "VALUE_2 = 2\n",
                encoding="utf-8",
            )
            self.git(repo, "add", "module.py")
            self.git(repo, "commit", "-m", "feat: drift after review")
            environment["GOVERNOR_HEAD_SHA"] = self.git(repo, "rev-parse", "HEAD")
            process = subprocess.run(
                [sys.executable, str(gate / "validate.py")],
                cwd=repo,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(1, process.returncode)
            codes = {item["code"] for item in json.loads(process.stdout)["errors"]}
            self.assertIn("REVIEW_SHA_MISMATCH", codes)


class SourceHygieneTests(unittest.TestCase):
    @staticmethod
    def governed_source_files() -> list[Path]:
        ignored_parts = {"__pycache__", ".direnv", ".governance", ".venv", "target"}
        return sorted(
            path
            for path in PLUGIN_ROOT.rglob("*")
            if path.is_file()
            and path.suffix in {".nix", ".py", ".rs", ".toml", ".yaml", ".yml"}
            and ignored_parts.isdisjoint(path.parts)
        )

    def test_source_files_have_llm_contracts(self) -> None:
        source_files = self.governed_source_files()
        self.assertTrue(source_files)
        missing = [
            str(path.relative_to(PLUGIN_ROOT))
            for path in source_files
            if not contract_blocks.has_valid_contract(path.read_text(encoding="utf-8"))
        ]
        self.assertEqual([], missing)

    def test_source_contract_references_self_host(self) -> None:
        identifiers: dict[str, str] = {}
        errors: list[str] = []
        for path in self.governed_source_files():
            source = path.read_text(encoding="utf-8")
            for contract in contract_blocks.parsed_contracts(source):
                identifier = contract["id"]
                if identifier in identifiers:
                    errors.append(
                        f"duplicate {identifier}: {identifiers[identifier]} and {path}"
                    )
                identifiers[identifier] = str(path)
                for field in ("source", "knowledge", "test"):
                    _, error = contract_blocks.resolve_contract_reference(
                        contract[field],
                        repo_root=PLUGIN_ROOT,
                        bundle_root=PLUGIN_ROOT,
                        allow_external=field == "source",
                    )
                    if error is not None:
                        errors.append(f"{path}:{field}:{contract[field]}: {error}")
                if not contract_blocks.enforcement_token_is_present(
                    source,
                    contract["enforced_by"],
                ):
                    errors.append(
                        f"{path}: enforcement token missing: {contract['enforced_by']}"
                    )
        self.assertEqual([], errors)

    def test_no_todo_placeholders_remain(self) -> None:
        offenders: list[str] = []
        placeholder = "[TODO" + ":"
        for path in sorted(PLUGIN_ROOT.rglob("*")):
            if (
                not path.is_file()
                or "__pycache__" in path.parts
                or ".governance" in path.parts
            ):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if placeholder in text:
                offenders.append(str(path.relative_to(PLUGIN_ROOT)))
        self.assertEqual([], offenders)

    def test_toolchain_has_a_pinned_security_checker(self) -> None:
        pins, findings = toolchain_catalog.validate_catalog(
            PLUGIN_ROOT / "toolchain.lock.json",
            ("pip-audit",),
        )
        self.assertEqual([], findings)
        security = pins["pip-audit"]
        self.assertEqual("python", security["language"])
        self.assertRegex(security["version"], r"^\d+\.\d+\.\d+$")
        self.assertTrue(security["source"].startswith("https://"))
        self.assertRegex(security["source_digest"], r"^sha256:[0-9a-f]{64}$")

    def test_python_audit_exports_every_uv_workspace_package(self) -> None:
        # LLM contract: locked workspace -> complete hashed audit input or test failure.
        catalog = json.loads(
            (PLUGIN_ROOT / "adapters/check-recipes.v1.json").read_text(encoding="utf-8")
        )
        export_recipe = next(
            recipe
            for recipe in catalog["recipes"]
            if recipe["id"] == "python.uv-export"
        )
        fixture = PLUGIN_ROOT / "tests/fixtures/uv-workspace-audit"

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "requirements.txt"
            argv = [
                str(output) if isinstance(atom, dict) else atom
                for atom in export_recipe["argv"]
            ]
            environment = {
                **os.environ,
                "UV_CACHE_DIR": str(Path(directory) / "cache"),
                "UV_OFFLINE": "1",
                "UV_PYTHON": sys.executable,
                "UV_PYTHON_DOWNLOADS": "never",
            }
            completed = subprocess.run(
                argv,
                cwd=fixture,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            requirements = output.read_text(encoding="utf-8")
            root_only_output = Path(directory) / "root-only-requirements.txt"
            root_only_argv = [
                str(root_only_output) if atom == str(output) else atom
                for atom in argv
                if atom != "--all-packages"
            ]
            root_only = subprocess.run(
                root_only_argv,
                cwd=fixture,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, root_only.returncode, root_only.stderr)
            root_only_requirements = root_only_output.read_text(encoding="utf-8")

        self.assertIn("idna==3.11", requirements)
        self.assertIn("--hash=sha256:", requirements)
        self.assertNotIn("idna==3.11", root_only_requirements)
        self.assertIn("--all-packages", argv)
        self.assertIn("--locked", argv)

        workflow = (PLUGIN_ROOT / ".github/workflows/proof-slow.yml").read_text(
            encoding="utf-8"
        )
        python_checks = workflow_run_block(
            workflow,
            "Check locked Python toolchain and dependencies",
        )
        export_start = python_checks.index("run_locked uv export")
        audit_start = python_checks.index("run_locked pip-audit", export_start)
        export_command = python_checks[export_start:audit_start]
        self.assertIn("--all-packages", export_command)
        self.assertIn("--locked", export_command)
        self.assertIn("--require-hashes", python_checks[audit_start:])

    def test_pre_nix_bootstrap_rejects_provenance_mutations(self) -> None:
        accepted = run_nix_bootstrap_fixture()
        self.assertEqual(0, accepted.returncode, accepted.stderr)

        cases = (
            (
                run_nix_bootstrap_fixture(downloaded_installer=b"tampered installer\n"),
                "FAILED",
            ),
            (
                run_nix_bootstrap_fixture(source_mismatch=True),
                "TOOLCHAIN_NIX_SOURCE_MISMATCH",
            ),
            (
                run_nix_bootstrap_fixture(action_mismatch=True),
                "TOOLCHAIN_ACTION_IDENTITY_MISMATCH",
            ),
            (
                run_nix_bootstrap_fixture(preinstalled_nix=True),
                "TOOLCHAIN_NIX_PREINSTALLED",
            ),
        )
        for rejected, evidence in cases:
            with self.subTest(evidence=evidence):
                self.assertNotEqual(0, rejected.returncode)
                self.assertIn(evidence, rejected.stdout + rejected.stderr)

    def test_repository_template_rejects_nix_bootstrap_mutations(self) -> None:
        accepted = run_nix_bootstrap_fixture(repository_template=True)
        self.assertEqual(0, accepted.returncode, accepted.stderr)

        cases = (
            (
                run_nix_bootstrap_fixture(
                    downloaded_installer=b"tampered installer\n",
                    repository_template=True,
                ),
                "FAILED",
            ),
            (
                run_nix_bootstrap_fixture(
                    source_mismatch=True,
                    repository_template=True,
                ),
                "TOOLCHAIN_NIX_SOURCE_MISMATCH",
            ),
            (
                run_nix_bootstrap_fixture(
                    action_mismatch=True,
                    repository_template=True,
                ),
                "TOOLCHAIN_ACTION_IDENTITY_MISMATCH",
            ),
            (
                run_nix_bootstrap_fixture(
                    preinstalled_nix=True,
                    repository_template=True,
                ),
                "TOOLCHAIN_NIX_PREINSTALLED",
            ),
        )
        for rejected, evidence in cases:
            with self.subTest(evidence=evidence):
                self.assertNotEqual(0, rejected.returncode)
                self.assertIn(evidence, rejected.stdout + rejected.stderr)

    def test_ci_lanes_are_disjoint_and_path_bounded(self) -> None:
        workflows = PLUGIN_ROOT / ".github/workflows"
        authority = (workflows / "governor-authority.yml").read_text(encoding="utf-8")
        shadow = (workflows / "shadow-fast.yml").read_text(encoding="utf-8")
        proof = (workflows / "proof-slow.yml").read_text(encoding="utf-8")
        kani = (workflows / "kani-shadow.yml").read_text(encoding="utf-8")

        for evidence in (
            "name: authority-fast",
            "pull_request_target:",
            "name: governor / authority",
            "cancel-in-progress: false",
            "python3 -B scripts/validate_pr_authority.py",
            '"classification":"CODE_FAIL"',
            '"classification":"INFRA_INCONCLUSIVE"',
        ):
            self.assertIn(evidence, authority)
        for forbidden in ("actions/checkout@", "nix ", "pull_request.head"):
            self.assertNotIn(forbidden, authority)

        for evidence in (
            "name: shadow-fast",
            "pull_request:",
            "merge_group:",
            "name: shadow-fast / validate",
            "cancel-in-progress: true",
            'ruff" format --check',
            'pyrefly" check',
            'ty" check',
            '"uv==$(locked_version uv)"',
            "-m unittest discover -s tests",
            '"authority":"none"',
            '"classification":"CODE_FAIL"',
            '"classification":"INFRA_INCONCLUSIVE"',
            '"duration_seconds":%s',
            "scripts/validate_repository_controls.sh",
        ):
            self.assertIn(evidence, shadow)
        for forbidden in (
            "cachix/install-nix-action@",
            "nix flake check",
            "cargo kani",
            "AWG_AUTHORITY_APP_ID",
            "publish_app_authority.py",
        ):
            self.assertNotIn(forbidden, shadow)

        for evidence in (
            "name: proof-slow-nix",
            "PR_METADATA_EDIT -> PRIOR_SAME_HEAD_PROOF_WORKFLOW",
            "PROOF_WORKFLOW_IDENTITY_BOUND_SUCCESS",
            "a metadata edit that replaces pending proof inherits its proof obligation",
            "missing prior proof falls back to full proof",
            "malformed readback fails closed",
            "permissions:\n  actions: read",
            "merge_group:",
            "workflow_dispatch:",
            "schedule:",
            "name: proof-slow / select",
            "name: proof-slow / nix",
            "name: governor / validate",
            "nix flake check",
            "AWG_RUN_NIX_INTEGRATION=1",
            "scripts/run_typed_ci.py",
            "Check Rust/Python differential acceptance",
            "--gate proof-slow-differential",
            'test_name="owner_scope_differential_acceptance"',
            "DIFFERENTIAL_TEST_SKIPPED",
            "DIFFERENTIAL_ACCEPTANCE_PASSED",
            "Enforce required repository controls",
            "scripts/validate_repository_controls.sh",
            "Reconcile metadata-only proof",
            "actions/workflows/proof-slow.yml/runs",
            ".workflow_runs[]",
            '.name == \\"proof-slow-nix\\"',
            "PRIOR_PROOF_WORKFLOW_MISSING_FALLBACK",
            "PRIOR_PROOF_WORKFLOW_READBACK_FAILED",
            "PRIOR_PROOF_WORKFLOW_IDENTITY_BOUND",
            "FULL_PROOF_FALLBACK",
            "for _ in 1 2",
            '"proof_claim":"none"',
            '"proof_claim":"full-nix"',
            '"proof_claim":"preserved-head"',
            '"cache_state":"%s"',
            '"classification":"CODE_FAIL"',
            '"classification":"INFRA_INCONCLUSIVE"',
        ):
            self.assertIn(evidence, proof)
        for evidence in (
            "name: proof-slow-kani",
            "merge_group:",
            "workflow_dispatch:",
            "schedule:",
            "name: proof-slow / kani",
            "cargo kani",
            '"cache_state":"disabled"',
        ):
            self.assertIn(evidence, kani)

        proof_skip_pattern = r"^(docs/|LICENSE$|NOTICE$|README\.md$)"
        self.assertIn(
            f"PROOF_SKIP_PATTERN: '{proof_skip_pattern}'",
            proof,
        )
        expected_kani_paths = {
            ".github/workflows/kani-shadow.yml",
            "rust/**",
            "scripts/run_typed_ci.py",
            "scripts/toolchain_catalog.py",
            "scripts/validate_kani_assurance.py",
            "toolchain.lock.json",
        }
        for event in ("pull_request", "push"):
            self.assertEqual((), workflow_event_paths(proof, event))
            self.assertEqual(
                expected_kani_paths,
                set(workflow_event_paths(kani, event)),
            )

        def kani_selected(path: str, patterns: set[str]) -> bool:
            return path in patterns or any(
                pattern.endswith("/**")
                and path.startswith(f"{pattern.removesuffix('/**')}/")
                for pattern in patterns
            )

        for docs_only in ("README.md", "docs/agents/ci.md"):
            self.assertIsNotNone(re.search(proof_skip_pattern, docs_only))
            self.assertFalse(kani_selected(docs_only, expected_kani_paths))
        for proof_input in (
            ".agent-work-governor/policy.toml",
            "adapters/codex/adapter.json",
            "references/canonical-runtime.lock.json",
            "rust/src/owner_scope.rs",
            "vendor/pyyaml-6.0.3.zip",
        ):
            self.assertIsNone(re.search(proof_skip_pattern, proof_input))
        self.assertTrue(kani_selected("rust/src/owner_scope.rs", expected_kani_paths))

        self.assertIn(
            "permissions:\n  contents: read\n\nconcurrency:",
            shadow,
        )
        self.assertIn(
            "permissions:\n  actions: read\n  checks: read\n  contents: read\n\nenv:",
            proof,
        )
        self.assertIn(
            "permissions:\n  contents: read\n\nconcurrency:",
            kani,
        )
        self.assertIn(
            "permissions:\n  contents: read\n  issues: read\n"
            "  pull-requests: read\n\nconcurrency:",
            authority,
        )
        self.assertIn("push:\n    branches: [main]", shadow)
        self.assertIn("push:\n    branches: [main]", proof)
        self.assertIn("push:\n    branches: [main]", kani)
        self.assertIn(
            "pull_request:\n    types: [opened, synchronize, reopened, edited]",
            shadow,
        )
        self.assertIn(
            "pull_request:\n    types: [opened, synchronize, reopened, edited]",
            proof,
        )
        body_only_edit = (
            "github.event.action == 'edited' && github.event.changes.base == null"
        )
        proof_admission = (
            "github.event.action != 'edited' || github.event.changes.base != null"
        )
        self.assertNotIn(f"{body_only_edit} && github.run_id || 'proof'", proof)
        self.assertEqual(2, proof.count(body_only_edit))
        self.assertEqual(1, proof.count(proof_admission))
        self.assertNotIn("proof-slow / metadata-edit-select", proof)
        self.assertNotIn("proof-slow / metadata-edit-nix", proof)
        self.assertNotIn("proof-slow / metadata-edit-required", proof)
        self.assertNotIn("commits/$PR_HEAD_SHA/check-runs", proof)
        self.assertNotIn("check_name=governor / validate", proof)
        self.assertEqual(1, proof.count("name: governor / validate"))

        def proof_event_contract(
            action: str,
            *,
            base_changed: bool,
            prior_success: bool = False,
        ) -> tuple[bool, bool, str]:
            body_only = action == "edited" and not base_changed
            if body_only:
                return (
                    False,
                    not prior_success,
                    "preserved-head" if prior_success else "full-proof-fallback",
                )
            return (
                True,
                True,
                "required",
            )

        self.assertEqual(
            (False, False, "preserved-head"),
            proof_event_contract(
                "edited",
                base_changed=False,
                prior_success=True,
            ),
        )
        self.assertEqual(
            (False, True, "full-proof-fallback"),
            proof_event_contract("edited", base_changed=False),
        )
        self.assertEqual(
            (True, True, "required"),
            proof_event_contract("edited", base_changed=True),
        )
        self.assertEqual(
            (True, True, "required"),
            proof_event_contract("synchronize", base_changed=False),
        )
        self.assertNotIn("pull_request_target:", shadow + proof + kani)
        self.assertNotIn("\n  push:", authority)
        self.assertNotIn("\n  merge_group:", authority)
        self.assertIn(
            "group: governor-authority-${{ github.event.pull_request.number }}",
            authority,
        )
        self.assertIn(
            "group: shadow-fast-${{ github.event.pull_request.number || github.ref }}",
            shadow,
        )
        self.assertIn(
            "group: proof-slow-nix-${{ github.event.pull_request.number || github.ref }}",
            proof,
        )
        self.assertIn(
            "group: proof-slow-kani-${{ github.event.pull_request.number || github.ref }}",
            kani,
        )
        self.assertEqual(1, authority.count("cancel-in-progress: false"))
        self.assertEqual(1, shadow.count("cancel-in-progress: true"))
        self.assertEqual(
            1,
            proof.count(
                "cancel-in-progress: ${{ github.event.action != 'edited' || "
                "github.event.changes.base != null }}"
            ),
        )
        self.assertEqual(1, kani.count("cancel-in-progress: true"))
        self.assertEqual(
            2,
            (shadow + proof).count("scripts/validate_repository_controls.sh"),
        )
        self.assertIn(
            "if: needs.select.result == 'success' && "
            "needs.select.outputs.preserved != 'true'",
            proof,
        )
        self.assertIn('"$PROOF_RESULT" == "success"', proof)

        job_names: list[str] = []
        workflow_names: list[str] = []
        for path in workflows.glob("*.yml"):
            source = path.read_text()
            job_names.extend(
                re.findall(r"^    name: (.+)$", source, flags=re.MULTILINE)
            )
            workflow_names.extend(
                re.findall(r"^name: (.+)$", source, flags=re.MULTILINE)
            )
        self.assertEqual(len(job_names), len(set(job_names)))
        self.assertEqual(len(workflow_names), len(set(workflow_names)))

    def test_kani_shadow_checkout_does_not_persist_credentials(self) -> None:
        workflow = (PLUGIN_ROOT / ".github/workflows/kani-shadow.yml").read_text(
            encoding="utf-8"
        )
        marker = "      - name: Check out the candidate revision"
        self.assertEqual(1, workflow.count(marker))
        checkout = workflow.split(marker, 1)[1].split("\n      - name:", 1)[0]
        lines = checkout.splitlines()
        self.assertEqual(
            1,
            lines.count(
                "        uses: actions/checkout@"
                "3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
            ),
        )
        self.assertEqual(1, lines.count("          persist-credentials: false"))
        self.assertNotIn("persist-credentials: true", checkout)
        self.assertEqual(
            1,
            lines.count(
                "          ref: ${{ github.event.pull_request.head.sha || github.sha }}"
            ),
        )

    def test_metadata_proof_requires_workflow_run_identity(self) -> None:
        head_sha = "a" * 40
        proof_run: dict[str, object] = {
            "id": 111,
            "workflow_id": 222,
            "run_attempt": 1,
            "name": "proof-slow-nix",
            "path": ".github/workflows/proof-slow.yml",
            "head_sha": head_sha,
            "event": "pull_request",
            "status": "completed",
            "conclusion": "success",
            "repository": {"full_name": "Anionix/agent-work-governor"},
        }
        accepted = run_metadata_proof_fixture(
            {"total_count": 1, "workflow_runs": [proof_run]}
        )
        self.assertEqual(0, accepted.returncode, accepted.stderr)
        self.assertIn("PRIOR_PROOF_WORKFLOW_IDENTITY_BOUND", accepted.stdout)
        same_workflow = {
            **proof_run,
            "id": 112,
            "run_attempt": 2,
        }
        accepted_multiple = run_metadata_proof_fixture(
            {"total_count": 2, "workflow_runs": [proof_run, same_workflow]}
        )
        self.assertEqual(0, accepted_multiple.returncode, accepted_multiple.stderr)

        unrelated: dict[str, object] = dict(proof_run)
        unrelated.update(
            {
                "name": "unrelated-workflow",
                "path": ".github/workflows/unrelated.yml@main",
                "jobs": [{"name": "governor / validate", "conclusion": "success"}],
            }
        )
        rejected = run_metadata_proof_fixture(
            {
                "total_count": 0,
                "workflow_runs": [],
                "check_runs": [unrelated],
            }
        )
        self.assertEqual(0, rejected.returncode, rejected.stderr)
        self.assertIn("PRIOR_PROOF_WORKFLOW_MISSING_FALLBACK", rejected.stdout)
        self.assertNotIn("IDENTITY_BOUND", rejected.stdout)

        contradictory_cases: tuple[dict[str, object], ...] = (
            {"total_count": 0, "workflow_runs": [proof_run]},
            {"total_count": "1", "workflow_runs": [proof_run]},
            {"total_count": 2, "workflow_runs": [proof_run, proof_run]},
            {
                "total_count": 2,
                "workflow_runs": [
                    proof_run,
                    {**same_workflow, "workflow_id": 333},
                ],
            },
            {"total_count": 1, "workflow_runs": []},
            {
                "total_count": 1,
                "workflow_runs": [{**proof_run, "workflow_id": "222"}],
            },
        )
        for contradictory in contradictory_cases:
            with self.subTest(contradictory=contradictory):
                invalid = run_metadata_proof_fixture(contradictory)
                self.assertEqual(2, invalid.returncode)
                self.assertIn(
                    "PRIOR_PROOF_WORKFLOW_RESPONSE_INVALID",
                    invalid.stdout,
                )

        malformed = run_metadata_proof_fixture({"total_count": 1})
        self.assertEqual(2, malformed.returncode)
        self.assertIn("PRIOR_PROOF_WORKFLOW_READBACK_FAILED", malformed.stdout)

    def test_required_repository_controls_fail_closed(self) -> None:
        for accepted in (
            run_repository_controls_fixture(contract_kind="regular"),
            run_repository_controls_fixture(contract_kind="ignored"),
            run_repository_controls_fixture(
                action=f"uses: docker://alpine@sha256:{'a' * 64}"
            ),
            run_repository_controls_fixture(
                docker_action_image=f"docker://alpine@sha256:{'a' * 64}"
            ),
            run_repository_controls_fixture(docker_action_image="Dockerfile"),
            run_repository_controls_fixture(template_action=f"owner/action@{'a' * 40}"),
            run_repository_controls_fixture(uses_input=True),
            run_repository_controls_fixture(tracked_output=".cargo/config.toml"),
            run_repository_controls_fixture(tracked_output=".gradle/gradle.properties"),
            run_repository_controls_fixture(tracked_output=".gradle/init.gradle"),
            run_repository_controls_fixture(tracked_output=".gradle/init.gradle.kts"),
            run_repository_controls_fixture(
                tracked_output=".gradle/init.d/cache-settings.init.gradle.kts"
            ),
            run_repository_controls_fixture(
                tracked_output="path.gradle/.gradle/gradle.properties"
            ),
        ):
            self.assertEqual(0, accepted.returncode, accepted.stderr)
        for contract_kind in ("missing", "symlink", "submodule", "unreadable"):
            rejected = run_repository_controls_fixture(contract_kind=contract_kind)
            with self.subTest(contract_kind=contract_kind):
                self.assertEqual(1, rejected.returncode)
                self.assertIn("REPOSITORY_CONTRACT_INVALID", rejected.stdout)
        for tracked_output in (
            ".gradle/caches/modules/a.jar",
            ".gradle/8.14.4/fileHashes/fileHashes.lock",
            ".gradle/buildOutputCleanup/cache.properties",
            ".cargo/registry/cache/a.crate",
            ".cargo/git/checkouts/repository/source.rs",
            ".cargo/.global-cache",
            ".cargo/.package-cache",
            ".cargo/.package-cache-mutate",
            ".governance/.gradle/gradle.properties",
            ".cargo/registry/.gradle/gradle.properties",
            ".gradle/init.d/cache/generated.gradle",
            ".gradle/init.d/gradle8/cache-settings.init.gradle.kts",
            ".gradle/caches/foo/.gradle/gradle.properties",
            "buck-out/v2/gen/output",
        ):
            rejected = run_repository_controls_fixture(tracked_output=tracked_output)
            with self.subTest(tracked_output=tracked_output):
                self.assertEqual(1, rejected.returncode)
                self.assertIn("TRACKED_RUNTIME_OUTPUT", rejected.stdout)
        cases = (
            (
                run_repository_controls_fixture(tracked_output="bin/tool"),
                "TRACKED_RUNTIME_OUTPUT",
            ),
            (
                run_repository_controls_fixture(tracked_output="build/artifact"),
                "TRACKED_RUNTIME_OUTPUT",
            ),
            (
                run_repository_controls_fixture(tracked_output="dist/package.whl"),
                "TRACKED_RUNTIME_OUTPUT",
            ),
            (
                run_repository_controls_fixture(tracked_output=".tox/py/pyvenv.cfg"),
                "TRACKED_RUNTIME_OUTPUT",
            ),
            (
                run_repository_controls_fixture(tracked_output=".nox/lint/pyvenv.cfg"),
                "TRACKED_RUNTIME_OUTPUT",
            ),
            (
                run_repository_controls_fixture(tracked_output="env/pyvenv.cfg"),
                "TRACKED_RUNTIME_OUTPUT",
            ),
            (
                run_repository_controls_fixture(
                    tracked_output="env/lib/python3.14/site-packages/pkg.py"
                ),
                "TRACKED_RUNTIME_OUTPUT",
            ),
            (
                run_repository_controls_fixture(
                    tracked_output="env/Scripts/python.exe"
                ),
                "TRACKED_RUNTIME_OUTPUT",
            ),
            (
                run_repository_controls_fixture(tracked_output="extension.pyd"),
                "TRACKED_RUNTIME_OUTPUT",
            ),
            (
                run_repository_controls_fixture(ignored_output=True),
                "TRACKED_RUNTIME_OUTPUT",
            ),
            (run_repository_controls_fixture(invalid_diff=True), "DIFF_INVALID"),
            (
                run_repository_controls_fixture(composite_action="owner/action@v1"),
                "UNPINNED_ACTION",
            ),
            (
                run_repository_controls_fixture(
                    docker_action_image="docker://alpine:latest"
                ),
                "UNPINNED_ACTION",
            ),
            (
                run_repository_controls_fixture(template_action="owner/action@v1"),
                "UNPINNED_ACTION",
            ),
        )
        for rejected, code in cases:
            with self.subTest(code=code):
                self.assertEqual(1, rejected.returncode)
                self.assertIn(code, rejected.stdout)
        for action in (
            "uses: owner/action@v1",
            '"uses" : "owner/action@v1"',
            "{uses: owner/action@v1}",
            "uses: docker://alpine:latest",
        ):
            rejected = run_repository_controls_fixture(action=action)
            with self.subTest(action=action):
                self.assertEqual(1, rejected.returncode)
                self.assertIn("UNPINNED_ACTION", rejected.stdout)

    def test_shadow_fast_exports_pinned_tools_to_clean_path(self) -> None:
        shadow = (PLUGIN_ROOT / ".github/workflows/shadow-fast.yml").read_text(
            encoding="utf-8"
        )
        bash = shutil.which("bash")
        self.assertIsNotNone(bash)
        assert bash is not None
        export_line = next(
            line.strip() for line in shadow.splitlines() if '>> "$GITHUB_PATH"' in line
        )
        self.assertEqual(
            'echo "$shadow_venv/bin" >> "$GITHUB_PATH"',
            export_line,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            venv_bin = root / "venv" / "bin"
            venv_bin.mkdir(parents=True)
            uv = venv_bin / "uv"
            uv.write_text(
                f"#!{sys.executable}\nprint('uv-visible')\n",
                encoding="utf-8",
            )
            uv.chmod(0o755)
            github_path = root / "github-path"
            environment = {
                "GITHUB_PATH": str(github_path),
                "PATH": "/usr/bin:/bin",
                "shadow_venv": str(root / "venv"),
            }
            subprocess.run(
                [bash, "-c", export_line],
                check=True,
                env=environment,
            )
            exported = github_path.read_text(encoding="utf-8").strip()
            self.assertEqual(str(venv_bin), exported)
            completed = subprocess.run(
                ["uv"],
                check=True,
                capture_output=True,
                env={"PATH": f"{exported}:/usr/bin:/bin"},
                text=True,
            )
            self.assertEqual("uv-visible", completed.stdout.strip())

    def test_proof_selector_requires_core_to_docs_rename(self) -> None:
        workflow = (PLUGIN_ROOT / ".github/workflows/proof-slow.yml").read_text(
            encoding="utf-8"
        )
        selector = workflow_run_block(workflow, "Select relevant proof input")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*arguments: str) -> str:
                completed = subprocess.run(
                    ["git", "-c", "commit.gpgsign=false", *arguments],
                    cwd=root,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                return completed.stdout.strip()

            git("init", "--quiet")
            git("config", "user.email", "ci@example.invalid")
            git("config", "user.name", "CI")
            source = root / "rust/src/owner_scope.rs"
            source.parent.mkdir(parents=True)
            source.write_text("fn decide() {}\n", encoding="utf-8")
            git("add", ".")
            git("commit", "--quiet", "-m", "core")
            base = git("rev-parse", "HEAD")
            (root / "docs").mkdir()
            git("mv", str(source.relative_to(root)), "docs/owner_scope.rs")
            git("commit", "--quiet", "-m", "rename")
            head = git("rev-parse", "HEAD")

            output = root / "github-output"
            environment = dict(os.environ)
            environment.update(
                {
                    "BASE_SHA": base,
                    "GITHUB_EVENT_NAME": "pull_request",
                    "GITHUB_OUTPUT": str(output),
                    "HEAD_SHA": head,
                    "PROOF_SKIP_PATTERN": (r"^(docs/|LICENSE$|NOTICE$|README\.md$)"),
                }
            )
            completed = subprocess.run(
                ["bash", "-c", selector],
                cwd=root,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual("required=true\n", output.read_text(encoding="utf-8"))

    def test_proof_slow_types_infrastructure_and_code_failures(self) -> None:
        workflow = (PLUGIN_ROOT / ".github/workflows/proof-slow.yml").read_text(
            encoding="utf-8"
        )
        check = workflow_run_block(workflow, "Check reproducible environment")
        self.assertIn("python3 scripts/run_typed_ci.py", check)
        self.assertIn("--code NIX_PROOF_FAILED", check)
        self.assertIn("--infra-code NIX_PROOF_INFRA", check)
        self.assertIn('if [[ "$status" -eq 2 ]]', check)
        self.assertNotIn("grep -Eqi", check)

    def test_buck2_release_digest_corruption_is_rejected(self) -> None:
        flake = (PLUGIN_ROOT / "flake.nix").read_text(encoding="utf-8")
        release_binding = flake[
            flake.index("bindBuck2ReleaseSource =") : flake.index(
                "# id: agent-work-governor.buck2-package-binding"
            )
        ]
        for evidence in (
            "expected.source != canonicalSource",
            'digest = builtins.match "sha256:([0-9a-f]{64})"',
            "pkgs.fetchurl",
            "url = expected.source;",
            "sha256 = builtins.head digest;",
        ):
            self.assertIn(evidence, release_binding)
        self.assertIn(
            "buck2-release-source = toolchain.buck2ReleaseSource;",
            flake,
        )

        regression = (PLUGIN_ROOT / "scripts/test_buck2_release_digest.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('pin["source_digest"] = f"sha256:{\'0\' * 64}"', regression)
        self.assertIn("BUCK2_PLATFORM_ARTIFACT_DRIFT", regression)
        self.assertIn('"path:$runtime#buck2-release-source"', regression)
        self.assertIn(
            'grep -Fqi "hash mismatch in fixed-output derivation"',
            regression,
        )
        self.assertIn(
            'grep -Fq "buck2-$release-release-launcher.drv"',
            regression,
        )
        self.assertIn('grep -Fq "specified: $corrupted_sri"', regression)
        syntax = subprocess.run(
            ["bash", "-n", "scripts/test_buck2_release_digest.sh"],
            cwd=PLUGIN_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, syntax.returncode, syntax.stderr)

        workflow = (PLUGIN_ROOT / ".github/workflows/proof-slow.yml").read_text(
            encoding="utf-8"
        )
        check = workflow_run_block(
            workflow,
            "Reject a corrupted Buck2 release digest",
        )
        self.assertIn("--code BUCK2_RELEASE_DIGEST_REGRESSION_FAILED", check)
        self.assertIn("--infra-code BUCK2_RELEASE_DIGEST_REGRESSION_INFRA", check)
        self.assertIn("bash scripts/test_buck2_release_digest.sh", check)

    def test_unified_toolchain_matches_project_and_environment_inputs(self) -> None:
        catalog_path = PLUGIN_ROOT / "toolchain.lock.json"
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        pins, findings = toolchain_catalog.validate_catalog(catalog_path)
        self.assertEqual([], findings)
        self.assertEqual("0.2", catalog["schema_version"])
        self.assertEqual(sorted(catalog["required"]), catalog["required"])
        self.assertLessEqual(set(catalog["required"]), set(pins))
        self.assertIn("python", {pin["language"] for pin in pins.values()})
        self.assertIn("rust", {pin["language"] for pin in pins.values()})
        self.assertEqual(
            "https://github.com/facebook/buck2/releases/download/2026-07-15/buck2",
            pins["buck2"]["source"],
        )
        self.assertEqual("2026.07.15", pins["buck2"]["version"])
        self.assertNotIn("buck2", catalog["required"])
        self.assertEqual(
            {"aarch64-darwin", "aarch64-linux", "x86_64-linux"},
            set(pins["buck2"]["artifacts"]),
        )
        self.assertIn(
            '"authority":"none"',
            (PLUGIN_ROOT / "scripts/buck2_shadow_probe.sh").read_text(encoding="utf-8"),
        )

        project = tomllib.loads(
            (PLUGIN_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        development_pins = dict(
            dependency.split("==", maxsplit=1)
            for dependency in project["dependency-groups"]["dev"]
            if "==" in dependency
        )
        uv_document = tomllib.loads(
            (PLUGIN_ROOT / "uv.lock").read_text(encoding="utf-8")
        )
        uv_versions = {
            package["name"]: package["version"] for package in uv_document["package"]
        }
        for tool in ("pyrefly", "ruff", "ty", "pip-audit"):
            self.assertEqual(pins[tool]["version"], development_pins[tool])
            self.assertEqual(pins[tool]["version"], uv_versions[tool])
        self.assertEqual(
            project["project"]["requires-python"],
            uv_document["requires-python"],
        )
        minimum_python = tuple(
            int(part)
            for part in project["project"]["requires-python"]
            .removeprefix(">=")
            .split(".")
        )
        locked_python = tuple(
            int(part) for part in pins["python"]["version"].split(".")
        )
        self.assertGreaterEqual(locked_python, minimum_python)

        rust_toolchain = tomllib.loads(
            (PLUGIN_ROOT / "rust/rust-toolchain.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(
            pins["rust"]["version"],
            rust_toolchain["toolchain"]["channel"],
        )
        self.assertEqual(pins["rust"]["version"], pins["cargo"]["version"])
        self.assertEqual(
            {"clippy", "rust-analyzer", "rust-src", "rustfmt"},
            set(rust_toolchain["toolchain"]["components"]),
        )
        self.assertEqual(pins["rust"]["version"], pins["rust-src"]["version"])
        for component in ("clippy", "rust-analyzer", "rust-src", "rustfmt"):
            self.assertEqual(pins["rust"]["source"], pins[component]["source"])
            self.assertEqual(
                pins["rust"]["source_digest"],
                pins[component]["source_digest"],
            )
        flake_lock = json.loads(
            (PLUGIN_ROOT / "flake.lock").read_text(encoding="utf-8")
        )
        root_inputs = flake_lock["nodes"][flake_lock["root"]]["inputs"]
        rust_overlay = flake_lock["nodes"][root_inputs["rust-overlay"]]
        self.assertEqual(
            [root_inputs["nixpkgs"]],
            rust_overlay["inputs"]["nixpkgs"],
        )
        for tool in ("nixpkgs", "rust-overlay", "rustsec-advisory-db"):
            input_node = flake_lock["nodes"][root_inputs[tool]]
            locked = input_node["locked"]
            original = input_node["original"]
            self.assertEqual(pins[tool]["version"], locked["rev"])
            self.assertEqual(locked["rev"], original["rev"])
            self.assertEqual(locked["owner"], original["owner"])
            self.assertEqual(locked["repo"], original["repo"])
            self.assertEqual(
                pins[tool]["source"],
                (
                    f"https://github.com/{locked['owner']}/{locked['repo']}"
                    f"/commit/{locked['rev']}"
                ),
            )
            nar_hash = base64.b64decode(locked["narHash"].removeprefix("sha256-")).hex()
            self.assertEqual(pins[tool]["source_digest"], f"sha256:{nar_hash}")

        workflow = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                PLUGIN_ROOT / ".github/workflows/shadow-fast.yml",
                PLUGIN_ROOT / ".github/workflows/governor-authority.yml",
                PLUGIN_ROOT / ".github/workflows/proof-slow.yml",
            )
        )
        workflow_actions = dict(
            re.findall(r"uses:\s+([^@\s]+)@([0-9a-f]{40})", workflow)
        )
        bootstrap_checkout = workflow_actions.pop("actions/checkout")
        self.assertEqual(
            "3d3c42e5aac5ba805825da76410c181273ba90b1",
            bootstrap_checkout,
        )
        self.assertNotIn("actions/checkout", pins)
        self.assertIn(
            "actions/checkout is intentionally outside toolchain.lock.json",
            workflow,
        )
        catalog_actions = {
            tool_id: pin["source_digest"].removeprefix("git:")
            for tool_id, pin in pins.items()
            if pin["language"] == "github_actions"
        }
        self.assertEqual(catalog_actions, workflow_actions)
        self.assertIn("scripts/toolchain_catalog.py", workflow)
        self.assertIn("scripts/project_toolchain_digest.py --check", workflow)
        self.assertIn("--tool-source nix", workflow)
        self.assertIn("--tool-source cachix/install-nix-action", workflow)
        self.assertIn("TOOLCHAIN_ACTION_IDENTITY_MISMATCH", workflow)
        self.assertIn("sha256sum --check --strict", workflow)
        self.assertIn("install_url: file://${{ runner.temp }}/nix-install", workflow)
        self.assertIn("command -v nix >/dev/null 2>&1", workflow)
        self.assertIn("--proto-redir '=https'", workflow)
        self.assertNotIn(".venv/bin/", workflow)
        self.assertIn("run_locked ruff format --check .", workflow)
        self.assertIn("run_locked pyrefly check", workflow)
        self.assertIn("assert_version rust-analyzer", workflow)
        self.assertIn("TOOLCHAIN_COMPONENT_MISSING::rust-src", workflow)
        self.assertIn("run_locked pip-audit", workflow)
        # LLM contract: workflow text -> isolated lock regeneration evidence
        # or this repository-contract test fails before merge.
        for evidence in (
            "nix flake lock",
            "--no-use-registries",
            "--output-lock-file",
            "scripts/validate_flake_lock_pair.py",
            "FLAKE_PAIR_UNCHANGED",
            "git archive",
            "git rev-parse HEAD",
            "git status --porcelain",
            "path:$source_tree",
            "flake.lock.regeneration-failed",
            "FlakeLockPairNixIntegrationTests",
        ):
            self.assertIn(evidence, workflow)
        self.assertNotIn("nix flake update", workflow)
        for evidence in (
            "Check shadow input byte stability",
            '"$target" --rebuild --no-link --print-out-paths',
            'nix hash path --type sha256 --base16 "$rebuilt"',
            'test ! -e "$rust_inputs/advisory-db/.git/index"',
            "safe.directory=$rust_inputs/advisory-db",
            "'HEAD^{commit}'",
        ):
            self.assertIn(evidence, workflow)
        self.assertLess(
            workflow.index("command -v nix >/dev/null 2>&1"),
            workflow.index("uses: cachix/install-nix-action@"),
        )
        self.assertLess(
            workflow.index("TOOLCHAIN_ACTION_IDENTITY_MISMATCH"),
            workflow.index("uses: cachix/install-nix-action@"),
        )
        self.assertLess(
            workflow.index("sha256sum --check --strict"),
            workflow.index("uses: cachix/install-nix-action@"),
        )
        flake = (PLUGIN_ROOT / "flake.nix").read_text(encoding="utf-8")
        for evidence in (
            "bindNixPackage",
            "pkgs.autoPatchelfHook",
            "pkgs.pythonManylinuxPackages.manylinux2014",
            'cat > "$CARGO_HOME/config.toml"',
            'directory = "${cargoVendor}"',
            "offline = true",
            "clippyPin.source == rustPin.source",
            "rustfmtPin.source == rustPin.source",
            "TOOLCHAIN_GIT_REPOSITORY_SELF_TEST_FAILED",
            "TOOLCHAIN_RUST_COMPONENT_SELF_TEST_FAILED",
            "TOOLCHAIN_PACKAGE_SOURCE_URL_MISMATCH",
            "TOOLCHAIN_PACKAGE_SOURCE_DIGEST_MISMATCH",
        ):
            self.assertIn(evidence, flake)
        for evidence in (
            "config maintenance.auto false",
            "config gc.auto 0",
            'rm "$git_dir/COMMIT_EDITMSG" "$git_dir/description" "$git_dir/index"',
            'find "$git_dir/objects" -maxdepth 1 -type f -delete',
        ):
            self.assertIn(evidence, flake)
        for evidence in (
            "scripts/validate_canonical.py --fetch-missing",
            "cargo audit --file rust/Cargo.lock",
            "cargo deny --manifest-path rust/Cargo.toml",
            "pip-audit --version",
            "ruff --version",
            "ty --version",
        ):
            self.assertIn(evidence, workflow)

    def test_privileged_harness_regression_is_post_merge_only(self) -> None:
        workflow = (PLUGIN_ROOT / ".github/workflows/harness-isolation.yml").read_text(
            encoding="utf-8"
        )
        for evidence in (
            "push:\n    branches: [main]",
            "permissions:\n  contents: read",
            "persist-credentials: false",
            "ref: ${{ github.sha }}",
            "name: harness / isolation / ubuntu-24.04 / authority",
            "runs-on: ubuntu-24.04",
            "ubuntu-arm-shadow:",
            "runs-on: ubuntu-24.04-arm",
            "macos-shadow:",
            "runs-on: macos-15",
            "steps: &harness-isolation-steps",
            "steps: *harness-isolation-steps",
            'bwrap="$(',
            "which bwrap",
            "apparmor_restrict_unprivileged_userns",
            "flags=(unconfined)",
            "userns,",
            'apparmor_parser -r "$apparmor_profile"',
            'apparmor_parser -R "$apparmor_profile"',
            'trusted_path="$(dirname "$bwrap"):$trusted_path"',
            "sudo /usr/bin/env -i",
            '"PATH=$trusted_path"',
            '"$python" -B -m unittest tests.test_bounded_harness',
            'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
        ):
            self.assertIn(evidence, workflow)
        self.assertNotIn("pull_request", workflow)
        self.assertNotIn("matrix:", workflow)
        self.assertNotIn("apparmor_restrict_unprivileged_userns=0", workflow)
        self.assertIn(
            ".github/workflows/harness-isolation.yml",
            (PLUGIN_ROOT / "flake.nix").read_text(encoding="utf-8"),
        )

    def test_shadow_workflow_is_observational_and_identity_bound(self) -> None:
        workflow = (PLUGIN_ROOT / ".github/workflows/governor-shadow.yml").read_text(
            encoding="utf-8"
        )
        for evidence in (
            "workflow_run:",
            "workflows: [proof-slow-nix]",
            "permissions:\n  actions: read\n  contents: read",
            "github.event.workflow_run.event == 'pull_request'",
            'job["name"] == "proof-slow / nix"',
            "needs.select.outputs.run == 'true'",
            "path: control",
            "persist-credentials: false",
            "github.event.workflow_run.head_sha",
            "repository: ${{ env.CANDIDATE_REPOSITORY }}",
            '"path:$control#default"',
            '"path:$control#shadow-inputs"',
            'nix store add-path "$subject"',
            "--no-update-lock-file --no-write-lock-file",
            "sudo /usr/bin/env -i",
            'trusted_pythonpath="${PYTHONPATH-}"',
            '"$python" -I -S - "$trusted_pythonpath"',
            "not resolved.is_relative_to(store)",
            '"PYTHONPATH=$trusted_pythonpath"',
            "NIX_(CC|BINTOOLS)_WRAPPER_TARGET_(BUILD|HOST)_",
            'root_environment+=("${wrapper_environment[@]}")',
            "NIX_BINTOOLS_FOR_BUILD",
            "NIX_CFLAGS_COMPILE_FOR_BUILD",
            "NIX_LDFLAGS_FOR_BUILD",
            "apparmor_restrict_unprivileged_userns",
            "flags=(unconfined)",
            "userns,",
            'apparmor_parser -r "$apparmor_profile"',
            'apparmor_parser -R "$apparmor_profile"',
            "--runtime-root",
            "--trusted-rust-inputs",
            "--evidence-root",
            "runner: [ubuntu-24.04, ubuntu-24.04-arm, macos-15]",
            "scripts/rust_dispatch.py",
            "scripts/bounded_harness.py",
            "PARITY_EVIDENCE",
            "SHADOW_REGRESSION",
            "SHADOW_INCONCLUSIVE",
            '"reason_codes"',
            '"launcher_diagnostic_sha256"',
            '"network_preflight_stage"',
            '"network-candidate-start"',
            '"network-candidate-ready-eof"',
            '"network-candidate-linux-loopback-rtnetlink-eperm"',
            '"network-candidate-socket-create-unexpected"',
            '"network-candidate-socket-operation-unexpected"',
            '"network-candidate-process-exit-unexpected"',
            'value.get("code")',
            '"HARNESS_NETWORK_SANDBOX_POLICY_UNSUPPORTED"',
            'value.get("schema_version") != "0.3"',
            '"observed_check_outcomes"',
            '"rust_failure_diagnostics"',
            '"UNKNOWN_NONZERO"',
            '"candidate_archive_sha256"',
            '"candidate_store_sha256"',
            '"plan_report_sha256"',
            '"receipt_sha256"',
            '"rust_inputs_sha256"',
            '"evidence_set_sha256"',
            '"verify_report_sha256"',
            "GITHUB_STEP_SUMMARY",
        ):
            self.assertIn(evidence, workflow)
        self.assertNotIn("apparmor_restrict_unprivileged_userns=0", workflow)
        for forbidden in (
            "secrets.",
            "governor / validate",
            "governor / authority",
            "nix build .#default",
            "nix develop -c",
            "subject/flake.nix",
            '"$subject/scripts/',
            "sudo --preserve-env",
        ):
            self.assertNotIn(forbidden, workflow)
        self.assertGreaterEqual(
            workflow.count("--no-update-lock-file --no-write-lock-file"),
            2,
        )
        self.assertIn(
            ".github/workflows/governor-shadow.yml",
            (PLUGIN_ROOT / "flake.nix").read_text(encoding="utf-8"),
        )
        promotion = (PLUGIN_ROOT / "docs/agents/shadow-ci.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("requires a separate Issue and protection-rule change", promotion)
        self.assertIn("never\nreplace the legacy gate", promotion)

    def test_shadow_evidence_v03_bounds_launcher_diagnostics(self) -> None:
        workflow = (PLUGIN_ROOT / ".github/workflows/governor-shadow.yml").read_text()
        embedded = workflow.split(
            """<<'PYTHON' > "$output/shadow.json"\n""",
            1,
        )[1].split("\n          PYTHON\n", 1)[0]
        script = textwrap.dedent(embedded)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, runtime = root / "output", root / "runtime"
            output.mkdir()
            runtime.mkdir()
            arguments = [
                str(output),
                str(runtime),
                *(["x"] * 8),
                "1",
                "1",
                "0",
                "70",
                "-1",
            ]
            expected_keys = [
                "candidate_archive_sha256",
                "candidate_head_sha",
                "candidate_repository",
                "candidate_store_sha256",
                "control_manifest_sha256",
                "control_sha",
                "evidence_set_sha256",
                "execution_plan_sha256",
                "legacy_conclusion",
                "launcher_diagnostic_sha256",
                "network_preflight_stage",
                "observed_check_outcomes",
                "rust_failure_diagnostics",
                "plan_report_sha256",
                "reason_codes",
                "receipt_sha256",
                "rust_inputs_sha256",
                "runner",
                "schema_version",
                "stage_exit",
                "state",
                "verify_report_sha256",
                "workflow_run_attempt",
                "workflow_run_id",
            ]
            fault: dict[str, object] = {
                "code": "HARNESS_NETWORK_SANDBOX_SETUP_FAILED",
                "completed": [],
                "failed": [],
                "launcher_diagnostic_sha256": None,
                "not_started": [],
                "running": [],
                "state": "HARNESS_FAULT",
            }
            for version, stage, digest, expected_stage, expected_digest in (
                (
                    "0.3",
                    "network-candidate-ready-output",
                    "a" * 64,
                    "network-candidate-ready-output",
                    "a" * 64,
                ),
                ("0.3", "network-candidate-start", "a" * 64, None, None),
                ("0.3", ["network-candidate-start"], "a" * 64, None, None),
                ("0.3", "candidate-controlled", "a" * 64, None, None),
                ("0.3", "network-candidate-start", "A" * 64, None, None),
                ("0.3", "network-candidate-start", "candidate", None, None),
                ("0.3", None, "a" * 64, None, None),
                ("0.3", "network-candidate-ready-eof", "a" * 64, None, None),
                ("0.3", "network-candidate-result", "a" * 64, None, None),
                (
                    "0.3",
                    "network-candidate-socket-create-unexpected",
                    None,
                    "network-candidate-socket-create-unexpected",
                    None,
                ),
                (
                    "0.3",
                    "network-candidate-socket-operation-unexpected",
                    None,
                    "network-candidate-socket-operation-unexpected",
                    None,
                ),
                (
                    "0.3",
                    "network-candidate-process-exit-unexpected",
                    None,
                    "network-candidate-process-exit-unexpected",
                    None,
                ),
                (
                    "0.3",
                    "network-candidate-linux-loopback-rtnetlink-eperm",
                    None,
                    None,
                    None,
                ),
                (
                    "0.3",
                    "network-candidate-linux-loopback-rtnetlink-eperm",
                    "a" * 64,
                    None,
                    None,
                ),
                (
                    "0.3",
                    "network-candidate-linux-loopback-rtnetlink-eperm",
                    hashlib.sha256(
                        b"bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted"
                    ).hexdigest(),
                    "network-candidate-linux-loopback-rtnetlink-eperm",
                    hashlib.sha256(
                        b"bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted"
                    ).hexdigest(),
                ),
                (
                    "0.3",
                    "network-trusted-ready-output",
                    "b" * 64,
                    None,
                    None,
                ),
                ("0.2", "network-candidate-start", None, None, None),
            ):
                if isinstance(stage, str) and (
                    stage.startswith("network-candidate-socket-")
                    or stage == "network-candidate-process-exit-unexpected"
                ):
                    code = "HARNESS_NETWORK_SANDBOX_POLICY_UNSUPPORTED"
                elif stage == "network-trusted-ready-output":
                    code = "HARNESS_INTERRUPTED"
                else:
                    code = "HARNESS_NETWORK_SANDBOX_SETUP_FAILED"
                with self.subTest(
                    version=version,
                    stage=stage,
                    digest=digest,
                    code=code,
                ):
                    fault["code"] = code
                    fault["schema_version"], fault["stage"] = version, stage
                    fault["launcher_diagnostic_sha256"] = digest
                    (runtime / "run.json.fault.json").write_text(json.dumps(fault))
                    process = subprocess.run(
                        [sys.executable, "-c", script, *arguments],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(0, process.returncode, process.stderr)
                    result = json.loads(process.stdout)
                    self.assertCountEqual(expected_keys, result)
                    self.assertEqual("0.3", result["schema_version"])
                    self.assertEqual(
                        expected_stage,
                        result["network_preflight_stage"],
                    )
                    self.assertEqual(
                        expected_digest,
                        result["launcher_diagnostic_sha256"],
                    )

            for code, stage in (
                (
                    "HARNESS_NETWORK_SANDBOX_SETUP_FAILED",
                    "network-candidate-socket-create-unexpected",
                ),
                (
                    "HARNESS_NETWORK_SANDBOX_POLICY_UNSUPPORTED",
                    "network-candidate-result",
                ),
            ):
                with self.subTest(code=code, stage=stage):
                    fault.update(
                        {
                            "code": code,
                            "launcher_diagnostic_sha256": None,
                            "schema_version": "0.3",
                            "stage": stage,
                        }
                    )
                    (runtime / "run.json.fault.json").write_text(json.dumps(fault))
                    process = subprocess.run(
                        [sys.executable, "-c", script, *arguments],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(0, process.returncode, process.stderr)
                    result = json.loads(process.stdout)
                    self.assertIsNone(result["network_preflight_stage"])

    def test_split_rust_toolchain_lock_has_no_stale_references(self) -> None:
        stale_lock = "rust/toolchain" + ".lock.json"
        stale_contract = "rust/toolchain" + ".lock.LLM-CONTRACT.md"
        self.assertFalse((PLUGIN_ROOT / stale_lock).exists())
        self.assertFalse((PLUGIN_ROOT / stale_contract).exists())

        ignored_parts = {
            ".git",
            "__pycache__",
            ".direnv",
            ".venv",
            "target",
            "tests",
        }
        offenders: list[str] = []
        for path in sorted(PLUGIN_ROOT.rglob("*")):
            if not path.is_file() or not ignored_parts.isdisjoint(path.parts):
                continue
            try:
                source = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if stale_lock in source or stale_contract in source:
                offenders.append(str(path.relative_to(PLUGIN_ROOT)))
        self.assertEqual([], offenders)

    def test_source_baseline_and_json_contract_sidecars_are_bound(self) -> None:
        baseline = tomllib.loads(
            (PLUGIN_ROOT / "SOURCE_BASELINE.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(
            "27862b406fffa58ac92b395f83ca970d08ef76b7d2220f63876b1c7113b63926",
            baseline["source_bundle_sha256"],
        )
        self.assertEqual(67, baseline["source_bundle_file_count"])
        self.assertEqual(65, baseline["source_only_file_count"])
        self.assertIn("bin/**", baseline["excluded_from_import"])
        self.assertIn("rust/target/**", baseline["excluded_from_import"])
        bindings = {}
        for binding in baseline["schema_bound_json_contracts"]:
            json_path, contract_path = binding.split("=", maxsplit=1)
            bindings[json_path] = contract_path
            self.assertTrue((PLUGIN_ROOT / json_path).is_file(), json_path)
            self.assertTrue((PLUGIN_ROOT / contract_path).is_file(), contract_path)
            self.assertIsNone(
                contract_blocks.contract_diagnostic(
                    (PLUGIN_ROOT / contract_path).read_text(encoding="utf-8")
                ),
                contract_path,
            )
            contract_source = (PLUGIN_ROOT / contract_path).read_text(encoding="utf-8")
            for contract in contract_blocks.parsed_contracts(contract_source):
                _, source_error = contract_blocks.resolve_contract_reference(
                    contract["source"],
                    repo_root=PLUGIN_ROOT,
                    bundle_root=PLUGIN_ROOT,
                    allow_external=True,
                )
                self.assertIsNone(source_error, contract_path)
                for field in ("knowledge", "test"):
                    _, reference_error = contract_blocks.resolve_contract_reference(
                        contract[field],
                        repo_root=PLUGIN_ROOT,
                        bundle_root=PLUGIN_ROOT,
                        allow_external=False,
                    )
                    self.assertIsNone(reference_error, contract_path)
                self.assertTrue(
                    contract_blocks.enforcement_token_is_present(
                        contract_source,
                        contract["enforced_by"],
                    ),
                    contract_path,
                )
        ignored_parts = {"bin", "target", ".governance", ".venv"}
        governed_json = {
            str(path.relative_to(PLUGIN_ROOT))
            for path in PLUGIN_ROOT.rglob("*.json")
            if ignored_parts.isdisjoint(path.parts)
        }
        self.assertEqual(governed_json, set(bindings))


if __name__ == "__main__":
    unittest.main()
