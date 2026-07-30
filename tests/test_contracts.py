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
        else ".github/workflows/governor.yml"
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
            else ".github/workflows/governor.yml"
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

        workflow = (PLUGIN_ROOT / ".github/workflows/governor.yml").read_text(
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

        workflow = (PLUGIN_ROOT / ".github/workflows/governor.yml").read_text(
            encoding="utf-8"
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
            "clippyPin.source == rustPin.source",
            "rustfmtPin.source == rustPin.source",
            "TOOLCHAIN_GIT_REPOSITORY_SELF_TEST_FAILED",
            "TOOLCHAIN_RUST_COMPONENT_SELF_TEST_FAILED",
            "TOOLCHAIN_PACKAGE_SOURCE_URL_MISMATCH",
            "TOOLCHAIN_PACKAGE_SOURCE_DIGEST_MISMATCH",
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
            "runner: [ubuntu-24.04, ubuntu-24.04-arm, macos-15]",
            'bwrap="$(',
            "which bwrap",
            'trusted_path="$(dirname "$bwrap"):$trusted_path"',
            "sudo /usr/bin/env -i",
            '"PATH=$trusted_path"',
            '"$python" -B -m unittest tests.test_bounded_harness',
            'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
        ):
            self.assertIn(evidence, workflow)
        self.assertNotIn("pull_request", workflow)
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
            "workflows: [governor]",
            "permissions:\n  contents: read",
            "github.event.workflow_run.event == 'pull_request'",
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
            '"network_preflight_stage"',
            '"network-candidate-start"',
            '"network-candidate-ready-eof"',
            '"network-candidate-linux-loopback-rtnetlink-eperm"',
            'value.get("schema_version") != "0.2"',
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

    def test_shadow_evidence_v02_bounds_network_stage(self) -> None:
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
            fault = {
                "code": "HARNESS_NETWORK_SANDBOX_SETUP_FAILED",
                "completed": [],
                "failed": [],
                "not_started": [],
                "running": [],
                "state": "HARNESS_FAULT",
            }
            for version, stage, expected in (
                ("0.2", "network-candidate-start", "network-candidate-start"),
                ("0.2", ["network-candidate-start"], None),
                ("0.2", "candidate-controlled", None),
                ("0.1", "network-candidate-start", None),
            ):
                with self.subTest(version=version, stage=stage):
                    fault["schema_version"], fault["stage"] = version, stage
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
                    self.assertEqual("0.2", result["schema_version"])
                    self.assertEqual(expected, result["network_preflight_stage"])

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
