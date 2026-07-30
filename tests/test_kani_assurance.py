"""Fail-closed tests for bounded Kani assurance evidence."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from scripts import validate_kani_assurance

# LLM-CONTRACT
# id: agent-work-governor.kani-assurance-tests
# state: FIXTURE_EVIDENCE -> PASS_RECEIPT | CLOSED_REJECTION
# preconditions: each test owns an isolated temporary repository and log
# invariant: only exact source, bounds, verification, and satisfied covers pass
# failure: unittest reports any accepted stale or incomplete evidence
# source: https://github.com/model-checking/kani/blob/4feaaad1d6a2378a6ff6caa3b4fc5d6999c7bb5d/kani-driver/src/cbmc_output_parser.rs
# knowledge: bundle:knowledge/policies/work-governor.md
# enforced_by: KaniAssuranceTests
# test: bundle:tests/test_kani_assurance.py


class KaniAssuranceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        source = self.root / "owner_scope.rs"
        source.write_text("fn decide() {}\n", encoding="utf-8")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        self.manifest = self.root / "assurance.toml"
        self.manifest.write_text(
            f"""
schema_version = "0.1"
mode = "shadow"
subject = "owner_scope::decide"
tool_id = "kani"
tool_version = "0.67.0"
source_path = "owner_scope.rs"
source_sha256 = "{digest}"
harness_sha256 = "{digest}"
invocation = "cargo kani --manifest-path rust/Cargo.toml --lib --harness <positive_harness>"
positive_harnesses = ["decision_gate_equivalence"]
negative_canary = "negative_canary_must_fail"
expected_covers = ["verified", "binding", "expired", "signature"]
non_vacuity = "concrete witnesses"
claims = ["intersection"]
excluded = ["crypto"]

[bounds]
binding_mask_bits = 8
timestamp_bits = 64
authority_bits = 6
unwind = 1
""".strip(),
            encoding="utf-8",
        )
        self.log = self.root / "kani.log"
        self.log.write_text(
            "".join(
                f'\t - Status: SATISFIED\n\t - Description: "{description}"\n'
                for description in ("verified", "binding", "expired", "signature")
            )
            + "VERIFICATION:- SUCCESSFUL\n",
            encoding="utf-8",
        )

    def validate(self) -> dict[str, object]:
        return validate_kani_assurance.validate(
            self.root, Path(self.manifest.name), self.log, "0.67.0"
        )

    def test_exact_evidence_emits_shadow_only_receipt(self) -> None:
        self.assertEqual("none", self.validate()["authority"])

    def test_unsatisfied_or_missing_cover_fails_closed(self) -> None:
        payload = self.log.read_text(encoding="utf-8")
        for mutation in (
            payload.replace("Status: SATISFIED", "Status: UNSATISFIABLE", 1),
            payload.replace('Description: "binding"\n', ""),
        ):
            self.log.write_text(mutation, encoding="utf-8")
            with self.assertRaises(validate_kani_assurance.AssuranceError):
                self.validate()

    def test_source_drift_and_duplicate_cover_fail_closed(self) -> None:
        (self.root / "owner_scope.rs").write_text("fn changed() {}\n", encoding="utf-8")
        with self.assertRaises(validate_kani_assurance.AssuranceError):
            self.validate()
        (self.root / "owner_scope.rs").write_text("fn decide() {}\n", encoding="utf-8")
        self.log.write_text(
            self.log.read_text(encoding="utf-8")
            + '\t - Status: SATISFIED\n\t - Description: "verified"\n',
            encoding="utf-8",
        )
        with self.assertRaises(validate_kani_assurance.AssuranceError):
            self.validate()

    def test_manifest_escape_and_missing_harness_result_fail_closed(self) -> None:
        with self.assertRaises(validate_kani_assurance.AssuranceError):
            validate_kani_assurance.validate(
                self.root, Path("..") / self.manifest.name, self.log, "0.67.0"
            )
        manifest = self.manifest.read_text(encoding="utf-8").replace(
            'positive_harnesses = ["decision_gate_equivalence"]',
            'positive_harnesses = ["decision_gate_equivalence", "intersection"]',
        )
        self.manifest.write_text(manifest, encoding="utf-8")
        with self.assertRaises(validate_kani_assurance.AssuranceError):
            self.validate()


if __name__ == "__main__":
    unittest.main()
