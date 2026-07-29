//! Public aggregate run-receipt verification tests.

use std::error::Error;

use agent_work_governor::{
    CheckOutcome, CheckReceipt, CheckReport, CheckRequest, EvidenceArtifact, Governor,
    MAX_CHECK_OUTPUT_BYTES, MAX_RUN_RECEIPT_BYTES, PlanBindings, PlanProject, RunReceipt, Status,
    VerificationOutcome, VerificationReason, VerificationReport,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

// LLM-CONTRACT
// id: agent-work-governor.receipt-verification-tests
// state: UNTRUSTED_RECEIPT -> GOVERNOR_VERIFY -> VERIFIED_PASS | VERIFIED_FAIL | RECEIPT_REJECTED
// preconditions: fixtures cross only the public Governor interface
// invariant: no receipt field, ordering, replay, or incomplete evidence can self-declare PASS
// failure: the Rust test harness reports the exact violated reason-code contract
// source: https://github.com/slsa-framework/slsa/blob/ae7fc76215004e8fae250c877eff8919bf048e3b/spec/verifying-artifacts.md
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: valid_exact_receipt_is_the_only_pass
// test: bundle:rust/tests/verification.rs

const REPOSITORY_SHA256: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const REVISION_SHA256: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const POLICY_SHA256: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const TOOLCHAIN_SHA256: &str = "c293da2e18d7659add467f51413d627d17dd5f2b70495536451cb33a786a9194";
const ENVIRONMENT_SHA256: &str = "5555555555555555555555555555555555555555555555555555555555555555";
const HARNESS_SHA256: &str = "6666666666666666666666666666666666666666666666666666666666666666";
const INVOCATION_SHA256: &str = "7777777777777777777777777777777777777777777777777777777777777777";
const DRIFT_SHA256: &str = "9999999999999999999999999999999999999999999999999999999999999999";
const OUTPUT: &[u8] = b"bounded output";
const TAMPERED_OUTPUT: &[u8] = b"bounded outpvt";

#[derive(Clone)]
struct Fixture {
    expected: PlanBindings,
    receipt: Value,
    evidence: Vec<EvidenceArtifact>,
}

fn bindings() -> PlanBindings {
    PlanBindings::new(
        REPOSITORY_SHA256,
        REVISION_SHA256,
        POLICY_SHA256,
        TOOLCHAIN_SHA256,
        ENVIRONMENT_SHA256,
    )
}

fn project() -> PlanProject {
    PlanProject::RustCargoWorkspace {
        working_directory: ".".into(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn valid_fixture() -> Result<Fixture, Box<dyn Error>> {
    let expected = bindings();
    let CheckReport::Plan(report) =
        Governor.check(CheckRequest::plan(expected.clone(), project()))?
    else {
        return Err("planning returned the wrong report variant".into());
    };
    let plan = report
        .execution_plan()
        .ok_or("valid fixture did not produce a plan")?;
    assert_eq!(
        "9c784444d43edcbe4e1888e3716b5df1ba80a8da4defe17b1d7454d56d3be28f",
        plan.coverage_sha256()
    );
    let document = serde_json::from_slice::<Value>(plan.canonical_json())?;
    let planned_checks = document
        .get("checks")
        .and_then(Value::as_array)
        .ok_or("canonical plan omitted checks")?;
    let mut checks = Vec::with_capacity(planned_checks.len());
    let mut evidence = Vec::with_capacity(planned_checks.len());
    for check in planned_checks {
        let identifier = check
            .get("identifier")
            .and_then(Value::as_str)
            .ok_or("canonical plan check omitted identifier")?;
        let path = format!(".governance/receipts/evidence/{identifier}.json");
        checks.push(CheckReceipt::new(
            identifier,
            &path,
            sha256_hex(OUTPUT),
            u64::try_from(OUTPUT.len())?,
            CheckOutcome::Exited { exit_code: 0 },
        ));
        evidence.push(EvidenceArtifact::new(path, OUTPUT.to_vec()));
    }
    let receipt = RunReceipt::new(
        expected.clone(),
        plan.sha256(),
        HARNESS_SHA256,
        INVOCATION_SHA256,
        plan.coverage_sha256(),
        checks,
    );
    Ok(Fixture {
        expected,
        receipt: serde_json::to_value(receipt)?,
        evidence,
    })
}

fn verify_bytes(
    expected: PlanBindings,
    receipt_json: Vec<u8>,
    evidence: Vec<EvidenceArtifact>,
    expected_harness_sha256: &str,
    expected_invocation_sha256: &str,
) -> Result<(VerificationReport, bool), Box<dyn Error>> {
    let report = Governor.check(CheckRequest::verify(
        expected,
        project(),
        expected_harness_sha256,
        expected_invocation_sha256,
        receipt_json,
        evidence,
    ))?;
    let succeeded = report.succeeded();
    let CheckReport::Verify(report) = report else {
        return Err("verification returned the wrong report variant".into());
    };
    Ok((report, succeeded))
}

fn verify_value(
    expected: PlanBindings,
    receipt: &Value,
    evidence: Vec<EvidenceArtifact>,
) -> Result<(VerificationReport, bool), Box<dyn Error>> {
    verify_bytes(
        expected,
        serde_json::to_vec(receipt)?,
        evidence,
        HARNESS_SHA256,
        INVOCATION_SHA256,
    )
}

fn assert_rejected(
    expected: PlanBindings,
    receipt: &Value,
    evidence: Vec<EvidenceArtifact>,
    expected_reason: VerificationReason,
) -> Result<(), Box<dyn Error>> {
    let (report, succeeded) = verify_value(expected, receipt, evidence)?;
    assert!(!succeeded);
    assert_eq!(Status::Fail, report.status());
    assert_eq!(VerificationOutcome::ReceiptRejected, report.outcome());
    assert_eq!(Some(expected_reason), report.reason());
    assert_eq!(
        Some(expected_reason.as_str()),
        report
            .findings()
            .first()
            .map(|finding| finding.code.as_str())
    );
    assert_eq!(0, report.mutation_count());
    Ok(())
}

#[test]
fn valid_exact_receipt_is_the_only_pass() -> Result<(), Box<dyn Error>> {
    let mut fixture = valid_fixture()?;
    let encoded = serde_json::to_string(&fixture.receipt)?;
    assert!(
        ["status", "verdict", "authority", "actor"]
            .iter()
            .all(|field| !encoded.contains(field))
    );

    let (report, succeeded) = verify_value(
        fixture.expected.clone(),
        &fixture.receipt,
        fixture.evidence.clone(),
    )?;
    assert!(succeeded);
    assert_eq!(Status::Pass, report.status());
    assert_eq!(VerificationOutcome::VerifiedPass, report.outcome());
    assert_eq!(None, report.reason());
    assert!(report.findings().is_empty());
    assert_eq!(0, report.mutation_count());
    let report_json = serde_json::to_value(&report)?;
    assert_eq!("VERIFIED_PASS", report_json["outcome"]);
    assert_eq!("PASS", report_json["status"]);
    assert!(report_json.get("reason").is_none());

    fixture
        .receipt
        .get_mut("checks")
        .and_then(Value::as_array_mut)
        .ok_or("receipt omitted checks")?
        .reverse();
    let (reordered, succeeded) =
        verify_value(fixture.expected, &fixture.receipt, fixture.evidence)?;
    assert!(succeeded);
    assert_eq!(VerificationOutcome::VerifiedPass, reordered.outcome());
    Ok(())
}

#[test]
fn every_expected_binding_rejects_stale_or_mismatched_evidence() -> Result<(), Box<dyn Error>> {
    let fixture = valid_fixture()?;
    for (pointer, expected_reason) in [
        (
            "/bindings/repository_sha256",
            VerificationReason::ReceiptRepositoryMismatch,
        ),
        (
            "/bindings/revision_sha256",
            VerificationReason::ReceiptRevisionMismatch,
        ),
        (
            "/bindings/policy_sha256",
            VerificationReason::ReceiptPolicyMismatch,
        ),
        (
            "/bindings/toolchain_sha256",
            VerificationReason::ReceiptToolchainMismatch,
        ),
        (
            "/bindings/environment_sha256",
            VerificationReason::ReceiptEnvironmentMismatch,
        ),
        (
            "/execution_plan_sha256",
            VerificationReason::ReceiptPlanMismatch,
        ),
        (
            "/harness_sha256",
            VerificationReason::ReceiptHarnessMismatch,
        ),
        (
            "/invocation_sha256",
            VerificationReason::ReceiptInvocationStale,
        ),
        (
            "/coverage_sha256",
            VerificationReason::ReceiptCoverageMismatch,
        ),
    ] {
        let mut candidate = fixture.receipt.clone();
        *candidate
            .pointer_mut(pointer)
            .ok_or("binding pointer was absent")? = json!(DRIFT_SHA256);
        assert_rejected(
            fixture.expected.clone(),
            &candidate,
            fixture.evidence.clone(),
            expected_reason,
        )?;
    }
    Ok(())
}

#[test]
fn receipt_evidence_set_is_exact_unique_bounded_and_safe() -> Result<(), Box<dyn Error>> {
    let fixture = valid_fixture()?;
    let checks = fixture
        .receipt
        .get("checks")
        .and_then(Value::as_array)
        .ok_or("receipt omitted checks")?;
    let first = checks.first().ok_or("receipt had no checks")?.clone();

    for (kind, expected_reason) in [
        ("missing", VerificationReason::ReceiptCheckMissing),
        ("duplicate", VerificationReason::ReceiptCheckDuplicate),
        ("extra", VerificationReason::ReceiptCheckExtra),
    ] {
        let mut candidate = fixture.receipt.clone();
        let candidate_checks = candidate
            .get_mut("checks")
            .and_then(Value::as_array_mut)
            .ok_or("receipt omitted checks")?;
        match kind {
            "missing" => {
                candidate_checks.remove(0);
            }
            "duplicate" => candidate_checks.push(first.clone()),
            "extra" => {
                let mut extra = first.clone();
                extra["identifier"] = json!("unplanned.check");
                extra["evidence_path"] =
                    json!(".governance/receipts/evidence/unplanned.check.json");
                candidate_checks.push(extra);
            }
            _ => return Err("unknown fixture mutation".into()),
        }
        assert_rejected(
            fixture.expected.clone(),
            &candidate,
            fixture.evidence.clone(),
            expected_reason,
        )?;
    }

    for unsafe_path in [
        "../outside.json",
        ".git/config",
        "NUL",
        ".governance/receipts/evidence/NUL.json",
    ] {
        let mut candidate = fixture.receipt.clone();
        candidate["checks"][0]["evidence_path"] = json!(unsafe_path);
        assert_rejected(
            fixture.expected.clone(),
            &candidate,
            fixture.evidence.clone(),
            VerificationReason::ReceiptEvidencePathUnsafe,
        )?;
    }

    let mut invalid_digest = fixture.receipt.clone();
    invalid_digest["checks"][0]["output_sha256"] = json!("INVALID");
    assert_rejected(
        fixture.expected.clone(),
        &invalid_digest,
        fixture.evidence.clone(),
        VerificationReason::ReceiptOutputDigestInvalid,
    )?;

    let mut oversized_claim = fixture.receipt.clone();
    oversized_claim["checks"][0]["output_bytes"] = json!(MAX_CHECK_OUTPUT_BYTES + 1);
    assert_rejected(
        fixture.expected.clone(),
        &oversized_claim,
        fixture.evidence.clone(),
        VerificationReason::ReceiptOutputSizeExceeded,
    )?;

    let mut duplicate_path = fixture.receipt.clone();
    duplicate_path["checks"][1]["evidence_path"] =
        duplicate_path["checks"][0]["evidence_path"].clone();
    assert_rejected(
        fixture.expected,
        &duplicate_path,
        fixture.evidence,
        VerificationReason::ReceiptEvidenceDuplicate,
    )?;
    Ok(())
}

#[test]
fn supplied_evidence_bytes_are_exact_unique_and_bounded() -> Result<(), Box<dyn Error>> {
    let fixture = valid_fixture()?;
    let mut missing_evidence = fixture.evidence.clone();
    missing_evidence.remove(0);
    assert_rejected(
        fixture.expected.clone(),
        &fixture.receipt,
        missing_evidence,
        VerificationReason::ReceiptEvidenceMissing,
    )?;

    let mut extra_evidence = fixture.evidence.clone();
    extra_evidence.push(EvidenceArtifact::new(
        ".governance/receipts/evidence/unplanned.json",
        OUTPUT.to_vec(),
    ));
    assert_rejected(
        fixture.expected.clone(),
        &fixture.receipt,
        extra_evidence,
        VerificationReason::ReceiptEvidenceExtra,
    )?;

    let mut duplicate_evidence = fixture.evidence.clone();
    duplicate_evidence.push(
        fixture
            .evidence
            .first()
            .ok_or("fixture omitted evidence")?
            .clone(),
    );
    assert_rejected(
        fixture.expected.clone(),
        &fixture.receipt,
        duplicate_evidence,
        VerificationReason::ReceiptEvidenceDuplicate,
    )?;

    let paths = fixture
        .receipt
        .get("checks")
        .and_then(Value::as_array)
        .ok_or("receipt omitted checks")?
        .iter()
        .map(|check| {
            check
                .get("evidence_path")
                .and_then(Value::as_str)
                .ok_or("check omitted evidence path")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let tampered_evidence = paths
        .iter()
        .map(|path| EvidenceArtifact::new(*path, TAMPERED_OUTPUT.to_vec()))
        .collect();
    assert_rejected(
        fixture.expected.clone(),
        &fixture.receipt,
        tampered_evidence,
        VerificationReason::ReceiptOutputDigestMismatch,
    )?;

    let mut size_mismatch = fixture.receipt.clone();
    size_mismatch["checks"][0]["output_bytes"] = json!(u64::try_from(OUTPUT.len())? + 1);
    assert_rejected(
        fixture.expected.clone(),
        &size_mismatch,
        fixture.evidence.clone(),
        VerificationReason::ReceiptOutputSizeMismatch,
    )?;

    let oversized_length = usize::try_from(MAX_CHECK_OUTPUT_BYTES)? + 1;
    let oversized_evidence = paths
        .iter()
        .map(|path| EvidenceArtifact::new(*path, vec![0; oversized_length]))
        .collect::<Vec<_>>();
    assert_rejected(
        fixture.expected,
        &fixture.receipt,
        oversized_evidence,
        VerificationReason::ReceiptOutputSizeExceeded,
    )?;
    Ok(())
}

#[test]
fn bounded_execution_failures_are_typed_and_never_mask_rejection() -> Result<(), Box<dyn Error>> {
    let fixture = valid_fixture()?;
    for (outcome, expected_reason) in [
        (
            json!({"EXITED": {"exit_code": 7}}),
            VerificationReason::ReceiptCheckExitNonzero,
        ),
        (json!("TIMED_OUT"), VerificationReason::ReceiptCheckTimedOut),
    ] {
        let mut candidate = fixture.receipt.clone();
        candidate["checks"][0]["outcome"] = outcome;
        let (report, succeeded) = verify_value(
            fixture.expected.clone(),
            &candidate,
            fixture.evidence.clone(),
        )?;
        assert!(!succeeded);
        assert_eq!(Status::Fail, report.status());
        assert_eq!(VerificationOutcome::VerifiedFail, report.outcome());
        assert_eq!(Some(expected_reason), report.reason());
    }

    let mut contradictory = fixture.receipt.clone();
    contradictory["checks"][0]["outcome"] = json!({"TIMED_OUT": {"exit_code": 0}});
    assert_rejected(
        fixture.expected.clone(),
        &contradictory,
        fixture.evidence.clone(),
        VerificationReason::ReceiptMalformed,
    )?;

    let mut invalid_after_failure = fixture.receipt.clone();
    invalid_after_failure["checks"][0]["outcome"] = json!({"EXITED": {"exit_code": 7}});
    invalid_after_failure["checks"][1]["evidence_path"] = json!("../outside.json");
    assert_rejected(
        fixture.expected,
        &invalid_after_failure,
        fixture.evidence,
        VerificationReason::ReceiptEvidencePathUnsafe,
    )?;
    Ok(())
}

#[test]
fn malformed_oversized_or_self_authorizing_receipts_never_pass() -> Result<(), Box<dyn Error>> {
    let fixture = valid_fixture()?;

    let (malformed, succeeded) = verify_bytes(
        fixture.expected.clone(),
        b"{".to_vec(),
        fixture.evidence.clone(),
        HARNESS_SHA256,
        INVOCATION_SHA256,
    )?;
    assert!(!succeeded);
    assert_eq!(
        Some(VerificationReason::ReceiptMalformed),
        malformed.reason()
    );

    let (oversized, succeeded) = verify_bytes(
        fixture.expected.clone(),
        vec![b' '; MAX_RUN_RECEIPT_BYTES + 1],
        fixture.evidence.clone(),
        HARNESS_SHA256,
        INVOCATION_SHA256,
    )?;
    assert!(!succeeded);
    assert_eq!(
        Some(VerificationReason::ReceiptSizeExceeded),
        oversized.reason()
    );

    for (field, value, expected_reason) in [
        (
            "verdict",
            json!("PASS"),
            VerificationReason::ReceiptMalformed,
        ),
        (
            "schema_version",
            json!("9.9"),
            VerificationReason::ReceiptSchemaUnsupported,
        ),
        (
            "harness_sha256",
            json!("invalid"),
            VerificationReason::ReceiptDigestInvalid,
        ),
    ] {
        let mut candidate = fixture.receipt.clone();
        candidate[field] = value;
        assert_rejected(
            fixture.expected.clone(),
            &candidate,
            fixture.evidence.clone(),
            expected_reason,
        )?;
    }

    for (harness, invocation, expected_reason) in [
        (
            "invalid",
            INVOCATION_SHA256,
            VerificationReason::VerifyHarnessDigestInvalid,
        ),
        (
            HARNESS_SHA256,
            "invalid",
            VerificationReason::VerifyInvocationDigestInvalid,
        ),
    ] {
        let (report, succeeded) = verify_bytes(
            fixture.expected.clone(),
            serde_json::to_vec(&fixture.receipt)?,
            fixture.evidence.clone(),
            harness,
            invocation,
        )?;
        assert!(!succeeded);
        assert_eq!(VerificationOutcome::ReceiptRejected, report.outcome());
        assert_eq!(Some(expected_reason), report.reason());
    }

    let invalid_plan_bindings = PlanBindings::new(
        "invalid",
        REVISION_SHA256,
        POLICY_SHA256,
        TOOLCHAIN_SHA256,
        ENVIRONMENT_SHA256,
    );
    let (plan_rejected, succeeded) = verify_bytes(
        invalid_plan_bindings,
        serde_json::to_vec(&fixture.receipt)?,
        fixture.evidence,
        HARNESS_SHA256,
        INVOCATION_SHA256,
    )?;
    assert!(!succeeded);
    assert_eq!(
        Some(VerificationReason::ReceiptPlanRecomputeRejected),
        plan_rejected.reason()
    );
    assert!(plan_rejected.execution_plan_sha256().is_none());
    Ok(())
}
