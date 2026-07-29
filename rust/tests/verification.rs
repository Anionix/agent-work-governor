//! Public aggregate run-receipt verification tests.

use std::error::Error;

use agent_work_governor::{
    CheckReceipt, CheckReport, CheckRequest, Governor, MAX_CHECK_OUTPUT_BYTES,
    MAX_RUN_RECEIPT_BYTES, PlanBindings, PlanProject, RunReceipt, Status, VerificationOutcome,
    VerificationReport,
};
use serde_json::{Value, json};

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
const TOOLCHAIN_SHA256: &str = "f123483a002951bec0907eb883c67ecdf3987561630947165f5ae30c3b34467a";
const ENVIRONMENT_SHA256: &str = "5555555555555555555555555555555555555555555555555555555555555555";
const HARNESS_SHA256: &str = "6666666666666666666666666666666666666666666666666666666666666666";
const INVOCATION_SHA256: &str = "7777777777777777777777777777777777777777777777777777777777777777";
const OUTPUT_SHA256: &str = "8888888888888888888888888888888888888888888888888888888888888888";
const DRIFT_SHA256: &str = "9999999999999999999999999999999999999999999999999999999999999999";

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

fn valid_receipt() -> Result<(PlanBindings, Value), Box<dyn Error>> {
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
    for check in planned_checks {
        let identifier = check
            .get("identifier")
            .and_then(Value::as_str)
            .ok_or("canonical plan check omitted identifier")?;
        checks.push(CheckReceipt::new(
            identifier,
            format!(".governance/receipts/evidence/{identifier}.json"),
            OUTPUT_SHA256,
            128,
            Some(0),
            false,
        ));
    }
    let receipt = RunReceipt::new(
        expected.clone(),
        plan.sha256(),
        HARNESS_SHA256,
        INVOCATION_SHA256,
        plan.coverage_sha256(),
        checks,
    );
    Ok((expected, serde_json::to_value(receipt)?))
}

fn verify_bytes(
    expected: PlanBindings,
    receipt_json: Vec<u8>,
    expected_harness_sha256: &str,
    expected_invocation_sha256: &str,
) -> Result<(VerificationReport, bool), Box<dyn Error>> {
    let report = Governor.check(CheckRequest::verify(
        expected,
        project(),
        expected_harness_sha256,
        expected_invocation_sha256,
        receipt_json,
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
) -> Result<(VerificationReport, bool), Box<dyn Error>> {
    verify_bytes(
        expected,
        serde_json::to_vec(receipt)?,
        HARNESS_SHA256,
        INVOCATION_SHA256,
    )
}

fn reason(report: &VerificationReport) -> Option<&str> {
    report
        .findings()
        .first()
        .map(|finding| finding.code.as_str())
}

fn assert_rejected(
    expected: PlanBindings,
    receipt: &Value,
    expected_reason: &str,
) -> Result<(), Box<dyn Error>> {
    let (report, succeeded) = verify_value(expected, receipt)?;
    assert!(!succeeded);
    assert_eq!(Status::Fail, report.status());
    assert_eq!(VerificationOutcome::ReceiptRejected, report.outcome());
    assert_eq!(Some(expected_reason), reason(&report));
    assert_eq!(0, report.mutation_count());
    Ok(())
}

#[test]
fn valid_exact_receipt_is_the_only_pass() -> Result<(), Box<dyn Error>> {
    let (expected, mut receipt) = valid_receipt()?;
    let encoded = serde_json::to_string(&receipt)?;
    assert!(
        ["status", "verdict", "authority", "actor"]
            .iter()
            .all(|field| !encoded.contains(field))
    );

    let (report, succeeded) = verify_value(expected.clone(), &receipt)?;
    assert!(succeeded);
    assert_eq!(Status::Pass, report.status());
    assert_eq!(VerificationOutcome::VerifiedPass, report.outcome());
    assert!(report.findings().is_empty());
    assert_eq!(0, report.mutation_count());
    let report_json = serde_json::to_value(&report)?;
    assert_eq!("VERIFIED_PASS", report_json["outcome"]);
    assert_eq!("PASS", report_json["status"]);

    receipt
        .get_mut("checks")
        .and_then(Value::as_array_mut)
        .ok_or("receipt omitted checks")?
        .reverse();
    let (reordered, succeeded) = verify_value(expected, &receipt)?;
    assert!(succeeded);
    assert_eq!(VerificationOutcome::VerifiedPass, reordered.outcome());
    Ok(())
}

#[test]
fn every_expected_binding_rejects_stale_or_mismatched_evidence() -> Result<(), Box<dyn Error>> {
    let (expected, receipt) = valid_receipt()?;
    for (pointer, expected_reason) in [
        ("/bindings/repository_sha256", "RECEIPT_REPOSITORY_MISMATCH"),
        ("/bindings/revision_sha256", "RECEIPT_REVISION_MISMATCH"),
        ("/bindings/policy_sha256", "RECEIPT_POLICY_MISMATCH"),
        ("/bindings/toolchain_sha256", "RECEIPT_TOOLCHAIN_MISMATCH"),
        (
            "/bindings/environment_sha256",
            "RECEIPT_ENVIRONMENT_MISMATCH",
        ),
        ("/execution_plan_sha256", "RECEIPT_PLAN_MISMATCH"),
        ("/harness_sha256", "RECEIPT_HARNESS_MISMATCH"),
        ("/invocation_sha256", "RECEIPT_INVOCATION_STALE"),
        ("/coverage_sha256", "RECEIPT_COVERAGE_MISMATCH"),
    ] {
        let mut candidate = receipt.clone();
        *candidate
            .pointer_mut(pointer)
            .ok_or("binding pointer was absent")? = json!(DRIFT_SHA256);
        assert_rejected(expected.clone(), &candidate, expected_reason)?;
    }
    Ok(())
}

#[test]
fn evidence_set_must_be_exact_unique_bounded_and_safe() -> Result<(), Box<dyn Error>> {
    let (expected, receipt) = valid_receipt()?;
    let checks = receipt
        .get("checks")
        .and_then(Value::as_array)
        .ok_or("receipt omitted checks")?;
    let first = checks.first().ok_or("receipt had no checks")?.clone();

    let mut missing = receipt.clone();
    missing
        .get_mut("checks")
        .and_then(Value::as_array_mut)
        .ok_or("receipt omitted checks")?
        .remove(0);
    assert_rejected(expected.clone(), &missing, "RECEIPT_CHECK_MISSING")?;

    let mut duplicate = receipt.clone();
    duplicate
        .get_mut("checks")
        .and_then(Value::as_array_mut)
        .ok_or("receipt omitted checks")?
        .push(first.clone());
    assert_rejected(expected.clone(), &duplicate, "RECEIPT_CHECK_DUPLICATE")?;

    let mut extra_check = first;
    extra_check["identifier"] = json!("unplanned.check");
    let mut extra = receipt.clone();
    extra
        .get_mut("checks")
        .and_then(Value::as_array_mut)
        .ok_or("receipt omitted checks")?
        .push(extra_check);
    assert_rejected(expected.clone(), &extra, "RECEIPT_CHECK_EXTRA")?;

    for (pointer, replacement, expected_reason) in [
        (
            "/checks/0/evidence_path",
            json!("../outside.json"),
            "RECEIPT_EVIDENCE_PATH_UNSAFE",
        ),
        (
            "/checks/0/output_sha256",
            json!("INVALID"),
            "RECEIPT_OUTPUT_DIGEST_INVALID",
        ),
        (
            "/checks/0/output_bytes",
            json!(MAX_CHECK_OUTPUT_BYTES + 1),
            "RECEIPT_OUTPUT_SIZE_EXCEEDED",
        ),
        (
            "/checks/0/exit_code",
            Value::Null,
            "RECEIPT_CHECK_EXIT_MISSING",
        ),
    ] {
        let mut candidate = receipt.clone();
        *candidate
            .pointer_mut(pointer)
            .ok_or("check pointer was absent")? = replacement;
        assert_rejected(expected.clone(), &candidate, expected_reason)?;
    }

    let mut invalid_after_failure = receipt.clone();
    let invalid_checks = invalid_after_failure
        .get_mut("checks")
        .and_then(Value::as_array_mut)
        .ok_or("receipt omitted checks")?;
    invalid_checks
        .get_mut(0)
        .ok_or("receipt omitted first check")?["exit_code"] = json!(7);
    invalid_checks
        .get_mut(1)
        .ok_or("receipt omitted second check")?["evidence_path"] = json!("../outside.json");
    assert_rejected(
        expected,
        &invalid_after_failure,
        "RECEIPT_EVIDENCE_PATH_UNSAFE",
    )?;

    Ok(())
}

#[test]
fn bounded_execution_failures_are_verified_fail_not_rejected() -> Result<(), Box<dyn Error>> {
    let (expected, receipt) = valid_receipt()?;
    for (pointer, replacement, expected_reason) in [
        (
            "/checks/0/exit_code",
            json!(7),
            "RECEIPT_CHECK_EXIT_NONZERO",
        ),
        (
            "/checks/0/timed_out",
            json!(true),
            "RECEIPT_CHECK_TIMED_OUT",
        ),
    ] {
        let mut candidate = receipt.clone();
        *candidate
            .pointer_mut(pointer)
            .ok_or("check pointer was absent")? = replacement;
        let (report, succeeded) = verify_value(expected.clone(), &candidate)?;
        assert!(!succeeded);
        assert_eq!(Status::Fail, report.status());
        assert_eq!(VerificationOutcome::VerifiedFail, report.outcome());
        assert_eq!(Some(expected_reason), reason(&report));
    }
    Ok(())
}

#[test]
fn malformed_oversized_or_self_authorizing_receipts_never_pass() -> Result<(), Box<dyn Error>> {
    let (expected, receipt) = valid_receipt()?;

    let (malformed, succeeded) = verify_bytes(
        expected.clone(),
        b"{".to_vec(),
        HARNESS_SHA256,
        INVOCATION_SHA256,
    )?;
    assert!(!succeeded);
    assert_eq!(Some("RECEIPT_MALFORMED"), reason(&malformed));

    let (oversized, succeeded) = verify_bytes(
        expected.clone(),
        vec![b' '; MAX_RUN_RECEIPT_BYTES + 1],
        HARNESS_SHA256,
        INVOCATION_SHA256,
    )?;
    assert!(!succeeded);
    assert_eq!(Some("RECEIPT_SIZE_EXCEEDED"), reason(&oversized));

    let mut self_authorizing = receipt.clone();
    self_authorizing["verdict"] = json!("PASS");
    assert_rejected(expected.clone(), &self_authorizing, "RECEIPT_MALFORMED")?;

    let mut unsupported = receipt.clone();
    unsupported["schema_version"] = json!("9.9");
    assert_rejected(expected.clone(), &unsupported, "RECEIPT_SCHEMA_UNSUPPORTED")?;

    let mut invalid_digest = receipt.clone();
    invalid_digest["harness_sha256"] = json!("invalid");
    assert_rejected(expected.clone(), &invalid_digest, "RECEIPT_DIGEST_INVALID")?;

    for (harness, invocation, expected_reason) in [
        (
            "invalid",
            INVOCATION_SHA256,
            "VERIFY_HARNESS_DIGEST_INVALID",
        ),
        (
            HARNESS_SHA256,
            "invalid",
            "VERIFY_INVOCATION_DIGEST_INVALID",
        ),
    ] {
        let (report, succeeded) = verify_bytes(
            expected.clone(),
            serde_json::to_vec(&receipt)?,
            harness,
            invocation,
        )?;
        assert!(!succeeded);
        assert_eq!(VerificationOutcome::ReceiptRejected, report.outcome());
        assert_eq!(Some(expected_reason), reason(&report));
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
        serde_json::to_vec(&receipt)?,
        HARNESS_SHA256,
        INVOCATION_SHA256,
    )?;
    assert!(!succeeded);
    assert_eq!(
        Some("RECEIPT_PLAN_RECOMPUTE_REJECTED"),
        reason(&plan_rejected)
    );
    assert!(plan_rejected.execution_plan_sha256().is_none());
    Ok(())
}
