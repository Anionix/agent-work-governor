//! Typed, fail-closed verification of untrusted aggregate run receipts.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    CanonicalExecutionPlan, CheckRequest, Finding, GovernorError, PlanBindings, PlanProject,
    Status, planning,
};

/// Maximum accepted aggregate receipt size: one mebibyte.
pub const MAX_RUN_RECEIPT_BYTES: usize = 1_048_576;
/// Maximum captured output represented by one check receipt: one mebibyte.
pub const MAX_CHECK_OUTPUT_BYTES: u64 = 1_048_576;
const RUN_RECEIPT_SCHEMA_VERSION: &str = "0.1";

// LLM-CONTRACT
// id: agent-work-governor.aggregate-receipt-verification
// state: PLAN_BOUND_RECEIPT -> VERIFIED_PASS | VERIFIED_FAIL | RECEIPT_REJECTED
// preconditions: plan inputs plus expected harness and invocation SHA-256 come from the verifier
// invariant: only Rust derives PASS after exact bindings, coverage, evidence, and outcomes match
// failure: malformed, stale, incomplete, unsafe, or self-authorizing evidence is rejected whole
// source: https://github.com/slsa-framework/slsa/blob/ae7fc76215004e8fae250c877eff8919bf048e3b/spec/verifying-artifacts.md
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: verify_receipt
// test: bundle:rust/tests/verification.rs

/// Evidence emitted for one check in a bounded run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckReceipt {
    identifier: String,
    evidence_path: String,
    output_sha256: String,
    output_bytes: u64,
    exit_code: Option<i32>,
    timed_out: bool,
}

impl CheckReceipt {
    /// Construct evidence without assigning any policy verdict.
    #[must_use]
    pub fn new(
        identifier: impl Into<String>,
        evidence_path: impl Into<String>,
        output_sha256: impl Into<String>,
        output_bytes: u64,
        exit_code: Option<i32>,
        timed_out: bool,
    ) -> Self {
        Self {
            identifier: identifier.into(),
            evidence_path: evidence_path.into(),
            output_sha256: output_sha256.into(),
            output_bytes,
            exit_code,
            timed_out,
        }
    }
}

/// Aggregate evidence emitted by a harness, without a caller-supplied verdict.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunReceipt {
    schema_version: String,
    bindings: PlanBindings,
    execution_plan_sha256: String,
    harness_sha256: String,
    invocation_sha256: String,
    coverage_sha256: String,
    checks: Vec<CheckReceipt>,
}

impl RunReceipt {
    /// Construct an aggregate receipt with the current closed schema.
    #[must_use]
    pub fn new(
        bindings: PlanBindings,
        execution_plan_sha256: impl Into<String>,
        harness_sha256: impl Into<String>,
        invocation_sha256: impl Into<String>,
        coverage_sha256: impl Into<String>,
        checks: Vec<CheckReceipt>,
    ) -> Self {
        Self {
            schema_version: RUN_RECEIPT_SCHEMA_VERSION.to_owned(),
            bindings,
            execution_plan_sha256: execution_plan_sha256.into(),
            harness_sha256: harness_sha256.into(),
            invocation_sha256: invocation_sha256.into(),
            coverage_sha256: coverage_sha256.into(),
            checks,
        }
    }
}

/// Closed verification outcome derived only by the Rust verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationOutcome {
    /// Every expected check matched; this does not authenticate an execution actor.
    VerifiedPass,
    /// A completely bound check reported timeout or nonzero exit.
    VerifiedFail,
    /// The receipt was malformed, incomplete, unsafe, stale, or mismatched.
    ReceiptRejected,
}

/// Result of verifying one aggregate receipt against a recomputed plan.
#[derive(Clone, Debug, Serialize)]
pub struct VerificationReport {
    bindings: PlanBindings,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_plan_sha256: Option<String>,
    expected_harness_sha256: String,
    expected_invocation_sha256: String,
    findings: Vec<Finding>,
    mutation_count: u64,
    outcome: VerificationOutcome,
    status: Status,
}

impl VerificationReport {
    /// Recomputed plan digest, absent when planning was rejected.
    #[must_use]
    pub fn execution_plan_sha256(&self) -> Option<&str> {
        self.execution_plan_sha256.as_deref()
    }

    /// Stable fail-closed findings.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Number of repository or external mutations; always zero.
    #[must_use]
    pub const fn mutation_count(&self) -> u64 {
        self.mutation_count
    }

    /// Closed verification outcome.
    #[must_use]
    pub const fn outcome(&self) -> VerificationOutcome {
        self.outcome
    }

    /// Overall status; only [`VerificationOutcome::VerifiedPass`] is `PASS`.
    #[must_use]
    pub const fn status(&self) -> Status {
        self.status
    }
}

struct VerificationContext {
    bindings: PlanBindings,
    execution_plan_sha256: Option<String>,
    expected_harness_sha256: String,
    expected_invocation_sha256: String,
}

impl VerificationContext {
    fn new(
        bindings: PlanBindings,
        execution_plan_sha256: Option<String>,
        expected_harness_sha256: String,
        expected_invocation_sha256: String,
    ) -> Self {
        Self {
            bindings,
            execution_plan_sha256,
            expected_harness_sha256,
            expected_invocation_sha256,
        }
    }

    fn finish(self, decision: ReceiptDecision) -> VerificationReport {
        let (outcome, findings) = match decision {
            ReceiptDecision::Pass => (VerificationOutcome::VerifiedPass, Vec::new()),
            ReceiptDecision::Fail(finding) => (VerificationOutcome::VerifiedFail, vec![finding]),
            ReceiptDecision::Reject(finding) => {
                (VerificationOutcome::ReceiptRejected, vec![finding])
            }
        };
        VerificationReport {
            bindings: self.bindings,
            execution_plan_sha256: self.execution_plan_sha256,
            expected_harness_sha256: self.expected_harness_sha256,
            expected_invocation_sha256: self.expected_invocation_sha256,
            findings,
            mutation_count: 0,
            outcome,
            status: if outcome == VerificationOutcome::VerifiedPass {
                Status::Pass
            } else {
                Status::Fail
            },
        }
    }
}

impl CheckRequest {
    /// Construct one pure receipt-verification request from untrusted JSON bytes.
    #[must_use]
    pub fn verify(
        bindings: PlanBindings,
        project: PlanProject,
        expected_harness_sha256: impl Into<String>,
        expected_invocation_sha256: impl Into<String>,
        receipt_json: Vec<u8>,
    ) -> Self {
        Self::Verify {
            bindings,
            project,
            expected_harness_sha256: expected_harness_sha256.into(),
            expected_invocation_sha256: expected_invocation_sha256.into(),
            receipt_json,
        }
    }
}

pub(crate) fn verify_receipt(
    bindings: PlanBindings,
    project: PlanProject,
    expected_harness_sha256: String,
    expected_invocation_sha256: String,
    receipt_json: &[u8],
) -> Result<VerificationReport, GovernorError> {
    let plan_report = planning::build_plan(bindings.clone(), project)?;
    let Some(plan) = plan_report.execution_plan() else {
        let reason = plan_report
            .findings()
            .first()
            .map_or("PLAN_REJECTED", |finding| finding.code.as_str());
        return Ok(VerificationContext::new(
            bindings,
            None,
            expected_harness_sha256,
            expected_invocation_sha256,
        )
        .finish(ReceiptDecision::Reject(Finding::policy(
            "RECEIPT_PLAN_RECOMPUTE_REJECTED",
            "plan",
            format!("recomputed plan was rejected: {reason}"),
        ))));
    };
    let context = VerificationContext::new(
        bindings,
        Some(plan.sha256().to_owned()),
        expected_harness_sha256,
        expected_invocation_sha256,
    );

    if let Some(finding) = invalid_expectation_digest(
        &context.expected_harness_sha256,
        &context.expected_invocation_sha256,
    ) {
        return Ok(context.finish(ReceiptDecision::Reject(finding)));
    }
    if receipt_json.len() > MAX_RUN_RECEIPT_BYTES {
        return Ok(context.finish(ReceiptDecision::Reject(Finding::policy(
            "RECEIPT_SIZE_EXCEEDED",
            "receipt_json",
            "aggregate receipt exceeds the one-mebibyte limit",
        ))));
    }
    let Ok(receipt) = serde_json::from_slice::<RunReceipt>(receipt_json) else {
        return Ok(context.finish(ReceiptDecision::Reject(Finding::policy(
            "RECEIPT_MALFORMED",
            "receipt_json",
            "receipt is not valid JSON in the closed aggregate schema",
        ))));
    };

    let decision = validate_receipt(
        &receipt,
        &context.bindings,
        plan,
        &context.expected_harness_sha256,
        &context.expected_invocation_sha256,
    );
    Ok(context.finish(decision))
}

fn invalid_expectation_digest(harness: &str, invocation: &str) -> Option<Finding> {
    [
        (
            "VERIFY_HARNESS_DIGEST_INVALID",
            "expected_harness_sha256",
            harness,
        ),
        (
            "VERIFY_INVOCATION_DIGEST_INVALID",
            "expected_invocation_sha256",
            invocation,
        ),
    ]
    .into_iter()
    .find(|(_, _, value)| !is_sha256(value))
    .map(|(code, field, _)| {
        Finding::policy(
            code,
            field,
            "expected exactly 64 lowercase hexadecimal characters",
        )
    })
}

enum ReceiptDecision {
    Pass,
    Fail(Finding),
    Reject(Finding),
}

fn validate_receipt(
    receipt: &RunReceipt,
    expected_bindings: &PlanBindings,
    plan: &CanonicalExecutionPlan,
    expected_harness_sha256: &str,
    expected_invocation_sha256: &str,
) -> ReceiptDecision {
    if receipt.schema_version != RUN_RECEIPT_SCHEMA_VERSION {
        return reject(
            "RECEIPT_SCHEMA_UNSUPPORTED",
            "schema_version",
            "receipt schema version is not supported",
        );
    }
    if let Some(finding) = invalid_run_digest(receipt) {
        return ReceiptDecision::Reject(finding);
    }
    if let Some(finding) = binding_mismatch(
        receipt,
        expected_bindings,
        plan,
        expected_harness_sha256,
        expected_invocation_sha256,
    ) {
        return ReceiptDecision::Reject(finding);
    }
    validate_checks(receipt, plan)
}

fn invalid_run_digest(receipt: &RunReceipt) -> Option<Finding> {
    receipt
        .bindings
        .fields()
        .into_iter()
        .map(|(field, value)| (format!("bindings.{field}"), value))
        .chain([
            (
                "execution_plan_sha256".to_owned(),
                receipt.execution_plan_sha256.as_str(),
            ),
            ("harness_sha256".to_owned(), receipt.harness_sha256.as_str()),
            (
                "invocation_sha256".to_owned(),
                receipt.invocation_sha256.as_str(),
            ),
            (
                "coverage_sha256".to_owned(),
                receipt.coverage_sha256.as_str(),
            ),
        ])
        .find(|(_, value)| !is_sha256(value))
        .map(|(field, _)| {
            Finding::policy(
                "RECEIPT_DIGEST_INVALID",
                &field,
                "expected exactly 64 lowercase hexadecimal characters",
            )
        })
}

fn binding_mismatch(
    receipt: &RunReceipt,
    expected: &PlanBindings,
    plan: &CanonicalExecutionPlan,
    expected_harness_sha256: &str,
    expected_invocation_sha256: &str,
) -> Option<Finding> {
    let codes = [
        "RECEIPT_REPOSITORY_MISMATCH",
        "RECEIPT_REVISION_MISMATCH",
        "RECEIPT_POLICY_MISMATCH",
        "RECEIPT_TOOLCHAIN_MISMATCH",
        "RECEIPT_ENVIRONMENT_MISMATCH",
    ];
    for (((field, actual), (_, expected)), code) in receipt
        .bindings
        .fields()
        .into_iter()
        .zip(expected.fields())
        .zip(codes)
    {
        if actual != expected {
            return Some(binding_finding(code, &format!("bindings.{field}")));
        }
    }
    [
        (
            "RECEIPT_PLAN_MISMATCH",
            "execution_plan_sha256",
            receipt.execution_plan_sha256.as_str(),
            plan.sha256(),
        ),
        (
            "RECEIPT_HARNESS_MISMATCH",
            "harness_sha256",
            receipt.harness_sha256.as_str(),
            expected_harness_sha256,
        ),
        (
            "RECEIPT_INVOCATION_STALE",
            "invocation_sha256",
            receipt.invocation_sha256.as_str(),
            expected_invocation_sha256,
        ),
        (
            "RECEIPT_COVERAGE_MISMATCH",
            "coverage_sha256",
            receipt.coverage_sha256.as_str(),
            plan.coverage_sha256(),
        ),
    ]
    .into_iter()
    .find(|(_, _, actual, expected)| actual != expected)
    .map(|(code, field, _, _)| binding_finding(code, field))
}

fn binding_finding(code: &str, field: &str) -> Finding {
    Finding::policy(
        code,
        field,
        "receipt binding does not match the verifier expectation",
    )
}

fn validate_checks(receipt: &RunReceipt, plan: &CanonicalExecutionPlan) -> ReceiptDecision {
    let expected = plan
        .check_identifiers()
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    index_checks(receipt, &expected).map_or_else(ReceiptDecision::Reject, |by_identifier| {
        validate_indexed_checks(&expected, &by_identifier)
    })
}

fn index_checks<'a>(
    receipt: &'a RunReceipt,
    expected: &BTreeSet<&str>,
) -> Result<BTreeMap<&'a str, &'a CheckReceipt>, Finding> {
    let mut by_identifier = BTreeMap::<&str, Vec<&CheckReceipt>>::new();
    for check in &receipt.checks {
        by_identifier
            .entry(&check.identifier)
            .or_default()
            .push(check);
    }

    if let Some((identifier, _)) = by_identifier
        .iter()
        .find(|(_, receipts)| receipts.len() != 1)
    {
        return Err(Finding::policy(
            "RECEIPT_CHECK_DUPLICATE",
            &format!("checks.{identifier}"),
            "check evidence occurs more than once",
        ));
    }
    if let Some(identifier) = by_identifier
        .keys()
        .find(|identifier| !expected.contains(**identifier))
    {
        return Err(Finding::policy(
            "RECEIPT_CHECK_EXTRA",
            &format!("checks.{identifier}"),
            "receipt contains evidence for an unplanned check",
        ));
    }
    if let Some(identifier) = expected
        .iter()
        .find(|identifier| !by_identifier.contains_key(**identifier))
    {
        return Err(Finding::policy(
            "RECEIPT_CHECK_MISSING",
            &format!("checks.{identifier}"),
            "receipt omits evidence for a planned check",
        ));
    }
    Ok(by_identifier
        .into_iter()
        .filter_map(|(identifier, receipts)| {
            receipts
                .into_iter()
                .next()
                .map(|receipt| (identifier, receipt))
        })
        .collect())
}

fn validate_indexed_checks(
    expected: &BTreeSet<&str>,
    by_identifier: &BTreeMap<&str, &CheckReceipt>,
) -> ReceiptDecision {
    for identifier in expected {
        let Some(check) = by_identifier.get(identifier).copied() else {
            return reject(
                "RECEIPT_CHECK_MISSING",
                &format!("checks.{identifier}"),
                "receipt omits evidence for a planned check",
            );
        };
        let field = format!("checks.{identifier}");
        if !safe_evidence_path(&check.evidence_path) {
            return reject(
                "RECEIPT_EVIDENCE_PATH_UNSAFE",
                &field,
                "evidence path must be a portable repository-relative file path",
            );
        }
        if !is_sha256(&check.output_sha256) {
            return reject(
                "RECEIPT_OUTPUT_DIGEST_INVALID",
                &field,
                "output digest must be 64 lowercase hexadecimal characters",
            );
        }
        if check.output_bytes > MAX_CHECK_OUTPUT_BYTES {
            return reject(
                "RECEIPT_OUTPUT_SIZE_EXCEEDED",
                &field,
                "check output exceeds the one-mebibyte limit",
            );
        }
        if !check.timed_out && check.exit_code.is_none() {
            return reject(
                "RECEIPT_CHECK_EXIT_MISSING",
                &field,
                "a completed check must include an exit code",
            );
        }
    }
    for identifier in expected {
        let check = by_identifier[identifier];
        let field = format!("checks.{identifier}");
        if check.timed_out {
            return ReceiptDecision::Fail(Finding::policy(
                "RECEIPT_CHECK_TIMED_OUT",
                &field,
                "a planned check timed out",
            ));
        }
        if check.exit_code != Some(0) {
            return ReceiptDecision::Fail(Finding::policy(
                "RECEIPT_CHECK_EXIT_NONZERO",
                &field,
                "a planned check exited nonzero",
            ));
        }
    }
    ReceiptDecision::Pass
}

fn reject(code: &str, field: &str, message: &str) -> ReceiptDecision {
    ReceiptDecision::Reject(Finding::policy(code, field, message))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_evidence_path(value: &str) -> bool {
    !value.is_empty()
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
}
