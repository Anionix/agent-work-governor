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
const EVIDENCE_PATH_PREFIX: &str = ".governance/receipts/evidence/";

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

/// Mutually exclusive process outcome reported for one bounded check.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckOutcome {
    /// The check process exited with an operating-system status code.
    Exited {
        /// Exact process exit code.
        exit_code: i32,
    },
    /// The bounded harness terminated the check after its deadline.
    TimedOut,
}

/// Evidence claim emitted for one check in a bounded run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckReceipt {
    identifier: String,
    evidence_path: String,
    output_sha256: String,
    output_bytes: u64,
    outcome: CheckOutcome,
}

impl CheckReceipt {
    /// Construct evidence without assigning any policy verdict.
    #[must_use]
    pub fn new(
        identifier: impl Into<String>,
        evidence_path: impl Into<String>,
        output_sha256: impl Into<String>,
        output_bytes: u64,
        outcome: CheckOutcome,
    ) -> Self {
        Self {
            identifier: identifier.into(),
            evidence_path: evidence_path.into(),
            output_sha256: output_sha256.into(),
            output_bytes,
            outcome,
        }
    }
}

/// Untrusted evidence bytes supplied independently of receipt digest claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceArtifact {
    path: String,
    bytes: Vec<u8>,
}

impl EvidenceArtifact {
    /// Construct one candidate artifact; verification validates its path and bytes.
    #[must_use]
    pub fn new(path: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            path: path.into(),
            bytes,
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

/// Closed stable reason codes for every non-PASS verification result.
#[allow(
    missing_docs,
    reason = "variant names are the exact stable machine-readable reason-code contract"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationReason {
    VerifyHarnessDigestInvalid,
    VerifyInvocationDigestInvalid,
    ReceiptPlanRecomputeRejected,
    ReceiptSizeExceeded,
    ReceiptMalformed,
    ReceiptSchemaUnsupported,
    ReceiptDigestInvalid,
    ReceiptRepositoryMismatch,
    ReceiptRevisionMismatch,
    ReceiptPolicyMismatch,
    ReceiptToolchainMismatch,
    ReceiptEnvironmentMismatch,
    ReceiptPlanMismatch,
    ReceiptHarnessMismatch,
    ReceiptInvocationStale,
    ReceiptCoverageMismatch,
    ReceiptCheckDuplicate,
    ReceiptCheckExtra,
    ReceiptCheckMissing,
    ReceiptEvidencePathUnsafe,
    ReceiptEvidenceDuplicate,
    ReceiptEvidenceExtra,
    ReceiptEvidenceMissing,
    ReceiptOutputDigestInvalid,
    ReceiptOutputSizeExceeded,
    ReceiptOutputSizeMismatch,
    ReceiptOutputDigestMismatch,
    ReceiptCheckTimedOut,
    ReceiptCheckExitNonzero,
}

impl VerificationReason {
    /// Exact machine-readable wire spelling used by [`Finding::code`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VerifyHarnessDigestInvalid => "VERIFY_HARNESS_DIGEST_INVALID",
            Self::VerifyInvocationDigestInvalid => "VERIFY_INVOCATION_DIGEST_INVALID",
            Self::ReceiptPlanRecomputeRejected => "RECEIPT_PLAN_RECOMPUTE_REJECTED",
            Self::ReceiptSizeExceeded => "RECEIPT_SIZE_EXCEEDED",
            Self::ReceiptMalformed => "RECEIPT_MALFORMED",
            Self::ReceiptSchemaUnsupported => "RECEIPT_SCHEMA_UNSUPPORTED",
            Self::ReceiptDigestInvalid => "RECEIPT_DIGEST_INVALID",
            Self::ReceiptRepositoryMismatch => "RECEIPT_REPOSITORY_MISMATCH",
            Self::ReceiptRevisionMismatch => "RECEIPT_REVISION_MISMATCH",
            Self::ReceiptPolicyMismatch => "RECEIPT_POLICY_MISMATCH",
            Self::ReceiptToolchainMismatch => "RECEIPT_TOOLCHAIN_MISMATCH",
            Self::ReceiptEnvironmentMismatch => "RECEIPT_ENVIRONMENT_MISMATCH",
            Self::ReceiptPlanMismatch => "RECEIPT_PLAN_MISMATCH",
            Self::ReceiptHarnessMismatch => "RECEIPT_HARNESS_MISMATCH",
            Self::ReceiptInvocationStale => "RECEIPT_INVOCATION_STALE",
            Self::ReceiptCoverageMismatch => "RECEIPT_COVERAGE_MISMATCH",
            Self::ReceiptCheckDuplicate => "RECEIPT_CHECK_DUPLICATE",
            Self::ReceiptCheckExtra => "RECEIPT_CHECK_EXTRA",
            Self::ReceiptCheckMissing => "RECEIPT_CHECK_MISSING",
            Self::ReceiptEvidencePathUnsafe => "RECEIPT_EVIDENCE_PATH_UNSAFE",
            Self::ReceiptEvidenceDuplicate => "RECEIPT_EVIDENCE_DUPLICATE",
            Self::ReceiptEvidenceExtra => "RECEIPT_EVIDENCE_EXTRA",
            Self::ReceiptEvidenceMissing => "RECEIPT_EVIDENCE_MISSING",
            Self::ReceiptOutputDigestInvalid => "RECEIPT_OUTPUT_DIGEST_INVALID",
            Self::ReceiptOutputSizeExceeded => "RECEIPT_OUTPUT_SIZE_EXCEEDED",
            Self::ReceiptOutputSizeMismatch => "RECEIPT_OUTPUT_SIZE_MISMATCH",
            Self::ReceiptOutputDigestMismatch => "RECEIPT_OUTPUT_DIGEST_MISMATCH",
            Self::ReceiptCheckTimedOut => "RECEIPT_CHECK_TIMED_OUT",
            Self::ReceiptCheckExitNonzero => "RECEIPT_CHECK_EXIT_NONZERO",
        }
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<VerificationReason>,
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

    /// Closed reason code for a rejected or failed receipt.
    #[must_use]
    pub const fn reason(&self) -> Option<VerificationReason> {
        self.reason
    }

    /// Overall status; only [`VerificationOutcome::VerifiedPass`] is `PASS`.
    #[must_use]
    pub const fn status(&self) -> Status {
        self.status
    }
}

struct DecisionFinding {
    field: String,
    message: String,
    reason: VerificationReason,
}

impl DecisionFinding {
    fn new(
        reason: VerificationReason,
        field: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
            reason,
        }
    }

    fn into_finding(self) -> Finding {
        Finding::policy(self.reason.as_str(), &self.field, self.message)
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
        let (outcome, reason, findings) = match decision {
            ReceiptDecision::Pass => (VerificationOutcome::VerifiedPass, None, Vec::new()),
            ReceiptDecision::Fail(finding) => (
                VerificationOutcome::VerifiedFail,
                Some(finding.reason),
                vec![finding.into_finding()],
            ),
            ReceiptDecision::Reject(finding) => (
                VerificationOutcome::ReceiptRejected,
                Some(finding.reason),
                vec![finding.into_finding()],
            ),
        };
        VerificationReport {
            bindings: self.bindings,
            execution_plan_sha256: self.execution_plan_sha256,
            expected_harness_sha256: self.expected_harness_sha256,
            expected_invocation_sha256: self.expected_invocation_sha256,
            findings,
            mutation_count: 0,
            outcome,
            reason,
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
        evidence: Vec<EvidenceArtifact>,
    ) -> Self {
        Self::Verify {
            bindings,
            project,
            expected_harness_sha256: expected_harness_sha256.into(),
            expected_invocation_sha256: expected_invocation_sha256.into(),
            receipt_json,
            evidence,
        }
    }
}

pub(crate) fn verify_receipt(
    bindings: PlanBindings,
    project: PlanProject,
    expected_harness_sha256: String,
    expected_invocation_sha256: String,
    receipt_json: &[u8],
    evidence: &[EvidenceArtifact],
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
        .finish(reject(
            VerificationReason::ReceiptPlanRecomputeRejected,
            "plan",
            format!("recomputed plan was rejected: {reason}"),
        )));
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
        return Ok(context.finish(reject(
            VerificationReason::ReceiptSizeExceeded,
            "receipt_json",
            "aggregate receipt exceeds the one-mebibyte limit",
        )));
    }
    let Ok(receipt) = serde_json::from_slice::<RunReceipt>(receipt_json) else {
        return Ok(context.finish(reject(
            VerificationReason::ReceiptMalformed,
            "receipt_json",
            "receipt is not valid JSON in the closed aggregate schema",
        )));
    };

    let decision = validate_receipt(
        &receipt,
        &context.bindings,
        plan,
        &context.expected_harness_sha256,
        &context.expected_invocation_sha256,
        evidence,
    );
    Ok(context.finish(decision))
}

fn invalid_expectation_digest(harness: &str, invocation: &str) -> Option<DecisionFinding> {
    [
        (
            VerificationReason::VerifyHarnessDigestInvalid,
            "expected_harness_sha256",
            harness,
        ),
        (
            VerificationReason::VerifyInvocationDigestInvalid,
            "expected_invocation_sha256",
            invocation,
        ),
    ]
    .into_iter()
    .find(|(_, _, value)| !is_sha256(value))
    .map(|(reason, field, _)| {
        DecisionFinding::new(
            reason,
            field,
            "expected exactly 64 lowercase hexadecimal characters",
        )
    })
}

enum ReceiptDecision {
    Pass,
    Fail(DecisionFinding),
    Reject(DecisionFinding),
}

fn validate_receipt(
    receipt: &RunReceipt,
    expected_bindings: &PlanBindings,
    plan: &CanonicalExecutionPlan,
    expected_harness_sha256: &str,
    expected_invocation_sha256: &str,
    evidence: &[EvidenceArtifact],
) -> ReceiptDecision {
    if receipt.schema_version != RUN_RECEIPT_SCHEMA_VERSION {
        return reject(
            VerificationReason::ReceiptSchemaUnsupported,
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
    validate_checks(receipt, plan, evidence)
}

fn invalid_run_digest(receipt: &RunReceipt) -> Option<DecisionFinding> {
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
            DecisionFinding::new(
                VerificationReason::ReceiptDigestInvalid,
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
) -> Option<DecisionFinding> {
    let codes = [
        VerificationReason::ReceiptRepositoryMismatch,
        VerificationReason::ReceiptRevisionMismatch,
        VerificationReason::ReceiptPolicyMismatch,
        VerificationReason::ReceiptToolchainMismatch,
        VerificationReason::ReceiptEnvironmentMismatch,
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
            VerificationReason::ReceiptPlanMismatch,
            "execution_plan_sha256",
            receipt.execution_plan_sha256.as_str(),
            plan.sha256(),
        ),
        (
            VerificationReason::ReceiptHarnessMismatch,
            "harness_sha256",
            receipt.harness_sha256.as_str(),
            expected_harness_sha256,
        ),
        (
            VerificationReason::ReceiptInvocationStale,
            "invocation_sha256",
            receipt.invocation_sha256.as_str(),
            expected_invocation_sha256,
        ),
        (
            VerificationReason::ReceiptCoverageMismatch,
            "coverage_sha256",
            receipt.coverage_sha256.as_str(),
            plan.coverage_sha256(),
        ),
    ]
    .into_iter()
    .find(|(_, _, actual, expected)| actual != expected)
    .map(|(code, field, _, _)| binding_finding(code, field))
}

fn binding_finding(reason: VerificationReason, field: &str) -> DecisionFinding {
    DecisionFinding::new(
        reason,
        field,
        "receipt binding does not match the verifier expectation",
    )
}

fn validate_checks(
    receipt: &RunReceipt,
    plan: &CanonicalExecutionPlan,
    evidence: &[EvidenceArtifact],
) -> ReceiptDecision {
    let expected = plan
        .check_identifiers()
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    index_checks(receipt, &expected).map_or_else(ReceiptDecision::Reject, |by_identifier| {
        validate_indexed_checks(&expected, &by_identifier, evidence)
    })
}

fn index_checks<'a>(
    receipt: &'a RunReceipt,
    expected: &BTreeSet<&str>,
) -> Result<BTreeMap<&'a str, &'a CheckReceipt>, DecisionFinding> {
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
        return Err(DecisionFinding::new(
            VerificationReason::ReceiptCheckDuplicate,
            format!("checks.{identifier}"),
            "check evidence occurs more than once",
        ));
    }
    if let Some(identifier) = by_identifier
        .keys()
        .find(|identifier| !expected.contains(**identifier))
    {
        return Err(DecisionFinding::new(
            VerificationReason::ReceiptCheckExtra,
            format!("checks.{identifier}"),
            "receipt contains evidence for an unplanned check",
        ));
    }
    if let Some(identifier) = expected
        .iter()
        .find(|identifier| !by_identifier.contains_key(**identifier))
    {
        return Err(DecisionFinding::new(
            VerificationReason::ReceiptCheckMissing,
            format!("checks.{identifier}"),
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
    evidence: &[EvidenceArtifact],
) -> ReceiptDecision {
    for identifier in expected {
        let Some(check) = by_identifier.get(identifier).copied() else {
            return reject(
                VerificationReason::ReceiptCheckMissing,
                format!("checks.{identifier}"),
                "receipt omits evidence for a planned check",
            );
        };
        let field = format!("checks.{identifier}");
        if !safe_evidence_path(&check.evidence_path) {
            return reject(
                VerificationReason::ReceiptEvidencePathUnsafe,
                &field,
                "evidence path must stay in the portable governance evidence namespace",
            );
        }
        if !is_sha256(&check.output_sha256) {
            return reject(
                VerificationReason::ReceiptOutputDigestInvalid,
                &field,
                "output digest must be 64 lowercase hexadecimal characters",
            );
        }
        if check.output_bytes > MAX_CHECK_OUTPUT_BYTES {
            return reject(
                VerificationReason::ReceiptOutputSizeExceeded,
                &field,
                "check output exceeds the one-mebibyte limit",
            );
        }
    }
    if let Err(finding) = validate_evidence(by_identifier, evidence) {
        return ReceiptDecision::Reject(finding);
    }
    for identifier in expected {
        let check = by_identifier[identifier];
        let field = format!("checks.{identifier}");
        match check.outcome {
            CheckOutcome::TimedOut => {
                return fail(
                    VerificationReason::ReceiptCheckTimedOut,
                    field,
                    "a planned check timed out",
                );
            }
            CheckOutcome::Exited { exit_code: 0 } => {}
            CheckOutcome::Exited { .. } => {
                return fail(
                    VerificationReason::ReceiptCheckExitNonzero,
                    field,
                    "a planned check exited nonzero",
                );
            }
        }
    }
    ReceiptDecision::Pass
}

fn validate_evidence(
    by_identifier: &BTreeMap<&str, &CheckReceipt>,
    evidence: &[EvidenceArtifact],
) -> Result<(), DecisionFinding> {
    let mut receipt_by_path = BTreeMap::new();
    for check in by_identifier.values() {
        if receipt_by_path
            .insert(check.evidence_path.as_str(), *check)
            .is_some()
        {
            return Err(DecisionFinding::new(
                VerificationReason::ReceiptEvidenceDuplicate,
                &check.evidence_path,
                "multiple check receipts claim the same evidence path",
            ));
        }
    }
    let evidence_by_path = index_evidence(evidence)?;
    if let Some(path) = evidence_by_path
        .keys()
        .find(|path| !receipt_by_path.contains_key(**path))
    {
        return Err(DecisionFinding::new(
            VerificationReason::ReceiptEvidenceExtra,
            *path,
            "verifier input contains evidence not claimed by a check receipt",
        ));
    }
    if let Some(path) = receipt_by_path
        .keys()
        .find(|path| !evidence_by_path.contains_key(**path))
    {
        return Err(DecisionFinding::new(
            VerificationReason::ReceiptEvidenceMissing,
            *path,
            "receipt claims evidence bytes that were not supplied to the verifier",
        ));
    }
    for (path, check) in receipt_by_path {
        let artifact = evidence_by_path[path];
        let actual_bytes = u64::try_from(artifact.bytes.len()).unwrap_or(u64::MAX);
        if actual_bytes > MAX_CHECK_OUTPUT_BYTES {
            return Err(DecisionFinding::new(
                VerificationReason::ReceiptOutputSizeExceeded,
                path,
                "supplied check evidence exceeds the one-mebibyte limit",
            ));
        }
        if actual_bytes != check.output_bytes {
            return Err(DecisionFinding::new(
                VerificationReason::ReceiptOutputSizeMismatch,
                path,
                "supplied evidence byte count does not match the receipt claim",
            ));
        }
        if crate::adapter_catalog::sha256_hex(&artifact.bytes) != check.output_sha256 {
            return Err(DecisionFinding::new(
                VerificationReason::ReceiptOutputDigestMismatch,
                path,
                "supplied evidence digest does not match the receipt claim",
            ));
        }
    }
    Ok(())
}

fn index_evidence(
    evidence: &[EvidenceArtifact],
) -> Result<BTreeMap<&str, &EvidenceArtifact>, DecisionFinding> {
    let mut by_path = BTreeMap::new();
    for artifact in evidence {
        if !safe_evidence_path(&artifact.path) {
            return Err(DecisionFinding::new(
                VerificationReason::ReceiptEvidencePathUnsafe,
                &artifact.path,
                "evidence path must stay in the portable governance evidence namespace",
            ));
        }
        if by_path.insert(artifact.path.as_str(), artifact).is_some() {
            return Err(DecisionFinding::new(
                VerificationReason::ReceiptEvidenceDuplicate,
                &artifact.path,
                "evidence bytes occur more than once for the same path",
            ));
        }
    }
    Ok(by_path)
}

fn reject(
    reason: VerificationReason,
    field: impl Into<String>,
    message: impl Into<String>,
) -> ReceiptDecision {
    ReceiptDecision::Reject(DecisionFinding::new(reason, field, message))
}

fn fail(
    reason: VerificationReason,
    field: impl Into<String>,
    message: impl Into<String>,
) -> ReceiptDecision {
    ReceiptDecision::Fail(DecisionFinding::new(reason, field, message))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_evidence_path(value: &str) -> bool {
    value
        .strip_prefix(EVIDENCE_PATH_PREFIX)
        .is_some_and(|relative| {
            !relative.is_empty()
                && relative.split('/').all(|part| {
                    !part.is_empty()
                        && part != "."
                        && part != ".."
                        && !part.ends_with('.')
                        && part.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                        })
                        && !windows_reserved_name(part)
                })
        })
}

fn windows_reserved_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}
