//! Fail-closed Rust implementation of the Agent Work Governor static checks.

mod adapter_catalog;
mod bootstrap;
mod contract;
mod governance_ir;
mod model;
mod okf;
mod owner_scope;
mod planning;
mod policy;
mod python_adapter;
mod reference;
mod rust_adapter;
mod verification;

use std::path::{Path, PathBuf};

pub use bootstrap::PlanAction;
pub use governance_ir::execution_plan::CanonicalExecutionPlan;
pub use model::{
    CheckReport, CheckRequest, Finding, OwnerScopeVerification, Preset, RepositoryReport, Status,
};
pub use okf::OkfStatus;
pub use owner_scope::{
    EffectiveAuthority, OwnerScopeFailure, OwnerScopeInput, OwnerScopeReport,
    RepositoryPolicySnapshot, evaluate_owner_scope,
};
pub use planning::{PlanBindings, PlanProject, PlanReport};
use thiserror::Error;
pub use verification::{
    CheckOutcome, CheckReceipt, EvidenceArtifact, MAX_CHECK_OUTPUT_BYTES, MAX_RUN_RECEIPT_BYTES,
    RunReceipt, VerificationOutcome, VerificationReason, VerificationReport,
};

/// Static Governor Module with one public checking Interface.
#[derive(Clone, Debug, Default)]
pub struct Governor;

/// Infrastructure faults distinct from ordinary fail-closed findings.
#[derive(Debug, Error)]
pub enum GovernorError {
    /// A file could not be read.
    #[error("failed to read {path}: {source}")]
    Read {
        /// Affected path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// A report could not be encoded.
    #[error("failed to encode report: {0}")]
    Encode(#[from] serde_json::Error),
    /// The canonical plan encoder violated its internal contract.
    #[error("failed to encode execution plan: {code}")]
    PlanEncoding {
        /// Stable internal reason code.
        code: &'static str,
    },
}

impl Governor {
    /// Evaluate one request without performing repository or external mutations.
    ///
    /// # Errors
    ///
    /// Returns [`GovernorError`] when a required input cannot be read or a
    /// report cannot be encoded. Policy and evidence failures are represented
    /// inside a successful, fail-closed [`CheckReport`].
    pub fn check(&self, request: CheckRequest) -> Result<CheckReport, GovernorError> {
        match request {
            CheckRequest::Policy { path } => {
                Ok(CheckReport::Policy(policy::validate_policy(&path)?))
            }
            CheckRequest::Contract {
                path,
                repo_root,
                bundle_root,
            } => Ok(CheckReport::Contract(contract::validate_file(
                &path,
                &repo_root,
                &bundle_root,
            )?)),
            CheckRequest::Okf { bundle } => Ok(CheckReport::Okf(okf::validate_bundle(&bundle)?)),
            CheckRequest::Bootstrap {
                repo,
                plugin_root,
                preset,
                allow_non_git,
            } => Ok(CheckReport::Bootstrap(bootstrap::build_plan(
                &repo,
                &plugin_root,
                preset,
                allow_non_git,
            )?)),
            CheckRequest::Repository {
                repo,
                plugin_root,
                owner_scope,
            } => {
                let snapshot =
                    RepositoryPolicySnapshot::load(&repo).map_err(|error| GovernorError::Read {
                        path: repo,
                        source: std::io::Error::other(error.to_string()),
                    })?;
                Ok(CheckReport::Repository(self.check_repository(
                    &snapshot,
                    &plugin_root,
                    owner_scope.as_ref(),
                )?))
            }
            CheckRequest::Plan { bindings, project } => {
                Ok(CheckReport::Plan(planning::build_plan(bindings, project)?))
            }
            CheckRequest::Verify {
                bindings,
                project,
                expected_harness_sha256,
                expected_invocation_sha256,
                receipt_json,
                evidence,
            } => Ok(CheckReport::Verify(verification::verify_receipt(
                bindings,
                project,
                expected_harness_sha256,
                expected_invocation_sha256,
                &receipt_json,
                &evidence,
            )?)),
        }
    }

    /// Check one repository through an already captured policy/identity snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`GovernorError`] when a non-authority input cannot be read.
    pub fn check_repository(
        &self,
        snapshot: &RepositoryPolicySnapshot,
        plugin_root: &Path,
        owner_scope: Option<&OwnerScopeInput>,
    ) -> Result<RepositoryReport, GovernorError> {
        check_repository(snapshot, plugin_root, owner_scope)
    }
}

fn check_repository(
    snapshot: &RepositoryPolicySnapshot,
    plugin_root: &Path,
    owner_scope_input: Option<&OwnerScopeInput>,
) -> Result<RepositoryReport, GovernorError> {
    let canonical_repo = snapshot.repository().to_path_buf();
    let policy_path = canonical_repo.join(".agent-work-governor/policy.toml");
    let policy = policy::evaluate_policy_snapshot(&policy_path, snapshot.policy_bytes());
    let okf = okf::validate_bundle(&plugin_root.join("knowledge"))?;
    let mut findings = policy.findings;

    if okf.okf_core.status != OkfStatus::Valid {
        findings.extend(okf.okf_core.errors);
        findings.extend(okf.okf_core.inconclusive);
    }
    if okf.governor_profile.status != OkfStatus::Valid {
        findings.extend(okf.governor_profile.errors);
    }

    let owner_scope = policy.repository_scope.as_deref() == Some("owner_original");
    let unresolved_scope = policy.repository_scope.as_deref() == Some("unknown");
    let misplaced_owner_scope = !owner_scope && owner_scope_input.is_some();
    let mut owner_scope_verification = OwnerScopeVerification::NotApplicable;
    let mut effective_authority = EffectiveAuthority::default();
    if owner_scope {
        match owner_scope_input {
            None => {
                owner_scope_verification = OwnerScopeVerification::Required;
                findings.push(Finding::path(
                    "OWNER_SCOPE_RECEIPT_REQUIRED",
                    &canonical_repo,
                    "owner-original authority requires repository-external receipt evidence",
                ));
            }
            Some(input) => match snapshot.verify(input) {
                Ok(verified) => {
                    owner_scope_verification = OwnerScopeVerification::Verified;
                    effective_authority = verified;
                }
                Err(error) => {
                    owner_scope_verification = OwnerScopeVerification::Rejected;
                    findings.push(Finding::path(error.code, &canonical_repo, error.message));
                }
            },
        }
    } else if owner_scope_input.is_some() {
        owner_scope_verification = OwnerScopeVerification::Rejected;
        findings.push(Finding::path(
            "OWNER_SCOPE_NOT_APPLICABLE",
            &canonical_repo,
            "external owner-scope evidence requires an owner-original policy",
        ));
    }
    let blocker = if !policy.valid {
        Some("POLICY_INVALID".to_owned())
    } else if okf.okf_core.status != OkfStatus::Valid
        || okf.governor_profile.status != OkfStatus::Valid
    {
        Some("KNOWLEDGE_BUNDLE_INVALID".to_owned())
    } else if unresolved_scope {
        findings.push(Finding::path(
            "SCOPE_UNRESOLVED",
            &canonical_repo,
            "declare repository_scope before enabling CI",
        ));
        Some("SCOPE_UNRESOLVED".to_owned())
    } else if misplaced_owner_scope {
        Some("OWNER_SCOPE_NOT_APPLICABLE".to_owned())
    } else if owner_scope {
        findings.push(Finding::path(
            "LLM_CONTRACT_AST_ATTESTATION_REQUIRED",
            &canonical_repo,
            "the static Rust checker cannot issue trusted AST-to-symbol attestations",
        ));
        findings.push(Finding::path(
            "CODE_REVIEW_ATTESTATION_UNTRUSTED",
            &canonical_repo,
            "repository-local review evidence cannot establish reviewer identity",
        ));
        Some("LLM_CONTRACT_AST_ATTESTATION_REQUIRED".to_owned())
    } else {
        None
    };

    let status = if blocker.is_none() {
        Status::Pass
    } else {
        Status::Fail
    };
    Ok(RepositoryReport {
        repository: canonical_repo.display().to_string(),
        status,
        findings,
        blocker,
        owner_scope_verification,
        effective_authority,
        mutation_count: 0,
    })
}

// LLM-CONTRACT
// id: agent-work-governor.rust-static-interface
// state: REQUEST -> PURE_CHECKS -> REPORT | PLANNED | VERIFIED | INFRASTRUCTURE_FAULT
// preconditions: paths and caller-supplied evidence/runtime grants are explicit protected inputs
// invariant: inputs grant zero authority; verification derives policy AND receipt AND runtime
// failure: missing, partial, unsafe, stale, malformed, invalid, or mismatched evidence fails closed
// source: bundle:knowledge/policies/work-governor.md
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: check
// test: bundle:rust/tests/interface.rs
