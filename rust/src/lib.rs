//! Fail-closed Rust implementation of the Agent Work Governor static checks.

mod bootstrap;
mod contract;
mod governance_ir;
mod model;
mod okf;
mod policy;
mod reference;

use std::path::{Path, PathBuf};

pub use bootstrap::PlanAction;
pub use model::{CheckReport, CheckRequest, Finding, Preset, RepositoryReport, Status};
pub use okf::OkfStatus;
use thiserror::Error;

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
            CheckRequest::Repository { repo, plugin_root } => Ok(CheckReport::Repository(
                check_repository(&repo, &plugin_root)?,
            )),
        }
    }
}

fn check_repository(repo: &Path, plugin_root: &Path) -> Result<RepositoryReport, GovernorError> {
    let canonical_repo = repo.canonicalize().map_err(|source| GovernorError::Read {
        path: repo.to_path_buf(),
        source,
    })?;
    let policy_path = canonical_repo.join(".agent-work-governor/policy.toml");
    let policy = policy::validate_policy(&policy_path)?;
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
        mutation_count: 0,
    })
}

// LLM-CONTRACT
// id: agent-work-governor.rust-static-interface
// state: REQUEST -> PURE_CHECKS -> REPORT | INFRASTRUCTURE_FAULT
// preconditions: paths are explicit and external attestations are not caller supplied
// invariant: check never mutates a repository and unknown trust cannot become PASS
// failure: return typed infrastructure faults or fail-closed findings
// source: bundle:knowledge/policies/work-governor.md
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: check
// test: bundle:rust/tests/interface.rs
