use std::path::PathBuf;

use serde::Serialize;

// LLM-CONTRACT
// id: agent-work-governor.rust-report-model
// state: DOMAIN_RESULT -> SERIALIZABLE_REPORT -> STABLE_WIRE_VALUE
// preconditions: validators construct reports through typed variants
// invariant: status and finding reason codes retain their exact wire spelling
// failure: serialization returns a typed serde error without partial output
// source: bundle:knowledge/policies/work-governor.md
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: succeeded
// test: bundle:rust/tests/interface.rs

/// One request accepted by the static Governor Module.
#[derive(Clone, Debug)]
pub enum CheckRequest {
    /// Validate one repository policy.
    Policy {
        /// Policy TOML path.
        path: PathBuf,
    },
    /// Validate LLM Contract comments and references in one source file.
    Contract {
        /// Source file to inspect.
        path: PathBuf,
        /// Repository root used by `repo:` references.
        repo_root: PathBuf,
        /// Governor bundle root used by `bundle:` references.
        bundle_root: PathBuf,
    },
    /// Validate an OKF bundle and the stricter Governor profile.
    Okf {
        /// Knowledge bundle root.
        bundle: PathBuf,
    },
    /// Produce a read-only repository bootstrap plan.
    Bootstrap {
        /// Target repository root.
        repo: PathBuf,
        /// Template source root.
        plugin_root: PathBuf,
        /// Policy preset.
        preset: Preset,
        /// Permit planning against a non-Git directory.
        allow_non_git: bool,
    },
    /// Run the common read-only repository check.
    Repository {
        /// Target repository root.
        repo: PathBuf,
        /// Installed or source plugin root.
        plugin_root: PathBuf,
        /// Repository-external evidence supplied by the protected caller.
        owner_scope: Option<crate::OwnerScopeInput>,
    },
    /// Produce one digest-bound execution plan from confirmed project facts.
    Plan {
        /// Repository and governed-environment bindings.
        bindings: crate::planning::PlanBindings,
        /// Closed caller-confirmed project profile.
        project: crate::planning::PlanProject,
    },
    /// Verify one untrusted aggregate receipt against a recomputed plan.
    Verify {
        /// Repository and governed-environment bindings used to recompute the plan.
        bindings: crate::planning::PlanBindings,
        /// Closed caller-confirmed project profile.
        project: crate::planning::PlanProject,
        /// Trusted expected digest of the bounded harness implementation.
        expected_harness_sha256: String,
        /// Verifier-owned digest identifying the expected run invocation.
        expected_invocation_sha256: String,
        /// Untrusted aggregate receipt JSON bytes.
        receipt_json: Vec<u8>,
        /// Untrusted evidence bytes supplied separately from receipt claims.
        evidence: Vec<crate::verification::EvidenceArtifact>,
    },
}

/// Supported bootstrap policy presets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Preset {
    /// Unknown-scope, read-only default.
    Safe,
    /// Strict rules for repositories owned by the user.
    OwnerOriginal,
}

/// Stable machine-readable status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    /// Every proven condition passed.
    Pass,
    /// At least one deterministic condition failed.
    Fail,
    /// Required evidence was inaccessible or unsupported.
    Inconclusive,
    /// A dry-run plan was produced without mutation.
    DryRun,
    /// A dry-run plan found an existing target conflict.
    Conflict,
    /// A canonical execution plan was produced without granting PASS authority.
    Planned,
}

/// Result of evaluating external owner-scope evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OwnerScopeVerification {
    /// The policy does not declare an owner-original repository.
    NotApplicable,
    /// An owner-original policy has no external receipt input.
    Required,
    /// Every external binding and signature check passed.
    Verified,
    /// Supplied evidence or its policy binding failed closed.
    Rejected,
}

/// A deterministic finding emitted by a check.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Finding {
    /// Stable reason code.
    pub code: String,
    /// Reader-facing explanation.
    pub message: String,
    /// Optional policy field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Optional filesystem path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Error, warning, or informational severity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

impl Finding {
    /// Construct an error finding with a policy field.
    #[must_use]
    pub fn policy(code: &str, field: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
            field: Some(field.to_owned()),
            path: None,
            severity: Some("error".to_owned()),
        }
    }

    /// Construct a path-scoped finding.
    #[must_use]
    pub fn path(code: &str, path: &std::path::Path, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
            field: None,
            path: Some(path.display().to_string()),
            severity: None,
        }
    }
}

/// Output variants returned through the single Governor Interface.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum CheckReport {
    /// Policy validation receipt.
    Policy(crate::policy::PolicyReceipt),
    /// Contract validation report.
    Contract(crate::contract::ContractReport),
    /// OKF core and profile report.
    Okf(crate::okf::OkfReport),
    /// Bootstrap dry-run report.
    Bootstrap(crate::bootstrap::BootstrapReport),
    /// Common repository report.
    Repository(RepositoryReport),
    /// Digest-bound execution plan report.
    Plan(crate::planning::PlanReport),
    /// Aggregate run-receipt verification report.
    Verify(crate::verification::VerificationReport),
}

impl CheckReport {
    /// Whether the report permits a zero process exit status.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        match self {
            Self::Policy(report) => report.valid,
            Self::Contract(report) => report.status == Status::Pass,
            Self::Okf(report) => {
                report.okf_core.status == crate::okf::OkfStatus::Valid
                    && report.governor_profile.status == crate::okf::OkfStatus::Valid
            }
            Self::Bootstrap(report) => report.status == Status::DryRun,
            Self::Repository(report) => report.status == Status::Pass,
            Self::Plan(report) => report.status() == Status::Planned,
            Self::Verify(report) => report.status() == Status::Pass,
        }
    }
}

/// Composite read-only repository result.
#[derive(Clone, Debug, Serialize)]
pub struct RepositoryReport {
    /// Canonical repository root.
    pub repository: String,
    /// Overall fail-closed status.
    pub status: Status,
    /// Deterministic findings.
    pub findings: Vec<Finding>,
    /// Primary reason preventing readiness.
    pub blocker: Option<String>,
    /// Result of external owner-scope receipt verification.
    pub owner_scope_verification: OwnerScopeVerification,
    /// Policy, receipt, and runtime authority intersection; zero unless verified.
    pub effective_authority: crate::EffectiveAuthority,
    /// Number of mutations performed; always zero in this crate.
    pub mutation_count: u64,
}
