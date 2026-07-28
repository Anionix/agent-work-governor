//! Typed public boundary for deterministic execution planning.

use crate::{
    CheckRequest, Finding, GovernorError, Status,
    governance_ir::{
        GovernanceIr,
        execution_plan::{CanonicalExecutionPlan, PlanEmitter},
    },
    python_adapter::{
        PythonLayout, PythonProjectDraft, RepositoryKind as PythonRepositoryKind, adapt_python,
    },
    rust_adapter::{
        FilePresence, RepositoryKind as RustRepositoryKind, RustLayout, RustProjectDraft,
        adapt_rust,
    },
};
use serde::Serialize;

// LLM-CONTRACT
// id: agent-work-governor.plan-interface
// state: PLAN_REQUEST -> EXECUTION_PLAN | FAIL_CLOSED_FINDING | TYPED_INFRASTRUCTURE_FAULT
// preconditions: five SHA-256 bindings and one closed project profile are caller-confirmed
// invariant: planning only joins bundled recipes with typed facts and never grants PASS or mutates
// failure: reject the whole plan with stable findings, or return a typed encoding fault
// source: repo:AGENTS.md
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: build_plan
// test: bundle:rust/tests/interface.rs

/// Digests that bind a plan to its repository and governed environment.
#[allow(
    clippy::struct_field_names,
    reason = "the repeated suffix is the exact public wire contract"
)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlanBindings {
    /// SHA-256 digest of the execution environment.
    pub environment_sha256: String,
    /// SHA-256 digest of the effective policy.
    pub policy_sha256: String,
    /// SHA-256 digest of the repository snapshot.
    pub repository_sha256: String,
    /// SHA-256 digest identifying the exact revision.
    pub revision_sha256: String,
    /// SHA-256 digest of the unified toolchain lock.
    pub toolchain_sha256: String,
}

impl PlanBindings {
    /// Construct explicit plan bindings. Validation occurs through [`crate::Governor::check`].
    pub fn new(
        repository_sha256: impl Into<String>,
        revision_sha256: impl Into<String>,
        policy_sha256: impl Into<String>,
        toolchain_sha256: impl Into<String>,
        environment_sha256: impl Into<String>,
    ) -> Self {
        Self {
            environment_sha256: environment_sha256.into(),
            policy_sha256: policy_sha256.into(),
            repository_sha256: repository_sha256.into(),
            revision_sha256: revision_sha256.into(),
            toolchain_sha256: toolchain_sha256.into(),
        }
    }

    fn fields(&self) -> [(&'static str, &str); 5] {
        [
            ("repository_sha256", &self.repository_sha256),
            ("revision_sha256", &self.revision_sha256),
            ("policy_sha256", &self.policy_sha256),
            ("toolchain_sha256", &self.toolchain_sha256),
            ("environment_sha256", &self.environment_sha256),
        ]
    }
}

/// One caller-confirmed, supported repository profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanProject {
    /// Confirm a Python-only uv/unittest repository.
    PythonUvUnittest {
        /// Repository-relative project working directory.
        working_directory: String,
    },
    /// Confirm a Rust-only Cargo workspace with manifest, lock, and deny config.
    RustCargoWorkspace {
        /// Repository-relative project working directory.
        working_directory: String,
    },
    /// Confirm a mixed uv/unittest and Cargo workspace repository.
    MixedUvCargo {
        /// Repository-relative Python working directory.
        python_working_directory: String,
        /// Repository-relative Rust working directory.
        rust_working_directory: String,
    },
}

impl CheckRequest {
    /// Construct one deterministic planning request.
    #[must_use]
    pub fn plan(bindings: PlanBindings, project: PlanProject) -> Self {
        Self::Plan { bindings, project }
    }
}

/// Result of producing or rejecting one digest-bound plan.
#[derive(Clone, Debug, Serialize)]
pub struct PlanReport {
    /// Digests bound to this report.
    bindings: PlanBindings,
    /// Canonical plan, present only when status is `PLANNED`.
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_plan: Option<CanonicalExecutionPlan>,
    /// Canonical plan digest, present only when status is `PLANNED`.
    #[serde(skip_serializing_if = "Option::is_none")]
    execution_plan_sha256: Option<String>,
    /// Stable findings, non-empty only when planning is rejected.
    findings: Vec<Finding>,
    /// Number of repository or external mutations; always zero.
    mutation_count: u64,
    /// Overall planning status.
    status: Status,
}

impl PlanReport {
    /// Digests bound to this report.
    #[must_use]
    pub const fn bindings(&self) -> &PlanBindings {
        &self.bindings
    }

    /// Overall planning status.
    #[must_use]
    pub const fn status(&self) -> Status {
        self.status
    }

    /// Canonical plan, present only when status is `PLANNED`.
    #[must_use]
    pub fn execution_plan(&self) -> Option<&CanonicalExecutionPlan> {
        self.execution_plan.as_ref()
    }

    /// Canonical plan digest, present only when status is `PLANNED`.
    #[must_use]
    pub fn execution_plan_sha256(&self) -> Option<&str> {
        self.execution_plan_sha256.as_deref()
    }

    /// Stable findings, non-empty only when planning is rejected.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Number of repository or external mutations; always zero.
    #[must_use]
    pub const fn mutation_count(&self) -> u64 {
        self.mutation_count
    }

    fn planned(bindings: PlanBindings, plan: CanonicalExecutionPlan) -> Self {
        let execution_plan_sha256 = Some(plan.sha256().to_owned());
        Self {
            bindings,
            execution_plan: Some(plan),
            execution_plan_sha256,
            findings: Vec::new(),
            mutation_count: 0,
            status: Status::Planned,
        }
    }

    fn rejected(bindings: PlanBindings, finding: Finding) -> Self {
        Self {
            bindings,
            execution_plan: None,
            execution_plan_sha256: None,
            findings: vec![finding],
            mutation_count: 0,
            status: Status::Fail,
        }
    }
}

pub(crate) fn build_plan(
    bindings: PlanBindings,
    project: PlanProject,
) -> Result<PlanReport, GovernorError> {
    let invalid_field = bindings
        .fields()
        .into_iter()
        .find(|(_, value)| !is_sha256(value))
        .map(|(field, _)| field);
    if let Some(field) = invalid_field {
        return Ok(PlanReport::rejected(
            bindings,
            Finding::policy(
                "PLAN_INPUT_DIGEST_INVALID",
                field,
                "expected exactly 64 lowercase hexadecimal characters",
            ),
        ));
    }

    let (ir, toolchain_digests) = match adapt_project(project) {
        Ok(value) => value,
        Err(finding) => return Ok(PlanReport::rejected(bindings, finding)),
    };
    if toolchain_digests
        .iter()
        .any(|digest| digest != &bindings.toolchain_sha256)
    {
        return Ok(PlanReport::rejected(
            bindings,
            Finding::policy(
                "PLAN_TOOLCHAIN_DIGEST_MISMATCH",
                "toolchain_sha256",
                "input digest does not match the bundled adapter toolchain",
            ),
        ));
    }

    match PlanEmitter::emit(&ir) {
        Ok(plan) => Ok(PlanReport::planned(bindings, plan)),
        Err(error) if error.is_encoding_failed() => {
            Err(GovernorError::PlanEncoding { code: error.code() })
        }
        Err(error) => Ok(PlanReport::rejected(
            bindings,
            Finding::policy(error.code(), "project", "execution plan was rejected"),
        )),
    }
}

fn adapt_project(project: PlanProject) -> Result<(GovernanceIr, Vec<String>), Finding> {
    match project {
        PlanProject::PythonUvUnittest { working_directory } => {
            let (ir, digest) = python_ir(PythonRepositoryKind::PythonOnly, working_directory)?;
            Ok((ir, vec![digest]))
        }
        PlanProject::RustCargoWorkspace { working_directory } => {
            let (ir, digest) = rust_ir(RustRepositoryKind::RustOnly, working_directory)?;
            Ok((ir, vec![digest]))
        }
        PlanProject::MixedUvCargo {
            python_working_directory,
            rust_working_directory,
        } => {
            let (python_ir, python_digest) =
                python_ir(PythonRepositoryKind::Mixed, python_working_directory)?;
            let (rust_ir, rust_digest) =
                rust_ir(RustRepositoryKind::Mixed, rust_working_directory)?;
            let ir = GovernanceIr::merge(vec![python_ir, rust_ir]).map_err(|error| {
                Finding::policy(
                    error.code(),
                    "project",
                    "combined governance IR was rejected",
                )
            })?;
            Ok((ir, vec![python_digest, rust_digest]))
        }
    }
}

fn python_ir(
    repository_kind: PythonRepositoryKind,
    working_directory: String,
) -> Result<(GovernanceIr, String), Finding> {
    adapt_python(PythonProjectDraft {
        repository_kind: Some(repository_kind),
        layout: Some(PythonLayout::UvUnittest),
        working_directory: Some(working_directory),
    })
    .map(crate::python_adapter::PythonCheckSet::into_plan_inputs)
    .map_err(|error| Finding::policy(error.code(), "project", "Python project was rejected"))
}

fn rust_ir(
    repository_kind: RustRepositoryKind,
    working_directory: String,
) -> Result<(GovernanceIr, String), Finding> {
    adapt_rust(RustProjectDraft {
        repository_kind: Some(repository_kind),
        layout: Some(RustLayout::CargoWorkspace),
        manifest: Some(FilePresence::Present),
        lockfile: Some(FilePresence::Present),
        deny_config: Some(FilePresence::Present),
        working_directory: Some(working_directory),
    })
    .map(crate::rust_adapter::RustCheckSet::into_plan_inputs)
    .map_err(|error| Finding::policy(error.code(), "project", "Rust project was rejected"))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
