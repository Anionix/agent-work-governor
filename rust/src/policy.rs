use std::collections::{BTreeSet, HashSet, VecDeque};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};
use toml::Value;

use crate::{Finding, GovernorError, ValidatedPolicyAuthority};

const SCHEMA_VERSION: &str = "0.1";
const ASK_MATT_SHA256: &str = "b1a134ada29cbfded84bc9a7f93356ab7a3d7f800edf1f541a2a964118ad45a7";
const ALLOWED_SCOPES: [&str; 4] = [
    "authorized_external",
    "external_read_only",
    "owner_original",
    "unknown",
];
const OWNER_GITHUB_GATES: [&str; 3] = [
    "one_pr_one_task",
    "require_review_closeout",
    "require_bug_issue_for_merged_finding",
];
const OWNER_QUALITY_GATES: [&str; 5] = [
    "require_llm_contract",
    "require_primary_sources",
    "require_code_review_skill",
    "require_type_check",
    "require_security_check",
];
const OWNER_ENVIRONMENT_GATES: [&str; 3] = [
    "require_nix_flake",
    "require_nix_lock",
    "require_pinned_toolchain",
];

enum PolicySource {
    Bytes(Vec<u8>),
    Missing,
    Unreadable(String),
}

/// Receipt compatible with the principal fields emitted by the Python policy validator.
#[allow(clippy::module_name_repetitions, clippy::struct_field_names)]
#[derive(Clone, Debug, Serialize)]
pub struct PolicyReceipt {
    /// Absolute policy path.
    pub policy_path: String,
    /// Digest of the policy bytes, absent when no regular file exists.
    pub policy_sha256: Option<String>,
    /// Digest of this validator implementation.
    pub validator_sha256: String,
    /// Policy schema version understood by this validator.
    pub schema_version: String,
    /// Whether no deterministic finding was emitted.
    pub valid: bool,
    /// Deterministic findings sorted by code, field, and message.
    pub findings: Vec<Finding>,
    /// Parsed repository scope when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository_scope: Option<String>,
}

/// Validate one policy without mutating the repository.
pub(crate) fn validate_policy(path: &Path) -> Result<PolicyReceipt, GovernorError> {
    evaluate_policy(path).map(|(receipt, _)| receipt)
}

pub(crate) fn evaluate_policy(
    path: &Path,
) -> Result<(PolicyReceipt, Option<ValidatedPolicyAuthority>), GovernorError> {
    let resolved = absolute_path(path)?;
    let source = match fs::read(&resolved) {
        Ok(bytes) => PolicySource::Bytes(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => PolicySource::Missing,
        Err(error) => PolicySource::Unreadable(error.to_string()),
    };
    let authority = match &source {
        PolicySource::Bytes(bytes) => ValidatedPolicyAuthority::from_bytes(bytes).ok(),
        PolicySource::Missing | PolicySource::Unreadable(_) => None,
    };

    let policy_sha256 = match &source {
        PolicySource::Bytes(bytes) => Some(sha256_bytes(bytes)),
        PolicySource::Missing | PolicySource::Unreadable(_) => None,
    };
    let (mut findings, repository_scope) = match source {
        PolicySource::Missing => (
            vec![Finding::policy(
                "POLICY_NOT_FOUND",
                &resolved.display().to_string(),
                "policy file does not exist",
            )],
            None,
        ),
        PolicySource::Unreadable(message) => (
            vec![Finding::policy(
                "POLICY_PARSE_ERROR",
                &resolved.display().to_string(),
                message,
            )],
            None,
        ),
        PolicySource::Bytes(bytes) => match parse_document(&bytes) {
            Ok(Value::Table(document)) => {
                let scope = string_value(document.get("repository_scope")).map(str::to_owned);
                (validate_document(&document), scope)
            }
            Ok(_) => (
                vec![Finding::policy(
                    "INVALID_POLICY_ROOT",
                    &resolved.display().to_string(),
                    "policy root must be a table",
                )],
                None,
            ),
            Err(message) => (
                vec![Finding::policy(
                    "POLICY_PARSE_ERROR",
                    &resolved.display().to_string(),
                    message,
                )],
                None,
            ),
        },
    };
    sort_findings(&mut findings);

    Ok((
        PolicyReceipt {
            policy_path: resolved.display().to_string(),
            policy_sha256,
            validator_sha256: sha256_bytes(include_bytes!("policy.rs")),
            schema_version: SCHEMA_VERSION.to_owned(),
            valid: findings.is_empty(),
            findings,
            repository_scope,
        },
        authority,
    ))
}

pub(crate) fn validated_authority(bytes: &[u8]) -> Option<(String, bool, bool)> {
    let Value::Table(document) = parse_document(bytes).ok()? else {
        return None;
    };
    if !validate_document(&document).is_empty() {
        return None;
    }
    let authority = document.get("authority")?.as_table()?;
    Some((
        sha256_bytes(bytes),
        authority.get("repository_write")?.as_bool()?,
        authority.get("external_side_effects")?.as_bool()?,
    ))
}

#[allow(clippy::too_many_lines)]
fn validate_document(document: &toml::Table) -> Vec<Finding> {
    let mut findings = Vec::new();

    if string_value(document.get("schema_version")) != Some(SCHEMA_VERSION) {
        findings.push(Finding::policy(
            "SCHEMA_VERSION_MISMATCH",
            "schema_version",
            format!("schema_version must be {SCHEMA_VERSION}"),
        ));
    }
    require_non_empty_string(
        document,
        "policy_id",
        "policy_id",
        "MISSING_POLICY_ID",
        "policy_id is required",
        &mut findings,
    );

    let scope = string_value(document.get("repository_scope"));
    if !scope.is_some_and(|candidate| ALLOWED_SCOPES.contains(&candidate)) {
        findings.push(Finding::policy(
            "INVALID_SCOPE",
            "repository_scope",
            "repository_scope must be one of ['authorized_external', 'external_read_only', 'owner_original', 'unknown']",
        ));
    }

    let authority = table(document, "authority", &mut findings);
    let repository_write = require_bool(
        authority,
        "repository_write",
        "authority.repository_write",
        None,
        &mut findings,
    );
    let external_side_effects = require_bool(
        authority,
        "external_side_effects",
        "authority.external_side_effects",
        None,
        &mut findings,
    );
    require_bool(
        authority,
        "destructive_actions",
        "authority.destructive_actions",
        Some(false),
        &mut findings,
    );
    if matches!(scope, Some("unknown" | "external_read_only")) {
        if repository_write == Some(true) {
            findings.push(Finding::policy(
                "SCOPE_AUTHORITY_CONFLICT",
                "authority.repository_write",
                format!(
                    "{} scope cannot grant repository writes",
                    scope.unwrap_or("unknown")
                ),
            ));
        }
        if external_side_effects == Some(true) {
            findings.push(Finding::policy(
                "SCOPE_AUTHORITY_CONFLICT",
                "authority.external_side_effects",
                format!(
                    "{} scope cannot grant external side effects",
                    scope.unwrap_or("unknown")
                ),
            ));
        }
    }
    if scope == Some("authorized_external") {
        let external_authority = table(document, "external_authority", &mut findings);
        for key in ["authority_receipt", "upstream_policy"] {
            require_non_empty_string(
                external_authority,
                key,
                &format!("external_authority.{key}"),
                "INVALID_STRING",
                &format!("external_authority.{key} must be non-empty"),
                &mut findings,
            );
        }
        for key in ["authority_receipt_sha256", "upstream_policy_sha256"] {
            let field = format!("external_authority.{key}");
            if !string_value(external_authority.get(key)).is_some_and(is_sha256) {
                findings.push(Finding::policy(
                    "INVALID_AUTHORITY_DIGEST",
                    &field,
                    format!("{field} must be a lower-case SHA-256 digest"),
                ));
            }
        }
        if repository_write == Some(true) || external_side_effects == Some(true) {
            findings.push(Finding::policy(
                "EXTERNAL_WRITE_ADAPTER_UNAVAILABLE",
                "repository_scope",
                "this static slice cannot establish an external trust root; use read-only authority",
            ));
        }
    }

    let budget = table(document, "budget", &mut findings);
    require_int(
        budget,
        "max_in_flight",
        "budget.max_in_flight",
        1,
        &mut findings,
    );
    require_int(
        budget,
        "max_delegation_depth",
        "budget.max_delegation_depth",
        0,
        &mut findings,
    );
    require_int(
        budget,
        "max_repair_rounds",
        "budget.max_repair_rounds",
        0,
        &mut findings,
    );

    let routing = table(document, "routing", &mut findings);
    if string_value(routing.get("authority")) != Some("ask-matt-or-explicit-user-selection") {
        findings.push(Finding::policy(
            "INVALID_ROUTING_AUTHORITY",
            "routing.authority",
            "routing authority must remain ask-matt-or-explicit-user-selection",
        ));
    }
    require_bool(
        routing,
        "require_explicit_route",
        "routing.require_explicit_route",
        Some(true),
        &mut findings,
    );
    require_bool(
        routing,
        "allow_route_substitution",
        "routing.allow_route_substitution",
        Some(false),
        &mut findings,
    );
    require_bool(
        routing,
        "implicit_ask_matt_invocation",
        "routing.implicit_ask_matt_invocation",
        Some(false),
        &mut findings,
    );
    match string_value(routing.get("ask_matt_sha256")) {
        Some(value) if is_sha256(value) && value != ASK_MATT_SHA256 => {
            findings.push(Finding::policy(
                "ROUTER_SOURCE_MISMATCH",
                "routing.ask_matt_sha256",
                "routing.ask_matt_sha256 must match the bundled ask-matt Adapter",
            ));
        }
        Some(value) if is_sha256(value) => {}
        _ => findings.push(Finding::policy(
            "INVALID_SOURCE_DIGEST",
            "routing.ask_matt_sha256",
            "routing.ask_matt_sha256 must be a lower-case SHA-256 digest",
        )),
    }

    let completion = table(document, "completion", &mut findings);
    for key in [
        "require_terminal_evidence",
        "require_satisfied_postcondition",
        "require_current_artifact_review",
    ] {
        require_bool(
            completion,
            key,
            &format!("completion.{key}"),
            Some(true),
            &mut findings,
        );
    }

    let knowledge = table(document, "knowledge", &mut findings);
    if string_value(knowledge.get("okf_version")) != Some("0.2") {
        findings.push(Finding::policy(
            "INVALID_OKF_VERSION",
            "knowledge.okf_version",
            "knowledge.okf_version must be 0.2",
        ));
    }
    require_non_empty_string(
        knowledge,
        "bundle",
        "knowledge.bundle",
        "MISSING_BUNDLE",
        "knowledge.bundle is required",
        &mut findings,
    );

    let receipts = table(document, "receipts", &mut findings);
    require_bool(
        receipts,
        "include_in_okf_bundle",
        "receipts.include_in_okf_bundle",
        Some(false),
        &mut findings,
    );
    let directory = require_non_empty_string(
        receipts,
        "directory",
        "receipts.directory",
        "MISSING_RECEIPT_DIRECTORY",
        "receipts.directory is required",
        &mut findings,
    );
    if directory.is_some_and(|value| !is_safe_relative_path(value)) {
        findings.push(Finding::policy(
            "UNSAFE_RECEIPT_DIRECTORY",
            "receipts.directory",
            "receipts.directory must be a repository-relative path without '..'",
        ));
    }

    if scope == Some("owner_original") {
        validate_owner_policy(document, &mut findings);
    }

    sort_findings(&mut findings);
    findings
}

fn parse_document(bytes: &[u8]) -> Result<Value, String> {
    let text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    toml::from_str::<Value>(text).map_err(|error| error.to_string())
}

fn validate_owner_policy(document: &toml::Table, findings: &mut Vec<Finding>) {
    let default_branch = require_non_empty_string(
        document,
        "default_branch",
        "default_branch",
        "INVALID_STRING",
        "default_branch must be non-empty",
        findings,
    );
    let github = table(document, "github", findings);
    let branch_base = require_non_empty_string(
        github,
        "branch_base",
        "github.branch_base",
        "INVALID_STRING",
        "github.branch_base must be non-empty",
        findings,
    );
    if let Some(default_branch) = default_branch {
        let expected_branch_base = format!("origin/{default_branch}");
        if branch_base != Some(expected_branch_base.as_str()) {
            findings.push(Finding::policy(
                "INVALID_BRANCH_BASE",
                "github.branch_base",
                "github.branch_base must equal origin/<default_branch>",
            ));
        }
    }
    for key in OWNER_GITHUB_GATES {
        require_bool(github, key, &format!("github.{key}"), Some(true), findings);
    }
    require_int(
        github,
        "product_diff_soft_target",
        "github.product_diff_soft_target",
        1,
        findings,
    );

    let quality = table(document, "quality", findings);
    for key in OWNER_QUALITY_GATES {
        require_bool(
            quality,
            key,
            &format!("quality.{key}"),
            Some(true),
            findings,
        );
    }
    if !string_value(quality.get("code_review_skill_sha256")).is_some_and(is_sha256) {
        findings.push(Finding::policy(
            "INVALID_REVIEW_SKILL_DIGEST",
            "quality.code_review_skill_sha256",
            "quality.code_review_skill_sha256 must be a lower-case SHA-256",
        ));
    }

    let environment = table(document, "environment", findings);
    for key in OWNER_ENVIRONMENT_GATES {
        require_bool(
            environment,
            key,
            &format!("environment.{key}"),
            Some(true),
            findings,
        );
    }
    let lock_path = require_non_empty_string(
        environment,
        "toolchain_lock",
        "environment.toolchain_lock",
        "INVALID_STRING",
        "environment.toolchain_lock must be non-empty",
        findings,
    );
    if lock_path.is_some_and(|value| !is_safe_relative_path(value)) {
        findings.push(Finding::policy(
            "UNSAFE_TOOLCHAIN_LOCK_PATH",
            "environment.toolchain_lock",
            "environment.toolchain_lock must be repository-relative without '..'",
        ));
    }
    require_string_list(
        environment,
        "required_tools",
        "environment.required_tools",
        findings,
    );
}

fn table<'a>(document: &'a toml::Table, key: &str, findings: &mut Vec<Finding>) -> &'a toml::Table {
    static EMPTY: std::sync::LazyLock<toml::Table> = std::sync::LazyLock::new(toml::Table::new);
    if let Some(Value::Table(value)) = document.get(key) {
        value
    } else {
        findings.push(Finding::policy(
            "MISSING_TABLE",
            key,
            format!("{key} must be a TOML table"),
        ));
        &EMPTY
    }
}

fn require_bool(
    table: &toml::Table,
    key: &str,
    field: &str,
    expected: Option<bool>,
    findings: &mut Vec<Finding>,
) -> Option<bool> {
    let Some(value) = table.get(key).and_then(Value::as_bool) else {
        findings.push(Finding::policy(
            "INVALID_BOOLEAN",
            field,
            format!("{field} must be boolean"),
        ));
        return None;
    };
    if expected.is_some_and(|required| value != required) {
        let required = if expected == Some(true) {
            "true"
        } else {
            "false"
        };
        findings.push(Finding::policy(
            "UNSAFE_VALUE",
            field,
            format!("{field} must be {required}"),
        ));
    }
    Some(value)
}

fn require_int(
    table: &toml::Table,
    key: &str,
    field: &str,
    minimum: i64,
    findings: &mut Vec<Finding>,
) -> Option<i64> {
    let value = table.get(key).and_then(Value::as_integer);
    if value.is_none_or(|candidate| candidate < minimum) {
        findings.push(Finding::policy(
            "INVALID_BUDGET",
            field,
            format!("{field} must be an integer >= {minimum}"),
        ));
        return None;
    }
    value
}

fn require_non_empty_string<'a>(
    table: &'a toml::Table,
    key: &str,
    field: &str,
    code: &str,
    message: &str,
    findings: &mut Vec<Finding>,
) -> Option<&'a str> {
    let value = string_value(table.get(key));
    if value.is_none_or(|candidate| candidate.trim().is_empty()) {
        findings.push(Finding::policy(code, field, message));
        return None;
    }
    value
}

fn require_string_list(table: &toml::Table, key: &str, field: &str, findings: &mut Vec<Finding>) {
    let valid = table
        .get(key)
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty())
        .is_some_and(|values| {
            let strings = values
                .iter()
                .filter_map(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .collect::<Vec<_>>();
            strings.len() == values.len()
                && strings.iter().collect::<BTreeSet<_>>().len() == strings.len()
        });
    if !valid {
        findings.push(Finding::policy(
            "INVALID_STRING_LIST",
            field,
            format!("{field} must be a non-empty list of unique strings"),
        ));
    }
}

fn string_value(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && !path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
}

fn absolute_path(path: &Path) -> Result<PathBuf, GovernorError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|directory| directory.join(path))
            .map_err(|source| GovernorError::Read {
                path: path.to_path_buf(),
                source,
            })?
    };
    resolve_allow_missing(&absolute).map_err(|source| GovernorError::Read {
        path: path.to_path_buf(),
        source,
    })
}

#[derive(Clone, Debug)]
enum ResolutionComponent {
    Prefix(OsString),
    RootDir,
    CurDir,
    ParentDir,
    Normal(OsString),
    EndSymlinkExpansion(PathBuf),
}

impl ResolutionComponent {
    fn from_component(component: Component<'_>) -> Self {
        match component {
            Component::Prefix(prefix) => Self::Prefix(prefix.as_os_str().to_owned()),
            Component::RootDir => Self::RootDir,
            Component::CurDir => Self::CurDir,
            Component::ParentDir => Self::ParentDir,
            Component::Normal(part) => Self::Normal(part.to_owned()),
        }
    }
}

fn prepend_components(pending: &mut VecDeque<ResolutionComponent>, path: &Path) {
    let components = path
        .components()
        .map(ResolutionComponent::from_component)
        .collect::<Vec<_>>();
    for component in components.into_iter().rev() {
        pending.push_front(component);
    }
}

fn resolve_allow_missing(path: &Path) -> io::Result<PathBuf> {
    let mut pending = VecDeque::new();
    prepend_components(&mut pending, path);
    let mut resolved = PathBuf::new();
    let mut active_symlinks = HashSet::new();

    while let Some(component) = pending.pop_front() {
        match component {
            ResolutionComponent::CurDir => {}
            ResolutionComponent::ParentDir => {
                resolved.pop();
            }
            ResolutionComponent::Normal(part) => {
                let candidate = resolved.join(part);
                let is_symlink = fs::symlink_metadata(&candidate)
                    .is_ok_and(|metadata| metadata.file_type().is_symlink());
                if is_symlink {
                    if !active_symlinks.insert(candidate.clone()) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "symlink cycle while resolving policy path at {}",
                                candidate.display()
                            ),
                        ));
                    }
                    let target = fs::read_link(&candidate)?;
                    pending.push_front(ResolutionComponent::EndSymlinkExpansion(candidate));
                    prepend_components(&mut pending, &target);
                } else {
                    resolved = candidate;
                }
            }
            ResolutionComponent::RootDir => {
                resolved.push(Path::new(std::path::MAIN_SEPARATOR_STR));
            }
            ResolutionComponent::Prefix(prefix) => {
                resolved.push(prefix);
            }
            ResolutionComponent::EndSymlinkExpansion(symlink) => {
                active_symlinks.remove(&symlink);
            }
        }
    }
    Ok(resolved)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|left, right| {
        (
            left.code.as_str(),
            left.field.as_deref().unwrap_or_default(),
            left.message.as_str(),
        )
            .cmp(&(
                right.code.as_str(),
                right.field.as_deref().unwrap_or_default(),
                right.message.as_str(),
            ))
    });
}

// LLM-CONTRACT
// id: agent-work-governor.rust-policy-validation
// state: RAW_PATH -> FINITE_SYMLINK_EXPANSION -> UNREAD -> PARSED -> VALID | INVALID
// preconditions: the policy path is explicit
// invariant: chain length never bypasses symlink expansion or grants repository write authority
// failure: cycles and unreadable links produce a typed fault; policy defects produce findings
// source: bundle:knowledge/policies/work-governor.md
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: validate_policy
// test: bundle:rust/tests/policy.rs
