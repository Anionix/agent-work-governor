//! Typed, language-neutral governance intermediate representation.
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

pub(crate) mod execution_plan;
pub(crate) mod execution_recipe;

// LLM-CONTRACT
// id: agent-work-governor.resolved-governance-ir
// state: VALID_CONFIG -> RESOLVED_GOVERNANCE_IR | UNRESOLVED_GIR
// preconditions: every draft field and dependency identifier is explicit
// invariant: resolved values contain only portable typed data, never shell or runtime authority
// failure: resolve returns one stable GIR reason code without a partial IR
// source: https://github.com/yaneurao/Pytra/blob/9f341e04fefd8eacac1081c59e80f4042ee80a6f/docs/en/guide/east-overview.md
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: resolve
// test: bundle:rust/src/governance_ir.rs

const SCHEMA_VERSION: &str = "0.1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Language {
    Python,
    Rust,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CheckKind {
    Dependency,
    Format,
    Lint,
    TypeCheck,
    Test,
    Security,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct CheckDraft {
    pub(crate) identifier: Option<String>,
    pub(crate) language: Option<Language>,
    pub(crate) kind: Option<CheckKind>,
    pub(crate) tool_identity: Option<String>,
    pub(crate) tool_version: Option<String>,
    pub(crate) path: Option<String>,
    pub(crate) dependencies: Option<Vec<String>>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub(crate) struct CheckId(String);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ToolPin {
    identity: String,
    version: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub(crate) struct Dependency(CheckId);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ResolvedCheck {
    identifier: CheckId,
    language: Language,
    kind: CheckKind,
    tool: ToolPin,
    path: String,
    dependencies: Vec<Dependency>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct GovernanceIr {
    schema_version: &'static str,
    checks: Vec<ResolvedCheck>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GovernanceIrError(&'static str);
impl GovernanceIrError {
    const MISSING_IDENTIFIER: Self = Self("GIR_MISSING_IDENTIFIER");
    const MISSING_LANGUAGE: Self = Self("GIR_MISSING_LANGUAGE");
    const MISSING_CHECK_KIND: Self = Self("GIR_MISSING_CHECK_KIND");
    const MISSING_TOOL_IDENTITY: Self = Self("GIR_MISSING_TOOL_IDENTITY");
    const MISSING_TOOL_VERSION: Self = Self("GIR_MISSING_TOOL_VERSION");
    const MISSING_PATH: Self = Self("GIR_MISSING_PATH");
    const DEPENDENCIES_UNDECLARED: Self = Self("GIR_DEPENDENCIES_UNDECLARED");
    const DUPLICATE_IDENTIFIER: Self = Self("GIR_DUPLICATE_IDENTIFIER");
    const UNKNOWN_IDENTIFIER: Self = Self("GIR_UNKNOWN_IDENTIFIER");
    const INVALID_IDENTIFIER: Self = Self("GIR_INVALID_IDENTIFIER");
    const INVALID_TOOL_IDENTITY: Self = Self("GIR_INVALID_TOOL_IDENTITY");
    const INVALID_TOOL_VERSION: Self = Self("GIR_INVALID_TOOL_VERSION");
    const INVALID_PATH: Self = Self("GIR_INVALID_PATH");

    pub(crate) const fn code(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for GovernanceIrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for GovernanceIrError {}

impl GovernanceIr {
    pub(crate) fn resolve(drafts: Vec<CheckDraft>) -> Result<Self, GovernanceIrError> {
        let checks = drafts
            .into_iter()
            .map(ResolvedCheck::resolve)
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_checks(checks)
    }

    pub(crate) fn merge(parts: Vec<Self>) -> Result<Self, GovernanceIrError> {
        Self::from_checks(parts.into_iter().flat_map(|part| part.checks).collect())
    }

    fn from_checks(mut checks: Vec<ResolvedCheck>) -> Result<Self, GovernanceIrError> {
        checks.sort_by(|left, right| left.identifier.cmp(&right.identifier));
        if checks
            .windows(2)
            .any(|pair| pair[0].identifier == pair[1].identifier)
        {
            return Err(GovernanceIrError::DUPLICATE_IDENTIFIER);
        }

        if checks
            .iter()
            .flat_map(|check| &check.dependencies)
            .any(|dependency| {
                checks
                    .binary_search_by(|check| check.identifier.cmp(&dependency.0))
                    .is_err()
            })
        {
            return Err(GovernanceIrError::UNKNOWN_IDENTIFIER);
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            checks,
        })
    }
}

impl ResolvedCheck {
    fn resolve(draft: CheckDraft) -> Result<Self, GovernanceIrError> {
        let identifier = CheckId(token(
            draft.identifier,
            GovernanceIrError::MISSING_IDENTIFIER,
            GovernanceIrError::INVALID_IDENTIFIER,
            false,
        )?);
        let tool = ToolPin {
            identity: token(
                draft.tool_identity,
                GovernanceIrError::MISSING_TOOL_IDENTITY,
                GovernanceIrError::INVALID_TOOL_IDENTITY,
                false,
            )?,
            version: token(
                draft.tool_version,
                GovernanceIrError::MISSING_TOOL_VERSION,
                GovernanceIrError::INVALID_TOOL_VERSION,
                true,
            )?,
        };
        let mut dependencies = required(
            draft.dependencies,
            GovernanceIrError::DEPENDENCIES_UNDECLARED,
        )?
        .into_iter()
        .map(|value| {
            token(
                Some(value),
                GovernanceIrError::MISSING_IDENTIFIER,
                GovernanceIrError::INVALID_IDENTIFIER,
                false,
            )
            .map(|value| Dependency(CheckId(value)))
        })
        .collect::<Result<Vec<_>, _>>()?;
        dependencies.sort();
        if dependencies.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(GovernanceIrError::DUPLICATE_IDENTIFIER);
        }
        Ok(Self {
            identifier,
            language: required(draft.language, GovernanceIrError::MISSING_LANGUAGE)?,
            kind: required(draft.kind, GovernanceIrError::MISSING_CHECK_KIND)?,
            tool,
            path: repo_path(draft.path)?,
            dependencies,
        })
    }
}

fn required<T>(value: Option<T>, error: GovernanceIrError) -> Result<T, GovernanceIrError> {
    value.ok_or(error)
}

fn token(
    value: Option<String>,
    missing: GovernanceIrError,
    invalid: GovernanceIrError,
    allow_plus: bool,
) -> Result<String, GovernanceIrError> {
    let value = required(value, missing)?;
    let edge_is_alphanumeric = value
        .as_bytes()
        .first()
        .zip(value.as_bytes().last())
        .is_some_and(|(first, last)| first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric());
    let chars_are_portable = value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'.' | b'_' | b'-')
            || (allow_plus && byte == b'+')
    });
    if edge_is_alphanumeric && chars_are_portable {
        Ok(value)
    } else {
        Err(invalid)
    }
}

fn repo_path(value: Option<String>) -> Result<String, GovernanceIrError> {
    let value = required(value, GovernanceIrError::MISSING_PATH)?;
    let segments_are_safe = value
        .split('/')
        .all(|part| !part.is_empty() && part != "." && part != "..");
    let chars_are_portable = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'));
    if value == "." || (segments_are_safe && chars_are_portable) {
        Ok(value)
    } else {
        Err(GovernanceIrError::INVALID_PATH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft(identifier: &str, dependencies: &[&str]) -> CheckDraft {
        CheckDraft {
            identifier: Some(identifier.into()),
            language: Some(Language::Python),
            kind: Some(CheckKind::Lint),
            tool_identity: Some("ruff".into()),
            tool_version: Some("0.16.0".into()),
            path: Some(".".into()),
            dependencies: Some(dependencies.iter().map(|value| (*value).into()).collect()),
        }
    }

    fn assert_error(result: Result<GovernanceIr, GovernanceIrError>, expected: &str) {
        assert_eq!(
            expected,
            result.err().map_or("resolved", GovernanceIrError::code)
        );
    }

    #[test]
    fn golden_serialization_contains_only_resolved_data() -> Result<(), Box<dyn Error>> {
        let uv = CheckDraft {
            kind: Some(CheckKind::Dependency),
            tool_identity: Some("uv".into()),
            tool_version: Some("0.11.33".into()),
            ..draft("python.uv", &[])
        };
        let ir = GovernanceIr::resolve(vec![uv, draft("python.ruff", &["python.uv"])])?;
        let encoded = serde_json::to_string(&ir)?;
        assert_eq!(
            r#"{"schema_version":"0.1","checks":[{"identifier":"python.ruff","language":"python","kind":"lint","tool":{"identity":"ruff","version":"0.16.0"},"path":".","dependencies":["python.uv"]},{"identifier":"python.uv","language":"python","kind":"dependency","tool":{"identity":"uv","version":"0.11.33"},"path":".","dependencies":[]}]}"#,
            encoded
        );
        assert!(
            ["command", "argv", "authority", "capability", "verdict"]
                .iter()
                .all(|forbidden| !encoded.contains(forbidden))
        );
        Ok(())
    }

    #[test]
    fn closed_enums_have_stable_wire_spellings() -> Result<(), Box<dyn Error>> {
        assert_eq!(
            r#"["python","rust"]"#,
            serde_json::to_string(&[Language::Python, Language::Rust])?
        );
        assert_eq!(
            r#"["dependency","format","lint","type_check","test","security"]"#,
            serde_json::to_string(&[
                CheckKind::Dependency,
                CheckKind::Format,
                CheckKind::Lint,
                CheckKind::TypeCheck,
                CheckKind::Test,
                CheckKind::Security,
            ])?
        );
        Ok(())
    }

    #[test]
    fn every_required_field_has_a_stable_code() {
        macro_rules! missing {
            ($field:ident, $code:literal) => {{
                let mut value = draft("valid", &[]);
                value.$field = None;
                assert_error(GovernanceIr::resolve(vec![value]), $code);
            }};
        }
        missing!(identifier, "GIR_MISSING_IDENTIFIER");
        missing!(language, "GIR_MISSING_LANGUAGE");
        missing!(kind, "GIR_MISSING_CHECK_KIND");
        missing!(tool_identity, "GIR_MISSING_TOOL_IDENTITY");
        missing!(tool_version, "GIR_MISSING_TOOL_VERSION");
        missing!(path, "GIR_MISSING_PATH");
        missing!(dependencies, "GIR_DEPENDENCIES_UNDECLARED");
        assert!(GovernanceIr::resolve(vec![draft("root", &[])]).is_ok());
    }

    #[test]
    fn hostile_unknown_and_duplicate_values_fail_closed() {
        for (value, code) in [
            (draft("bad id", &[]), "GIR_INVALID_IDENTIFIER"),
            (draft("root", &["missing"]), "GIR_UNKNOWN_IDENTIFIER"),
            (draft("root", &["root", "root"]), "GIR_DUPLICATE_IDENTIFIER"),
        ] {
            assert_error(GovernanceIr::resolve(vec![value]), code);
        }
        assert_error(
            GovernanceIr::resolve(vec![draft("same", &[]), draft("same", &[])]),
            "GIR_DUPLICATE_IDENTIFIER",
        );
        let mut hostile = draft("root", &[]);
        hostile.tool_identity = Some("sh -c id".into());
        assert_error(
            GovernanceIr::resolve(vec![hostile]),
            "GIR_INVALID_TOOL_IDENTITY",
        );
        let mut hostile = draft("root", &[]);
        hostile.tool_version = Some("1;id".into());
        assert_error(
            GovernanceIr::resolve(vec![hostile]),
            "GIR_INVALID_TOOL_VERSION",
        );
        let mut hostile = draft("root", &[]);
        hostile.path = Some("../../tmp".into());
        assert_error(GovernanceIr::resolve(vec![hostile]), "GIR_INVALID_PATH");
    }

    #[test]
    fn serialization_is_order_independent() -> Result<(), Box<dyn Error>> {
        let first = vec![
            draft("check.c", &["check.b", "check.a"]),
            draft("check.a", &[]),
            draft("check.b", &[]),
        ];
        let mut second = first.clone();
        second.reverse();
        second[2]
            .dependencies
            .as_mut()
            .ok_or("missing dependencies")?
            .reverse();
        assert_eq!(
            serde_json::to_vec(&GovernanceIr::resolve(first)?)?,
            serde_json::to_vec(&GovernanceIr::resolve(second)?)?
        );
        Ok(())
    }
}
