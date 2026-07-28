//! Pure mapping from resolved Python project facts to typed governed checks.
#![allow(
    dead_code,
    reason = "Issue #4 defines the private adapter before Issue #7 exposes planning"
)]

use crate::{
    adapter_catalog::{closed_id, sha256_hex, tool_version},
    governance_ir::{CheckDraft, CheckKind, GovernanceIr, Language},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const RECIPE_BYTES: &str = include_str!("../../adapters/check-recipes.v1.json");
const RECIPE_SCHEMA: &str = "0.2";
const RECIPE_SHA256: &str = "35dd14bb851cc822d50327db3f5bb3ccb89b2e5f8a958d35f19d27166a302333";
const TOOLCHAIN_BYTES: &str = include_str!("../../toolchain.lock.json");

// LLM-CONTRACT
// id: agent-work-governor.deterministic-python-adapter
// state: RESOLVED_PYTHON_PROJECT + UNIFIED_TOOLCHAIN + VERSIONED_RECIPES -> DIGEST_BOUND_PYTHON_CHECK_SET | ADAPTER_REJECTED
// preconditions: project kind, layout, workdir, and bundled catalog bytes are explicit and validated
// invariant: output is command-free GIR plus exact recipe/toolchain digests; consumer text never enters argv
// failure: return one stable PY_ADAPTER reason code and no partial GovernanceIR
// source: https://github.com/yaneurao/Pytra/blob/9f341e04fefd8eacac1081c59e80f4042ee80a6f/docs/en/guide/emitter-overview.md
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: adapt_python
// test: bundle:rust/src/python_adapter.rs

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RepositoryKind {
    PythonOnly,
    Mixed,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PythonLayout {
    UvUnittest,
    Unsupported,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PythonProjectDraft {
    pub(crate) repository_kind: Option<RepositoryKind>,
    pub(crate) layout: Option<PythonLayout>,
    pub(crate) working_directory: Option<String>,
}

closed_id!(PythonCheckId {
    PipAudit => "python.pip-audit",
    RuffFormat => "python.ruff-format",
    RuffLint => "python.ruff-lint",
    Tests => "python.tests",
    Ty => "python.ty",
    UvExport => "python.uv-export",
    UvLock => "python.uv-lock",
});

closed_id!(PythonToolId {
    PipAudit => "pip-audit",
    Python => "python",
    Ruff => "ruff",
    Ty => "ty",
    Uv => "uv",
});

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
enum PythonArtifactId {
    PythonAuditRequirements,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(untagged)]
enum ArgAtom {
    Literal(String),
    Artifact { artifact: PythonArtifactId },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipeCatalogDraft {
    schema_version: String,
    language: Language,
    recipes: Vec<Recipe>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum WorkingDirectory {
    ProjectRoot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Recipe {
    id: PythonCheckId,
    kind: CheckKind,
    tool: PythonToolId,
    argv: Vec<ArgAtom>,
    dependencies: Vec<PythonCheckId>,
    input_artifacts: Vec<PythonArtifactId>,
    output_artifacts: Vec<PythonArtifactId>,
    working_directory: WorkingDirectory,
    timeout_seconds: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct PythonCheckSet {
    catalog_version: String,
    catalog_sha256: String,
    toolchain_sha256: String,
    governance_ir: GovernanceIr,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("{0}")]
pub(crate) struct PythonAdapterError(&'static str);

impl PythonAdapterError {
    const PROJECT_INCOMPLETE: Self = Self("PY_ADAPTER_PROJECT_INCOMPLETE");
    const LAYOUT_UNSUPPORTED: Self = Self("PY_ADAPTER_LAYOUT_UNSUPPORTED");
    const RECIPE_CATALOG_INVALID: Self = Self("PY_ADAPTER_RECIPE_CATALOG_INVALID");
    const TOOLCHAIN_CATALOG_INVALID: Self = Self("PY_ADAPTER_TOOLCHAIN_CATALOG_INVALID");
    const GIR_REJECTED: Self = Self("PY_ADAPTER_GIR_REJECTED");

    pub(crate) const fn code(self) -> &'static str {
        self.0
    }
}

fn parse_recipe_catalog(bytes: &str) -> Result<Vec<Recipe>, PythonAdapterError> {
    let mut draft: RecipeCatalogDraft =
        serde_json::from_str(bytes).map_err(|_| PythonAdapterError::RECIPE_CATALOG_INVALID)?;
    if sha256_hex(bytes.as_bytes()) != RECIPE_SHA256
        || draft.schema_version != RECIPE_SCHEMA
        || draft.language != Language::Python
    {
        return Err(PythonAdapterError::RECIPE_CATALOG_INVALID);
    }
    draft.recipes.sort_by_key(|recipe| recipe.id);
    Ok(draft.recipes)
}

pub(crate) fn adapt_python(
    project: PythonProjectDraft,
) -> Result<PythonCheckSet, PythonAdapterError> {
    match project
        .repository_kind
        .ok_or(PythonAdapterError::PROJECT_INCOMPLETE)?
    {
        RepositoryKind::PythonOnly | RepositoryKind::Mixed => {}
        RepositoryKind::Unsupported => return Err(PythonAdapterError::LAYOUT_UNSUPPORTED),
    }
    match project
        .layout
        .ok_or(PythonAdapterError::PROJECT_INCOMPLETE)?
    {
        PythonLayout::UvUnittest => {}
        PythonLayout::Unsupported => return Err(PythonAdapterError::LAYOUT_UNSUPPORTED),
    }
    let working_directory = project
        .working_directory
        .ok_or(PythonAdapterError::PROJECT_INCOMPLETE)?;
    let recipes = parse_recipe_catalog(RECIPE_BYTES)?;
    let mut drafts = Vec::with_capacity(recipes.len());

    for recipe in recipes {
        let version = tool_version(TOOLCHAIN_BYTES, "python", recipe.tool.as_str())
            .map_err(|_| PythonAdapterError::TOOLCHAIN_CATALOG_INVALID)?;
        let recipe_workdir = match recipe.working_directory {
            WorkingDirectory::ProjectRoot => working_directory.clone(),
        };
        drafts.push(CheckDraft {
            identifier: Some(recipe.id.as_str().into()),
            language: Some(Language::Python),
            kind: Some(recipe.kind),
            tool_identity: Some(recipe.tool.as_str().into()),
            tool_version: Some(version),
            path: Some(recipe_workdir.clone()),
            dependencies: Some(
                recipe
                    .dependencies
                    .iter()
                    .map(|dependency| dependency.as_str().into())
                    .collect(),
            ),
        });
    }
    let governance_ir =
        GovernanceIr::resolve(drafts).map_err(|_| PythonAdapterError::GIR_REJECTED)?;
    Ok(PythonCheckSet {
        catalog_version: RECIPE_SCHEMA.into(),
        catalog_sha256: sha256_hex(RECIPE_BYTES.as_bytes()),
        toolchain_sha256: sha256_hex(TOOLCHAIN_BYTES.as_bytes()),
        governance_ir,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(kind: RepositoryKind, path: &str) -> PythonProjectDraft {
        PythonProjectDraft {
            repository_kind: Some(kind),
            layout: Some(PythonLayout::UvUnittest),
            working_directory: Some(path.into()),
        }
    }

    fn assert_error(result: Result<PythonCheckSet, PythonAdapterError>, expected: &'static str) {
        assert_eq!(
            expected,
            result.err().map_or("resolved", PythonAdapterError::code)
        );
    }

    fn atom(value: &ArgAtom) -> &str {
        match value {
            ArgAtom::Literal(value) => value,
            ArgAtom::Artifact { .. } => "<python-audit-requirements>",
        }
    }

    #[test]
    fn python_only_fixture_has_exact_closed_recipe_set() -> Result<(), Box<dyn std::error::Error>> {
        let checks = adapt_python(project(RepositoryKind::PythonOnly, "."))?;
        assert_eq!(
            serde_json::to_vec(&checks)?,
            serde_json::to_vec(&adapt_python(project(RepositoryKind::PythonOnly, "."))?)?
        );
        let encoded = serde_json::to_value(checks)?;
        let checks = encoded["governance_ir"]["checks"]
            .as_array()
            .ok_or("GIR checks are not an array")?;
        assert_eq!(7, checks.len());
        assert_eq!("0.2", encoded["catalog_version"]);
        assert_eq!(
            "35dd14bb851cc822d50327db3f5bb3ccb89b2e5f8a958d35f19d27166a302333",
            encoded["catalog_sha256"]
        );
        assert_eq!(
            "f123483a002951bec0907eb883c67ecdf3987561630947165f5ae30c3b34467a",
            encoded["toolchain_sha256"]
        );
        assert_eq!("python.pip-audit", checks[0]["identifier"]);
        assert_eq!(
            serde_json::json!(["python.uv-export"]),
            checks[0]["dependencies"]
        );
        assert_eq!("0.11.33", checks[6]["tool"]["version"]);
        assert!(checks.iter().all(|check| check["path"] == "."));
        assert!(!serde_json::to_string(&encoded)?.contains("\"argv\""));
        let ids = checks
            .iter()
            .map(|check| check["identifier"].as_str().unwrap_or_default())
            .collect::<Vec<_>>();
        assert_eq!(
            [
                "python.pip-audit",
                "python.ruff-format",
                "python.ruff-lint",
                "python.tests",
                "python.ty",
                "python.uv-export",
                "python.uv-lock"
            ],
            ids.as_slice()
        );
        Ok(())
    }

    #[test]
    fn mixed_fixture_changes_only_the_explicit_workdir() -> Result<(), Box<dyn std::error::Error>> {
        let root = adapt_python(project(RepositoryKind::PythonOnly, "."))?;
        let mixed = adapt_python(project(RepositoryKind::Mixed, "python"))?;
        assert_eq!(root.catalog_version, mixed.catalog_version);
        assert_eq!(root.catalog_sha256, mixed.catalog_sha256);
        assert_eq!(root.toolchain_sha256, mixed.toolchain_sha256);
        let root = serde_json::to_value(root)?;
        let mixed = serde_json::to_value(mixed)?;
        let root_checks = root["governance_ir"]["checks"]
            .as_array()
            .ok_or("root GIR checks are not an array")?;
        let mixed_checks = mixed["governance_ir"]["checks"]
            .as_array()
            .ok_or("mixed GIR checks are not an array")?;
        for (root, mixed) in root_checks.iter().zip(mixed_checks) {
            assert_eq!(root["identifier"], mixed["identifier"]);
            assert_eq!(root["tool"], mixed["tool"]);
            assert_eq!(".", root["path"]);
            assert_eq!("python", mixed["path"]);
        }
        Ok(())
    }

    #[test]
    fn invalid_projects_fail_closed_without_partial_ir() {
        assert_error(
            adapt_python(project(RepositoryKind::Unsupported, ".")),
            "PY_ADAPTER_LAYOUT_UNSUPPORTED",
        );

        let mut missing_layout = project(RepositoryKind::PythonOnly, ".");
        missing_layout.layout = None;
        assert_error(
            adapt_python(missing_layout),
            "PY_ADAPTER_PROJECT_INCOMPLETE",
        );
        assert_error(
            adapt_python(project(RepositoryKind::Mixed, "../python")),
            "PY_ADAPTER_GIR_REJECTED",
        );
    }

    #[test]
    fn bundled_recipe_catalog_is_exact_and_artifact_typed() -> Result<(), Box<dyn std::error::Error>>
    {
        let recipes = parse_recipe_catalog(RECIPE_BYTES)?;
        assert_eq!(RECIPE_SHA256, sha256_hex(RECIPE_BYTES.as_bytes()));
        assert_eq!(7, recipes.len());
        assert_eq!("python.pip-audit", recipes[0].id.as_str());
        assert_eq!("python.uv-lock", recipes[6].id.as_str());
        let export = &recipes[5];
        assert_eq!(
            [PythonArtifactId::PythonAuditRequirements],
            recipes[0].input_artifacts.as_slice()
        );
        assert_eq!(
            [PythonArtifactId::PythonAuditRequirements],
            export.output_artifacts.as_slice()
        );
        assert_eq!(
            [
                "uv",
                "export",
                "--quiet",
                "--locked",
                "--all-extras",
                "--all-groups",
                "--no-emit-workspace",
                "--format",
                "requirements.txt",
                "--output-file",
                "<python-audit-requirements>"
            ],
            export.argv.iter().map(atom).collect::<Vec<_>>().as_slice()
        );
        assert_eq!(
            [
                "python", "-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test*.py"
            ],
            recipes[3]
                .argv
                .iter()
                .map(atom)
                .collect::<Vec<_>>()
                .as_slice()
        );
        assert_eq!(180, recipes[0].timeout_seconds);
        Ok(())
    }

    #[test]
    fn catalog_mutations_fail_without_partial_recipes() {
        for mutated in [
            RECIPE_BYTES.replacen(
                "\"schema_version\": \"0.2\"",
                "\"schema_version\": \"0.3\"",
                1,
            ),
            RECIPE_BYTES.replacen(
                "\"dependencies\": []",
                "\"dependencies\": [\"python.pip-audit\"]",
                1,
            ),
            RECIPE_BYTES.replacen("\"python.uv-lock\"", "\"python.unknown\"", 1),
        ] {
            assert_eq!(
                Some("PY_ADAPTER_RECIPE_CATALOG_INVALID"),
                parse_recipe_catalog(&mutated)
                    .err()
                    .map(PythonAdapterError::code)
            );
        }
    }

    #[test]
    fn embedded_toolchain_projection_is_exact_and_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        for (tool, version) in [
            (PythonToolId::PipAudit, "2.10.1"),
            (PythonToolId::Python, "3.14.6"),
            (PythonToolId::Ruff, "0.16.0"),
            (PythonToolId::Ty, "0.0.64"),
            (PythonToolId::Uv, "0.11.33"),
        ] {
            assert_eq!(
                version,
                tool_version(TOOLCHAIN_BYTES, "python", tool.as_str())?
            );
        }
        let wrong_schema = TOOLCHAIN_BYTES.replacen(
            "\"schema_version\": \"0.2\"",
            "\"schema_version\": \"0.3\"",
            1,
        );
        assert!(tool_version(&wrong_schema, "python", PythonToolId::Ruff.as_str()).is_err());
        let wrong_language = TOOLCHAIN_BYTES.replacen(
            "\"id\": \"ruff\", \"language\": \"python\"",
            "\"id\": \"ruff\", \"language\": \"rust\"",
            1,
        );
        assert!(tool_version(&wrong_language, "python", PythonToolId::Ruff.as_str()).is_err());
        Ok(())
    }
}
