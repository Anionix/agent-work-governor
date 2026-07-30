//! Pure mapping from resolved Rust project facts to typed governed checks.
use crate::{
    adapter_catalog::{closed_id, sha256_hex, tool_version},
    governance_ir::{
        CheckDraft, CheckKind, GovernanceIr, Language,
        execution_recipe::{ExecutionRecipe, ExecutionRecipeDraft, RecipeArg},
    },
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const RECIPE_BYTES: &str = include_str!("../../adapters/rust-check-recipes.v1.json");
const RECIPE_SCHEMA: &str = "0.1";
const RECIPE_SHA256: &str = "490d065a8e981a347f287b44eace3ce481a5f2e7c019536f1cd8f8c89bdc8b8c";
const TOOLCHAIN_BYTES: &str = include_str!("../../toolchain.lock.json");

// LLM-CONTRACT
// id: agent-work-governor.deterministic-rust-adapter
// state: RESOLVED_RUST_PROJECT + UNIFIED_TOOLCHAIN + VERSIONED_RECIPES -> DIGEST_BOUND_RUST_CHECK_SET | ADAPTER_REJECTED
// preconditions: repository kind, Cargo layout, required-file presence, workdir, and bundled catalog bytes are explicit
// invariant: the pure adapter returns command-free GIR plus exact recipe/toolchain digests; repository text never enters argv
// failure: return one stable RUST_ADAPTER reason code and no partial GovernanceIR
// source: https://github.com/yaneurao/Pytra/blob/9f341e04fefd8eacac1081c59e80f4042ee80a6f/docs/en/guide/emitter-overview.md
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: adapt_rust
// test: bundle:rust/src/rust_adapter.rs

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RepositoryKind {
    RustOnly,
    Mixed,
    #[allow(
        dead_code,
        reason = "stable unsupported-profile rejection is unit tested"
    )]
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RustLayout {
    CargoWorkspace,
    #[allow(
        dead_code,
        reason = "stable unsupported-layout rejection is unit tested"
    )]
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FilePresence {
    Present,
    #[allow(dead_code, reason = "stable missing-file rejection is unit tested")]
    Missing,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RustProjectDraft {
    pub(crate) repository_kind: Option<RepositoryKind>,
    pub(crate) layout: Option<RustLayout>,
    pub(crate) manifest: Option<FilePresence>,
    pub(crate) lockfile: Option<FilePresence>,
    pub(crate) deny_config: Option<FilePresence>,
    pub(crate) working_directory: Option<String>,
}

closed_id!(RustCheckId {
    CargoAudit => "rust.cargo-audit",
    CargoDeny => "rust.cargo-deny",
    Clippy => "rust.clippy",
    Rustfmt => "rust.rustfmt",
    Tests => "rust.tests",
});

closed_id!(RustToolId {
    Cargo => "cargo",
    CargoAudit => "cargo-audit",
    CargoDeny => "cargo-deny",
    Clippy => "clippy",
    Rustfmt => "rustfmt",
});

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
    id: RustCheckId,
    kind: CheckKind,
    tool: RustToolId,
    argv: Vec<String>,
    dependencies: Vec<RustCheckId>,
    working_directory: WorkingDirectory,
    timeout_seconds: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct RustCheckSet {
    catalog_version: String,
    catalog_sha256: String,
    toolchain_sha256: String,
    governance_ir: GovernanceIr,
}

impl RustCheckSet {
    pub(crate) fn into_plan_inputs(self) -> (GovernanceIr, String) {
        (self.governance_ir, self.toolchain_sha256)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("{0}")]
pub(crate) struct RustAdapterError(&'static str);

impl RustAdapterError {
    const PROJECT_INCOMPLETE: Self = Self("RUST_ADAPTER_PROJECT_INCOMPLETE");
    const LAYOUT_UNSUPPORTED: Self = Self("RUST_ADAPTER_LAYOUT_UNSUPPORTED");
    const RECIPE_CATALOG_INVALID: Self = Self("RUST_ADAPTER_RECIPE_CATALOG_INVALID");
    const TOOLCHAIN_CATALOG_INVALID: Self = Self("RUST_ADAPTER_TOOLCHAIN_CATALOG_INVALID");
    const GIR_REJECTED: Self = Self("RUST_ADAPTER_GIR_REJECTED");

    pub(crate) const fn code(self) -> &'static str {
        self.0
    }
}

fn parse_rust_recipe_catalog(bytes: &str) -> Result<Vec<Recipe>, RustAdapterError> {
    let mut draft: RecipeCatalogDraft =
        serde_json::from_str(bytes).map_err(|_| RustAdapterError::RECIPE_CATALOG_INVALID)?;
    if sha256_hex(bytes.as_bytes()) != RECIPE_SHA256
        || draft.schema_version != RECIPE_SCHEMA
        || draft.language != Language::Rust
    {
        return Err(RustAdapterError::RECIPE_CATALOG_INVALID);
    }
    draft.recipes.sort_by_key(|recipe| recipe.id);
    Ok(draft.recipes)
}

pub(crate) fn execution_recipes() -> Result<Vec<ExecutionRecipe>, RustAdapterError> {
    parse_rust_recipe_catalog(RECIPE_BYTES)?
        .into_iter()
        .map(|recipe| {
            match recipe.working_directory {
                WorkingDirectory::ProjectRoot => {}
            }
            let argv = recipe
                .argv
                .into_iter()
                .map(RecipeArg::literal)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| RustAdapterError::RECIPE_CATALOG_INVALID)?;
            ExecutionRecipe::resolve(ExecutionRecipeDraft {
                argv,
                dependencies: recipe
                    .dependencies
                    .iter()
                    .map(|dependency| dependency.as_str().into())
                    .collect(),
                identifier: recipe.id.as_str().into(),
                input_artifacts: Vec::new(),
                kind: recipe.kind,
                language: Language::Rust,
                output_artifacts: Vec::new(),
                timeout_seconds: recipe.timeout_seconds,
                tool_identity: recipe.tool.as_str().into(),
            })
            .map_err(|_| RustAdapterError::RECIPE_CATALOG_INVALID)
        })
        .collect()
}

pub(crate) fn adapt_rust(project: RustProjectDraft) -> Result<RustCheckSet, RustAdapterError> {
    match project
        .repository_kind
        .ok_or(RustAdapterError::PROJECT_INCOMPLETE)?
    {
        RepositoryKind::RustOnly | RepositoryKind::Mixed => {}
        RepositoryKind::Unsupported => return Err(RustAdapterError::LAYOUT_UNSUPPORTED),
    }
    match project.layout.ok_or(RustAdapterError::PROJECT_INCOMPLETE)? {
        RustLayout::CargoWorkspace => {}
        RustLayout::Unsupported => return Err(RustAdapterError::LAYOUT_UNSUPPORTED),
    }
    if project.manifest != Some(FilePresence::Present)
        || project.lockfile != Some(FilePresence::Present)
        || project.deny_config != Some(FilePresence::Present)
    {
        return Err(RustAdapterError::PROJECT_INCOMPLETE);
    }
    let working_directory = project
        .working_directory
        .ok_or(RustAdapterError::PROJECT_INCOMPLETE)?;
    let recipes = parse_rust_recipe_catalog(RECIPE_BYTES)?;
    let mut drafts = Vec::with_capacity(recipes.len());
    for recipe in recipes {
        let version = tool_version(TOOLCHAIN_BYTES, "rust", recipe.tool.as_str())
            .map_err(|_| RustAdapterError::TOOLCHAIN_CATALOG_INVALID)?;
        let recipe_workdir = match recipe.working_directory {
            WorkingDirectory::ProjectRoot => working_directory.clone(),
        };
        drafts.push(CheckDraft {
            identifier: Some(recipe.id.as_str().into()),
            language: Some(Language::Rust),
            kind: Some(recipe.kind),
            tool_identity: Some(recipe.tool.as_str().into()),
            tool_version: Some(version),
            path: Some(recipe_workdir),
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
        GovernanceIr::resolve(drafts).map_err(|_| RustAdapterError::GIR_REJECTED)?;
    Ok(RustCheckSet {
        catalog_version: RECIPE_SCHEMA.into(),
        catalog_sha256: sha256_hex(RECIPE_BYTES.as_bytes()),
        toolchain_sha256: sha256_hex(TOOLCHAIN_BYTES.as_bytes()),
        governance_ir,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(kind: RepositoryKind, path: &str) -> RustProjectDraft {
        RustProjectDraft {
            repository_kind: Some(kind),
            layout: Some(RustLayout::CargoWorkspace),
            manifest: Some(FilePresence::Present),
            lockfile: Some(FilePresence::Present),
            deny_config: Some(FilePresence::Present),
            working_directory: Some(path.into()),
        }
    }

    fn assert_error(result: Result<RustCheckSet, RustAdapterError>, expected: &'static str) {
        assert_eq!(
            expected,
            result.err().map_or("resolved", RustAdapterError::code)
        );
    }

    #[test]
    fn rust_only_fixture_has_exact_deterministic_check_set()
    -> Result<(), Box<dyn std::error::Error>> {
        let checks = adapt_rust(project(RepositoryKind::RustOnly, "."))?;
        assert_eq!(
            serde_json::to_vec(&checks)?,
            serde_json::to_vec(&adapt_rust(project(RepositoryKind::RustOnly, "."))?)?
        );
        let encoded = serde_json::to_value(checks)?;
        let checks = encoded["governance_ir"]["checks"]
            .as_array()
            .ok_or("GIR checks are not an array")?;
        assert_eq!(5, checks.len());
        assert_eq!("0.1", encoded["catalog_version"]);
        assert_eq!(RECIPE_SHA256, encoded["catalog_sha256"]);
        assert_eq!(
            sha256_hex(TOOLCHAIN_BYTES.as_bytes()),
            encoded["toolchain_sha256"]
        );
        assert_eq!("0.22.2", checks[0]["tool"]["version"]);
        assert_eq!("1.97.1", checks[4]["tool"]["version"]);
        assert!(checks.iter().all(|check| check["path"] == "."));
        assert!(!serde_json::to_string(&encoded)?.contains("\"argv\""));
        assert_eq!(
            [
                "rust.cargo-audit",
                "rust.cargo-deny",
                "rust.clippy",
                "rust.rustfmt",
                "rust.tests"
            ],
            checks
                .iter()
                .map(|check| check["identifier"].as_str().unwrap_or_default())
                .collect::<Vec<_>>()
                .as_slice()
        );
        Ok(())
    }

    #[test]
    fn mixed_fixture_changes_only_the_explicit_workdir() -> Result<(), Box<dyn std::error::Error>> {
        let root = serde_json::to_value(adapt_rust(project(RepositoryKind::RustOnly, "."))?)?;
        let mixed = serde_json::to_value(adapt_rust(project(RepositoryKind::Mixed, "rust"))?)?;
        assert_eq!(root["catalog_sha256"], mixed["catalog_sha256"]);
        assert_eq!(root["toolchain_sha256"], mixed["toolchain_sha256"]);
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
            assert_eq!("rust", mixed["path"]);
        }
        Ok(())
    }

    #[test]
    fn incomplete_and_unsupported_projects_fail_closed() {
        assert_error(
            adapt_rust(project(RepositoryKind::Unsupported, ".")),
            "RUST_ADAPTER_LAYOUT_UNSUPPORTED",
        );
        let mut missing_lock = project(RepositoryKind::RustOnly, ".");
        missing_lock.lockfile = Some(FilePresence::Missing);
        assert_error(adapt_rust(missing_lock), "RUST_ADAPTER_PROJECT_INCOMPLETE");
        let mut missing_config = project(RepositoryKind::RustOnly, ".");
        missing_config.deny_config = None;
        assert_error(
            adapt_rust(missing_config),
            "RUST_ADAPTER_PROJECT_INCOMPLETE",
        );
        let mut unsupported_layout = project(RepositoryKind::RustOnly, ".");
        unsupported_layout.layout = Some(RustLayout::Unsupported);
        assert_error(
            adapt_rust(unsupported_layout),
            "RUST_ADAPTER_LAYOUT_UNSUPPORTED",
        );
        assert_error(
            adapt_rust(project(RepositoryKind::Mixed, "../rust")),
            "RUST_ADAPTER_GIR_REJECTED",
        );
    }

    #[test]
    fn bundled_recipe_catalog_owns_exact_commands() -> Result<(), Box<dyn std::error::Error>> {
        let recipes = parse_rust_recipe_catalog(RECIPE_BYTES)?;
        assert_eq!(RECIPE_SHA256, sha256_hex(RECIPE_BYTES.as_bytes()));
        let expected = [
            (
                "rust.cargo-audit",
                &[
                    "cargo",
                    "audit",
                    "--no-fetch",
                    "--deny",
                    "warnings",
                    "--file",
                    "Cargo.lock",
                ][..],
                180,
            ),
            (
                "rust.cargo-deny",
                &[
                    "cargo",
                    "deny",
                    "--manifest-path",
                    "Cargo.toml",
                    "--config",
                    "deny.toml",
                    "--workspace",
                    "--locked",
                    "--offline",
                    "--all-features",
                    "check",
                    "advisories",
                    "bans",
                    "licenses",
                    "sources",
                ],
                300,
            ),
            (
                "rust.clippy",
                &[
                    "cargo",
                    "clippy",
                    "--workspace",
                    "--all-targets",
                    "--all-features",
                    "--locked",
                    "--offline",
                    "--",
                    "-D",
                    "warnings",
                ],
                300,
            ),
            ("rust.rustfmt", &["cargo", "fmt", "--all", "--check"], 60),
            (
                "rust.tests",
                &[
                    "cargo",
                    "test",
                    "--workspace",
                    "--all-features",
                    "--locked",
                    "--offline",
                ],
                600,
            ),
        ];
        assert_eq!(expected.len(), recipes.len());
        for (recipe, (id, argv, timeout)) in recipes.iter().zip(expected) {
            assert_eq!(id, recipe.id.as_str());
            assert_eq!(
                argv,
                recipe.argv.iter().map(String::as_str).collect::<Vec<_>>()
            );
            assert!(recipe.dependencies.is_empty());
            assert_eq!(timeout, recipe.timeout_seconds);
        }
        Ok(())
    }

    #[test]
    fn recipe_and_toolchain_mutations_fail_without_partial_output()
    -> Result<(), Box<dyn std::error::Error>> {
        for mutated in [
            RECIPE_BYTES.replacen(
                "\"schema_version\": \"0.1\"",
                "\"schema_version\": \"9\"",
                1,
            ),
            RECIPE_BYTES.replacen("\"--locked\"", "\"--offline\"", 1),
            RECIPE_BYTES.replacen("\"rust.tests\"", "\"rust.unknown\"", 1),
            RECIPE_BYTES.replacen("\"rust.tests\"", "\"rust.rustfmt\"", 1),
        ] {
            assert_eq!(
                Some("RUST_ADAPTER_RECIPE_CATALOG_INVALID"),
                parse_rust_recipe_catalog(&mutated)
                    .err()
                    .map(RustAdapterError::code)
            );
        }
        for (tool, version) in [
            (RustToolId::Cargo, "1.97.1"),
            (RustToolId::CargoAudit, "0.22.2"),
            (RustToolId::CargoDeny, "0.20.2"),
            (RustToolId::Clippy, "0.1.97"),
            (RustToolId::Rustfmt, "1.9.0"),
        ] {
            assert_eq!(
                version,
                tool_version(TOOLCHAIN_BYTES, "rust", tool.as_str())?
            );
        }
        let wrong_language = TOOLCHAIN_BYTES.replacen(
            "\"id\": \"clippy\", \"language\": \"rust\"",
            "\"id\": \"clippy\", \"language\": \"python\"",
            1,
        );
        assert!(tool_version(&wrong_language, "rust", RustToolId::Clippy.as_str()).is_err());
        Ok(())
    }
}
