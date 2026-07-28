//! Canonical, digest-bound execution plans derived from resolved governance IR.

use super::{
    CheckId, CheckKind, Dependency, GovernanceIr, Language, ResolvedCheck,
    execution_recipe::{ExecutionRecipe, RecipeArg},
};
use serde::{Serialize, Serializer, ser::Error as _};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const PLAN_SCHEMA_VERSION: &str = "0.1";

// LLM-CONTRACT
// id: agent-work-governor.canonical-execution-plan
// state: RESOLVED_GOVERNANCE_IR + DIGEST_BOUND_LANGUAGE_RECIPES -> CANONICAL_EXECUTION_PLAN | PLAN_REJECTED
// preconditions: the typed IR and digest-bound adapter recipes are complete and explicit
// invariant: emit joins exact recipe data and emits canonical bytes without inference or execution
// failure: emit returns one stable PLAN reason code without bytes or a digest
// source: https://github.com/cyberphone/json-canonicalization/blob/19d51d7fe467d4706a3ff08adf8a748f29fc21e0/README.md
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: emit
// test: bundle:rust/src/governance_ir/execution_plan.rs

/// Opaque canonical plan with exact JSON bytes and their SHA-256 digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalExecutionPlan {
    canonical_json: Vec<u8>,
    sha256: String,
}

impl CanonicalExecutionPlan {
    /// Exact canonical JSON bytes covered by [`Self::sha256`].
    #[must_use]
    pub fn canonical_json(&self) -> &[u8] {
        &self.canonical_json
    }

    /// Lowercase SHA-256 digest of [`Self::canonical_json`].
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

impl Serialize for CanonicalExecutionPlan {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_json::from_slice::<serde_json::Value>(&self.canonical_json)
            .map_err(S::Error::custom)?
            .serialize(serializer)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("{0}")]
pub(crate) struct PlanError(&'static str);

impl PlanError {
    const EMPTY: Self = Self("PLAN_EMPTY");
    const CYCLE: Self = Self("PLAN_CYCLE");
    const CATALOG_INVALID: Self = Self("PLAN_CATALOG_INVALID");
    const UNKNOWN_CHECK: Self = Self("PLAN_UNKNOWN_CHECK");
    const RECIPE_MISMATCH: Self = Self("PLAN_RECIPE_MISMATCH");
    const ENCODING_FAILED: Self = Self("PLAN_ENCODING_FAILED");

    pub(crate) const fn code(self) -> &'static str {
        self.0
    }

    pub(crate) fn is_encoding_failed(self) -> bool {
        self.0 == Self::ENCODING_FAILED.0
    }
}

pub(crate) struct PlanEmitter;

impl PlanEmitter {
    pub(crate) fn emit(ir: &GovernanceIr) -> Result<CanonicalExecutionPlan, PlanError> {
        if ir.checks.is_empty() {
            return Err(PlanError::EMPTY);
        }
        let recipes = closed_recipes()?;
        let checks = topological_checks(ir)?
            .into_iter()
            .map(|check| bind(check, &recipes).map(PlanCheck::from))
            .collect::<Result<Vec<_>, _>>()?;
        let canonical_json = serde_json::to_vec(&PlanDocument {
            checks,
            schema_version: PLAN_SCHEMA_VERSION,
        })
        .map_err(|_| PlanError::ENCODING_FAILED)?;
        Ok(CanonicalExecutionPlan {
            sha256: crate::adapter_catalog::sha256_hex(&canonical_json),
            canonical_json,
        })
    }
}

fn topological_checks(ir: &GovernanceIr) -> Result<Vec<&ResolvedCheck>, PlanError> {
    let mut emitted = BTreeSet::<&CheckId>::new();
    let mut ordered = Vec::with_capacity(ir.checks.len());
    while ordered.len() < ir.checks.len() {
        let Some(check) = ir.checks.iter().find(|check| {
            !emitted.contains(&check.identifier)
                && check
                    .dependencies
                    .iter()
                    .all(|dependency| emitted.contains(&dependency.0))
        }) else {
            return Err(PlanError::CYCLE);
        };
        emitted.insert(&check.identifier);
        ordered.push(check);
    }
    Ok(ordered)
}

fn closed_recipes() -> Result<Vec<ExecutionRecipe>, PlanError> {
    let mut recipes =
        crate::python_adapter::execution_recipes().map_err(|_| PlanError::CATALOG_INVALID)?;
    recipes
        .extend(crate::rust_adapter::execution_recipes().map_err(|_| PlanError::CATALOG_INVALID)?);
    recipes.sort_by(|left, right| left.identifier().cmp(right.identifier()));
    if recipes
        .windows(2)
        .any(|pair| pair[0].identifier() == pair[1].identifier())
    {
        return Err(PlanError::CATALOG_INVALID);
    }
    validate_recipe_graph(&recipes)?;
    Ok(recipes)
}

// LLM-CONTRACT
// id: agent-work-governor.closed-artifact-graph
// state: TYPED_EXECUTION_RECIPES -> CLOSED_ARTIFACT_GRAPH | PLAN_CATALOG_INVALID
// preconditions: recipe identifiers, dependencies, and artifact directions are explicit
// invariant: every input has one producer reachable through an acyclic dependency graph
// failure: graph validation rejects the whole catalog without returning a partial plan
// source: repo:adapters/check-recipes.v1.LLM-CONTRACT.md
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: validate_recipe_graph
// test: bundle:rust/src/governance_ir/execution_plan.rs
fn validate_recipe_graph(recipes: &[ExecutionRecipe]) -> Result<(), PlanError> {
    let by_id = recipes
        .iter()
        .map(|recipe| (recipe.identifier(), recipe))
        .collect::<BTreeMap<_, _>>();
    let mut emitted = BTreeSet::new();
    while emitted.len() < recipes.len() {
        let Some(recipe) = recipes.iter().find(|recipe| {
            !emitted.contains(recipe.identifier())
                && recipe
                    .dependencies()
                    .iter()
                    .all(|dependency| emitted.contains(dependency.as_str()))
        }) else {
            return Err(PlanError::CATALOG_INVALID);
        };
        emitted.insert(recipe.identifier());
    }

    let mut producers = BTreeMap::new();
    for recipe in recipes {
        for artifact in recipe.output_artifacts() {
            if producers
                .insert(artifact.as_str(), recipe.identifier())
                .is_some()
            {
                return Err(PlanError::CATALOG_INVALID);
            }
        }
    }
    for recipe in recipes {
        for artifact in recipe.input_artifacts() {
            let producer = producers
                .get(artifact.as_str())
                .ok_or(PlanError::CATALOG_INVALID)?;
            if !dependency_reaches(recipe, producer, &by_id) {
                return Err(PlanError::CATALOG_INVALID);
            }
        }
    }
    Ok(())
}

fn dependency_reaches<'a>(
    consumer: &'a ExecutionRecipe,
    producer: &str,
    by_id: &BTreeMap<&'a str, &'a ExecutionRecipe>,
) -> bool {
    let mut pending = consumer
        .dependencies()
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let mut visited = BTreeSet::new();
    while let Some(dependency) = pending.pop() {
        if dependency == producer {
            return true;
        }
        if !visited.insert(dependency) {
            continue;
        }
        let Some(recipe) = by_id.get(dependency) else {
            return false;
        };
        pending.extend(recipe.dependencies().iter().map(String::as_str));
    }
    false
}

fn bind<'a>(
    check: &'a ResolvedCheck,
    recipes: &'a [ExecutionRecipe],
) -> Result<(&'a ResolvedCheck, &'a ExecutionRecipe), PlanError> {
    let recipe = recipes
        .binary_search_by(|recipe| recipe.identifier().cmp(&check.identifier.0))
        .map(|index| &recipes[index])
        .map_err(|_| PlanError::UNKNOWN_CHECK)?;
    let dependencies_match = recipe.dependencies().iter().map(String::as_str).eq(check
        .dependencies
        .iter()
        .map(|dependency| dependency.0.0.as_str()));
    if recipe.language() == check.language
        && recipe.kind() == check.kind
        && recipe.tool_identity() == check.tool.identity
        && dependencies_match
    {
        Ok((check, recipe))
    } else {
        Err(PlanError::RECIPE_MISMATCH)
    }
}

#[derive(Serialize)]
struct PlanDocument<'a> {
    checks: Vec<PlanCheck<'a>>,
    schema_version: &'static str,
}

#[derive(Serialize)]
struct PlanCheck<'a> {
    argv: &'a [RecipeArg],
    dependencies: &'a [Dependency],
    identifier: &'a CheckId,
    input_artifacts: &'a [String],
    kind: CheckKind,
    language: Language,
    output_artifacts: &'a [String],
    path: &'a str,
    timeout_seconds: u16,
    tool: PlanTool<'a>,
}

impl<'a> From<(&'a ResolvedCheck, &'a ExecutionRecipe)> for PlanCheck<'a> {
    fn from((check, recipe): (&'a ResolvedCheck, &'a ExecutionRecipe)) -> Self {
        Self {
            argv: recipe.argv(),
            dependencies: &check.dependencies,
            identifier: &check.identifier,
            input_artifacts: recipe.input_artifacts(),
            kind: check.kind,
            language: check.language,
            output_artifacts: recipe.output_artifacts(),
            path: &check.path,
            timeout_seconds: recipe.timeout_seconds(),
            tool: PlanTool {
                identity: &check.tool.identity,
                version: &check.tool.version,
            },
        }
    }
}

#[derive(Serialize)]
struct PlanTool<'a> {
    identity: &'a str,
    version: &'a str,
}

#[cfg(test)]
mod tests {
    use super::super::CheckDraft;
    use super::super::execution_recipe::ExecutionRecipeDraft;
    use super::*;
    use std::error::Error as StdError;

    fn draft(
        id: &str,
        language: Language,
        kind: CheckKind,
        tool: &str,
        path: &str,
        dependencies: &[&str],
    ) -> CheckDraft {
        CheckDraft {
            identifier: Some(id.into()),
            language: Some(language),
            kind: Some(kind),
            tool_identity: Some(tool.into()),
            tool_version: Some(
                if language == Language::Python {
                    "0.11.33"
                } else {
                    "1.97.1"
                }
                .into(),
            ),
            path: Some(path.into()),
            dependencies: Some(dependencies.iter().map(|value| (*value).into()).collect()),
        }
    }

    fn fixtures() -> Vec<CheckDraft> {
        vec![
            draft(
                "rust.tests",
                Language::Rust,
                CheckKind::Test,
                "cargo",
                "rust",
                &[],
            ),
            draft(
                "python.uv-export",
                Language::Python,
                CheckKind::Dependency,
                "uv",
                ".",
                &["python.uv-lock"],
            ),
            draft(
                "python.uv-lock",
                Language::Python,
                CheckKind::Dependency,
                "uv",
                ".",
                &[],
            ),
        ]
    }

    fn assert_error(result: Result<CanonicalExecutionPlan, PlanError>, expected: &str) {
        assert_eq!(expected, result.err().map_or("planned", PlanError::code));
    }

    fn recipe(
        identifier: &str,
        dependencies: &[&str],
        input_artifacts: &[&str],
        output_artifacts: &[&str],
    ) -> Result<ExecutionRecipe, Box<dyn StdError>> {
        let argv = std::iter::once(RecipeArg::literal("tool".into())?)
            .chain(
                input_artifacts
                    .iter()
                    .chain(output_artifacts)
                    .map(|artifact| RecipeArg::artifact((*artifact).into()))
                    .collect::<Result<Vec<_>, _>>()?,
            )
            .collect();
        Ok(ExecutionRecipe::resolve(ExecutionRecipeDraft {
            argv,
            dependencies: dependencies
                .iter()
                .map(|dependency| (*dependency).into())
                .collect(),
            identifier: identifier.into(),
            input_artifacts: input_artifacts
                .iter()
                .map(|artifact| (*artifact).into())
                .collect(),
            kind: CheckKind::Test,
            language: Language::Rust,
            output_artifacts: output_artifacts
                .iter()
                .map(|artifact| (*artifact).into())
                .collect(),
            timeout_seconds: 1,
            tool_identity: "tool".into(),
        })?)
    }

    #[test]
    fn mixed_golden_is_canonical_and_digest_bound() -> Result<(), Box<dyn StdError>> {
        let plan = PlanEmitter::emit(&GovernanceIr::resolve(fixtures())?)?;
        assert_eq!(
            br#"{"checks":[{"argv":["uv","lock","--check"],"dependencies":[],"identifier":"python.uv-lock","input_artifacts":[],"kind":"dependency","language":"python","output_artifacts":[],"path":".","timeout_seconds":60,"tool":{"identity":"uv","version":"0.11.33"}},{"argv":["uv","export","--quiet","--locked","--all-extras","--all-groups","--no-emit-workspace","--format","requirements.txt","--output-file",{"artifact":"python-audit-requirements"}],"dependencies":["python.uv-lock"],"identifier":"python.uv-export","input_artifacts":[],"kind":"dependency","language":"python","output_artifacts":["python-audit-requirements"],"path":".","timeout_seconds":60,"tool":{"identity":"uv","version":"0.11.33"}},{"argv":["cargo","test","--workspace","--all-features","--locked","--offline"],"dependencies":[],"identifier":"rust.tests","input_artifacts":[],"kind":"test","language":"rust","output_artifacts":[],"path":"rust","timeout_seconds":600,"tool":{"identity":"cargo","version":"1.97.1"}}],"schema_version":"0.1"}"#,
            plan.canonical_json.as_slice()
        );
        assert_eq!(
            "853f8cf3d4ef642e0be5d4f0724f947f0326e8c3ee14201d62d45ce3ce7b215f",
            plan.sha256
        );
        let encoded = String::from_utf8(plan.canonical_json)?;
        assert!(
            ["command", "authority", "capability", "verdict", "receipt"]
                .iter()
                .all(|forbidden| !encoded.contains(forbidden))
        );
        Ok(())
    }

    #[test]
    fn equivalent_ir_is_byte_identical() -> Result<(), Box<dyn StdError>> {
        let expected = PlanEmitter::emit(&GovernanceIr::resolve(fixtures())?)?;
        let mut reversed = fixtures();
        reversed.reverse();
        assert_eq!(
            expected,
            PlanEmitter::emit(&GovernanceIr::resolve(reversed)?)?
        );
        Ok(())
    }

    #[test]
    fn artifact_graph_requires_one_reachable_producer() -> Result<(), Box<dyn StdError>> {
        let producer = recipe("check.producer", &[], &[], &["artifact"])?;
        let intermediary = recipe("check.intermediary", &["check.producer"], &[], &[])?;
        let consumer = recipe(
            "check.consumer",
            &["check.intermediary"],
            &["artifact"],
            &[],
        )?;
        assert_eq!(
            Ok(()),
            validate_recipe_graph(&[consumer.clone(), intermediary, producer.clone()])
        );

        let missing = recipe("check.missing", &[], &["missing"], &[])?;
        assert_eq!(
            Err(PlanError::CATALOG_INVALID),
            validate_recipe_graph(&[missing])
        );

        let unreachable = recipe("check.unreachable", &[], &["artifact"], &[])?;
        assert_eq!(
            Err(PlanError::CATALOG_INVALID),
            validate_recipe_graph(&[producer.clone(), unreachable])
        );

        let duplicate = recipe("check.duplicate", &[], &[], &["artifact"])?;
        assert_eq!(
            Err(PlanError::CATALOG_INVALID),
            validate_recipe_graph(&[producer, duplicate])
        );
        Ok(())
    }

    #[test]
    fn artifact_graph_rejects_unknown_or_cyclic_dependencies() -> Result<(), Box<dyn StdError>> {
        let unknown = recipe("check.unknown", &["check.missing"], &[], &[])?;
        assert_eq!(
            Err(PlanError::CATALOG_INVALID),
            validate_recipe_graph(&[unknown])
        );
        let left = recipe("check.left", &["check.right"], &[], &[])?;
        let right = recipe("check.right", &["check.left"], &[], &[])?;
        assert_eq!(
            Err(PlanError::CATALOG_INVALID),
            validate_recipe_graph(&[left, right])
        );
        Ok(())
    }

    #[test]
    fn empty_cycle_unknown_and_mismatch_fail_closed() -> Result<(), Box<dyn StdError>> {
        assert_error(
            PlanEmitter::emit(&GovernanceIr::resolve(Vec::new())?),
            "PLAN_EMPTY",
        );
        let cycle = GovernanceIr::resolve(vec![
            draft(
                "check.a",
                Language::Rust,
                CheckKind::Test,
                "cargo",
                ".",
                &["check.b"],
            ),
            draft(
                "check.b",
                Language::Rust,
                CheckKind::Test,
                "cargo",
                ".",
                &["check.a"],
            ),
        ])?;
        assert_error(PlanEmitter::emit(&cycle), "PLAN_CYCLE");
        let unknown = GovernanceIr::resolve(vec![draft(
            "rust.unknown",
            Language::Rust,
            CheckKind::Test,
            "cargo",
            ".",
            &[],
        )])?;
        assert_error(PlanEmitter::emit(&unknown), "PLAN_UNKNOWN_CHECK");
        let mut mismatch = fixtures().pop().ok_or("missing fixture")?;
        mismatch.kind = Some(CheckKind::Lint);
        assert_error(
            PlanEmitter::emit(&GovernanceIr::resolve(vec![mismatch])?),
            "PLAN_RECIPE_MISMATCH",
        );
        Ok(())
    }
}
