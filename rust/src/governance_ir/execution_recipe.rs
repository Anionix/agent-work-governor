//! Typed projection of digest-bound language recipe catalogs.

use super::{CheckKind, Language};
use serde::Serialize;

// LLM-CONTRACT
// id: agent-work-governor.typed-execution-recipe
// state: DIGEST_BOUND_LANGUAGE_RECIPE -> TYPED_EXECUTION_RECIPE | RECIPE_REJECTED
// preconditions: the language adapter has validated its immutable recipe catalog
// invariant: argv atoms and execution metadata remain typed and contain no consumer text
// failure: the adapter returns no recipe projection when catalog validation fails
// source: https://github.com/yaneurao/Pytra/blob/9f341e04fefd8eacac1081c59e80f4042ee80a6f/docs/en/guide/emitter-overview.md
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: ExecutionRecipe
// test: bundle:rust/src/governance_ir/execution_plan.rs

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub(crate) enum RecipeArg {
    Literal(String),
    Artifact { artifact: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecutionRecipe {
    pub(crate) argv: Vec<RecipeArg>,
    pub(crate) dependencies: Vec<String>,
    pub(crate) identifier: String,
    pub(crate) input_artifacts: Vec<String>,
    pub(crate) kind: CheckKind,
    pub(crate) language: Language,
    pub(crate) output_artifacts: Vec<String>,
    pub(crate) timeout_seconds: u16,
    pub(crate) tool_identity: String,
}
