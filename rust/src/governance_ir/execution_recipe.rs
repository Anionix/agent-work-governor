//! Typed projection of digest-bound language recipe catalogs.

use super::{CheckKind, Language};
use serde::Serialize;
use std::collections::BTreeSet;
use thiserror::Error;

// LLM-CONTRACT
// id: agent-work-governor.typed-execution-recipe
// state: DIGEST_BOUND_RECIPE_DRAFT -> TYPED_EXECUTION_RECIPE | RECIPE_REJECTED
// preconditions: the language adapter has validated its immutable recipe catalog
// invariant: argv atoms and execution metadata remain typed and contain no consumer text
// failure: the adapter returns no recipe projection when catalog validation fails
// source: https://github.com/yaneurao/Pytra/blob/9f341e04fefd8eacac1081c59e80f4042ee80a6f/docs/en/guide/emitter-overview.md
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: resolve
// test: bundle:rust/src/governance_ir/execution_plan.rs

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub(crate) struct RecipeArg(RecipeArgValue);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
enum RecipeArgValue {
    Literal(String),
    Artifact { artifact: String },
}

impl RecipeArg {
    pub(crate) fn literal(value: String) -> Result<Self, ExecutionRecipeError> {
        if value.is_empty()
            || !value.is_ascii()
            || value.bytes().any(|byte| byte.is_ascii_control())
        {
            Err(ExecutionRecipeError)
        } else {
            Ok(Self(RecipeArgValue::Literal(value)))
        }
    }

    pub(crate) fn artifact(value: String) -> Result<Self, ExecutionRecipeError> {
        if portable_token(&value) {
            Ok(Self(RecipeArgValue::Artifact { artifact: value }))
        } else {
            Err(ExecutionRecipeError)
        }
    }

    fn artifact_name(&self) -> Option<&str> {
        match &self.0 {
            RecipeArgValue::Literal(_) => None,
            RecipeArgValue::Artifact { artifact } => Some(artifact),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecutionRecipeDraft {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExecutionRecipe {
    argv: Vec<RecipeArg>,
    dependencies: Vec<String>,
    identifier: String,
    input_artifacts: Vec<String>,
    kind: CheckKind,
    language: Language,
    output_artifacts: Vec<String>,
    timeout_seconds: u16,
    tool_identity: String,
}

impl ExecutionRecipe {
    pub(crate) fn resolve(mut draft: ExecutionRecipeDraft) -> Result<Self, ExecutionRecipeError> {
        draft.dependencies.sort();
        draft.input_artifacts.sort();
        draft.output_artifacts.sort();
        let metadata = draft
            .dependencies
            .iter()
            .chain(&draft.input_artifacts)
            .chain(&draft.output_artifacts);
        let unique = [
            &draft.dependencies,
            &draft.input_artifacts,
            &draft.output_artifacts,
        ]
        .iter()
        .all(|values| values.windows(2).all(|pair| pair[0] != pair[1]));
        let declared_artifacts = draft
            .input_artifacts
            .iter()
            .chain(&draft.output_artifacts)
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let argv_artifacts = draft
            .argv
            .iter()
            .filter_map(RecipeArg::artifact_name)
            .collect::<BTreeSet<_>>();
        let directions_are_disjoint = draft
            .input_artifacts
            .iter()
            .all(|artifact| draft.output_artifacts.binary_search(artifact).is_err());
        if draft.argv.is_empty()
            || draft.timeout_seconds == 0
            || !portable_token(&draft.identifier)
            || !portable_token(&draft.tool_identity)
            || !metadata.into_iter().all(|value| portable_token(value))
            || !unique
            || !directions_are_disjoint
            || argv_artifacts != declared_artifacts
        {
            return Err(ExecutionRecipeError);
        }
        Ok(Self {
            argv: draft.argv,
            dependencies: draft.dependencies,
            identifier: draft.identifier,
            input_artifacts: draft.input_artifacts,
            kind: draft.kind,
            language: draft.language,
            output_artifacts: draft.output_artifacts,
            timeout_seconds: draft.timeout_seconds,
            tool_identity: draft.tool_identity,
        })
    }

    pub(super) fn argv(&self) -> &[RecipeArg] {
        &self.argv
    }

    pub(super) fn dependencies(&self) -> &[String] {
        &self.dependencies
    }

    pub(super) fn identifier(&self) -> &str {
        &self.identifier
    }

    pub(super) fn input_artifacts(&self) -> &[String] {
        &self.input_artifacts
    }

    pub(super) const fn kind(&self) -> CheckKind {
        self.kind
    }

    pub(super) const fn language(&self) -> Language {
        self.language
    }

    pub(super) fn output_artifacts(&self) -> &[String] {
        &self.output_artifacts
    }

    pub(super) const fn timeout_seconds(&self) -> u16 {
        self.timeout_seconds
    }

    pub(super) fn tool_identity(&self) -> &str {
        &self.tool_identity
    }
}

fn portable_token(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .zip(value.as_bytes().last())
        .is_some_and(|(first, last)| first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("EXECUTION_RECIPE_INVALID")]
pub(crate) struct ExecutionRecipeError;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as StdError;

    #[test]
    fn resolved_recipes_reject_invalid_primitives() -> Result<(), Box<dyn StdError>> {
        assert!(RecipeArg::literal(String::new()).is_err());
        assert!(RecipeArg::literal("bad\0argv".into()).is_err());
        assert!(RecipeArg::artifact("../artifact".into()).is_err());
        let draft = ExecutionRecipeDraft {
            argv: vec![RecipeArg::literal("tool".into())?],
            dependencies: Vec::new(),
            identifier: "check.valid".into(),
            input_artifacts: Vec::new(),
            kind: CheckKind::Test,
            language: Language::Rust,
            output_artifacts: Vec::new(),
            timeout_seconds: 0,
            tool_identity: "tool".into(),
        };
        assert!(ExecutionRecipe::resolve(draft).is_err());
        let undeclared_artifact = ExecutionRecipeDraft {
            argv: vec![
                RecipeArg::literal("tool".into())?,
                RecipeArg::artifact("artifact".into())?,
            ],
            dependencies: Vec::new(),
            identifier: "check.valid".into(),
            input_artifacts: Vec::new(),
            kind: CheckKind::Test,
            language: Language::Rust,
            output_artifacts: Vec::new(),
            timeout_seconds: 1,
            tool_identity: "tool".into(),
        };
        assert!(ExecutionRecipe::resolve(undeclared_artifact).is_err());
        Ok(())
    }
}
