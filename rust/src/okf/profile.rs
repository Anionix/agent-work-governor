use std::path::Path;

use serde_json::{Map, Value};

use crate::model::Finding;

use super::issue;
use super::resources::resource_exists;
use super::scalars::{valid_actor, valid_date, valid_datetime};

// LLM-CONTRACT
// id: agent-work-governor.rust-okf-profile
// state: PARSED_METADATA -> GOVERNOR_PROFILE_CHECKS -> VALID | INVALID
// preconditions: JSON-compatible metadata, body text, document path, and bundle are explicit
// invariant: profile failures retain Python-compatible reason codes and ordering
// failure: append deterministic profile findings without changing OKF core conformance
// source: bundle:scripts/validate_okf.py
// knowledge: bundle:knowledge/references/okf-v0.2.md
// enforced_by: profile_common
// test: bundle:rust/tests/okf.rs

#[allow(clippy::too_many_lines)]
pub(super) fn profile_common(
    metadata: &Map<String, Value>,
    path: &Path,
    errors: &mut Vec<Finding>,
) {
    match metadata.get("generated").and_then(Value::as_object) {
        None => errors.push(issue(
            "PROFILE_GENERATED_REQUIRED",
            path,
            "generated mapping is required",
        )),
        Some(generated)
            if !valid_actor(generated.get("by")) || !valid_datetime(generated.get("at")) =>
        {
            errors.push(issue(
                "PROFILE_GENERATED_INVALID",
                path,
                "generated requires a valid actor and ISO 8601 datetime",
            ));
        }
        Some(_) => {}
    }

    if !matches!(
        metadata.get("status").and_then(Value::as_str),
        Some("draft" | "stable" | "deprecated")
    ) {
        errors.push(issue(
            "PROFILE_STATUS_INVALID",
            path,
            "status must be draft, stable, or deprecated",
        ));
    }

    if !valid_date(metadata.get("stale_after")) {
        errors.push(issue(
            "PROFILE_STALE_AFTER_REQUIRED",
            path,
            "stale_after must be an absolute ISO date",
        ));
    }

    match metadata.get("sources").and_then(Value::as_array) {
        None => errors.push(issue(
            "PROFILE_SOURCES_REQUIRED",
            path,
            "sources must be non-empty",
        )),
        Some(sources) if sources.is_empty() => errors.push(issue(
            "PROFILE_SOURCES_REQUIRED",
            path,
            "sources must be non-empty",
        )),
        Some(sources) => {
            for (index, source) in sources.iter().enumerate() {
                let Some(source) = source.as_object() else {
                    errors.push(issue(
                        "PROFILE_SOURCE_INVALID",
                        path,
                        format!("sources[{index}].resource is required"),
                    ));
                    continue;
                };
                if source.get("resource").and_then(Value::as_str).is_none() {
                    errors.push(issue(
                        "PROFILE_SOURCE_INVALID",
                        path,
                        format!("sources[{index}].resource is required"),
                    ));
                    continue;
                }
                if source.get("author").is_some() && !valid_actor(source.get("author")) {
                    errors.push(issue(
                        "PROFILE_SOURCE_AUTHOR_INVALID",
                        path,
                        format!("sources[{index}].author must follow the OKF actor convention"),
                    ));
                }
                if source.get("last_modified").is_some() && !valid_date(source.get("last_modified"))
                {
                    errors.push(issue(
                        "PROFILE_SOURCE_DATE_INVALID",
                        path,
                        format!("sources[{index}].last_modified must be an ISO date"),
                    ));
                }
            }
        }
    }

    let Some(verified) = metadata.get("verified") else {
        return;
    };
    match verified {
        Value::Object(event) => validate_verified_event(event, 0, path, errors),
        Value::Array(events) if !events.is_empty() => {
            for (index, event) in events.iter().enumerate() {
                let Some(event) = event.as_object() else {
                    errors.push(issue(
                        "PROFILE_VERIFIED_INVALID",
                        path,
                        format!("verified[{index}] requires a valid actor and datetime"),
                    ));
                    continue;
                };
                validate_verified_event(event, index, path, errors);
            }
        }
        _ => errors.push(issue(
            "PROFILE_VERIFIED_INVALID",
            path,
            "verified must be a mapping or list",
        )),
    }
}

fn validate_verified_event(
    event: &Map<String, Value>,
    index: usize,
    path: &Path,
    errors: &mut Vec<Finding>,
) {
    if !valid_actor(event.get("by")) || !valid_datetime(event.get("at")) {
        errors.push(issue(
            "PROFILE_VERIFIED_INVALID",
            path,
            format!("verified[{index}] requires a valid actor and datetime"),
        ));
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn profile_computation(
    metadata: &Map<String, Value>,
    body: &str,
    path: &Path,
    bundle: &Path,
    errors: &mut Vec<Finding>,
) {
    if metadata
        .get("runtime")
        .and_then(Value::as_str)
        .is_none_or(|runtime| runtime.trim().is_empty())
    {
        errors.push(issue(
            "COMPUTATION_RUNTIME_REQUIRED",
            path,
            "runtime is required",
        ));
    }

    match metadata.get("parameters") {
        None => {}
        Some(Value::Array(parameters)) => {
            for (index, parameter) in parameters.iter().enumerate() {
                let Some(parameter) = parameter.as_object() else {
                    errors.push(issue(
                        "COMPUTATION_PARAMETER_INVALID",
                        path,
                        format!("parameters[{index}] must be a mapping"),
                    ));
                    continue;
                };
                if parameter.get("name").and_then(Value::as_str).is_none()
                    || parameter.get("type").and_then(Value::as_str).is_none()
                {
                    errors.push(issue(
                        "COMPUTATION_PARAMETER_INVALID",
                        path,
                        format!("parameters[{index}] requires name and type"),
                    ));
                }
                if parameter.get("required").and_then(Value::as_bool).is_none() {
                    errors.push(issue(
                        "COMPUTATION_PARAMETER_INVALID",
                        path,
                        format!("parameters[{index}].required must be boolean"),
                    ));
                }
            }
        }
        Some(_) => errors.push(issue(
            "COMPUTATION_PARAMETERS_INVALID",
            path,
            "parameters must be a list",
        )),
    }

    let computation = metadata.get("computation");
    if computation.is_some() && computation.and_then(Value::as_str).is_none() {
        errors.push(issue(
            "COMPUTATION_PATH_INVALID",
            path,
            "computation must be a path string when present",
        ));
    }
    let computation_path = computation.and_then(Value::as_str);
    let has_inline = body.contains("# Computation") && body.contains("```");
    let has_file = computation_path.is_some_and(|value| !value.is_empty());
    if has_file == has_inline {
        errors.push(issue(
            "COMPUTATION_SOURCE_AMBIGUOUS",
            path,
            "provide exactly one computation path or inline computation fence",
        ));
    } else if let Some(resource) = computation_path.filter(|_| has_file)
        && !resource_exists(resource, path, bundle)
    {
        errors.push(issue(
            "COMPUTATION_PATH_MISSING",
            path,
            format!("computation path does not exist: {resource}"),
        ));
    }

    match metadata.get("executor").and_then(Value::as_object) {
        Some(executor) if valid_executor(executor) => {
            if let Some(resource) = executor.get("resource").and_then(Value::as_str)
                && !resource_exists(resource, path, bundle)
            {
                errors.push(issue(
                    "COMPUTATION_EXECUTOR_MISSING",
                    path,
                    format!("executor resource does not exist: {resource}"),
                ));
            }
        }
        _ => errors.push(issue(
            "COMPUTATION_EXECUTOR_INVALID",
            path,
            "executor requires resource and a non-empty receipt field list",
        )),
    }

    match metadata.get("attester").and_then(Value::as_object) {
        Some(attester) => {
            if let Some(resource) = attester.get("resource").and_then(Value::as_str) {
                if !resource_exists(resource, path, bundle) {
                    errors.push(issue(
                        "COMPUTATION_ATTESTER_MISSING",
                        path,
                        format!("attester resource does not exist: {resource}"),
                    ));
                }
            } else {
                errors.push(issue(
                    "COMPUTATION_ATTESTER_INVALID",
                    path,
                    "attester.resource is required",
                ));
            }
        }
        None => errors.push(issue(
            "COMPUTATION_ATTESTER_INVALID",
            path,
            "attester.resource is required",
        )),
    }
}

#[must_use]
fn valid_executor(executor: &Map<String, Value>) -> bool {
    if executor.get("resource").and_then(Value::as_str).is_none() {
        return false;
    }
    let Some(receipt) = executor.get("receipt").and_then(Value::as_array) else {
        return false;
    };
    !receipt.is_empty()
        && receipt
            .iter()
            .all(|field| field.as_str().is_some_and(|field| !field.is_empty()))
}
