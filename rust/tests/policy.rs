//! Policy validation integration tests.

use std::fs;

use agent_work_governor::{CheckReport, CheckRequest, Governor};
use tempfile::tempdir;

#[test]
fn bundled_safe_policy_is_valid() -> Result<(), Box<dyn std::error::Error>> {
    let plugin_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("Rust crate must have a plugin parent")?;
    let path = plugin_root.join("assets/repository/.agent-work-governor/policy.toml");

    let CheckReport::Policy(receipt) = Governor.check(CheckRequest::Policy { path })? else {
        return Err("policy request must return a policy receipt".into());
    };

    assert!(receipt.valid);
    assert!(receipt.findings.is_empty());
    assert_eq!(receipt.repository_scope.as_deref(), Some("unknown"));
    assert!(receipt.policy_sha256.is_some());
    Ok(())
}

#[test]
fn restricted_scope_findings_match_python_order_and_messages()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    let path = temporary.path().join("policy.toml");
    let source = include_str!("../../assets/repository/.agent-work-governor/policy.toml")
        .replace("repository_write = false", "repository_write = true")
        .replace(
            "external_side_effects = false",
            "external_side_effects = true",
        );
    fs::write(&path, source)?;

    let CheckReport::Policy(receipt) = Governor.check(CheckRequest::Policy { path })? else {
        return Err("policy request must return a policy receipt".into());
    };

    let actual = receipt
        .findings
        .iter()
        .map(|finding| {
            (
                finding.code.as_str(),
                finding.field.as_deref(),
                finding.message.as_str(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        vec![
            (
                "SCOPE_AUTHORITY_CONFLICT",
                Some("authority.external_side_effects"),
                "unknown scope cannot grant external side effects",
            ),
            (
                "SCOPE_AUTHORITY_CONFLICT",
                Some("authority.repository_write"),
                "unknown scope cannot grant repository writes",
            ),
        ]
    );
    Ok(())
}

// LLM-CONTRACT
// id: agent-work-governor.rust-policy-validation-tests
// state: FIXTURE -> CHECK -> COMPATIBLE | TEST_FAILURE
// preconditions: fixtures are explicit and use the bundled policy schema
// invariant: reason code, field, message, and deterministic order match Python
// failure: fail the Rust test target without mutating repository policy
// source: bundle:scripts/validate_policy.py
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: bundled_safe_policy_is_valid
// test: bundle:rust/tests/policy.rs
