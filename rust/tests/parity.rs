//! Differential compatibility tests against the Python policy validator.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use tempfile::tempdir;

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct ComparableReport {
    valid: bool,
    findings: Vec<ComparableFinding>,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct ComparableFinding {
    code: String,
    field: String,
    message: String,
}

type Mutation = (&'static str, &'static str);

const SAFE_MUTATIONS: &[Mutation] = &[
    ("schema_version = \"0.1\"", "schema_version = \"9\""),
    (
        "policy_id = \"repository-safe-default\"",
        "policy_id = \"\"",
    ),
    (
        "repository_scope = \"unknown\"",
        "repository_scope = \"future\"",
    ),
    ("repository_write = false", "repository_write = \"false\""),
    ("destructive_actions = false", "destructive_actions = true"),
    ("max_in_flight = 1", "max_in_flight = 0"),
    (
        "authority = \"ask-matt-or-explicit-user-selection\"",
        "authority = \"self\"",
    ),
    (
        "require_explicit_route = true",
        "require_explicit_route = false",
    ),
    (
        "ask_matt_sha256 = \"b1a134ada29cbfded84bc9a7f93356ab7a3d7f800edf1f541a2a964118ad45a7\"",
        "ask_matt_sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"",
    ),
    (
        "ask_matt_sha256 = \"b1a134ada29cbfded84bc9a7f93356ab7a3d7f800edf1f541a2a964118ad45a7\"",
        "ask_matt_sha256 = \"bad\"",
    ),
    (
        "require_terminal_evidence = true",
        "require_terminal_evidence = false",
    ),
    ("okf_version = \"0.2\"", "okf_version = \"9\""),
    (
        "bundle = \"plugin://agent-work-governor/knowledge\"",
        "bundle = \"\"",
    ),
    (
        "include_in_okf_bundle = false",
        "include_in_okf_bundle = true",
    ),
    (
        "directory = \".governance/receipts\"",
        "directory = \"../escape\"",
    ),
];

const OWNER_MUTATIONS: &[Mutation] = &[
    ("default_branch = \"main\"", "default_branch = \"\""),
    (
        "branch_base = \"origin/main\"",
        "branch_base = \"origin/trunk\"",
    ),
    ("one_pr_one_task = true", "one_pr_one_task = false"),
    (
        "code_review_skill_sha256 = \"6a65cc61114f96db07ec41e3920e67c9c5bf70dd6e0901eb9460ebcb2bdc209f\"",
        "code_review_skill_sha256 = \"bad\"",
    ),
    ("require_nix_flake = true", "require_nix_flake = false"),
    (
        "toolchain_lock = \".agent-work-governor/toolchain.lock.json\"",
        "toolchain_lock = \"../toolchain.lock.json\"",
    ),
    (
        "required_tools = [\"uv\", \"ruff\", \"ty\", \"pip-audit\"]",
        "required_tools = []",
    ),
];

fn plugin_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

fn run_report(
    command: &mut Command,
) -> Result<(i32, ComparableReport), Box<dyn std::error::Error>> {
    let output = command.output()?;
    let exit_code = output
        .status
        .code()
        .ok_or("validator terminated without an exit code")?;
    let report = serde_json::from_slice(&output.stdout)?;
    Ok((exit_code, report))
}

fn python_report(path: &Path) -> Result<(i32, ComparableReport), Box<dyn std::error::Error>> {
    let root = plugin_root();
    run_report(
        Command::new("python3")
            .current_dir(&root)
            .arg("scripts/validate_policy.py")
            .arg(path)
            .arg("--json"),
    )
}

fn rust_report(path: &Path) -> Result<(i32, ComparableReport), Box<dyn std::error::Error>> {
    run_report(
        Command::new(env!("CARGO_BIN_EXE_agent-work-governor"))
            .arg("policy")
            .arg(path),
    )
}

fn assert_exact_parity(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(python_report(path)?, rust_report(path)?);
    Ok(())
}

fn exercise_mutations(
    base: &str,
    mutations: &[Mutation],
    directory: &Path,
    group: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for (index, &(from, to)) in mutations.iter().enumerate() {
        let mutated = base.replacen(from, to, 1);
        if mutated == base {
            return Err(format!("{group} mutation {index} did not match its fixture").into());
        }
        let path = directory.join(format!("{group}-{index}.toml"));
        fs::write(&path, mutated)?;
        assert_exact_parity(&path)?;
    }
    Ok(())
}

#[test]
fn policy_reports_match_python() -> Result<(), Box<dyn std::error::Error>> {
    let root = plugin_root();
    let policies = [
        root.join("assets/repository/.agent-work-governor/policy.toml"),
        root.join("assets/presets/owner-original.toml"),
    ];
    for path in policies {
        assert_exact_parity(&path)?;
    }

    let temporary = tempdir()?;
    let path = temporary.path().join("policy.toml");
    let source =
        fs::read_to_string(root.join("assets/repository/.agent-work-governor/policy.toml"))?
            .replace("repository_write = false", "repository_write = true")
            .replace(
                "external_side_effects = false",
                "external_side_effects = true",
            );
    fs::write(&path, source)?;
    assert_exact_parity(&path)?;
    Ok(())
}

#[test]
fn policy_reason_code_corpus_matches_python() -> Result<(), Box<dyn std::error::Error>> {
    let root = plugin_root();
    let safe = fs::read_to_string(root.join("assets/repository/.agent-work-governor/policy.toml"))?;
    let owner = fs::read_to_string(root.join("assets/presets/owner-original.toml"))?;
    let temporary = tempdir()?;
    exercise_mutations(&safe, SAFE_MUTATIONS, temporary.path(), "safe")?;
    exercise_mutations(&owner, OWNER_MUTATIONS, temporary.path(), "owner")?;
    Ok(())
}

#[test]
fn policy_io_failures_return_compatible_receipts() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    let missing = temporary.path().join("missing.toml");
    assert_exact_parity(&missing)?;

    let (python_exit, python) = python_report(temporary.path())?;
    let (rust_exit, rust) = rust_report(temporary.path())?;
    assert_eq!(python_exit, rust_exit);
    assert!(!python.valid);
    assert_eq!(python.valid, rust.valid);
    let python_keys = python
        .findings
        .iter()
        .map(|finding| (&finding.code, &finding.field))
        .collect::<Vec<_>>();
    let rust_keys = rust
        .findings
        .iter()
        .map(|finding| (&finding.code, &finding.field))
        .collect::<Vec<_>>();
    assert_eq!(python_keys, rust_keys);
    assert_eq!(python_keys.len(), 1);
    assert_eq!(python_keys[0].0, "POLICY_PARSE_ERROR");
    assert_eq!(
        python_keys[0].1,
        &temporary.path().canonicalize()?.display().to_string()
    );

    let existing = temporary.path().join("existing-policy.toml");
    fs::copy(
        plugin_root().join("assets/repository/.agent-work-governor/policy.toml"),
        &existing,
    )?;
    let through_missing_parent = temporary
        .path()
        .join("missing")
        .join("..")
        .join("existing-policy.toml");
    assert_exact_parity(&through_missing_parent)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn policy_broken_symlink_parent_resolution_matches_python() -> Result<(), Box<dyn std::error::Error>>
{
    use std::os::unix::fs::symlink;

    let temporary = tempdir()?;
    let repo = temporary.path().join("repo");
    let outside = temporary.path().join("outside");
    fs::create_dir_all(&repo)?;
    fs::create_dir_all(&outside)?;
    fs::copy(
        plugin_root().join("assets/repository/.agent-work-governor/policy.toml"),
        repo.join("policy.toml"),
    )?;
    symlink("../outside/missing-parent", repo.join("broken"))?;

    let through_broken_symlink = repo.join("broken").join("..").join("policy.toml");
    let (python_exit, python) = python_report(&through_broken_symlink)?;
    let (rust_exit, rust) = rust_report(&through_broken_symlink)?;

    assert_eq!(python_exit, 1);
    assert!(!python.valid);
    assert_eq!(python.findings.len(), 1);
    assert_eq!(python.findings[0].code, "POLICY_NOT_FOUND");
    assert_eq!(
        python.findings[0].field,
        outside
            .canonicalize()?
            .join("policy.toml")
            .display()
            .to_string()
    );
    assert_eq!((python_exit, python), (rust_exit, rust));
    Ok(())
}

#[cfg(unix)]
#[test]
fn policy_long_acyclic_symlink_chain_matches_python() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let temporary = tempdir()?;
    let repo = temporary.path().join("repo");
    let outside = temporary.path().join("outside");
    fs::create_dir_all(&repo)?;
    fs::create_dir_all(&outside)?;
    fs::copy(
        plugin_root().join("assets/repository/.agent-work-governor/policy.toml"),
        repo.join("policy.toml"),
    )?;
    for index in 0..40 {
        symlink(
            format!("link-{}", index + 1),
            repo.join(format!("link-{index}")),
        )?;
    }
    symlink("../outside/missing-parent", repo.join("link-40"))?;

    let through_chain = repo.join("link-0").join("..").join("policy.toml");
    let (python_exit, python) = python_report(&through_chain)?;
    let (rust_exit, rust) = rust_report(&through_chain)?;

    assert_eq!(python_exit, 1);
    assert!(!python.valid);
    assert_eq!(python.findings.len(), 1);
    assert_eq!(python.findings[0].code, "POLICY_NOT_FOUND");
    assert_eq!(
        python.findings[0].field,
        outside
            .canonicalize()?
            .join("policy.toml")
            .display()
            .to_string()
    );
    assert_eq!((python_exit, python), (rust_exit, rust));
    Ok(())
}

#[cfg(unix)]
#[test]
fn policy_symlink_cycle_is_a_typed_fail_closed_fault() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let temporary = tempdir()?;
    symlink("cycle-b", temporary.path().join("cycle-a"))?;
    symlink("cycle-a", temporary.path().join("cycle-b"))?;

    let output = Command::new(env!("CARGO_BIN_EXE_agent-work-governor"))
        .arg("policy")
        .arg(temporary.path().join("cycle-a"))
        .output()?;
    assert_eq!(output.status.code(), Some(70));
    assert!(output.stdout.is_empty());

    let fault: serde_json::Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(fault["status"], "INCONCLUSIVE");
    assert_eq!(fault["mutation_count"], 0);
    assert!(
        fault["error"]
            .as_str()
            .is_some_and(|message| message.contains("symlink cycle"))
    );
    Ok(())
}

// LLM-CONTRACT
// id: agent-work-governor.rust-policy-differential-test
// state: SHARED_OR_SYMLINK_FIXTURE -> FINITE_EXPANSION | CYCLE_FAULT -> TERMINAL_EVIDENCE
// preconditions: Python 3 and the built Rust CLI are available to the test harness
// invariant: acyclic chain length cannot change resolved paths, status, or ordered findings
// failure: cycles exit 70 with typed JSON; differential mismatches preserve both reports
// source: bundle:scripts/validate_policy.py
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: policy_reports_match_python
// test: bundle:rust/tests/parity.rs
