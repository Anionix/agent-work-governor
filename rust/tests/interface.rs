//! Public-interface and dry-run integration tests.

use std::fs;
use std::os::unix::fs::symlink;
use std::process::Command;

use agent_work_governor::{
    CheckReport, CheckRequest, EvidenceArtifact, Governor, MAX_CHECK_OUTPUT_BYTES, PlanAction,
    PlanBindings, PlanProject, Preset, Status,
};
use tempfile::tempdir;

// LLM-CONTRACT
// id: agent-work-governor.rust-interface-tests
// state: FIXTURE -> GOVERNOR_CHECK -> OBSERVABLE_REPORT
// preconditions: all fixtures live in temporary directories or the plugin bundle
// invariant: tests cross the same single Interface as production callers
// failure: the Rust test harness reports the violated observable contract
// source: bundle:knowledge/policies/work-governor.md
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: bootstrap_is_dry_run
// test: bundle:rust/tests/interface.rs

fn plugin_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(
            || std::path::PathBuf::from("."),
            std::path::Path::to_path_buf,
        )
}

#[test]
fn informational_help_and_version_exit_successfully() -> Result<(), Box<dyn std::error::Error>> {
    for argument in ["--help", "--version"] {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-work-governor"))
            .arg(argument)
            .output()?;
        assert!(output.status.success(), "{argument}");
        assert!(!output.stdout.is_empty(), "{argument}");
    }
    Ok(())
}

fn copy_required_plugin_sources(
    destination: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    for relative in [
        "assets/repository/AGENTS.agent-work-governor.md",
        "assets/repository/.agent-work-governor/gitignore.snippet",
        "assets/repository/.agent-work-governor/policy.toml",
        "assets/repository/.agent-work-governor/validate.py",
        "assets/repository/.github/workflows/agent-work-governor.yml",
        "assets/presets/owner-original.toml",
        "scripts/validate_policy.py",
        "scripts/contract_blocks.py",
        "scripts/toolchain_catalog.py",
        "toolchain.lock.json",
        "knowledge/policies/work-governor.md",
        "tests/test_repo_bundle.py",
    ] {
        let target = destination.join(relative);
        fs::create_dir_all(target.parent().ok_or("repository asset has no parent")?)?;
        fs::copy(plugin_root().join(relative), target)?;
    }
    Ok(())
}

#[test]
fn bootstrap_is_dry_run() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    fs::create_dir(temporary.path().join(".git"))?;
    let report = Governor.check(CheckRequest::Bootstrap {
        repo: temporary.path().to_path_buf(),
        plugin_root: plugin_root(),
        preset: Preset::Safe,
        allow_non_git: false,
    })?;
    let CheckReport::Bootstrap(report) = report else {
        return Err("unexpected report variant".into());
    };
    assert_eq!(Status::DryRun, report.status);
    assert_eq!(0, report.mutation_count);
    assert!(!temporary.path().join(".agent-work-governor").exists());
    assert!(!report.plan.is_empty());
    assert!(
        report
            .plan
            .iter()
            .all(|item| item.action == PlanAction::WouldCreate)
    );
    Ok(())
}

#[test]
fn bootstrap_maps_the_catalog_and_validator_to_consumer_paths()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    fs::create_dir(temporary.path().join(".git"))?;
    let report = Governor.check(CheckRequest::Bootstrap {
        repo: temporary.path().to_path_buf(),
        plugin_root: plugin_root(),
        preset: Preset::Safe,
        allow_non_git: false,
    })?;
    let CheckReport::Bootstrap(report) = report else {
        return Err("unexpected report variant".into());
    };
    for (source_suffix, target_suffix) in [
        (
            "scripts/toolchain_catalog.py",
            ".agent-work-governor/toolchain_catalog.py",
        ),
        (
            "toolchain.lock.json",
            ".agent-work-governor/toolchain.lock.json",
        ),
    ] {
        assert!(report.plan.iter().any(|item| {
            std::path::Path::new(&item.source).ends_with(source_suffix)
                && std::path::Path::new(&item.target).ends_with(target_suffix)
        }));
    }
    assert!(
        report.plan.iter().all(|item| {
            !std::path::Path::new(&item.source).ends_with("rust/toolchain.lock.json")
        })
    );
    Ok(())
}

#[test]
fn owner_repository_stays_fail_closed_without_external_attesters()
-> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    let gate = temporary.path().join(".agent-work-governor");
    fs::create_dir_all(&gate)?;
    fs::copy(
        plugin_root().join("assets/presets/owner-original.toml"),
        gate.join("policy.toml"),
    )?;
    let report = Governor.check(CheckRequest::Repository {
        repo: temporary.path().to_path_buf(),
        plugin_root: plugin_root(),
    })?;
    let CheckReport::Repository(report) = report else {
        return Err("unexpected report variant".into());
    };
    assert_eq!(Status::Fail, report.status);
    assert_eq!(
        Some("LLM_CONTRACT_AST_ATTESTATION_REQUIRED"),
        report.blocker.as_deref()
    );
    assert_eq!(0, report.mutation_count);
    Ok(())
}

#[test]
fn unknown_repository_scope_never_passes() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    let gate = temporary.path().join(".agent-work-governor");
    fs::create_dir_all(&gate)?;
    fs::copy(
        plugin_root().join("assets/repository/.agent-work-governor/policy.toml"),
        gate.join("policy.toml"),
    )?;
    let report = Governor.check(CheckRequest::Repository {
        repo: temporary.path().to_path_buf(),
        plugin_root: plugin_root(),
    })?;
    let CheckReport::Repository(report) = report else {
        return Err("unexpected report variant".into());
    };
    assert_eq!(Status::Fail, report.status);
    assert_eq!(Some("SCOPE_UNRESOLVED"), report.blocker.as_deref());
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "SCOPE_UNRESOLVED")
    );
    assert_eq!(0, report.mutation_count);
    Ok(())
}

#[test]
fn bootstrap_rejects_a_missing_template_source() -> Result<(), Box<dyn std::error::Error>> {
    let repository = tempdir()?;
    fs::create_dir(repository.path().join(".git"))?;
    let incomplete_plugin = tempdir()?;
    copy_required_plugin_sources(incomplete_plugin.path())?;
    fs::remove_file(
        incomplete_plugin
            .path()
            .join("assets/repository/.agent-work-governor/policy.toml"),
    )?;

    let result = Governor.check(CheckRequest::Bootstrap {
        repo: repository.path().to_path_buf(),
        plugin_root: incomplete_plugin.path().to_path_buf(),
        preset: Preset::Safe,
        allow_non_git: false,
    });
    let Err(error) = result else {
        return Err("missing bootstrap sources must fail closed".into());
    };
    assert!(error.to_string().contains("policy.toml"));
    assert!(!repository.path().join(".agent-work-governor").exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn bootstrap_rejects_a_required_source_symlink() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let repository = tempdir()?;
    fs::create_dir(repository.path().join(".git"))?;
    let plugin = tempdir()?;
    copy_required_plugin_sources(plugin.path())?;
    let policy = plugin
        .path()
        .join("assets/repository/.agent-work-governor/policy.toml");
    fs::remove_file(&policy)?;
    symlink(
        plugin_root().join("assets/repository/.agent-work-governor/policy.toml"),
        &policy,
    )?;

    let result = Governor.check(CheckRequest::Bootstrap {
        repo: repository.path().to_path_buf(),
        plugin_root: plugin.path().to_path_buf(),
        preset: Preset::Safe,
        allow_non_git: false,
    });
    let Err(error) = result else {
        return Err("a required source symlink must fail closed".into());
    };
    assert!(error.to_string().contains("policy.toml"));
    assert!(
        error
            .to_string()
            .contains("required bootstrap source path is not a symlink-free regular file")
    );
    assert!(!repository.path().join(".agent-work-governor").exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn bootstrap_rejects_a_symlinked_source_parent() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let repository = tempdir()?;
    fs::create_dir(repository.path().join(".git"))?;
    let plugin = tempdir()?;
    copy_required_plugin_sources(plugin.path())?;
    let source_parent = plugin.path().join("assets/repository/.agent-work-governor");
    let relocated = plugin.path().join("relocated-agent-work-governor");
    fs::rename(&source_parent, &relocated)?;
    symlink(&relocated, &source_parent)?;

    let result = Governor.check(CheckRequest::Bootstrap {
        repo: repository.path().to_path_buf(),
        plugin_root: plugin.path().to_path_buf(),
        preset: Preset::Safe,
        allow_non_git: false,
    });
    let Err(error) = result else {
        return Err("a symlinked required source parent must fail closed".into());
    };
    assert!(error.to_string().contains(".agent-work-governor"));
    assert!(!repository.path().join(".agent-work-governor").exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn bootstrap_rejects_a_symlinked_support_source_parent() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let repository = tempdir()?;
    fs::create_dir(repository.path().join(".git"))?;
    let plugin = tempdir()?;
    copy_required_plugin_sources(plugin.path())?;
    let scripts = plugin.path().join("scripts");
    let relocated = plugin.path().join("relocated-scripts");
    fs::rename(&scripts, &relocated)?;
    symlink(&relocated, &scripts)?;

    let result = Governor.check(CheckRequest::Bootstrap {
        repo: repository.path().to_path_buf(),
        plugin_root: plugin.path().to_path_buf(),
        preset: Preset::Safe,
        allow_non_git: false,
    });
    let Err(error) = result else {
        return Err("a symlinked support source parent must fail closed".into());
    };
    assert!(error.to_string().contains("scripts"));
    assert!(!repository.path().join(".agent-work-governor").exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn bootstrap_rejects_a_broken_target_parent_symlink() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let temporary = tempdir()?;
    let repository = temporary.path().join("repo");
    fs::create_dir_all(repository.join(".git"))?;
    fs::create_dir(temporary.path().join("outside"))?;
    symlink(
        "../outside/missing-parent",
        repository.join(".agent-work-governor"),
    )?;

    let report = Governor.check(CheckRequest::Bootstrap {
        repo: repository.clone(),
        plugin_root: plugin_root(),
        preset: Preset::Safe,
        allow_non_git: false,
    })?;
    let CheckReport::Bootstrap(report) = report else {
        return Err("unexpected report variant".into());
    };
    assert_eq!(Status::Conflict, report.status);
    assert_eq!(0, report.mutation_count);
    assert!(
        report
            .conflicts
            .iter()
            .any(|path| path.ends_with(".agent-work-governor/policy.toml"))
    );
    assert!(repository.join(".agent-work-governor").is_symlink());
    Ok(())
}

#[test]
fn bootstrap_rejects_a_regular_file_repository() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    let repository = temporary.path().join("not-a-directory");
    fs::write(&repository, "not a repository\n")?;
    let result = Governor.check(CheckRequest::Bootstrap {
        repo: repository.clone(),
        plugin_root: plugin_root(),
        preset: Preset::Safe,
        allow_non_git: true,
    });
    let Err(error) = result else {
        return Err("a regular file cannot be a bootstrap repository".into());
    };
    assert!(error.to_string().contains("path is not a directory"));
    assert_eq!("not a repository\n", fs::read_to_string(repository)?);
    Ok(())
}

const REPOSITORY_SHA256: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const REVISION_SHA256: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const POLICY_SHA256: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const TOOLCHAIN_SHA256: &str = "bc726d3a3415647eb95c55fef2b963b7b69cace38dc2bd4aa25f8e91db45a0b1";
const ENVIRONMENT_SHA256: &str = "5555555555555555555555555555555555555555555555555555555555555555";

fn plan_bindings(values: [&str; 5]) -> PlanBindings {
    PlanBindings::new(values[0], values[1], values[2], values[3], values[4])
}

fn valid_plan_bindings() -> PlanBindings {
    plan_bindings([
        REPOSITORY_SHA256,
        REVISION_SHA256,
        POLICY_SHA256,
        TOOLCHAIN_SHA256,
        ENVIRONMENT_SHA256,
    ])
}

fn assert_plan_cli_matches_library(
    project: PlanProject,
    project_arguments: &[&str],
) -> Result<String, Box<dyn std::error::Error>> {
    let report = Governor.check(CheckRequest::plan(valid_plan_bindings(), project))?;
    let succeeded = report.succeeded();
    let encoded = serde_json::to_string_pretty(&report)?;
    let temporary = tempdir()?;
    let sentinel = temporary.path().join("sentinel");
    fs::write(&sentinel, "unchanged\n")?;
    let output = Command::new(env!("CARGO_BIN_EXE_agent-work-governor"))
        .args([
            "plan",
            "--repository-sha256",
            REPOSITORY_SHA256,
            "--revision-sha256",
            REVISION_SHA256,
            "--policy-sha256",
            POLICY_SHA256,
            "--toolchain-sha256",
            TOOLCHAIN_SHA256,
            "--environment-sha256",
            ENVIRONMENT_SHA256,
        ])
        .args(project_arguments)
        .current_dir(temporary.path())
        .output()?;
    assert_eq!(succeeded, output.status.success());
    assert_eq!(format!("{encoded}\n").as_bytes(), output.stdout);
    assert!(output.stderr.is_empty());
    assert_eq!("unchanged\n", fs::read_to_string(sentinel)?);
    assert_eq!(1, fs::read_dir(temporary.path())?.count());
    Ok(encoded)
}

#[test]
fn plan_library_and_cli_match_the_golden_report() -> Result<(), Box<dyn std::error::Error>> {
    let encoded = assert_plan_cli_matches_library(
        PlanProject::RustCargoWorkspace {
            working_directory: ".".into(),
        },
        &["rust-cargo-workspace", "--working-directory", "."],
    )?;
    let expected = include_str!("fixtures/rust-plan-report.json").trim_end();
    assert_eq!(expected, encoded);
    assert!(!encoded.contains("\"authority\""));
    assert!(!encoded.contains("\"receipt\""));
    assert!(!encoded.contains("\"verdict\""));
    Ok(())
}

#[test]
fn verify_cli_matches_the_fail_closed_library_report() -> Result<(), Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    let receipt = temporary.path().join("receipt.json");
    let evidence_root = temporary.path().join("evidence");
    let evidence = "rust.tests.log";
    let logical_evidence = format!(".governance/receipts/evidence/{evidence}");
    fs::create_dir_all(&evidence_root)?;
    fs::write(&receipt, "{}")?;
    fs::write(evidence_root.join(evidence), "untrusted\n")?;
    let expected_harness = "6666666666666666666666666666666666666666666666666666666666666666";
    let expected_invocation = "7777777777777777777777777777777777777777777777777777777777777777";
    let report = Governor.check(CheckRequest::verify(
        valid_plan_bindings(),
        PlanProject::RustCargoWorkspace {
            working_directory: ".".into(),
        },
        expected_harness,
        expected_invocation,
        b"{}".to_vec(),
        vec![EvidenceArtifact::new(
            &logical_evidence,
            b"untrusted\n".to_vec(),
        )],
    ))?;
    let encoded = serde_json::to_string_pretty(&report)?;
    let invoke = |root: &std::path::Path, evidence_path: &str| {
        Command::new(env!("CARGO_BIN_EXE_agent-work-governor"))
            .args([
                "verify",
                "--repository-sha256",
                REPOSITORY_SHA256,
                "--revision-sha256",
                REVISION_SHA256,
                "--policy-sha256",
                POLICY_SHA256,
                "--toolchain-sha256",
                TOOLCHAIN_SHA256,
                "--environment-sha256",
                ENVIRONMENT_SHA256,
                "--expected-harness-sha256",
                expected_harness,
                "--expected-invocation-sha256",
                expected_invocation,
            ])
            .arg("--receipt")
            .arg(&receipt)
            .arg("--evidence-root")
            .arg(root)
            .arg("--evidence")
            .arg(evidence_path)
            .args(["rust-cargo-workspace", "--working-directory", "."])
            .current_dir(temporary.path())
            .output()
    };
    let output = invoke(&evidence_root, evidence)?;
    assert_eq!(Some(1), output.status.code());
    assert_eq!(format!("{encoded}\n").as_bytes(), output.stdout);
    assert!(output.stderr.is_empty());
    let outside = temporary.path().join("outside.log");
    fs::write(&outside, "outside")?;
    symlink(&outside, evidence_root.join("linked.log"))?;
    fs::write(
        evidence_root.join("oversized.log"),
        vec![0_u8; usize::try_from(MAX_CHECK_OUTPUT_BYTES)? + 1],
    )?;
    for rejected in ["../outside.log", "linked.log", "oversized.log"] {
        let output = invoke(&evidence_root, rejected)?;
        assert_eq!(Some(70), output.status.code());
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8(output.stderr)?.contains("INCONCLUSIVE"));
    }
    Ok(())
}

#[test]
fn every_profile_and_rejection_match_the_cli() -> Result<(), Box<dyn std::error::Error>> {
    let python = assert_plan_cli_matches_library(
        PlanProject::PythonUvUnittest {
            working_directory: ".".into(),
        },
        &["python-uv-unittest", "--working-directory", "."],
    )?;
    assert_eq!(
        7,
        serde_json::from_str::<serde_json::Value>(&python)?["execution_plan"]["checks"]
            .as_array()
            .map_or(0, Vec::len)
    );
    let mixed = assert_plan_cli_matches_library(
        PlanProject::MixedUvCargo {
            python_working_directory: "python".into(),
            rust_working_directory: "rust".into(),
        },
        &[
            "mixed-uv-cargo",
            "--python-working-directory",
            "python",
            "--rust-working-directory",
            "rust",
        ],
    )?;
    assert_eq!(
        12,
        serde_json::from_str::<serde_json::Value>(&mixed)?["execution_plan"]["checks"]
            .as_array()
            .map_or(0, Vec::len)
    );
    let rejected = assert_plan_cli_matches_library(
        PlanProject::RustCargoWorkspace {
            working_directory: "../rust".into(),
        },
        &["rust-cargo-workspace", "--working-directory", "../rust"],
    )?;
    assert_eq!(
        include_str!("fixtures/rejected-plan-report.json").trim_end(),
        rejected
    );
    Ok(())
}

#[test]
fn malformed_bindings_and_toolchain_drift_fail_without_a_plan()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = [
        REPOSITORY_SHA256,
        REVISION_SHA256,
        POLICY_SHA256,
        TOOLCHAIN_SHA256,
        ENVIRONMENT_SHA256,
    ];
    for index in 0..valid.len() {
        let mut values = valid;
        values[index] = "ABC";
        let report = Governor.check(CheckRequest::plan(
            plan_bindings(values),
            PlanProject::PythonUvUnittest {
                working_directory: ".".into(),
            },
        ))?;
        let CheckReport::Plan(report) = report else {
            return Err("unexpected report variant".into());
        };
        assert_eq!(Status::Fail, report.status());
        assert_eq!(0, report.mutation_count());
        assert!(report.execution_plan().is_none());
        assert_eq!("PLAN_INPUT_DIGEST_INVALID", report.findings()[0].code);
    }

    let report = Governor.check(CheckRequest::plan(
        plan_bindings([
            REPOSITORY_SHA256,
            REVISION_SHA256,
            POLICY_SHA256,
            ENVIRONMENT_SHA256,
            ENVIRONMENT_SHA256,
        ]),
        PlanProject::PythonUvUnittest {
            working_directory: ".".into(),
        },
    ))?;
    let CheckReport::Plan(report) = report else {
        return Err("unexpected report variant".into());
    };
    assert_eq!("PLAN_TOOLCHAIN_DIGEST_MISMATCH", report.findings()[0].code);
    assert!(report.execution_plan().is_none());
    Ok(())
}

#[test]
fn mixed_plan_is_deterministic_and_unsafe_facts_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let request = || {
        CheckRequest::plan(
            valid_plan_bindings(),
            PlanProject::MixedUvCargo {
                python_working_directory: "python".into(),
                rust_working_directory: "rust".into(),
            },
        )
    };
    let first = Governor.check(request())?;
    let second = Governor.check(request())?;
    assert_eq!(serde_json::to_vec(&first)?, serde_json::to_vec(&second)?,);
    let encoded = serde_json::to_value(first)?;
    assert_eq!(
        12,
        encoded["execution_plan"]["checks"]
            .as_array()
            .map_or(0, Vec::len)
    );
    assert_eq!(0, encoded["mutation_count"]);
    assert_eq!("PLANNED", encoded["status"]);

    Ok(())
}
