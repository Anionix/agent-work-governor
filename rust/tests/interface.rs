//! Public-interface and dry-run integration tests.

use std::fs;
use std::process::Command;

use agent_work_governor::{CheckReport, CheckRequest, Governor, PlanAction, Preset, Status};
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
