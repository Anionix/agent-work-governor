//! Command-line interface for read-only Agent Work Governor checks.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use agent_work_governor::{CheckRequest, Governor, PlanBindings, PlanProject, Preset};
use clap::error::ErrorKind;
use clap::{Args, Parser, Subcommand, ValueEnum};

// LLM-CONTRACT
// id: agent-work-governor.rust-cli
// state: ARGUMENTS -> INFORMATIONAL_OUTPUT | TYPED_REQUEST -> JSON_REPORT | CLI_FAULT
// preconditions: callers provide explicit paths or plan bindings but no trusted verdict flags
// invariant: only informational output or a successful report exits zero; all modes remain read-only
// failure: usage exits 64, infrastructure faults exit 70, stopped checks exit 1
// source: bundle:knowledge/policies/work-governor.md
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: run
// test: bundle:rust/tests/interface.rs

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the common fail-closed repository check.
    Check {
        /// Repository root.
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        /// Plugin source or installed bundle root.
        #[arg(long)]
        plugin_root: Option<PathBuf>,
    },
    /// Validate one policy TOML file.
    Policy {
        /// Policy path.
        policy: PathBuf,
    },
    /// Validate one source file's LLM Contract comments.
    Contract {
        /// Source path.
        path: PathBuf,
        /// Repository root for `repo:` references.
        #[arg(long)]
        repo_root: PathBuf,
        /// Governor bundle root for `bundle:` references.
        #[arg(long)]
        bundle_root: PathBuf,
    },
    /// Validate an OKF knowledge bundle.
    Okf {
        /// Bundle root.
        bundle: PathBuf,
    },
    /// Produce a repository-local dry-run plan.
    Bootstrap {
        /// Target repository root.
        #[arg(long)]
        repo: PathBuf,
        /// Plugin source root.
        #[arg(long)]
        plugin_root: PathBuf,
        /// Policy preset.
        #[arg(long, value_enum, default_value = "safe")]
        preset: CliPreset,
        /// Permit planning in a non-Git directory.
        #[arg(long)]
        allow_non_git: bool,
    },
    /// Produce a digest-bound canonical execution plan.
    Plan {
        /// Repository, revision, policy, toolchain, and environment bindings.
        #[command(flatten)]
        bindings: CliPlanBindings,
        /// Caller-confirmed supported project profile.
        #[command(subcommand)]
        project: CliPlanProject,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliPreset {
    Safe,
    OwnerOriginal,
}

impl From<CliPreset> for Preset {
    fn from(value: CliPreset) -> Self {
        match value {
            CliPreset::Safe => Self::Safe,
            CliPreset::OwnerOriginal => Self::OwnerOriginal,
        }
    }
}

#[derive(Debug, Args)]
struct CliPlanBindings {
    /// SHA-256 digest of the repository snapshot.
    #[arg(long = "repository-sha256")]
    repository: String,
    /// SHA-256 digest identifying the exact revision.
    #[arg(long = "revision-sha256")]
    revision: String,
    /// SHA-256 digest of the effective policy.
    #[arg(long = "policy-sha256")]
    policy: String,
    /// SHA-256 digest of the unified toolchain lock.
    #[arg(long = "toolchain-sha256")]
    toolchain: String,
    /// SHA-256 digest of the execution environment.
    #[arg(long = "environment-sha256")]
    environment: String,
}

impl CliPlanBindings {
    fn into_model(self) -> PlanBindings {
        PlanBindings::new(
            self.repository,
            self.revision,
            self.policy,
            self.toolchain,
            self.environment,
        )
    }
}

#[derive(Debug, Subcommand)]
enum CliPlanProject {
    /// Confirm a Python-only uv/unittest repository.
    PythonUvUnittest {
        /// Repository-relative project working directory.
        #[arg(long)]
        working_directory: String,
    },
    /// Confirm a Rust-only Cargo workspace with required locked files.
    RustCargoWorkspace {
        /// Repository-relative project working directory.
        #[arg(long)]
        working_directory: String,
    },
    /// Confirm a mixed uv/unittest and Cargo workspace repository.
    MixedUvCargo {
        /// Repository-relative Python working directory.
        #[arg(long)]
        python_working_directory: String,
        /// Repository-relative Rust working directory.
        #[arg(long)]
        rust_working_directory: String,
    },
}

impl CliPlanProject {
    fn into_model(self) -> PlanProject {
        match self {
            Self::PythonUvUnittest { working_directory } => {
                PlanProject::PythonUvUnittest { working_directory }
            }
            Self::RustCargoWorkspace { working_directory } => {
                PlanProject::RustCargoWorkspace { working_directory }
            }
            Self::MixedUvCargo {
                python_working_directory,
                rust_working_directory,
            } => PlanProject::MixedUvCargo {
                python_working_directory,
                rust_working_directory,
            },
        }
    }
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(value) => value,
        Err(error) => {
            let informational = matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            );
            let _ = error.print();
            return if informational {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(64)
            };
        }
    };
    match run(cli) {
        Ok(code) => code,
        Err(error) => {
            let fallback = serde_json::json!({
                "status": "INCONCLUSIVE",
                "error": error.to_string(),
                "mutation_count": 0
            });
            eprintln!(
                "{}",
                serde_json::to_string_pretty(&fallback)
                    .unwrap_or_else(|_| "{\"status\":\"INCONCLUSIVE\"}".to_owned())
            );
            ExitCode::from(70)
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let request = match cli.command {
        Command::Check { repo, plugin_root } => {
            let plugin_root = plugin_root.unwrap_or_else(|| default_plugin_root(&repo));
            CheckRequest::Repository { repo, plugin_root }
        }
        Command::Policy { policy } => CheckRequest::Policy { path: policy },
        Command::Contract {
            path,
            repo_root,
            bundle_root,
        } => CheckRequest::Contract {
            path,
            repo_root,
            bundle_root,
        },
        Command::Okf { bundle } => CheckRequest::Okf { bundle },
        Command::Bootstrap {
            repo,
            plugin_root,
            preset,
            allow_non_git,
        } => CheckRequest::Bootstrap {
            repo,
            plugin_root,
            preset: preset.into(),
            allow_non_git,
        },
        Command::Plan { bindings, project } => {
            CheckRequest::plan(bindings.into_model(), project.into_model())
        }
    };

    let report = Governor.check(request)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(if report.succeeded() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn default_plugin_root(repo: &Path) -> PathBuf {
    let installed = repo.join(".agent-work-governor");
    if installed.join("knowledge").is_dir() {
        installed
    } else if let Some(packaged) = packaged_plugin_root() {
        packaged
    } else {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
    }
}

fn packaged_plugin_root() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let prefix = executable.parent()?.parent()?;
    let candidate = prefix.join("share/agent-work-governor");
    candidate.join("knowledge").is_dir().then_some(candidate)
}
