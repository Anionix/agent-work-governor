use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::Serialize;

use crate::{GovernorError, Preset, Status};

const REQUIRED_REPOSITORY_ASSETS: [&str; 5] = [
    "AGENTS.agent-work-governor.md",
    ".agent-work-governor/gitignore.snippet",
    ".agent-work-governor/policy.toml",
    ".agent-work-governor/validate.py",
    ".github/workflows/agent-work-governor.yml",
];

const FIXED_SOURCE_MAPPINGS: [(&str, &str); 6] = [
    (
        "scripts/validate_policy.py",
        ".agent-work-governor/validate_policy.py",
    ),
    (
        "scripts/contract_blocks.py",
        ".agent-work-governor/contract_blocks.py",
    ),
    (
        "scripts/toolchain_catalog.py",
        ".agent-work-governor/toolchain_catalog.py",
    ),
    (
        "toolchain.lock.json",
        ".agent-work-governor/toolchain.lock.json",
    ),
    (
        "knowledge/policies/work-governor.md",
        ".agent-work-governor/knowledge/policies/work-governor.md",
    ),
    (
        "tests/test_repo_bundle.py",
        ".agent-work-governor/tests/test_repo_bundle.py",
    ),
];

const OWNER_POLICY_SOURCE: &str = "assets/presets/owner-original.toml";

// LLM-CONTRACT
// id: agent-work-governor.rust-bootstrap-plan
// state: TARGET_DISCOVERED -> SOURCES_MAPPED -> DRY_RUN | CONFLICT
// preconditions: repository and plugin roots are explicit readable directories
// invariant: planning performs zero mutations and rejects required-source or target-parent symlinks
// failure: return a typed infrastructure fault or deterministic conflict report
// source: bundle:knowledge/policies/work-governor.md
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: build_plan
// test: bundle:rust/tests/interface.rs

/// A closed set of read-only bootstrap plan actions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanAction {
    /// The target does not exist and a harness could create it.
    WouldCreate,
    /// Source and target bytes are already identical.
    Unchanged,
    /// The target is unsafe, incompatible, or contains different bytes.
    Conflict,
}

/// One planned template mapping.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlanItem {
    /// Canonical template source.
    pub source: String,
    /// Intended repository target.
    pub target: String,
    /// `would_create`, `unchanged`, or `conflict`.
    pub action: PlanAction,
}

/// Read-only bootstrap result.
#[derive(Clone, Debug, Serialize)]
pub struct BootstrapReport {
    /// Dry-run or conflict status.
    pub status: Status,
    /// Always zero for this static implementation.
    pub mutation_count: u64,
    /// Conflicting targets.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<String>,
    /// Complete deterministic mapping plan.
    pub plan: Vec<PlanItem>,
}

pub(crate) fn build_plan(
    repo: &Path,
    plugin_root: &Path,
    preset: Preset,
    allow_non_git: bool,
) -> Result<BootstrapReport, GovernorError> {
    let repo = canonical_directory(repo)?;
    let plugin_root = canonical_directory(plugin_root)?;
    if !allow_non_git && !repo.join(".git").exists() {
        return Ok(BootstrapReport {
            status: Status::Conflict,
            mutation_count: 0,
            conflicts: vec![format!("{} is not a Git repository", repo.display())],
            plan: Vec::new(),
        });
    }

    preflight_required_sources(&plugin_root)?;
    let mut mappings = repository_assets(&plugin_root)?;
    mappings.extend(
        FIXED_SOURCE_MAPPINGS
            .map(|(source, target)| (plugin_root.join(source), PathBuf::from(target))),
    );
    mappings.sort_by(|left, right| left.1.cmp(&right.1));

    let owner_policy = plugin_root.join(OWNER_POLICY_SOURCE);
    let mut plan = Vec::with_capacity(mappings.len());
    let mut conflicts = Vec::new();
    for (source, relative) in mappings {
        let actual_source = if preset == Preset::OwnerOriginal
            && relative == Path::new(".agent-work-governor/policy.toml")
        {
            owner_policy.clone()
        } else {
            source
        };
        let target = repo.join(&relative);
        let action = target_action(&repo, &actual_source, &target)?;
        if action == PlanAction::Conflict {
            conflicts.push(target.display().to_string());
        }
        plan.push(PlanItem {
            source: actual_source.display().to_string(),
            target: target.display().to_string(),
            action,
        });
    }

    Ok(BootstrapReport {
        status: if conflicts.is_empty() {
            Status::DryRun
        } else {
            Status::Conflict
        },
        mutation_count: 0,
        conflicts,
        plan,
    })
}

fn canonical_directory(path: &Path) -> Result<PathBuf, GovernorError> {
    let resolved = path.canonicalize().map_err(|source| GovernorError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if !resolved.is_dir() {
        return Err(GovernorError::Read {
            path: resolved,
            source: std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                "path is not a directory",
            ),
        });
    }
    Ok(resolved)
}

fn repository_assets(plugin_root: &Path) -> Result<Vec<(PathBuf, PathBuf)>, GovernorError> {
    let source_root = plugin_root.join("assets/repository");
    let mut files = Vec::new();
    collect_files(&source_root, &source_root, &mut files)?;
    Ok(files)
}

fn preflight_required_sources(plugin_root: &Path) -> Result<(), GovernorError> {
    for relative in REQUIRED_REPOSITORY_ASSETS {
        require_regular_source(plugin_root, &Path::new("assets/repository").join(relative))?;
    }
    for (source, _) in FIXED_SOURCE_MAPPINGS {
        require_regular_source(plugin_root, Path::new(source))?;
    }
    require_regular_source(plugin_root, Path::new(OWNER_POLICY_SOURCE))
}

fn require_regular_source(root: &Path, relative: &Path) -> Result<(), GovernorError> {
    let mut candidate = root.to_path_buf();
    let mut components = relative.components().peekable();
    while let Some(component) = components.next() {
        candidate.push(component);
        let metadata = fs::symlink_metadata(&candidate).map_err(|source| GovernorError::Read {
            path: candidate.clone(),
            source,
        })?;
        let is_final = components.peek().is_none();
        let wrong_kind = if is_final {
            !metadata.is_file()
        } else {
            !metadata.is_dir()
        };
        if metadata.file_type().is_symlink() || wrong_kind {
            return Err(GovernorError::Read {
                path: candidate,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "required bootstrap source path is not a symlink-free regular file",
                ),
            });
        }
    }
    Ok(())
}

fn collect_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<(PathBuf, PathBuf)>,
) -> Result<(), GovernorError> {
    let entries = fs::read_dir(directory).map_err(|source| GovernorError::Read {
        path: directory.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| GovernorError::Read {
            path: directory.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let kind = entry.file_type().map_err(|source| GovernorError::Read {
            path: path.clone(),
            source,
        })?;
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            collect_files(root, &path, files)?;
        } else if kind.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_or_else(|_| path.clone(), Path::to_path_buf);
            files.push((path, relative));
        }
    }
    Ok(())
}

fn target_action(repo: &Path, source: &Path, target: &Path) -> Result<PlanAction, GovernorError> {
    if source.is_symlink() {
        return Ok(PlanAction::Conflict);
    }
    let expected = fs::read(source).map_err(|source_error| GovernorError::Read {
        path: source.to_path_buf(),
        source: source_error,
    })?;
    if target.is_symlink() || parent_escapes(repo, target) {
        return Ok(PlanAction::Conflict);
    }
    if !target.exists() {
        return Ok(PlanAction::WouldCreate);
    }
    if !target.is_file() {
        return Ok(PlanAction::Conflict);
    }
    let actual = fs::read(target).map_err(|source_error| GovernorError::Read {
        path: target.to_path_buf(),
        source: source_error,
    })?;
    Ok(if actual == expected {
        PlanAction::Unchanged
    } else {
        PlanAction::Conflict
    })
}

fn parent_escapes(repo: &Path, target: &Path) -> bool {
    let Ok(relative) = target.strip_prefix(repo) else {
        return true;
    };
    let Some(parent) = relative.parent() else {
        return true;
    };
    let mut candidate = repo.to_path_buf();
    for component in parent.components() {
        match component {
            Component::CurDir => continue,
            Component::Normal(part) => candidate.push(part),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return true,
        }
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => return true,
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return true,
        }
    }
    false
}
