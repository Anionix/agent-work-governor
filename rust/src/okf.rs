//! JSON-compatible OKF v0.2 and Governor-profile validation.

mod profile;
mod resources;
mod scalars;

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{CWD, Dir, FileType, Mode, OFlags, fstat, openat};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::GovernorError;
use crate::model::Finding;
use profile::{profile_common, profile_computation};
use resources::link_warnings;
use scalars::parse_log_dates;

// LLM-CONTRACT
// id: agent-work-governor.rust-okf-validation
// state: BUNDLE -> DOCUMENTS -> CORE_VERDICT + PROFILE_VERDICT
// preconditions: the bundle path is explicit and filesystem reads are bounded to validation
// invariant: profile errors stay distinct and document reads use symlink-free bundle directory fds
// failure: unsupported general YAML is INCONCLUSIVE and inaccessible documents fail closed
// source: https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/3fcbb9f828c2f23d109c855ee403c3a4c81f3a96/okf/SPEC.md
// knowledge: bundle:knowledge/references/okf-v0.2.md
// enforced_by: validate_bundle
// test: bundle:rust/tests/okf.rs

const PARSER_PROFILE: &str = "JSON-compatible YAML";

/// A closed OKF validation state with stable lowercase JSON spelling.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OkfStatus {
    /// Every required condition was proven.
    Valid,
    /// At least one deterministic violation was found.
    Invalid,
    /// The supported parser profile could not prove a verdict.
    Inconclusive,
}

/// OKF-core portion of a validation report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CoreReport {
    /// `valid`, `invalid`, or `inconclusive`.
    pub status: OkfStatus,
    /// Deterministic OKF-core failures.
    pub errors: Vec<Finding>,
    /// Documents that require a general YAML parser.
    pub inconclusive: Vec<Finding>,
}

/// Strict Governor-profile portion of a validation report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProfileReport {
    /// `valid`, `invalid`, or `inconclusive`.
    pub status: OkfStatus,
    /// Deterministic Governor-profile failures.
    pub errors: Vec<Finding>,
}

/// Combined OKF-core and Governor-profile report.
#[allow(clippy::module_name_repetitions)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OkfReport {
    /// Canonical or absolute bundle path.
    pub bundle: String,
    /// Parser subset proven by this implementation.
    pub parser_profile: String,
    /// OKF-core result.
    pub okf_core: CoreReport,
    /// Stricter Governor-profile result.
    pub governor_profile: ProfileReport,
    /// Non-blocking OKF-compatible warnings.
    pub warnings: Vec<Finding>,
}

#[must_use]
fn issue(code: &str, path: &Path, message: impl Into<String>) -> Finding {
    Finding::path(code, path, message)
}

#[must_use]
fn split_frontmatter(text: &str) -> (Option<String>, String) {
    let lines: Vec<&str> = text.lines().collect();
    if lines.first().copied() != Some("---") {
        return (None, text.to_owned());
    }
    let Some(end) = lines.iter().skip(1).position(|line| *line == "---") else {
        return (None, text.to_owned());
    };
    let absolute_end = end + 1;
    (
        Some(lines[1..absolute_end].join("\n").trim().to_owned()),
        lines[(absolute_end + 1)..].join("\n"),
    )
}

#[must_use]
fn parse_frontmatter(
    raw: Option<&str>,
    path: &Path,
) -> (Option<Map<String, Value>>, Option<Finding>) {
    let Some(raw) = raw else {
        return (
            None,
            Some(issue(
                "MISSING_FRONTMATTER",
                path,
                "frontmatter is required",
            )),
        );
    };
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return (
            None,
            Some(issue(
                "YAML_PARSE_INCONCLUSIVE",
                path,
                "v0.1 validator proves only the JSON-compatible YAML profile",
            )),
        );
    };
    let Value::Object(metadata) = value else {
        return (
            None,
            Some(issue(
                "INVALID_FRONTMATTER_ROOT",
                path,
                "frontmatter must be a mapping",
            )),
        );
    };
    (Some(metadata), None)
}

struct MarkdownDocument {
    path: PathBuf,
    regular_file: bool,
    text: io::Result<String>,
}

struct MarkdownCandidate {
    path: PathBuf,
    relative: PathBuf,
    parent_inode: u64,
    inode: u64,
    regular_file: bool,
    discovery_error: Option<io::Error>,
}

struct MarkdownBundle {
    root: OwnedFd,
    documents: Vec<MarkdownCandidate>,
}

struct DirectoryCandidate {
    relative: PathBuf,
    inode: u64,
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK
}

fn open_directory_path(path: &Path) -> io::Result<OwnedFd> {
    let mut directory =
        openat(CWD, "/", directory_flags(), Mode::empty()).map_err(io::Error::from)?;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => {
                directory = openat(&directory, part, directory_flags(), Mode::empty())
                    .map_err(io::Error::from)?;
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "bundle directory path is not absolute and normalized",
                ));
            }
        }
    }
    Ok(directory)
}

fn reopen_directory(root: &OwnedFd, relative: &Path, expected_inode: u64) -> io::Result<OwnedFd> {
    let mut directory =
        openat(root, ".", directory_flags(), Mode::empty()).map_err(io::Error::from)?;
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bundle-relative directory path is not normalized",
            ));
        };
        directory =
            openat(&directory, part, directory_flags(), Mode::empty()).map_err(io::Error::from)?;
    }
    let metadata = fstat(&directory).map_err(io::Error::from)?;
    if !FileType::from_raw_mode(metadata.st_mode).is_dir()
        || (expected_inode != 0 && metadata.st_ino != expected_inode)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bundle directory is not the discovered symlink-free directory",
        ));
    }
    Ok(directory)
}

fn read_markdown_at(
    parent: &OwnedFd,
    name: &std::ffi::CStr,
    inode: u64,
    discovered_regular_file: bool,
) -> MarkdownDocument {
    let descriptor = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    );
    let descriptor = match descriptor {
        Ok(descriptor) => descriptor,
        Err(source) => {
            return MarkdownDocument {
                path: PathBuf::new(),
                regular_file: discovered_regular_file,
                text: Err(source.into()),
            };
        }
    };
    let metadata = match fstat(&descriptor) {
        Ok(metadata) => metadata,
        Err(source) => {
            return MarkdownDocument {
                path: PathBuf::new(),
                regular_file: discovered_regular_file,
                text: Err(source.into()),
            };
        }
    };
    let regular_file = FileType::from_raw_mode(metadata.st_mode).is_file();
    if !FileType::from_raw_mode(metadata.st_mode).is_file()
        || (inode != 0 && metadata.st_ino != inode)
    {
        return MarkdownDocument {
            path: PathBuf::new(),
            regular_file: discovered_regular_file || regular_file,
            text: Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Markdown document is not the discovered symlink-free regular file",
            )),
        };
    }
    let mut file = File::from(descriptor);
    let mut text = String::new();
    MarkdownDocument {
        path: PathBuf::new(),
        regular_file: true,
        text: file.read_to_string(&mut text).map(|_| text),
    }
}

fn discover_markdown_documents(bundle: &Path) -> Result<MarkdownBundle, GovernorError> {
    let root = open_directory_path(bundle).map_err(|source| GovernorError::Read {
        path: bundle.to_path_buf(),
        source,
    })?;
    let root_metadata = fstat(&root).map_err(|source| GovernorError::Read {
        path: bundle.to_path_buf(),
        source: source.into(),
    })?;
    let mut directories = vec![DirectoryCandidate {
        relative: PathBuf::new(),
        inode: root_metadata.st_ino,
    }];
    let mut documents = Vec::new();
    while let Some(candidate) = directories.pop() {
        let directory_path = bundle.join(&candidate.relative);
        let directory =
            reopen_directory(&root, &candidate.relative, candidate.inode).map_err(|source| {
                GovernorError::Read {
                    path: directory_path.clone(),
                    source,
                }
            })?;
        let directory_metadata = fstat(&directory).map_err(|source| GovernorError::Read {
            path: directory_path.clone(),
            source: source.into(),
        })?;
        let mut entries = Dir::read_from(&directory).map_err(|source| GovernorError::Read {
            path: directory_path.clone(),
            source: source.into(),
        })?;
        for entry in &mut entries {
            let entry = entry.map_err(|source| GovernorError::Read {
                path: directory_path.clone(),
                source: source.into(),
            })?;
            let name_bytes = entry.file_name().to_bytes();
            if matches!(name_bytes, b"." | b"..") {
                continue;
            }
            let name = OsStr::from_bytes(name_bytes);
            let relative = candidate.relative.join(name);
            let path = bundle.join(&relative);
            let is_markdown = path.extension().is_some_and(|extension| extension == "md");
            let mut discovery_error = None;
            match openat(
                &directory,
                entry.file_name(),
                directory_flags(),
                Mode::empty(),
            ) {
                Ok(child) => {
                    let metadata = fstat(&child).map_err(|source| GovernorError::Read {
                        path: path.clone(),
                        source: source.into(),
                    })?;
                    if entry.ino() != 0 && metadata.st_ino != entry.ino() {
                        return Err(GovernorError::Read {
                            path,
                            source: io::Error::new(
                                io::ErrorKind::InvalidData,
                                "bundle directory entry changed during discovery",
                            ),
                        });
                    }
                    directories.push(DirectoryCandidate {
                        relative: relative.clone(),
                        inode: metadata.st_ino,
                    });
                }
                Err(rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP) => {}
                Err(source) if is_markdown => {
                    discovery_error = Some(source.into());
                }
                Err(source) => {
                    return Err(GovernorError::Read {
                        path,
                        source: source.into(),
                    });
                }
            }
            if is_markdown {
                documents.push(MarkdownCandidate {
                    path: path.clone(),
                    relative,
                    parent_inode: directory_metadata.st_ino,
                    inode: entry.ino(),
                    regular_file: entry.file_type().is_file(),
                    discovery_error,
                });
            }
        }
    }
    documents.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(MarkdownBundle { root, documents })
}

fn read_markdown_candidate(
    bundle: &MarkdownBundle,
    candidate: MarkdownCandidate,
) -> MarkdownDocument {
    if let Some(error) = candidate.discovery_error {
        return MarkdownDocument {
            path: candidate.path,
            regular_file: candidate.regular_file,
            text: Err(error),
        };
    }
    let parent_relative = candidate.relative.parent().unwrap_or_else(|| Path::new(""));
    let parent = match reopen_directory(&bundle.root, parent_relative, candidate.parent_inode) {
        Ok(parent) => parent,
        Err(error) => {
            return MarkdownDocument {
                path: candidate.path,
                regular_file: candidate.regular_file,
                text: Err(error),
            };
        }
    };
    let Some(name) = candidate.relative.file_name() else {
        return MarkdownDocument {
            path: candidate.path,
            regular_file: candidate.regular_file,
            text: Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Markdown candidate has no file name",
            )),
        };
    };
    let name = std::ffi::CString::new(name.as_bytes());
    let mut document = match name {
        Ok(name) => read_markdown_at(&parent, &name, candidate.inode, candidate.regular_file),
        Err(error) => MarkdownDocument {
            path: PathBuf::new(),
            regular_file: candidate.regular_file,
            text: Err(io::Error::new(io::ErrorKind::InvalidInput, error)),
        },
    };
    document.path = candidate.path;
    document
}

fn absolute_or_canonical(path: &Path) -> Result<PathBuf, GovernorError> {
    match path.canonicalize() {
        Ok(canonical) => Ok(canonical),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            if path.is_absolute() {
                Ok(path.to_path_buf())
            } else {
                std::env::current_dir()
                    .map(|directory| directory.join(path))
                    .map_err(|source| GovernorError::Read {
                        path: path.to_path_buf(),
                        source,
                    })
            }
        }
        Err(source) => Err(GovernorError::Read {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Validate an OKF bundle using the Python validator's JSON-compatible profile.
///
/// # Errors
///
/// Returns [`GovernorError::Read`] when directory discovery itself cannot be completed. A
/// document-level read failure remains a deterministic `DOCUMENT_READ_ERROR` finding.
#[allow(clippy::if_not_else, clippy::too_many_lines)]
pub fn validate_bundle(bundle: &Path) -> Result<OkfReport, GovernorError> {
    let bundle = absolute_or_canonical(bundle)?;
    let mut core_errors = Vec::new();
    let mut core_inconclusive = Vec::new();
    let mut profile_errors = Vec::new();
    let mut warnings = Vec::new();

    if !bundle.is_dir() {
        core_errors.push(issue(
            "BUNDLE_NOT_FOUND",
            &bundle,
            "bundle directory does not exist",
        ));
    } else {
        let root_index = bundle.join("index.md");
        let mut markdown_bundle = discover_markdown_documents(&bundle)?;
        let mut root_index_is_file = false;
        for candidate in std::mem::take(&mut markdown_bundle.documents) {
            let document = read_markdown_candidate(&markdown_bundle, candidate);
            let path = document.path;
            if path == root_index && document.regular_file {
                root_index_is_file = true;
            }
            let text = match document.text {
                Ok(text) => text,
                Err(error) => {
                    core_errors.push(issue("DOCUMENT_READ_ERROR", &path, error.to_string()));
                    continue;
                }
            };
            let (raw, body) = split_frontmatter(&text);
            if path.file_name().is_some_and(|name| name == "index.md") {
                if path == root_index {
                    if raw.is_none() {
                        profile_errors.push(issue(
                            "PROFILE_OKF_VERSION",
                            &path,
                            "root index must declare okf_version \"0.2\"",
                        ));
                    } else {
                        let (metadata, parse_issue) = parse_frontmatter(raw.as_deref(), &path);
                        if let Some(parse_issue) = parse_issue {
                            core_inconclusive.push(parse_issue);
                        } else if metadata
                            .as_ref()
                            .and_then(|metadata| metadata.get("okf_version"))
                            .and_then(Value::as_str)
                            != Some("0.2")
                        {
                            profile_errors.push(issue(
                                "PROFILE_OKF_VERSION",
                                &path,
                                "root index must declare okf_version \"0.2\"",
                            ));
                        }
                    }
                } else if raw.is_some() {
                    core_errors.push(issue(
                        "RESERVED_FRONTMATTER",
                        &path,
                        "only bundle-root index.md may contain frontmatter",
                    ));
                }
                warnings.extend(link_warnings(&body, &path, &bundle));
                continue;
            }

            if path.file_name().is_some_and(|name| name == "log.md") {
                if raw.is_some() {
                    core_errors.push(issue(
                        "RESERVED_FRONTMATTER",
                        &path,
                        "log.md must not have frontmatter",
                    ));
                }
                parse_log_dates(&body, &path, &mut core_errors);
                continue;
            }

            let (metadata, parse_issue) = parse_frontmatter(raw.as_deref(), &path);
            if let Some(parse_issue) = parse_issue {
                if parse_issue.code == "YAML_PARSE_INCONCLUSIVE" {
                    core_inconclusive.push(parse_issue);
                } else {
                    core_errors.push(parse_issue);
                }
                continue;
            }
            let Some(metadata) = metadata else {
                continue;
            };
            let concept_type = metadata.get("type").and_then(Value::as_str);
            if concept_type.is_none_or(|concept_type| concept_type.trim().is_empty()) {
                core_errors.push(issue(
                    "TYPE_REQUIRED",
                    &path,
                    "type must be a non-empty string",
                ));
                continue;
            }

            profile_common(&metadata, &path, &mut profile_errors);
            if concept_type == Some("Attested Computation") {
                profile_computation(&metadata, &body, &path, &bundle, &mut profile_errors);
            }
            warnings.extend(link_warnings(&body, &path, &bundle));
        }
        if !root_index_is_file {
            profile_errors.insert(
                0,
                issue(
                    "PROFILE_INDEX_REQUIRED",
                    &root_index,
                    "Governor profile requires index.md",
                ),
            );
        }
    }

    let core_status = if core_errors.is_empty() {
        if core_inconclusive.is_empty() {
            OkfStatus::Valid
        } else {
            OkfStatus::Inconclusive
        }
    } else {
        OkfStatus::Invalid
    };
    let profile_status = if core_status == OkfStatus::Valid && profile_errors.is_empty() {
        OkfStatus::Valid
    } else if core_status == OkfStatus::Inconclusive && core_errors.is_empty() {
        OkfStatus::Inconclusive
    } else {
        OkfStatus::Invalid
    };

    Ok(OkfReport {
        bundle: bundle.display().to_string(),
        parser_profile: PARSER_PROFILE.to_owned(),
        okf_core: CoreReport {
            status: core_status,
            errors: core_errors,
            inconclusive: core_inconclusive,
        },
        governor_profile: ProfileReport {
            status: profile_status,
            errors: profile_errors,
        },
        warnings,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;

    use tempfile::tempdir;

    use super::open_directory_path;

    #[test]
    fn markdown_bundle_parent_symlink_swap_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempdir()?;
        let parent = temporary.path().join("bundle-parent");
        let bundle = parent.join("bundle");
        let relocated = temporary.path().join("relocated-parent");
        fs::create_dir_all(&bundle)?;
        fs::rename(&parent, &relocated)?;
        symlink(&relocated, &parent)?;

        let Err(_) = open_directory_path(&bundle) else {
            return Err("a swapped bundle parent symlink must fail closed".into());
        };
        Ok(())
    }
}
