use std::env;
use std::fmt;
use std::path::{Component, Path, PathBuf};

use regex::Regex;

// LLM-CONTRACT
// id: agent-work-governor.rust-contract-reference
// state: DECLARED_REFERENCE -> BOUNDED_LOCATION -> LOCAL_FILE | IMMUTABLE_EXTERNAL | INVALID
// preconditions: repository and bundle roots are explicit
// invariant: one percent decode cannot escape the selected root and symlinks cannot widen it
// failure: return a stable Python-compatible reference diagnostic
// source: bundle:knowledge/policies/work-governor.md
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: resolve_contract_reference
// test: bundle:rust/tests/contract.rs

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ResolvedReference {
    Local(PathBuf),
    ImmutableExternal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReferenceError {
    ImmutableExternalRequired,
    SchemeRequired,
    UnsafePath,
    EscapesRoot,
    MissingRegularFile,
}

impl ReferenceError {
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::ImmutableExternalRequired => "external source locator must be immutable",
            Self::SchemeRequired => "reference must use the bundle: or repo: scheme",
            Self::UnsafePath => "reference contains an unsafe path",
            Self::EscapesRoot => "reference escapes its declared root",
            Self::MissingRegularFile => "reference does not name an existing regular file",
        }
    }
}

impl fmt::Display for ReferenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

pub(crate) fn resolve_contract_reference(
    reference: &str,
    repo_root: &Path,
    bundle_root: &Path,
    allow_external: bool,
) -> Result<ResolvedReference, ReferenceError> {
    if allow_external && immutable_external_source(reference) {
        return Ok(ResolvedReference::ImmutableExternal);
    }

    let Some((scheme, raw_path)) = reference.split_once(':') else {
        return Err(ReferenceError::SchemeRequired);
    };
    let selected_root = match scheme {
        "repo" => repo_root,
        "bundle" => bundle_root,
        _ if allow_external && is_external_locator(reference) => {
            return Err(ReferenceError::ImmutableExternalRequired);
        }
        _ => return Err(ReferenceError::SchemeRequired),
    };

    let relative = safe_relative_path(raw_path).ok_or(ReferenceError::UnsafePath)?;
    let base = canonical_or_absolute(selected_root);
    let unresolved = relative
        .iter()
        .fold(base.clone(), |path, part| path.join(part));
    let resolved = unresolved
        .canonicalize()
        .map_err(|_| ReferenceError::MissingRegularFile)?;

    if !resolved.starts_with(&base) {
        return Err(ReferenceError::EscapesRoot);
    }
    if !resolved.is_file() {
        return Err(ReferenceError::MissingRegularFile);
    }
    Ok(ResolvedReference::Local(resolved))
}

fn safe_relative_path(raw_path: &str) -> Option<Vec<String>> {
    let decoded = percent_decode_once(raw_path);
    if decoded.is_empty()
        || decoded.contains('\0')
        || decoded.contains('\\')
        || decoded.starts_with('/')
    {
        return None;
    }

    let mut parts = Vec::new();
    // Path components normalize repeated separators, non-leading `.`, and trailing
    // separators, so validate the decoded syntax before constructing any Path.
    // Primary source: https://doc.rust-lang.org/1.97.1/std/path/index.html#path-normalization
    for part in decoded.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return None;
        }
        parts.push(part.to_owned());
    }
    Some(parts)
}

fn percent_decode_once(value: &str) -> String {
    let input = value.as_bytes();
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'%' && index + 2 < input.len() {
            let high = hexadecimal(input[index + 1]);
            let low = hexadecimal(input[index + 2]);
            if let (Some(high), Some(low)) = (high, low) {
                output.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        output.push(input[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

const fn hexadecimal(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn immutable_external_source(reference: &str) -> bool {
    if reference.starts_with("doi:") {
        return regex_matches(r"\Adoi:10\.\d{4,9}/\S+\z", reference);
    }
    if reference.starts_with("arxiv:") {
        return regex_matches(
            r"\A(?i:arxiv:(?:\d{4}\.\d{4,5}|[a-z-]+/\d{7})v[1-9]\d*)\z",
            reference,
        );
    }
    immutable_github_blob(reference)
}

fn immutable_github_blob(reference: &str) -> bool {
    let Some(remainder) = strip_ascii_case_prefix(reference, "https://") else {
        return false;
    };
    let authority_end = match remainder.find(['/', '?', '#']) {
        Some(index) => index,
        None => remainder.len(),
    };
    let authority = &remainder[..authority_end];
    let host_and_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = host_and_port
        .split_once(':')
        .map_or(host_and_port, |(name, _)| name);
    if !host.eq_ignore_ascii_case("github.com") {
        return false;
    }

    let path_and_suffix = &remainder[authority_end..];
    let path_end = match path_and_suffix.find(['?', '#']) {
        Some(index) => index,
        None => path_and_suffix.len(),
    };
    regex_matches(r"(?i)/blob/[0-9a-f]{40}/", &path_and_suffix[..path_end])
}

fn strip_ascii_case_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value
        .get(..prefix.len())
        .filter(|candidate| candidate.eq_ignore_ascii_case(prefix))
        .and_then(|_| value.get(prefix.len()..))
}

fn regex_matches(pattern: &str, value: &str) -> bool {
    Regex::new(pattern).is_ok_and(|compiled| compiled.is_match(value))
}

fn is_external_locator(reference: &str) -> bool {
    reference.starts_with("https:")
        || reference.starts_with("doi:")
        || reference.starts_with("arxiv:")
}

fn canonical_or_absolute(path: &Path) -> PathBuf {
    if let Ok(resolved) = path.canonicalize() {
        return resolved;
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else if let Ok(directory) = env::current_dir() {
        directory.join(path)
    } else {
        path.to_path_buf()
    };
    normalize_lexically(&absolute)
}

fn normalize_lexically(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
            Component::RootDir | Component::Prefix(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}
