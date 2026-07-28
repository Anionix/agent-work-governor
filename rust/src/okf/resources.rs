use std::path::{Path, PathBuf};

use crate::model::Finding;

use super::issue;

// LLM-CONTRACT
// id: agent-work-governor.rust-okf-resources
// state: DECLARED_RESOURCE -> EXPLICIT_LOCATION -> EXISTS | MISSING | EXTERNAL
// preconditions: document and bundle paths are explicit validation inputs
// invariant: computation resources and Markdown links share one read-only location rule
// failure: preserve the stable missing-resource or broken-link finding without mutation
// source: https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/3fcbb9f828c2f23d109c855ee403c3a4c81f3a96/okf/SPEC.md
// knowledge: bundle:knowledge/references/okf-v0.2.md
// enforced_by: resource_exists
// test: bundle:rust/tests/okf.rs

#[must_use]
fn local_resource_path(resource: &str, document: &Path, bundle: &Path) -> PathBuf {
    if resource.starts_with('/') {
        bundle.join(resource.trim_start_matches('/'))
    } else {
        document
            .parent()
            .map_or_else(|| PathBuf::from(resource), |parent| parent.join(resource))
    }
}

#[must_use]
pub(super) fn resource_exists(resource: &str, document: &Path, bundle: &Path) -> bool {
    resource.contains("://") || local_resource_path(resource, document, bundle).exists()
}

#[must_use]
fn markdown_targets(body: &str) -> Vec<&str> {
    let mut targets = Vec::new();
    let mut remainder = body;
    while let Some(open) = remainder.find('[') {
        let after_open = &remainder[(open + 1)..];
        let Some(label_end) = after_open.find("](") else {
            break;
        };
        if label_end == 0 {
            remainder = &after_open[2..];
            continue;
        }
        let after_label = &after_open[(label_end + 2)..];
        let Some(target_end) = after_label.find(')') else {
            break;
        };
        if target_end > 0 {
            targets.push(&after_label[..target_end]);
        }
        remainder = &after_label[(target_end + 1)..];
    }
    targets
}

#[must_use]
pub(super) fn link_warnings(body: &str, path: &Path, bundle: &Path) -> Vec<Finding> {
    let mut warnings = Vec::new();
    for raw_target in markdown_targets(body) {
        let target = raw_target
            .split_once('#')
            .map_or(raw_target, |(head, _)| head);
        if target.is_empty() || target.contains("://") || target.starts_with("mailto:") {
            continue;
        }
        let mut resolved = local_resource_path(target, path, bundle);
        if target.ends_with('/') {
            resolved.push("index.md");
        }
        if !resolved.exists() {
            warnings.push(issue(
                "BROKEN_LINK_ALLOWED_BY_OKF",
                path,
                format!("unresolved link: {raw_target}"),
            ));
        }
    }
    warnings
}
