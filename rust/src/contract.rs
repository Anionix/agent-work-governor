use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::Serialize;

use crate::GovernorError;
use crate::model::{Finding, Status};
use crate::reference::resolve_contract_reference;

// LLM-CONTRACT
// id: agent-work-governor.rust-contract-validation
// state: UTF8_SOURCE -> CONTRACTS_PARSED -> PASS | FAIL
// preconditions: source, repository root, and bundle root are explicit
// invariant: comment shape and references are prechecks and never claim AST symbol attestation
// failure: return stable findings or a typed source-read fault without mutation
// source: bundle:knowledge/policies/work-governor.md
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: validate_file
// test: bundle:rust/tests/contract.rs

const REQUIRED_FIELDS: [&str; 9] = [
    "id",
    "state",
    "preconditions",
    "invariant",
    "failure",
    "source",
    "knowledge",
    "enforced_by",
    "test",
];

#[derive(Clone, Debug, Serialize)]
/// Read-only result of validating one source file's LLM contracts.
pub struct ContractReport {
    /// Canonical source path when available.
    pub path: String,
    /// Pass only when every shape and reference precheck succeeds.
    pub status: Status,
    /// Deterministic Python-compatible failures.
    pub findings: Vec<Finding>,
    /// Number of marker blocks discovered in the source.
    pub contract_count: usize,
    /// Number of filesystem mutations, always zero.
    pub mutation_count: u64,
}

#[derive(Clone, Debug)]
struct ParsedContract {
    fields: BTreeMap<String, String>,
}

impl ParsedContract {
    fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }
}

struct ReferenceValidationContext<'a> {
    source_path: &'a Path,
    repo_root: &'a Path,
    bundle_root: &'a Path,
    findings: &'a mut Vec<Finding>,
}

impl ReferenceValidationContext<'_> {
    fn validate_field(
        &mut self,
        contract: &ParsedContract,
        identifier: &str,
        field: &str,
        code: &str,
        allow_external: bool,
    ) {
        let Some(reference) = contract.field(field) else {
            return;
        };
        if let Err(error) =
            resolve_contract_reference(reference, self.repo_root, self.bundle_root, allow_external)
        {
            self.findings.push(contract_finding(
                code,
                self.source_path,
                Some(format!("{identifier}.{field}")),
                error.message().to_owned(),
            ));
        }
    }
}

pub(crate) fn validate_file(
    path: &Path,
    repo_root: &Path,
    bundle_root: &Path,
) -> Result<ContractReport, GovernorError> {
    let source = fs::read_to_string(path).map_err(|source| GovernorError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let report_path = canonical_or_display(path);
    let contracts = parsed_contracts(&source);
    let mut findings = Vec::new();

    if let Some(diagnostic) = contract_diagnostic(&contracts) {
        findings.push(contract_finding(
            "LLM_CONTRACT_INVALID",
            &report_path,
            None,
            diagnostic,
        ));
    } else {
        validate_references(
            &contracts,
            &source,
            &report_path,
            repo_root,
            bundle_root,
            &mut findings,
        );
    }
    sort_findings(&mut findings);

    Ok(ContractReport {
        path: report_path.display().to_string(),
        status: if findings.is_empty() {
            Status::Pass
        } else {
            Status::Fail
        },
        findings,
        contract_count: contracts.len(),
        mutation_count: 0,
    })
}

fn validate_references(
    contracts: &[ParsedContract],
    source: &str,
    source_path: &Path,
    repo_root: &Path,
    bundle_root: &Path,
    findings: &mut Vec<Finding>,
) {
    let mut context = ReferenceValidationContext {
        source_path,
        repo_root,
        bundle_root,
        findings,
    };
    for contract in contracts {
        let Some(identifier) = contract.field("id") else {
            continue;
        };
        context.validate_field(
            contract,
            identifier,
            "source",
            "LLM_CONTRACT_SOURCE_INVALID",
            true,
        );
        context.validate_field(
            contract,
            identifier,
            "knowledge",
            "LLM_CONTRACT_KNOWLEDGE_INVALID",
            false,
        );
        context.validate_field(
            contract,
            identifier,
            "test",
            "LLM_CONTRACT_TEST_INVALID",
            false,
        );

        let Some(symbol) = contract.field("enforced_by") else {
            continue;
        };
        if !enforcement_token_is_present(source, symbol) {
            context.findings.push(contract_finding(
                "LLM_CONTRACT_ENFORCEMENT_MISSING",
                context.source_path,
                Some(format!("{identifier}.enforced_by")),
                "enforced_by token is absent outside standalone comment metadata".to_owned(),
            ));
        }
    }
}

fn parsed_contracts(source: &str) -> Vec<ParsedContract> {
    let lines: Vec<&str> = source.lines().collect();
    let mut contracts = Vec::new();
    for (marker_index, line) in lines.iter().enumerate() {
        let Some(marker) = standalone_comment(line) else {
            continue;
        };
        if !marker.trim().eq_ignore_ascii_case("LLM-CONTRACT") {
            continue;
        }

        let mut fields = BTreeMap::new();
        for candidate in lines.iter().skip(marker_index + 1).take(16) {
            let Some(comment) = standalone_comment(candidate) else {
                if !fields.is_empty() {
                    break;
                }
                continue;
            };
            if let Some((key, value)) = contract_field(&comment) {
                fields.insert(key, value);
            }
        }
        contracts.push(ParsedContract { fields });
    }
    contracts
}

fn contract_diagnostic(contracts: &[ParsedContract]) -> Option<String> {
    if contracts.is_empty() {
        return Some("missing LLM-CONTRACT comment marker".to_owned());
    }

    let mut smallest_missing: Option<BTreeSet<&str>> = None;
    let mut identifiers = BTreeSet::new();
    for contract in contracts {
        let missing: BTreeSet<&str> = REQUIRED_FIELDS
            .iter()
            .copied()
            .filter(|field| !contract.fields.contains_key(*field))
            .collect();
        if !missing.is_empty() {
            if smallest_missing
                .as_ref()
                .is_none_or(|current| missing.len() < current.len())
            {
                smallest_missing = Some(missing);
            }
            continue;
        }

        if contract
            .field("state")
            .is_some_and(|state| !state.contains("->"))
        {
            return Some("state field must contain a transition arrow (->)".to_owned());
        }
        if let Some(identifier) = contract.field("id")
            && !identifiers.insert(identifier.to_owned())
        {
            return Some(format!(
                "contract id must be unique within the file: {identifier}"
            ));
        }
    }

    smallest_missing.map(|missing| {
        format!(
            "contract block is missing required fields: {}",
            missing.into_iter().collect::<Vec<_>>().join(", ")
        )
    })
}

fn standalone_comment(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let body = if let Some(rest) = trimmed.strip_prefix('#') {
        rest
    } else if trimmed.starts_with("//") {
        trimmed.trim_start_matches('/')
    } else if let Some(rest) = trimmed.strip_prefix("--") {
        rest
    } else if trimmed.starts_with("/*") {
        trimmed
            .strip_prefix('/')
            .map(|rest| rest.trim_start_matches('*'))?
    } else if trimmed.starts_with('*') {
        trimmed.trim_start_matches('*')
    } else {
        return None;
    };

    let body = body.trim();
    let content = body.strip_suffix("*/").map_or(body, str::trim_end);
    Some(content.trim().to_owned())
}

fn contract_field(comment: &str) -> Option<(String, String)> {
    let (raw_key, raw_value) = comment.trim().split_once(':')?;
    let key = REQUIRED_FIELDS
        .iter()
        .find(|candidate| raw_key.trim().eq_ignore_ascii_case(candidate))?;
    let value = raw_value.trim();
    if value.is_empty() {
        return None;
    }
    Some(((*key).to_owned(), value.to_owned()))
}

fn enforcement_token_is_present(source: &str, symbol: &str) -> bool {
    let executable_text = source
        .lines()
        .map(|line| {
            if standalone_comment(line).is_some() {
                ""
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let pattern = format!(r"\b{}\b", regex::escape(symbol));
    Regex::new(&pattern).is_ok_and(|compiled| compiled.is_match(&executable_text))
}

fn contract_finding(code: &str, path: &Path, field: Option<String>, message: String) -> Finding {
    Finding {
        code: code.to_owned(),
        message,
        field,
        path: Some(path.display().to_string()),
        severity: Some("error".to_owned()),
    }
}

fn canonical_or_display(path: &Path) -> PathBuf {
    match path.canonicalize() {
        Ok(canonical) => canonical,
        Err(_) => path.to_path_buf(),
    }
}

fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|left, right| {
        (
            left.code.as_str(),
            left.field.as_deref().map_or("", |field| field),
            left.message.as_str(),
        )
            .cmp(&(
                right.code.as_str(),
                right.field.as_deref().map_or("", |field| field),
                right.message.as_str(),
            ))
    });
}
