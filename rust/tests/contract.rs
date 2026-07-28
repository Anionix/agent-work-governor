//! Public-interface compatibility tests for Rust LLM contract prechecks.

use std::fs;
use std::path::PathBuf;

use agent_work_governor::{CheckReport, CheckRequest, Finding, Governor, Status};
use tempfile::{TempDir, tempdir};

// LLM-CONTRACT
// id: agent-work-governor.rust-contract-tests
// state: ISOLATED_FIXTURE -> GOVERNOR_CHECK -> COMPATIBLE_REPORT
// preconditions: fixtures are confined to temporary directories
// invariant: tests exercise the public read-only Governor Interface
// failure: the Rust test harness reports the violated compatibility contract
// source: bundle:knowledge/policies/work-governor.md
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: valid_contract_and_references_pass
// test: bundle:rust/tests/contract.rs

struct Fixture {
    _temporary: TempDir,
    repo: PathBuf,
    bundle: PathBuf,
    source: PathBuf,
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let temporary = tempdir()?;
    let repo = temporary.path().join("repo");
    let bundle = temporary.path().join("bundle");
    fs::create_dir_all(&repo)?;
    fs::create_dir_all(&bundle)?;
    fs::write(bundle.join("evidence.md"), "primary evidence\n")?;
    let source = repo.join("subject.rs");
    Ok(Fixture {
        _temporary: temporary,
        repo,
        bundle,
        source,
    })
}

fn contract_source(source_reference: &str, enforced_by: &str, body: &str) -> String {
    format!(
        "/* LLM-CONTRACT */\n\
         // id: fixture.contract\n\
         // state: INPUT -> OUTPUT\n\
         // preconditions: input exists\n\
         // invariant: output remains bounded\n\
         // failure: return a typed error\n\
         // source: {source_reference}\n\
         // knowledge: bundle:evidence.md\n\
         // enforced_by: {enforced_by}\n\
         // test: repo:subject.rs\n\
         {body}\n"
    )
}

fn check(fixture: &Fixture) -> Result<CheckReport, Box<dyn std::error::Error>> {
    Ok(Governor.check(CheckRequest::Contract {
        path: fixture.source.clone(),
        repo_root: fixture.repo.clone(),
        bundle_root: fixture.bundle.clone(),
    })?)
}

fn finding_message<'a>(findings: &'a [Finding], code: &str) -> Option<&'a str> {
    findings
        .iter()
        .find(|finding| finding.code == code)
        .map(|finding| finding.message.as_str())
}

#[test]
fn valid_contract_and_references_pass() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    fs::write(
        &fixture.source,
        contract_source(
            "bundle:evidence.md",
            "enforce_contract",
            "fn enforce_contract() {}",
        ),
    )?;

    let CheckReport::Contract(report) = check(&fixture)? else {
        return Err("unexpected report variant".into());
    };
    assert_eq!(Status::Pass, report.status);
    assert_eq!(1, report.contract_count);
    assert_eq!(0, report.mutation_count);
    assert!(report.findings.is_empty());
    assert_eq!(
        fixture.source.canonicalize()?.display().to_string(),
        report.path
    );
    Ok(())
}

#[test]
fn shape_diagnostics_match_python_contract() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let cases = [
        (
            "fn no_contract() {}\n".to_owned(),
            "missing LLM-CONTRACT comment marker",
        ),
        (
            "// LLM-CONTRACT\n".to_owned(),
            "contract block is missing required fields: enforced_by, failure, id, invariant, knowledge, preconditions, source, state, test",
        ),
        (
            contract_source(
                "bundle:evidence.md",
                "enforce_contract",
                "fn enforce_contract() {}",
            )
            .replace("INPUT -> OUTPUT", "ONLY_ONE_STATE"),
            "state field must contain a transition arrow (->)",
        ),
    ];

    for (source, expected) in cases {
        fs::write(&fixture.source, source)?;
        let CheckReport::Contract(report) = check(&fixture)? else {
            return Err("unexpected report variant".into());
        };
        assert_eq!(Status::Fail, report.status);
        assert_eq!(
            Some(expected),
            finding_message(&report.findings, "LLM_CONTRACT_INVALID")
        );
    }

    let complete = contract_source(
        "bundle:evidence.md",
        "enforce_contract",
        "fn enforce_contract() {}",
    );
    fs::write(&fixture.source, format!("{complete}\n{complete}"))?;
    let CheckReport::Contract(report) = check(&fixture)? else {
        return Err("unexpected report variant".into());
    };
    assert_eq!(
        Some("contract id must be unique within the file: fixture.contract"),
        finding_message(&report.findings, "LLM_CONTRACT_INVALID")
    );
    Ok(())
}

#[test]
fn immutable_external_sources_are_distinguished_from_mutable_locators()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let immutable = [
        "doi:10.1234/governor.1",
        "arxiv:2607.01236v2",
        "https://github.com/owner/repo/blob/0123456789abcdef0123456789abcdef01234567/source.rs",
    ];
    for reference in immutable {
        fs::write(
            &fixture.source,
            contract_source(reference, "enforce_contract", "fn enforce_contract() {}"),
        )?;
        let CheckReport::Contract(report) = check(&fixture)? else {
            return Err("unexpected report variant".into());
        };
        assert_eq!(Status::Pass, report.status);
    }

    fs::write(
        &fixture.source,
        contract_source(
            "https://github.com/owner/repo/blob/main/source.rs",
            "enforce_contract",
            "fn enforce_contract() {}",
        ),
    )?;
    let CheckReport::Contract(report) = check(&fixture)? else {
        return Err("unexpected report variant".into());
    };
    assert_eq!(
        Some("external source locator must be immutable"),
        finding_message(&report.findings, "LLM_CONTRACT_SOURCE_INVALID")
    );
    Ok(())
}

#[test]
fn percent_encoded_traversal_is_rejected_after_one_decode() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = fixture()?;
    fs::write(
        &fixture.source,
        contract_source(
            "bundle:%2e%2e/outside.md",
            "enforce_contract",
            "fn enforce_contract() {}",
        ),
    )?;
    let CheckReport::Contract(report) = check(&fixture)? else {
        return Err("unexpected report variant".into());
    };
    assert_eq!(
        Some("reference contains an unsafe path"),
        finding_message(&report.findings, "LLM_CONTRACT_SOURCE_INVALID")
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlink_escape_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let fixture = fixture()?;
    let outside = fixture
        .bundle
        .parent()
        .ok_or("bundle has no parent")?
        .join("outside.md");
    fs::write(&outside, "outside\n")?;
    symlink(&outside, fixture.bundle.join("escape.md"))?;
    fs::write(
        &fixture.source,
        contract_source(
            "bundle:escape.md",
            "enforce_contract",
            "fn enforce_contract() {}",
        ),
    )?;

    let CheckReport::Contract(report) = check(&fixture)? else {
        return Err("unexpected report variant".into());
    };
    assert_eq!(
        Some("reference escapes its declared root"),
        finding_message(&report.findings, "LLM_CONTRACT_SOURCE_INVALID")
    );
    Ok(())
}

#[test]
fn enforcement_token_must_exist_outside_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    fs::write(
        &fixture.source,
        contract_source("bundle:evidence.md", "ghost_symbol", ""),
    )?;
    let CheckReport::Contract(report) = check(&fixture)? else {
        return Err("unexpected report variant".into());
    };
    assert_eq!(
        Some("enforced_by token is absent outside standalone comment metadata"),
        finding_message(&report.findings, "LLM_CONTRACT_ENFORCEMENT_MISSING")
    );

    fs::write(
        &fixture.source,
        contract_source("bundle:evidence.md", "ghost_symbol", "fn ghost_symbol() {}"),
    )?;
    let CheckReport::Contract(report) = check(&fixture)? else {
        return Err("unexpected report variant".into());
    };
    assert_eq!(Status::Pass, report.status);
    Ok(())
}

#[test]
fn missing_repo_test_reference_is_a_typed_finding() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let source = contract_source(
        "bundle:evidence.md",
        "enforce_contract",
        "fn enforce_contract() {}",
    )
    .replace("repo:subject.rs", "repo:missing.rs");
    fs::write(&fixture.source, source)?;

    let CheckReport::Contract(report) = check(&fixture)? else {
        return Err("unexpected report variant".into());
    };
    assert_eq!(
        Some("reference does not name an existing regular file"),
        finding_message(&report.findings, "LLM_CONTRACT_TEST_INVALID")
    );
    Ok(())
}
