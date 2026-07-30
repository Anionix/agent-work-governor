//! External `OwnerScopeReceipt` integration tests.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use agent_work_governor::{
    CheckReport, CheckRequest, EffectiveAuthority, Governor, OwnerScopeFailure, OwnerScopeInput,
    OwnerScopeVerification, RepositoryPolicySnapshot, Status, evaluate_owner_scope,
};
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

// LLM-CONTRACT
// id: agent-work-governor.owner-scope-tests
// state: SIGNED_FIXTURE + TRUSTED_BINDINGS -> INTERSECTION | CLOSED_FAILURE
// preconditions: fixtures use separate repository and external evidence directories
// invariant: copied policy, altered binding, stale time, invalid signature, and local evidence never grant authority
// failure: the Rust test harness reports a non-closed result
// source: https://github.com/dalek-cryptography/curve25519-dalek/blob/8016d6d9b9cdbaa681f24147e0b9377cc8cef934/ed25519-dalek/src/verifying.rs
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: valid_receipt_only_grants_the_three_way_intersection
// test: bundle:rust/tests/owner_scope.rs

const REPOSITORY_ID: u64 = 123_456;
const OWNER_ID: u64 = 789;
const FULL_NAME: &str = "Anionix/agent-work-governor";
const NOW: u64 = 2_000_000_000;
const MISMATCHED_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum InputMutation {
    None,
    Missing,
    Malformed,
    ContradictoryKey,
    WrongRepository,
    WrongOwner,
    InvalidSignature,
}

const REQUIRED_CASE_COUNT: usize = 14;
const FULL_AUTHORITY: EffectiveAuthority = authority(true, true);
const REQUIRED_CASE_IDS: [&str; REQUIRED_CASE_COUNT] = [
    "contradictory-key",
    "expired",
    "invalid-signature",
    "malformed",
    "missing",
    "policy-digest-mismatch",
    "policy-external-denial",
    "policy-repository-denial",
    "receipt-external-denial",
    "receipt-repository-denial",
    "runtime-external-denial",
    "runtime-repository-denial",
    "wrong-owner",
    "wrong-repository",
];

const fn authority(repository_write: bool, external_side_effects: bool) -> EffectiveAuthority {
    EffectiveAuthority {
        repository_write,
        external_side_effects,
    }
}

fn closed_decision(code: &str) -> ComparableDecision {
    ComparableDecision {
        status: Status::Fail,
        code: code.to_owned(),
        verification: OwnerScopeVerification::Rejected,
        repository_write: false,
        external_side_effects: false,
        exit_class: ExitClass::Fail,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ExitClass {
    Pass,
    Fail,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DifferentialCorpus {
    schema_version: String,
    cases: Vec<DifferentialCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DifferentialCase {
    id: String,
    expires_at: u64,
    policy_digest_mismatch: bool,
    policy_authority: EffectiveAuthority,
    receipt_authority: EffectiveAuthority,
    runtime_authority: EffectiveAuthority,
    input_mutation: InputMutation,
    expected: ComparableDecision,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ComparableDecision {
    status: Status,
    code: String,
    verification: OwnerScopeVerification,
    repository_write: bool,
    external_side_effects: bool,
    exit_class: ExitClass,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteReport {
    status: Status,
    code: String,
    owner_scope_verification: OwnerScopeVerification,
    effective_authority: EffectiveAuthority,
    mutation_count: u64,
}

impl RouteReport {
    fn is_consistent(&self) -> bool {
        let closed = self.effective_authority == EffectiveAuthority::default();
        let decision = match self.owner_scope_verification {
            OwnerScopeVerification::Required => {
                self.status == Status::Fail && self.code == "OWNER_SCOPE_RECEIPT_REQUIRED" && closed
            }
            OwnerScopeVerification::Rejected => {
                self.status == Status::Fail
                    && [
                        "OWNER_SCOPE_BINDING_MISMATCH",
                        "OWNER_SCOPE_EVIDENCE_INSIDE_REPOSITORY",
                        "OWNER_SCOPE_EVIDENCE_INVALID",
                        "OWNER_SCOPE_KEY_INVALID",
                        "OWNER_SCOPE_NOT_APPLICABLE",
                        "OWNER_SCOPE_POLICY_INVALID",
                        "OWNER_SCOPE_RECEIPT_EXPIRED",
                        "OWNER_SCOPE_RECEIPT_INVALID",
                        "OWNER_SCOPE_SIGNATURE_INVALID",
                    ]
                    .contains(&self.code.as_str())
                    && closed
            }
            OwnerScopeVerification::Verified => {
                self.status == Status::Pass && self.code == "OWNER_SCOPE_VERIFIED"
            }
            OwnerScopeVerification::NotApplicable => false,
        };
        self.mutation_count == 0 && decision
    }
}

struct Fixture {
    _root: TempDir,
    repo: PathBuf,
    receipt: PathBuf,
    public_key: PathBuf,
    key_sha256: String,
}

impl Fixture {
    fn new(
        expires_at: u64,
        policy_digest_override: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_authority(
            expires_at,
            policy_digest_override,
            None,
            FULL_AUTHORITY,
            FULL_AUTHORITY,
        )
    }

    fn with_policy(
        expires_at: u64,
        policy_digest_override: Option<&str>,
        repository_write: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_authority(
            expires_at,
            policy_digest_override,
            None,
            EffectiveAuthority {
                repository_write,
                external_side_effects: true,
            },
            FULL_AUTHORITY,
        )
    }

    fn with_authority(
        expires_at: u64,
        policy_digest_override: Option<&str>,
        repository_scope: Option<&str>,
        policy_authority: EffectiveAuthority,
        receipt_authority: EffectiveAuthority,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let repo = root.path().join("repo");
        let evidence = root.path().join("external");
        fs::create_dir_all(repo.join(".agent-work-governor"))?;
        fs::create_dir(&evidence)?;
        let mut policy_bytes =
            fs::read_to_string(plugin_root()?.join("assets/presets/owner-original.toml"))?;
        policy_bytes = policy_bytes.replace(
            "repository_scope = \"owner_original\"",
            &format!(
                "repository_scope = \"{}\"",
                repository_scope.unwrap_or("owner_original")
            ),
        );
        if !policy_authority.repository_write {
            policy_bytes =
                policy_bytes.replace("repository_write = true", "repository_write = false");
        }
        if !policy_authority.external_side_effects {
            policy_bytes = policy_bytes.replace(
                "external_side_effects = true",
                "external_side_effects = false",
            );
        }
        let policy_bytes = policy_bytes.into_bytes();
        fs::write(repo.join(".agent-work-governor/policy.toml"), &policy_bytes)?;
        let actual_policy_sha256 = hex(&Sha256::digest(&policy_bytes));
        let receipt_policy_sha256 =
            policy_digest_override.map_or_else(|| actual_policy_sha256.clone(), str::to_owned);
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let public_key_bytes = signing_key.verifying_key().to_bytes();
        let key_sha256 = hex(&Sha256::digest(public_key_bytes));
        let public_key = evidence.join("owner.pub");
        fs::write(&public_key, public_key_bytes)?;
        let payload = serde_json::to_vec(&serde_json::json!({
            "schema_version": "0.1",
            "repository_id": REPOSITORY_ID,
            "owner_id": OWNER_ID,
            "repository_full_name": FULL_NAME,
            "policy_sha256": receipt_policy_sha256,
            "issuer": "test-root",
            "key_id": &key_sha256,
            "issued_at": NOW - 60,
            "expires_at": expires_at,
            "repository_write": receipt_authority.repository_write,
            "external_side_effects": receipt_authority.external_side_effects
        }))?;
        let mut message = b"agent-work-governor-owner-scope-v1\n".to_vec();
        message.extend_from_slice(&payload);
        let signature = hex(&signing_key.sign(&message).to_bytes());
        let receipt_bytes = format!(
            "{{\"payload\":{},\"signature_hex\":\"{signature}\"}}",
            std::str::from_utf8(&payload)?
        );
        let receipt = evidence.join("owner-receipt.json");
        fs::write(&receipt, receipt_bytes)?;
        Ok(Self {
            _root: root,
            repo,
            receipt,
            public_key,
            key_sha256,
        })
    }

    fn input(&self) -> OwnerScopeInput {
        OwnerScopeInput {
            receipt_path: self.receipt.clone(),
            public_key_path: self.public_key.clone(),
            trusted_key_sha256: self.key_sha256.clone(),
            repository_id: REPOSITORY_ID,
            owner_id: OWNER_ID,
            repository_full_name: FULL_NAME.to_owned(),
            issuer: "test-root".to_owned(),
            now_epoch_seconds: NOW,
            runtime_authority: EffectiveAuthority {
                repository_write: true,
                external_side_effects: false,
            },
        }
    }

    fn check(&self, input: &OwnerScopeInput) -> Result<EffectiveAuthority, OwnerScopeFailure> {
        RepositoryPolicySnapshot::load(&self.repo)?.verify(input)
    }
}

fn plugin_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "Rust crate must have a plugin parent".into())
}

#[test]
fn valid_receipt_only_grants_the_three_way_intersection() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = Fixture::new(NOW + 60, None)?;
    let authority = fixture.check(&fixture.input())?;
    assert!(authority.repository_write);
    assert!(!authority.external_side_effects);
    Ok(())
}

#[test]
fn signed_policy_digest_cannot_be_combined_with_different_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::with_policy(NOW + 60, None, false)?;
    let authority = fixture.check(&fixture.input())?;
    assert!(!authority.repository_write);
    Ok(())
}

#[test]
fn owner_scope_cli_rejects_receipt_for_replaced_repository_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(NOW + 60, None)?;
    let policy_path = fixture.repo.join(".agent-work-governor/policy.toml");
    let restricted = fs::read_to_string(&policy_path)?
        .replace("repository_write = true", "repository_write = false");
    fs::write(policy_path, restricted)?;

    let input = fixture.input();
    let result = run_route(
        Command::new(env!("CARGO_BIN_EXE_agent-work-governor"))
            .args(cli_arguments(&fixture, Some(&input))),
    )?;
    assert_eq!(closed_decision("OWNER_SCOPE_BINDING_MISMATCH"), result);
    Ok(())
}

#[test]
fn owner_scope_cli_rejects_non_owner_policy_with_matching_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    // LLM contract: valid non-owner policy + matching signed receipt -> stable
    // not-applicable failure; zero authority cannot be mislabeled VERIFIED.
    let fixture = Fixture::with_authority(
        NOW + 60,
        None,
        Some("external_read_only"),
        EffectiveAuthority::default(),
        FULL_AUTHORITY,
    )?;
    let input = fixture.input();
    assert_closed(fixture.check(&input), "OWNER_SCOPE_NOT_APPLICABLE");

    let result = run_route(
        Command::new(env!("CARGO_BIN_EXE_agent-work-governor"))
            .args(cli_arguments(&fixture, Some(&input))),
    )?;
    assert_eq!(closed_decision("OWNER_SCOPE_NOT_APPLICABLE"), result);
    Ok(())
}

#[test]
fn repository_report_preserves_blockers_and_closes_verifier_failures()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(NOW + 60, None)?;
    let CheckReport::Repository(verified) = Governor.check(CheckRequest::Repository {
        repo: fixture.repo.clone(),
        plugin_root: plugin_root()?,
        owner_scope: Some(fixture.input()),
    })?
    else {
        return Err("unexpected report variant".into());
    };
    assert_eq!(Status::Fail, verified.status);
    assert_eq!(
        OwnerScopeVerification::Verified,
        verified.owner_scope_verification
    );
    assert!(verified.effective_authority.repository_write);
    assert!(!verified.effective_authority.external_side_effects);
    assert_eq!(
        Some("LLM_CONTRACT_AST_ATTESTATION_REQUIRED"),
        verified.blocker.as_deref()
    );

    let mut invalid = fixture.input();
    invalid.issuer = "wrong-root".to_owned();
    let CheckReport::Repository(rejected) = Governor.check(CheckRequest::Repository {
        repo: fixture.repo.clone(),
        plugin_root: plugin_root()?,
        owner_scope: Some(invalid),
    })?
    else {
        return Err("unexpected report variant".into());
    };
    assert_eq!(
        OwnerScopeVerification::Rejected,
        rejected.owner_scope_verification
    );
    assert_eq!(EffectiveAuthority::default(), rejected.effective_authority);
    assert!(
        rejected
            .findings
            .iter()
            .any(|finding| finding.code == "OWNER_SCOPE_BINDING_MISMATCH")
    );
    Ok(())
}

#[test]
fn receipt_binding_expiry_and_signature_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let mismatch = Fixture::new(NOW + 60, Some(&"0".repeat(64)))?;
    assert_closed(
        mismatch.check(&mismatch.input()),
        "OWNER_SCOPE_BINDING_MISMATCH",
    );

    let key_mismatch = Fixture::new(NOW + 60, None)?;
    let mut input = key_mismatch.input();
    input.trusted_key_sha256 = "0".repeat(64);
    assert_closed(key_mismatch.check(&input), "OWNER_SCOPE_BINDING_MISMATCH");

    let repository_mismatch = Fixture::new(NOW + 60, None)?;
    let mut input = repository_mismatch.input();
    input.repository_id += 1;
    assert_closed(
        repository_mismatch.check(&input),
        "OWNER_SCOPE_BINDING_MISMATCH",
    );

    let owner_mismatch = Fixture::new(NOW + 60, None)?;
    let mut input = owner_mismatch.input();
    input.owner_id += 1;
    assert_closed(owner_mismatch.check(&input), "OWNER_SCOPE_BINDING_MISMATCH");

    let issuer_mismatch = Fixture::new(NOW + 60, None)?;
    let mut input = issuer_mismatch.input();
    input.issuer = "another-root".to_owned();
    assert_closed(
        issuer_mismatch.check(&input),
        "OWNER_SCOPE_BINDING_MISMATCH",
    );

    let expired = Fixture::new(NOW, None)?;
    assert_closed(
        expired.check(&expired.input()),
        "OWNER_SCOPE_RECEIPT_EXPIRED",
    );

    let invalid = Fixture::new(NOW + 60, None)?;
    let mut receipt = fs::read_to_string(&invalid.receipt)?;
    receipt.replace_range(receipt.len() - 3..receipt.len() - 2, "0");
    fs::write(&invalid.receipt, receipt)?;
    assert_closed(
        invalid.check(&invalid.input()),
        "OWNER_SCOPE_SIGNATURE_INVALID",
    );
    Ok(())
}

// LLM-CONTRACT
// id: agent-work-governor.owner-scope-differential-acceptance
// state: VERSIONED_CASE_BYTES -> RUST_CLI + PYTHON_DISPATCH -> EXACT_PARITY | CLOSED_FAILURE
// preconditions: each case gets one shared repository, receipt, key, and argument snapshot
// invariant: Python only forwards the exact Rust arguments and cannot independently grant authority
// failure: schema drift, case omission, route failure, partial output, or any mismatch fails the test
// source: doi:10.17487/RFC8785
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: owner_scope_differential_acceptance
// test: bundle:rust/tests/owner_scope.rs
#[test]
#[ignore = "runs in the separate proof-slow differential gate"]
fn owner_scope_differential_acceptance() -> Result<(), Box<dyn std::error::Error>> {
    assert_differential_schemas_fail_closed()?;
    let corpus = load_corpus(include_str!("fixtures/owner-scope-differential.json"))?;

    let root = plugin_root()?;
    let rust_binary = Path::new(env!("CARGO_BIN_EXE_agent-work-governor"));
    let python_adapter = root.join("rust/tests/fixtures/python_owner_scope_adapter.py");
    let fixture_count = corpus.cases.len();

    for case in corpus.cases {
        let (fixture, input) = materialize_case(&case)?;
        let arguments = cli_arguments(&fixture, input.as_ref());
        let direct = run_route(Command::new(rust_binary).args(&arguments))?;
        let adapter = run_route(
            Command::new("python3")
                .arg(&python_adapter)
                .arg(rust_binary)
                .args(&arguments),
        )?;
        assert_eq!(direct, adapter, "route mismatch for {}", case.id);
        assert_eq!(case.expected, direct, "unexpected result for {}", case.id);
    }
    println!(
        "{}",
        serde_json::json!({
            "code": "DIFFERENTIAL_ACCEPTANCE_PASSED",
            "fixture_count": fixture_count,
            "python_adapter_sha256": file_sha256(&python_adapter)?,
            "python_dispatch_sha256": file_sha256(&root.join("scripts/rust_dispatch.py"))?,
            "rust_artifact_sha256": file_sha256(rust_binary)?,
            "schema_version": corpus.schema_version,
            "status": "PASS"
        })
    );
    Ok(())
}

fn assert_differential_schemas_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let unknown_schema = include_str!("fixtures/owner-scope-differential.json").replacen(
        "\"schema_version\": \"0.1\"",
        "\"schema_version\": \"9\"",
        1,
    );
    assert!(load_corpus(&unknown_schema).is_err());

    let baseline: serde_json::Value = serde_json::from_str(concat!(
        r#"{"status":"FAIL","code":"OWNER_SCOPE_RECEIPT_REQUIRED","#,
        r#""owner_scope_verification":"REQUIRED","#,
        r#""effective_authority":{"repository_write":false,"external_side_effects":false},"mutation_count":0}"#
    ))?;
    assert!(normalize_route(&serde_json::to_vec(&baseline)?, 1).is_ok());

    let mut partial = baseline.clone();
    partial
        .as_object_mut()
        .ok_or("synthetic report is not an object")?
        .remove("code");
    assert!(normalize_route(&serde_json::to_vec(&partial)?, 1).is_err());

    let mut unknown = baseline.clone();
    unknown
        .as_object_mut()
        .ok_or("synthetic report is not an object")?
        .insert("unexpected".to_owned(), serde_json::Value::Bool(true));
    assert!(normalize_route(&serde_json::to_vec(&unknown)?, 1).is_err());

    let mut contradictory = baseline;
    contradictory
        .as_object_mut()
        .ok_or("synthetic report is not an object")?
        .insert(
            "code".to_owned(),
            serde_json::Value::String("OWNER_SCOPE_BINDING_MISMATCH".to_owned()),
        );
    assert!(normalize_route(&serde_json::to_vec(&contradictory)?, 1).is_err());

    let mut mutated = serde_json::from_value::<serde_json::Value>(serde_json::json!({
        "status": "PASS",
        "code": "OWNER_SCOPE_VERIFIED",
        "owner_scope_verification": "VERIFIED",
        "effective_authority": {
            "repository_write": true,
            "external_side_effects": true
        },
        "mutation_count": 0
    }))?;
    mutated
        .as_object_mut()
        .ok_or("synthetic report is not an object")?
        .insert("mutation_count".to_owned(), serde_json::Value::from(1));
    assert!(normalize_route(&serde_json::to_vec(&mutated)?, 0).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlinked_receipt_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new(NOW + 60, None)?;
    let linked = fixture.receipt.with_extension("link");
    symlink(&fixture.receipt, &linked)?;
    let mut input = fixture.input();
    input.receipt_path = linked;
    assert_closed(fixture.check(&input), "OWNER_SCOPE_EVIDENCE_INVALID");
    Ok(())
}

#[cfg(unix)]
#[test]
fn repository_check_does_not_reopen_a_refused_policy_symlink()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    // LLM contract: refused descriptor snapshot + valid symlink target ->
    // POLICY_INVALID; pathname fallback cannot turn closed state into PASS.
    let fixture = Fixture::new(NOW + 60, None)?;
    let policy_path = fixture.repo.join(".agent-work-governor/policy.toml");
    let external_policy = fixture.public_key.with_file_name("external-policy.toml");
    let policy = fs::read_to_string(&policy_path)?
        .replace(
            "repository_scope = \"owner_original\"",
            "repository_scope = \"external_read_only\"",
        )
        .replace("repository_write = true", "repository_write = false")
        .replace(
            "external_side_effects = true",
            "external_side_effects = false",
        );
    fs::write(&external_policy, policy)?;
    let CheckReport::Policy(external_report) = Governor.check(CheckRequest::Policy {
        path: external_policy.clone(),
    })?
    else {
        return Err("unexpected report variant".into());
    };
    assert!(external_report.valid);
    fs::remove_file(&policy_path)?;
    symlink(&external_policy, &policy_path)?;

    let CheckReport::Repository(report) = Governor.check(CheckRequest::Repository {
        repo: fixture.repo.clone(),
        plugin_root: plugin_root()?,
        owner_scope: None,
    })?
    else {
        return Err("unexpected report variant".into());
    };
    assert_eq!(Status::Fail, report.status);
    assert_eq!(Some("POLICY_INVALID"), report.blocker.as_deref());
    assert_eq!(EffectiveAuthority::default(), report.effective_authority);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "POLICY_PARSE_ERROR")
    );
    Ok(())
}

#[test]
fn repository_local_receipt_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(NOW + 60, None)?;
    let local = fixture.repo.join("receipt.json");
    fs::copy(&fixture.receipt, &local)?;
    let mut input = fixture.input();
    input.receipt_path = local;
    assert_closed(
        fixture.check(&input),
        "OWNER_SCOPE_EVIDENCE_INSIDE_REPOSITORY",
    );
    Ok(())
}

#[test]
fn renamed_repository_snapshot_still_rejects_local_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    // LLM contract: opened repository identity + later path rename -> the same
    // containment boundary or closed failure; renaming cannot externalize evidence.
    let fixture = Fixture::new(NOW + 60, None)?;
    let snapshot = RepositoryPolicySnapshot::load(&fixture.repo)?;
    let moved = fixture.repo.with_file_name("moved-repo");
    fs::rename(&fixture.repo, &moved)?;
    let mut input = fixture.input();
    input.receipt_path = moved.join("receipt.json");
    input.public_key_path = moved.join("owner.pub");
    fs::copy(&fixture.receipt, &input.receipt_path)?;
    fs::copy(&fixture.public_key, &input.public_key_path)?;

    assert_closed_report(
        evaluate_owner_scope(&snapshot, Some(&input)),
        "OWNER_SCOPE_EVIDENCE_INSIDE_REPOSITORY",
    )?;
    let report = Governor.check_repository(&snapshot, &plugin_root()?, Some(&input))?;
    assert_eq!(
        OwnerScopeVerification::Rejected,
        report.owner_scope_verification
    );
    assert_eq!(EffectiveAuthority::default(), report.effective_authority);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "OWNER_SCOPE_EVIDENCE_INSIDE_REPOSITORY")
    );
    Ok(())
}

#[test]
fn public_evaluator_rejects_local_evidence_with_noncanonical_repository_path()
-> Result<(), Box<dyn std::error::Error>> {
    // LLM contract: noncanonical repository spelling + local evidence -> one
    // descriptor-normalized boundary or closed failure; lexical aliases grant nothing.
    let fixture = Fixture::new(NOW + 60, None)?;
    let mut input = fixture.input();
    input.receipt_path = fixture.repo.join("receipt.json");
    input.public_key_path = fixture.repo.join("owner.pub");
    fs::copy(&fixture.receipt, &input.receipt_path)?;
    fs::copy(&fixture.public_key, &input.public_key_path)?;
    let noncanonical = fixture.repo.join("..").join("repo");
    let snapshot = RepositoryPolicySnapshot::load(&noncanonical)?;

    assert_closed_report(
        evaluate_owner_scope(&snapshot, Some(&input)),
        "OWNER_SCOPE_EVIDENCE_INSIDE_REPOSITORY",
    )?;
    Ok(())
}

#[test]
fn oversized_receipt_and_wrong_key_length_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let oversized = Fixture::new(NOW + 60, None)?;
    fs::write(&oversized.receipt, vec![b'x'; 16 * 1024 + 1])?;
    assert_closed(
        oversized.check(&oversized.input()),
        "OWNER_SCOPE_EVIDENCE_INVALID",
    );

    let wrong_key = Fixture::new(NOW + 60, None)?;
    fs::write(&wrong_key.public_key, [0_u8; 31])?;
    assert_closed(
        wrong_key.check(&wrong_key.input()),
        "OWNER_SCOPE_KEY_INVALID",
    );
    Ok(())
}

fn assert_closed(result: Result<EffectiveAuthority, OwnerScopeFailure>, code: &str) {
    assert_eq!(result.map_err(|error| error.code), Err(code));
}

fn assert_closed_report(
    report: agent_work_governor::OwnerScopeReport,
    code: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let report: RouteReport = serde_json::from_value(serde_json::to_value(report)?)?;
    assert!(report.is_consistent());
    assert_eq!(code, report.code);
    assert_eq!(EffectiveAuthority::default(), report.effective_authority);
    Ok(())
}

fn materialize_case(
    case: &DifferentialCase,
) -> Result<(Fixture, Option<OwnerScopeInput>), Box<dyn std::error::Error>> {
    let digest_override = case.policy_digest_mismatch.then_some(MISMATCHED_SHA256);
    let fixture = Fixture::with_authority(
        case.expires_at,
        digest_override,
        None,
        case.policy_authority,
        case.receipt_authority,
    )?;
    if case.input_mutation == InputMutation::Missing {
        return Ok((fixture, None));
    }
    let mut input = fixture.input();
    input.runtime_authority = case.runtime_authority;
    match case.input_mutation {
        InputMutation::Malformed => fs::write(&fixture.receipt, b"{")?,
        InputMutation::ContradictoryKey => {
            MISMATCHED_SHA256.clone_into(&mut input.trusted_key_sha256);
        }
        InputMutation::WrongRepository => input.repository_id += 1,
        InputMutation::WrongOwner => input.owner_id += 1,
        InputMutation::InvalidSignature => corrupt_signature(&fixture.receipt)?,
        InputMutation::None | InputMutation::Missing => {}
    }
    Ok((fixture, Some(input)))
}

fn cli_arguments(fixture: &Fixture, input: Option<&OwnerScopeInput>) -> Vec<String> {
    let mut arguments = vec![
        "owner-scope".to_owned(),
        "--repo".to_owned(),
        fixture.repo.display().to_string(),
    ];
    if let Some(input) = input {
        for (flag, value) in [
            ("--owner-receipt", input.receipt_path.display().to_string()),
            (
                "--owner-public-key",
                input.public_key_path.display().to_string(),
            ),
            (
                "--owner-trusted-key-sha256",
                input.trusted_key_sha256.clone(),
            ),
            ("--owner-repository-id", input.repository_id.to_string()),
            ("--owner-id", input.owner_id.to_string()),
            (
                "--owner-repository-full-name",
                input.repository_full_name.clone(),
            ),
            ("--owner-issuer", input.issuer.clone()),
            (
                "--owner-now-epoch-seconds",
                input.now_epoch_seconds.to_string(),
            ),
            (
                "--runtime-repository-write",
                input.runtime_authority.repository_write.to_string(),
            ),
            (
                "--runtime-external-side-effects",
                input.runtime_authority.external_side_effects.to_string(),
            ),
        ] {
            arguments.extend([flag.to_owned(), value]);
        }
    }
    arguments
}

fn run_route(command: &mut Command) -> Result<ComparableDecision, Box<dyn std::error::Error>> {
    let output = command.output()?;
    let exit_code = output
        .status
        .code()
        .ok_or("differential route terminated without an exit code")?;
    normalize_route(&output.stdout, exit_code).map_err(|error| {
        format!(
            "{error}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into()
    })
}

fn load_corpus(source: &str) -> Result<DifferentialCorpus, Box<dyn std::error::Error>> {
    let corpus: DifferentialCorpus = serde_json::from_str(source)?;
    if corpus.schema_version != "0.1" {
        return Err(format!("unsupported differential schema: {}", corpus.schema_version).into());
    }
    if corpus.cases.len() != REQUIRED_CASE_COUNT {
        return Err("differential corpus has an incomplete case count".into());
    }
    let case_ids = corpus
        .cases
        .iter()
        .map(|case| case.id.as_str())
        .collect::<BTreeSet<_>>();
    let required_ids = REQUIRED_CASE_IDS.into_iter().collect::<BTreeSet<_>>();
    if case_ids != required_ids {
        return Err("differential corpus has duplicate or missing case ids".into());
    }
    Ok(corpus)
}

fn normalize_route(
    stdout: &[u8],
    exit_code: i32,
) -> Result<ComparableDecision, Box<dyn std::error::Error>> {
    let report = decode_route(stdout)?;
    if !report.is_consistent() {
        return Err("differential report has contradictory decision fields".into());
    }
    let exit_class = match exit_code {
        0 => ExitClass::Pass,
        1 => ExitClass::Fail,
        _ => return Err("differential route returned an unsupported exit code".into()),
    };
    if (report.status == Status::Pass) != (exit_class == ExitClass::Pass) {
        return Err("differential status and exit class disagree".into());
    }
    Ok(ComparableDecision {
        status: report.status,
        code: report.code,
        verification: report.owner_scope_verification,
        repository_write: report.effective_authority.repository_write,
        external_side_effects: report.effective_authority.external_side_effects,
        exit_class,
    })
}

fn decode_route(stdout: &[u8]) -> Result<RouteReport, Box<dyn std::error::Error>> {
    serde_json::from_slice(stdout)
        .map_err(|error| format!("differential route returned invalid JSON: {error}").into())
}

fn file_sha256(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    Ok(hex(&Sha256::digest(fs::read(path)?)))
}

fn corrupt_signature(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut receipt = fs::read_to_string(path)?;
    let marker = "\"signature_hex\":\"";
    let index = receipt
        .find(marker)
        .ok_or("signed receipt has no signature field")?
        + marker.len();
    let replacement = if receipt.as_bytes()[index] == b'0' {
        "1"
    } else {
        "0"
    };
    receipt.replace_range(index..=index, replacement);
    fs::write(path, receipt)?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
