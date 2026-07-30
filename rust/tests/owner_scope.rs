//! External `OwnerScopeReceipt` integration tests.

use std::fs;
use std::path::{Path, PathBuf};

use agent_work_governor::{
    CheckReport, CheckRequest, EffectiveAuthority, Governor, OwnerScopeFailure, OwnerScopeInput,
    OwnerScopeVerification, Status, ValidatedPolicyAuthority, verify_owner_scope,
};
use ed25519_dalek::{Signer, SigningKey};
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

struct Fixture {
    _root: TempDir,
    repo: PathBuf,
    policy: ValidatedPolicyAuthority,
    receipt: PathBuf,
    public_key: PathBuf,
    key_sha256: String,
}

impl Fixture {
    fn new(
        expires_at: u64,
        policy_digest_override: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_policy(expires_at, policy_digest_override, true)
    }

    fn with_policy(
        expires_at: u64,
        policy_digest_override: Option<&str>,
        repository_write: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let repo = root.path().join("repo");
        let evidence = root.path().join("external");
        fs::create_dir_all(repo.join(".agent-work-governor"))?;
        fs::create_dir(&evidence)?;
        let plugin_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or("Rust crate must have a plugin parent")?
            .to_path_buf();
        let mut policy_bytes =
            fs::read_to_string(plugin_root.join("assets/presets/owner-original.toml"))?;
        if !repository_write {
            policy_bytes =
                policy_bytes.replace("repository_write = true", "repository_write = false");
        }
        let policy_bytes = policy_bytes.into_bytes();
        fs::write(repo.join(".agent-work-governor/policy.toml"), &policy_bytes)?;
        let actual_policy_sha256 = hex(&Sha256::digest(&policy_bytes));
        let policy = ValidatedPolicyAuthority::from_bytes(&policy_bytes)?;
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
            "repository_write": true,
            "external_side_effects": true
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
            policy,
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
        verify_owner_scope(&self.repo, input, &self.policy)
    }
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
fn repository_report_preserves_blockers_and_closes_verifier_failures()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(NOW + 60, None)?;
    let CheckReport::Repository(verified) = Governor.check(CheckRequest::Repository {
        repo: fixture.repo.clone(),
        plugin_root: Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or("missing plugin root")?
            .to_path_buf(),
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
        plugin_root: Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or("missing plugin root")?
            .to_path_buf(),
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

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
