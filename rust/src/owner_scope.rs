use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};

use ed25519_dalek::{Signature, VerifyingKey};
use rustix::fs::{CWD, FileType, Mode, OFlags, fstat, openat};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};

use crate::{OwnerScopeVerification, Status};

const RECEIPT_SCHEMA: &str = "0.1";
const RECEIPT_DOMAIN: &[u8] = b"agent-work-governor-owner-scope-v1\n";
const MAX_RECEIPT_BYTES: usize = 16 * 1024;
const MAX_POLICY_BYTES: usize = 64 * 1024;
const MAX_DIRECTORY_ANCESTORS: usize = 4_096;

// LLM-CONTRACT
// id: agent-work-governor.owner-scope-receipt
// state: EXTERNAL_BYTES + TRUSTED_BINDINGS -> VERIFIED_INTERSECTION | CLOSED_FAILURE
// preconditions: the caller supplies repository identity, time, runtime grants, trusted key, and validated owner-original policy bytes
// invariant: only owner-original policy can verify; policy cannot widen signed receipt capability or caller runtime authority
// failure: every missing, malformed, stale, mismatched, local, or invalid signature yields zero authority
// source: https://github.com/dalek-cryptography/curve25519-dalek/blob/8016d6d9b9cdbaa681f24147e0b9377cc8cef934/ed25519-dalek/src/verifying.rs
// knowledge: repo:knowledge/policies/work-governor.md
// enforced_by: verify_owner_scope_with_boundary
// test: repo:rust/tests/owner_scope.rs

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedReceipt {
    payload: Box<RawValue>,
    signature_hex: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReceiptPayload {
    schema_version: String,
    repository_id: u64,
    owner_id: u64,
    repository_full_name: String,
    policy_sha256: String,
    issuer: String,
    key_id: String,
    issued_at: u64,
    expires_at: u64,
    repository_write: bool,
    external_side_effects: bool,
}

/// Untrusted evidence and runtime grants supplied by one protected caller.
///
/// Its non-optional fields form the protected all-or-none input set. This input
/// is never effective authority. [`RepositoryPolicySnapshot::verify`] derives
/// only the intersection of validated policy, signed receipt capabilities, and
/// runtime grants. Missing, unsafe, stale, malformed, signature-invalid, or
/// binding-mismatched evidence is a closed failure and grants zero authority.
#[derive(Clone, Debug)]
pub struct OwnerScopeInput {
    /// Path to the signed receipt outside the governed repository.
    pub receipt_path: PathBuf,
    /// Path to the trusted raw 32-byte Ed25519 public key.
    pub public_key_path: PathBuf,
    /// Caller-pinned SHA-256 digest of the trusted public key.
    pub trusted_key_sha256: String,
    /// Immutable GitHub repository database ID expected by the caller.
    pub repository_id: u64,
    /// Immutable GitHub owner database ID expected by the caller.
    pub owner_id: u64,
    /// Case-preserving `owner/name` expected by the caller.
    pub repository_full_name: String,
    /// Trusted issuer identity expected by the caller.
    pub issuer: String,
    /// Caller-observed Unix time used for bounded validity checks.
    pub now_epoch_seconds: u64,
    /// Runtime authority intersected with policy and receipt capability.
    pub runtime_authority: EffectiveAuthority,
}

/// Authority bits left after all independent grants are intersected.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveAuthority {
    /// Permission to mutate the governed repository.
    pub repository_write: bool,
    /// Permission to perform external side effects.
    pub external_side_effects: bool,
}

// LLM-CONTRACT
// id: agent-work-governor.owner-scope-pure-report
// state: REPOSITORY_SNAPSHOT + OPTIONAL_RECEIPT_INPUT -> VERIFIED_INTERSECTION | CLOSED_FAILURE
// preconditions: the caller supplies one opaque repository identity captured with its exact policy bytes
// invariant: only verified policy AND receipt AND runtime bits can appear in a PASS report
// failure: missing or invalid evidence emits a zero-authority FAIL report with a stable code
// source: repo:knowledge/policies/work-governor.md
// knowledge: repo:knowledge/policies/work-governor.md
// enforced_by: evaluate_owner_scope
// test: repo:rust/tests/owner_scope.rs

/// Pure owner-scope decision emitted independently of repository readiness checks.
///
/// Fields stay private so callers can only construct this report through the
/// validated evaluator; it is an output-only wire type.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OwnerScopeReport {
    status: Status,
    code: String,
    owner_scope_verification: OwnerScopeVerification,
    effective_authority: EffectiveAuthority,
    mutation_count: u64,
}

/// Policy digest and authority derived from the same validated byte snapshot.
#[derive(Clone, Debug)]
pub(crate) struct ValidatedPolicyAuthority {
    sha256: String,
    repository_scope: String,
    authority: EffectiveAuthority,
}

/// Opaque repository identity and policy bytes captured through one descriptor tree.
pub struct RepositoryPolicySnapshot {
    boundary: RepositoryBoundary,
    policy_bytes: Option<Vec<u8>>,
}

struct RepositoryBoundary {
    root: OwnedFd,
    canonical_path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BindingChecks(u8);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecisionInput {
    bindings: BindingChecks,
    issued_at: u64,
    expires_at: u64,
    now: u64,
    signature_verified: bool,
    policy: EffectiveAuthority,
    receipt: EffectiveAuthority,
    runtime: EffectiveAuthority,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DecisionFailure {
    BindingMismatch,
    ReceiptExpired,
    SignatureInvalid,
}

/// Stable closed-failure evidence from receipt verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{code}: {message}")]
pub struct OwnerScopeFailure {
    /// Machine-readable reason code.
    pub code: &'static str,
    /// Human-readable failure detail.
    pub message: &'static str,
}

impl ValidatedPolicyAuthority {
    /// Validate policy bytes and bind their digest to their authority bits.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when the bytes do not form a valid governor policy.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, OwnerScopeFailure> {
        let (sha256, repository_scope, repository_write, external_side_effects) =
            crate::policy::validated_authority(bytes).ok_or_else(|| {
                OwnerScopeFailure::new(
                    "OWNER_SCOPE_POLICY_INVALID",
                    "policy bytes must satisfy the closed governor policy schema",
                )
            })?;
        Ok(Self {
            sha256,
            repository_scope,
            authority: EffectiveAuthority {
                repository_write,
                external_side_effects,
            },
        })
    }
}

impl RepositoryPolicySnapshot {
    /// Open the governed repository and its current policy as one symlink-free snapshot.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when the repository or policy cannot be opened
    /// as bounded regular descriptor-backed inputs.
    pub fn load(repository: &Path) -> Result<Self, OwnerScopeFailure> {
        // LLM contract: repository path -> opaque root fd + exact policy bytes
        // or closed policy state; later renames cannot separate identity from policy.
        let failure = policy_failure();
        let boundary = RepositoryBoundary::open(repository, failure)?;
        let policy_bytes = openat(
            &boundary.root,
            ".agent-work-governor",
            directory_flags(),
            Mode::empty(),
        )
        .ok()
        .and_then(|gate| {
            openat(
                &gate,
                "policy.toml",
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .ok()
        })
        .and_then(|policy| read_bounded_file(policy, MAX_POLICY_BYTES, failure).ok());
        Ok(Self {
            boundary,
            policy_bytes,
        })
    }

    /// Verify one receipt against the exact policy and repository identity in
    /// this snapshot.
    ///
    /// # Errors
    ///
    /// Returns a stable closed failure when policy, evidence, or a trusted
    /// binding is invalid.
    pub fn verify(&self, input: &OwnerScopeInput) -> Result<EffectiveAuthority, OwnerScopeFailure> {
        let policy = self
            .policy_bytes
            .as_deref()
            .ok_or_else(policy_failure)
            .and_then(ValidatedPolicyAuthority::from_bytes)?;
        if policy.repository_scope != "owner_original" {
            return Err(OwnerScopeFailure::new(
                "OWNER_SCOPE_NOT_APPLICABLE",
                "external owner-scope evidence requires an owner-original policy",
            ));
        }
        verify_owner_scope_with_boundary(&self.boundary, input, &policy)
    }

    pub(crate) fn policy_bytes(&self) -> Option<&[u8]> {
        self.policy_bytes.as_deref()
    }

    pub(crate) fn repository(&self) -> &Path {
        &self.boundary.canonical_path
    }
}

impl RepositoryBoundary {
    fn open(repository: &Path, failure: OwnerScopeFailure) -> Result<Self, OwnerScopeFailure> {
        let canonical_path = repository.canonicalize().map_err(|_| failure)?;
        Ok(Self {
            root: open_directory_path(&canonical_path, failure)?,
            canonical_path,
        })
    }
}

fn verify_owner_scope_with_boundary(
    boundary: &RepositoryBoundary,
    input: &OwnerScopeInput,
    policy: &ValidatedPolicyAuthority,
) -> Result<EffectiveAuthority, OwnerScopeFailure> {
    let receipt_bytes = read_external(boundary, &input.receipt_path, MAX_RECEIPT_BYTES)?;
    let public_key_bytes = read_external(boundary, &input.public_key_path, 32)?;
    let public_key_array: [u8; 32] = public_key_bytes.try_into().map_err(|_| {
        OwnerScopeFailure::new(
            "OWNER_SCOPE_KEY_INVALID",
            "trusted Ed25519 public key must contain exactly 32 bytes",
        )
    })?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_array).map_err(|_| {
        OwnerScopeFailure::new(
            "OWNER_SCOPE_KEY_INVALID",
            "trusted Ed25519 public key is not a valid compressed point",
        )
    })?;
    let receipt: SignedReceipt = serde_json::from_slice(&receipt_bytes).map_err(|_| {
        OwnerScopeFailure::new(
            "OWNER_SCOPE_RECEIPT_INVALID",
            "receipt must match the closed owner-scope JSON schema",
        )
    })?;
    let payload: ReceiptPayload = serde_json::from_str(receipt.payload.get()).map_err(|_| {
        OwnerScopeFailure::new(
            "OWNER_SCOPE_RECEIPT_INVALID",
            "receipt payload must match the closed owner-scope JSON schema",
        )
    })?;

    let expected_key_id = sha256_hex(&public_key_array);
    let mut message = RECEIPT_DOMAIN.to_vec();
    message.extend_from_slice(receipt.payload.get().as_bytes());
    let signature_verified =
        decode_hex::<64>(&receipt.signature_hex).is_some_and(|signature_bytes| {
            verifying_key
                .verify_strict(&message, &Signature::from_bytes(&signature_bytes))
                .is_ok()
        });
    decide(DecisionInput {
        bindings: BindingChecks::from_array([
            payload.schema_version == RECEIPT_SCHEMA,
            payload.repository_id == input.repository_id
                && payload.owner_id == input.owner_id
                && payload.repository_full_name == input.repository_full_name,
            payload.policy_sha256 == policy.sha256,
            payload.issuer == input.issuer,
            input.trusted_key_sha256 == expected_key_id && payload.key_id == expected_key_id,
        ]),
        issued_at: payload.issued_at,
        expires_at: payload.expires_at,
        now: input.now_epoch_seconds,
        signature_verified,
        policy: policy.authority,
        receipt: EffectiveAuthority {
            repository_write: payload.repository_write,
            external_side_effects: payload.external_side_effects,
        },
        runtime: input.runtime_authority,
    })
    .map_err(DecisionFailure::owner_scope_failure)
}

/// Evaluate owner scope against policy bytes and repository identity captured
/// through the same descriptor tree.
#[must_use]
pub fn evaluate_owner_scope(
    snapshot: &RepositoryPolicySnapshot,
    input: Option<&OwnerScopeInput>,
) -> OwnerScopeReport {
    let Some(input) = input else {
        return OwnerScopeReport::closed(
            OwnerScopeVerification::Required,
            "OWNER_SCOPE_RECEIPT_REQUIRED",
        );
    };
    OwnerScopeReport::from_verification(snapshot.verify(input))
}

impl OwnerScopeReport {
    fn from_verification(
        result: Result<EffectiveAuthority, OwnerScopeFailure>,
    ) -> OwnerScopeReport {
        match result {
            Ok(effective_authority) => Self {
                status: Status::Pass,
                code: "OWNER_SCOPE_VERIFIED".to_owned(),
                owner_scope_verification: OwnerScopeVerification::Verified,
                effective_authority,
                mutation_count: 0,
            },
            Err(error) => Self::closed(OwnerScopeVerification::Rejected, error.code),
        }
    }

    fn closed(owner_scope_verification: OwnerScopeVerification, code: &'static str) -> Self {
        Self {
            status: Status::Fail,
            code: code.to_owned(),
            owner_scope_verification,
            effective_authority: EffectiveAuthority {
                repository_write: false,
                external_side_effects: false,
            },
            mutation_count: 0,
        }
    }

    /// Whether the pure authority decision passed.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.status == Status::Pass
    }
}

fn decide(input: DecisionInput) -> Result<EffectiveAuthority, DecisionFailure> {
    if !input.bindings.all() {
        return Err(DecisionFailure::BindingMismatch);
    }
    if !input.time_is_valid() {
        return Err(DecisionFailure::ReceiptExpired);
    }
    if !input.signature_verified {
        return Err(DecisionFailure::SignatureInvalid);
    }
    Ok(EffectiveAuthority {
        repository_write: input.policy.repository_write
            && input.receipt.repository_write
            && input.runtime.repository_write,
        external_side_effects: input.policy.external_side_effects
            && input.receipt.external_side_effects
            && input.runtime.external_side_effects,
    })
}

impl BindingChecks {
    const ALL: u8 = 0b1_1111;

    const fn from_array(checks: [bool; 5]) -> Self {
        Self(
            (checks[0] as u8)
                | ((checks[1] as u8) << 1)
                | ((checks[2] as u8) << 2)
                | ((checks[3] as u8) << 3)
                | ((checks[4] as u8) << 4),
        )
    }

    const fn all(self) -> bool {
        self.0 & Self::ALL == Self::ALL
    }
}

impl DecisionInput {
    const fn time_is_valid(self) -> bool {
        self.issued_at <= self.now && self.now < self.expires_at
    }
}

impl DecisionFailure {
    const fn owner_scope_failure(self) -> OwnerScopeFailure {
        match self {
            Self::BindingMismatch => OwnerScopeFailure::new(
                "OWNER_SCOPE_BINDING_MISMATCH",
                "receipt identity, policy, issuer, or trusted key binding does not match",
            ),
            Self::ReceiptExpired => OwnerScopeFailure::new(
                "OWNER_SCOPE_RECEIPT_EXPIRED",
                "receipt validity interval does not contain the caller-observed time",
            ),
            Self::SignatureInvalid => OwnerScopeFailure::new(
                "OWNER_SCOPE_SIGNATURE_INVALID",
                "receipt signature does not verify with the trusted public key",
            ),
        }
    }
}

fn read_external(
    boundary: &RepositoryBoundary,
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, OwnerScopeFailure> {
    let failure = evidence_failure();
    let metadata = std::fs::symlink_metadata(path).map_err(|_| failure)?;
    if !metadata.file_type().is_file() {
        return Err(failure);
    }
    let canonical = path.canonicalize().map_err(|_| failure)?;
    let parent = canonical
        .parent()
        .ok_or(failure)
        .and_then(|path| open_directory_path(path, failure))?;
    if directory_is_within_repository(&parent, &boundary.root, failure)? {
        return Err(OwnerScopeFailure::new(
            "OWNER_SCOPE_EVIDENCE_INSIDE_REPOSITORY",
            "owner-scope evidence must be stored outside the governed repository",
        ));
    }
    let name = canonical.file_name().ok_or(failure)?;
    let descriptor = openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| failure)?;
    read_bounded_file(descriptor, maximum, failure)
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK
}

fn open_directory_path(
    path: &Path,
    failure: OwnerScopeFailure,
) -> Result<OwnedFd, OwnerScopeFailure> {
    let mut directory = openat(CWD, "/", directory_flags(), Mode::empty()).map_err(|_| failure)?;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => {
                directory = openat(&directory, part, directory_flags(), Mode::empty())
                    .map_err(|_| failure)?;
            }
            Component::ParentDir | Component::Prefix(_) => return Err(failure),
        }
    }
    Ok(directory)
}

fn directory_is_within_repository(
    directory: &OwnedFd,
    repository: &OwnedFd,
    failure: OwnerScopeFailure,
) -> Result<bool, OwnerScopeFailure> {
    let repository_stat = fstat(repository).map_err(|_| failure)?;
    let mut current =
        openat(directory, ".", directory_flags(), Mode::empty()).map_err(|_| failure)?;
    for _ in 0..MAX_DIRECTORY_ANCESTORS {
        let current_stat = fstat(&current).map_err(|_| failure)?;
        if current_stat.st_dev == repository_stat.st_dev
            && current_stat.st_ino == repository_stat.st_ino
        {
            return Ok(true);
        }
        let parent =
            openat(&current, "..", directory_flags(), Mode::empty()).map_err(|_| failure)?;
        let parent_stat = fstat(&parent).map_err(|_| failure)?;
        if parent_stat.st_dev == current_stat.st_dev && parent_stat.st_ino == current_stat.st_ino {
            return Ok(false);
        }
        current = parent;
    }
    Err(failure)
}

fn read_bounded_file(
    descriptor: OwnedFd,
    maximum: usize,
    failure: OwnerScopeFailure,
) -> Result<Vec<u8>, OwnerScopeFailure> {
    let stat = fstat(&descriptor).map_err(|_| failure)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || usize::try_from(stat.st_size).map_or(true, |size| size > maximum)
    {
        return Err(failure);
    }
    let mut bytes = Vec::new();
    File::from(descriptor)
        .take(u64::try_from(maximum).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| failure)?;
    if bytes.len() > maximum {
        return Err(failure);
    }
    Ok(bytes)
}

const fn policy_failure() -> OwnerScopeFailure {
    OwnerScopeFailure::new(
        "OWNER_SCOPE_POLICY_INVALID",
        "repository policy could not be read as bounded descriptor-backed bytes",
    )
}

const fn evidence_failure() -> OwnerScopeFailure {
    OwnerScopeFailure::new(
        "OWNER_SCOPE_EVIDENCE_INVALID",
        "owner-scope evidence or repository identity could not be opened safely",
    )
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(output)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

impl OwnerScopeFailure {
    const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    fn any_authority() -> EffectiveAuthority {
        EffectiveAuthority {
            repository_write: kani::any(),
            external_side_effects: kani::any(),
        }
    }

    fn any_input() -> DecisionInput {
        DecisionInput {
            bindings: BindingChecks(kani::any()),
            issued_at: kani::any(),
            expires_at: kani::any(),
            now: kani::any(),
            signature_verified: kani::any(),
            policy: any_authority(),
            receipt: any_authority(),
            runtime: any_authority(),
        }
    }

    #[kani::proof]
    #[kani::unwind(1)]
    fn decision_gate_equivalence() {
        let input = any_input();
        let decision = decide(input);
        assert_eq!(
            decision.is_ok(),
            input.bindings.all()
                && input.issued_at <= input.now
                && input.now < input.expires_at
                && input.signature_verified
        );
        kani::cover!(decision.is_ok(), "verified decision is reachable");
        kani::cover!(
            matches!(decision, Err(DecisionFailure::BindingMismatch)),
            "binding mismatch is reachable"
        );
        kani::cover!(
            matches!(decision, Err(DecisionFailure::ReceiptExpired)),
            "expired receipt is reachable"
        );
        kani::cover!(
            matches!(decision, Err(DecisionFailure::SignatureInvalid)),
            "invalid signature is reachable"
        );
    }

    #[kani::proof]
    #[kani::unwind(1)]
    fn binding_encoding_is_exact() {
        let checks: [bool; 5] = [
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
            kani::any(),
        ];
        assert_eq!(
            BindingChecks::from_array(checks).all(),
            checks[0] && checks[1] && checks[2] && checks[3] && checks[4]
        );
    }

    #[kani::proof]
    #[kani::unwind(1)]
    fn verified_authority_is_exact_intersection() {
        let input = any_input();
        if let Ok(authority) = decide(input) {
            assert_eq!(
                authority.repository_write,
                input.policy.repository_write
                    && input.receipt.repository_write
                    && input.runtime.repository_write
            );
            assert_eq!(
                authority.external_side_effects,
                input.policy.external_side_effects
                    && input.receipt.external_side_effects
                    && input.runtime.external_side_effects
            );
            assert!(!authority.repository_write || input.policy.repository_write);
            assert!(!authority.repository_write || input.receipt.repository_write);
            assert!(!authority.repository_write || input.runtime.repository_write);
            assert!(!authority.external_side_effects || input.policy.external_side_effects);
            assert!(!authority.external_side_effects || input.receipt.external_side_effects);
            assert!(!authority.external_side_effects || input.runtime.external_side_effects);
        }
    }

    #[kani::proof]
    #[kani::unwind(1)]
    fn decision_paths_are_reachable() {
        let authority = EffectiveAuthority {
            repository_write: true,
            external_side_effects: true,
        };
        let verified = decide(DecisionInput {
            bindings: BindingChecks::from_array([true; 5]),
            issued_at: 10,
            expires_at: 12,
            now: 11,
            signature_verified: true,
            policy: authority,
            receipt: authority,
            runtime: authority,
        });
        assert_eq!(verified, Ok(authority));

        let denied = decide(DecisionInput {
            signature_verified: false,
            ..DecisionInput {
                bindings: BindingChecks::from_array([true; 5]),
                issued_at: 10,
                expires_at: 12,
                now: 11,
                signature_verified: true,
                policy: authority,
                receipt: authority,
                runtime: authority,
            }
        });
        assert_eq!(denied, Err(DecisionFailure::SignatureInvalid));
    }

    #[cfg(feature = "kani-canary")]
    #[kani::proof]
    #[kani::unwind(1)]
    fn negative_canary_must_fail() {
        assert!(false, "the Kani runner must reject a false property");
    }
}
