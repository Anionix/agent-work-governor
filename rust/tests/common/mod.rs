//! Shared digest helpers for public integration tests.

use sha2::{Digest, Sha256};

// LLM-CONTRACT
// id: agent-work-governor.integration-test-digests
// state: FIXTURE_BYTES -> SHA256_HEX -> TEST_BINDING
// preconditions: callers supply immutable compile-time or in-memory fixture bytes
// invariant: every integration test uses the same lowercase SHA-256 encoding
// failure: a digest mismatch fails the consuming Rust integration test
// source: repo:toolchain.lock.json
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: sha256_hex
// test: bundle:rust/tests/interface.rs

pub fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub fn toolchain_sha256() -> String {
    sha256_hex(include_bytes!("../../../toolchain.lock.json"))
}
