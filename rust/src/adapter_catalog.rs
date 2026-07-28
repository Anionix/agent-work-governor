//! Shared, pure support for deterministic language-adapter catalogs.
#![allow(
    dead_code,
    reason = "Issues #4 and #5 define private adapters before Issue #7 exposes planning"
)]

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

const TOOLCHAIN_SCHEMA: &str = "0.2";

// LLM-CONTRACT
// id: agent-work-governor.adapter-catalog-projection
// state: VALIDATED_TOOLCHAIN_BYTES + CLOSED_SELECTOR -> EXACT_TOOL_VERSION | CATALOG_REJECTED
// preconditions: the canonical validator has checked the bundled unified catalog
// invariant: selectors are adapter-owned; repository text cannot choose a tool or version
// failure: return ADAPTER_CATALOG_INVALID without a partial projection
// source: https://github.com/yaneurao/Pytra/blob/9f341e04fefd8eacac1081c59e80f4042ee80a6f/docs/en/guide/emitter-overview.md
// knowledge: bundle:knowledge/policies/work-governor.md
// enforced_by: tool_version
// test: bundle:rust/src/rust_adapter.rs

macro_rules! closed_id {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, serde::Deserialize, Eq, Ord, PartialEq, PartialOrd)]
        enum $name {
            $(#[serde(rename = $wire)] $variant),+
        }
        impl $name {
            const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire),+
                }
            }
        }
    };
}
pub(crate) use closed_id;

#[derive(Debug, Deserialize)]
struct ToolchainCatalog {
    schema_version: String,
    tools: Vec<ToolchainPin>,
}

#[derive(Debug, Deserialize)]
struct ToolchainPin {
    id: String,
    language: String,
    version: String,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("ADAPTER_CATALOG_INVALID")]
pub(crate) struct AdapterCatalogError;

pub(crate) fn tool_version(
    bytes: &str,
    language: &str,
    tool: &str,
) -> Result<String, AdapterCatalogError> {
    let catalog: ToolchainCatalog = serde_json::from_str(bytes).map_err(|_| AdapterCatalogError)?;
    if catalog.schema_version != TOOLCHAIN_SCHEMA {
        return Err(AdapterCatalogError);
    }
    let mut matches = catalog.tools.iter().filter(|pin| pin.id == tool);
    let pin = matches.next().ok_or(AdapterCatalogError)?;
    let numeric = pin
        .version
        .split('.')
        .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()));
    if matches.next().is_none() && pin.language == language && numeric {
        Ok(pin.version.clone())
    } else {
        Err(AdapterCatalogError)
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
