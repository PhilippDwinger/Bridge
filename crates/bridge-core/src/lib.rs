//! # bridge-core – the foundation
//!
//! Data types, strict and canonical JSON (RFC 8785), the crypto suite B4-1 (Ed25519, X25519, HKDF-SHA256,
//! ChaCha20-Poly1305, SHA-256), identities and key cards, master keys from 24 BIP-39 words, signed statements,
//! envelopes, error codes, blobs (files by content), private-file encryption and app manifests (docs/07).
//! No I/O, no clock and no randomness unless passed in - fully testable. All cryptography of Bridge lives here
//! (Zero Trust rule Z10, nonce invariant N1 in ADR 0008).
//!
//! Layering (docs/03_ARCHITEKTUR.md): this crate depends on no other Bridge crate.

pub mod app;
pub mod blob;
pub mod content;
pub mod crypto;
pub mod encoding;
pub mod envelope;
pub mod error;
pub mod file;
pub mod id;
pub mod json;
pub mod keys;
pub mod link;
pub mod mnemonic;
pub mod pow;
pub mod request;
pub mod statement;
pub mod stream;

pub use app::{AppFile, AppManifest, FileType};
pub use blob::{BlobId, HashList};
pub use content::{Content, ContentType, Payload, StreamTicket};
pub use envelope::{Address, Envelope, Kind};
pub use error::{CoreError, CoreResult};
pub use file::FileKey;
pub use id::Id;
pub use keys::{Identity, KeyCard, Role};
pub use link::JoinLink;
pub use mnemonic::Mnemonic;
pub use pow::Puzzle;
pub use request::SignedRequest;
pub use statement::{Draft, Statement};
pub use stream::{Part, StreamOpener, StreamSealer};

use std::net::IpAddr;

use serde_json::{Map, Value};

/// Name of this compartment (Abteil), used in logs and diagnostics.
pub const COMPARTMENT: &str = "bridge-core";
/// Protocol version (`"v"` in every object).
pub const PROTOCOL_VERSION: i64 = 4;
/// Tolerated clock difference between parties: 5 minutes.
pub const CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;

/// The key for per-address limits and counters: IPv4 as is (also IPv4-mapped IPv6), IPv6 by its /64 network - one
/// IPv6 user usually owns a whole /64 and could otherwise rotate addresses for free.
#[must_use]
pub fn address_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut segments = v6.segments();
                segments[4..].fill(0);
                IpAddr::V6(segments.into())
            }
        },
    }
}

pub(crate) fn field_str<'a>(object: &'a Map<String, Value>, name: &str) -> CoreResult<&'a str> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| CoreError::BadFormat(format!("{name}: missing or not a string")))
}

pub(crate) fn field_i64(object: &Map<String, Value>, name: &str) -> CoreResult<i64> {
    object
        .get(name)
        .and_then(Value::as_i64)
        .ok_or_else(|| CoreError::BadFormat(format!("{name}: missing or not an integer")))
}

#[cfg(test)]
mod tests {
    #[test]
    fn compartment_name_matches_crate() {
        assert_eq!(super::COMPARTMENT, env!("CARGO_PKG_NAME"));
    }
}
