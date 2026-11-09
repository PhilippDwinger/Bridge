//! # bridge-core – the foundation
//!
//! Data types, canonical JSON (RFC 8785), the crypto suite B4-1 (Ed25519, X25519, HKDF-SHA256,
//! ChaCha20-Poly1305, SHA-256), identities and key cards, signed statements, envelopes, error codes.
//! No I/O, no clock and no randomness unless passed in - fully testable. All cryptography of Bridge lives here
//! (Zero Trust rule Z10, nonce invariant N1 in ADR 0008).
//!
//! Layering (docs/03_ARCHITEKTUR.md): this crate may only depend on the crates listed in its `Cargo.toml`;
//! Cargo enforces that dependencies only point downwards.
//!
//! Status: Phase 1 scaffold - no functionality yet.

/// Name of this compartment (Abteil), used in logs and diagnostics.
pub const COMPARTMENT: &str = "bridge-core";

#[cfg(test)]
mod tests {
    #[test]
    fn compartment_name_matches_crate() {
        assert_eq!(super::COMPARTMENT, env!("CARGO_PKG_NAME"));
    }
}
