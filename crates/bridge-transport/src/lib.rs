//! # bridge-transport – how bytes travel
//!
//! Internet (HTTPS), LAN (mDNS discovery + TLS pinned to the node's signed key card), later QUIC/WebRTC/Bluetooth.
//! Knows nothing about networks or rights - the protocol is independent of the transport (ADR 0004).
//!
//! Layering (docs/03_ARCHITEKTUR.md): this crate may only depend on the crates listed in its `Cargo.toml`;
//! Cargo enforces that dependencies only point downwards.
//!
//! Status: Phase 1 scaffold - no functionality yet.

/// Name of this compartment (Abteil), used in logs and diagnostics.
pub const COMPARTMENT: &str = "bridge-transport";

#[cfg(test)]
mod tests {
    #[test]
    fn compartment_name_matches_crate() {
        assert_eq!(super::COMPARTMENT, env!("CARGO_PKG_NAME"));
    }
}
