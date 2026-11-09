//! # bridge-net – BridgeNet
//!
//! Network manifest, membership cards, trust levels 0-3, seals, admin delegations, revocations, bans and the
//! transparency log (Merkle tree, witnesses, gossip - ADR 0006).
//!
//! Layering (docs/03_ARCHITEKTUR.md): this crate may only depend on the crates listed in its `Cargo.toml`;
//! Cargo enforces that dependencies only point downwards.
//!
//! Status: Phase 1 scaffold - no functionality yet.

/// Name of this compartment (Abteil), used in logs and diagnostics.
pub const COMPARTMENT: &str = "bridge-net";

#[cfg(test)]
mod tests {
    #[test]
    fn compartment_name_matches_crate() {
        assert_eq!(super::COMPARTMENT, env!("CARGO_PKG_NAME"));
    }
}
