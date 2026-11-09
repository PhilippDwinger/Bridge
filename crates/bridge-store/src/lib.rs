//! # bridge-store – persistence
//!
//! One SQLite database per node (WAL mode) with schema migrations; large data as files addressed by SHA-256.
//! Nothing important is lost on a restart.
//!
//! Layering (docs/03_ARCHITEKTUR.md): this crate may only depend on the crates listed in its `Cargo.toml`;
//! Cargo enforces that dependencies only point downwards.
//!
//! Status: Phase 1 scaffold - no functionality yet.

/// Name of this compartment (Abteil), used in logs and diagnostics.
pub const COMPARTMENT: &str = "bridge-store";

#[cfg(test)]
mod tests {
    #[test]
    fn compartment_name_matches_crate() {
        assert_eq!(super::COMPARTMENT, env!("CARGO_PKG_NAME"));
    }
}
