//! # bridge-plugin-api – the plugin boundary
//!
//! The only interface a service (plugin) sees. Core services use it as Rust crates, foreign plugins as WebAssembly
//! components in a sandbox (ADR 0005). Plugins never get keys - signing/decrypting goes through this API.
//!
//! Layering (docs/03_ARCHITEKTUR.md): this crate may only depend on the crates listed in its `Cargo.toml`;
//! Cargo enforces that dependencies only point downwards.
//!
//! Status: Phase 1 scaffold - no functionality yet.

/// Name of this compartment (Abteil), used in logs and diagnostics.
pub const COMPARTMENT: &str = "bridge-plugin-api";

#[cfg(test)]
mod tests {
    #[test]
    fn compartment_name_matches_crate() {
        assert_eq!(super::COMPARTMENT, env!("CARGO_PKG_NAME"));
    }
}
