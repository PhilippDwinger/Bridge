//! # bridge-plugin-api – the plugin boundary
//!
//! The only interface a service (plugin) sees. Core services use it as Rust crates, foreign plugins as WebAssembly
//! components in a sandbox (ADR 0005). Plugins never get keys - signing/decrypting goes through this API.
//!
//! Layering (docs/03_ARCHITEKTUR.md): this crate may only depend on the crates listed in its `Cargo.toml`;
//! Cargo enforces that dependencies only point downwards.
//!
//! Since phase 6 (docs/10 §4, ADR 0024): a service that answers tasks sees only [`Task`]s - opened and verified by the
//! program that holds the key - and gives back [`Reply`]s; the program seals and sends them, only to the verified
//! sender of the task.

use bridge_core::Id;

/// Name of this compartment (Abteil), used in logs and diagnostics.
pub const COMPARTMENT: &str = "bridge-plugin-api";

/// A task for a service: the opened, verified content of one envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    /// The envelope's ID (a reply names it).
    pub id: [u8; 16],
    /// The verified sender.
    pub from: Id,
    /// The sender is an agent of this owner (checked by the program, docs/10 §3.4).
    pub agent_of: Option<Id>,
    /// Media type of `data`.
    pub ctype: String,
    /// The payload (text as UTF-8).
    pub data: Vec<u8>,
}

/// A service's answer to a task: goes back to the task's sender only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The task it answers.
    pub task: [u8; 16],
    /// Media type of `data`.
    pub ctype: String,
    /// The payload.
    pub data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    #[test]
    fn compartment_name_matches_crate() {
        assert_eq!(super::COMPARTMENT, env!("CARGO_PKG_NAME"));
    }
}
