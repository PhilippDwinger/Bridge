//! # bridge-net – BridgeNet (docs/06)
//!
//! Pure logic of a network: typed statements (manifest, delegation, invite, member, seal, revoke, ban, head, cosign,
//! home, app, name, label), the transparency log as an RFC 6962 Merkle tree with signed heads, witness cosignatures and split-view
//! evidence (ADR 0006), and the network state that every node computes by replaying the log in order (ADR 0009).
//!
//! No I/O, no clock (times are passed in), no global state, no randomness - every function is deterministic and
//! testable. All cryptography goes through `bridge_core::crypto` (rule Z10).
//!
//! Layering (docs/03_ARCHITEKTUR.md): this crate may only depend on the crates listed in its `Cargo.toml`;
//! Cargo enforces that dependencies only point downwards.
//!
//! Typical use by a node (docs/06 §5–§9):
//! - log operator: `state.validate_candidate(&statement, now)?` → `log.append(&statement)?` →
//!   `state.apply(statement.canonical_bytes())` → periodically `log.issue_head(&operator, now)`;
//! - witness: `verify_head` → check consistency to the last cosigned head of this operator → `issue_cosign`;
//! - everybody else: `NetState::check_witnessed` (heads up to the own log; rules by size, rescue) - for a head
//!   beyond it `WitnessedHead::precheck` under the current rules or `NetState::may_fetch` → fetch entries →
//!   compare the root with the head → `Ahead::parse` + `NetState::rules_ahead` (current rules, replay a copy with
//!   `NetState::apply_tracked`, or refuse) → for every change of the log rules passed, its transition head
//!   (`Transitions::endorsement`: newest first, one at a time, stop at the first that is not endorsed) →
//!   `Log::append_bytes` + `NetState::apply` for each new entry;
//!   `Evidence::check` on every pair of heads seen.

use std::collections::BTreeMap;

use bridge_core::{Id, KeyCard};

pub mod apps;
pub mod blocklist;
pub mod error;
pub mod log;
pub mod merkle;
pub mod names;
pub mod state;
pub mod statements;

pub use apps::{CheckedApp, check_app, check_standing, is_web_host, valid_hosts};
pub use blocklist::{BlockEntry, Blocklist, Blocklists};
pub use error::{NetError, NetResult};
pub use log::{
    Evidence, Head, Log, WitnessedHead, check_new_entries, issue_cosign, issue_head, parse_entry, verify_cosign,
    verify_head,
};
pub use merkle::{Hash, Tree};
pub use names::{AdultPolicy, Category, Label, LabelTarget, Name, NameKind, NameRules};
pub use state::{
    Ahead, Applied, Endorsement, NameInfo, NetState, ResolvedName, RulesAhead, SealInfo, Search, Transition,
    Transitions,
};
pub use statements::{
    AppRules, Approvals, Ban, Body, Cosign, Delegation, GatewayEntry, HeadBody, Home, Invite, Join, JoinMode, Kind,
    Limits, LogRules, Manifest, Member, Revoke, RevokeTarget, Right, Rights, Seal, Service, Services, WATCH_SERVICES,
    WatchRules,
};

/// Name of this compartment (Abteil), used in logs and diagnostics.
pub const COMPARTMENT: &str = "bridge-net";

/// Where key cards come from when signatures of log operators, witnesses or other parties are checked.
/// Cards are self-certifying (ID = fingerprint of the signing key), so any source is fine - a wrong card simply
/// fails verification. Implemented by [`NetState`] (cards from the log), maps and slices of cards, and pairs
/// (first source first).
pub trait Cards {
    /// The card for `id`, if known.
    fn card(&self, id: &Id) -> Option<&KeyCard>;
}

impl<T: Cards + ?Sized> Cards for &T {
    fn card(&self, id: &Id) -> Option<&KeyCard> {
        (**self).card(id)
    }
}

impl Cards for BTreeMap<Id, KeyCard> {
    fn card(&self, id: &Id) -> Option<&KeyCard> {
        self.get(id)
    }
}

impl Cards for [KeyCard] {
    fn card(&self, id: &Id) -> Option<&KeyCard> {
        self.iter().find(|card| card.id() == id)
    }
}

impl Cards for Vec<KeyCard> {
    fn card(&self, id: &Id) -> Option<&KeyCard> {
        self.as_slice().card(id)
    }
}

impl<A: Cards, B: Cards> Cards for (A, B) {
    fn card(&self, id: &Id) -> Option<&KeyCard> {
        self.0.card(id).or_else(|| self.1.card(id))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn compartment_name_matches_crate() {
        assert_eq!(super::COMPARTMENT, env!("CARGO_PKG_NAME"));
    }
}
