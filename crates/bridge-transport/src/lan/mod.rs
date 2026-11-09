//! # LAN transport (ADR 0004, docs/04 §7, docs/06 §2)
//!
//! Devices in the same network work together without the Internet:
//! - [`TlsIdentity`]: each node has a self-signed TLS certificate. Its SHA-256 fingerprint is the `tls` field of the
//!   node's signed key card, so nobody can swap it. [`crate::serve_tls`] serves with it.
//! - [`crate::HttpClient::new_pinned`]: a client that trusts exactly that one certificate (pinning instead of a
//!   certificate authority; names and dates do not matter).
//! - [`LanAnnouncer`], [`browse`] and [`find`]: mDNS/DNS-SD (`_bridge4._tcp`) says where a node is right now. That
//!   is only a hint where to try - trust starts with the pinned TLS handshake, and everything above it is signed
//!   anyway. [`Discovery`] is the one switch nodes and SDKs use: off, mDNS, or addresses given by the program.
//!
//! TLS protects metadata here: contents are end-to-end encrypted and signed before they reach the transport.

mod discovery;
mod mdns;
mod tls;

pub use discovery::{DEFAULT_LISTEN, Discovery, LanHints};
pub use mdns::{
    LanAnnouncer, LanPeer, MAX_ADDRS_PER_PEER, MAX_INSTANCES_PER_ID, MAX_PEERS, SERVICE_TYPE, Wanted, browse,
    browse_matching, find,
};
pub use tls::TlsIdentity;
