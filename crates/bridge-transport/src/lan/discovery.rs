//! Where a program looks for nodes in the LAN: nowhere, mDNS, or hints it was given (docs/06 §2).
//!
//! Nodes and SDKs share this one type (S5). Whatever it returns is a hint only - the pinned TLS handshake decides.
//! Failures (no multicast, blocked by a firewall) give an empty list: the LAN is a shortcut, the Internet address
//! stays the fallback.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::mdns::{self, LanPeer, MAX_ADDRS_PER_PEER, MAX_PEERS, Wanted};

/// How long [`Discovery::mdns`] listens by default.
pub const DEFAULT_LISTEN: Duration = Duration::from_secs(2);

/// Where to look for nodes in the LAN.
#[derive(Debug, Clone, Default)]
pub enum Discovery {
    /// Do not look (Internet only).
    #[default]
    Off,
    /// mDNS/DNS-SD (`_bridge4._tcp`): listen this long each time (at most 30 s; [`Discovery::find`] returns as
    /// soon as the node was seen).
    Mdns(Duration),
    /// Addresses given by the program (tests, networks that block multicast, addresses from a QR code). Shared:
    /// the program can change them while a node or client uses them.
    Hints(LanHints),
}

impl Discovery {
    /// mDNS with the default listening time (2 s).
    #[must_use]
    pub fn mdns() -> Self {
        Self::Mdns(DEFAULT_LISTEN)
    }

    /// Whether this looks anywhere at all.
    #[must_use]
    pub fn is_on(&self) -> bool {
        !matches!(self, Self::Off)
    }

    /// The nodes seen in the LAN now (at most [`MAX_PEERS`], each with at most [`MAX_ADDRS_PER_PEER`] addresses, in
    /// the order they were first seen).
    pub async fn peers(&self) -> Vec<LanPeer> {
        self.peers_matching(&|_| true).await
    }

    /// Like [`Discovery::peers`], only announcements of IDs `wanted` accepts - filtered before any limit, so other
    /// IDs can not crowd out the wanted ones.
    pub async fn peers_matching(&self, wanted: Wanted<'_>) -> Vec<LanPeer> {
        match self {
            Self::Off => Vec::new(),
            Self::Mdns(listen) => mdns::browse_matching(*listen, wanted).await.unwrap_or_else(|error| {
                tracing::debug!(%error, "LAN discovery");
                Vec::new()
            }),
            Self::Hints(hints) => hints.snapshot().into_iter().filter(|peer| wanted(&peer.id)).collect(),
        }
    }

    /// The announcements of one node ID (several are possible - try them all).
    pub async fn find(&self, node_id: &str) -> Vec<LanPeer> {
        match self {
            Self::Off => Vec::new(),
            Self::Mdns(listen) => mdns::find(node_id, *listen).await.unwrap_or_else(|error| {
                tracing::debug!(%error, "LAN discovery");
                Vec::new()
            }),
            Self::Hints(hints) => hints.snapshot().into_iter().filter(|peer| peer.id == node_id).collect(),
        }
    }
}

/// A shared, bounded list of LAN addresses (cheap to clone; all clones are the same list).
#[derive(Clone, Default)]
pub struct LanHints(Arc<Mutex<Vec<LanPeer>>>);

impl LanHints {
    /// A list with these peers (bounded like an mDNS result).
    #[must_use]
    pub fn new(peers: Vec<LanPeer>) -> Self {
        let hints = Self::default();
        hints.set(peers);
        hints
    }

    /// Replaces the list.
    pub fn set(&self, peers: Vec<LanPeer>) {
        let mut peers: Vec<LanPeer> = peers.into_iter().take(MAX_PEERS).map(bounded).collect();
        peers.retain(|peer| !peer.addrs.is_empty() && peer.port != 0);
        *self.lock() = peers;
    }

    /// Adds one peer (ignored when the list is full).
    pub fn push(&self, peer: LanPeer) {
        let peer = bounded(peer);
        let mut peers = self.lock();
        if peers.len() < MAX_PEERS && !peer.addrs.is_empty() && peer.port != 0 {
            peers.push(peer);
        }
    }

    /// A copy of the list.
    #[must_use]
    pub fn snapshot(&self) -> Vec<LanPeer> {
        self.lock().clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<LanPeer>> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl fmt::Debug for LanHints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LanHints").field(&self.lock().len()).finish()
    }
}

fn bounded(mut peer: LanPeer) -> LanPeer {
    peer.addrs.truncate(MAX_ADDRS_PER_PEER);
    peer
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    const ID: &str = "abcdefghijklmnopqrstuvwxyz234567";
    const OTHER: &str = "bbcdefghijklmnopqrstuvwxyz234567";

    fn peer(id: &str, port: u16, addrs: usize) -> LanPeer {
        LanPeer { id: id.into(), addrs: (0..addrs).map(|i| IpAddr::from([10, 0, 0, i as u8])).collect(), port }
    }

    #[tokio::test]
    async fn off_finds_nothing_and_hints_are_shared_and_bounded() {
        assert!(Discovery::Off.peers().await.is_empty() && !Discovery::Off.is_on());
        let hints = LanHints::new(vec![peer(ID, 4711, 20), peer(OTHER, 1, 1), peer(ID, 0, 1), peer(ID, 9, 0)]);
        let discovery = Discovery::Hints(hints.clone());
        assert!(discovery.is_on());
        let found = discovery.find(ID).await;
        assert_eq!(found.len(), 1, "port 0 and no address are dropped: {found:?}");
        assert_eq!(found[0].addrs.len(), MAX_ADDRS_PER_PEER);
        hints.push(peer(ID, 4712, 1)); // changed later: seen by the clone in `discovery`
        assert_eq!(discovery.find(ID).await.len(), 2);
        assert_eq!(discovery.peers().await.len(), 3);
        assert_eq!(discovery.peers_matching(&|id| id == OTHER).await.len(), 1, "filtered");
        for port in 0..(MAX_PEERS as u16 + 10) {
            hints.push(peer(OTHER, port + 1, 1));
        }
        assert_eq!(hints.snapshot().len(), MAX_PEERS, "bounded");
        assert!(format!("{hints:?}").contains("256"));
    }
}
