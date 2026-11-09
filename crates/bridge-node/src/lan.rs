//! The node in the LAN (ADR 0004, docs/06 §2): a second listener with TLS and the node's own certificate
//! (`node-tls.pem`, its fingerprint is the `tls` field of the node's card), an mDNS announcement, and - for nodes of
//! a network - a small directory of where other nodes were seen in the LAN, so node-to-node calls can take the
//! pinned LAN path first.
//!
//! Discovery is bounded and never runs per request: a background duty looks every `rediscover` (default 30 s) and
//! keeps what it saw for three rounds; calls only read the directory. A hint is only a hint: the connection is made
//! with the pin from the peer's card in the network log, so a wrong or hostile hint just fails its TLS handshake
//! and the next address (finally the public one) is tried. Hostile hints can not crowd out real ones: with a
//! network state only IDs whose card in the log pins a certificate are looked for - filtered inside the discovery,
//! before any of its limits (others are never contacted over the LAN anyway) -, without one the least recently seen
//! ID makes room; several announcements of one ID are merged earliest first and in turns, so a copy of an ID can
//! not take all its address slots; a failed address is forgotten only for the ID it was listed for (docs/06 §2).

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bridge_core::Id;
use bridge_transport::lan::MAX_INSTANCES_PER_ID;
use bridge_transport::{Discovery, LanPeer, ServerConfig};

use crate::{Node, lock};

/// Most nodes the directory remembers.
const MAX_NODES: usize = bridge_transport::lan::MAX_PEERS;
/// Most LAN addresses remembered per node.
pub(crate) const MAX_URLS_PER_NODE: usize = 8;
/// Most announcements looked at in one update (the discovery returns at most 256; a bound of its own anyway).
const MAX_ANNOUNCEMENTS: usize = 4 * MAX_NODES;
/// A node not seen for this many discovery rounds is forgotten.
const ROUNDS_KEPT: u32 = 3;
/// Longest mDNS listening time of one round (the transport's bound).
const MAX_LISTEN: Duration = Duration::from_secs(30);

/// LAN access of a node (docs/06 §2).
#[derive(Debug, Clone)]
pub struct LanConfig {
    /// Address of the TLS listener, e.g. `0.0.0.0:7443` (port 0: any free port).
    pub listen: SocketAddr,
    /// Announce the node via mDNS (`_bridge4._tcp`, TXT `id`, `v`, and `net` in a network).
    pub announce: bool,
    /// Where the node looks for other nodes of its network in the LAN (default: mDNS).
    pub discovery: Discovery,
    /// How often it looks (default 30 s).
    pub rediscover: Duration,
}

impl LanConfig {
    /// LAN on `listen`: announced, other nodes found via mDNS every 30 s.
    #[must_use]
    pub fn new(listen: SocketAddr) -> Self {
        Self { listen, announce: true, discovery: Discovery::mdns(), rediscover: Duration::from_secs(30) }
    }
}

/// The limits of the LAN listener: those of the main listener, but no trusted proxies - nobody stands between a
/// LAN client and the node, so `X-Forwarded-For` is never believed there (a local program could otherwise pick any
/// address for itself).
pub(crate) fn server_config(main: &ServerConfig) -> ServerConfig {
    ServerConfig { trusted_proxies: Vec::new(), ..main.clone() }
}

/// Where other nodes were seen in the LAN lately.
pub(crate) struct Directory {
    discovery: Discovery,
    rediscover: Duration,
    seen: Mutex<HashMap<Id, Seen>>,
    next_seq: Mutex<u64>,
}

struct Seen {
    urls: Vec<String>,
    at: Instant,
    /// Insertion order within a round (ties of `at`): the oldest goes first.
    seq: u64,
}

impl Directory {
    pub(crate) fn new(config: &LanConfig) -> Self {
        Self {
            discovery: config.discovery.clone(),
            rediscover: config.rediscover.max(Duration::from_millis(50)),
            seen: Mutex::new(HashMap::new()),
            next_seq: Mutex::new(0),
        }
    }

    pub(crate) fn is_on(&self) -> bool {
        self.discovery.is_on()
    }

    /// How long a hint is kept: three rounds, each the listening time plus the pause after it.
    fn keep(&self) -> Duration {
        let listen = match &self.discovery {
            Discovery::Mdns(listen) => (*listen).min(MAX_LISTEN),
            Discovery::Off | Discovery::Hints(_) => Duration::ZERO,
        };
        self.rediscover.saturating_add(listen).saturating_mul(ROUNDS_KEPT)
    }

    /// `https://` addresses where `id` was seen lately (empty if not).
    pub(crate) fn urls_of(&self, id: &Id) -> Vec<String> {
        let keep = self.keep();
        lock(&self.seen)
            .get(id)
            .filter(|seen| seen.at.elapsed() < keep)
            .map(|seen| seen.urls.clone())
            .unwrap_or_default()
    }

    /// Forgets a LAN address of the node `id` after a failed connection (stale, or a lying announcement): calls go
    /// to the next address at once instead of waiting for it again; the next discovery round brings it back if it
    /// is announced. Other IDs listed with the same address keep it.
    pub(crate) fn forget(&self, id: &Id, url: &str) {
        let mut seen = lock(&self.seen);
        if let Some(entry) = seen.get_mut(id) {
            entry.urls.retain(|known| known != url);
            if entry.urls.is_empty() {
                seen.remove(id);
            }
        }
    }

    /// Takes the result of one discovery round (announcements in the order first seen): the newest round wins,
    /// nodes not seen for three rounds are forgotten, at most 256 nodes with 8 addresses each. `pinned`: with a
    /// network state, the IDs whose card in the log pins a certificate - only those are kept (filtered before any
    /// limit); `None` (no state yet): any ID. Several announcements of one ID (at most 4) are merged in turns, the
    /// earliest first: a copy can not take all address slots of the real node. The mDNS discovery always keeps the
    /// node's own (canonical) announcement and lists it first among its ID (review 6, finding 5), so the cap of 4
    /// here never drops it. When the table is full, the least recently seen ID makes room.
    pub(crate) fn update(&self, peers: Vec<LanPeer>, me: &Id, pinned: Option<&HashSet<Id>>) {
        let now = Instant::now();
        let mut grouped: Vec<(Id, Vec<Vec<String>>)> = Vec::new();
        for peer in peers.into_iter().take(MAX_ANNOUNCEMENTS) {
            let Ok(id) = Id::parse(&peer.id) else { continue };
            if &id == me || pinned.is_some_and(|pinned| !pinned.contains(&id)) {
                continue;
            }
            let room = grouped.len() < MAX_NODES;
            match grouped.iter_mut().find(|(known, _)| known == &id) {
                Some((_, announcements)) if announcements.len() < MAX_INSTANCES_PER_ID => {
                    announcements.push(peer.urls());
                }
                Some(_) => {}
                None if room => grouped.push((id, vec![peer.urls()])),
                None => {}
            }
        }
        let fresh: Vec<(Id, Vec<String>)> =
            grouped.into_iter().map(|(id, announcements)| (id, in_turns(&announcements))).collect();
        let keep = self.keep();
        let mut seen = lock(&self.seen);
        let mut next_seq = lock(&self.next_seq);
        seen.retain(|_, seen| now.duration_since(seen.at) < keep);
        for (id, urls) in fresh {
            if !seen.contains_key(&id) && seen.len() >= MAX_NODES {
                let oldest = seen.iter().min_by_key(|(_, seen)| (seen.at, seen.seq)).map(|(id, _)| id.clone());
                if let Some(oldest) = oldest {
                    seen.remove(&oldest);
                }
            }
            *next_seq = next_seq.wrapping_add(1);
            seen.insert(id, Seen { urls, at: now, seq: *next_seq });
        }
    }
}

/// The addresses of several announcements of one ID, in turns (first address of each, then the second ...), the
/// earliest announcement first; at most 8, no duplicates.
fn in_turns(announcements: &[Vec<String>]) -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();
    for turn in 0..MAX_URLS_PER_NODE {
        for url in announcements.iter().filter_map(|list| list.get(turn)) {
            if urls.len() < MAX_URLS_PER_NODE && !urls.contains(url) {
                urls.push(url.clone());
            }
        }
    }
    urls
}

/// The discovery duty of a network node: look (only for IDs it would contact over the LAN), remember, wait -
/// forever (aborted on shutdown).
pub(crate) async fn discover(node: Node) {
    let Some(directory) = node.inner.lan.as_ref() else { return };
    loop {
        let wanted = |id: &str| node.lan_wanted(id);
        let peers = directory.discovery.peers_matching(&wanted).await;
        let pinned = node.lan_pinned(&peers);
        directory.update(peers, node.inner.identity.id(), pinned.as_ref());
        tokio::time::sleep(directory.rediscover).await;
    }
}

impl Node {
    /// Whether an announced ID is worth a slot in the discovery: not this node, and - with a network state - its
    /// card in the log pins a TLS certificate (one short lock per announcement); without a state any ID.
    fn lan_wanted(&self, announced: &str) -> bool {
        let Ok(id) = Id::parse(announced) else { return false };
        if &id == self.inner.identity.id() {
            return false;
        }
        self.with_core(|core| core.state.card_of(&id).is_some_and(|card| card.tls().is_some())).unwrap_or(true)
    }

    /// Of the IDs in `peers`, those whose card in the network log pins a TLS certificate; `None` while this node
    /// has no network state (bounded by the discovery result, one lock).
    fn lan_pinned(&self, peers: &[LanPeer]) -> Option<HashSet<Id>> {
        self.with_core(|core| {
            peers
                .iter()
                .filter_map(|peer| Id::parse(&peer.id).ok())
                .filter(|id| core.state.card_of(id).is_some_and(|card| card.tls().is_some()))
                .collect()
        })
        .ok()
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    fn id(byte: u8) -> Id {
        Id::of_sign_key(&[byte; 32])
    }

    fn peer(id: &Id, port: u16, addrs: &[[u8; 4]]) -> LanPeer {
        LanPeer { id: id.to_string(), addrs: addrs.iter().map(|ip| IpAddr::from(*ip)).collect(), port }
    }

    #[test]
    fn lan_listener_never_trusts_proxies() {
        let main = ServerConfig {
            trusted_proxies: vec![IpAddr::from([127, 0, 0, 1])],
            max_body_bytes: 1234,
            ..ServerConfig::default()
        };
        let lan = server_config(&main);
        assert!(lan.trusted_proxies.is_empty());
        assert_eq!(lan.max_body_bytes, 1234, "the same limits otherwise");
    }

    #[test]
    fn hints_are_kept_for_three_rounds_including_the_listening_time() {
        let mdns = LanConfig { rediscover: Duration::from_secs(30), ..LanConfig::new(([0, 0, 0, 0], 0).into()) };
        assert_eq!(Directory::new(&mdns).keep(), Duration::from_secs(96), "3 x (30 s pause + 2 s listening)");
        let long = LanConfig { discovery: Discovery::Mdns(Duration::from_secs(600)), ..mdns };
        assert_eq!(Directory::new(&long).keep(), Duration::from_secs(180), "listening is bounded to 30 s");
    }

    #[test]
    fn directory_keeps_recent_bounded_hints_and_never_itself() {
        let config = LanConfig {
            rediscover: Duration::from_millis(60),
            discovery: Discovery::Hints(bridge_transport::LanHints::default()),
            ..LanConfig::new(([0, 0, 0, 0], 0).into())
        };
        let directory = Directory::new(&config);
        let (me, other) = (id(1), id(2));
        let many: Vec<[u8; 4]> = (0..20).map(|i| [10, 0, 0, i]).collect();
        directory.update(
            vec![peer(&me, 1, &[[10, 0, 0, 1]]), peer(&other, 4711, &many), peer(&other, 4712, &many)],
            &me,
            None,
        );
        assert!(directory.urls_of(&me).is_empty(), "never talk to yourself");
        let urls = directory.urls_of(&other);
        assert_eq!(urls.len(), MAX_URLS_PER_NODE);
        assert_eq!(urls[0], "https://10.0.0.0:4711");
        directory.forget(&other, "https://10.0.0.0:4711");
        assert_eq!(directory.urls_of(&other).len(), MAX_URLS_PER_NODE - 1, "a failed address is skipped");
        // Gone from the next rounds: forgotten after three of them.
        std::thread::sleep(Duration::from_millis(200));
        assert!(directory.urls_of(&other).is_empty());
        directory.update(Vec::new(), &me, None);
        assert!(lock(&directory.seen).is_empty());
        // Bounded number of nodes.
        let flood: Vec<LanPeer> = (0..400u16)
            .map(|i| {
                let mut key = [9u8; 32];
                key[..2].copy_from_slice(&i.to_be_bytes());
                peer(&Id::of_sign_key(&key), 1, &[[10, 0, 0, 1]])
            })
            .collect();
        directory.update(flood, &me, None);
        assert!(lock(&directory.seen).len() <= MAX_NODES);
    }

    fn hints_directory() -> Directory {
        Directory::new(&LanConfig {
            rediscover: Duration::from_secs(30),
            discovery: Discovery::Hints(bridge_transport::LanHints::default()),
            ..LanConfig::new(([0, 0, 0, 0], 0).into())
        })
    }

    fn fake_ids(count: u16, tag: u8) -> Vec<Id> {
        (0..count)
            .map(|i| {
                let mut key = [tag; 32];
                key[..2].copy_from_slice(&i.to_be_bytes());
                Id::of_sign_key(&key)
            })
            .collect()
    }

    /// Review 4, finding 5: a fake ID announced with a real node's address. The failed connection to the fake ID
    /// forgets the address only for the fake ID - the real node keeps it.
    #[test]
    fn a_failed_address_is_forgotten_only_for_its_id() {
        let directory = hints_directory();
        let (me, real, fake) = (id(1), id(2), id(3));
        directory.update(vec![peer(&real, 7443, &[[10, 0, 0, 5]]), peer(&fake, 7443, &[[10, 0, 0, 5]])], &me, None);
        directory.forget(&fake, "https://10.0.0.5:7443");
        assert_eq!(directory.urls_of(&real), vec!["https://10.0.0.5:7443".to_owned()], "the real node keeps it");
        assert!(directory.urls_of(&fake).is_empty());
        directory.forget(&id(4), "https://10.0.0.5:7443"); // unknown ID: nothing happens
        assert_eq!(directory.urls_of(&real).len(), 1);
    }

    /// Review 4, finding 5: with a network state only IDs that pin a certificate in the log are kept, so a flood of
    /// made-up IDs can not crowd them out.
    #[test]
    fn with_a_network_state_only_pinned_ids_are_kept() {
        let directory = hints_directory();
        let me = id(1);
        let known: Vec<Id> = fake_ids(3, 7);
        let pinned: HashSet<Id> = known.iter().cloned().collect();
        let mut flood: Vec<LanPeer> = fake_ids(400, 9).iter().map(|id| peer(id, 1, &[[10, 0, 0, 9]])).collect();
        flood.truncate(250);
        flood.extend(known.iter().map(|id| peer(id, 7443, &[[10, 0, 0, 7]])));
        directory.update(flood, &me, Some(&pinned));
        assert_eq!(lock(&directory.seen).len(), known.len(), "only the pinned IDs");
        for id in &known {
            assert_eq!(directory.urls_of(id).len(), 1);
        }
    }

    /// Review 5, finding 6: 300 made-up IDs announced before the pinned ones no longer cut them off (the filter runs
    /// before the limit).
    #[test]
    fn three_hundred_made_up_ids_first_do_not_crowd_out_pinned_ones() {
        let directory = hints_directory();
        let me = id(1);
        let known: Vec<Id> = fake_ids(3, 7);
        let pinned: HashSet<Id> = known.iter().cloned().collect();
        let mut flood: Vec<LanPeer> = fake_ids(300, 9).iter().map(|id| peer(id, 1, &[[10, 0, 0, 9]])).collect();
        flood.extend(known.iter().map(|id| peer(id, 7443, &[[10, 0, 0, 7]])));
        assert!(flood.len() > 300);
        directory.update(flood, &me, Some(&pinned));
        for id in &known {
            assert_eq!(directory.urls_of(id), vec!["https://10.0.0.7:7443".to_owned()]);
        }
    }

    /// Review 5, finding 6: a copy of a real node's announcement (same ID, another instance, 8 addresses of its own)
    /// can not take all 8 address slots; the earliest announcement comes first. Further copies get no slot at all.
    #[test]
    fn copies_of_an_id_share_its_address_slots_earliest_first() {
        let directory = hints_directory();
        let (me, real) = (id(1), id(2));
        let own: Vec<[u8; 4]> = (0..8).map(|i| [10, 0, 1, i]).collect();
        let copied: Vec<[u8; 4]> = (0..8).map(|i| [10, 0, 2, i]).collect();
        let mut announcements = vec![peer(&real, 7443, &own), peer(&real, 7443, &copied)];
        announcements.extend((0..300u16).map(|i| peer(&real, 1000 + i, &[[10, 0, 3, 1]])));
        directory.update(announcements, &me, None);
        let urls = directory.urls_of(&real);
        assert_eq!(urls.len(), MAX_URLS_PER_NODE);
        assert_eq!(urls[0], "https://10.0.1.0:7443", "the earliest announcement first");
        let real_ones = urls.iter().filter(|url| url.starts_with("https://10.0.1.")).count();
        assert!(real_ones >= MAX_URLS_PER_NODE / MAX_INSTANCES_PER_ID, "{urls:?}");
        assert!(urls.iter().filter(|url| url.starts_with("https://10.0.2.")).count() < MAX_URLS_PER_NODE);
        assert!(!urls.iter().any(|url| url.contains(":1299")), "the 300th copy gets nothing");
    }

    /// Review 4, finding 5: without a network state, a full table makes room for new IDs (oldest first) instead of
    /// keeping the first 256 for good.
    #[test]
    fn without_a_state_the_oldest_id_makes_room() {
        let directory = hints_directory();
        let me = id(1);
        let first: Vec<Id> = fake_ids(256, 9);
        directory.update(first.iter().map(|id| peer(id, 1, &[[10, 0, 0, 9]])).collect(), &me, None);
        assert_eq!(lock(&directory.seen).len(), MAX_NODES);
        let real = id(2);
        directory.update(vec![peer(&real, 7443, &[[10, 0, 0, 5]])], &me, None);
        assert_eq!(lock(&directory.seen).len(), MAX_NODES);
        assert_eq!(directory.urls_of(&real).len(), 1, "a newly seen node gets in");
        assert!(directory.urls_of(&first[0]).is_empty(), "the oldest made room");
        assert_eq!(directory.urls_of(&first[255]).len(), 1, "the newest of the old round stays");
    }
}
