//! mDNS/DNS-SD hints where nodes are (docs/06 §2): service `_bridge4._tcp.local.`, TXT `id=<node id>` and `v=4`.
//!
//! Everything learned here is untrusted - anyone in the LAN can announce anything. A [`LanPeer`] only says where to
//! try; trust starts with the pinned TLS handshake ([`crate::HttpClient::new_pinned`] with the `tls` pin from the
//! node's signed key card). Results are bounded (peers, addresses, time) and malformed announcements are ignored.
//!
//! Decisions: the instance name is the node ID (unique, so nodes on one PC do not collide), the host name is
//! `bridge4-<node id>.local.`; the same ID may show up more than once (e.g. an attacker copying it) - try each.
//!
//! Crowding (review 5): a caller says which IDs it wants ([`browse_matching`]); that filter runs before any limit, so
//! a flood of other IDs never takes a slot. Of one ID at most [`MAX_INSTANCES_PER_ID`] announcements are kept (first
//! come), and results come in the order they were first seen - so the merge per ID can put the earliest first.
//! Review 6: the canonical announcement of an ID (instance name = ID) is always kept - a copy makes room - and comes
//! first among the announcements of its ID, so copies that came first can not push the real node out.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use bridge_core::Id;
use mdns_sd::{ScopedIp, ServiceDaemon, ServiceEvent, ServiceInfo, TxtProperties};

use crate::{TransportError, TransportResult};

/// The DNS-SD service type of Bridge 4 nodes.
pub const SERVICE_TYPE: &str = "_bridge4._tcp.local.";
/// Max peers one [`browse`] returns (a flooding neighbour cannot grow the list without bound, Z5).
pub const MAX_PEERS: usize = 256;
/// Max addresses kept per peer.
pub const MAX_ADDRS_PER_PEER: usize = 8;
/// Max announcements (instance names) of one node ID kept in one look: copies of an ID under other names can not
/// fill the list.
pub const MAX_INSTANCES_PER_ID: usize = 4;
/// Value of the TXT key `v`.
const PROTOCOL: &str = "4";
/// Upper bound for one browse.
const MAX_BROWSE_TIME: Duration = Duration::from_secs(30);
/// [`find`]: after the first matching announcement, listen this much longer for more with the same ID (a copy by
/// someone else must not hide the real one).
const FIND_GRACE: Duration = Duration::from_millis(300);
/// Addresses looked at per announcement before sorting and cutting to [`MAX_ADDRS_PER_PEER`].
const MAX_ADDR_CANDIDATES: usize = 64;
/// Max extra TXT entries of an announcement.
const MAX_EXTRA_TXT: usize = 8;
/// Max length of a TXT key (RFC 6763 §6.4 recommends at most 9 characters).
const MAX_TXT_KEY: usize = 9;
/// Max length of a TXT value.
const MAX_TXT_VALUE: usize = 100;

/// A node seen in the LAN: where to try, nothing more. `id` has the form of a node ID (32 characters of Base32);
/// whether it is really that node only the pinned TLS handshake shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanPeer {
    /// The announced node ID (validated form only).
    pub id: String,
    /// Announced addresses (1 to [`MAX_ADDRS_PER_PEER`], sorted, IPv4 first; no IPv6 link-local without scope).
    pub addrs: Vec<IpAddr>,
    /// The announced TLS port.
    pub port: u16,
}

impl LanPeer {
    /// The addresses to try with [`crate::HttpClient::new_pinned`]: `https://<ip>:<port>` (IPv6 in brackets), at
    /// most [`MAX_ADDRS_PER_PEER`].
    #[must_use]
    pub fn urls(&self) -> Vec<String> {
        self.addrs
            .iter()
            .take(MAX_ADDRS_PER_PEER)
            .map(|ip| format!("https://{}", std::net::SocketAddr::new(*ip, self.port)))
            .collect()
    }
}

/// Announces this node in the LAN as long as it lives. Stops (with a goodbye) on [`LanAnnouncer::shutdown`] or drop.
pub struct LanAnnouncer {
    daemon: Daemon,
    fullname: String,
}

impl LanAnnouncer {
    /// Starts announcing `node_id` (a node ID) on `port` (the port of [`crate::serve_tls`]) on all interfaces.
    /// `extra_txt`: up to 8 more TXT entries; keys are 1-9 characters `a-z`, `0-9`, `-` (not `id` or `v`), values
    /// at most 100 characters of printable ASCII.
    pub fn start(node_id: &str, port: u16, extra_txt: &[(&str, &str)]) -> TransportResult<Self> {
        let id = Id::parse(node_id).map_err(|_| TransportError::Config("mDNS: not a node ID".into()))?;
        if port == 0 {
            return Err(TransportError::Config("mDNS: port 0".into()));
        }
        check_extra_txt(extra_txt)?;
        let mut properties: Vec<(&str, &str)> = vec![("id", id.as_str()), ("v", PROTOCOL)];
        properties.extend_from_slice(extra_txt);
        let host = format!("bridge4-{id}.local.");
        let info = ServiceInfo::new(SERVICE_TYPE, id.as_str(), &host, (), port, &properties[..])
            .map_err(discovery)?
            .enable_addr_auto(); // announce the addresses the interfaces have now and later
        let fullname = info.get_fullname().to_owned();
        let daemon = Daemon::new()?;
        daemon.0.register(info).map_err(discovery)?;
        Ok(Self { daemon, fullname })
    }

    /// Stops announcing (sends a goodbye so others forget the entry).
    pub fn shutdown(self) {
        drop(self);
    }
}

impl Drop for LanAnnouncer {
    fn drop(&mut self) {
        let _ = self.daemon.0.unregister(&self.fullname); // queued before the daemon's shutdown (see `Daemon`)
    }
}

impl fmt::Debug for LanAnnouncer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LanAnnouncer").field("fullname", &self.fullname).finish_non_exhaustive()
    }
}

/// Which announced node IDs a caller wants (applied before any limit).
pub type Wanted<'a> = &'a (dyn Fn(&str) -> bool + Sync);

/// Listens for `timeout` (at most 30 s) and returns the nodes announced in the LAN (at most [`MAX_PEERS`], in the
/// order they were first seen). Only hints: connect with the pinned TLS client and trust nothing before that
/// handshake.
pub async fn browse(timeout: Duration) -> TransportResult<Vec<LanPeer>> {
    browse_matching(timeout, &|_| true).await
}

/// Like [`browse`], but only announcements of IDs `wanted` accepts - checked before any limit, so a flood of other
/// IDs can not crowd out the wanted ones (a node passes the IDs it would ever contact over the LAN).
pub async fn browse_matching(timeout: Duration, wanted: Wanted<'_>) -> TransportResult<Vec<LanPeer>> {
    collect(timeout, wanted, false).await
}

/// Looks for the announcements of one node ID: returns shortly (300 ms) after the first one is seen, at the latest
/// after `timeout` (at most 30 s). Empty if the node is not announced. Only hints, like [`browse`].
pub async fn find(node_id: &str, timeout: Duration) -> TransportResult<Vec<LanPeer>> {
    let id = Id::parse(node_id).map_err(|_| TransportError::Config("mDNS: not a node ID".into()))?;
    let id = id.as_str();
    collect(timeout, &|announced| announced == id, true).await
}

/// The browse loop. `find`: stop soon after a wanted ID was seen.
async fn collect(timeout: Duration, wanted: Wanted<'_>, find: bool) -> TransportResult<Vec<LanPeer>> {
    let daemon = Daemon::new()?;
    let events = daemon.0.browse(SERVICE_TYPE).map_err(discovery)?;
    let mut deadline = tokio::time::Instant::now() + timeout.min(MAX_BROWSE_TIME);
    let mut collector = Collector::new(wanted);
    while let Ok(Ok(event)) = tokio::time::timeout_at(deadline, events.recv_async()).await {
        match event {
            ServiceEvent::ServiceResolved(service) => {
                let addresses = service.addresses.iter().map(ScopedIp::to_ip_addr);
                let peer = peer_from(&service.ty_domain, service.port, addresses, &service.txt_properties);
                if collector.resolved(&service.fullname, peer) && find {
                    deadline = deadline.min(tokio::time::Instant::now() + FIND_GRACE);
                }
            }
            ServiceEvent::ServiceRemoved(_, fullname) => collector.removed(&fullname),
            _ => {}
        }
    }
    Ok(collector.finish())
}

/// What one look collects, by announced instance name (a copy of a node's ID under another name can not replace
/// the original): only wanted IDs - filtered before any limit -, first come first kept (at most [`MAX_PEERS`]
/// instances, at most [`MAX_INSTANCES_PER_ID`] of one ID), each with the order in which it was first seen.
///
/// The **canonical** instance of an ID - instance name = the TXT `id`, as every node announces itself - is always
/// admitted (review 6, finding 5): if the limits are reached, a copy (another instance name with the same ID, or
/// else a copy of any ID) makes room. Copies came first otherwise kept the real node out. In the result the
/// canonical instance comes first among the instances of its ID (the merge per ID puts the earliest first).
pub(crate) struct Collector<'a> {
    wanted: Wanted<'a>,
    found: HashMap<String, Found>,
    seen: u64,
}

/// One kept announcement: when it was first seen, whether its instance name is its ID, the peer.
struct Found {
    seen: u64,
    canonical: bool,
    peer: LanPeer,
}

impl<'a> Collector<'a> {
    pub(crate) fn new(wanted: Wanted<'a>) -> Self {
        Self { wanted, found: HashMap::new(), seen: 0 }
    }

    /// An announcement was resolved (`None`: malformed). Returns whether it is kept now.
    pub(crate) fn resolved(&mut self, fullname: &str, peer: Option<LanPeer>) -> bool {
        let Some(peer) = peer.filter(|peer| (self.wanted)(&peer.id)) else {
            // The latest announcement of this instance is malformed or not wanted (any more): forget it.
            self.found.remove(fullname);
            return false;
        };
        if let Some(known) = self.found.get_mut(fullname) {
            if known.peer.id == peer.id {
                known.peer = peer; // a new announcement of the same instance (new addresses), it keeps its place
                return true;
            }
            self.found.remove(fullname); // another ID under this name: a new arrival
        }
        let canonical = is_canonical(fullname, &peer.id);
        let same_id = self.found.values().filter(|known| known.peer.id == peer.id).count();
        let full = self.found.len() >= MAX_PEERS;
        if full || same_id >= MAX_INSTANCES_PER_ID {
            if !canonical {
                return false; // first come, first kept
            }
            // The real node: a copy of its ID makes room - or, if the list is full of other IDs, the latest copy of
            // any ID. Only canonical instances everywhere: it stays out (first come).
            let copy_of_same = |known: &Found| !known.canonical && known.peer.id == peer.id;
            let victim = if same_id >= MAX_INSTANCES_PER_ID { self.latest(copy_of_same) } else { None }
                .or_else(|| if full { self.latest(|known: &Found| !known.canonical) } else { None });
            let Some(victim) = victim else { return false };
            self.found.remove(&victim);
        }
        self.seen = self.seen.saturating_add(1);
        self.found.insert(fullname.to_owned(), Found { seen: self.seen, canonical, peer });
        true
    }

    /// The instance name of the latest kept announcement that `matches`.
    fn latest(&self, matches: impl Fn(&Found) -> bool) -> Option<String> {
        self.found
            .iter()
            .filter(|(_, known)| matches(known))
            .max_by_key(|(_, known)| known.seen)
            .map(|(name, _)| name.clone())
    }

    /// The announcement of an instance was withdrawn.
    pub(crate) fn removed(&mut self, fullname: &str) {
        self.found.remove(fullname);
    }

    /// The announcements in the order their ID was first seen; within an ID the canonical instance first, then the
    /// copies in the order they were first seen.
    pub(crate) fn finish(self) -> Vec<LanPeer> {
        let mut first_of_id: HashMap<String, u64> = HashMap::new();
        for known in self.found.values() {
            let first = first_of_id.entry(known.peer.id.clone()).or_insert(known.seen);
            *first = (*first).min(known.seen);
        }
        let mut found: Vec<(u64, bool, u64, LanPeer)> = self
            .found
            .into_values()
            .map(|known| {
                let first = first_of_id.get(&known.peer.id).copied().unwrap_or(known.seen);
                (first, !known.canonical, known.seen, known.peer)
            })
            .collect();
        found.sort_by_key(|(first, copy, seen, _)| (*first, *copy, *seen));
        found.into_iter().map(|(.., peer)| peer).collect()
    }
}

/// Whether an announcement's instance name is its ID - how every node announces itself ([`LanAnnouncer::start`]).
fn is_canonical(fullname: &str, id: &str) -> bool {
    fullname.strip_suffix(SERVICE_TYPE).and_then(|instance| instance.strip_suffix('.')) == Some(id)
}

/// Checks one resolved announcement. `None` = malformed or not for us: ignored.
fn peer_from(
    ty_domain: &str,
    port: u16,
    addresses: impl IntoIterator<Item = IpAddr>,
    txt: &TxtProperties,
) -> Option<LanPeer> {
    if ty_domain != SERVICE_TYPE || port == 0 || txt_value(txt, "v")? != PROTOCOL {
        return None;
    }
    let id = Id::parse(txt_value(txt, "id")?).ok()?;
    let mut addrs: Vec<IpAddr> = addresses.into_iter().take(MAX_ADDR_CANDIDATES).filter(|ip| usable(*ip)).collect();
    addrs.sort();
    addrs.dedup();
    addrs.truncate(MAX_ADDRS_PER_PEER);
    if addrs.is_empty() {
        return None;
    }
    Some(LanPeer { id: id.as_str().to_owned(), addrs, port })
}

/// A TXT value that is present and UTF-8 (keys are case-insensitive, the first entry of a key counts - RFC 6763).
fn txt_value<'a>(txt: &'a TxtProperties, key: &str) -> Option<&'a str> {
    std::str::from_utf8(txt.get_property_val(key)??).ok()
}

/// Addresses one can connect to. IPv6 link-local is dropped: without its interface (scope) it is not reachable.
fn usable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !(v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast()),
        IpAddr::V6(v6) => !(v6.is_unspecified() || v6.is_multicast() || (v6.segments()[0] & 0xffc0) == 0xfe80),
    }
}

fn check_extra_txt(extra: &[(&str, &str)]) -> TransportResult<()> {
    if extra.len() > MAX_EXTRA_TXT {
        return Err(TransportError::Config("mDNS: too many TXT entries".into()));
    }
    for (index, (key, value)) in extra.iter().enumerate() {
        let key_ok = (1..=MAX_TXT_KEY).contains(&key.len())
            && key.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && *key != "id"
            && *key != "v"
            && !extra[..index].iter().any(|(earlier, _)| earlier == key);
        let value_ok = value.len() <= MAX_TXT_VALUE && value.bytes().all(|b| (0x20..=0x7e).contains(&b));
        if !(key_ok && value_ok) {
            return Err(TransportError::Config(format!("mDNS: bad TXT entry {key:?}")));
        }
    }
    Ok(())
}

/// One mDNS daemon (its own thread and sockets - no global state). Shut down when dropped.
struct Daemon(ServiceDaemon);

impl Daemon {
    fn new() -> TransportResult<Self> {
        ServiceDaemon::new().map(Self).map_err(discovery)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.shutdown(); // asynchronous: the daemon thread finishes queued work (goodbyes), then exits
    }
}

fn discovery(error: mdns_sd::Error) -> TransportError {
    TransportError::Connection(format!("mDNS: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "abcdefghijklmnopqrstuvwxyz234567";

    /// TXT record wire format: length-prefixed `key=value` strings.
    fn txt(entries: &[&[u8]]) -> TxtProperties {
        let mut raw = Vec::new();
        for entry in entries {
            raw.push(u8::try_from(entry.len()).unwrap_or(u8::MAX));
            raw.extend_from_slice(entry);
        }
        TxtProperties::from(&raw[..])
    }

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().filter_map(|ip| ip.parse().ok()).collect()
    }

    fn good_txt() -> TxtProperties {
        txt(&[format!("id={ID}").as_bytes(), b"v=4"])
    }

    #[test]
    fn well_formed_announcement_becomes_a_peer() {
        let peer =
            peer_from(SERVICE_TYPE, 4711, ips(&["fe80::1", "192.168.1.20", "2001:db8::5", "10.0.0.2"]), &good_txt());
        assert_eq!(
            peer,
            Some(LanPeer { id: ID.into(), addrs: ips(&["10.0.0.2", "192.168.1.20", "2001:db8::5"]), port: 4711 })
        );
        // Keys are case-insensitive, extra keys are ignored, duplicate keys: the first counts (RFC 6763 §6.4).
        let mixed = txt(&[format!("ID={ID}").as_bytes(), b"V=4", b"net=x", b"id=bad"]);
        assert_eq!(peer_from(SERVICE_TYPE, 1, ips(&["10.0.0.2"]), &mixed).map(|peer| peer.id), Some(ID.into()));
    }

    #[test]
    fn malformed_announcements_are_ignored() {
        let addrs = ips(&["192.168.1.20"]);
        let upper = ID.to_uppercase();
        let short = &ID[..31];
        let cases: Vec<(&str, TxtProperties)> = vec![
            ("no TXT", txt(&[])),
            ("no id", txt(&[b"v=4"])),
            ("no version", txt(&[format!("id={ID}").as_bytes()])),
            ("wrong version", txt(&[format!("id={ID}").as_bytes(), b"v=3"])),
            ("version without value", txt(&[format!("id={ID}").as_bytes(), b"v"])),
            ("id without value", txt(&[b"id", b"v=4"])),
            ("id upper case", txt(&[format!("id={upper}").as_bytes(), b"v=4"])),
            ("id too short", txt(&[format!("id={short}").as_bytes(), b"v=4"])),
            ("id too long", txt(&[format!("id={ID}a").as_bytes(), b"v=4"])),
            ("id not base32", txt(&[format!("id={}1", &ID[..31]).as_bytes(), b"v=4"])),
            ("id not UTF-8", txt(&[b"id=\xff\xfe", b"v=4"])),
            ("id with a dot", txt(&[format!("id={}.", &ID[..31]).as_bytes(), b"v=4"])),
            ("garbage", TxtProperties::from(&b"\xff\x00\x13"[..])),
        ];
        for (name, properties) in cases {
            assert_eq!(peer_from(SERVICE_TYPE, 4711, addrs.clone(), &properties), None, "{name}");
        }
        assert_eq!(peer_from(SERVICE_TYPE, 0, addrs.clone(), &good_txt()), None, "port 0");
        assert_eq!(peer_from("_http._tcp.local.", 4711, addrs, &good_txt()), None, "other service type");
        let useless = ips(&["0.0.0.0", "::", "224.0.0.251", "ff02::fb", "255.255.255.255", "fe80::1"]);
        assert_eq!(peer_from(SERVICE_TYPE, 4711, useless, &good_txt()), None, "no usable address");
    }

    #[test]
    fn addresses_are_bounded() {
        let many: Vec<IpAddr> = (0..=255u8).map(|i| IpAddr::from([10, 0, 0, i])).chain(ips(&["10.0.0.1"])).collect();
        let peer = peer_from(SERVICE_TYPE, 4711, many, &good_txt());
        assert_eq!(peer.map(|peer| peer.addrs.len()), Some(MAX_ADDRS_PER_PEER));
    }

    #[test]
    fn announcer_checks_its_input() {
        type Case<'a> = (&'a str, u16, Vec<(&'a str, &'a str)>);
        let bad: [Case<'_>; 9] = [
            ("not-an-id", 4711, vec![]),
            (ID, 0, vec![]),
            (ID, 4711, vec![("id", "x")]),
            (ID, 4711, vec![("v", "5")]),
            (ID, 4711, vec![("", "x")]),
            (ID, 4711, vec![("toolongkey", "x")]),
            (ID, 4711, vec![("Net", "x")]),
            (ID, 4711, vec![("net", "a\u{7f}")]),
            (ID, 4711, vec![("net", "x"), ("net", "y")]),
        ];
        for (id, port, extra) in &bad {
            assert!(LanAnnouncer::start(id, *port, extra).is_err(), "{id} {port} {extra:?}");
        }
        let long = "x".repeat(MAX_TXT_VALUE + 1);
        assert!(LanAnnouncer::start(ID, 4711, &[("net", &long)]).is_err());
        let keys: Vec<String> = (0..=MAX_EXTRA_TXT).map(|i| format!("k{i}")).collect();
        let many: Vec<(&str, &str)> = keys.iter().map(|key| (key.as_str(), "x")).collect();
        assert!(LanAnnouncer::start(ID, 4711, &many).is_err());
    }

    #[test]
    fn peer_urls_are_https_with_port_and_brackets() {
        let peer = LanPeer { id: ID.into(), addrs: ips(&["192.168.1.20", "2001:db8::5"]), port: 4711 };
        assert_eq!(peer.urls(), vec!["https://192.168.1.20:4711".to_owned(), "https://[2001:db8::5]:4711".to_owned()]);
    }

    fn fake_id(i: u16, tag: u8) -> String {
        let mut key = [tag; 32];
        key[..2].copy_from_slice(&i.to_be_bytes());
        Id::of_sign_key(&key).as_str().to_owned()
    }

    fn announcement(id: &str, last: u8) -> LanPeer {
        LanPeer { id: id.to_owned(), addrs: ips(&[&format!("10.0.0.{last}")]), port: 7443 }
    }

    /// Review 5, finding 6: 300 announcements of made-up IDs come first. Without a filter they fill the list (first
    /// come); with the caller's filter (the IDs it would contact) they take no slot, and the wanted ones are kept -
    /// even if copies of a wanted ID under 300 other names try to fill the list as well.
    #[test]
    fn a_flood_of_unwanted_or_copied_announcements_can_not_crowd_out_wanted_ones() {
        let real: Vec<String> = (0..3).map(|i| fake_id(i, 7)).collect();
        let flood: Vec<String> = (0..300).map(|i| fake_id(i, 9)).collect();
        let feed = |collector: &mut Collector<'_>| {
            for (i, id) in flood.iter().enumerate() {
                collector.resolved(&format!("{id}.flood"), Some(announcement(id, 9)));
                // A copy of the first real ID under yet another name.
                collector.resolved(&format!("copy-{i}"), Some(announcement(&real[0], 66)));
            }
            for (i, id) in real.iter().enumerate() {
                collector.resolved(&format!("{id}.real"), Some(announcement(id, u8::try_from(i).unwrap_or(0))));
            }
        };
        let mut unfiltered = Collector::new(&|_| true);
        feed(&mut unfiltered);
        let peers = unfiltered.finish();
        assert_eq!(peers.len(), MAX_PEERS, "bounded");
        assert!(!peers.iter().any(|peer| peer.id == real[1]), "without a filter the flood crowds them out");
        let wanted = |id: &str| real.iter().any(|known| known == id);
        let mut filtered = Collector::new(&wanted);
        feed(&mut filtered);
        let peers = filtered.finish();
        for id in &real[1..] {
            assert_eq!(peers.iter().filter(|peer| &peer.id == id).count(), 1, "{id} is kept");
        }
        // Of the copied ID only the first MAX_INSTANCES_PER_ID announcements stay (the real one came too late here).
        assert_eq!(peers.iter().filter(|peer| peer.id == real[0]).count(), MAX_INSTANCES_PER_ID);
        assert_eq!(peers.len(), MAX_INSTANCES_PER_ID + 2);
    }

    /// Review 6, finding 5: four copies of a real node's ID under other instance names come first and fill the slots
    /// of that ID. The real node's own announcement (instance name = its ID) still gets in - the latest copy makes
    /// room - and comes first among its ID. Further copies stay out; with the whole list full, a copy of any ID makes
    /// room for a real node, but never another real node.
    #[test]
    fn the_canonical_announcement_of_an_id_is_always_kept() {
        let real = fake_id(1, 4);
        let canonical = format!("{real}.{SERVICE_TYPE}");
        let mut collector = Collector::new(&|_| true);
        for i in 0..MAX_INSTANCES_PER_ID {
            let name = format!("copy-{i}.{SERVICE_TYPE}");
            assert!(collector.resolved(&name, Some(announcement(&real, 66 + u8::try_from(i).unwrap_or(0)))));
        }
        assert!(!collector.resolved(&format!("late.{SERVICE_TYPE}"), Some(announcement(&real, 99))), "full");
        assert!(collector.resolved(&canonical, Some(announcement(&real, 1))), "the real node gets in");
        assert!(!collector.resolved(&format!("later.{SERVICE_TYPE}"), Some(announcement(&real, 98))));
        assert!(collector.resolved(&canonical, Some(announcement(&real, 2))), "re-announced: stays");
        let peers = collector.finish();
        assert_eq!(peers.len(), MAX_INSTANCES_PER_ID);
        assert_eq!(peers[0].addrs, ips(&["10.0.0.2"]), "the canonical one first: {peers:?}");
        assert!(!peers.iter().any(|peer| peer.addrs == ips(&["10.0.0.69"])), "the latest copy made room");

        // The whole list full: copies of other IDs and real nodes.
        let mut collector = Collector::new(&|_| true);
        let others: Vec<String> = (0..u16::try_from(MAX_PEERS).unwrap_or(0)).map(|i| fake_id(i, 5)).collect();
        for (i, id) in others.iter().enumerate() {
            let name = if i % 2 == 0 { format!("{id}.{SERVICE_TYPE}") } else { format!("copy-{i}.{SERVICE_TYPE}") };
            assert!(collector.resolved(&name, Some(announcement(id, 7))));
        }
        assert!(!collector.resolved(&format!("copy-x.{SERVICE_TYPE}"), Some(announcement(&real, 3))), "full");
        assert!(collector.resolved(&canonical, Some(announcement(&real, 1))), "a copy made room");
        let peers = collector.finish();
        assert_eq!(peers.len(), MAX_PEERS);
        assert_eq!(peers.last().map(|peer| peer.id.clone()), Some(real.clone()));
        assert!(!peers.iter().any(|peer| peer.id == others[MAX_PEERS - 1]), "the latest copy went");
        // Only real nodes in the list: the next real node stays out (first come).
        let mut collector = Collector::new(&|_| true);
        for id in &others {
            assert!(collector.resolved(&format!("{id}.{SERVICE_TYPE}"), Some(announcement(id, 7))));
        }
        assert!(!collector.resolved(&canonical, Some(announcement(&real, 1))));
        // Not canonical: another service type in the name, a prefix of the ID, the ID with a suffix.
        for name in [format!("{real}._http._tcp.local."), format!("{real}x.{SERVICE_TYPE}"), real.clone()] {
            assert!(!is_canonical(&name, &real), "{name}");
        }
        assert!(is_canonical(&canonical, &real));
    }

    #[test]
    fn announcements_come_in_the_order_first_seen_and_can_be_withdrawn() {
        let (a, b) = (fake_id(1, 3), fake_id(2, 3));
        let mut collector = Collector::new(&|_| true);
        assert!(collector.resolved("b", Some(announcement(&b, 2))));
        assert!(collector.resolved("a", Some(announcement(&a, 1))));
        assert!(collector.resolved("b", Some(announcement(&b, 3))), "re-announced: keeps its place, new address");
        assert!(collector.resolved("gone", Some(announcement(&a, 4))));
        collector.removed("gone");
        assert!(!collector.resolved("broken", None));
        let peers = collector.finish();
        assert_eq!(peers.iter().map(|peer| peer.id.clone()).collect::<Vec<_>>(), vec![b, a]);
        assert_eq!(peers[0].addrs, ips(&["10.0.0.3"]));
        // A kept instance whose next announcement is malformed or unwanted is forgotten.
        let only = fake_id(5, 3);
        let wanted = |id: &str| id == only;
        let mut collector = Collector::new(&wanted);
        assert!(collector.resolved("x", Some(announcement(&only, 1))));
        assert!(!collector.resolved("x", Some(announcement(&fake_id(6, 3), 1))));
        assert!(collector.finish().is_empty());
    }

    #[tokio::test]
    async fn find_checks_the_id() {
        assert!(find("not-an-id", Duration::from_millis(10)).await.is_err());
    }

    /// Announce and find this node on this machine. Needs multicast on a network interface - some CI runners
    /// (Windows) block it, so it runs only with `cargo test -- --ignored` (CI: Ubuntu).
    #[tokio::test]
    #[ignore = "needs multicast"]
    async fn announce_and_browse_find_this_node() -> TransportResult<()> {
        // A fresh ID per run, so parallel runs and other machines in the network do not interfere.
        let seed = format!("{:?}{}", std::time::SystemTime::now(), std::process::id());
        let id = Id::of_sign_key(&bridge_core::crypto::sha256(seed.as_bytes())).as_str().to_owned();
        let announcer = LanAnnouncer::start(&id, 47_110, &[("net", "test")])?;
        let mut seen = None;
        for _ in 0..5 {
            let peers = browse(Duration::from_secs(2)).await?;
            assert!(peers.len() <= MAX_PEERS);
            if let Some(peer) = peers.into_iter().find(|peer| peer.id == id) {
                seen = Some(peer);
                break;
            }
        }
        let peer = seen.ok_or_else(|| TransportError::Connection("own announcement not found".into()))?;
        assert_eq!(peer.port, 47_110);
        assert!(!peer.addrs.is_empty() && peer.addrs.len() <= MAX_ADDRS_PER_PEER);
        // `find` returns soon after the node is seen, and only announcements of that ID.
        let started = std::time::Instant::now();
        let found = find(&id, Duration::from_secs(10)).await?;
        assert!(!found.is_empty() && found.iter().all(|peer| peer.id == id), "{found:?}");
        assert!(started.elapsed() < Duration::from_secs(8), "find waited for the whole timeout");
        announcer.shutdown();
        Ok(())
    }
}
