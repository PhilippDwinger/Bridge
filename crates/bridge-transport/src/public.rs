//! Calls to addresses that another identity chose (review 8, docs/06 §2 "Adress-Schutz"): a node that probes the
//! address of a registered node, or talks to a host whose card only a watcher sealed, must not become a tool against
//! its own network (server-side request forgery: `http://127.0.0.1:7380/…`, `http://169.254.169.254/…`, the router).
//!
//! [`HttpClient::new_public`] resolves the name once, keeps only public addresses ([`is_public_ip`]) and connects to
//! exactly those: the name is pinned to them for this client (no second lookup that could answer differently -
//! DNS rebinding), every other name is refused, no proxy sits in between. IP literals are checked as they are, in the
//! normalized form the HTTP client itself uses (`http://2130706433/` is `127.0.0.1`).
//!
//! Which addresses count is the [`PeerAddresses`] rule: `Public` (the default of `bridge-node`), `Tailnet` (public plus
//! Tailscale's own ranges - for networks whose nodes reach each other through Tailscale; BridgeControll's default) or
//! `Any` (no check; LAN-only networks, tests). [`HttpClient::new_checked`] applies one.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::{HttpClient, MAX_BASE_URL, MAX_RESPONSE_BYTES, TransportError, TransportResult};

/// Which addresses a node calls when another node chose them (docs/06 §2 "Adress-Schutz").
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PeerAddresses {
    /// Only public addresses ([`is_public_ip`]).
    #[default]
    Public,
    /// Public addresses and Tailscale's ranges ([`is_tailnet_ip`]): 100.64.0.0/10 and fd7a:115c:a1e0::/48 - still no
    /// loopback, RFC 1918, link-local, other ULAs …
    Tailnet,
    /// Every address (no check at all).
    Any,
}

impl PeerAddresses {
    /// Wire/CLI name: `public`, `tailnet`, `any`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Tailnet => "tailnet",
            Self::Any => "any",
        }
    }

    /// From the wire/CLI name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "public" => Some(Self::Public),
            "tailnet" => Some(Self::Tailnet),
            "any" => Some(Self::Any),
            _ => None,
        }
    }

    /// Whether `ip` may be called under this rule.
    #[must_use]
    pub fn allows(self, ip: IpAddr) -> bool {
        match self {
            Self::Public => is_public_ip(ip),
            Self::Tailnet => is_public_ip(ip) || is_tailnet_ip(ip),
            Self::Any => true,
        }
    }
}

/// Whether `ip` is in Tailscale's ranges: 100.64.0.0/10 (shared address space, Tailscale's node addresses) or
/// fd7a:115c:a1e0::/48 (Tailscale's IPv6 ULA prefix); an IPv4 address mapped into IPv6 counts by itself.
#[must_use]
pub fn is_tailnet_ip(ip: IpAddr) -> bool {
    let v4 = match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    };
    match (v4, ip) {
        (Some(v4), _) => {
            let [a, b, _, _] = v4.octets();
            a == 100 && (b & 0xc0) == 64
        }
        (None, IpAddr::V6(v6)) => v6.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
        (None, IpAddr::V4(_)) => false,
    }
}

/// Most addresses taken from one DNS answer.
const MAX_RESOLVED: usize = 8;
/// Longest wait for a DNS answer.
const MAX_LOOKUP: Duration = Duration::from_secs(3);

/// Whether `ip` is a public unicast address: not unspecified, loopback, private (RFC 1918), shared/CGNAT
/// (100.64.0.0/10 - also Tailscale), link-local, multicast, broadcast, documentation, benchmarking, reserved, IETF
/// protocol assignments; for IPv6 also not unique-local (fc00::/7), link- or site-local, the IPv4-compatible and
/// discard ranges, Teredo, and IPv4-mapped / NAT64 / 6to4 addresses only if the IPv4 address inside is public.
#[must_use]
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => public_v6(v6),
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || (a == 100 && (b & 0xc0) == 64)
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (b & 0xfe) == 18)
        || a >= 240)
}

fn public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return public_v4(v4);
    }
    let s = ip.segments();
    let embedded = |high: u16, low: u16| Ipv4Addr::from((u32::from(high) << 16) | u32::from(low));
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        return public_v4(embedded(s[6], s[7])); // NAT64 well-known prefix 64:ff9b::/96
    }
    if s[0] == 0x2002 {
        return public_v4(embedded(s[1], s[2])); // 6to4 2002::/16
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xffc0) == 0xfec0
        || s[0..6] == [0, 0, 0, 0, 0, 0]
        || (s[0] == 0x0064 && s[1] == 0xff9b)
        || (s[0] == 0x0100 && s[1..4] == [0, 0, 0])
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        || (s[0] == 0x2001 && s[1] == 0))
}

/// A resolver that answers nothing: the only names this client knows are the ones pinned to checked addresses.
struct NoDns;

impl reqwest::dns::Resolve for NoDns {
    fn resolve(&self, _name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async {
            Err::<reqwest::dns::Addrs, _>("no lookups: the address was checked and pinned before".into())
        })
    }
}

impl HttpClient {
    /// A client for `base_url` that only ever connects to public addresses: [`HttpClient::new_checked`] with
    /// [`PeerAddresses::Public`].
    pub async fn new_public(base_url: &str, timeout: Duration) -> TransportResult<Self> {
        Self::new_checked(base_url, timeout, PeerAddresses::Public).await
    }

    /// A client for `base_url` that only ever connects to addresses `rule` allows (see the module docs): an IP literal
    /// must be allowed; a name is resolved now (at most 3 s, at most 8 addresses), the other answers are dropped, and
    /// the name is pinned to the rest. Refused (`TransportError::Refused`) if nothing allowed is left. With
    /// [`PeerAddresses::Any`] it is a plain [`HttpClient::new`].
    pub async fn new_checked(base_url: &str, timeout: Duration, rule: PeerAddresses) -> TransportResult<Self> {
        if rule == PeerAddresses::Any {
            return Self::new(base_url, timeout);
        }
        let base = base_url.trim_end_matches('/').to_owned();
        if !(base.starts_with("http://") || base.starts_with("https://")) || base.len() > MAX_BASE_URL {
            return Err(TransportError::Config("URL must start with http:// or https://".into()));
        }
        let url = reqwest::Url::parse(&base).map_err(|e| TransportError::Config(e.to_string()))?;
        if !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
            return Err(TransportError::Config("URL with user, query or fragment".into()));
        }
        let host = url.host_str().ok_or_else(|| TransportError::Config("URL without host".into()))?.to_owned();
        let port = url.port_or_known_default().ok_or_else(|| TransportError::Config("URL without port".into()))?;
        let mut builder = Self::builder(timeout).no_proxy().dns_resolver(Arc::new(NoDns));
        let literal = host.strip_prefix('[').and_then(|inner| inner.strip_suffix(']')).unwrap_or(&host);
        if let Ok(ip) = literal.parse::<IpAddr>() {
            if !rule.allows(ip) {
                return Err(TransportError::Refused(format!("{ip} is not allowed ({})", rule.as_str())));
            }
        } else {
            let addrs = resolve_allowed(&host, port, timeout.min(MAX_LOOKUP), rule).await?;
            builder = builder.resolve_to_addrs(&host, &addrs);
        }
        let inner = builder.build().map_err(|e| TransportError::Config(e.to_string()))?;
        Ok(Self { inner, base, max_response_bytes: MAX_RESPONSE_BYTES })
    }
}

/// The addresses of `host` that `rule` allows (at most [`MAX_RESOLVED`]); refused if there is none.
async fn resolve_allowed(
    host: &str,
    port: u16,
    limit: Duration,
    rule: PeerAddresses,
) -> TransportResult<Vec<SocketAddr>> {
    let lookup = tokio::net::lookup_host((host, port));
    let found = tokio::time::timeout(limit, lookup)
        .await
        .map_err(|_| TransportError::Connection(format!("{host}: no DNS answer in time")))?
        .map_err(|e| TransportError::Connection(format!("{host}: {e}")))?;
    let mut public = Vec::new();
    let mut refused = None;
    for addr in found.take(4 * MAX_RESOLVED) {
        if !rule.allows(addr.ip()) {
            refused.get_or_insert(addr.ip());
        } else if public.len() < MAX_RESOLVED && !public.contains(&addr) {
            public.push(addr);
        }
    }
    if public.is_empty() {
        let why =
            refused.map_or_else(|| "no address".to_owned(), |ip| format!("{ip} is not allowed ({})", rule.as_str()));
        return Err(TransportError::Refused(format!("{host}: {why}")));
    }
    Ok(public)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_and_non_public_addresses() {
        for public in ["8.8.8.8", "1.1.1.1", "100.63.255.255", "100.128.0.1", "172.32.0.1", "2a00:1450:4001::1"] {
            let ip: IpAddr = public.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            assert!(is_public_ip(ip), "{public}");
        }
        for private in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "127.255.0.9",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.100.100.100",
            "100.127.255.254",
            "224.0.0.251",
            "239.255.255.250",
            "255.255.255.255",
            "240.0.0.1",
            "192.0.0.8",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.7",
            "203.0.113.9",
            "::",
            "::1",
            "::127.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:10.1.2.3",
            "64:ff9b::a00:1",
            "64:ff9b:1::1",
            "2002:7f00:1::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "febf::1",
            "fec0::1",
            "ff02::1",
            "2001:db8::1",
            "2001:0:4136:e378::1",
            "100::1",
        ] {
            let ip: IpAddr = private.parse().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
            assert!(!is_public_ip(ip), "{private}");
        }
        // IPv4 inside IPv6 counts by the IPv4 address.
        let mapped: IpAddr = "::ffff:8.8.8.8".parse().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(is_public_ip(mapped));
        let six_to_four: IpAddr = "2002:808:808::1".parse().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(is_public_ip(six_to_four));
    }

    /// Follow-up of review 8: `tailnet` allows Tailscale's ranges (100.64.0.0/10, fd7a:115c:a1e0::/48) on top of the
    /// public ones - nothing else; `public` refuses them; private ranges are refused by both.
    #[test]
    fn tailnet_rule_allows_only_tailscale_ranges() {
        let ip = |text: &str| text.parse::<IpAddr>().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        for tailnet in ["100.64.0.1", "100.100.100.100", "100.127.255.254", "fd7a:115c:a1e0::1", "::ffff:100.64.1.2"] {
            assert!(PeerAddresses::Tailnet.allows(ip(tailnet)), "{tailnet}");
            assert!(!PeerAddresses::Public.allows(ip(tailnet)), "{tailnet}");
            assert!(PeerAddresses::Any.allows(ip(tailnet)));
        }
        for private in [
            "10.0.0.1",
            "127.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254",
            "::1",
            "fd7a:115c:a1e1::1",
            "fd00::1",
        ] {
            assert!(!PeerAddresses::Tailnet.allows(ip(private)), "{private}");
            assert!(!PeerAddresses::Public.allows(ip(private)), "{private}");
        }
        for public in ["8.8.8.8", "2a00:1450:4001::1"] {
            assert!(PeerAddresses::Tailnet.allows(ip(public)) && PeerAddresses::Public.allows(ip(public)));
        }
        for rule in [PeerAddresses::Public, PeerAddresses::Tailnet, PeerAddresses::Any] {
            assert_eq!(PeerAddresses::parse(rule.as_str()), Some(rule));
        }
        assert_eq!(PeerAddresses::parse("alle"), None);
        assert_eq!(PeerAddresses::default(), PeerAddresses::Public);
    }

    #[tokio::test]
    async fn tailnet_clients_reach_tailscale_but_not_private() {
        let built =
            |url: &'static str, rule| async move { HttpClient::new_checked(url, Duration::from_secs(1), rule).await };
        assert!(built("http://100.64.0.1:8443/k", PeerAddresses::Tailnet).await.is_ok(), "allowed (nothing sent yet)");
        assert!(built("http://[fd7a:115c:a1e0::5]/k", PeerAddresses::Tailnet).await.is_ok());
        assert!(matches!(built("http://100.64.0.1/k", PeerAddresses::Public).await, Err(TransportError::Refused(_))));
        for rule in [PeerAddresses::Public, PeerAddresses::Tailnet] {
            for url in ["http://10.0.0.1/x", "http://127.0.0.1:7380", "http://localhost:7380", "http://[fd00::1]/"] {
                assert!(matches!(built(url, rule).await, Err(TransportError::Refused(_))), "{url} {rule:?}");
            }
        }
        assert!(built("http://10.0.0.1/x", PeerAddresses::Any).await.is_ok(), "any: no check");
    }

    /// Review 8, finding 2: member-chosen addresses that point into the node's own machine or network are refused
    /// before any connection - also as names that resolve there, and in the IPv4 forms the URL parser normalizes.
    #[tokio::test]
    async fn non_public_targets_are_refused_before_connecting() {
        // A listener on 127.0.0.1 that must never see a request.
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0));
        let port = listener.as_ref().map_or(1, |listener| listener.local_addr().map_or(1, |addr| addr.port()));
        let local = format!("http://127.0.0.1:{port}");
        for url in [
            local.as_str(),
            "http://127.0.0.1:7380/x",
            "http://[::1]:7400",
            "http://[::ffff:127.0.0.1]/",
            "http://169.254.169.254/latest/meta-data",
            "http://10.0.0.1/x",
            "http://100.100.100.100/",
            "http://[fd00::1]/",
            "http://[fe80::1]/",
            "http://0.0.0.0:7400",
            "http://2130706433/",
            "http://0x7f.1/",
            "http://localhost:7380",
        ] {
            let result = HttpClient::new_public(url, Duration::from_secs(2)).await;
            assert!(matches!(result, Err(TransportError::Refused(_))), "{url}: {:?}", result.map(|_| "a client"));
        }
        if let Ok(listener) = listener {
            listener.set_nonblocking(true).ok();
            assert!(listener.accept().is_err(), "nothing connected to the local listener");
        }
        // Not even a malformed URL gets through.
        assert!(HttpClient::new_public("ftp://8.8.8.8", Duration::from_secs(1)).await.is_err());
    }
}
