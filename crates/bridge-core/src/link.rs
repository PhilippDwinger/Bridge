//! Join links (docs/06 §7):
//! `bridge4://join?net=<net id>&gw=<url-encoded gateway URL>&code=<invite code>&node=<gateway id>&tls=<pin>`.
//!
//! One format for everybody (S5): the node program reads it for `--join-net`, the SDKs for `Client::join`, the CLI
//! prints it. Parsing is strict and bounded: at most 1024 characters, every key at most once, the network ID in
//! its fixed form, the gateway a valid address (docs/06 §2), the code from a small alphabet. Unknown keys are
//! ignored (later versions may add some), but count against the limit of 8 parameters.
//!
//! LAN (docs/06 §2): `node` pins the gateway's ID (a gateway with another ID is refused on every path), `tls` is the
//! Base64url SHA-256 of the gateway's TLS certificate from its signed key card - with both, a client looks for the
//! gateway in the LAN first and connects with exactly that certificate. `tls` needs `node` (the LAN is searched by
//! node ID), `node` alone is fine (pinning over the Internet).

use crate::encoding::{b64, b64_fixed};
use crate::error::{CoreError, CoreResult};
use crate::id::Id;
use crate::keys::check_url;

/// Prefix of every join link.
pub const JOIN_PREFIX: &str = "bridge4://join?";
/// Maximum length of a join link.
pub const MAX_LINK_CHARS: usize = 1024;
/// Maximum number of parameters in a join link.
const MAX_PARAMS: usize = 8;
/// Shortest and longest invite code.
pub const INVITE_CODE_CHARS: std::ops::RangeInclusive<usize> = 4..=64;

/// A parsed join link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinLink {
    /// The network to join.
    pub net: Id,
    /// Address of a gateway of that network.
    pub gateway: String,
    /// Invite code (networks with template `invite`).
    pub code: Option<String>,
    /// ID of the gateway: pinned on every path (required with `tls`).
    pub node: Option<Id>,
    /// TLS pin of the gateway for the LAN: SHA-256 of its certificate (the `tls` field of its key card).
    pub tls: Option<[u8; 32]>,
}

/// Checks an invite code: 4-64 characters of `A-Z`, `a-z`, `0-9` and `-`.
pub fn check_invite_code(code: &str) -> CoreResult<()> {
    if !INVITE_CODE_CHARS.contains(&code.len()) || !code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(CoreError::format("code: 4-64 characters of A-Z, a-z, 0-9 and -"));
    }
    Ok(())
}

impl JoinLink {
    /// Parses a link (strict, see module docs).
    pub fn parse(text: &str) -> CoreResult<Self> {
        if text.len() > MAX_LINK_CHARS {
            return Err(CoreError::TooLarge("join link".into()));
        }
        let query = text
            .trim()
            .strip_prefix(JOIN_PREFIX)
            .ok_or_else(|| CoreError::format(format!("join link: must start with {JOIN_PREFIX}")))?;
        let (mut net, mut gateway, mut code, mut node, mut tls) = (None, None, None, None, None);
        for (count, pair) in query.split('&').enumerate() {
            if count >= MAX_PARAMS {
                return Err(CoreError::format("join link: too many parameters"));
            }
            let (key, value) = pair.split_once('=').ok_or_else(|| CoreError::format("join link: key=value"))?;
            let slot = match key {
                "net" => &mut net,
                "gw" => &mut gateway,
                "code" => &mut code,
                "node" => &mut node,
                "tls" => &mut tls,
                _ => continue,
            };
            if slot.replace(percent_decode(value)?).is_some() {
                return Err(CoreError::format(format!("join link: {key} twice")));
            }
        }
        let net = Id::parse(&net.ok_or_else(|| CoreError::format("join link: net missing"))?)?;
        let gateway = gateway.ok_or_else(|| CoreError::format("join link: gw missing"))?;
        check_url(&gateway)?;
        if let Some(code) = &code {
            check_invite_code(code)?;
        }
        let node = node.map(|node| Id::parse(&node)).transpose()?;
        if node.as_ref() == Some(&net) {
            return Err(CoreError::format("join link: node is the network key, not a gateway"));
        }
        let tls = tls.map(|tls| b64_fixed::<32>(&tls, "join link: tls")).transpose()?;
        if tls.is_some() && node.is_none() {
            return Err(CoreError::format("join link: tls needs node"));
        }
        Ok(Self { net, gateway, code, node, tls })
    }

    /// The link as text.
    #[must_use]
    pub fn to_link(&self) -> String {
        let mut link = format!("{JOIN_PREFIX}net={}&gw={}", self.net, percent_encode(&self.gateway));
        if let Some(code) = &self.code {
            link.push_str("&code=");
            link.push_str(&percent_encode(code));
        }
        if let Some(node) = &self.node {
            link.push_str("&node=");
            link.push_str(node.as_str());
        }
        if let Some(tls) = &self.tls {
            link.push_str("&tls=");
            link.push_str(&b64(tls));
        }
        link
    }
}

/// Percent-encodes everything except the unreserved characters of RFC 3986.
fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len() * 3);
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Decodes `%XX` escapes. The result must be printable ASCII (addresses, IDs and codes are).
fn percent_decode(text: &str) -> CoreResult<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let hex = bytes.get(index + 1..index + 3).ok_or_else(|| CoreError::format("join link: bad % escape"))?;
            let hex = std::str::from_utf8(hex).map_err(|_| CoreError::format("join link: bad % escape"))?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| CoreError::format("join link: bad % escape"))?);
            index += 3;
        } else {
            out.push(byte);
            index += 1;
        }
    }
    if !out.iter().all(u8::is_ascii_graphic) {
        return Err(CoreError::format("join link: only printable ASCII"));
    }
    String::from_utf8(out).map_err(|_| CoreError::format("join link: only printable ASCII"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net() -> Id {
        Id::of_sign_key(&[3u8; 32])
    }

    #[test]
    fn roundtrip_with_and_without_code() -> CoreResult<()> {
        let link = JoinLink {
            net: net(),
            gateway: "https://pc.tail91b057.ts.net:8443/n1/".into(),
            code: None,
            node: None,
            tls: None,
        };
        let text = link.to_link();
        assert!(
            text.starts_with("bridge4://join?net=") && text.contains("gw=https%3A%2F%2Fpc.tail91b057.ts.net%3A8443")
        );
        assert_eq!(JoinLink::parse(&text)?, link);
        let invite = JoinLink { code: Some("K7Q2-M9XA-TT3P".into()), ..link };
        assert_eq!(JoinLink::parse(&invite.to_link())?, invite);
        // Unknown keys are ignored, unencoded addresses work as well
        let plain = format!("bridge4://join?net={}&gw=http://127.0.0.1:7400&future=1", net());
        assert_eq!(JoinLink::parse(&plain)?.gateway, "http://127.0.0.1:7400");
        Ok(())
    }

    #[test]
    fn lan_parameters_roundtrip_and_are_checked() -> CoreResult<()> {
        let gateway = Id::of_sign_key(&[4u8; 32]);
        let pin = crate::crypto::sha256(b"certificate");
        let link = JoinLink {
            net: net(),
            gateway: "https://pc.tail91b057.ts.net:8443/n1".into(),
            code: Some("K7Q2-M9XA-TT3P".into()),
            node: Some(gateway.clone()),
            tls: Some(pin),
        };
        let text = link.to_link();
        assert!(text.ends_with(&format!("&node={gateway}&tls={}", b64(&pin))), "{text}");
        assert_eq!(JoinLink::parse(&text)?, link);
        let pinned_only = JoinLink { tls: None, code: None, ..link.clone() };
        assert_eq!(JoinLink::parse(&pinned_only.to_link())?, pinned_only, "node alone pins over the Internet");
        // The longest possible link still fits: a 200-character address, every byte escaped, code, node and pin.
        let long = JoinLink { gateway: format!("https://{}", "%".repeat(192)), code: Some("a".repeat(64)), ..link };
        assert!(long.to_link().len() <= MAX_LINK_CHARS, "{}", long.to_link().len());
        assert_eq!(JoinLink::parse(&long.to_link())?, long);

        let base = format!("bridge4://join?net={}&gw=https%3A%2F%2Fa.example", net());
        let short_pin = &b64(&pin)[..42];
        for bad in [
            format!("{base}&tls={}", b64(&pin)),                         // tls without node
            format!("{base}&node={gateway}&tls={short_pin}"),            // 31 bytes
            format!("{base}&node={gateway}&tls={}A", b64(&pin)),         // 33 bytes
            format!("{base}&node={gateway}&tls={}", b64(&[1u8; 16])),    // 16 bytes
            format!("{base}&node={gateway}&tls={}=", b64(&pin)),         // padding is not canonical
            format!("{base}&node={gateway}&tls=%2B{}", &b64(&pin)[1..]), // standard base64 '+'
            format!("{base}&node={gateway}&tls="),                       // empty
            format!("{base}&node={gateway}&tls={}&tls={}", b64(&pin), b64(&pin)), // twice
            format!("{base}&node={gateway}&node={gateway}"),             // twice
            format!("{base}&node=XYZ"),                                  // not an ID
            format!("{base}&node={}", gateway.as_str().to_uppercase()),  // not the canonical form
            format!("{base}&node={}", net()),                            // the network key is no gateway
        ] {
            assert!(JoinLink::parse(&bad).is_err(), "{bad}");
        }
        Ok(())
    }

    #[test]
    fn attacks_are_refused() {
        let good = format!("net={}&gw=https%3A%2F%2Fa.example", net());
        for bad in [
            format!("https://join?{good}"),
            format!("bridge4://join?{good}&net={}", net()),
            "bridge4://join?gw=https%3A%2F%2Fa.example".to_owned(),
            format!("bridge4://join?net={}", net()),
            "bridge4://join?net=XYZ&gw=https%3A%2F%2Fa.example".to_owned(),
            format!("bridge4://join?net={}&gw=ftp%3A%2F%2Fa", net()),
            format!("bridge4://join?{good}&code=a b"),
            format!("bridge4://join?{good}&code=%0A%0A%0A%0A"),
            format!("bridge4://join?{good}&code=abc"),
            format!("bridge4://join?{good}&code=%zz"),
            format!("bridge4://join?{good}&code=%4"),
            format!("bridge4://join?{good}{}", "&x=1".repeat(10)),
            format!("bridge4://join?{good}&code={}", "a".repeat(2000)),
            format!("bridge4://join?{good}&gw"),
        ] {
            assert!(JoinLink::parse(&bad).is_err(), "{bad}");
        }
        assert!(check_invite_code("ABCD-1234").is_ok());
        assert!(check_invite_code("ä-ab").is_err());
    }
}
