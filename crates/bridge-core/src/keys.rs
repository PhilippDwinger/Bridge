//! Identities (secret) and key cards (public, self-signed) - docs/02 §5, docs/04 §2.

use std::fmt;

use ed25519_dalek::SigningKey;
use rand_core::{CryptoRng, RngCore};
use serde_json::{Map, Value, json};
use x25519_dalek::StaticSecret;
use zeroize::Zeroizing;

use crate::crypto;
use crate::encoding::{b64, b64_fixed};
use crate::error::{CoreError, CoreResult};
use crate::id::Id;
use crate::json::{canonical, canonical_without, parse_strict};
use crate::{PROTOCOL_VERSION, field_i64, field_str};

/// Maximum size of a key card in bytes.
pub const MAX_KEY_CARD_BYTES: usize = 2048;
/// Maximum length of the optional display name.
pub const MAX_NAME_CHARS: usize = 64;
/// Maximum number of addresses (`urls`) on a node card (docs/06 §2).
pub const MAX_URLS: usize = 4;
/// Maximum length of one address in characters.
pub const MAX_URL_CHARS: usize = 200;

/// Checks one address (key cards, manifests - one rule, S5): starts with `https://` or `http://`, something follows,
/// at most 200 characters, printable ASCII only (no whitespace, no control characters).
pub fn check_url(url: &str) -> CoreResult<()> {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"));
    let ok = url.len() <= MAX_URL_CHARS
        && rest.is_some_and(|rest| !rest.is_empty())
        && url.bytes().all(|b| b.is_ascii_graphic());
    if !ok {
        return Err(CoreError::format("url: expected http(s)://..., at most 200 printable ASCII characters"));
    }
    Ok(())
}

/// What an identity is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// A program that uses networks.
    Client,
    /// A running Bridge process.
    Node,
    /// The main key of a network (its ID is the network ID).
    Net,
    /// An admin key delegated by a network's main key.
    Admin,
}

impl Role {
    /// Wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Node => "node",
            Self::Net => "net",
            Self::Admin => "admin",
        }
    }

    fn parse(text: &str) -> CoreResult<Self> {
        match text {
            "client" => Ok(Self::Client),
            "node" => Ok(Self::Node),
            "net" => Ok(Self::Net),
            "admin" => Ok(Self::Admin),
            _ => Err(CoreError::format("role: unknown")),
        }
    }
}

/// A secret identity: Ed25519 key for signing + X25519 key for receiving. Secrets are wiped from memory on drop.
pub struct Identity {
    signing: SigningKey,
    receiving: StaticSecret,
    id: Id,
}

impl Identity {
    /// A new identity from the operating system's (or a test's) random source.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let signing = crypto::generate_signing_key(rng);
        let receiving = crypto::generate_box_secret(rng);
        Self::from_parts(signing, receiving)
    }

    /// An identity from stored secret bytes (key files, recovery). Callers must protect these bytes.
    #[must_use]
    pub fn from_secret_bytes(sign_secret: &[u8; 32], receive_secret: &[u8; 32]) -> Self {
        Self::from_parts(crypto::signing_key_from_bytes(sign_secret), crypto::box_secret_from_bytes(receive_secret))
    }

    fn from_parts(signing: SigningKey, receiving: StaticSecret) -> Self {
        let id = Id::of_sign_key(&crypto::sign_public(&signing));
        Self { signing, receiving, id }
    }

    /// The ID of this identity.
    #[must_use]
    pub fn id(&self) -> &Id {
        &self.id
    }

    /// The public signing key.
    #[must_use]
    pub fn sign_public(&self) -> [u8; 32] {
        crypto::sign_public(&self.signing)
    }

    /// The public receiving (X25519) key.
    #[must_use]
    pub fn receive_public(&self) -> [u8; 32] {
        crypto::box_public(&self.receiving)
    }

    /// Creates the self-signed key card of this identity (no addresses).
    pub fn key_card(&self, role: Role, name: Option<&str>, iat_ms: i64) -> CoreResult<KeyCard> {
        self.key_card_with(role, name, &[], None, iat_ms)
    }

    /// Creates the self-signed key card with addresses (`urls`, 0-4) and the TLS pin (`tls`, SHA-256 of the DER
    /// certificate) - both only allowed for role `node` (docs/06 §2). Both are signed like every other field.
    pub fn key_card_with(
        &self,
        role: Role,
        name: Option<&str>,
        urls: &[String],
        tls: Option<[u8; 32]>,
        iat_ms: i64,
    ) -> CoreResult<KeyCard> {
        let mut object = Map::new();
        object.insert("v".into(), json!(PROTOCOL_VERSION));
        object.insert("t".into(), json!("key"));
        object.insert("id".into(), json!(self.id.as_str()));
        object.insert("sign".into(), json!(b64(&self.sign_public())));
        object.insert("box".into(), json!(b64(&self.receive_public())));
        object.insert("role".into(), json!(role.as_str()));
        if let Some(name) = name {
            object.insert("name".into(), json!(name));
        }
        if !urls.is_empty() {
            object.insert("urls".into(), json!(urls));
        }
        if let Some(tls) = tls {
            object.insert("tls".into(), json!(b64(&tls)));
        }
        object.insert("iat".into(), json!(iat_ms));
        let signature = self.sign_canonical("key", &canonical(&Value::Object(object.clone()))?);
        object.insert("sig".into(), json!(b64(&signature)));
        KeyCard::from_value(Value::Object(object))
    }

    pub(crate) fn sign_canonical(&self, domain: &str, canonical_bytes: &[u8]) -> [u8; 64] {
        crypto::sign(&self.signing, domain, canonical_bytes)
    }

    /// The secret bytes (signing secret, receiving secret) for storing in a key file. Handle with care: whoever has
    /// these bytes *is* this identity. The returned buffers are wiped when dropped.
    #[must_use]
    pub fn secret_bytes(&self) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
        (Zeroizing::new(self.signing.to_bytes()), Zeroizing::new(self.receiving.to_bytes()))
    }

    pub(crate) fn receiving_secret(&self) -> &StaticSecret {
        &self.receiving
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print secrets.
        write!(f, "Identity({})", self.id)
    }
}

/// The public, self-signed card of an identity. Constructed only through checks: a `KeyCard` value is always
/// well-formed and its signature and ID are valid.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyCard {
    raw: Map<String, Value>,
    id: Id,
    sign: [u8; 32],
    receive: [u8; 32],
    role: Role,
    iat: i64,
    urls: Vec<String>,
    tls: Option<[u8; 32]>,
}

impl KeyCard {
    /// Parses and fully verifies a key card from bytes.
    pub fn parse(bytes: &[u8]) -> CoreResult<Self> {
        Self::from_value(parse_strict(bytes, MAX_KEY_CARD_BYTES)?)
    }

    /// Verifies a key card given as JSON value: form, ID = fingerprint of the signing key, self-signature.
    pub fn from_value(value: Value) -> CoreResult<Self> {
        if crate::json::depth(&value) > 4 || canonical(&value)?.len() > MAX_KEY_CARD_BYTES {
            return Err(CoreError::TooLarge("key card".into()));
        }
        let Value::Object(raw) = value else {
            return Err(CoreError::format("key card: not an object"));
        };
        if field_i64(&raw, "v")? != PROTOCOL_VERSION || field_str(&raw, "t")? != "key" {
            return Err(CoreError::format("key card: wrong version or type"));
        }
        let id = Id::parse(field_str(&raw, "id")?)?;
        let sign = b64_fixed::<32>(field_str(&raw, "sign")?, "sign")?;
        let receive = b64_fixed::<32>(field_str(&raw, "box")?, "box")?;
        let role = Role::parse(field_str(&raw, "role")?)?;
        if let Some(name) = raw.get("name") {
            let name = name.as_str().ok_or_else(|| CoreError::format("name: not a string"))?;
            if name.chars().count() > MAX_NAME_CHARS {
                return Err(CoreError::format("name: too long"));
            }
        }
        let iat = field_i64(&raw, "iat")?;
        if iat < 0 {
            return Err(CoreError::format("iat: negative"));
        }
        let urls = parse_urls(raw.get("urls"))?;
        let tls = match raw.get("tls") {
            None => None,
            Some(value) => {
                Some(b64_fixed::<32>(value.as_str().ok_or_else(|| CoreError::format("tls: not a string"))?, "tls")?)
            }
        };
        if (!urls.is_empty() || tls.is_some()) && role != Role::Node {
            return Err(CoreError::format("urls/tls: only on node cards"));
        }
        let signature = b64_fixed::<64>(field_str(&raw, "sig")?, "sig")?;
        if Id::of_sign_key(&sign) != id {
            return Err(CoreError::BadSignature);
        }
        crypto::verify(&sign, "key", &canonical_without(&raw, &["sig"])?, &signature)?;
        Ok(Self { raw, id, sign, receive, role, iat, urls, tls })
    }

    /// ID of the identity.
    #[must_use]
    pub fn id(&self) -> &Id {
        &self.id
    }
    /// Public signing key.
    #[must_use]
    pub fn sign_public(&self) -> &[u8; 32] {
        &self.sign
    }
    /// Public receiving key.
    #[must_use]
    pub fn receive_public(&self) -> &[u8; 32] {
        &self.receive
    }
    /// Role.
    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }
    /// Issued at (ms).
    #[must_use]
    pub fn iat(&self) -> i64 {
        self.iat
    }
    /// Addresses of a node (empty if none).
    #[must_use]
    pub fn urls(&self) -> &[String] {
        &self.urls
    }
    /// TLS pin of a node: SHA-256 of its DER certificate.
    #[must_use]
    pub fn tls(&self) -> Option<&[u8; 32]> {
        self.tls.as_ref()
    }
    /// The card as JSON value (exactly as signed).
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Object(self.raw.clone())
    }
    /// The card as canonical JSON bytes.
    pub fn to_bytes(&self) -> CoreResult<Vec<u8>> {
        canonical(&self.to_value())
    }
}

/// `urls`: absent, or 1-4 distinct valid addresses.
fn parse_urls(value: Option<&Value>) -> CoreResult<Vec<String>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let list = value
        .as_array()
        .filter(|list| (1..=MAX_URLS).contains(&list.len()))
        .ok_or_else(|| CoreError::format("urls: 1..=4 addresses"))?;
    let mut urls: Vec<String> = Vec::with_capacity(list.len());
    for item in list {
        let url = item.as_str().ok_or_else(|| CoreError::format("urls: not a string"))?;
        check_url(url)?;
        if urls.iter().any(|known| known == url) {
            return Err(CoreError::format("urls: duplicate"));
        }
        urls.push(url.to_owned());
    }
    Ok(urls)
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn key_card_roundtrip_and_tamper() -> CoreResult<()> {
        let identity = Identity::generate(&mut OsRng);
        let card = identity.key_card(Role::Client, Some("Spiel A"), 1_000)?;
        assert_eq!(card.id(), identity.id());
        let bytes = card.to_bytes()?;
        assert_eq!(KeyCard::parse(&bytes)?, card);

        // Tamper: change the name -> signature no longer fits
        let mut value = card.to_value();
        value["name"] = json!("Fake");
        assert_eq!(KeyCard::from_value(value), Err(CoreError::BadSignature));

        // Swap in another identity's signing key -> ID no longer fits
        let other = Identity::generate(&mut OsRng);
        let mut value = card.to_value();
        value["sign"] = json!(b64(&other.sign_public()));
        assert_eq!(KeyCard::from_value(value), Err(CoreError::BadSignature));

        // Unknown role, wrong version
        let mut value = card.to_value();
        value["role"] = json!("god");
        assert!(KeyCard::from_value(value).is_err());
        let mut value = card.to_value();
        value["v"] = json!(3);
        assert!(KeyCard::from_value(value).is_err());
        Ok(())
    }

    #[test]
    fn urls_and_tls_are_signed_and_checked() -> CoreResult<()> {
        let node = Identity::generate(&mut OsRng);
        let urls = vec!["https://pc.tail91b057.ts.net:8443/n1".to_string(), "http://192.168.1.20:7700".to_string()];
        let pin = crypto::sha256(b"certificate");
        let card = node.key_card_with(Role::Node, Some("Knoten"), &urls, Some(pin), 5)?;
        assert_eq!(card.urls(), urls.as_slice());
        assert_eq!(card.tls(), Some(&pin));
        assert_eq!(KeyCard::parse(&card.to_bytes()?)?, card);
        // Without addresses: the old builder still works and gives none.
        let plain = node.key_card(Role::Node, None, 5)?;
        assert!(plain.urls().is_empty() && plain.tls().is_none());

        // Tamper: change, add or drop an address, change the pin -> signature no longer fits.
        for change in [
            json!(["https://evil.example"]),
            json!(["https://pc.tail91b057.ts.net:8443/n1", "http://192.168.1.20:7700", "https://evil.example"]),
            json!(["https://pc.tail91b057.ts.net:8443/n1"]),
        ] {
            let mut value = card.to_value();
            value["urls"] = change;
            assert_eq!(KeyCard::from_value(value), Err(CoreError::BadSignature));
        }
        let mut value = card.to_value();
        value["tls"] = json!(b64(&crypto::sha256(b"other certificate")));
        assert_eq!(KeyCard::from_value(value), Err(CoreError::BadSignature));
        let mut value = card.to_value();
        value.as_object_mut().map(|object| object.remove("tls"));
        assert_eq!(KeyCard::from_value(value), Err(CoreError::BadSignature));

        // Bad values are refused by the builder and by the parser (before the signature).
        let long = format!("https://{}", "a".repeat(MAX_URL_CHARS));
        let five: Vec<String> = (0..5).map(|i| format!("https://n{i}.example")).collect();
        for bad in [
            vec!["ftp://x.example".to_string()],
            vec!["https://".to_string()],
            vec!["https://a b.example".to_string()],
            vec!["https://a.example/\u{7}".to_string()],
            vec!["https://ä.example".to_string()],
            vec![long],
            vec!["https://same.example".to_string(), "https://same.example".to_string()],
            five,
        ] {
            assert!(node.key_card_with(Role::Node, None, &bad, None, 0).is_err(), "{bad:?}");
            let mut value = card.to_value();
            value["urls"] = json!(bad);
            assert!(matches!(KeyCard::from_value(value), Err(CoreError::BadFormat(_))));
        }
        for bad in [json!([]), json!("https://x.example"), json!([1])] {
            let mut value = card.to_value();
            value["urls"] = bad;
            assert!(matches!(KeyCard::from_value(value), Err(CoreError::BadFormat(_))));
        }
        for bad in [json!(b64(&[1u8; 31])), json!(b64(&[1u8; 33])), json!(7), json!("not base64!")] {
            let mut value = card.to_value();
            value["tls"] = bad;
            assert!(KeyCard::from_value(value).is_err());
        }
        // Only node cards carry addresses or pins.
        assert!(node.key_card_with(Role::Client, None, &urls, None, 0).is_err());
        assert!(node.key_card_with(Role::Admin, None, &[], Some(pin), 0).is_err());
        Ok(())
    }

    #[test]
    fn debug_never_shows_secrets() {
        let identity = Identity::from_secret_bytes(&[9u8; 32], &[8u8; 32]);
        let text = format!("{identity:?}");
        assert!(text.starts_with("Identity(") && !text.contains("09"));
    }
}
