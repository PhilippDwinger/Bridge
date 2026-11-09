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

    /// Creates the self-signed key card of this identity.
    pub fn key_card(&self, role: Role, name: Option<&str>, iat_ms: i64) -> CoreResult<KeyCard> {
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
        let signature = b64_fixed::<64>(field_str(&raw, "sig")?, "sig")?;
        if Id::of_sign_key(&sign) != id {
            return Err(CoreError::BadSignature);
        }
        crypto::verify(&sign, "key", &canonical_without(&raw, &["sig"])?, &signature)?;
        Ok(Self { raw, id, sign, receive, role, iat })
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
    fn debug_never_shows_secrets() {
        let identity = Identity::from_secret_bytes(&[9u8; 32], &[8u8; 32]);
        let text = format!("{identity:?}");
        assert!(text.starts_with("Identity(") && !text.contains("09"));
    }
}
