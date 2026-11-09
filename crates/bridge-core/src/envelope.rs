//! Envelopes (docs/04 §4): signed by the sender, encrypted for exactly one recipient.
//! Nodes on the way can check form, time and signature - but never read the content (Z1).
//!
//! Nonce invariant N1 (ADR 0008): the pair (key, nonce) never repeats. `seal` creates the one-time X25519 key and
//! the random nonce itself - the API has no way to pass in a key or a nonce.

use rand_core::{CryptoRng, RngCore};
use serde_json::{Map, Value, json};

use crate::crypto::{self, SecretKey};
use crate::encoding::{b64, b64_fixed, b64_var};
use crate::error::{CoreError, CoreResult};
use crate::id::Id;
use crate::json::{canonical, canonical_without, parse_strict};
use crate::keys::{Identity, KeyCard};
use crate::{CLOCK_SKEW_MS, PROTOCOL_VERSION, field_i64, field_str};

/// Maximum size of an envelope in bytes (larger content goes as a stream).
pub const MAX_ENVELOPE_BYTES: usize = 256 * 1024;
/// Maximum plaintext of one envelope.
pub const MAX_PLAINTEXT_BYTES: usize = 180 * 1024;
/// Maximum nesting depth of an envelope (all known fields are flat; unknown fields may nest a little). Keeps room
/// for wrapping envelopes into answers without exceeding the strict parser's depth.
pub const MAX_ENVELOPE_DEPTH: usize = 8;
/// Maximum lifetime of an envelope (7 days).
pub const MAX_TTL_SECONDS: u32 = 7 * 24 * 3600;

const SIGN_DOMAIN: &str = "env";
const HKDF_INFO: &[u8] = b"bridge4/env/v1";

/// What an envelope is for (visible to nodes, needed for routing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A message.
    Msg,
    /// A request to a service.
    Req,
    /// The response to a request.
    Res,
    /// An event (topic).
    Evt,
    /// An acknowledgement.
    Ack,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Msg => "msg",
            Self::Req => "req",
            Self::Res => "res",
            Self::Evt => "evt",
            Self::Ack => "ack",
        }
    }
    fn parse(text: &str) -> CoreResult<Self> {
        Ok(match text {
            "msg" => Self::Msg,
            "req" => Self::Req,
            "res" => Self::Res,
            "evt" => Self::Evt,
            "ack" => Self::Ack,
            _ => return Err(CoreError::format("kind: unknown")),
        })
    }
}

/// Everything the sender decides about an envelope (keys and nonce are not part of it - see N1).
#[derive(Debug, Clone)]
pub struct Address<'a> {
    /// Network.
    pub net: &'a Id,
    /// Recipient (its verified key card).
    pub to: &'a KeyCard,
    /// What it is.
    pub kind: Kind,
    /// Issued at (ms).
    pub iat: i64,
    /// Lifetime (s).
    pub ttl: u32,
}

/// An envelope whose form has been checked. Signature: [`Envelope::verify`]. Content: [`Envelope::open`].
#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
    raw: Map<String, Value>,
    id: [u8; 16],
    net: Id,
    from: Id,
    to: Id,
    kind: Kind,
    iat: i64,
    ttl: u32,
    epk: [u8; 32],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    signature: [u8; 64],
}

impl Envelope {
    /// Encrypts `plaintext` for `address.to` and signs it as `sender`.
    pub fn seal<R: RngCore + CryptoRng>(
        sender: &Identity,
        address: &Address<'_>,
        plaintext: &[u8],
        rng: &mut R,
    ) -> CoreResult<Self> {
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(CoreError::TooLarge("plaintext".into()));
        }
        if address.ttl == 0 || address.ttl > MAX_TTL_SECONDS || address.iat < 0 {
            return Err(CoreError::format("ttl/iat out of range"));
        }
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);
        let (epk, shared) = crypto::agree_one_time(address.to.receive_public(), rng)?;
        let key = derive_key(&shared, &epk, address.to.receive_public(), &id)?;

        let mut raw = Map::new();
        raw.insert("v".into(), json!(PROTOCOL_VERSION));
        raw.insert("t".into(), json!("env"));
        raw.insert("id".into(), json!(b64(&id)));
        raw.insert("net".into(), json!(address.net.as_str()));
        raw.insert("from".into(), json!(sender.id().as_str()));
        raw.insert("to".into(), json!(address.to.id().as_str()));
        raw.insert("iat".into(), json!(address.iat));
        raw.insert("ttl".into(), json!(address.ttl));
        raw.insert("kind".into(), json!(address.kind.as_str()));
        raw.insert("epk".into(), json!(b64(&epk)));
        raw.insert("n".into(), json!(b64(&nonce)));
        let aad = canonical(&Value::Object(raw.clone()))?;
        let ciphertext = crypto::aead_seal(&key, &nonce, plaintext, &aad)?;
        raw.insert("ct".into(), json!(b64(&ciphertext)));
        let signature = sender.sign_canonical(SIGN_DOMAIN, &canonical(&Value::Object(raw.clone()))?);
        raw.insert("sig".into(), json!(b64(&signature)));
        Self::from_value(Value::Object(raw))
    }

    /// Parses bytes (size first) and checks the form. Cheap - no signature, no decryption.
    pub fn parse(bytes: &[u8]) -> CoreResult<Self> {
        Self::from_value(parse_strict(bytes, MAX_ENVELOPE_BYTES)?)
    }

    /// Checks the form of an envelope given as JSON value.
    pub fn from_value(value: Value) -> CoreResult<Self> {
        if crate::json::depth(&value) > MAX_ENVELOPE_DEPTH {
            return Err(CoreError::format("envelope: nested too deep"));
        }
        let Value::Object(raw) = value else {
            return Err(CoreError::format("envelope: not an object"));
        };
        if field_i64(&raw, "v")? != PROTOCOL_VERSION || field_str(&raw, "t")? != "env" {
            return Err(CoreError::format("envelope: wrong version or type"));
        }
        let iat = field_i64(&raw, "iat")?;
        let ttl = u32::try_from(field_i64(&raw, "ttl")?).map_err(|_| CoreError::format("ttl: out of range"))?;
        if iat < 0 || ttl == 0 || ttl > MAX_TTL_SECONDS {
            return Err(CoreError::format("iat/ttl out of range"));
        }
        let ciphertext = b64_var(field_str(&raw, "ct")?, "ct", MAX_PLAINTEXT_BYTES + 16)?;
        if ciphertext.len() < 16 {
            return Err(CoreError::format("ct: too short"));
        }
        Ok(Self {
            id: b64_fixed::<16>(field_str(&raw, "id")?, "id")?,
            net: Id::parse(field_str(&raw, "net")?)?,
            from: Id::parse(field_str(&raw, "from")?)?,
            to: Id::parse(field_str(&raw, "to")?)?,
            kind: Kind::parse(field_str(&raw, "kind")?)?,
            iat,
            ttl,
            epk: b64_fixed::<32>(field_str(&raw, "epk")?, "epk")?,
            nonce: b64_fixed::<12>(field_str(&raw, "n")?, "n")?,
            ciphertext,
            signature: b64_fixed::<64>(field_str(&raw, "sig")?, "sig")?,
            raw,
        })
    }

    /// Time check against `now_ms`: not issued too far in the future, not expired.
    pub fn check_time(&self, now_ms: i64) -> CoreResult<()> {
        if self.iat > now_ms + CLOCK_SKEW_MS {
            return Err(CoreError::NotYetValid);
        }
        if now_ms >= self.expires_at() {
            return Err(CoreError::Expired);
        }
        Ok(())
    }

    /// Verifies that `sender` (its verified key card) signed exactly this envelope.
    pub fn verify(&self, sender: &KeyCard) -> CoreResult<()> {
        if sender.id() != &self.from {
            return Err(CoreError::BadSignature);
        }
        crypto::verify(sender.sign_public(), SIGN_DOMAIN, &canonical_without(&self.raw, &["sig"])?, &self.signature)
    }

    /// Verifies the sender's signature and decrypts. Only the recipient can do this.
    pub fn open(&self, recipient: &Identity, sender: &KeyCard) -> CoreResult<Vec<u8>> {
        self.verify(sender)?;
        if recipient.id() != &self.to {
            return Err(CoreError::CannotOpen);
        }
        let shared = crypto::agree_static(recipient.receiving_secret(), &self.epk)?;
        let key = derive_key(&shared, &self.epk, &recipient.receive_public(), &self.id)?;
        let aad = canonical_without(&self.raw, &["ct", "sig"])?;
        crypto::aead_open(&key, &self.nonce, &self.ciphertext, &aad)
    }

    /// Envelope ID (for replay protection: a node/recipient remembers seen IDs until `expires_at`).
    #[must_use]
    pub fn id(&self) -> &[u8; 16] {
        &self.id
    }
    /// Network.
    #[must_use]
    pub fn net(&self) -> &Id {
        &self.net
    }
    /// Sender (claimed until `verify`).
    #[must_use]
    pub fn from(&self) -> &Id {
        &self.from
    }
    /// Recipient.
    #[must_use]
    pub fn to(&self) -> &Id {
        &self.to
    }
    /// Kind.
    #[must_use]
    pub fn kind(&self) -> Kind {
        self.kind
    }
    /// End of life (ms).
    #[must_use]
    pub fn expires_at(&self) -> i64 {
        self.iat.saturating_add(i64::from(self.ttl) * 1000)
    }
    /// The one-time public key (for N1 tests and diagnostics).
    #[must_use]
    pub fn ephemeral_public(&self) -> &[u8; 32] {
        &self.epk
    }
    /// The nonce (for N1 tests and diagnostics).
    #[must_use]
    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }
    /// Size of the encrypted content.
    #[must_use]
    pub fn ciphertext_len(&self) -> usize {
        self.ciphertext.len()
    }
    /// The envelope as JSON value (exactly as signed) - for tests and diagnostics.
    #[must_use]
    pub fn to_value_for_tests(&self) -> Value {
        Value::Object(self.raw.clone())
    }
    /// Canonical JSON bytes (what travels).
    pub fn to_bytes(&self) -> CoreResult<Vec<u8>> {
        canonical(&Value::Object(self.raw.clone()))
    }
}

fn derive_key(shared: &[u8; 32], epk: &[u8; 32], recipient: &[u8; 32], id: &[u8; 16]) -> CoreResult<SecretKey> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(epk);
    salt[32..].copy_from_slice(recipient);
    let mut info = Vec::with_capacity(HKDF_INFO.len() + 16);
    info.extend_from_slice(HKDF_INFO);
    info.extend_from_slice(id);
    crypto::derive_key(shared, &salt, &info)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use rand_core::OsRng;

    use super::*;
    use crate::keys::Role;

    fn party() -> CoreResult<(Identity, KeyCard)> {
        let identity = Identity::generate(&mut OsRng);
        let card = identity.key_card(Role::Client, None, 0)?;
        Ok((identity, card))
    }

    #[test]
    fn nonce_invariant_n1_no_repeats() -> CoreResult<()> {
        let (alice, _) = party()?;
        let (_bob, bob_card) = party()?;
        let net = alice.id().clone();
        let address = Address { net: &net, to: &bob_card, kind: Kind::Msg, iat: 1, ttl: 60 };
        let mut keys = HashSet::new();
        let mut nonces = HashSet::new();
        let mut ciphertexts = HashSet::new();
        for _ in 0..5_000 {
            let envelope = Envelope::seal(&alice, &address, b"same plaintext", &mut OsRng)?;
            assert!(keys.insert(*envelope.ephemeral_public()), "one-time key repeated");
            assert!(nonces.insert(*envelope.nonce()), "nonce repeated");
            assert!(ciphertexts.insert(envelope.to_bytes()?), "same plaintext must give different ciphertext");
        }
        Ok(())
    }

    #[test]
    fn low_order_one_time_key_is_rejected() -> CoreResult<()> {
        // A malicious sender (it signs correctly) uses an all-zero one-time key: the shared secret would be zero.
        let (mallory, mallory_card) = party()?;
        let (bob, bob_card) = party()?;
        let net = mallory.id().clone();
        let address = Address { net: &net, to: &bob_card, kind: Kind::Msg, iat: 1, ttl: 60 };
        let envelope = Envelope::seal(&mallory, &address, b"x", &mut OsRng)?;
        let mut raw = envelope.raw.clone();
        raw.insert("epk".into(), json!(b64(&[0u8; 32])));
        raw.remove("sig");
        let signature = mallory.sign_canonical(SIGN_DOMAIN, &canonical(&Value::Object(raw.clone()))?);
        raw.insert("sig".into(), json!(b64(&signature)));
        let forged = Envelope::from_value(Value::Object(raw))?;
        assert_eq!(forged.verify(&mallory_card), Ok(()), "signature is valid ...");
        assert_eq!(
            forged.open(&bob, &mallory_card),
            Err(CoreError::CannotOpen),
            "... but a zero shared secret is refused"
        );
        Ok(())
    }
}
