//! Signed requests (`rq`, docs/04 §7): everything that changes something at a node is signed by the caller.
//! A request is bound to one node (`aud`), valid only for a short time around `iat`, and carries a random nonce `n`
//! so the node can refuse a second use (replay).

use rand_core::{CryptoRng, RngCore};
use serde_json::{Map, Value, json};

use crate::crypto;
use crate::encoding::{b64, b64_fixed};
use crate::error::{CoreError, CoreResult};
use crate::id::Id;
use crate::json::{canonical, canonical_without, parse_strict};
use crate::keys::{Identity, KeyCard};
use crate::{CLOCK_SKEW_MS, PROTOCOL_VERSION, field_i64, field_str};

/// Maximum size of a signed request in bytes.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Maximum length of an operation name.
pub const MAX_OP_CHARS: usize = 24;

const DOMAIN: &str = "rq";

/// A request whose form has been checked. Check [`SignedRequest::check`] (node + time) and
/// [`SignedRequest::verify`] (signature) before acting on it.
#[derive(Debug, Clone, PartialEq)]
pub struct SignedRequest {
    raw: Map<String, Value>,
    aud: Id,
    iss: Id,
    iat: i64,
    nonce: [u8; 16],
    op: String,
    signature: [u8; 64],
}

impl SignedRequest {
    /// Signs an operation `op` with `body` (an object) for the node `aud`.
    pub fn sign<R: RngCore + CryptoRng>(
        signer: &Identity,
        aud: &Id,
        op: &str,
        body: Value,
        iat_ms: i64,
        rng: &mut R,
    ) -> CoreResult<Self> {
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);
        let mut raw = Map::new();
        raw.insert("v".into(), json!(PROTOCOL_VERSION));
        raw.insert("t".into(), json!("rq"));
        raw.insert("aud".into(), json!(aud.as_str()));
        raw.insert("iss".into(), json!(signer.id().as_str()));
        raw.insert("iat".into(), json!(iat_ms));
        raw.insert("n".into(), json!(b64(&nonce)));
        raw.insert("op".into(), json!(op));
        raw.insert("body".into(), body);
        let signature = signer.sign_canonical(DOMAIN, &canonical(&Value::Object(raw.clone()))?);
        raw.insert("sig".into(), json!(b64(&signature)));
        let request = Self::from_value(Value::Object(raw))?;
        if canonical(&request.to_value())?.len() > MAX_REQUEST_BYTES {
            return Err(CoreError::TooLarge("request".into()));
        }
        Ok(request)
    }

    /// Parses bytes (size first) and checks the form.
    pub fn parse(bytes: &[u8]) -> CoreResult<Self> {
        Self::from_value(parse_strict(bytes, MAX_REQUEST_BYTES)?)
    }

    /// Checks the form of a request given as JSON value.
    pub fn from_value(value: Value) -> CoreResult<Self> {
        let Value::Object(raw) = value else {
            return Err(CoreError::format("request: not an object"));
        };
        if field_i64(&raw, "v")? != PROTOCOL_VERSION || field_str(&raw, "t")? != "rq" {
            return Err(CoreError::format("request: wrong version or type"));
        }
        let op = field_str(&raw, "op")?;
        if op.is_empty() || op.len() > MAX_OP_CHARS || !op.bytes().all(|b| b.is_ascii_lowercase() || b == b'-') {
            return Err(CoreError::format("op: bad name"));
        }
        if !raw.get("body").is_some_and(Value::is_object) {
            return Err(CoreError::format("body: not an object"));
        }
        let iat = field_i64(&raw, "iat")?;
        if iat < 0 {
            return Err(CoreError::format("iat: negative"));
        }
        Ok(Self {
            aud: Id::parse(field_str(&raw, "aud")?)?,
            iss: Id::parse(field_str(&raw, "iss")?)?,
            iat,
            nonce: b64_fixed::<16>(field_str(&raw, "n")?, "n")?,
            op: op.to_owned(),
            signature: b64_fixed::<64>(field_str(&raw, "sig")?, "sig")?,
            raw,
        })
    }

    /// Cheap checks: meant for this node and inside the time window (±5 minutes around `iat`).
    pub fn check(&self, node: &Id, now_ms: i64) -> CoreResult<()> {
        if &self.aud != node {
            return Err(CoreError::BadSignature); // a request for another node is never valid here
        }
        if self.iat > now_ms.saturating_add(CLOCK_SKEW_MS) {
            return Err(CoreError::NotYetValid);
        }
        if now_ms.saturating_sub(self.iat) > CLOCK_SKEW_MS {
            return Err(CoreError::Expired);
        }
        Ok(())
    }

    /// Verifies the signature with the caller's (verified) key card.
    pub fn verify(&self, card: &KeyCard) -> CoreResult<()> {
        if card.id() != &self.iss {
            return Err(CoreError::BadSignature);
        }
        crypto::verify(card.sign_public(), DOMAIN, &canonical_without(&self.raw, &["sig"])?, &self.signature)
    }

    /// The node this request is for.
    #[must_use]
    pub fn aud(&self) -> &Id {
        &self.aud
    }
    /// The caller (claimed until `verify`).
    #[must_use]
    pub fn iss(&self) -> &Id {
        &self.iss
    }
    /// Issued at (ms).
    #[must_use]
    pub fn iat(&self) -> i64 {
        self.iat
    }
    /// Random nonce (replay protection: a node remembers `(iss, n)` for the time window).
    #[must_use]
    pub fn nonce(&self) -> &[u8; 16] {
        &self.nonce
    }
    /// The operation.
    #[must_use]
    pub fn op(&self) -> &str {
        &self.op
    }
    /// The body (always an object).
    #[must_use]
    pub fn body(&self) -> &Value {
        self.raw.get("body").unwrap_or(&Value::Null)
    }
    /// The request as JSON value (exactly as signed).
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Object(self.raw.clone())
    }
    /// Canonical bytes (what travels).
    pub fn to_bytes(&self) -> CoreResult<Vec<u8>> {
        canonical(&self.to_value())
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;
    use crate::keys::Role;

    #[test]
    fn sign_check_verify_and_tamper() -> CoreResult<()> {
        let alice = Identity::generate(&mut OsRng);
        let card = alice.key_card(Role::Client, None, 0)?;
        let node = Identity::generate(&mut OsRng);
        let other_node = Identity::generate(&mut OsRng);
        let request = SignedRequest::sign(&alice, node.id(), "ack", json!({"ids": []}), 1_000_000, &mut OsRng)?;
        let parsed = SignedRequest::parse(&request.to_bytes()?)?;
        parsed.check(node.id(), 1_000_000)?;
        parsed.verify(&card)?;
        assert_eq!(parsed.op(), "ack");

        assert_eq!(parsed.check(other_node.id(), 1_000_000), Err(CoreError::BadSignature), "other node");
        assert_eq!(parsed.check(node.id(), 1_000_000 + CLOCK_SKEW_MS + 1), Err(CoreError::Expired));
        assert_eq!(parsed.check(node.id(), 1_000_000 - CLOCK_SKEW_MS - 1), Err(CoreError::NotYetValid));

        for (field, value) in [
            ("op", json!("send")),
            ("body", json!({"ids": ["x"]})),
            ("aud", json!(other_node.id().as_str())),
            ("iat", json!(1_000_001)),
            ("n", json!(b64(&[0u8; 16]))),
        ] {
            let mut changed = request.to_value();
            changed[field] = value;
            let changed = SignedRequest::from_value(changed)?;
            assert_eq!(changed.verify(&card), Err(CoreError::BadSignature), "{field}");
        }
        let mallory = Identity::generate(&mut OsRng).key_card(Role::Client, None, 0)?;
        assert_eq!(parsed.verify(&mallory), Err(CoreError::BadSignature), "card of someone else");
        Ok(())
    }

    #[test]
    fn form_is_strict() -> CoreResult<()> {
        let alice = Identity::generate(&mut OsRng);
        let node = Identity::generate(&mut OsRng);
        assert!(SignedRequest::sign(&alice, node.id(), "Bad Op", json!({}), 0, &mut OsRng).is_err());
        assert!(SignedRequest::sign(&alice, node.id(), "ack", json!([1]), 0, &mut OsRng).is_err());
        let big = "x".repeat(MAX_REQUEST_BYTES);
        assert!(matches!(
            SignedRequest::sign(&alice, node.id(), "ack", json!({"big": big}), 0, &mut OsRng),
            Err(CoreError::TooLarge(_))
        ));
        assert!(matches!(SignedRequest::parse(&vec![b' '; MAX_REQUEST_BYTES + 1]), Err(CoreError::TooLarge(_))));
        Ok(())
    }
}
