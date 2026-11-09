//! Signed statements ("Aussagen", docs/04 §3): manifest, delegation, member, seal, revoke, ban, name, log, pow …
//! Public, readable by everyone, trusted only after verification. One signer (`iss` + `sig`) or several (`sigs`).
//! The signature domain is the kind itself (`bridge4/<t>`, docs/04 §1); kinds of other objects are reserved.

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

use crate::encoding::{b64, b64_fixed};
use crate::error::{CoreError, CoreResult};
use crate::id::Id;
use crate::json::{canonical_without, parse_strict};
use crate::keys::{Identity, KeyCard};
use crate::{CLOCK_SKEW_MS, PROTOCOL_VERSION, field_i64, field_str};

/// Maximum size of a statement in bytes.
pub const MAX_STATEMENT_BYTES: usize = 64 * 1024;
/// Maximum number of signers of one statement.
pub const MAX_SIGNERS: usize = 16;
/// Maximum lifetime of a statement (2 years).
pub const MAX_STATEMENT_LIFETIME_MS: i64 = 2 * 366 * 24 * 3600 * 1000;

/// Object types that are not statements (they have their own format and signature domain).
const RESERVED_TYPES: [&str; 5] = ["env", "key", "rq", "pow", "part"];

/// What every statement says, before signing.
#[derive(Debug, Clone)]
pub struct Draft<'a> {
    /// Kind (`t`), e.g. "seal".
    pub kind: &'a str,
    /// Network the statement belongs to.
    pub net: &'a Id,
    /// Issued at (ms).
    pub iat: i64,
    /// Expires (ms).
    pub exp: i64,
    /// Content (an object).
    pub body: Value,
}

/// A statement whose form has been checked. Signatures are checked with [`Statement::verify`].
#[derive(Debug, Clone, PartialEq)]
pub struct Statement {
    raw: Map<String, Value>,
    kind: String,
    net: Id,
    iat: i64,
    exp: i64,
    signers: Vec<(Id, [u8; 64])>,
}

impl Statement {
    /// Signs a draft by one identity (`iss` + `sig`).
    pub fn sign(draft: &Draft<'_>, signer: &Identity) -> CoreResult<Self> {
        let mut raw = base_object(draft)?;
        raw.insert("iss".into(), json!(signer.id().as_str()));
        let signature = signer.sign_canonical(draft.kind, &canonical_without(&raw, &["sig"])?);
        raw.insert("sig".into(), json!(b64(&signature)));
        Self::from_value(Value::Object(raw))
    }

    /// Signs a draft by several identities (`sigs`) - for "k of n admins" actions.
    pub fn sign_multi(draft: &Draft<'_>, signers: &[&Identity]) -> CoreResult<Self> {
        if signers.is_empty() || signers.len() > MAX_SIGNERS {
            return Err(CoreError::format("sigs: 1..=16 signers"));
        }
        let raw = base_object(draft)?;
        let bytes = canonical_without(&raw, &["sigs"])?;
        let sigs: Vec<Value> = signers
            .iter()
            .map(|s| json!({"iss": s.id().as_str(), "sig": b64(&s.sign_canonical(draft.kind, &bytes))}))
            .collect();
        let mut raw = raw;
        raw.insert("sigs".into(), Value::Array(sigs));
        Self::from_value(Value::Object(raw))
    }

    /// Parses bytes and checks the form (not the signatures).
    pub fn parse(bytes: &[u8]) -> CoreResult<Self> {
        Self::from_value(parse_strict(bytes, MAX_STATEMENT_BYTES)?)
    }

    /// Checks the form of a statement given as JSON value (not the signatures).
    pub fn from_value(value: Value) -> CoreResult<Self> {
        let Value::Object(raw) = value else {
            return Err(CoreError::format("statement: not an object"));
        };
        if field_i64(&raw, "v")? != PROTOCOL_VERSION {
            return Err(CoreError::format("statement: wrong version"));
        }
        let kind = field_str(&raw, "t")?.to_owned();
        if kind.is_empty()
            || kind.len() > 16
            || !kind.bytes().all(|b| b.is_ascii_lowercase())
            || RESERVED_TYPES.contains(&kind.as_str())
        {
            return Err(CoreError::format("statement: bad kind"));
        }
        let net = Id::parse(field_str(&raw, "net")?)?;
        let iat = field_i64(&raw, "iat")?;
        let exp = field_i64(&raw, "exp")?;
        if iat < 0 || exp <= iat || exp - iat > MAX_STATEMENT_LIFETIME_MS {
            return Err(CoreError::format("statement: bad iat/exp"));
        }
        if !raw.get("body").is_some_and(Value::is_object) {
            return Err(CoreError::format("statement: body must be an object"));
        }
        let signers = match (raw.get("sig"), raw.get("sigs")) {
            (Some(_), None) => {
                let issuer = Id::parse(field_str(&raw, "iss")?)?;
                vec![(issuer, b64_fixed::<64>(field_str(&raw, "sig")?, "sig")?)]
            }
            (None, Some(Value::Array(list))) if !list.is_empty() && list.len() <= MAX_SIGNERS => {
                if raw.contains_key("iss") {
                    return Err(CoreError::format("statement: iss together with sigs"));
                }
                let mut seen = BTreeSet::new();
                let mut signers = Vec::with_capacity(list.len());
                for entry in list {
                    let Value::Object(entry) = entry else {
                        return Err(CoreError::format("sigs: entries must be objects"));
                    };
                    let issuer = Id::parse(field_str(entry, "iss")?)?;
                    if !seen.insert(issuer.clone()) {
                        return Err(CoreError::format("sigs: same signer twice"));
                    }
                    signers.push((issuer, b64_fixed::<64>(field_str(entry, "sig")?, "sig")?));
                }
                signers
            }
            _ => return Err(CoreError::format("statement: needs either sig or sigs (1..=16)")),
        };
        Ok(Self { raw, kind, net, iat, exp, signers })
    }

    /// Verifies the signatures. `cards` are the key cards of the possible signers (already verified, e.g. from the
    /// network's delegations). Returns the IDs of all signers whose signature is valid; fails if fewer than
    /// `threshold` are valid or any listed signature is invalid.
    pub fn verify(&self, cards: &[&KeyCard], threshold: usize) -> CoreResult<Vec<Id>> {
        let skip = if self.raw.contains_key("sigs") { "sigs" } else { "sig" };
        let bytes = canonical_without(&self.raw, &[skip])?;
        let mut valid = Vec::new();
        for (issuer, signature) in &self.signers {
            let card = cards.iter().find(|c| c.id() == issuer).ok_or(CoreError::BadSignature)?;
            crate::crypto::verify(card.sign_public(), &self.kind, &bytes, signature)?;
            valid.push(issuer.clone());
        }
        if threshold == 0 || valid.len() < threshold {
            return Err(CoreError::BadSignature);
        }
        Ok(valid)
    }

    /// Checks the validity window against `now_ms` (with clock-skew tolerance for `iat`).
    pub fn check_time(&self, now_ms: i64) -> CoreResult<()> {
        if self.iat > now_ms + CLOCK_SKEW_MS {
            return Err(CoreError::NotYetValid);
        }
        if now_ms >= self.exp {
            return Err(CoreError::Expired);
        }
        Ok(())
    }

    /// Kind (`t`).
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }
    /// Network.
    #[must_use]
    pub fn net(&self) -> &Id {
        &self.net
    }
    /// Signer IDs (as claimed - only trusted after `verify`).
    #[must_use]
    pub fn claimed_signers(&self) -> Vec<&Id> {
        self.signers.iter().map(|(id, _)| id).collect()
    }
    /// Content.
    #[must_use]
    pub fn body(&self) -> &Value {
        self.raw.get("body").unwrap_or(&Value::Null)
    }
    /// Issued at / expires (ms).
    #[must_use]
    pub fn times(&self) -> (i64, i64) {
        (self.iat, self.exp)
    }
    /// The statement as JSON value (exactly as signed).
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Object(self.raw.clone())
    }
}

fn base_object(draft: &Draft<'_>) -> CoreResult<Map<String, Value>> {
    if !draft.body.is_object() {
        return Err(CoreError::format("body must be an object"));
    }
    let mut raw = Map::new();
    raw.insert("v".into(), json!(PROTOCOL_VERSION));
    raw.insert("t".into(), json!(draft.kind));
    raw.insert("net".into(), json!(draft.net.as_str()));
    raw.insert("iat".into(), json!(draft.iat));
    raw.insert("exp".into(), json!(draft.exp));
    raw.insert("body".into(), draft.body.clone());
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;
    use crate::keys::Role;

    fn setup() -> CoreResult<(Identity, KeyCard, Id)> {
        let admin = Identity::generate(&mut OsRng);
        let card = admin.key_card(Role::Admin, None, 0)?;
        let net = Identity::generate(&mut OsRng).id().clone();
        Ok((admin, card, net))
    }

    #[test]
    fn single_signature() -> CoreResult<()> {
        let (admin, card, net) = setup()?;
        let draft = Draft { kind: "seal", net: &net, iat: 1_000, exp: 100_000, body: json!({"node": "x", "level": 2}) };
        let statement = Statement::sign(&draft, &admin)?;
        assert_eq!(statement.verify(&[&card], 1)?, vec![admin.id().clone()]);
        let reparsed = Statement::parse(&crate::json::canonical(&statement.to_value())?)?;
        assert_eq!(reparsed.verify(&[&card], 1)?.len(), 1);

        // Tamper with the body
        let mut value = statement.to_value();
        value["body"]["level"] = json!(3);
        assert_eq!(Statement::from_value(value)?.verify(&[&card], 1), Err(CoreError::BadSignature));
        // A signature of another kind of object can not be reused (domain separation): sign as key card domain
        let mut value = statement.to_value();
        value["t"] = json!("ban");
        assert_eq!(Statement::from_value(value)?.verify(&[&card], 1), Err(CoreError::BadSignature));
        // Unknown signer
        let stranger = Identity::generate(&mut OsRng).key_card(Role::Admin, None, 0)?;
        assert_eq!(statement.verify(&[&stranger], 1), Err(CoreError::BadSignature));
        Ok(())
    }

    #[test]
    fn multi_signature_threshold() -> CoreResult<()> {
        let (a, card_a, net) = setup()?;
        let b = Identity::generate(&mut OsRng);
        let card_b = b.key_card(Role::Admin, None, 0)?;
        let draft = Draft { kind: "delegation", net: &net, iat: 0, exp: 10, body: json!({}) };
        let statement = Statement::sign_multi(&draft, &[&a, &b])?;
        assert_eq!(statement.verify(&[&card_a, &card_b], 2)?.len(), 2);
        assert_eq!(statement.verify(&[&card_a, &card_b], 3), Err(CoreError::BadSignature), "threshold not reached");
        // The same signer twice does not count twice
        let one = Statement::sign_multi(&draft, &[&a])?;
        let mut value = one.to_value();
        let entry = value["sigs"][0].clone();
        value["sigs"] = json!([entry.clone(), entry]);
        assert!(Statement::from_value(value).is_err());
        Ok(())
    }

    #[test]
    fn form_and_time_checks() -> CoreResult<()> {
        let (admin, _card, net) = setup()?;
        let draft = Draft { kind: "seal", net: &net, iat: 10_000, exp: 20_000, body: json!({}) };
        let statement = Statement::sign(&draft, &admin)?;
        assert_eq!(statement.check_time(15_000), Ok(()));
        assert_eq!(statement.check_time(20_000), Err(CoreError::Expired));
        assert_eq!(statement.check_time(10_000 - CLOCK_SKEW_MS - 1), Err(CoreError::NotYetValid));
        for bad in [json!("x"), json!([])] {
            let draft = Draft { kind: "seal", net: &net, iat: 0, exp: 1, body: bad };
            assert!(Statement::sign(&draft, &admin).is_err());
        }
        let draft = Draft { kind: "Seal!", net: &net, iat: 0, exp: 1, body: json!({}) };
        assert!(Statement::sign(&draft, &admin).is_err());
        let draft = Draft { kind: "seal", net: &net, iat: 5, exp: 5, body: json!({}) };
        assert!(Statement::sign(&draft, &admin).is_err(), "exp must be after iat");
        Ok(())
    }
}
