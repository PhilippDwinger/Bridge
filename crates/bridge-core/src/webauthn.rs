//! WebAuthn (passkeys) for Bridge Login (docs/11 §9, ADR 0027) - only what a relying party checks, no attestation:
//!
//! - **Credential**: its ID (1-255 bytes), algorithm (ES256 = COSE -7, EdDSA = COSE -8) and public key as SPKI DER
//!   (as `AuthenticatorAttestationResponse.getPublicKey()` gives it) - checked to be a usable key.
//! - **Client data**: `type` (`webauthn.create` / `webauthn.get`), `challenge` (exactly the one handed out) and
//!   `origin` (exactly the node's own) - at most 4 KiB.
//! - **Authenticator data**: the RP ID hash (SHA-256 of the node's host), the flag "user present"; the signature
//!   counter (37 bytes at least, at most 1 KiB).
//! - **Assertion**: the signature over `authenticatorData ‖ SHA-256(clientDataJSON)` with the credential's key.

use serde_json::Value;

use crate::crypto::{ed25519_spki_key, es256_key_ok, sha256, verify_ed25519_spki, verify_es256};
use crate::encoding::b64;
use crate::error::{CoreError, CoreResult};

/// Longest credential ID (WebAuthn: at most 1023 - authenticators use far less).
pub const MAX_CREDENTIAL_ID: usize = 255;
/// Longest SPKI DER of a public key.
pub const MAX_SPKI: usize = 256;
/// Longest client data JSON.
pub const MAX_CLIENT_DATA: usize = 4096;
/// Longest authenticator data.
pub const MAX_AUTH_DATA: usize = 1024;
/// Longest signature (ES256 DER: at most 72 bytes).
pub const MAX_SIGNATURE: usize = 128;
/// Flag "user present".
pub const FLAG_UP: u8 = 0x01;
/// Flag "user verified".
pub const FLAG_UV: u8 = 0x04;

/// A passkey algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    /// ECDSA P-256 with SHA-256 (COSE -7) - nearly every device.
    Es256,
    /// Ed25519 (COSE -8).
    EdDsa,
}

impl Alg {
    /// The COSE algorithm number.
    #[must_use]
    pub fn cose(self) -> i64 {
        match self {
            Self::Es256 => -7,
            Self::EdDsa => -8,
        }
    }

    /// The algorithm for a COSE number (only the two above).
    #[must_use]
    pub fn from_cose(number: i64) -> Option<Self> {
        match number {
            -7 => Some(Self::Es256),
            -8 => Some(Self::EdDsa),
            _ => None,
        }
    }
}

/// A passkey's public part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// The credential ID (as the authenticator chose it).
    pub id: Vec<u8>,
    /// Its algorithm.
    pub alg: Alg,
    /// Its public key (SPKI DER).
    pub key: Vec<u8>,
}

impl Credential {
    /// A checked credential: ID 1-255 bytes, known algorithm, a usable key of that algorithm.
    pub fn new(id: Vec<u8>, cose: i64, key: Vec<u8>) -> CoreResult<Self> {
        if id.is_empty() || id.len() > MAX_CREDENTIAL_ID {
            return Err(CoreError::format("credential: id 1-255 bytes"));
        }
        let alg = Alg::from_cose(cose).ok_or_else(|| CoreError::format("credential: only ES256 (-7) or EdDSA (-8)"))?;
        let usable = key.len() <= MAX_SPKI
            && match alg {
                Alg::Es256 => es256_key_ok(&key),
                Alg::EdDsa => ed25519_spki_key(&key).is_some(),
            };
        if !usable {
            return Err(CoreError::format("credential: not a usable public key"));
        }
        Ok(Self { id, alg, key })
    }

    /// Verifies an assertion of this passkey: the signature over `auth_data ‖ SHA-256(client_data)`.
    pub fn verify_assertion(&self, auth_data: &[u8], client_data: &[u8], signature: &[u8]) -> CoreResult<()> {
        if signature.len() > MAX_SIGNATURE || auth_data.len() > MAX_AUTH_DATA || client_data.len() > MAX_CLIENT_DATA {
            return Err(CoreError::BadSignature);
        }
        let mut message = Vec::with_capacity(auth_data.len() + 32);
        message.extend_from_slice(auth_data);
        message.extend_from_slice(&sha256(client_data));
        match self.alg {
            Alg::Es256 => verify_es256(&self.key, &message, signature),
            Alg::EdDsa => verify_ed25519_spki(&self.key, &message, signature),
        }
    }
}

/// Checks client data JSON: its `type`, `challenge` (Base64url without padding of exactly `challenge`) and `origin`.
pub fn check_client_data(bytes: &[u8], kind: &str, challenge: &[u8], origin: &str) -> CoreResult<()> {
    if bytes.len() > MAX_CLIENT_DATA {
        return Err(CoreError::TooLarge("client data".into()));
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| CoreError::format("client data: not JSON"))?;
    let field = |name: &str| value.get(name).and_then(Value::as_str);
    if field("type") != Some(kind) {
        return Err(CoreError::format("client data: wrong type"));
    }
    if field("challenge") != Some(b64(challenge).as_str()) {
        return Err(CoreError::format("client data: wrong challenge"));
    }
    if field("origin") != Some(origin) {
        return Err(CoreError::format("client data: wrong origin"));
    }
    if value.get("crossOrigin").and_then(Value::as_bool) == Some(true) {
        return Err(CoreError::format("client data: cross-origin"));
    }
    Ok(())
}

/// The fixed part of authenticator data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthData {
    /// SHA-256 of the RP ID.
    pub rp_id_hash: [u8; 32],
    /// Flags.
    pub flags: u8,
    /// The signature counter (0 if the authenticator has none).
    pub sign_count: u32,
}

/// Checks authenticator data: at least 37 bytes, at most [`MAX_AUTH_DATA`], the RP ID hash of `rp_id`, "user present".
pub fn check_auth_data(bytes: &[u8], rp_id: &str) -> CoreResult<AuthData> {
    if bytes.len() < 37 || bytes.len() > MAX_AUTH_DATA {
        return Err(CoreError::format("authenticator data: length"));
    }
    let rp_id_hash: [u8; 32] = bytes[..32].try_into().map_err(|_| CoreError::format("authenticator data"))?;
    let flags = bytes[32];
    let sign_count = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);
    if rp_id_hash != sha256(rp_id.as_bytes()) {
        return Err(CoreError::format("authenticator data: other relying party"));
    }
    if flags & FLAG_UP == 0 {
        return Err(CoreError::format("authenticator data: user not present"));
    }
    Ok(AuthData { rp_id_hash, flags, sign_count })
}

/// Checks the WebAuthn data of an **approval** - a passkey signing an account entry (docs/11 §14): client data of
/// type `webauthn.get` over exactly `challenge`, not cross-origin, authenticator data with "user present". Origin and
/// RP ID are checked by the node that took the ceremony (each entrance has its own); the signature binds the entry.
pub fn check_approval(client_data: &[u8], auth_data: &[u8], challenge: &[u8]) -> CoreResult<()> {
    if client_data.len() > MAX_CLIENT_DATA {
        return Err(CoreError::TooLarge("client data".into()));
    }
    let value: Value = serde_json::from_slice(client_data).map_err(|_| CoreError::format("client data: not JSON"))?;
    let field = |name: &str| value.get(name).and_then(Value::as_str);
    if field("type") != Some("webauthn.get") {
        return Err(CoreError::format("approval: wrong type"));
    }
    if field("challenge") != Some(b64(challenge).as_str()) {
        return Err(CoreError::format("approval: not for this entry"));
    }
    if value.get("crossOrigin").and_then(Value::as_bool) == Some(true) {
        return Err(CoreError::format("approval: cross-origin"));
    }
    if auth_data.len() < 37 || auth_data.len() > MAX_AUTH_DATA || auth_data[32] & FLAG_UP == 0 {
        return Err(CoreError::format("approval: authenticator data"));
    }
    Ok(())
}

/// The relying party of a node's public address: its host as RP ID and `scheme://host[:port]` as the only origin -
/// `https`, or `http` only for `localhost` (tests). `None` for anything else (an IP address can not be an RP ID).
#[must_use]
pub fn relying_party(url: &str) -> Option<(String, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) && !port.is_empty() => (host, Some(port)),
        _ => (authority, None),
    };
    let host = host.to_ascii_lowercase();
    let domain = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty() && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && !host.split('.').all(|label| label.bytes().all(|b| b.is_ascii_digit()));
    let allowed = match scheme {
        "https" => domain,
        "http" => host == "localhost",
        _ => false,
    };
    if !allowed {
        return None;
    }
    let origin = match port {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    };
    Some((host, origin))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relying_parties() {
        assert_eq!(
            relying_party("https://Muttchen.tail91b057.ts.net/bridge4/testnetz"),
            Some(("muttchen.tail91b057.ts.net".into(), "https://muttchen.tail91b057.ts.net".into()))
        );
        assert_eq!(
            relying_party("https://pc.ts.net:8443/bridge4/n"),
            Some(("pc.ts.net".into(), "https://pc.ts.net:8443".into()))
        );
        assert_eq!(
            relying_party("http://localhost:7390/bridge4/n"),
            Some(("localhost".into(), "http://localhost:7390".into()))
        );
        for bad in [
            "http://pc.ts.net/x",
            "https://127.0.0.1/x",
            "https://user@pc.ts.net/",
            "ftp://pc.ts.net",
            "pc.ts.net",
            "https://",
            "https://a_b.net/",
        ] {
            assert_eq!(relying_party(bad), None, "{bad}");
        }
    }

    #[test]
    fn client_and_authenticator_data() -> CoreResult<()> {
        let challenge = [7u8; 32];
        let good = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://pc.ts.net","crossOrigin":false,"other":1}}"#,
            b64(&challenge)
        );
        check_client_data(good.as_bytes(), "webauthn.get", &challenge, "https://pc.ts.net")?;
        for (bytes, kind, origin) in [
            (good.as_str(), "webauthn.create", "https://pc.ts.net"),
            (good.as_str(), "webauthn.get", "https://evil.ts.net"),
            (
                r#"{"type":"webauthn.get","challenge":"AAAA","origin":"https://pc.ts.net"}"#,
                "webauthn.get",
                "https://pc.ts.net",
            ),
            ("nicht json", "webauthn.get", "https://pc.ts.net"),
        ] {
            assert!(check_client_data(bytes.as_bytes(), kind, &challenge, origin).is_err(), "{bytes} {kind} {origin}");
        }
        let cross = good.replace("\"crossOrigin\":false", "\"crossOrigin\":true");
        assert!(check_client_data(cross.as_bytes(), "webauthn.get", &challenge, "https://pc.ts.net").is_err());
        let mut auth = sha256(b"pc.ts.net").to_vec();
        auth.extend_from_slice(&[FLAG_UP | FLAG_UV, 0, 0, 0, 9]);
        let parsed = check_auth_data(&auth, "pc.ts.net")?;
        assert_eq!((parsed.flags & FLAG_UV, parsed.sign_count), (FLAG_UV, 9));
        assert!(check_auth_data(&auth, "evil.ts.net").is_err(), "other RP");
        assert!(check_auth_data(&auth[..36], "pc.ts.net").is_err(), "short");
        let mut absent = auth.clone();
        absent[32] = 0;
        assert!(check_auth_data(&absent, "pc.ts.net").is_err(), "user not present");
        Ok(())
    }

    #[test]
    fn credentials_and_assertions() -> CoreResult<()> {
        use ed25519_dalek::Signer as _;
        let auth = b"authenticator data".to_vec();
        let client = br#"{"type":"webauthn.get"}"#.to_vec();
        let mut message = auth.clone();
        message.extend_from_slice(&sha256(&client));
        // EdDSA.
        let ed = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let mut spki = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
        spki.extend_from_slice(&ed.verifying_key().to_bytes());
        let credential = Credential::new(vec![1, 2, 3], -8, spki.clone())?;
        let signature = ed.sign(&message).to_bytes();
        credential.verify_assertion(&auth, &client, &signature)?;
        assert!(credential.verify_assertion(b"other", &client, &signature).is_err(), "other data");
        assert!(credential.verify_assertion(&auth, b"{}", &signature).is_err(), "other client data");
        assert!(Credential::new(Vec::new(), -8, spki.clone()).is_err(), "empty id");
        assert!(Credential::new(vec![1], -257, spki.clone()).is_err(), "RS256 not supported");
        assert!(Credential::new(vec![1], -7, spki.clone()).is_err(), "an Ed25519 key is no ES256 key");
        assert!(Credential::new(vec![1], -8, vec![0x30; 44]).is_err(), "garbage");
        let mut weak = spki[..12].to_vec();
        weak.extend_from_slice(&[0u8; 32]);
        assert!(Credential::new(vec![1], -8, weak).is_err(), "weak key");
        // ES256, also with the high-S twin of a signature.
        let p = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).map_err(|_| CoreError::BadSignature)?;
        let der = crate::crypto::es256_spki(p.verifying_key().to_encoded_point(false).as_bytes());
        let es = Credential::new(vec![9; 16], -7, der)?;
        let signature: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(&p, &message);
        es.verify_assertion(&auth, &client, signature.to_der().as_bytes())?;
        let (r, s) = signature.split_scalars();
        let high = p256::ecdsa::Signature::from_scalars(r, -*s).map_err(|_| CoreError::BadSignature)?;
        es.verify_assertion(&auth, &client, high.to_der().as_bytes())?;
        assert!(es.verify_assertion(&auth, b"{}", signature.to_der().as_bytes()).is_err());
        assert!(es.verify_assertion(&auth, &client, &signature.to_bytes()).is_err(), "raw r||s is no DER");
        assert!(es.verify_assertion(&auth, &client, &[0u8; 200]).is_err(), "too long");
        Ok(())
    }
}
