//! All cryptographic primitives of Bridge in one place (Zero Trust rule Z10: no own crypto, only reviewed libraries;
//! crypto suite B4-1 in docs/02 §4). Other modules never touch the crypto libraries directly.
//!
//! - Signatures: Ed25519 with domain separation (`"bridge4/<domain>\n" + canonical bytes`), strict verification.
//! - Key agreement: X25519, only contributory results are accepted (no all-zero shared secret).
//! - Key derivation: HKDF-SHA256. Encryption: ChaCha20-Poly1305. Hash: SHA-256.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{CoreError, CoreResult};

/// A 32-byte secret key that is wiped from memory when dropped.
pub(crate) type SecretKey = Zeroizing<[u8; 32]>;

/// SHA-256 of `bytes`.
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// SHA-256 over several parts (as if concatenated).
#[must_use]
pub fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Incremental SHA-256 (for streams).
#[derive(Clone, Default)]
pub(crate) struct Hasher(Sha256);

impl Hasher {
    pub(crate) fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
    pub(crate) fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

fn domain_message(domain: &str, canonical: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(9 + domain.len() + canonical.len());
    message.extend_from_slice(b"bridge4/");
    message.extend_from_slice(domain.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(canonical);
    message
}

pub(crate) fn generate_signing_key<R: RngCore + CryptoRng>(rng: &mut R) -> SigningKey {
    SigningKey::generate(rng)
}

pub(crate) fn signing_key_from_bytes(secret: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(secret)
}

pub(crate) fn sign_public(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

pub(crate) fn sign(key: &SigningKey, domain: &str, canonical: &[u8]) -> [u8; 64] {
    key.sign(&domain_message(domain, canonical)).to_bytes()
}

/// Strict verification: rejects weak (small-order) public keys and non-canonical signatures.
pub(crate) fn verify(public_key: &[u8; 32], domain: &str, canonical: &[u8], signature: &[u8; 64]) -> CoreResult<()> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| CoreError::BadSignature)?;
    if key.is_weak() {
        return Err(CoreError::BadSignature);
    }
    key.verify_strict(&domain_message(domain, canonical), &Signature::from_bytes(signature))
        .map_err(|_| CoreError::BadSignature)
}

pub(crate) fn generate_box_secret<R: RngCore + CryptoRng>(rng: &mut R) -> StaticSecret {
    StaticSecret::random_from_rng(rng)
}

pub(crate) fn box_secret_from_bytes(secret: &[u8; 32]) -> StaticSecret {
    StaticSecret::from(*secret)
}

pub(crate) fn box_public(secret: &StaticSecret) -> [u8; 32] {
    PublicKey::from(secret).to_bytes()
}

/// Creates a one-time key pair (N1: only ever created here) and agrees with `peer`.
/// Returns the one-time public key and the shared secret.
pub(crate) fn agree_one_time<R: RngCore + CryptoRng>(
    peer: &[u8; 32],
    rng: &mut R,
) -> CoreResult<([u8; 32], SecretKey)> {
    let ephemeral = EphemeralSecret::random_from_rng(&mut *rng);
    let public = PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&PublicKey::from(*peer));
    if !shared.was_contributory() {
        return Err(CoreError::CannotOpen); // peer key of low order
    }
    Ok((public, Zeroizing::new(*shared.as_bytes())))
}

/// Agreement with a long-lived secret (the recipient side).
pub(crate) fn agree_static(secret: &StaticSecret, peer: &[u8; 32]) -> CoreResult<SecretKey> {
    let shared = secret.diffie_hellman(&PublicKey::from(*peer));
    if !shared.was_contributory() {
        return Err(CoreError::CannotOpen);
    }
    Ok(Zeroizing::new(*shared.as_bytes()))
}

/// HKDF-SHA256 to a 32-byte key.
pub(crate) fn derive_key(ikm: &[u8; 32], salt: &[u8], info: &[u8]) -> CoreResult<SecretKey> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, key.as_mut_slice()).map_err(|_| CoreError::CannotOpen)?;
    Ok(key)
}

/// A fresh random 32-byte key (stream content keys; created only inside this crate - N1).
pub(crate) fn random_key<R: RngCore + CryptoRng>(rng: &mut R) -> SecretKey {
    let mut key = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(key.as_mut_slice());
    key
}

pub(crate) fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> CoreResult<Vec<u8>> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CoreError::CannotOpen)
}

pub(crate) fn aead_open(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> CoreResult<Vec<u8>> {
    ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| CoreError::CannotOpen)
}

/// Number of leading zero bits (proof-of-work).
#[must_use]
pub fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut bits = 0;
    for byte in hash {
        if *byte == 0 {
            bits += 8;
        } else {
            return bits + byte.leading_zeros();
        }
    }
    bits
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn sha256_known_vector() {
        let hash = sha256(b"abc");
        assert_eq!(hash[..4], [0xba, 0x78, 0x16, 0xbf]);
        assert_eq!(sha256_parts(&[b"a", b"bc"]), hash);
    }

    #[test]
    fn domain_separation() -> CoreResult<()> {
        let key = generate_signing_key(&mut OsRng);
        let signature = sign(&key, "key", b"{}");
        verify(&sign_public(&key), "key", b"{}", &signature)?;
        assert_eq!(verify(&sign_public(&key), "env", b"{}", &signature), Err(CoreError::BadSignature));
        assert_eq!(verify(&sign_public(&key), "key", b"{ }", &signature), Err(CoreError::BadSignature));
        Ok(())
    }

    #[test]
    fn weak_and_low_order_keys_are_refused() {
        // Ed25519 identity point (small order) - must be refused even with a "valid" signature.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(verify(&identity, "key", b"x", &[0u8; 64]), Err(CoreError::BadSignature));
        assert!(agree_one_time(&[0u8; 32], &mut OsRng).is_err());
        let secret = generate_box_secret(&mut OsRng);
        assert!(agree_static(&secret, &[0u8; 32]).is_err());
    }

    #[test]
    fn aead_detects_changes() -> CoreResult<()> {
        let key = [7u8; 32];
        let nonce = [1u8; 12];
        let sealed = aead_seal(&key, &nonce, b"hello", b"aad")?;
        assert_eq!(aead_open(&key, &nonce, &sealed, b"aad")?, b"hello");
        assert!(aead_open(&key, &nonce, &sealed, b"aaD").is_err());
        assert!(aead_open(&[8u8; 32], &nonce, &sealed, b"aad").is_err());
        Ok(())
    }

    #[test]
    fn zero_bits() {
        let mut hash = [0xffu8; 32];
        assert_eq!(leading_zero_bits(&hash), 0);
        hash[0] = 0;
        hash[1] = 0x1f;
        assert_eq!(leading_zero_bits(&hash), 11);
        assert_eq!(leading_zero_bits(&[0u8; 32]), 256);
    }
}
