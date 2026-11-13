//! All cryptographic primitives of Bridge in one place (Zero Trust rule Z10: no own crypto, only reviewed libraries;
//! crypto suite B4-1 in docs/02 §4). Other modules never touch the crypto libraries directly.
//!
//! - Signatures: Ed25519 with domain separation (`"bridge4/<domain>\n" + canonical bytes`), strict verification.
//! - Key agreement: X25519, only contributory results are accepted (no all-zero shared secret).
//! - Key derivation: HKDF-SHA256. Encryption: ChaCha20-Poly1305. Hash: SHA-256.
//! - Passkeys (Bridge Login, ADR 0027): only *verifying* WebAuthn signatures - ES256 (ECDSA P-256 + SHA-256, key as
//!   SPKI DER, signature as DER) and EdDSA (Ed25519, key as SPKI DER, strict) without a Bridge domain (the format is
//!   WebAuthn's).

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

/// A message authentication code under `key` (at least 16 bytes): HKDF-SHA256 with `key` as input key material and
/// `"bridge4/mac/<domain>\n" + message` as info, 32 bytes - that is HMAC-SHA256 with the extracted key over the info
/// (a PRF of domain and message). For local protocols, e.g. BridgeControll's second start proving and checking the
/// launch key without sending it.
pub fn mac(key: &[u8], domain: &str, message: &[u8]) -> CoreResult<[u8; 32]> {
    if key.len() < 16 {
        return Err(CoreError::format("mac: key too short"));
    }
    let mut info = Vec::with_capacity(13 + domain.len() + message.len());
    info.extend_from_slice(b"bridge4/mac/");
    info.extend_from_slice(domain.as_bytes());
    info.push(b'\n');
    info.extend_from_slice(message);
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, key).expand(&info, &mut out).map_err(|_| CoreError::format("mac: hkdf"))?;
    Ok(out)
}

/// A domain-separated signature of arbitrary bytes - **only** for building test vectors that a correct signer would
/// never produce (feature `test-vectors`, enabled by the test crate alone; release programs never have it).
#[cfg(feature = "test-vectors")]
#[must_use]
pub fn sign_for_vectors(identity: &crate::keys::Identity, domain: &str, message: &[u8]) -> [u8; 64] {
    identity.sign_canonical(domain, message)
}

/// Compares two codes without an early exit (no timing hint about where they differ).
#[must_use]
pub fn mac_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
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

/// The SPKI DER prefix of an Ed25519 public key (RFC 8410): `SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING }`.
const ED25519_SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

/// Whether `spki` is a usable ES256 (P-256) public key in SPKI DER.
#[must_use]
pub fn es256_key_ok(spki: &[u8]) -> bool {
    use p256::pkcs8::DecodePublicKey as _;
    p256::ecdsa::VerifyingKey::from_public_key_der(spki).is_ok()
}

/// Verifies an ES256 signature (DER) of a passkey over `message` (SHA-256 is applied here, as WebAuthn defines). A
/// high-S signature is accepted like its low-S twin (authenticators produce both).
pub fn verify_es256(spki: &[u8], message: &[u8], signature_der: &[u8]) -> CoreResult<()> {
    use p256::ecdsa::signature::Verifier as _;
    use p256::pkcs8::DecodePublicKey as _;
    let key = p256::ecdsa::VerifyingKey::from_public_key_der(spki).map_err(|_| CoreError::BadSignature)?;
    let signature = p256::ecdsa::Signature::from_der(signature_der).map_err(|_| CoreError::BadSignature)?;
    let signature = signature.normalize_s().unwrap_or(signature);
    key.verify(message, &signature).map_err(|_| CoreError::BadSignature)
}

/// The raw Ed25519 key of an SPKI DER - or `None` (wrong form, weak key).
#[must_use]
pub fn ed25519_spki_key(spki: &[u8]) -> Option<[u8; 32]> {
    let raw: [u8; 32] = spki.strip_prefix(&ED25519_SPKI_PREFIX[..])?.try_into().ok()?;
    let key = VerifyingKey::from_bytes(&raw).ok()?;
    (!key.is_weak()).then_some(raw)
}

/// Verifies an EdDSA (Ed25519) signature of a passkey over `message` - strict, no domain (WebAuthn's format).
pub fn verify_ed25519_spki(spki: &[u8], message: &[u8], signature: &[u8]) -> CoreResult<()> {
    let raw = ed25519_spki_key(spki).ok_or(CoreError::BadSignature)?;
    let signature: [u8; 64] = signature.try_into().map_err(|_| CoreError::BadSignature)?;
    let key = VerifyingKey::from_bytes(&raw).map_err(|_| CoreError::BadSignature)?;
    key.verify_strict(message, &Signature::from_bytes(&signature)).map_err(|_| CoreError::BadSignature)
}

/// The SPKI DER prefix of a P-256 public key: `SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING }`.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// The SPKI DER of an uncompressed P-256 point (`04 ‖ x ‖ y`) - not checked here ([`es256_key_ok`] does).
#[must_use]
pub fn es256_spki(point: &[u8]) -> Vec<u8> {
    let mut spki = P256_SPKI_PREFIX.to_vec();
    spki.extend_from_slice(point);
    spki
}

/// Test authenticator (feature `test-vectors`): the SPKI DER of the ES256 key of `secret` and a DER signature over
/// `message` - for tests of Bridge Login without a browser.
#[cfg(feature = "test-vectors")]
#[must_use]
pub fn es256_test_sign(secret: &[u8; 32], message: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use p256::ecdsa::signature::Signer as _;
    let Ok(key) = p256::ecdsa::SigningKey::from_slice(secret) else { return (Vec::new(), Vec::new()) };
    let spki = es256_spki(key.verifying_key().to_encoded_point(false).as_bytes());
    let signature: p256::ecdsa::Signature = key.sign(message);
    (spki, signature.to_der().as_bytes().to_vec())
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
pub(crate) fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> CoreResult<SecretKey> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, key.as_mut_slice()).map_err(|_| CoreError::CannotOpen)?;
    Ok(key)
}

/// Longest English BIP-39 word (8 letters) times 24 words plus separators - enough to never reallocate (a
/// reallocation would leave an unwiped copy of the words behind).
const BIP39_WORDS_CAPACITY: usize = 24 * 9;

/// The 24 English BIP-39 words (checksum included) for 32 bytes of entropy, separated by single spaces.
/// 256 bits is a valid BIP-39 size, so this cannot fail; should the library ever refuse, the result is empty and
/// every later parse of it fails (fail closed).
pub(crate) fn bip39_words(entropy: &[u8; 32]) -> Zeroizing<String> {
    let mut words = Zeroizing::new(String::with_capacity(BIP39_WORDS_CAPACITY));
    if let Ok(mnemonic) = bip39::Mnemonic::from_entropy_in(bip39::Language::English, entropy) {
        for (index, word) in mnemonic.words().enumerate() {
            if index > 0 {
                words.push(' ');
            }
            words.push_str(word);
        }
    }
    words
}

/// The 32 bytes of entropy behind normalized English words (lower case, single spaces, exactly 24 words).
/// Checks every word against the list and the BIP-39 checksum. Errors never contain the words themselves.
pub(crate) fn bip39_entropy(normalized: &str) -> CoreResult<Zeroizing<[u8; 32]>> {
    let mnemonic =
        bip39::Mnemonic::parse_in_normalized(bip39::Language::English, normalized).map_err(|error| match error {
            bip39::Error::UnknownWord(index) => {
                CoreError::format(format!("mnemonic: word {} is not in the word list", index + 1))
            }
            bip39::Error::InvalidChecksum => CoreError::format("mnemonic: checksum does not match (typo?)"),
            _ => CoreError::format("mnemonic: invalid"),
        })?;
    let (bytes, length) = mnemonic.to_entropy_array();
    let bytes = Zeroizing::new(bytes);
    if length != 32 {
        return Err(CoreError::format("mnemonic: expected 256 bits"));
    }
    let mut entropy = Zeroizing::new([0u8; 32]);
    entropy.copy_from_slice(&bytes[..32]);
    Ok(entropy)
}

/// BIP-39 seed (PBKDF2-HMAC-SHA512, 2048 rounds, salt "mnemonic" + passphrase, 64 bytes) of the English words for
/// `entropy`. `passphrase` must already be NFKD-normalized (Bridge only uses "").
pub(crate) fn bip39_seed(entropy: &[u8; 32], passphrase: &str) -> CoreResult<Zeroizing<[u8; 64]>> {
    let mnemonic = bip39::Mnemonic::from_entropy_in(bip39::Language::English, entropy)
        .map_err(|_| CoreError::format("mnemonic: invalid entropy"))?;
    Ok(Zeroizing::new(mnemonic.to_seed_normalized(passphrase)))
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
    fn mac_depends_on_key_domain_and_message() -> CoreResult<()> {
        let key = [7u8; 32];
        let tag = mac(&key, "launch", b"nonce")?;
        assert_eq!(tag, mac(&key, "launch", b"nonce")?, "deterministic");
        assert!(mac_eq(&tag, &mac(&key, "launch", b"nonce")?));
        for other in [mac(&[8u8; 32], "launch", b"nonce")?, mac(&key, "answer", b"nonce")?, mac(&key, "launch", b"x")?]
        {
            assert!(!mac_eq(&tag, &other));
        }
        // Domain and message are separated: ("ab", "c") is not ("a", "bc").
        assert_ne!(mac(&key, "ab", b"c")?, mac(&key, "a", b"bc")?);
        assert!(mac(&[1u8; 15], "launch", b"nonce").is_err(), "short keys are refused");
        Ok(())
    }

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
    fn bip39_official_vector() -> CoreResult<()> {
        // Official BIP-39 test vector (trezor/python-mnemonic, vectors.json): entropy 0x00 * 32, passphrase "TREZOR".
        let words = bip39_words(&[0u8; 32]);
        let expected_words = ["abandon"; 23].join(" ") + " art";
        assert_eq!(words.as_str(), expected_words);
        let seed = bip39_seed(&[0u8; 32], "TREZOR")?;
        let expected = "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3\
                        de6f5d4a10be8ed2a5e608d68f92fcc8";
        let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected);
        assert_eq!(*bip39_entropy(&words)?, [0u8; 32]);
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
