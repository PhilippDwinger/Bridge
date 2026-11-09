//! The master key of a network from 24 recovery words (docs/06 §1).
//!
//! - Create: 32 random bytes → 24 English BIP-39 words (with checksum).
//! - Derive (deterministic, the same words give the same key everywhere):
//!   `seed = BIP-39 seed(words, passphrase "")`, then `sign = HKDF-SHA256(seed, salt "bridge4/master/v1", info "sign")`
//!   and `box = HKDF-SHA256(seed, salt "bridge4/master/v1", info "box")`.
//! - Typos fail at the BIP-39 checksum before any key exists.
//!
//! The words are a secret: they are wiped from memory when dropped and never appear in `Debug` output or errors.

use std::fmt;

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::crypto;
use crate::error::{CoreError, CoreResult};
use crate::keys::Identity;

/// Number of words of a master key.
pub const MNEMONIC_WORDS: usize = 24;
/// Maximum length of typed-in words (generous for extra spaces and line breaks).
pub const MAX_MNEMONIC_INPUT_BYTES: usize = 1024;
/// HKDF salt of the master key derivation.
const MASTER_SALT: &[u8] = b"bridge4/master/v1";

/// 24 recovery words (internally the 32 bytes of entropy behind them). Wiped on drop; not `Clone` on purpose.
pub struct Mnemonic {
    entropy: Zeroizing<[u8; 32]>,
}

impl Mnemonic {
    /// New words from 32 random bytes of the operating system's (or a test's) random source.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut entropy = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(entropy.as_mut_slice());
        Self { entropy }
    }

    /// Reads typed-in words: any whitespace between words, any letter case. Exactly 24 words from the English list
    /// with a valid checksum.
    pub fn parse(text: &str) -> CoreResult<Self> {
        if text.len() > MAX_MNEMONIC_INPUT_BYTES {
            return Err(CoreError::TooLarge("mnemonic".into()));
        }
        if !text.is_ascii() {
            return Err(CoreError::format("mnemonic: only words of the English list (a-z)"));
        }
        let mut normalized = Zeroizing::new(String::with_capacity(text.len()));
        let mut count = 0usize;
        for word in text.split_ascii_whitespace() {
            count += 1;
            if count > MNEMONIC_WORDS {
                return Err(CoreError::format(format!("mnemonic: more than {MNEMONIC_WORDS} words")));
            }
            if count > 1 {
                normalized.push(' ');
            }
            normalized.extend(word.chars().map(|c| c.to_ascii_lowercase()));
        }
        if count != MNEMONIC_WORDS {
            return Err(CoreError::format(format!("mnemonic: expected {MNEMONIC_WORDS} words, got {count}")));
        }
        Ok(Self { entropy: crypto::bip39_entropy(&normalized)? })
    }

    /// The 24 words, lower case, separated by single spaces (to show once; never store them).
    #[must_use]
    pub fn words(&self) -> Zeroizing<String> {
        crypto::bip39_words(&self.entropy)
    }

    /// The master identity (docs/06 §1). Its ID is the network ID; its key card has role `net`.
    pub fn to_identity(&self) -> CoreResult<Identity> {
        let seed = crypto::bip39_seed(&self.entropy, "")?;
        let sign = crypto::derive_key(seed.as_slice(), MASTER_SALT, b"sign")?;
        let receive = crypto::derive_key(seed.as_slice(), MASTER_SALT, b"box")?;
        Ok(Identity::from_secret_bytes(&sign, &receive))
    }
}

impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the words or the entropy.
        f.write_str("Mnemonic(24 words, hidden)")
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    const ZERO_WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                              abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                              abandon art";

    #[test]
    fn known_answer_for_zero_entropy() -> CoreResult<()> {
        // Seed for passphrase "" and the derived net ID computed independently (Python hashlib + cryptography):
        // pins the whole chain words → seed → HKDF → Ed25519 → ID, so any change is detected.
        let mnemonic = Mnemonic::parse(ZERO_WORDS)?;
        let seed = crypto::bip39_seed(&mnemonic.entropy, "")?;
        let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e24\
             3c4a0eafb290d399480840"
        );
        let identity = mnemonic.to_identity()?;
        assert_eq!(identity.id().as_str(), "g4hi5jca7r5nlepnk6rkn7n2522ae4bp");
        let (sign, receive) = identity.secret_bytes();
        assert_eq!(sign[..4], [0x13, 0x67, 0x35, 0x66]);
        assert_eq!(receive[..4], [0xb3, 0x65, 0x4c, 0xde]);
        Ok(())
    }

    #[test]
    fn roundtrip_is_deterministic_and_normalizes_input() -> CoreResult<()> {
        let mnemonic = Mnemonic::generate(&mut OsRng);
        let words = mnemonic.words();
        assert_eq!(words.split(' ').count(), MNEMONIC_WORDS);
        let again = Mnemonic::parse(&words)?;
        assert_eq!(again.to_identity()?.id(), mnemonic.to_identity()?.id());
        assert_eq!(again.to_identity()?.receive_public(), mnemonic.to_identity()?.receive_public());

        // Upper case, tabs, line breaks and extra spaces do not matter.
        let messy = format!("  {}\n", words.to_uppercase().replace(' ', " \t\n  "));
        assert_eq!(Mnemonic::parse(&messy)?.to_identity()?.id(), mnemonic.to_identity()?.id());

        // Different words, different key.
        assert_ne!(Mnemonic::generate(&mut OsRng).to_identity()?.id(), mnemonic.to_identity()?.id());
        Ok(())
    }

    #[test]
    fn wrong_words_are_refused_before_any_key_exists() {
        // Checksum: the last word of the zero vector is "art"; "abandon" there breaks the checksum.
        let bad_checksum = ["abandon"; 24].join(" ");
        assert!(matches!(Mnemonic::parse(&bad_checksum), Err(CoreError::BadFormat(m)) if m.contains("checksum")));
        // 23 and 25 words
        let words: Vec<&str> = ZERO_WORDS.split(' ').collect();
        assert!(Mnemonic::parse(&words[..23].join(" ")).is_err());
        assert!(Mnemonic::parse(&format!("{ZERO_WORDS} abandon")).is_err());
        // 12 words with a valid checksum (a valid BIP-39 size, but not for Bridge)
        assert!(Mnemonic::parse(&(["abandon"; 11].join(" ") + " about")).is_err());
        // Unknown word (position given, the word itself never)
        let unknown = ZERO_WORDS.replacen("abandon", "bridgex", 1);
        let result = Mnemonic::parse(&unknown);
        assert!(
            matches!(&result, Err(CoreError::BadFormat(m)) if m.contains("word 1") && !m.contains("bridgex")),
            "{result:?}"
        );
        // Non-ASCII, empty, oversized
        assert!(Mnemonic::parse(&ZERO_WORDS.replacen("abandon", "abändon", 1)).is_err());
        assert!(Mnemonic::parse("").is_err());
        assert!(matches!(Mnemonic::parse(&" ".repeat(MAX_MNEMONIC_INPUT_BYTES + 1)), Err(CoreError::TooLarge(_))));
    }

    #[test]
    fn debug_never_shows_words() -> CoreResult<()> {
        let mnemonic = Mnemonic::parse(ZERO_WORDS)?;
        let text = format!("{mnemonic:?}");
        assert!(!text.contains("abandon") && !text.contains("art") && !text.contains('0'), "{text}");
        Ok(())
    }
}
