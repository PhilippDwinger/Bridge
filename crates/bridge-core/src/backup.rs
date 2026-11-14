//! The owner backup's encryption (docs/12 §10.2): sealed **for** the net key's receiving key (X25519, in the master
//! card of the genesis manifest) - the owner's PC can make a backup without knowing the 24 words, only the words open
//! it.
//!
//! `B4BACKUP1` ‖ one-time public key (32) ‖ nonce (12) ‖ ChaCha20-Poly1305 ciphertext. Key: HKDF-SHA256 over the
//! X25519 agreement, salt = one-time public key ‖ recipient key, info = `"bridge4/backup\n"` ‖ net ID. The net ID is
//! also the associated data: a backup of one network never opens as one of another.

use rand_core::{CryptoRng, RngCore};

use crate::crypto;
use crate::error::{CoreError, CoreResult};
use crate::id::Id;
use crate::keys::Identity;

/// The first bytes of every backup.
pub const MAGIC: &[u8; 9] = b"B4BACKUP1";
/// Largest plaintext.
pub const MAX_BACKUP_BYTES: usize = 1024 * 1024;
const HEADER: usize = 9 + 32 + 12;
/// ChaCha20-Poly1305 tag.
const TAG: usize = 16;

fn info(net: &Id) -> Vec<u8> {
    let mut info = b"bridge4/backup\n".to_vec();
    info.extend_from_slice(net.as_str().as_bytes());
    info
}

/// Seals `plaintext` (at most [`MAX_BACKUP_BYTES`]) of network `net` for the receiving key `recipient`.
pub fn seal<R: RngCore + CryptoRng>(
    plaintext: &[u8],
    net: &Id,
    recipient: &[u8; 32],
    rng: &mut R,
) -> CoreResult<Vec<u8>> {
    if plaintext.len() > MAX_BACKUP_BYTES {
        return Err(CoreError::TooLarge("backup".into()));
    }
    let (one_time, shared) = crypto::agree_one_time(recipient, rng)?;
    let salt = [one_time.as_slice(), recipient.as_slice()].concat();
    let key = crypto::derive_key(shared.as_slice(), &salt, &info(net))?;
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let ciphertext = crypto::aead_seal(&key, &nonce, plaintext, net.as_str().as_bytes())?;
    let mut out = Vec::with_capacity(HEADER + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&one_time);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Opens a backup of `net` with the net key `master` (from the 24 words).
pub fn open(sealed: &[u8], net: &Id, master: &Identity) -> CoreResult<Vec<u8>> {
    if sealed.len() > HEADER + TAG + MAX_BACKUP_BYTES {
        return Err(CoreError::TooLarge("backup".into()));
    }
    if sealed.len() < HEADER + TAG || !sealed.starts_with(MAGIC) {
        return Err(CoreError::format("backup: not a Bridge backup"));
    }
    let one_time: [u8; 32] = sealed[9..41].try_into().map_err(|_| CoreError::format("backup"))?;
    let nonce: [u8; 12] = sealed[41..HEADER].try_into().map_err(|_| CoreError::format("backup"))?;
    let shared = crypto::agree_static(master.receiving_secret(), &one_time)?;
    let salt = [one_time.as_slice(), master.receive_public().as_slice()].concat();
    let key = crypto::derive_key(shared.as_slice(), &salt, &info(net))?;
    crypto::aead_open(&key, &nonce, &sealed[HEADER..], net.as_str().as_bytes())
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;
    use crate::mnemonic::Mnemonic;

    #[test]
    fn only_the_words_open_it() -> CoreResult<()> {
        let words = Mnemonic::generate(&mut OsRng);
        let master = words.to_identity()?;
        let net = master.id().clone();
        let sealed = seal(b"admin-key und app-keys", &net, &master.receive_public(), &mut OsRng)?;
        assert_eq!(open(&sealed, &net, &words.to_identity()?)?, b"admin-key und app-keys");
        assert_ne!(sealed, seal(b"admin-key und app-keys", &net, &master.receive_public(), &mut OsRng)?, "fresh");

        let other = Mnemonic::generate(&mut OsRng).to_identity()?;
        assert_eq!(open(&sealed, &net, &other), Err(CoreError::CannotOpen), "other words");
        assert_eq!(open(&sealed, other.id(), &master), Err(CoreError::CannotOpen), "another network");
        for position in [9, 41, HEADER, sealed.len() - 1] {
            let mut changed = sealed.clone();
            changed[position] ^= 1;
            assert!(open(&changed, &net, &master).is_err(), "byte {position}");
        }
        assert!(open(&sealed[..sealed.len() - 1], &net, &master).is_err(), "cut");
        assert!(open(&sealed[..HEADER], &net, &master).is_err(), "no ciphertext");
        assert!(open(b"B4BACKUP2", &net, &master).is_err());
        let big = vec![0u8; MAX_BACKUP_BYTES + 1];
        assert!(matches!(seal(&big, &net, &master.receive_public(), &mut OsRng), Err(CoreError::TooLarge(_))));
        assert!(seal(b"x", &net, &[0u8; 32], &mut OsRng).is_err(), "a low-order key");
        Ok(())
    }
}
