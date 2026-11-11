//! Private files (docs/07 §1): Bridge sees blobs only as bytes, so a client encrypts a private file before it
//! uploads it. Each file gets its own random 32-byte key and an 8-byte random nonce prefix, both made here only
//! (nonce invariant N1, ADR 0008). Plaintext chunk `i` (65,520 bytes, the last one shorter) is sealed with
//! ChaCha20-Poly1305, nonce = prefix ‖ i (4 bytes big endian), AAD = `"bridge4/file/v1"` ‖ i ‖ last flag - so the
//! sealed chunks are exactly the 64 KiB parts of the encrypted blob, can be opened one by one in any order (parallel
//! downloads), and can be neither reordered, nor cut off, nor moved into another file. An empty file still has one
//! sealed chunk (just the tag), so an encrypted blob is never empty.
//!
//! The key travels to the recipients inside an envelope (content type `data`, [`FileKey::to_bytes`]).

use std::fmt;

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::blob::{MAX_PARTS, PART_BYTES};
use crate::crypto::{self, SecretKey};
use crate::error::{CoreError, CoreResult};

/// Length of the authentication tag added to every chunk.
const TAG_BYTES: usize = 16;
/// Plaintext bytes per chunk: one sealed chunk is exactly one blob part.
pub const FILE_CHUNK_BYTES: usize = PART_BYTES - TAG_BYTES;
/// Largest private file (65,536 chunks).
pub const MAX_FILE_BYTES: u64 = FILE_CHUNK_BYTES as u64 * MAX_PARTS as u64;
/// Length of [`FileKey::to_bytes`]: key (32) ‖ nonce prefix (8).
pub const FILE_KEY_BYTES: usize = 40;

const AAD: &[u8] = b"bridge4/file/v1";

/// The secret of one private file: content key and nonce prefix. Made only by [`FileKey::generate`] (N1).
#[derive(Clone, PartialEq, Eq)]
pub struct FileKey {
    key: SecretKey,
    prefix: [u8; 8],
}

impl fmt::Debug for FileKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FileKey(…)") // never print the key
    }
}

impl FileKey {
    /// A new key for one file (never reuse it for another file).
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let key = crypto::random_key(rng);
        let mut prefix = [0u8; 8];
        rng.fill_bytes(&mut prefix);
        Self { key, prefix }
    }

    /// The key as bytes for the envelope to the recipients (key ‖ prefix). Wiped when dropped.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; FILE_KEY_BYTES]> {
        let mut bytes = Zeroizing::new([0u8; FILE_KEY_BYTES]);
        bytes[..32].copy_from_slice(self.key.as_slice());
        bytes[32..].copy_from_slice(&self.prefix);
        bytes
    }

    /// A key received in an envelope (only for opening).
    pub fn from_bytes(bytes: &[u8]) -> CoreResult<Self> {
        if bytes.len() != FILE_KEY_BYTES {
            return Err(CoreError::format("file key: expected 40 bytes"));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&bytes[..32]);
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&bytes[32..]);
        Ok(Self { key, prefix })
    }
}

/// Number of sealed chunks of a file of `plain_size` bytes: `max(1, ceil(size / 65,520))`.
pub fn chunks_for(plain_size: u64) -> CoreResult<u32> {
    if plain_size > MAX_FILE_BYTES {
        return Err(CoreError::TooLarge("file".into()));
    }
    u32::try_from(plain_size.div_ceil(FILE_CHUNK_BYTES as u64).max(1)).map_err(|_| CoreError::TooLarge("file".into()))
}

/// Size of the encrypted blob of a file of `plain_size` bytes.
pub fn encrypted_size(plain_size: u64) -> CoreResult<u64> {
    Ok(plain_size + u64::from(chunks_for(plain_size)?) * TAG_BYTES as u64)
}

/// Size of the file inside an encrypted blob of `encrypted` bytes (fails for sizes no file can have).
pub fn plain_size(encrypted: u64) -> CoreResult<u64> {
    let chunks = encrypted.div_ceil(PART_BYTES as u64);
    let plain = encrypted
        .checked_sub(chunks * TAG_BYTES as u64)
        .filter(|_| chunks >= 1)
        .ok_or_else(|| CoreError::format("file: not an encrypted size"))?;
    if encrypted_size(plain)? != encrypted {
        return Err(CoreError::format("file: not an encrypted size"));
    }
    Ok(plain)
}

fn nonce(prefix: &[u8; 8], index: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(prefix);
    nonce[8..].copy_from_slice(&index.to_be_bytes());
    nonce
}

fn aad(index: u32, last: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD.len() + 5);
    aad.extend_from_slice(AAD);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(u8::from(last));
    aad
}

fn chunk_len(plain_size: u64, chunks: u32, index: u32) -> usize {
    if index + 1 < chunks {
        FILE_CHUNK_BYTES
    } else {
        usize::try_from(plain_size - u64::from(chunks - 1) * FILE_CHUNK_BYTES as u64).unwrap_or(usize::MAX)
    }
}

/// Encrypts one file chunk by chunk, in order, with its own new key.
pub struct FileSealer {
    key: FileKey,
    size: u64,
    chunks: u32,
    next: u32,
}

impl FileSealer {
    /// Starts a file of `plain_size` bytes with a new key.
    pub fn start<R: RngCore + CryptoRng>(plain_size: u64, rng: &mut R) -> CoreResult<Self> {
        let chunks = chunks_for(plain_size)?;
        Ok(Self { key: FileKey::generate(rng), size: plain_size, chunks, next: 0 })
    }

    /// The file's key (to send to the recipients).
    #[must_use]
    pub fn key(&self) -> &FileKey {
        &self.key
    }

    /// Encrypts the next chunk: every chunk but the last is exactly [`FILE_CHUNK_BYTES`] long. The result is the
    /// next part of the encrypted blob.
    pub fn seal_next(&mut self, chunk: &[u8]) -> CoreResult<Vec<u8>> {
        if self.next >= self.chunks {
            return Err(CoreError::format("file: all chunks already sealed"));
        }
        let index = self.next;
        if chunk.len() != chunk_len(self.size, self.chunks, index) {
            return Err(CoreError::format("file: wrong chunk size"));
        }
        let last = index + 1 == self.chunks;
        let sealed = crypto::aead_seal(&self.key.key, &nonce(&self.key.prefix, index), chunk, &aad(index, last))?;
        self.next += 1;
        Ok(sealed)
    }

    /// All chunks sealed?
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.next == self.chunks
    }
}

/// Opens the parts of an encrypted blob, each on its own and in any order.
pub struct FileOpener {
    key: FileKey,
    encrypted: u64,
    chunks: u32,
}

impl FileOpener {
    /// For an encrypted blob of `encrypted` bytes (its size comes from the blob ID, so it can not be cut off).
    pub fn new(key: &FileKey, encrypted: u64) -> CoreResult<Self> {
        plain_size(encrypted)?;
        let chunks =
            u32::try_from(encrypted.div_ceil(PART_BYTES as u64)).map_err(|_| CoreError::TooLarge("file".into()))?;
        Ok(Self { key: key.clone(), encrypted, chunks })
    }

    /// Size of the file.
    #[must_use]
    pub fn plain_size(&self) -> u64 {
        self.encrypted - u64::from(self.chunks) * TAG_BYTES as u64
    }

    /// Decrypts part `index` of the encrypted blob.
    pub fn open_part(&self, index: u32, part: &[u8]) -> CoreResult<Vec<u8>> {
        if index >= self.chunks || crate::blob::part_len(self.encrypted, index) != Some(part.len()) {
            return Err(CoreError::CannotOpen);
        }
        let last = index + 1 == self.chunks;
        crypto::aead_open(&self.key.key, &nonce(&self.key.prefix, index), part, &aad(index, last))
    }
}

/// Encrypts a file in memory with a new key: (key, encrypted blob).
pub fn encrypt_file<R: RngCore + CryptoRng>(data: &[u8], rng: &mut R) -> CoreResult<(FileKey, Vec<u8>)> {
    let size = u64::try_from(data.len()).map_err(|_| CoreError::TooLarge("file".into()))?;
    let mut sealer = FileSealer::start(size, rng)?;
    let mut out = Vec::with_capacity(usize::try_from(encrypted_size(size)?).unwrap_or(0));
    if data.is_empty() {
        out.extend_from_slice(&sealer.seal_next(&[])?);
    }
    for chunk in data.chunks(FILE_CHUNK_BYTES) {
        out.extend_from_slice(&sealer.seal_next(chunk)?);
    }
    Ok((sealer.key, out))
}

/// Decrypts a whole encrypted blob in memory.
pub fn decrypt_file(key: &FileKey, encrypted: &[u8]) -> CoreResult<Vec<u8>> {
    let opener = FileOpener::new(key, encrypted.len() as u64)?;
    let mut out = Vec::with_capacity(usize::try_from(opener.plain_size()).unwrap_or(0));
    for (index, part) in encrypted.chunks(PART_BYTES).enumerate() {
        let index = u32::try_from(index).map_err(|_| CoreError::TooLarge("file".into()))?;
        out.extend_from_slice(&opener.open_part(index, part)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;
    use crate::blob::HashList;

    fn data(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 253) as u8).collect()
    }

    #[test]
    fn roundtrip_and_blob_alignment() -> CoreResult<()> {
        for size in [0usize, 1, FILE_CHUNK_BYTES - 1, FILE_CHUNK_BYTES, FILE_CHUNK_BYTES + 1, 3 * PART_BYTES + 9] {
            let plain = data(size);
            let (key, encrypted) = encrypt_file(&plain, &mut OsRng)?;
            assert_eq!(encrypted.len() as u64, encrypted_size(size as u64)?);
            assert_eq!(plain_size(encrypted.len() as u64)?, size as u64);
            // Every sealed chunk is one blob part: the blob's parts open one by one, in any order.
            let list = HashList::of(&encrypted)?;
            assert_eq!(list.parts(), chunks_for(size as u64)?);
            let opener = FileOpener::new(&key, encrypted.len() as u64)?;
            let parts: Vec<&[u8]> = encrypted.chunks(PART_BYTES).collect();
            let mut opened: Vec<Vec<u8>> = Vec::new();
            for index in (0..parts.len()).rev() {
                opened.insert(0, opener.open_part(index as u32, parts[index])?);
            }
            assert_eq!(opened.concat(), plain, "size {size}");
            assert_eq!(decrypt_file(&key, &encrypted)?, plain);
            // The key survives the trip through an envelope.
            assert_eq!(decrypt_file(&FileKey::from_bytes(key.to_bytes().as_slice())?, &encrypted)?, plain);
        }
        Ok(())
    }

    #[test]
    fn tampering_reordering_and_cutting_are_detected() -> CoreResult<()> {
        let plain = data(3 * FILE_CHUNK_BYTES + 100);
        let (key, encrypted) = encrypt_file(&plain, &mut OsRng)?;
        let opener = FileOpener::new(&key, encrypted.len() as u64)?;
        let parts: Vec<&[u8]> = encrypted.chunks(PART_BYTES).collect();
        // A flipped bit.
        let mut flipped = parts[1].to_vec();
        flipped[3] ^= 1;
        assert_eq!(opener.open_part(1, &flipped), Err(CoreError::CannotOpen));
        // Another part's bytes under this number (same length).
        assert_eq!(opener.open_part(1, parts[0]), Err(CoreError::CannotOpen));
        // Cut off: the file ends after part 2 - part 2 is not the last, so it does not open as the last part.
        let cut = FileOpener::new(&key, 3 * PART_BYTES as u64)?;
        assert_eq!(cut.open_part(2, parts[2]), Err(CoreError::CannotOpen));
        // A part of another file (another key) and another key for this file.
        let (other_key, other) = encrypt_file(&plain, &mut OsRng)?;
        assert_eq!(opener.open_part(0, &other[..PART_BYTES]), Err(CoreError::CannotOpen));
        assert!(decrypt_file(&other_key, &encrypted).is_err());
        // Sizes no encrypted file can have; wrong key bytes.
        assert!(FileOpener::new(&key, 0).is_err());
        assert!(FileOpener::new(&key, 15).is_err());
        assert!(plain_size(PART_BYTES as u64 + 10).is_err());
        assert!(FileKey::from_bytes(&[0u8; 39]).is_err());
        assert!(opener.open_part(9, parts[0]).is_err());
        Ok(())
    }

    #[test]
    fn sealer_enforces_sizes_and_keys_never_repeat() -> CoreResult<()> {
        let mut sealer = FileSealer::start(10, &mut OsRng)?;
        assert!(sealer.seal_next(&[0u8; 9]).is_err());
        sealer.seal_next(&[0u8; 10])?;
        assert!(sealer.is_done() && sealer.seal_next(&[0u8; 10]).is_err());
        assert!(FileSealer::start(MAX_FILE_BYTES + 1, &mut OsRng).is_err());
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            assert!(seen.insert(*FileKey::generate(&mut OsRng).to_bytes()));
        }
        assert!(format!("{:?}", FileKey::generate(&mut OsRng)).contains('…'));
        Ok(())
    }
}
