//! Files as blobs (docs/07 §1): a file is split into parts of 64 KiB (the last one shorter, an empty file has no
//! parts). Its **blob ID** is `SHA-256("bridge4/blob/v1\n" ‖ size as 8 bytes big endian ‖ h₀ ‖ h₁ ‖ …)` with
//! `hᵢ = SHA-256(part i)`, as Base64url. The ID fixes the size and every part: whoever knows the ID checks any
//! source - the hash list against the ID first, then every part against its hash, from as many sources as wanted,
//! in any order.
//!
//! Bridge sees blobs only as bytes; private files are encrypted before (see [`crate::file`]).
//! `bridge4/blob/v1` is a hash domain only (nothing is signed with it), so it can not collide with a statement kind.

use std::fmt;

use crate::crypto::{self, Hasher};
use crate::encoding::{b64, b64_fixed};
use crate::error::{CoreError, CoreResult};

/// Bytes per part (every part but the last has exactly this size).
pub const PART_BYTES: usize = 64 * 1024;
/// Most parts of one blob.
pub const MAX_PARTS: u32 = 65_536;
/// Largest blob (4 GiB).
pub const MAX_BLOB_BYTES: u64 = PART_BYTES as u64 * MAX_PARTS as u64;
/// Most hashes in one page of a hash list on the wire (`/v4/blob/begin`, `/v4/blob/hashes`).
pub const HASH_PAGE: u32 = 4096;

const ID_DOMAIN: &[u8] = b"bridge4/blob/v1\n";

/// Number of parts of a blob of `size` bytes: `ceil(size / 64 KiB)` (0 for an empty blob). Fails above 4 GiB.
pub fn parts_for(size: u64) -> CoreResult<u32> {
    if size > MAX_BLOB_BYTES {
        return Err(CoreError::TooLarge("blob".into()));
    }
    u32::try_from(size.div_ceil(PART_BYTES as u64)).map_err(|_| CoreError::TooLarge("blob".into()))
}

/// Length of part `index` of a blob of `size` bytes (`None` if there is no such part).
#[must_use]
pub fn part_len(size: u64, index: u32) -> Option<usize> {
    let parts = parts_for(size).ok()?;
    if index >= parts {
        return None;
    }
    let start = u64::from(index) * PART_BYTES as u64;
    usize::try_from((size - start).min(PART_BYTES as u64)).ok()
}

/// Byte offset of part `index`.
#[must_use]
pub fn part_offset(index: u32) -> u64 {
    u64::from(index) * PART_BYTES as u64
}

/// SHA-256 of one part.
#[must_use]
pub fn part_hash(data: &[u8]) -> [u8; 32] {
    crypto::sha256(data)
}

/// Checks part `index` of a blob of `size` bytes against its hash: exact length, then the hash.
pub fn verify_part(hash: &[u8; 32], size: u64, index: u32, data: &[u8]) -> CoreResult<()> {
    if part_len(size, index) != Some(data.len()) {
        return Err(CoreError::format("blob part: wrong length"));
    }
    if &part_hash(data) != hash {
        return Err(CoreError::format("blob part: does not match its hash"));
    }
    Ok(())
}

/// The ID of a blob (32 bytes; Base64url on the wire, lower-case hex in file names - Base64url differs only by case
/// on some file systems).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlobId([u8; 32]);

impl BlobId {
    /// Parses the wire form (canonical Base64url of 32 bytes).
    pub fn parse(text: &str) -> CoreResult<Self> {
        Ok(Self(b64_fixed::<32>(text, "blob")?))
    }

    /// The raw 32 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The wire form (Base64url).
    #[must_use]
    pub fn to_text(&self) -> String {
        b64(&self.0)
    }

    /// Lower-case hex (64 characters) - safe as a file name on every file system.
    #[must_use]
    pub fn hex(&self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

impl fmt::Display for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

impl fmt::Debug for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlobId({})", self.to_text())
    }
}

/// The hashes of all parts of a blob, in order, with the size. Constructed only through checks: the number of
/// hashes always fits the size.
#[derive(Clone, PartialEq, Eq)]
pub struct HashList {
    size: u64,
    hashes: Vec<[u8; 32]>,
}

impl fmt::Debug for HashList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashList").field("size", &self.size).field("parts", &self.hashes.len()).finish()
    }
}

impl HashList {
    /// A hash list for `size` bytes: exactly `parts_for(size)` hashes.
    pub fn new(size: u64, hashes: Vec<[u8; 32]>) -> CoreResult<Self> {
        if hashes.len() != parts_for(size)? as usize {
            return Err(CoreError::format("hash list: number of hashes does not fit the size"));
        }
        Ok(Self { size, hashes })
    }

    /// The hash list of data in memory.
    pub fn of(data: &[u8]) -> CoreResult<Self> {
        let size = u64::try_from(data.len()).map_err(|_| CoreError::TooLarge("blob".into()))?;
        parts_for(size)?;
        Self::new(size, data.chunks(PART_BYTES).map(part_hash).collect())
    }

    /// The blob ID this list belongs to.
    #[must_use]
    pub fn id(&self) -> BlobId {
        let mut hasher = Hasher::default();
        hasher.update(ID_DOMAIN);
        hasher.update(&self.size.to_be_bytes());
        for hash in &self.hashes {
            hasher.update(hash);
        }
        BlobId(hasher.finish())
    }

    /// Checks that this list belongs to `id` (the only way to trust a hash list from another source).
    pub fn check(&self, id: &BlobId) -> CoreResult<()> {
        if &self.id() != id {
            return Err(CoreError::format("hash list does not match the blob ID"));
        }
        Ok(())
    }

    /// Size of the blob in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Number of parts.
    #[must_use]
    pub fn parts(&self) -> u32 {
        u32::try_from(self.hashes.len()).unwrap_or(u32::MAX)
    }

    /// All hashes, in order.
    #[must_use]
    pub fn hashes(&self) -> &[[u8; 32]] {
        &self.hashes
    }

    /// The hash of part `index`.
    #[must_use]
    pub fn hash(&self, index: u32) -> Option<&[u8; 32]> {
        self.hashes.get(index as usize)
    }

    /// Checks part `index` (length and hash).
    pub fn verify_part(&self, index: u32, data: &[u8]) -> CoreResult<()> {
        let hash = self.hash(index).ok_or_else(|| CoreError::format("blob part: no such part"))?;
        verify_part(hash, self.size, index, data)
    }
}

/// Builds a hash list part by part (for files that are not in memory): every part but the last must be exactly
/// [`PART_BYTES`] long.
#[derive(Debug, Default)]
pub struct HashListBuilder {
    size: u64,
    hashes: Vec<[u8; 32]>,
    short: bool,
}

impl HashListBuilder {
    /// Adds the next part.
    pub fn push(&mut self, part: &[u8]) -> CoreResult<()> {
        if part.is_empty() || part.len() > PART_BYTES || self.short {
            return Err(CoreError::format("hash list: parts must be 64 KiB (the last one may be shorter)"));
        }
        if self.hashes.len() >= MAX_PARTS as usize {
            return Err(CoreError::TooLarge("blob".into()));
        }
        self.short = part.len() < PART_BYTES;
        self.size += part.len() as u64;
        self.hashes.push(part_hash(part));
        Ok(())
    }

    /// The finished hash list.
    pub fn finish(self) -> CoreResult<HashList> {
        HashList::new(self.size, self.hashes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn parts_and_lengths() -> CoreResult<()> {
        assert_eq!(parts_for(0)?, 0);
        assert_eq!(parts_for(1)?, 1);
        assert_eq!(parts_for(PART_BYTES as u64)?, 1);
        assert_eq!(parts_for(PART_BYTES as u64 + 1)?, 2);
        assert_eq!(parts_for(MAX_BLOB_BYTES)?, MAX_PARTS);
        assert!(matches!(parts_for(MAX_BLOB_BYTES + 1), Err(CoreError::TooLarge(_))));
        assert_eq!(part_len(0, 0), None);
        assert_eq!(part_len(10, 0), Some(10));
        assert_eq!(part_len(10, 1), None);
        assert_eq!(part_len(PART_BYTES as u64 + 3, 0), Some(PART_BYTES));
        assert_eq!(part_len(PART_BYTES as u64 + 3, 1), Some(3));
        assert_eq!(part_len(MAX_BLOB_BYTES, MAX_PARTS - 1), Some(PART_BYTES));
        assert_eq!(part_len(MAX_BLOB_BYTES, MAX_PARTS), None);
        Ok(())
    }

    #[test]
    fn id_binds_size_and_every_part() -> CoreResult<()> {
        for size in [0usize, 1, PART_BYTES - 1, PART_BYTES, PART_BYTES + 1, 3 * PART_BYTES + 17] {
            let bytes = data(size);
            let list = HashList::of(&bytes)?;
            assert_eq!(list.size(), size as u64);
            assert_eq!(list.parts(), parts_for(size as u64)?);
            let id = list.id();
            list.check(&id)?;
            assert_eq!(BlobId::parse(&id.to_text())?, id);
            assert_eq!(id.hex().len(), 64);
            for (index, part) in bytes.chunks(PART_BYTES).enumerate() {
                list.verify_part(index as u32, part)?;
            }
            // The builder gives the same list.
            let mut builder = HashListBuilder::default();
            for part in bytes.chunks(PART_BYTES) {
                builder.push(part)?;
            }
            assert_eq!(builder.finish()?, list);
        }
        // Known answer: the empty blob is the hash of the domain and eight zero bytes.
        let empty = HashList::of(&[])?.id();
        assert_eq!(*empty.as_bytes(), crypto::sha256_parts(&[ID_DOMAIN, &[0u8; 8]]));
        Ok(())
    }

    #[test]
    fn forged_lists_and_parts_are_refused() -> CoreResult<()> {
        let bytes = data(3 * PART_BYTES + 5);
        let list = HashList::of(&bytes)?;
        let id = list.id();
        // Another size with the same hashes, a swapped or changed hash: another ID.
        let mut swapped = list.hashes().to_vec();
        swapped.swap(0, 1);
        let mut changed = list.hashes().to_vec();
        changed[3][0] ^= 1;
        for forged in [HashList::new(list.size() - 1, list.hashes().to_vec())?, HashList::new(list.size(), swapped)?] {
            assert!(forged.check(&id).is_err());
        }
        assert!(HashList::new(list.size(), changed)?.check(&id).is_err());
        // Wrong number of hashes for the size.
        assert!(HashList::new(list.size(), list.hashes()[..3].to_vec()).is_err());
        assert!(HashList::new(0, vec![[0u8; 32]]).is_err());
        // Parts: changed byte, wrong length, wrong index, no such part.
        let mut part = bytes[..PART_BYTES].to_vec();
        part[7] ^= 1;
        assert!(list.verify_part(0, &part).is_err());
        assert!(list.verify_part(0, &bytes[..PART_BYTES - 1]).is_err());
        assert!(list.verify_part(1, &bytes[..PART_BYTES]).is_err());
        assert!(list.verify_part(4, b"x").is_err());
        assert!(list.verify_part(3, &bytes[3 * PART_BYTES..]).is_ok());
        // Builder: a short part in the middle, an empty part.
        let mut builder = HashListBuilder::default();
        builder.push(&bytes[..10])?;
        assert!(builder.push(&bytes[..PART_BYTES]).is_err());
        assert!(HashListBuilder::default().push(&[]).is_err());
        // IDs: only canonical Base64url of 32 bytes.
        assert!(BlobId::parse("abc").is_err());
        assert!(BlobId::parse(&b64(&[1u8; 31])).is_err());
        assert!(BlobId::parse(&format!("{}=", id.to_text())).is_err());
        Ok(())
    }
}
