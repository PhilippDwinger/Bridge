//! Streams for large data (docs/04 §6). A stream is a head envelope (content type `stream`, carrying the secret
//! [`StreamTicket`]) plus parts of 64 KiB. Each part is encrypted with the stream's own random key; the nonce is the
//! random prefix plus the part number, and the part number and the "last" flag are bound in the associated data -
//! parts can be neither reordered, nor cut off, nor moved into another stream.
//!
//! N1 (ADR 0008): the content key is created here only, new for every stream; part numbers strictly increase.

use rand_core::{CryptoRng, RngCore};
use serde_json::{Map, Value, json};

use crate::content::{Content, ContentType, Payload, StreamTicket};
use crate::crypto::{self, Hasher, SecretKey};
use crate::encoding::{b64, b64_fixed, b64_var};
use crate::envelope::{Address, Envelope};
use crate::error::{CoreError, CoreResult};
use crate::json::{canonical, parse_strict};
use crate::keys::Identity;
use crate::{PROTOCOL_VERSION, field_i64, field_str};

/// Plaintext bytes per part (all parts but the last have exactly this size).
pub const PART_BYTES: usize = 64 * 1024;
/// Maximum number of parts of one stream.
pub const MAX_PARTS: u32 = 65_536;
/// Maximum size of a stream (4 GiB).
pub const MAX_STREAM_BYTES: u64 = PART_BYTES as u64 * MAX_PARTS as u64;
/// Maximum size of one part object in bytes.
pub const MAX_PART_OBJECT_BYTES: usize = 96 * 1024;

const PART_AAD: &[u8] = b"bridge4/part/v1";

/// Number of parts for `size` bytes: `max(1, ceil(size / PART_BYTES))`.
#[must_use]
pub fn parts_for(size: u64) -> u32 {
    let parts = size.div_ceil(PART_BYTES as u64).max(1);
    u32::try_from(parts).unwrap_or(u32::MAX)
}

/// One encrypted part (form checked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    sid: [u8; 16],
    index: u32,
    last: bool,
    ciphertext: Vec<u8>,
}

impl Part {
    /// Parses bytes (size first) and checks the form.
    pub fn parse(bytes: &[u8]) -> CoreResult<Self> {
        Self::from_value(parse_strict(bytes, MAX_PART_OBJECT_BYTES)?)
    }

    /// Checks the form of a part given as JSON value.
    pub fn from_value(value: Value) -> CoreResult<Self> {
        let Value::Object(raw) = value else {
            return Err(CoreError::format("part: not an object"));
        };
        if field_i64(&raw, "v")? != PROTOCOL_VERSION || field_str(&raw, "t")? != "part" {
            return Err(CoreError::format("part: wrong version or type"));
        }
        let index = u32::try_from(field_i64(&raw, "i")?).map_err(|_| CoreError::format("i: out of range"))?;
        if index >= MAX_PARTS {
            return Err(CoreError::format("i: out of range"));
        }
        let last = raw.get("last").and_then(Value::as_bool).ok_or_else(|| CoreError::format("last: not a bool"))?;
        let ciphertext = b64_var(field_str(&raw, "ct")?, "ct", PART_BYTES + 16)?;
        if ciphertext.len() < 16 {
            return Err(CoreError::format("ct: too short"));
        }
        Ok(Self { sid: b64_fixed::<16>(field_str(&raw, "sid")?, "sid")?, index, last, ciphertext })
    }

    /// The part as JSON value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut raw = Map::new();
        raw.insert("v".into(), json!(PROTOCOL_VERSION));
        raw.insert("t".into(), json!("part"));
        raw.insert("sid".into(), json!(b64(&self.sid)));
        raw.insert("i".into(), json!(self.index));
        raw.insert("last".into(), json!(self.last));
        raw.insert("ct".into(), json!(b64(&self.ciphertext)));
        Value::Object(raw)
    }

    /// Canonical bytes (what travels).
    pub fn to_bytes(&self) -> CoreResult<Vec<u8>> {
        canonical(&self.to_value())
    }

    /// The stream (ID of the head envelope).
    #[must_use]
    pub fn sid(&self) -> &[u8; 16] {
        &self.sid
    }
    /// Part number.
    #[must_use]
    pub fn index(&self) -> u32 {
        self.index
    }
    /// Last part?
    #[must_use]
    pub fn is_last(&self) -> bool {
        self.last
    }
    /// Size of the encrypted part.
    #[must_use]
    pub fn ciphertext_len(&self) -> usize {
        self.ciphertext.len()
    }

    #[cfg(test)]
    pub(crate) fn ciphertext_mut(&mut self) -> &mut Vec<u8> {
        &mut self.ciphertext
    }
}

fn nonce(prefix: &[u8; 8], index: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(prefix);
    nonce[8..].copy_from_slice(&index.to_be_bytes());
    nonce
}

fn aad(sid: &[u8; 16], index: u32, last: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(PART_AAD.len() + 21);
    aad.extend_from_slice(PART_AAD);
    aad.extend_from_slice(sid);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(u8::from(last));
    aad
}

fn expected_len(size: u64, parts: u32, index: u32) -> usize {
    if index + 1 < parts {
        PART_BYTES
    } else {
        usize::try_from(size - u64::from(parts - 1) * PART_BYTES as u64).unwrap_or(usize::MAX)
    }
}

/// Encrypts the parts of one stream, in order.
pub struct StreamSealer {
    key: SecretKey,
    prefix: [u8; 8],
    sid: [u8; 16],
    size: u64,
    parts: u32,
    next: u32,
}

impl StreamSealer {
    /// Creates the head envelope for `size` bytes with SHA-256 `hash` and a sealer for the parts.
    pub fn start<R: RngCore + CryptoRng>(
        sender: &Identity,
        address: &Address<'_>,
        ctype: &str,
        size: u64,
        hash: [u8; 32],
        rng: &mut R,
    ) -> CoreResult<(Envelope, Self)> {
        if size > MAX_STREAM_BYTES {
            return Err(CoreError::TooLarge("stream".into()));
        }
        let key = crypto::random_key(rng);
        let mut prefix = [0u8; 8];
        rng.fill_bytes(&mut prefix);
        let parts = parts_for(size);
        let ticket = StreamTicket { key: key.clone(), prefix, size, parts, hash };
        let content = Content {
            kind: ContentType::Stream,
            ctype: ctype.into(),
            payload: Payload::Stream(ticket),
            reply: None,
            card: None,
        };
        let head = Envelope::seal(sender, address, &content.to_bytes()?, rng)?;
        let sid = *head.id();
        Ok((head, Self { key, prefix, sid, size, parts, next: 0 }))
    }

    /// Encrypts the next part. Every part but the last must be exactly [`PART_BYTES`] long.
    pub fn seal_next(&mut self, chunk: &[u8]) -> CoreResult<Part> {
        if self.next >= self.parts {
            return Err(CoreError::format("stream: all parts already sealed"));
        }
        let index = self.next;
        if chunk.len() != expected_len(self.size, self.parts, index) {
            return Err(CoreError::format("stream: wrong part size"));
        }
        let last = index + 1 == self.parts;
        let ciphertext =
            crypto::aead_seal(&self.key, &nonce(&self.prefix, index), chunk, &aad(&self.sid, index, last))?;
        self.next += 1;
        Ok(Part { sid: self.sid, index, last, ciphertext })
    }

    /// All parts sealed?
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.next == self.parts
    }
}

/// Seals data that is already in memory: head envelope + all parts.
pub fn seal_stream<R: RngCore + CryptoRng>(
    sender: &Identity,
    address: &Address<'_>,
    ctype: &str,
    data: &[u8],
    rng: &mut R,
) -> CoreResult<(Envelope, Vec<Part>)> {
    let size = u64::try_from(data.len()).map_err(|_| CoreError::TooLarge("stream".into()))?;
    let (head, mut sealer) = StreamSealer::start(sender, address, ctype, size, crypto::sha256(data), rng)?;
    let mut parts = Vec::with_capacity(sealer.parts as usize);
    if data.is_empty() {
        parts.push(sealer.seal_next(&[])?);
    }
    for chunk in data.chunks(PART_BYTES) {
        parts.push(sealer.seal_next(chunk)?);
    }
    Ok((head, parts))
}

/// Opens the parts of one stream, in order, and checks size and hash at the end.
pub struct StreamOpener {
    key: SecretKey,
    prefix: [u8; 8],
    sid: [u8; 16],
    size: u64,
    parts: u32,
    hash: [u8; 32],
    next: u32,
    hasher: Hasher,
}

impl StreamOpener {
    /// From an opened head envelope and its content.
    pub fn new(head: &Envelope, content: &Content) -> CoreResult<Self> {
        let Payload::Stream(ticket) = &content.payload else {
            return Err(CoreError::format("not a stream head"));
        };
        Ok(Self {
            key: ticket.key.clone(),
            prefix: ticket.prefix,
            sid: *head.id(),
            size: ticket.size,
            parts: ticket.parts,
            hash: ticket.hash,
            next: 0,
            hasher: Hasher::default(),
        })
    }

    /// Decrypts the next part (must be the expected one).
    pub fn open_next(&mut self, part: &Part) -> CoreResult<Vec<u8>> {
        if part.sid != self.sid || part.index != self.next || self.next >= self.parts {
            return Err(CoreError::format("stream: unexpected part"));
        }
        let last = part.index + 1 == self.parts;
        if part.last != last {
            return Err(CoreError::CannotOpen);
        }
        let plain = crypto::aead_open(
            &self.key,
            &nonce(&self.prefix, part.index),
            &part.ciphertext,
            &aad(&self.sid, part.index, last),
        )?;
        if plain.len() != expected_len(self.size, self.parts, part.index) {
            return Err(CoreError::CannotOpen);
        }
        self.hasher.update(&plain);
        self.next += 1;
        Ok(plain)
    }

    /// Call after the last part: checks that all parts arrived and the hash matches.
    pub fn finish(self) -> CoreResult<()> {
        if self.next != self.parts || self.hasher.finish() != self.hash {
            return Err(CoreError::CannotOpen);
        }
        Ok(())
    }
}

/// Opens a complete stream in memory. `max_bytes` protects the caller's memory.
pub fn open_stream(head: &Envelope, content: &Content, parts: &[Part], max_bytes: u64) -> CoreResult<Vec<u8>> {
    let mut opener = StreamOpener::new(head, content)?;
    if opener.size > max_bytes {
        return Err(CoreError::TooLarge("stream".into()));
    }
    let mut data = Vec::with_capacity(usize::try_from(opener.size).unwrap_or(0));
    for part in parts {
        data.extend_from_slice(&opener.open_next(part)?);
    }
    opener.finish()?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;
    use crate::keys::{KeyCard, Role};
    use crate::{Id, Kind};

    struct Setup {
        alice: Identity,
        alice_card: KeyCard,
        bob: Identity,
        bob_card: KeyCard,
        net: Id,
    }

    fn setup() -> CoreResult<Setup> {
        let alice = Identity::generate(&mut OsRng);
        let bob = Identity::generate(&mut OsRng);
        Ok(Setup {
            alice_card: alice.key_card(Role::Client, None, 0)?,
            bob_card: bob.key_card(Role::Client, None, 0)?,
            net: Identity::generate(&mut OsRng).id().clone(),
            alice,
            bob,
        })
    }

    fn send(s: &Setup, data: &[u8]) -> CoreResult<(Envelope, Vec<Part>)> {
        let address = Address { net: &s.net, to: &s.bob_card, kind: Kind::Msg, iat: 0, ttl: 600 };
        seal_stream(&s.alice, &address, "application/octet-stream", data, &mut OsRng)
    }

    fn receive(s: &Setup, head: &Envelope, parts: &[Part]) -> CoreResult<Vec<u8>> {
        let content = Content::parse(&head.open(&s.bob, &s.alice_card)?)?;
        open_stream(head, &content, parts, MAX_STREAM_BYTES)
    }

    #[test]
    fn roundtrip_sizes() -> CoreResult<()> {
        let s = setup()?;
        for size in [0usize, 1, PART_BYTES - 1, PART_BYTES, PART_BYTES + 1, 3 * PART_BYTES + 17] {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let (head, parts) = send(&s, &data)?;
            assert_eq!(parts.len() as u32, parts_for(size as u64));
            let parts: Vec<Part> = parts.iter().map(|p| Part::parse(&p.to_bytes()?)).collect::<CoreResult<_>>()?;
            assert_eq!(receive(&s, &head, &parts)?, data, "size {size}");
        }
        Ok(())
    }

    #[test]
    fn reorder_cut_swap_and_tamper_are_detected() -> CoreResult<()> {
        let s = setup()?;
        let data = vec![7u8; 3 * PART_BYTES];
        let (head, parts) = send(&s, &data)?;
        // reorder
        let swapped = vec![parts[1].clone(), parts[0].clone(), parts[2].clone()];
        assert!(receive(&s, &head, &swapped).is_err());
        // cut off
        assert!(receive(&s, &head, &parts[..2]).is_err());
        // renumbered part (index changed in the clear) fails the AEAD
        let mut renumbered = parts.clone();
        renumbered[1].index = 0;
        assert!(receive(&s, &head, &renumbered).is_err());
        // fake "last" flag on an earlier part
        let mut fake_last = parts[..2].to_vec();
        fake_last[1].last = true;
        assert!(receive(&s, &head, &fake_last).is_err());
        // a part from another stream (same sizes, same sender)
        let (_, other) = send(&s, &data)?;
        let mut mixed = parts.clone();
        mixed[1] = Part { sid: parts[1].sid, ..other[1].clone() };
        assert!(receive(&s, &head, &mixed).is_err());
        // a flipped bit
        let mut flipped = parts.clone();
        flipped[2].ciphertext_mut()[5] ^= 1;
        assert!(receive(&s, &head, &flipped).is_err());
        // untouched: fine
        assert_eq!(receive(&s, &head, &parts)?, data);
        Ok(())
    }

    #[test]
    fn sealer_enforces_sizes_and_order() -> CoreResult<()> {
        let s = setup()?;
        let address = Address { net: &s.net, to: &s.bob_card, kind: Kind::Msg, iat: 0, ttl: 600 };
        let (_, mut sealer) = StreamSealer::start(&s.alice, &address, "x/y", 100, [0u8; 32], &mut OsRng)?;
        assert!(sealer.seal_next(&[0u8; 99]).is_err());
        sealer.seal_next(&[0u8; 100])?;
        assert!(sealer.is_done());
        assert!(sealer.seal_next(&[0u8; 100]).is_err(), "no part after the last");
        assert!(StreamSealer::start(&s.alice, &address, "x/y", MAX_STREAM_BYTES + 1, [0u8; 32], &mut OsRng).is_err());
        Ok(())
    }

    #[test]
    fn wrong_hash_in_head_is_detected() -> CoreResult<()> {
        let s = setup()?;
        let address = Address { net: &s.net, to: &s.bob_card, kind: Kind::Msg, iat: 0, ttl: 600 };
        let (head, mut sealer) = StreamSealer::start(&s.alice, &address, "x/y", 3, [9u8; 32], &mut OsRng)?;
        let part = sealer.seal_next(b"abc")?;
        assert_eq!(receive(&s, &head, &[part]), Err(CoreError::CannotOpen));
        Ok(())
    }

    #[test]
    fn content_keys_and_prefixes_never_repeat() -> CoreResult<()> {
        let s = setup()?;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..500 {
            let (head, _) = send(&s, b"x")?;
            let content = Content::parse(&head.open(&s.bob, &s.alice_card)?)?;
            let Payload::Stream(ticket) = content.payload else {
                return Err(CoreError::format("no ticket"));
            };
            assert!(seen.insert((*ticket.key, ticket.prefix)));
        }
        Ok(())
    }
}
