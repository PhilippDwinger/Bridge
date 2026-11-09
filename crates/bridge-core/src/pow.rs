//! Proof-of-work puzzles (docs/04 §8, ADR 0007: optional / under load only). A node issues a signed puzzle; the
//! client finds an 8-byte `c` so that `SHA-256(JCS(puzzle) ‖ c)` has at least `bits` leading zero bits.
//! Each puzzle is valid once (the node remembers it) and only briefly.

use rand_core::{CryptoRng, RngCore};
use serde_json::{Map, Value, json};

use crate::crypto;
use crate::encoding::{b64, b64_fixed};
use crate::error::{CoreError, CoreResult};
use crate::id::Id;
use crate::json::{canonical, canonical_without, parse_strict};
use crate::keys::{Identity, KeyCard};
use crate::{PROTOCOL_VERSION, field_i64, field_str};

/// Highest difficulty a node may ask for (about 270 million hashes on average).
pub const MAX_POW_BITS: u32 = 28;
/// Lifetime of a puzzle: 2 minutes.
pub const POW_LIFETIME_MS: i64 = 2 * 60 * 1000;
/// Maximum size of a puzzle in bytes.
pub const MAX_PUZZLE_BYTES: usize = 1024;

const DOMAIN: &str = "pow";

/// A puzzle whose form has been checked.
#[derive(Debug, Clone, PartialEq)]
pub struct Puzzle {
    raw: Map<String, Value>,
    canonical: Vec<u8>,
    node: Id,
    bits: u32,
    exp: i64,
    signature: [u8; 64],
}

impl Puzzle {
    /// Issues a new puzzle (node side).
    pub fn issue<R: RngCore + CryptoRng>(node: &Identity, bits: u32, now_ms: i64, rng: &mut R) -> CoreResult<Self> {
        if bits > MAX_POW_BITS {
            return Err(CoreError::format("bits: too high"));
        }
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);
        let mut raw = Map::new();
        raw.insert("v".into(), json!(PROTOCOL_VERSION));
        raw.insert("t".into(), json!("pow"));
        raw.insert("node".into(), json!(node.id().as_str()));
        raw.insert("nonce".into(), json!(b64(&nonce)));
        raw.insert("bits".into(), json!(bits));
        raw.insert("exp".into(), json!(now_ms.saturating_add(POW_LIFETIME_MS)));
        let signature = node.sign_canonical(DOMAIN, &canonical(&Value::Object(raw.clone()))?);
        raw.insert("sig".into(), json!(b64(&signature)));
        Self::from_value(Value::Object(raw))
    }

    /// Parses bytes (size first) and checks the form.
    pub fn parse(bytes: &[u8]) -> CoreResult<Self> {
        Self::from_value(parse_strict(bytes, MAX_PUZZLE_BYTES)?)
    }

    /// Checks the form of a puzzle given as JSON value.
    pub fn from_value(value: Value) -> CoreResult<Self> {
        let Value::Object(raw) = value else {
            return Err(CoreError::format("puzzle: not an object"));
        };
        if field_i64(&raw, "v")? != PROTOCOL_VERSION || field_str(&raw, "t")? != "pow" {
            return Err(CoreError::format("puzzle: wrong version or type"));
        }
        let bits = u32::try_from(field_i64(&raw, "bits")?).map_err(|_| CoreError::format("bits: out of range"))?;
        if bits > MAX_POW_BITS {
            return Err(CoreError::format("bits: too high"));
        }
        b64_fixed::<16>(field_str(&raw, "nonce")?, "nonce")?;
        Ok(Self {
            canonical: canonical(&Value::Object(raw.clone()))?,
            node: Id::parse(field_str(&raw, "node")?)?,
            bits,
            exp: field_i64(&raw, "exp")?,
            signature: b64_fixed::<64>(field_str(&raw, "sig")?, "sig")?,
            raw,
        })
    }

    /// Verifies that the node (its verified key card) issued this puzzle (client side).
    pub fn verify(&self, node: &KeyCard) -> CoreResult<()> {
        if node.id() != &self.node {
            return Err(CoreError::BadSignature);
        }
        crypto::verify(node.sign_public(), DOMAIN, &canonical_without(&self.raw, &["sig"])?, &self.signature)
    }

    /// Checks a solution (node side; the node also makes sure each puzzle is used only once).
    pub fn check_solution(&self, solution: &[u8; 8], now_ms: i64) -> CoreResult<()> {
        if now_ms >= self.exp {
            return Err(CoreError::Expired);
        }
        if crypto::leading_zero_bits(&crypto::sha256_parts(&[&self.canonical, solution])) < self.bits {
            return Err(CoreError::PowRequired);
        }
        Ok(())
    }

    /// Searches a solution with at most `max_tries` hashes (client side). `None` if not found.
    #[must_use]
    pub fn solve(&self, max_tries: u64) -> Option<[u8; 8]> {
        (0..max_tries).map(u64::to_be_bytes).find(|candidate| {
            crypto::leading_zero_bits(&crypto::sha256_parts(&[&self.canonical, candidate])) >= self.bits
        })
    }

    /// Difficulty.
    #[must_use]
    pub fn bits(&self) -> u32 {
        self.bits
    }
    /// End of validity (ms).
    #[must_use]
    pub fn expires_at(&self) -> i64 {
        self.exp
    }
    /// The puzzle as JSON value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Object(self.raw.clone())
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;
    use crate::keys::Role;

    #[test]
    fn issue_solve_check() -> CoreResult<()> {
        let node = Identity::generate(&mut OsRng);
        let card = node.key_card(Role::Node, None, 0)?;
        let puzzle = Puzzle::issue(&node, 12, 1_000, &mut OsRng)?;
        let received = Puzzle::parse(&canonical(&puzzle.to_value())?)?;
        received.verify(&card)?;
        let solution = received.solve(1 << 22).ok_or(CoreError::PowRequired)?;
        puzzle.check_solution(&solution, 1_000)?;
        assert_eq!(puzzle.check_solution(&solution, 1_000 + POW_LIFETIME_MS), Err(CoreError::Expired));
        Ok(())
    }

    #[test]
    fn wrong_solution_and_forged_puzzle_fail() -> CoreResult<()> {
        let node = Identity::generate(&mut OsRng);
        let card = node.key_card(Role::Node, None, 0)?;
        let puzzle = Puzzle::issue(&node, 20, 0, &mut OsRng)?;
        // A random guess passes 20 bits only with probability 1 / 1,000,000; try a few known-bad ones.
        let wrong = (0u64..16).map(u64::to_be_bytes).filter(|c| puzzle.check_solution(c, 0).is_err()).count();
        assert!(wrong >= 15);
        // Easier puzzle with the same signature: detected.
        let mut easier = puzzle.to_value();
        easier["bits"] = json!(1);
        assert_eq!(Puzzle::from_value(easier)?.verify(&card), Err(CoreError::BadSignature));
        assert!(Puzzle::issue(&node, MAX_POW_BITS + 1, 0, &mut OsRng).is_err());
        let mut too_hard = puzzle.to_value();
        too_hard["bits"] = json!(200);
        assert!(Puzzle::from_value(too_hard).is_err());
        Ok(())
    }

    #[test]
    fn zero_bits_needs_no_work() -> CoreResult<()> {
        let node = Identity::generate(&mut OsRng);
        let puzzle = Puzzle::issue(&node, 0, 0, &mut OsRng)?;
        assert_eq!(puzzle.solve(1), Some([0u8; 8]));
        Ok(())
    }
}
