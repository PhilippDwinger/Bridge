//! Merkle tree of the transparency log, exactly as RFC 6962 §2.1 (algorithms for verification from RFC 9162 §2.1):
//! leaf = SHA-256(0x00 ‖ entry), node = SHA-256(0x01 ‖ left ‖ right), empty tree = SHA-256("").
//!
//! - Inclusion proof: entry `index` is in the tree of size `size`.
//! - Consistency proof: the tree of size `m` is a prefix of the tree of size `n`.
//!
//! [`Tree`] keeps the hash of every complete, aligned subtree (level 0 = leaves, level h = subtrees of 2^h leaves;
//! about 2n hashes, append-only). Every RFC 6962 subtree that a root or proof needs is either such a complete
//! subtree or splits into one complete subtree and a right edge, so roots of prefixes, inclusion and consistency
//! proofs cost O(log n) hash operations, never O(n) (unauthenticated endpoints serve them, docs/06 §9). Levels are
//! stored in shared, frozen chunks: a clone (snapshot) of a large tree is cheap and can be worked on outside locks.
//!
//! Verification never panics and rejects every malformed input (index ≥ size, m > n, too long or too short proofs).
//! For `m == 0` the consistency proof is empty and only valid with the empty root (every tree extends the empty
//! tree); for `m == n` it is empty and the roots must be equal (RFC 9162 §2.1.4).

use std::sync::Arc;

use bridge_core::crypto::{sha256, sha256_parts};

use crate::error::{NetError, NetResult};

/// A SHA-256 hash.
pub type Hash = [u8; 32];

/// Largest tree size (formal bound, far beyond any real log).
pub const MAX_TREE_SIZE: u64 = 1 << 32;
/// Longest accepted proof (real proofs for trees up to 2^32 entries have at most 33 hashes).
pub const MAX_PROOF_HASHES: usize = 64;
/// Hashes per frozen chunk of a tree level (chunks are shared between snapshots).
const CHUNK: usize = 256;

#[cfg(test)]
thread_local! {
    /// Test instrumentation: inner node hashes computed on this thread.
    static NODE_HASHES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Hash of a leaf: SHA-256(0x00 ‖ data).
#[must_use]
pub fn leaf_hash(data: &[u8]) -> Hash {
    sha256_parts(&[&[0x00], data])
}

/// Hash of an inner node: SHA-256(0x01 ‖ left ‖ right).
#[must_use]
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    #[cfg(test)]
    NODE_HASHES.with(|count| count.set(count.get() + 1));
    sha256_parts(&[&[0x01], left, right])
}

/// Root of the empty tree: SHA-256("").
#[must_use]
pub fn empty_root() -> Hash {
    sha256(b"")
}

/// Merkle Tree Hash over leaf hashes (RFC 6962 §2.1). O(n), no recursion: complete subtrees are merged on a stack
/// (left subtree = largest power of two), then folded from the right. For a prefix of a log use [`Tree::root_at`].
#[must_use]
pub fn root(leaves: &[Hash]) -> Hash {
    let mut stack: Vec<(u32, Hash)> = Vec::new();
    for leaf in leaves {
        let (mut height, mut hash) = (0u32, *leaf);
        while let Some(&(top, left)) = stack.last() {
            if top != height {
                break;
            }
            stack.pop();
            hash = node_hash(&left, &hash);
            height += 1;
        }
        stack.push((height, hash));
    }
    let mut subtrees = stack.iter().rev();
    let Some(&(_, mut hash)) = subtrees.next() else {
        return empty_root();
    };
    for (_, left) in subtrees {
        hash = node_hash(left, &hash);
    }
    hash
}

/// Checks an inclusion proof (RFC 9162 §2.1.3.2).
#[must_use]
pub fn verify_inclusion(leaf: &Hash, index: u64, size: u64, proof: &[Hash], root: &Hash) -> bool {
    if index >= size || size > MAX_TREE_SIZE || proof.len() > MAX_PROOF_HASHES {
        return false;
    }
    let (mut fnode, mut snode) = (index, size - 1);
    let mut hash = *leaf;
    for sibling in proof {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            hash = node_hash(sibling, &hash);
            while fnode & 1 == 0 && fnode != 0 {
                fnode >>= 1;
                snode >>= 1;
            }
        } else {
            hash = node_hash(&hash, sibling);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && hash == *root
}

/// Checks a consistency proof (RFC 9162 §2.1.4.2).
#[must_use]
pub fn verify_consistency(m: u64, n: u64, root_m: &Hash, root_n: &Hash, proof: &[Hash]) -> bool {
    if m > n || n > MAX_TREE_SIZE || proof.len() > MAX_PROOF_HASHES {
        return false;
    }
    if m == n {
        return proof.is_empty() && root_m == root_n;
    }
    if m == 0 {
        return proof.is_empty() && *root_m == empty_root();
    }
    // 0 < m < n: the proof can never be empty.
    let seed: &[Hash] = if m.is_power_of_two() { std::slice::from_ref(root_m) } else { &[] };
    let mut path = seed.iter().chain(proof.iter());
    let Some(first) = path.next() else {
        return false;
    };
    let (mut fnode, mut snode) = (m - 1, n - 1);
    while fnode & 1 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }
    let (mut first_root, mut second_root) = (*first, *first);
    for hash in path {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            first_root = node_hash(hash, &first_root);
            second_root = node_hash(hash, &second_root);
            while fnode & 1 == 0 && fnode != 0 {
                fnode >>= 1;
                snode >>= 1;
            }
        } else {
            second_root = node_hash(&second_root, hash);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    first_root == *root_m && second_root == *root_n && snode == 0
}

/// Largest power of two strictly below `n` (n ≥ 2).
fn split_point(n: u64) -> u64 {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// One level of the tree: the hashes of all complete subtrees of one height, in order. Full chunks are frozen and
/// shared (a clone copies at most one chunk of hashes per level plus the chunk pointers).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Level {
    frozen: Vec<Arc<[Hash]>>,
    tail: Vec<Hash>,
}

impl Level {
    fn get(&self, index: u64) -> Option<&Hash> {
        let index = usize::try_from(index).ok()?;
        let (chunk, offset) = (index / CHUNK, index % CHUNK);
        match self.frozen.get(chunk) {
            Some(frozen) => frozen.get(offset),
            None if chunk == self.frozen.len() => self.tail.get(offset),
            None => None,
        }
    }

    fn push(&mut self, hash: Hash) {
        self.tail.push(hash);
        if self.tail.len() >= CHUNK {
            let full = std::mem::replace(&mut self.tail, Vec::with_capacity(CHUNK));
            self.frozen.push(Arc::from(full));
        }
    }
}

/// The Merkle tree of a log (capped at [`MAX_TREE_SIZE`] leaves): hashes of all complete subtrees, see module docs.
/// Cheap to clone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tree {
    size: u64,
    /// `levels[h]` holds the subtrees of 2^h leaves; `levels[0]` the leaves.
    levels: Vec<Level>,
}

impl Tree {
    /// An empty tree.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a leaf hash; returns its index. Amortized O(1).
    pub fn push(&mut self, leaf: Hash) -> NetResult<u64> {
        let index = self.size;
        if index >= MAX_TREE_SIZE {
            return Err(NetError::quota("tree full"));
        }
        let (mut height, mut position, mut hash) = (0usize, index, leaf);
        loop {
            if self.levels.len() <= height {
                self.levels.push(Level::default());
            }
            let level = self.levels.get_mut(height).ok_or_else(|| NetError::quota("tree"))?;
            level.push(hash);
            if position & 1 == 0 {
                break;
            }
            // This subtree completes a pair: its parent is complete too.
            let left = *level.get(position - 1).ok_or_else(|| NetError::quota("tree"))?;
            hash = node_hash(&left, &hash);
            height += 1;
            position >>= 1;
        }
        self.size = index + 1;
        Ok(index)
    }

    /// Adds an entry (hashes it as a leaf); returns its index.
    pub fn push_entry(&mut self, data: &[u8]) -> NetResult<u64> {
        self.push(leaf_hash(data))
    }

    /// Number of leaves.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Root of the whole tree (O(log n)).
    #[must_use]
    pub fn root(&self) -> Hash {
        self.root_at(self.size).unwrap_or_else(|_| empty_root())
    }

    /// Root of the first `m` leaves (O(log n)); `m` must not exceed the size.
    pub fn root_at(&self, m: u64) -> NetResult<Hash> {
        self.check_size(m)?;
        if m == 0 {
            return Ok(empty_root());
        }
        self.subtree(0, m)
    }

    /// Inclusion proof (RFC 6962 `PATH`) for leaf `index` in the tree of size `size`, deepest sibling first.
    pub fn inclusion(&self, index: u64, size: u64) -> NetResult<Vec<Hash>> {
        self.check_size(size)?;
        if index >= size {
            return Err(NetError::format("inclusion: index must be below size"));
        }
        let mut proof = Vec::new();
        self.path(index, 0, size, &mut proof)?;
        Ok(proof)
    }

    /// Consistency proof (RFC 6962 `PROOF(m, D[n])`) from size `m` to size `n`. Empty for `m == 0` and `m == n`.
    pub fn consistency(&self, m: u64, n: u64) -> NetResult<Vec<Hash>> {
        self.check_size(n)?;
        if m > n {
            return Err(NetError::format("consistency: m must not exceed n"));
        }
        let mut proof = Vec::new();
        if m == 0 || m == n {
            return Ok(proof);
        }
        self.subproof(m, 0, n, true, &mut proof)?;
        Ok(proof)
    }

    fn check_size(&self, size: u64) -> NetResult<()> {
        if size > self.size {
            return Err(NetError::format("tree: size beyond the known leaves"));
        }
        Ok(())
    }

    /// RFC 6962 MTH of the leaves `[lo, hi)` (0 ≤ lo < hi ≤ size): a stored complete subtree when the range is
    /// one, else split at the largest power of two below its length. For the ranges roots and proofs ask for (lo
    /// aligned to the split), the left part is always stored, so this is O(log n).
    fn subtree(&self, lo: u64, hi: u64) -> NetResult<Hash> {
        let length = hi.saturating_sub(lo);
        if length == 0 || hi > self.size {
            return Err(NetError::format("tree: empty or unknown range"));
        }
        if length.is_power_of_two() && lo % length == 0 {
            let height = length.trailing_zeros() as usize;
            return self
                .levels
                .get(height)
                .and_then(|level| level.get(lo / length))
                .copied()
                .ok_or_else(|| NetError::format("tree: missing subtree"));
        }
        let k = split_point(length);
        Ok(node_hash(&self.subtree(lo, lo + k)?, &self.subtree(lo + k, hi)?))
    }

    /// RFC 6962 `PATH(index, D[lo:hi])`. Recursion depth ≤ log2(n) + 1.
    fn path(&self, index: u64, lo: u64, hi: u64, proof: &mut Vec<Hash>) -> NetResult<()> {
        if hi - lo <= 1 {
            return Ok(());
        }
        let k = split_point(hi - lo);
        if index < lo + k {
            self.path(index, lo, lo + k, proof)?;
            proof.push(self.subtree(lo + k, hi)?);
        } else {
            self.path(index, lo + k, hi, proof)?;
            proof.push(self.subtree(lo, lo + k)?);
        }
        Ok(())
    }

    /// RFC 6962 `SUBPROOF(m, D[lo:hi], complete)` for lo < m ≤ hi (m counts leaves from the start of the tree).
    fn subproof(&self, m: u64, lo: u64, hi: u64, complete: bool, proof: &mut Vec<Hash>) -> NetResult<()> {
        if m >= hi {
            if !complete {
                proof.push(self.subtree(lo, hi)?);
            }
            return Ok(());
        }
        let k = split_point(hi - lo);
        if m <= lo + k {
            self.subproof(m, lo, lo + k, complete, proof)?;
            proof.push(self.subtree(lo + k, hi)?);
        } else {
            self.subproof(m, lo + k, hi, false, proof)?;
            proof.push(self.subtree(lo, lo + k)?);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Straightforward reference implementation on raw data, written directly from the RFC 6962 definitions.
    fn ref_mth(data: &[Vec<u8>]) -> Hash {
        match data.len() {
            0 => sha256(b""),
            1 => sha256_parts(&[&[0], &data[0]]),
            n => {
                let mut k = 1;
                while k * 2 < n {
                    k *= 2;
                }
                sha256_parts(&[&[1], &ref_mth(&data[..k]), &ref_mth(&data[k..])])
            }
        }
    }

    fn ref_path(m: usize, data: &[Vec<u8>]) -> Vec<Hash> {
        let n = data.len();
        if n <= 1 {
            return Vec::new();
        }
        let mut k = 1;
        while k * 2 < n {
            k *= 2;
        }
        if m < k {
            let mut proof = ref_path(m, &data[..k]);
            proof.push(ref_mth(&data[k..]));
            proof
        } else {
            let mut proof = ref_path(m - k, &data[k..]);
            proof.push(ref_mth(&data[..k]));
            proof
        }
    }

    fn ref_subproof(m: usize, data: &[Vec<u8>], complete: bool) -> Vec<Hash> {
        let n = data.len();
        if m == n {
            return if complete { Vec::new() } else { vec![ref_mth(data)] };
        }
        let mut k = 1;
        while k * 2 < n {
            k *= 2;
        }
        if m <= k {
            let mut proof = ref_subproof(m, &data[..k], complete);
            proof.push(ref_mth(&data[k..]));
            proof
        } else {
            let mut proof = ref_subproof(m - k, &data[k..], false);
            proof.push(ref_mth(&data[..k]));
            proof
        }
    }

    fn data(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("entry {i}").into_bytes()).collect()
    }

    fn tree_of(data: &[Vec<u8>]) -> NetResult<Tree> {
        let mut tree = Tree::new();
        for entry in data {
            tree.push_entry(entry)?;
        }
        Ok(tree)
    }

    fn flipped(proof: &[Hash], position: usize, bit: usize) -> Vec<Hash> {
        let mut copy = proof.to_vec();
        if let Some(hash) = copy.get_mut(position) {
            hash[bit / 8] ^= 1 << (bit % 8);
        }
        copy
    }

    #[test]
    fn known_values() -> NetResult<()> {
        // RFC 6962 / Certificate Transparency: empty tree root and leaf of an empty entry.
        let hex = |h: Hash| h.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(hex(empty_root()), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hex(leaf_hash(b"")), "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d");
        assert_eq!(Tree::new().root(), empty_root());
        assert_eq!(Tree::new().root_at(0)?, empty_root());
        Ok(())
    }

    #[test]
    fn roots_and_proofs_match_the_reference_for_all_sizes() -> NetResult<()> {
        for n in 1..=70usize {
            let data = data(n);
            let tree = tree_of(&data)?;
            let size = n as u64;
            assert_eq!(tree.root(), ref_mth(&data), "root of {n}");
            for m in 0..=n {
                let root_m = tree.root_at(m as u64)?;
                assert_eq!(root_m, ref_mth(&data[..m]), "prefix root {m} of {n}");
                // Consistency m -> n
                let proof = tree.consistency(m as u64, size)?;
                let expected = if m == 0 { Vec::new() } else { ref_subproof(m, &data, true) };
                assert_eq!(proof, expected, "consistency {m} -> {n}");
                assert!(verify_consistency(m as u64, size, &root_m, &tree.root(), &proof), "verify {m} -> {n}");
            }
            for index in 0..n {
                let proof = tree.inclusion(index as u64, size)?;
                assert_eq!(proof, ref_path(index, &data), "path {index} in {n}");
                assert!(proof.len() <= 7);
                let leaf = leaf_hash(&data[index]);
                assert!(verify_inclusion(&leaf, index as u64, size, &proof, &tree.root()), "verify {index} in {n}");
                // Every proof also works for every larger tree size (old entries stay provable).
                if n < 70 && index == 0 {
                    let bigger = tree_of(&self::data(n + 1))?;
                    let proof = bigger.inclusion(0, size)?;
                    assert!(verify_inclusion(&leaf, 0, size, &proof, &tree.root()));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn tampered_inclusion_proofs_fail() -> NetResult<()> {
        for n in [1usize, 2, 3, 5, 8, 13, 31, 32, 33] {
            let data = data(n);
            let tree = tree_of(&data)?;
            let (size, root) = (n as u64, tree.root());
            for (index, entry) in data.iter().enumerate() {
                let proof = tree.inclusion(index as u64, size)?;
                let leaf = leaf_hash(entry);
                for position in 0..proof.len() {
                    for bit in [0, 7, 100, 255] {
                        assert!(!verify_inclusion(&leaf, index as u64, size, &flipped(&proof, position, bit), &root));
                    }
                }
                let mut wrong_leaf = leaf;
                wrong_leaf[0] ^= 1;
                assert!(!verify_inclusion(&wrong_leaf, index as u64, size, &proof, &root));
                let mut wrong_root = root;
                wrong_root[31] ^= 1;
                assert!(!verify_inclusion(&leaf, index as u64, size, &proof, &wrong_root));
                // Wrong index or size, shortened or extended proof
                for other in 0..n {
                    if other != index {
                        assert!(!verify_inclusion(&leaf, other as u64, size, &proof, &root), "{index}->{other}/{n}");
                    }
                }
                // (A wrong size with the right root can still fit the proof's shape - e.g. leaf 0 of 3 vs. 4: the head
                // binds size and root together, so callers always pass a matching pair.)
                assert!(!verify_inclusion(&leaf, size, size, &proof, &root), "index == size");
                assert!(!verify_inclusion(&leaf, u64::MAX, u64::MAX, &proof, &root));
                if !proof.is_empty() {
                    assert!(!verify_inclusion(&leaf, index as u64, size, &proof[..proof.len() - 1], &root));
                }
                let mut longer = proof.clone();
                longer.push(root);
                assert!(!verify_inclusion(&leaf, index as u64, size, &longer, &root));
            }
        }
        assert!(!verify_inclusion(&[0; 32], 0, 0, &[], &[0; 32]), "empty tree has no leaves");
        assert!(!verify_inclusion(&[0; 32], 0, 2, &[[0; 32]; 65], &[0; 32]), "proof too long");
        Ok(())
    }

    #[test]
    fn tampered_consistency_proofs_fail() -> NetResult<()> {
        for n in [2usize, 3, 4, 5, 7, 8, 9, 16, 17, 33] {
            let data = data(n);
            let tree = tree_of(&data)?;
            let root_n = tree.root();
            for m in 1..n {
                let root_m = tree.root_at(m as u64)?;
                let proof = tree.consistency(m as u64, n as u64)?;
                assert!(!proof.is_empty());
                for position in 0..proof.len() {
                    for bit in [0, 9, 255] {
                        let bad = flipped(&proof, position, bit);
                        assert!(!verify_consistency(m as u64, n as u64, &root_m, &root_n, &bad), "{m}->{n}");
                    }
                }
                let mut wrong = root_m;
                wrong[0] ^= 1;
                assert!(!verify_consistency(m as u64, n as u64, &wrong, &root_n, &proof));
                let mut wrong = root_n;
                wrong[0] ^= 1;
                assert!(!verify_consistency(m as u64, n as u64, &root_m, &wrong, &proof));
                assert!(!verify_consistency(m as u64, n as u64, &root_m, &root_n, &[]), "empty proof");
                assert!(!verify_consistency(m as u64, n as u64, &root_m, &root_n, &proof[1..]));
                let mut longer = proof.clone();
                longer.push(root_n);
                assert!(!verify_consistency(m as u64, n as u64, &root_m, &root_n, &longer));
                assert!(!verify_consistency(n as u64, m as u64, &root_n, &root_m, &proof), "m > n");
            }
            // m == 0 and m == n
            assert!(verify_consistency(0, n as u64, &empty_root(), &root_n, &[]));
            assert!(!verify_consistency(0, n as u64, &root_n, &root_n, &[]));
            assert!(!verify_consistency(0, n as u64, &empty_root(), &root_n, &[root_n]));
            assert!(verify_consistency(n as u64, n as u64, &root_n, &root_n, &[]));
            assert!(!verify_consistency(n as u64, n as u64, &root_n, &empty_root(), &[]));
            assert!(!verify_consistency(n as u64, n as u64, &root_n, &root_n, &[root_n]));
        }
        assert!(!verify_consistency(1, u64::MAX, &[0; 32], &[0; 32], &[[0; 32]]), "size beyond bound");
        Ok(())
    }

    /// Regression (review 3, finding 4): roots of prefixes and proofs at a large size cost O(log n) hash
    /// operations (the endpoints serving them are unauthenticated), and snapshots share the stored subtrees.
    #[test]
    fn proofs_at_a_large_size_are_cheap() -> NetResult<()> {
        let n: u64 = 200_000;
        let mut tree = Tree::new();
        for i in 0..n {
            tree.push_entry(&i.to_le_bytes())?;
        }
        // Hash operations of one call, its result and its time (best of three runs: a busy machine may pause a
        // thread, the operations count is exact).
        let counted = |work: &dyn Fn() -> NetResult<usize>| -> NetResult<(u64, usize, std::time::Duration)> {
            let mut best = std::time::Duration::MAX;
            let (mut hashes, mut length) = (0, 0);
            for _ in 0..3 {
                let before = NODE_HASHES.with(std::cell::Cell::get);
                let started = std::time::Instant::now();
                length = work()?;
                best = best.min(started.elapsed());
                hashes = NODE_HASHES.with(std::cell::Cell::get) - before;
            }
            Ok((hashes, length, best))
        };
        // log2(200k) < 18: a root or proof needs at most a few dozen inner hashes (the old code: ~n).
        let bound = 4 * 18;
        let mut slowest = std::time::Duration::ZERO;
        for (index, m) in [(0, n), (n / 2 + 1, n), (n - 1, n), (12_345, 150_001), (65_535, 131_073)] {
            let (hashes, _, time) = counted(&|| Ok(usize::from(tree.root_at(m)? != [0; 32])))?;
            assert!(hashes <= bound, "root_at({m}): {hashes} hashes");
            slowest = slowest.max(time);
            let (hashes, length, time) = counted(&|| Ok(tree.inclusion(index.min(m - 1), m)?.len()))?;
            assert!(hashes <= bound && length <= 18, "inclusion({index}, {m}): {hashes} hashes");
            slowest = slowest.max(time);
            let (hashes, length, time) = counted(&|| Ok(tree.consistency(index.max(1), m)?.len()))?;
            assert!(hashes <= bound && length <= 2 * 18, "consistency({index}, {m}): {hashes} hashes");
            slowest = slowest.max(time);
        }
        assert!(slowest < std::time::Duration::from_millis(5), "slowest call took {slowest:?}");
        // The answers are still right (spot check against the plain computations on a copy).
        let leaves: Vec<Hash> = (0..1_000u64).map(|i| leaf_hash(&i.to_le_bytes())).collect();
        assert_eq!(tree.root_at(1_000)?, root(&leaves));
        let proof = tree.inclusion(777, n)?;
        assert!(verify_inclusion(&leaf_hash(&777u64.to_le_bytes()), 777, n, &proof, &tree.root()));
        let proof = tree.consistency(150_001, n)?;
        assert!(verify_consistency(150_001, n, &tree.root_at(150_001)?, &tree.root(), &proof));
        // A snapshot shares the frozen chunks: growing it does not change the original.
        let mut snapshot = tree.clone();
        snapshot.push_entry(b"more")?;
        assert_eq!((tree.size(), snapshot.size()), (n, n + 1));
        assert_eq!(snapshot.root_at(n)?, tree.root());
        Ok(())
    }

    #[test]
    fn generation_rejects_bad_arguments() -> NetResult<()> {
        let tree = tree_of(&data(5))?;
        assert!(tree.inclusion(5, 5).is_err());
        assert!(tree.inclusion(0, 6).is_err());
        assert!(tree.inclusion(0, 0).is_err());
        assert!(tree.consistency(3, 2).is_err());
        assert!(tree.consistency(1, 6).is_err());
        assert_eq!(tree.consistency(0, 5)?, Vec::<Hash>::new());
        assert_eq!(tree.consistency(5, 5)?, Vec::<Hash>::new());
        assert!(tree.root_at(6).is_err());
        assert!(tree.root_at(u64::MAX).is_err());
        Ok(())
    }
}
