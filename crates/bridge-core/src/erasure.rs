//! Erasure coding (docs/09 §2): Reed-Solomon over GF(2^8), systematic, with a Cauchy matrix. `k` data shards and `m`
//! parity shards of equal length; **any `k` of the `n = k + m` shards** give the data back. Used by the storage
//! service: a file (already encrypted at the client) becomes `n` shards on `n` storage nodes and survives the loss of
//! any `m` of them.
//!
//! - Field GF(256) with the polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D), log/exp tables built at first use.
//! - Generator: the identity for the data shards, below it the Cauchy matrix `C[j][i] = 1 / (x_j + y_i)` with
//!   `y_i = i` and `x_j = k + j` (all distinct, so every entry exists). Every square submatrix of a Cauchy matrix is
//!   invertible, so every `k` rows of the generator are - that is the "any k of n" property.
//! - Decoding inverts the `k × k` matrix of the rows that are there (Gauss-Jordan in the field); missing parity shards
//!   are computed again from the data (repair).
//!
//! No secrets, no crypto: the shards of an encrypted file are ciphertext. Bounds: `1 ≤ k`, `k + m ≤ 64`, shards up to
//! [`MAX_SHARD_BYTES`]; every input is checked (lengths, counts) - errors, never panics.

use std::sync::OnceLock;

use crate::error::{CoreError, CoreResult};

/// Most shards of one stripe (data + parity).
pub const MAX_SHARDS: usize = 64;
/// Largest shard.
pub const MAX_SHARD_BYTES: usize = 64 * 1024 * 1024;

struct Tables {
    exp: [u8; 512],
    log: [u8; 256],
}

fn tables() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        let mut x: u16 = 1;
        for (power, slot) in exp.iter_mut().take(255).enumerate() {
            *slot = x as u8;
            log[x as usize] = power as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11D;
            }
        }
        for index in 255..512 {
            exp[index] = exp[index - 255];
        }
        Tables { exp, log }
    })
}

fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let t = tables();
    t.exp[t.log[a as usize] as usize + t.log[b as usize] as usize]
}

fn inv(a: u8) -> CoreResult<u8> {
    if a == 0 {
        return Err(CoreError::format("erasure: no inverse of 0"));
    }
    let t = tables();
    Ok(t.exp[255 - t.log[a as usize] as usize])
}

/// `out ^= factor * input` for every byte (the inner loop of encoding and decoding).
fn mul_add(out: &mut [u8], input: &[u8], factor: u8) {
    if factor == 0 {
        return;
    }
    if factor == 1 {
        for (o, i) in out.iter_mut().zip(input) {
            *o ^= i;
        }
        return;
    }
    let t = tables();
    let lf = t.log[factor as usize] as usize;
    for (o, &i) in out.iter_mut().zip(input) {
        if i != 0 {
            *o ^= t.exp[lf + t.log[i as usize] as usize];
        }
    }
}

/// A Reed-Solomon code with `k` data and `m` parity shards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Erasure {
    k: usize,
    m: usize,
    /// The `m × k` Cauchy part of the generator.
    parity: Vec<Vec<u8>>,
}

impl Erasure {
    /// A code with `k ≥ 1` data and `m ≥ 0` parity shards, `k + m ≤` [`MAX_SHARDS`].
    pub fn new(k: usize, m: usize) -> CoreResult<Self> {
        if k == 0 || k.saturating_add(m) > MAX_SHARDS {
            return Err(CoreError::format("erasure: 1 ≤ k and k + m ≤ 64"));
        }
        let mut parity = Vec::with_capacity(m);
        for j in 0..m {
            let mut row = Vec::with_capacity(k);
            for i in 0..k {
                // x_j + y_i in GF(2^8) is XOR; x_j = k + j, y_i = i are distinct and < 64, so never 0.
                row.push(inv(((k + j) ^ i) as u8)?);
            }
            parity.push(row);
        }
        Ok(Self { k, m, parity })
    }

    /// Data shards.
    #[must_use]
    pub fn data_shards(&self) -> usize {
        self.k
    }

    /// Parity shards.
    #[must_use]
    pub fn parity_shards(&self) -> usize {
        self.m
    }

    /// All shards.
    #[must_use]
    pub fn total_shards(&self) -> usize {
        self.k + self.m
    }

    /// Shard length for `len` bytes of data (at least 1).
    #[must_use]
    pub fn shard_len(&self, len: usize) -> usize {
        len.div_ceil(self.k).max(1)
    }

    /// Splits `data` into `k` data shards (the last one padded with zeros) and adds `m` parity shards.
    pub fn encode(&self, data: &[u8]) -> CoreResult<Vec<Vec<u8>>> {
        let len = self.shard_len(data.len());
        if len > MAX_SHARD_BYTES {
            return Err(CoreError::format("erasure: shard too large"));
        }
        let mut shards: Vec<Vec<u8>> = (0..self.k)
            .map(|i| {
                let start = (i * len).min(data.len());
                let end = ((i + 1) * len).min(data.len());
                let mut shard = data[start..end].to_vec();
                shard.resize(len, 0);
                shard
            })
            .collect();
        for row in &self.parity {
            let mut out = vec![0u8; len];
            for (factor, shard) in row.iter().zip(&shards) {
                mul_add(&mut out, shard, *factor);
            }
            shards.push(out);
        }
        Ok(shards)
    }

    /// The generator row of shard `index`.
    fn row(&self, index: usize) -> Vec<u8> {
        if index < self.k {
            let mut row = vec![0u8; self.k];
            row[index] = 1;
            row
        } else {
            self.parity[index - self.k].clone()
        }
    }

    /// Fills every missing shard (`None`) from any `k` present ones. All present shards must have the same length.
    pub fn reconstruct(&self, shards: &mut [Option<Vec<u8>>]) -> CoreResult<()> {
        let n = self.total_shards();
        if shards.len() != n {
            return Err(CoreError::format("erasure: wrong number of shards"));
        }
        let present: Vec<usize> = (0..n).filter(|&i| shards[i].is_some()).collect();
        if present.len() < self.k {
            return Err(CoreError::format("erasure: fewer than k shards left"));
        }
        let len = shards[present[0]].as_ref().map_or(0, Vec::len);
        if len == 0 || len > MAX_SHARD_BYTES || present.iter().any(|&i| shards[i].as_ref().map_or(0, Vec::len) != len) {
            return Err(CoreError::format("erasure: shards of different or no length"));
        }
        if present.len() == n {
            return Ok(());
        }
        // The data shards from the first k present ones: invert their generator rows.
        let rows: Vec<usize> = present.iter().copied().take(self.k).collect();
        let inverse = invert(rows.iter().map(|&r| self.row(r)).collect())?;
        let mut data: Vec<Vec<u8>> = Vec::with_capacity(self.k);
        for (i, inverse_row) in inverse.iter().enumerate() {
            if let Some(shard) = &shards[i] {
                data.push(shard.clone());
                continue;
            }
            let mut out = vec![0u8; len];
            for (factor, &r) in inverse_row.iter().zip(&rows) {
                if let Some(shard) = &shards[r] {
                    mul_add(&mut out, shard, *factor);
                }
            }
            data.push(out);
        }
        for i in 0..n {
            if shards[i].is_some() {
                continue;
            }
            if i < self.k {
                shards[i] = Some(data[i].clone());
            } else {
                let mut out = vec![0u8; len];
                for (factor, shard) in self.parity[i - self.k].iter().zip(&data) {
                    mul_add(&mut out, shard, *factor);
                }
                shards[i] = Some(out);
            }
        }
        Ok(())
    }

    /// The data back from the `k` data shards (complete, in order), cut to `len` bytes.
    pub fn join(&self, shards: &[Vec<u8>], len: usize) -> CoreResult<Vec<u8>> {
        if shards.len() < self.k {
            return Err(CoreError::format("erasure: fewer than k data shards"));
        }
        let shard_len = shards[0].len();
        if shards.iter().take(self.k).any(|shard| shard.len() != shard_len) || shard_len.saturating_mul(self.k) < len {
            return Err(CoreError::format("erasure: shards do not hold the length"));
        }
        let mut data = Vec::with_capacity(shard_len * self.k);
        for shard in shards.iter().take(self.k) {
            data.extend_from_slice(shard);
        }
        data.truncate(len);
        Ok(data)
    }
}

/// Inverts a square matrix over GF(2^8) (Gauss-Jordan).
fn invert(mut matrix: Vec<Vec<u8>>) -> CoreResult<Vec<Vec<u8>>> {
    let size = matrix.len();
    let mut inverse: Vec<Vec<u8>> = (0..size)
        .map(|i| {
            let mut row = vec![0u8; size];
            row[i] = 1;
            row
        })
        .collect();
    for col in 0..size {
        let pivot = (col..size).find(|&r| matrix[r][col] != 0).ok_or(CoreError::format("erasure: singular"))?;
        matrix.swap(col, pivot);
        inverse.swap(col, pivot);
        let factor = inv(matrix[col][col])?;
        for c in 0..size {
            matrix[col][c] = mul(matrix[col][c], factor);
            inverse[col][c] = mul(inverse[col][c], factor);
        }
        for r in 0..size {
            if r == col || matrix[r][col] == 0 {
                continue;
            }
            let f = matrix[r][col];
            let (pivot_m, pivot_i) = (matrix[col].clone(), inverse[col].clone());
            mul_add(&mut matrix[r], &pivot_m, f);
            mul_add(&mut inverse[r], &pivot_i, f);
        }
    }
    Ok(inverse)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn field_arithmetic() -> CoreResult<()> {
        for a in 1..=255u8 {
            assert_eq!(mul(a, inv(a)?), 1, "{a}");
        }
        assert_eq!(mul(0, 7), 0);
        assert!(inv(0).is_err());
        Ok(())
    }

    /// Every loss pattern of up to m shards of a 6+4 code gives the data back.
    #[test]
    fn any_k_of_n() -> CoreResult<()> {
        let code = Erasure::new(6, 4)?;
        let input = data(10_001);
        let shards = code.encode(&input)?;
        assert_eq!(shards.len(), 10);
        for mask in 0u32..(1 << 10) {
            if mask.count_ones() > 4 {
                continue;
            }
            let mut damaged: Vec<Option<Vec<u8>>> =
                shards.iter().enumerate().map(|(i, s)| (mask & (1 << i) == 0).then(|| s.clone())).collect();
            code.reconstruct(&mut damaged)?;
            let full: Vec<Vec<u8>> = damaged.into_iter().map(Option::unwrap_or_default).collect();
            assert_eq!(full, shards, "mask {mask:b}");
            assert_eq!(code.join(&full, input.len())?, input);
        }
        Ok(())
    }

    #[test]
    fn edge_cases() -> CoreResult<()> {
        // No parity, a single data shard, empty data, the largest code.
        for (k, m) in [(1, 0), (1, 3), (3, 0), (32, 32)] {
            let code = Erasure::new(k, m)?;
            for len in [0, 1, k, 1000] {
                let input = data(len);
                let shards = code.encode(&input)?;
                assert_eq!(code.join(&shards, len)?, input);
            }
        }
        assert!(Erasure::new(0, 4).is_err());
        assert!(Erasure::new(40, 25).is_err());
        Ok(())
    }

    /// Attack: too few shards, shards of different length, the wrong count - errors, no panic.
    #[test]
    fn bad_inputs_are_errors() -> CoreResult<()> {
        let code = Erasure::new(4, 2)?;
        let shards = code.encode(&data(100))?;
        let mut few: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
        few[0] = None;
        few[1] = None;
        few[2] = None;
        assert!(code.reconstruct(&mut few).is_err());
        let mut uneven: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
        uneven[5] = Some(vec![1, 2, 3]);
        uneven[0] = None;
        assert!(code.reconstruct(&mut uneven).is_err());
        let mut short: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).take(5).collect();
        assert!(code.reconstruct(&mut short).is_err());
        assert!(code.join(&shards[..3], 100).is_err());
        assert!(code.join(&shards, 10_000).is_err());
        Ok(())
    }
}
