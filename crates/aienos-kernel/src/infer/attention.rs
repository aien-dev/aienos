//! Allocation-free single-query decode attention over caller-owned KV storage.

use super::gemm::{self, KernelError};

/// Fixed-capacity row-major key/value cache for decode attention.
pub struct KvCache<'a> {
    keys: &'a mut [f32],
    values: &'a mut [f32],
    capacity: usize,
    n_kv_heads: usize,
    head_dim: usize,
    len: usize,
}

impl<'a> KvCache<'a> {
    /// Creates a cache backed by `keys` and `values`, each sized for capacity.
    pub fn new(
        keys: &'a mut [f32],
        values: &'a mut [f32],
        capacity: usize,
        n_kv_heads: usize,
        head_dim: usize,
    ) -> Result<Self, KernelError> {
        if n_kv_heads == 0 || head_dim == 0 {
            return Err(KernelError::InvalidParameter);
        }
        let required = capacity
            .checked_mul(n_kv_heads)
            .and_then(|n| n.checked_mul(head_dim))
            .ok_or(KernelError::Shape)?;
        if keys.len() < required || values.len() < required {
            return Err(KernelError::Shape);
        }
        Ok(Self {
            keys,
            values,
            capacity,
            n_kv_heads,
            head_dim,
            len: 0,
        })
    }

    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Appends one token containing all KV heads.
    pub fn append(&mut self, key: &[f32], value: &[f32]) -> Result<(), KernelError> {
        let width = self.n_kv_heads * self.head_dim;
        if key.len() != width || value.len() != width {
            return Err(KernelError::Shape);
        }
        if self.len == self.capacity {
            return Err(KernelError::Shape);
        }
        let start = self.len * width;
        self.keys[start..start + width].copy_from_slice(key);
        self.values[start..start + width].copy_from_slice(value);
        self.len += 1;
        Ok(())
    }

    fn key(&self, pos: usize, head: usize) -> &[f32] {
        let start = (pos * self.n_kv_heads + head) * self.head_dim;
        &self.keys[start..start + self.head_dim]
    }

    fn value(&self, pos: usize, head: usize) -> &[f32] {
        let start = (pos * self.n_kv_heads + head) * self.head_dim;
        &self.values[start..start + self.head_dim]
    }
}

/// Computes all query heads at `position` using grouped-query attention.
///
/// `query` and `output` are head-major with `n_heads * head_dim` elements.
/// Each contiguous group of `n_heads / n_kv_heads` query heads shares a KV
/// head. `scores` is scratch space for at least `position + 1` scores.
pub fn decode(
    query: &[f32],
    output: &mut [f32],
    cache: &KvCache<'_>,
    n_heads: usize,
    position: usize,
    scores: &mut [f32],
) -> Result<(), KernelError> {
    if n_heads == 0 || !n_heads.is_multiple_of(cache.n_kv_heads) {
        return Err(KernelError::InvalidParameter);
    }
    let width = n_heads
        .checked_mul(cache.head_dim)
        .ok_or(KernelError::Shape)?;
    let tokens = position.checked_add(1).ok_or(KernelError::Shape)?;
    if query.len() != width
        || output.len() != width
        || position >= cache.len
        || scores.len() < tokens
    {
        return Err(KernelError::Shape);
    }
    let group_size = n_heads / cache.n_kv_heads;
    let scale = 1.0 / gemm::sqrt_approx(cache.head_dim as f32);
    for head in 0..n_heads {
        let kv_head = head / group_size;
        let q = &query[head * cache.head_dim..(head + 1) * cache.head_dim];
        for (token, score) in scores[..tokens].iter_mut().enumerate() {
            *score = q
                .iter()
                .zip(cache.key(token, kv_head))
                .map(|(a, b)| a * b)
                .sum::<f32>()
                * scale;
        }
        gemm::softmax(&mut scores[..tokens])?;
        let out = &mut output[head * cache.head_dim..(head + 1) * cache.head_dim];
        out.fill(0.0);
        for (token, &weight) in scores[..tokens].iter().enumerate() {
            for (dst, &v) in out.iter_mut().zip(cache.value(token, kv_head)) {
                *dst += weight * v;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache<'a>(
        keys: &'a mut [f32],
        values: &'a mut [f32],
        capacity: usize,
        kv_heads: usize,
        dim: usize,
    ) -> KvCache<'a> {
        KvCache::new(keys, values, capacity, kv_heads, dim).unwrap()
    }

    #[test]
    fn one_token_returns_value_exactly() {
        let (mut keys, mut values) = ([0.0; 2], [0.0; 2]);
        let mut kv = cache(&mut keys, &mut values, 1, 1, 2);
        kv.append(&[1.0, 2.0], &[7.0, -3.0]).unwrap();
        let mut out = [0.0; 2];
        decode(&[0.5, 1.0], &mut out, &kv, 1, 0, &mut [0.0]).unwrap();
        assert_eq!(out, [7.0, -3.0]);
    }

    #[test]
    fn two_head_hand_computed_attention() {
        let (mut keys, mut values) = ([1.0, 0.0, 0.0, 1.0], [2.0, 4.0, 8.0, 10.0]);
        let mut kv = cache(&mut keys, &mut values, 2, 1, 2);
        kv.append(&[1.0, 0.0], &[2.0, 4.0]).unwrap();
        kv.append(&[0.0, 1.0], &[8.0, 10.0]).unwrap();
        let query = [0.0; 4];
        let mut out = [0.0; 4];
        decode(&query, &mut out, &kv, 2, 1, &mut [0.0; 2]).unwrap();
        assert_eq!(out, [5.0, 7.0, 5.0, 7.0]);
    }

    #[test]
    fn random_inputs_match_scalar_reference() {
        let mut seed = 0x1234_5678_u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed as i32 as f32) / i32::MAX as f32
        };
        let (mut keys, mut values) = ([0.0; 12], [0.0; 12]);
        let mut kv = cache(&mut keys, &mut values, 3, 1, 4);
        let ks: std::vec::Vec<_> = (0..12).map(|_| next()).collect();
        let vs: std::vec::Vec<_> = (0..12).map(|_| next()).collect();
        for i in 0..3 {
            kv.append(&ks[i * 4..i * 4 + 4], &vs[i * 4..i * 4 + 4])
                .unwrap();
        }
        let query: std::vec::Vec<_> = (0..8).map(|_| next()).collect();
        let mut out = [0.0; 8];
        decode(&query, &mut out, &kv, 2, 2, &mut [0.0; 3]).unwrap();
        for head in 0..2 {
            let q = &query[head * 4..head * 4 + 4];
            let mut logits = [0.0; 3];
            for t in 0..3 {
                logits[t] = q
                    .iter()
                    .zip(&ks[t * 4..t * 4 + 4])
                    .map(|(a, b)| a * b)
                    .sum::<f32>()
                    / 2.0;
            }
            let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
            let weights: std::vec::Vec<_> = logits.iter().map(|x| (x - max).exp()).collect();
            let total: f32 = weights.iter().sum();
            for d in 0..4 {
                let expected: f32 = (0..3).map(|t| weights[t] / total * vs[t * 4 + d]).sum();
                assert!((out[head * 4 + d] - expected).abs() < 2e-5);
            }
        }
    }

    #[test]
    fn gqa_maps_groups_of_query_heads_to_kv_heads() {
        let (mut keys, mut values) = ([0.0; 4], [3.0, 4.0, 9.0, 10.0]);
        let mut kv = cache(&mut keys, &mut values, 1, 2, 2);
        kv.append(&[0.0; 4], &[3.0, 4.0, 9.0, 10.0]).unwrap();
        let mut out = [0.0; 8];
        decode(&[0.0; 8], &mut out, &kv, 4, 0, &mut [0.0]).unwrap();
        assert_eq!(out, [3.0, 4.0, 3.0, 4.0, 9.0, 10.0, 9.0, 10.0]);
    }

    #[test]
    fn append_rejects_capacity_overflow() {
        let (mut keys, mut values) = ([0.0; 2], [0.0; 2]);
        let mut kv = cache(&mut keys, &mut values, 1, 1, 2);
        kv.append(&[0.0; 2], &[0.0; 2]).unwrap();
        assert_eq!(kv.append(&[0.0; 2], &[0.0; 2]), Err(KernelError::Shape));
    }
}
