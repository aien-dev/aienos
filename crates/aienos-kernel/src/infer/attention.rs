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

    // ---- AO-1 (Drake.s attention hardening cut): independent oracle coverage. Values carry
    // head-distinct bands: token t, kv head j, dim d -> 1000 (j+1) + 20 t + d, so every output
    // value decodes back to where it came from.
    fn banded(t: usize, j: usize, d: usize) -> f32 {
        (1000 * (j + 1) + 20 * t + d) as f32
    }
    fn absf(x: f32) -> f32 {
        if x < 0.0 {
            -x
        } else {
            x
        }
    }
    fn lcg(seed: &mut u64) -> f32 {
        *seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((*seed >> 33) as f32 / (1u64 << 31) as f32) * 2.0 - 1.0
    }

    const D: usize = 4;
    const KV: usize = 2;
    const H: usize = 8;
    const T: usize = 4;

    /// Query head h points at token h % T (K is `10 e_t`, so the match scores 50 and the
    /// rest 0); fills `out` with the decode result.
    fn banded_decode(out: &mut [f32; H * D]) {
        let mut keys = [0.0f32; T * KV * D];
        let mut values = [0.0f32; T * KV * D];
        let mut kv = cache(&mut keys, &mut values, T, KV, D);
        for t in 0..T {
            let mut k = [0.0f32; KV * D];
            let mut v = [0.0f32; KV * D];
            for j in 0..KV {
                k[j * D + t] = 10.0;
                for d in 0..D {
                    v[j * D + d] = banded(t, j, d);
                }
            }
            kv.append(&k, &v).unwrap();
        }
        let mut q = [0.0f32; H * D];
        for h in 0..H {
            q[h * D + (h % T)] = 10.0;
        }
        let mut scores = [0.0f32; T];
        decode(&q, out, &kv, H, T - 1, &mut scores).unwrap();
    }

    #[test]
    fn query_rows_kv_groups_and_head_major_output_decode_from_bands() {
        let mut out = [0.0f32; H * D];
        banded_decode(&mut out);
        let group = H / KV;
        for h in 0..H {
            for d in 0..D {
                let x = out[h * D + d];
                let want = banded(h % T, h / group, d);
                assert!(absf(x - want) < 1e-2, "head {h} dim {d}: {x} vs {want}");
                let n = (x + 0.5) as usize;
                assert_eq!(n / 1000 - 1, h / group, "kv head band of head {h}");
                assert_eq!((n % 1000) / 20, h % T, "token digit of head {h}");
                assert_eq!(n % 20, d, "dim digit of head {h}");
            }
        }
        // negatives: the h ^ 1 query row, the h ^ 1 output row and the modulo kv mapping are
        // all different answers by at least one band step
        for h in 0..H {
            let j = h / group;
            assert!(absf(out[h * D] - banded((h ^ 1) % T, j, 0)) >= 19.0);
            assert!(absf(out[(h ^ 1) * D] - banded(h % T, j, 0)) >= 19.0);
            if h % KV != j {
                assert!(absf(out[h * D] - banded(h % T, h % KV, 0)) >= 999.0);
            }
        }
        // dim-major reinterpretation is not the same vector
        let mut worst = 0.0f32;
        for h in 0..H {
            for d in 0..D {
                worst = worst.max(absf(out[d * H + h] - banded(h % T, h / group, d)));
            }
        }
        assert!(worst >= 19.0, "a dim-major output would have passed");
    }

    #[test]
    fn dense_output_projection_mixes_heads_and_catches_a_permutation() {
        let mut attn = [0.0f32; H * D];
        banded_decode(&mut attn);
        for x in attn.iter_mut() {
            *x /= 100.0;
        }
        const ROWS: usize = 6; // hidden width deliberately != H * D
        let mut seed = 0xd0u64;
        let mut w = [0.0f32; ROWS * H * D];
        for x in w.iter_mut() {
            *x = lcg(&mut seed);
        }
        let mut y = [0.0f32; ROWS];
        gemm::matvec_ref(&w, &attn, &mut y, ROWS, H * D, H * D, 1, 1).unwrap();
        for (r, yr) in y.iter().enumerate() {
            let mut hand = 0.0f32;
            let mut heads = 0;
            for h in 0..H {
                let mut part = 0.0f32;
                for d in 0..D {
                    part += w[r * H * D + h * D + d] * attn[h * D + d];
                }
                if part != 0.0 {
                    heads += 1;
                }
                hand += part;
            }
            assert!(heads >= 2, "row {r} mixes one head only");
            assert!(absf(yr - hand) < 1e-4, "row {r}: {yr} vs {hand}");
        }
        let mut perm = attn;
        for d in 0..D {
            perm.swap(d, D + d);
        }
        let mut y_perm = [0.0f32; ROWS];
        gemm::matvec_ref(&w, &perm, &mut y_perm, ROWS, H * D, H * D, 1, 1).unwrap();
        let mut worst = 0.0f32;
        for r in 0..ROWS {
            worst = worst.max(absf(y[r] - y_perm[r]));
        }
        assert!(
            worst > 0.05,
            "swapping two heads before W_o changed nothing"
        );
    }

    #[test]
    fn decode_refuses_wrong_shapes_and_head_counts() {
        let (mut keys, mut values) = ([0.0f32; 2 * KV * D], [0.0f32; 2 * KV * D]);
        let mut kv = cache(&mut keys, &mut values, 2, KV, D);
        kv.append(&[0.0; KV * D], &[1.0; KV * D]).unwrap();
        let q = [0.0f32; H * D];
        let mut out = [0.0f32; H * D];
        let mut scores = [0.0f32; 2];
        assert_eq!(
            decode(&q[..5 * D], &mut out[..5 * D], &kv, 5, 0, &mut scores),
            Err(KernelError::InvalidParameter),
            "5 heads over 2 kv heads"
        );
        assert_eq!(
            decode(&q, &mut out, &kv, 0, 0, &mut scores),
            Err(KernelError::InvalidParameter)
        );
        assert_eq!(
            decode(&q[..H * D - 1], &mut out, &kv, H, 0, &mut scores),
            Err(KernelError::Shape),
            "short query"
        );
        assert_eq!(
            decode(&q, &mut out[..H * D - D], &kv, H, 0, &mut scores),
            Err(KernelError::Shape),
            "short output"
        );
        assert_eq!(
            decode(&q, &mut out, &kv, H, 1, &mut scores),
            Err(KernelError::Shape),
            "position past the appended tokens"
        );
        assert_eq!(
            decode(&q, &mut out, &kv, H, 0, &mut scores[..0]),
            Err(KernelError::Shape),
            "no score scratch"
        );
        // and the good call still works: one token, output is exactly V per kv group
        decode(&q, &mut out, &kv, H, 0, &mut scores).unwrap();
        assert!(out.iter().all(|x| *x == 1.0));
    }
}
