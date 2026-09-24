//! Allocation-free Llama-style rotary position embeddings.

use super::gemm::{self, KernelError};

fn ln_approx(x: f32) -> f32 {
    let bits = x.to_bits();
    let exponent = ((bits >> 23) & 0xff) as i32 - 127;
    let mantissa = f32::from_bits((bits & 0x7f_ffff) | (127 << 23));
    let y = (mantissa - 1.0) / (mantissa + 1.0);
    let y2 = y * y;
    let series = y * (1.0 + y2 * (1.0 / 3.0 + y2 * (1.0 / 5.0 + y2 * (1.0 / 7.0 + y2 / 9.0))));
    2.0 * series + exponent as f32 * core::f32::consts::LN_2
}

fn sin_cos_approx(angle: f32) -> (f32, f32) {
    let x = (angle + core::f32::consts::PI) % core::f32::consts::TAU - core::f32::consts::PI;
    let x2 = x * x;
    let sin =
        x * (1.0 + x2 * (-1.0 / 6.0 + x2 * (1.0 / 120.0 + x2 * (-1.0 / 5040.0 + x2 / 362880.0))));
    let cos = 1.0 + x2 * (-1.0 / 2.0 + x2 * (1.0 / 24.0 + x2 * (-1.0 / 720.0 + x2 / 40320.0)));
    let norm = gemm::sqrt_approx(sin * sin + cos * cos);
    (sin / norm, cos / norm)
}

/// Precomputes rotary cosine and sine values into caller-owned tables.
///
/// Tables are row-major with `head_dim / 2` values per position. Each pair
/// `(x[2*i], x[2*i + 1])` is rotated by the corresponding angle.
pub fn precompute(
    theta: f32,
    head_dim: usize,
    max_seq_len: usize,
    cos: &mut [f32],
    sin: &mut [f32],
) -> Result<(), KernelError> {
    if theta <= 0.0 || !theta.is_finite() || head_dim == 0 || !head_dim.is_multiple_of(2) {
        return Err(KernelError::InvalidParameter);
    }
    let pairs = head_dim / 2;
    let needed = max_seq_len.checked_mul(pairs).ok_or(KernelError::Shape)?;
    if cos.len() < needed || sin.len() < needed {
        return Err(KernelError::Shape);
    }
    for pos in 0..max_seq_len {
        for pair in 0..pairs {
            let exponent = (2 * pair) as f32 / head_dim as f32;
            let frequency = gemm::exp_approx(exponent * ln_approx(theta));
            let angle = pos as f32 / frequency;
            let index = pos * pairs + pair;
            let (sin_value, cos_value) = sin_cos_approx(angle);
            cos[index] = cos_value;
            sin[index] = sin_value;
        }
    }
    Ok(())
}

/// Rotates all query and key heads in place for one sequence position.
pub fn apply(
    q: &mut [f32],
    k: &mut [f32],
    position: usize,
    head_dim: usize,
    cos: &[f32],
    sin: &[f32],
) -> Result<(), KernelError> {
    if head_dim == 0 || !head_dim.is_multiple_of(2) {
        return Err(KernelError::InvalidParameter);
    }
    let pairs = head_dim / 2;
    let offset = position.checked_mul(pairs).ok_or(KernelError::Shape)?;
    if !q.len().is_multiple_of(head_dim)
        || !k.len().is_multiple_of(head_dim)
        || offset
            .checked_add(pairs)
            .is_none_or(|end| end > cos.len() || end > sin.len())
    {
        return Err(KernelError::Shape);
    }
    rotate(
        q,
        head_dim,
        &cos[offset..offset + pairs],
        &sin[offset..offset + pairs],
    );
    rotate(
        k,
        head_dim,
        &cos[offset..offset + pairs],
        &sin[offset..offset + pairs],
    );
    Ok(())
}

fn rotate(values: &mut [f32], head_dim: usize, cos: &[f32], sin: &[f32]) {
    for head in values.chunks_exact_mut(head_dim) {
        for pair in 0..cos.len() {
            let even = head[2 * pair];
            let odd = head[2 * pair + 1];
            head[2 * pair] = even * cos[pair] - odd * sin[pair];
            head[2 * pair + 1] = even * sin[pair] + odd * cos[pair];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(dim: usize, len: usize) -> (std::vec::Vec<f32>, std::vec::Vec<f32>) {
        let mut cos = std::vec![0.0; dim / 2 * len];
        let mut sin = std::vec![0.0; dim / 2 * len];
        precompute(500_000.0, dim, len, &mut cos, &mut sin).unwrap();
        (cos, sin)
    }

    #[test]
    fn position_zero_is_identity() {
        let (cos, sin) = table(4, 3);
        let mut q = [1.0, 2.0, 3.0, 4.0];
        let mut k = q;
        apply(&mut q, &mut k, 0, 4, &cos, &sin).unwrap();
        assert_eq!(q, [1.0, 2.0, 3.0, 4.0]);
        assert_eq!(k, q);
    }

    #[test]
    fn rotation_preserves_each_pair_norm() {
        let (cos, sin) = table(4, 3);
        let mut q = [3.0, 4.0, 5.0, 12.0];
        let mut k = q;
        apply(&mut q, &mut k, 2, 4, &cos, &sin).unwrap();
        for (before, after) in [
            (25.0, q[0] * q[0] + q[1] * q[1]),
            (169.0, q[2] * q[2] + q[3] * q[3]),
        ] {
            assert!((before - after).abs() < 1e-4);
        }
    }
}
