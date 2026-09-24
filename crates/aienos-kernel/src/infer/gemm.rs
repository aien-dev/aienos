//! Allocation-free row-major matrix and activation kernels.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelError {
    Shape,
    InvalidParameter,
}

pub(crate) fn sqrt_approx(x: f32) -> f32 {
    if x == 0.0 {
        return 0.0;
    }
    let mut y = f32::from_bits((x.to_bits() >> 1) + 0x1fc0_0000);
    for _ in 0..5 {
        y = 0.5 * (y + x / y);
    }
    y
}

pub(crate) fn exp_approx(x: f32) -> f32 {
    let x = x.clamp(-87.0, 88.0);
    let scaled = x * core::f32::consts::LOG2_E;
    let n = if scaled >= 0.0 {
        (scaled + 0.5) as i32
    } else {
        (scaled - 0.5) as i32
    };
    let r = x - n as f32 * core::f32::consts::LN_2;
    let p = 1.0 + r * (1.0 + r * (0.5 + r * (1.0 / 6.0 + r * (1.0 / 24.0 + r / 120.0))));
    p * f32::from_bits(((n + 127) as u32) << 23)
}

fn fits(len: usize, rows: usize, cols: usize, stride: usize) -> bool {
    rows == 0
        || cols == 0
        || (stride >= cols
            && (rows - 1)
                .checked_mul(stride)
                .and_then(|n| n.checked_add(cols))
                .is_some_and(|n| n <= len))
}

/// Scalar reference matrix-vector product: `out[r] = matrix[r, :] dot vector[:]`.
#[allow(clippy::too_many_arguments)]
pub fn matvec_ref(
    matrix: &[f32],
    vector: &[f32],
    out: &mut [f32],
    rows: usize,
    cols: usize,
    matrix_stride: usize,
    vector_stride: usize,
    out_stride: usize,
) -> Result<(), KernelError> {
    if !fits(matrix.len(), rows, cols, matrix_stride)
        || !fits(vector.len(), cols, 1, vector_stride)
        || !fits(out.len(), rows, 1, out_stride)
    {
        return Err(KernelError::Shape);
    }
    for r in 0..rows {
        let mut sum = 0.0;
        for c in 0..cols {
            sum += matrix[r * matrix_stride + c] * vector[c * vector_stride];
        }
        out[r * out_stride] = sum;
    }
    Ok(())
}

/// AArch64 NEON matrix-vector product, with four independent accumulators.
#[allow(clippy::too_many_arguments)]
pub fn matvec(
    matrix: &[f32],
    vector: &[f32],
    out: &mut [f32],
    rows: usize,
    cols: usize,
    matrix_stride: usize,
    vector_stride: usize,
    out_stride: usize,
) -> Result<(), KernelError> {
    if !fits(matrix.len(), rows, cols, matrix_stride)
        || !fits(vector.len(), cols, 1, vector_stride)
        || !fits(out.len(), rows, 1, out_stride)
    {
        return Err(KernelError::Shape);
    }
    // The NEON path loads 4 contiguous vector elements at a time, so it is only
    // valid for a contiguous vector; strided vectors take the scalar path.
    #[cfg(target_arch = "aarch64")]
    if vector_stride == 1 {
        // SAFETY: caller-facing shape checks prove every accessed element is in bounds.
        unsafe {
            matvec_neon(
                matrix,
                vector,
                out,
                rows,
                cols,
                matrix_stride,
                vector_stride,
                out_stride,
            );
        }
        return Ok(());
    }
    matvec_ref(
        matrix,
        vector,
        out,
        rows,
        cols,
        matrix_stride,
        vector_stride,
        out_stride,
    )?;
    Ok(())
}

#[cfg(target_arch = "aarch64")]
#[allow(clippy::too_many_arguments)]
unsafe fn matvec_neon(
    a: &[f32],
    x: &[f32],
    y: &mut [f32],
    m: usize,
    n: usize,
    as_: usize,
    xs: usize,
    ys: usize,
) {
    use core::arch::aarch64::*;
    for r in 0..m {
        let (mut s0, mut s1, mut s2, mut s3) = (
            vdupq_n_f32(0.),
            vdupq_n_f32(0.),
            vdupq_n_f32(0.),
            vdupq_n_f32(0.),
        );
        let (mut c, end) = (0, n / 16 * 16);
        while c < end {
            let p = a.as_ptr().add(r * as_ + c);
            let q = x.as_ptr().add(c * xs);
            s0 = vfmaq_f32(s0, vld1q_f32(p), vld1q_f32(q));
            s1 = vfmaq_f32(s1, vld1q_f32(p.add(4)), vld1q_f32(q.add(4 * xs)));
            s2 = vfmaq_f32(s2, vld1q_f32(p.add(8)), vld1q_f32(q.add(8 * xs)));
            s3 = vfmaq_f32(s3, vld1q_f32(p.add(12)), vld1q_f32(q.add(12 * xs)));
            c += 16;
        }
        let mut total = vaddvq_f32(vaddq_f32(vaddq_f32(s0, s1), vaddq_f32(s2, s3)));
        while c < n {
            total += *a.get_unchecked(r * as_ + c) * *x.get_unchecked(c * xs);
            c += 1;
        }
        *y.get_unchecked_mut(r * ys) = total;
    }
}

/// Scalar reference row-major matrix multiplication with explicit row strides.
#[allow(clippy::too_many_arguments)]
pub fn matmul_ref(
    a: &[f32],
    b: &[f32],
    out: &mut [f32],
    m: usize,
    k: usize,
    n: usize,
    a_stride: usize,
    b_stride: usize,
    out_stride: usize,
) -> Result<(), KernelError> {
    if !fits(a.len(), m, k, a_stride)
        || !fits(b.len(), k, n, b_stride)
        || !fits(out.len(), m, n, out_stride)
    {
        return Err(KernelError::Shape);
    }
    for i in 0..m {
        for j in 0..n {
            let mut sum = 0.;
            for p in 0..k {
                sum += a[i * a_stride + p] * b[p * b_stride + j];
            }
            out[i * out_stride + j] = sum;
        }
    }
    Ok(())
}

/// Row-major matrix multiplication. Uses NEON on AArch64 and scalar elsewhere.
#[allow(clippy::too_many_arguments)]
pub fn matmul(
    a: &[f32],
    b: &[f32],
    out: &mut [f32],
    m: usize,
    k: usize,
    n: usize,
    a_stride: usize,
    b_stride: usize,
    out_stride: usize,
) -> Result<(), KernelError> {
    if !fits(a.len(), m, k, a_stride)
        || !fits(b.len(), k, n, b_stride)
        || !fits(out.len(), m, n, out_stride)
    {
        return Err(KernelError::Shape);
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: shape checks establish bounds for the vector and tail loops.
    unsafe {
        matmul_neon(a, b, out, m, k, n, a_stride, b_stride, out_stride);
    }
    #[cfg(not(target_arch = "aarch64"))]
    matmul_ref(a, b, out, m, k, n, a_stride, b_stride, out_stride)?;
    Ok(())
}

#[cfg(target_arch = "aarch64")]
#[allow(clippy::too_many_arguments)]
unsafe fn matmul_neon(
    a: &[f32],
    b: &[f32],
    out: &mut [f32],
    m: usize,
    k: usize,
    n: usize,
    as_: usize,
    bs: usize,
    os: usize,
) {
    use core::arch::aarch64::*;
    for i in 0..m {
        let mut j = 0;
        while j + 4 <= n {
            let mut acc = vdupq_n_f32(0.);
            let mut p = 0;
            while p + 4 <= k {
                for u in 0..4 {
                    acc = vfmaq_n_f32(
                        acc,
                        vld1q_f32(b.as_ptr().add((p + u) * bs + j)),
                        *a.get_unchecked(i * as_ + p + u),
                    );
                }
                p += 4;
            }
            while p < k {
                acc = vfmaq_n_f32(
                    acc,
                    vld1q_f32(b.as_ptr().add(p * bs + j)),
                    *a.get_unchecked(i * as_ + p),
                );
                p += 1;
            }
            vst1q_f32(out.as_mut_ptr().add(i * os + j), acc);
            j += 4;
        }
        while j < n {
            let mut sum = 0.;
            for p in 0..k {
                sum += *a.get_unchecked(i * as_ + p) * *b.get_unchecked(p * bs + j);
            }
            *out.get_unchecked_mut(i * os + j) = sum;
            j += 1;
        }
    }
}

/// RMS normalization in place: `x / sqrt(mean(x²) + epsilon) * weight`.
pub fn rms_norm(x: &mut [f32], weight: &[f32], epsilon: f32) -> Result<(), KernelError> {
    if x.len() != weight.len() {
        return Err(KernelError::Shape);
    }
    if !epsilon.is_finite() || epsilon <= 0. {
        return Err(KernelError::InvalidParameter);
    }
    if x.is_empty() {
        return Ok(());
    }
    let mean = x.iter().map(|v| v * v).sum::<f32>() / x.len() as f32;
    let scale = sqrt_approx(mean + epsilon).recip();
    for (v, w) in x.iter_mut().zip(weight) {
        *v *= scale * *w;
    }
    Ok(())
}

/// Stable softmax, computed in place with maximum subtraction.
pub fn softmax(x: &mut [f32]) -> Result<(), KernelError> {
    if x.iter().any(|v| !v.is_finite()) {
        return Err(KernelError::InvalidParameter);
    }
    if x.is_empty() {
        return Ok(());
    }
    let max = x.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let sum: f32 = x
        .iter_mut()
        .map(|v| {
            *v = exp_approx(*v - max);
            *v
        })
        .sum();
    for v in x {
        *v /= sum;
    }
    Ok(())
}

/// SiLU activation, `x * sigmoid(x)`, in place.
pub fn silu(x: &mut [f32]) {
    for v in x {
        *v /= 1. + exp_approx(-*v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> f32 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 as i32 as f32) / i32::MAX as f32
        }
    }
    fn close(a: &[f32], b: &[f32]) {
        for (&x, &y) in a.iter().zip(b) {
            assert!((x - y).abs() <= 1e-5 * y.abs().max(1.0), "{x} != {y}");
        }
    }
    #[test]
    fn products_match_reference_odd_and_even() {
        let mut rng = Rng(0x1234_5678);
        for &n in &[1, 3, 17, 64, 129] {
            let a: Vec<_> = (0..n * n).map(|_| rng.next()).collect();
            let x: Vec<_> = (0..n).map(|_| rng.next()).collect();
            let mut want = vec![0.; n];
            let mut got = vec![0.; n];
            matvec_ref(&a, &x, &mut want, n, n, n, 1, 1).unwrap();
            matvec(&a, &x, &mut got, n, n, n, 1, 1).unwrap();
            close(&got, &want);
            let b: Vec<_> = (0..n * n).map(|_| rng.next()).collect();
            let mut want = vec![0.; n * n];
            let mut got = vec![0.; n * n];
            matmul_ref(&a, &b, &mut want, n, n, n, n, n, n).unwrap();
            matmul(&a, &b, &mut got, n, n, n, n, n, n).unwrap();
            close(&got, &want);
        }
    }
    #[test]
    fn softmax_sums_to_one() {
        let mut x = [1000., 1001., 999.];
        softmax(&mut x).unwrap();
        assert!((x.iter().sum::<f32>() - 1.).abs() < 1e-6);
    }
    #[test]
    fn rms_norm_hand_value() {
        let mut x = [3., 4.];
        rms_norm(&mut x, &[1., 2.], 1.).unwrap();
        let d = 13.5f32.sqrt();
        assert!((x[0] - 3. / d).abs() < 1e-6);
        assert!((x[1] - 8. / d).abs() < 1e-6);
    }
    #[test]
    #[ignore = "benchmark"]
    fn benchmark_matvec_4096() {
        let a = vec![0.001; 4096 * 4096];
        let x = vec![0.001; 4096];
        let mut y = vec![0.; 4096];
        let t = std::time::Instant::now();
        matvec(&a, &x, &mut y, 4096, 4096, 4096, 1, 1).unwrap();
        let s = t.elapsed().as_secs_f64();
        println!("matvec GFLOP/s: {}", 2. * 4096f64 * 4096. / s / 1e9);
    }
    #[test]
    fn strided_vector_matches_reference() {
        // Review regression: NEON loads assumed a contiguous vector.
        let matrix = [1.0f32; 16];
        let vector = [1.0f32, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0];
        let mut out = [0.0f32; 1];
        matvec(&matrix, &vector, &mut out, 1, 4, 16, 2, 1).unwrap();
        assert_eq!(out[0], 4.0);
        let long = [1.0f32; 32];
        let mut out = [0.0f32; 1];
        matvec(&[1.0; 16], &long, &mut out, 1, 16, 16, 2, 1).unwrap();
        assert_eq!(out[0], 16.0);
    }
}
