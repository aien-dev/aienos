//! ggml block dequantizers (scalar reference implementations).
//!
//! Formulas follow ggml's `dequantize_row_q4_K` / `dequantize_row_q6_K`
//! (ggml-quants.c). Both formats pack 256 weights per super-block.

use alloc::vec::Vec;

use crate::gguf::GgmlType;
use crate::half::f16_to_f32;

/// Weights per K-quant super-block.
pub const QK_K: usize = 256;
/// Bytes per Q4_K block: f16 d, f16 dmin, 12 bytes scales/mins, 128 bytes nibbles.
pub const Q4K_BYTES: usize = 144;
/// Bytes per Q6_K block: 128 ql, 64 qh, 16 i8 scales, f16 d.
pub const Q6K_BYTES: usize = 210;

/// Reasons a dequantization request is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuantError {
    /// Type has no dequantizer here.
    Unsupported(GgmlType),
    /// Source length is not the whole number of blocks that `out` needs.
    BadLength,
}

fn rd_f16(b: &[u8], at: usize) -> f32 {
    f16_to_f32(u16::from_le_bytes([b[at], b[at + 1]]))
}

/// 6-bit scale and min for sub-block `j` (0..8) from the 12 packed bytes.
fn scale_min_k4(j: usize, q: &[u8]) -> (u8, u8) {
    if j < 4 {
        (q[j] & 63, q[j + 4] & 63)
    } else {
        (
            (q[j + 4] & 0x0f) | ((q[j - 4] >> 6) << 4),
            (q[j + 4] >> 4) | ((q[j] >> 6) << 4),
        )
    }
}

/// Dequantize one Q4_K block (144 bytes) into 256 floats.
pub fn dequant_q4k_block(block: &[u8; Q4K_BYTES], out: &mut [f32; QK_K]) {
    let d = rd_f16(block, 0);
    let dmin = rd_f16(block, 2);
    let scales = &block[4..16];
    let qs = &block[16..144];
    for j in 0..4 {
        let (sc1, m1) = scale_min_k4(2 * j, scales);
        let (sc2, m2) = scale_min_k4(2 * j + 1, scales);
        let (d1, mn1) = (d * sc1 as f32, dmin * m1 as f32);
        let (d2, mn2) = (d * sc2 as f32, dmin * m2 as f32);
        let q = &qs[32 * j..32 * j + 32];
        let o = &mut out[64 * j..64 * j + 64];
        for l in 0..32 {
            o[l] = d1 * (q[l] & 0x0f) as f32 - mn1;
            o[l + 32] = d2 * (q[l] >> 4) as f32 - mn2;
        }
    }
}

/// Dequantize one Q6_K block (210 bytes) into 256 floats.
pub fn dequant_q6k_block(block: &[u8; Q6K_BYTES], out: &mut [f32; QK_K]) {
    let d = rd_f16(block, 208);
    for half in 0..2 {
        let ql = &block[64 * half..64 * half + 64];
        let qh = &block[128 + 32 * half..128 + 32 * half + 32];
        let sc = &block[192 + 8 * half..192 + 8 * half + 8];
        let o = &mut out[128 * half..128 * half + 128];
        for l in 0..32 {
            let is = l / 16;
            let h = qh[l];
            let q1 = ((ql[l] & 0x0f) | ((h & 3) << 4)) as i32 - 32;
            let q2 = ((ql[l + 32] & 0x0f) | (((h >> 2) & 3) << 4)) as i32 - 32;
            let q3 = ((ql[l] >> 4) | (((h >> 4) & 3) << 4)) as i32 - 32;
            let q4 = ((ql[l + 32] >> 4) | (((h >> 6) & 3) << 4)) as i32 - 32;
            o[l] = d * (sc[is] as i8) as f32 * q1 as f32;
            o[l + 32] = d * (sc[is + 2] as i8) as f32 * q2 as f32;
            o[l + 64] = d * (sc[is + 4] as i8) as f32 * q3 as f32;
            o[l + 96] = d * (sc[is + 6] as i8) as f32 * q4 as f32;
        }
    }
}

fn as_block<const N: usize>(b: &[u8]) -> &[u8; N] {
    // Callers pass chunks_exact(N) slices, so the length is always N.
    b.try_into().expect("chunk length is N")
}

/// Independent partial sums per 32-weight sub-block. Eight f32 lanes give the
/// compiler two NEON vectors of fused multiply-adds in flight instead of one
/// serial chain of dependent additions, with no `unsafe` (aienos#34 L6).
const LANES: usize = 8;

/// Weights per Q4_K sub-block (one 6-bit scale and min each).
pub const Q4K_SUB: usize = 32;

/// `sums[k] = sum(x[32k..32k+32])`, one per Q4_K sub-block of `x`. Independent
/// of the weights, so a matvec computes it once and reuses it for every row.
pub fn sub_block_sums(x: &[f32], sums: &mut [f32]) {
    for (c, s) in x.chunks_exact(Q4K_SUB).zip(sums.iter_mut()) {
        let mut lanes = [0f32; LANES];
        for b in c.chunks_exact(LANES) {
            for i in 0..LANES {
                lanes[i] += b[i];
            }
        }
        *s = lanes.iter().sum();
    }
}

/// `sum(nibble(q[l]) * x[l])` over 32 weights; `hi` picks the high nibble.
#[inline(always)]
fn nibble_dot(q: &[u8; Q4K_SUB], hi: bool, x: &[f32; Q4K_SUB]) -> f32 {
    let mut lanes = [0f32; LANES];
    for c in 0..Q4K_SUB / LANES {
        let qb: &[u8; LANES] = q[LANES * c..LANES * c + LANES].try_into().expect("8 bytes");
        let xb: &[f32; LANES] = x[LANES * c..LANES * c + LANES].try_into().expect("8 x");
        for i in 0..LANES {
            let n = if hi { qb[i] >> 4 } else { qb[i] & 0x0f };
            lanes[i] += n as f32 * xb[i];
        }
    }
    lanes.iter().sum()
}

/// Dot product of one Q4_K block with 256 f32 activations, given the eight
/// sub-block sums of `x` (see [`sub_block_sums`]).
///
/// Same quantity as `dequant_q4k_block` followed by a dot (f32 throughout, no
/// int8 rounding of `x`), evaluated per sub-block as
/// `d*sc * sum(q*x) - dmin*m * sum(x)`. Only the floating-point summation
/// order differs from the serial reference.
pub fn dot_q4k_f32_sums(block: &[u8; Q4K_BYTES], x: &[f32; QK_K], xs: &[f32; 8]) -> f32 {
    let d = rd_f16(block, 0);
    let dmin = rd_f16(block, 2);
    let scales = &block[4..16];
    let qs: &[u8; 128] = block[16..144].try_into().expect("128 nibble bytes");
    let mut acc = 0f32;
    for j in 0..4 {
        let (sc1, m1) = scale_min_k4(2 * j, scales);
        let (sc2, m2) = scale_min_k4(2 * j + 1, scales);
        let q: &[u8; Q4K_SUB] = qs[32 * j..32 * j + 32].try_into().expect("32 bytes");
        let x1: &[f32; Q4K_SUB] = x[64 * j..64 * j + 32].try_into().expect("32 x");
        let x2: &[f32; Q4K_SUB] = x[64 * j + 32..64 * j + 64].try_into().expect("32 x");
        acc += d * sc1 as f32 * nibble_dot(q, false, x1) - dmin * m1 as f32 * xs[2 * j];
        acc += d * sc2 as f32 * nibble_dot(q, true, x2) - dmin * m2 as f32 * xs[2 * j + 1];
    }
    acc
}

/// Dot product of one Q4_K block with 256 f32 activations (computes the
/// sub-block sums of `x` itself; use [`dot_q4k_f32_sums`] in a row loop).
pub fn dot_q4k_f32(block: &[u8; Q4K_BYTES], x: &[f32; QK_K]) -> f32 {
    let mut xs = [0f32; 8];
    sub_block_sums(x, &mut xs);
    dot_q4k_f32_sums(block, x, &xs)
}

/// `sum((q-32) * x)` over 16 weights of one Q6_K scale group, from two
/// quarter-row nibble sources and the two high bits in `qh`.
#[inline(always)]
fn q6_group_dot(ql: &[u8; 16], shift_l: u32, qh: &[u8; 16], shift_h: u32, x: &[f32; 16]) -> f32 {
    let mut lanes = [0f32; LANES];
    for c in 0..2 {
        for i in 0..LANES {
            let l = LANES * c + i;
            let q = (((ql[l] >> shift_l) & 0x0f) | (((qh[l] >> shift_h) & 3) << 4)) as i32 - 32;
            lanes[i] += q as f32 * x[l];
        }
    }
    lanes.iter().sum()
}

/// Dot product of one Q6_K block with 256 f32 activations (same scheme as
/// [`dot_q4k_f32_sums`]: per 16-weight scale group, `d*sc * sum((q-32)*x)`).
pub fn dot_q6k_f32(block: &[u8; Q6K_BYTES], x: &[f32; QK_K]) -> f32 {
    let d = rd_f16(block, 208);
    let mut acc = 0f32;
    for half in 0..2 {
        let ql = &block[64 * half..64 * half + 64];
        let qh = &block[128 + 32 * half..128 + 32 * half + 32];
        let sc = &block[192 + 8 * half..192 + 8 * half + 8];
        let xs = &x[128 * half..128 * half + 128];
        // Quarter k of this half uses ql bytes (k&1)*32.. with nibble shift
        // 4*(k>>1) and qh bit pair 2k, exactly as dequant_q6k_block.
        for k in 0..4 {
            let qlo = 32 * (k & 1);
            let shift_l = 4 * (k >> 1) as u32;
            let shift_h = 2 * k as u32;
            for g in 0..2 {
                let qlg: &[u8; 16] = ql[qlo + 16 * g..qlo + 16 * g + 16]
                    .try_into()
                    .expect("16 ql");
                let qhg: &[u8; 16] = qh[16 * g..16 * g + 16].try_into().expect("16 qh");
                let xg: &[f32; 16] = xs[32 * k + 16 * g..32 * k + 16 * g + 16]
                    .try_into()
                    .expect("16 x");
                acc +=
                    d * (sc[2 * k + g] as i8) as f32 * q6_group_dot(qlg, shift_l, qhg, shift_h, xg);
            }
        }
    }
    acc
}

/// Dot of a whole quantized row (`src`, `x.len()` weights) with `x`.
pub fn dot_row(ty: GgmlType, src: &[u8], x: &[f32]) -> Result<f32, QuantError> {
    let mut sums = alloc::vec![0f32; x.len() / Q4K_SUB];
    sub_block_sums(x, &mut sums);
    dot_row_sums(ty, src, x, &sums)
}

/// [`dot_row`] with the sub-block sums of `x` supplied (`x.len() / 32` values
/// from [`sub_block_sums`]); only Q4_K reads them.
pub fn dot_row_sums(ty: GgmlType, src: &[u8], x: &[f32], sums: &[f32]) -> Result<f32, QuantError> {
    let (bw, bb) = ty.block();
    if !matches!(ty, GgmlType::Q4K | GgmlType::Q6K) {
        return Err(QuantError::Unsupported(ty));
    }
    if x.len() % bw != 0 || src.len() != x.len() / bw * bb || sums.len() < x.len() / Q4K_SUB {
        return Err(QuantError::BadLength);
    }
    let mut acc = 0f32;
    for ((blk, xs), ss) in src
        .chunks_exact(bb)
        .zip(x.chunks_exact(QK_K))
        .zip(sums.chunks_exact(QK_K / Q4K_SUB))
    {
        let xs: &[f32; QK_K] = xs.try_into().expect("chunk is QK_K");
        acc += if ty == GgmlType::Q4K {
            dot_q4k_f32_sums(as_block(blk), xs, ss.try_into().expect("8 sums"))
        } else {
            dot_q6k_f32(as_block(blk), xs)
        };
    }
    Ok(acc)
}

/// Dequantize `out.len()` weights of type `ty` from `src` (whole blocks).
pub fn dequantize(ty: GgmlType, src: &[u8], out: &mut [f32]) -> Result<(), QuantError> {
    let (bw, bb) = ty.block();
    if out.len() % bw != 0 || src.len() != out.len() / bw * bb {
        return Err(QuantError::BadLength);
    }
    match ty {
        GgmlType::Q4K => {
            for (blk, o) in src.chunks_exact(bb).zip(out.chunks_exact_mut(QK_K)) {
                dequant_q4k_block(as_block(blk), o.try_into().expect("chunk is QK_K"));
            }
        }
        GgmlType::Q6K => {
            for (blk, o) in src.chunks_exact(bb).zip(out.chunks_exact_mut(QK_K)) {
                dequant_q6k_block(as_block(blk), o.try_into().expect("chunk is QK_K"));
            }
        }
        other => {
            if !crate::gguf::plain_to_f32(other, src, out) {
                return Err(QuantError::Unsupported(other));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Int8 activation path (aienos#34 L6): activations on ggml's Q8_K grid, dots
// accumulated in i32. The inner loops are written in the shape the compiler
// turns into `sdot`/`usdot` when the target has dotprod/i8mm (build with
// `-C target-feature=+dotprod,+i8mm`; GB10 has both). Without those features
// they still vectorize to widening multiplies.
// ---------------------------------------------------------------------------

/// Activations per Q8_K group sum (ggml's `bsums`).
pub const Q8K_GROUP: usize = 16;

/// Activations quantized to ggml's Q8_K grid (see [`quantize_q8k`]), with
/// room for `capacity` values so a forward pass allocates nothing.
pub struct Q8Act {
    d: Vec<f32>,
    q: Vec<i8>,
    bsums: Vec<i32>,
    len: usize,
}

impl Q8Act {
    /// Room for `capacity` activations (rounded down to whole 256-blocks).
    pub fn with_capacity(capacity: usize) -> Self {
        let blocks = capacity / QK_K;
        Self {
            d: alloc::vec![0.0; blocks],
            q: alloc::vec![0; blocks * QK_K],
            bsums: alloc::vec![0; blocks * (QK_K / Q8K_GROUP)],
            len: 0,
        }
    }

    /// Quantize `x` (a multiple of 256 values, at most the capacity).
    pub fn quantize(&mut self, x: &[f32]) -> Result<(), QuantError> {
        if x.len() % QK_K != 0 || x.len() > self.q.len() {
            return Err(QuantError::BadLength);
        }
        self.len = x.len();
        quantize_q8k(
            x,
            &mut self.q[..x.len()],
            &mut self.d[..x.len() / QK_K],
            &mut self.bsums[..x.len() / Q8K_GROUP],
        );
        Ok(())
    }

    /// Number of quantized activations held.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True before the first `quantize`.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Per-block scales (`len / 256`).
    pub fn scales(&self) -> &[f32] {
        &self.d[..self.len / QK_K]
    }

    /// The int8 values.
    pub fn values(&self) -> &[i8] {
        &self.q[..self.len]
    }

    /// Sums of the int8 values over 16 consecutive positions (`len / 16`).
    pub fn group_sums(&self) -> &[i32] {
        &self.bsums[..self.len / Q8K_GROUP]
    }
}

/// ggml's `quantize_row_q8_K`: per 256-block, `d = max / -127` (`max` the
/// value of largest magnitude), `q = min(127, nearest_int(x / d))` with ties
/// to even, `bsums` the sums of `q` over 16 consecutive values. The values
/// `q * d` are exactly what `decode::q8k_round` leaves in place.
pub fn quantize_q8k(x: &[f32], q: &mut [i8], d: &mut [f32], bsums: &mut [i32]) {
    let rows = x
        .chunks_exact(QK_K)
        .zip(q.chunks_exact_mut(QK_K))
        .zip(d.iter_mut())
        .zip(bsums.chunks_exact_mut(QK_K / Q8K_GROUP));
    for (((xb, qb), db), sb) in rows {
        let mut amax = 0f32;
        let mut max = 0f32;
        for &v in xb {
            if v.abs() > amax {
                amax = v.abs();
                max = v;
            }
        }
        if amax == 0.0 {
            *db = 0.0;
            qb.fill(0);
            sb.fill(0);
            continue;
        }
        let iscale = -127.0 / max;
        *db = 1.0 / iscale;
        for (xi, qi) in xb.iter().zip(qb.iter_mut()) {
            // nearest_int: magic-number rounding (ties to even), as ggml.
            let t = (*xi * iscale + 12_582_912.0) - 12_582_912.0;
            *qi = t.min(127.0) as i8;
        }
        for (g, s) in qb.chunks_exact(Q8K_GROUP).zip(sb.iter_mut()) {
            *s = g.iter().map(|&v| v as i32).sum();
        }
    }
}

/// `(sum(lo_nibble(q[l]) * y[l]), sum(hi_nibble(q[l]) * y[32 + l]))` over
/// 32 bytes: the shape that becomes four `usdot`.
#[inline(always)]
fn nibble_dot_i8(q: &[u8; Q4K_SUB], y: &[i8; 2 * Q4K_SUB]) -> (i32, i32) {
    let mut lo = 0i32;
    let mut hi = 0i32;
    for l in 0..Q4K_SUB {
        lo += (q[l] & 0x0f) as i32 * y[l] as i32;
    }
    for l in 0..Q4K_SUB {
        hi += (q[l] >> 4) as i32 * y[Q4K_SUB + l] as i32;
    }
    (lo, hi)
}

/// Dot of one Q4_K block with 256 Q8_K activations (`y`, block scale `yd`,
/// 16 group sums `ys`): ggml's `ggml_vec_dot_q4_K_q8_K`, i32 accumulation,
/// `d*sum(sc*q.y) - dmin*sum(m*sum(y))`.
pub fn dot_q4k_q8k(
    block: &[u8; Q4K_BYTES],
    y: &[i8; QK_K],
    yd: f32,
    ys: &[i32; QK_K / Q8K_GROUP],
) -> f32 {
    let d = rd_f16(block, 0);
    let dmin = rd_f16(block, 2);
    let scales = &block[4..16];
    let qs: &[u8; 128] = block[16..144].try_into().expect("128 nibble bytes");
    let mut sumi = 0i32;
    let mut mins = 0i32;
    for j in 0..4 {
        let (sc1, m1) = scale_min_k4(2 * j, scales);
        let (sc2, m2) = scale_min_k4(2 * j + 1, scales);
        let q: &[u8; Q4K_SUB] = qs[32 * j..32 * j + 32].try_into().expect("32 bytes");
        let yj: &[i8; 2 * Q4K_SUB] = y[64 * j..64 * j + 64].try_into().expect("64 y");
        let (lo, hi) = nibble_dot_i8(q, yj);
        sumi += sc1 as i32 * lo + sc2 as i32 * hi;
        mins +=
            m1 as i32 * (ys[4 * j] + ys[4 * j + 1]) + m2 as i32 * (ys[4 * j + 2] + ys[4 * j + 3]);
    }
    yd * (d * sumi as f32 - dmin * mins as f32)
}

/// One 32-weight quarter of a Q6_K half: two 16-weight scale groups,
/// `sum(sc * (q - 32) * y)` with `q` the unsigned 6-bit value (0..=63) from
/// nibble shift `SL` of `ql` and bit pair `SH` of `qh`, and the `-32`
/// applied through the group sums of `y`. Two plain loops (assemble, then
/// multiply) so each becomes vector code (`usdot` with i8mm).
#[inline(always)]
fn q6_quarter_i8<const SL: u32, const SH: u32>(
    ql: &[u8; 32],
    qh: &[u8; 32],
    sc: &[u8; 2],
    y: &[i8; 32],
    ys: &[i32; 2],
) -> i32 {
    let mut q = [0u8; 32];
    for l in 0..32 {
        q[l] = ((ql[l] >> SL) & 0x0f) | (((qh[l] >> SH) & 3) << 4);
    }
    let mut acc = 0i32;
    for g in 0..2 {
        let mut s = 0i32;
        for l in 0..Q8K_GROUP {
            s += q[Q8K_GROUP * g + l] as i32 * y[Q8K_GROUP * g + l] as i32;
        }
        acc += (sc[g] as i8) as i32 * (s - 32 * ys[g]);
    }
    acc
}

/// Dot of one Q6_K block with 256 Q8_K activations: ggml's
/// `ggml_vec_dot_q6_K_q8_K` (i32 accumulation).
pub fn dot_q6k_q8k(
    block: &[u8; Q6K_BYTES],
    y: &[i8; QK_K],
    yd: f32,
    ys: &[i32; QK_K / Q8K_GROUP],
) -> f32 {
    let d = rd_f16(block, 208);
    let mut isum = 0i32;
    for half in 0..2 {
        let ql = &block[64 * half..64 * half + 64];
        let ql0: &[u8; 32] = ql[..32].try_into().expect("32 ql");
        let ql1: &[u8; 32] = ql[32..].try_into().expect("32 ql");
        let qh: &[u8; 32] = block[128 + 32 * half..128 + 32 * half + 32]
            .try_into()
            .expect("32 qh");
        let sc = &block[192 + 8 * half..192 + 8 * half + 8];
        let yh = &y[128 * half..128 * half + 128];
        let sh = &ys[8 * half..8 * half + 8];
        // Quarter k uses ql bytes (k&1)*32.., nibble shift 4*(k>>1), qh bit
        // pair 2k and scales sc[2k..2k+2], exactly as dequant_q6k_block.
        let a = |r: core::ops::Range<usize>| -> (&[u8; 2], &[i8; 32], &[i32; 2]) {
            (
                sc[r.start / 16..r.start / 16 + 2].try_into().expect("2 sc"),
                yh[r.clone()].try_into().expect("32 y"),
                sh[r.start / 16..r.start / 16 + 2]
                    .try_into()
                    .expect("2 sums"),
            )
        };
        let (s0, y0, b0) = a(0..32);
        let (s1, y1, b1) = a(32..64);
        let (s2, y2, b2) = a(64..96);
        let (s3, y3, b3) = a(96..128);
        isum += q6_quarter_i8::<0, 0>(ql0, qh, s0, y0, b0);
        isum += q6_quarter_i8::<0, 2>(ql1, qh, s1, y1, b1);
        isum += q6_quarter_i8::<4, 4>(ql0, qh, s2, y2, b2);
        isum += q6_quarter_i8::<4, 6>(ql1, qh, s3, y3, b3);
    }
    yd * d * isum as f32
}

/// Dot of a whole quantized row (`act.len()` weights) with Q8_K activations.
pub fn dot_row_q8k(ty: GgmlType, src: &[u8], act: &Q8Act) -> Result<f32, QuantError> {
    let (bw, bb) = ty.block();
    if !matches!(ty, GgmlType::Q4K | GgmlType::Q6K) {
        return Err(QuantError::Unsupported(ty));
    }
    let n = act.len();
    if n % bw != 0 || src.len() != n / bw * bb {
        return Err(QuantError::BadLength);
    }
    let mut acc = 0f32;
    let blocks = src
        .chunks_exact(bb)
        .zip(act.values().chunks_exact(QK_K))
        .zip(act.scales())
        .zip(act.group_sums().chunks_exact(QK_K / Q8K_GROUP));
    for (((blk, y), &yd), ys) in blocks {
        let y: &[i8; QK_K] = y.try_into().expect("chunk is QK_K");
        let ys: &[i32; QK_K / Q8K_GROUP] = ys.try_into().expect("16 sums");
        acc += if ty == GgmlType::Q4K {
            dot_q4k_q8k(as_block(blk), y, yd, ys)
        } else {
            dot_q6k_q8k(as_block(blk), y, yd, ys)
        };
    }
    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: [u8; 2] = [0x00, 0x3c]; // f16 1.0

    #[test]
    fn q4k_hand_block() {
        // d=1, dmin=1. Sub-block j has scale j+1 and min j (all < 16 so they
        // sit in the plain low 6 bits of bytes 0..8). Nibble pattern: low
        // nibble = l%16, high nibble = 15 - l%16.
        let mut b = [0u8; Q4K_BYTES];
        b[0..2].copy_from_slice(&ONE);
        b[2..4].copy_from_slice(&ONE);
        for j in 0..4 {
            b[4 + j] = (j + 1) as u8; // scales 1..4 for sub-blocks 0..4
            b[8 + j] = j as u8; // mins 0..3
        }
        // sub-blocks 4..8: low nibble of bytes 8..12 = scale, high = min, and
        // the top two bits of bytes 0..4 / 4..8 are 0 so no extension.
        for j in 4..8 {
            b[8 + j] = ((j + 1) as u8) | ((j as u8) << 4);
        }
        for l in 0..128 {
            let lo = (l % 16) as u8;
            b[16 + l] = lo | ((15 - lo) << 4);
        }
        let mut out = [0f32; QK_K];
        dequant_q4k_block(&b, &mut out);
        for sb in 0..8 {
            let j = sb / 2;
            let (sc, mn) = (sb + 1, sb);
            for l in 0..32 {
                let lo = (l % 16) as f32;
                let q = if sb % 2 == 0 { lo } else { 15.0 - lo };
                let expect = sc as f32 * q - mn as f32;
                assert_eq!(out[32 * sb + l], expect, "sb {sb} l {l} (j {j})");
            }
        }
    }

    #[test]
    fn q4k_scale_extension_bits() {
        // Sub-block 4: scale = 0xf | (3 << 4) = 63 (byte 8 low nibble + byte 0 >> 6);
        // min = 0x2 | (2 << 4) = 34 (byte 8 high nibble + byte 4 >> 6).
        let mut b = [0u8; Q4K_BYTES];
        b[0..2].copy_from_slice(&ONE);
        b[2..4].copy_from_slice(&ONE);
        b[4] = 3 << 6; // byte 0 of scales: top bits -> scale high of sb4
        b[8] = 2 << 6; // byte 4 of scales: top bits -> min high of sb4
        b[12] = 0x0f | (0x2 << 4);
        for q in b[16..].iter_mut() {
            *q = 0x11;
        }
        let mut out = [0f32; QK_K];
        dequant_q4k_block(&b, &mut out);
        // sb4 is the low half of j=2 qs; nibble 1 -> 63*1 - 42.
        assert_eq!(out[128], 63.0 - 34.0);
        // sb0 has scale 0, min 0 -> exactly 0.
        assert_eq!(out[0], 0.0);
    }

    #[test]
    fn q6k_hand_block() {
        // d=1, all scales 1, ql nibbles = 0x0, qh = 0 -> q = -32 everywhere
        // for low nibbles; set specific positions to check the bit layout.
        let mut b = [0u8; Q6K_BYTES];
        b[208..210].copy_from_slice(&ONE);
        for i in 0..16 {
            b[192 + i] = 1;
        }
        let mut out = [0f32; QK_K];
        dequant_q6k_block(&b, &mut out);
        assert!(out.iter().all(|&v| v == -32.0));
        // l=0 of the first half: ql[0]=0x5a, qh[0]=0b11_10_01_00.
        b[0] = 0x5a;
        b[128] = 0b1110_0100;
        dequant_q6k_block(&b, &mut out);
        assert_eq!(out[0], 0xa as f32 - 32.0); // q1
        assert_eq!(out[64], ((0x5) | (2 << 4)) as f32 - 32.0); // q3: qh bits 4..6 = 2
        assert_eq!(out[32], 16.0 - 32.0); // q2: low nibble 0, qh bits 2..4 = 1
        assert_eq!(out[96], 48.0 - 32.0); // q4: low nibble of ql[32]=0, qh bits 6..8 = 3
    }

    #[test]
    fn q6k_scales_are_signed_and_per_16() {
        let mut b = [0u8; Q6K_BYTES];
        b[208..210].copy_from_slice(&ONE);
        for i in 0..16 {
            b[192 + i] = (i as i8 - 8) as u8;
        }
        // ql/qh zero -> q=-32; weight p has scale index p/16.
        let mut out = [0f32; QK_K];
        dequant_q6k_block(&b, &mut out);
        for p in 0..QK_K {
            assert_eq!(out[p], (p / 16) as f32 * -32.0 + 8.0 * 32.0, "p {p}");
        }
    }

    fn lcg(seed: &mut u64) -> u32 {
        *seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (*seed >> 33) as u32
    }

    fn serial_dot(w: &[f32; QK_K], x: &[f32; QK_K]) -> f32 {
        w.iter().zip(x).map(|(a, b)| a * b).sum()
    }

    #[test]
    fn q4k_fused_dot_matches_dequant_then_dot() {
        let mut seed = 7u64;
        for _ in 0..200 {
            let mut b = [0u8; Q4K_BYTES];
            for v in b.iter_mut() {
                *v = lcg(&mut seed) as u8;
            }
            // Keep d and dmin finite and modest: exponent bits in a sane range.
            b[1] = 0x30 | (b[1] & 0x03);
            b[3] = 0x2c | (b[3] & 0x03);
            let mut x = [0f32; QK_K];
            for v in x.iter_mut() {
                *v = (lcg(&mut seed) % 2001) as f32 / 1000.0 - 1.0;
            }
            let mut w = [0f32; QK_K];
            dequant_q4k_block(&b, &mut w);
            let want = serial_dot(&w, &x);
            let got = dot_q4k_f32(&b, &x);
            let scale = w.iter().zip(x).map(|(a, b)| (a * b).abs()).sum::<f32>();
            assert!(
                (got - want).abs() <= 1e-5 * scale.max(1e-3),
                "got {got} want {want} (scale {scale})"
            );
        }
    }

    #[test]
    fn q6k_fused_dot_matches_dequant_then_dot() {
        let mut seed = 11u64;
        for _ in 0..200 {
            let mut b = [0u8; Q6K_BYTES];
            for v in b.iter_mut() {
                *v = lcg(&mut seed) as u8;
            }
            b[209] = 0x30 | (b[209] & 0x03);
            let mut x = [0f32; QK_K];
            for v in x.iter_mut() {
                *v = (lcg(&mut seed) % 2001) as f32 / 1000.0 - 1.0;
            }
            let mut w = [0f32; QK_K];
            dequant_q6k_block(&b, &mut w);
            let want = serial_dot(&w, &x);
            let got = dot_q6k_f32(&b, &x);
            let scale = w.iter().zip(x).map(|(a, b)| (a * b).abs()).sum::<f32>();
            assert!(
                (got - want).abs() <= 1e-5 * scale.max(1e-3),
                "got {got} want {want} (scale {scale})"
            );
        }
    }

    fn random_block<const N: usize>(seed: &mut u64) -> [u8; N] {
        let mut b = [0u8; N];
        for v in b.iter_mut() {
            *v = lcg(seed) as u8;
        }
        b
    }

    fn random_x(seed: &mut u64, x: &mut [f32]) {
        for v in x.iter_mut() {
            *v = (lcg(seed) % 2001) as f32 / 1000.0 - 1.0;
        }
    }

    #[test]
    fn q8k_quantize_matches_q8k_round() {
        let mut seed = 11u64;
        let mut x = [0f32; 2 * QK_K];
        random_x(&mut seed, &mut x);
        x[300] = 0.0;
        let mut act = Q8Act::with_capacity(2 * QK_K);
        act.quantize(&x).unwrap();
        let mut rounded = x;
        crate::decode::q8k_round(&mut rounded);
        assert_eq!(act.len(), 2 * QK_K);
        for (blk, (&d, q)) in act
            .scales()
            .iter()
            .zip(act.values().chunks_exact(QK_K))
            .enumerate()
        {
            for (l, &qi) in q.iter().enumerate() {
                assert_eq!(
                    qi as f32 * d,
                    rounded[blk * QK_K + l],
                    "block {blk} value {l}"
                );
            }
        }
        for (g, &s) in act.group_sums().iter().enumerate() {
            let want: i32 = act.values()[16 * g..16 * g + 16]
                .iter()
                .map(|&v| v as i32)
                .sum();
            assert_eq!(s, want);
        }
        // Zero block: zero scale, zero values.
        let z = [0f32; QK_K];
        act.quantize(&z).unwrap();
        assert_eq!(act.scales(), &[0.0]);
        assert!(act.values().iter().all(|&v| v == 0));
        // Length rules.
        assert_eq!(act.quantize(&x[..100]), Err(QuantError::BadLength));
        let big = [0f32; 3 * QK_K];
        assert_eq!(act.quantize(&big), Err(QuantError::BadLength));
    }

    #[test]
    fn q4k_int8_dot_matches_f32_dot_of_rounded_activations() {
        let mut seed = 13u64;
        let mut act = Q8Act::with_capacity(QK_K);
        for _ in 0..200 {
            let mut b: [u8; Q4K_BYTES] = random_block(&mut seed);
            b[1] = 0x30 | (b[1] & 0x03);
            b[3] = 0x2c | (b[3] & 0x03);
            let mut x = [0f32; QK_K];
            random_x(&mut seed, &mut x);
            act.quantize(&x).unwrap();
            let mut xr = x;
            crate::decode::q8k_round(&mut xr);
            let mut w = [0f32; QK_K];
            dequant_q4k_block(&b, &mut w);
            let want = serial_dot(&w, &xr);
            let y: &[i8; QK_K] = act.values().try_into().unwrap();
            let ys: &[i32; 16] = act.group_sums().try_into().unwrap();
            let got = dot_q4k_q8k(&b, y, act.scales()[0], ys);
            let scale = w.iter().zip(xr).map(|(a, b)| (a * b).abs()).sum::<f32>();
            assert!(
                (got - want).abs() <= 1e-4 * scale.max(1e-3),
                "got {got} want {want} (scale {scale})"
            );
        }
    }

    #[test]
    fn q6k_int8_dot_matches_f32_dot_of_rounded_activations() {
        let mut seed = 17u64;
        let mut act = Q8Act::with_capacity(QK_K);
        for _ in 0..200 {
            let mut b: [u8; Q6K_BYTES] = random_block(&mut seed);
            b[209] = 0x30 | (b[209] & 0x03);
            let mut x = [0f32; QK_K];
            random_x(&mut seed, &mut x);
            act.quantize(&x).unwrap();
            let mut xr = x;
            crate::decode::q8k_round(&mut xr);
            let mut w = [0f32; QK_K];
            dequant_q6k_block(&b, &mut w);
            let want = serial_dot(&w, &xr);
            let y: &[i8; QK_K] = act.values().try_into().unwrap();
            let ys: &[i32; 16] = act.group_sums().try_into().unwrap();
            let got = dot_q6k_q8k(&b, y, act.scales()[0], ys);
            let scale = w.iter().zip(xr).map(|(a, b)| (a * b).abs()).sum::<f32>();
            assert!(
                (got - want).abs() <= 1e-4 * scale.max(1e-3),
                "got {got} want {want} (scale {scale})"
            );
        }
    }

    #[test]
    fn int8_row_dot_matches_block_sum_and_checks_lengths() {
        let mut seed = 19u64;
        let mut x = [0f32; 2 * QK_K];
        random_x(&mut seed, &mut x);
        let mut act = Q8Act::with_capacity(2 * QK_K);
        act.quantize(&x).unwrap();
        let mut src = [0u8; 2 * Q4K_BYTES];
        for v in src.iter_mut() {
            *v = lcg(&mut seed) as u8;
        }
        for blk in src.chunks_exact_mut(Q4K_BYTES) {
            blk[1] = 0x30 | (blk[1] & 0x03);
            blk[3] = 0x2c | (blk[3] & 0x03);
        }
        let got = dot_row_q8k(GgmlType::Q4K, &src, &act).unwrap();
        let mut want = 0f32;
        for (i, blk) in src.chunks_exact(Q4K_BYTES).enumerate() {
            let y: &[i8; QK_K] = act.values()[i * QK_K..(i + 1) * QK_K].try_into().unwrap();
            let ys: &[i32; 16] = act.group_sums()[16 * i..16 * i + 16].try_into().unwrap();
            want += dot_q4k_q8k(as_block(blk), y, act.scales()[i], ys);
        }
        assert_eq!(got, want);
        assert_eq!(
            dot_row_q8k(GgmlType::Q4K, &src[..Q4K_BYTES], &act),
            Err(QuantError::BadLength)
        );
        assert_eq!(
            dot_row_q8k(GgmlType::F32, &src, &act),
            Err(QuantError::Unsupported(GgmlType::F32))
        );
    }

    #[test]
    fn length_checks() {
        let mut out = [0f32; QK_K];
        assert_eq!(
            dequantize(GgmlType::Q4K, &[0u8; 143], &mut out),
            Err(QuantError::BadLength)
        );
        assert_eq!(
            dequantize(GgmlType::Q5K, &[0u8; 176], &mut out),
            Err(QuantError::Unsupported(GgmlType::Q5K))
        );
        let x = [1f32; QK_K];
        assert_eq!(dot_row(GgmlType::Q4K, &[0u8; Q4K_BYTES], &x), Ok(0.0));
    }
}
