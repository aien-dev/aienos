//! Quantized dot products on int8 activations with Armv8.2 dot product
//! (SDOT), for Cortex-A76 class cores (Raspberry Pi 5) and anything newer.
//!
//! Method (the one llama.cpp uses for K-quants, `ggml_vec_dot_q4_K_q8_K` and
//! `ggml_vec_dot_q6_K_q8_K`, ggml-cpu/arch/arm/quants.c at 4a89937: Q4_K body
//! lines 2789-2840, Q6_K body lines 3492-3560; `vdotq_s32` is
//! `ggml_vdotq_s32`, ggml-cpu-impl.h:319): the activation vector is quantized
//! once per 256-wide block to int8 ("Q8_K": scale `d = max/-127`, rounding to
//! nearest even, plus 16 group sums), the 4-bit/6-bit weights are unpacked to
//! bytes with and/shift/or, `sdot` multiplies 16 byte pairs into 4 i32 lanes,
//! and the per-sub-block scales are applied in integer arithmetic. Only the
//! block scale and min scale are floats.
//!
//! Selection is a typed capability: a [`DotProd`] token exists only when the
//! caller said the CPU has dotprod (the kernel passes the decode of
//! `ID_AA64ISAR0_EL1.DP`, never assumed here). Every SDOT function checks
//! nothing itself; it is only reachable with a token. Without the token the
//! scalar f32 path in `quant.rs` runs, unchanged. On non-aarch64 targets no
//! token can be made and the portable integer reference below is the only
//! implementation (it is also what the tests compare the SDOT code with).
//!
//! No libm, no allocation in the dot path; `Q8Act` is sized once.

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::gguf::GgmlType;
use crate::half::f16_to_f32;
use crate::quant::{scale_min_k4, QuantError, Q4K_BYTES, Q6K_BYTES, QK_K};

/// Proof that the CPU running this code has the Armv8.2 dot product
/// instructions. Made only by [`DotProd::new`] from a feature flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DotProd(());

impl DotProd {
    /// `Some` when `cpu_has_dotprod` is true and this build targets aarch64.
    pub fn new(cpu_has_dotprod: bool) -> Option<Self> {
        if cfg!(target_arch = "aarch64") && cpu_has_dotprod {
            Some(Self(()))
        } else {
            None
        }
    }
}

static CPU_DOTPROD: AtomicBool = AtomicBool::new(false);

/// Record the CPU's dotprod feature (the kernel calls this once at boot from
/// its feature decode). New `DecodeState`s pick it up. Default: off.
pub fn set_cpu_dotprod(on: bool) {
    CPU_DOTPROD.store(on, Ordering::Relaxed);
}

/// The recorded capability, if any.
pub fn cpu_dotprod() -> Option<DotProd> {
    DotProd::new(CPU_DOTPROD.load(Ordering::Relaxed))
}

/// Activations quantized to ggml's Q8_K blocks, preallocated.
pub struct Q8Act {
    qs: Vec<i8>,
    d: Vec<f32>,
    bsums: Vec<i16>,
    nblk: usize,
}

impl Q8Act {
    /// Room for vectors of up to `cols` values (rounded up to whole blocks).
    pub fn with_capacity(cols: usize) -> Self {
        let nb = cols.div_ceil(QK_K);
        Self {
            qs: vec![0; nb * QK_K],
            d: vec![0.0; nb],
            bsums: vec![0; nb * 16],
            nblk: 0,
        }
    }

    /// Quantize `x` (length a multiple of 256, at most the capacity). Same
    /// arithmetic as ggml `quantize_row_q8_K_ref`: the element of largest
    /// magnitude (first on ties) maps to -127, `d = 1/iscale`, round to
    /// nearest even, clamp at 127.
    pub fn quantize(&mut self, x: &[f32]) -> Result<(), QuantError> {
        if x.len() % QK_K != 0 || x.len() / QK_K > self.d.len() {
            return Err(QuantError::BadLength);
        }
        self.nblk = x.len() / QK_K;
        for (i, blk) in x.chunks_exact(QK_K).enumerate() {
            let qs = &mut self.qs[i * QK_K..(i + 1) * QK_K];
            let bs = &mut self.bsums[i * 16..(i + 1) * 16];
            let mut amax = 0f32;
            let mut max = 0f32;
            for &v in blk {
                if v.abs() > amax {
                    amax = v.abs();
                    max = v;
                }
            }
            if amax == 0.0 {
                self.d[i] = 0.0;
                qs.fill(0);
                bs.fill(0);
                continue;
            }
            let iscale = -127.0 / max;
            for (q, &v) in qs.iter_mut().zip(blk) {
                let t = v * iscale;
                // nearest_int: magic-number rounding (ties to even), as ggml.
                *q = (((t + 12_582_912.0) - 12_582_912.0).min(127.0)) as i8;
            }
            for (g, s) in bs.iter_mut().enumerate() {
                *s = qs[16 * g..16 * g + 16].iter().map(|&q| q as i16).sum();
            }
            self.d[i] = 1.0 / iscale;
        }
        Ok(())
    }

    /// Number of 256-blocks in the last quantized vector.
    pub fn blocks(&self) -> usize {
        self.nblk
    }

    /// Dequantized value `q * d` (what the dot actually sees); for tests.
    pub fn value(&self, i: usize) -> f32 {
        self.qs[i] as f32 * self.d[i / QK_K]
    }

    fn block(&self, i: usize) -> Q8Blk<'_> {
        Q8Blk {
            d: self.d[i],
            qs: self.qs[i * QK_K..(i + 1) * QK_K].try_into().expect("QK_K"),
            bsums: self.bsums[i * 16..(i + 1) * 16].try_into().expect("16"),
        }
    }
}

#[derive(Clone, Copy)]
struct Q8Blk<'a> {
    d: f32,
    qs: &'a [i8; QK_K],
    bsums: &'a [i16; 16],
}

fn rd_f16(b: &[u8], at: usize) -> f32 {
    f16_to_f32(u16::from_le_bytes([b[at], b[at + 1]]))
}

/// Unpack the eight 6-bit scales and mins of a Q4_K block.
fn q4k_scales(blk: &[u8; Q4K_BYTES]) -> ([u8; 8], [u8; 8]) {
    let (mut sc, mut mn) = ([0u8; 8], [0u8; 8]);
    for j in 0..8 {
        let (s, m) = scale_min_k4(j, &blk[4..16]);
        sc[j] = s;
        mn[j] = m;
    }
    (sc, mn)
}

/// Portable integer reference for one Q4_K block: `(sumi, sumi_mins)` where
/// `sumi = sum_sb scale[sb] * sum_{l in sb} nibble * q8` and
/// `sumi_mins = sum_sb min[sb] * sum_{l in sb} q8`.
fn q4k_accum_ref(blk: &[u8; Q4K_BYTES], y: &Q8Blk<'_>) -> (i32, i32) {
    let (sc, mn) = q4k_scales(blk);
    let qs = &blk[16..144];
    let (mut sumi, mut mins) = (0i32, 0i32);
    for j in 0..4 {
        let (mut lo, mut hi) = (0i32, 0i32);
        for l in 0..32 {
            let b = qs[32 * j + l];
            lo += (b & 0x0f) as i32 * y.qs[64 * j + l] as i32;
            hi += (b >> 4) as i32 * y.qs[64 * j + 32 + l] as i32;
        }
        sumi += lo * sc[2 * j] as i32 + hi * sc[2 * j + 1] as i32;
    }
    for sb in 0..8 {
        mins += mn[sb] as i32 * (y.bsums[2 * sb] as i32 + y.bsums[2 * sb + 1] as i32);
    }
    (sumi, mins)
}

/// Portable integer reference for one Q6_K block: `(isum, isum_mins)`; the
/// weight is `d * scale * (q - 32)`, so the block dot is
/// `isum - 32 * isum_mins` with `isum_mins = sum_g scale[g] * bsum[g]`.
fn q6k_accum_ref(blk: &[u8; Q6K_BYTES], y: &Q8Blk<'_>) -> (i32, i32) {
    let sc = &blk[192..208];
    let mut isum = 0i32;
    for half in 0..2 {
        let ql = &blk[64 * half..64 * half + 64];
        let qh = &blk[128 + 32 * half..128 + 32 * half + 32];
        let yy = &y.qs[128 * half..128 * half + 128];
        for l in 0..32 {
            let is = l / 16;
            let h = qh[l];
            let q1 = ((ql[l] & 0x0f) | ((h & 3) << 4)) as i32;
            let q2 = ((ql[l + 32] & 0x0f) | (((h >> 2) & 3) << 4)) as i32;
            let q3 = ((ql[l] >> 4) | (((h >> 4) & 3) << 4)) as i32;
            let q4 = ((ql[l + 32] >> 4) | (((h >> 6) & 3) << 4)) as i32;
            let s = |k: usize| sc[8 * half + is + k] as i8 as i32;
            isum += q1 * yy[l] as i32 * s(0)
                + q2 * yy[l + 32] as i32 * s(2)
                + q3 * yy[l + 64] as i32 * s(4)
                + q4 * yy[l + 96] as i32 * s(6);
        }
    }
    let mut mins = 0i32;
    for g in 0..16 {
        mins += sc[g] as i8 as i32 * y.bsums[g] as i32;
    }
    (isum, mins)
}

fn q4k_finish(blk: &[u8; Q4K_BYTES], y: &Q8Blk<'_>, acc: (i32, i32)) -> f32 {
    let d = y.d * rd_f16(blk, 0);
    let dmin = y.d * rd_f16(blk, 2);
    d * acc.0 as f32 - dmin * acc.1 as f32
}

fn q6k_finish(blk: &[u8; Q6K_BYTES], y: &Q8Blk<'_>, acc: (i32, i32)) -> f32 {
    rd_f16(blk, 208) * y.d * (acc.0 - 32 * acc.1) as f32
}

/// Block dot with the portable integer arithmetic (reference for the tests;
/// also the only path on non-aarch64).
pub fn dot_q4k_q8_ref(blk: &[u8; Q4K_BYTES], q8: &Q8Act, bi: usize) -> f32 {
    let y = q8.block(bi);
    q4k_finish(blk, &y, q4k_accum_ref(blk, &y))
}

/// Same for Q6_K.
pub fn dot_q6k_q8_ref(blk: &[u8; Q6K_BYTES], q8: &Q8Act, bi: usize) -> f32 {
    let y = q8.block(bi);
    q6k_finish(blk, &y, q6k_accum_ref(blk, &y))
}

#[cfg(target_arch = "aarch64")]
mod neon {
    use super::*;
    use core::arch::aarch64::*;

    /// # Safety
    /// CPU must implement FEAT_DotProd (guaranteed by holding a [`DotProd`]).
    #[inline]
    #[target_feature(enable = "dotprod")]
    pub unsafe fn q4k_accum(blk: &[u8; Q4K_BYTES], y: &Q8Blk<'_>) -> (i32, i32) {
        let (sc, mn) = q4k_scales(blk);
        let m4 = vdupq_n_u8(0x0f);
        let qp = blk.as_ptr().add(16);
        let yp = y.qs.as_ptr();
        let mut sumv = vdupq_n_s32(0);
        let zero = vdupq_n_s32(0);
        for j in 0..4 {
            let a0 = vld1q_u8(qp.add(32 * j));
            let a1 = vld1q_u8(qp.add(32 * j + 16));
            let y0 = vld1q_s8(yp.add(64 * j));
            let y1 = vld1q_s8(yp.add(64 * j + 16));
            let y2 = vld1q_s8(yp.add(64 * j + 32));
            let y3 = vld1q_s8(yp.add(64 * j + 48));
            let lo = vdotq_s32(
                vdotq_s32(zero, vreinterpretq_s8_u8(vandq_u8(a0, m4)), y0),
                vreinterpretq_s8_u8(vandq_u8(a1, m4)),
                y1,
            );
            let hi = vdotq_s32(
                vdotq_s32(zero, vreinterpretq_s8_u8(vshrq_n_u8::<4>(a0)), y2),
                vreinterpretq_s8_u8(vshrq_n_u8::<4>(a1)),
                y3,
            );
            sumv = vmlaq_n_s32(sumv, lo, sc[2 * j] as i32);
            sumv = vmlaq_n_s32(sumv, hi, sc[2 * j + 1] as i32);
        }
        let mut mins = 0i32;
        for sb in 0..8 {
            mins += mn[sb] as i32 * (y.bsums[2 * sb] as i32 + y.bsums[2 * sb + 1] as i32);
        }
        (vaddvq_s32(sumv), mins)
    }

    /// # Safety
    /// As [`q4k_accum`].
    #[inline]
    #[target_feature(enable = "dotprod")]
    pub unsafe fn q6k_accum(blk: &[u8; Q6K_BYTES], y: &Q8Blk<'_>) -> (i32, i32) {
        let m4 = vdupq_n_u8(0x0f);
        let m3 = vdupq_n_u8(0x03);
        let zero = vdupq_n_s32(0);
        let sc = &blk[192..208];
        let mut isum = 0i32;
        for half in 0..2 {
            let ql = blk.as_ptr().add(64 * half);
            let qh = blk.as_ptr().add(128 + 32 * half);
            let yp = y.qs.as_ptr().add(128 * half);
            let s = &sc[8 * half..8 * half + 8];
            let (qh0, qh1) = (vld1q_u8(qh), vld1q_u8(qh.add(16)));
            let (l0, l1, l2, l3) = (
                vld1q_u8(ql),
                vld1q_u8(ql.add(16)),
                vld1q_u8(ql.add(32)),
                vld1q_u8(ql.add(48)),
            );
            // low nibbles, qh bit pairs 0 and 1
            let h0 = vshlq_n_u8::<4>(vandq_u8(qh0, m3));
            let h1 = vshlq_n_u8::<4>(vandq_u8(qh1, m3));
            let h2 = vshlq_n_u8::<4>(vandq_u8(vshrq_n_u8::<2>(qh0), m3));
            let h3 = vshlq_n_u8::<4>(vandq_u8(vshrq_n_u8::<2>(qh1), m3));
            let b = [
                vorrq_u8(vandq_u8(l0, m4), h0),
                vorrq_u8(vandq_u8(l1, m4), h1),
                vorrq_u8(vandq_u8(l2, m4), h2),
                vorrq_u8(vandq_u8(l3, m4), h3),
            ];
            for k in 0..4 {
                let p = vdotq_s32(zero, vreinterpretq_s8_u8(b[k]), vld1q_s8(yp.add(16 * k)));
                isum += vaddvq_s32(p) * s[k] as i8 as i32;
            }
            // high nibbles, qh bit pairs 2 and 3
            let h0 = vshlq_n_u8::<4>(vandq_u8(vshrq_n_u8::<4>(qh0), m3));
            let h1 = vshlq_n_u8::<4>(vandq_u8(vshrq_n_u8::<4>(qh1), m3));
            let h2 = vshlq_n_u8::<4>(vandq_u8(vshrq_n_u8::<6>(qh0), m3));
            let h3 = vshlq_n_u8::<4>(vandq_u8(vshrq_n_u8::<6>(qh1), m3));
            let b = [
                vorrq_u8(vshrq_n_u8::<4>(l0), h0),
                vorrq_u8(vshrq_n_u8::<4>(l1), h1),
                vorrq_u8(vshrq_n_u8::<4>(l2), h2),
                vorrq_u8(vshrq_n_u8::<4>(l3), h3),
            ];
            for k in 0..4 {
                let p = vdotq_s32(
                    zero,
                    vreinterpretq_s8_u8(b[k]),
                    vld1q_s8(yp.add(64 + 16 * k)),
                );
                isum += vaddvq_s32(p) * s[4 + k] as i8 as i32;
            }
        }
        let mut mins = 0i32;
        for g in 0..16 {
            mins += sc[g] as i8 as i32 * y.bsums[g] as i32;
        }
        (isum, mins)
    }

    /// # Safety
    /// As [`q4k_accum`]; `src` is whole Q4_K blocks and `q8` has the same count.
    #[target_feature(enable = "dotprod")]
    pub unsafe fn row_q4k(src: &[u8], q8: &Q8Act) -> f32 {
        let mut acc = 0f32;
        for (i, b) in src.chunks_exact(Q4K_BYTES).enumerate() {
            let blk: &[u8; Q4K_BYTES] = b.try_into().expect("Q4K_BYTES");
            let y = q8.block(i);
            acc += q4k_finish(blk, &y, q4k_accum(blk, &y));
        }
        acc
    }

    /// # Safety
    /// As [`row_q4k`] for Q6_K.
    #[target_feature(enable = "dotprod")]
    pub unsafe fn row_q6k(src: &[u8], q8: &Q8Act) -> f32 {
        let mut acc = 0f32;
        for (i, b) in src.chunks_exact(Q6K_BYTES).enumerate() {
            let blk: &[u8; Q6K_BYTES] = b.try_into().expect("Q6K_BYTES");
            let y = q8.block(i);
            acc += q6k_finish(blk, &y, q6k_accum(blk, &y));
        }
        acc
    }
}

/// SDOT block dot (Q4_K); test and bench hook, needs the capability token.
#[cfg(target_arch = "aarch64")]
pub fn dot_q4k_q8_sdot(_t: DotProd, blk: &[u8; Q4K_BYTES], q8: &Q8Act, bi: usize) -> f32 {
    let y = q8.block(bi);
    // SAFETY: the token proves FEAT_DotProd.
    unsafe { q4k_finish(blk, &y, neon::q4k_accum(blk, &y)) }
}

/// SDOT block dot (Q6_K).
#[cfg(target_arch = "aarch64")]
pub fn dot_q6k_q8_sdot(_t: DotProd, blk: &[u8; Q6K_BYTES], q8: &Q8Act, bi: usize) -> f32 {
    let y = q8.block(bi);
    // SAFETY: the token proves FEAT_DotProd.
    unsafe { q6k_finish(blk, &y, neon::q6k_accum(blk, &y)) }
}

/// Integer accumulations `(sum, mins)` of the SDOT block code; tests compare
/// them bit for bit with the portable reference.
#[cfg(target_arch = "aarch64")]
pub fn q4k_accum_sdot(_t: DotProd, blk: &[u8; Q4K_BYTES], q8: &Q8Act, bi: usize) -> (i32, i32) {
    let y = q8.block(bi);
    // SAFETY: the token proves FEAT_DotProd.
    unsafe { neon::q4k_accum(blk, &y) }
}

/// As [`q4k_accum_sdot`] for Q6_K.
#[cfg(target_arch = "aarch64")]
pub fn q6k_accum_sdot(_t: DotProd, blk: &[u8; Q6K_BYTES], q8: &Q8Act, bi: usize) -> (i32, i32) {
    let y = q8.block(bi);
    // SAFETY: the token proves FEAT_DotProd.
    unsafe { neon::q6k_accum(blk, &y) }
}

/// Portable accumulations (reference) for the tests.
pub fn q4k_accum_portable(blk: &[u8; Q4K_BYTES], q8: &Q8Act, bi: usize) -> (i32, i32) {
    q4k_accum_ref(blk, &q8.block(bi))
}

/// As [`q4k_accum_portable`] for Q6_K.
pub fn q6k_accum_portable(blk: &[u8; Q6K_BYTES], q8: &Q8Act, bi: usize) -> (i32, i32) {
    q6k_accum_ref(blk, &q8.block(bi))
}

/// Dot of a whole quantized row with the quantized activations, using SDOT.
pub fn dot_row_q8(_t: DotProd, ty: GgmlType, src: &[u8], q8: &Q8Act) -> Result<f32, QuantError> {
    let (bw, bb) = ty.block();
    if !matches!(ty, GgmlType::Q4K | GgmlType::Q6K) {
        return Err(QuantError::Unsupported(ty));
    }
    if src.len() % bb != 0 || src.len() / bb != q8.blocks() || bw != QK_K {
        return Err(QuantError::BadLength);
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: the token proves FEAT_DotProd; lengths checked above.
        Ok(unsafe {
            if ty == GgmlType::Q4K {
                neon::row_q4k(src, q8)
            } else {
                neon::row_q6k(src, q8)
            }
        })
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let mut acc = 0f32;
        for (i, b) in src.chunks_exact(bb).enumerate() {
            acc += if ty == GgmlType::Q4K {
                dot_q4k_q8_ref(b.try_into().expect("Q4K_BYTES"), q8, i)
            } else {
                dot_q6k_q8_ref(b.try_into().expect("Q6K_BYTES"), q8, i)
            };
        }
        Ok(acc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::q8k_round;
    use crate::quant::{dequant_q4k_block, dequant_q6k_block, dot_row};
    use std::eprintln;
    use std::vec::Vec;

    /// xorshift64*, fixed seeds.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
        fn byte(&mut self) -> u8 {
            (self.next() >> 32) as u8
        }
        fn unit(&mut self) -> f32 {
            ((self.next() >> 40) as f32 / (1u64 << 24) as f32) * 2.0 - 1.0
        }
    }

    fn token() -> Option<DotProd> {
        #[cfg(target_arch = "aarch64")]
        {
            DotProd::new(std::arch::is_aarch64_feature_detected!("dotprod"))
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            None
        }
    }

    fn f16(v: f32) -> [u8; 2] {
        // exact for the values used here (small integers and halves)
        let bits = v.to_bits();
        if v == 0.0 {
            return [0, 0];
        }
        let sign = ((bits >> 16) & 0x8000) as u16;
        let e = ((bits >> 23) & 0xff) as i32 - 127 + 15;
        let m = ((bits >> 13) & 0x3ff) as u16;
        (sign | ((e as u16) << 10) | m).to_le_bytes()
    }

    #[derive(Clone, Copy)]
    enum Fill {
        Random,
        MaxScales,
        ZeroScales,
        AllOnes,
        AllZero,
    }

    fn q4k_block(r: &mut Rng, fill: Fill) -> [u8; Q4K_BYTES] {
        let mut b = [0u8; Q4K_BYTES];
        for x in b.iter_mut() {
            *x = r.byte();
        }
        match fill {
            Fill::Random => {}
            Fill::MaxScales => b[4..16].fill(0xff), // all scales and mins = 63
            Fill::ZeroScales => b[4..16].fill(0),
            Fill::AllOnes => {
                b[4..].fill(0xff);
            }
            Fill::AllZero => b[4..].fill(0),
        }
        b[0..2].copy_from_slice(&f16(0.0625 * (1 + r.byte() % 8) as f32));
        b[2..4].copy_from_slice(&f16(0.03125 * (1 + r.byte() % 8) as f32));
        b
    }

    fn q6k_block(r: &mut Rng, fill: Fill) -> [u8; Q6K_BYTES] {
        let mut b = [0u8; Q6K_BYTES];
        for x in b.iter_mut() {
            *x = r.byte();
        }
        match fill {
            Fill::Random => {}
            Fill::MaxScales => {
                for (i, s) in b[192..208].iter_mut().enumerate() {
                    *s = if i % 2 == 0 { 127 } else { 0x80 }; // +127 and -128
                }
            }
            Fill::ZeroScales => b[192..208].fill(0),
            Fill::AllOnes => b[..192].fill(0xff),
            Fill::AllZero => b[..192].fill(0),
        }
        b[208..210].copy_from_slice(&f16(0.0625 * (1 + r.byte() % 8) as f32));
        b
    }

    fn acts(r: &mut Rng, nblk: usize, kind: u8) -> (Vec<f32>, Q8Act) {
        let mut x = std::vec![0f32; nblk * QK_K];
        for (i, v) in x.iter_mut().enumerate() {
            *v = match kind {
                0 => r.unit() * 3.0,
                1 => 1.0, // all equal: every q = -127
                2 => {
                    if i % 2 == 0 {
                        100.0
                    } else {
                        -100.0
                    }
                } // extremes of both signs
                _ => 0.0,
            };
        }
        let mut q = Q8Act::with_capacity(x.len());
        q.quantize(&x).unwrap();
        (x, q)
    }

    #[test]
    fn quantize_matches_q8k_round_and_sums() {
        let mut r = Rng(0x1234_5678_9abc_def1);
        let (x, q) = acts(&mut r, 6, 0);
        let mut want = x.clone();
        q8k_round(&mut want);
        for i in 0..x.len() {
            assert_eq!(q.value(i).to_bits(), want[i].to_bits(), "elem {i}");
        }
        for b in 0..6 {
            for g in 0..16 {
                let s: i32 = (0..16).map(|l| q.qs[b * QK_K + 16 * g + l] as i32).sum();
                assert_eq!(q.bsums[b * 16 + g] as i32, s);
            }
            let m = q.qs[b * QK_K..(b + 1) * QK_K]
                .iter()
                .map(|&v| (v as i32).abs())
                .max();
            assert_eq!(m, Some(127));
        }
        // all-zero block: scale 0, all zero
        let (_, z) = acts(&mut r, 2, 3);
        assert!(z.d[..2].iter().all(|&d| d == 0.0) && z.qs.iter().all(|&v| v == 0));
        // length rules
        let mut q = Q8Act::with_capacity(256);
        assert_eq!(q.quantize(&[0.0; 100]), Err(QuantError::BadLength));
        assert_eq!(q.quantize(&[0.0; 512]), Err(QuantError::BadLength));
    }

    /// Dot of the dequantized weights with the dequantized (rounded)
    /// activations in f32: what the integer path must reproduce up to float
    /// summation order and the f16-scaled products.
    fn f32_reference(w: &[f32; QK_K], q: &Q8Act, bi: usize) -> (f32, f32) {
        let mut dot = 0f64;
        let mut mag = 0f64;
        for l in 0..QK_K {
            let t = w[l] as f64 * q.value(bi * QK_K + l) as f64;
            dot += t;
            mag += t.abs();
        }
        (dot as f32, mag as f32)
    }

    const FILLS: [Fill; 5] = [
        Fill::Random,
        Fill::MaxScales,
        Fill::ZeroScales,
        Fill::AllOnes,
        Fill::AllZero,
    ];

    #[test]
    fn q4k_integer_dot_equals_f32_dot_of_rounded_activations() {
        let mut r = Rng(0xdead_beef_0001);
        for n in 0..400 {
            let blk = q4k_block(&mut r, FILLS[n % 5]);
            let (_, q) = acts(&mut r, 1, (n % 4) as u8);
            let mut w = [0f32; QK_K];
            dequant_q4k_block(&blk, &mut w);
            let (want, mag) = f32_reference(&w, &q, 0);
            let got = dot_q4k_q8_ref(&blk, &q, 0);
            assert!(
                (got - want).abs() <= 2e-5 * mag.max(1e-3),
                "n {n}: {got} vs {want}"
            );
        }
    }

    #[test]
    fn q6k_integer_dot_equals_f32_dot_of_rounded_activations() {
        let mut r = Rng(0xdead_beef_0002);
        for n in 0..400 {
            let blk = q6k_block(&mut r, FILLS[n % 5]);
            let (_, q) = acts(&mut r, 1, (n % 4) as u8);
            let mut w = [0f32; QK_K];
            dequant_q6k_block(&blk, &mut w);
            let (want, mag) = f32_reference(&w, &q, 0);
            let got = dot_q6k_q8_ref(&blk, &q, 0);
            assert!(
                (got - want).abs() <= 2e-5 * mag.max(1e-3),
                "n {n}: {got} vs {want}"
            );
        }
    }

    #[test]
    fn sdot_accumulations_are_bit_exact_vs_portable_q4k() {
        let Some(t) = token() else {
            eprintln!("SKIP: no dotprod on this CPU or not aarch64");
            return;
        };
        let mut r = Rng(0x5eed_0004);
        for n in 0..2000 {
            let blk = q4k_block(&mut r, FILLS[n % 5]);
            let (_, q) = acts(&mut r, 1, (n % 4) as u8);
            #[cfg(target_arch = "aarch64")]
            {
                assert_eq!(
                    q4k_accum_sdot(t, &blk, &q, 0),
                    q4k_accum_portable(&blk, &q, 0),
                    "n {n}"
                );
                assert_eq!(
                    dot_q4k_q8_sdot(t, &blk, &q, 0).to_bits(),
                    dot_q4k_q8_ref(&blk, &q, 0).to_bits()
                );
            }
            let _ = t;
        }
    }

    #[test]
    fn sdot_accumulations_are_bit_exact_vs_portable_q6k() {
        let Some(t) = token() else {
            eprintln!("SKIP: no dotprod on this CPU or not aarch64");
            return;
        };
        let mut r = Rng(0x5eed_0006);
        for n in 0..2000 {
            let blk = q6k_block(&mut r, FILLS[n % 5]);
            let (_, q) = acts(&mut r, 1, (n % 4) as u8);
            #[cfg(target_arch = "aarch64")]
            {
                assert_eq!(
                    q6k_accum_sdot(t, &blk, &q, 0),
                    q6k_accum_portable(&blk, &q, 0),
                    "n {n}"
                );
                assert_eq!(
                    dot_q6k_q8_sdot(t, &blk, &q, 0).to_bits(),
                    dot_q6k_q8_ref(&blk, &q, 0).to_bits()
                );
            }
            let _ = t;
        }
    }

    /// Hand-computed block (no random data): Q4_K, d=1, dmin=1, scale of
    /// sub-block j is j+1, min j, all nibbles 3, activations all equal so
    /// every q8 is -127 and d_y = 1/(-127/1) = -1/127.
    #[test]
    fn q4k_hand_computed_scale_application() {
        let mut b = [0u8; Q4K_BYTES];
        b[0..2].copy_from_slice(&f16(1.0));
        b[2..4].copy_from_slice(&f16(1.0));
        for j in 0..4 {
            b[4 + j] = (j + 1) as u8;
            b[8 + j] = j as u8;
        }
        for j in 4..8 {
            b[8 + j] = ((j + 1) as u8) | ((j as u8) << 4);
        }
        b[16..].fill(0x33);
        let x = [1.0f32; QK_K];
        let mut q = Q8Act::with_capacity(QK_K);
        q.quantize(&x).unwrap();
        // sumi = sum_sb scale*3*32*(-127); sumi_mins = sum_sb min*32*(-127)
        let sumi: i32 = (1..=8).map(|s| s * 3 * 32 * -127).sum();
        let mins: i32 = (0..8).map(|m| m * 32 * -127).sum();
        assert_eq!(q4k_accum_portable(&b, &q, 0), (sumi, mins));
        let dy = 1.0f32 / (-127.0f32 / 1.0);
        let want = dy * sumi as f32 - dy * mins as f32;
        assert_eq!(dot_q4k_q8_ref(&b, &q, 0), want);
        // the true f32 dot is sum(scale*3 - min) over 32 values each
        let truth: f32 = (0..8).map(|s| ((s + 1) * 3 - s) as f32 * 32.0).sum();
        assert!((want - truth).abs() < 1e-3, "{want} vs {truth}");
        #[cfg(target_arch = "aarch64")]
        if let Some(t) = token() {
            assert_eq!(dot_q4k_q8_sdot(t, &b, &q, 0), want);
        }
    }

    #[test]
    fn row_dot_matches_scalar_path_and_checks_lengths() {
        let mut r = Rng(0x7007);
        let nb = 9;
        let mut src4 = Vec::new();
        let mut src6 = Vec::new();
        for n in 0..nb {
            src4.extend_from_slice(&q4k_block(&mut r, FILLS[n % 5]));
            src6.extend_from_slice(&q6k_block(&mut r, FILLS[n % 5]));
        }
        let (x, q) = acts(&mut r, nb, 0);
        let mut xr = x.clone();
        q8k_round(&mut xr);
        let Some(t) = token() else {
            // portable reference still agrees with the scalar f32 row dot
            return;
        };
        for (ty, src) in [(GgmlType::Q4K, &src4), (GgmlType::Q6K, &src6)] {
            let got = dot_row_q8(t, ty, src, &q).unwrap();
            let want = dot_row(ty, src, &xr).unwrap();
            let mag: f32 = xr.iter().map(|v| v.abs()).sum::<f32>() * 60.0;
            assert!((got - want).abs() <= 1e-4 * mag, "{ty:?}: {got} vs {want}");
            assert_eq!(dot_row_q8(t, ty, &src[1..], &q), Err(QuantError::BadLength));
        }
        assert_eq!(
            dot_row_q8(t, GgmlType::F32, &src4, &q),
            Err(QuantError::Unsupported(GgmlType::F32))
        );
    }

    #[test]
    fn token_only_when_flag_set() {
        assert_eq!(DotProd::new(false), None);
        set_cpu_dotprod(false);
        assert_eq!(cpu_dotprod(), None);
    }
}
