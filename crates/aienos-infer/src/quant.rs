//! ggml block dequantizers (scalar reference implementations).
//!
//! Formulas follow ggml's `dequantize_row_q4_K` / `dequantize_row_q6_K`
//! (ggml-quants.c). Both formats pack 256 weights per super-block.

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

/// Dot product of one Q4_K block with 256 f32 activations (dequantize, then
/// accumulate in f32; scalar reference, not bit-identical to ggml's q8 path).
pub fn dot_q4k_f32(block: &[u8; Q4K_BYTES], x: &[f32; QK_K]) -> f32 {
    let mut w = [0f32; QK_K];
    dequant_q4k_block(block, &mut w);
    w.iter().zip(x).map(|(a, b)| a * b).sum()
}

/// Dot product of one Q6_K block with 256 f32 activations.
pub fn dot_q6k_f32(block: &[u8; Q6K_BYTES], x: &[f32; QK_K]) -> f32 {
    let mut w = [0f32; QK_K];
    dequant_q6k_block(block, &mut w);
    w.iter().zip(x).map(|(a, b)| a * b).sum()
}

/// Dot of a whole quantized row (`src`, `x.len()` weights) with `x`.
pub fn dot_row(ty: GgmlType, src: &[u8], x: &[f32]) -> Result<f32, QuantError> {
    let (bw, bb) = ty.block();
    if !matches!(ty, GgmlType::Q4K | GgmlType::Q6K) {
        return Err(QuantError::Unsupported(ty));
    }
    if x.len() % bw != 0 || src.len() != x.len() / bw * bb {
        return Err(QuantError::BadLength);
    }
    let mut acc = 0f32;
    for (blk, xs) in src.chunks_exact(bb).zip(x.chunks_exact(QK_K)) {
        let xs: &[f32; QK_K] = xs.try_into().expect("chunk is QK_K");
        acc += if ty == GgmlType::Q4K {
            dot_q4k_f32(as_block(blk), xs)
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
