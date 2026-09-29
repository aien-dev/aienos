//! Pure-Rust, allocation-free AES-256 block cipher implementation conforming to FIPS 197.
//!
//! Designed for bare-metal `#![no_std]` without external dependencies.
//!
//! # Constant-time design
//!
//! The S-box is computed, not looked up: each byte is inverted in GF(2^8)
//! (as `x^254`) and then passed through the FIPS 197 affine transform. All
//! arithmetic is shifts, masks and XORs with a fixed number of steps, so no
//! memory address and no branch depends on key or data bytes. The same S-box
//! routine serves encryption (`SubBytes`) and key expansion (`SubWord`).
//! Bytes are processed 16 at a time packed in a `u128` ("SIMD within a
//! register"), which keeps the cost reasonable without a lookup table.
//!
//! This is slower than a table-driven AES. Hardware AES instructions
//! (ARMv8 FEAT_AES: `AESE`/`AESMC`) are constant-time and much faster; they
//! are a possible future speedup and are **not** implemented here.

/// AES-256 expanded round keys (15 rounds, 4 words per round = 60 words = 240 bytes).
#[derive(Clone)]
pub struct Aes256Key {
    round_keys: [u32; 60],
}

impl core::fmt::Debug for Aes256Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Aes256Key([REDACTED])")
    }
}

impl Drop for Aes256Key {
    fn drop(&mut self) {
        for word in &mut self.round_keys {
            unsafe { core::ptr::write_volatile(word, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Round constants.
const RCON: [u32; 10] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000,
];

/// `m` repeated in every byte lane of a `u128`.
const fn lanes(m: u8) -> u128 {
    (m as u128) * 0x0101_0101_0101_0101_0101_0101_0101_0101
}

const LSB: u128 = lanes(0x01);
const LOW7: u128 = lanes(0x7f);

/// Turn a lane value of 0 or 1 into 0x00 or 0xff, per lane, without branches.
///
/// `(bits << 8) - bits` equals `bits * 0xff` lane by lane: every lane's
/// product fits in its own byte, so no carry or borrow crosses lanes, and the
/// identity holds modulo 2^128 even when the top lane's shift falls off.
#[inline(always)]
fn lane_mask(bits: u128) -> u128 {
    (bits << 8).wrapping_sub(bits)
}

/// Multiply every byte lane by `x` in GF(2^8) (FIPS 197 `xtime`), branch-free.
#[inline(always)]
fn xtime_lanes(a: u128) -> u128 {
    let hi = (a >> 7) & LSB; // 0 or 1 per lane: did the top bit fall out?
                             // hi * 0x1b per lane, written as shifts so lanes stay independent.
    let reduce = hi ^ (hi << 1) ^ (hi << 3) ^ (hi << 4);
    ((a & LOW7) << 1) ^ reduce
}

/// Lane-wise GF(2^8) multiply `a * b` modulo x^8 + x^4 + x^3 + x + 1.
///
/// Always runs exactly 8 steps; each bit of `b` selects via a mask, not a branch.
#[inline(always)]
fn gf_mul_lanes(mut a: u128, b: u128) -> u128 {
    let mut acc = 0u128;
    let mut i = 0;
    while i < 8 {
        acc ^= a & lane_mask((b >> i) & LSB);
        a = xtime_lanes(a);
        i += 1;
    }
    acc
}

/// Lane-wise rotate-left of each byte by `k` (1..=7).
#[inline(always)]
fn rotl_lanes(x: u128, k: u32) -> u128 {
    let hi = lanes(0xffu8 << k);
    let lo = lanes(0xffu8 >> (8 - k));
    ((x << k) & hi) | ((x >> (8 - k)) & lo)
}

/// Constant-time AES S-box applied to all 16 byte lanes of `x` at once.
///
/// S(b) = Affine(b^254), where b^254 is the multiplicative inverse of b in
/// GF(2^8) (and 0 maps to 0). The exponent is reached with a fixed addition
/// chain of 11 multiplications.
#[inline(never)]
fn sub_bytes_ct(x: u128) -> u128 {
    let x2 = gf_mul_lanes(x, x);
    let x3 = gf_mul_lanes(x2, x);
    let x6 = gf_mul_lanes(x3, x3);
    let x12 = gf_mul_lanes(x6, x6);
    let x15 = gf_mul_lanes(x12, x3);
    let x30 = gf_mul_lanes(x15, x15);
    let x60 = gf_mul_lanes(x30, x30);
    let x120 = gf_mul_lanes(x60, x60);
    let x240 = gf_mul_lanes(x120, x120);
    let x252 = gf_mul_lanes(x240, x12);
    let inv = gf_mul_lanes(x252, x2);

    // FIPS 197 affine transform: b ^ rotl1 ^ rotl2 ^ rotl3 ^ rotl4 ^ 0x63.
    inv ^ rotl_lanes(inv, 1)
        ^ rotl_lanes(inv, 2)
        ^ rotl_lanes(inv, 3)
        ^ rotl_lanes(inv, 4)
        ^ lanes(0x63)
}

/// Constant-time S-box of a single byte (used by tests and for clarity).
#[cfg(test)]
fn sbox_ct(b: u8) -> u8 {
    sub_bytes_ct(b as u128) as u8
}

#[inline(always)]
fn sub_word(w: u32) -> u32 {
    sub_bytes_ct(w as u128) as u32
}

#[inline(always)]
fn rot_word(w: u32) -> u32 {
    w.rotate_left(8)
}

#[inline(always)]
fn xtime(x: u8) -> u8 {
    // Branch-free: 0x1b where the top bit was set, 0 otherwise.
    (x << 1) ^ (0x1bu8 & 0u8.wrapping_sub(x >> 7))
}

impl Aes256Key {
    /// Expand a 32-byte key into 15 round keys per FIPS 197.
    ///
    /// The schedule is built directly inside the returned value, so no
    /// separate stack copy of the round keys is left behind.
    pub fn new(key: &[u8; 32]) -> Self {
        let mut out = Self {
            round_keys: [0u32; 60],
        };
        let rk = &mut out.round_keys;
        for i in 0..8 {
            rk[i] =
                u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
        }

        // `i % 8` depends only on the public loop index, never on key bytes.
        for i in 8..60 {
            let mut temp = rk[i - 1];
            if i % 8 == 0 {
                temp = sub_word(rot_word(temp)) ^ RCON[(i / 8) - 1];
            } else if i % 8 == 4 {
                temp = sub_word(temp);
            }
            rk[i] = rk[i - 8] ^ temp;
        }

        out
    }

    /// Encrypt a single 16-byte block in place per FIPS 197.
    ///
    /// Works directly on the caller's buffer, so no intermediate state copy
    /// is left on the stack.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let state = block;

        // Initial round: AddRoundKey
        Self::add_round_key(state, &self.round_keys[0..4]);

        // Rounds 1 to 13
        for round in 1..14 {
            Self::sub_bytes(state);
            Self::shift_rows(state);
            Self::mix_columns(state);
            Self::add_round_key(state, &self.round_keys[round * 4..(round + 1) * 4]);
        }

        // Final round 14 (no MixColumns)
        Self::sub_bytes(state);
        Self::shift_rows(state);
        Self::add_round_key(state, &self.round_keys[14 * 4..15 * 4]);
    }

    #[inline(always)]
    fn add_round_key(state: &mut [u8; 16], rk: &[u32]) {
        for c in 0..4 {
            let word_bytes = rk[c].to_be_bytes();
            state[c * 4] ^= word_bytes[0];
            state[c * 4 + 1] ^= word_bytes[1];
            state[c * 4 + 2] ^= word_bytes[2];
            state[c * 4 + 3] ^= word_bytes[3];
        }
    }

    #[inline(always)]
    fn sub_bytes(state: &mut [u8; 16]) {
        *state = sub_bytes_ct(u128::from_le_bytes(*state)).to_le_bytes();
    }

    #[inline(always)]
    fn shift_rows(state: &mut [u8; 16]) {
        // State is stored column-major:
        // state[0] state[4] state[8]  state[12]
        // state[1] state[5] state[9]  state[13]
        // state[2] state[6] state[10] state[14]
        // state[3] state[7] state[11] state[15]
        let s1 = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = s1;

        let s2 = state[2];
        let s6 = state[6];
        state[2] = state[10];
        state[6] = state[14];
        state[10] = s2;
        state[14] = s6;

        let s3 = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = state[3];
        state[3] = s3;
    }

    #[inline(always)]
    fn mix_columns(state: &mut [u8; 16]) {
        for c in 0..4 {
            let idx = c * 4;
            let s0 = state[idx];
            let s1 = state[idx + 1];
            let s2 = state[idx + 2];
            let s3 = state[idx + 3];

            let h0 = xtime(s0);
            let h1 = xtime(s1);
            let h2 = xtime(s2);
            let h3 = xtime(s3);

            state[idx] = h0 ^ s1 ^ h1 ^ s2 ^ s3;
            state[idx + 1] = s0 ^ h1 ^ s2 ^ h2 ^ s3;
            state[idx + 2] = s0 ^ s1 ^ h2 ^ s3 ^ h3;
            state[idx + 3] = s0 ^ h0 ^ s1 ^ s2 ^ h3;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference Rijndael S-box from FIPS 197 Figure 7, used only to check `sub_bytes_ct`.
    #[rustfmt::skip]
    const SBOX: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ];

    #[test]
    fn test_constant_time_sbox_matches_fips197_table() {
        for b in 0..=255u8 {
            assert_eq!(
                sbox_ct(b),
                SBOX[b as usize],
                "S-box mismatch at input {b:#04x}"
            );
        }
        // All 16 lanes at once, with every lane holding a different input.
        for base in (0..=255u8).step_by(16) {
            let mut input = [0u8; 16];
            for (i, v) in input.iter_mut().enumerate() {
                *v = base.wrapping_add(i as u8);
            }
            let out = sub_bytes_ct(u128::from_le_bytes(input)).to_le_bytes();
            for i in 0..16 {
                assert_eq!(out[i], SBOX[input[i] as usize]);
            }
        }
    }

    #[test]
    fn test_aes_256_fips_197_c2() {
        // NIST FIPS 197 Appendix C.2 Test Vector (AES-256)
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let mut block: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ];

        let cipher = Aes256Key::new(&key);
        cipher.encrypt_block(&mut block);
        assert_eq!(block, expected);
    }
}
