//! Pure-Rust, allocation-free AES-256 block cipher implementation conforming to FIPS 197.
//!
//! Designed for bare-metal `#![no_std]` without external dependencies.

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
    }
}

/// Rijndael S-box.
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

/// Round constants.
const RCON: [u32; 10] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000,
];

#[inline(always)]
fn sub_word(w: u32) -> u32 {
    let b0 = SBOX[((w >> 24) & 0xff) as usize] as u32;
    let b1 = SBOX[((w >> 16) & 0xff) as usize] as u32;
    let b2 = SBOX[((w >> 8) & 0xff) as usize] as u32;
    let b3 = SBOX[(w & 0xff) as usize] as u32;
    (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

#[inline(always)]
fn rot_word(w: u32) -> u32 {
    w.rotate_left(8)
}

#[inline(always)]
fn xtime(x: u8) -> u8 {
    (x << 1) ^ (if (x & 0x80) != 0 { 0x1b } else { 0 })
}

impl Aes256Key {
    /// Expand a 32-byte key into 15 round keys per FIPS 197.
    pub fn new(key: &[u8; 32]) -> Self {
        let mut round_keys = [0u32; 60];
        for i in 0..8 {
            round_keys[i] =
                u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
        }

        for i in 8..60 {
            let mut temp = round_keys[i - 1];
            if i % 8 == 0 {
                temp = sub_word(rot_word(temp)) ^ RCON[(i / 8) - 1];
            } else if i % 8 == 4 {
                temp = sub_word(temp);
            }
            round_keys[i] = round_keys[i - 8] ^ temp;
        }

        Self { round_keys }
    }

    /// Encrypt a single 16-byte block in place per FIPS 197.
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let mut state = *block;

        // Initial round: AddRoundKey
        Self::add_round_key(&mut state, &self.round_keys[0..4]);

        // Rounds 1 to 13
        for round in 1..14 {
            Self::sub_bytes(&mut state);
            Self::shift_rows(&mut state);
            Self::mix_columns(&mut state);
            Self::add_round_key(&mut state, &self.round_keys[round * 4..(round + 1) * 4]);
        }

        // Final round 14 (no MixColumns)
        Self::sub_bytes(&mut state);
        Self::shift_rows(&mut state);
        Self::add_round_key(&mut state, &self.round_keys[14 * 4..15 * 4]);

        *block = state;
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
        for b in state.iter_mut() {
            *b = SBOX[*b as usize];
        }
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
