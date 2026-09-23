//! Pure-Rust, sovereign SHA-256 implementation conforming to FIPS 180-4.
//!
//! Fully deterministic and zero-dependency, safe for bare-metal `#![no_std]`.

/// 32-byte digest returned by SHA-256.
pub type Digest = [u8; 32];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 state machine.
#[derive(Clone, Debug)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buf_len: usize,
    total_len_bytes: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Initialize a new SHA-256 state with FIPS 180-4 standard IV.
    pub const fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buf_len: 0,
            total_len_bytes: 0,
        }
    }

    /// Ingest a slice of bytes into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        self.total_len_bytes = self.total_len_bytes.wrapping_add(data.len() as u64);
        let mut offset = 0;

        // Fill remaining buffer if not empty
        if self.buf_len > 0 {
            let to_copy = core::cmp::min(64 - self.buf_len, data.len());
            self.buffer[self.buf_len..self.buf_len + to_copy].copy_from_slice(&data[..to_copy]);
            self.buf_len += to_copy;
            offset += to_copy;

            if self.buf_len == 64 {
                let block = self.buffer;
                Self::process_block(&mut self.state, &block);
                self.buf_len = 0;
            }
        }

        // Process full 64-byte chunks
        while offset + 64 <= data.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[offset..offset + 64]);
            Self::process_block(&mut self.state, &block);
            offset += 64;
        }

        // Buffer remaining bytes
        if offset < data.len() {
            let rem = data.len() - offset;
            self.buffer[..rem].copy_from_slice(&data[offset..]);
            self.buf_len = rem;
        }
    }

    /// Finalize hash calculation and return the 32-byte digest.
    pub fn finalize(mut self) -> Digest {
        let bit_len = self.total_len_bytes.wrapping_mul(8);

        // Append 0x80 byte
        self.buffer[self.buf_len] = 0x80;
        self.buf_len += 1;

        // If buffer len > 56, pad with zeros, process block, then pad next block
        if self.buf_len > 56 {
            for b in &mut self.buffer[self.buf_len..64] {
                *b = 0;
            }
            let block = self.buffer;
            Self::process_block(&mut self.state, &block);
            self.buffer = [0u8; 64];
            self.buf_len = 0;
        }

        // Pad with zeros up to byte 56
        for b in &mut self.buffer[self.buf_len..56] {
            *b = 0;
        }

        // Append bit length as 64-bit big endian integer
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        Self::process_block(&mut self.state, &block);

        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn process_block(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
}

/// Compute the SHA-256 digest of arbitrary byte data.
pub fn hash(data: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

/// HMAC-SHA256 for a 32-byte secret and a sequence of message slices.
pub fn hmac_sha256(key: &[u8; 32], parts: &[&[u8]]) -> Digest {
    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    for (index, byte) in key.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }

    let mut inner = Sha256::new();
    inner.update(&inner_pad);
    for part in parts {
        inner.update(part);
    }
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&outer_pad);
    outer.update(&inner_digest);
    outer.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256_rfc4231_case_1() {
        let mut key = [0u8; 32];
        key[..20].fill(0x0b);
        assert_eq!(
            hmac_sha256(&key, &[b"Hi ", b"There"]),
            [
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7,
            ]
        );
    }

    #[test]
    fn test_sha256_empty() {
        // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let res = hash(b"");
        assert_eq!(
            res,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
    }

    #[test]
    fn test_sha256_abc() {
        // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let res = hash(b"abc");
        assert_eq!(
            res,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }
}
