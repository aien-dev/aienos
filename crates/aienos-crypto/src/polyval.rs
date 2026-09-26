//! Pure-Rust, allocation-free POLYVAL universal hash implementation conforming to RFC 8452.
//!
//! Evaluates polynomial authentication tags over GF(2^128) modulo
//! x^128 + x^127 + x^126 + x^121 + 1.

/// 16-byte POLYVAL block.
pub type Block = [u8; 16];

/// POLYVAL state accumulator.
#[derive(Clone, Debug, Default)]
pub struct Polyval {
    key: Block,
    accumulator: Block,
}

impl Drop for Polyval {
    fn drop(&mut self) {
        for b in &mut self.key {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        for b in &mut self.accumulator {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
    }
}

/// Constant field element x^-1: byte 15 = 0xe1, bytes 0..15 = 0x00.
const X_INV_BYTE_15: u8 = 0xe1;

/// Multiply polynomial V by x^-1 modulo x^128 + x^127 + x^126 + x^121 + 1.
#[inline(always)]
fn div_x(v: &mut Block) {
    let lsb = v[0] & 1;

    // Shift 128-bit array right by 1 bit (little-endian: bit 0 is LSB of byte 0).
    let mut carry = 0u8;
    for byte in v.iter_mut().rev() {
        let next_carry = *byte & 1;
        *byte = (*byte >> 1) | (carry << 7);
        carry = next_carry;
    }

    if lsb != 0 {
        v[15] ^= X_INV_BYTE_15;
    }
}

/// Compute dot(a, b) = a * b * x^-128 mod P(x) per RFC 8452 Section 3.
pub fn dot(a: &Block, b: &Block) -> Block {
    let mut v = [0u8; 16];

    for i in 0..128 {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let bit = (a[byte_idx] >> bit_idx) & 1;

        if bit != 0 {
            for j in 0..16 {
                v[j] ^= b[j];
            }
        }

        div_x(&mut v);
    }

    v
}

impl Polyval {
    /// Initialize POLYVAL with a 16-byte authentication key H.
    pub fn new(key: &Block) -> Self {
        Self {
            key: *key,
            accumulator: [0u8; 16],
        }
    }

    /// Reset accumulator to zero.
    pub fn reset(&mut self) {
        self.accumulator = [0u8; 16];
    }

    /// Process a single 16-byte block: S_j = dot(S_{j-1} ^ X_j, H).
    pub fn update_block(&mut self, block: &Block) {
        for (acc, b) in self.accumulator.iter_mut().zip(block.iter()) {
            *acc ^= b;
        }
        self.accumulator = dot(&self.accumulator, &self.key);
    }

    /// Process arbitrary slice of padded 16-byte blocks.
    pub fn update(&mut self, data: &[u8]) {
        assert!(
            data.len().is_multiple_of(16),
            "POLYVAL input must be 16-byte aligned"
        );
        let (chunks, _) = data.as_chunks::<16>();
        for chunk in chunks {
            self.update_block(chunk);
        }
    }

    /// Finalize and return current 16-byte accumulator S_s.
    pub fn finalize(self) -> Block {
        self.accumulator
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_block(hex: &str) -> Block {
        assert_eq!(hex.len(), 32);
        let mut block = [0u8; 16];
        for i in 0..16 {
            block[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        block
    }

    #[test]
    fn test_polyval_rfc8452_section_7_dot() {
        let a = hex_to_block("66e94bd4ef8a2c3b884cfa59ca342b2e");
        let b = hex_to_block("ff000000000000000000000000000000");
        let expected = hex_to_block("ebe563401e7e91ea3ad6426b8140c394");

        let res = dot(&a, &b);
        assert_eq!(res, expected);
    }

    #[test]
    fn test_polyval_rfc8452_appendix_a_worked_example() {
        let h = hex_to_block("25629347589242761d31f826ba4b757b");
        let x1 = hex_to_block("4f4f95668c83dfb6401762bb2d01a262");
        let x2 = hex_to_block("d1a24ddd2721d006bbe45f20d3c9f362");
        let expected = hex_to_block("f7a3b47b846119fae5b7866cf5e5b77e");

        let mut poly = Polyval::new(&h);
        poly.update_block(&x1);
        poly.update_block(&x2);
        assert_eq!(poly.finalize(), expected);
    }
}
