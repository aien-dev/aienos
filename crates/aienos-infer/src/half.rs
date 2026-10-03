//! IEEE binary16 and bfloat16 to f32 without std.

/// Convert an IEEE 754 binary16 bit pattern to f32 (exact for all inputs,
/// including subnormals, infinities and NaNs).
pub fn f16_to_f32(h: u16) -> f32 {
    let sign = ((h >> 15) as u32) << 31;
    let exp = ((h >> 10) & 0x1f) as u32;
    let man = (h & 0x3ff) as u32;
    let bits = if exp == 0 {
        if man == 0 {
            sign
        } else {
            // Subnormal: normalise.
            let shift = man.leading_zeros() - 21; // man has <= 10 bits
            let m = (man << shift) & 0x3ff;
            let e = 113 - shift; // 127 - 15 + 1 - shift
            sign | (e << 23) | (m << 13)
        }
    } else if exp == 0x1f {
        sign | 0x7f80_0000 | (man << 13)
    } else {
        sign | ((exp + 112) << 23) | (man << 13)
    };
    f32::from_bits(bits)
}

/// Convert a bfloat16 bit pattern to f32.
pub fn bf16_to_f32(b: u16) -> f32 {
    f32::from_bits((b as u32) << 16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_values() {
        assert_eq!(f16_to_f32(0x0000), 0.0);
        assert_eq!(f16_to_f32(0x3c00), 1.0);
        assert_eq!(f16_to_f32(0xc000), -2.0);
        assert_eq!(f16_to_f32(0x3800), 0.5);
        assert_eq!(f16_to_f32(0x7bff), 65504.0);
        assert_eq!(f16_to_f32(0x0400), f32::from_bits(0x3880_0000)); // 2^-14 smallest normal
        assert_eq!(f16_to_f32(0x0001), f32::from_bits(0x3380_0000)); // 2^-24 smallest subnormal
        assert_eq!(f16_to_f32(0x03ff), 1023.0 / 16_777_216.0); // 1023 * 2^-24
        assert!(f16_to_f32(0x7c00).is_infinite());
        assert!(f16_to_f32(0xfc00).is_sign_negative());
        assert!(f16_to_f32(0x7e00).is_nan());
        assert_eq!(f16_to_f32(0x8000).to_bits(), 0x8000_0000);
        assert_eq!(bf16_to_f32(0x3f80), 1.0);
    }
}
