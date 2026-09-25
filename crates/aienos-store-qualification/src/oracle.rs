//! Independent CRC32C (Castagnoli) and SHA-256 ObjectId oracle.

use sha2::{Digest, Sha256};

pub const OBJECT_DOMAIN_V1: &[u8] = b"AIENOS-STORE-OBJECT-V1\0";
pub const STORE_UNIT_BYTES: usize = 4096;

/// Independent software implementation of CRC32C (Castagnoli 0x82F63B78).
/// Strictly independent of any production or hardware-accelerated CRC code.
pub fn independent_crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x82F6_3B78;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Independent SHA-256 ObjectId reconstruction matching ADR 0015 / Store v1.
/// SHA256("AIENOS-STORE-OBJECT-V1\0" || kind:u16le || version:u16le || byte_length:u64le || semantic_bytes)
pub fn independent_object_id(
    kind: u16,
    version: u16,
    byte_length: u64,
    semantic_bytes: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(OBJECT_DOMAIN_V1);
    hasher.update(kind.to_le_bytes());
    hasher.update(version.to_le_bytes());
    hasher.update(byte_length.to_le_bytes());
    hasher.update(semantic_bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32c_standard_vectors() {
        // Standard Castagnoli CRC32C test vectors
        assert_eq!(independent_crc32c(b""), 0x0000_0000);
        assert_eq!(independent_crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(independent_crc32c(&[0x00; 32]), 0x8A91_36AA);
        assert_eq!(independent_crc32c(&[0xFF; 32]), 0x62A8_AB43);
    }

    #[test]
    fn test_object_id_independent_calculation() {
        let id1 = independent_object_id(1, 1, 4, b"test");
        let id2 = independent_object_id(1, 1, 4, b"test");
        assert_eq!(id1, id2);
        // Semantic mutation alters ID
        let id3 = independent_object_id(1, 1, 4, b"tesu");
        assert_ne!(id1, id3);
    }
}
