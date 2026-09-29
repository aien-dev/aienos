//! AES-256 through RustCrypto's constant-time no_std implementation.
//! The zeroize feature wipes expanded round keys when the cipher is dropped.
use aes::cipher::{BlockEncrypt, KeyInit};

#[derive(Clone)]
pub struct Aes256Key {
    cipher: aes::Aes256,
}

impl core::fmt::Debug for Aes256Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Aes256Key([REDACTED])")
    }
}

impl Aes256Key {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: aes::Aes256::new(key.into()),
        }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        self.cipher.encrypt_block(block.into());
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
