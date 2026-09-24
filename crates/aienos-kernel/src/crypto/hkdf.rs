//! HKDF-SHA256 (RFC 5869).
use super::hmac::HmacSha256;
use super::sha256::Digest;

const HASH_LEN: usize = 32;

fn zeroize(bytes: &mut [u8]) {
    for byte in bytes {
        // Volatile writes prevent the compiler from eliding secret cleanup.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
}

/// HKDF expand error for outputs longer than RFC 5869 permits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HkdfError {
    /// Output length exceeds 255 SHA-256 blocks (8160 bytes).
    OutputTooLong,
}

/// HKDF-Extract(salt, IKM), returning the 32-byte pseudorandom key.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Digest {
    let mut hmac = HmacSha256::new(salt);
    hmac.update(ikm);
    hmac.finalize()
}

/// HKDF-Expand(PRK, info), writing output in place.
pub fn hkdf_expand(prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), HkdfError> {
    if out.len() > 255 * HASH_LEN {
        return Err(HkdfError::OutputTooLong);
    }
    let mut scratch = ExpandScratch {
        block: [0; HASH_LEN],
    };
    let previous = &mut scratch.block;
    let mut previous_len = 0;
    let mut written = 0;
    let blocks = out.len().div_ceil(HASH_LEN);
    for counter in 1..=blocks {
        let mut hmac = HmacSha256::new(prk);
        hmac.update(&previous[..previous_len]);
        hmac.update(info);
        hmac.update(&[counter as u8]);
        *previous = hmac.finalize();
        previous_len = HASH_LEN;
        let n = core::cmp::min(HASH_LEN, out.len() - written);
        out[written..written + n].copy_from_slice(&previous[..n]);
        written += n;
    }
    Ok(())
}

impl Drop for ExpandScratch {
    fn drop(&mut self) {
        zeroize(&mut self.block);
    }
}

// Kept as a drop guard so scratch is wiped on every exit path, including panic.
struct ExpandScratch {
    block: Digest,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bytes(hex: &str) -> std::vec::Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
    fn case(ikm: &[u8], salt: &[u8], info: &[u8], length: usize, prk: &str, okm: &str) {
        let actual_prk = hkdf_extract(salt, ikm);
        assert_eq!(actual_prk.as_slice(), bytes(prk));
        let mut actual = std::vec![0; length];
        hkdf_expand(&actual_prk, info, &mut actual).unwrap();
        assert_eq!(actual, bytes(okm));
    }
    #[test]
    fn rfc5869_cases_1_to_3() {
        case(
            &[0x0b; 22],
            &bytes("000102030405060708090a0b0c"),
            &bytes("f0f1f2f3f4f5f6f7f8f9"),
            42,
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );
        case(
            &[0x0b; 22],
            &[],
            &[],
            42,
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        );
        let ikm = bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f");
        let salt = bytes("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
        let info = bytes("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        case(&ikm, &salt, &info, 82,
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");
    }
    #[test]
    fn length_limit_and_compare() {
        let mut too_long = std::vec![0; 255 * HASH_LEN + 1];
        assert_eq!(
            hkdf_expand(&[0; 32], b"", &mut too_long),
            Err(HkdfError::OutputTooLong)
        );
        let mut max = std::vec![0; 255 * HASH_LEN];
        hkdf_expand(&[0; 32], b"", &mut max).unwrap();
        assert!(super::super::hmac::constant_time_eq(&max, &max));
    }
}
