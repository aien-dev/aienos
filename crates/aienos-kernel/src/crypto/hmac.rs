//! HMAC-SHA256 (RFC 2104).
use super::sha256::{hash, Digest, Sha256};

const BLOCK_LEN: usize = 64;

fn zeroize(bytes: &mut [u8]) {
    for byte in bytes {
        // Volatile writes prevent the compiler from eliding secret cleanup.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
}

/// Streaming HMAC-SHA256 state. The keyed pads are erased when it is dropped.
pub struct HmacSha256 {
    inner: Option<Sha256>,
    outer_pad: [u8; BLOCK_LEN],
}

impl HmacSha256 {
    /// Start an HMAC operation with any key length.
    pub fn new(key: &[u8]) -> Self {
        let mut key_block = [0u8; BLOCK_LEN];
        if key.len() > BLOCK_LEN {
            let mut key_digest = hash(key);
            key_block[..32].copy_from_slice(&key_digest);
            zeroize(&mut key_digest);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }
        let mut inner_pad = [0x36; BLOCK_LEN];
        let mut outer_pad = [0x5c; BLOCK_LEN];
        for i in 0..BLOCK_LEN {
            inner_pad[i] ^= key_block[i];
            outer_pad[i] ^= key_block[i];
        }
        zeroize(&mut key_block);
        let mut inner = Sha256::new();
        inner.update(&inner_pad);
        zeroize(&mut inner_pad);
        Self {
            inner: Some(inner),
            outer_pad,
        }
    }

    /// Add message bytes to the MAC.
    pub fn update(&mut self, data: &[u8]) {
        self.inner
            .as_mut()
            .expect("HMAC state finalized")
            .update(data);
    }

    /// Finish the MAC and erase its retained outer pad.
    pub fn finalize(mut self) -> Digest {
        let mut inner_digest = self.inner.take().expect("HMAC state finalized").finalize();
        let mut outer = Sha256::new();
        outer.update(&self.outer_pad);
        outer.update(&inner_digest);
        let result = outer.finalize();
        zeroize(&mut inner_digest);
        zeroize(&mut self.outer_pad);
        result
    }
}

impl Drop for HmacSha256 {
    fn drop(&mut self) {
        zeroize(&mut self.outer_pad);
    }
}

/// Compute HMAC-SHA256 over a single message.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Digest {
    let mut hmac = HmacSha256::new(key);
    hmac.update(message);
    hmac.finalize()
}

/// Compare tags without exiting early based on their contents.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for i in 0..core::cmp::max(a.len(), b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= usize::from(x ^ y);
    }
    diff == 0
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
    fn check(key: &[u8], message: &[u8], expected: &str) {
        let mut h = HmacSha256::new(key);
        for part in message.chunks(7) {
            h.update(part);
        }
        let tag = h.finalize();
        let expected = bytes(expected);
        assert_eq!(&tag[..expected.len()], expected.as_slice());
    }
    #[test]
    fn rfc4231_cases_1_to_7() {
        check(
            &[0x0b; 20],
            b"Hi There",
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        );
        check(
            b"Jefe",
            b"what do ya want for nothing?",
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        );
        check(
            &[0xaa; 20],
            &[0xdd; 50],
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        );
        let key4: std::vec::Vec<u8> = (1..=25).collect();
        check(&key4, &[0xcd; 50], "82558a389a443c0ea4cc819899f2083a");
        check(
            &[0x0c; 20],
            b"Test With Truncation",
            "a3b6167473100ee06e0c796c2955552b",
        );
        check(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        );
        check(&[0xaa; 131], b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
    }
    #[test]
    fn compare_tags() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"samf"));
        assert!(!constant_time_eq(b"same", b"same!"));
    }
}
