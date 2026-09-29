//! Pure-Rust, allocation-free AES-256-GCM-SIV AEAD implementation conforming to RFC 8452.
//!
//! Nonce-misuse-resistant authenticated encryption with associated data (AEAD)
//! using 256-bit keys, 96-bit nonces, and 128-bit authentication tags.
//!
//! Secret intermediates (derived keys, key-derivation scratch, CTR keystream,
//! padded plaintext tails) live in self-wiping buffers, so they are zeroed on
//! every return path, including authentication failure.

use crate::aes::Aes256Key;
use crate::polyval::Polyval;
use crate::Secret;

/// Tag size in bytes (128 bits).
pub const TAG_LEN: usize = 16;
/// Nonce size in bytes (96 bits).
pub const NONCE_LEN: usize = 12;
/// Key size in bytes (256 bits).
pub const KEY_LEN: usize = 32;

/// Error returned when decryption authentication verification fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticationError;

/// Derive the 128-bit authentication key and 256-bit encryption key per RFC 8452 Section 4.
///
/// Both returned buffers wipe themselves on drop, including caller error paths.
pub fn derive_keys(key: &[u8; 32], nonce: &[u8; 12]) -> (Secret<16>, Secret<32>) {
    let mut auth_key = Secret::<16>::zeroed();
    let mut enc_key = Secret::<32>::zeroed();
    derive_keys_into(key, nonce, &mut auth_key.0, &mut enc_key.0);
    (auth_key, enc_key)
}

/// Derive both per-nonce keys into caller-owned buffers. The scratch block is wiped.
fn derive_keys_into(
    key: &[u8; 32],
    nonce: &[u8; 12],
    auth_key: &mut [u8; 16],
    enc_key: &mut [u8; 32],
) {
    let k_cipher = Aes256Key::new(key);
    let mut scratch = Secret::<16>::zeroed();
    let block = &mut scratch.0;

    for i in 0..6u32 {
        block[0..4].copy_from_slice(&i.to_le_bytes());
        block[4..16].copy_from_slice(nonce);

        k_cipher.encrypt_block(block);

        match i {
            0 => auth_key[0..8].copy_from_slice(&block[0..8]),
            1 => auth_key[8..16].copy_from_slice(&block[0..8]),
            2 => enc_key[0..8].copy_from_slice(&block[0..8]),
            3 => enc_key[8..16].copy_from_slice(&block[0..8]),
            4 => enc_key[16..24].copy_from_slice(&block[0..8]),
            5 => enc_key[24..32].copy_from_slice(&block[0..8]),
            _ => unreachable!(),
        }
    }
}

/// Constant-time comparison of two 16-byte tags.
#[inline(never)]
fn constant_time_eq_tag(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Compute length block: 64-bit le AAD bit len || 64-bit le plaintext bit len.
fn make_length_block(aad_len: usize, plaintext_len: usize) -> [u8; 16] {
    let mut len_block = [0u8; 16];
    let aad_bits = (aad_len as u64).wrapping_mul(8);
    let pt_bits = (plaintext_len as u64).wrapping_mul(8);
    len_block[0..8].copy_from_slice(&aad_bits.to_le_bytes());
    len_block[8..16].copy_from_slice(&pt_bits.to_le_bytes());
    len_block
}

/// Compute SIV tag given auth_key, enc_cipher, nonce, aad, and plaintext.
fn compute_tag(
    auth_key: &[u8; 16],
    enc_cipher: &Aes256Key,
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> [u8; 16] {
    let mut poly = Polyval::new(auth_key);

    // Feed AAD padded to 16-byte boundary
    let (aad_chunks, aad_rem) = aad.as_chunks::<16>();
    for chunk in aad_chunks {
        poly.update_block(chunk);
    }
    if !aad_rem.is_empty() {
        let mut b = Secret::<16>::zeroed();
        b.0[..aad_rem.len()].copy_from_slice(aad_rem);
        poly.update_block(&b.0);
    }

    // Feed plaintext padded to 16-byte boundary
    let (pt_chunks, pt_rem) = plaintext.as_chunks::<16>();
    for chunk in pt_chunks {
        poly.update_block(chunk);
    }
    if !pt_rem.is_empty() {
        // Holds a plaintext tail: wiped on drop.
        let mut b = Secret::<16>::zeroed();
        b.0[..pt_rem.len()].copy_from_slice(pt_rem);
        poly.update_block(&b.0);
    }

    // Feed length block
    let len_block = make_length_block(aad.len(), plaintext.len());
    poly.update_block(&len_block);

    let mut s_s = poly.finalize();

    // XOR first 12 bytes with nonce, clear MSB of last byte
    for i in 0..12 {
        s_s[i] ^= nonce[i];
    }
    s_s[15] &= 0x7f;

    // Encrypt with enc_key
    enc_cipher.encrypt_block(&mut s_s);
    s_s
}

/// Perform AES-CTR keystream encryption/decryption in place.
fn apply_ctr(enc_cipher: &Aes256Key, tag: &[u8; 16], buf: &mut [u8]) {
    let mut counter_block = *tag;
    counter_block[15] |= 0x80;

    // Keystream bytes are secret (they unmask the plaintext): wiped on drop.
    let mut keystream = Secret::<16>::zeroed();
    let mut offset = 0;
    while offset < buf.len() {
        keystream.0 = counter_block;
        enc_cipher.encrypt_block(&mut keystream.0);

        let ctr = u32::from_le_bytes([
            counter_block[0],
            counter_block[1],
            counter_block[2],
            counter_block[3],
        ]);
        counter_block[0..4].copy_from_slice(&ctr.wrapping_add(1).to_le_bytes());

        let todo = core::cmp::min(buf.len() - offset, 16);
        for i in 0..todo {
            buf[offset + i] ^= keystream.0[i];
        }
        offset += todo;
    }
}

/// Encrypt plaintext with AES-256-GCM-SIV per RFC 8452.
///
/// Output slice `out_ciphertext_and_tag` must be exactly `plaintext.len() + TAG_LEN` bytes.
pub fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    out_ciphertext_and_tag: &mut [u8],
) {
    assert_eq!(
        out_ciphertext_and_tag.len(),
        plaintext.len() + TAG_LEN,
        "Destination buffer must equal plaintext len + 16"
    );

    // Derived keys live in self-wiping buffers, wiped on every return path.
    let mut auth_key = Secret::<16>::zeroed();
    let mut enc_key = Secret::<32>::zeroed();
    derive_keys_into(key, nonce, &mut auth_key.0, &mut enc_key.0);
    let enc_cipher = Aes256Key::new(&enc_key.0);

    let tag = compute_tag(&auth_key.0, &enc_cipher, nonce, aad, plaintext);

    // Copy plaintext into output slice, then apply CTR in place
    out_ciphertext_and_tag[..plaintext.len()].copy_from_slice(plaintext);
    apply_ctr(
        &enc_cipher,
        &tag,
        &mut out_ciphertext_and_tag[..plaintext.len()],
    );

    // Append 16-byte tag
    out_ciphertext_and_tag[plaintext.len()..].copy_from_slice(&tag);
}

/// Decrypt ciphertext with AES-256-GCM-SIV per RFC 8452.
///
/// Plaintext is written to `out_plaintext`, which must be `ciphertext_and_tag.len() - TAG_LEN` bytes.
/// If authentication fails, `out_plaintext` is zeroed and `Err(AuthenticationError)` is returned.
pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
    out_plaintext: &mut [u8],
) -> Result<(), AuthenticationError> {
    if ciphertext_and_tag.len() < TAG_LEN {
        return Err(AuthenticationError);
    }
    let ciphertext_len = ciphertext_and_tag.len() - TAG_LEN;
    assert_eq!(
        out_plaintext.len(),
        ciphertext_len,
        "Destination plaintext buffer must equal ciphertext len"
    );

    let (ciphertext, received_tag_slice) = ciphertext_and_tag.split_at(ciphertext_len);
    let mut received_tag = [0u8; 16];
    received_tag.copy_from_slice(received_tag_slice);

    // Derived keys live in self-wiping buffers, wiped on every return path
    // (success and authentication failure alike).
    let mut auth_key = Secret::<16>::zeroed();
    let mut enc_key = Secret::<32>::zeroed();
    derive_keys_into(key, nonce, &mut auth_key.0, &mut enc_key.0);
    let enc_cipher = Aes256Key::new(&enc_key.0);

    // Decrypt in place into out_plaintext
    out_plaintext.copy_from_slice(ciphertext);
    apply_ctr(&enc_cipher, &received_tag, out_plaintext);

    // Compute expected tag over decrypted plaintext
    let expected_tag = compute_tag(&auth_key.0, &enc_cipher, nonce, aad, out_plaintext);

    if constant_time_eq_tag(&received_tag, &expected_tag) {
        Ok(())
    } else {
        // Zero decrypted plaintext on failure
        crate::wipe(out_plaintext);
        Err(AuthenticationError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    #[test]
    fn public_derived_keys_are_guarded_and_redacted() {
        let key = [0x31; KEY_LEN];
        let nonce = [0x72; NONCE_LEN];
        let (auth, enc) = derive_keys(&key, &nonce);
        let mut expected_auth = [0; 16];
        let mut expected_enc = [0; 32];
        derive_keys_into(&key, &nonce, &mut expected_auth, &mut expected_enc);
        assert_eq!(*auth, expected_auth);
        assert_eq!(*enc, expected_enc);
        assert_eq!(
            std::format!("{auth:?} {enc:?}"),
            "Secret([REDACTED]) Secret([REDACTED])"
        );
        crate::wipe(&mut expected_auth);
        crate::wipe(&mut expected_enc);
    }

    fn hex_to_vec(hex: &str) -> std::vec::Vec<u8> {
        let mut v = std::vec::Vec::new();
        for i in 0..hex.len() / 2 {
            v.push(u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap());
        }
        v
    }

    #[test]
    fn test_rfc8452_appendix_c_aes256_16byte_pt_0byte_aad() {
        let key_vec =
            hex_to_vec("0100000000000000000000000000000000000000000000000000000000000000");
        let nonce_vec = hex_to_vec("030000000000000000000000");
        let pt_vec = hex_to_vec("01000000000000000000000000000000");
        let expected_result =
            hex_to_vec("85a01b63025ba19b7fd3ddfc033b3e76c9eac6fa700942702e90862383c6c366");

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_vec);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_vec);

        let mut out = vec![0u8; pt_vec.len() + TAG_LEN];
        encrypt(&key, &nonce, b"", &pt_vec, &mut out);
        assert_eq!(out, expected_result);

        let mut decrypted = vec![0u8; pt_vec.len()];
        decrypt(&key, &nonce, b"", &out, &mut decrypted).expect("Decryption failed");
        assert_eq!(decrypted, pt_vec);
    }

    #[test]
    fn test_rfc8452_appendix_c_aes256_8byte_pt_1byte_aad() {
        let key_vec =
            hex_to_vec("0100000000000000000000000000000000000000000000000000000000000000");
        let nonce_vec = hex_to_vec("030000000000000000000000");
        let pt_vec = hex_to_vec("0200000000000000");
        let aad_vec = hex_to_vec("01");
        let expected_result = hex_to_vec("1de22967237a813291213f267e3b452f02d01ae33e4ec854");

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_vec);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_vec);

        let mut out = vec![0u8; pt_vec.len() + TAG_LEN];
        encrypt(&key, &nonce, &aad_vec, &pt_vec, &mut out);
        assert_eq!(out, expected_result);

        let mut decrypted = vec![0u8; pt_vec.len()];
        decrypt(&key, &nonce, &aad_vec, &out, &mut decrypted).expect("Decryption failed");
        assert_eq!(decrypted, pt_vec);

        // Tamper test
        out[0] ^= 0x01;
        assert_eq!(
            decrypt(&key, &nonce, &aad_vec, &out, &mut decrypted),
            Err(AuthenticationError)
        );
        // Ensure memory was zeroed on failure
        assert_eq!(decrypted, vec![0u8; pt_vec.len()]);
    }
}
