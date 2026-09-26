//! M5 authenticated streaming envelope over Store v1 (ADR 0017 Section 2.3).
//!
//! Wraps application payload objects in chunked AEAD envelopes using AES-256-GCM-SIV.
//! Chunk size is bounded to 64 KiB to guarantee bounded memory scratchpads during
//! verification, and every chunk authenticates store identity, object kind/version,
//! envelope header, chunk index, and length to prevent splicing, reordering, truncation,
//! or cross-store replay.

extern crate alloc;

use alloc::vec::Vec;

pub use aienos_crypto::aes_gcm_siv::{
    decrypt as raw_decrypt, encrypt as raw_encrypt, AuthenticationError, KEY_LEN, NONCE_LEN,
    TAG_LEN,
};

/// 8-byte magic for M5 envelopes: "AIENENV1".
pub const ENVELOPE_MAGIC: &[u8; 8] = b"AIENENV1";
/// Format version for M5 envelopes.
pub const ENVELOPE_VERSION_1: u16 = 1;
/// Cipher suite identifier for AES-256-GCM-SIV per ADR 0017.
pub const CIPHER_SUITE_AES_256_GCM_SIV: u16 = 0x0001;
/// Default chunk size: 64 KiB (65,536 bytes).
pub const DEFAULT_CHUNK_SIZE: u32 = 65536;
/// Envelope header length: fixed 64 bytes.
pub const ENVELOPE_HEADER_LEN: usize = 64;
/// Additional Authenticated Data domain separator prefix for M5 chunks.
pub const CHUNK_AAD_PREFIX: &[u8; 19] = b"AIENOS-M5-CHUNK-V1\0";
/// Total length of per-chunk AAD: 19 + 16 + 2 + 2 + 64 + 4 + 4 = 111 bytes.
pub const CHUNK_AAD_LEN: usize = 111;

/// Error conditions encountered when inspecting or decrypting an envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Input is smaller than the 64-byte envelope header.
    HeaderTooShort,
    /// Invalid magic bytes.
    InvalidMagic,
    /// Unsupported envelope version.
    UnsupportedVersion(u16),
    /// Unsupported cipher suite.
    UnsupportedCipherSuite(u16),
    /// Invalid flags.
    InvalidFlags(u32),
    /// Invalid chunk size (must be > 0 and <= 64 KiB).
    InvalidChunkSize(u32),
    /// Nonzero reserved bytes.
    NonzeroReserved,
    /// Ciphertext length does not match expected length from header.
    LengthMismatch,
    /// AEAD authentication verification failed for a chunk.
    AuthenticationFailed,
}

/// Fixed 64-byte authenticated envelope header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvelopeHeader {
    pub magic: [u8; 8],
    pub envelope_version: u16,
    pub cipher_suite: u16,
    pub flags: u32,
    pub chunk_size: u32,
    pub total_plaintext_len: u64,
    pub envelope_id: [u8; 16],
    pub nonce_prefix: [u8; 8],
    pub key_epoch: u64,
    pub reserved: u32,
}

impl EnvelopeHeader {
    /// Encode the header into a fixed 64-byte array.
    pub fn encode(&self) -> [u8; ENVELOPE_HEADER_LEN] {
        let mut out = [0u8; ENVELOPE_HEADER_LEN];
        out[0..8].copy_from_slice(&self.magic);
        out[8..10].copy_from_slice(&self.envelope_version.to_le_bytes());
        out[10..12].copy_from_slice(&self.cipher_suite.to_le_bytes());
        out[12..16].copy_from_slice(&self.flags.to_le_bytes());
        out[16..20].copy_from_slice(&self.chunk_size.to_le_bytes());
        out[20..28].copy_from_slice(&self.total_plaintext_len.to_le_bytes());
        out[28..44].copy_from_slice(&self.envelope_id);
        out[44..52].copy_from_slice(&self.nonce_prefix);
        out[52..60].copy_from_slice(&self.key_epoch.to_le_bytes());
        out[60..64].copy_from_slice(&self.reserved.to_le_bytes());
        out
    }

    /// Decode and validate a 64-byte envelope header.
    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() < ENVELOPE_HEADER_LEN {
            return Err(EnvelopeError::HeaderTooShort);
        }

        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[0..8]);
        if magic != *ENVELOPE_MAGIC {
            return Err(EnvelopeError::InvalidMagic);
        }

        let envelope_version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if envelope_version != ENVELOPE_VERSION_1 {
            return Err(EnvelopeError::UnsupportedVersion(envelope_version));
        }

        let cipher_suite = u16::from_le_bytes([bytes[10], bytes[11]]);
        if cipher_suite != CIPHER_SUITE_AES_256_GCM_SIV {
            return Err(EnvelopeError::UnsupportedCipherSuite(cipher_suite));
        }

        let flags = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        if flags != 0 {
            return Err(EnvelopeError::InvalidFlags(flags));
        }

        let chunk_size = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        if chunk_size == 0 || chunk_size > DEFAULT_CHUNK_SIZE {
            return Err(EnvelopeError::InvalidChunkSize(chunk_size));
        }

        let mut total_pt_bytes = [0u8; 8];
        total_pt_bytes.copy_from_slice(&bytes[20..28]);
        let total_plaintext_len = u64::from_le_bytes(total_pt_bytes);

        let mut envelope_id = [0u8; 16];
        envelope_id.copy_from_slice(&bytes[28..44]);

        let mut nonce_prefix = [0u8; 8];
        nonce_prefix.copy_from_slice(&bytes[44..52]);

        let mut epoch_bytes = [0u8; 8];
        epoch_bytes.copy_from_slice(&bytes[52..60]);
        let key_epoch = u64::from_le_bytes(epoch_bytes);

        let reserved = u32::from_le_bytes([bytes[60], bytes[61], bytes[62], bytes[63]]);
        if reserved != 0 {
            return Err(EnvelopeError::NonzeroReserved);
        }

        Ok(Self {
            magic,
            envelope_version,
            cipher_suite,
            flags,
            chunk_size,
            total_plaintext_len,
            envelope_id,
            nonce_prefix,
            key_epoch,
            reserved,
        })
    }

    /// Calculate the number of chunks for this envelope.
    pub fn chunk_count(&self) -> usize {
        if self.total_plaintext_len == 0 {
            1
        } else {
            let cs = self.chunk_size as u64;
            self.total_plaintext_len.div_ceil(cs) as usize
        }
    }

    /// Calculate the expected total ciphertext envelope size (header + ciphertext + tags).
    pub fn expected_envelope_len(&self) -> usize {
        let chunks = self.chunk_count();
        ENVELOPE_HEADER_LEN + (self.total_plaintext_len as usize) + (chunks * TAG_LEN)
    }
}

/// Derive the 12-byte nonce for a specific chunk index: nonce_prefix[8] || chunk_index:u32le.
pub fn derive_chunk_nonce(nonce_prefix: &[u8; 8], chunk_index: u32) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[0..8].copy_from_slice(nonce_prefix);
    nonce[8..12].copy_from_slice(&chunk_index.to_le_bytes());
    nonce
}

/// Format the 111-byte AAD for a specific chunk.
pub fn compute_chunk_aad(
    store_uuid: &[u8; 16],
    object_kind: u16,
    object_version: u16,
    header_64b: &[u8; ENVELOPE_HEADER_LEN],
    chunk_index: u32,
    chunk_plaintext_len: u32,
) -> [u8; CHUNK_AAD_LEN] {
    let mut aad = [0u8; CHUNK_AAD_LEN];
    let mut offset = 0;

    aad[offset..offset + 19].copy_from_slice(CHUNK_AAD_PREFIX);
    offset += 19;

    aad[offset..offset + 16].copy_from_slice(store_uuid);
    offset += 16;

    aad[offset..offset + 2].copy_from_slice(&object_kind.to_le_bytes());
    offset += 2;

    aad[offset..offset + 2].copy_from_slice(&object_version.to_le_bytes());
    offset += 2;

    aad[offset..offset + 64].copy_from_slice(header_64b);
    offset += 64;

    aad[offset..offset + 4].copy_from_slice(&chunk_index.to_le_bytes());
    offset += 4;

    aad[offset..offset + 4].copy_from_slice(&chunk_plaintext_len.to_le_bytes());
    offset += 4;

    debug_assert_eq!(offset, CHUNK_AAD_LEN);
    aad
}

/// Encrypt arbitrary plaintext into an authenticated streaming envelope.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_envelope(
    key: &[u8; KEY_LEN],
    store_uuid: &[u8; 16],
    object_kind: u16,
    object_version: u16,
    envelope_id: &[u8; 16],
    nonce_prefix: &[u8; 8],
    key_epoch: u64,
    plaintext: &[u8],
) -> Vec<u8> {
    let header = EnvelopeHeader {
        magic: *ENVELOPE_MAGIC,
        envelope_version: ENVELOPE_VERSION_1,
        cipher_suite: CIPHER_SUITE_AES_256_GCM_SIV,
        flags: 0,
        chunk_size: DEFAULT_CHUNK_SIZE,
        total_plaintext_len: plaintext.len() as u64,
        envelope_id: *envelope_id,
        nonce_prefix: *nonce_prefix,
        key_epoch,
        reserved: 0,
    };

    let header_bytes = header.encode();
    let total_envelope_len = header.expected_envelope_len();
    let mut out = Vec::with_capacity(total_envelope_len);
    out.extend_from_slice(&header_bytes);

    let chunk_size = header.chunk_size as usize;

    if plaintext.is_empty() {
        // Zero-length plaintext has 1 empty chunk producing a 16-byte tag
        let nonce = derive_chunk_nonce(nonce_prefix, 0);
        let aad = compute_chunk_aad(store_uuid, object_kind, object_version, &header_bytes, 0, 0);
        let mut chunk_out = [0u8; TAG_LEN];
        raw_encrypt(key, &nonce, &aad, &[], &mut chunk_out);
        out.extend_from_slice(&chunk_out);
    } else {
        for (i, pt_chunk) in plaintext.chunks(chunk_size).enumerate() {
            let chunk_idx = i as u32;
            let nonce = derive_chunk_nonce(nonce_prefix, chunk_idx);
            let aad = compute_chunk_aad(
                store_uuid,
                object_kind,
                object_version,
                &header_bytes,
                chunk_idx,
                pt_chunk.len() as u32,
            );
            let mut chunk_out = alloc::vec![0u8; pt_chunk.len() + TAG_LEN];
            raw_encrypt(key, &nonce, &aad, pt_chunk, &mut chunk_out);
            out.extend_from_slice(&chunk_out);
        }
    }

    debug_assert_eq!(out.len(), total_envelope_len);
    out
}

/// Decrypt an authenticated streaming envelope, returning the verified plaintext.
///
/// Invariant: Plaintext chunks are verified in private scratch buffers before being
/// committed to the output buffer. Any tag mismatch halts immediately and wipes memory.
pub fn decrypt_envelope(
    key: &[u8; KEY_LEN],
    store_uuid: &[u8; 16],
    object_kind: u16,
    object_version: u16,
    envelope_bytes: &[u8],
) -> Result<Vec<u8>, EnvelopeError> {
    if envelope_bytes.len() < ENVELOPE_HEADER_LEN {
        return Err(EnvelopeError::HeaderTooShort);
    }

    let header = EnvelopeHeader::decode(&envelope_bytes[0..ENVELOPE_HEADER_LEN])?;
    if envelope_bytes.len() != header.expected_envelope_len() {
        return Err(EnvelopeError::LengthMismatch);
    }

    let mut header_bytes = [0u8; ENVELOPE_HEADER_LEN];
    header_bytes.copy_from_slice(&envelope_bytes[0..ENVELOPE_HEADER_LEN]);

    let chunk_size = header.chunk_size as usize;
    let chunk_count = header.chunk_count();
    let mut plaintext = Vec::with_capacity(header.total_plaintext_len as usize);

    let mut cursor = ENVELOPE_HEADER_LEN;

    if header.total_plaintext_len == 0 {
        let chunk_bytes = &envelope_bytes[cursor..cursor + TAG_LEN];
        let nonce = derive_chunk_nonce(&header.nonce_prefix, 0);
        let aad = compute_chunk_aad(store_uuid, object_kind, object_version, &header_bytes, 0, 0);

        let mut scratchpad = [0u8; 0];
        raw_decrypt(key, &nonce, &aad, chunk_bytes, &mut scratchpad)
            .map_err(|_| EnvelopeError::AuthenticationFailed)?;
        return Ok(plaintext);
    }

    let mut remaining = header.total_plaintext_len as usize;

    for i in 0..chunk_count {
        let chunk_idx = i as u32;
        let pt_chunk_len = core::cmp::min(remaining, chunk_size);
        let ct_chunk_len = pt_chunk_len + TAG_LEN;

        let ct_chunk = &envelope_bytes[cursor..cursor + ct_chunk_len];
        cursor += ct_chunk_len;
        remaining -= pt_chunk_len;

        let nonce = derive_chunk_nonce(&header.nonce_prefix, chunk_idx);
        let aad = compute_chunk_aad(
            store_uuid,
            object_kind,
            object_version,
            &header_bytes,
            chunk_idx,
            pt_chunk_len as u32,
        );

        // Verification scratchpad: verified before writing to caller buffer
        let mut scratchpad = alloc::vec![0u8; pt_chunk_len];
        if raw_decrypt(key, &nonce, &aad, ct_chunk, &mut scratchpad).is_err() {
            // Scratchpad was wiped by raw_decrypt on failure; wipe and drop plaintext
            for b in plaintext.iter_mut() {
                unsafe { core::ptr::write_volatile(b, 0) };
            }
            return Err(EnvelopeError::AuthenticationFailed);
        }

        plaintext.extend_from_slice(&scratchpad);
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope_roundtrip_small() {
        let key = [0x42u8; 32];
        let store_uuid = [0x11u8; 16];
        let envelope_id = [0x22u8; 16];
        let nonce_prefix = [0x33u8; 8];
        let pt = b"Sovereign AIENOS M5 Encrypted State";

        let env = encrypt_envelope(
            &key,
            &store_uuid,
            16,
            1,
            &envelope_id,
            &nonce_prefix,
            100,
            pt,
        );

        let decrypted = decrypt_envelope(&key, &store_uuid, 16, 1, &env).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_envelope_roundtrip_empty() {
        let key = [0x55u8; 32];
        let store_uuid = [0x77u8; 16];
        let envelope_id = [0x88u8; 16];
        let nonce_prefix = [0x99u8; 8];
        let pt = b"";

        let env = encrypt_envelope(&key, &store_uuid, 17, 1, &envelope_id, &nonce_prefix, 1, pt);

        assert_eq!(env.len(), ENVELOPE_HEADER_LEN + TAG_LEN);
        let decrypted = decrypt_envelope(&key, &store_uuid, 17, 1, &env).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_envelope_roundtrip_multi_chunk() {
        let key = [0xaau8; 32];
        let store_uuid = [0xbbu8; 16];
        let envelope_id = [0xccu8; 16];
        let nonce_prefix = [0xddu8; 8];

        // 70 KiB of test data (crosses 64 KiB boundary into 2 chunks)
        let mut pt = alloc::vec![0u8; 70 * 1024];
        for (i, b) in pt.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }

        let env = encrypt_envelope(
            &key,
            &store_uuid,
            18,
            1,
            &envelope_id,
            &nonce_prefix,
            42,
            &pt,
        );

        let header = EnvelopeHeader::decode(&env).unwrap();
        assert_eq!(header.chunk_count(), 2);
        assert_eq!(env.len(), ENVELOPE_HEADER_LEN + pt.len() + 2 * TAG_LEN);

        let decrypted = decrypt_envelope(&key, &store_uuid, 18, 1, &env).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_envelope_cross_store_and_kind_binding() {
        let key = [0x12u8; 32];
        let store_uuid = [0x34u8; 16];
        let other_store = [0x99u8; 16];
        let envelope_id = [0x56u8; 16];
        let nonce_prefix = [0x78u8; 8];
        let pt = b"Confidential branch checkpoint";

        let env = encrypt_envelope(&key, &store_uuid, 20, 1, &envelope_id, &nonce_prefix, 1, pt);

        // Foreign store UUID must fail verification
        assert_eq!(
            decrypt_envelope(&key, &other_store, 20, 1, &env),
            Err(EnvelopeError::AuthenticationFailed)
        );

        // Mismatched object kind must fail verification
        assert_eq!(
            decrypt_envelope(&key, &store_uuid, 21, 1, &env),
            Err(EnvelopeError::AuthenticationFailed)
        );

        // Bit-flip in ciphertext must fail verification
        let mut corrupted = env.clone();
        corrupted[ENVELOPE_HEADER_LEN + 5] ^= 0x01;
        assert_eq!(
            decrypt_envelope(&key, &store_uuid, 20, 1, &corrupted),
            Err(EnvelopeError::AuthenticationFailed)
        );
    }
}
