//! Sovereign cryptographic primitives for AIENOS.

pub mod envelope;
pub mod hkdf;
pub mod hmac;
pub mod sha256;

pub use envelope::{
    decrypt_envelope, derive_chunk_nonce, encrypt_envelope, EnvelopeError, EnvelopeHeader,
    DEFAULT_CHUNK_SIZE, ENVELOPE_HEADER_LEN, ENVELOPE_MAGIC, ENVELOPE_VERSION_1,
};
pub use hkdf::{hkdf_expand, hkdf_extract, HkdfError};
pub use hmac::{constant_time_eq, hmac_sha256, HmacSha256};
pub use sha256::{hash, Digest, Sha256};
