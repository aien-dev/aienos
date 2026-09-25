//! Binary Artifact v0 signature-block constants and view.
//!
//! Signature verification and trust-anchor interfaces are introduced in
//! P2-3; parsing never treats signature bytes as trust.

use crate::error::ArtifactError;
use crate::format::SIGNATURE_ALGORITHM_ED25519;

pub const SIGNATURE_DOMAIN: &[u8] = b"AIENOS-ARTIFACT-SIGNATURE-V1\0";
pub const SIGNATURE_BLOCK_SIZE: usize = 100;
pub const SIGNATURE_SIZE: usize = 64;
pub const PUBLIC_KEY_SIZE: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureBlock<'a> {
    pub algorithm: u16,
    pub signer_fingerprint: &'a [u8; 32],
    pub signature: &'a [u8; SIGNATURE_SIZE],
}

impl<'a> SignatureBlock<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, ArtifactError> {
        if bytes.len() != SIGNATURE_BLOCK_SIZE {
            return Err(if bytes.len() < SIGNATURE_BLOCK_SIZE {
                ArtifactError::Truncated
            } else {
                ArtifactError::WrongLength
            });
        }
        let algorithm = u16::from_le_bytes([bytes[0], bytes[1]]);
        if algorithm != SIGNATURE_ALGORITHM_ED25519 {
            return Err(ArtifactError::BadSignatureFormat);
        }
        if bytes[2] != 0 || bytes[3] != 0 {
            return Err(ArtifactError::ReservedNonZero);
        }
        let signer_fingerprint = bytes[4..36]
            .try_into()
            .map_err(|_| ArtifactError::Truncated)?;
        let signature = bytes[36..100]
            .try_into()
            .map_err(|_| ArtifactError::Truncated)?;
        Ok(Self {
            algorithm,
            signer_fingerprint,
            signature,
        })
    }
}
