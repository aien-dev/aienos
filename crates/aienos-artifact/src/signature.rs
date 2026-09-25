//! Binary Artifact v0 signature-block, trust, and verification interfaces.

use crate::error::ArtifactError;
use crate::format::SIGNATURE_ALGORITHM_ED25519;
use crate::id::{compute_artifact_id, ArtifactId};
use crate::verify::{parse_and_identify, IdentifiedArtifact};
use aienos_crypto::sha256::{hash, Digest};
use ed25519_dalek::{Signature, VerifyingKey};

pub const SIGNATURE_DOMAIN: &[u8] = b"AIENOS-ARTIFACT-SIGNATURE-V1\0";
pub const SIGNATURE_BLOCK_SIZE: usize = 100;
pub const SIGNATURE_SIZE: usize = 64;
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const ARTIFACT_SIGNATURE_MESSAGE_SIZE: usize = SIGNATURE_DOMAIN.len() + 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustTier {
    Production,
    Seed0bQualification,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrustedSigner {
    pub public_key: [u8; PUBLIC_KEY_SIZE],
    pub tier: TrustTier,
}

pub trait TrustAnchorSet {
    fn find(&self, fingerprint: &Digest) -> Option<TrustedSigner>;
}

/// Production trust remains fail-closed until the owner identity ceremony.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmptyTrustAnchorSet;

/// The ordinary production set intentionally contains no anchors before M5.
pub type ProductionTrustAnchorSet = EmptyTrustAnchorSet;

impl TrustAnchorSet for EmptyTrustAnchorSet {
    fn find(&self, _fingerprint: &Digest) -> Option<TrustedSigner> {
        None
    }
}

pub trait SignatureVerifier {
    fn verify(
        &self,
        public_key: &[u8; PUBLIC_KEY_SIZE],
        message: &[u8],
        signature: &[u8; SIGNATURE_SIZE],
    ) -> bool;
}

/// Signs a domain-separated admission-receipt digest. Implementations own
/// their key custody; the kernel-facing artifact crate stores no private key.
pub trait ReceiptSigner {
    fn signer_fingerprint(&self) -> Digest;
    fn sign_receipt_digest(&self, digest: &Digest) -> Result<[u8; SIGNATURE_SIZE], ArtifactError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Ed25519Verifier;

impl SignatureVerifier for Ed25519Verifier {
    fn verify(
        &self,
        public_key: &[u8; PUBLIC_KEY_SIZE],
        message: &[u8],
        signature: &[u8; SIGNATURE_SIZE],
    ) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        key.verify_strict(message, &Signature::from_bytes(signature))
            .is_ok()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedArtifact<'a> {
    identified: IdentifiedArtifact<'a>,
    signer_fingerprint: Digest,
    trust_tier: TrustTier,
}

impl<'a> VerifiedArtifact<'a> {
    pub const fn identified(&self) -> &IdentifiedArtifact<'a> {
        &self.identified
    }

    pub const fn signer_fingerprint(&self) -> &Digest {
        &self.signer_fingerprint
    }

    pub const fn trust_tier(&self) -> TrustTier {
        self.trust_tier
    }
}

pub trait ArtifactVerifier {
    fn verify<'a>(&self, bytes: &'a [u8]) -> Result<VerifiedArtifact<'a>, ArtifactError>;
}

pub struct ConfiguredArtifactVerifier<'a, A, S> {
    anchors: &'a A,
    signatures: S,
}

impl<'a, A, S> ConfiguredArtifactVerifier<'a, A, S> {
    pub const fn new(anchors: &'a A, signatures: S) -> Self {
        Self {
            anchors,
            signatures,
        }
    }
}

impl<A: TrustAnchorSet, S: SignatureVerifier> ArtifactVerifier
    for ConfiguredArtifactVerifier<'_, A, S>
{
    fn verify<'b>(&self, bytes: &'b [u8]) -> Result<VerifiedArtifact<'b>, ArtifactError> {
        let identified = parse_and_identify(bytes)?;
        let fingerprint = *identified.artifact.signer_fingerprint;
        let signer = self
            .anchors
            .find(&fingerprint)
            .ok_or(ArtifactError::UntrustedSigner)?;
        if hash(&signer.public_key) != fingerprint {
            return Err(ArtifactError::UntrustedSigner);
        }

        let mut message = [0u8; ARTIFACT_SIGNATURE_MESSAGE_SIZE];
        message[..SIGNATURE_DOMAIN.len()].copy_from_slice(SIGNATURE_DOMAIN);
        message[SIGNATURE_DOMAIN.len()..].copy_from_slice(identified.artifact_id.as_bytes());
        if !self
            .signatures
            .verify(&signer.public_key, &message, identified.artifact.signature)
        {
            return Err(ArtifactError::BadSignature);
        }
        Ok(VerifiedArtifact {
            identified,
            signer_fingerprint: fingerprint,
            trust_tier: signer.tier,
        })
    }
}

#[cfg(feature = "seed0b-test-anchor")]
pub mod seed0b_test_anchor {
    use super::{TrustAnchorSet, TrustTier, TrustedSigner};
    use aienos_crypto::sha256::{hash, Digest};

    pub const LABEL: &str = "SEED-0B QUALIFICATION BUILD — TEST ONLY TRUST ANCHOR";

    // RFC 8032 test-vector public key. Its matching seed is for tests and
    // qualification fixtures only; never use it for production identity.
    pub const PUBLIC_KEY: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    #[derive(Clone, Copy, Debug, Default)]
    pub struct Seed0bTestAnchorSet;

    impl TrustAnchorSet for Seed0bTestAnchorSet {
        fn find(&self, fingerprint: &Digest) -> Option<TrustedSigner> {
            let expected = hash(&PUBLIC_KEY);
            (*fingerprint == expected).then_some(TrustedSigner {
                public_key: PUBLIC_KEY,
                tier: TrustTier::Seed0bQualification,
            })
        }
    }
}

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

pub fn artifact_signature_message(
    artifact_id: &ArtifactId,
) -> [u8; ARTIFACT_SIGNATURE_MESSAGE_SIZE] {
    let mut message = [0u8; ARTIFACT_SIGNATURE_MESSAGE_SIZE];
    message[..SIGNATURE_DOMAIN.len()].copy_from_slice(SIGNATURE_DOMAIN);
    message[SIGNATURE_DOMAIN.len()..].copy_from_slice(artifact_id.as_bytes());
    message
}

pub fn signer_fingerprint(public_key: &[u8; PUBLIC_KEY_SIZE]) -> Digest {
    hash(public_key)
}

pub fn identify_unsigned_artifact(bytes: &[u8]) -> Result<ArtifactId, ArtifactError> {
    let artifact = crate::format::Artifact::parse(bytes)?;
    Ok(compute_artifact_id(&artifact))
}
