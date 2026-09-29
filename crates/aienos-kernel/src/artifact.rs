//! Binary Artifact v0 and SEED-0B Native Capability Admission (ADR 0014).
//!
//! Enforces exact-byte identity, canonical hash computation, cryptographic signature
//! verification, capability manifest validation, and verifiable admission receipt emission.
//! Every format is fixed-size little-endian without architecture or pointer dependencies.

use crate::abi::ABI_VERSION;
use crate::caps::Rights;
use crate::crypto::hmac::{constant_time_eq, hmac_sha256};
use crate::crypto::sha256::{hash as sha256_hash, Digest as Sha256Digest, Sha256};
use core::mem::{offset_of, size_of};

extern crate alloc;
use alloc::vec::Vec;

/// Magic bytes identifying a Binary Artifact v0 container ("AIENART0").
pub const ARTIFACT_MAGIC: [u8; 8] = *b"AIENART0";

/// Magic bytes identifying a Capability Admission Receipt v0 ("AIENRCP0").
pub const RECEIPT_MAGIC: [u8; 8] = *b"AIENRCP0";

/// Binary Artifact container format version 0.
pub const FORMAT_VERSION_0: u16 = 0;

/// Admission Receipt format version 0.
pub const RECEIPT_VERSION_0: u16 = 0;

/// Target architecture: AArch64 (0xAA64).
pub const ARCH_AARCH64: u32 = 0x0000_AA64;

/// Container flags: artifact contains executable code payload.
pub const FLAG_EXECUTABLE: u16 = 1 << 0;

/// Container flags: artifact requires strict MMU and capability isolation.
pub const FLAG_STRICT_ISOLATION: u16 = 1 << 1;

/// Container flags: artifact execution is reversible without persistent mutation.
pub const FLAG_REVERSIBLE: u16 = 1 << 2;

/// Signature algorithm: HMAC-SHA256 with test-anchor / authority secret.
pub const SIG_ALGO_HMAC_SHA256: u16 = 1;

/// Signature algorithm: Ed25519 signature.
pub const SIG_ALGO_ED25519: u16 = 2;

/// Size of the fixed ArtifactHeaderV0 in bytes.
pub const HEADER_SIZE: usize = 80;

/// Size of the fixed CapabilityManifestV0 in bytes.
pub const MANIFEST_SIZE: usize = 256;

/// Maximum capability requests per artifact manifest.
pub const MAX_CAPABILITY_REQUESTS: usize = 8;

/// Maximum capability grants per admission receipt.
pub const MAX_CAPABILITY_GRANTS: usize = 8;

/// Size of the fixed SignatureBlockV0 in bytes.
pub const SIGNATURE_BLOCK_SIZE: usize = 112;

/// Size of the signed receipt body in bytes before signature.
pub const RECEIPT_BODY_SIZE: usize = 472;

/// Size of the fixed AdmissionReceiptV0 in bytes.
pub const RECEIPT_SIZE: usize = 536;

/// Domain separation strings per ADR 0014.
pub const DOMAIN_ARTIFACT_V0: &[u8] = b"AIENOS-ARTIFACT-V0";
pub const DOMAIN_ARTIFACT_SIG_V0: &[u8] = b"AIENOS-ARTIFACT-SIGNATURE-V0";
pub const DOMAIN_RECEIPT_V0: &[u8] = b"AIENOS-ADMISSION-RECEIPT-V0";
pub const DOMAIN_RECEIPT_SIG_V0: &[u8] = b"AIENOS-ADMISSION-RECEIPT-SIGNATURE-V0";

/// Explicit test-only authority secret marker for non-production tests.
pub const TEST_ONLY_AUTHORITY_SECRET: [u8; 32] = [
    0x54, 0x45, 0x53, 0x54, 0x5f, 0x4f, 0x4e, 0x4c, // "TEST_ONL"
    0x59, 0x5f, 0x41, 0x55, 0x54, 0x48, 0x4f, 0x52, // "Y_AUTHOR"
    0x49, 0x54, 0x59, 0x5f, 0x53, 0x45, 0x43, 0x52, // "ITY_SECR"
    0x45, 0x54, 0x5f, 0x56, 0x30, 0x2e, 0x31, 0x21, // "ET_V0.1!"
];

/// Explicit test-only receipt signer secret marker for non-production tests.
pub const TEST_ONLY_RECEIPT_SECRET: [u8; 32] = [
    0x54, 0x45, 0x53, 0x54, 0x5f, 0x4f, 0x4e, 0x4c, // "TEST_ONL"
    0x59, 0x5f, 0x52, 0x45, 0x43, 0x45, 0x49, 0x50, // "Y_RECEIP"
    0x54, 0x5f, 0x53, 0x49, 0x47, 0x4e, 0x45, 0x52, // "T_SIGNER"
    0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x56, 0x30, 0x21, // "_KEY_V0!"
];

/// Errors occurring during artifact parsing, verification, or admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactError {
    BufferTooSmall,
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedArch,
    SectionOutOfBounds,
    SectionOverlap,
    ReservedFieldNonZero,
    CanonicalDigestMismatch,
    InvalidSignature,
    UntrustedSigner,
    RightsEscalation,
    MemoryLimitExceeded,
    GenerationOutdated,
    UnsupportedAbi,
    PayloadEmpty,
    MalformedCapabilityRequest,
    ReceiptArtifactMismatch,
    ReceiptTampered,
    ExecutionFailed,
}

/// Status code recorded in an AdmissionReceiptV0.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionStatus {
    Admitted = 0,
    InvalidMagic = 1,
    TamperedDigest = 2,
    InvalidSignature = 3,
    RightsEscalation = 4,
    MemoryLimitExceeded = 5,
    GenerationOutdated = 6,
    UnsupportedAbi = 7,
    MalformedContainer = 8,
    UntrustedSigner = 9,
    MalformedCapabilityRequest = 10,
}

impl AdmissionStatus {
    pub const fn from_u16(val: u16) -> Option<Self> {
        match val {
            0 => Some(Self::Admitted),
            1 => Some(Self::InvalidMagic),
            2 => Some(Self::TamperedDigest),
            3 => Some(Self::InvalidSignature),
            4 => Some(Self::RightsEscalation),
            5 => Some(Self::MemoryLimitExceeded),
            6 => Some(Self::GenerationOutdated),
            7 => Some(Self::UnsupportedAbi),
            8 => Some(Self::MalformedContainer),
            9 => Some(Self::UntrustedSigner),
            10 => Some(Self::MalformedCapabilityRequest),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Little-endian field helpers

const fn get_u16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

const fn get_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

const fn get_u64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        b[at], b[at + 1], b[at + 2], b[at + 3],
        b[at + 4], b[at + 5], b[at + 6], b[at + 7],
    ])
}

fn put(out: &mut [u8], at: usize, bytes: &[u8]) {
    out[at..at + bytes.len()].copy_from_slice(bytes);
}

// ---------------------------------------------------------------------------
// ArtifactHeaderV0

/// Fixed 80-byte header at the start of every Binary Artifact v0 container.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactHeaderV0 {
    pub magic: [u8; 8],
    pub format_version: u16,
    pub flags: u16,
    pub arch: u32,
    pub capability_id: [u8; 32],
    pub manifest_offset: u32,
    pub manifest_size: u32,
    pub payload_offset: u32,
    pub payload_size: u32,
    pub signature_offset: u32,
    pub signature_size: u32,
    pub total_size: u32,
    pub reserved: [u8; 4],
}

impl ArtifactHeaderV0 {
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        put(&mut out, 0, &self.magic);
        put(&mut out, 8, &self.format_version.to_le_bytes());
        put(&mut out, 10, &self.flags.to_le_bytes());
        put(&mut out, 12, &self.arch.to_le_bytes());
        put(&mut out, 16, &self.capability_id);
        put(&mut out, 48, &self.manifest_offset.to_le_bytes());
        put(&mut out, 52, &self.manifest_size.to_le_bytes());
        put(&mut out, 56, &self.payload_offset.to_le_bytes());
        put(&mut out, 60, &self.payload_size.to_le_bytes());
        put(&mut out, 64, &self.signature_offset.to_le_bytes());
        put(&mut out, 68, &self.signature_size.to_le_bytes());
        put(&mut out, 72, &self.total_size.to_le_bytes());
        put(&mut out, 76, &self.reserved);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ArtifactError> {
        if bytes.len() < HEADER_SIZE {
            return Err(ArtifactError::BufferTooSmall);
        }
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[0..8]);
        if magic != ARTIFACT_MAGIC {
            return Err(ArtifactError::InvalidMagic);
        }
        let format_version = get_u16(bytes, 8);
        if format_version != FORMAT_VERSION_0 {
            return Err(ArtifactError::UnsupportedVersion);
        }
        let flags = get_u16(bytes, 10);
        let arch = get_u32(bytes, 12);
        if arch != ARCH_AARCH64 {
            return Err(ArtifactError::UnsupportedArch);
        }
        let mut capability_id = [0u8; 32];
        capability_id.copy_from_slice(&bytes[16..48]);
        let manifest_offset = get_u32(bytes, 48);
        let manifest_size = get_u32(bytes, 52);
        let payload_offset = get_u32(bytes, 56);
        let payload_size = get_u32(bytes, 60);
        let signature_offset = get_u32(bytes, 64);
        let signature_size = get_u32(bytes, 68);
        let total_size = get_u32(bytes, 72);
        let mut reserved = [0u8; 4];
        reserved.copy_from_slice(&bytes[76..80]);
        if reserved != [0; 4] {
            return Err(ArtifactError::ReservedFieldNonZero);
        }

        // Section bounds and layout invariants:
        if (manifest_offset as usize) < HEADER_SIZE {
            return Err(ArtifactError::SectionOutOfBounds);
        }
        if manifest_size as usize != MANIFEST_SIZE {
            return Err(ArtifactError::SectionOutOfBounds);
        }
        let manifest_end = manifest_offset.checked_add(manifest_size)
            .ok_or(ArtifactError::SectionOutOfBounds)?;
        if manifest_end > payload_offset {
            return Err(ArtifactError::SectionOverlap);
        }
        if payload_size == 0 {
            return Err(ArtifactError::PayloadEmpty);
        }
        let payload_end = payload_offset.checked_add(payload_size)
            .ok_or(ArtifactError::SectionOutOfBounds)?;
        if payload_end > signature_offset {
            return Err(ArtifactError::SectionOverlap);
        }
        if signature_size as usize != SIGNATURE_BLOCK_SIZE {
            return Err(ArtifactError::SectionOutOfBounds);
        }
        let signature_end = signature_offset.checked_add(signature_size)
            .ok_or(ArtifactError::SectionOutOfBounds)?;
        if signature_end > total_size {
            return Err(ArtifactError::SectionOutOfBounds);
        }

        Ok(Self {
            magic,
            format_version,
            flags,
            arch,
            capability_id,
            manifest_offset,
            manifest_size,
            payload_offset,
            payload_size,
            signature_offset,
            signature_size,
            total_size,
            reserved,
        })
    }
}

// ---------------------------------------------------------------------------
// CapabilityRequest & CapabilityGrant

/// Explicit scoped capability request within an artifact manifest (Section 3).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapabilityRequest {
    pub resource_kind: u32,
    pub resource_id: u32,
    pub rights: u32,
    pub reserved: u32,
    pub bounds: u64,
}

impl CapabilityRequest {
    pub const SIZE: usize = 24;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        put(&mut out, 0, &self.resource_kind.to_le_bytes());
        put(&mut out, 4, &self.resource_id.to_le_bytes());
        put(&mut out, 8, &self.rights.to_le_bytes());
        put(&mut out, 12, &self.reserved.to_le_bytes());
        put(&mut out, 16, &self.bounds.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ArtifactError> {
        if bytes.len() < Self::SIZE {
            return Err(ArtifactError::BufferTooSmall);
        }
        let resource_kind = get_u32(bytes, 0);
        let resource_id = get_u32(bytes, 4);
        let rights = get_u32(bytes, 8);
        let reserved = get_u32(bytes, 12);
        if reserved != 0 {
            return Err(ArtifactError::ReservedFieldNonZero);
        }
        let bounds = get_u64(bytes, 16);
        Ok(Self {
            resource_kind,
            resource_id,
            rights,
            reserved,
            bounds,
        })
    }
}

/// Explicit granted capability record in an Admission Receipt (Section 3).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapabilityGrant {
    pub resource_kind: u32,
    pub resource_id: u32,
    pub rights: u32,
    pub reserved: u32,
    pub bounds: u64,
}

impl CapabilityGrant {
    pub const SIZE: usize = 24;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        put(&mut out, 0, &self.resource_kind.to_le_bytes());
        put(&mut out, 4, &self.resource_id.to_le_bytes());
        put(&mut out, 8, &self.rights.to_le_bytes());
        put(&mut out, 12, &self.reserved.to_le_bytes());
        put(&mut out, 16, &self.bounds.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ArtifactError> {
        if bytes.len() < Self::SIZE {
            return Err(ArtifactError::BufferTooSmall);
        }
        let resource_kind = get_u32(bytes, 0);
        let resource_id = get_u32(bytes, 4);
        let rights = get_u32(bytes, 8);
        let reserved = get_u32(bytes, 12);
        if reserved != 0 {
            return Err(ArtifactError::ReservedFieldNonZero);
        }
        let bounds = get_u64(bytes, 16);
        Ok(Self {
            resource_kind,
            resource_id,
            rights,
            reserved,
            bounds,
        })
    }
}

// ---------------------------------------------------------------------------
// CapabilityManifestV0

/// Fixed 256-byte capability manifest in Binary Artifact v0.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityManifestV0 {
    pub abi_version: u16,
    pub target_generation: u16,
    pub entry_offset: u32,
    pub code_pages: u32,
    pub data_pages: u32,
    pub stack_pages: u32,
    pub hardware_target: u32,
    pub capability_count: u32,
    pub signer_id: [u8; 32],
    pub reserved: [u8; 4],
    pub requests: [CapabilityRequest; MAX_CAPABILITY_REQUESTS],
}

impl CapabilityManifestV0 {
    pub fn to_bytes(&self) -> [u8; MANIFEST_SIZE] {
        let mut out = [0u8; MANIFEST_SIZE];
        put(&mut out, 0, &self.abi_version.to_le_bytes());
        put(&mut out, 2, &self.target_generation.to_le_bytes());
        put(&mut out, 4, &self.entry_offset.to_le_bytes());
        put(&mut out, 8, &self.code_pages.to_le_bytes());
        put(&mut out, 12, &self.data_pages.to_le_bytes());
        put(&mut out, 16, &self.stack_pages.to_le_bytes());
        put(&mut out, 20, &self.hardware_target.to_le_bytes());
        put(&mut out, 24, &self.capability_count.to_le_bytes());
        put(&mut out, 28, &self.signer_id);
        put(&mut out, 60, &self.reserved);
        for (i, req) in self.requests.iter().enumerate() {
            let offset = 64 + i * CapabilityRequest::SIZE;
            put(&mut out, offset, &req.to_bytes());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ArtifactError> {
        if bytes.len() < MANIFEST_SIZE {
            return Err(ArtifactError::BufferTooSmall);
        }
        let abi_version = get_u16(bytes, 0);
        let target_generation = get_u16(bytes, 2);
        let entry_offset = get_u32(bytes, 4);
        let code_pages = get_u32(bytes, 8);
        let data_pages = get_u32(bytes, 12);
        let stack_pages = get_u32(bytes, 16);
        let hardware_target = get_u32(bytes, 20);
        let capability_count = get_u32(bytes, 24);
        if capability_count as usize > MAX_CAPABILITY_REQUESTS {
            return Err(ArtifactError::MalformedCapabilityRequest);
        }
        let mut signer_id = [0u8; 32];
        signer_id.copy_from_slice(&bytes[28..60]);
        let mut reserved = [0u8; 4];
        reserved.copy_from_slice(&bytes[60..64]);
        if reserved != [0; 4] {
            return Err(ArtifactError::ReservedFieldNonZero);
        }

        let mut requests = [CapabilityRequest::default(); MAX_CAPABILITY_REQUESTS];
        for (i, req) in requests.iter_mut().enumerate() {
            let offset = 64 + i * CapabilityRequest::SIZE;
            *req = CapabilityRequest::decode(&bytes[offset..offset + CapabilityRequest::SIZE])?;
        }

        Ok(Self {
            abi_version,
            target_generation,
            entry_offset,
            code_pages,
            data_pages,
            stack_pages,
            hardware_target,
            capability_count,
            signer_id,
            reserved,
            requests,
        })
    }

    /// Compute canonical digest over active requested capabilities.
    pub fn compute_requests_digest(&self) -> Sha256Digest {
        let mut h = Sha256::new();
        let count = core::cmp::min(self.capability_count as usize, MAX_CAPABILITY_REQUESTS);
        for req in &self.requests[..count] {
            h.update(&req.to_bytes());
        }
        h.finalize()
    }
}

// ---------------------------------------------------------------------------
// SignatureBlockV0

/// Fixed 112-byte signature block in Binary Artifact v0.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureBlockV0 {
    pub algo: u16,
    pub key_epoch: u16,
    pub sig_len: u32,
    pub signer_pubkey: [u8; 32],
    pub signature: [u8; 64],
    pub reserved: [u8; 8],
}

impl SignatureBlockV0 {
    pub fn to_bytes(&self) -> [u8; SIGNATURE_BLOCK_SIZE] {
        let mut out = [0u8; SIGNATURE_BLOCK_SIZE];
        put(&mut out, 0, &self.algo.to_le_bytes());
        put(&mut out, 2, &self.key_epoch.to_le_bytes());
        put(&mut out, 4, &self.sig_len.to_le_bytes());
        put(&mut out, 8, &self.signer_pubkey);
        put(&mut out, 40, &self.signature);
        put(&mut out, 104, &self.reserved);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ArtifactError> {
        if bytes.len() < SIGNATURE_BLOCK_SIZE {
            return Err(ArtifactError::BufferTooSmall);
        }
        let algo = get_u16(bytes, 0);
        let key_epoch = get_u16(bytes, 2);
        let sig_len = get_u32(bytes, 4);
        let mut signer_pubkey = [0u8; 32];
        signer_pubkey.copy_from_slice(&bytes[8..40]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[40..104]);
        let mut reserved = [0u8; 8];
        reserved.copy_from_slice(&bytes[104..112]);
        if reserved != [0; 8] {
            return Err(ArtifactError::ReservedFieldNonZero);
        }

        Ok(Self {
            algo,
            key_epoch,
            sig_len,
            signer_pubkey,
            signature,
            reserved,
        })
    }
}

// ---------------------------------------------------------------------------
// AdmissionReceiptV0

/// Fixed 536-byte verifiable capability admission receipt (Sections 5 and 6).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionReceiptV0 {
    pub magic: [u8; 8],
    pub receipt_version: u16,
    pub status: u16,
    pub policy_version: u32,
    pub generation: u32,
    pub grant_count: u32,
    pub nonce: u64,
    pub timestamp_ticks: u64,
    pub artifact_id: [u8; 32],
    pub signer_id: [u8; 32],
    pub machine_id: [u8; 32],
    pub verifier_id: [u8; 32],
    pub code_pages: u16,
    pub data_pages: u16,
    pub stack_pages: u16,
    pub reserved_u16: u16,
    pub requests_digest: [u8; 32],
    pub grants_digest: [u8; 32],
    pub grants: [CapabilityGrant; MAX_CAPABILITY_GRANTS],
    pub receipt_id: [u8; 32],
    pub reserved: [u8; 8],
    pub signature: [u8; 64],
}

impl AdmissionReceiptV0 {
    pub fn to_bytes(&self) -> [u8; RECEIPT_SIZE] {
        let mut out = [0u8; RECEIPT_SIZE];
        put(&mut out, 0, &self.magic);
        put(&mut out, 8, &self.receipt_version.to_le_bytes());
        put(&mut out, 10, &self.status.to_le_bytes());
        put(&mut out, 12, &self.policy_version.to_le_bytes());
        put(&mut out, 16, &self.generation.to_le_bytes());
        put(&mut out, 20, &self.grant_count.to_le_bytes());
        put(&mut out, 24, &self.nonce.to_le_bytes());
        put(&mut out, 32, &self.timestamp_ticks.to_le_bytes());
        put(&mut out, 40, &self.artifact_id);
        put(&mut out, 72, &self.signer_id);
        put(&mut out, 104, &self.machine_id);
        put(&mut out, 136, &self.verifier_id);
        put(&mut out, 168, &self.code_pages.to_le_bytes());
        put(&mut out, 170, &self.data_pages.to_le_bytes());
        put(&mut out, 172, &self.stack_pages.to_le_bytes());
        put(&mut out, 174, &self.reserved_u16.to_le_bytes());
        put(&mut out, 176, &self.requests_digest);
        put(&mut out, 208, &self.grants_digest);
        for (i, grant) in self.grants.iter().enumerate() {
            let offset = 240 + i * CapabilityGrant::SIZE;
            put(&mut out, offset, &grant.to_bytes());
        }
        put(&mut out, 432, &self.receipt_id);
        put(&mut out, 464, &self.reserved);
        put(&mut out, 472, &self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ArtifactError> {
        if bytes.len() < RECEIPT_SIZE {
            return Err(ArtifactError::BufferTooSmall);
        }
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[0..8]);
        if magic != RECEIPT_MAGIC {
            return Err(ArtifactError::InvalidMagic);
        }
        let receipt_version = get_u16(bytes, 8);
        if receipt_version != RECEIPT_VERSION_0 {
            return Err(ArtifactError::UnsupportedVersion);
        }
        let status = get_u16(bytes, 10);
        let policy_version = get_u32(bytes, 12);
        let generation = get_u32(bytes, 16);
        let grant_count = get_u32(bytes, 20);
        if grant_count as usize > MAX_CAPABILITY_GRANTS {
            return Err(ArtifactError::MalformedCapabilityRequest);
        }
        let nonce = get_u64(bytes, 24);
        let timestamp_ticks = get_u64(bytes, 32);
        let mut artifact_id = [0u8; 32];
        artifact_id.copy_from_slice(&bytes[40..72]);
        let mut signer_id = [0u8; 32];
        signer_id.copy_from_slice(&bytes[72..104]);
        let mut machine_id = [0u8; 32];
        machine_id.copy_from_slice(&bytes[104..136]);
        let mut verifier_id = [0u8; 32];
        verifier_id.copy_from_slice(&bytes[136..168]);
        let code_pages = get_u16(bytes, 168);
        let data_pages = get_u16(bytes, 170);
        let stack_pages = get_u16(bytes, 172);
        let reserved_u16 = get_u16(bytes, 174);
        if reserved_u16 != 0 {
            return Err(ArtifactError::ReservedFieldNonZero);
        }
        let mut requests_digest = [0u8; 32];
        requests_digest.copy_from_slice(&bytes[176..208]);
        let mut grants_digest = [0u8; 32];
        grants_digest.copy_from_slice(&bytes[208..240]);

        let mut grants = [CapabilityGrant::default(); MAX_CAPABILITY_GRANTS];
        for (i, grant) in grants.iter_mut().enumerate() {
            let offset = 240 + i * CapabilityGrant::SIZE;
            *grant = CapabilityGrant::decode(&bytes[offset..offset + CapabilityGrant::SIZE])?;
        }

        let mut receipt_id = [0u8; 32];
        receipt_id.copy_from_slice(&bytes[432..464]);
        let mut reserved = [0u8; 8];
        reserved.copy_from_slice(&bytes[464..472]);
        if reserved != [0; 8] {
            return Err(ArtifactError::ReservedFieldNonZero);
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[472..536]);

        let receipt = Self {
            magic,
            receipt_version,
            status,
            policy_version,
            generation,
            grant_count,
            nonce,
            timestamp_ticks,
            artifact_id,
            signer_id,
            machine_id,
            verifier_id,
            code_pages,
            data_pages,
            stack_pages,
            reserved_u16,
            requests_digest,
            grants_digest,
            grants,
            receipt_id,
            reserved,
            signature,
        };

        if !receipt.verify_receipt_id() {
            return Err(ArtifactError::ReceiptTampered);
        }
        Ok(receipt)
    }

    /// Compute canonical ReceiptId: HASH("AIENOS-ADMISSION-RECEIPT-V0" || bytes 0..432).
    pub fn compute_receipt_id(&self) -> Sha256Digest {
        let raw = self.to_bytes();
        let mut h = Sha256::new();
        h.update(DOMAIN_RECEIPT_V0);
        h.update(&raw[..432]);
        h.finalize()
    }

    /// Verify that self.receipt_id matches the domain-separated hash of fields 0..432.
    pub fn verify_receipt_id(&self) -> bool {
        let expected = self.compute_receipt_id();
        constant_time_eq(&self.receipt_id, &expected)
    }

    /// Sign the receipt with the receipt authority secret.
    pub fn sign_receipt(&mut self, secret: &[u8; 32]) {
        self.receipt_id = self.compute_receipt_id();
        let mut preimage = [0u8; DOMAIN_RECEIPT_SIG_V0.len() + 32];
        preimage[..DOMAIN_RECEIPT_SIG_V0.len()].copy_from_slice(DOMAIN_RECEIPT_SIG_V0);
        preimage[DOMAIN_RECEIPT_SIG_V0.len()..].copy_from_slice(&self.receipt_id);
        let sig = hmac_sha256(secret, &preimage);
        self.signature[..32].copy_from_slice(&sig);
    }

    /// Verify cryptographic receipt signature.
    pub fn verify_signature(&self, secret: &[u8; 32]) -> bool {
        if !self.verify_receipt_id() {
            return false;
        }
        let mut preimage = [0u8; DOMAIN_RECEIPT_SIG_V0.len() + 32];
        preimage[..DOMAIN_RECEIPT_SIG_V0.len()].copy_from_slice(DOMAIN_RECEIPT_SIG_V0);
        preimage[DOMAIN_RECEIPT_SIG_V0.len()..].copy_from_slice(&self.receipt_id);
        let expected_sig = hmac_sha256(secret, &preimage);
        constant_time_eq(&expected_sig, &self.signature[..32])
    }

    pub fn is_admitted(&self) -> bool {
        self.status == AdmissionStatus::Admitted as u16 && self.verify_receipt_id()
    }
}

// ---------------------------------------------------------------------------
// Exact-Byte Identity & Canonical Domain-Separated Hash Calculation (Section 2)

/// Compute canonical ArtifactId = HASH("AIENOS-ARTIFACT-V0" || canonical_unsigned_artifact).
pub fn compute_artifact_id(canonical_unsigned_artifact: &[u8]) -> Sha256Digest {
    let mut h = Sha256::new();
    h.update(DOMAIN_ARTIFACT_V0);
    h.update(canonical_unsigned_artifact);
    h.finalize()
}

/// Compute canonical domain-separated signature = SIGN("AIENOS-ARTIFACT-SIGNATURE-V0" || ArtifactId).
pub fn compute_artifact_signature(secret: &[u8; 32], artifact_id: &[u8; 32]) -> Sha256Digest {
    let mut preimage = [0u8; DOMAIN_ARTIFACT_SIG_V0.len() + 32];
    preimage[..DOMAIN_ARTIFACT_SIG_V0.len()].copy_from_slice(DOMAIN_ARTIFACT_SIG_V0);
    preimage[DOMAIN_ARTIFACT_SIG_V0.len()..].copy_from_slice(artifact_id);
    hmac_sha256(secret, &preimage)
}

/// Compute the canonical digest over Header + Manifest + Payload up to signature_offset.
pub fn compute_canonical_digest(artifact_bytes: &[u8]) -> Result<Sha256Digest, ArtifactError> {
    if artifact_bytes.len() < HEADER_SIZE {
        return Err(ArtifactError::BufferTooSmall);
    }
    let header = ArtifactHeaderV0::decode(&artifact_bytes[..HEADER_SIZE])?;
    if (artifact_bytes.len() as u32) != header.total_size {
        return Err(ArtifactError::SectionOutOfBounds);
    }
    if (header.signature_offset as usize) > artifact_bytes.len() {
        return Err(ArtifactError::SectionOutOfBounds);
    }
    Ok(compute_artifact_id(&artifact_bytes[..header.signature_offset as usize]))
}

// ---------------------------------------------------------------------------
// ArtifactBuilder

/// Builder for constructing and signing a Binary Artifact v0 container.
pub struct ArtifactBuilder {
    flags: u16,
    capability_id: [u8; 32],
    abi_version: u16,
    target_generation: u16,
    entry_offset: u32,
    code_pages: u32,
    data_pages: u32,
    stack_pages: u32,
    hardware_target: u32,
    requests: Vec<CapabilityRequest>,
    payload: Vec<u8>,
}

impl ArtifactBuilder {
    pub fn new(capability_id_str: &str, payload_bytes: &[u8]) -> Self {
        let mut id = [0u8; 32];
        let id_bytes = capability_id_str.as_bytes();
        let copy_len = core::cmp::min(id_bytes.len(), 32);
        id[..copy_len].copy_from_slice(&id_bytes[..copy_len]);

        Self {
            flags: FLAG_EXECUTABLE | FLAG_STRICT_ISOLATION,
            capability_id: id,
            abi_version: ABI_VERSION,
            target_generation: 1,
            entry_offset: 0,
            code_pages: 1,
            data_pages: 0,
            stack_pages: 1,
            hardware_target: 0,
            requests: Vec::new(),
            payload: payload_bytes.to_vec(),
        }
    }

    pub fn with_request(mut self, req: CapabilityRequest) -> Self {
        if self.requests.len() < MAX_CAPABILITY_REQUESTS {
            self.requests.push(req);
        }
        self
    }

    pub fn with_generation(mut self, gen: u16) -> Self {
        self.target_generation = gen;
        self
    }

    pub fn with_code_pages(mut self, pages: u32) -> Self {
        self.code_pages = pages;
        self
    }

    pub fn with_stack_pages(mut self, pages: u32) -> Self {
        self.stack_pages = pages;
        self
    }

    pub fn with_abi_version(mut self, abi: u16) -> Self {
        self.abi_version = abi;
        self
    }

    pub fn with_entry_offset(mut self, offset: u32) -> Self {
        self.entry_offset = offset;
        self
    }

    /// Build and cryptographically sign the artifact using authority HMAC secret.
    pub fn build_and_sign(
        self,
        authority_secret: &[u8; 32],
        signer_pubkey: &[u8; 32],
    ) -> Result<Vec<u8>, ArtifactError> {
        let payload_size = self.payload.len() as u32;
        if payload_size == 0 {
            return Err(ArtifactError::PayloadEmpty);
        }
        let manifest_offset = HEADER_SIZE as u32;
        let manifest_size = MANIFEST_SIZE as u32;
        let payload_offset = manifest_offset + manifest_size;
        let signature_offset = payload_offset + payload_size;
        let signature_size = SIGNATURE_BLOCK_SIZE as u32;
        let total_size = signature_offset + signature_size;

        let header = ArtifactHeaderV0 {
            magic: ARTIFACT_MAGIC,
            format_version: FORMAT_VERSION_0,
            flags: self.flags,
            arch: ARCH_AARCH64,
            capability_id: self.capability_id,
            manifest_offset,
            manifest_size,
            payload_offset,
            payload_size,
            signature_offset,
            signature_size,
            total_size,
            reserved: [0; 4],
        };

        let mut req_array = [CapabilityRequest::default(); MAX_CAPABILITY_REQUESTS];
        for (i, req) in self.requests.iter().enumerate() {
            req_array[i] = *req;
        }

        let manifest = CapabilityManifestV0 {
            abi_version: self.abi_version,
            target_generation: self.target_generation,
            entry_offset: self.entry_offset,
            code_pages: self.code_pages,
            data_pages: self.data_pages,
            stack_pages: self.stack_pages,
            hardware_target: self.hardware_target,
            capability_count: self.requests.len() as u32,
            signer_id: *signer_pubkey,
            reserved: [0; 4],
            requests: req_array,
        };

        let mut out = Vec::with_capacity(total_size as usize);
        out.extend_from_slice(&header.to_bytes());
        out.extend_from_slice(&manifest.to_bytes());
        out.extend_from_slice(&self.payload);

        // Domain-separated ArtifactId:
        let artifact_id = compute_artifact_id(&out);
        let hmac_tag = compute_artifact_signature(authority_secret, &artifact_id);

        let mut signature_field = [0u8; 64];
        signature_field[..32].copy_from_slice(&hmac_tag);

        let sig_block = SignatureBlockV0 {
            algo: SIG_ALGO_HMAC_SHA256,
            key_epoch: 1,
            sig_len: 32,
            signer_pubkey: *signer_pubkey,
            signature: signature_field,
            reserved: [0; 8],
        };
        out.extend_from_slice(&sig_block.to_bytes());

        assert_eq!(out.len(), total_size as usize);
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Cryptographic Interfaces (Section 4)

pub trait SignatureVerifier {
    fn verify_signature(&self, key: &[u8; 32], message: &[u8], sig: &[u8]) -> bool;
}

pub trait ArtifactVerifier {
    fn verify_artifact(&self, artifact_bytes: &[u8]) -> Result<AdmittedArtifactView<'_>, ArtifactError>;
}

pub trait ReceiptSigner {
    fn sign_receipt(&self, receipt: &mut AdmissionReceiptV0);
}

/// Explicit test-only trust anchors for unit and integration testing.
pub struct TestOnlyTrustAnchors {
    pub authority_secret: [u8; 32],
    pub receipt_secret: [u8; 32],
    pub signer_id: [u8; 32],
}

impl Default for TestOnlyTrustAnchors {
    fn default() -> Self {
        Self {
            authority_secret: TEST_ONLY_AUTHORITY_SECRET,
            receipt_secret: TEST_ONLY_RECEIPT_SECRET,
            signer_id: sha256_hash(&TEST_ONLY_AUTHORITY_SECRET),
        }
    }
}

// ---------------------------------------------------------------------------
// Admission Policy & Engine (Section 3 and 7)

/// Policy defining constraints and authority envelopes for artifact admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionPolicy {
    pub allowed_machine_id: [u8; 32],
    pub verifier_id: [u8; 32],
    pub signing_secret: [u8; 32],
    pub receipt_secret: [u8; 32],
    pub allowed_signer_id: Option<[u8; 32]>,
    pub policy_version: u32,
    pub min_generation: u32,
    pub max_code_pages: u32,
    pub max_data_pages: u32,
    pub max_stack_pages: u32,
    pub allowed_envelope: [CapabilityGrant; MAX_CAPABILITY_GRANTS],
    pub allowed_envelope_count: usize,
}

impl Default for AdmissionPolicy {
    fn default() -> Self {
        let mut envelope = [CapabilityGrant::default(); MAX_CAPABILITY_GRANTS];
        // Default permission: Console output with WRITE rights up to 4096 bytes:
        envelope[0] = CapabilityGrant {
            resource_kind: 1, // CONSOLE
            resource_id: 0,   // ANY
            rights: Rights::WRITE.bits() as u32,
            reserved: 0,
            bounds: 4096,
        };

        Self {
            allowed_machine_id: [0x42; 32],
            verifier_id: [0x11; 32],
            signing_secret: TEST_ONLY_AUTHORITY_SECRET,
            receipt_secret: TEST_ONLY_RECEIPT_SECRET,
            allowed_signer_id: None,
            policy_version: 1,
            min_generation: 1,
            max_code_pages: 4,
            max_data_pages: 4,
            max_stack_pages: 4,
            allowed_envelope: envelope,
            allowed_envelope_count: 1,
        }
    }
}

/// Validated view of an admitted artifact ready for task window placement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmittedArtifactView<'a> {
    pub header: ArtifactHeaderV0,
    pub manifest: CapabilityManifestV0,
    pub payload: &'a [u8],
    pub artifact_id: Sha256Digest,
    pub signer_pubkey: [u8; 32],
}

/// Execute the cryptographic admission pipeline against an artifact byte slice.
///
/// Fails closed: any validation error produces an explicit Rejection receipt
/// and returns an error without admitting or loading the code payload.
pub fn admit_artifact<'a>(
    artifact_bytes: &'a [u8],
    policy: &AdmissionPolicy,
    nonce: u64,
    timestamp_ticks: u64,
) -> (AdmissionReceiptV0, Result<AdmittedArtifactView<'a>, ArtifactError>) {
    let make_rejection = |status: AdmissionStatus, err: ArtifactError, id: [u8; 32]| {
        let mut r = AdmissionReceiptV0 {
            magic: RECEIPT_MAGIC,
            receipt_version: RECEIPT_VERSION_0,
            status: status as u16,
            policy_version: policy.policy_version,
            generation: policy.min_generation,
            grant_count: 0,
            nonce,
            timestamp_ticks,
            artifact_id: id,
            signer_id: [0; 32],
            machine_id: policy.allowed_machine_id,
            verifier_id: policy.verifier_id,
            code_pages: 0,
            data_pages: 0,
            stack_pages: 0,
            reserved_u16: 0,
            requests_digest: [0; 32],
            grants_digest: [0; 32],
            grants: [CapabilityGrant::default(); MAX_CAPABILITY_GRANTS],
            receipt_id: [0; 32],
            reserved: [0; 8],
            signature: [0; 64],
        };
        r.sign_receipt(&policy.receipt_secret);
        (r, Err(err))
    };

    if artifact_bytes.len() < HEADER_SIZE + MANIFEST_SIZE + SIGNATURE_BLOCK_SIZE {
        return make_rejection(AdmissionStatus::MalformedContainer, ArtifactError::BufferTooSmall, [0; 32]);
    }

    let header = match ArtifactHeaderV0::decode(&artifact_bytes[..HEADER_SIZE]) {
        Ok(h) => h,
        Err(e) => {
            let status = match e {
                ArtifactError::InvalidMagic => AdmissionStatus::InvalidMagic,
                _ => AdmissionStatus::MalformedContainer,
            };
            return make_rejection(status, e, [0; 32]);
        }
    };

    if (artifact_bytes.len() as u32) != header.total_size {
        return make_rejection(AdmissionStatus::MalformedContainer, ArtifactError::SectionOutOfBounds, [0; 32]);
    }

    let manifest_bytes = &artifact_bytes[header.manifest_offset as usize..(header.manifest_offset + header.manifest_size) as usize];
    let manifest = match CapabilityManifestV0::decode(manifest_bytes) {
        Ok(m) => m,
        Err(e) => return make_rejection(AdmissionStatus::MalformedContainer, e, [0; 32]),
    };

    let sig_bytes = &artifact_bytes[header.signature_offset as usize..(header.signature_offset + header.signature_size) as usize];
    let sig_block = match SignatureBlockV0::decode(sig_bytes) {
        Ok(s) => s,
        Err(e) => return make_rejection(AdmissionStatus::MalformedContainer, e, [0; 32]),
    };

    // Domain-separated ArtifactId:
    let artifact_id = compute_artifact_id(&artifact_bytes[..header.signature_offset as usize]);

    // Cryptographic signature verification:
    if sig_block.algo != SIG_ALGO_HMAC_SHA256 {
        return make_rejection(AdmissionStatus::InvalidSignature, ArtifactError::InvalidSignature, artifact_id);
    }
    let expected_hmac = compute_artifact_signature(&policy.signing_secret, &artifact_id);
    if !constant_time_eq(&expected_hmac, &sig_block.signature[..32]) {
        return make_rejection(AdmissionStatus::InvalidSignature, ArtifactError::InvalidSignature, artifact_id);
    }

    // Signer authorization:
    if let Some(expected_signer) = policy.allowed_signer_id {
        if !constant_time_eq(&expected_signer, &sig_block.signer_pubkey) {
            return make_rejection(AdmissionStatus::UntrustedSigner, ArtifactError::UntrustedSigner, artifact_id);
        }
    }

    // Manifest ABI check:
    if manifest.abi_version != ABI_VERSION {
        return make_rejection(AdmissionStatus::UnsupportedAbi, ArtifactError::UnsupportedAbi, artifact_id);
    }

    // Generation check:
    if (manifest.target_generation as u32) < policy.min_generation {
        return make_rejection(AdmissionStatus::GenerationOutdated, ArtifactError::GenerationOutdated, artifact_id);
    }

    // Memory limit checks:
    if manifest.code_pages > policy.max_code_pages
        || manifest.data_pages > policy.max_data_pages
        || manifest.stack_pages > policy.max_stack_pages
    {
        return make_rejection(AdmissionStatus::MemoryLimitExceeded, ArtifactError::MemoryLimitExceeded, artifact_id);
    }

    let payload = &artifact_bytes[header.payload_offset as usize..(header.payload_offset + header.payload_size) as usize];
    if (manifest.entry_offset as usize) >= payload.len() {
        return make_rejection(AdmissionStatus::MalformedContainer, ArtifactError::SectionOutOfBounds, artifact_id);
    }

    // Scoped capability evaluation (Section 3: granted ⊆ requested):
    let mut granted_list = [CapabilityGrant::default(); MAX_CAPABILITY_GRANTS];
    let mut grant_count = 0;
    let req_count = core::cmp::min(manifest.capability_count as usize, MAX_CAPABILITY_REQUESTS);

    for req in &manifest.requests[..req_count] {
        // Find matching policy grant:
        let mut matched = false;
        for env in &policy.allowed_envelope[..policy.allowed_envelope_count] {
            if env.resource_kind == req.resource_kind && (env.resource_id == 0 || env.resource_id == req.resource_id) {
                // Rights escalation check: requested rights must be covered by policy envelope:
                if (req.rights & !env.rights) != 0 {
                    return make_rejection(AdmissionStatus::RightsEscalation, ArtifactError::RightsEscalation, artifact_id);
                }
                // Attenuate: granted = requested ∩ policy
                let granted_rights = req.rights & env.rights;
                let granted_bounds = core::cmp::min(req.bounds, env.bounds);
                granted_list[grant_count] = CapabilityGrant {
                    resource_kind: req.resource_kind,
                    resource_id: req.resource_id,
                    rights: granted_rights,
                    reserved: 0,
                    bounds: granted_bounds,
                };
                grant_count += 1;
                matched = true;
                break;
            }
        }
        if !matched {
            // Requested resource not permitted by policy envelope:
            return make_rejection(AdmissionStatus::RightsEscalation, ArtifactError::RightsEscalation, artifact_id);
        }
    }

    let requests_digest = manifest.compute_requests_digest();
    let mut h_grants = Sha256::new();
    for g in &granted_list[..grant_count] {
        h_grants.update(&g.to_bytes());
    }
    let grants_digest = h_grants.finalize();

    // Admitted: emit signed receipt:
    let mut receipt = AdmissionReceiptV0 {
        magic: RECEIPT_MAGIC,
        receipt_version: RECEIPT_VERSION_0,
        status: AdmissionStatus::Admitted as u16,
        policy_version: policy.policy_version,
        generation: manifest.target_generation as u32,
        grant_count: grant_count as u32,
        nonce,
        timestamp_ticks,
        artifact_id,
        signer_id: sig_block.signer_pubkey,
        machine_id: policy.allowed_machine_id,
        verifier_id: policy.verifier_id,
        code_pages: manifest.code_pages as u16,
        data_pages: manifest.data_pages as u16,
        stack_pages: manifest.stack_pages as u16,
        reserved_u16: 0,
        requests_digest,
        grants_digest,
        grants: granted_list,
        receipt_id: [0; 32],
        reserved: [0; 8],
        signature: [0; 64],
    };
    receipt.sign_receipt(&policy.receipt_secret);

    let view = AdmittedArtifactView {
        header,
        manifest,
        payload,
        artifact_id,
        signer_pubkey: sig_block.signer_pubkey,
    };

    (receipt, Ok(view))
}

// ---------------------------------------------------------------------------
// Struct layout and alignment assertions

const _: () = {
    assert!(size_of::<ArtifactHeaderV0>() == HEADER_SIZE);
    assert!(offset_of!(ArtifactHeaderV0, magic) == 0);
    assert!(offset_of!(ArtifactHeaderV0, format_version) == 8);
    assert!(offset_of!(ArtifactHeaderV0, flags) == 10);
    assert!(offset_of!(ArtifactHeaderV0, arch) == 12);
    assert!(offset_of!(ArtifactHeaderV0, capability_id) == 16);
    assert!(offset_of!(ArtifactHeaderV0, manifest_offset) == 48);
    assert!(offset_of!(ArtifactHeaderV0, manifest_size) == 52);
    assert!(offset_of!(ArtifactHeaderV0, payload_offset) == 56);
    assert!(offset_of!(ArtifactHeaderV0, payload_size) == 60);
    assert!(offset_of!(ArtifactHeaderV0, signature_offset) == 64);
    assert!(offset_of!(ArtifactHeaderV0, signature_size) == 68);
    assert!(offset_of!(ArtifactHeaderV0, total_size) == 72);
    assert!(offset_of!(ArtifactHeaderV0, reserved) == 76);

    assert!(size_of::<CapabilityRequest>() == 24);
    assert!(offset_of!(CapabilityRequest, resource_kind) == 0);
    assert!(offset_of!(CapabilityRequest, resource_id) == 4);
    assert!(offset_of!(CapabilityRequest, rights) == 8);
    assert!(offset_of!(CapabilityRequest, reserved) == 12);
    assert!(offset_of!(CapabilityRequest, bounds) == 16);

    assert!(size_of::<CapabilityGrant>() == 24);
    assert!(offset_of!(CapabilityGrant, resource_kind) == 0);
    assert!(offset_of!(CapabilityGrant, resource_id) == 4);
    assert!(offset_of!(CapabilityGrant, rights) == 8);
    assert!(offset_of!(CapabilityGrant, reserved) == 12);
    assert!(offset_of!(CapabilityGrant, bounds) == 16);

    assert!(size_of::<CapabilityManifestV0>() == MANIFEST_SIZE);
    assert!(offset_of!(CapabilityManifestV0, abi_version) == 0);
    assert!(offset_of!(CapabilityManifestV0, target_generation) == 2);
    assert!(offset_of!(CapabilityManifestV0, entry_offset) == 4);
    assert!(offset_of!(CapabilityManifestV0, code_pages) == 8);
    assert!(offset_of!(CapabilityManifestV0, data_pages) == 12);
    assert!(offset_of!(CapabilityManifestV0, stack_pages) == 16);
    assert!(offset_of!(CapabilityManifestV0, hardware_target) == 20);
    assert!(offset_of!(CapabilityManifestV0, capability_count) == 24);
    assert!(offset_of!(CapabilityManifestV0, signer_id) == 28);
    assert!(offset_of!(CapabilityManifestV0, reserved) == 60);
    assert!(offset_of!(CapabilityManifestV0, requests) == 64);

    assert!(size_of::<SignatureBlockV0>() == SIGNATURE_BLOCK_SIZE);
    assert!(offset_of!(SignatureBlockV0, algo) == 0);
    assert!(offset_of!(SignatureBlockV0, key_epoch) == 2);
    assert!(offset_of!(SignatureBlockV0, sig_len) == 4);
    assert!(offset_of!(SignatureBlockV0, signer_pubkey) == 8);
    assert!(offset_of!(SignatureBlockV0, signature) == 40);
    assert!(offset_of!(SignatureBlockV0, reserved) == 104);

    assert!(size_of::<AdmissionReceiptV0>() == RECEIPT_SIZE);
    assert!(offset_of!(AdmissionReceiptV0, magic) == 0);
    assert!(offset_of!(AdmissionReceiptV0, receipt_version) == 8);
    assert!(offset_of!(AdmissionReceiptV0, status) == 10);
    assert!(offset_of!(AdmissionReceiptV0, policy_version) == 12);
    assert!(offset_of!(AdmissionReceiptV0, generation) == 16);
    assert!(offset_of!(AdmissionReceiptV0, grant_count) == 20);
    assert!(offset_of!(AdmissionReceiptV0, nonce) == 24);
    assert!(offset_of!(AdmissionReceiptV0, timestamp_ticks) == 32);
    assert!(offset_of!(AdmissionReceiptV0, artifact_id) == 40);
    assert!(offset_of!(AdmissionReceiptV0, signer_id) == 72);
    assert!(offset_of!(AdmissionReceiptV0, machine_id) == 104);
    assert!(offset_of!(AdmissionReceiptV0, verifier_id) == 136);
    assert!(offset_of!(AdmissionReceiptV0, code_pages) == 168);
    assert!(offset_of!(AdmissionReceiptV0, data_pages) == 170);
    assert!(offset_of!(AdmissionReceiptV0, stack_pages) == 172);
    assert!(offset_of!(AdmissionReceiptV0, reserved_u16) == 174);
    assert!(offset_of!(AdmissionReceiptV0, requests_digest) == 176);
    assert!(offset_of!(AdmissionReceiptV0, grants_digest) == 208);
    assert!(offset_of!(AdmissionReceiptV0, grants) == 240);
    assert!(offset_of!(AdmissionReceiptV0, receipt_id) == 432);
    assert!(offset_of!(AdmissionReceiptV0, reserved) == 464);
    assert!(offset_of!(AdmissionReceiptV0, signature) == 472);
};

// ---------------------------------------------------------------------------
// Unit tests and Mandatory Negative Tests (Section 12)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip() {
        let header = ArtifactHeaderV0 {
            magic: ARTIFACT_MAGIC,
            format_version: FORMAT_VERSION_0,
            flags: FLAG_EXECUTABLE | FLAG_STRICT_ISOLATION,
            arch: ARCH_AARCH64,
            capability_id: *b"seed0b.test.capability\0\0\0\0\0\0\0\0\0\0",
            manifest_offset: 80,
            manifest_size: 256,
            payload_offset: 336,
            payload_size: 16,
            signature_offset: 352,
            signature_size: 112,
            total_size: 464,
            reserved: [0; 4],
        };
        let bytes = header.to_bytes();
        let decoded = ArtifactHeaderV0::decode(&bytes).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn manifest_round_trip() {
        let mut manifest = CapabilityManifestV0 {
            abi_version: ABI_VERSION,
            target_generation: 1,
            entry_offset: 0,
            code_pages: 1,
            data_pages: 0,
            stack_pages: 1,
            hardware_target: 0,
            capability_count: 1,
            signer_id: [0x5a; 32],
            reserved: [0; 4],
            requests: [CapabilityRequest::default(); MAX_CAPABILITY_REQUESTS],
        };
        manifest.requests[0] = CapabilityRequest {
            resource_kind: 1,
            resource_id: 0,
            rights: Rights::WRITE.bits() as u32,
            reserved: 0,
            bounds: 4096,
        };

        let bytes = manifest.to_bytes();
        let decoded = CapabilityManifestV0::decode(&bytes).unwrap();
        assert_eq!(manifest, decoded);
    }

    #[test]
    fn receipt_round_trip_and_signature_verification() {
        let secret = [0x99u8; 32];
        let mut receipt = AdmissionReceiptV0 {
            magic: RECEIPT_MAGIC,
            receipt_version: RECEIPT_VERSION_0,
            status: AdmissionStatus::Admitted as u16,
            policy_version: 1,
            generation: 1,
            grant_count: 1,
            nonce: 1001,
            timestamp_ticks: 123456,
            artifact_id: [0xaa; 32],
            signer_id: [0xbb; 32],
            machine_id: [0x42; 32],
            verifier_id: [0x11; 32],
            code_pages: 1,
            data_pages: 0,
            stack_pages: 1,
            reserved_u16: 0,
            requests_digest: [0xcc; 32],
            grants_digest: [0xdd; 32],
            grants: [CapabilityGrant::default(); MAX_CAPABILITY_GRANTS],
            receipt_id: [0; 32],
            reserved: [0; 8],
            signature: [0; 64],
        };
        receipt.grants[0] = CapabilityGrant {
            resource_kind: 1,
            resource_id: 0,
            rights: Rights::WRITE.bits() as u32,
            reserved: 0,
            bounds: 4096,
        };

        receipt.sign_receipt(&secret);
        assert!(receipt.verify_signature(&secret));
        assert!(receipt.is_admitted());

        let bytes = receipt.to_bytes();
        let decoded = AdmissionReceiptV0::decode(&bytes).unwrap();
        assert_eq!(receipt, decoded);
        assert!(decoded.verify_signature(&secret));
    }

    #[test]
    fn build_sign_and_admit_success() {
        let anchors = TestOnlyTrustAnchors::default();
        let payload = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        let req = CapabilityRequest {
            resource_kind: 1, // CONSOLE
            resource_id: 0,
            rights: Rights::WRITE.bits() as u32,
            reserved: 0,
            bounds: 4096,
        };

        let artifact = ArtifactBuilder::new("seed0b.echo", &payload)
            .with_request(req)
            .with_generation(1)
            .build_and_sign(&anchors.authority_secret, &anchors.signer_id)
            .unwrap();

        let policy = AdmissionPolicy {
            allowed_signer_id: Some(anchors.signer_id),
            ..Default::default()
        };

        let (receipt, view) = admit_artifact(&artifact, &policy, 100, 2000);
        assert!(receipt.is_admitted());
        assert_eq!(receipt.status, AdmissionStatus::Admitted as u16);
        assert_eq!(receipt.grant_count, 1);
        assert_eq!(receipt.grants[0].rights, Rights::WRITE.bits() as u32);
        let view = view.unwrap();
        assert_eq!(view.payload, &payload);
        assert_eq!(view.artifact_id, receipt.artifact_id);
    }

    // --- Mandatory Negative Tests (Section 12) ---

    #[test]
    fn negative_1_wrong_magic() {
        let anchors = TestOnlyTrustAnchors::default();
        let mut artifact = ArtifactBuilder::new("seed0b.test", &[0x42; 64])
            .build_and_sign(&anchors.authority_secret, &anchors.signer_id)
            .unwrap();
        artifact[0] = b'X';
        let (receipt, res) = admit_artifact(&artifact, &AdmissionPolicy::default(), 1, 0);
        assert_eq!(receipt.status, AdmissionStatus::InvalidMagic as u16);
        assert_eq!(res, Err(ArtifactError::InvalidMagic));
    }

    #[test]
    fn negative_2_unknown_artifact_version() {
        let anchors = TestOnlyTrustAnchors::default();
        let mut artifact = ArtifactBuilder::new("seed0b.test", &[0x42; 64])
            .build_and_sign(&anchors.authority_secret, &anchors.signer_id)
            .unwrap();
        artifact[8] = 99; // format_version
        let (receipt, res) = admit_artifact(&artifact, &AdmissionPolicy::default(), 1, 0);
        assert_eq!(receipt.status, AdmissionStatus::MalformedContainer as u16);
        assert_eq!(res, Err(ArtifactError::UnsupportedVersion));
    }

    #[test]
    fn negative_3_wrong_abi_version() {
        let anchors = TestOnlyTrustAnchors::default();
        let artifact = ArtifactBuilder::new("seed0b.test", &[0x42; 64])
            .with_abi_version(99)
            .build_and_sign(&anchors.authority_secret, &anchors.signer_id)
            .unwrap();
        let (receipt, res) = admit_artifact(&artifact, &AdmissionPolicy::default(), 1, 0);
        assert_eq!(receipt.status, AdmissionStatus::UnsupportedAbi as u16);
        assert_eq!(res, Err(ArtifactError::UnsupportedAbi));
    }

    #[test]
    fn negative_4_wrong_target_architecture() {
        let anchors = TestOnlyTrustAnchors::default();
        let mut artifact = ArtifactBuilder::new("seed0b.test", &[0x42; 64])
            .build_and_sign(&anchors.authority_secret, &anchors.signer_id)
            .unwrap();
        artifact[12] = 0x86; // arch
        let (receipt, res) = admit_artifact(&artifact, &AdmissionPolicy::default(), 1, 0);
        assert_eq!(receipt.status, AdmissionStatus::MalformedContainer as u16);
        assert_eq!(res, Err(ArtifactError::UnsupportedArch));
    }

    #[test]
    fn negative_5_truncated_header() {
        let short = [0u8; 40];
        let (receipt, res) = admit_artifact(&short, &AdmissionPolicy::default(), 1, 0);
        assert_eq!(receipt.status, AdmissionStatus::MalformedContainer as u16);
        assert_eq!(res, Err(ArtifactError::BufferTooSmall));
    }

    #[test]
    fn negative_6_truncated_payload() {
        let anchors = TestOnlyTrustAnchors::default();
        let artifact = ArtifactBuilder::new("seed0b.test", &[0x42; 64])
            .build_and_sign(&anchors.authority_secret, &anchors.signer_id)
            .unwrap();
        let truncated = &artifact[..artifact.len() - 10];
        let (receipt, res) = admit_artifact(truncated, &AdmissionPolicy::default(), 1, 0);
        assert_eq!(receipt.status, AdmissionStatus::MalformedContainer as u16);
        assert_eq!(res, Err(ArtifactError::SectionOutOfBounds));
    }

    #[test]
    fn negative_7_payload_length_overflow() {
        let anchors = TestOnlyTrustAnchors::default();
        let mut artifact = ArtifactBuilder::new("seed0b.test", &[0x42; 64])
            .build_and_sign(&anchors.authority_secret, &anchors.signer_id)
            .unwrap();
        // Set payload_size to u32::MAX:
        artifact[60..64].copy_from_slice(&u32::MAX.to_le_bytes());
        let (receipt, res) = admit_artifact(&artifact, &AdmissionPolicy::default(), 1, 0);
        assert_eq!(receipt.status, AdmissionStatus::MalformedContainer as u16);
        assert_eq!(res, Err(ArtifactError::SectionOutOfBounds));
    }

    #[test]
    fn negative_8_offset_overflow() {
        let anchors = TestOnlyTrustAnchors::default();
        let mut artifact = ArtifactBuilder::new("seed0b.test", &[0x42; 64])
            .build_and_sign(&anchors.authority_secret, &anchors.signer_id)
            .unwrap();
        // Set manifest_offset to u32::MAX:
        artifact[48..52].copy_from_slice(&u32::MAX.to_le_bytes());
        let (receipt, res) = admit_artifact(&artifact, &AdmissionPolicy::default(), 1, 0);
        assert_eq!(receipt.status, AdmissionStatus::MalformedContainer as u16);
        assert_eq!(res, Err(ArtifactError::SectionOutOfBounds));
    }

    #[test]
    fn negative_9_overlapping_regions() {
        let anchors = TestOnlyTrustAnchors::default();
        let mut artifact = ArtifactBuilder::new("seed0b.test", &[0x42; 64])
            .build_and_sign(&anchors.authority_secret, &anchors.signer_id)
            .unwrap();
        // Set payload_offset inside manifest:
        artifact[56..60].copy_from_slice(&100u32.to_le_bytes());
        let (receipt, res) = admit_artifact(&artifact, &AdmissionPolicy::default(), 1, 0);
        assert_eq!(receipt.status, AdmissionStatus::MalformedContainer as u16);
        assert_eq!(res, Err(ArtifactError::SectionOverlap));
    }

    #[test]
    fn negative_10_entry_outside_executable_region() {
        let anchors = TestOnlyTrustAnchors::default();
        let artifact = ArtifactBuilder::new("seed0b.test", &[0x42; 64])
            .with_entry_offset(100) // payload is only 4 bytes!
            .build_and_sign(&anchors.authority_secret, &anchors.signer_id)
            .unwrap();
        let (receipt, res) = admit_artifact(&artifact, &AdmissionPolicy::default(), 1, 0);
        assert_eq!(receipt.status, AdmissionStatus::MalformedContainer as u16);
        assert_eq!(res, Err(ArtifactError::SectionOutOfBounds));
    }

    #[test]
    fn negative_11_single_byte_payload_mutation() {
        let anchors = TestOnlyTrustAnchors::default();
        let mut artifact = ArtifactBuilder::new("seed0b.test", &[0x42; 64])
            .build_and_sign(&anchors.authority_secret, &anchors.signer_id)
            .unwrap();
        let payload_start = 80 + 256;
        artifact[payload_start] ^= 0x01; // mutate payload byte
        let (receipt, res) = admit_artifact(&artifact, &AdmissionPolicy::default(), 1, 0);
        assert_eq!(receipt.status, AdmissionStatus::InvalidSignature as u16);
        assert_eq!(res, Err(ArtifactError::InvalidSignature));
    }

    #[test]
    fn negative_12_single_byte_manifest_mutation() {
        let anchors = TestOnlyTrustAnchors::default();
        let mut artifact = ArtifactBuilder::new("seed0b.test", &[0x42; 64])
            .build_and_sign(&anchors.authority_secret, &anchors.signer_id)
            .unwrap();
        let manifest_start = 80;
        artifact[manifest_start + 8] ^= 0x01; // mutate code_pages byte
        let (receipt, res) = admit_artifact(&artifact, &AdmissionPolicy::default(), 1, 0);
        assert_eq!(receipt.status, AdmissionStatus::InvalidSignature as u16);
        assert_eq!(res, Err(ArtifactError::InvalidSignature));
    }

    #[test]
    fn negative_13_forged_signature() {
        let anchors = TestOnlyTrustAnchors::default();
        let bad_secret = [0x13u8; 32];
        let artifact = ArtifactBuilder::new("seed0b.test", &[0x42; 64])
            .build_and_sign(&bad_secret, &anchors.signer_id)
            .unwrap();
        let (receipt, res) = admit_artifact(&artifact, &AdmissionPolicy::default(), 1, 0);
        assert_eq!(receipt.status, AdmissionStatus::InvalidSignature as u16);
        assert_eq!(res, Err(ArtifactError::InvalidSignature));
    }

    #[test]
    fn negative_14_untrusted_signer() {
        let anchors = TestOnlyTrustAnchors::default();
        let untrusted_pubkey = [0xeeu8; 32];
        let artifact = ArtifactBuilder::new("seed0b.test", &[0x42; 64])
            .build_and_sign(&anchors.authority_secret, &untrusted_pubkey)
            .unwrap();
        let policy = AdmissionPolicy {
            allowed_signer_id: Some(anchors.signer_id),
            ..Default::default()
        };
        let (receipt, res) = admit_artifact(&artifact, &policy, 1, 0);
        assert_eq!(receipt.status, AdmissionStatus::UntrustedSigner as u16);
        assert_eq!(res, Err(ArtifactError::UntrustedSigner));
    }

    #[test]
    fn negative_15_malformed_capability_request() {
        let anchors = TestOnlyTrustAnchors::default();
        let mut artifact = ArtifactBuilder::new("seed0b.test", &[0x42; 64])
            .build_and_sign(&anchors.authority_secret, &anchors.signer_id)
            .unwrap();
        // Set reserved field in manifest request 0:
        artifact[80 + 64 + 12] = 1;
        let (receipt, res) = admit_artifact(&artifact, &AdmissionPolicy::default(), 1, 0);
        assert_eq!(receipt.status, AdmissionStatus::MalformedContainer as u16);
        assert_eq!(res, Err(ArtifactError::ReservedFieldNonZero));
    }

    #[test]
    fn negative_16_rights_escalation() {
        let anchors = TestOnlyTrustAnchors::default();
        let req = CapabilityRequest {
            resource_kind: 1, // CONSOLE
            resource_id: 0,
            rights: (Rights::WRITE | Rights::REVOKE).bits() as u32, // Requests REVOKE which policy forbids
            reserved: 0,
            bounds: 4096,
        };
        let artifact = ArtifactBuilder::new("seed0b.escalate", &[1, 2, 3, 4])
            .with_request(req)
            .build_and_sign(&anchors.authority_secret, &anchors.signer_id)
            .unwrap();
        let (receipt, res) = admit_artifact(&artifact, &AdmissionPolicy::default(), 1, 0);
        assert_eq!(receipt.status, AdmissionStatus::RightsEscalation as u16);
        assert_eq!(res, Err(ArtifactError::RightsEscalation));
    }

    #[test]
    fn negative_17_outdated_generation() {
        let anchors = TestOnlyTrustAnchors::default();
        let artifact = ArtifactBuilder::new("seed0b.old", &[1, 2, 3, 4])
            .with_generation(1)
            .build_and_sign(&anchors.authority_secret, &anchors.signer_id)
            .unwrap();
        let policy = AdmissionPolicy {
            min_generation: 2,
            ..Default::default()
        };
        let (receipt, res) = admit_artifact(&artifact, &policy, 1, 0);
        assert_eq!(receipt.status, AdmissionStatus::GenerationOutdated as u16);
        assert_eq!(res, Err(ArtifactError::GenerationOutdated));
    }

    #[test]
    fn negative_18_memory_limit_exceeded() {
        let anchors = TestOnlyTrustAnchors::default();
        let artifact = ArtifactBuilder::new("seed0b.big", &[1, 2, 3, 4])
            .with_code_pages(16) // Policy max is 4
            .build_and_sign(&anchors.authority_secret, &anchors.signer_id)
            .unwrap();
        let (receipt, res) = admit_artifact(&artifact, &AdmissionPolicy::default(), 1, 0);
        assert_eq!(receipt.status, AdmissionStatus::MemoryLimitExceeded as u16);
        assert_eq!(res, Err(ArtifactError::MemoryLimitExceeded));
    }

    #[test]
    fn negative_19_receipt_tampering() {
        let anchors = TestOnlyTrustAnchors::default();
        let mut receipt = AdmissionReceiptV0 {
            magic: RECEIPT_MAGIC,
            receipt_version: RECEIPT_VERSION_0,
            status: AdmissionStatus::Admitted as u16,
            policy_version: 1,
            generation: 1,
            grant_count: 0,
            nonce: 42,
            timestamp_ticks: 100,
            artifact_id: [1; 32],
            signer_id: [2; 32],
            machine_id: [3; 32],
            verifier_id: [4; 32],
            code_pages: 1,
            data_pages: 0,
            stack_pages: 1,
            reserved_u16: 0,
            requests_digest: [0; 32],
            grants_digest: [0; 32],
            grants: [CapabilityGrant::default(); MAX_CAPABILITY_GRANTS],
            receipt_id: [0; 32],
            reserved: [0; 8],
            signature: [0; 64],
        };
        receipt.sign_receipt(&anchors.receipt_secret);
        assert!(receipt.verify_signature(&anchors.receipt_secret));

        // Tamper receipt body:
        receipt.generation = 999;
        assert!(!receipt.verify_receipt_id());
        assert!(!receipt.verify_signature(&anchors.receipt_secret));

        let bytes = receipt.to_bytes();
        assert_eq!(AdmissionReceiptV0::decode(&bytes), Err(ArtifactError::ReceiptTampered));
    }

    #[test]
    fn negative_20_generation_zero_handle_rejected() {
        use crate::abi::{AbiError, Handle};
        assert_eq!(Handle::new(1, 0), Err(AbiError::InvalidHandle));
    }
}
