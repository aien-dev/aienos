//! Admission Receipt v0 (ADR 0014 §7): a 512-byte canonical record of one
//! candidate's verification, admission and execution outcome.
//!
//! The in-memory [`Receipt`] is a view only; the contract is the byte layout
//! produced by [`encode`]. The kernel emits unsigned records (signature block
//! all zero); only host qualification tooling signs them (§7.3).

use aienos_crypto::sha256::{hash, Digest, Sha256};

use crate::error::ArtifactError;
use crate::format::SIGNATURE_ALGORITHM_ED25519;
use crate::signature::{ReceiptSigner, SignatureVerifier, PUBLIC_KEY_SIZE, SIGNATURE_SIZE};

pub const RECEIPT_MAGIC: &[u8; 8] = b"AIENRCP\0";
pub const RECEIPT_VERSION: u16 = 0;
pub const RECEIPT_HEADER_SIZE: usize = 96;
pub const RECEIPT_SIZE: usize = 512;
pub const RECEIPT_SIGNATURE_OFFSET: usize = 400;
pub const RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"AIENOS-ADMISSION-RECEIPT-SIGNATURE-V1\0";
pub const RECEIPT_DIGEST_DOMAIN: &[u8] = b"AIENOS-ADMISSION-RECEIPT-V1\0";
pub const RECEIPT_NONCE_DOMAIN: &[u8] = b"AIENOS-ADMISSION-RECEIPT-NONCE-V1\0";

/// Presence flags (offset 16).
pub const FLAG_MACHINE_ID: u32 = 1 << 0;
pub const FLAG_CONTEXT_ID: u32 = 1 << 1;
pub const FLAG_TIMESTAMP: u32 = 1 << 2;
pub const VALID_FLAGS: u32 = FLAG_MACHINE_ID | FLAG_CONTEXT_ID | FLAG_TIMESTAMP;

/// Result flags (offset 72).
pub const RESULT_READ_OK: u32 = 1 << 0;
pub const RESULT_WRITE_DENIED: u32 = 1 << 1;
pub const RESULT_RECLAIMED: u32 = 1 << 2;
pub const RESULT_CANARY_PASSED: u32 = 1 << 3;
pub const RESULT_FORGED_DENIED: u32 = 1 << 4;
pub const RESULT_MAPPED_BYTES_MATCH: u32 = 1 << 5;
pub const RESULT_EXECUTED_BYTES_MATCH: u32 = 1 << 6;
pub const RESULT_WX_SEALED: u32 = 1 << 7;
pub const VALID_RESULT_FLAGS: u32 = 0xff;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ReceiptDecision {
    Admitted = 1,
    Rejected = 2,
    CanaryFailed = 3,
    Destroyed = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum QualificationTier {
    Seed0bQemu = 1,
    Seed0bMachine1 = 2,
}

/// Offset 64; §7.3 mapping of the task runtime outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ExecutionStatusCode {
    NotRun = 0,
    Exited = 1,
    Timeout = 2,
    Fault = 3,
    BadSyscall = 4,
    ResourceOverrun = 5,
    CanaryFailed = 6,
}

/// In-memory view of one receipt. Encoding is explicit and field by field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Receipt {
    pub flags: u32,
    pub decision: ReceiptDecision,
    pub tier: QualificationTier,
    pub sequence: u64,
    pub nonce: [u8; 16],
    pub observed_time_ns: u64,
    pub execution_status: ExecutionStatusCode,
    pub exit_status: i32,
    pub result_flags: u32,
    pub rejection_stage: u16,
    pub rejection_reason: u16,
    pub syscalls: u32,
    pub object_reads_ok: u32,
    pub denials: u32,
    pub frames_reserved: u32,
    pub artifact_id: Digest,
    pub payload_digest: Digest,
    pub artifact_signer_fingerprint: Digest,
    pub policy_digest: Digest,
    pub requested_capability_digest: Digest,
    pub granted_capability_digest: Digest,
    pub resource_envelope_digest: Digest,
    pub verifier_identity: Digest,
    pub machine_id_digest: Digest,
    pub generation: u64,
    pub context_id: u64,
}

/// Canonical 512-byte record with an all-zero signature block.
pub fn encode(r: &Receipt) -> [u8; RECEIPT_SIZE] {
    let mut b = [0u8; RECEIPT_SIZE];
    b[0..8].copy_from_slice(RECEIPT_MAGIC);
    put16(&mut b, 8, RECEIPT_VERSION);
    put16(&mut b, 10, RECEIPT_HEADER_SIZE as u16);
    put32(&mut b, 12, RECEIPT_SIZE as u32);
    put32(&mut b, 16, r.flags);
    put16(&mut b, 20, r.decision as u16);
    put16(&mut b, 22, r.tier as u16);
    put64(&mut b, 24, r.sequence);
    b[32..48].copy_from_slice(&r.nonce);
    put64(&mut b, 48, r.observed_time_ns);
    put32(&mut b, 64, r.execution_status as u32);
    b[68..72].copy_from_slice(&r.exit_status.to_le_bytes());
    put32(&mut b, 72, r.result_flags);
    put16(&mut b, 76, r.rejection_stage);
    put16(&mut b, 78, r.rejection_reason);
    put32(&mut b, 80, r.syscalls);
    put32(&mut b, 84, r.object_reads_ok);
    put32(&mut b, 88, r.denials);
    put32(&mut b, 92, r.frames_reserved);
    for (offset, digest) in [
        (96, &r.artifact_id),
        (128, &r.payload_digest),
        (160, &r.artifact_signer_fingerprint),
        (192, &r.policy_digest),
        (224, &r.requested_capability_digest),
        (256, &r.granted_capability_digest),
        (288, &r.resource_envelope_digest),
        (320, &r.verifier_identity),
        (352, &r.machine_id_digest),
    ] {
        b[offset..offset + 32].copy_from_slice(digest);
    }
    put64(&mut b, 384, r.generation);
    put64(&mut b, 392, r.context_id);
    b
}

/// `SHA256("AIENOS-ADMISSION-RECEIPT-V1\0" || bytes[0..400])`.
pub fn receipt_digest(bytes: &[u8; RECEIPT_SIZE]) -> Digest {
    let mut h = Sha256::new();
    h.update(RECEIPT_DIGEST_DOMAIN);
    h.update(&bytes[..RECEIPT_SIGNATURE_OFFSET]);
    h.finalize()
}

/// Deterministic per-context nonce (§7.3).
pub fn receipt_nonce(verifier_identity: &Digest, sequence: u64) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(RECEIPT_NONCE_DOMAIN);
    h.update(verifier_identity);
    h.update(&sequence.to_le_bytes());
    let d = h.finalize();
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&d[..16]);
    nonce
}

/// Canonical verifier build identity bytes (§7.1): 40 lowercase hex commit
/// characters, target u16 LE, ABI u16 LE, qualification feature id.
/// Returns `None` unless `commit` is exactly 40 lowercase hex digits.
pub fn verifier_identity_bytes(
    commit: &[u8],
    target: u16,
    abi: u16,
    feature: u8,
) -> Option<[u8; 45]> {
    if commit.len() != 40
        || !commit
            .iter()
            .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let mut out = [0u8; 45];
    out[..40].copy_from_slice(commit);
    out[40..42].copy_from_slice(&target.to_le_bytes());
    out[42..44].copy_from_slice(&abi.to_le_bytes());
    out[44] = feature;
    Some(out)
}

/// Stage codes (§7.3).
pub const MAX_REJECTION_STAGE: u16 = 9;
/// Loader reason codes (§7.3), after the `ArtifactError` range 1..=19.
pub const LOADER_REASON_FIRST: u16 = 0x101;
pub const LOADER_REASON_LAST: u16 = 0x10a;

impl ReceiptDecision {
    pub const fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::Admitted),
            2 => Some(Self::Rejected),
            3 => Some(Self::CanaryFailed),
            4 => Some(Self::Destroyed),
            _ => None,
        }
    }
}

impl QualificationTier {
    pub const fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::Seed0bQemu),
            2 => Some(Self::Seed0bMachine1),
            _ => None,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Seed0bQemu => "SEED-0B-QEMU",
            Self::Seed0bMachine1 => "SEED-0B-MACHINE1",
        }
    }
}

impl ExecutionStatusCode {
    pub const fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::NotRun),
            1 => Some(Self::Exited),
            2 => Some(Self::Timeout),
            3 => Some(Self::Fault),
            4 => Some(Self::BadSyscall),
            5 => Some(Self::ResourceOverrun),
            6 => Some(Self::CanaryFailed),
            _ => None,
        }
    }
}

const fn valid_reason(code: u16) -> bool {
    matches!(code, 1..=19) || (code >= LOADER_REASON_FIRST && code <= LOADER_REASON_LAST)
}

/// Strictly decode one record (signed or unsigned). Error mapping:
/// short → `Truncated`, long → `WrongLength`, magic → `BadMagic`,
/// version/header/record size → `UnsupportedVersion`, unknown presence or
/// result bits → `UnsupportedFlags`, reserved bytes → `ReservedNonZero`,
/// signature algorithm → `BadSignatureFormat`, and every enum, code,
/// presence, consistency or nonce violation → `MalformedReceipt`.
pub fn decode(bytes: &[u8]) -> Result<Receipt, ArtifactError> {
    if bytes.len() < RECEIPT_SIZE {
        return Err(ArtifactError::Truncated);
    }
    if bytes.len() > RECEIPT_SIZE {
        return Err(ArtifactError::WrongLength);
    }
    if &bytes[0..8] != RECEIPT_MAGIC {
        return Err(ArtifactError::BadMagic);
    }
    if get16(bytes, 8) != RECEIPT_VERSION
        || usize::from(get16(bytes, 10)) != RECEIPT_HEADER_SIZE
        || get32(bytes, 12) as usize != RECEIPT_SIZE
    {
        return Err(ArtifactError::UnsupportedVersion);
    }
    let flags = get32(bytes, 16);
    let result_flags = get32(bytes, 72);
    if flags & !VALID_FLAGS != 0 || result_flags & !VALID_RESULT_FLAGS != 0 {
        return Err(ArtifactError::UnsupportedFlags);
    }
    if bytes[56..64].iter().any(|b| *b != 0) || bytes[500..512].iter().any(|b| *b != 0) {
        return Err(ArtifactError::ReservedNonZero);
    }
    if bytes[400..500].iter().any(|b| *b != 0) {
        if get16(bytes, 400) != SIGNATURE_ALGORITHM_ED25519 {
            return Err(ArtifactError::BadSignatureFormat);
        }
        if bytes[402..404].iter().any(|b| *b != 0) {
            return Err(ArtifactError::ReservedNonZero);
        }
    }
    let malformed = ArtifactError::MalformedReceipt;
    let decision = ReceiptDecision::from_u16(get16(bytes, 20)).ok_or(malformed)?;
    let tier = QualificationTier::from_u16(get16(bytes, 22)).ok_or(malformed)?;
    let execution_status = ExecutionStatusCode::from_u32(get32(bytes, 64)).ok_or(malformed)?;
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&bytes[32..48]);
    let digest_at = |at: usize| {
        let mut d = [0u8; 32];
        d.copy_from_slice(&bytes[at..at + 32]);
        d
    };
    let r = Receipt {
        flags,
        decision,
        tier,
        sequence: get64(bytes, 24),
        nonce,
        observed_time_ns: get64(bytes, 48),
        execution_status,
        exit_status: i32::from_le_bytes([bytes[68], bytes[69], bytes[70], bytes[71]]),
        result_flags,
        rejection_stage: get16(bytes, 76),
        rejection_reason: get16(bytes, 78),
        syscalls: get32(bytes, 80),
        object_reads_ok: get32(bytes, 84),
        denials: get32(bytes, 88),
        frames_reserved: get32(bytes, 92),
        artifact_id: digest_at(96),
        payload_digest: digest_at(128),
        artifact_signer_fingerprint: digest_at(160),
        policy_digest: digest_at(192),
        requested_capability_digest: digest_at(224),
        granted_capability_digest: digest_at(256),
        resource_envelope_digest: digest_at(288),
        verifier_identity: digest_at(320),
        machine_id_digest: digest_at(352),
        generation: get64(bytes, 384),
        context_id: get64(bytes, 392),
    };
    validate(&r)?;
    Ok(r)
}

/// §7.1/§7.3 semantic rules shared by `decode` and producers.
pub fn validate(r: &Receipt) -> Result<(), ArtifactError> {
    let bad = Err(ArtifactError::MalformedReceipt);
    if r.flags & FLAG_MACHINE_ID == 0 && r.machine_id_digest != [0; 32] {
        return bad;
    }
    if r.flags & FLAG_CONTEXT_ID == 0 && (r.generation != 0 || r.context_id != 0) {
        return bad;
    }
    if r.flags & FLAG_TIMESTAMP == 0 && r.observed_time_ns != 0 {
        return bad;
    }
    if r.rejection_stage > MAX_REJECTION_STAGE
        || (r.rejection_reason != 0 && !valid_reason(r.rejection_reason))
    {
        return bad;
    }
    match r.decision {
        ReceiptDecision::Rejected => {
            if r.rejection_stage == 0
                || r.rejection_reason == 0
                || r.execution_status != ExecutionStatusCode::NotRun
                || r.exit_status != 0
                || r.syscalls != 0
                || r.object_reads_ok != 0
                || r.denials != 0
                || r.result_flags & !RESULT_RECLAIMED != 0
            {
                return bad;
            }
        }
        _ => {
            if r.rejection_stage != 0 || r.rejection_reason != 0 {
                return bad;
            }
        }
    }
    if r.result_flags & RESULT_CANARY_PASSED != 0
        && (r.execution_status != ExecutionStatusCode::Exited || r.exit_status != 0)
    {
        return bad;
    }
    if r.nonce != receipt_nonce(&r.verifier_identity, r.sequence) {
        return bad;
    }
    Ok(())
}

/// True when bytes 400..512 are all zero (kernel-emitted record).
pub fn is_unsigned(bytes: &[u8; RECEIPT_SIZE]) -> bool {
    bytes[RECEIPT_SIGNATURE_OFFSET..].iter().all(|b| *b == 0)
}

/// `RECEIPT_SIGNATURE_DOMAIN || ReceiptDigest`.
pub fn signature_message(digest: &Digest) -> [u8; RECEIPT_SIGNATURE_DOMAIN.len() + 32] {
    let mut m = [0u8; RECEIPT_SIGNATURE_DOMAIN.len() + 32];
    m[..RECEIPT_SIGNATURE_DOMAIN.len()].copy_from_slice(RECEIPT_SIGNATURE_DOMAIN);
    m[RECEIPT_SIGNATURE_DOMAIN.len()..].copy_from_slice(digest);
    m
}

/// Sign a valid unsigned record in place.
pub fn sign(
    bytes: &mut [u8; RECEIPT_SIZE],
    signer: &impl ReceiptSigner,
) -> Result<(), ArtifactError> {
    if !is_unsigned(bytes) {
        return Err(ArtifactError::BadSignatureFormat);
    }
    decode(bytes)?;
    let digest = receipt_digest(bytes);
    let signature = signer.sign_receipt_digest(&digest)?;
    put16(bytes, 400, SIGNATURE_ALGORITHM_ED25519);
    bytes[404..436].copy_from_slice(&signer.signer_fingerprint());
    bytes[436..500].copy_from_slice(&signature);
    Ok(())
}

/// Receipt signing keys the verifier trusts. Distinct from artifact anchors.
pub trait ReceiptAnchorSet {
    fn find(&self, fingerprint: &Digest) -> Option<[u8; PUBLIC_KEY_SIZE]>;
}

/// Production receipt anchors are empty until M5 and fail closed.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmptyReceiptAnchorSet;

impl ReceiptAnchorSet for EmptyReceiptAnchorSet {
    fn find(&self, _fingerprint: &Digest) -> Option<[u8; PUBLIC_KEY_SIZE]> {
        None
    }
}

/// Decode and authenticate a signed record.
pub fn verify(
    bytes: &[u8],
    anchors: &impl ReceiptAnchorSet,
    signatures: &impl SignatureVerifier,
) -> Result<Receipt, ArtifactError> {
    let receipt = decode(bytes)?;
    let mut record = [0u8; RECEIPT_SIZE];
    record.copy_from_slice(bytes);
    if is_unsigned(&record) {
        return Err(ArtifactError::BadSignatureFormat);
    }
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&record[404..436]);
    let key = anchors
        .find(&fingerprint)
        .ok_or(ArtifactError::UntrustedSigner)?;
    if hash(&key) != fingerprint {
        return Err(ArtifactError::UntrustedSigner);
    }
    let mut signature = [0u8; SIGNATURE_SIZE];
    signature.copy_from_slice(&record[436..500]);
    let message = signature_message(&receipt_digest(&record));
    if !signatures.verify(&key, &message, &signature) {
        return Err(ArtifactError::BadSignature);
    }
    Ok(receipt)
}

/// TEST-ONLY SEED-0B receipt signing identity: RFC 8032 TEST 2 public key,
/// distinct from the artifact test key (TEST 1). Its seed exists only in
/// debug host qualification tooling and tests.
#[cfg(feature = "seed0b-test-anchor")]
pub mod seed0b_test_receipt_anchor {
    use super::ReceiptAnchorSet;
    use aienos_crypto::sha256::{hash, Digest};

    pub const LABEL: &str = "SEED-0B QUALIFICATION RECEIPT KEY — TEST ONLY";

    pub const PUBLIC_KEY: [u8; 32] = [
        0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e,
        0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4,
        0x66, 0x0c,
    ];

    #[derive(Clone, Copy, Debug, Default)]
    pub struct Seed0bTestReceiptAnchorSet;

    impl ReceiptAnchorSet for Seed0bTestReceiptAnchorSet {
        fn find(&self, fingerprint: &Digest) -> Option<[u8; 32]> {
            (*fingerprint == hash(&PUBLIC_KEY)).then_some(PUBLIC_KEY)
        }
    }
}

fn get16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn get32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn get64(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(v)
}

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
