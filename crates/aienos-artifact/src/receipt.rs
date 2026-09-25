//! Admission Receipt v0 (ADR 0014 §7): a 512-byte canonical record of one
//! candidate's verification, admission and execution outcome.
//!
//! The in-memory [`Receipt`] is a view only; the contract is the byte layout
//! produced by [`encode`]. The kernel emits unsigned records (signature block
//! all zero); only host qualification tooling signs them (§7.3).

use aienos_crypto::sha256::{Digest, Sha256};

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

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
