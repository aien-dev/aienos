//! Admission Receipt v0 constants. Canonical receipt encoding and signing are
//! implemented with the admission lifecycle and qualification receipt work.

pub const RECEIPT_MAGIC: &[u8; 8] = b"AIENRCP\0";
pub const RECEIPT_VERSION: u16 = 0;
pub const RECEIPT_HEADER_SIZE: usize = 96;
pub const RECEIPT_SIZE: usize = 512;
pub const RECEIPT_SIGNATURE_OFFSET: usize = 400;
pub const RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"AIENOS-ADMISSION-RECEIPT-SIGNATURE-V1\0";
pub const RECEIPT_DIGEST_DOMAIN: &[u8] = b"AIENOS-ADMISSION-RECEIPT-V1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ReceiptDecision {
    Admitted = 1,
    Rejected = 2,
    CanaryFailed = 3,
    Destroyed = 4,
}
