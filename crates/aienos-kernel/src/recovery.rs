//! AIENOS Deterministic Recovery Core (ADR 0006).
//!
//! A non-model, deterministic subsystem for:
//! - Offline local operator credential authentication
//! - Transactional A/B boot slot rollback
//! - Deterministic WAL truncation upon corruption without AI dependencies

use crate::crypto::sha256;

/// Boot slot identifier for transactional updates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootSlot {
    SlotA,
    SlotB,
}

impl BootSlot {
    /// Return the alternate slot.
    pub fn alternate(self) -> Self {
        match self {
            Self::SlotA => Self::SlotB,
            Self::SlotB => Self::SlotA,
        }
    }
}

/// Operational state of a boot slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotHealth {
    Unverified,
    ConfirmedGood,
    FailedRollback,
}

/// Transactional A/B slot manager for deterministic kernel rollback.
#[derive(Clone, Debug)]
pub struct SlotManager {
    pub active_slot: BootSlot,
    pub slot_a_health: SlotHealth,
    pub slot_b_health: SlotHealth,
    pub boot_attempts: u32,
    pub max_boot_attempts: u32,
}

impl SlotManager {
    /// Initialize with SlotA as primary confirmed good.
    pub fn new() -> Self {
        Self {
            active_slot: BootSlot::SlotA,
            slot_a_health: SlotHealth::ConfirmedGood,
            slot_b_health: SlotHealth::Unverified,
            boot_attempts: 0,
            max_boot_attempts: 3,
        }
    }

    /// Mark active slot as confirmed good after reaching health milestone.
    pub fn mark_milestone_healthy(&mut self) {
        self.boot_attempts = 0;
        match self.active_slot {
            BootSlot::SlotA => self.slot_a_health = SlotHealth::ConfirmedGood,
            BootSlot::SlotB => self.slot_b_health = SlotHealth::ConfirmedGood,
        }
    }

    /// Record a failed boot attempt; triggers deterministic rollback if threshold exceeded.
    pub fn record_boot_attempt(&mut self) -> bool {
        self.boot_attempts += 1;
        if self.boot_attempts >= self.max_boot_attempts {
            // Trigger automatic rollback to alternate slot
            match self.active_slot {
                BootSlot::SlotA => self.slot_a_health = SlotHealth::FailedRollback,
                BootSlot::SlotB => self.slot_b_health = SlotHealth::FailedRollback,
            }
            self.active_slot = self.active_slot.alternate();
            self.boot_attempts = 0;
            true // Rolled back
        } else {
            false
        }
    }
}

impl Default for SlotManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Offline local operator credential verifier without network or model dependencies.
///
/// Invariant (ADR 0006): Offline authentication must use Argon2id key derivation for human
/// passphrases before challenge-response (or hardware/FIDO keys); do not use bare SHA-256
/// for password verification. Fast hashing over human passwords is strictly prohibited to
/// resist offline brute-force and dictionary attacks.
pub struct OperatorAuth;

impl OperatorAuth {
    /// Verify an operator authorization token against a high-entropy root key / derived credential.
    ///
    /// The `derived_key_hash` must represent either a hardware-sealed key (e.g. FIDO/YubiKey)
    /// or a high-entropy root key derived from a human passphrase via Argon2id.
    /// Bare SHA-256 password verification is strictly prohibited.
    pub fn verify_offline_credentials(
        derived_key_hash: &[u8; 32],
        challenge: &[u8; 32],
        signature: &[u8; 32],
    ) -> bool {
        let mut hasher = sha256::Sha256::new();
        hasher.update(derived_key_hash);
        hasher.update(challenge);
        let expected = hasher.finalize();
        &expected == signature
    }
}

/// Deterministic Write-Ahead Log frame recovery with truncation on corruption.
pub struct WalRecovery;

impl WalRecovery {
    /// Scan a serialized binary WAL log, validating per-record checksums.
    ///
    /// If corruption is encountered, deterministically truncates the log
    /// at the last valid record boundary, preserving all uncorrupted history.
    pub fn recover_and_truncate(raw_wal: &[u8]) -> (usize, usize) {
        let mut offset = 0;
        let mut valid_records = 0;

        while offset + 36 <= raw_wal.len() {
            let record_len = u32::from_be_bytes([
                raw_wal[offset],
                raw_wal[offset + 1],
                raw_wal[offset + 2],
                raw_wal[offset + 3],
            ]) as usize;

            let expected_checksum = &raw_wal[offset + 4..offset + 36];
            let payload_start = offset + 36;
            let payload_end = match payload_start.checked_add(record_len) {
                Some(end) => end,
                None => break, // Overflow in record length header: stop at valid boundary
            };

            if payload_end > raw_wal.len() {
                // Incomplete or truncated record: stop at last valid boundary
                break;
            }

            let actual_checksum = sha256::hash(&raw_wal[payload_start..payload_end]);
            if actual_checksum != expected_checksum {
                // Corrupted record detected: halt and truncate log here
                break;
            }

            valid_records += 1;
            offset = payload_end;
        }

        let truncated_valid_bytes = offset;
        (valid_records, truncated_valid_bytes)
    }

    /// Helper to format a single WAL entry with 4-byte length and 32-byte SHA-256 checksum.
    pub fn encode_entry(payload: &[u8], buf: &mut [u8]) -> usize {
        let len = payload.len() as u32;
        let checksum = sha256::hash(payload);

        let total_len = 36 + payload.len();
        if buf.len() < total_len {
            return 0;
        }

        buf[0..4].copy_from_slice(&len.to_be_bytes());
        buf[4..36].copy_from_slice(&checksum);
        buf[36..total_len].copy_from_slice(payload);
        total_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_rollback_on_failure() {
        let mut mgr = SlotManager::new();
        assert_eq!(mgr.active_slot, BootSlot::SlotA);

        assert!(!mgr.record_boot_attempt());
        assert!(!mgr.record_boot_attempt());
        // 3rd attempt triggers rollback
        assert!(mgr.record_boot_attempt());
        assert_eq!(mgr.active_slot, BootSlot::SlotB);
        assert_eq!(mgr.slot_a_health, SlotHealth::FailedRollback);

        // SlotB reaches health milestone
        mgr.mark_milestone_healthy();
        assert_eq!(mgr.slot_b_health, SlotHealth::ConfirmedGood);
    }

    #[test]
    fn test_wal_truncation_on_corruption() {
        let mut buffer = [0u8; 512];
        let mut offset = 0;

        // Entry 1: 10 bytes
        let e1 = b"boot_start";
        let n1 = WalRecovery::encode_entry(e1, &mut buffer[offset..]);
        offset += n1;

        // Entry 2: 12 bytes
        let e2 = b"cortex_mount";
        let n2 = WalRecovery::encode_entry(e2, &mut buffer[offset..]);
        offset += n2;

        // Verify clean log
        let (valid_count, valid_bytes) = WalRecovery::recover_and_truncate(&buffer[..offset]);
        assert_eq!(valid_count, 2);
        assert_eq!(valid_bytes, offset);

        // Entry 3: Corrupt byte in payload
        let e3 = b"corrupted_entry_here";
        let n3 = WalRecovery::encode_entry(e3, &mut buffer[offset..]);
        // Corrupt one byte of e3's payload
        buffer[offset + 40] ^= 0xFF;
        let total_with_corrupt = offset + n3;

        // Recovery should reject entry 3 and truncate cleanly back to 2 valid entries!
        let (recovered_count, recovered_bytes) =
            WalRecovery::recover_and_truncate(&buffer[..total_with_corrupt]);
        assert_eq!(recovered_count, 2);
        assert_eq!(recovered_bytes, offset);
    }

    #[test]
    fn test_wal_zero_length_entry_and_overflow_protection() {
        let mut buffer = [0u8; 256];
        let mut offset = 0;

        // 1. Encode valid zero-length entry
        let n0 = WalRecovery::encode_entry(b"", &mut buffer[offset..]);
        assert_eq!(n0, 36);
        offset += n0;

        // 2. Encode normal entry
        let n1 = WalRecovery::encode_entry(b"checkpoint", &mut buffer[offset..]);
        offset += n1;

        let (valid_count, valid_bytes) = WalRecovery::recover_and_truncate(&buffer[..offset]);
        assert_eq!(valid_count, 2);
        assert_eq!(valid_bytes, offset);

        // 3. Craft malicious length header (u32::MAX) that could cause integer overflow
        let mut malicious_buf = [0u8; 100];
        malicious_buf[0..4].copy_from_slice(&u32::MAX.to_be_bytes());
        malicious_buf[4..36].copy_from_slice(&[0xAAu8; 32]);
        let (mal_count, mal_bytes) = WalRecovery::recover_and_truncate(&malicious_buf);
        assert_eq!(mal_count, 0);
        assert_eq!(mal_bytes, 0);

        // 4. Incomplete header (< 36 bytes)
        let (inc_count, inc_bytes) = WalRecovery::recover_and_truncate(&[1, 2, 3, 4, 5]);
        assert_eq!(inc_count, 0);
        assert_eq!(inc_bytes, 0);

        // 5. Empty slice
        let (empty_count, empty_bytes) = WalRecovery::recover_and_truncate(&[]);
        assert_eq!(empty_count, 0);
        assert_eq!(empty_bytes, 0);
    }
}
