//! AIENOS Deterministic Recovery Core (ADR 0006).
//!
//! A non-model, deterministic subsystem for:
//! - Offline local operator credential authentication
//! - Transactional A/B boot slot rollback
//! - Deterministic WAL truncation upon corruption without AI dependencies

use crate::crypto::{constant_time_eq, sha256, HmacSha256};

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

/// Domain-separation prefix for the offline operator challenge-response MAC.
///
/// It is prepended to the challenge inside the HMAC input so a tag produced for this
/// credential check can never be confused with any other HMAC use of the same key. The
/// trailing NUL terminates the label; the challenge that follows is always 32 bytes.
pub const OPERATOR_AUTH_DOMAIN: &[u8] = b"AIENOS-RECOVERY-OPERATOR-AUTH-v1\0";

impl OperatorAuth {
    /// Verify an operator's response to an offline challenge.
    ///
    /// Computes exactly:
    ///
    /// ```text
    /// expected = HMAC-SHA256(key     = derived_key,
    ///                        message = OPERATOR_AUTH_DOMAIN || challenge)
    /// ```
    ///
    /// where `OPERATOR_AUTH_DOMAIN` is `b"AIENOS-RECOVERY-OPERATOR-AUTH-v1\0"` (33 bytes),
    /// and accepts only if `expected` equals `response`, compared with
    /// [`constant_time_eq`] so the check does not exit early on the first differing byte.
    ///
    /// `derived_key` is treated as an opaque 32-byte high-entropy secret. Where it comes
    /// from (Argon2id over a human passphrase, a FIDO/hardware-sealed key, or something
    /// else) is out of scope for this function and not yet decided; ADR 0006 only forbids
    /// deriving it with a fast hash of a human password. Challenge freshness (nonce
    /// generation, single use, replay protection) is the caller's responsibility.
    pub fn verify_offline_credentials(
        derived_key: &[u8; 32],
        challenge: &[u8; 32],
        response: &[u8; 32],
    ) -> bool {
        let expected = Self::expected_response(derived_key, challenge);
        constant_time_eq(&expected, response)
    }

    /// The response a holder of `derived_key` must present for `challenge`
    /// (used by operator-side tooling to answer a challenge).
    pub fn expected_response(derived_key: &[u8; 32], challenge: &[u8; 32]) -> [u8; 32] {
        let mut mac = HmacSha256::new(derived_key);
        mac.update(OPERATOR_AUTH_DOMAIN);
        mac.update(challenge);
        mac.finalize()
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
    use crate::crypto::hmac_sha256;

    const KEY: [u8; 32] = {
        let mut k = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            k[i] = i as u8; // 00..1f
            i += 1;
        }
        k
    };
    const CHALLENGE: [u8; 32] = {
        let mut c = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            c[i] = 0xa0 + i as u8; // a0..bf
            i += 1;
        }
        c
    };
    /// HMAC-SHA256(key = 00..1f, "AIENOS-RECOVERY-OPERATOR-AUTH-v1\0" || a0..bf), computed
    /// independently with `openssl dgst -sha256 -mac HMAC -macopt hexkey:<KEY>`.
    const KAT_RESPONSE: [u8; 32] = [
        0xf6, 0x16, 0x2d, 0xa5, 0xf8, 0x79, 0xe9, 0xbd, 0x4d, 0xef, 0xc7, 0x10, 0x8c, 0x46, 0x3b,
        0x5d, 0x16, 0x4f, 0x4d, 0xb6, 0x8a, 0xe9, 0x91, 0x78, 0x1b, 0xf7, 0x98, 0xfc, 0x14, 0x90,
        0x7a, 0xaa,
    ];

    #[test]
    fn hmac_primitive_rfc4231_case_2() {
        let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            tag,
            [
                0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
                0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
                0x64, 0xec, 0x38, 0x43,
            ]
        );
    }

    #[test]
    fn operator_auth_known_answer_accepted() {
        assert_eq!(OPERATOR_AUTH_DOMAIN.len(), 33);
        assert_eq!(
            OperatorAuth::expected_response(&KEY, &CHALLENGE),
            KAT_RESPONSE
        );
        let mut msg = [0u8; 65];
        msg[..33].copy_from_slice(OPERATOR_AUTH_DOMAIN);
        msg[33..].copy_from_slice(&CHALLENGE);
        assert_eq!(hmac_sha256(&KEY, &msg), KAT_RESPONSE);
        assert!(OperatorAuth::verify_offline_credentials(
            &KEY,
            &CHALLENGE,
            &KAT_RESPONSE
        ));
    }

    #[test]
    fn operator_auth_rejects_any_single_bit_flip() {
        for byte in 0..32 {
            for bit in 0..8 {
                let mask = 1u8 << bit;

                let mut response = KAT_RESPONSE;
                response[byte] ^= mask;
                assert!(
                    !OperatorAuth::verify_offline_credentials(&KEY, &CHALLENGE, &response),
                    "response flip byte {byte} bit {bit} accepted"
                );

                let mut challenge = CHALLENGE;
                challenge[byte] ^= mask;
                assert!(
                    !OperatorAuth::verify_offline_credentials(&KEY, &challenge, &KAT_RESPONSE),
                    "challenge flip byte {byte} bit {bit} accepted"
                );

                let mut key = KEY;
                key[byte] ^= mask;
                assert!(
                    !OperatorAuth::verify_offline_credentials(&key, &CHALLENGE, &KAT_RESPONSE),
                    "key flip byte {byte} bit {bit} accepted"
                );
            }
        }
    }

    #[test]
    fn operator_auth_rejects_legacy_bare_sha256_response() {
        let mut hasher = sha256::Sha256::new();
        hasher.update(&KEY);
        hasher.update(&CHALLENGE);
        let legacy = hasher.finalize();
        assert_ne!(legacy, KAT_RESPONSE);
        assert!(!OperatorAuth::verify_offline_credentials(
            &KEY, &CHALLENGE, &legacy
        ));
    }

    #[test]
    fn operator_auth_rejects_undomained_hmac_and_zero_response() {
        // Plain HMAC over the challenge without the domain prefix must not verify.
        let undomained = hmac_sha256(&KEY, &CHALLENGE);
        assert!(!OperatorAuth::verify_offline_credentials(
            &KEY,
            &CHALLENGE,
            &undomained
        ));
        assert!(!OperatorAuth::verify_offline_credentials(
            &KEY, &CHALLENGE, &[0u8; 32]
        ));
        // All-zero key and challenge still require the real MAC, not zeros.
        assert!(!OperatorAuth::verify_offline_credentials(
            &[0u8; 32], &[0u8; 32], &[0u8; 32]
        ));
    }

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
