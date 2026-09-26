//! M5 Key Hierarchy, Security Manifests, and Anti-Rollback (ADR 0017).
//!
//! Normative implementation of storage security roots:
//! - Subkey derivation via HKDF-SHA256 (K_cortex, K_agent, K_artifact, K_root_auth)
//! - KeySlotManifest (kind = 21, plaintext bootstrap object with up to 4 keyslots)
//! - SecurityManifest (kind = 22, 256-byte fixed root object authenticated under K_root_auth)
//! - MigrationManifest (kind = 23, identity-preserving migration authorization)
//! - AntiRollbackSource trait, RollbackAnchor, and epoch validation protocol.

extern crate alloc;

use alloc::vec::Vec;

use crate::crypto::hkdf::hkdf_expand;
use crate::crypto::hmac::{constant_time_eq, HmacSha256};
use crate::store::v1::ObjectId;
use aienos_crypto::aes_gcm_siv::{decrypt as raw_decrypt, encrypt as raw_encrypt, TAG_LEN};

pub const KIND_KEYSLOT_MANIFEST: u16 = 21;
pub const KIND_SECURITY_MANIFEST: u16 = 22;
pub const KIND_MIGRATION_MANIFEST: u16 = 23;

pub const KEYSLOT_MANIFEST_MAGIC: &[u8; 8] = b"AIENKSL1";
pub const SECURITY_MANIFEST_MAGIC: &[u8; 8] = b"AIENSEC1";
pub const MIGRATION_MANIFEST_MAGIC: &[u8; 8] = b"AIENMIG1";

pub const SECURITY_FORMAT_VERSION: u16 = 1;
pub const SECURITY_MANIFEST_SIZE: usize = 256;
pub const KEYSLOT_HEADER_SIZE: usize = 128;
pub const KEYSLOT_DESCRIPTOR_SIZE: usize = 128;
pub const KEYSLOT_MAX_SLOTS: usize = 4;
pub const KEYSLOT_MAX_ARENA_BYTES: usize = 32768; // 32 KiB
pub const ROOT_AUTH_DOMAIN_PREFIX: &[u8; 23] = b"AIENOS-M5-ROOT-AUTH-V1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityError {
    FormatError(&'static str),
    BufferTooShort,
    InvalidMagic,
    UnsupportedVersion,
    NonzeroReserved,
    AuthenticationFailed,
    KeySlotIndexOutOfRange,
    PayloadArenaOverflow,
}

// ---------------------------------------------------------------------------
// 1. Subkey Derivation from K_vol
// ---------------------------------------------------------------------------

/// Subkeys derived deterministically from K_vol via HKDF-SHA256 (ADR 0017 Section 2.2).
#[derive(Clone)]
pub struct DerivedSubkeys {
    pub k_cortex: [u8; 32],
    pub k_agent: [u8; 32],
    pub k_artifact: [u8; 32],
    pub k_root_auth: [u8; 32],
}

impl Drop for DerivedSubkeys {
    fn drop(&mut self) {
        for b in &mut self.k_cortex {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        for b in &mut self.k_agent {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        for b in &mut self.k_artifact {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        for b in &mut self.k_root_auth {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
    }
}

/// Derive operational subkeys from K_vol using HKDF-SHA256 domain-separated labels.
pub fn derive_subkeys(k_vol: &[u8; 32]) -> DerivedSubkeys {
    let mut k_cortex = [0u8; 32];
    let mut k_agent = [0u8; 32];
    let mut k_artifact = [0u8; 32];
    let mut k_root_auth = [0u8; 32];

    hkdf_expand(k_vol, b"AIENOS/M5/CORTEX-V1", &mut k_cortex)
        .expect("HKDF expand 32 bytes cannot fail");
    hkdf_expand(k_vol, b"AIENOS/M5/AGENT-STATE-V1", &mut k_agent)
        .expect("HKDF expand 32 bytes cannot fail");
    hkdf_expand(k_vol, b"AIENOS/M5/ARTIFACT-V1", &mut k_artifact)
        .expect("HKDF expand 32 bytes cannot fail");
    hkdf_expand(k_vol, b"AIENOS/M5/ROOT-AUTH-V1", &mut k_root_auth)
        .expect("HKDF expand 32 bytes cannot fail");

    DerivedSubkeys {
        k_cortex,
        k_agent,
        k_artifact,
        k_root_auth,
    }
}

// ---------------------------------------------------------------------------
// 2. KeySlotManifest (kind = 21)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum KeySlotType {
    Empty = 0,
    Tpm2PolicyAuthorize = 1,
    RecoveryArgon2id = 2,
    RecoveryRawSecret = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeySlotDescriptor {
    pub slot_type: KeySlotType,
    pub wrap_suite: u8,
    pub kdf_suite: u8,
    pub flags: u8,
    pub slot_id: u32,
    pub key_epoch: u64,
    pub salt: [u8; 16],
    pub argon_m_kib: u32,
    pub argon_t_cost: u32,
    pub argon_p_cost: u32,
    pub wrap_nonce: [u8; 12],
    pub wrapped_k_vol: [u8; 32],
    pub wrap_tag: [u8; 16],
    pub payload_offset: u32,
    pub payload_length: u32,
    pub reserved: [u8; 16],
}

impl KeySlotDescriptor {
    pub const EMPTY: Self = Self {
        slot_type: KeySlotType::Empty,
        wrap_suite: 0x01,
        kdf_suite: 0x00,
        flags: 0,
        slot_id: 0,
        key_epoch: 0,
        salt: [0; 16],
        argon_m_kib: 0,
        argon_t_cost: 0,
        argon_p_cost: 0,
        wrap_nonce: [0; 12],
        wrapped_k_vol: [0; 32],
        wrap_tag: [0; 16],
        payload_offset: 0,
        payload_length: 0,
        reserved: [0; 16],
    };

    pub fn encode(&self) -> [u8; KEYSLOT_DESCRIPTOR_SIZE] {
        let mut out = [0u8; KEYSLOT_DESCRIPTOR_SIZE];
        out[0] = self.slot_type as u8;
        out[1] = self.wrap_suite;
        out[2] = self.kdf_suite;
        out[3] = self.flags;
        out[4..8].copy_from_slice(&self.slot_id.to_le_bytes());
        out[8..16].copy_from_slice(&self.key_epoch.to_le_bytes());
        out[16..32].copy_from_slice(&self.salt);
        out[32..36].copy_from_slice(&self.argon_m_kib.to_le_bytes());
        out[36..40].copy_from_slice(&self.argon_t_cost.to_le_bytes());
        out[40..44].copy_from_slice(&self.argon_p_cost.to_le_bytes());
        out[44..56].copy_from_slice(&self.wrap_nonce);
        out[56..88].copy_from_slice(&self.wrapped_k_vol);
        out[88..104].copy_from_slice(&self.wrap_tag);
        out[104..108].copy_from_slice(&self.payload_offset.to_le_bytes());
        out[108..112].copy_from_slice(&self.payload_length.to_le_bytes());
        out[112..128].copy_from_slice(&self.reserved);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SecurityError> {
        if bytes.len() < KEYSLOT_DESCRIPTOR_SIZE {
            return Err(SecurityError::BufferTooShort);
        }
        let slot_type = match bytes[0] {
            0 => KeySlotType::Empty,
            1 => KeySlotType::Tpm2PolicyAuthorize,
            2 => KeySlotType::RecoveryArgon2id,
            3 => KeySlotType::RecoveryRawSecret,
            _ => return Err(SecurityError::FormatError("unknown slot type")),
        };
        let wrap_suite = bytes[1];
        let kdf_suite = bytes[2];
        let flags = bytes[3];
        let slot_id = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let key_epoch = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&bytes[16..32]);
        let argon_m_kib = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);
        let argon_t_cost = u32::from_le_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]);
        let argon_p_cost = u32::from_le_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]);

        if argon_m_kib > 131072 || argon_t_cost > 10 || argon_p_cost > 16 {
            return Err(SecurityError::FormatError(
                "argon2 parameters exceed bounds",
            ));
        }

        let mut wrap_nonce = [0u8; 12];
        wrap_nonce.copy_from_slice(&bytes[44..56]);
        let mut wrapped_k_vol = [0u8; 32];
        wrapped_k_vol.copy_from_slice(&bytes[56..88]);
        let mut wrap_tag = [0u8; 16];
        wrap_tag.copy_from_slice(&bytes[88..104]);

        let payload_offset = u32::from_le_bytes([bytes[104], bytes[105], bytes[106], bytes[107]]);
        let payload_length = u32::from_le_bytes([bytes[108], bytes[109], bytes[110], bytes[111]]);

        let mut reserved = [0u8; 16];
        reserved.copy_from_slice(&bytes[112..128]);
        if reserved.iter().any(|b| *b != 0) {
            return Err(SecurityError::NonzeroReserved);
        }

        Ok(Self {
            slot_type,
            wrap_suite,
            kdf_suite,
            flags,
            slot_id,
            key_epoch,
            salt,
            argon_m_kib,
            argon_t_cost,
            argon_p_cost,
            wrap_nonce,
            wrapped_k_vol,
            wrap_tag,
            payload_offset,
            payload_length,
            reserved,
        })
    }

    /// Unwrap K_vol given the corresponding 32-byte KEK.
    pub fn unwrap_k_vol(&self, kek: &[u8; 32]) -> Result<[u8; 32], SecurityError> {
        if self.slot_type == KeySlotType::Empty {
            return Err(SecurityError::FormatError("cannot unwrap empty keyslot"));
        }
        if self.wrap_suite != 0x01 {
            return Err(SecurityError::FormatError("unsupported wrap suite"));
        }

        let mut ciphertext_and_tag = [0u8; 32 + TAG_LEN];
        ciphertext_and_tag[0..32].copy_from_slice(&self.wrapped_k_vol);
        ciphertext_and_tag[32..48].copy_from_slice(&self.wrap_tag);

        let mut k_vol = [0u8; 32];
        let aad = self.slot_id.to_le_bytes();

        raw_decrypt(kek, &self.wrap_nonce, &aad, &ciphertext_and_tag, &mut k_vol)
            .map_err(|_| SecurityError::AuthenticationFailed)?;

        Ok(k_vol)
    }

    /// Wrap K_vol with the given 32-byte KEK and fresh 12-byte nonce.
    pub fn wrap_k_vol(&mut self, kek: &[u8; 32], k_vol: &[u8; 32], nonce: &[u8; 12]) {
        self.wrap_suite = 0x01;
        self.wrap_nonce = *nonce;
        let aad = self.slot_id.to_le_bytes();

        let mut out = [0u8; 32 + TAG_LEN];
        raw_encrypt(kek, nonce, &aad, k_vol, &mut out);

        self.wrapped_k_vol.copy_from_slice(&out[0..32]);
        self.wrap_tag.copy_from_slice(&out[32..48]);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySlotManifest {
    pub store_uuid: [u8; 16],
    pub manifest_sequence: u64,
    pub previous_keyslot_manifest_id: ObjectId,
    pub active_key_epoch: u64,
    pub slot_count: u32,
    pub slots: [KeySlotDescriptor; KEYSLOT_MAX_SLOTS],
    pub payload_arena: Vec<u8>,
}

impl KeySlotManifest {
    pub fn encode(&self) -> Result<Vec<u8>, SecurityError> {
        if self.payload_arena.len() > KEYSLOT_MAX_ARENA_BYTES {
            return Err(SecurityError::PayloadArenaOverflow);
        }
        let total_size = KEYSLOT_HEADER_SIZE
            + (KEYSLOT_MAX_SLOTS * KEYSLOT_DESCRIPTOR_SIZE)
            + self.payload_arena.len();
        let mut out = Vec::with_capacity(total_size);

        out.extend_from_slice(KEYSLOT_MANIFEST_MAGIC);
        out.extend_from_slice(&SECURITY_FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&self.store_uuid);
        out.extend_from_slice(&self.manifest_sequence.to_le_bytes());
        out.extend_from_slice(&self.previous_keyslot_manifest_id.0);
        out.extend_from_slice(&self.active_key_epoch.to_le_bytes());
        out.extend_from_slice(&self.slot_count.to_le_bytes());
        out.extend_from_slice(&[0u8; 48]); // reserved

        for slot in &self.slots {
            out.extend_from_slice(&slot.encode());
        }

        out.extend_from_slice(&self.payload_arena);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SecurityError> {
        let fixed_header_len = KEYSLOT_HEADER_SIZE + (KEYSLOT_MAX_SLOTS * KEYSLOT_DESCRIPTOR_SIZE);
        if bytes.len() < fixed_header_len {
            return Err(SecurityError::BufferTooShort);
        }

        if &bytes[0..8] != KEYSLOT_MANIFEST_MAGIC {
            return Err(SecurityError::InvalidMagic);
        }

        let format_version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if format_version != SECURITY_FORMAT_VERSION {
            return Err(SecurityError::UnsupportedVersion);
        }

        let flags = u16::from_le_bytes([bytes[10], bytes[11]]);
        if flags != 0 {
            return Err(SecurityError::FormatError("nonzero keyslot manifest flags"));
        }

        let mut store_uuid = [0u8; 16];
        store_uuid.copy_from_slice(&bytes[12..28]);

        let manifest_sequence = u64::from_le_bytes([
            bytes[28], bytes[29], bytes[30], bytes[31], bytes[32], bytes[33], bytes[34], bytes[35],
        ]);

        let mut prev_id = [0u8; 32];
        prev_id.copy_from_slice(&bytes[36..68]);
        let previous_keyslot_manifest_id = ObjectId(prev_id);

        let active_key_epoch = u64::from_le_bytes([
            bytes[68], bytes[69], bytes[70], bytes[71], bytes[72], bytes[73], bytes[74], bytes[75],
        ]);

        let slot_count = u32::from_le_bytes([bytes[76], bytes[77], bytes[78], bytes[79]]);
        if slot_count as usize > KEYSLOT_MAX_SLOTS {
            return Err(SecurityError::KeySlotIndexOutOfRange);
        }

        if bytes[80..128].iter().any(|b| *b != 0) {
            return Err(SecurityError::NonzeroReserved);
        }

        let mut slots = [KeySlotDescriptor::EMPTY; KEYSLOT_MAX_SLOTS];
        for (i, slot) in slots.iter_mut().enumerate() {
            let start = KEYSLOT_HEADER_SIZE + (i * KEYSLOT_DESCRIPTOR_SIZE);
            *slot = KeySlotDescriptor::decode(&bytes[start..start + KEYSLOT_DESCRIPTOR_SIZE])?;
        }

        let arena_bytes = &bytes[fixed_header_len..];
        if arena_bytes.len() > KEYSLOT_MAX_ARENA_BYTES {
            return Err(SecurityError::PayloadArenaOverflow);
        }

        Ok(Self {
            store_uuid,
            manifest_sequence,
            previous_keyslot_manifest_id,
            active_key_epoch,
            slot_count,
            slots,
            payload_arena: arena_bytes.to_vec(),
        })
    }
}

// ---------------------------------------------------------------------------
// 3. SecurityManifest (kind = 22)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecurityManifest {
    pub format_version: u16,
    pub flags: u16,
    pub reserved: u32,
    pub store_uuid: [u8; 16],
    pub generation: u64,
    pub security_sequence: u64,
    pub epoch: u64,
    pub key_epoch: u64,
    pub previous_security_manifest_id: ObjectId,
    pub keyslot_manifest_id: ObjectId,
    pub agent_root_id: ObjectId,
    pub continuity_manifest_id: ObjectId,
    pub migration_manifest_id: ObjectId,
    pub root_mac: [u8; 32],
}

impl SecurityManifest {
    /// Compute HMAC-SHA256 over header bytes [0..224] using K_root_auth.
    pub fn compute_mac(&self, k_root_auth: &[u8; 32]) -> [u8; 32] {
        let mut unsigned_bytes = [0u8; 224];
        unsigned_bytes[0..8].copy_from_slice(SECURITY_MANIFEST_MAGIC);
        unsigned_bytes[8..10].copy_from_slice(&self.format_version.to_le_bytes());
        unsigned_bytes[10..12].copy_from_slice(&self.flags.to_le_bytes());
        unsigned_bytes[12..16].copy_from_slice(&self.reserved.to_le_bytes());
        unsigned_bytes[16..32].copy_from_slice(&self.store_uuid);
        unsigned_bytes[32..40].copy_from_slice(&self.generation.to_le_bytes());
        unsigned_bytes[40..48].copy_from_slice(&self.security_sequence.to_le_bytes());
        unsigned_bytes[48..56].copy_from_slice(&self.epoch.to_le_bytes());
        unsigned_bytes[56..64].copy_from_slice(&self.key_epoch.to_le_bytes());
        unsigned_bytes[64..96].copy_from_slice(&self.previous_security_manifest_id.0);
        unsigned_bytes[96..128].copy_from_slice(&self.keyslot_manifest_id.0);
        unsigned_bytes[128..160].copy_from_slice(&self.agent_root_id.0);
        unsigned_bytes[160..192].copy_from_slice(&self.continuity_manifest_id.0);
        unsigned_bytes[192..224].copy_from_slice(&self.migration_manifest_id.0);

        let mut hmac = HmacSha256::new(k_root_auth);
        hmac.update(ROOT_AUTH_DOMAIN_PREFIX);
        hmac.update(&unsigned_bytes);
        hmac.finalize()
    }

    /// Sign this manifest in place under K_root_auth.
    pub fn sign(&mut self, k_root_auth: &[u8; 32]) {
        self.root_mac = self.compute_mac(k_root_auth);
    }

    /// Verify this manifest's root_mac in constant time.
    pub fn verify(&self, k_root_auth: &[u8; 32]) -> bool {
        let expected = self.compute_mac(k_root_auth);
        constant_time_eq(&self.root_mac, &expected)
    }

    /// Encode the 256-byte SecurityManifest.
    pub fn encode(&self) -> [u8; SECURITY_MANIFEST_SIZE] {
        let mut out = [0u8; SECURITY_MANIFEST_SIZE];
        out[0..8].copy_from_slice(SECURITY_MANIFEST_MAGIC);
        out[8..10].copy_from_slice(&self.format_version.to_le_bytes());
        out[10..12].copy_from_slice(&self.flags.to_le_bytes());
        out[12..16].copy_from_slice(&self.reserved.to_le_bytes());
        out[16..32].copy_from_slice(&self.store_uuid);
        out[32..40].copy_from_slice(&self.generation.to_le_bytes());
        out[40..48].copy_from_slice(&self.security_sequence.to_le_bytes());
        out[48..56].copy_from_slice(&self.epoch.to_le_bytes());
        out[56..64].copy_from_slice(&self.key_epoch.to_le_bytes());
        out[64..96].copy_from_slice(&self.previous_security_manifest_id.0);
        out[96..128].copy_from_slice(&self.keyslot_manifest_id.0);
        out[128..160].copy_from_slice(&self.agent_root_id.0);
        out[160..192].copy_from_slice(&self.continuity_manifest_id.0);
        out[192..224].copy_from_slice(&self.migration_manifest_id.0);
        out[224..256].copy_from_slice(&self.root_mac);
        out
    }

    /// Decode and structurally validate a 256-byte SecurityManifest.
    pub fn decode(bytes: &[u8]) -> Result<Self, SecurityError> {
        if bytes.len() != SECURITY_MANIFEST_SIZE {
            return Err(SecurityError::BufferTooShort);
        }

        if &bytes[0..8] != SECURITY_MANIFEST_MAGIC {
            return Err(SecurityError::InvalidMagic);
        }

        let format_version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if format_version != SECURITY_FORMAT_VERSION {
            return Err(SecurityError::UnsupportedVersion);
        }

        let flags = u16::from_le_bytes([bytes[10], bytes[11]]);
        if flags != 0 {
            return Err(SecurityError::FormatError(
                "nonzero security manifest flags",
            ));
        }

        let reserved = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        if reserved != 0 {
            return Err(SecurityError::NonzeroReserved);
        }

        let mut store_uuid = [0u8; 16];
        store_uuid.copy_from_slice(&bytes[16..32]);

        let generation = u64::from_le_bytes([
            bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37], bytes[38], bytes[39],
        ]);
        let security_sequence = u64::from_le_bytes([
            bytes[40], bytes[41], bytes[42], bytes[43], bytes[44], bytes[45], bytes[46], bytes[47],
        ]);
        let epoch = u64::from_le_bytes([
            bytes[48], bytes[49], bytes[50], bytes[51], bytes[52], bytes[53], bytes[54], bytes[55],
        ]);
        let key_epoch = u64::from_le_bytes([
            bytes[56], bytes[57], bytes[58], bytes[59], bytes[60], bytes[61], bytes[62], bytes[63],
        ]);

        let mut prev_id = [0u8; 32];
        prev_id.copy_from_slice(&bytes[64..96]);
        let previous_security_manifest_id = ObjectId(prev_id);

        let mut keyslot_id = [0u8; 32];
        keyslot_id.copy_from_slice(&bytes[96..128]);
        let keyslot_manifest_id = ObjectId(keyslot_id);

        let mut agent_id = [0u8; 32];
        agent_id.copy_from_slice(&bytes[128..160]);
        let agent_root_id = ObjectId(agent_id);

        let mut cont_id = [0u8; 32];
        cont_id.copy_from_slice(&bytes[160..192]);
        let continuity_manifest_id = ObjectId(cont_id);

        let mut mig_id = [0u8; 32];
        mig_id.copy_from_slice(&bytes[192..224]);
        let migration_manifest_id = ObjectId(mig_id);

        let mut root_mac = [0u8; 32];
        root_mac.copy_from_slice(&bytes[224..256]);

        Ok(Self {
            format_version,
            flags,
            reserved,
            store_uuid,
            generation,
            security_sequence,
            epoch,
            key_epoch,
            previous_security_manifest_id,
            keyslot_manifest_id,
            agent_root_id,
            continuity_manifest_id,
            migration_manifest_id,
            root_mac,
        })
    }
}

// ---------------------------------------------------------------------------
// 4. MigrationManifest (kind = 23)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MigrationManifest {
    pub format_version: u16,
    pub flags: u16,
    pub reserved: u32,
    pub agent_root_id: ObjectId,
    pub genesis_store_uuid: [u8; 16],
    pub origin_store_uuid: [u8; 16],
    pub target_store_uuid: [u8; 16],
    pub origin_security_manifest_id: ObjectId,
    pub origin_continuity_manifest_id: ObjectId,
    pub origin_sequence: u64,
    pub origin_incarnation: u64,
    pub origin_epoch: u64,
    pub origin_rollback_digest: [u8; 32],
    pub migration_sequence: u64,
    pub offline_signature: [u8; 64],
}

pub const MIGRATION_MANIFEST_SIZE: usize =
    8 + 2 + 2 + 4 + 32 + 16 + 16 + 16 + 32 + 32 + 8 + 8 + 8 + 32 + 8 + 64;

impl MigrationManifest {
    pub fn encode(&self) -> [u8; MIGRATION_MANIFEST_SIZE] {
        let mut out = [0u8; MIGRATION_MANIFEST_SIZE];
        out[0..8].copy_from_slice(MIGRATION_MANIFEST_MAGIC);
        out[8..10].copy_from_slice(&self.format_version.to_le_bytes());
        out[10..12].copy_from_slice(&self.flags.to_le_bytes());
        out[12..16].copy_from_slice(&self.reserved.to_le_bytes());
        out[16..48].copy_from_slice(&self.agent_root_id.0);
        out[48..64].copy_from_slice(&self.genesis_store_uuid);
        out[64..80].copy_from_slice(&self.origin_store_uuid);
        out[80..96].copy_from_slice(&self.target_store_uuid);
        out[96..128].copy_from_slice(&self.origin_security_manifest_id.0);
        out[128..160].copy_from_slice(&self.origin_continuity_manifest_id.0);
        out[160..168].copy_from_slice(&self.origin_sequence.to_le_bytes());
        out[168..176].copy_from_slice(&self.origin_incarnation.to_le_bytes());
        out[176..184].copy_from_slice(&self.origin_epoch.to_le_bytes());
        out[184..216].copy_from_slice(&self.origin_rollback_digest);
        out[216..224].copy_from_slice(&self.migration_sequence.to_le_bytes());
        out[224..288].copy_from_slice(&self.offline_signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SecurityError> {
        if bytes.len() != MIGRATION_MANIFEST_SIZE {
            return Err(SecurityError::BufferTooShort);
        }
        if &bytes[0..8] != MIGRATION_MANIFEST_MAGIC {
            return Err(SecurityError::InvalidMagic);
        }
        let format_version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if format_version != SECURITY_FORMAT_VERSION {
            return Err(SecurityError::UnsupportedVersion);
        }
        let flags = u16::from_le_bytes([bytes[10], bytes[11]]);
        if flags != 0 {
            return Err(SecurityError::FormatError("nonzero migration flags"));
        }
        let reserved = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        if reserved != 0 {
            return Err(SecurityError::NonzeroReserved);
        }

        let mut agent_root_id = [0u8; 32];
        agent_root_id.copy_from_slice(&bytes[16..48]);
        let mut genesis_store_uuid = [0u8; 16];
        genesis_store_uuid.copy_from_slice(&bytes[48..64]);
        let mut origin_store_uuid = [0u8; 16];
        origin_store_uuid.copy_from_slice(&bytes[64..80]);
        let mut target_store_uuid = [0u8; 16];
        target_store_uuid.copy_from_slice(&bytes[80..96]);

        let mut orig_sec = [0u8; 32];
        orig_sec.copy_from_slice(&bytes[96..128]);
        let mut orig_cont = [0u8; 32];
        orig_cont.copy_from_slice(&bytes[128..160]);

        let origin_sequence = u64::from_le_bytes([
            bytes[160], bytes[161], bytes[162], bytes[163], bytes[164], bytes[165], bytes[166],
            bytes[167],
        ]);
        let origin_incarnation = u64::from_le_bytes([
            bytes[168], bytes[169], bytes[170], bytes[171], bytes[172], bytes[173], bytes[174],
            bytes[175],
        ]);
        let origin_epoch = u64::from_le_bytes([
            bytes[176], bytes[177], bytes[178], bytes[179], bytes[180], bytes[181], bytes[182],
            bytes[183],
        ]);

        let mut origin_rollback_digest = [0u8; 32];
        origin_rollback_digest.copy_from_slice(&bytes[184..216]);

        let migration_sequence = u64::from_le_bytes([
            bytes[216], bytes[217], bytes[218], bytes[219], bytes[220], bytes[221], bytes[222],
            bytes[223],
        ]);

        let mut offline_signature = [0u8; 64];
        offline_signature.copy_from_slice(&bytes[224..288]);

        Ok(Self {
            format_version,
            flags,
            reserved,
            agent_root_id: ObjectId(agent_root_id),
            genesis_store_uuid,
            origin_store_uuid,
            target_store_uuid,
            origin_security_manifest_id: ObjectId(orig_sec),
            origin_continuity_manifest_id: ObjectId(orig_cont),
            origin_sequence,
            origin_incarnation,
            origin_epoch,
            origin_rollback_digest,
            migration_sequence,
            offline_signature,
        })
    }
}

// ---------------------------------------------------------------------------
// 5. AntiRollbackSource & Boot Protocol (ADR 0017 Section 2.6)
// ---------------------------------------------------------------------------

/// Off-disk hardware anti-rollback anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RollbackAnchor {
    pub store_uuid: [u8; 16],
    pub epoch: u64,
    pub commit_record_id: ObjectId,
    pub security_root_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AntiRollbackError {
    DeviceError,
    PermissionDenied,
}

/// Abstract hardware off-disk anti-rollback source (TPM NV index, RPMB, or secure flash).
pub trait AntiRollbackSource {
    fn read_anchor(
        &self,
        store_uuid: &[u8; 16],
    ) -> Result<Option<RollbackAnchor>, AntiRollbackError>;
    fn advance_anchor(&mut self, anchor: &RollbackAnchor) -> Result<(), AntiRollbackError>;
}

/// Evaluation decision produced by comparing disk security state against the hardware anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AntiRollbackDecision {
    /// Valid normal resume: disk matches the current anchored security epoch.
    ValidResume,
    /// Prepared unanchored epoch: disk committed epoch E+1, but anchor has not advanced yet.
    /// External effects remain frozen until the anchor advancement completes.
    PreparedEpochAdvance {
        disk_epoch: u64,
        disk_digest: [u8; 32],
    },
    /// Replay detected: halt into Recovery Core (RecoveryRequired::RollbackDetected).
    RollbackDetected(&'static str),
    /// Inconsistent epoch jump: halt into Recovery Core (RecoveryRequired::InconsistentEpoch).
    InconsistentEpoch(&'static str),
}

/// Validate disk security state against the hardware anti-rollback anchor per ADR 0017 Section 2.6.
pub fn evaluate_anti_rollback(
    disk_epoch: u64,
    disk_digest: &[u8; 32],
    anchor: Option<&RollbackAnchor>,
) -> AntiRollbackDecision {
    let Some(anchor) = anchor else {
        // First boot / genesis initialization
        return AntiRollbackDecision::PreparedEpochAdvance {
            disk_epoch,
            disk_digest: *disk_digest,
        };
    };

    if disk_epoch == anchor.epoch && constant_time_eq(disk_digest, &anchor.security_root_digest) {
        AntiRollbackDecision::ValidResume
    } else if disk_epoch == anchor.epoch + 1 {
        AntiRollbackDecision::PreparedEpochAdvance {
            disk_epoch,
            disk_digest: *disk_digest,
        }
    } else if disk_epoch < anchor.epoch {
        AntiRollbackDecision::RollbackDetected("disk epoch behind anchor (rollback detected)")
    } else if disk_epoch == anchor.epoch
        && !constant_time_eq(disk_digest, &anchor.security_root_digest)
    {
        AntiRollbackDecision::RollbackDetected(
            "digest mismatch at current epoch (rollback detected)",
        )
    } else {
        AntiRollbackDecision::InconsistentEpoch("disk epoch jumped ahead of anchor (> anchor + 1)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subkey_derivation_separation() {
        let k_vol = [0x5au8; 32];
        let subkeys = derive_subkeys(&k_vol);

        assert_ne!(subkeys.k_cortex, subkeys.k_agent);
        assert_ne!(subkeys.k_cortex, subkeys.k_artifact);
        assert_ne!(subkeys.k_cortex, subkeys.k_root_auth);
        assert_ne!(subkeys.k_agent, subkeys.k_root_auth);
        assert_ne!(subkeys.k_cortex, k_vol);
    }

    #[test]
    fn test_keyslot_manifest_roundtrip_and_unwrap() {
        let k_vol = [0x77u8; 32];
        let k_recovery_kek = [0x88u8; 32];
        let store_uuid = [0x11u8; 16];

        let mut slot0 = KeySlotDescriptor::EMPTY;
        slot0.slot_type = KeySlotType::RecoveryRawSecret;
        slot0.slot_id = 0;
        slot0.key_epoch = 1;
        slot0.wrap_k_vol(&k_recovery_kek, &k_vol, &[0x33u8; 12]);

        let manifest = KeySlotManifest {
            store_uuid,
            manifest_sequence: 1,
            previous_keyslot_manifest_id: ObjectId([0; 32]),
            active_key_epoch: 1,
            slot_count: 1,
            slots: [
                slot0,
                KeySlotDescriptor::EMPTY,
                KeySlotDescriptor::EMPTY,
                KeySlotDescriptor::EMPTY,
            ],
            payload_arena: alloc::vec![0xaa, 0xbb, 0xcc],
        };

        let encoded = manifest.encode().unwrap();
        let decoded = KeySlotManifest::decode(&encoded).unwrap();

        assert_eq!(decoded.store_uuid, store_uuid);
        assert_eq!(decoded.slot_count, 1);
        assert_eq!(decoded.payload_arena, alloc::vec![0xaa, 0xbb, 0xcc]);

        // Unwrapping with valid KEK succeeds and yields exact original K_vol
        let unwrapped = decoded.slots[0].unwrap_k_vol(&k_recovery_kek).unwrap();
        assert_eq!(unwrapped, k_vol);

        // Unwrapping with wrong KEK fails authentication
        let wrong_kek = [0x99u8; 32];
        assert_eq!(
            decoded.slots[0].unwrap_k_vol(&wrong_kek),
            Err(SecurityError::AuthenticationFailed)
        );
    }

    #[test]
    fn test_security_manifest_roundtrip_and_mac() {
        let k_root_auth = [0x44u8; 32];
        let store_uuid = [0x22u8; 16];

        let mut manifest = SecurityManifest {
            format_version: 1,
            flags: 0,
            reserved: 0,
            store_uuid,
            generation: 10,
            security_sequence: 1,
            epoch: 5,
            key_epoch: 1,
            previous_security_manifest_id: ObjectId([0; 32]),
            keyslot_manifest_id: ObjectId([1; 32]),
            agent_root_id: ObjectId([2; 32]),
            continuity_manifest_id: ObjectId([3; 32]),
            migration_manifest_id: ObjectId([0; 32]),
            root_mac: [0; 32],
        };

        manifest.sign(&k_root_auth);
        assert!(manifest.verify(&k_root_auth));

        let encoded = manifest.encode();
        assert_eq!(encoded.len(), SECURITY_MANIFEST_SIZE);

        let decoded = SecurityManifest::decode(&encoded).unwrap();
        assert!(decoded.verify(&k_root_auth));

        // Wrong key fails
        let wrong_key = [0x55u8; 32];
        assert!(!decoded.verify(&wrong_key));
    }

    #[test]
    fn test_anti_rollback_decision_matrix() {
        let store_uuid = [0x11u8; 16];
        let digest_1 = [0xaa; 32];
        let digest_2 = [0xbb; 32];

        let anchor = RollbackAnchor {
            store_uuid,
            epoch: 10,
            commit_record_id: ObjectId([1; 32]),
            security_root_digest: digest_1,
        };

        // 1. Same epoch, matching digest -> ValidResume
        assert_eq!(
            evaluate_anti_rollback(10, &digest_1, Some(&anchor)),
            AntiRollbackDecision::ValidResume
        );

        // 2. Next epoch (E + 1) -> PreparedEpochAdvance
        assert_eq!(
            evaluate_anti_rollback(11, &digest_2, Some(&anchor)),
            AntiRollbackDecision::PreparedEpochAdvance {
                disk_epoch: 11,
                disk_digest: digest_2
            }
        );

        // 3. Stale epoch (E - 1) -> RollbackDetected
        assert!(matches!(
            evaluate_anti_rollback(9, &digest_1, Some(&anchor)),
            AntiRollbackDecision::RollbackDetected(_)
        ));

        // 4. Same epoch, altered digest -> RollbackDetected
        assert!(matches!(
            evaluate_anti_rollback(10, &digest_2, Some(&anchor)),
            AntiRollbackDecision::RollbackDetected(_)
        ));

        // 5. Jumped epoch (E + 2) -> InconsistentEpoch
        assert!(matches!(
            evaluate_anti_rollback(12, &digest_2, Some(&anchor)),
            AntiRollbackDecision::InconsistentEpoch(_)
        ));
    }
}
