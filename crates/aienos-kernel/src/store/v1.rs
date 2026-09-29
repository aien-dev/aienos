//! System Store v1 wire format and host-testable transactional store.
//!
//! Every persistent integer is encoded explicitly. No Rust struct layout is
//! read from or written to media.

use crate::block::{BlockError, BlockDevice};
use crate::crypto::sha256::{Sha256, Digest};
use alloc::vec;
use alloc::vec::Vec;

pub const STORE_UNIT_BYTES: usize = 4096;
pub const MAX_CATALOG_ENTRIES: usize = 4096;
pub const CATALOG_ENTRY_BYTES: usize = 64;
pub const CATALOG_HEADER_BYTES: usize = 16;
pub const MAX_OBJECT_BYTES: usize = 67_108_864;
pub const MAX_OBJECT_UNITS: u32 = 16_384;
pub const MAX_TRANSACTION_OBJECTS: usize = 256;
pub const MAX_TRANSACTION_UNITS: u64 = 32_768;
pub const MAX_REGION_UNITS: u64 = 4_294_967_296;

const SUPERBLOCK_MAGIC: &[u8; 8] = b"AIENSTR1";
const CATALOG_MAGIC: &[u8; 8] = b"AIENCAT1";
const COMMIT_MAGIC: &[u8; 8] = b"AIENCMT1";
const OBJECT_DOMAIN: &[u8] = b"AIENOS-STORE-OBJECT-V1\0";
const SUPERBLOCK_CRC_OFFSET: usize = 168;
const SUPERBLOCK_USED_BYTES: usize = 172;
const COMMIT_BYTES: usize = 232;
const KIND_CATALOG: u16 = 1;
const KIND_COMMIT: u16 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ObjectId(pub [u8; 32]);

impl ObjectId {
    pub const ZERO: Self = Self([0; 32]);

    pub fn calculate(kind: u16, version: u16, semantic: &[u8]) -> Result<Self, StoreError> {
        if kind == 0 || version == 0 || semantic.is_empty() {
            return Err(StoreError::InvalidObject);
        }
        let byte_length = u64::try_from(semantic.len()).map_err(|_| StoreError::ObjectTooLarge)?;
        if byte_length > MAX_OBJECT_BYTES as u64 {
            return Err(StoreError::ObjectTooLarge);
        }
        let mut hash = Sha256::new();
        hash.update(OBJECT_DOMAIN);
        hash.update(&kind.to_le_bytes());
        hash.update(&version.to_le_bytes());
        hash.update(&byte_length.to_le_bytes());
        hash.update(semantic);
        Ok(Self(hash.finalize()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectDescriptor {
    pub id: ObjectId,
    pub kind: u16,
    pub version: u16,
    pub first_unit: u64,
    pub byte_length: u64,
    pub unit_count: u32,
    pub flags: u16,
}

impl ObjectDescriptor {
    pub fn validate(&self, high_water: u64) -> Result<(), StoreError> {
        if self.kind == 0 || self.version == 0 || self.flags != 0 || self.byte_length == 0 {
            return Err(StoreError::MalformedDescriptor);
        }
        if self.byte_length > MAX_OBJECT_BYTES as u64 {
            return Err(StoreError::ObjectTooLarge);
        }
        let expected = self
            .byte_length
            .checked_add(STORE_UNIT_BYTES as u64 - 1)
            .ok_or(StoreError::LengthOverflow)?
            / STORE_UNIT_BYTES as u64;
        if expected != u64::from(self.unit_count) || self.unit_count > MAX_OBJECT_UNITS {
            return Err(StoreError::MalformedDescriptor);
        }
        let end = self
            .first_unit
            .checked_add(u64::from(self.unit_count))
            .ok_or(StoreError::LengthOverflow)?;
        if self.first_unit < 2 || end > high_water {
            return Err(StoreError::OutOfBounds);
        }
        Ok(())
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<(), StoreError> {
        if out.len() != CATALOG_ENTRY_BYTES {
            return Err(StoreError::InvalidLength);
        }
        self.validate(u64::MAX)?;
        out.fill(0);
        out[0..32].copy_from_slice(&self.id.0);
        put_u16(out, 32, self.kind);
        put_u16(out, 34, self.version);
        put_u64(out, 36, self.first_unit);
        put_u64(out, 44, self.byte_length);
        put_u32(out, 52, self.unit_count);
        put_u16(out, 56, self.flags);
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() != CATALOG_ENTRY_BYTES || bytes[58..64].iter().any(|b| *b != 0) {
            return Err(StoreError::MalformedDescriptor);
        }
        let mut id = [0; 32];
        id.copy_from_slice(&bytes[..32]);
        let value = Self {
            id: ObjectId(id),
            kind: get_u16(bytes, 32)?,
            version: get_u16(bytes, 34)?,
            first_unit: get_u64(bytes, 36)?,
            byte_length: get_u64(bytes, 44)?,
            unit_count: get_u32(bytes, 52)?,
            flags: get_u16(bytes, 56)?,
        };
        value.validate(u64::MAX)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Catalog {
    pub entries: Vec<ObjectDescriptor>,
}

impl Catalog {
    pub fn new(mut entries: Vec<ObjectDescriptor>) -> Result<Self, StoreError> {
        if entries.len() > MAX_CATALOG_ENTRIES {
            return Err(StoreError::CatalogFull);
        }
        entries.sort_by_key(|entry| entry.id);
        for pair in entries.windows(2) {
            if pair[0].id == pair[1].id {
                return Err(StoreError::DuplicateObjectConflict);
            }
        }
        Ok(Self { entries })
    }

    pub fn encode(&self) -> Result<Vec<u8>, StoreError> {
        if self.entries.len() > MAX_CATALOG_ENTRIES {
            return Err(StoreError::CatalogFull);
        }
        let size = CATALOG_HEADER_BYTES
            .checked_add(self.entries.len().checked_mul(CATALOG_ENTRY_BYTES).ok_or(StoreError::LengthOverflow)?)
            .ok_or(StoreError::LengthOverflow)?;
        if size > MAX_OBJECT_BYTES {
            return Err(StoreError::ObjectTooLarge);
        }
        let mut out = vec![0; size];
        out[..8].copy_from_slice(CATALOG_MAGIC);
        put_u16(&mut out, 8, 1);
        put_u16(&mut out, 10, CATALOG_ENTRY_BYTES as u16);
        put_u32(&mut out, 12, self.entries.len() as u32);
        let mut last: Option<ObjectId> = None;
        for (index, entry) in self.entries.iter().enumerate() {
            if last.is_some_and(|id| id >= entry.id) {
                return Err(StoreError::CatalogOrder);
            }
            if entry.kind == KIND_CATALOG || entry.kind == KIND_COMMIT {
                return Err(StoreError::InvalidObjectKind);
            }
            let start = CATALOG_HEADER_BYTES + index * CATALOG_ENTRY_BYTES;
            entry.encode(&mut out[start..start + CATALOG_ENTRY_BYTES])?;
            last = Some(entry.id);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() < CATALOG_HEADER_BYTES || &bytes[..8] != CATALOG_MAGIC {
            return Err(StoreError::BadCatalogMagic);
        }
        if get_u16(bytes, 8)? != 1 || get_u16(bytes, 10)? as usize != CATALOG_ENTRY_BYTES {
            return Err(StoreError::UnsupportedVersion);
        }
        let count = get_u32(bytes, 12)? as usize;
        if count > MAX_CATALOG_ENTRIES {
            return Err(StoreError::CatalogFull);
        }
        let expected = CATALOG_HEADER_BYTES
            .checked_add(count.checked_mul(CATALOG_ENTRY_BYTES).ok_or(StoreError::LengthOverflow)?)
            .ok_or(StoreError::LengthOverflow)?;
        if bytes.len() != expected {
            return Err(StoreError::InvalidLength);
        }
        let mut entries = Vec::with_capacity(count);
        let mut last: Option<ObjectId> = None;
        for index in 0..count {
            let start = CATALOG_HEADER_BYTES + index * CATALOG_ENTRY_BYTES;
            let entry = ObjectDescriptor::decode(&bytes[start..start + CATALOG_ENTRY_BYTES])?;
            if entry.kind == KIND_CATALOG || entry.kind == KIND_COMMIT {
                return Err(StoreError::InvalidObjectKind);
            }
            if last.is_some_and(|id| id >= entry.id) {
                return Err(StoreError::CatalogOrder);
            }
            last = Some(entry.id);
            entries.push(entry);
        }
        Ok(Self { entries })
    }

    pub fn descriptor(&self, id: ObjectId) -> Option<ObjectDescriptor> {
        self.entries
            .binary_search_by_key(&id, |entry| entry.id)
            .ok()
            .and_then(|index| self.entries.get(index).copied())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitRecord {
    pub format_major: u16,
    pub format_minor: u16,
    pub required_features: u64,
    pub compatible_features: u64,
    pub store_uuid: [u8; 16],
    pub region_units: u64,
    pub generation: u64,
    pub previous_generation: u64,
    pub previous_commit_id: ObjectId,
    pub previous_catalog_id: ObjectId,
    pub catalog_id: ObjectId,
    pub catalog_first_unit: u64,
    pub catalog_byte_length: u64,
    pub catalog_unit_count: u32,
    pub catalog_entry_count: u32,
    pub committed_high_water_unit: u64,
    /// Zero means this storage transaction does not publish a logical system generation.
    pub published_manifest_id: ObjectId,
}

impl CommitRecord {
    pub fn encode(&self) -> Result<Vec<u8>, StoreError> {
        if self.generation == 0 || self.region_units > MAX_REGION_UNITS {
            return Err(StoreError::MalformedCommit);
        }
        let mut out = vec![0; COMMIT_BYTES];
        out[..8].copy_from_slice(COMMIT_MAGIC);
        put_u16(&mut out, 8, 1);
        put_u16(&mut out, 10, COMMIT_BYTES as u16);
        put_u16(&mut out, 12, self.format_major);
        put_u16(&mut out, 14, self.format_minor);
        put_u64(&mut out, 16, self.required_features);
        put_u64(&mut out, 24, self.compatible_features);
        out[32..48].copy_from_slice(&self.store_uuid);
        put_u64(&mut out, 48, self.region_units);
        put_u64(&mut out, 56, self.generation);
        put_u64(&mut out, 64, self.previous_generation);
        out[72..104].copy_from_slice(&self.previous_commit_id.0);
        out[104..136].copy_from_slice(&self.previous_catalog_id.0);
        out[136..168].copy_from_slice(&self.catalog_id.0);
        put_u64(&mut out, 168, self.catalog_first_unit);
        put_u64(&mut out, 176, self.catalog_byte_length);
        put_u32(&mut out, 184, self.catalog_unit_count);
        put_u32(&mut out, 188, self.catalog_entry_count);
        put_u64(&mut out, 192, self.committed_high_water_unit);
        out[200..232].copy_from_slice(&self.published_manifest_id.0);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() != COMMIT_BYTES || &bytes[..8] != COMMIT_MAGIC {
            return Err(StoreError::MalformedCommit);
        }
        if get_u16(bytes, 8)? != 1 || get_u16(bytes, 10)? as usize != COMMIT_BYTES {
            return Err(StoreError::UnsupportedVersion);
        }
        let mut store_uuid = [0; 16];
        store_uuid.copy_from_slice(&bytes[32..48]);
        let mut previous_commit = [0; 32];
        previous_commit.copy_from_slice(&bytes[72..104]);
        let mut previous_catalog = [0; 32];
        previous_catalog.copy_from_slice(&bytes[104..136]);
        let mut catalog = [0; 32];
        catalog.copy_from_slice(&bytes[136..168]);
        let mut manifest = [0; 32];
        manifest.copy_from_slice(&bytes[200..232]);
        let value = Self {
            format_major: get_u16(bytes, 12)?,
            format_minor: get_u16(bytes, 14)?,
            required_features: get_u64(bytes, 16)?,
            compatible_features: get_u64(bytes, 24)?,
            store_uuid,
            region_units: get_u64(bytes, 48)?,
            generation: get_u64(bytes, 56)?,
            previous_generation: get_u64(bytes, 64)?,
            previous_commit_id: ObjectId(previous_commit),
            previous_catalog_id: ObjectId(previous_catalog),
            catalog_id: ObjectId(catalog),
            catalog_first_unit: get_u64(bytes, 168)?,
            catalog_byte_length: get_u64(bytes, 176)?,
            catalog_unit_count: get_u32(bytes, 184)?,
            catalog_entry_count: get_u32(bytes, 188)?,
            committed_high_water_unit: get_u64(bytes, 192)?,
            published_manifest_id: ObjectId(manifest),
        };
        if value.generation == 0 || value.region_units > MAX_REGION_UNITS {
            return Err(StoreError::MalformedCommit);
        }
        Ok(value)
    }

    pub fn id(&self) -> Result<ObjectId, StoreError> {
        ObjectId::calculate(KIND_COMMIT, 1, &self.encode()?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Superblock {
    pub format_major: u16,
    pub format_minor: u16,
    pub required_features: u64,
    pub compatible_features: u64,
    pub store_uuid: [u8; 16],
    pub slot_id: u32,
    pub region_units: u64,
    pub generation: u64,
    pub commit_record_id: ObjectId,
    pub commit_record_unit: u64,
    pub catalog_id: ObjectId,
    pub catalog_first_unit: u64,
    pub catalog_byte_length: u64,
    pub catalog_unit_count: u32,
    pub catalog_entry_count: u32,
    pub committed_high_water_unit: u64,
}

impl Superblock {
    pub fn encode(&self) -> Result<[u8; STORE_UNIT_BYTES], StoreError> {
        if self.slot_id > 1 || self.region_units < 4 || self.region_units > MAX_REGION_UNITS {
            return Err(StoreError::MalformedSuperblock);
        }
        let mut out = [0; STORE_UNIT_BYTES];
        out[..8].copy_from_slice(SUPERBLOCK_MAGIC);
        put_u16(&mut out, 8, self.format_major);
        put_u16(&mut out, 10, self.format_minor);
        put_u64(&mut out, 12, self.required_features);
        put_u64(&mut out, 20, self.compatible_features);
        out[28..44].copy_from_slice(&self.store_uuid);
        put_u32(&mut out, 44, self.slot_id);
        put_u64(&mut out, 48, self.region_units);
        put_u64(&mut out, 56, self.generation);
        out[64..96].copy_from_slice(&self.commit_record_id.0);
        put_u64(&mut out, 96, self.commit_record_unit);
        out[104..136].copy_from_slice(&self.catalog_id.0);
        put_u64(&mut out, 136, self.catalog_first_unit);
        put_u64(&mut out, 144, self.catalog_byte_length);
        put_u32(&mut out, 152, self.catalog_unit_count);
        put_u32(&mut out, 156, self.catalog_entry_count);
        put_u64(&mut out, 160, self.committed_high_water_unit);
        // CRC field is zero while calculated, as required by ADR 0015.
        let crc = crc32c(&out);
        put_u32(&mut out, SUPERBLOCK_CRC_OFFSET, crc);
        Ok(out)
    }

    pub fn decode(bytes: &[u8], expected_slot: u32) -> Result<Self, StoreError> {
        if bytes.len() != STORE_UNIT_BYTES || &bytes[..8] != SUPERBLOCK_MAGIC {
            return Err(StoreError::BadSuperblockMagic);
        }
        if bytes[SUPERBLOCK_USED_BYTES..].iter().any(|b| *b != 0) {
            return Err(StoreError::NonzeroReserved);
        }
        let mut canonical = [0; STORE_UNIT_BYTES];
        canonical.copy_from_slice(bytes);
        let stored_crc = get_u32(bytes, SUPERBLOCK_CRC_OFFSET)?;
        canonical[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].fill(0);
        if crc32c(&canonical) != stored_crc {
            return Err(StoreError::BadSuperblockCrc);
        }
        let mut store_uuid = [0; 16];
        store_uuid.copy_from_slice(&bytes[28..44]);
        let mut commit_record_id = [0; 32];
        commit_record_id.copy_from_slice(&bytes[64..96]);
        let mut catalog_id = [0; 32];
        catalog_id.copy_from_slice(&bytes[104..136]);
        let value = Self {
            format_major: get_u16(bytes, 8)?,
            format_minor: get_u16(bytes, 10)?,
            required_features: get_u64(bytes, 12)?,
            compatible_features: get_u64(bytes, 20)?,
            store_uuid,
            slot_id: get_u32(bytes, 44)?,
            region_units: get_u64(bytes, 48)?,
            generation: get_u64(bytes, 56)?,
            commit_record_id: ObjectId(commit_record_id),
            commit_record_unit: get_u64(bytes, 96)?,
            catalog_id: ObjectId(catalog_id),
            catalog_first_unit: get_u64(bytes, 136)?,
            catalog_byte_length: get_u64(bytes, 144)?,
            catalog_unit_count: get_u32(bytes, 152)?,
            catalog_entry_count: get_u32(bytes, 156)?,
            committed_high_water_unit: get_u64(bytes, 160)?,
        };
        if value.slot_id != expected_slot {
            return Err(StoreError::WrongSuperblockSlot);
        }
        if value.format_major != 1 {
            return Err(StoreError::UnsupportedVersion);
        }
        if value.region_units < 4
            || value.region_units > MAX_REGION_UNITS
            || value.committed_high_water_unit < 4
            || value.committed_high_water_unit > value.region_units
            || value.generation == 0
        {
            return Err(StoreError::MalformedSuperblock);
        }
        Ok(value)
    }

    pub fn logical_eq(&self, other: &Self) -> bool {
        self.format_major == other.format_major
            && self.format_minor == other.format_minor
            && self.required_features == other.required_features
            && self.compatible_features == other.compatible_features
            && self.store_uuid == other.store_uuid
            && self.region_units == other.region_units
            && self.generation == other.generation
            && self.commit_record_id == other.commit_record_id
            && self.commit_record_unit == other.commit_record_unit
            && self.catalog_id == other.catalog_id
            && self.catalog_first_unit == other.catalog_first_unit
            && self.catalog_byte_length == other.catalog_byte_length
            && self.catalog_unit_count == other.catalog_unit_count
            && self.catalog_entry_count == other.catalog_entry_count
            && self.committed_high_water_unit == other.committed_high_water_unit
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreClassification {
    Unformatted,
    ForeignOrUnknown,
    UnsupportedVersion,
    CorruptStore,
    ProvisioningIncomplete,
    ConflictingRoots,
    InconsistentHistory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    Io(BlockError),
    InvalidDevice,
    Unformatted,
    ForeignOrUnknown,
    UnsupportedVersion,
    CorruptStore,
    ProvisioningIncomplete,
    ConflictingRoots,
    InconsistentHistory,
    ReadOnlyRecovery,
    WriterPoisoned,
    CommitOutcomeUnknown { attempted_generation: u64, attempted_commit_id: ObjectId },
    InvalidObject,
    InvalidObjectKind,
    ObjectTooLarge,
    MalformedDescriptor,
    DuplicateObjectConflict,
    CatalogFull,
    CatalogOrder,
    BadCatalogMagic,
    MalformedCommit,
    MalformedSuperblock,
    BadSuperblockMagic,
    BadSuperblockCrc,
    WrongSuperblockSlot,
    NonzeroReserved,
    LengthOverflow,
    InvalidLength,
    OutOfBounds,
    NoSpace { required_units: u64, available_units: u64 },
    GenerationExhausted,
    UnsupportedFeatures,
    IntegrityFailure(ObjectId),
}

impl From<BlockError> for StoreError {
    fn from(error: BlockError) -> Self { Self::Io(error) }
}

// CRC-32C/Castagnoli, reflected polynomial 0x82f63b78.
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
        }
    }
    !crc
}

fn get_u16(b: &[u8], at: usize) -> Result<u16, StoreError> {
    let slice = b.get(at..at.checked_add(2).ok_or(StoreError::LengthOverflow)?).ok_or(StoreError::InvalidLength)?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}
fn get_u32(b: &[u8], at: usize) -> Result<u32, StoreError> {
    let slice = b.get(at..at.checked_add(4).ok_or(StoreError::LengthOverflow)?).ok_or(StoreError::InvalidLength)?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}
fn get_u64(b: &[u8], at: usize) -> Result<u64, StoreError> {
    let slice = b.get(at..at.checked_add(8).ok_or(StoreError::LengthOverflow)?).ok_or(StoreError::InvalidLength)?;
    Ok(u64::from_le_bytes([slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7]]))
}
fn put_u16(b: &mut [u8], at: usize, value: u16) { b[at..at + 2].copy_from_slice(&value.to_le_bytes()); }
fn put_u32(b: &mut [u8], at: usize, value: u32) { b[at..at + 4].copy_from_slice(&value.to_le_bytes()); }
fn put_u64(b: &mut [u8], at: usize, value: u64) { b[at..at + 8].copy_from_slice(&value.to_le_bytes()); }

// Mounting and transactional operations are implemented below this wire layer.
