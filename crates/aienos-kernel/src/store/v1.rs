//! Canonical System Store v1 encodings from ADR 0015.
//!
//! This module provides format primitives only. It does not read or write a
//! device, provision a region, mount a store, or implement transactions.

use alloc::vec;
use alloc::vec::Vec;

use crate::crypto::sha256::Sha256;

pub const STORE_UNIT_BYTES: usize = 4096;
pub const MAX_CATALOG_ENTRIES: usize = 4096;
pub const CATALOG_HEADER_BYTES: usize = 16;
pub const CATALOG_ENTRY_BYTES: usize = 64;
pub const MAX_OBJECT_BYTES: u64 = 67_108_864;
pub const MAX_OBJECT_UNITS: u32 = 16_384;
pub const MAX_TRANSACTION_OBJECTS: usize = 256;
pub const MAX_TRANSACTION_UNITS: u64 = 32_768;
pub const MAX_REGION_UNITS: u64 = 4_294_967_296;
pub const OBJECT_KIND_CATALOG: u16 = 1;
pub const OBJECT_KIND_COMMIT_RECORD: u16 = 2;
pub const OBJECT_VERSION_V1: u16 = 1;
pub const COMMIT_RECORD_BYTES: usize = 200;
pub const SUPERBLOCK_CRC_OFFSET: usize = 168;
pub const SUPERBLOCK_RESERVED_OFFSET: usize = 172;

const OBJECT_DOMAIN: &[u8] = b"AIENOS-STORE-OBJECT-V1\0";
const CATALOG_MAGIC: &[u8; 8] = b"AIENCAT1";
const COMMIT_MAGIC: &[u8; 8] = b"AIENCMT1";
const SUPERBLOCK_MAGIC: &[u8; 8] = b"AIENSTR1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatError {
    InvalidLength,
    InvalidObject,
    ObjectTooLarge,
    LengthOverflow,
    MalformedDescriptor,
    OutOfBounds,
    Overlap,
    CatalogTooLarge,
    CatalogOrder,
    DuplicateObject,
    BadCatalogMagic,
    UnsupportedVersion,
    MalformedCommitRecord,
    MalformedSuperblock,
    BadSuperblockMagic,
    BadSuperblockCrc,
    NonzeroReserved,
    WrongSuperblockSlot,
    UnsupportedFeatures,
    IntegrityFailure,
    InvalidGeneration,
    ConflictingRoots,
    InconsistentHistory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ObjectId(pub [u8; 32]);

impl ObjectId {
    pub fn calculate(kind: u16, version: u16, semantic_bytes: &[u8]) -> Result<Self, FormatError> {
        if kind == 0 || version == 0 || semantic_bytes.is_empty() {
            return Err(FormatError::InvalidObject);
        }
        if semantic_bytes.len() as u64 > MAX_OBJECT_BYTES {
            return Err(FormatError::ObjectTooLarge);
        }
        let length =
            u64::try_from(semantic_bytes.len()).map_err(|_| FormatError::ObjectTooLarge)?;
        let mut hash = Sha256::new();
        hash.update(OBJECT_DOMAIN);
        hash.update(&kind.to_le_bytes());
        hash.update(&version.to_le_bytes());
        hash.update(&length.to_le_bytes());
        hash.update(semantic_bytes);
        Ok(Self(hash.finalize()))
    }

    /// Validate an entire physical object extent, including zero final padding.
    pub fn validate_extent(
        self,
        kind: u16,
        version: u16,
        byte_length: u64,
        extent: &[u8],
    ) -> Result<(), FormatError> {
        let units = object_unit_count(byte_length)?;
        let extent_length = usize::try_from(u64::from(units) * STORE_UNIT_BYTES as u64)
            .map_err(|_| FormatError::LengthOverflow)?;
        if extent.len() != extent_length {
            return Err(FormatError::InvalidLength);
        }
        let semantic_length =
            usize::try_from(byte_length).map_err(|_| FormatError::LengthOverflow)?;
        if extent[semantic_length..].iter().any(|byte| *byte != 0) {
            return Err(FormatError::NonzeroReserved);
        }
        if Self::calculate(kind, version, &extent[..semantic_length])? != self {
            return Err(FormatError::IntegrityFailure);
        }
        Ok(())
    }
}

pub fn object_unit_count(byte_length: u64) -> Result<u32, FormatError> {
    if byte_length == 0 {
        return Err(FormatError::InvalidObject);
    }
    if byte_length > MAX_OBJECT_BYTES {
        return Err(FormatError::ObjectTooLarge);
    }
    let units = byte_length
        .checked_add(STORE_UNIT_BYTES as u64 - 1)
        .ok_or(FormatError::LengthOverflow)?
        / STORE_UNIT_BYTES as u64;
    let units = u32::try_from(units).map_err(|_| FormatError::LengthOverflow)?;
    if units > MAX_OBJECT_UNITS {
        return Err(FormatError::ObjectTooLarge);
    }
    Ok(units)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogEntry {
    pub object_id: ObjectId,
    pub kind: u16,
    pub version: u16,
    pub first_unit: u64,
    pub byte_length: u64,
    pub unit_count: u32,
    pub flags: u16,
}

impl CatalogEntry {
    pub fn encode(self) -> Result<[u8; CATALOG_ENTRY_BYTES], FormatError> {
        self.validate_shape()?;
        let mut bytes = [0u8; CATALOG_ENTRY_BYTES];
        bytes[0..32].copy_from_slice(&self.object_id.0);
        put_u16(&mut bytes, 32, self.kind);
        put_u16(&mut bytes, 34, self.version);
        put_u64(&mut bytes, 36, self.first_unit);
        put_u64(&mut bytes, 44, self.byte_length);
        put_u32(&mut bytes, 52, self.unit_count);
        put_u16(&mut bytes, 56, self.flags);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() != CATALOG_ENTRY_BYTES {
            return Err(FormatError::InvalidLength);
        }
        if bytes[58..64].iter().any(|byte| *byte != 0) {
            return Err(FormatError::NonzeroReserved);
        }
        let mut id = [0; 32];
        id.copy_from_slice(&bytes[..32]);
        let value = Self {
            object_id: ObjectId(id),
            kind: get_u16(bytes, 32)?,
            version: get_u16(bytes, 34)?,
            first_unit: get_u64(bytes, 36)?,
            byte_length: get_u64(bytes, 44)?,
            unit_count: get_u32(bytes, 52)?,
            flags: get_u16(bytes, 56)?,
        };
        value.validate_shape()?;
        Ok(value)
    }

    fn validate_shape(self) -> Result<(), FormatError> {
        if self.kind < 3 || self.version == 0 || self.flags != 0 {
            return Err(FormatError::MalformedDescriptor);
        }
        if object_unit_count(self.byte_length)? != self.unit_count {
            return Err(FormatError::MalformedDescriptor);
        }
        Ok(())
    }

    pub fn validate_bounds(
        self,
        region_units: u64,
        catalog_first_unit: u64,
        committed_high_water: u64,
    ) -> Result<(), FormatError> {
        self.validate_shape()?;
        if !(4..=MAX_REGION_UNITS).contains(&region_units)
            || committed_high_water < 4
            || committed_high_water > region_units
        {
            return Err(FormatError::OutOfBounds);
        }
        let end = self
            .first_unit
            .checked_add(u64::from(self.unit_count))
            .ok_or(FormatError::LengthOverflow)?;
        if self.first_unit < 2
            || end > catalog_first_unit
            || end > committed_high_water
            || end > region_units
        {
            return Err(FormatError::OutOfBounds);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Catalog {
    pub entries: Vec<CatalogEntry>,
}

impl Catalog {
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        if self.entries.len() > MAX_CATALOG_ENTRIES {
            return Err(FormatError::CatalogTooLarge);
        }
        self.check_order()?;
        let bytes_length = CATALOG_HEADER_BYTES
            .checked_add(
                self.entries
                    .len()
                    .checked_mul(CATALOG_ENTRY_BYTES)
                    .ok_or(FormatError::LengthOverflow)?,
            )
            .ok_or(FormatError::LengthOverflow)?;
        let mut bytes = vec![0u8; bytes_length];
        bytes[..8].copy_from_slice(CATALOG_MAGIC);
        put_u16(&mut bytes, 8, 1);
        put_u16(&mut bytes, 10, CATALOG_ENTRY_BYTES as u16);
        put_u32(&mut bytes, 12, self.entries.len() as u32);
        for (index, entry) in self.entries.iter().copied().enumerate() {
            let start = CATALOG_HEADER_BYTES + index * CATALOG_ENTRY_BYTES;
            bytes[start..start + CATALOG_ENTRY_BYTES].copy_from_slice(&entry.encode()?);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() < CATALOG_HEADER_BYTES {
            return Err(FormatError::InvalidLength);
        }
        if &bytes[..8] != CATALOG_MAGIC {
            return Err(FormatError::BadCatalogMagic);
        }
        if get_u16(bytes, 8)? != 1 || get_u16(bytes, 10)? != CATALOG_ENTRY_BYTES as u16 {
            return Err(FormatError::UnsupportedVersion);
        }
        let count =
            usize::try_from(get_u32(bytes, 12)?).map_err(|_| FormatError::LengthOverflow)?;
        if count > MAX_CATALOG_ENTRIES {
            return Err(FormatError::CatalogTooLarge);
        }
        let expected = CATALOG_HEADER_BYTES
            .checked_add(
                count
                    .checked_mul(CATALOG_ENTRY_BYTES)
                    .ok_or(FormatError::LengthOverflow)?,
            )
            .ok_or(FormatError::LengthOverflow)?;
        if bytes.len() != expected {
            return Err(FormatError::InvalidLength);
        }
        let mut entries = Vec::with_capacity(count);
        for index in 0..count {
            let start = CATALOG_HEADER_BYTES + index * CATALOG_ENTRY_BYTES;
            entries.push(CatalogEntry::decode(
                &bytes[start..start + CATALOG_ENTRY_BYTES],
            )?);
        }
        let catalog = Self { entries };
        catalog.check_order()?;
        Ok(catalog)
    }

    pub fn validate_extents(
        &self,
        region_units: u64,
        catalog_first_unit: u64,
        committed_high_water: u64,
    ) -> Result<(), FormatError> {
        if !(4..=MAX_REGION_UNITS).contains(&region_units)
            || committed_high_water < 4
            || committed_high_water > region_units
            || catalog_first_unit < 2
            || catalog_first_unit >= region_units
        {
            return Err(FormatError::OutOfBounds);
        }
        let mut extents = Vec::with_capacity(self.entries.len());
        for entry in self.entries.iter().copied() {
            entry.validate_bounds(region_units, catalog_first_unit, committed_high_water)?;
            let end = entry
                .first_unit
                .checked_add(u64::from(entry.unit_count))
                .ok_or(FormatError::LengthOverflow)?;
            extents.push((entry.first_unit, end));
        }
        extents.sort_unstable();
        if extents.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(FormatError::Overlap);
        }
        Ok(())
    }

    fn check_order(&self) -> Result<(), FormatError> {
        for pair in self.entries.windows(2) {
            if pair[0].object_id >= pair[1].object_id {
                return if pair[0].object_id == pair[1].object_id {
                    Err(FormatError::DuplicateObject)
                } else {
                    Err(FormatError::CatalogOrder)
                };
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitRecord {
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
    pub committed_high_water: u64,
}

impl CommitRecord {
    pub fn encode(&self) -> Result<[u8; COMMIT_RECORD_BYTES], FormatError> {
        self.validate()?;
        let mut bytes = [0u8; COMMIT_RECORD_BYTES];
        bytes[..8].copy_from_slice(COMMIT_MAGIC);
        put_u16(&mut bytes, 8, 1);
        put_u16(&mut bytes, 10, COMMIT_RECORD_BYTES as u16);
        put_u16(&mut bytes, 12, 1);
        put_u16(&mut bytes, 14, 0);
        put_u64(&mut bytes, 16, 0);
        put_u64(&mut bytes, 24, 0);
        bytes[32..48].copy_from_slice(&self.store_uuid);
        put_u64(&mut bytes, 48, self.region_units);
        put_u64(&mut bytes, 56, self.generation);
        put_u64(&mut bytes, 64, self.previous_generation);
        bytes[72..104].copy_from_slice(&self.previous_commit_id.0);
        bytes[104..136].copy_from_slice(&self.previous_catalog_id.0);
        bytes[136..168].copy_from_slice(&self.catalog_id.0);
        put_u64(&mut bytes, 168, self.catalog_first_unit);
        put_u64(&mut bytes, 176, self.catalog_byte_length);
        put_u32(&mut bytes, 184, self.catalog_unit_count);
        put_u32(&mut bytes, 188, self.catalog_entry_count);
        put_u64(&mut bytes, 192, self.committed_high_water);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() != COMMIT_RECORD_BYTES || &bytes[..8] != COMMIT_MAGIC {
            return Err(FormatError::MalformedCommitRecord);
        }
        if get_u16(bytes, 8)? != 1 || get_u16(bytes, 10)? as usize != COMMIT_RECORD_BYTES {
            return Err(FormatError::UnsupportedVersion);
        }
        if get_u16(bytes, 12)? != 1 || get_u16(bytes, 14)? != 0 {
            return Err(FormatError::UnsupportedVersion);
        }
        if get_u64(bytes, 16)? != 0 || get_u64(bytes, 24)? != 0 {
            return Err(FormatError::UnsupportedFeatures);
        }
        let mut store_uuid = [0; 16];
        store_uuid.copy_from_slice(&bytes[32..48]);
        let mut prev_commit = [0; 32];
        prev_commit.copy_from_slice(&bytes[72..104]);
        let mut prev_catalog = [0; 32];
        prev_catalog.copy_from_slice(&bytes[104..136]);
        let mut catalog = [0; 32];
        catalog.copy_from_slice(&bytes[136..168]);
        let record = Self {
            store_uuid,
            region_units: get_u64(bytes, 48)?,
            generation: get_u64(bytes, 56)?,
            previous_generation: get_u64(bytes, 64)?,
            previous_commit_id: ObjectId(prev_commit),
            previous_catalog_id: ObjectId(prev_catalog),
            catalog_id: ObjectId(catalog),
            catalog_first_unit: get_u64(bytes, 168)?,
            catalog_byte_length: get_u64(bytes, 176)?,
            catalog_unit_count: get_u32(bytes, 184)?,
            catalog_entry_count: get_u32(bytes, 188)?,
            committed_high_water: get_u64(bytes, 192)?,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn object_id(&self) -> Result<ObjectId, FormatError> {
        ObjectId::calculate(
            OBJECT_KIND_COMMIT_RECORD,
            OBJECT_VERSION_V1,
            &self.encode()?,
        )
    }

    pub fn validate(&self) -> Result<(), FormatError> {
        if !(4..=MAX_REGION_UNITS).contains(&self.region_units) || self.generation == 0 {
            return Err(FormatError::MalformedCommitRecord);
        }
        let expected_bytes = CATALOG_HEADER_BYTES
            .checked_add(
                usize::try_from(self.catalog_entry_count)
                    .map_err(|_| FormatError::LengthOverflow)?
                    .checked_mul(CATALOG_ENTRY_BYTES)
                    .ok_or(FormatError::LengthOverflow)?,
            )
            .ok_or(FormatError::LengthOverflow)?;
        if self.catalog_entry_count as usize > MAX_CATALOG_ENTRIES
            || self.catalog_byte_length != expected_bytes as u64
            || object_unit_count(self.catalog_byte_length)? != self.catalog_unit_count
        {
            return Err(FormatError::MalformedCommitRecord);
        }
        let catalog_end = self
            .catalog_first_unit
            .checked_add(u64::from(self.catalog_unit_count))
            .ok_or(FormatError::LengthOverflow)?;
        if self.catalog_first_unit < 2
            || catalog_end >= self.region_units
            || self.committed_high_water != catalog_end + 1
            || self.committed_high_water > self.region_units
        {
            return Err(FormatError::MalformedCommitRecord);
        }
        if self.generation == 1 {
            if self.previous_generation != 0
                || self.previous_commit_id != ObjectId([0; 32])
                || self.previous_catalog_id != ObjectId([0; 32])
            {
                return Err(FormatError::InvalidGeneration);
            }
        } else if self.previous_generation.checked_add(1) != Some(self.generation)
            || self.previous_commit_id == ObjectId([0; 32])
            || self.previous_catalog_id == ObjectId([0; 32])
        {
            return Err(FormatError::InvalidGeneration);
        }
        Ok(())
    }

    pub fn validates_catalog(
        &self,
        catalog_id: ObjectId,
        catalog: &Catalog,
    ) -> Result<(), FormatError> {
        let semantic = catalog.encode()?;
        if self.catalog_id != catalog_id
            || self.catalog_entry_count as usize != catalog.entries.len()
            || self.catalog_byte_length != semantic.len() as u64
            || object_unit_count(semantic.len() as u64)? != self.catalog_unit_count
            || ObjectId::calculate(OBJECT_KIND_CATALOG, OBJECT_VERSION_V1, &semantic)? != catalog_id
        {
            return Err(FormatError::IntegrityFailure);
        }
        Ok(())
    }

    pub fn identifies_predecessor(&self, previous: &Self, previous_id: ObjectId) -> bool {
        self.generation.checked_sub(1) == Some(previous.generation)
            && self.previous_generation == previous.generation
            && self.previous_commit_id == previous_id
            && self.previous_catalog_id == previous.catalog_id
            && self.store_uuid == previous.store_uuid
            && self.region_units == previous.region_units
            && self.catalog_first_unit >= previous.committed_high_water
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Superblock {
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
    pub committed_high_water: u64,
}

impl Superblock {
    pub fn encode(&self) -> Result<[u8; STORE_UNIT_BYTES], FormatError> {
        self.validate_shape()?;
        let mut bytes = [0u8; STORE_UNIT_BYTES];
        bytes[..8].copy_from_slice(SUPERBLOCK_MAGIC);
        put_u16(&mut bytes, 8, 1);
        put_u16(&mut bytes, 10, 0);
        put_u64(&mut bytes, 12, 0);
        put_u64(&mut bytes, 20, 0);
        bytes[28..44].copy_from_slice(&self.store_uuid);
        put_u32(&mut bytes, 44, self.slot_id);
        put_u64(&mut bytes, 48, self.region_units);
        put_u64(&mut bytes, 56, self.generation);
        bytes[64..96].copy_from_slice(&self.commit_record_id.0);
        put_u64(&mut bytes, 96, self.commit_record_unit);
        bytes[104..136].copy_from_slice(&self.catalog_id.0);
        put_u64(&mut bytes, 136, self.catalog_first_unit);
        put_u64(&mut bytes, 144, self.catalog_byte_length);
        put_u32(&mut bytes, 152, self.catalog_unit_count);
        put_u32(&mut bytes, 156, self.catalog_entry_count);
        put_u64(&mut bytes, 160, self.committed_high_water);
        let checksum = crc32c(&bytes);
        put_u32(&mut bytes, SUPERBLOCK_CRC_OFFSET, checksum);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8], expected_slot: u32) -> Result<Self, FormatError> {
        if bytes.len() != STORE_UNIT_BYTES || &bytes[..8] != SUPERBLOCK_MAGIC {
            return Err(FormatError::BadSuperblockMagic);
        }
        let stored_crc = get_u32(bytes, SUPERBLOCK_CRC_OFFSET)?;
        let mut canonical = [0u8; STORE_UNIT_BYTES];
        canonical.copy_from_slice(bytes);
        canonical[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].fill(0);
        if crc32c(&canonical) != stored_crc {
            return Err(FormatError::BadSuperblockCrc);
        }
        if bytes[SUPERBLOCK_RESERVED_OFFSET..]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(FormatError::NonzeroReserved);
        }
        if get_u16(bytes, 8)? != 1 || get_u16(bytes, 10)? != 0 {
            return Err(FormatError::UnsupportedVersion);
        }
        if get_u64(bytes, 12)? != 0 || get_u64(bytes, 20)? != 0 {
            return Err(FormatError::UnsupportedFeatures);
        }
        let slot_id = get_u32(bytes, 44)?;
        if slot_id != expected_slot || slot_id > 1 {
            return Err(FormatError::WrongSuperblockSlot);
        }
        let mut uuid = [0; 16];
        uuid.copy_from_slice(&bytes[28..44]);
        let mut commit = [0; 32];
        commit.copy_from_slice(&bytes[64..96]);
        let mut catalog = [0; 32];
        catalog.copy_from_slice(&bytes[104..136]);
        let value = Self {
            store_uuid: uuid,
            slot_id,
            region_units: get_u64(bytes, 48)?,
            generation: get_u64(bytes, 56)?,
            commit_record_id: ObjectId(commit),
            commit_record_unit: get_u64(bytes, 96)?,
            catalog_id: ObjectId(catalog),
            catalog_first_unit: get_u64(bytes, 136)?,
            catalog_byte_length: get_u64(bytes, 144)?,
            catalog_unit_count: get_u32(bytes, 152)?,
            catalog_entry_count: get_u32(bytes, 156)?,
            committed_high_water: get_u64(bytes, 160)?,
        };
        value.validate_shape()?;
        Ok(value)
    }

    pub fn validate_commit(
        &self,
        commit_id: ObjectId,
        commit: &CommitRecord,
    ) -> Result<(), FormatError> {
        if self.commit_record_id != commit_id
            || self.store_uuid != commit.store_uuid
            || self.region_units != commit.region_units
            || self.generation != commit.generation
            || self.catalog_id != commit.catalog_id
            || self.catalog_first_unit != commit.catalog_first_unit
            || self.catalog_byte_length != commit.catalog_byte_length
            || self.catalog_unit_count != commit.catalog_unit_count
            || self.catalog_entry_count != commit.catalog_entry_count
            || self.committed_high_water != commit.committed_high_water
            || self.commit_record_unit.checked_add(1) != Some(commit.committed_high_water)
            || self
                .catalog_first_unit
                .checked_add(u64::from(self.catalog_unit_count))
                != Some(self.commit_record_unit)
        {
            return Err(FormatError::MalformedSuperblock);
        }
        Ok(())
    }

    pub fn equivalent_root(&self, other: &Self) -> bool {
        self.store_uuid == other.store_uuid
            && self.region_units == other.region_units
            && self.generation == other.generation
            && self.commit_record_id == other.commit_record_id
    }

    fn validate_shape(&self) -> Result<(), FormatError> {
        if self.slot_id > 1
            || !(4..=MAX_REGION_UNITS).contains(&self.region_units)
            || self.generation == 0
            || self.committed_high_water > self.region_units
            || self.committed_high_water < 4
        {
            return Err(FormatError::MalformedSuperblock);
        }
        let expected_catalog_length = CATALOG_HEADER_BYTES
            .checked_add(
                usize::try_from(self.catalog_entry_count)
                    .map_err(|_| FormatError::LengthOverflow)?
                    .checked_mul(CATALOG_ENTRY_BYTES)
                    .ok_or(FormatError::LengthOverflow)?,
            )
            .ok_or(FormatError::LengthOverflow)?;
        let catalog_end = self
            .catalog_first_unit
            .checked_add(u64::from(self.catalog_unit_count))
            .ok_or(FormatError::LengthOverflow)?;
        if self.catalog_entry_count as usize > MAX_CATALOG_ENTRIES
            || self.catalog_byte_length != expected_catalog_length as u64
            || object_unit_count(self.catalog_byte_length)? != self.catalog_unit_count
            || self.catalog_first_unit < 2
            || catalog_end != self.commit_record_unit
            || self.commit_record_unit.checked_add(1) != Some(self.committed_high_water)
        {
            return Err(FormatError::MalformedSuperblock);
        }
        Ok(())
    }
}

/// CRC-32C/Castagnoli, reflected polynomial 0x82f63b78, init/xorout all ones.
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

fn get_u16(bytes: &[u8], offset: usize) -> Result<u16, FormatError> {
    let field = bytes
        .get(offset..offset.checked_add(2).ok_or(FormatError::LengthOverflow)?)
        .ok_or(FormatError::InvalidLength)?;
    Ok(u16::from_le_bytes([field[0], field[1]]))
}
fn get_u32(bytes: &[u8], offset: usize) -> Result<u32, FormatError> {
    let field = bytes
        .get(offset..offset.checked_add(4).ok_or(FormatError::LengthOverflow)?)
        .ok_or(FormatError::InvalidLength)?;
    Ok(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}
fn get_u64(bytes: &[u8], offset: usize) -> Result<u64, FormatError> {
    let field = bytes
        .get(offset..offset.checked_add(8).ok_or(FormatError::LengthOverflow)?)
        .ok_or(FormatError::InvalidLength)?;
    Ok(u64::from_le_bytes([
        field[0], field[1], field[2], field[3], field[4], field[5], field[6], field[7],
    ]))
}
fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), N * 2);
        let mut out = [0; N];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
        }
        out
    }

    fn assert_sha256(bytes: &[u8], expected: &str) {
        let mut hash = Sha256::new();
        hash.update(bytes);
        assert_eq!(hash.finalize(), from_hex::<32>(expected));
    }

    fn sample_genesis() -> (CommitRecord, ObjectId, Superblock) {
        let catalog = Catalog { entries: vec![] };
        let catalog_bytes = catalog.encode().unwrap();
        let catalog_id =
            ObjectId::calculate(OBJECT_KIND_CATALOG, OBJECT_VERSION_V1, &catalog_bytes).unwrap();
        let record = CommitRecord {
            store_uuid: core::array::from_fn(|index| index as u8),
            region_units: 16,
            generation: 1,
            previous_generation: 0,
            previous_commit_id: ObjectId([0; 32]),
            previous_catalog_id: ObjectId([0; 32]),
            catalog_id,
            catalog_first_unit: 2,
            catalog_byte_length: catalog_bytes.len() as u64,
            catalog_unit_count: 1,
            catalog_entry_count: 0,
            committed_high_water: 4,
        };
        let commit_id = record.object_id().unwrap();
        let superblock = Superblock {
            store_uuid: record.store_uuid,
            slot_id: 0,
            region_units: record.region_units,
            generation: record.generation,
            commit_record_id: commit_id,
            commit_record_unit: 3,
            catalog_id,
            catalog_first_unit: 2,
            catalog_byte_length: catalog_bytes.len() as u64,
            catalog_unit_count: 1,
            catalog_entry_count: 0,
            committed_high_water: 4,
        };
        (record, catalog_id, superblock)
    }

    #[test]
    fn object_id_and_catalog_vectors_match_adr_0015() {
        let semantic: [u8; 16] = core::array::from_fn(|index| index as u8);
        let standalone = ObjectId::calculate(0x1234, 0x5678, &semantic).unwrap();
        assert_eq!(
            standalone.0,
            from_hex("80b93b4e31915bf7a7fd4607e686e757924425d9a4f9c1e84f51672d1b9b1334")
        );

        let empty = Catalog { entries: vec![] };
        let empty_bytes = empty.encode().unwrap();
        assert_eq!(
            empty_bytes,
            from_hex::<16>("4149454e434154310100400000000000")
        );
        let empty_id =
            ObjectId::calculate(OBJECT_KIND_CATALOG, OBJECT_VERSION_V1, &empty_bytes).unwrap();
        assert_eq!(
            empty_id.0,
            from_hex("44197839cf88e93c480d77a0c234ce21362a038d33d398ead10e062906d7be6a")
        );

        let app_id = ObjectId::calculate(3, 1, &semantic).unwrap();
        assert_eq!(
            app_id.0,
            from_hex("307663335463d5f838fdd1b60950a02c873a28cd6cea13c2ffbfa5d8e41145a6")
        );
        let entry = CatalogEntry {
            object_id: app_id,
            kind: 3,
            version: 1,
            first_unit: 4,
            byte_length: 16,
            unit_count: 1,
            flags: 0,
        };
        let one = Catalog {
            entries: vec![entry],
        };
        let one_bytes = one.encode().unwrap();
        assert_eq!(one_bytes.len(), 80);
        assert_sha256(
            &one_bytes,
            "3b8b9ea39606ad6abba5f20db970872b20487663cfff69024a6cc01d7e951645",
        );
        let one_id =
            ObjectId::calculate(OBJECT_KIND_CATALOG, OBJECT_VERSION_V1, &one_bytes).unwrap();
        assert_eq!(
            one_id.0,
            from_hex("15d05f57a32d04af08fc9ba5d88c2fd9fdf09ba9858cfa35b25bb6e66c1f7c85")
        );
        assert_eq!(Catalog::decode(&one_bytes).unwrap(), one);
    }

    #[test]
    fn commit_superblock_genesis_and_adjacent_vectors_match_adr_0015() {
        let (genesis, empty_catalog_id, mut genesis_sb) = sample_genesis();
        let genesis_bytes = genesis.encode().unwrap();
        assert_sha256(
            &genesis_bytes,
            "54e2090af026678f548a8096a5781caeef14122f2cc22d65f4afa69e65a198f0",
        );
        let genesis_id = genesis.object_id().unwrap();
        assert_eq!(
            genesis_id.0,
            from_hex("655010d6bc51309dc8f00d44ea167f65e074cb065881d33eec3af6eda4c2d422")
        );
        let mut commit_unit = [0; STORE_UNIT_BYTES];
        commit_unit[..COMMIT_RECORD_BYTES].copy_from_slice(&genesis_bytes);
        assert_sha256(
            &commit_unit,
            "d23bfa188198e0b285e12411ab8054183f67b2e67cbe03933a2444297a98dc4d",
        );
        assert_eq!(CommitRecord::decode(&genesis_bytes).unwrap(), genesis);

        genesis_sb.validate_commit(genesis_id, &genesis).unwrap();
        let sb_a = genesis_sb.encode().unwrap();
        assert_sha256(
            &sb_a,
            "fd25f10310b662942275d0b72255a9f3a4e389b6e34d111465884a467e7ebdbc",
        );
        let crc_a = get_u32(&sb_a, SUPERBLOCK_CRC_OFFSET).unwrap();
        assert_eq!(crc_a.to_le_bytes(), from_hex("fc775a27"));
        assert_eq!(Superblock::decode(&sb_a, 0).unwrap(), genesis_sb);

        genesis_sb.slot_id = 1;
        let sb_b = genesis_sb.encode().unwrap();
        assert_sha256(
            &sb_b,
            "e75a62a7a81ac318487ad1def438933430df9c199a1e5ef8942ef599731018e7",
        );
        assert_eq!(
            get_u32(&sb_b, SUPERBLOCK_CRC_OFFSET).unwrap().to_le_bytes(),
            from_hex("98353ee3")
        );
        let decoded_b = Superblock::decode(&sb_b, 1).unwrap();
        assert!(Superblock::decode(&sb_a, 0)
            .unwrap()
            .equivalent_root(&decoded_b));
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);

        let semantic: [u8; 16] = core::array::from_fn(|index| index as u8);
        let app_id = ObjectId::calculate(3, 1, &semantic).unwrap();
        let gen2_catalog = Catalog {
            entries: vec![CatalogEntry {
                object_id: app_id,
                kind: 3,
                version: 1,
                first_unit: 4,
                byte_length: 16,
                unit_count: 1,
                flags: 0,
            }],
        };
        let gen2_catalog_bytes = gen2_catalog.encode().unwrap();
        let gen2_catalog_id =
            ObjectId::calculate(OBJECT_KIND_CATALOG, OBJECT_VERSION_V1, &gen2_catalog_bytes)
                .unwrap();
        let gen2 = CommitRecord {
            store_uuid: genesis.store_uuid,
            region_units: genesis.region_units,
            generation: 2,
            previous_generation: 1,
            previous_commit_id: genesis_id,
            previous_catalog_id: empty_catalog_id,
            catalog_id: gen2_catalog_id,
            catalog_first_unit: 5,
            catalog_byte_length: 80,
            catalog_unit_count: 1,
            catalog_entry_count: 1,
            committed_high_water: 7,
        };
        assert!(gen2.identifies_predecessor(&genesis, genesis_id));
        let gen2_bytes = gen2.encode().unwrap();
        assert_sha256(
            &gen2_bytes,
            "2a1a929eaae3b473531ee70ee8bb945ffe6ca05caf0b5e7a8c69d2179e1e716c",
        );
        let gen2_id = gen2.object_id().unwrap();
        assert_eq!(
            gen2_id.0,
            from_hex("7787f3c9a29560e67987c4c83dd2b49ab402ee27975432a0f43fdf50749d11c1")
        );
        let gen2_sb = Superblock {
            store_uuid: gen2.store_uuid,
            slot_id: 0,
            region_units: gen2.region_units,
            generation: 2,
            commit_record_id: gen2_id,
            commit_record_unit: 6,
            catalog_id: gen2_catalog_id,
            catalog_first_unit: 5,
            catalog_byte_length: 80,
            catalog_unit_count: 1,
            catalog_entry_count: 1,
            committed_high_water: 7,
        };
        gen2_sb.validate_commit(gen2_id, &gen2).unwrap();
        assert_sha256(
            &gen2_sb.encode().unwrap(),
            "47c84fb7394d4fb5b52d1b600fe67c4f3f07d41ed98ffadde2afa15b4dc9ddcc",
        );
    }

    #[test]
    fn malformed_object_catalog_and_extent_vectors_are_rejected() {
        let semantic = [0x5au8; 16];
        assert_eq!(
            ObjectId::calculate(3, 1, &[]),
            Err(FormatError::InvalidObject)
        );
        assert_eq!(
            ObjectId::calculate(0, 1, &semantic),
            Err(FormatError::InvalidObject)
        );
        let id = ObjectId::calculate(3, 1, &semantic).unwrap();
        let entry = CatalogEntry {
            object_id: id,
            kind: 3,
            version: 1,
            first_unit: 2,
            byte_length: 16,
            unit_count: 1,
            flags: 0,
        };
        let mut encoded_entry = entry.encode().unwrap();
        encoded_entry[58] = 1;
        assert_eq!(
            CatalogEntry::decode(&encoded_entry),
            Err(FormatError::NonzeroReserved)
        );
        let mut bad_flags = entry;
        bad_flags.flags = 1;
        assert_eq!(bad_flags.encode(), Err(FormatError::MalformedDescriptor));

        let ordered = Catalog {
            entries: vec![
                entry,
                CatalogEntry {
                    object_id: ObjectId([0xff; 32]),
                    ..entry
                },
            ],
        };
        assert!(ordered.encode().is_ok());
        let reversed = Catalog {
            entries: vec![ordered.entries[1], ordered.entries[0]],
        };
        assert_eq!(reversed.encode(), Err(FormatError::CatalogOrder));
        let duplicate = Catalog {
            entries: vec![entry, entry],
        };
        assert_eq!(duplicate.encode(), Err(FormatError::DuplicateObject));

        let mut empty_bytes = Catalog { entries: vec![] }.encode().unwrap();
        empty_bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            Catalog::decode(&empty_bytes),
            Err(FormatError::InvalidLength)
        );
        let mut bad_magic = Catalog { entries: vec![] }.encode().unwrap();
        bad_magic[0] ^= 1;
        assert_eq!(
            Catalog::decode(&bad_magic),
            Err(FormatError::BadCatalogMagic)
        );

        let mut physical = [0; STORE_UNIT_BYTES];
        physical[..semantic.len()].copy_from_slice(&semantic);
        id.validate_extent(3, 1, semantic.len() as u64, &physical)
            .unwrap();
        physical[STORE_UNIT_BYTES - 1] = 1;
        assert_eq!(
            id.validate_extent(3, 1, semantic.len() as u64, &physical),
            Err(FormatError::NonzeroReserved)
        );
        physical[STORE_UNIT_BYTES - 1] = 0;
        physical[0] ^= 1;
        assert_eq!(
            id.validate_extent(3, 1, semantic.len() as u64, &physical),
            Err(FormatError::IntegrityFailure)
        );

        let first = CatalogEntry {
            first_unit: 2,
            ..entry
        };
        let overlap = Catalog {
            entries: vec![
                entry,
                CatalogEntry {
                    object_id: ObjectId([0xff; 32]),
                    ..first
                },
            ],
        };
        assert_eq!(
            overlap.validate_extents(32, 5, 8),
            Err(FormatError::Overlap)
        );
        assert_eq!(
            entry.validate_bounds(8, 2, 8),
            Err(FormatError::OutOfBounds)
        );
    }

    #[test]
    fn malformed_generation_high_water_and_superblock_bytes_are_rejected() {
        let (genesis, _, sb) = sample_genesis();
        let mut broken_genesis = genesis.clone();
        broken_genesis.previous_generation = 1;
        assert_eq!(broken_genesis.encode(), Err(FormatError::InvalidGeneration));
        let mut broken_high_water = genesis.clone();
        broken_high_water.committed_high_water = 5;
        assert_eq!(
            broken_high_water.encode(),
            Err(FormatError::MalformedCommitRecord)
        );

        let bytes = sb.encode().unwrap();
        let mut bad_crc = bytes;
        bad_crc[168] ^= 1;
        assert_eq!(
            Superblock::decode(&bad_crc, 0),
            Err(FormatError::BadSuperblockCrc)
        );
        let mut reserved = bytes;
        reserved[SUPERBLOCK_RESERVED_OFFSET] = 1;
        reserved[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].fill(0);
        let corrected_crc = crc32c(&reserved);
        put_u32(&mut reserved, SUPERBLOCK_CRC_OFFSET, corrected_crc);
        assert_eq!(
            Superblock::decode(&reserved, 0),
            Err(FormatError::NonzeroReserved)
        );
        assert_eq!(
            Superblock::decode(&bytes, 1),
            Err(FormatError::WrongSuperblockSlot)
        );

        let mut changed_unit = sb.clone();
        changed_unit.commit_record_unit = 2;
        assert_eq!(
            changed_unit.validate_commit(genesis.object_id().unwrap(), &genesis),
            Err(FormatError::MalformedSuperblock)
        );
        assert_eq!(
            genesis.validates_catalog(genesis.catalog_id, &Catalog { entries: vec![] }),
            Ok(())
        );
    }
}
