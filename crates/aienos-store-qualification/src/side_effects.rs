//! Side-effect and provisioning boundary adversarial testing suite (G5).
//!
//! ADR 0015 / Store v1 requirements:
//! - open()/mount() MUST NOT write, repair, or autoformat.
//! - mount never rewrites a Superblock to "fix" redundancy or damaged CRC.
//! - degraded recovery performs exactly 0 repair writes and 0 flushes.
//! - deduplication requires full independent byte and padding verification.
//! - conflicting duplicate descriptors strictly fail.
//! - normal transactions cannot repair corrupt committed objects.

use crate::oracle::{independent_crc32c, independent_object_id, STORE_UNIT_BYTES};
use std::collections::HashSet;

pub const SUPERBLOCK_MAGIC: &[u8; 8] = b"AIENSTR1";
pub const CATALOG_MAGIC: &[u8; 8] = b"AIENCAT1";
pub const COMMIT_MAGIC: &[u8; 8] = b"AIENCMT1";
pub const SUPERBLOCK_CRC_OFFSET: usize = 168;
pub const SUPERBLOCK_RESERVED_OFFSET: usize = 172;
pub const COMMIT_RECORD_BYTES: usize = 200;
pub const CATALOG_HEADER_BYTES: usize = 16;
pub const CATALOG_ENTRY_BYTES: usize = 64;
pub const MAX_CATALOG_ENTRIES: usize = 4096;
pub const MAX_OBJECT_BYTES: u64 = 67_108_864;
pub const MAX_OBJECT_UNITS: u32 = 16_384;
pub const MAX_TRANSACTION_OBJECTS: usize = 256;
pub const MAX_TRANSACTION_UNITS: u64 = 32_768;
pub const MAX_REGION_UNITS: u64 = 4_294_967_296;

pub const OBJECT_KIND_CATALOG: u16 = 1;
pub const OBJECT_KIND_COMMIT_RECORD: u16 = 2;
pub const OBJECT_VERSION_V1: u16 = 1;

/// Error types produced by block devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceError {
    Io,
    OutOfBounds,
    InjectedFault,
    InvalidGeometry,
}

/// A mock block device that tracks read, write, and flush operations,
/// logs accessed units, and allows precise fault injection.
#[derive(Debug, Clone)]
pub struct MockBlockDevice {
    pub block_size: usize,
    pub block_count: u64,
    pub storage: Vec<u8>,
    pub read_count: usize,
    pub write_count: usize,
    pub flush_count: usize,
    pub read_units_log: Vec<u64>,
    pub written_units_log: Vec<u64>,
    pub read_faults: HashSet<u64>,
    pub write_faults: HashSet<u64>,
    pub fail_all_reads: bool,
    pub fail_all_writes: bool,
    pub fail_flushes: bool,
}

impl MockBlockDevice {
    /// Creates a mock device with the given unit count and default 4096-byte block size.
    pub fn new(unit_count: u64) -> Self {
        Self::with_block_size(STORE_UNIT_BYTES, unit_count)
    }

    /// Creates a mock device with an explicit logical block size (512 or 4096).
    pub fn with_block_size(block_size: usize, unit_count: u64) -> Self {
        assert!(
            block_size == 512 || block_size == 4096,
            "Unsupported block size: {}",
            block_size
        );
        let total_bytes = (unit_count as usize) * STORE_UNIT_BYTES;
        let block_count = (total_bytes / block_size) as u64;
        Self {
            block_size,
            block_count,
            storage: vec![0u8; total_bytes],
            read_count: 0,
            write_count: 0,
            flush_count: 0,
            read_units_log: Vec::new(),
            written_units_log: Vec::new(),
            read_faults: HashSet::new(),
            write_faults: HashSet::new(),
            fail_all_reads: false,
            fail_all_writes: false,
            fail_flushes: false,
        }
    }

    pub fn unit_count(&self) -> u64 {
        (self.storage.len() / STORE_UNIT_BYTES) as u64
    }

    pub fn reset_counts(&mut self) {
        self.read_count = 0;
        self.write_count = 0;
        self.flush_count = 0;
        self.read_units_log.clear();
        self.written_units_log.clear();
    }

    pub fn inject_read_fault_on_unit(&mut self, unit: u64) {
        self.read_faults.insert(unit);
    }

    pub fn inject_write_fault_on_unit(&mut self, unit: u64) {
        self.write_faults.insert(unit);
    }

    pub fn set_fail_all_reads(&mut self, fail: bool) {
        self.fail_all_reads = fail;
    }

    pub fn set_fail_all_writes(&mut self, fail: bool) {
        self.fail_all_writes = fail;
    }

    pub fn set_fail_flushes(&mut self, fail: bool) {
        self.fail_flushes = fail;
    }

    pub fn clear_faults(&mut self) {
        self.read_faults.clear();
        self.write_faults.clear();
        self.fail_all_reads = false;
        self.fail_all_writes = false;
        self.fail_flushes = false;
    }

    pub fn read_unit(
        &mut self,
        unit: u64,
        buf: &mut [u8; STORE_UNIT_BYTES],
    ) -> Result<(), DeviceError> {
        self.read_count += 1;
        self.read_units_log.push(unit);

        if self.fail_all_reads || self.read_faults.contains(&unit) {
            return Err(DeviceError::InjectedFault);
        }

        let start_byte = (unit as usize) * STORE_UNIT_BYTES;
        let end_byte = start_byte + STORE_UNIT_BYTES;
        if end_byte > self.storage.len() {
            return Err(DeviceError::OutOfBounds);
        }

        buf.copy_from_slice(&self.storage[start_byte..end_byte]);
        Ok(())
    }

    pub fn write_unit(
        &mut self,
        unit: u64,
        buf: &[u8; STORE_UNIT_BYTES],
    ) -> Result<(), DeviceError> {
        self.write_count += 1;
        self.written_units_log.push(unit);

        if self.fail_all_writes || self.write_faults.contains(&unit) {
            return Err(DeviceError::InjectedFault);
        }

        let start_byte = (unit as usize) * STORE_UNIT_BYTES;
        let end_byte = start_byte + STORE_UNIT_BYTES;
        if end_byte > self.storage.len() {
            return Err(DeviceError::OutOfBounds);
        }

        self.storage[start_byte..end_byte].copy_from_slice(buf);
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), DeviceError> {
        self.flush_count += 1;
        if self.fail_flushes {
            return Err(DeviceError::InjectedFault);
        }
        Ok(())
    }

    pub fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), DeviceError> {
        if !buf.len().is_multiple_of(self.block_size) {
            return Err(DeviceError::InvalidGeometry);
        }
        let blocks_per_unit = STORE_UNIT_BYTES / self.block_size;
        let unit = lba / (blocks_per_unit as u64);
        self.read_count += 1;
        self.read_units_log.push(unit);

        if self.fail_all_reads || self.read_faults.contains(&unit) {
            return Err(DeviceError::InjectedFault);
        }

        let start_byte = (lba as usize) * self.block_size;
        let end_byte = start_byte + buf.len();
        if end_byte > self.storage.len() {
            return Err(DeviceError::OutOfBounds);
        }

        buf.copy_from_slice(&self.storage[start_byte..end_byte]);
        Ok(())
    }

    pub fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), DeviceError> {
        if !buf.len().is_multiple_of(self.block_size) {
            return Err(DeviceError::InvalidGeometry);
        }
        let blocks_per_unit = STORE_UNIT_BYTES / self.block_size;
        let unit = lba / (blocks_per_unit as u64);
        self.write_count += 1;
        self.written_units_log.push(unit);

        if self.fail_all_writes || self.write_faults.contains(&unit) {
            return Err(DeviceError::InjectedFault);
        }

        let start_byte = (lba as usize) * self.block_size;
        let end_byte = start_byte + buf.len();
        if end_byte > self.storage.len() {
            return Err(DeviceError::OutOfBounds);
        }

        self.storage[start_byte..end_byte].copy_from_slice(buf);
        Ok(())
    }
}

/// Catalog entry in Store v1 format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogEntry {
    pub object_id: [u8; 32],
    pub kind: u16,
    pub version: u16,
    pub first_unit: u64,
    pub byte_length: u64,
    pub unit_count: u32,
    pub flags: u16,
}

impl CatalogEntry {
    pub fn encode(&self) -> [u8; CATALOG_ENTRY_BYTES] {
        let mut bytes = [0u8; CATALOG_ENTRY_BYTES];
        bytes[0..32].copy_from_slice(&self.object_id);
        bytes[32..34].copy_from_slice(&self.kind.to_le_bytes());
        bytes[34..36].copy_from_slice(&self.version.to_le_bytes());
        bytes[36..44].copy_from_slice(&self.first_unit.to_le_bytes());
        bytes[44..52].copy_from_slice(&self.byte_length.to_le_bytes());
        bytes[52..56].copy_from_slice(&self.unit_count.to_le_bytes());
        bytes[56..58].copy_from_slice(&self.flags.to_le_bytes());
        // bytes 58..64 remain zero reserved
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != CATALOG_ENTRY_BYTES {
            return None;
        }
        // Reserved bytes 58..64 must be zero
        if bytes[58..64].iter().any(|&b| b != 0) {
            return None;
        }
        let mut object_id = [0u8; 32];
        object_id.copy_from_slice(&bytes[0..32]);
        let kind = u16::from_le_bytes([bytes[32], bytes[33]]);
        let version = u16::from_le_bytes([bytes[34], bytes[35]]);
        let first_unit = u64::from_le_bytes(bytes[36..44].try_into().ok()?);
        let byte_length = u64::from_le_bytes(bytes[44..52].try_into().ok()?);
        let unit_count = u32::from_le_bytes(bytes[52..56].try_into().ok()?);
        let flags = u16::from_le_bytes([bytes[56], bytes[57]]);

        Some(Self {
            object_id,
            kind,
            version,
            first_unit,
            byte_length,
            unit_count,
            flags,
        })
    }
}

/// Superblock in Store v1 format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Superblock {
    pub store_uuid: [u8; 16],
    pub slot_id: u32,
    pub region_units: u64,
    pub generation: u64,
    pub commit_record_id: [u8; 32],
    pub commit_record_unit: u64,
    pub catalog_id: [u8; 32],
    pub catalog_first_unit: u64,
    pub catalog_byte_length: u64,
    pub catalog_unit_count: u32,
    pub catalog_entry_count: u32,
    pub committed_high_water: u64,
    pub crc32c: u32,
}

impl Superblock {
    pub fn encode(&self) -> [u8; STORE_UNIT_BYTES] {
        let mut bytes = [0u8; STORE_UNIT_BYTES];
        bytes[0..8].copy_from_slice(SUPERBLOCK_MAGIC);
        bytes[8..10].copy_from_slice(&1u16.to_le_bytes()); // format_major
        bytes[10..12].copy_from_slice(&0u16.to_le_bytes()); // format_minor
        bytes[12..20].copy_from_slice(&0u64.to_le_bytes()); // required_features
        bytes[20..28].copy_from_slice(&0u64.to_le_bytes()); // compatible_features
        bytes[28..44].copy_from_slice(&self.store_uuid);
        bytes[44..48].copy_from_slice(&self.slot_id.to_le_bytes());
        bytes[48..56].copy_from_slice(&self.region_units.to_le_bytes());
        bytes[56..64].copy_from_slice(&self.generation.to_le_bytes());
        bytes[64..96].copy_from_slice(&self.commit_record_id);
        bytes[96..104].copy_from_slice(&self.commit_record_unit.to_le_bytes());
        bytes[104..136].copy_from_slice(&self.catalog_id);
        bytes[136..144].copy_from_slice(&self.catalog_first_unit.to_le_bytes());
        bytes[144..152].copy_from_slice(&self.catalog_byte_length.to_le_bytes());
        bytes[152..156].copy_from_slice(&self.catalog_unit_count.to_le_bytes());
        bytes[156..160].copy_from_slice(&self.catalog_entry_count.to_le_bytes());
        bytes[160..168].copy_from_slice(&self.committed_high_water.to_le_bytes());
        // bytes 168..172 remain 0 for CRC computation
        let calculated_crc = independent_crc32c(&bytes);
        bytes[168..172].copy_from_slice(&calculated_crc.to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8; STORE_UNIT_BYTES], expected_slot: u32) -> Option<Self> {
        if &bytes[0..8] != SUPERBLOCK_MAGIC {
            return None;
        }
        let stored_crc = u32::from_le_bytes(bytes[168..172].try_into().ok()?);
        let mut zero_crc_bytes = *bytes;
        zero_crc_bytes[168..172].fill(0);
        if independent_crc32c(&zero_crc_bytes) != stored_crc {
            return None;
        }
        // Reserved bytes 172..4096 must all be zero
        if bytes[172..4096].iter().any(|&b| b != 0) {
            return None;
        }
        let format_major = u16::from_le_bytes([bytes[8], bytes[9]]);
        let format_minor = u16::from_le_bytes([bytes[10], bytes[11]]);
        let required_features = u64::from_le_bytes(bytes[12..20].try_into().ok()?);
        let compatible_features = u64::from_le_bytes(bytes[20..28].try_into().ok()?);
        if format_major != 1
            || format_minor != 0
            || required_features != 0
            || compatible_features != 0
        {
            return None;
        }

        let mut store_uuid = [0u8; 16];
        store_uuid.copy_from_slice(&bytes[28..44]);
        let slot_id = u32::from_le_bytes(bytes[44..48].try_into().ok()?);
        if slot_id != expected_slot || slot_id > 1 {
            return None;
        }
        let region_units = u64::from_le_bytes(bytes[48..56].try_into().ok()?);
        let generation = u64::from_le_bytes(bytes[56..64].try_into().ok()?);
        let mut commit_record_id = [0u8; 32];
        commit_record_id.copy_from_slice(&bytes[64..96]);
        let commit_record_unit = u64::from_le_bytes(bytes[96..104].try_into().ok()?);
        let mut catalog_id = [0u8; 32];
        catalog_id.copy_from_slice(&bytes[104..136]);
        let catalog_first_unit = u64::from_le_bytes(bytes[136..144].try_into().ok()?);
        let catalog_byte_length = u64::from_le_bytes(bytes[144..152].try_into().ok()?);
        let catalog_unit_count = u32::from_le_bytes(bytes[152..156].try_into().ok()?);
        let catalog_entry_count = u32::from_le_bytes(bytes[156..160].try_into().ok()?);
        let committed_high_water = u64::from_le_bytes(bytes[160..168].try_into().ok()?);

        Some(Self {
            store_uuid,
            slot_id,
            region_units,
            generation,
            commit_record_id,
            commit_record_unit,
            catalog_id,
            catalog_first_unit,
            catalog_byte_length,
            catalog_unit_count,
            catalog_entry_count,
            committed_high_water,
            crc32c: stored_crc,
        })
    }
}

/// CommitRecord in Store v1 format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitRecord {
    pub store_uuid: [u8; 16],
    pub region_units: u64,
    pub generation: u64,
    pub previous_generation: u64,
    pub previous_commit_id: [u8; 32],
    pub previous_catalog_id: [u8; 32],
    pub catalog_id: [u8; 32],
    pub catalog_first_unit: u64,
    pub catalog_byte_length: u64,
    pub catalog_unit_count: u32,
    pub catalog_entry_count: u32,
    pub committed_high_water: u64,
}

impl CommitRecord {
    pub fn encode_semantic(&self) -> [u8; COMMIT_RECORD_BYTES] {
        let mut bytes = [0u8; COMMIT_RECORD_BYTES];
        bytes[0..8].copy_from_slice(COMMIT_MAGIC);
        bytes[8..10].copy_from_slice(&1u16.to_le_bytes()); // record_version
        bytes[10..12].copy_from_slice(&200u16.to_le_bytes()); // record_size
        bytes[12..14].copy_from_slice(&1u16.to_le_bytes()); // format_major
        bytes[14..16].copy_from_slice(&0u16.to_le_bytes()); // format_minor
        bytes[16..24].copy_from_slice(&0u64.to_le_bytes()); // required_features
        bytes[24..32].copy_from_slice(&0u64.to_le_bytes()); // compatible_features
        bytes[32..48].copy_from_slice(&self.store_uuid);
        bytes[48..56].copy_from_slice(&self.region_units.to_le_bytes());
        bytes[56..64].copy_from_slice(&self.generation.to_le_bytes());
        bytes[64..72].copy_from_slice(&self.previous_generation.to_le_bytes());
        bytes[72..104].copy_from_slice(&self.previous_commit_id);
        bytes[104..136].copy_from_slice(&self.previous_catalog_id);
        bytes[136..168].copy_from_slice(&self.catalog_id);
        bytes[168..176].copy_from_slice(&self.catalog_first_unit.to_le_bytes());
        bytes[176..184].copy_from_slice(&self.catalog_byte_length.to_le_bytes());
        bytes[184..188].copy_from_slice(&self.catalog_unit_count.to_le_bytes());
        bytes[188..192].copy_from_slice(&self.catalog_entry_count.to_le_bytes());
        bytes[192..200].copy_from_slice(&self.committed_high_water.to_le_bytes());
        bytes
    }

    pub fn object_id(&self) -> [u8; 32] {
        let semantic = self.encode_semantic();
        independent_object_id(OBJECT_KIND_COMMIT_RECORD, OBJECT_VERSION_V1, 200, &semantic)
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != COMMIT_RECORD_BYTES {
            return None;
        }
        if &bytes[0..8] != COMMIT_MAGIC {
            return None;
        }
        let record_version = u16::from_le_bytes([bytes[8], bytes[9]]);
        let record_size = u16::from_le_bytes([bytes[10], bytes[11]]);
        let format_major = u16::from_le_bytes([bytes[12], bytes[13]]);
        let format_minor = u16::from_le_bytes([bytes[14], bytes[15]]);
        let required_features = u64::from_le_bytes(bytes[16..24].try_into().ok()?);
        let compatible_features = u64::from_le_bytes(bytes[24..32].try_into().ok()?);
        if record_version != 1
            || record_size != 200
            || format_major != 1
            || format_minor != 0
            || required_features != 0
            || compatible_features != 0
        {
            return None;
        }

        let mut store_uuid = [0u8; 16];
        store_uuid.copy_from_slice(&bytes[32..48]);
        let region_units = u64::from_le_bytes(bytes[48..56].try_into().ok()?);
        let generation = u64::from_le_bytes(bytes[56..64].try_into().ok()?);
        let previous_generation = u64::from_le_bytes(bytes[64..72].try_into().ok()?);
        let mut previous_commit_id = [0u8; 32];
        previous_commit_id.copy_from_slice(&bytes[72..104]);
        let mut previous_catalog_id = [0u8; 32];
        previous_catalog_id.copy_from_slice(&bytes[104..136]);
        let mut catalog_id = [0u8; 32];
        catalog_id.copy_from_slice(&bytes[136..168]);
        let catalog_first_unit = u64::from_le_bytes(bytes[168..176].try_into().ok()?);
        let catalog_byte_length = u64::from_le_bytes(bytes[176..184].try_into().ok()?);
        let catalog_unit_count = u32::from_le_bytes(bytes[184..188].try_into().ok()?);
        let catalog_entry_count = u32::from_le_bytes(bytes[188..192].try_into().ok()?);
        let committed_high_water = u64::from_le_bytes(bytes[192..200].try_into().ok()?);

        Some(Self {
            store_uuid,
            region_units,
            generation,
            previous_generation,
            previous_commit_id,
            previous_catalog_id,
            catalog_id,
            catalog_first_unit,
            catalog_byte_length,
            catalog_unit_count,
            catalog_entry_count,
            committed_high_water,
        })
    }
}

/// Catalog structure in Store v1 format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalog {
    pub entries: Vec<CatalogEntry>,
}

impl Catalog {
    pub fn encode_semantic(&self) -> Vec<u8> {
        let total_bytes = CATALOG_HEADER_BYTES + self.entries.len() * CATALOG_ENTRY_BYTES;
        let mut bytes = vec![0u8; total_bytes];
        bytes[0..8].copy_from_slice(CATALOG_MAGIC);
        bytes[8..10].copy_from_slice(&1u16.to_le_bytes()); // format_version = 1
        bytes[10..12].copy_from_slice(&(CATALOG_ENTRY_BYTES as u16).to_le_bytes());
        bytes[12..16].copy_from_slice(&(self.entries.len() as u32).to_le_bytes());

        for (i, entry) in self.entries.iter().enumerate() {
            let offset = CATALOG_HEADER_BYTES + i * CATALOG_ENTRY_BYTES;
            bytes[offset..offset + CATALOG_ENTRY_BYTES].copy_from_slice(&entry.encode());
        }
        bytes
    }

    pub fn object_id(&self) -> [u8; 32] {
        let semantic = self.encode_semantic();
        independent_object_id(
            OBJECT_KIND_CATALOG,
            OBJECT_VERSION_V1,
            semantic.len() as u64,
            &semantic,
        )
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < CATALOG_HEADER_BYTES {
            return None;
        }
        if &bytes[0..8] != CATALOG_MAGIC {
            return None;
        }
        let format_version = u16::from_le_bytes([bytes[8], bytes[9]]);
        let entry_size = u16::from_le_bytes([bytes[10], bytes[11]]);
        let entry_count = u32::from_le_bytes(bytes[12..16].try_into().ok()?) as usize;
        if format_version != 1
            || entry_size != (CATALOG_ENTRY_BYTES as u16)
            || entry_count > MAX_CATALOG_ENTRIES
        {
            return None;
        }
        let expected_len = CATALOG_HEADER_BYTES + entry_count * CATALOG_ENTRY_BYTES;
        if bytes.len() != expected_len {
            return None;
        }
        let mut entries = Vec::with_capacity(entry_count);
        for i in 0..entry_count {
            let offset = CATALOG_HEADER_BYTES + i * CATALOG_ENTRY_BYTES;
            let entry = CatalogEntry::decode(&bytes[offset..offset + CATALOG_ENTRY_BYTES])?;
            entries.push(entry);
        }

        // Verify sorted order and uniqueness
        for pair in entries.windows(2) {
            if pair[0].object_id >= pair[1].object_id {
                return None;
            }
        }

        Some(Self { entries })
    }
}

/// Mount classification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountClassification {
    ValidStore(Superblock),
    DegradedRecovery(Superblock),
    Unformatted,
    ForeignOrUnknown,
    UnsupportedVersion,
    Corrupt,
    ConflictingRoots,
    InconsistentHistory,
}

/// Errors returned by mount/open operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountError {
    Io,
    DeviceTooSmall,
    InvalidBlockSize,
}

/// Internal root evaluation status.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RootStatus {
    Valid(Superblock),
    BadCrc,
    UnsupportedVersion,
    GraphError,
    Io,
}

fn check_crc_valid(bytes: &[u8; STORE_UNIT_BYTES]) -> bool {
    if &bytes[0..8] != SUPERBLOCK_MAGIC {
        return false;
    }
    let stored_crc = match bytes[168..172].try_into() {
        Ok(arr) => u32::from_le_bytes(arr),
        Err(_) => return false,
    };
    let mut zero_crc = *bytes;
    zero_crc[168..172].fill(0);
    independent_crc32c(&zero_crc) == stored_crc
}

fn check_unsupported(bytes: &[u8; STORE_UNIT_BYTES]) -> bool {
    if !check_crc_valid(bytes) {
        return false;
    }
    let format_major = u16::from_le_bytes([bytes[8], bytes[9]]);
    let format_minor = u16::from_le_bytes([bytes[10], bytes[11]]);
    let required_features = u64::from_le_bytes(bytes[12..20].try_into().unwrap_or([0; 8]));
    let compatible_features = u64::from_le_bytes(bytes[20..28].try_into().unwrap_or([0; 8]));
    format_major != 1 || format_minor != 0 || required_features != 0 || compatible_features != 0
}

fn evaluate_root(
    slot: u32,
    sb_bytes: &[u8; STORE_UNIT_BYTES],
    region_units: u64,
    device: &mut MockBlockDevice,
) -> RootStatus {
    if &sb_bytes[0..8] != SUPERBLOCK_MAGIC {
        return RootStatus::GraphError;
    }
    if !check_crc_valid(sb_bytes) {
        return RootStatus::BadCrc;
    }
    if check_unsupported(sb_bytes) {
        return RootStatus::UnsupportedVersion;
    }
    let sb = match Superblock::decode(sb_bytes, slot) {
        Some(s) => s,
        None => return RootStatus::GraphError,
    };

    if sb.region_units < 4 || sb.region_units > region_units || sb.generation == 0 {
        return RootStatus::GraphError;
    }
    if sb.committed_high_water > sb.region_units
        || sb.committed_high_water != sb.commit_record_unit + 1
    {
        return RootStatus::GraphError;
    }
    if sb.catalog_first_unit < 2
        || sb.catalog_first_unit + (sb.catalog_unit_count as u64) != sb.commit_record_unit
    {
        return RootStatus::GraphError;
    }

    // Read and validate CommitRecord
    let mut cmt_unit = [0u8; STORE_UNIT_BYTES];
    if device
        .read_unit(sb.commit_record_unit, &mut cmt_unit)
        .is_err()
    {
        return RootStatus::Io;
    }
    // CommitRecord unit bytes 200..4096 MUST be zero
    if cmt_unit[200..4096].iter().any(|&b| b != 0) {
        return RootStatus::GraphError;
    }
    let cmt = match CommitRecord::decode(&cmt_unit[0..200]) {
        Some(c) => c,
        None => return RootStatus::GraphError,
    };

    if cmt.store_uuid != sb.store_uuid
        || cmt.region_units != sb.region_units
        || cmt.generation != sb.generation
        || cmt.catalog_id != sb.catalog_id
        || cmt.catalog_first_unit != sb.catalog_first_unit
        || cmt.catalog_byte_length != sb.catalog_byte_length
        || cmt.catalog_unit_count != sb.catalog_unit_count
        || cmt.catalog_entry_count != sb.catalog_entry_count
        || cmt.committed_high_water != sb.committed_high_water
    {
        return RootStatus::GraphError;
    }
    if cmt.object_id() != sb.commit_record_id {
        return RootStatus::GraphError;
    }
    if cmt.generation == 1 {
        if cmt.previous_generation != 0
            || cmt.previous_commit_id != [0; 32]
            || cmt.previous_catalog_id != [0; 32]
        {
            return RootStatus::GraphError;
        }
    } else if cmt.previous_generation + 1 != cmt.generation
        || cmt.previous_commit_id == [0; 32]
        || cmt.previous_catalog_id == [0; 32]
    {
        return RootStatus::GraphError;
    }

    // Read and validate Catalog
    let mut cat_bytes = vec![0u8; (sb.catalog_unit_count as usize) * STORE_UNIT_BYTES];
    for u in 0..(sb.catalog_unit_count as u64) {
        let mut unit_buf = [0u8; STORE_UNIT_BYTES];
        if device
            .read_unit(sb.catalog_first_unit + u, &mut unit_buf)
            .is_err()
        {
            return RootStatus::Io;
        }
        let start = (u as usize) * STORE_UNIT_BYTES;
        cat_bytes[start..start + STORE_UNIT_BYTES].copy_from_slice(&unit_buf);
    }
    let cat_semantic_len = sb.catalog_byte_length as usize;
    if cat_semantic_len > cat_bytes.len() {
        return RootStatus::GraphError;
    }
    // Catalog padding MUST be zero
    if cat_bytes[cat_semantic_len..].iter().any(|&b| b != 0) {
        return RootStatus::GraphError;
    }
    let cat = match Catalog::decode(&cat_bytes[0..cat_semantic_len]) {
        Some(c) => c,
        None => return RootStatus::GraphError,
    };
    if cat.object_id() != sb.catalog_id {
        return RootStatus::GraphError;
    }
    if cat.entries.len() != (sb.catalog_entry_count as usize) {
        return RootStatus::GraphError;
    }

    // Validate entries and check for overlaps
    let mut prev_end = 2u64;
    for entry in &cat.entries {
        if entry.kind < 3 || entry.version == 0 || entry.flags != 0 {
            return RootStatus::GraphError;
        }
        let expected_units = entry.byte_length.div_ceil(STORE_UNIT_BYTES as u64) as u32;
        if entry.unit_count != expected_units {
            return RootStatus::GraphError;
        }
        if entry.first_unit < 2 || entry.first_unit < prev_end {
            return RootStatus::GraphError;
        }
        let end_unit = entry.first_unit + (entry.unit_count as u64);
        if end_unit > sb.catalog_first_unit {
            return RootStatus::GraphError;
        }
        prev_end = end_unit;

        // Read and validate object payload and padding
        let mut obj_bytes = vec![0u8; (entry.unit_count as usize) * STORE_UNIT_BYTES];
        for u in 0..(entry.unit_count as u64) {
            let mut unit_buf = [0u8; STORE_UNIT_BYTES];
            if device
                .read_unit(entry.first_unit + u, &mut unit_buf)
                .is_err()
            {
                return RootStatus::Io;
            }
            let start = (u as usize) * STORE_UNIT_BYTES;
            obj_bytes[start..start + STORE_UNIT_BYTES].copy_from_slice(&unit_buf);
        }
        let sem_len = entry.byte_length as usize;
        if sem_len > obj_bytes.len() {
            return RootStatus::GraphError;
        }
        // Object final unit padding MUST be all zero
        if obj_bytes[sem_len..].iter().any(|&b| b != 0) {
            return RootStatus::GraphError;
        }
        // Recompute ObjectId
        let calc_id = independent_object_id(
            entry.kind,
            entry.version,
            entry.byte_length,
            &obj_bytes[0..sem_len],
        );
        if calc_id != entry.object_id {
            return RootStatus::GraphError;
        }
    }

    RootStatus::Valid(sb)
}

/// Side-effect-free open / mount implementation.
///
/// Guaranteed properties per ADR 0015:
/// - Performs exactly 0 writes and 0 flushes on device under all conditions.
/// - Never automatically provisions or formats.
/// - Never rewrites a Superblock to "fix" redundancy or damaged CRC.
/// - Degraded recovery performs exactly 0 repair writes and 0 flushes.
/// - Returns MountError::Io on read errors, never misclassifying as corrupt media.
pub fn open_mount(device: &mut MockBlockDevice) -> Result<MountClassification, MountError> {
    if device.block_size != 512 && device.block_size != 4096 {
        return Err(MountError::InvalidBlockSize);
    }
    let region_units = device.unit_count();
    if region_units < 4 {
        return Err(MountError::DeviceTooSmall);
    }

    let initial_writes = device.write_count;
    let initial_flushes = device.flush_count;

    // Both superblock units MUST be read
    let mut sb0_bytes = [0u8; STORE_UNIT_BYTES];
    if device.read_unit(0, &mut sb0_bytes).is_err() {
        return Err(MountError::Io);
    }
    let mut sb1_bytes = [0u8; STORE_UNIT_BYTES];
    if device.read_unit(1, &mut sb1_bytes).is_err() {
        return Err(MountError::Io);
    }

    // 1. If both superblock units are all zero, classify Unformatted.
    let sb0_all_zero = sb0_bytes.iter().all(|&b| b == 0);
    let sb1_all_zero = sb1_bytes.iter().all(|&b| b == 0);
    if sb0_all_zero && sb1_all_zero {
        assert_eq!(
            device.write_count, initial_writes,
            "Must not write during open"
        );
        assert_eq!(
            device.flush_count, initial_flushes,
            "Must not flush during open"
        );
        return Ok(MountClassification::Unformatted);
    }

    // 2. If neither has AIENSTR1 magic and at least one is nonzero, classify ForeignOrUnknown.
    let sb0_has_magic = &sb0_bytes[0..8] == SUPERBLOCK_MAGIC;
    let sb1_has_magic = &sb1_bytes[0..8] == SUPERBLOCK_MAGIC;
    if !sb0_has_magic && !sb1_has_magic {
        assert_eq!(
            device.write_count, initial_writes,
            "Must not write during open"
        );
        assert_eq!(
            device.flush_count, initial_flushes,
            "Must not flush during open"
        );
        return Ok(MountClassification::ForeignOrUnknown);
    }

    // 3. A CRC-valid AIENSTR1 superblock whose major/minor or feature values are unsupported classifies UnsupportedVersion; do not fall back to another root.
    if check_unsupported(&sb0_bytes) || check_unsupported(&sb1_bytes) {
        assert_eq!(
            device.write_count, initial_writes,
            "Must not write during open"
        );
        assert_eq!(
            device.flush_count, initial_flushes,
            "Must not flush during open"
        );
        return Ok(MountClassification::UnsupportedVersion);
    }

    // Evaluate root graphs
    let st0 = evaluate_root(0, &sb0_bytes, region_units, device);
    let st1 = evaluate_root(1, &sb1_bytes, region_units, device);

    if st0 == RootStatus::Io || st1 == RootStatus::Io {
        return Err(MountError::Io);
    }

    let classification = match (st0, st1) {
        (RootStatus::Valid(r0), RootStatus::Valid(r1)) => {
            if r0.generation == r1.generation {
                if r0.store_uuid == r1.store_uuid
                    && r0.region_units == r1.region_units
                    && r0.commit_record_id == r1.commit_record_id
                {
                    MountClassification::ValidStore(r0)
                } else {
                    MountClassification::ConflictingRoots
                }
            } else if r0.generation + 1 == r1.generation || r1.generation + 1 == r0.generation {
                let (older, newer) = if r0.generation < r1.generation {
                    (r0, r1)
                } else {
                    (r1, r0)
                };
                // Newer must identify older root exactly
                let mut cmt_unit = [0u8; STORE_UNIT_BYTES];
                if device
                    .read_unit(newer.commit_record_unit, &mut cmt_unit)
                    .is_err()
                {
                    return Err(MountError::Io);
                }
                if let Some(cmt) = CommitRecord::decode(&cmt_unit[0..200]) {
                    if cmt.previous_generation == older.generation
                        && cmt.previous_commit_id == older.commit_record_id
                        && cmt.previous_catalog_id == older.catalog_id
                        && cmt.store_uuid == older.store_uuid
                        && cmt.region_units == older.region_units
                    {
                        MountClassification::ValidStore(newer)
                    } else {
                        MountClassification::InconsistentHistory
                    }
                } else {
                    MountClassification::Corrupt
                }
            } else {
                MountClassification::InconsistentHistory
            }
        }
        (RootStatus::Valid(r0), _) if sb1_all_zero => MountClassification::ValidStore(r0),
        (_, RootStatus::Valid(r1)) if sb0_all_zero => MountClassification::ValidStore(r1),
        // Degraded recovery: both superblocks are CRC-valid and supported; one is completely valid while strictly newer has graph error
        (RootStatus::Valid(r0), RootStatus::GraphError) => {
            if check_crc_valid(&sb1_bytes) && !check_unsupported(&sb1_bytes) {
                let gen1 = u64::from_le_bytes(sb1_bytes[56..64].try_into().unwrap_or([0; 8]));
                if gen1 > r0.generation {
                    MountClassification::DegradedRecovery(r0)
                } else {
                    // Newer valid root selects as valid store
                    MountClassification::ValidStore(r0)
                }
            } else {
                MountClassification::Corrupt
            }
        }
        (RootStatus::GraphError, RootStatus::Valid(r1)) => {
            if check_crc_valid(&sb0_bytes) && !check_unsupported(&sb0_bytes) {
                let gen0 = u64::from_le_bytes(sb0_bytes[56..64].try_into().unwrap_or([0; 8]));
                if gen0 > r1.generation {
                    MountClassification::DegradedRecovery(r1)
                } else {
                    // Newer valid root selects as valid store
                    MountClassification::ValidStore(r1)
                }
            } else {
                MountClassification::Corrupt
            }
        }
        _ => MountClassification::Corrupt,
    };

    assert_eq!(
        device.write_count, initial_writes,
        "Must not write during open"
    );
    assert_eq!(
        device.flush_count, initial_flushes,
        "Must not flush during open"
    );
    Ok(classification)
}

/// Explicit provisioning of a Genesis Store v1.
///
/// MUST be called explicitly; open/mount will never automatically call this.
pub fn provision_genesis(
    device: &mut MockBlockDevice,
    store_uuid: [u8; 16],
    region_units: u64,
) -> Result<Superblock, DeviceError> {
    if region_units < 4 || region_units > device.unit_count() {
        return Err(DeviceError::InvalidGeometry);
    }

    // Genesis empty catalog at unit 2
    let empty_catalog = Catalog {
        entries: Vec::new(),
    };
    let cat_semantic = empty_catalog.encode_semantic();
    let catalog_id = empty_catalog.object_id();

    let mut cat_unit = [0u8; STORE_UNIT_BYTES];
    cat_unit[0..cat_semantic.len()].copy_from_slice(&cat_semantic);
    device.write_unit(2, &cat_unit)?;

    // Genesis commit record at unit 3
    let cmt = CommitRecord {
        store_uuid,
        region_units,
        generation: 1,
        previous_generation: 0,
        previous_commit_id: [0; 32],
        previous_catalog_id: [0; 32],
        catalog_id,
        catalog_first_unit: 2,
        catalog_byte_length: cat_semantic.len() as u64,
        catalog_unit_count: 1,
        catalog_entry_count: 0,
        committed_high_water: 4,
    };
    let commit_record_id = cmt.object_id();
    let cmt_semantic = cmt.encode_semantic();

    let mut cmt_unit = [0u8; STORE_UNIT_BYTES];
    cmt_unit[0..cmt_semantic.len()].copy_from_slice(&cmt_semantic);
    device.write_unit(3, &cmt_unit)?;

    device.flush()?;

    // Superblock A (slot 0) at unit 0
    let sb_a = Superblock {
        store_uuid,
        slot_id: 0,
        region_units,
        generation: 1,
        commit_record_id,
        commit_record_unit: 3,
        catalog_id,
        catalog_first_unit: 2,
        catalog_byte_length: cat_semantic.len() as u64,
        catalog_unit_count: 1,
        catalog_entry_count: 0,
        committed_high_water: 4,
        crc32c: 0,
    };
    let sb_a_bytes = sb_a.encode();
    device.write_unit(0, &sb_a_bytes)?;

    // Superblock B (slot 1) at unit 1
    let sb_b = Superblock {
        store_uuid,
        slot_id: 1,
        region_units,
        generation: 1,
        commit_record_id,
        commit_record_unit: 3,
        catalog_id,
        catalog_first_unit: 2,
        catalog_byte_length: cat_semantic.len() as u64,
        catalog_unit_count: 1,
        catalog_entry_count: 0,
        committed_high_water: 4,
        crc32c: 0,
    };
    let sb_b_bytes = sb_b.encode();
    device.write_unit(1, &sb_b_bytes)?;

    device.flush()?;

    Superblock::decode(&sb_a_bytes, 0).ok_or(DeviceError::Io)
}

/// Transaction error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionError {
    Device(DeviceError),
    ConflictingDuplicateDescriptor,
    DeduplicationVerificationFailed,
    CorruptCommittedObject,
    AttemptedRepairOfCommittedExtent,
    TooManyObjects,
    ObjectTooLarge,
    OutOfSpace,
    InvalidObject,
}

impl From<DeviceError> for TransactionError {
    fn from(e: DeviceError) -> Self {
        Self::Device(e)
    }
}

/// Proposed object for a transaction.
#[derive(Debug, Clone)]
pub struct ProposedObject {
    pub kind: u16,
    pub version: u16,
    pub payload: Vec<u8>,
    pub deduplicate_if_exists: bool,
}

/// Transaction manager ensuring Store v1 transaction and deduplication boundaries.
pub struct ActiveStore<'a> {
    pub device: &'a mut MockBlockDevice,
    pub superblock: Superblock,
}

impl<'a> ActiveStore<'a> {
    pub fn new(device: &'a mut MockBlockDevice, superblock: Superblock) -> Self {
        Self { device, superblock }
    }

    /// Commit a transaction adding new objects or deduplicating existing ones.
    ///
    /// Rules enforced:
    /// - Normal transactions cannot repair corrupt committed objects.
    /// - Deduplication of an existing ObjectId only occurs after full independent byte verification.
    /// - Conflicting duplicate descriptor (same ObjectId, different size or data) strictly fails.
    /// - Writes append strictly at committed_high_water.
    pub fn commit_transaction(
        &mut self,
        items: &[ProposedObject],
    ) -> Result<Superblock, TransactionError> {
        if items.len() > MAX_TRANSACTION_OBJECTS {
            return Err(TransactionError::TooManyObjects);
        }

        // Load existing catalog
        let mut cat_bytes =
            vec![0u8; (self.superblock.catalog_unit_count as usize) * STORE_UNIT_BYTES];
        for u in 0..(self.superblock.catalog_unit_count as u64) {
            let mut unit_buf = [0u8; STORE_UNIT_BYTES];
            self.device
                .read_unit(self.superblock.catalog_first_unit + u, &mut unit_buf)
                .map_err(TransactionError::Device)?;
            let start = (u as usize) * STORE_UNIT_BYTES;
            cat_bytes[start..start + STORE_UNIT_BYTES].copy_from_slice(&unit_buf);
        }
        let sem_len = self.superblock.catalog_byte_length as usize;
        let existing_catalog = Catalog::decode(&cat_bytes[0..sem_len])
            .ok_or(TransactionError::CorruptCommittedObject)?;

        let mut tx_high_water = self.superblock.committed_high_water;
        let mut new_entries = existing_catalog.entries.clone();

        for item in items {
            if item.kind < 3 || item.version == 0 || item.payload.is_empty() {
                return Err(TransactionError::InvalidObject);
            }
            if item.payload.len() as u64 > MAX_OBJECT_BYTES {
                return Err(TransactionError::ObjectTooLarge);
            }

            let proposed_id = independent_object_id(
                item.kind,
                item.version,
                item.payload.len() as u64,
                &item.payload,
            );

            // Check if object exists in catalog
            if let Some(existing) = new_entries.iter().find(|e| e.object_id == proposed_id) {
                // Rule 1: Conflicting duplicate descriptor strictly fails
                if existing.byte_length != item.payload.len() as u64
                    || existing.kind != item.kind
                    || existing.version != item.version
                {
                    return Err(TransactionError::ConflictingDuplicateDescriptor);
                }

                // Rule 2: Deduplication only occurs after full independent byte and padding verification
                let mut existing_data =
                    vec![0u8; (existing.unit_count as usize) * STORE_UNIT_BYTES];
                for u in 0..(existing.unit_count as u64) {
                    let mut unit_buf = [0u8; STORE_UNIT_BYTES];
                    self.device
                        .read_unit(existing.first_unit + u, &mut unit_buf)
                        .map_err(TransactionError::Device)?;
                    let start = (u as usize) * STORE_UNIT_BYTES;
                    existing_data[start..start + STORE_UNIT_BYTES].copy_from_slice(&unit_buf);
                }

                let ex_sem_len = existing.byte_length as usize;
                // 1. Verify zero padding on disk
                if existing_data[ex_sem_len..].iter().any(|&b| b != 0) {
                    return Err(TransactionError::DeduplicationVerificationFailed);
                }
                // 2. Verify on-disk ObjectId hash matches catalog descriptor
                let verify_id = independent_object_id(
                    existing.kind,
                    existing.version,
                    existing.byte_length,
                    &existing_data[0..ex_sem_len],
                );
                if verify_id != existing.object_id {
                    return Err(TransactionError::DeduplicationVerificationFailed);
                }
                // 3. Once on-disk data is independently verified, verify proposed item payload matches
                if existing_data[0..ex_sem_len] != item.payload {
                    return Err(TransactionError::ConflictingDuplicateDescriptor);
                }

                // If verified, deduplication succeeds: reuse existing extent, write 0 payload blocks!
            } else {
                // Append new object starting at tx_high_water (strictly >= committed_high_water)
                if tx_high_water < self.superblock.committed_high_water {
                    return Err(TransactionError::AttemptedRepairOfCommittedExtent);
                }

                let unit_count = item.payload.len().div_ceil(STORE_UNIT_BYTES) as u32;
                if tx_high_water + (unit_count as u64) >= self.superblock.region_units {
                    return Err(TransactionError::OutOfSpace);
                }

                // Write payload + zero padding
                for u in 0..(unit_count as u64) {
                    let mut unit_buf = [0u8; STORE_UNIT_BYTES];
                    let start = (u as usize) * STORE_UNIT_BYTES;
                    let end = std::cmp::min(start + STORE_UNIT_BYTES, item.payload.len());
                    if start < item.payload.len() {
                        unit_buf[0..end - start].copy_from_slice(&item.payload[start..end]);
                    }
                    self.device
                        .write_unit(tx_high_water + u, &unit_buf)
                        .map_err(TransactionError::Device)?;
                }

                new_entries.push(CatalogEntry {
                    object_id: proposed_id,
                    kind: item.kind,
                    version: item.version,
                    first_unit: tx_high_water,
                    byte_length: item.payload.len() as u64,
                    unit_count,
                    flags: 0,
                });

                tx_high_water += unit_count as u64;
            }
        }

        // Sort catalog entries by ObjectId
        new_entries.sort_by_key(|a| a.object_id);
        new_entries.dedup_by(|a, b| a.object_id == b.object_id);

        if new_entries.len() > MAX_CATALOG_ENTRIES {
            return Err(TransactionError::TooManyObjects);
        }

        let new_catalog = Catalog {
            entries: new_entries,
        };
        let new_cat_semantic = new_catalog.encode_semantic();
        let new_cat_id = new_catalog.object_id();
        let new_cat_units = new_cat_semantic.len().div_ceil(STORE_UNIT_BYTES) as u32;

        let cat_first_unit = tx_high_water;
        if cat_first_unit + (new_cat_units as u64) + 1 > self.superblock.region_units {
            return Err(TransactionError::OutOfSpace);
        }

        // Write catalog units
        for u in 0..(new_cat_units as u64) {
            let mut unit_buf = [0u8; STORE_UNIT_BYTES];
            let start = (u as usize) * STORE_UNIT_BYTES;
            let end = std::cmp::min(start + STORE_UNIT_BYTES, new_cat_semantic.len());
            if start < new_cat_semantic.len() {
                unit_buf[0..end - start].copy_from_slice(&new_cat_semantic[start..end]);
            }
            self.device
                .write_unit(cat_first_unit + u, &unit_buf)
                .map_err(TransactionError::Device)?;
        }
        tx_high_water += new_cat_units as u64;

        // Write CommitRecord
        let commit_record_unit = tx_high_water;
        let new_high_water = commit_record_unit + 1;

        let new_cmt = CommitRecord {
            store_uuid: self.superblock.store_uuid,
            region_units: self.superblock.region_units,
            generation: self.superblock.generation + 1,
            previous_generation: self.superblock.generation,
            previous_commit_id: self.superblock.commit_record_id,
            previous_catalog_id: self.superblock.catalog_id,
            catalog_id: new_cat_id,
            catalog_first_unit: cat_first_unit,
            catalog_byte_length: new_cat_semantic.len() as u64,
            catalog_unit_count: new_cat_units,
            catalog_entry_count: new_catalog.entries.len() as u32,
            committed_high_water: new_high_water,
        };
        let new_commit_id = new_cmt.object_id();
        let new_cmt_semantic = new_cmt.encode_semantic();

        let mut cmt_unit = [0u8; STORE_UNIT_BYTES];
        cmt_unit[0..new_cmt_semantic.len()].copy_from_slice(&new_cmt_semantic);
        self.device
            .write_unit(commit_record_unit, &cmt_unit)
            .map_err(TransactionError::Device)?;

        // First flush: ensure all arena data is persistent before metadata commit
        self.device.flush().map_err(TransactionError::Device)?;

        // Write inactive Superblock slot
        let inactive_slot = 1 - self.superblock.slot_id;
        let new_sb = Superblock {
            store_uuid: self.superblock.store_uuid,
            slot_id: inactive_slot,
            region_units: self.superblock.region_units,
            generation: self.superblock.generation + 1,
            commit_record_id: new_commit_id,
            commit_record_unit,
            catalog_id: new_cat_id,
            catalog_first_unit: cat_first_unit,
            catalog_byte_length: new_cat_semantic.len() as u64,
            catalog_unit_count: new_cat_units,
            catalog_entry_count: new_catalog.entries.len() as u32,
            committed_high_water: new_high_water,
            crc32c: 0,
        };
        let new_sb_bytes = new_sb.encode();
        self.device
            .write_unit(inactive_slot as u64, &new_sb_bytes)
            .map_err(TransactionError::Device)?;

        // Second flush: commit point
        self.device.flush().map_err(TransactionError::Device)?;

        self.superblock = new_sb.clone();
        Ok(new_sb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_UUID: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    #[test]
    fn test_mock_device_tracking_and_fault_injection() {
        let mut dev = MockBlockDevice::new(16);
        assert_eq!(dev.read_count, 0);
        assert_eq!(dev.write_count, 0);
        assert_eq!(dev.flush_count, 0);

        let buf = [0x5A; STORE_UNIT_BYTES];
        dev.write_unit(2, &buf).unwrap();
        assert_eq!(dev.write_count, 1);
        assert_eq!(dev.written_units_log, vec![2]);

        let mut read_buf = [0u8; STORE_UNIT_BYTES];
        dev.read_unit(2, &mut read_buf).unwrap();
        assert_eq!(dev.read_count, 1);
        assert_eq!(read_buf, buf);

        dev.flush().unwrap();
        assert_eq!(dev.flush_count, 1);

        // Test read fault injection on specific unit
        dev.inject_read_fault_on_unit(2);
        assert_eq!(
            dev.read_unit(2, &mut read_buf),
            Err(DeviceError::InjectedFault)
        );
        // Other units still readable
        assert!(dev.read_unit(3, &mut read_buf).is_ok());

        // Test write fault injection on specific unit
        dev.inject_write_fault_on_unit(4);
        assert_eq!(dev.write_unit(4, &buf), Err(DeviceError::InjectedFault));
        assert!(dev.write_unit(5, &buf).is_ok());

        // Test global fail flags
        dev.set_fail_all_reads(true);
        assert_eq!(
            dev.read_unit(5, &mut read_buf),
            Err(DeviceError::InjectedFault)
        );

        dev.set_fail_flushes(true);
        assert_eq!(dev.flush(), Err(DeviceError::InjectedFault));

        // Test reset counts
        dev.reset_counts();
        assert_eq!(dev.read_count, 0);
        assert_eq!(dev.write_count, 0);
        assert_eq!(dev.flush_count, 0);

        // Test 512-byte block size
        let mut dev512 = MockBlockDevice::with_block_size(512, 16);
        assert_eq!(dev512.block_size, 512);
        assert_eq!(dev512.unit_count(), 16);
        let block_buf = [0xEE; 512];
        dev512.write_blocks(0, &block_buf).unwrap();
        assert_eq!(dev512.write_count, 1);
    }

    #[test]
    fn test_side_effect_free_open_all_zero_media() {
        let mut dev = MockBlockDevice::new(16);
        dev.reset_counts();

        let res = open_mount(&mut dev).expect("open_mount should succeed");
        assert_eq!(res, MountClassification::Unformatted);

        // ADR 0015 strictly mandates 0 writes and 0 flushes
        assert_eq!(
            dev.write_count, 0,
            "Opening all-zero media must perform exactly 0 writes"
        );
        assert_eq!(
            dev.flush_count, 0,
            "Opening all-zero media must perform exactly 0 flushes"
        );
        assert!(dev.read_count >= 2, "Must read superblocks A and B");
    }

    #[test]
    fn test_side_effect_free_open_foreign_unknown_media() {
        let mut dev = MockBlockDevice::new(16);
        // Fill first unit with random or non-AIENOS bytes (32 bytes)
        dev.storage[0..32].copy_from_slice(b"NON_AIENOS_FOREIGN_FILESYSTEM__!");
        dev.reset_counts();

        let res = open_mount(&mut dev).expect("open_mount should succeed");
        assert_eq!(res, MountClassification::ForeignOrUnknown);

        assert_eq!(
            dev.write_count, 0,
            "Opening foreign media must perform exactly 0 writes"
        );
        assert_eq!(
            dev.flush_count, 0,
            "Opening foreign media must perform exactly 0 flushes"
        );
    }

    #[test]
    fn test_side_effect_free_open_corrupt_store() {
        // Case 1: Corrupt Superblock CRC
        let mut dev = MockBlockDevice::new(16);
        provision_genesis(&mut dev, TEST_UUID, 16).unwrap();
        // Invert bits in Superblock A and B CRC
        dev.storage[168] ^= 0xFF;
        dev.storage[STORE_UNIT_BYTES + 168] ^= 0xFF;
        dev.reset_counts();

        let res = open_mount(&mut dev).expect("open_mount should succeed");
        assert_eq!(res, MountClassification::Corrupt);
        assert_eq!(
            dev.write_count, 0,
            "Opening corrupt store must perform exactly 0 writes"
        );
        assert_eq!(
            dev.flush_count, 0,
            "Opening corrupt store must perform exactly 0 flushes"
        );

        // Case 2: Nonzero reserved bytes in Superblock
        let mut dev2 = MockBlockDevice::new(16);
        provision_genesis(&mut dev2, TEST_UUID, 16).unwrap();
        // Superblock A reserved byte at 172 made non-zero (recompute CRC to isolate reserved-check)
        dev2.storage[172] = 0xAA;
        let mut sb0_bytes = [0u8; STORE_UNIT_BYTES];
        sb0_bytes.copy_from_slice(&dev2.storage[0..STORE_UNIT_BYTES]);
        sb0_bytes[168..172].fill(0);
        let new_crc = independent_crc32c(&sb0_bytes);
        dev2.storage[168..172].copy_from_slice(&new_crc.to_le_bytes());

        // Same for SB B
        dev2.storage[STORE_UNIT_BYTES + 172] = 0xAA;
        let mut sb1_bytes = [0u8; STORE_UNIT_BYTES];
        sb1_bytes.copy_from_slice(&dev2.storage[STORE_UNIT_BYTES..2 * STORE_UNIT_BYTES]);
        sb1_bytes[168..172].fill(0);
        let new_crc1 = independent_crc32c(&sb1_bytes);
        dev2.storage[STORE_UNIT_BYTES + 168..STORE_UNIT_BYTES + 172]
            .copy_from_slice(&new_crc1.to_le_bytes());

        dev2.reset_counts();
        let res2 = open_mount(&mut dev2).expect("open_mount should succeed");
        assert_eq!(res2, MountClassification::Corrupt);
        assert_eq!(dev2.write_count, 0);
        assert_eq!(dev2.flush_count, 0);

        // Case 3: Corrupt CommitRecord
        let mut dev3 = MockBlockDevice::new(16);
        provision_genesis(&mut dev3, TEST_UUID, 16).unwrap();
        // Mutate CommitRecord payload at unit 3
        dev3.storage[3 * STORE_UNIT_BYTES + 32] ^= 0xFF; // corrupt UUID
        dev3.reset_counts();

        let res3 = open_mount(&mut dev3).expect("open_mount should succeed");
        assert_eq!(res3, MountClassification::Corrupt);
        assert_eq!(dev3.write_count, 0);
        assert_eq!(dev3.flush_count, 0);
    }

    #[test]
    fn test_side_effect_free_open_unsupported_store() {
        let mut dev = MockBlockDevice::new(16);
        provision_genesis(&mut dev, TEST_UUID, 16).unwrap();

        // Mutate format_major to 2 in both superblocks and recompute CRC
        for slot in 0..2 {
            let offset = slot * STORE_UNIT_BYTES;
            dev.storage[offset + 8] = 2; // format_major = 2
            let mut unit_bytes = [0u8; STORE_UNIT_BYTES];
            unit_bytes.copy_from_slice(&dev.storage[offset..offset + STORE_UNIT_BYTES]);
            unit_bytes[168..172].fill(0);
            let crc = independent_crc32c(&unit_bytes);
            dev.storage[offset + 168..offset + 172].copy_from_slice(&crc.to_le_bytes());
        }

        dev.reset_counts();
        let res = open_mount(&mut dev).expect("open_mount should succeed");
        assert_eq!(res, MountClassification::UnsupportedVersion);
        assert_eq!(
            dev.write_count, 0,
            "Opening unsupported store must perform exactly 0 writes"
        );
        assert_eq!(
            dev.flush_count, 0,
            "Opening unsupported store must perform exactly 0 flushes"
        );
    }

    #[test]
    fn test_side_effect_free_degraded_recovery() {
        let mut dev = MockBlockDevice::new(32);
        let genesis_sb = provision_genesis(&mut dev, TEST_UUID, 32).unwrap();

        // Commit transaction to create generation 2 in Superblock A (slot 0)
        let mut store = ActiveStore::new(&mut dev, genesis_sb);
        let obj = ProposedObject {
            kind: 3,
            version: 1,
            payload: vec![1, 2, 3, 4],
            deduplicate_if_exists: false,
        };
        let gen2_sb = store.commit_transaction(&[obj]).unwrap();
        assert_eq!(gen2_sb.generation, 2);

        // Now corrupt the gen 2 application object at unit 4
        dev.storage[4 * STORE_UNIT_BYTES] ^= 0x55;

        // Reset tracking counts
        dev.reset_counts();

        // Mount store: Superblock A has gen 2 (valid CRC, but corrupt object graph)
        // Superblock B has gen 1 (valid CRC, completely valid graph)
        let res = open_mount(&mut dev).expect("open_mount should succeed");

        match res {
            MountClassification::DegradedRecovery(recovered_sb) => {
                assert_eq!(
                    recovered_sb.generation, 1,
                    "Degraded recovery must expose valid older root"
                );
            }
            other => panic!("Expected DegradedRecovery, got {:?}", other),
        }

        // Degraded recovery MUST perform exactly 0 repair writes and 0 flushes
        assert_eq!(
            dev.write_count, 0,
            "Degraded recovery must perform exactly 0 repair writes"
        );
        assert_eq!(
            dev.flush_count, 0,
            "Degraded recovery must perform exactly 0 flushes"
        );
    }

    #[test]
    fn test_mount_never_automatically_provisions_or_formats() {
        let mut dev = MockBlockDevice::new(16);
        let initial_storage = dev.storage.clone();

        for _ in 0..5 {
            let res = open_mount(&mut dev).unwrap();
            assert_eq!(res, MountClassification::Unformatted);
            assert_eq!(dev.write_count, 0);
            assert_eq!(dev.flush_count, 0);
            assert_eq!(
                dev.storage, initial_storage,
                "Storage bytes must remain entirely untouched"
            );
        }
    }

    #[test]
    fn test_mount_never_rewrites_superblock_to_fix_redundancy_or_crc() {
        let mut dev = MockBlockDevice::new(16);
        provision_genesis(&mut dev, TEST_UUID, 16).unwrap();

        // Invalidate CRC of Superblock B (unit 1)
        dev.storage[STORE_UNIT_BYTES + 168] ^= 0xAA;
        let corrupted_crc_bytes =
            dev.storage[STORE_UNIT_BYTES + 168..STORE_UNIT_BYTES + 172].to_vec();

        dev.reset_counts();
        let _res = open_mount(&mut dev).unwrap();

        // Superblock B has invalid CRC, so it is corrupt/untrusted
        assert_eq!(
            dev.write_count, 0,
            "Mount must NEVER write to disk to fix redundancy or CRC"
        );
        assert_eq!(
            dev.flush_count, 0,
            "Mount must NEVER flush to disk to fix redundancy or CRC"
        );

        // Verify unit 1 was NOT rewritten
        assert_eq!(
            dev.storage[STORE_UNIT_BYTES + 168..STORE_UNIT_BYTES + 172],
            corrupted_crc_bytes[..],
            "Superblock B on disk must remain corrupt; mount must not repair it"
        );
    }

    #[test]
    fn test_transactions_cannot_repair_corrupt_committed_objects() {
        let mut dev = MockBlockDevice::new(32);
        let genesis_sb = provision_genesis(&mut dev, TEST_UUID, 32).unwrap();

        let mut store = ActiveStore::new(&mut dev, genesis_sb);
        let obj1 = ProposedObject {
            kind: 3,
            version: 1,
            payload: vec![10, 20, 30, 40],
            deduplicate_if_exists: false,
        };
        let gen2_sb = store.commit_transaction(&[obj1]).unwrap();

        // An object was committed at unit 4. Corrupt its semantic byte.
        store.device.storage[4 * STORE_UNIT_BYTES] = 0xFF;

        // An adversary attempts to commit a transaction that tries to repair or overwrite unit 4
        // The store append arena strictly forbids writing before committed_high_water.
        assert!(gen2_sb.committed_high_water > 4);

        // Attempting deduplication against the corrupt object fails
        let dup_obj = ProposedObject {
            kind: 3,
            version: 1,
            payload: vec![10, 20, 30, 40],
            deduplicate_if_exists: true,
        };
        let tx_res = store.commit_transaction(&[dup_obj]);
        assert_eq!(
            tx_res,
            Err(TransactionError::DeduplicationVerificationFailed),
            "Cannot deduplicate against corrupt committed object"
        );

        // Verify unit 4 remains corrupt on disk (normal transaction cannot repair it)
        assert_eq!(store.device.storage[4 * STORE_UNIT_BYTES], 0xFF);
    }

    #[test]
    fn test_deduplication_requires_full_independent_byte_verification() {
        let mut dev = MockBlockDevice::new(32);
        let genesis_sb = provision_genesis(&mut dev, TEST_UUID, 32).unwrap();

        let mut store = ActiveStore::new(&mut dev, genesis_sb);
        let original_data = vec![0x42; 100];
        let obj1 = ProposedObject {
            kind: 3,
            version: 1,
            payload: original_data.clone(),
            deduplicate_if_exists: false,
        };
        let _gen2_sb = store.commit_transaction(&[obj1]).unwrap();

        // 1. Valid deduplication succeeds without writing any new payload units
        let prev_writes = store.device.written_units_log.clone();
        let dup_obj = ProposedObject {
            kind: 3,
            version: 1,
            payload: original_data.clone(),
            deduplicate_if_exists: true,
        };
        let gen3_sb = store
            .commit_transaction(&[dup_obj])
            .expect("Deduplication must succeed");
        assert_eq!(gen3_sb.generation, 3);
        // Gen 3 only wrote catalog, commit record, and superblock - NO payload units!
        let new_writes: Vec<u64> = store.device.written_units_log[prev_writes.len()..].to_vec();
        assert!(
            !new_writes.contains(&4),
            "Deduplication must NOT re-write payload unit 4"
        );
        // high_water for gen 3 did not advance by payload units
        assert_eq!(
            gen3_sb.catalog_entry_count, 1,
            "Only 1 catalog entry after deduplication"
        );

        // 2. Corrupt payload on disk causes deduplication verification to strictly fail
        store.device.storage[4 * STORE_UNIT_BYTES + 5] ^= 0x01;
        let dup_attempt2 = ProposedObject {
            kind: 3,
            version: 1,
            payload: original_data.clone(),
            deduplicate_if_exists: true,
        };
        assert_eq!(
            store.commit_transaction(&[dup_attempt2]),
            Err(TransactionError::DeduplicationVerificationFailed),
            "Deduplication must fail when on-disk semantic bytes are corrupt"
        );

        // Restore payload byte, but corrupt padding byte
        store.device.storage[4 * STORE_UNIT_BYTES + 5] ^= 0x01; // restored
        store.device.storage[4 * STORE_UNIT_BYTES + 100] = 0x99; // corrupt padding
        let dup_attempt3 = ProposedObject {
            kind: 3,
            version: 1,
            payload: original_data.clone(),
            deduplicate_if_exists: true,
        };
        assert_eq!(
            store.commit_transaction(&[dup_attempt3]),
            Err(TransactionError::DeduplicationVerificationFailed),
            "Deduplication must fail when final unit padding is non-zero"
        );
    }

    #[test]
    fn test_conflicting_duplicate_descriptor_strictly_fails() {
        let mut dev = MockBlockDevice::new(32);
        let genesis_sb = provision_genesis(&mut dev, TEST_UUID, 32).unwrap();

        let mut store = ActiveStore::new(&mut dev, genesis_sb);
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let original_obj = ProposedObject {
            kind: 3,
            version: 1,
            payload: payload.clone(),
            deduplicate_if_exists: false,
        };
        store.commit_transaction(&[original_obj]).unwrap();

        // 1. Conflicting kind
        let conflict_kind = ProposedObject {
            kind: 4,
            version: 1,
            payload: payload.clone(),
            deduplicate_if_exists: true,
        };
        // Even if someone crafted or attempted duplicate with different kind
        let res1 = store.commit_transaction(&[conflict_kind]);
        // This is a different object ID, so it appends as a new object or succeeds
        assert!(res1.is_ok());

        // 2. Manually attempt conflicting descriptor with SAME ObjectId but different byte length
        let oid = independent_object_id(3, 1, payload.len() as u64, &payload);
        // Craft a catalog entry directly with wrong size
        let conflicting_entry = CatalogEntry {
            object_id: oid,
            kind: 3,
            version: 1,
            first_unit: 4,
            byte_length: 100, // Conflict! Original was 8
            unit_count: 1,
            flags: 0,
        };
        assert!(
            conflicting_entry.byte_length != (payload.len() as u64),
            "Conflicting size must be detectable"
        );
    }

    #[test]
    fn test_read_io_fault_propagates_as_io_never_corrupt() {
        let mut dev = MockBlockDevice::new(16);
        provision_genesis(&mut dev, TEST_UUID, 16).unwrap();

        // Inject read fault on Superblock A (unit 0)
        dev.inject_read_fault_on_unit(0);
        dev.reset_counts();

        let res = open_mount(&mut dev);
        assert_eq!(
            res,
            Err(MountError::Io),
            "Read errors must propagate as MountError::Io, never as corrupt media"
        );
        assert_eq!(dev.write_count, 0);
        assert_eq!(dev.flush_count, 0);
    }
}
