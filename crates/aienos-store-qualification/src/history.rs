//! Root and history state-machine adversarial qualification suite (G4).
//!
//! Provides an independent state machine, adversarial mutation harness, and
//! qualification test matrix for dual-superblock resolution (ADR 0015 § 4, § 5).
//!
//! Evaluates the 13 canonical mount cases:
//! - Case 1: Same generation + equivalent root (both valid and identical -> valid)
//! - Case 2: Same generation + conflicting logical root (different CommitRecord/Catalog -> ConflictingRoots failure)
//! - Case 3: Generation N and N-1 with exact predecessor link (Slot N CommitRecord binds Slot N-1 -> valid Gen N)
//! - Case 4: Generation N and N-1 with wrong predecessor link (InconsistentHistory failure)
//! - Case 5: Generation N and N-2 (skip generation / InconsistentHistory failure)
//! - Case 6: Newer root graph-invalid, older root valid (degraded recovery to older root)
//! - Case 7: Older root graph-invalid, newer root valid (valid newer root, degraded history)
//! - Case 8: Both roots graph-invalid (CorruptStore / unrecoverable)
//! - Case 9: All-zero region (Unformatted)
//! - Case 10: Unknown nonzero data in region (ForeignOrUnknown)
//! - Case 11: Unsupported Store version (UnsupportedVersion)
//! - Case 12: One root CRC-corrupt, other root valid (fallback to valid root)
//! - Case 13: Required-device-read I/O error (MountError::Io)
//!
//! Strictly enforces semantic distinctions in the error taxonomy:
//! - Unformatted != ForeignOrUnknown
//! - ForeignOrUnknown != UnsupportedVersion
//! - UnsupportedVersion != ConflictingRoots
//! - ConflictingRoots != InconsistentHistory
//! - InconsistentHistory != MountError::Io
//! - Unreadable is not corrupt: I/O errors must NOT be silently treated as corrupt or trigger improper fallback.

use std::collections::HashSet;
use std::fmt;

use crate::oracle::{independent_crc32c, independent_object_id, STORE_UNIT_BYTES};

pub const SUPERBLOCK_A_UNIT: u64 = 0;
pub const SUPERBLOCK_B_UNIT: u64 = 1;
pub const SUPERBLOCK_MAGIC: &[u8; 8] = b"AIENSTR1";
pub const COMMIT_RECORD_MAGIC: &[u8; 8] = b"AIENCMT1";
pub const CATALOG_MAGIC: &[u8; 8] = b"AIENCAT1";

pub const SUPERBLOCK_CRC_OFFSET: usize = 168;
pub const SUPERBLOCK_RESERVED_OFFSET: usize = 172;
pub const COMMIT_RECORD_SEMANTIC_BYTES: usize = 200;
pub const CATALOG_HEADER_BYTES: usize = 16;
pub const CATALOG_ENTRY_BYTES: usize = 64;
pub const MAX_CATALOG_ENTRIES: usize = 4096;
pub const MAX_OBJECT_BYTES: u64 = 67_108_864;
pub const MAX_REGION_UNITS: u64 = 4_294_967_296;

pub const OBJECT_KIND_CATALOG: u16 = 1;
pub const OBJECT_KIND_COMMIT_RECORD: u16 = 2;
pub const OBJECT_VERSION_V1: u16 = 1;

/// Identifies the physical superblock slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SuperblockSlot {
    SlotA = 0,
    SlotB = 1,
}

impl SuperblockSlot {
    pub fn unit(&self) -> u64 {
        match self {
            SuperblockSlot::SlotA => SUPERBLOCK_A_UNIT,
            SuperblockSlot::SlotB => SUPERBLOCK_B_UNIT,
        }
    }

    pub fn slot_id(&self) -> u32 {
        *self as u32
    }

    pub fn other(&self) -> Self {
        match self {
            SuperblockSlot::SlotA => SuperblockSlot::SlotB,
            SuperblockSlot::SlotB => SuperblockSlot::SlotA,
        }
    }
}

/// High-level taxonomy of mount classifications required by ADR 0015 § 5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MountClassification {
    ValidStore,
    DegradedRecovery,
    Unformatted,
    ForeignOrUnknown,
    UnsupportedVersion,
    ConflictingRoots,
    InconsistentHistory,
    CorruptStore,
    IoError,
}

impl fmt::Display for MountClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MountClassification::ValidStore => write!(f, "ValidStore"),
            MountClassification::DegradedRecovery => write!(f, "DegradedRecovery"),
            MountClassification::Unformatted => write!(f, "Unformatted"),
            MountClassification::ForeignOrUnknown => write!(f, "ForeignOrUnknown"),
            MountClassification::UnsupportedVersion => write!(f, "UnsupportedVersion"),
            MountClassification::ConflictingRoots => write!(f, "ConflictingRoots"),
            MountClassification::InconsistentHistory => write!(f, "InconsistentHistory"),
            MountClassification::CorruptStore => write!(f, "CorruptStore"),
            MountClassification::IoError => write!(f, "IoError"),
        }
    }
}

/// Detailed mount error taxonomy adhering to ADR 0015.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountError {
    /// Both superblocks are all-zero.
    Unformatted,
    /// Neither superblock has AIENSTR1 magic and at least one is nonzero.
    ForeignOrUnknown,
    /// A CRC-valid AIENSTR1 superblock specifies unsupported format version or features.
    UnsupportedVersion {
        major: u16,
        minor: u16,
        required_features: u64,
    },
    /// Both roots are valid and at the same generation, but logical roots differ.
    ConflictingRoots,
    /// Both roots are valid, but generation relationships or predecessor binds are invalid.
    InconsistentHistory { details: String },
    /// Store corruption that prevents safe recovery.
    CorruptStore { details: String },
    /// Block-device I/O read failure. Strictly distinct from corrupt media.
    Io { unit: u64, message: String },
}

impl MountError {
    pub fn classification(&self) -> MountClassification {
        match self {
            MountError::Unformatted => MountClassification::Unformatted,
            MountError::ForeignOrUnknown => MountClassification::ForeignOrUnknown,
            MountError::UnsupportedVersion { .. } => MountClassification::UnsupportedVersion,
            MountError::ConflictingRoots => MountClassification::ConflictingRoots,
            MountError::InconsistentHistory { .. } => MountClassification::InconsistentHistory,
            MountError::CorruptStore { .. } => MountClassification::CorruptStore,
            MountError::Io { .. } => MountClassification::IoError,
        }
    }
}

impl fmt::Display for MountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MountError::Unformatted => write!(f, "store is unformatted (all-zero superblocks)"),
            MountError::ForeignOrUnknown => {
                write!(f, "store has foreign or unknown data (no AIENSTR1 magic)")
            }
            MountError::UnsupportedVersion {
                major,
                minor,
                required_features,
            } => {
                write!(
                    f,
                    "unsupported store version: v{}.{}, required_features: 0x{:016x}",
                    major, minor, required_features
                )
            }
            MountError::ConflictingRoots => {
                write!(
                    f,
                    "conflicting roots at same generation without equivalent commit records"
                )
            }
            MountError::InconsistentHistory { details } => {
                write!(f, "inconsistent history: {}", details)
            }
            MountError::CorruptStore { details } => {
                write!(f, "corrupt store: {}", details)
            }
            MountError::Io { unit, message } => {
                write!(f, "block device I/O error on unit {}: {}", unit, message)
            }
        }
    }
}

impl std::error::Error for MountError {}

/// Full resolution outcome of dual-superblock mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountResolution {
    /// Valid store selected.
    Valid {
        active_slot: SuperblockSlot,
        generation: u64,
        degraded_history: bool,
        commit_record_id: [u8; 32],
        catalog_id: [u8; 32],
        committed_high_water: u64,
    },
    /// Valid older root exposed read-only because newer root has graph errors.
    DegradedRecovery {
        active_slot: SuperblockSlot,
        generation: u64,
        commit_record_id: [u8; 32],
        catalog_id: [u8; 32],
        committed_high_water: u64,
    },
    /// Mount failed with a deterministic classified error.
    Failed(MountError),
}

impl MountResolution {
    pub fn classification(&self) -> MountClassification {
        match self {
            MountResolution::Valid { .. } => MountClassification::ValidStore,
            MountResolution::DegradedRecovery { .. } => MountClassification::DegradedRecovery,
            MountResolution::Failed(err) => err.classification(),
        }
    }

    pub fn is_valid(&self) -> bool {
        matches!(self, MountResolution::Valid { .. })
    }

    pub fn is_degraded_recovery(&self) -> bool {
        matches!(self, MountResolution::DegradedRecovery { .. })
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, MountResolution::Failed(_))
    }
}

/// Abstract storage device interface for reading 4096-byte units.
pub trait StorageDevice {
    fn read_unit(&self, unit: u64) -> Result<[u8; STORE_UNIT_BYTES], MountError>;
    fn unit_count(&self) -> u64;
}

/// In-memory mock storage device with configurable I/O fault injection.
#[derive(Debug, Clone)]
pub struct MockStoreDevice {
    pub units: Vec<[u8; STORE_UNIT_BYTES]>,
    pub io_fault_units: HashSet<u64>,
}

impl MockStoreDevice {
    pub fn new(unit_count: usize) -> Self {
        Self {
            units: vec![[0u8; STORE_UNIT_BYTES]; unit_count],
            io_fault_units: HashSet::new(),
        }
    }

    pub fn write_unit(&mut self, unit: u64, data: &[u8]) {
        let idx = unit as usize;
        if idx >= self.units.len() {
            self.units.resize(idx + 1, [0u8; STORE_UNIT_BYTES]);
        }
        self.units[idx].copy_from_slice(data);
    }

    pub fn inject_io_fault(&mut self, unit: u64) {
        self.io_fault_units.insert(unit);
    }

    pub fn clear_io_fault(&mut self, unit: u64) {
        self.io_fault_units.remove(&unit);
    }

    pub fn corrupt_byte(&mut self, unit: u64, offset: usize, xor_mask: u8) {
        let idx = unit as usize;
        if idx < self.units.len() && offset < STORE_UNIT_BYTES {
            self.units[idx][offset] ^= xor_mask;
        }
    }
}

impl StorageDevice for MockStoreDevice {
    fn read_unit(&self, unit: u64) -> Result<[u8; STORE_UNIT_BYTES], MountError> {
        if self.io_fault_units.contains(&unit) {
            return Err(MountError::Io {
                unit,
                message: format!("synthetic device I/O read failure at unit {}", unit),
            });
        }
        let idx = unit as usize;
        if idx >= self.units.len() {
            return Err(MountError::Io {
                unit,
                message: format!("unit {} out of device bounds ({})", unit, self.units.len()),
            });
        }
        Ok(self.units[idx])
    }

    fn unit_count(&self) -> u64 {
        self.units.len() as u64
    }
}

// =========================================================================
// Independent Canonical Encoders / Decoders for Store v1 Structures
// =========================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSuperblock {
    pub format_major: u16,
    pub format_minor: u16,
    pub required_features: u64,
    pub compatible_features: u64,
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
}

impl RawSuperblock {
    pub fn encode(&self) -> [u8; STORE_UNIT_BYTES] {
        let mut bytes = [0u8; STORE_UNIT_BYTES];
        bytes[0..8].copy_from_slice(SUPERBLOCK_MAGIC);
        bytes[8..10].copy_from_slice(&self.format_major.to_le_bytes());
        bytes[10..12].copy_from_slice(&self.format_minor.to_le_bytes());
        bytes[12..20].copy_from_slice(&self.required_features.to_le_bytes());
        bytes[20..28].copy_from_slice(&self.compatible_features.to_le_bytes());
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

        // CRC computed with 168..172 as zero
        bytes[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].fill(0);
        let crc = independent_crc32c(&bytes);
        bytes[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCommitRecord {
    pub record_version: u16,
    pub record_size: u16,
    pub format_major: u16,
    pub format_minor: u16,
    pub required_features: u64,
    pub compatible_features: u64,
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

impl RawCommitRecord {
    pub fn encode_semantic(&self) -> [u8; COMMIT_RECORD_SEMANTIC_BYTES] {
        let mut bytes = [0u8; COMMIT_RECORD_SEMANTIC_BYTES];
        bytes[0..8].copy_from_slice(COMMIT_RECORD_MAGIC);
        bytes[8..10].copy_from_slice(&self.record_version.to_le_bytes());
        bytes[10..12].copy_from_slice(&self.record_size.to_le_bytes());
        bytes[12..14].copy_from_slice(&self.format_major.to_le_bytes());
        bytes[14..16].copy_from_slice(&self.format_minor.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.required_features.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.compatible_features.to_le_bytes());
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

    pub fn encode_unit(&self) -> [u8; STORE_UNIT_BYTES] {
        let mut unit = [0u8; STORE_UNIT_BYTES];
        unit[..COMMIT_RECORD_SEMANTIC_BYTES].copy_from_slice(&self.encode_semantic());
        unit
    }

    pub fn object_id(&self) -> [u8; 32] {
        let semantic = self.encode_semantic();
        independent_object_id(
            OBJECT_KIND_COMMIT_RECORD,
            OBJECT_VERSION_V1,
            COMMIT_RECORD_SEMANTIC_BYTES as u64,
            &semantic,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCatalogEntry {
    pub object_id: [u8; 32],
    pub kind: u16,
    pub version: u16,
    pub first_unit: u64,
    pub byte_length: u64,
    pub unit_count: u32,
    pub flags: u16,
}

impl RawCatalogEntry {
    pub fn encode(&self) -> [u8; CATALOG_ENTRY_BYTES] {
        let mut bytes = [0u8; CATALOG_ENTRY_BYTES];
        bytes[0..32].copy_from_slice(&self.object_id);
        bytes[32..34].copy_from_slice(&self.kind.to_le_bytes());
        bytes[34..36].copy_from_slice(&self.version.to_le_bytes());
        bytes[36..44].copy_from_slice(&self.first_unit.to_le_bytes());
        bytes[44..52].copy_from_slice(&self.byte_length.to_le_bytes());
        bytes[52..56].copy_from_slice(&self.unit_count.to_le_bytes());
        bytes[56..58].copy_from_slice(&self.flags.to_le_bytes());
        // 58..64 is zero reserved
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCatalog {
    pub entries: Vec<RawCatalogEntry>,
}

impl RawCatalog {
    pub fn semantic_bytes(&self) -> Vec<u8> {
        let mut bytes =
            Vec::with_capacity(CATALOG_HEADER_BYTES + self.entries.len() * CATALOG_ENTRY_BYTES);
        bytes.extend_from_slice(CATALOG_MAGIC);
        bytes.extend_from_slice(&1u16.to_le_bytes()); // format_version = 1
        bytes.extend_from_slice(&(CATALOG_ENTRY_BYTES as u16).to_le_bytes()); // entry_size = 64
        bytes.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for entry in &self.entries {
            bytes.extend_from_slice(&entry.encode());
        }
        bytes
    }

    pub fn unit_count(&self) -> u32 {
        let sem_len = self.semantic_bytes().len() as u64;
        sem_len.div_ceil(STORE_UNIT_BYTES as u64) as u32
    }

    pub fn encode_units(&self) -> Vec<[u8; STORE_UNIT_BYTES]> {
        let semantic = self.semantic_bytes();
        let u_count = self.unit_count() as usize;
        let mut result = vec![[0u8; STORE_UNIT_BYTES]; u_count];
        let mut remaining = semantic.as_slice();
        for unit in result.iter_mut() {
            if remaining.is_empty() {
                break;
            }
            let to_copy = remaining.len().min(STORE_UNIT_BYTES);
            unit[..to_copy].copy_from_slice(&remaining[..to_copy]);
            remaining = &remaining[to_copy..];
        }
        result
    }

    pub fn object_id(&self) -> [u8; 32] {
        let semantic = self.semantic_bytes();
        independent_object_id(
            OBJECT_KIND_CATALOG,
            OBJECT_VERSION_V1,
            semantic.len() as u64,
            &semantic,
        )
    }
}

/// Synthetic generator for deterministic valid Store v1 histories.
pub struct SyntheticStoreBuilder {
    pub store_uuid: [u8; 16],
    pub region_units: u64,
}

impl SyntheticStoreBuilder {
    pub fn new(store_uuid: [u8; 16], region_units: u64) -> Self {
        Self {
            store_uuid,
            region_units,
        }
    }

    /// Build a valid Genesis store (generation 1) with an empty catalog.
    /// Slot A and Slot B both contain equivalent valid superblocks.
    pub fn build_genesis(&self) -> MockStoreDevice {
        let mut device = MockStoreDevice::new(self.region_units as usize);

        let catalog = RawCatalog { entries: vec![] };
        let catalog_id = catalog.object_id();
        let catalog_units = catalog.encode_units();
        let catalog_first_unit = 2u64;
        let catalog_unit_count = catalog.unit_count() as u64;

        for (i, unit) in catalog_units.iter().enumerate() {
            device.write_unit(catalog_first_unit + i as u64, unit);
        }

        let commit_unit = catalog_first_unit + catalog_unit_count; // unit 3
        let high_water = commit_unit + 1; // unit 4

        let commit = RawCommitRecord {
            record_version: 1,
            record_size: COMMIT_RECORD_SEMANTIC_BYTES as u16,
            format_major: 1,
            format_minor: 0,
            required_features: 0,
            compatible_features: 0,
            store_uuid: self.store_uuid,
            region_units: self.region_units,
            generation: 1,
            previous_generation: 0,
            previous_commit_id: [0u8; 32],
            previous_catalog_id: [0u8; 32],
            catalog_id,
            catalog_first_unit,
            catalog_byte_length: catalog.semantic_bytes().len() as u64,
            catalog_unit_count: catalog.unit_count(),
            catalog_entry_count: 0,
            committed_high_water: high_water,
        };
        let commit_id = commit.object_id();
        device.write_unit(commit_unit, &commit.encode_unit());

        let sb_a = RawSuperblock {
            format_major: 1,
            format_minor: 0,
            required_features: 0,
            compatible_features: 0,
            store_uuid: self.store_uuid,
            slot_id: 0,
            region_units: self.region_units,
            generation: 1,
            commit_record_id: commit_id,
            commit_record_unit: commit_unit,
            catalog_id,
            catalog_first_unit,
            catalog_byte_length: catalog.semantic_bytes().len() as u64,
            catalog_unit_count: catalog.unit_count(),
            catalog_entry_count: 0,
            committed_high_water: high_water,
        };
        device.write_unit(SUPERBLOCK_A_UNIT, &sb_a.encode());

        let sb_b = RawSuperblock { slot_id: 1, ..sb_a };
        device.write_unit(SUPERBLOCK_B_UNIT, &sb_b.encode());

        device
    }

    /// Advance history by committing generation N+1 into `target_slot`, binding predecessor `from_slot`.
    pub fn advance_generation(
        &self,
        device: &mut MockStoreDevice,
        from_slot: SuperblockSlot,
        target_slot: SuperblockSlot,
        payload: &[u8],
    ) {
        // Read previous superblock metadata
        let prev_sb_bytes = device.read_unit(from_slot.unit()).unwrap();
        let prev_gen = u64::from_le_bytes(prev_sb_bytes[56..64].try_into().unwrap());
        let prev_high_water = u64::from_le_bytes(prev_sb_bytes[160..168].try_into().unwrap());
        let mut prev_commit_id = [0u8; 32];
        prev_commit_id.copy_from_slice(&prev_sb_bytes[64..96]);
        let mut prev_catalog_id = [0u8; 32];
        prev_catalog_id.copy_from_slice(&prev_sb_bytes[104..136]);

        // Place new app object at prev_high_water
        let app_first_unit = prev_high_water;
        let app_len = payload.len() as u64;
        let app_unit_count = app_len.div_ceil(STORE_UNIT_BYTES as u64).max(1);
        let app_id = independent_object_id(3, 1, app_len, payload);

        let mut app_extent = vec![0u8; (app_unit_count as usize) * STORE_UNIT_BYTES];
        app_extent[..payload.len()].copy_from_slice(payload);
        for i in 0..app_unit_count {
            let offset = (i as usize) * STORE_UNIT_BYTES;
            device.write_unit(
                app_first_unit + i,
                &app_extent[offset..offset + STORE_UNIT_BYTES],
            );
        }

        // New catalog at app_first_unit + app_unit_count
        let cat_first_unit = app_first_unit + app_unit_count;
        let cat_entry = RawCatalogEntry {
            object_id: app_id,
            kind: 3,
            version: 1,
            first_unit: app_first_unit,
            byte_length: app_len,
            unit_count: app_unit_count as u32,
            flags: 0,
        };
        let catalog = RawCatalog {
            entries: vec![cat_entry],
        };
        let cat_id = catalog.object_id();
        let cat_units = catalog.encode_units();
        for (i, unit) in cat_units.iter().enumerate() {
            device.write_unit(cat_first_unit + i as u64, unit);
        }

        // New commit record at cat_first_unit + cat_unit_count
        let commit_unit = cat_first_unit + (catalog.unit_count() as u64);
        let new_high_water = commit_unit + 1;
        let new_gen = prev_gen + 1;

        let commit = RawCommitRecord {
            record_version: 1,
            record_size: COMMIT_RECORD_SEMANTIC_BYTES as u16,
            format_major: 1,
            format_minor: 0,
            required_features: 0,
            compatible_features: 0,
            store_uuid: self.store_uuid,
            region_units: self.region_units,
            generation: new_gen,
            previous_generation: prev_gen,
            previous_commit_id: prev_commit_id,
            previous_catalog_id: prev_catalog_id,
            catalog_id: cat_id,
            catalog_first_unit: cat_first_unit,
            catalog_byte_length: catalog.semantic_bytes().len() as u64,
            catalog_unit_count: catalog.unit_count(),
            catalog_entry_count: 1,
            committed_high_water: new_high_water,
        };
        let commit_id = commit.object_id();
        device.write_unit(commit_unit, &commit.encode_unit());

        // Write new superblock to target_slot
        let sb = RawSuperblock {
            format_major: 1,
            format_minor: 0,
            required_features: 0,
            compatible_features: 0,
            store_uuid: self.store_uuid,
            slot_id: target_slot.slot_id(),
            region_units: self.region_units,
            generation: new_gen,
            commit_record_id: commit_id,
            commit_record_unit: commit_unit,
            catalog_id: cat_id,
            catalog_first_unit: cat_first_unit,
            catalog_byte_length: catalog.semantic_bytes().len() as u64,
            catalog_unit_count: catalog.unit_count(),
            catalog_entry_count: 1,
            committed_high_water: new_high_water,
        };
        device.write_unit(target_slot.unit(), &sb.encode());
    }
}

// =========================================================================
// Dual Superblock State Machine Resolver (ADR 0015 § 5)
// =========================================================================

#[derive(Debug, Clone)]
pub struct ValidatedRoot {
    pub slot: SuperblockSlot,
    pub generation: u64,
    pub store_uuid: [u8; 16],
    pub region_units: u64,
    pub commit_record_id: [u8; 32],
    pub commit_record_unit: u64,
    pub catalog_id: [u8; 32],
    pub committed_high_water: u64,
    pub commit_record: RawCommitRecord,
}

#[derive(Debug, Clone)]
enum SlotValidationStatus {
    Valid(Box<ValidatedRoot>),
    GraphInvalid {
        generation: u64,
        #[allow(dead_code)]
        store_uuid: [u8; 16],
        #[allow(dead_code)]
        region_units: u64,
    },
    MalformedSuperblock,
    CrcCorrupt,
    AllZero,
}

/// Independent state machine resolving dual-superblock root selection.
pub fn resolve_dual_superblocks<D: StorageDevice>(device: &D) -> MountResolution {
    // 0. The two superblock units MUST both be read.
    // Any block-device read error MUST be reported as MountError::Io, never as corrupt media.
    let sb_a_bytes = match device.read_unit(SUPERBLOCK_A_UNIT) {
        Ok(bytes) => bytes,
        Err(err) => return MountResolution::Failed(err),
    };
    let sb_b_bytes = match device.read_unit(SUPERBLOCK_B_UNIT) {
        Ok(bytes) => bytes,
        Err(err) => return MountResolution::Failed(err),
    };

    // 1. If both superblock units are all zero, classify Unformatted.
    let a_all_zero = sb_a_bytes.iter().all(|&b| b == 0);
    let b_all_zero = sb_b_bytes.iter().all(|&b| b == 0);
    if a_all_zero && b_all_zero {
        return MountResolution::Failed(MountError::Unformatted);
    }

    // 2. If neither has AIENSTR1 magic and at least one is nonzero, classify ForeignOrUnknown.
    let a_has_magic = &sb_a_bytes[0..8] == SUPERBLOCK_MAGIC;
    let b_has_magic = &sb_b_bytes[0..8] == SUPERBLOCK_MAGIC;
    if !a_has_magic && !b_has_magic {
        return MountResolution::Failed(MountError::ForeignOrUnknown);
    }

    // 3. A CRC-valid AIENSTR1 superblock whose major/minor or feature values are unsupported
    // classifies UnsupportedVersion; do not fall back to another root.
    for bytes in [&sb_a_bytes, &sb_b_bytes] {
        if &bytes[0..8] == SUPERBLOCK_MAGIC && check_sb_crc(bytes) {
            let major = u16::from_le_bytes([bytes[8], bytes[9]]);
            let minor = u16::from_le_bytes([bytes[10], bytes[11]]);
            let req_feat = u64::from_le_bytes(bytes[12..20].try_into().unwrap());
            if major != 1 || minor != 0 || req_feat != 0 {
                return MountResolution::Failed(MountError::UnsupportedVersion {
                    major,
                    minor,
                    required_features: req_feat,
                });
            }
        }
    }

    // 4. Validate each slot independently through the full object graph.
    let status_a = match validate_slot_and_graph(device, &sb_a_bytes, SuperblockSlot::SlotA) {
        Ok(status) => status,
        Err(err) => return MountResolution::Failed(err), // Device I/O errors abort immediately!
    };
    let status_b = match validate_slot_and_graph(device, &sb_b_bytes, SuperblockSlot::SlotB) {
        Ok(status) => status,
        Err(err) => return MountResolution::Failed(err), // Device I/O errors abort immediately!
    };

    // 5. Evaluate dual roots according to ADR 0015 § 5 rules.
    match (status_a, status_b) {
        // Both roots completely valid
        (SlotValidationStatus::Valid(root_a), SlotValidationStatus::Valid(root_b)) => {
            if root_a.generation == root_b.generation {
                // Same generation: equivalent roots are redundant valid copies; non-equivalent are ConflictingRoots
                let equivalent = root_a.store_uuid == root_b.store_uuid
                    && root_a.region_units == root_b.region_units
                    && root_a.commit_record_id == root_b.commit_record_id;
                if equivalent {
                    MountResolution::Valid {
                        active_slot: SuperblockSlot::SlotA,
                        generation: root_a.generation,
                        degraded_history: false,
                        commit_record_id: root_a.commit_record_id,
                        catalog_id: root_a.catalog_id,
                        committed_high_water: root_a.committed_high_water,
                    }
                } else {
                    MountResolution::Failed(MountError::ConflictingRoots)
                }
            } else {
                // Different generations
                let (newer, older) = if root_a.generation > root_b.generation {
                    (&root_a, &root_b)
                } else {
                    (&root_b, &root_a)
                };

                // Check generation delta
                if newer.generation.checked_sub(older.generation) == Some(1) {
                    // Check predecessor links
                    let valid_history = newer.store_uuid == older.store_uuid
                        && newer.region_units == older.region_units
                        && newer.commit_record.previous_generation == older.generation
                        && newer.commit_record.previous_commit_id == older.commit_record_id
                        && newer.commit_record.previous_catalog_id == older.catalog_id;

                    if valid_history {
                        MountResolution::Valid {
                            active_slot: newer.slot,
                            generation: newer.generation,
                            degraded_history: false,
                            commit_record_id: newer.commit_record_id,
                            catalog_id: newer.catalog_id,
                            committed_high_water: newer.committed_high_water,
                        }
                    } else {
                        MountResolution::Failed(MountError::InconsistentHistory {
                            details: format!(
                                "adjacent generations {} and {} predecessor mismatch",
                                newer.generation, older.generation
                            ),
                        })
                    }
                } else {
                    // Generation difference > 1: non-adjacent generations
                    MountResolution::Failed(MountError::InconsistentHistory {
                        details: format!(
                            "non-adjacent generations: newer {} and older {}",
                            newer.generation, older.generation
                        ),
                    })
                }
            }
        }

        // Newer root graph-invalid, older root valid -> DegradedRecovery
        (
            SlotValidationStatus::Valid(valid),
            SlotValidationStatus::GraphInvalid { generation, .. },
        )
        | (
            SlotValidationStatus::GraphInvalid { generation, .. },
            SlotValidationStatus::Valid(valid),
        ) => {
            if generation > valid.generation {
                // Strictly newer root has graph error -> degraded recovery to older root
                MountResolution::DegradedRecovery {
                    active_slot: valid.slot,
                    generation: valid.generation,
                    commit_record_id: valid.commit_record_id,
                    catalog_id: valid.catalog_id,
                    committed_high_water: valid.committed_high_water,
                }
            } else if generation < valid.generation {
                // Older root has graph error -> newer root is valid, degraded history
                MountResolution::Valid {
                    active_slot: valid.slot,
                    generation: valid.generation,
                    degraded_history: true,
                    commit_record_id: valid.commit_record_id,
                    catalog_id: valid.catalog_id,
                    committed_high_water: valid.committed_high_water,
                }
            } else {
                // Graph-invalid root at the same generation as valid root
                MountResolution::Failed(MountError::CorruptStore {
                    details: "graph-invalid root at same generation as valid root".into(),
                })
            }
        }

        // One root valid, the other root all-zero
        (SlotValidationStatus::Valid(valid), SlotValidationStatus::AllZero)
        | (SlotValidationStatus::AllZero, SlotValidationStatus::Valid(valid)) => {
            MountResolution::Valid {
                active_slot: valid.slot,
                generation: valid.generation,
                degraded_history: false,
                commit_record_id: valid.commit_record_id,
                catalog_id: valid.catalog_id,
                committed_high_water: valid.committed_high_water,
            }
        }

        // One root valid, the other root CRC corrupt (fallback to valid root)
        (SlotValidationStatus::Valid(valid), SlotValidationStatus::CrcCorrupt)
        | (SlotValidationStatus::CrcCorrupt, SlotValidationStatus::Valid(valid)) => {
            MountResolution::Valid {
                active_slot: valid.slot,
                generation: valid.generation,
                degraded_history: false,
                commit_record_id: valid.commit_record_id,
                catalog_id: valid.catalog_id,
                committed_high_water: valid.committed_high_water,
            }
        }

        // Both roots graph-invalid
        (SlotValidationStatus::GraphInvalid { .. }, SlotValidationStatus::GraphInvalid { .. }) => {
            MountResolution::Failed(MountError::CorruptStore {
                details: "both superblock roots have graph errors".into(),
            })
        }

        // Any other combination where no valid root exists
        _ => MountResolution::Failed(MountError::CorruptStore {
            details: "unrecoverable: no valid superblock root found".into(),
        }),
    }
}

/// Helper that verifies superblock CRC32C over 4096 bytes with 168..172 zeroed.
fn check_sb_crc(bytes: &[u8; STORE_UNIT_BYTES]) -> bool {
    let stored_crc = u32::from_le_bytes(
        bytes[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    let mut canonical = *bytes;
    canonical[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].fill(0);
    independent_crc32c(&canonical) == stored_crc
}

/// Validate a single superblock slot and its referenced object graph.
///
/// Returns:
/// - `Ok(SlotValidationStatus)` on completion
/// - `Err(MountError::Io)` on any device I/O error during traversal!
fn validate_slot_and_graph<D: StorageDevice>(
    device: &D,
    bytes: &[u8; STORE_UNIT_BYTES],
    expected_slot: SuperblockSlot,
) -> Result<SlotValidationStatus, MountError> {
    if bytes.iter().all(|&b| b == 0) {
        return Ok(SlotValidationStatus::AllZero);
    }
    if &bytes[0..8] != SUPERBLOCK_MAGIC || !check_sb_crc(bytes) {
        return Ok(SlotValidationStatus::CrcCorrupt);
    }

    // Reserved bytes (172..4096) must be all zero
    if bytes[SUPERBLOCK_RESERVED_OFFSET..].iter().any(|&b| b != 0) {
        return Ok(SlotValidationStatus::MalformedSuperblock);
    }

    let slot_id = u32::from_le_bytes(bytes[44..48].try_into().unwrap());
    if slot_id != expected_slot.slot_id() {
        return Ok(SlotValidationStatus::MalformedSuperblock);
    }

    let region_units = u64::from_le_bytes(bytes[48..56].try_into().unwrap());
    let generation = u64::from_le_bytes(bytes[56..64].try_into().unwrap());
    let commit_record_unit = u64::from_le_bytes(bytes[96..104].try_into().unwrap());
    let catalog_first_unit = u64::from_le_bytes(bytes[136..144].try_into().unwrap());
    let catalog_byte_length = u64::from_le_bytes(bytes[144..152].try_into().unwrap());
    let catalog_unit_count = u32::from_le_bytes(bytes[152..156].try_into().unwrap());
    let catalog_entry_count = u32::from_le_bytes(bytes[156..160].try_into().unwrap());
    let high_water = u64::from_le_bytes(bytes[160..168].try_into().unwrap());

    let mut store_uuid = [0u8; 16];
    store_uuid.copy_from_slice(&bytes[28..44]);
    let mut commit_record_id = [0u8; 32];
    commit_record_id.copy_from_slice(&bytes[64..96]);
    let mut catalog_id = [0u8; 32];
    catalog_id.copy_from_slice(&bytes[104..136]);

    if !(4..=MAX_REGION_UNITS).contains(&region_units)
        || generation == 0
        || high_water > region_units
        || high_water < 4
    {
        return Ok(SlotValidationStatus::MalformedSuperblock);
    }

    // Now validate the referenced graph.
    // Device I/O errors MUST bubble up as Err(MountError::Io)!

    // 1. Commit Record
    if commit_record_unit >= region_units
        || commit_record_unit < 2
        || commit_record_unit + 1 != high_water
    {
        return Ok(SlotValidationStatus::GraphInvalid {
            generation,
            store_uuid,
            region_units,
        });
    }
    let commit_bytes = device.read_unit(commit_record_unit)?;
    // Remainder of CommitRecord unit (200..4096) must be all zero
    if commit_bytes[COMMIT_RECORD_SEMANTIC_BYTES..]
        .iter()
        .any(|&b| b != 0)
    {
        return Ok(SlotValidationStatus::GraphInvalid {
            generation,
            store_uuid,
            region_units,
        });
    }
    if &commit_bytes[0..8] != COMMIT_RECORD_MAGIC {
        return Ok(SlotValidationStatus::GraphInvalid {
            generation,
            store_uuid,
            region_units,
        });
    }
    let calculated_commit_id = independent_object_id(
        OBJECT_KIND_COMMIT_RECORD,
        OBJECT_VERSION_V1,
        COMMIT_RECORD_SEMANTIC_BYTES as u64,
        &commit_bytes[..COMMIT_RECORD_SEMANTIC_BYTES],
    );
    if calculated_commit_id != commit_record_id {
        return Ok(SlotValidationStatus::GraphInvalid {
            generation,
            store_uuid,
            region_units,
        });
    }

    let c_store_uuid: [u8; 16] = commit_bytes[32..48].try_into().unwrap();
    let c_region_units = u64::from_le_bytes(commit_bytes[48..56].try_into().unwrap());
    let c_gen = u64::from_le_bytes(commit_bytes[56..64].try_into().unwrap());
    let c_prev_gen = u64::from_le_bytes(commit_bytes[64..72].try_into().unwrap());
    let c_prev_commit_id: [u8; 32] = commit_bytes[72..104].try_into().unwrap();
    let c_prev_catalog_id: [u8; 32] = commit_bytes[104..136].try_into().unwrap();
    let c_catalog_id: [u8; 32] = commit_bytes[136..168].try_into().unwrap();
    let c_cat_first_unit = u64::from_le_bytes(commit_bytes[168..176].try_into().unwrap());
    let c_cat_byte_length = u64::from_le_bytes(commit_bytes[176..184].try_into().unwrap());
    let c_cat_unit_count = u32::from_le_bytes(commit_bytes[184..188].try_into().unwrap());
    let c_cat_entry_count = u32::from_le_bytes(commit_bytes[188..192].try_into().unwrap());
    let c_high_water = u64::from_le_bytes(commit_bytes[192..200].try_into().unwrap());

    if c_store_uuid != store_uuid
        || c_region_units != region_units
        || c_gen != generation
        || c_catalog_id != catalog_id
        || c_cat_first_unit != catalog_first_unit
        || c_cat_byte_length != catalog_byte_length
        || c_cat_unit_count != catalog_unit_count
        || c_cat_entry_count != catalog_entry_count
        || c_high_water != high_water
        || catalog_first_unit + (catalog_unit_count as u64) != commit_record_unit
    {
        return Ok(SlotValidationStatus::GraphInvalid {
            generation,
            store_uuid,
            region_units,
        });
    }

    // 2. Catalog
    let expected_cat_len =
        CATALOG_HEADER_BYTES as u64 + (catalog_entry_count as u64) * (CATALOG_ENTRY_BYTES as u64);
    if catalog_byte_length != expected_cat_len {
        return Ok(SlotValidationStatus::GraphInvalid {
            generation,
            store_uuid,
            region_units,
        });
    }
    let expected_cat_units = catalog_byte_length.div_ceil(STORE_UNIT_BYTES as u64) as u32;
    if catalog_unit_count != expected_cat_units {
        return Ok(SlotValidationStatus::GraphInvalid {
            generation,
            store_uuid,
            region_units,
        });
    }

    let mut cat_bytes = Vec::with_capacity((catalog_unit_count as usize) * STORE_UNIT_BYTES);
    for u in 0..(catalog_unit_count as u64) {
        let unit_data = device.read_unit(catalog_first_unit + u)?;
        cat_bytes.extend_from_slice(&unit_data);
    }
    // Trailing padding must be zero
    if cat_bytes[catalog_byte_length as usize..]
        .iter()
        .any(|&b| b != 0)
    {
        return Ok(SlotValidationStatus::GraphInvalid {
            generation,
            store_uuid,
            region_units,
        });
    }
    // Validate Catalog ObjectId
    let calculated_cat_id = independent_object_id(
        OBJECT_KIND_CATALOG,
        OBJECT_VERSION_V1,
        catalog_byte_length,
        &cat_bytes[..catalog_byte_length as usize],
    );
    if calculated_cat_id != catalog_id {
        return Ok(SlotValidationStatus::GraphInvalid {
            generation,
            store_uuid,
            region_units,
        });
    }

    // Check catalog header
    if &cat_bytes[0..8] != CATALOG_MAGIC {
        return Ok(SlotValidationStatus::GraphInvalid {
            generation,
            store_uuid,
            region_units,
        });
    }

    // 3. Application Objects in Catalog
    let mut prev_id: Option<[u8; 32]> = None;
    let mut allocated_extents: Vec<(u64, u64)> = Vec::new();

    for i in 0..(catalog_entry_count as usize) {
        let entry_offset = CATALOG_HEADER_BYTES + i * CATALOG_ENTRY_BYTES;
        let entry_bytes = &cat_bytes[entry_offset..entry_offset + CATALOG_ENTRY_BYTES];
        let mut obj_id = [0u8; 32];
        obj_id.copy_from_slice(&entry_bytes[0..32]);

        // Sorted ordering strictly enforced
        if let Some(prev) = prev_id {
            if obj_id <= prev {
                return Ok(SlotValidationStatus::GraphInvalid {
                    generation,
                    store_uuid,
                    region_units,
                });
            }
        }
        prev_id = Some(obj_id);

        let kind = u16::from_le_bytes([entry_bytes[32], entry_bytes[33]]);
        let version = u16::from_le_bytes([entry_bytes[34], entry_bytes[35]]);
        let first_unit = u64::from_le_bytes(entry_bytes[36..44].try_into().unwrap());
        let byte_len = u64::from_le_bytes(entry_bytes[44..52].try_into().unwrap());
        let u_count = u32::from_le_bytes(entry_bytes[52..56].try_into().unwrap());
        let flags = u16::from_le_bytes([entry_bytes[56], entry_bytes[57]]);
        let reserved = &entry_bytes[58..64];

        if kind < 3 || version == 0 || flags != 0 || reserved.iter().any(|&b| b != 0) {
            return Ok(SlotValidationStatus::GraphInvalid {
                generation,
                store_uuid,
                region_units,
            });
        }
        if byte_len == 0 || byte_len > MAX_OBJECT_BYTES {
            return Ok(SlotValidationStatus::GraphInvalid {
                generation,
                store_uuid,
                region_units,
            });
        }
        let expected_u_count = byte_len.div_ceil(STORE_UNIT_BYTES as u64) as u32;
        if u_count != expected_u_count {
            return Ok(SlotValidationStatus::GraphInvalid {
                generation,
                store_uuid,
                region_units,
            });
        }
        let end_unit = first_unit + (u_count as u64);
        if first_unit < 2 || end_unit > catalog_first_unit {
            return Ok(SlotValidationStatus::GraphInvalid {
                generation,
                store_uuid,
                region_units,
            });
        }

        // Check extent non-overlap
        for (other_start, other_end) in &allocated_extents {
            if !(end_unit <= *other_start || first_unit >= *other_end) {
                return Ok(SlotValidationStatus::GraphInvalid {
                    generation,
                    store_uuid,
                    region_units,
                });
            }
        }
        allocated_extents.push((first_unit, end_unit));

        // Read and validate object bytes
        let mut obj_bytes = Vec::with_capacity((u_count as usize) * STORE_UNIT_BYTES);
        for u in 0..(u_count as u64) {
            let u_data = device.read_unit(first_unit + u)?;
            obj_bytes.extend_from_slice(&u_data);
        }
        if obj_bytes[byte_len as usize..].iter().any(|&b| b != 0) {
            return Ok(SlotValidationStatus::GraphInvalid {
                generation,
                store_uuid,
                region_units,
            });
        }
        let calculated_obj_id =
            independent_object_id(kind, version, byte_len, &obj_bytes[..byte_len as usize]);
        if calculated_obj_id != obj_id {
            return Ok(SlotValidationStatus::GraphInvalid {
                generation,
                store_uuid,
                region_units,
            });
        }
    }

    let commit_record = RawCommitRecord {
        record_version: 1,
        record_size: COMMIT_RECORD_SEMANTIC_BYTES as u16,
        format_major: 1,
        format_minor: 0,
        required_features: 0,
        compatible_features: 0,
        store_uuid,
        region_units,
        generation,
        previous_generation: c_prev_gen,
        previous_commit_id: c_prev_commit_id,
        previous_catalog_id: c_prev_catalog_id,
        catalog_id,
        catalog_first_unit,
        catalog_byte_length,
        catalog_unit_count,
        catalog_entry_count,
        committed_high_water: high_water,
    };

    Ok(SlotValidationStatus::Valid(Box::new(ValidatedRoot {
        slot: expected_slot,
        generation,
        store_uuid,
        region_units,
        commit_record_id,
        commit_record_unit,
        catalog_id,
        committed_high_water: high_water,
        commit_record,
    })))
}

// =========================================================================
// Tests: 13 Mount Cases & Semantic Distinction Qualification Suite
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_UUID: [u8; 16] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00,
    ];

    // =====================================================================
    // Requirement 2: Strict Semantic Distinctions in Error Taxonomy
    // =====================================================================

    #[test]
    fn test_error_taxonomy_strict_semantic_distinctions() {
        // Enforce all inequality relationships specified in Requirement 2:
        // - Unformatted != ForeignOrUnknown
        // - ForeignOrUnknown != UnsupportedVersion
        // - UnsupportedVersion != ConflictingRoots
        // - ConflictingRoots != InconsistentHistory
        // - InconsistentHistory != MountError::Io

        assert_ne!(
            MountClassification::Unformatted,
            MountClassification::ForeignOrUnknown
        );
        assert_ne!(
            MountClassification::ForeignOrUnknown,
            MountClassification::UnsupportedVersion
        );
        assert_ne!(
            MountClassification::UnsupportedVersion,
            MountClassification::ConflictingRoots
        );
        assert_ne!(
            MountClassification::ConflictingRoots,
            MountClassification::InconsistentHistory
        );
        assert_ne!(
            MountClassification::InconsistentHistory,
            MountClassification::IoError
        );

        let err_unformatted = MountError::Unformatted;
        let err_foreign = MountError::ForeignOrUnknown;
        let err_version = MountError::UnsupportedVersion {
            major: 2,
            minor: 0,
            required_features: 0,
        };
        let err_conflicting = MountError::ConflictingRoots;
        let err_inconsistent = MountError::InconsistentHistory {
            details: "bad predecessor".into(),
        };
        let err_io = MountError::Io {
            unit: 0,
            message: "hardware timeout".into(),
        };
        let err_corrupt = MountError::CorruptStore {
            details: "bad sha256".into(),
        };

        assert_ne!(err_unformatted, err_foreign);
        assert_ne!(err_foreign, err_version);
        assert_ne!(err_version, err_conflicting);
        assert_ne!(err_conflicting, err_inconsistent);
        assert_ne!(err_inconsistent, err_io);
        assert_ne!(err_io, err_corrupt);

        assert_eq!(
            err_unformatted.classification(),
            MountClassification::Unformatted
        );
        assert_eq!(
            err_foreign.classification(),
            MountClassification::ForeignOrUnknown
        );
        assert_eq!(
            err_version.classification(),
            MountClassification::UnsupportedVersion
        );
        assert_eq!(
            err_conflicting.classification(),
            MountClassification::ConflictingRoots
        );
        assert_eq!(
            err_inconsistent.classification(),
            MountClassification::InconsistentHistory
        );
        assert_eq!(err_io.classification(), MountClassification::IoError);
        assert_eq!(
            err_corrupt.classification(),
            MountClassification::CorruptStore
        );
    }

    // =====================================================================
    // Case 1: Same generation + equivalent root (both valid and identical -> valid)
    // =====================================================================

    #[test]
    fn test_case_1_same_generation_equivalent_roots() {
        let builder = SyntheticStoreBuilder::new(TEST_UUID, 16);
        let device = builder.build_genesis();

        let resolution = resolve_dual_superblocks(&device);
        assert_eq!(resolution.classification(), MountClassification::ValidStore);
        if let MountResolution::Valid {
            active_slot,
            generation,
            degraded_history,
            ..
        } = resolution
        {
            assert_eq!(active_slot, SuperblockSlot::SlotA);
            assert_eq!(generation, 1);
            assert!(!degraded_history);
        } else {
            panic!("expected Valid resolution, got {:?}", resolution);
        }
    }

    // =====================================================================
    // Case 2: Same generation + conflicting logical root (ConflictingRoots failure)
    // =====================================================================

    #[test]
    fn test_case_2_same_generation_conflicting_roots() {
        let builder = SyntheticStoreBuilder::new(TEST_UUID, 16);
        let mut device = builder.build_genesis();

        // Mutate Slot B CommitRecord to point to a different catalog ID
        let mut sb_b = device.read_unit(SUPERBLOCK_B_UNIT).unwrap();
        sb_b[104] ^= 0xff; // mutate catalog_id in superblock
                           // Recompute superblock B CRC
        sb_b[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].fill(0);
        let crc = independent_crc32c(&sb_b);
        sb_b[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
        device.write_unit(SUPERBLOCK_B_UNIT, &sb_b);

        // Also build a distinct valid commit record for Slot B at unit 4
        // to make Slot B internally valid but logically conflicting
        let mut commit_b = RawCommitRecord {
            record_version: 1,
            record_size: COMMIT_RECORD_SEMANTIC_BYTES as u16,
            format_major: 1,
            format_minor: 0,
            required_features: 0,
            compatible_features: 0,
            store_uuid: TEST_UUID,
            region_units: 16,
            generation: 1,
            previous_generation: 0,
            previous_commit_id: [0u8; 32],
            previous_catalog_id: [0u8; 32],
            catalog_id: [0xaa; 32],
            catalog_first_unit: 5,
            catalog_byte_length: 16,
            catalog_unit_count: 1,
            catalog_entry_count: 0,
            committed_high_water: 7,
        };
        device.write_unit(6, &commit_b.encode_unit());

        let empty_cat = RawCatalog { entries: vec![] };
        let cat_units = empty_cat.encode_units();
        device.write_unit(5, &cat_units[0]);
        commit_b.catalog_id = empty_cat.object_id();
        let commit_b_id = commit_b.object_id();
        device.write_unit(6, &commit_b.encode_unit());

        let sb_b_valid = RawSuperblock {
            format_major: 1,
            format_minor: 0,
            required_features: 0,
            compatible_features: 0,
            store_uuid: TEST_UUID,
            slot_id: 1,
            region_units: 16,
            generation: 1,
            commit_record_id: commit_b_id,
            commit_record_unit: 6,
            catalog_id: empty_cat.object_id(),
            catalog_first_unit: 5,
            catalog_byte_length: 16,
            catalog_unit_count: 1,
            catalog_entry_count: 0,
            committed_high_water: 7,
        };
        device.write_unit(SUPERBLOCK_B_UNIT, &sb_b_valid.encode());

        let resolution = resolve_dual_superblocks(&device);
        assert_eq!(
            resolution.classification(),
            MountClassification::ConflictingRoots
        );
        assert_eq!(
            resolution,
            MountResolution::Failed(MountError::ConflictingRoots)
        );
    }

    // =====================================================================
    // Case 3: Generation N and N-1 with exact predecessor link (valid Gen N)
    // =====================================================================

    #[test]
    fn test_case_3_adjacent_generation_exact_predecessor_link() {
        let builder = SyntheticStoreBuilder::new(TEST_UUID, 32);
        let mut device = builder.build_genesis();

        // Advance to Gen 2: Slot A has Gen 1, Slot B gets Gen 2
        builder.advance_generation(
            &mut device,
            SuperblockSlot::SlotA,
            SuperblockSlot::SlotB,
            b"hello world",
        );

        let resolution = resolve_dual_superblocks(&device);
        assert_eq!(resolution.classification(), MountClassification::ValidStore);
        if let MountResolution::Valid {
            active_slot,
            generation,
            degraded_history,
            ..
        } = resolution
        {
            assert_eq!(active_slot, SuperblockSlot::SlotB);
            assert_eq!(generation, 2);
            assert!(!degraded_history);
        } else {
            panic!("expected Valid resolution, got {:?}", resolution);
        }

        // Test symmetric direction: Slot B has Gen 2, Slot A gets Gen 3
        builder.advance_generation(
            &mut device,
            SuperblockSlot::SlotB,
            SuperblockSlot::SlotA,
            b"second payload",
        );
        let res3 = resolve_dual_superblocks(&device);
        assert_eq!(res3.classification(), MountClassification::ValidStore);
        if let MountResolution::Valid {
            active_slot,
            generation,
            degraded_history,
            ..
        } = res3
        {
            assert_eq!(active_slot, SuperblockSlot::SlotA);
            assert_eq!(generation, 3);
            assert!(!degraded_history);
        } else {
            panic!("expected Valid resolution, got {:?}", res3);
        }
    }

    // =====================================================================
    // Case 4: Generation N and N-1 with wrong predecessor link (InconsistentHistory)
    // =====================================================================

    #[test]
    fn test_case_4_adjacent_generation_wrong_predecessor_link() {
        let builder = SyntheticStoreBuilder::new(TEST_UUID, 32);
        let mut device = builder.build_genesis();
        builder.advance_generation(
            &mut device,
            SuperblockSlot::SlotA,
            SuperblockSlot::SlotB,
            b"hello",
        );

        // Read Slot B superblock to locate its commit record
        let sb_b_bytes = device.read_unit(SUPERBLOCK_B_UNIT).unwrap();
        let commit_unit = u64::from_le_bytes(sb_b_bytes[96..104].try_into().unwrap());
        let mut commit_bytes = device.read_unit(commit_unit).unwrap();

        // Tamper with previous_commit_id (offset 72..104)
        commit_bytes[72] ^= 0xff;
        // Recompute commit record ObjectId and update superblock
        let new_commit_id = independent_object_id(
            OBJECT_KIND_COMMIT_RECORD,
            OBJECT_VERSION_V1,
            COMMIT_RECORD_SEMANTIC_BYTES as u64,
            &commit_bytes[..COMMIT_RECORD_SEMANTIC_BYTES],
        );
        device.write_unit(commit_unit, &commit_bytes);

        let mut new_sb_b = sb_b_bytes;
        new_sb_b[64..96].copy_from_slice(&new_commit_id);
        new_sb_b[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].fill(0);
        let crc = independent_crc32c(&new_sb_b);
        new_sb_b[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4]
            .copy_from_slice(&crc.to_le_bytes());
        device.write_unit(SUPERBLOCK_B_UNIT, &new_sb_b);

        let resolution = resolve_dual_superblocks(&device);
        assert_eq!(
            resolution.classification(),
            MountClassification::InconsistentHistory
        );
        if let MountResolution::Failed(MountError::InconsistentHistory { .. }) = resolution {
            // Success
        } else {
            panic!("expected InconsistentHistory, got {:?}", resolution);
        }
    }

    // =====================================================================
    // Case 5: Generation N and N-2 (skip generation / InconsistentHistory failure)
    // =====================================================================

    #[test]
    fn test_case_5_skipped_generation() {
        let builder = SyntheticStoreBuilder::new(TEST_UUID, 64);
        let mut device = builder.build_genesis(); // Gen 1 in Slot A & B

        // Advance Gen 1 -> Gen 2 in Slot B
        builder.advance_generation(
            &mut device,
            SuperblockSlot::SlotA,
            SuperblockSlot::SlotB,
            b"gen2",
        );
        // Advance Gen 2 -> Gen 3 in Slot A
        builder.advance_generation(
            &mut device,
            SuperblockSlot::SlotB,
            SuperblockSlot::SlotA,
            b"gen3",
        );

        // Now restore Slot B back to Gen 1, so Slot A has Gen 3 and Slot B has Gen 1 (delta = 2)
        let genesis_device = builder.build_genesis();
        let gen1_sb = genesis_device.read_unit(SUPERBLOCK_B_UNIT).unwrap();
        device.write_unit(SUPERBLOCK_B_UNIT, &gen1_sb);

        let resolution = resolve_dual_superblocks(&device);
        assert_eq!(
            resolution.classification(),
            MountClassification::InconsistentHistory
        );
        if let MountResolution::Failed(MountError::InconsistentHistory { details }) = resolution {
            assert!(details.contains("non-adjacent"));
        } else {
            panic!("expected InconsistentHistory failure, got {:?}", resolution);
        }
    }

    // =====================================================================
    // Case 6: Newer root graph-invalid, older root valid (degraded recovery)
    // =====================================================================

    #[test]
    fn test_case_6_newer_graph_invalid_older_valid() {
        let builder = SyntheticStoreBuilder::new(TEST_UUID, 32);
        let mut device = builder.build_genesis();
        // Slot A has Gen 1 (older, valid), Slot B has Gen 2 (newer)
        builder.advance_generation(
            &mut device,
            SuperblockSlot::SlotA,
            SuperblockSlot::SlotB,
            b"gen2 payload",
        );

        // Corrupt the newer application object in Gen 2 (located at unit 4)
        device.corrupt_byte(4, 0, 0xaa);

        let resolution = resolve_dual_superblocks(&device);
        assert_eq!(
            resolution.classification(),
            MountClassification::DegradedRecovery
        );
        if let MountResolution::DegradedRecovery {
            active_slot,
            generation,
            ..
        } = resolution
        {
            assert_eq!(active_slot, SuperblockSlot::SlotA);
            assert_eq!(generation, 1);
        } else {
            panic!("expected DegradedRecovery, got {:?}", resolution);
        }

        // Test symmetric case: Slot B has Gen 2 (older, valid), Slot A has Gen 3 (newer, corrupted)
        let mut device2 = builder.build_genesis();
        builder.advance_generation(
            &mut device2,
            SuperblockSlot::SlotA,
            SuperblockSlot::SlotB,
            b"gen2",
        );
        builder.advance_generation(
            &mut device2,
            SuperblockSlot::SlotB,
            SuperblockSlot::SlotA,
            b"gen3 payload",
        );
        // Gen 3 app object at unit 7
        device2.corrupt_byte(7, 0, 0x55);

        let res2 = resolve_dual_superblocks(&device2);
        assert_eq!(res2.classification(), MountClassification::DegradedRecovery);
        if let MountResolution::DegradedRecovery {
            active_slot,
            generation,
            ..
        } = res2
        {
            assert_eq!(active_slot, SuperblockSlot::SlotB);
            assert_eq!(generation, 2);
        } else {
            panic!("expected DegradedRecovery to Slot B, got {:?}", res2);
        }
    }

    // =====================================================================
    // Case 7: Older root graph-invalid, newer root valid (valid newer, degraded history)
    // =====================================================================

    #[test]
    fn test_case_7_older_graph_invalid_newer_valid() {
        let builder = SyntheticStoreBuilder::new(TEST_UUID, 32);
        let mut device = builder.build_genesis();
        // Slot A has Gen 1 (older), Slot B has Gen 2 (newer)
        builder.advance_generation(
            &mut device,
            SuperblockSlot::SlotA,
            SuperblockSlot::SlotB,
            b"gen2 payload",
        );

        // Corrupt Gen 1 CommitRecord at unit 3
        device.corrupt_byte(3, 10, 0xff);

        let resolution = resolve_dual_superblocks(&device);
        assert_eq!(resolution.classification(), MountClassification::ValidStore);
        if let MountResolution::Valid {
            active_slot,
            generation,
            degraded_history,
            ..
        } = resolution
        {
            assert_eq!(active_slot, SuperblockSlot::SlotB);
            assert_eq!(generation, 2);
            assert!(
                degraded_history,
                "history must be marked degraded when older root is corrupt"
            );
        } else {
            panic!(
                "expected Valid with degraded_history=true, got {:?}",
                resolution
            );
        }
    }

    // =====================================================================
    // Case 8: Both roots graph-invalid (CorruptStore / unrecoverable)
    // =====================================================================

    #[test]
    fn test_case_8_both_roots_graph_invalid() {
        let builder = SyntheticStoreBuilder::new(TEST_UUID, 32);
        let mut device = builder.build_genesis();
        builder.advance_generation(
            &mut device,
            SuperblockSlot::SlotA,
            SuperblockSlot::SlotB,
            b"gen2",
        );

        // Corrupt Gen 1 commit record at unit 3
        device.corrupt_byte(3, 0, 0x11);
        // Corrupt Gen 2 commit record at unit 6
        device.corrupt_byte(6, 0, 0x22);

        let resolution = resolve_dual_superblocks(&device);
        assert_eq!(
            resolution.classification(),
            MountClassification::CorruptStore
        );
        if let MountResolution::Failed(MountError::CorruptStore { .. }) = resolution {
            // Success
        } else {
            panic!("expected CorruptStore, got {:?}", resolution);
        }
    }

    // =====================================================================
    // Case 9: All-zero region (Unformatted)
    // =====================================================================

    #[test]
    fn test_case_9_all_zero_region_unformatted() {
        let device = MockStoreDevice::new(16); // all units initialized to 0
        let resolution = resolve_dual_superblocks(&device);
        assert_eq!(
            resolution.classification(),
            MountClassification::Unformatted
        );
        assert_eq!(resolution, MountResolution::Failed(MountError::Unformatted));
    }

    // =====================================================================
    // Case 10: Unknown nonzero data in region (ForeignOrUnknown)
    // =====================================================================

    #[test]
    fn test_case_10_foreign_or_unknown() {
        let mut device = MockStoreDevice::new(16);
        // Write arbitrary non-AIENOS data to unit 0
        let foreign_data = b"EXT4-SUPERBLOCK-FOREIGN-FILE-SYSTEM-IDENTIFIER";
        let mut unit0 = [0u8; STORE_UNIT_BYTES];
        unit0[..foreign_data.len()].copy_from_slice(foreign_data);
        device.write_unit(0, &unit0);

        let resolution = resolve_dual_superblocks(&device);
        assert_eq!(
            resolution.classification(),
            MountClassification::ForeignOrUnknown
        );
        assert_eq!(
            resolution,
            MountResolution::Failed(MountError::ForeignOrUnknown)
        );
    }

    // =====================================================================
    // Case 11: Unsupported Store version (UnsupportedVersion)
    // =====================================================================

    #[test]
    fn test_case_11_unsupported_version_and_features() {
        let builder = SyntheticStoreBuilder::new(TEST_UUID, 16);

        // 1. Unsupported major version (e.g. 2.0)
        let mut device_major = builder.build_genesis();
        let mut sb_a = device_major.read_unit(SUPERBLOCK_A_UNIT).unwrap();
        sb_a[8..10].copy_from_slice(&2u16.to_le_bytes()); // major = 2
        sb_a[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].fill(0);
        let crc = independent_crc32c(&sb_a);
        sb_a[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
        device_major.write_unit(SUPERBLOCK_A_UNIT, &sb_a);

        let res_major = resolve_dual_superblocks(&device_major);
        assert_eq!(
            res_major.classification(),
            MountClassification::UnsupportedVersion
        );
        assert_eq!(
            res_major,
            MountResolution::Failed(MountError::UnsupportedVersion {
                major: 2,
                minor: 0,
                required_features: 0
            })
        );

        // 2. Unsupported minor version (e.g. 1.1)
        let mut device_minor = builder.build_genesis();
        let mut sb_minor = device_minor.read_unit(SUPERBLOCK_A_UNIT).unwrap();
        sb_minor[10..12].copy_from_slice(&1u16.to_le_bytes()); // minor = 1
        sb_minor[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].fill(0);
        let crc = independent_crc32c(&sb_minor);
        sb_minor[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4]
            .copy_from_slice(&crc.to_le_bytes());
        device_minor.write_unit(SUPERBLOCK_A_UNIT, &sb_minor);

        let res_minor = resolve_dual_superblocks(&device_minor);
        assert_eq!(
            res_minor.classification(),
            MountClassification::UnsupportedVersion
        );

        // 3. Unsupported required features mask
        let mut device_feat = builder.build_genesis();
        let mut sb_feat = device_feat.read_unit(SUPERBLOCK_B_UNIT).unwrap();
        sb_feat[12..20].copy_from_slice(&0x0001_0000u64.to_le_bytes());
        sb_feat[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].fill(0);
        let crc = independent_crc32c(&sb_feat);
        sb_feat[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4]
            .copy_from_slice(&crc.to_le_bytes());
        device_feat.write_unit(SUPERBLOCK_B_UNIT, &sb_feat);

        let res_feat = resolve_dual_superblocks(&device_feat);
        assert_eq!(
            res_feat.classification(),
            MountClassification::UnsupportedVersion
        );

        // 4. Verify rule: "do not fall back to another root" when one is unsupported version
        // Even though Slot A in device_feat is valid v1, resolution MUST NOT fall back!
        assert_eq!(
            res_feat.classification(),
            MountClassification::UnsupportedVersion
        );
    }

    // =====================================================================
    // Case 12: One root CRC-corrupt, other root valid (fallback to valid root)
    // =====================================================================

    #[test]
    fn test_case_12_one_root_crc_corrupt_fallback() {
        let builder = SyntheticStoreBuilder::new(TEST_UUID, 16);

        // Subcase A: Slot A CRC corrupt, Slot B valid -> selects Slot B
        let mut device_a = builder.build_genesis();
        device_a.corrupt_byte(SUPERBLOCK_A_UNIT, 50, 0xef); // corrupt body of Slot A without updating CRC

        let res_a = resolve_dual_superblocks(&device_a);
        assert_eq!(res_a.classification(), MountClassification::ValidStore);
        if let MountResolution::Valid {
            active_slot,
            generation,
            ..
        } = res_a
        {
            assert_eq!(active_slot, SuperblockSlot::SlotB);
            assert_eq!(generation, 1);
        } else {
            panic!("expected Valid with Slot B, got {:?}", res_a);
        }

        // Subcase B: Slot B CRC corrupt, Slot A valid -> selects Slot A
        let mut device_b = builder.build_genesis();
        device_b.corrupt_byte(SUPERBLOCK_B_UNIT, 50, 0xef); // corrupt body of Slot B without updating CRC

        let res_b = resolve_dual_superblocks(&device_b);
        assert_eq!(res_b.classification(), MountClassification::ValidStore);
        if let MountResolution::Valid {
            active_slot,
            generation,
            ..
        } = res_b
        {
            assert_eq!(active_slot, SuperblockSlot::SlotA);
            assert_eq!(generation, 1);
        } else {
            panic!("expected Valid with Slot A, got {:?}", res_b);
        }
    }

    // =====================================================================
    // Case 13: Required-device-read I/O error (MountError::Io)
    // =====================================================================

    #[test]
    fn test_case_13_device_io_errors_never_fallback_nor_corrupt() {
        let builder = SyntheticStoreBuilder::new(TEST_UUID, 32);

        // 1. I/O error on Unit 0 (Superblock A)
        let mut dev_io_0 = builder.build_genesis();
        dev_io_0.inject_io_fault(SUPERBLOCK_A_UNIT);
        let res_io_0 = resolve_dual_superblocks(&dev_io_0);
        assert_eq!(res_io_0.classification(), MountClassification::IoError);
        assert_ne!(res_io_0.classification(), MountClassification::CorruptStore);
        assert_ne!(res_io_0.classification(), MountClassification::ValidStore); // MUST NOT fall back to Slot B!
        if let MountResolution::Failed(MountError::Io { unit, .. }) = res_io_0 {
            assert_eq!(unit, 0);
        } else {
            panic!("expected MountError::Io, got {:?}", res_io_0);
        }

        // 2. I/O error on Unit 1 (Superblock B)
        let mut dev_io_1 = builder.build_genesis();
        dev_io_1.inject_io_fault(SUPERBLOCK_B_UNIT);
        let res_io_1 = resolve_dual_superblocks(&dev_io_1);
        assert_eq!(res_io_1.classification(), MountClassification::IoError);
        assert_ne!(res_io_1.classification(), MountClassification::ValidStore); // MUST NOT fall back to Slot A!

        // 3. I/O error on Commit Record unit (unit 3)
        let mut dev_io_commit = builder.build_genesis();
        dev_io_commit.inject_io_fault(3);
        let res_io_commit = resolve_dual_superblocks(&dev_io_commit);
        assert_eq!(res_io_commit.classification(), MountClassification::IoError);
        assert_ne!(
            res_io_commit.classification(),
            MountClassification::CorruptStore
        );

        // 4. I/O error on Catalog unit (unit 2)
        let mut dev_io_cat = builder.build_genesis();
        dev_io_cat.inject_io_fault(2);
        let res_io_cat = resolve_dual_superblocks(&dev_io_cat);
        assert_eq!(res_io_cat.classification(), MountClassification::IoError);
        assert_ne!(
            res_io_cat.classification(),
            MountClassification::CorruptStore
        );

        // 5. I/O error on Application Object unit
        let mut dev_io_app = builder.build_genesis();
        builder.advance_generation(
            &mut dev_io_app,
            SuperblockSlot::SlotA,
            SuperblockSlot::SlotB,
            b"payload",
        );
        // App object is at unit 4
        dev_io_app.inject_io_fault(4);
        let res_io_app = resolve_dual_superblocks(&dev_io_app);
        assert_eq!(res_io_app.classification(), MountClassification::IoError);
        assert_ne!(
            res_io_app.classification(),
            MountClassification::CorruptStore
        );
    }

    // =====================================================================
    // Additional Edge Cases: One root valid and one all-zero
    // =====================================================================

    #[test]
    fn test_one_root_valid_other_all_zero() {
        let builder = SyntheticStoreBuilder::new(TEST_UUID, 16);

        // Slot A valid, Slot B all zero
        let mut dev_b_zero = builder.build_genesis();
        dev_b_zero.write_unit(SUPERBLOCK_B_UNIT, &[0u8; STORE_UNIT_BYTES]);
        let res_b = resolve_dual_superblocks(&dev_b_zero);
        assert_eq!(res_b.classification(), MountClassification::ValidStore);
        if let MountResolution::Valid {
            active_slot,
            generation,
            ..
        } = res_b
        {
            assert_eq!(active_slot, SuperblockSlot::SlotA);
            assert_eq!(generation, 1);
        } else {
            panic!("expected Valid with Slot A, got {:?}", res_b);
        }

        // Slot B valid, Slot A all zero
        let mut dev_a_zero = builder.build_genesis();
        dev_a_zero.write_unit(SUPERBLOCK_A_UNIT, &[0u8; STORE_UNIT_BYTES]);
        let res_a = resolve_dual_superblocks(&dev_a_zero);
        assert_eq!(res_a.classification(), MountClassification::ValidStore);
        if let MountResolution::Valid {
            active_slot,
            generation,
            ..
        } = res_a
        {
            assert_eq!(active_slot, SuperblockSlot::SlotB);
            assert_eq!(generation, 1);
        } else {
            panic!("expected Valid with Slot B, got {:?}", res_a);
        }
    }

    #[test]
    fn test_same_generation_one_valid_one_graph_invalid_fails() {
        let builder = SyntheticStoreBuilder::new(TEST_UUID, 16);
        let mut device = builder.build_genesis(); // both Gen 1

        // Break commit record pointer in Slot B so it is GraphInvalid at Gen 1
        let mut sb_b = device.read_unit(SUPERBLOCK_B_UNIT).unwrap();
        sb_b[64] ^= 0x55; // wrong commit_record_id
        sb_b[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].fill(0);
        let crc = independent_crc32c(&sb_b);
        sb_b[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
        device.write_unit(SUPERBLOCK_B_UNIT, &sb_b);

        let resolution = resolve_dual_superblocks(&device);
        assert_eq!(
            resolution.classification(),
            MountClassification::CorruptStore
        );
    }
}
