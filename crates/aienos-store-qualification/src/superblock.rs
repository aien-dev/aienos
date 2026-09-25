//! Superblock adversarial qualification suite (G1) for AIENOS P3 System Store v1.
//!
//! Owns Superblock malformed-format fixtures and qualification tests conforming to ADR 0015.
//! Strictly uses the independent CRC32C oracle in `crate::oracle::independent_crc32c`.
//! NEVER calls or imports production CRC code.

use crate::oracle::{independent_crc32c, independent_object_id, STORE_UNIT_BYTES};

pub const SUPERBLOCK_MAGIC: &[u8; 8] = b"AIENSTR1";
pub const SUPERBLOCK_CRC_OFFSET: usize = 168;
pub const SUPERBLOCK_RESERVED_OFFSET: usize = 172;
pub const SUPERBLOCK_RESERVED_BYTES: usize = 3924;
pub const MAX_REGION_UNITS: u64 = 4_294_967_296;
pub const MIN_REGION_UNITS: u64 = 4;
pub const MIN_HIGH_WATER: u64 = 4;
pub const MAX_CATALOG_ENTRIES: u32 = 4096;
pub const CATALOG_HEADER_BYTES: usize = 16;
pub const CATALOG_ENTRY_BYTES: usize = 64;
pub const COMMIT_RECORD_BYTES: usize = 200;
pub const COMMIT_RECORD_MAGIC: &[u8; 8] = b"AIENCMT1";
pub const CATALOG_MAGIC: &[u8; 8] = b"AIENCAT1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuperblockError {
    Truncated {
        actual: usize,
        expected: usize,
    },
    BadMagic([u8; 8]),
    BadCrc {
        stored: u32,
        computed: u32,
    },
    NonzeroReserved {
        offset: usize,
        value: u8,
    },
    UnsupportedVersion {
        major: u16,
        minor: u16,
    },
    UnsupportedFeatures {
        required: u64,
        compatible: u64,
    },
    MalformedSlot {
        slot_id: u32,
    },
    WrongSlot {
        slot_id: u32,
        expected: u32,
    },
    RegionSizeInconsistency {
        declared: u64,
        reason: &'static str,
    },
    InvalidGeneration {
        generation: u64,
        reason: &'static str,
    },
    GenerationMismatch {
        sb_generation: u64,
        commit_generation: u64,
    },
    HighWaterError {
        high_water: u64,
        reason: &'static str,
    },
    MalformedCommitRecordDescriptor {
        reason: &'static str,
    },
    MalformedCatalogDescriptor {
        reason: &'static str,
    },
    CatalogCountDisagreement {
        declared_entries: u32,
        actual_entries: u32,
    },
    CommitRecordDisagreement {
        field: &'static str,
    },
    GraphValidationFailed {
        reason: &'static str,
    },
}

/// Decoded Superblock fields for independent qualification analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuperblockData {
    pub magic: [u8; 8],
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
    pub crc32c: u32,
}

/// Declared block-device physical geometry for region-size consistency checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockGeometry {
    pub block_size: u64,
    pub block_count: u64,
}

impl BlockGeometry {
    pub fn new(block_size: u64, block_count: u64) -> Self {
        Self {
            block_size,
            block_count,
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.block_size.saturating_mul(self.block_count)
    }

    pub fn total_units(&self) -> u64 {
        self.total_bytes() / (STORE_UNIT_BYTES as u64)
    }
}

/// Calculate Superblock CRC32C using strictly the independent software oracle.
/// Bytes 168..172 are treated as zero during calculation.
pub fn calculate_superblock_crc(unit: &[u8; STORE_UNIT_BYTES]) -> u32 {
    let mut scratch = *unit;
    scratch[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].fill(0);
    independent_crc32c(&scratch)
}

/// Compute and write independent CRC32C into bytes 168..172.
pub fn rechecksum_superblock(unit: &mut [u8; STORE_UNIT_BYTES]) {
    unit[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].fill(0);
    let crc = independent_crc32c(unit);
    unit[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
}

/// Builder for constructing valid and adversarial Superblock units (4096 bytes).
#[derive(Debug, Clone)]
pub struct SuperblockBuilder {
    pub magic: [u8; 8],
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
    pub reserved: [u8; SUPERBLOCK_RESERVED_BYTES],
}

impl Default for SuperblockBuilder {
    fn default() -> Self {
        Self::genesis(0)
    }
}

impl SuperblockBuilder {
    /// Construct a genesis Superblock baseline matching ADR 0015 specification and golden vectors.
    pub fn genesis(slot_id: u32) -> Self {
        // Pre-calculate canonical empty catalog and genesis commit record IDs
        let cat_semantic = [
            0x41, 0x49, 0x45, 0x4e, 0x43, 0x41, 0x54, 0x31, // "AIENCAT1"
            0x01, 0x00, // format_version: 1
            0x40, 0x00, // entry_size: 64
            0x00, 0x00, 0x00, 0x00, // entry_count: 0
        ];
        let catalog_id = independent_object_id(1, 1, 16, &cat_semantic);

        let mut cmt_semantic = [0u8; COMMIT_RECORD_BYTES];
        cmt_semantic[0..8].copy_from_slice(COMMIT_RECORD_MAGIC);
        cmt_semantic[8..10].copy_from_slice(&1u16.to_le_bytes()); // record_version: 1
        cmt_semantic[10..12].copy_from_slice(&200u16.to_le_bytes()); // record_size: 200
        cmt_semantic[12..14].copy_from_slice(&1u16.to_le_bytes()); // format_major: 1
        cmt_semantic[14..16].copy_from_slice(&0u16.to_le_bytes()); // format_minor: 0
        cmt_semantic[16..24].copy_from_slice(&0u64.to_le_bytes()); // required_features: 0
        cmt_semantic[24..32].copy_from_slice(&0u64.to_le_bytes()); // compatible_features: 0
        let store_uuid = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        cmt_semantic[32..48].copy_from_slice(&store_uuid);
        cmt_semantic[48..56].copy_from_slice(&16u64.to_le_bytes()); // region_units: 16
        cmt_semantic[56..64].copy_from_slice(&1u64.to_le_bytes()); // generation: 1
        cmt_semantic[64..72].copy_from_slice(&0u64.to_le_bytes()); // prev_generation: 0
        cmt_semantic[72..104].copy_from_slice(&[0u8; 32]); // prev_commit_id: 0
        cmt_semantic[104..136].copy_from_slice(&[0u8; 32]); // prev_catalog_id: 0
        cmt_semantic[136..168].copy_from_slice(&catalog_id);
        cmt_semantic[168..176].copy_from_slice(&2u64.to_le_bytes()); // catalog_first_unit: 2
        cmt_semantic[176..184].copy_from_slice(&16u64.to_le_bytes()); // catalog_byte_length: 16
        cmt_semantic[184..188].copy_from_slice(&1u32.to_le_bytes()); // catalog_unit_count: 1
        cmt_semantic[188..192].copy_from_slice(&0u32.to_le_bytes()); // catalog_entry_count: 0
        cmt_semantic[192..200].copy_from_slice(&4u64.to_le_bytes()); // committed_high_water: 4

        let commit_record_id = independent_object_id(2, 1, 200, &cmt_semantic);

        Self {
            magic: *SUPERBLOCK_MAGIC,
            format_major: 1,
            format_minor: 0,
            required_features: 0,
            compatible_features: 0,
            store_uuid,
            slot_id,
            region_units: 16,
            generation: 1,
            commit_record_id,
            commit_record_unit: 3,
            catalog_id,
            catalog_first_unit: 2,
            catalog_byte_length: 16,
            catalog_unit_count: 1,
            catalog_entry_count: 0,
            committed_high_water: 4,
            reserved: [0u8; SUPERBLOCK_RESERVED_BYTES],
        }
    }

    pub fn with_slot(mut self, slot: u32) -> Self {
        self.slot_id = slot;
        self
    }

    pub fn with_magic(mut self, magic: [u8; 8]) -> Self {
        self.magic = magic;
        self
    }

    pub fn with_version(mut self, major: u16, minor: u16) -> Self {
        self.format_major = major;
        self.format_minor = minor;
        self
    }

    pub fn with_features(mut self, required: u64, compatible: u64) -> Self {
        self.required_features = required;
        self.compatible_features = compatible;
        self
    }

    pub fn with_store_uuid(mut self, uuid: [u8; 16]) -> Self {
        self.store_uuid = uuid;
        self
    }

    pub fn with_region_units(mut self, r: u64) -> Self {
        self.region_units = r;
        self
    }

    pub fn with_generation(mut self, gen: u64) -> Self {
        self.generation = gen;
        self
    }

    pub fn with_commit_record(mut self, id: [u8; 32], unit: u64) -> Self {
        self.commit_record_id = id;
        self.commit_record_unit = unit;
        self
    }

    pub fn with_catalog(
        mut self,
        id: [u8; 32],
        first_unit: u64,
        byte_length: u64,
        unit_count: u32,
        entry_count: u32,
    ) -> Self {
        self.catalog_id = id;
        self.catalog_first_unit = first_unit;
        self.catalog_byte_length = byte_length;
        self.catalog_unit_count = unit_count;
        self.catalog_entry_count = entry_count;
        self
    }

    pub fn with_high_water(mut self, hw: u64) -> Self {
        self.committed_high_water = hw;
        self
    }

    /// Build a 4096-byte unit with raw (zero) CRC field.
    pub fn build_unit_unchecksummed(&self) -> [u8; STORE_UNIT_BYTES] {
        let mut bytes = [0u8; STORE_UNIT_BYTES];
        bytes[0..8].copy_from_slice(&self.magic);
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
        bytes[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].fill(0);
        bytes[SUPERBLOCK_RESERVED_OFFSET..].copy_from_slice(&self.reserved);
        bytes
    }

    /// Build a fully checksummed 4096-byte unit using the independent CRC32C oracle.
    pub fn build_unit(&self) -> [u8; STORE_UNIT_BYTES] {
        let mut bytes = self.build_unit_unchecksummed();
        rechecksum_superblock(&mut bytes);
        bytes
    }
}

/// Parse and validate a Superblock unit raw byte representation.
/// Validates CRC, magic, reserved bytes, slot ID, version, features, and field sanity.
pub fn parse_and_validate_superblock(
    bytes: &[u8],
    expected_slot: Option<u32>,
) -> Result<SuperblockData, SuperblockError> {
    if bytes.len() != STORE_UNIT_BYTES {
        return Err(SuperblockError::Truncated {
            actual: bytes.len(),
            expected: STORE_UNIT_BYTES,
        });
    }

    // 1. Magic check (first 8 bytes)
    let mut magic = [0u8; 8];
    magic.copy_from_slice(&bytes[0..8]);
    if &magic != SUPERBLOCK_MAGIC {
        return Err(SuperblockError::BadMagic(magic));
    }

    // 2. Physical credibility: Verify CRC32C via independent oracle
    let stored_crc = u32::from_le_bytes([
        bytes[SUPERBLOCK_CRC_OFFSET],
        bytes[SUPERBLOCK_CRC_OFFSET + 1],
        bytes[SUPERBLOCK_CRC_OFFSET + 2],
        bytes[SUPERBLOCK_CRC_OFFSET + 3],
    ]);

    let mut canonical = [0u8; STORE_UNIT_BYTES];
    canonical.copy_from_slice(bytes);
    canonical[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].fill(0);
    let computed_crc = independent_crc32c(&canonical);
    if stored_crc != computed_crc {
        return Err(SuperblockError::BadCrc {
            stored: stored_crc,
            computed: computed_crc,
        });
    }

    // 3. Strict reserved byte enforcement: bytes 172..4096 MUST BE ALL ZERO
    for (idx, &byte) in bytes[SUPERBLOCK_RESERVED_OFFSET..].iter().enumerate() {
        if byte != 0 {
            return Err(SuperblockError::NonzeroReserved {
                offset: SUPERBLOCK_RESERVED_OFFSET + idx,
                value: byte,
            });
        }
    }

    // 4. Format version check
    let format_major = u16::from_le_bytes([bytes[8], bytes[9]]);
    let format_minor = u16::from_le_bytes([bytes[10], bytes[11]]);
    if format_major != 1 || format_minor != 0 {
        return Err(SuperblockError::UnsupportedVersion {
            major: format_major,
            minor: format_minor,
        });
    }

    // 5. Feature flags check
    let required_features = u64::from_le_bytes(bytes[12..20].try_into().unwrap());
    let compatible_features = u64::from_le_bytes(bytes[20..28].try_into().unwrap());
    if required_features != 0 || compatible_features != 0 {
        return Err(SuperblockError::UnsupportedFeatures {
            required: required_features,
            compatible: compatible_features,
        });
    }

    // 6. Slot ID check
    let slot_id = u32::from_le_bytes(bytes[44..48].try_into().unwrap());
    if slot_id > 1 {
        return Err(SuperblockError::MalformedSlot { slot_id });
    }
    if let Some(expected) = expected_slot {
        if slot_id != expected {
            return Err(SuperblockError::WrongSlot { slot_id, expected });
        }
    }

    let mut store_uuid = [0u8; 16];
    store_uuid.copy_from_slice(&bytes[28..44]);

    // 7. Region units check
    let region_units = u64::from_le_bytes(bytes[48..56].try_into().unwrap());
    if region_units < MIN_REGION_UNITS {
        return Err(SuperblockError::RegionSizeInconsistency {
            declared: region_units,
            reason: "region_units less than minimum 4",
        });
    }
    if region_units > MAX_REGION_UNITS {
        return Err(SuperblockError::RegionSizeInconsistency {
            declared: region_units,
            reason: "region_units exceeds MAX_REGION_UNITS",
        });
    }

    // 8. Generation check
    let generation = u64::from_le_bytes(bytes[56..64].try_into().unwrap());
    if generation == 0 {
        return Err(SuperblockError::InvalidGeneration {
            generation,
            reason: "generation must be nonzero",
        });
    }

    let mut commit_record_id = [0u8; 32];
    commit_record_id.copy_from_slice(&bytes[64..96]);
    let commit_record_unit = u64::from_le_bytes(bytes[96..104].try_into().unwrap());

    let mut catalog_id = [0u8; 32];
    catalog_id.copy_from_slice(&bytes[104..136]);
    let catalog_first_unit = u64::from_le_bytes(bytes[136..144].try_into().unwrap());
    let catalog_byte_length = u64::from_le_bytes(bytes[144..152].try_into().unwrap());
    let catalog_unit_count = u32::from_le_bytes(bytes[152..156].try_into().unwrap());
    let catalog_entry_count = u32::from_le_bytes(bytes[156..160].try_into().unwrap());

    let committed_high_water = u64::from_le_bytes(bytes[160..168].try_into().unwrap());

    // 9. Catalog descriptor sanity
    if catalog_first_unit < 2 {
        return Err(SuperblockError::MalformedCatalogDescriptor {
            reason: "catalog_first_unit must be >= 2",
        });
    }
    if catalog_unit_count == 0 {
        return Err(SuperblockError::MalformedCatalogDescriptor {
            reason: "catalog_unit_count cannot be 0",
        });
    }
    if catalog_entry_count > MAX_CATALOG_ENTRIES {
        return Err(SuperblockError::CatalogCountDisagreement {
            declared_entries: catalog_entry_count,
            actual_entries: MAX_CATALOG_ENTRIES,
        });
    }
    let expected_cat_bytes = (CATALOG_HEADER_BYTES as u64)
        .checked_add(
            (catalog_entry_count as u64)
                .checked_mul(CATALOG_ENTRY_BYTES as u64)
                .ok_or(SuperblockError::MalformedCatalogDescriptor {
                    reason: "catalog byte length arithmetic overflow",
                })?,
        )
        .ok_or(SuperblockError::MalformedCatalogDescriptor {
            reason: "catalog byte length arithmetic overflow",
        })?;
    if catalog_byte_length != expected_cat_bytes {
        return Err(SuperblockError::MalformedCatalogDescriptor {
            reason: "catalog_byte_length does not match 16 + entry_count * 64",
        });
    }
    let expected_cat_units = catalog_byte_length.div_ceil(STORE_UNIT_BYTES as u64) as u32;
    if catalog_unit_count != expected_cat_units {
        return Err(SuperblockError::MalformedCatalogDescriptor {
            reason: "catalog_unit_count does not match ceil(catalog_byte_length / 4096)",
        });
    }
    let catalog_end = catalog_first_unit
        .checked_add(catalog_unit_count as u64)
        .ok_or(SuperblockError::MalformedCatalogDescriptor {
            reason: "catalog unit extent overflows u64",
        })?;
    if catalog_end >= region_units {
        return Err(SuperblockError::MalformedCatalogDescriptor {
            reason: "catalog extent overflows region boundary",
        });
    }

    // 10. CommitRecord descriptor sanity
    if commit_record_unit >= region_units {
        return Err(SuperblockError::MalformedCommitRecordDescriptor {
            reason: "commit_record_unit exceeds region_units",
        });
    }
    if commit_record_unit != catalog_end {
        return Err(SuperblockError::MalformedCommitRecordDescriptor {
            reason: "commit_record_unit must immediately follow catalog extent without holes",
        });
    }

    // 11. High-water sanity
    if committed_high_water < 2 {
        return Err(SuperblockError::HighWaterError {
            high_water: committed_high_water,
            reason: "high_water < 2 is strictly invalid",
        });
    }
    if committed_high_water < MIN_HIGH_WATER {
        return Err(SuperblockError::HighWaterError {
            high_water: committed_high_water,
            reason: "high_water < 4 violates minimum store layout",
        });
    }
    if committed_high_water > region_units {
        return Err(SuperblockError::HighWaterError {
            high_water: committed_high_water,
            reason: "high_water > region_units",
        });
    }
    if committed_high_water < commit_record_unit {
        return Err(SuperblockError::HighWaterError {
            high_water: committed_high_water,
            reason: "high_water < commit_record_unit",
        });
    }
    if committed_high_water != commit_record_unit + 1 {
        return Err(SuperblockError::HighWaterError {
            high_water: committed_high_water,
            reason: "high_water must equal commit_record_unit + 1",
        });
    }

    Ok(SuperblockData {
        magic,
        format_major,
        format_minor,
        required_features,
        compatible_features,
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

/// Verify declared block geometry against declared Superblock region units.
pub fn verify_superblock_geometry(
    sb: &SuperblockData,
    geometry: BlockGeometry,
) -> Result<(), SuperblockError> {
    let physical_units = geometry.total_units();
    if sb.region_units > physical_units {
        return Err(SuperblockError::RegionSizeInconsistency {
            declared: sb.region_units,
            reason: "declared region_units exceeds physical block device capacity",
        });
    }
    Ok(())
}

/// Verify Superblock graph consistency against commit record and catalog objects.
/// Enforces: CRC-valid DOES NOT imply graph-valid.
pub fn verify_superblock_graph(
    sb: &SuperblockData,
    commit_unit_bytes: Option<&[u8]>,
    catalog_unit_bytes: Option<&[u8]>,
) -> Result<(), SuperblockError> {
    if let Some(commit_bytes) = commit_unit_bytes {
        if commit_bytes.len() < STORE_UNIT_BYTES {
            return Err(SuperblockError::GraphValidationFailed {
                reason: "CommitRecord unit length is truncated",
            });
        }
        if &commit_bytes[0..8] != COMMIT_RECORD_MAGIC {
            return Err(SuperblockError::GraphValidationFailed {
                reason: "CommitRecord magic mismatch",
            });
        }
        // Commit record semantic bytes are exactly 200 bytes
        let semantic_commit = &commit_bytes[..COMMIT_RECORD_BYTES];
        let commit_padding = &commit_bytes[COMMIT_RECORD_BYTES..STORE_UNIT_BYTES];
        if commit_padding.iter().any(|&b| b != 0) {
            return Err(SuperblockError::GraphValidationFailed {
                reason: "CommitRecord non-zero padding in unit extent",
            });
        }
        // Recalculate CommitRecord ObjectId independently
        let calculated_commit_id =
            independent_object_id(2, 1, COMMIT_RECORD_BYTES as u64, semantic_commit);
        if calculated_commit_id != sb.commit_record_id {
            return Err(SuperblockError::CommitRecordDisagreement {
                field: "commit_record_id",
            });
        }

        let cmt_uuid: [u8; 16] = semantic_commit[32..48].try_into().unwrap();
        let cmt_region = u64::from_le_bytes(semantic_commit[48..56].try_into().unwrap());
        let cmt_gen = u64::from_le_bytes(semantic_commit[56..64].try_into().unwrap());
        let mut cmt_cat_id = [0u8; 32];
        cmt_cat_id.copy_from_slice(&semantic_commit[136..168]);
        let cmt_cat_first = u64::from_le_bytes(semantic_commit[168..176].try_into().unwrap());
        let cmt_cat_len = u64::from_le_bytes(semantic_commit[176..184].try_into().unwrap());
        let cmt_cat_units = u32::from_le_bytes(semantic_commit[184..188].try_into().unwrap());
        let cmt_cat_entries = u32::from_le_bytes(semantic_commit[188..192].try_into().unwrap());
        let cmt_high_water = u64::from_le_bytes(semantic_commit[192..200].try_into().unwrap());

        if cmt_gen != sb.generation {
            return Err(SuperblockError::GenerationMismatch {
                sb_generation: sb.generation,
                commit_generation: cmt_gen,
            });
        }
        if cmt_uuid != sb.store_uuid {
            return Err(SuperblockError::CommitRecordDisagreement {
                field: "store_uuid",
            });
        }
        if cmt_region != sb.region_units {
            return Err(SuperblockError::CommitRecordDisagreement {
                field: "region_units",
            });
        }
        if cmt_cat_id != sb.catalog_id {
            return Err(SuperblockError::CommitRecordDisagreement {
                field: "catalog_id",
            });
        }
        if cmt_cat_first != sb.catalog_first_unit {
            return Err(SuperblockError::CommitRecordDisagreement {
                field: "catalog_first_unit",
            });
        }
        if cmt_cat_len != sb.catalog_byte_length {
            return Err(SuperblockError::CommitRecordDisagreement {
                field: "catalog_byte_length",
            });
        }
        if cmt_cat_units != sb.catalog_unit_count {
            return Err(SuperblockError::CommitRecordDisagreement {
                field: "catalog_unit_count",
            });
        }
        if cmt_cat_entries != sb.catalog_entry_count {
            return Err(SuperblockError::CommitRecordDisagreement {
                field: "catalog_entry_count",
            });
        }
        if cmt_high_water != sb.committed_high_water {
            return Err(SuperblockError::CommitRecordDisagreement {
                field: "committed_high_water",
            });
        }
    }

    if let Some(cat_bytes) = catalog_unit_bytes {
        let expected_total_bytes = sb.catalog_unit_count as usize * STORE_UNIT_BYTES;
        if cat_bytes.len() < expected_total_bytes {
            return Err(SuperblockError::GraphValidationFailed {
                reason: "Catalog unit extent is truncated",
            });
        }
        if &cat_bytes[0..8] != CATALOG_MAGIC {
            return Err(SuperblockError::GraphValidationFailed {
                reason: "Catalog magic mismatch",
            });
        }
        let cat_entry_count = u32::from_le_bytes(cat_bytes[12..16].try_into().unwrap());
        if cat_entry_count != sb.catalog_entry_count {
            return Err(SuperblockError::CatalogCountDisagreement {
                declared_entries: sb.catalog_entry_count,
                actual_entries: cat_entry_count,
            });
        }
        let semantic_len = sb.catalog_byte_length as usize;
        let semantic_cat = &cat_bytes[..semantic_len];
        let padding_cat = &cat_bytes[semantic_len..expected_total_bytes];
        if padding_cat.iter().any(|&b| b != 0) {
            return Err(SuperblockError::GraphValidationFailed {
                reason: "Catalog non-zero padding in unit extent",
            });
        }
        let calculated_cat_id = independent_object_id(1, 1, sb.catalog_byte_length, semantic_cat);
        if calculated_cat_id != sb.catalog_id {
            return Err(SuperblockError::GraphValidationFailed {
                reason: "Catalog ObjectId mismatch",
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_golden_vector_superblock_a_and_b_crc() {
        let sb_a = SuperblockBuilder::genesis(0).build_unit();
        let parsed_a = parse_and_validate_superblock(&sb_a, Some(0)).expect("valid superblock A");
        assert_eq!(parsed_a.slot_id, 0);
        assert_eq!(parsed_a.generation, 1);
        assert_eq!(parsed_a.committed_high_water, 4);
        assert_eq!(parsed_a.crc32c, 0x275a77fc);

        let sb_b = SuperblockBuilder::genesis(1).build_unit();
        let parsed_b = parse_and_validate_superblock(&sb_b, Some(1)).expect("valid superblock B");
        assert_eq!(parsed_b.slot_id, 1);
        assert_eq!(parsed_b.generation, 1);
        assert_eq!(parsed_b.committed_high_water, 4);
        assert_eq!(parsed_b.crc32c, 0xe33e3598);

        // Superblock A and B differ only in slot_id and CRC
        assert_ne!(parsed_a.crc32c, parsed_b.crc32c);
        assert_ne!(sb_a[44..48], sb_b[44..48]);
        assert_eq!(sb_a[0..44], sb_b[0..44]);
        assert_eq!(sb_a[48..168], sb_b[48..168]);
        assert_eq!(sb_a[172..], sb_b[172..]);
    }

    #[test]
    fn test_adversarial_wrong_magic() {
        let base = SuperblockBuilder::genesis(0);

        let malformed_magics: [&[u8; 8]; 7] = [
            b"AIENOS_S", // wrong prefix
            b"AIENST01", // old ADR 0003 magic
            b"AIENCAT1", // catalog magic
            b"AIENCMT1", // commit magic
            b"NOTASTOR", // random ascii
            &[0u8; 8],   // all zeroes
            b"AIENSTR2", // version mutated magic
        ];

        for bad_magic in malformed_magics {
            let unit = base.clone().with_magic(*bad_magic).build_unit();
            let err = parse_and_validate_superblock(&unit, Some(0));
            assert_eq!(err, Err(SuperblockError::BadMagic(*bad_magic)));
        }

        // Test non-ASCII and single bit flip in magic
        let mut flipped_magic = *SUPERBLOCK_MAGIC;
        flipped_magic[0] ^= 0x01;
        let unit = base.clone().with_magic(flipped_magic).build_unit();
        assert_eq!(
            parse_and_validate_superblock(&unit, Some(0)),
            Err(SuperblockError::BadMagic(flipped_magic))
        );
    }

    #[test]
    fn test_adversarial_unsupported_format_version() {
        let base = SuperblockBuilder::genesis(0);

        for (major, minor) in [(0, 0), (2, 0), (0xFFFF, 0), (1, 1), (1, 0xFFFF), (2, 1)] {
            let unit = base.clone().with_version(major, minor).build_unit();
            let err = parse_and_validate_superblock(&unit, Some(0));
            assert_eq!(
                err,
                Err(SuperblockError::UnsupportedVersion { major, minor }),
                "testing major={major}, minor={minor}"
            );
        }
    }

    #[test]
    fn test_adversarial_unknown_features() {
        let base = SuperblockBuilder::genesis(0);

        for (req, comp) in [
            (1u64, 0u64),
            (1 << 63, 0),
            (0x1234, 0),
            (0, 1),
            (0, 1 << 63),
            (0, 0x5678),
            (1, 1),
        ] {
            let unit = base.clone().with_features(req, comp).build_unit();
            let err = parse_and_validate_superblock(&unit, Some(0));
            assert_eq!(
                err,
                Err(SuperblockError::UnsupportedFeatures {
                    required: req,
                    compatible: comp
                }),
                "testing required={req}, compatible={comp}"
            );
        }
    }

    #[test]
    fn test_adversarial_malformed_slot_id() {
        let base = SuperblockBuilder::genesis(0);

        for bad_slot in [2u32, 3, 4, 100, 0xFFFFFFFF] {
            let unit = base.clone().with_slot(bad_slot).build_unit();
            let err = parse_and_validate_superblock(&unit, None);
            assert_eq!(
                err,
                Err(SuperblockError::MalformedSlot { slot_id: bad_slot })
            );
        }

        // Test slot mismatch against expected slot
        let unit_a = base.clone().with_slot(0).build_unit();
        assert_eq!(
            parse_and_validate_superblock(&unit_a, Some(1)),
            Err(SuperblockError::WrongSlot {
                slot_id: 0,
                expected: 1
            })
        );

        let unit_b = base.clone().with_slot(1).build_unit();
        assert_eq!(
            parse_and_validate_superblock(&unit_b, Some(0)),
            Err(SuperblockError::WrongSlot {
                slot_id: 1,
                expected: 0
            })
        );
    }

    #[test]
    fn test_adversarial_region_size_inconsistency() {
        let base = SuperblockBuilder::genesis(0);

        // Region units less than minimum 4
        for bad_units in [0u64, 1, 2, 3] {
            let unit = base.clone().with_region_units(bad_units).build_unit();
            let err = parse_and_validate_superblock(&unit, Some(0));
            assert_eq!(
                err,
                Err(SuperblockError::RegionSizeInconsistency {
                    declared: bad_units,
                    reason: "region_units less than minimum 4"
                })
            );
        }

        // Region units exceeding MAX_REGION_UNITS (2^32 = 4,294,967,296)
        let too_large = MAX_REGION_UNITS + 1;
        let unit = base.clone().with_region_units(too_large).build_unit();
        assert_eq!(
            parse_and_validate_superblock(&unit, Some(0)),
            Err(SuperblockError::RegionSizeInconsistency {
                declared: too_large,
                reason: "region_units exceeds MAX_REGION_UNITS"
            })
        );

        // Inconsistency with physical device block geometry
        let valid_sb = parse_and_validate_superblock(&base.build_unit(), Some(0)).unwrap();
        // Base declares 16 units = 65,536 bytes.
        // Geometry providing only 8 units (e.g. 64 blocks of 512 bytes = 32,768 bytes = 8 units)
        let small_geometry = BlockGeometry::new(512, 64);
        assert_eq!(
            verify_superblock_geometry(&valid_sb, small_geometry),
            Err(SuperblockError::RegionSizeInconsistency {
                declared: 16,
                reason: "declared region_units exceeds physical block device capacity"
            })
        );

        // Sufficient geometry passes
        let adequate_geometry = BlockGeometry::new(4096, 32);
        assert!(verify_superblock_geometry(&valid_sb, adequate_geometry).is_ok());
    }

    #[test]
    fn test_adversarial_generation_errors() {
        let base = SuperblockBuilder::genesis(0);

        // Generation 0 is strictly illegal
        let unit_gen0 = base.clone().with_generation(0).build_unit();
        assert_eq!(
            parse_and_validate_superblock(&unit_gen0, Some(0)),
            Err(SuperblockError::InvalidGeneration {
                generation: 0,
                reason: "generation must be nonzero"
            })
        );

        // Generation mismatch with CommitRecord
        let valid_sb = parse_and_validate_superblock(&base.build_unit(), Some(0)).unwrap();
        let mut commit_bytes = [0u8; 4096];
        // Populate valid commit record
        commit_bytes[0..8].copy_from_slice(COMMIT_RECORD_MAGIC);
        commit_bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
        commit_bytes[10..12].copy_from_slice(&200u16.to_le_bytes());
        commit_bytes[12..14].copy_from_slice(&1u16.to_le_bytes());
        commit_bytes[14..16].copy_from_slice(&0u16.to_le_bytes());
        commit_bytes[32..48].copy_from_slice(&valid_sb.store_uuid);
        commit_bytes[48..56].copy_from_slice(&valid_sb.region_units.to_le_bytes());
        commit_bytes[56..64].copy_from_slice(&2u64.to_le_bytes()); // Generation 2 (mismatch with SB gen 1)
        commit_bytes[136..168].copy_from_slice(&valid_sb.catalog_id);
        commit_bytes[168..176].copy_from_slice(&valid_sb.catalog_first_unit.to_le_bytes());
        commit_bytes[176..184].copy_from_slice(&valid_sb.catalog_byte_length.to_le_bytes());
        commit_bytes[184..188].copy_from_slice(&valid_sb.catalog_unit_count.to_le_bytes());
        commit_bytes[188..192].copy_from_slice(&valid_sb.catalog_entry_count.to_le_bytes());
        commit_bytes[192..200].copy_from_slice(&valid_sb.committed_high_water.to_le_bytes());

        // Recompute object ID for mismatched commit
        let mismatched_id = independent_object_id(2, 1, 200, &commit_bytes[..200]);
        let mut sb_with_mismatched_cmt = valid_sb.clone();
        sb_with_mismatched_cmt.commit_record_id = mismatched_id;

        assert_eq!(
            verify_superblock_graph(&sb_with_mismatched_cmt, Some(&commit_bytes), None),
            Err(SuperblockError::GenerationMismatch {
                sb_generation: 1,
                commit_generation: 2
            })
        );
    }

    #[test]
    fn test_adversarial_high_water_errors() {
        let base = SuperblockBuilder::genesis(0);

        // high_water < 2
        for hw in [0u64, 1] {
            let unit = base.clone().with_high_water(hw).build_unit();
            assert_eq!(
                parse_and_validate_superblock(&unit, Some(0)),
                Err(SuperblockError::HighWaterError {
                    high_water: hw,
                    reason: "high_water < 2 is strictly invalid"
                })
            );
        }

        // high_water < 4
        for hw in [2u64, 3] {
            let unit = base.clone().with_high_water(hw).build_unit();
            assert_eq!(
                parse_and_validate_superblock(&unit, Some(0)),
                Err(SuperblockError::HighWaterError {
                    high_water: hw,
                    reason: "high_water < 4 violates minimum store layout"
                })
            );
        }

        // high_water > region_units (declared 16)
        let unit_overflow = base.clone().with_high_water(17).build_unit();
        assert_eq!(
            parse_and_validate_superblock(&unit_overflow, Some(0)),
            Err(SuperblockError::HighWaterError {
                high_water: 17,
                reason: "high_water > region_units"
            })
        );

        // high_water < commit_record_unit (commit_record_unit = 3)
        // With commit_record_unit = 5, region_units = 16:
        let unit_below_commit = base
            .clone()
            .with_catalog(base.catalog_id, 2, 16, 1, 0)
            .with_commit_record(base.commit_record_id, 3)
            .with_high_water(2)
            .build_unit();
        assert_eq!(
            parse_and_validate_superblock(&unit_below_commit, Some(0)),
            Err(SuperblockError::HighWaterError {
                high_water: 2,
                reason: "high_water < 4 violates minimum store layout"
            })
        );

        // high_water == commit_record_unit (must be commit_record_unit + 1)
        let unit_equal_commit = base.clone().with_high_water(3).build_unit();
        assert_eq!(
            parse_and_validate_superblock(&unit_equal_commit, Some(0)),
            Err(SuperblockError::HighWaterError {
                high_water: 3,
                reason: "high_water < 4 violates minimum store layout"
            })
        );

        // high_water != commit_record_unit + 1 (e.g. 5 instead of 4)
        let unit_not_adjacent = base.clone().with_high_water(5).build_unit();
        assert_eq!(
            parse_and_validate_superblock(&unit_not_adjacent, Some(0)),
            Err(SuperblockError::HighWaterError {
                high_water: 5,
                reason: "high_water must equal commit_record_unit + 1"
            })
        );
    }

    #[test]
    fn test_adversarial_malformed_commit_record_descriptor() {
        let base = SuperblockBuilder::genesis(0);

        // commit_record_unit not immediately following catalog (hole created)
        let unit_hole = base
            .clone()
            .with_catalog(base.catalog_id, 2, 16, 1, 0)
            .with_commit_record(base.commit_record_id, 4) // should be 3
            .with_high_water(5)
            .build_unit();
        assert_eq!(
            parse_and_validate_superblock(&unit_hole, Some(0)),
            Err(SuperblockError::MalformedCommitRecordDescriptor {
                reason: "commit_record_unit must immediately follow catalog extent without holes"
            })
        );

        // commit_record_unit >= region_units
        let unit_oob = base
            .clone()
            .with_catalog(base.catalog_id, 14, 16, 1, 0)
            .with_commit_record(base.commit_record_id, 16) // region is 16
            .with_high_water(17)
            .build_unit();
        assert_eq!(
            parse_and_validate_superblock(&unit_oob, Some(0)),
            Err(SuperblockError::MalformedCommitRecordDescriptor {
                reason: "commit_record_unit exceeds region_units"
            })
        );
    }

    #[test]
    fn test_adversarial_malformed_catalog_descriptor() {
        let base = SuperblockBuilder::genesis(0);

        // catalog_first_unit < 2 (units 0 and 1 are reserved for Superblocks)
        for bad_first in [0u64, 1] {
            let unit = base
                .clone()
                .with_catalog(base.catalog_id, bad_first, 16, 1, 0)
                .build_unit();
            assert_eq!(
                parse_and_validate_superblock(&unit, Some(0)),
                Err(SuperblockError::MalformedCatalogDescriptor {
                    reason: "catalog_first_unit must be >= 2"
                })
            );
        }

        // catalog_unit_count == 0
        let unit_zero_units = base
            .clone()
            .with_catalog(base.catalog_id, 2, 16, 0, 0)
            .build_unit();
        assert_eq!(
            parse_and_validate_superblock(&unit_zero_units, Some(0)),
            Err(SuperblockError::MalformedCatalogDescriptor {
                reason: "catalog_unit_count cannot be 0"
            })
        );

        // catalog byte length disagreement: length declared != 16 + count * 64
        let unit_bad_len = base
            .clone()
            .with_catalog(base.catalog_id, 2, 17, 1, 0) // declared 17 bytes for 0 entries
            .build_unit();
        assert_eq!(
            parse_and_validate_superblock(&unit_bad_len, Some(0)),
            Err(SuperblockError::MalformedCatalogDescriptor {
                reason: "catalog_byte_length does not match 16 + entry_count * 64"
            })
        );

        // catalog unit count disagreement: unit count != ceil(len / 4096)
        let unit_bad_units = base
            .clone()
            .with_catalog(base.catalog_id, 2, 16, 2, 0) // 16 bytes needs 1 unit, declared 2
            .build_unit();
        assert_eq!(
            parse_and_validate_superblock(&unit_bad_units, Some(0)),
            Err(SuperblockError::MalformedCatalogDescriptor {
                reason: "catalog_unit_count does not match ceil(catalog_byte_length / 4096)"
            })
        );

        // catalog extent overflowing region
        let unit_cat_overflow = base
            .clone()
            .with_catalog(base.catalog_id, 15, 16, 1, 0) // 15 + 1 = 16 == region_units
            .build_unit();
        assert_eq!(
            parse_and_validate_superblock(&unit_cat_overflow, Some(0)),
            Err(SuperblockError::MalformedCatalogDescriptor {
                reason: "catalog extent overflows region boundary"
            })
        );
    }

    #[test]
    fn test_adversarial_catalog_count_disagreement() {
        let base = SuperblockBuilder::genesis(0);

        // Declaring entry count exceeding MAX_CATALOG_ENTRIES (4096)
        let too_many_entries = MAX_CATALOG_ENTRIES + 1;
        let expected_bytes = 16 + (too_many_entries as u64) * 64;
        let unit_count = expected_bytes.div_ceil(4096) as u32;
        let unit = base
            .clone()
            .with_region_units(100)
            .with_catalog(
                base.catalog_id,
                2,
                expected_bytes,
                unit_count,
                too_many_entries,
            )
            .with_commit_record(base.commit_record_id, 2 + unit_count as u64)
            .with_high_water(2 + unit_count as u64 + 1)
            .build_unit();
        assert_eq!(
            parse_and_validate_superblock(&unit, Some(0)),
            Err(SuperblockError::CatalogCountDisagreement {
                declared_entries: too_many_entries,
                actual_entries: MAX_CATALOG_ENTRIES
            })
        );

        // Disagreement between SB declared entry count and actual Catalog object
        let valid_sb = parse_and_validate_superblock(&base.build_unit(), Some(0)).unwrap();
        let mut actual_catalog = [0u8; 4096];
        actual_catalog[0..8].copy_from_slice(CATALOG_MAGIC);
        actual_catalog[8..10].copy_from_slice(&1u16.to_le_bytes());
        actual_catalog[10..12].copy_from_slice(&64u16.to_le_bytes());
        actual_catalog[12..16].copy_from_slice(&1u32.to_le_bytes()); // Actual catalog has 1 entry, SB declared 0
        assert_eq!(
            verify_superblock_graph(&valid_sb, None, Some(&actual_catalog)),
            Err(SuperblockError::CatalogCountDisagreement {
                declared_entries: 0,
                actual_entries: 1
            })
        );
    }

    #[test]
    fn test_adversarial_nonzero_reserved_bytes() {
        let base = SuperblockBuilder::genesis(0);
        let valid_unit = base.build_unit();

        // 1. Corrupting any single reserved byte without recomputing CRC fails BadCrc
        let mut unchecksummed_corrupt = valid_unit;
        unchecksummed_corrupt[172] = 0x01;
        assert!(matches!(
            parse_and_validate_superblock(&unchecksummed_corrupt, Some(0)),
            Err(SuperblockError::BadCrc { .. })
        ));

        // 2. Corrupting reserved byte WITH recomputed valid CRC MUST FAIL NonzeroReserved!
        // Test key boundaries
        for target_offset in [
            SUPERBLOCK_RESERVED_OFFSET,     // 172 (first reserved byte)
            SUPERBLOCK_RESERVED_OFFSET + 1, // 173
            200,
            512,
            1024,
            2048,
            4095, // last reserved byte
        ] {
            let mut unit = valid_unit;
            unit[target_offset] = 0xA5;
            rechecksum_superblock(&mut unit);
            let err = parse_and_validate_superblock(&unit, Some(0));
            assert_eq!(
                err,
                Err(SuperblockError::NonzeroReserved {
                    offset: target_offset,
                    value: 0xA5
                }),
                "testing offset {target_offset}"
            );
        }

        // Exhaustive sweep across reserved bytes: step by 37 bytes to thoroughly cover the region
        let mut step_offset = SUPERBLOCK_RESERVED_OFFSET;
        while step_offset < STORE_UNIT_BYTES {
            let mut unit = valid_unit;
            unit[step_offset] = 0x55;
            rechecksum_superblock(&mut unit);
            assert_eq!(
                parse_and_validate_superblock(&unit, Some(0)),
                Err(SuperblockError::NonzeroReserved {
                    offset: step_offset,
                    value: 0x55
                }),
                "testing sweep offset {step_offset}"
            );
            step_offset += 37;
        }
    }

    #[test]
    fn test_adversarial_wrong_crc() {
        let base = SuperblockBuilder::genesis(0);
        let valid_unit = base.build_unit();

        // 1. Bit flip in CRC field (bytes 168..172)
        for crc_byte_offset in SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4 {
            for bit in 0..8 {
                let mut unit = valid_unit;
                unit[crc_byte_offset] ^= 1 << bit;
                let err = parse_and_validate_superblock(&unit, Some(0));
                assert!(
                    matches!(err, Err(SuperblockError::BadCrc { .. })),
                    "testing bit flip at crc offset {crc_byte_offset}, bit {bit}"
                );
            }
        }

        // 2. Bit flip in data payload without updating CRC
        for payload_offset in [
            8, 10, 12, 20, 28, 44, 48, 56, 64, 96, 136, 144, 152, 156, 160,
        ] {
            let mut unit = valid_unit;
            unit[payload_offset] ^= 0x01;
            let err = parse_and_validate_superblock(&unit, Some(0));
            assert!(
                matches!(err, Err(SuperblockError::BadCrc { .. })),
                "testing bit flip in payload offset {payload_offset}"
            );
        }
    }

    #[test]
    fn test_adversarial_truncated_superblock() {
        let base = SuperblockBuilder::genesis(0);
        let valid_unit = base.build_unit();

        for bad_len in [0, 1, 16, 64, 168, 172, 512, 1024, 4095] {
            let truncated = &valid_unit[..bad_len];
            assert_eq!(
                parse_and_validate_superblock(truncated, Some(0)),
                Err(SuperblockError::Truncated {
                    actual: bad_len,
                    expected: STORE_UNIT_BYTES
                }),
                "testing truncated length {bad_len}"
            );
        }

        // Oversized unit
        let mut oversized = vec![0u8; 4097];
        oversized[..4096].copy_from_slice(&valid_unit);
        assert_eq!(
            parse_and_validate_superblock(&oversized, Some(0)),
            Err(SuperblockError::Truncated {
                actual: 4097,
                expected: STORE_UNIT_BYTES
            })
        );
    }

    #[test]
    fn test_crc_valid_does_not_imply_graph_valid() {
        // Requirement 3: Explicitly verify that CRC-valid DOES NOT imply graph-valid.
        // A superblock with a perfectly valid CRC but pointing to invalid high-water,
        // corrupt commit descriptor, or broken graph relationships MUST be rejected!

        let base = SuperblockBuilder::genesis(0);

        // Case 1: Perfectly valid CRC, but pointing to invalid high-water (high_water < commit_unit)
        let mut sb1 = base
            .clone()
            .with_catalog(base.catalog_id, 2, 16, 1, 0)
            .with_commit_record(base.commit_record_id, 3)
            .with_high_water(2)
            .build_unit_unchecksummed();
        rechecksum_superblock(&mut sb1);
        // Verify CRC is mathematically valid
        let stored_crc1 = u32::from_le_bytes(sb1[168..172].try_into().unwrap());
        let computed_crc1 = calculate_superblock_crc(&sb1);
        assert_eq!(stored_crc1, computed_crc1, "CRC must be valid");
        // But validation MUST reject it!
        assert!(matches!(
            parse_and_validate_superblock(&sb1, Some(0)),
            Err(SuperblockError::HighWaterError { .. })
        ));

        // Case 2: Perfectly valid CRC, but high_water > region_units
        let mut sb2 = base.clone().with_high_water(999).build_unit_unchecksummed();
        rechecksum_superblock(&mut sb2);
        assert_eq!(
            calculate_superblock_crc(&sb2),
            u32::from_le_bytes(sb2[168..172].try_into().unwrap())
        );
        assert_eq!(
            parse_and_validate_superblock(&sb2, Some(0)),
            Err(SuperblockError::HighWaterError {
                high_water: 999,
                reason: "high_water > region_units"
            })
        );

        // Case 3: Perfectly valid CRC, but malformed CommitRecord descriptor (gap before commit record)
        let mut sb3 = base
            .clone()
            .with_catalog(base.catalog_id, 2, 16, 1, 0)
            .with_commit_record(base.commit_record_id, 5)
            .with_high_water(6)
            .build_unit_unchecksummed();
        rechecksum_superblock(&mut sb3);
        assert_eq!(
            calculate_superblock_crc(&sb3),
            u32::from_le_bytes(sb3[168..172].try_into().unwrap())
        );
        assert_eq!(
            parse_and_validate_superblock(&sb3, Some(0)),
            Err(SuperblockError::MalformedCommitRecordDescriptor {
                reason: "commit_record_unit must immediately follow catalog extent without holes"
            })
        );

        // Case 4: Perfectly valid CRC, but malformed catalog descriptor (catalog_unit_count == 0)
        let mut sb4 = base
            .clone()
            .with_catalog(base.catalog_id, 2, 16, 0, 0)
            .build_unit_unchecksummed();
        rechecksum_superblock(&mut sb4);
        assert_eq!(
            calculate_superblock_crc(&sb4),
            u32::from_le_bytes(sb4[168..172].try_into().unwrap())
        );
        assert_eq!(
            parse_and_validate_superblock(&sb4, Some(0)),
            Err(SuperblockError::MalformedCatalogDescriptor {
                reason: "catalog_unit_count cannot be 0"
            })
        );

        // Case 5: Perfectly valid CRC and format, but CommitRecord object on disk has corrupted payload
        let valid_sb_unit = base.build_unit();
        let parsed_valid_sb = parse_and_validate_superblock(&valid_sb_unit, Some(0)).unwrap();

        let mut corrupt_commit_extent = [0u8; 4096];
        corrupt_commit_extent[0..8].copy_from_slice(COMMIT_RECORD_MAGIC);
        corrupt_commit_extent[8..10].copy_from_slice(&1u16.to_le_bytes());
        corrupt_commit_extent[10..12].copy_from_slice(&200u16.to_le_bytes());
        corrupt_commit_extent[32..48].copy_from_slice(&parsed_valid_sb.store_uuid);
        // Corrupt generation inside commit record
        corrupt_commit_extent[56..64].copy_from_slice(&99u64.to_le_bytes());

        assert_eq!(
            verify_superblock_graph(&parsed_valid_sb, Some(&corrupt_commit_extent), None),
            Err(SuperblockError::CommitRecordDisagreement {
                field: "commit_record_id"
            })
        );

        // Case 6: Perfectly valid CRC and format, but physical device geometry is too small for declared region
        let restricted_device = BlockGeometry::new(512, 16); // 8,192 bytes = 2 units < declared 16 units
        assert_eq!(
            verify_superblock_geometry(&parsed_valid_sb, restricted_device),
            Err(SuperblockError::RegionSizeInconsistency {
                declared: 16,
                reason: "declared region_units exceeds physical block device capacity"
            })
        );
    }
}
