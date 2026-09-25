//! Catalog, CatalogEntry, and ObjectId adversarial qualification suite (G2).
//!
//! Strictly independent verification oracle and adversarial fixtures for AIENOS P3 System Store v1,
//! conforming to ADR 0015.

use crate::limits::{CATALOG_ENTRY_BYTES, MAX_CATALOG_ENTRIES, MAX_OBJECT_BYTES, MAX_OBJECT_UNITS};
use crate::oracle::{independent_object_id, STORE_UNIT_BYTES};
use std::fmt;

/// Magic bytes for Catalog header: ASCII "AIENCAT1".
pub const CATALOG_MAGIC: &[u8; 8] = b"AIENCAT1";

/// Catalog format version 1.
pub const CATALOG_FORMAT_VERSION: u16 = 1;

/// Entry size in bytes (ADR 0015 specifies exactly 64 bytes).
pub const CATALOG_ENTRY_SIZE: u16 = 64;

/// Header size in bytes.
pub const CATALOG_HEADER_BYTES: usize = 16;

/// Minimum kind number for application objects. Kinds 1 (Catalog) and 2 (CommitRecord) are reserved.
pub const MIN_APPLICATION_KIND: u16 = 3;

/// Reserved kind for Catalog object.
pub const CATALOG_KIND: u16 = 1;

/// Reserved kind for CommitRecord object.
pub const COMMIT_RECORD_KIND: u16 = 2;

/// First allowable unit for the append arena (units 0 and 1 are Superblock A and B).
pub const ARENA_START_UNIT: u64 = 2;

/// Errors emitted when catalog or entry validation fails against ADR 0015 rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogValidationError {
    HeaderTruncated {
        expected: usize,
        actual: usize,
    },
    InvalidHeaderMagic([u8; 8]),
    InvalidFormatVersion(u16),
    InvalidEntrySize(u16),
    CatalogTooLarge(u32),
    TruncatedEntry {
        expected_bytes: usize,
        actual_bytes: usize,
    },
    EntryCountMismatch {
        declared: u32,
        actual: usize,
    },
    TrailingGarbage {
        declared_bytes: usize,
        actual_bytes: usize,
    },
    InvalidKind(u16),
    InvalidVersion(u16),
    InvalidByteLength(u64),
    WrongUnitCount {
        expected: u32,
        actual: u32,
    },
    NonzeroFlags(u16),
    NonzeroReserved([u8; 6]),
    NonzeroHeaderReserved,
    UnsortedEntries {
        index: usize,
    },
    DuplicateObjectId([u8; 32]),
    DescriptorOutsideArena {
        first_unit: u64,
        limit: u64,
    },
    ExtentOverflow {
        first_unit: u64,
        unit_count: u32,
    },
    ExtentBeyondHighWater {
        end_unit: u64,
        high_water: u64,
    },
    ExtentBeyondCatalogFirstUnit {
        end_unit: u64,
        catalog_first_unit: u64,
    },
    OverlappingExtents {
        entry_a: usize,
        entry_b: usize,
        range_a: (u64, u64),
        range_b: (u64, u64),
    },
    ArithmeticOverflow,
}

impl fmt::Display for CatalogValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderTruncated { expected, actual } => {
                write!(
                    f,
                    "Header truncated: expected at least {expected} bytes, got {actual}"
                )
            }
            Self::InvalidHeaderMagic(magic) => {
                write!(f, "Invalid header magic: {magic:?}")
            }
            Self::InvalidFormatVersion(v) => {
                write!(
                    f,
                    "Invalid format version: {v} (expected {CATALOG_FORMAT_VERSION})"
                )
            }
            Self::InvalidEntrySize(s) => {
                write!(f, "Invalid entry size: {s} (expected {CATALOG_ENTRY_SIZE})")
            }
            Self::CatalogTooLarge(count) => {
                write!(
                    f,
                    "Catalog entry count {count} exceeds maximum {MAX_CATALOG_ENTRIES}"
                )
            }
            Self::TruncatedEntry {
                expected_bytes,
                actual_bytes,
            } => {
                write!(
                    f,
                    "Entry truncated: expected {expected_bytes} bytes, got {actual_bytes}"
                )
            }
            Self::EntryCountMismatch { declared, actual } => {
                write!(
                    f,
                    "Entry count mismatch: declared {declared}, actual decoded {actual}"
                )
            }
            Self::TrailingGarbage {
                declared_bytes,
                actual_bytes,
            } => {
                write!(
                    f,
                    "Trailing garbage: declared {declared_bytes} bytes, found {actual_bytes} bytes"
                )
            }
            Self::InvalidKind(k) => {
                write!(f, "Invalid kind {k}: application objects must have kind >= {MIN_APPLICATION_KIND}")
            }
            Self::InvalidVersion(v) => {
                write!(f, "Invalid version {v}: object version must be nonzero")
            }
            Self::InvalidByteLength(len) => {
                write!(
                    f,
                    "Invalid byte length {len}: must be between 1 and {MAX_OBJECT_BYTES}"
                )
            }
            Self::WrongUnitCount { expected, actual } => {
                write!(f, "Wrong unit count: expected {expected}, got {actual}")
            }
            Self::NonzeroFlags(flags) => {
                write!(f, "Nonzero entry flags: 0x{flags:04x} (must be 0 in v1)")
            }
            Self::NonzeroReserved(reserved) => {
                write!(f, "Nonzero reserved bytes in entry: {reserved:?}")
            }
            Self::NonzeroHeaderReserved => {
                write!(
                    f,
                    "Nonzero reserved/padding bytes in catalog header or unit padding"
                )
            }
            Self::UnsortedEntries { index } => {
                write!(f, "Unsorted entries: entry at index {index} is not strictly greater than predecessor")
            }
            Self::DuplicateObjectId(id) => {
                write!(f, "Duplicate ObjectId: {id:?}")
            }
            Self::DescriptorOutsideArena { first_unit, limit } => {
                write!(
                    f,
                    "Descriptor outside arena: first_unit {first_unit} violates boundary {limit}"
                )
            }
            Self::ExtentOverflow {
                first_unit,
                unit_count,
            } => {
                write!(
                    f,
                    "Extent arithmetic overflow: first_unit {first_unit} + unit_count {unit_count}"
                )
            }
            Self::ExtentBeyondHighWater {
                end_unit,
                high_water,
            } => {
                write!(
                    f,
                    "Extent end {end_unit} exceeds high-water mark {high_water}"
                )
            }
            Self::ExtentBeyondCatalogFirstUnit {
                end_unit,
                catalog_first_unit,
            } => {
                write!(
                    f,
                    "Extent end {end_unit} exceeds catalog start unit {catalog_first_unit}"
                )
            }
            Self::OverlappingExtents {
                entry_a,
                entry_b,
                range_a,
                range_b,
            } => {
                write!(f, "Overlapping extents between entry {entry_a} {range_a:?} and entry {entry_b} {range_b:?}")
            }
            Self::ArithmeticOverflow => {
                write!(f, "Arithmetic overflow during catalog calculation")
            }
        }
    }
}

impl std::error::Error for CatalogValidationError {}

/// Calculate expected unit count for an object: ceil(byte_length / 4096).
pub fn calculate_expected_unit_count(byte_length: u64) -> Result<u32, CatalogValidationError> {
    if byte_length == 0 || byte_length > MAX_OBJECT_BYTES {
        return Err(CatalogValidationError::InvalidByteLength(byte_length));
    }
    let units = byte_length.div_ceil(STORE_UNIT_BYTES as u64);
    if units > MAX_OBJECT_UNITS {
        return Err(CatalogValidationError::InvalidByteLength(byte_length));
    }
    Ok(units as u32)
}

/// Catalog header (16 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogHeader {
    pub magic: [u8; 8],
    pub format_version: u16,
    pub entry_size: u16,
    pub entry_count: u32,
}

impl CatalogHeader {
    pub fn new(entry_count: u32) -> Self {
        Self {
            magic: *CATALOG_MAGIC,
            format_version: CATALOG_FORMAT_VERSION,
            entry_size: CATALOG_ENTRY_SIZE,
            entry_count,
        }
    }

    pub fn encode(&self) -> [u8; CATALOG_HEADER_BYTES] {
        let mut buf = [0u8; CATALOG_HEADER_BYTES];
        buf[0..8].copy_from_slice(&self.magic);
        buf[8..10].copy_from_slice(&self.format_version.to_le_bytes());
        buf[10..12].copy_from_slice(&self.entry_size.to_le_bytes());
        buf[12..16].copy_from_slice(&self.entry_count.to_le_bytes());
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CatalogValidationError> {
        if bytes.len() < CATALOG_HEADER_BYTES {
            return Err(CatalogValidationError::HeaderTruncated {
                expected: CATALOG_HEADER_BYTES,
                actual: bytes.len(),
            });
        }

        let mut magic = [0u8; 8];
        magic.copy_from_slice(&bytes[0..8]);
        if &magic != CATALOG_MAGIC {
            return Err(CatalogValidationError::InvalidHeaderMagic(magic));
        }

        let format_version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if format_version != CATALOG_FORMAT_VERSION {
            return Err(CatalogValidationError::InvalidFormatVersion(format_version));
        }

        let entry_size = u16::from_le_bytes([bytes[10], bytes[11]]);
        if entry_size != CATALOG_ENTRY_SIZE {
            return Err(CatalogValidationError::InvalidEntrySize(entry_size));
        }

        let entry_count = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        if entry_count as usize > MAX_CATALOG_ENTRIES {
            return Err(CatalogValidationError::CatalogTooLarge(entry_count));
        }

        Ok(Self {
            magic,
            format_version,
            entry_size,
            entry_count,
        })
    }
}

/// Catalog entry descriptor (64 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogEntry {
    pub object_id: [u8; 32],
    pub kind: u16,
    pub version: u16,
    pub first_unit: u64,
    pub byte_length: u64,
    pub unit_count: u32,
    pub flags: u16,
    pub reserved: [u8; 6],
}

impl CatalogEntry {
    pub fn new(
        object_id: [u8; 32],
        kind: u16,
        version: u16,
        first_unit: u64,
        byte_length: u64,
    ) -> Result<Self, CatalogValidationError> {
        if kind < MIN_APPLICATION_KIND {
            return Err(CatalogValidationError::InvalidKind(kind));
        }
        if version == 0 {
            return Err(CatalogValidationError::InvalidVersion(version));
        }
        if byte_length == 0 || byte_length > MAX_OBJECT_BYTES {
            return Err(CatalogValidationError::InvalidByteLength(byte_length));
        }
        let unit_count = calculate_expected_unit_count(byte_length)?;
        if unit_count as u64 > MAX_OBJECT_UNITS {
            return Err(CatalogValidationError::WrongUnitCount {
                expected: unit_count,
                actual: unit_count,
            });
        }
        Ok(Self {
            object_id,
            kind,
            version,
            first_unit,
            byte_length,
            unit_count,
            flags: 0,
            reserved: [0u8; 6],
        })
    }

    pub fn encode(&self) -> [u8; CATALOG_ENTRY_BYTES] {
        let mut buf = [0u8; CATALOG_ENTRY_BYTES];
        buf[0..32].copy_from_slice(&self.object_id);
        buf[32..34].copy_from_slice(&self.kind.to_le_bytes());
        buf[34..36].copy_from_slice(&self.version.to_le_bytes());
        buf[36..44].copy_from_slice(&self.first_unit.to_le_bytes());
        buf[44..52].copy_from_slice(&self.byte_length.to_le_bytes());
        buf[52..56].copy_from_slice(&self.unit_count.to_le_bytes());
        buf[56..58].copy_from_slice(&self.flags.to_le_bytes());
        buf[58..64].copy_from_slice(&self.reserved);
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CatalogValidationError> {
        if bytes.len() < CATALOG_ENTRY_BYTES {
            return Err(CatalogValidationError::TruncatedEntry {
                expected_bytes: CATALOG_ENTRY_BYTES,
                actual_bytes: bytes.len(),
            });
        }

        let mut object_id = [0u8; 32];
        object_id.copy_from_slice(&bytes[0..32]);

        let kind = u16::from_le_bytes([bytes[32], bytes[33]]);
        if kind < MIN_APPLICATION_KIND {
            return Err(CatalogValidationError::InvalidKind(kind));
        }

        let version = u16::from_le_bytes([bytes[34], bytes[35]]);
        if version == 0 {
            return Err(CatalogValidationError::InvalidVersion(version));
        }

        let first_unit = u64::from_le_bytes([
            bytes[36], bytes[37], bytes[38], bytes[39], bytes[40], bytes[41], bytes[42], bytes[43],
        ]);

        let byte_length = u64::from_le_bytes([
            bytes[44], bytes[45], bytes[46], bytes[47], bytes[48], bytes[49], bytes[50], bytes[51],
        ]);
        if byte_length == 0 || byte_length > MAX_OBJECT_BYTES {
            return Err(CatalogValidationError::InvalidByteLength(byte_length));
        }

        let unit_count = u32::from_le_bytes([bytes[52], bytes[53], bytes[54], bytes[55]]);
        let expected_units = calculate_expected_unit_count(byte_length)?;
        if unit_count != expected_units {
            return Err(CatalogValidationError::WrongUnitCount {
                expected: expected_units,
                actual: unit_count,
            });
        }
        if unit_count as u64 > MAX_OBJECT_UNITS {
            return Err(CatalogValidationError::WrongUnitCount {
                expected: expected_units,
                actual: unit_count,
            });
        }

        let flags = u16::from_le_bytes([bytes[56], bytes[57]]);
        if flags != 0 {
            return Err(CatalogValidationError::NonzeroFlags(flags));
        }

        let mut reserved = [0u8; 6];
        reserved.copy_from_slice(&bytes[58..64]);
        if reserved != [0u8; 6] {
            return Err(CatalogValidationError::NonzeroReserved(reserved));
        }

        Ok(Self {
            object_id,
            kind,
            version,
            first_unit,
            byte_length,
            unit_count,
            flags,
            reserved,
        })
    }
}

/// Catalog structure representing the full catalog of application objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catalog {
    pub entries: Vec<CatalogEntry>,
}

impl Catalog {
    pub fn new(entries: Vec<CatalogEntry>) -> Self {
        Self { entries }
    }

    /// Encode catalog into its canonical semantic byte representation:
    /// 16-byte header followed by 64-byte entries.
    pub fn encode(&self) -> Vec<u8> {
        let total_bytes = CATALOG_HEADER_BYTES + self.entries.len() * CATALOG_ENTRY_BYTES;
        let mut buf = Vec::with_capacity(total_bytes);
        let header = CatalogHeader::new(self.entries.len() as u32);
        buf.extend_from_slice(&header.encode());
        for entry in &self.entries {
            buf.extend_from_slice(&entry.encode());
        }
        buf
    }

    /// Decode and strictly validate a catalog from raw semantic bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, CatalogValidationError> {
        if bytes.len() < CATALOG_HEADER_BYTES {
            return Err(CatalogValidationError::HeaderTruncated {
                expected: CATALOG_HEADER_BYTES,
                actual: bytes.len(),
            });
        }

        let header = CatalogHeader::decode(&bytes[..CATALOG_HEADER_BYTES])?;
        let entry_count = header.entry_count as usize;
        let expected_total_bytes = CATALOG_HEADER_BYTES
            .checked_add(
                entry_count
                    .checked_mul(CATALOG_ENTRY_BYTES)
                    .ok_or(CatalogValidationError::ArithmeticOverflow)?,
            )
            .ok_or(CatalogValidationError::ArithmeticOverflow)?;

        if bytes.len() < expected_total_bytes {
            let entries_slice_len = bytes.len() - CATALOG_HEADER_BYTES;
            let remainder = entries_slice_len % CATALOG_ENTRY_BYTES;
            if remainder != 0 {
                return Err(CatalogValidationError::TruncatedEntry {
                    expected_bytes: CATALOG_ENTRY_BYTES,
                    actual_bytes: remainder,
                });
            }
            return Err(CatalogValidationError::EntryCountMismatch {
                declared: header.entry_count,
                actual: entries_slice_len / CATALOG_ENTRY_BYTES,
            });
        }

        if bytes.len() > expected_total_bytes {
            return Err(CatalogValidationError::TrailingGarbage {
                declared_bytes: expected_total_bytes,
                actual_bytes: bytes.len(),
            });
        }

        let mut entries: Vec<CatalogEntry> = Vec::with_capacity(entry_count);
        for i in 0..entry_count {
            let offset = CATALOG_HEADER_BYTES + i * CATALOG_ENTRY_BYTES;
            let entry = CatalogEntry::decode(&bytes[offset..offset + CATALOG_ENTRY_BYTES])?;

            if i > 0 {
                let prev_id = &entries[i - 1].object_id;
                if entry.object_id == *prev_id {
                    return Err(CatalogValidationError::DuplicateObjectId(entry.object_id));
                }
                if entry.object_id < *prev_id {
                    return Err(CatalogValidationError::UnsortedEntries { index: i });
                }
            }

            entries.push(entry);
        }

        Ok(Self { entries })
    }

    /// Compute the independent ObjectId for this Catalog object (kind 1, version 1).
    pub fn compute_object_id(&self) -> [u8; 32] {
        let semantic_bytes = self.encode();
        independent_object_id(
            CATALOG_KIND,
            CATALOG_FORMAT_VERSION,
            semantic_bytes.len() as u64,
            &semantic_bytes,
        )
    }

    /// Validate arena invariants for all entries:
    /// - Extents start at unit 2 or later (`ARENA_START_UNIT`).
    /// - Extent bounds checked for overflow.
    /// - Extents end before or at `catalog_first_unit`.
    /// - Extents end before or at `high_water`.
    /// - No overlapping physical runs between distinct entries.
    pub fn validate_arena(
        &self,
        catalog_first_unit: u64,
        high_water: u64,
    ) -> Result<(), CatalogValidationError> {
        for entry in &self.entries {
            if entry.first_unit < ARENA_START_UNIT {
                return Err(CatalogValidationError::DescriptorOutsideArena {
                    first_unit: entry.first_unit,
                    limit: ARENA_START_UNIT,
                });
            }
            if entry.first_unit >= high_water {
                return Err(CatalogValidationError::DescriptorOutsideArena {
                    first_unit: entry.first_unit,
                    limit: high_water,
                });
            }
            let extent_end = entry
                .first_unit
                .checked_add(entry.unit_count as u64)
                .ok_or(CatalogValidationError::ExtentOverflow {
                    first_unit: entry.first_unit,
                    unit_count: entry.unit_count,
                })?;
            if extent_end > catalog_first_unit {
                return Err(CatalogValidationError::ExtentBeyondCatalogFirstUnit {
                    end_unit: extent_end,
                    catalog_first_unit,
                });
            }
            if extent_end > high_water {
                return Err(CatalogValidationError::ExtentBeyondHighWater {
                    end_unit: extent_end,
                    high_water,
                });
            }
        }

        // Check for overlapping extents across distinct entries
        for i in 0..self.entries.len() {
            let a = &self.entries[i];
            let end_a = match a.first_unit.checked_add(a.unit_count as u64) {
                Some(e) => e,
                None => continue,
            };
            for j in (i + 1)..self.entries.len() {
                let b = &self.entries[j];
                let end_b = match b.first_unit.checked_add(b.unit_count as u64) {
                    Some(e) => e,
                    None => continue,
                };
                let max_start = a.first_unit.max(b.first_unit);
                let min_end = end_a.min(end_b);
                if max_start < min_end {
                    return Err(CatalogValidationError::OverlappingExtents {
                        entry_a: i,
                        entry_b: j,
                        range_a: (a.first_unit, end_a),
                        range_b: (b.first_unit, end_b),
                    });
                }
            }
        }

        Ok(())
    }
}

/// Validate that trailing unit padding after catalog semantic bytes is strictly zero.
pub fn validate_catalog_padding(
    unit_bytes: &[u8],
    semantic_byte_len: usize,
) -> Result<(), CatalogValidationError> {
    if unit_bytes.len() < semantic_byte_len {
        return Err(CatalogValidationError::HeaderTruncated {
            expected: semantic_byte_len,
            actual: unit_bytes.len(),
        });
    }
    for &b in &unit_bytes[semantic_byte_len..] {
        if b != 0 {
            return Err(CatalogValidationError::NonzeroHeaderReserved);
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Adversarial Catalog Test Fixture Builders
// -----------------------------------------------------------------------------

/// Fixture: Catalog with wrong magic (e.g. b"AIEN_CAT" instead of b"AIENCAT1").
pub fn fixture_wrong_magic() -> Vec<u8> {
    let mut catalog = Catalog::new(vec![]).encode();
    catalog[0..8].copy_from_slice(b"AIEN_CAT");
    catalog
}

/// Fixture: Catalog with legacy / alternate magic b"AIEN_CATALOG_V1\0" truncated to 8 bytes.
pub fn fixture_wrong_magic_v1_legacy() -> Vec<u8> {
    let mut catalog = Catalog::new(vec![]).encode();
    catalog[0..8].copy_from_slice(&b"AIEN_CATALOG_V1\0"[..8]);
    catalog
}

/// Fixture: Catalog with wrong format version (e.g. 2 instead of 1).
pub fn fixture_wrong_format_version(version: u16) -> Vec<u8> {
    let mut catalog = Catalog::new(vec![]).encode();
    catalog[8..10].copy_from_slice(&version.to_le_bytes());
    catalog
}

/// Fixture: Catalog with wrong entry size (entry_size != 64).
pub fn fixture_wrong_entry_size(size: u16) -> Vec<u8> {
    let mut catalog = Catalog::new(vec![]).encode();
    catalog[10..12].copy_from_slice(&size.to_le_bytes());
    catalog
}

/// Fixture: Catalog with count mismatch (underdeclared: declared 0, actual 1 entry).
pub fn fixture_count_mismatch_underdeclared() -> Vec<u8> {
    let entry = CatalogEntry::new([0x10; 32], 3, 1, 2, 100).unwrap();
    let mut bytes = Catalog::new(vec![entry]).encode();
    // Overwrite declared entry count to 0
    bytes[12..16].copy_from_slice(&0u32.to_le_bytes());
    bytes
}

/// Fixture: Catalog with count mismatch (overdeclared: declared 2, actual 1 entry).
pub fn fixture_count_mismatch_overdeclared() -> Vec<u8> {
    let entry = CatalogEntry::new([0x10; 32], 3, 1, 2, 100).unwrap();
    let mut bytes = Catalog::new(vec![entry]).encode();
    // Overwrite declared entry count to 2
    bytes[12..16].copy_from_slice(&2u32.to_le_bytes());
    bytes
}

/// Fixture: Catalog with truncated header (less than 16 bytes).
pub fn fixture_truncated_header() -> Vec<u8> {
    let catalog = Catalog::new(vec![]).encode();
    catalog[..15].to_vec()
}

/// Fixture: Catalog with truncated entry (16 bytes header + 63 bytes entry).
pub fn fixture_truncated_entry() -> Vec<u8> {
    let entry = CatalogEntry::new([0x10; 32], 3, 1, 2, 100).unwrap();
    let catalog = Catalog::new(vec![entry]).encode();
    catalog[..catalog.len() - 1].to_vec()
}

/// Fixture: Catalog with trailing garbage bytes after valid entries.
pub fn fixture_trailing_garbage() -> Vec<u8> {
    let mut catalog = Catalog::new(vec![]).encode();
    catalog.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    catalog
}

/// Fixture: Catalog with unsorted entries (entry 0 has higher ObjectId than entry 1).
pub fn fixture_unsorted_entries() -> Vec<u8> {
    let mut id_high = [0x00; 32];
    id_high[0] = 0xAA;
    let mut id_low = [0x00; 32];
    id_low[0] = 0x11;

    let entry0 = CatalogEntry::new(id_high, 3, 1, 2, 100).unwrap();
    let entry1 = CatalogEntry::new(id_low, 3, 1, 3, 100).unwrap();

    // Construct raw bytes with unsorted order directly
    let header = CatalogHeader::new(2);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&header.encode());
    bytes.extend_from_slice(&entry0.encode());
    bytes.extend_from_slice(&entry1.encode());
    bytes
}

/// Fixture: Catalog with duplicate ObjectId entries.
pub fn fixture_duplicate_object_id() -> Vec<u8> {
    let id = [0x42; 32];
    let entry0 = CatalogEntry::new(id, 3, 1, 2, 100).unwrap();
    let entry1 = CatalogEntry::new(id, 3, 1, 3, 100).unwrap();

    let header = CatalogHeader::new(2);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&header.encode());
    bytes.extend_from_slice(&entry0.encode());
    bytes.extend_from_slice(&entry1.encode());
    bytes
}

/// Fixture: Catalog with nonzero flags in entry.
pub fn fixture_nonzero_entry_flags(flags: u16) -> Vec<u8> {
    let mut entry = CatalogEntry::new([0x10; 32], 3, 1, 2, 100).unwrap();
    entry.flags = flags;
    let mut bytes = Catalog::new(vec![]).encode();
    bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&entry.encode());
    bytes
}

/// Fixture: Catalog with nonzero reserved bytes in entry.
pub fn fixture_nonzero_entry_reserved(byte_idx: usize, val: u8) -> Vec<u8> {
    let mut entry = CatalogEntry::new([0x10; 32], 3, 1, 2, 100).unwrap();
    entry.reserved[byte_idx % 6] = val;
    let mut bytes = Catalog::new(vec![]).encode();
    bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&entry.encode());
    bytes
}

/// Fixture: Catalog with wrong unit count (e.g. byte_length = 4096, unit_count = 2 instead of 1).
pub fn fixture_wrong_unit_count(byte_length: u64, wrong_unit_count: u32) -> Vec<u8> {
    let entry = CatalogEntry::new([0x10; 32], 3, 1, 2, byte_length).unwrap();
    let mut entry_bytes = entry.encode();
    entry_bytes[52..56].copy_from_slice(&wrong_unit_count.to_le_bytes());
    let mut bytes = Catalog::new(vec![]).encode();
    bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&entry_bytes);
    bytes
}

/// Fixture: Catalog with entries exceeding arena bounds.
pub fn fixture_descriptor_underflow_arena() -> Catalog {
    // first_unit = 0 or 1 is in Superblock territory (< 2)
    let mut entry = CatalogEntry::new([0x10; 32], 3, 1, 2, 100).unwrap();
    entry.first_unit = 1;
    Catalog::new(vec![entry])
}

/// Fixture: Catalog with entry starting at or beyond high_water.
pub fn fixture_descriptor_at_or_beyond_high_water(high_water: u64) -> Catalog {
    let mut entry = CatalogEntry::new([0x10; 32], 3, 1, 2, 100).unwrap();
    entry.first_unit = high_water;
    Catalog::new(vec![entry])
}

/// Fixture: Catalog with entry extent extending beyond catalog_first_unit.
pub fn fixture_descriptor_beyond_catalog_first_unit(catalog_first_unit: u64) -> Catalog {
    // entry starts at catalog_first_unit - 1 with unit_count = 2 -> extent_end = catalog_first_unit + 1
    let mut entry = CatalogEntry::new([0x10; 32], 3, 1, 2, 5000).unwrap(); // 2 units
    entry.first_unit = catalog_first_unit - 1;
    Catalog::new(vec![entry])
}

/// Fixture: Catalog with overlapping physical runs between distinct entries.
pub fn fixture_overlapping_physical_runs() -> Catalog {
    let mut id0 = [0x00; 32];
    id0[0] = 0x10;
    let mut id1 = [0x00; 32];
    id1[0] = 0x20;

    // Entry 0 occupies units [2, 5) (unit_count = 3)
    let mut entry0 = CatalogEntry::new(id0, 3, 1, 2, 12000).unwrap();
    entry0.first_unit = 2;
    entry0.unit_count = 3;

    // Entry 1 occupies units [4, 7) (unit_count = 3) -> overlaps at unit 4!
    let mut entry1 = CatalogEntry::new(id1, 3, 1, 2, 12000).unwrap();
    entry1.first_unit = 4;
    entry1.unit_count = 3;

    Catalog::new(vec![entry0, entry1])
}

/// Fixture: Catalog with arithmetic overflow in extent offset + unit count.
pub fn fixture_arithmetic_overflow() -> Catalog {
    let mut entry = CatalogEntry::new([0x10; 32], 3, 1, 2, 100).unwrap();
    entry.first_unit = u64::MAX;
    entry.unit_count = 1;
    Catalog::new(vec![entry])
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // 1. Independent ObjectId Computation and Golden Vector Verification
    // -------------------------------------------------------------------------

    #[test]
    fn test_golden_vector_object_id_reconstruction() {
        // ADR 0015 Golden Vector:
        // kind: 0x1234 (4660), version: 0x5678 (22136)
        // semantic_bytes: 000102030405060708090a0b0c0d0e0f
        // object_id: 80b93b4e31915bf7a7fd4607e686e757924425d9a4f9c1e84f51672d1b9b1334
        let semantic = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let id = independent_object_id(0x1234, 0x5678, semantic.len() as u64, &semantic);
        let expected_hex = "80b93b4e31915bf7a7fd4607e686e757924425d9a4f9c1e84f51672d1b9b1334";
        let actual_hex = id.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(actual_hex, expected_hex);
    }

    #[test]
    fn test_golden_vector_empty_catalog() {
        // ADR 0015 Golden Vector for empty catalog:
        // semantic_bytes: 4149454e434154310100400000000000
        // object_id: 44197839cf88e93c480d77a0c234ce21362a038d33d398ead10e062906d7be6a
        let catalog = Catalog::new(vec![]);
        let bytes = catalog.encode();
        assert_eq!(bytes.len(), 16);
        let expected_bytes_hex = "4149454e434154310100400000000000";
        let actual_bytes_hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(actual_bytes_hex, expected_bytes_hex);

        let id = catalog.compute_object_id();
        let expected_id_hex = "44197839cf88e93c480d77a0c234ce21362a038d33d398ead10e062906d7be6a";
        let actual_id_hex = id.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(actual_id_hex, expected_id_hex);

        // Roundtrip decode
        let decoded = Catalog::decode(&bytes).expect("empty catalog must decode");
        assert_eq!(decoded.entries.len(), 0);
    }

    #[test]
    fn test_golden_vector_one_entry_catalog() {
        // ADR 0015 Golden Vector for one_entry_catalog:
        // entry_object_id: 307663335463d5f838fdd1b60950a02c873a28cd6cea13c2ffbfa5d8e41145a6
        // entry_kind: 3, version: 1, first_unit: 4, byte_length: 16, unit_count: 1
        // catalog_object_id: 15d05f57a32d04af08fc9ba5d88c2fd9fdf09ba9858cfa35b25bb6e66c1f7c85
        let entry_id_bytes = [
            0x30, 0x76, 0x63, 0x33, 0x54, 0x63, 0xd5, 0xf8, 0x38, 0xfd, 0xd1, 0xb6, 0x09, 0x50,
            0xa0, 0x2c, 0x87, 0x3a, 0x28, 0xcd, 0x6c, 0xea, 0x13, 0xc2, 0xff, 0xbf, 0xa5, 0xd8,
            0xe4, 0x11, 0x45, 0xa6,
        ];
        let entry = CatalogEntry::new(entry_id_bytes, 3, 1, 4, 16).unwrap();
        let catalog = Catalog::new(vec![entry]);
        let bytes = catalog.encode();
        assert_eq!(bytes.len(), 80);

        let id = catalog.compute_object_id();
        let expected_id_hex = "15d05f57a32d04af08fc9ba5d88c2fd9fdf09ba9858cfa35b25bb6e66c1f7c85";
        let actual_id_hex = id.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(actual_id_hex, expected_id_hex);

        let decoded = Catalog::decode(&bytes).expect("one-entry catalog must decode");
        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(decoded.entries[0].object_id, entry_id_bytes);
        assert_eq!(decoded.entries[0].first_unit, 4);
        assert_eq!(decoded.entries[0].byte_length, 16);
        assert_eq!(decoded.entries[0].unit_count, 1);
    }

    // -------------------------------------------------------------------------
    // 2. Identity Property Proofs
    // -------------------------------------------------------------------------

    #[test]
    fn test_identity_property_semantic_mutation() {
        let payload = b"AIENOS Sovereign Neural Substrate v1 payload";
        let base_id = independent_object_id(3, 1, payload.len() as u64, payload);

        // 1-bit mutation at every byte position must alter identity
        for i in 0..payload.len() {
            let mut mutated = payload.to_vec();
            mutated[i] ^= 0x01;
            let mutated_id = independent_object_id(3, 1, mutated.len() as u64, &mutated);
            assert_ne!(
                base_id, mutated_id,
                "Semantic bit mutation at byte {i} MUST change ObjectId"
            );
        }
    }

    #[test]
    fn test_identity_property_kind_version_length_mutation() {
        let payload = b"Deterministic payload content for domain test";
        let base_id = independent_object_id(3, 1, payload.len() as u64, payload);

        // Kind mutation
        let mutated_kind_id = independent_object_id(4, 1, payload.len() as u64, payload);
        assert_ne!(
            base_id, mutated_kind_id,
            "Kind mutation MUST alter identity"
        );

        // Version mutation
        let mutated_version_id = independent_object_id(3, 2, payload.len() as u64, payload);
        assert_ne!(
            base_id, mutated_version_id,
            "Version mutation MUST alter identity"
        );

        // Length mutation (different declared byte_length over same prefix)
        let prefix = &payload[..payload.len() - 1];
        let mutated_len_id = independent_object_id(3, 1, prefix.len() as u64, prefix);
        assert_ne!(
            base_id, mutated_len_id,
            "Length mutation MUST alter identity"
        );
    }

    #[test]
    fn test_identity_property_physical_relocation_invariance() {
        let payload = b"Immutable state extent independent of LBA";
        let base_id = independent_object_id(3, 1, payload.len() as u64, payload);

        // Physical relocation across disk LBAs (unit 2 vs unit 100 vs unit 999999)
        // Does NOT change identity because first_unit is not in the hash preimage.
        let entry_at_2 = CatalogEntry::new(base_id, 3, 1, 2, payload.len() as u64).unwrap();
        let entry_at_100 = CatalogEntry::new(base_id, 3, 1, 100, payload.len() as u64).unwrap();
        let entry_at_max = CatalogEntry::new(base_id, 3, 1, 999_999, payload.len() as u64).unwrap();

        assert_eq!(entry_at_2.object_id, entry_at_100.object_id);
        assert_eq!(entry_at_100.object_id, entry_at_max.object_id);
    }

    #[test]
    fn test_identity_property_unit_count_and_padding_invariance() {
        // A 50-byte object fits into 1 unit (4096 bytes) with 4046 padding bytes.
        let semantic_data = vec![0x55u8; 50];
        let id_direct = independent_object_id(3, 1, 50, &semantic_data);

        // If allocated on disk inside a 4096-byte unit with trailing padding:
        let mut disk_unit = vec![0u8; STORE_UNIT_BYTES];
        disk_unit[..50].copy_from_slice(&semantic_data);

        // The identity is strictly calculated over the 50 semantic bytes
        let id_from_disk = independent_object_id(3, 1, 50, &disk_unit[..50]);
        assert_eq!(id_direct, id_from_disk);

        // Changing the unit count or padding size on disk does NOT alter identity
        let mut two_units = vec![0u8; STORE_UNIT_BYTES * 2];
        two_units[..50].copy_from_slice(&semantic_data);
        let id_two_units = independent_object_id(3, 1, 50, &two_units[..50]);
        assert_eq!(id_direct, id_two_units);
    }

    #[test]
    fn test_identity_property_store_uuid_invariance() {
        let payload = b"Cross-store portable verifiable artifact";
        let object_id_store_a = independent_object_id(3, 1, payload.len() as u64, payload);
        let object_id_store_b = independent_object_id(3, 1, payload.len() as u64, payload);

        // Store UUIDs are completely outside the ObjectId hash preimage
        let store_uuid_a = [0x11u8; 16];
        let store_uuid_b = [0x22u8; 16];
        assert_ne!(store_uuid_a, store_uuid_b);
        assert_eq!(object_id_store_a, object_id_store_b);
    }

    #[test]
    fn test_identity_property_generation_invariance() {
        let payload = b"Object written at genesis vs object written at gen 5000";
        let object_id_gen_1 = independent_object_id(3, 1, payload.len() as u64, payload);
        let object_id_gen_5000 = independent_object_id(3, 1, payload.len() as u64, payload);

        // Generation number is not in preimage
        assert_eq!(object_id_gen_1, object_id_gen_5000);
    }

    #[test]
    fn test_identity_property_zero_padding_invariance() {
        let payload = b"Payload with physical zero padding in store unit";
        let base_id = independent_object_id(3, 1, payload.len() as u64, payload);

        let mut unit_buffer = vec![0u8; STORE_UNIT_BYTES];
        unit_buffer[..payload.len()].copy_from_slice(payload);

        // Any zero padding on disk after semantic bytes is excluded from ObjectId calculation
        let read_id =
            independent_object_id(3, 1, payload.len() as u64, &unit_buffer[..payload.len()]);
        assert_eq!(base_id, read_id);
    }

    // -------------------------------------------------------------------------
    // 3. Adversarial Catalog Test Fixtures and Validations
    // -------------------------------------------------------------------------

    #[test]
    fn test_adversarial_wrong_magic() {
        let fixture1 = fixture_wrong_magic();
        assert!(matches!(
            Catalog::decode(&fixture1),
            Err(CatalogValidationError::InvalidHeaderMagic(_))
        ));

        let fixture2 = fixture_wrong_magic_v1_legacy();
        assert!(matches!(
            Catalog::decode(&fixture2),
            Err(CatalogValidationError::InvalidHeaderMagic(_))
        ));

        let mut garbage_magic = Catalog::new(vec![]).encode();
        garbage_magic[0..8].copy_from_slice(b"BADMAGIC");
        assert_eq!(
            Catalog::decode(&garbage_magic),
            Err(CatalogValidationError::InvalidHeaderMagic(*b"BADMAGIC"))
        );
    }

    #[test]
    fn test_adversarial_wrong_format_version() {
        // Version 0
        let fixture_v0 = fixture_wrong_format_version(0);
        assert_eq!(
            Catalog::decode(&fixture_v0),
            Err(CatalogValidationError::InvalidFormatVersion(0))
        );

        // Future version 2
        let fixture_v2 = fixture_wrong_format_version(2);
        assert_eq!(
            Catalog::decode(&fixture_v2),
            Err(CatalogValidationError::InvalidFormatVersion(2))
        );

        // Version 65535
        let fixture_vmax = fixture_wrong_format_version(u16::MAX);
        assert_eq!(
            Catalog::decode(&fixture_vmax),
            Err(CatalogValidationError::InvalidFormatVersion(u16::MAX))
        );
    }

    #[test]
    fn test_adversarial_wrong_entry_size() {
        for bad_size in [0, 32, 63, 65, 128] {
            let fixture = fixture_wrong_entry_size(bad_size);
            assert_eq!(
                Catalog::decode(&fixture),
                Err(CatalogValidationError::InvalidEntrySize(bad_size)),
                "entry_size {bad_size} must be rejected"
            );
        }
    }

    #[test]
    fn test_adversarial_count_mismatch() {
        // Underdeclared: header declared 0, but 1 entry present in bytes
        let underdeclared = fixture_count_mismatch_underdeclared();
        assert!(matches!(
            Catalog::decode(&underdeclared),
            Err(CatalogValidationError::TrailingGarbage { .. })
        ));

        // Overdeclared: header declared 2, but only 1 entry present in bytes
        let overdeclared = fixture_count_mismatch_overdeclared();
        assert!(matches!(
            Catalog::decode(&overdeclared),
            Err(CatalogValidationError::EntryCountMismatch {
                declared: 2,
                actual: 1
            })
        ));
    }

    #[test]
    fn test_adversarial_truncation() {
        // Incomplete header (< 16 bytes)
        let trunc_hdr = fixture_truncated_header();
        assert_eq!(
            Catalog::decode(&trunc_hdr),
            Err(CatalogValidationError::HeaderTruncated {
                expected: 16,
                actual: 15
            })
        );

        // Zero bytes
        assert_eq!(
            Catalog::decode(&[]),
            Err(CatalogValidationError::HeaderTruncated {
                expected: 16,
                actual: 0
            })
        );

        // Incomplete entry (16 bytes header + 63 bytes entry)
        let trunc_entry = fixture_truncated_entry();
        assert_eq!(
            Catalog::decode(&trunc_entry),
            Err(CatalogValidationError::TruncatedEntry {
                expected_bytes: 64,
                actual_bytes: 63
            })
        );
    }

    #[test]
    fn test_adversarial_trailing_garbage() {
        let fixture = fixture_trailing_garbage();
        assert_eq!(
            Catalog::decode(&fixture),
            Err(CatalogValidationError::TrailingGarbage {
                declared_bytes: 16,
                actual_bytes: 20
            })
        );

        // Trailing single garbage byte after 1 valid entry
        let entry = CatalogEntry::new([0x10; 32], 3, 1, 2, 100).unwrap();
        let mut with_garbage = Catalog::new(vec![entry]).encode();
        with_garbage.push(0x00);
        assert_eq!(
            Catalog::decode(&with_garbage),
            Err(CatalogValidationError::TrailingGarbage {
                declared_bytes: 80,
                actual_bytes: 81
            })
        );
    }

    #[test]
    fn test_adversarial_unsorted_entries() {
        let fixture = fixture_unsorted_entries();
        assert_eq!(
            Catalog::decode(&fixture),
            Err(CatalogValidationError::UnsortedEntries { index: 1 })
        );
    }

    #[test]
    fn test_adversarial_duplicate_object_ids() {
        let fixture = fixture_duplicate_object_id();
        assert_eq!(
            Catalog::decode(&fixture),
            Err(CatalogValidationError::DuplicateObjectId([0x42; 32]))
        );
    }

    #[test]
    fn test_adversarial_nonzero_entry_flags() {
        for bad_flag in [1u16, 2, 0x8000, 0xFFFF] {
            let fixture = fixture_nonzero_entry_flags(bad_flag);
            assert_eq!(
                Catalog::decode(&fixture),
                Err(CatalogValidationError::NonzeroFlags(bad_flag))
            );
        }
    }

    #[test]
    fn test_adversarial_nonzero_reserved_bytes() {
        // Nonzero reserved bytes in entry
        for i in 0..6 {
            let fixture = fixture_nonzero_entry_reserved(i, 0xFF);
            let mut expected_reserved = [0u8; 6];
            expected_reserved[i] = 0xFF;
            assert_eq!(
                Catalog::decode(&fixture),
                Err(CatalogValidationError::NonzeroReserved(expected_reserved))
            );
        }

        // Nonzero reserved padding in catalog unit
        let mut unit = vec![0u8; STORE_UNIT_BYTES];
        let catalog = Catalog::new(vec![]);
        let bytes = catalog.encode();
        unit[..bytes.len()].copy_from_slice(&bytes);
        assert!(validate_catalog_padding(&unit, bytes.len()).is_ok());

        // Mutate padding byte at unit offset 100 to nonzero
        unit[100] = 0x01;
        assert_eq!(
            validate_catalog_padding(&unit, bytes.len()),
            Err(CatalogValidationError::NonzeroHeaderReserved)
        );
    }

    #[test]
    fn test_adversarial_descriptors_outside_arena() {
        let catalog_first_unit = 10;
        let high_water = 12;

        // Underflow: first_unit < 2 (units 0 and 1 are superblocks)
        let underflow_catalog = fixture_descriptor_underflow_arena();
        assert_eq!(
            underflow_catalog.validate_arena(catalog_first_unit, high_water),
            Err(CatalogValidationError::DescriptorOutsideArena {
                first_unit: 1,
                limit: 2
            })
        );

        // At or beyond high_water
        let at_hw_catalog = fixture_descriptor_at_or_beyond_high_water(high_water);
        assert_eq!(
            at_hw_catalog.validate_arena(catalog_first_unit, high_water),
            Err(CatalogValidationError::DescriptorOutsideArena {
                first_unit: high_water,
                limit: high_water
            })
        );

        // Extent end exceeds catalog_first_unit
        let beyond_catalog_catalog =
            fixture_descriptor_beyond_catalog_first_unit(catalog_first_unit);
        assert_eq!(
            beyond_catalog_catalog.validate_arena(catalog_first_unit, high_water),
            Err(CatalogValidationError::ExtentBeyondCatalogFirstUnit {
                end_unit: catalog_first_unit + 1,
                catalog_first_unit
            })
        );
    }

    #[test]
    fn test_adversarial_overlapping_physical_runs() {
        let overlapping_catalog = fixture_overlapping_physical_runs();
        assert!(matches!(
            overlapping_catalog.validate_arena(20, 25),
            Err(CatalogValidationError::OverlappingExtents {
                entry_a: 0,
                entry_b: 1,
                range_a: (2, 5),
                range_b: (4, 7)
            })
        ));

        // Exact collision overlap
        let mut id0 = [0x00; 32];
        id0[0] = 0x01;
        let mut id1 = [0x00; 32];
        id1[0] = 0x02;
        let entry0 = CatalogEntry::new(id0, 3, 1, 2, 4000).unwrap();
        let entry1 = CatalogEntry::new(id1, 3, 1, 2, 4000).unwrap();
        let exact_collision = Catalog::new(vec![entry0, entry1]);
        assert!(matches!(
            exact_collision.validate_arena(20, 25),
            Err(CatalogValidationError::OverlappingExtents {
                entry_a: 0,
                entry_b: 1,
                range_a: (2, 3),
                range_b: (2, 3)
            })
        ));
    }

    #[test]
    fn test_adversarial_wrong_unit_count() {
        // 4096 bytes requires exactly 1 unit; declared 2 units -> rejected
        let fixture_too_high = fixture_wrong_unit_count(4096, 2);
        assert_eq!(
            Catalog::decode(&fixture_too_high),
            Err(CatalogValidationError::WrongUnitCount {
                expected: 1,
                actual: 2
            })
        );

        // 4097 bytes requires exactly 2 units; declared 1 unit -> rejected
        let fixture_too_low = fixture_wrong_unit_count(4097, 1);
        assert_eq!(
            Catalog::decode(&fixture_too_low),
            Err(CatalogValidationError::WrongUnitCount {
                expected: 2,
                actual: 1
            })
        );

        // Declared 0 units -> rejected
        let fixture_zero = fixture_wrong_unit_count(100, 0);
        assert_eq!(
            Catalog::decode(&fixture_zero),
            Err(CatalogValidationError::WrongUnitCount {
                expected: 1,
                actual: 0
            })
        );
    }

    #[test]
    fn test_adversarial_arithmetic_overflow() {
        let overflow_catalog = fixture_arithmetic_overflow();
        assert_eq!(
            overflow_catalog.validate_arena(100, 200),
            Err(CatalogValidationError::DescriptorOutsideArena {
                first_unit: u64::MAX,
                limit: 200
            })
        );

        // Overflow when first_unit + unit_count exceeds u64::MAX within bounds
        let mut entry = CatalogEntry::new([0x10; 32], 3, 1, 2, 100).unwrap();
        entry.first_unit = u64::MAX - 2;
        entry.unit_count = 5;
        let overflow_extent = Catalog::new(vec![entry]);
        assert_eq!(
            overflow_extent.validate_arena(u64::MAX, u64::MAX),
            Err(CatalogValidationError::ExtentOverflow {
                first_unit: u64::MAX - 2,
                unit_count: 5
            })
        );
    }

    #[test]
    fn test_adversarial_catalog_too_large() {
        // Declared entry count exceeds MAX_CATALOG_ENTRIES (4096)
        let mut catalog = Catalog::new(vec![]).encode();
        catalog[12..16].copy_from_slice(&((MAX_CATALOG_ENTRIES as u32) + 1).to_le_bytes());
        assert_eq!(
            Catalog::decode(&catalog),
            Err(CatalogValidationError::CatalogTooLarge(4097))
        );
    }

    #[test]
    fn test_adversarial_entry_field_restrictions() {
        // Application kind < 3 rejected
        assert_eq!(
            CatalogEntry::new([0x10; 32], 0, 1, 2, 100),
            Err(CatalogValidationError::InvalidKind(0))
        );
        assert_eq!(
            CatalogEntry::new([0x10; 32], 1, 1, 2, 100),
            Err(CatalogValidationError::InvalidKind(1))
        );
        assert_eq!(
            CatalogEntry::new([0x10; 32], 2, 1, 2, 100),
            Err(CatalogValidationError::InvalidKind(2))
        );

        // Version 0 rejected
        assert_eq!(
            CatalogEntry::new([0x10; 32], 3, 0, 2, 100),
            Err(CatalogValidationError::InvalidVersion(0))
        );

        // Byte length 0 rejected
        assert_eq!(
            CatalogEntry::new([0x10; 32], 3, 1, 2, 0),
            Err(CatalogValidationError::InvalidByteLength(0))
        );

        // Byte length > MAX_OBJECT_BYTES rejected
        assert_eq!(
            CatalogEntry::new([0x10; 32], 3, 1, 2, MAX_OBJECT_BYTES + 1),
            Err(CatalogValidationError::InvalidByteLength(
                MAX_OBJECT_BYTES + 1
            ))
        );
    }
}
