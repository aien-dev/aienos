//! Arithmetic and limits property testing suite (G3).
//!
//! Provides normative constants, verified checked arithmetic, and an adversarial
//! boundary-test harness for AIENOS P3 System Store v1 (ADR 0015).
//!
//! Enforces:
//! - Exact architectural constants
//! - Checked byte-to-unit ceil division
//! - Non-wrapping offset and unit arithmetic
//! - Region, catalog, transaction, and generation boundaries
//! - Zero panics, zero wraparounds, zero truncations, zero platform-width dependencies.

/// Size of one Store unit in bytes (ADR 0015 § 1).
pub const STORE_UNIT_BYTES: u64 = 4096;

/// Maximum entries in a single catalog (ADR 0015 § 1).
pub const MAX_CATALOG_ENTRIES: usize = 4096;

/// Encoded size of a single catalog entry in bytes (ADR 0015 § 1, § 2).
pub const CATALOG_ENTRY_BYTES: usize = 64;

/// Maximum size of an individual object in bytes: 64 MiB (ADR 0015 § 1).
pub const MAX_OBJECT_BYTES: u64 = 67_108_864;

/// Maximum units allocated to an individual object: 16,384 (64 MiB / 4 KiB) (ADR 0015 § 1).
pub const MAX_OBJECT_UNITS: u64 = 16_384;

/// Maximum application objects committed in a single transaction (ADR 0015 § 1).
pub const MAX_TRANSACTION_OBJECTS: usize = 256;

/// Maximum total units committed in a single transaction: 32,768 (128 MiB) (ADR 0015 § 1).
pub const MAX_TRANSACTION_UNITS: u64 = 32_768;

/// Maximum region units addressable in Store v1: 4,294,967,296 (16 TiB @ 4 KiB) (ADR 0015 § 1).
pub const MAX_REGION_UNITS: u64 = 4_294_967_296;

/// Minimum region units required for a valid Store: 4 (Superblock A, B, Catalog, CommitRecord) (ADR 0015 § 3).
pub const MIN_REGION_UNITS: u64 = 4;

/// First unit of the append arena: unit 2 (units 0 and 1 are Superblocks A and B) (ADR 0015 § Decision).
pub const FIRST_ARENA_UNIT: u64 = 2;

/// Fixed size of the Catalog header in bytes (ADR 0015 § 2).
pub const CATALOG_HEADER_BYTES: u64 = 16;

/// Fixed semantic byte size of a CommitRecord (ADR 0015 § 3).
pub const COMMIT_RECORD_BYTES: u64 = 200;

/// Store units occupied by a CommitRecord (ADR 0015 § 3).
pub const COMMIT_RECORD_UNITS: u64 = 1;

/// Limit and boundary validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitError {
    /// Object length cannot be zero (ADR 0015 § 1).
    ZeroLengthObject,
    /// Object length exceeds MAX_OBJECT_BYTES (64 MiB).
    ObjectTooLarge { bytes: u64, max: u64 },
    /// Object unit count exceeds MAX_OBJECT_UNITS (16,384).
    ObjectUnitsExceeded { units: u64, max: u64 },
    /// Catalog entry count exceeds MAX_CATALOG_ENTRIES (4096).
    CatalogFull { count: usize, max: usize },
    /// No space in bounded region for transaction units.
    NoSpace {
        high_water: u64,
        needed: u64,
        region_units: u64,
    },
    /// Generation counter has reached u64::MAX and cannot advance without overflow.
    GenerationExhausted { generation: u64 },
    /// Generation must be nonzero.
    ZeroGeneration,
    /// Transaction contains more than MAX_TRANSACTION_OBJECTS (256).
    TransactionObjectsExceeded { count: usize, max: usize },
    /// Transaction consumes more than MAX_TRANSACTION_UNITS (32,768).
    TransactionUnitsExceeded { units: u64, max: u64 },
    /// Region units outside supported range [MIN_REGION_UNITS, MAX_REGION_UNITS].
    RegionUnitsOutOfRange { units: u64, min: u64, max: u64 },
    /// Extent starts in reserved superblock units [0, 2).
    InvalidArenaUnit { unit: u64 },
    /// Extent extends past the specified boundary (high-water or region-units).
    ExtentOutOfBounds { start: u64, end: u64, bound: u64 },
    /// Adjacent extents overlap or violate append ordering.
    ExtentOverlap { first_end: u64, second_start: u64 },
    /// Declared unit count does not match ceil(byte_length / 4096).
    UnitCountMismatch { calculated: u64, declared: u64 },
    /// Zero unit count is invalid for an extent.
    ZeroUnitExtent,
    /// Integer arithmetic overflow or wrap hazard.
    ArithmeticOverflow { context: &'static str },
    /// Truncation hazard during integer width conversion.
    IntegerTruncation {
        from_type: &'static str,
        to_type: &'static str,
    },
}

impl core::fmt::Display for LimitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LimitError::ZeroLengthObject => write!(f, "zero-length objects are invalid"),
            LimitError::ObjectTooLarge { bytes, max } => {
                write!(f, "object size {} bytes exceeds max {}", bytes, max)
            }
            LimitError::ObjectUnitsExceeded { units, max } => {
                write!(f, "object units {} exceeds max {}", units, max)
            }
            LimitError::CatalogFull { count, max } => {
                write!(f, "catalog full: entry count {} exceeds max {}", count, max)
            }
            LimitError::NoSpace {
                high_water,
                needed,
                region_units,
            } => {
                write!(
                    f,
                    "no space: high_water ({}) + needed ({}) > region_units ({})",
                    high_water, needed, region_units
                )
            }
            LimitError::GenerationExhausted { generation } => {
                write!(f, "generation exhausted at {}", generation)
            }
            LimitError::ZeroGeneration => write!(f, "generation must be nonzero"),
            LimitError::TransactionObjectsExceeded { count, max } => {
                write!(f, "transaction objects {} exceeds max {}", count, max)
            }
            LimitError::TransactionUnitsExceeded { units, max } => {
                write!(f, "transaction units {} exceeds max {}", units, max)
            }
            LimitError::RegionUnitsOutOfRange { units, min, max } => {
                write!(
                    f,
                    "region units {} outside valid range [{}, {}]",
                    units, min, max
                )
            }
            LimitError::InvalidArenaUnit { unit } => {
                write!(f, "unit {} is in reserved superblock area (< 2)", unit)
            }
            LimitError::ExtentOutOfBounds { start, end, bound } => {
                write!(
                    f,
                    "extent [{}, {}) extends past bound {}",
                    start, end, bound
                )
            }
            LimitError::ExtentOverlap {
                first_end,
                second_start,
            } => {
                write!(
                    f,
                    "extent ending at {} overlaps next extent starting at {}",
                    first_end, second_start
                )
            }
            LimitError::UnitCountMismatch {
                calculated,
                declared,
            } => {
                write!(
                    f,
                    "unit count mismatch: calculated {}, declared {}",
                    calculated, declared
                )
            }
            LimitError::ZeroUnitExtent => write!(f, "extent unit count cannot be zero"),
            LimitError::ArithmeticOverflow { context } => {
                write!(f, "arithmetic overflow in {}", context)
            }
            LimitError::IntegerTruncation { from_type, to_type } => {
                write!(
                    f,
                    "integer truncation hazard converting from {} to {}",
                    from_type, to_type
                )
            }
        }
    }
}

impl std::error::Error for LimitError {}

/// Convert a byte length to Store units using checked ceil division: `(bytes + 4095) / 4096`.
///
/// Validates that:
/// - `bytes > 0` (zero-length objects are invalid per ADR 0015 § 1)
/// - `bytes <= MAX_OBJECT_BYTES` (64 MiB)
/// - Arithmetic does not overflow
/// - Resulting units `<= MAX_OBJECT_UNITS` (16,384)
pub fn checked_bytes_to_units(bytes: u64) -> Result<u64, LimitError> {
    if bytes == 0 {
        return Err(LimitError::ZeroLengthObject);
    }
    if bytes > MAX_OBJECT_BYTES {
        return Err(LimitError::ObjectTooLarge {
            bytes,
            max: MAX_OBJECT_BYTES,
        });
    }

    let units = raw_checked_ceil_div_units(bytes)?;

    if units > MAX_OBJECT_UNITS {
        return Err(LimitError::ObjectUnitsExceeded {
            units,
            max: MAX_OBJECT_UNITS,
        });
    }

    Ok(units)
}

/// Raw checked ceiling division by `STORE_UNIT_BYTES` without object size limits.
///
/// Safely computes `ceil(bytes / 4096)` without arithmetic overflow:
/// Handles the edge case where `bytes > u64::MAX - 4095`.
pub fn raw_checked_ceil_div_units(bytes: u64) -> Result<u64, LimitError> {
    if bytes == 0 {
        return Ok(0);
    }
    // Using checked_add to protect against addition overflow when bytes > u64::MAX - 4095
    match bytes.checked_add(STORE_UNIT_BYTES - 1) {
        Some(sum) => Ok(sum / STORE_UNIT_BYTES),
        None => {
            // Safe fallback arithmetic: div + mod
            let div = bytes / STORE_UNIT_BYTES;
            let rem = bytes % STORE_UNIT_BYTES;
            let add = if rem > 0 { 1 } else { 0 };
            div.checked_add(add).ok_or(LimitError::ArithmeticOverflow {
                context: "raw_checked_ceil_div_units",
            })
        }
    }
}

/// Compute extent end unit `first_unit + unit_count` with checked arithmetic.
///
/// Validates that:
/// - `first_unit >= FIRST_ARENA_UNIT` (2)
/// - `unit_count > 0`
/// - `first_unit + unit_count` does not wrap or overflow `u64`.
pub fn checked_extent_end(first_unit: u64, unit_count: u64) -> Result<u64, LimitError> {
    if first_unit < FIRST_ARENA_UNIT {
        return Err(LimitError::InvalidArenaUnit { unit: first_unit });
    }
    if unit_count == 0 {
        return Err(LimitError::ZeroUnitExtent);
    }
    first_unit
        .checked_add(unit_count)
        .ok_or(LimitError::ArithmeticOverflow {
            context: "checked_extent_end",
        })
}

/// Validate that an extent `[first_unit, first_unit + unit_count)` is strictly bounded.
pub fn validate_extent_bounds(
    first_unit: u64,
    unit_count: u64,
    bound_unit: u64,
) -> Result<u64, LimitError> {
    let end_unit = checked_extent_end(first_unit, unit_count)?;
    if end_unit > bound_unit {
        return Err(LimitError::ExtentOutOfBounds {
            start: first_unit,
            end: end_unit,
            bound: bound_unit,
        });
    }
    Ok(end_unit)
}

/// Validate catalog entry count against `MAX_CATALOG_ENTRIES` (4096).
pub fn validate_catalog_entry_count(count: usize) -> Result<(), LimitError> {
    if count > MAX_CATALOG_ENTRIES {
        Err(LimitError::CatalogFull {
            count,
            max: MAX_CATALOG_ENTRIES,
        })
    } else {
        Ok(())
    }
}

/// Compute semantic byte size for a catalog: `16 + entry_count * 64`.
///
/// Uses checked arithmetic to prevent overflow.
pub fn catalog_semantic_bytes(entry_count: usize) -> Result<u64, LimitError> {
    validate_catalog_entry_count(entry_count)?;
    let count_u64 = entry_count as u64;
    let entries_size = count_u64.checked_mul(CATALOG_ENTRY_BYTES as u64).ok_or(
        LimitError::ArithmeticOverflow {
            context: "catalog_semantic_bytes mul",
        },
    )?;
    CATALOG_HEADER_BYTES
        .checked_add(entries_size)
        .ok_or(LimitError::ArithmeticOverflow {
            context: "catalog_semantic_bytes add",
        })
}

/// Compute unit count for a catalog: `ceil(semantic_bytes / 4096)`.
pub fn catalog_unit_count(entry_count: usize) -> Result<u64, LimitError> {
    let bytes = catalog_semantic_bytes(entry_count)?;
    raw_checked_ceil_div_units(bytes)
}

/// Check for NoSpace condition: `high_water + txn_units > region_units`.
///
/// Returns the new `committed_high_water` if space is sufficient.
pub fn check_no_space(
    high_water: u64,
    txn_units: u64,
    region_units: u64,
) -> Result<u64, LimitError> {
    validate_region_units(region_units)?;
    if high_water < FIRST_ARENA_UNIT {
        return Err(LimitError::InvalidArenaUnit { unit: high_water });
    }

    let new_high_water = high_water
        .checked_add(txn_units)
        .ok_or(LimitError::NoSpace {
            high_water,
            needed: txn_units,
            region_units,
        })?;

    if new_high_water > region_units {
        Err(LimitError::NoSpace {
            high_water,
            needed: txn_units,
            region_units,
        })
    } else {
        Ok(new_high_water)
    }
}

/// Check generation advancement from `current_gen` to `current_gen + 1`.
///
/// Returns `Err(GenerationExhausted)` when `current_gen == u64::MAX`.
pub fn check_generation_advance(current_gen: u64) -> Result<u64, LimitError> {
    if current_gen == 0 {
        return Err(LimitError::ZeroGeneration);
    }
    current_gen
        .checked_add(1)
        .ok_or(LimitError::GenerationExhausted {
            generation: current_gen,
        })
}

/// Validate region units within normative boundaries `[MIN_REGION_UNITS, MAX_REGION_UNITS]`.
pub fn validate_region_units(region_units: u64) -> Result<(), LimitError> {
    if !(MIN_REGION_UNITS..=MAX_REGION_UNITS).contains(&region_units) {
        Err(LimitError::RegionUnitsOutOfRange {
            units: region_units,
            min: MIN_REGION_UNITS,
            max: MAX_REGION_UNITS,
        })
    } else {
        Ok(())
    }
}

/// Validate transaction bounds: object count and total unit consumption.
pub fn validate_transaction_limits(
    object_count: usize,
    total_units: u64,
) -> Result<(), LimitError> {
    if object_count > MAX_TRANSACTION_OBJECTS {
        return Err(LimitError::TransactionObjectsExceeded {
            count: object_count,
            max: MAX_TRANSACTION_OBJECTS,
        });
    }
    if total_units > MAX_TRANSACTION_UNITS {
        return Err(LimitError::TransactionUnitsExceeded {
            units: total_units,
            max: MAX_TRANSACTION_UNITS,
        });
    }
    Ok(())
}

/// Validate an application object descriptor per ADR 0015 § 1, § 2.
pub fn validate_object_descriptor(
    kind: u16,
    version: u16,
    byte_length: u64,
    declared_units: u32,
    first_unit: u64,
    bound_unit: u64,
) -> Result<u64, LimitError> {
    if kind < 3 {
        return Err(LimitError::ArithmeticOverflow {
            context: "reserved object kind (< 3)",
        });
    }
    if version == 0 {
        return Err(LimitError::ArithmeticOverflow {
            context: "zero object version",
        });
    }
    let expected_units = checked_bytes_to_units(byte_length)?;
    if (declared_units as u64) != expected_units {
        return Err(LimitError::UnitCountMismatch {
            calculated: expected_units,
            declared: declared_units as u64,
        });
    }
    validate_extent_bounds(first_unit, expected_units, bound_unit)
}

/// Safe platform-independent integer cast from u64 to u32 with truncation detection.
pub fn safe_u64_to_u32(val: u64) -> Result<u32, LimitError> {
    u32::try_from(val).map_err(|_| LimitError::IntegerTruncation {
        from_type: "u64",
        to_type: "u32",
    })
}

/// Safe platform-independent integer cast from u64 to usize with truncation detection.
pub fn safe_u64_to_usize(val: u64) -> Result<usize, LimitError> {
    usize::try_from(val).map_err(|_| LimitError::IntegerTruncation {
        from_type: "u64",
        to_type: "usize",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // 1. Normative Constants Verification
    // =========================================================================

    #[test]
    fn test_normative_architectural_constants() {
        assert_eq!(STORE_UNIT_BYTES, 4096, "STORE_UNIT_BYTES must be 4096");
        assert_eq!(
            MAX_CATALOG_ENTRIES, 4096,
            "MAX_CATALOG_ENTRIES must be 4096"
        );
        assert_eq!(CATALOG_ENTRY_BYTES, 64, "CATALOG_ENTRY_BYTES must be 64");
        assert_eq!(
            MAX_OBJECT_BYTES, 67_108_864,
            "MAX_OBJECT_BYTES must be 64 MiB"
        );
        assert_eq!(
            MAX_OBJECT_UNITS, 16_384,
            "MAX_OBJECT_UNITS must be 16,384 units"
        );
        assert_eq!(
            MAX_TRANSACTION_OBJECTS, 256,
            "MAX_TRANSACTION_OBJECTS must be 256"
        );
        assert_eq!(
            MAX_TRANSACTION_UNITS, 32_768,
            "MAX_TRANSACTION_UNITS must be 32,768 units"
        );
        assert_eq!(
            MAX_REGION_UNITS, 4_294_967_296,
            "MAX_REGION_UNITS must be 2^32"
        );
        assert_eq!(MIN_REGION_UNITS, 4, "MIN_REGION_UNITS must be 4");
        assert_eq!(FIRST_ARENA_UNIT, 2, "FIRST_ARENA_UNIT must be 2");
    }

    #[test]
    fn test_architectural_constant_identities() {
        // 64 MiB / 4 KiB == 16,384 units
        assert_eq!(MAX_OBJECT_BYTES / STORE_UNIT_BYTES, MAX_OBJECT_UNITS);
        assert_eq!(MAX_OBJECT_BYTES % STORE_UNIT_BYTES, 0);

        // 32,768 units * 4096 == 134,217,728 bytes (128 MiB)
        assert_eq!(MAX_TRANSACTION_UNITS * STORE_UNIT_BYTES, 134_217_728);

        // 4,294_967_296 units * 4096 == 17,592,186,044,416 bytes (16 TiB)
        assert_eq!(MAX_REGION_UNITS * STORE_UNIT_BYTES, 17_592_186_044_416);

        // Catalog entry storage: 4096 entries * 64 bytes = 262,144 bytes
        assert_eq!(MAX_CATALOG_ENTRIES * CATALOG_ENTRY_BYTES, 262_144);

        // Full catalog semantic bytes: 16 header + 262,144 = 262,160 bytes
        let full_catalog_bytes =
            CATALOG_HEADER_BYTES + (MAX_CATALOG_ENTRIES as u64) * (CATALOG_ENTRY_BYTES as u64);
        assert_eq!(full_catalog_bytes, 262_160);

        // Full catalog occupies 65 units: ceil(262,160 / 4096) = 65
        let full_catalog_units = full_catalog_bytes.div_ceil(STORE_UNIT_BYTES);
        assert_eq!(full_catalog_units, 65);
    }

    // =========================================================================
    // 2. Checked Byte-to-Unit Ceil Division Boundary Suite
    // =========================================================================

    #[test]
    fn test_byte_to_unit_conversions_at_boundaries() {
        // 0 bytes is invalid per ADR 0015
        assert_eq!(checked_bytes_to_units(0), Err(LimitError::ZeroLengthObject));

        // Sub-unit boundary tests: (1..=4096) -> exactly 1 unit
        assert_eq!(checked_bytes_to_units(1).unwrap(), 1);
        assert_eq!(checked_bytes_to_units(2).unwrap(), 1);
        assert_eq!(checked_bytes_to_units(4095).unwrap(), 1);
        assert_eq!(checked_bytes_to_units(4096).unwrap(), 1);

        // Just over one unit: 4097 -> exactly 2 units
        assert_eq!(checked_bytes_to_units(4097).unwrap(), 2);
        assert_eq!(checked_bytes_to_units(8191).unwrap(), 2);
        assert_eq!(checked_bytes_to_units(8192).unwrap(), 2);
        assert_eq!(checked_bytes_to_units(8193).unwrap(), 3);

        // Near MAX_OBJECT_BYTES boundaries
        // MAX_OBJECT_BYTES - 4096 = 67_104_768 -> 16,383 units
        assert_eq!(
            checked_bytes_to_units(MAX_OBJECT_BYTES - 4096).unwrap(),
            16_383
        );
        // MAX_OBJECT_BYTES - 4095 -> 16,384 units
        assert_eq!(
            checked_bytes_to_units(MAX_OBJECT_BYTES - 4095).unwrap(),
            16_384
        );
        // MAX_OBJECT_BYTES - 1 -> 16,384 units
        assert_eq!(
            checked_bytes_to_units(MAX_OBJECT_BYTES - 1).unwrap(),
            16_384
        );
        // Exactly MAX_OBJECT_BYTES (67_108_864) -> 16,384 units
        assert_eq!(checked_bytes_to_units(MAX_OBJECT_BYTES).unwrap(), 16_384);

        // One-over-maximum: MAX_OBJECT_BYTES + 1 -> ObjectTooLarge
        assert_eq!(
            checked_bytes_to_units(MAX_OBJECT_BYTES + 1),
            Err(LimitError::ObjectTooLarge {
                bytes: MAX_OBJECT_BYTES + 1,
                max: MAX_OBJECT_BYTES,
            })
        );
        assert_eq!(
            checked_bytes_to_units(MAX_OBJECT_BYTES + 4096),
            Err(LimitError::ObjectTooLarge {
                bytes: MAX_OBJECT_BYTES + 4096,
                max: MAX_OBJECT_BYTES,
            })
        );
    }

    #[test]
    fn test_raw_ceil_div_extreme_and_overflow_hazards() {
        assert_eq!(raw_checked_ceil_div_units(0).unwrap(), 0);
        assert_eq!(raw_checked_ceil_div_units(1).unwrap(), 1);
        assert_eq!(raw_checked_ceil_div_units(4096).unwrap(), 1);
        assert_eq!(raw_checked_ceil_div_units(4097).unwrap(), 2);

        // Huge byte values that would cause (bytes + 4095) to overflow u64 if unchecked
        let overflow_threshold = u64::MAX - (STORE_UNIT_BYTES - 1); // u64::MAX - 4095
        assert_eq!(overflow_threshold.checked_add(4095), Some(u64::MAX));

        // Exactly at overflow threshold: sum is u64::MAX
        let res1 = raw_checked_ceil_div_units(overflow_threshold);
        assert!(res1.is_ok(), "Threshold value must not overflow or panic");

        // Beyond overflow threshold: naive addition would wrap to 0 or panic
        let res2 = raw_checked_ceil_div_units(overflow_threshold + 1);
        assert!(
            res2.is_ok(),
            "Safe ceil division must handle values near u64::MAX without panic"
        );

        let res_max = raw_checked_ceil_div_units(u64::MAX);
        assert!(res_max.is_ok(), "u64::MAX must not panic");
        // u64::MAX / 4096 + 1
        let expected_max_units = (u64::MAX / 4096) + 1;
        assert_eq!(res_max.unwrap(), expected_max_units);
    }

    // =========================================================================
    // 3. Checked Offset + Unit Count Arithmetic & Overlap Checks
    // =========================================================================

    #[test]
    fn test_checked_extent_end_valid_and_boundaries() {
        // Valid normal extent
        assert_eq!(checked_extent_end(2, 1).unwrap(), 3);
        assert_eq!(checked_extent_end(2, 100).unwrap(), 102);

        // Reserved superblock area (< 2) rejected
        assert_eq!(
            checked_extent_end(0, 1),
            Err(LimitError::InvalidArenaUnit { unit: 0 })
        );
        assert_eq!(
            checked_extent_end(1, 1),
            Err(LimitError::InvalidArenaUnit { unit: 1 })
        );

        // Zero-length extent rejected
        assert_eq!(checked_extent_end(2, 0), Err(LimitError::ZeroUnitExtent));

        // High region extent
        assert_eq!(
            checked_extent_end(MAX_REGION_UNITS - 10, 10).unwrap(),
            MAX_REGION_UNITS
        );
    }

    #[test]
    fn test_checked_extent_end_overflow_hazards() {
        // Extent addition that would wrap around to 0 or small number if unchecked
        // E.g. u64::MAX.wrapping_add(1) == 0
        assert_eq!(
            checked_extent_end(u64::MAX, 1),
            Err(LimitError::ArithmeticOverflow {
                context: "checked_extent_end",
            })
        );
        assert_eq!(
            checked_extent_end(u64::MAX - 5, 10),
            Err(LimitError::ArithmeticOverflow {
                context: "checked_extent_end",
            })
        );
        assert_eq!(
            checked_extent_end(100, u64::MAX),
            Err(LimitError::ArithmeticOverflow {
                context: "checked_extent_end",
            })
        );
    }

    #[test]
    fn test_validate_extent_bounds_against_high_water_and_region() {
        // High water = 1000
        let high_water = 1000u64;

        // Valid extents wholly within high_water
        assert_eq!(validate_extent_bounds(2, 10, high_water).unwrap(), 12);
        assert_eq!(validate_extent_bounds(2, 998, high_water).unwrap(), 1000);

        // Boundary violations:
        // Ending exactly at high_water + 1
        assert_eq!(
            validate_extent_bounds(2, 999, high_water),
            Err(LimitError::ExtentOutOfBounds {
                start: 2,
                end: 1001,
                bound: high_water,
            })
        );

        // Starting at or beyond high_water
        assert_eq!(
            validate_extent_bounds(1000, 1, high_water),
            Err(LimitError::ExtentOutOfBounds {
                start: 1000,
                end: 1001,
                bound: high_water,
            })
        );
        assert_eq!(
            validate_extent_bounds(1001, 1, high_water),
            Err(LimitError::ExtentOutOfBounds {
                start: 1001,
                end: 1002,
                bound: high_water,
            })
        );

        // Testing bounds against MAX_REGION_UNITS
        assert_eq!(
            validate_extent_bounds(MAX_REGION_UNITS - 1, 1, MAX_REGION_UNITS).unwrap(),
            MAX_REGION_UNITS
        );
        assert_eq!(
            validate_extent_bounds(MAX_REGION_UNITS - 1, 2, MAX_REGION_UNITS),
            Err(LimitError::ExtentOutOfBounds {
                start: MAX_REGION_UNITS - 1,
                end: MAX_REGION_UNITS + 1,
                bound: MAX_REGION_UNITS,
            })
        );
    }

    // =========================================================================
    // 4. CatalogFull Condition Tests (> 4096 entries)
    // =========================================================================

    #[test]
    fn test_catalog_entry_count_boundaries() {
        // Valid counts: 0 through 4096
        assert!(validate_catalog_entry_count(0).is_ok());
        assert!(validate_catalog_entry_count(1).is_ok());
        assert!(validate_catalog_entry_count(4095).is_ok());
        assert!(validate_catalog_entry_count(MAX_CATALOG_ENTRIES).is_ok());

        // One-over-maximum: 4097 -> CatalogFull
        assert_eq!(
            validate_catalog_entry_count(MAX_CATALOG_ENTRIES + 1),
            Err(LimitError::CatalogFull {
                count: 4097,
                max: MAX_CATALOG_ENTRIES,
            })
        );

        // Arbitrary large counts
        assert_eq!(
            validate_catalog_entry_count(10_000),
            Err(LimitError::CatalogFull {
                count: 10_000,
                max: MAX_CATALOG_ENTRIES,
            })
        );
        assert_eq!(
            validate_catalog_entry_count(usize::MAX),
            Err(LimitError::CatalogFull {
                count: usize::MAX,
                max: MAX_CATALOG_ENTRIES,
            })
        );
    }

    #[test]
    fn test_catalog_semantic_bytes_and_units() {
        // 0 entries: 16 bytes header -> 1 unit
        assert_eq!(catalog_semantic_bytes(0).unwrap(), 16);
        assert_eq!(catalog_unit_count(0).unwrap(), 1);

        // 1 entry: 16 + 64 = 80 bytes -> 1 unit
        assert_eq!(catalog_semantic_bytes(1).unwrap(), 80);
        assert_eq!(catalog_unit_count(1).unwrap(), 1);

        // 63 entries: 16 + 63 * 64 = 4048 bytes -> 1 unit
        assert_eq!(catalog_semantic_bytes(63).unwrap(), 4048);
        assert_eq!(catalog_unit_count(63).unwrap(), 1);

        // 64 entries: 16 + 64 * 64 = 4112 bytes -> 2 units
        assert_eq!(catalog_semantic_bytes(64).unwrap(), 4112);
        assert_eq!(catalog_unit_count(64).unwrap(), 2);

        // 4096 entries (max): 16 + 4096 * 64 = 262,160 bytes -> 65 units
        assert_eq!(
            catalog_semantic_bytes(MAX_CATALOG_ENTRIES).unwrap(),
            262_160
        );
        assert_eq!(catalog_unit_count(MAX_CATALOG_ENTRIES).unwrap(), 65);

        // 4097 entries -> CatalogFull
        assert_eq!(
            catalog_semantic_bytes(MAX_CATALOG_ENTRIES + 1),
            Err(LimitError::CatalogFull {
                count: 4097,
                max: MAX_CATALOG_ENTRIES,
            })
        );
        assert_eq!(
            catalog_unit_count(MAX_CATALOG_ENTRIES + 1),
            Err(LimitError::CatalogFull {
                count: 4097,
                max: MAX_CATALOG_ENTRIES,
            })
        );
    }

    // =========================================================================
    // 5. NoSpace Condition Tests (high_water + txn_units > region_units)
    // =========================================================================

    #[test]
    fn test_no_space_exact_boundaries() {
        let region = 1000u64;

        // Exact fit: high_water (900) + txn_units (100) == region (1000)
        assert_eq!(check_no_space(900, 100, region).unwrap(), 1000);

        // One unit over: high_water (900) + txn_units (101) == 1001 > 1000 -> NoSpace
        assert_eq!(
            check_no_space(900, 101, region),
            Err(LimitError::NoSpace {
                high_water: 900,
                needed: 101,
                region_units: 1000,
            })
        );

        // Zero units needed at exact capacity
        assert_eq!(check_no_space(1000, 0, region).unwrap(), 1000);

        // Exceeding when high_water is already at capacity
        assert_eq!(
            check_no_space(1000, 1, region),
            Err(LimitError::NoSpace {
                high_water: 1000,
                needed: 1,
                region_units: 1000,
            })
        );
    }

    #[test]
    fn test_no_space_at_max_region_units() {
        let region = MAX_REGION_UNITS; // 4_294_967_296

        // Exact fit at maximum possible region
        let high_water = region - MAX_TRANSACTION_UNITS; // 4_294_967_296 - 32_768
        assert_eq!(
            check_no_space(high_water, MAX_TRANSACTION_UNITS, region).unwrap(),
            region
        );

        // One-over-maximum boundary
        assert_eq!(
            check_no_space(high_water + 1, MAX_TRANSACTION_UNITS, region),
            Err(LimitError::NoSpace {
                high_water: high_water + 1,
                needed: MAX_TRANSACTION_UNITS,
                region_units: region,
            })
        );
    }

    #[test]
    fn test_no_space_arithmetic_overflow_wrapping_hazards() {
        // High water + txn_units overflows u64
        // Unchecked wrapping arithmetic: (u64::MAX - 10).wrapping_add(20) == 9
        // If 9 < region_units, a naive check would mistakenly report plenty of space!
        let high_water = u64::MAX - 10;
        let txn_units = 20u64;
        let region = MAX_REGION_UNITS;

        assert_eq!(
            check_no_space(high_water, txn_units, region),
            Err(LimitError::NoSpace {
                high_water,
                needed: txn_units,
                region_units: region,
            })
        );
    }

    // =========================================================================
    // 6. GenerationExhausted Condition Tests (generation u64::MAX)
    // =========================================================================

    #[test]
    fn test_generation_advance_boundaries() {
        // Zero generation is forbidden (ADR 0015 § 3, § 4)
        assert_eq!(check_generation_advance(0), Err(LimitError::ZeroGeneration));

        // Genesis advance: 1 -> 2
        assert_eq!(check_generation_advance(1).unwrap(), 2);

        // Typical advance
        assert_eq!(check_generation_advance(100).unwrap(), 101);

        // Advance to u64::MAX - 1
        assert_eq!(
            check_generation_advance(u64::MAX - 2).unwrap(),
            u64::MAX - 1
        );

        // Advance from u64::MAX - 1 to u64::MAX (highest valid generation)
        assert_eq!(check_generation_advance(u64::MAX - 1).unwrap(), u64::MAX);

        // Exhaustion: advancing from u64::MAX must NOT wrap to 0
        // (u64::MAX.wrapping_add(1) == 0 is catastrophic)
        assert_eq!(
            check_generation_advance(u64::MAX),
            Err(LimitError::GenerationExhausted {
                generation: u64::MAX,
            })
        );
    }

    // =========================================================================
    // 7. Maximum Valid Values vs One-Over-Maximum for Every Architectural Constant
    // =========================================================================

    #[test]
    fn test_max_valid_vs_one_over_max_catalog_entries() {
        // Max valid: 4096
        assert!(validate_catalog_entry_count(MAX_CATALOG_ENTRIES).is_ok());
        // One over: 4097
        assert_eq!(
            validate_catalog_entry_count(MAX_CATALOG_ENTRIES + 1),
            Err(LimitError::CatalogFull {
                count: 4097,
                max: MAX_CATALOG_ENTRIES,
            })
        );
    }

    #[test]
    fn test_max_valid_vs_one_over_max_object_bytes() {
        // Max valid: 67_108_864 bytes (64 MiB) -> 16,384 units
        assert_eq!(
            checked_bytes_to_units(MAX_OBJECT_BYTES).unwrap(),
            MAX_OBJECT_UNITS
        );
        // One over: 67_108_865 bytes -> ObjectTooLarge
        assert_eq!(
            checked_bytes_to_units(MAX_OBJECT_BYTES + 1),
            Err(LimitError::ObjectTooLarge {
                bytes: MAX_OBJECT_BYTES + 1,
                max: MAX_OBJECT_BYTES,
            })
        );
    }

    #[test]
    fn test_max_valid_vs_one_over_max_transaction_objects() {
        // Max valid: 256 objects
        assert!(
            validate_transaction_limits(MAX_TRANSACTION_OBJECTS, MAX_TRANSACTION_UNITS).is_ok()
        );
        // One over: 257 objects
        assert_eq!(
            validate_transaction_limits(MAX_TRANSACTION_OBJECTS + 1, MAX_TRANSACTION_UNITS),
            Err(LimitError::TransactionObjectsExceeded {
                count: 257,
                max: MAX_TRANSACTION_OBJECTS,
            })
        );
    }

    #[test]
    fn test_max_valid_vs_one_over_max_transaction_units() {
        // Max valid: 32,768 units
        assert!(
            validate_transaction_limits(MAX_TRANSACTION_OBJECTS, MAX_TRANSACTION_UNITS).is_ok()
        );
        // One over: 32,769 units
        assert_eq!(
            validate_transaction_limits(MAX_TRANSACTION_OBJECTS, MAX_TRANSACTION_UNITS + 1),
            Err(LimitError::TransactionUnitsExceeded {
                units: 32_769,
                max: MAX_TRANSACTION_UNITS,
            })
        );
    }

    #[test]
    fn test_min_and_max_valid_vs_out_of_bounds_region_units() {
        // Under minimum: 3 units -> RegionUnitsOutOfRange (min is 4)
        assert_eq!(
            validate_region_units(MIN_REGION_UNITS - 1),
            Err(LimitError::RegionUnitsOutOfRange {
                units: 3,
                min: 4,
                max: MAX_REGION_UNITS,
            })
        );
        // Min valid: 4 units
        assert!(validate_region_units(MIN_REGION_UNITS).is_ok());

        // Max valid: 4_294_967_296 units (2^32)
        assert!(validate_region_units(MAX_REGION_UNITS).is_ok());

        // One over max: 4_294_967_297 units -> RegionUnitsOutOfRange
        assert_eq!(
            validate_region_units(MAX_REGION_UNITS + 1),
            Err(LimitError::RegionUnitsOutOfRange {
                units: MAX_REGION_UNITS + 1,
                min: 4,
                max: MAX_REGION_UNITS,
            })
        );
    }

    // =========================================================================
    // 8. Platform-Width and Integer Truncation Invariants
    // =========================================================================

    #[test]
    fn test_platform_width_and_truncation_detection() {
        // MAX_REGION_UNITS is 4_294_967_296 (2^32).
        // If truncated to u32, (MAX_REGION_UNITS as u32) produces 0!
        let truncated_as_u32 = MAX_REGION_UNITS as u32;
        assert_eq!(
            truncated_as_u32, 0,
            "Demonstrating truncation hazard of `as u32`"
        );

        // safe_u64_to_u32 must catch this truncation error:
        assert_eq!(
            safe_u64_to_u32(MAX_REGION_UNITS),
            Err(LimitError::IntegerTruncation {
                from_type: "u64",
                to_type: "u32",
            })
        );

        // Values within u32 range must succeed:
        assert_eq!(safe_u64_to_u32(u32::MAX as u64).unwrap(), u32::MAX);
        assert_eq!(safe_u64_to_u32(0).unwrap(), 0);

        // Total region byte capacity: 4_294_967_296 * 4096 = 17,592,186,044,416 (16 TiB)
        // If truncated to u32:
        let total_bytes_u64 = MAX_REGION_UNITS * STORE_UNIT_BYTES;
        assert_eq!(
            total_bytes_u64 as u32, 0,
            "Demonstrating 16 TiB truncation hazard"
        );
        assert_eq!(
            safe_u64_to_u32(total_bytes_u64),
            Err(LimitError::IntegerTruncation {
                from_type: "u64",
                to_type: "u32",
            })
        );
    }

    // =========================================================================
    // 9. Object Descriptor Qualification
    // =========================================================================

    #[test]
    fn test_object_descriptor_qualification() {
        let bound = 1000u64;

        // Valid descriptor: kind 3, version 1, 10,000 bytes -> ceil(10,000 / 4096) = 3 units
        // first_unit = 10, declared_units = 3 -> end = 13 <= bound
        assert_eq!(
            validate_object_descriptor(3, 1, 10_000, 3, 10, bound).unwrap(),
            13
        );

        // Reserved kind (< 3) rejected
        assert!(validate_object_descriptor(1, 1, 10_000, 3, 10, bound).is_err());
        assert!(validate_object_descriptor(2, 1, 10_000, 3, 10, bound).is_err());

        // Zero version rejected
        assert!(validate_object_descriptor(3, 0, 10_000, 3, 10, bound).is_err());

        // Declared units mismatch rejected
        assert_eq!(
            validate_object_descriptor(3, 1, 10_000, 2, 10, bound),
            Err(LimitError::UnitCountMismatch {
                calculated: 3,
                declared: 2,
            })
        );
        assert_eq!(
            validate_object_descriptor(3, 1, 10_000, 4, 10, bound),
            Err(LimitError::UnitCountMismatch {
                calculated: 3,
                declared: 4,
            })
        );

        // Extent out of bounds rejected
        assert_eq!(
            validate_object_descriptor(3, 1, 10_000, 3, 998, bound),
            Err(LimitError::ExtentOutOfBounds {
                start: 998,
                end: 1001,
                bound,
            })
        );
    }

    // =========================================================================
    // 10. Adversarial Panic and Property Sweep (Zero Panics / Zero Wraparounds)
    // =========================================================================

    #[test]
    fn test_zero_panics_adversarial_property_sweep() {
        // An adversarial sweep across extreme integers, zero, and boundary points
        let test_values: &[u64] = &[
            0,
            1,
            2,
            3,
            4,
            5,
            4095,
            4096,
            4097,
            8191,
            8192,
            8193,
            16_384,
            32_768,
            67_108_863,
            67_108_864,
            67_108_865,
            u32::MAX as u64 - 1,
            u32::MAX as u64,
            u32::MAX as u64 + 1,
            MAX_REGION_UNITS - 1,
            MAX_REGION_UNITS,
            MAX_REGION_UNITS + 1,
            u64::MAX - 4096,
            u64::MAX - 4095,
            u64::MAX - 1,
            u64::MAX,
        ];

        for &val in test_values {
            // Must return Ok or Err, never panic
            let _ = checked_bytes_to_units(val);
            let _ = raw_checked_ceil_div_units(val);
            let _ = validate_region_units(val);
            let _ = check_generation_advance(val);
            let _ = safe_u64_to_u32(val);

            for &other in test_values {
                let _ = checked_extent_end(val, other);
                let _ = check_no_space(val, other, MAX_REGION_UNITS);
                let _ = validate_extent_bounds(val, other, MAX_REGION_UNITS);
            }
        }
    }
}
