# ADR 0015: AIENOS System Store v1 Format

Status: Accepted for P3-1 format freeze
Date: 2026-09-25
Scope: Permanent System Store v1 bytes, canonical encodings, and format-level validation.
Out of scope: Native NVMe drivers, QEMU power-cut orchestration, Cortex persistence, Agent State integration, TRUST-1, Machine 1 storage, GB10, general evidence infrastructure, and complete transaction or mount implementation.

## Decision

System Store v1 MUST use the byte layouts and rules in this ADR. Implementations MUST NOT serialize native structure layouts, host endianness, implicit padding, or implementation defaults. Every multibyte integer is unsigned little-endian. Every reserved byte is zero when written and MUST be zero when read.

The permanent Store unit is exactly 4096 bytes. The only supported physical logical-block sizes are 512 and 4096 bytes. Implementations MUST NOT use read-modify-write to emulate a Store unit. The required layering is:

`BlockDevice → provisioning → BoundedBlockDevice → StoreDevice → Store`

The bounded region is expressed in 4096-byte Store units, with unit 0 = Superblock A, unit 1 = Superblock B, and units 2 onward = append arena. `open()` MUST NOT write, repair, or autoformat. It MUST distinguish `Unformatted`, `ForeignOrUnknown`, `UnsupportedVersion`, `Corrupt/RecoveryRequired`, and a valid Store. A block-device read error MUST be reported as `MountError::Io`, never as corrupt media.

## 1. Canonical constants and object identity

The following v1 limits are mandatory:

| Name | Value |
|---|---:|
| `STORE_UNIT_BYTES` | 4096 |
| `MAX_CATALOG_ENTRIES` | 4096 |
| `CATALOG_ENTRY_BYTES` | 64 |
| `MAX_OBJECT_BYTES` | 67,108,864 |
| `MAX_OBJECT_UNITS` | 16,384 |
| `MAX_TRANSACTION_OBJECTS` | 256 |
| `MAX_TRANSACTION_UNITS` | 32,768 |
| `MAX_REGION_UNITS` | 4,294,967,296 |

The catalog limit is an entry count. A full 4096-entry catalog is 262,160 semantic bytes (16 + 4096 × 64), occupying 65 Store units after final-unit padding. The numeric kind reservations, nonzero kind/version rule, format version 1.0, zero feature masks, and magic values below are explicit v1 format-owner decisions.

An ObjectId is exactly 32 bytes:

```text
SHA256(
  ASCII("AIENOS-STORE-OBJECT-V1\0")
  || kind:u16le || version:u16le || byte_length:u64le
  || semantic_bytes[byte_length]
)
```

The domain contains exactly one terminal NUL. `kind` and `version` MUST be nonzero. Kind 1 is reserved for Catalog, kind 2 for CommitRecord, and kinds 3 through 65535 are application object kinds. Catalog and CommitRecord object version is 1. Zero-length objects are invalid. Physical location, unit count, Store UUID, generation, catalog membership, and final physical padding are excluded from ObjectId. Object bytes occupy one contiguous run of `ceil(byte_length / 4096)` units. Bytes `[byte_length, unit_count × 4096)` MUST be zero and are not semantic bytes. A descriptor MUST report that exact unit count, remain wholly in the append arena and within the bounded region and committed high-water, and not overlap another object extent. Each ObjectId MUST be recalculated as SHA-256 of the domain, descriptor kind/version/byte_length in the specified encodings, and exactly `byte_length` semantic bytes. An existing ObjectId MAY be deduplicated only after independently validating its descriptor, semantic bytes, ObjectId, and final padding.

## 2. Catalog bytes

A Catalog is an ordinary kind-1, version-1 object. Its semantic bytes have exactly this header and entry sequence; the catalog object's own final unit padding follows its semantic bytes and is zero.

### Header (16 bytes)

| Offset | Size | Field | Required value/encoding |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `AIENCAT1` |
| 8 | 2 | format_version | u16 LE = 1 |
| 10 | 2 | entry_size | u16 LE = 64 |
| 12 | 4 | entry_count | u32 LE, 0 through 4096 |

The semantic length MUST equal `16 + entry_count × 64`, with checked arithmetic. There are no trailing bytes.

### CatalogEntry (64 bytes)

| Offset | Size | Field | Required value/encoding |
|---:|---:|---|---|
| 0 | 32 | ObjectId | raw digest bytes |
| 32 | 2 | kind | u16 LE; at least 3 |
| 34 | 2 | version | u16 LE; nonzero |
| 36 | 8 | first_unit | u64 LE; region-relative |
| 44 | 8 | byte_length | u64 LE; 1 through `MAX_OBJECT_BYTES` |
| 52 | 4 | unit_count | u32 LE; exactly `ceil(byte_length / 4096)`, at most `MAX_OBJECT_UNITS` |
| 56 | 2 | flags | u16 LE = 0 |
| 58 | 6 | reserved | all zero |

Entries MUST be in strictly increasing lexicographic order by the 32 ObjectId bytes. Duplicate IDs are invalid. Each application extent MUST start at unit 2 or later, end at or before `catalog_first_unit`, and not overlap any other application extent. The Catalog extent MUST start at or after unit 2, have `ceil((16 + entry_count × 64) / 4096)` units, and end exactly at `commit_record_unit`. The one-unit CommitRecord extent MUST follow the Catalog and end at exclusive committed high-water. These extents MUST lie within `[2, region_units)`, and no object padding extent may overlap another object or metadata extent. The catalog lists application objects only; Catalog and CommitRecord objects are referenced by CommitRecord/Superblock fields and are not catalog entries. A new commit writes a new immutable full catalog. Store v1 MUST NOT delete, replace, relocate, or repair an existing application object or catalog entry.

## 3. CommitRecord bytes and generations

A CommitRecord is an ordinary kind-2, version-1 object. Its semantic bytes are exactly 200 bytes, followed by zero padding to the end of its single 4096-byte Store unit. Its complete field layout is:

| Offset | Size | Field | Required value/encoding |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `AIENCMT1` |
| 8 | 2 | record_version | u16 LE = 1 |
| 10 | 2 | record_size | u16 LE = 200 |
| 12 | 2 | format_major | u16 LE = 1 |
| 14 | 2 | format_minor | u16 LE = 0 |
| 16 | 8 | required_features | u64 LE = 0 in v1 |
| 24 | 8 | compatible_features | u64 LE = 0 in v1 |
| 32 | 16 | store_uuid | provisioned random 128-bit identity |
| 48 | 8 | region_units | u64 LE, 4 through `MAX_REGION_UNITS` |
| 56 | 8 | generation | u64 LE, nonzero |
| 64 | 8 | previous_generation | u64 LE |
| 72 | 32 | previous_commit_id | ObjectId bytes |
| 104 | 32 | previous_catalog_id | ObjectId bytes |
| 136 | 32 | catalog_id | ObjectId bytes |
| 168 | 8 | catalog_first_unit | u64 LE |
| 176 | 8 | catalog_byte_length | u64 LE |
| 184 | 4 | catalog_unit_count | u32 LE |
| 188 | 4 | catalog_entry_count | u32 LE |
| 192 | 8 | committed_high_water | u64 LE, exclusive |

The CommitRecord ObjectId is computed with the ObjectId formula over exactly these 200 semantic bytes. No other fields or trailing semantic bytes are permitted. The CommitRecord binds the format and features, Store UUID, region geometry, current generation, predecessor generation/CommitRecord/catalog, current catalog identity and descriptor, and committed high-water.

Genesis has generation 1, previous_generation 0, all-zero previous CommitRecord and previous catalog IDs, a real empty-or-populated Catalog object, and a real CommitRecord object. A non-genesis generation MUST equal its predecessor generation + 1 using checked arithmetic, and its previous CommitRecord and catalog IDs MUST equal that predecessor's identities. One Store history MUST retain the same Store UUID and region geometry in every generation. A transaction's CommitRecord is at `commit_first_unit`; its committed high-water MUST equal `commit_first_unit + 1`. Region units name `[0, region_units)`; the minimum region is 4 units.

Transaction append order is new application objects, complete new catalog, then one-unit CommitRecord. For a non-genesis generation, newly appended objects MUST form one contiguous run beginning at the predecessor's committed high-water; the Catalog MUST immediately follow that run (or begin at the predecessor high-water if there are no newly written objects). There MUST be no holes or backfill. Before the first persistent write, all size, count, arithmetic, transaction, and bounded-region capacity limits MUST be checked. A preflight failure MUST produce zero persistent writes. The write sequence is payload objects, catalog, CommitRecord, flush, inactive superblock, flush. The second flush is the commit point. The active superblock MUST NOT be rewritten as part of a transaction. Committed high-water is exclusive; after recovery an uncommitted tail beyond it may be reused, which is not general garbage collection.

## 4. Superblock bytes and CRC32C

Each superblock occupies exactly one 4096-byte Store unit. Bytes 172 through 4095 MUST be zero. The fields before the CRC are:

| Offset | Size | Field | Required value/encoding |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `AIENSTR1` |
| 8 | 2 | format_major | u16 LE = 1 |
| 10 | 2 | format_minor | u16 LE = 0 |
| 12 | 8 | required_features | u64 LE = 0 |
| 20 | 8 | compatible_features | u64 LE = 0 |
| 28 | 16 | store_uuid | same as CommitRecord |
| 44 | 4 | slot_id | u32 LE: 0 for A, 1 for B |
| 48 | 8 | region_units | u64 LE, 4 through `MAX_REGION_UNITS` |
| 56 | 8 | generation | u64 LE, nonzero |
| 64 | 32 | commit_record_id | ObjectId bytes |
| 96 | 8 | commit_record_unit | u64 LE |
| 104 | 32 | catalog_id | ObjectId bytes |
| 136 | 8 | catalog_first_unit | u64 LE |
| 144 | 8 | catalog_byte_length | u64 LE |
| 152 | 4 | catalog_unit_count | u32 LE |
| 156 | 4 | catalog_entry_count | u32 LE |
| 160 | 8 | committed_high_water | u64 LE, exclusive |
| 168 | 4 | crc32c | CRC-32C/Castagnoli |
| 172 | 3924 | reserved | all zero |

CRC-32C is the reflected Castagnoli algorithm (reflected polynomial `0x82f63b78`), init `0xffffffff`, xorout `0xffffffff`. To calculate the checksum, process all 4096 bytes with bytes 168 through 171 treated as zero. A reader MUST verify the CRC before trusting other superblock fields. The CRC establishes physical superblock credibility; SHA-256 establishes logical object integrity; the flushed superblock establishes commit authority.

The CRC-valid superblock's generation, Store UUID, region, CommitRecord ID/unit, catalog ID/descriptor, and high-water MUST exactly agree with its validated CommitRecord. In particular, `committed_high_water == commit_record_unit + 1`. The CommitRecord's catalog descriptor MUST agree with the decoded Catalog's ObjectId, semantic byte length (`16 + entry_count × 64`), unit count, and entry count. Superblock A and B that reference the same logical root differ only in `slot_id` and consequently CRC. A and B represent equivalent logical roots exactly when the Store UUID, format/features, generation, and CommitRecord ObjectId match; slot and physical CommitRecord unit are excluded. All other copies of root fields are checked against the CommitRecord before this equivalence comparison.

## 5. Format and root validation

Validation MUST follow this trust chain and MUST validate every referenced object before accepting a root:

`Bounded Region → Superblock CRC32C → SHA-256 CommitRecord → SHA-256 Catalog → sorted descriptors → SHA-256 Objects → Generation`

The Superblock's CommitRecord reference MUST identify one full Store unit; the semantic CommitRecord bytes MUST hash to its ObjectId and its remainder MUST be zero. Its catalog reference MUST identify `catalog_unit_count` contiguous units whose semantic length and ObjectId match the CommitRecord; catalog padding MUST be zero. Every catalog descriptor MUST satisfy its exact length/unit formula, bounds, non-overlap, zero-padded physical representation, and ObjectId. Metadata that points to any corrupt object is not a valid root. CRC-valid metadata alone never constitutes a valid root.

The two superblock units MUST both be read. Any actual read error while reading either root or any referenced object returns `MountError::Io`. Classification is deterministic:

1. If both superblock units are all zero, classify `Unformatted`.
2. If neither has `AIENSTR1` magic and at least one is nonzero, classify `ForeignOrUnknown`.
3. A CRC-valid `AIENSTR1` superblock whose major/minor or feature values are unsupported classifies `UnsupportedVersion`; do not fall back to another root.
4. Otherwise, invalid CRC, reserved bytes, malformed fields, or a graph-invalid root is `Corrupt/RecoveryRequired`, except for the specific degraded case below.
5. If both roots validate and have the same generation, equivalent roots are redundant valid copies; non-equivalent roots are `ConflictingRoots`.
6. If both roots validate and generations differ by exactly one, they MUST have the same Store UUID and region geometry. The newer root is normal only when its predecessor generation, CommitRecord ID, and catalog ID identify the older root exactly. Otherwise classify `InconsistentHistory`.
7. If both roots validate but are not adjacent, classify `InconsistentHistory`.
8. If one root is completely valid and the other is all zero, the valid root is a valid Store. If both superblocks are CRC-valid and supported, and one is completely valid while the strictly newer root has a graph error, the valid older root MUST be exposed read-only as `DegradedRecovery`. If a newer root is completely valid while the older root has a graph error, select the newer valid root as a valid Store. If one root is completely valid and the peer slot has an invalid CRC, wrong magic, or malformed superblock structure (and does not constitute a CRC-valid unsupported format), the valid root MUST be exposed read-only as `DegradedRecovery`; in-band transactions MUST be prohibited while mounted in `DegradedRecovery`; any subsequent repair, replacement, or reprovisioning requires separately authorized out-of-band recovery authority. A graph-invalid root at the same generation as the valid root, or a valid Store paired with a CRC-valid unsupported-version superblock, MUST classify as `Corrupt/RecoveryRequired` or `UnsupportedVersion` as specified above; implementations MUST NOT silently fall back to a writable mount based only on single-slot readability.

When both roots validate, the older/newer comparison uses generation without wrapping; overflow is invalid. A valid graph with a generation relationship error is history-inconsistent, not object-corrupt. Store v1 provides crash/corruption recovery and MUST NOT claim malicious full-device anti-rollback protection; trusted anti-rollback belongs to M5.

## 6. Canonical vectors

The repository's checked-in canonical vectors MUST include byte-exact ObjectId, empty and one-entry Catalog, CommitRecord, Superblock A/B, CRC32C, genesis, adjacent-generation, and equivalent-root examples. Negative vectors MUST exercise reserved bytes, lengths, counts, ordering, duplicates, bounds, CRC, ObjectIds, generation relationships, and high-water marks. Vectors are normative examples of the encodings above; parsers MUST reject malformed bytes rather than normalizing them.
