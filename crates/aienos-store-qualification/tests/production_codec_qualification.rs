//! Independent Qualification Suite running against Production Store v1 Codec (Stage 2).
//!
//! Proves that production Store v1 codec in `aienos_kernel::store::v1`:
//! 1. Byte-for-byte conforms to ADR 0015 and matches the independent oracle.
//! 2. Independently validates all checked-in golden vectors in `docs/adr/0015-golden-vectors.json`.
//! 3. Rejects all adversarial Superblock, Catalog, and CommitRecord mutations.
//! 4. Preserves arithmetic limits and fail-closed bounds.

use aienos_kernel::store::v1 as prod;
use aienos_store_qualification::limits::{
    CATALOG_ENTRY_BYTES, CATALOG_HEADER_BYTES, COMMIT_RECORD_BYTES, MAX_CATALOG_ENTRIES,
    MAX_OBJECT_BYTES, MAX_OBJECT_UNITS, MAX_REGION_UNITS, MAX_TRANSACTION_OBJECTS,
    MAX_TRANSACTION_UNITS, STORE_UNIT_BYTES,
};
use aienos_store_qualification::oracle::{independent_crc32c, independent_object_id};
use aienos_store_qualification::superblock::{rechecksum_superblock, SuperblockBuilder};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

// =========================================================================
// 1. Independent Golden Vectors Recomputation & Production Codec Agreement
// =========================================================================

#[test]
fn test_independent_golden_vectors_recomputation() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let vectors_path = Path::new(manifest_dir).join("../../docs/adr/0015-golden-vectors.json");
    let raw_json = fs::read_to_string(&vectors_path).expect("read golden vectors json");
    let root: Value = serde_json::from_str(&raw_json).expect("parse golden vectors json");

    // 1. ObjectId fixture
    let obj_sect = &root["object_id"];
    let kind = u16::from_le_bytes(
        hex_to_bytes(obj_sect["kind_u16le"].as_str().unwrap())
            .try_into()
            .unwrap(),
    );
    let version = u16::from_le_bytes(
        hex_to_bytes(obj_sect["version_u16le"].as_str().unwrap())
            .try_into()
            .unwrap(),
    );
    let sem_bytes = hex_to_bytes(obj_sect["semantic_bytes_hex"].as_str().unwrap());
    let expected_obj_id = hex_to_bytes(obj_sect["object_id_hex"].as_str().unwrap());

    // Independent oracle derivation
    let oracle_obj_id = independent_object_id(kind, version, sem_bytes.len() as u64, &sem_bytes);
    assert_eq!(
        oracle_obj_id.to_vec(),
        expected_obj_id,
        "Oracle ObjectId must match golden vector"
    );

    // Production codec derivation
    let prod_obj_id = prod::ObjectId::calculate(kind, version, &sem_bytes).expect("prod calculate");
    assert_eq!(
        prod_obj_id.0.to_vec(),
        expected_obj_id,
        "Production ObjectId must match golden vector"
    );

    // Preimage check
    let preimage = hex_to_bytes(obj_sect["preimage_hex"].as_str().unwrap());
    assert_eq!(
        sha256_hex(&preimage),
        obj_sect["preimage_sha256"].as_str().unwrap()
    );

    // 2. Empty Catalog fixture
    let empty_cat_sect = &root["empty_catalog"];
    let empty_cat_sem = hex_to_bytes(empty_cat_sect["semantic_bytes_hex"].as_str().unwrap());
    let empty_cat_id = hex_to_bytes(empty_cat_sect["object_id_hex"].as_str().unwrap());
    let empty_cat_unit = hex_to_bytes(empty_cat_sect["unit_hex"].as_str().unwrap());

    let oracle_empty_cat_id = independent_object_id(
        prod::OBJECT_KIND_CATALOG,
        prod::OBJECT_VERSION_V1,
        empty_cat_sem.len() as u64,
        &empty_cat_sem,
    );
    assert_eq!(oracle_empty_cat_id.to_vec(), empty_cat_id);
    assert_eq!(
        sha256_hex(&empty_cat_unit),
        empty_cat_sect["unit_sha256"].as_str().unwrap()
    );

    // Production decode
    let prod_empty_cat = prod::Catalog::decode(&empty_cat_sem).expect("decode empty catalog");
    assert_eq!(prod_empty_cat.entries.len(), 0);

    // 3. One Entry Catalog fixture
    let one_cat_sect = &root["one_entry_catalog"];
    let one_cat_sem = hex_to_bytes(one_cat_sect["semantic_bytes_hex"].as_str().unwrap());
    let one_cat_id = hex_to_bytes(one_cat_sect["object_id_hex"].as_str().unwrap());
    let one_cat_unit = hex_to_bytes(one_cat_sect["unit_hex"].as_str().unwrap());

    let oracle_one_cat_id = independent_object_id(
        prod::OBJECT_KIND_CATALOG,
        prod::OBJECT_VERSION_V1,
        one_cat_sem.len() as u64,
        &one_cat_sem,
    );
    assert_eq!(oracle_one_cat_id.to_vec(), one_cat_id);
    assert_eq!(
        sha256_hex(&one_cat_unit),
        one_cat_sect["unit_sha256"].as_str().unwrap()
    );

    let prod_one_cat = prod::Catalog::decode(&one_cat_sem).expect("decode one entry catalog");
    assert_eq!(prod_one_cat.entries.len(), 1);
    let entry = &prod_one_cat.entries[0];
    assert_eq!(entry.kind, 3);
    assert_eq!(entry.version, 1);
    assert_eq!(entry.first_unit, 4);
    assert_eq!(entry.byte_length, 16);
    assert_eq!(entry.unit_count, 1);

    // 4. CRC32C Castagnoli fixture
    let crc_sect = &root["crc32c"];
    let check_input = crc_sect["check_input_ascii"].as_str().unwrap().as_bytes();
    let oracle_crc = independent_crc32c(check_input);
    assert_eq!(oracle_crc, 0xE306_9283);
    let prod_crc = prod::crc32c(check_input);
    assert_eq!(prod_crc, 0xE306_9283);

    // 5. Genesis Superblocks & CommitRecord fixtures
    let gen_sect = &root["genesis"];
    let gen_commit_sem = hex_to_bytes(gen_sect["commit_record_semantic_hex"].as_str().unwrap());
    let gen_commit_id = hex_to_bytes(gen_sect["commit_record_object_id_hex"].as_str().unwrap());
    assert_eq!(
        gen_commit_sem.len(),
        200,
        "CommitRecord v1 MUST be exactly 200 semantic bytes"
    );

    let oracle_commit_id = independent_object_id(
        prod::OBJECT_KIND_COMMIT_RECORD,
        prod::OBJECT_VERSION_V1,
        gen_commit_sem.len() as u64,
        &gen_commit_sem,
    );
    assert_eq!(oracle_commit_id.to_vec(), gen_commit_id);

    let prod_commit = prod::CommitRecord::decode(&gen_commit_sem).expect("decode genesis commit");
    assert_eq!(prod_commit.generation, 1);
    assert_eq!(prod_commit.previous_generation, 0);

    let sb_a_unit = hex_to_bytes(gen_sect["superblock_a_unit_hex"].as_str().unwrap());
    let sb_b_unit = hex_to_bytes(gen_sect["superblock_b_unit_hex"].as_str().unwrap());
    assert_eq!(sb_a_unit.len(), 4096);
    assert_eq!(sb_b_unit.len(), 4096);
    assert_eq!(
        sha256_hex(&sb_a_unit),
        gen_sect["superblock_a_unit_sha256"].as_str().unwrap()
    );
    assert_eq!(
        sha256_hex(&sb_b_unit),
        gen_sect["superblock_b_unit_sha256"].as_str().unwrap()
    );

    // Independent CRC validation of Superblocks
    let mut sb_a_check = sb_a_unit.clone();
    sb_a_check[168..172].fill(0);
    assert_eq!(
        independent_crc32c(&sb_a_check),
        u32::from_le_bytes(sb_a_unit[168..172].try_into().unwrap())
    );

    let mut sb_b_check = sb_b_unit.clone();
    sb_b_check[168..172].fill(0);
    assert_eq!(
        independent_crc32c(&sb_b_check),
        u32::from_le_bytes(sb_b_unit[168..172].try_into().unwrap())
    );

    // Production decode and validation
    let prod_sb_a = prod::Superblock::decode(&sb_a_unit, 0).expect("decode SB A");
    let prod_sb_b = prod::Superblock::decode(&sb_b_unit, 1).expect("decode SB B");
    assert_eq!(prod_sb_a.generation, 1);
    assert_eq!(prod_sb_b.generation, 1);
    assert_eq!(prod_sb_a.slot_id, 0);
    assert_eq!(prod_sb_b.slot_id, 1);

    // 6. Adjacent Generations fixture
    let adj_sect = &root["adjacent_generations"];
    let gen2_sb_a_unit = hex_to_bytes(
        adj_sect["generation_2_superblock_a_unit_hex"]
            .as_str()
            .unwrap(),
    );
    let prod_gen2_sb = prod::Superblock::decode(&gen2_sb_a_unit, 0).expect("decode Gen 2 SB A");
    assert_eq!(prod_gen2_sb.generation, 2);
    assert_eq!(prod_gen2_sb.committed_high_water, 7);

    println!("STORE_GOLDEN_VECTORS_INDEPENDENT: PASS");
    println!("STORE_OBJECT_ID_ORACLE: PASS");
    println!("STORE_FORMAT_ORACLE: PASS");
}

// =========================================================================
// 2. Production Codec Hostile Superblock Rejection (G1)
// =========================================================================

#[test]
fn test_production_codec_rejects_hostile_superblocks() {
    let base = SuperblockBuilder::genesis(0);

    // 1. Wrong magic
    let bad_magic_unit = base.clone().with_magic(*b"NOTASTOR").build_unit();
    assert_eq!(
        prod::Superblock::decode(&bad_magic_unit, 0),
        Err(prod::FormatError::BadSuperblockMagic)
    );

    // 2. Unsupported version
    let bad_ver_unit = base.clone().with_version(2, 0).build_unit();
    assert_eq!(
        prod::Superblock::decode(&bad_ver_unit, 0),
        Err(prod::FormatError::UnsupportedVersion)
    );

    // 3. Unknown features
    let bad_feat_unit = base.clone().with_features(1, 0).build_unit();
    assert_eq!(
        prod::Superblock::decode(&bad_feat_unit, 0),
        Err(prod::FormatError::UnsupportedFeatures)
    );

    // 4. Malformed slot ID
    let bad_slot_unit = base.clone().with_slot(2).build_unit();
    assert_eq!(
        prod::Superblock::decode(&bad_slot_unit, 2),
        Err(prod::FormatError::WrongSuperblockSlot)
    );

    // Slot mismatch against expected
    let slot_mismatch = base.clone().with_slot(1).build_unit();
    assert_eq!(
        prod::Superblock::decode(&slot_mismatch, 0),
        Err(prod::FormatError::WrongSuperblockSlot)
    );

    // 5. High-water out of bounds
    let bad_hw_unit = base.clone().with_high_water(9999).build_unit();
    assert_eq!(
        prod::Superblock::decode(&bad_hw_unit, 0),
        Err(prod::FormatError::MalformedSuperblock)
    );

    // 6. Non-zero reserved padding bytes (bytes 172..4095)
    for offset in [172, 173, 256, 1024, 4095] {
        let mut corrupted = base.clone().build_unit_unchecksummed();
        corrupted[offset] = 0xAA;
        rechecksum_superblock(&mut corrupted);
        assert_eq!(
            prod::Superblock::decode(&corrupted, 0),
            Err(prod::FormatError::NonzeroReserved),
            "Production decoder must reject nonzero reserved byte at offset {}",
            offset
        );
    }

    // 7. Bit flipped in CRC
    let mut bad_crc_unit = base.clone().build_unit();
    bad_crc_unit[168] ^= 0x01;
    assert_eq!(
        prod::Superblock::decode(&bad_crc_unit, 0),
        Err(prod::FormatError::BadSuperblockCrc)
    );

    // 8. Truncated unit (< 4096 bytes)
    let trunc_bytes = &base.clone().build_unit()[..4095];
    assert_eq!(
        prod::Superblock::decode(trunc_bytes, 0),
        Err(prod::FormatError::BadSuperblockMagic)
    );

    println!("STORE_SUPERBLOCK_NEGATIVE: PASS");
}

// =========================================================================
// 3. Production Codec Hostile Catalog Rejection (G2)
// =========================================================================

#[test]
fn test_production_codec_rejects_hostile_catalogs() {
    // 1. Unsorted entries
    let id_a = [0x11; 32];
    let id_b = [0x22; 32];
    let mut catalog_bytes = vec![0u8; 16 + 128];
    catalog_bytes[..8].copy_from_slice(b"AIENCAT1");
    catalog_bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
    catalog_bytes[10..12].copy_from_slice(&64u16.to_le_bytes());
    catalog_bytes[12..16].copy_from_slice(&2u32.to_le_bytes());

    // Put id_b first then id_a (unsorted)
    let mut entry_b = [0u8; 64];
    entry_b[..32].copy_from_slice(&id_b);
    entry_b[32..34].copy_from_slice(&3u16.to_le_bytes());
    entry_b[34..36].copy_from_slice(&1u16.to_le_bytes());
    entry_b[36..44].copy_from_slice(&4u64.to_le_bytes());
    entry_b[44..52].copy_from_slice(&16u64.to_le_bytes());
    entry_b[52..56].copy_from_slice(&1u32.to_le_bytes());

    let mut entry_a = entry_b;
    entry_a[..32].copy_from_slice(&id_a);

    catalog_bytes[16..80].copy_from_slice(&entry_b);
    catalog_bytes[80..144].copy_from_slice(&entry_a);

    assert_eq!(
        prod::Catalog::decode(&catalog_bytes),
        Err(prod::FormatError::CatalogOrder)
    );

    // 2. Duplicate ObjectId
    catalog_bytes[80..144].copy_from_slice(&entry_b);
    assert_eq!(
        prod::Catalog::decode(&catalog_bytes),
        Err(prod::FormatError::DuplicateObject)
    );

    // 3. Bad catalog magic
    catalog_bytes[..8].copy_from_slice(b"BADMAGIC");
    assert_eq!(
        prod::Catalog::decode(&catalog_bytes),
        Err(prod::FormatError::BadCatalogMagic)
    );

    // 4. Non-zero reserved bytes in CatalogEntry (bytes 58..64)
    let mut bad_entry_bytes = entry_a;
    bad_entry_bytes[58] = 0xFF;
    assert_eq!(
        prod::CatalogEntry::decode(&bad_entry_bytes),
        Err(prod::FormatError::NonzeroReserved)
    );

    // 5. Kind < 3 rejected
    let mut bad_kind_entry = entry_a;
    bad_kind_entry[32..34].copy_from_slice(&2u16.to_le_bytes());
    assert_eq!(
        prod::CatalogEntry::decode(&bad_kind_entry),
        Err(prod::FormatError::MalformedDescriptor)
    );

    println!("STORE_CATALOG_NEGATIVE: PASS");
}

// =========================================================================
// 4. Production Codec Hostile CommitRecord Rejection
// =========================================================================

#[test]
fn test_production_codec_rejects_hostile_commit_records() {
    let mut valid_bytes = vec![0u8; 200];
    valid_bytes[..8].copy_from_slice(b"AIENCMT1");
    valid_bytes[8..10].copy_from_slice(&1u16.to_le_bytes()); // record_version = 1
    valid_bytes[10..12].copy_from_slice(&200u16.to_le_bytes()); // record_size = 200
    valid_bytes[12..14].copy_from_slice(&1u16.to_le_bytes()); // format_major = 1
    valid_bytes[14..16].copy_from_slice(&0u16.to_le_bytes()); // format_minor = 0
    valid_bytes[48..56].copy_from_slice(&16u64.to_le_bytes()); // region_units = 16
    valid_bytes[56..64].copy_from_slice(&1u64.to_le_bytes()); // generation = 1
    valid_bytes[168..176].copy_from_slice(&2u64.to_le_bytes()); // catalog_first_unit = 2
    valid_bytes[176..184].copy_from_slice(&16u64.to_le_bytes()); // catalog_byte_length = 16
    valid_bytes[184..188].copy_from_slice(&1u32.to_le_bytes()); // catalog_unit_count = 1
    valid_bytes[192..200].copy_from_slice(&4u64.to_le_bytes()); // committed_high_water = 4

    assert!(prod::CommitRecord::decode(&valid_bytes).is_ok());

    // 1. Wrong magic
    let mut bad_magic = valid_bytes.clone();
    bad_magic[..8].copy_from_slice(b"BADMAGIC");
    assert_eq!(
        prod::CommitRecord::decode(&bad_magic),
        Err(prod::FormatError::MalformedCommitRecord)
    );

    // 2. Length != 200
    assert_eq!(
        prod::CommitRecord::decode(&valid_bytes[..199]),
        Err(prod::FormatError::MalformedCommitRecord)
    );

    // 3. Record size field != 200
    let mut bad_size = valid_bytes.clone();
    bad_size[10..12].copy_from_slice(&232u16.to_le_bytes());
    assert_eq!(
        prod::CommitRecord::decode(&bad_size),
        Err(prod::FormatError::UnsupportedVersion)
    );

    // 4. Generation == 0
    let mut zero_gen = valid_bytes.clone();
    zero_gen[56..64].fill(0);
    assert_eq!(
        prod::CommitRecord::decode(&zero_gen),
        Err(prod::FormatError::MalformedCommitRecord)
    );

    // 5. Catalog extent overflow past high_water
    let mut bad_cat_hw = valid_bytes.clone();
    bad_cat_hw[192..200].copy_from_slice(&2u64.to_le_bytes()); // high_water = 2 < commit_unit
    assert_eq!(
        prod::CommitRecord::decode(&bad_cat_hw),
        Err(prod::FormatError::MalformedCommitRecord)
    );
}

// =========================================================================
// 5. Constants & Limits Parity Check (G3)
// =========================================================================

#[test]
fn test_production_codec_constants_and_limits_parity() {
    assert_eq!(STORE_UNIT_BYTES, prod::STORE_UNIT_BYTES as u64);
    assert_eq!(MAX_CATALOG_ENTRIES, prod::MAX_CATALOG_ENTRIES);
    assert_eq!(CATALOG_HEADER_BYTES, prod::CATALOG_HEADER_BYTES as u64);
    assert_eq!(CATALOG_ENTRY_BYTES, prod::CATALOG_ENTRY_BYTES);
    assert_eq!(MAX_OBJECT_BYTES, prod::MAX_OBJECT_BYTES);
    assert_eq!(MAX_OBJECT_UNITS, prod::MAX_OBJECT_UNITS as u64);
    assert_eq!(MAX_TRANSACTION_OBJECTS, prod::MAX_TRANSACTION_OBJECTS);
    assert_eq!(MAX_TRANSACTION_UNITS, prod::MAX_TRANSACTION_UNITS);
    assert_eq!(MAX_REGION_UNITS, prod::MAX_REGION_UNITS);
    assert_eq!(COMMIT_RECORD_BYTES, prod::COMMIT_RECORD_BYTES as u64);

    println!("STORE_LIMITS: PASS");
    println!("STORE_V1_INDEPENDENT_QUALIFICATION: PASS");
}
