//! Canonical System Store v1 genesis units (ADR 0015 §5).

use alloc::vec::Vec;

use super::v1::{
    object_unit_count, Catalog, CommitRecord, ObjectId, Superblock, OBJECT_KIND_CATALOG,
    OBJECT_VERSION_V1, STORE_UNIT_BYTES,
};

/// Units 0..4 of a freshly formatted Store: Superblock A, an all-zero slot B
/// (so the first transaction exercises the "inactive slot initially zero"
/// case), the empty catalog at unit 2 and the genesis CommitRecord at unit 3.
pub fn genesis_units(store_uuid: [u8; 16], region_units: u64) -> [[u8; STORE_UNIT_BYTES]; 4] {
    let catalog = Catalog {
        entries: Vec::new(),
    };
    let catalog_bytes = catalog.encode().expect("empty catalog encodes");
    let catalog_id = ObjectId::calculate(OBJECT_KIND_CATALOG, OBJECT_VERSION_V1, &catalog_bytes)
        .expect("catalog id");
    let catalog_units = object_unit_count(catalog_bytes.len() as u64).expect("catalog units");
    let catalog_first = 2u64;
    let commit_unit = catalog_first + u64::from(catalog_units);
    let high_water = commit_unit + 1;

    let commit = CommitRecord {
        store_uuid,
        region_units,
        generation: 1,
        previous_generation: 0,
        previous_commit_id: ObjectId([0u8; 32]),
        previous_catalog_id: ObjectId([0u8; 32]),
        catalog_id,
        catalog_first_unit: catalog_first,
        catalog_byte_length: catalog_bytes.len() as u64,
        catalog_unit_count: catalog_units,
        catalog_entry_count: 0,
        committed_high_water: high_water,
    };
    let commit_bytes = commit.encode().expect("genesis commit encodes");
    let commit_id = commit.object_id().expect("commit id");

    let superblock = Superblock {
        store_uuid,
        slot_id: 0,
        region_units,
        generation: 1,
        commit_record_id: commit_id,
        commit_record_unit: commit_unit,
        catalog_id,
        catalog_first_unit: catalog_first,
        catalog_byte_length: catalog_bytes.len() as u64,
        catalog_unit_count: catalog_units,
        catalog_entry_count: 0,
        committed_high_water: high_water,
    };

    let mut out = [[0u8; STORE_UNIT_BYTES]; 4];
    out[0].copy_from_slice(&superblock.encode().expect("genesis superblock encodes"));
    out[2][..catalog_bytes.len()].copy_from_slice(&catalog_bytes);
    out[3][..commit_bytes.len()].copy_from_slice(&commit_bytes);
    out
}
