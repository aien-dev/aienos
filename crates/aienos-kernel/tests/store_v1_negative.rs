use aienos_kernel::store::v1::{
    crc32c, Catalog, CatalogEntry, CommitRecord, FormatError, ObjectId, Superblock,
    COMMIT_RECORD_BYTES, MAX_CATALOG_ENTRIES, STORE_UNIT_BYTES,
};

fn oid(kind: u16, data: &[u8]) -> ObjectId {
    ObjectId::calculate(kind, 1, data).unwrap()
}

fn entry(first_unit: u64, data: &[u8]) -> CatalogEntry {
    CatalogEntry {
        object_id: oid(3, data),
        kind: 3,
        version: 1,
        first_unit,
        byte_length: data.len() as u64,
        unit_count: 1,
        flags: 0,
    }
}

fn empty_catalog() -> (Catalog, Vec<u8>, ObjectId) {
    let catalog = Catalog { entries: vec![] };
    let bytes = catalog.encode().unwrap();
    let id = oid(1, &bytes);
    (catalog, bytes, id)
}

fn genesis() -> CommitRecord {
    let (_, _, catalog_id) = empty_catalog();
    CommitRecord {
        store_uuid: [0x11; 16],
        region_units: 8,
        generation: 1,
        previous_generation: 0,
        previous_commit_id: ObjectId([0; 32]),
        previous_catalog_id: ObjectId([0; 32]),
        catalog_id,
        catalog_first_unit: 2,
        catalog_byte_length: 16,
        catalog_unit_count: 1,
        catalog_entry_count: 0,
        committed_high_water: 4,
    }
}

fn superblock(slot_id: u32, commit: &CommitRecord) -> Superblock {
    Superblock {
        store_uuid: commit.store_uuid,
        slot_id,
        region_units: commit.region_units,
        generation: commit.generation,
        commit_record_id: commit.object_id().unwrap(),
        commit_record_unit: 3,
        catalog_id: commit.catalog_id,
        catalog_first_unit: commit.catalog_first_unit,
        catalog_byte_length: commit.catalog_byte_length,
        catalog_unit_count: commit.catalog_unit_count,
        catalog_entry_count: commit.catalog_entry_count,
        committed_high_water: commit.committed_high_water,
    }
}

fn rechecksum_superblock(bytes: &mut [u8]) {
    bytes[168..172].fill(0);
    let crc = crc32c(bytes);
    bytes[168..172].copy_from_slice(&crc.to_le_bytes());
}

#[test]
fn catalog_rejects_bad_header_counts_and_exact_lengths() {
    let (_, valid, _) = empty_catalog();

    for (offset, replacement) in [(0, b'X'), (8, 2), (10, 63)] {
        let mut malformed = valid.clone();
        malformed[offset] = replacement;
        assert!(Catalog::decode(&malformed).is_err(), "offset {offset}");
    }

    let mut wrong_count = valid.clone();
    wrong_count[12..16].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(
        Catalog::decode(&wrong_count),
        Err(FormatError::InvalidLength)
    );
    assert_eq!(
        Catalog::decode(&valid[..15]),
        Err(FormatError::InvalidLength)
    );
    let mut trailing = valid.clone();
    trailing.push(0);
    assert_eq!(Catalog::decode(&trailing), Err(FormatError::InvalidLength));

    let mut over_limit = valid;
    over_limit[12..16].copy_from_slice(&((MAX_CATALOG_ENTRIES as u32) + 1).to_le_bytes());
    assert_eq!(
        Catalog::decode(&over_limit),
        Err(FormatError::CatalogTooLarge)
    );
}

#[test]
fn catalog_rejects_entry_reserved_flags_and_invalid_lengths() {
    let mut encoded = entry(2, b"x").encode().unwrap();
    for offset in 58..64 {
        let mut malformed = encoded;
        malformed[offset] = 1;
        assert_eq!(
            CatalogEntry::decode(&malformed),
            Err(FormatError::NonzeroReserved)
        );
    }

    encoded[56] = 1;
    assert_eq!(
        CatalogEntry::decode(&encoded),
        Err(FormatError::MalformedDescriptor)
    );

    for (offset, value) in [
        (32, 0u64), // kind zero
        (34, 0),    // version zero
        (44, 0),    // length zero
        (44, 67_108_865),
        (52, 0), // unit count zero
        (52, 2), // incorrect ceil(length / unit)
    ] {
        let mut malformed = entry(2, b"x").encode().unwrap();
        let bytes = value.to_le_bytes();
        let width = if offset == 44 {
            8
        } else if offset == 52 {
            4
        } else {
            2
        };
        malformed[offset..offset + width].copy_from_slice(&bytes[..width]);
        assert!(
            CatalogEntry::decode(&malformed).is_err(),
            "offset {offset}, value {value}"
        );
    }
    assert_eq!(
        ObjectId::calculate(3, 1, b""),
        Err(FormatError::InvalidObject)
    );
}

#[test]
fn catalog_rejects_unsorted_and_duplicate_object_ids() {
    let a = entry(2, b"a");
    let b = entry(3, b"b");
    let (low, high) = if a.object_id < b.object_id {
        (a, b)
    } else {
        (b, a)
    };

    let sorted = Catalog {
        entries: vec![low, high],
    }
    .encode()
    .unwrap();
    assert!(Catalog::decode(&sorted).is_ok());

    let descending = Catalog {
        entries: vec![high, low],
    }
    .encode();
    assert_eq!(descending, Err(FormatError::CatalogOrder));

    let duplicate = Catalog {
        entries: vec![low, low],
    }
    .encode();
    assert_eq!(duplicate, Err(FormatError::DuplicateObject));
}

#[test]
fn catalog_entry_bounds_reject_metadata_overflow_and_high_water_violations() {
    let valid = entry(2, b"x");
    assert!(valid.validate_bounds(8, 4, 5).is_ok());
    assert_eq!(
        entry(0, b"x").validate_bounds(8, 4, 5),
        Err(FormatError::OutOfBounds)
    );
    assert_eq!(
        entry(1, b"x").validate_bounds(8, 4, 5),
        Err(FormatError::OutOfBounds)
    );
    assert_eq!(
        entry(4, b"x").validate_bounds(8, 4, 5),
        Err(FormatError::OutOfBounds)
    );
    assert_eq!(
        entry(2, b"x").validate_bounds(8, 4, 2),
        Err(FormatError::OutOfBounds)
    );
    assert_eq!(
        entry(3, b"x").validate_bounds(2, 8, 8),
        Err(FormatError::OutOfBounds)
    );

    let mut overflow = valid;
    overflow.first_unit = u64::MAX;
    assert_eq!(
        overflow.validate_bounds(8, 8, 8),
        Err(FormatError::LengthOverflow)
    );
}

#[test]
fn catalog_extents_reject_overlap_and_metadata_overlap() {
    let a = entry(2, b"first");
    let b = entry(2, b"second");
    let mut entries = vec![a, b];
    entries.sort_by_key(|item| item.object_id);
    let catalog = Catalog { entries };
    assert_eq!(
        catalog.validate_extents(16, 4, 8),
        Err(FormatError::Overlap)
    );

    let metadata_overlap = Catalog {
        entries: vec![entry(3, b"third")],
    };
    assert_eq!(
        metadata_overlap.validate_extents(16, 3, 8),
        Err(FormatError::OutOfBounds)
    );
}

#[test]
fn object_id_rejects_semantic_mutation_wrong_identity_and_nonzero_padding() {
    let semantic = b"payload";
    let id = oid(3, semantic);
    let mut extent = vec![0; STORE_UNIT_BYTES];
    extent[..semantic.len()].copy_from_slice(semantic);
    assert!(id
        .validate_extent(3, 1, semantic.len() as u64, &extent)
        .is_ok());

    let mut changed_semantic = extent.clone();
    changed_semantic[0] ^= 1;
    assert_eq!(
        id.validate_extent(3, 1, semantic.len() as u64, &changed_semantic),
        Err(FormatError::IntegrityFailure)
    );

    let mut changed_padding = extent.clone();
    changed_padding[STORE_UNIT_BYTES - 1] = 1;
    assert_eq!(
        id.validate_extent(3, 1, semantic.len() as u64, &changed_padding),
        Err(FormatError::NonzeroReserved)
    );

    assert_eq!(
        id.validate_extent(4, 1, semantic.len() as u64, &extent),
        Err(FormatError::IntegrityFailure)
    );
    assert_eq!(
        id.validate_extent(3, 2, semantic.len() as u64, &extent),
        Err(FormatError::IntegrityFailure)
    );
    assert_eq!(
        id.validate_extent(3, 1, (semantic.len() + 1) as u64, &extent),
        Err(FormatError::IntegrityFailure)
    );
    assert_eq!(
        id.validate_extent(3, 1, semantic.len() as u64, &extent[..STORE_UNIT_BYTES - 1]),
        Err(FormatError::InvalidLength)
    );
    assert_eq!(
        ObjectId::calculate(3, 1, b""),
        Err(FormatError::InvalidObject)
    );
}

#[test]
fn crc32c_known_answer_and_superblock_rejects_corruption_reserved_and_slot() {
    assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    let commit = genesis();
    let valid = superblock(0, &commit).encode().unwrap();
    assert!(Superblock::decode(&valid, 0).is_ok());

    let mut field_corrupt = valid;
    field_corrupt[56] ^= 1;
    assert_eq!(
        Superblock::decode(&field_corrupt, 0),
        Err(FormatError::BadSuperblockCrc)
    );

    let mut crc_corrupt = valid;
    crc_corrupt[168] ^= 1;
    assert_eq!(
        Superblock::decode(&crc_corrupt, 0),
        Err(FormatError::BadSuperblockCrc)
    );

    for offset in 172..STORE_UNIT_BYTES {
        let mut reserved = valid;
        reserved[offset] = 1;
        rechecksum_superblock(&mut reserved);
        assert_eq!(
            Superblock::decode(&reserved, 0),
            Err(FormatError::NonzeroReserved),
            "offset {offset}"
        );
    }

    assert_eq!(
        Superblock::decode(&valid, 1),
        Err(FormatError::WrongSuperblockSlot)
    );

    for (offset, value) in [(48, 3u64), (56, 0), (160, 5)] {
        let mut malformed = valid;
        malformed[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        rechecksum_superblock(&mut malformed);
        assert_eq!(
            Superblock::decode(&malformed, 0),
            Err(FormatError::MalformedSuperblock),
            "offset {offset}"
        );
    }

    let mut unsupported_features = valid;
    unsupported_features[12] = 1;
    rechecksum_superblock(&mut unsupported_features);
    assert_eq!(
        Superblock::decode(&unsupported_features, 0),
        Err(FormatError::UnsupportedFeatures)
    );
}

#[test]
fn commit_record_rejects_lengths_features_generation_and_high_water() {
    let good = genesis();
    let encoded = good.encode().unwrap();
    assert_eq!(encoded.len(), COMMIT_RECORD_BYTES);
    assert_eq!(CommitRecord::decode(&encoded).unwrap(), good);

    for bad_length in [COMMIT_RECORD_BYTES - 1, COMMIT_RECORD_BYTES + 1] {
        let malformed = vec![0u8; bad_length];
        assert!(CommitRecord::decode(&malformed).is_err());
    }

    for (offset, value) in [
        (56, 0u64),
        (64, 1),
        (176, 15),
        (184, 2),
        (188, 1),
        (192, 3),
        (192, 5),
    ] {
        let mut malformed = encoded;
        malformed[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        assert!(
            CommitRecord::decode(&malformed).is_err(),
            "offset {offset}, value {value}"
        );
    }

    let mut oversized_region = encoded;
    oversized_region[48..56].copy_from_slice(&4_294_967_297u64.to_le_bytes());
    assert!(CommitRecord::decode(&oversized_region).is_err());

    let mut features = encoded;
    features[16] = 1;
    assert_eq!(
        CommitRecord::decode(&features),
        Err(FormatError::UnsupportedFeatures)
    );

    let commit_id = good.object_id().unwrap();
    let mut padded_commit = vec![0u8; STORE_UNIT_BYTES];
    padded_commit[..encoded.len()].copy_from_slice(&encoded);
    assert!(commit_id
        .validate_extent(2, 1, encoded.len() as u64, &padded_commit)
        .is_ok());
    padded_commit[STORE_UNIT_BYTES - 1] = 1;
    assert_eq!(
        commit_id.validate_extent(2, 1, encoded.len() as u64, &padded_commit),
        Err(FormatError::NonzeroReserved)
    );

    let mut malformed_genesis = good.clone();
    malformed_genesis.previous_generation = 1;
    assert_eq!(
        malformed_genesis.encode(),
        Err(FormatError::InvalidGeneration)
    );
}

#[test]
fn generation_link_requires_adjacent_generation_and_exact_predecessor_ids() {
    let previous = genesis();
    let previous_id = previous.object_id().unwrap();
    let mut next = previous.clone();
    next.generation = 2;
    next.previous_generation = 1;
    next.previous_commit_id = previous_id;
    next.previous_catalog_id = previous.catalog_id;
    next.catalog_first_unit = 4;
    next.committed_high_water = 6;
    assert!(next.encode().is_ok());
    assert!(next.identifies_predecessor(&previous, previous_id));

    next.previous_catalog_id.0[0] ^= 1;
    assert!(!next.identifies_predecessor(&previous, previous_id));
    next.previous_catalog_id = previous.catalog_id;
    next.previous_commit_id.0[0] ^= 1;
    assert!(!next.identifies_predecessor(&previous, previous_id));
    next.previous_commit_id = previous_id;
    next.previous_generation = 0;
    assert_eq!(next.encode(), Err(FormatError::InvalidGeneration));

    let mut overflow = next;
    overflow.generation = u64::MAX;
    overflow.previous_generation = u64::MAX - 1;
    overflow.previous_commit_id = ObjectId([1; 32]);
    overflow.previous_catalog_id = ObjectId([1; 32]);
    assert!(overflow.encode().is_ok());
    overflow.generation = u64::MAX;
    overflow.previous_generation = u64::MAX;
    assert_eq!(overflow.encode(), Err(FormatError::InvalidGeneration));
}

#[test]
fn superblock_commit_validation_binds_commit_unit_catalog_and_high_water() {
    let commit = genesis();
    let sb = superblock(0, &commit);
    assert!(sb
        .validate_commit(commit.object_id().unwrap(), &commit)
        .is_ok());

    let mut wrong_commit_unit = sb.clone();
    wrong_commit_unit.commit_record_unit = 2;
    assert_eq!(
        wrong_commit_unit.validate_commit(commit.object_id().unwrap(), &commit),
        Err(FormatError::MalformedSuperblock)
    );

    let mut wrong_catalog = sb.clone();
    wrong_catalog.catalog_first_unit = 1;
    assert_eq!(
        wrong_catalog.validate_commit(commit.object_id().unwrap(), &commit),
        Err(FormatError::MalformedSuperblock)
    );

    let mut wrong_high_water = sb;
    wrong_high_water.committed_high_water = 3;
    assert_eq!(
        wrong_high_water.validate_commit(commit.object_id().unwrap(), &commit),
        Err(FormatError::MalformedSuperblock)
    );
}
