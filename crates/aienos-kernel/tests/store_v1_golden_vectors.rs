//! ADR 0015 golden vectors: the kernel's own Store v1 encoders must reproduce
//! every byte of docs/adr/0015-golden-vectors.json, and every vector must
//! decode back to the value that produced it.
//!
//! Every section is read through [`Section`], which records the keys it
//! checked; each section check ends with [`Section::finish`], which fails if
//! the JSON carries a field this test did not assert. Adding a vector to the
//! frozen file therefore requires adding its assertion here.

use std::cell::RefCell;
use std::collections::BTreeSet;

use aienos_kernel::crypto::sha256::Sha256;
use aienos_kernel::store::v1::{
    crc32c, Catalog, CatalogEntry, CommitRecord, ObjectId, Superblock, CATALOG_HEADER_BYTES,
    STORE_UNIT_BYTES, SUPERBLOCK_CRC_OFFSET,
};
use serde_json::Value;

const VECTORS: &str = include_str!("../../../docs/adr/0015-golden-vectors.json");
const UUID: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
/// ObjectId preimage domain from ADR 0015 (NUL-terminated).
const OBJECT_DOMAIN: &[u8] = b"AIENOS-STORE-OBJECT-V1\0";

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("golden vector JSON parses")
}

fn decode_hex(s: &str, what: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "{what} has odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|_| panic!("{what}: bad hex")))
        .collect()
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

/// One JSON section plus the set of keys the test has asserted.
struct Section<'a> {
    name: &'static str,
    obj: &'a serde_json::Map<String, Value>,
    used: RefCell<BTreeSet<String>>,
}

impl<'a> Section<'a> {
    fn new(v: &'a Value, name: &'static str) -> Self {
        let obj = v[name]
            .as_object()
            .unwrap_or_else(|| panic!("missing section {name}"));
        Self {
            name,
            obj,
            used: RefCell::new(BTreeSet::new()),
        }
    }

    fn raw(&self, key: &str) -> &'a Value {
        self.used.borrow_mut().insert(key.to_string());
        self.obj
            .get(key)
            .unwrap_or_else(|| panic!("missing {}.{key}", self.name))
    }

    fn str(&self, key: &str) -> &'a str {
        self.raw(key)
            .as_str()
            .unwrap_or_else(|| panic!("{}.{key} is not a string", self.name))
    }

    fn u64(&self, key: &str) -> u64 {
        self.raw(key)
            .as_u64()
            .unwrap_or_else(|| panic!("{}.{key} is not an integer", self.name))
    }

    fn hex(&self, key: &str) -> Vec<u8> {
        decode_hex(self.str(key), &format!("{}.{key}", self.name))
    }

    /// Assert `actual` equals the hex field `key` byte for byte.
    fn bytes(&self, key: &str, actual: &[u8]) {
        let expected = self.hex(key);
        assert_eq!(
            actual.len(),
            expected.len(),
            "{}.{key}: length differs",
            self.name
        );
        if let Some(i) = actual.iter().zip(&expected).position(|(a, b)| a != b) {
            panic!(
                "{}.{key}: first mismatch at byte {i}: kernel {:#04x}, vector {:#04x}",
                self.name, actual[i], expected[i]
            );
        }
    }

    /// Assert the `*_sha256` field `key` is SHA-256 of `data`.
    fn digest(&self, key: &str, data: &[u8]) {
        assert!(key.ends_with("sha256"), "{key} is not a digest field");
        self.bytes(key, &sha256(data));
    }

    /// Every key present in the JSON section must have been asserted.
    fn finish(self) {
        let present: BTreeSet<String> = self.obj.keys().cloned().collect();
        let used = self.used.into_inner();
        let unchecked: Vec<_> = present.difference(&used).collect();
        assert!(
            unchecked.is_empty(),
            "{}: fields not asserted by this test: {unchecked:?}",
            self.name
        );
    }
}

fn unit(semantic: &[u8]) -> Vec<u8> {
    assert!(!semantic.is_empty() && semantic.len() <= STORE_UNIT_BYTES);
    let mut u = semantic.to_vec();
    u.resize(STORE_UNIT_BYTES, 0);
    u
}

fn id(kind: u16, version: u16, semantic: &[u8]) -> ObjectId {
    ObjectId::calculate(kind, version, semantic).expect("object id")
}

/// ADR 0015 ObjectId preimage, built independently of the kernel so the
/// vector's preimage bytes are checked against the contract, then tied to the
/// kernel's ObjectId by hashing.
fn preimage(kind: u16, version: u16, semantic: &[u8]) -> Vec<u8> {
    let mut p = OBJECT_DOMAIN.to_vec();
    p.extend_from_slice(&kind.to_le_bytes());
    p.extend_from_slice(&version.to_le_bytes());
    p.extend_from_slice(&(semantic.len() as u64).to_le_bytes());
    p.extend_from_slice(semantic);
    p
}

struct Graph {
    empty_catalog: Vec<u8>,
    empty_catalog_id: ObjectId,
    one_entry: CatalogEntry,
    one_catalog: Vec<u8>,
    one_catalog_id: ObjectId,
    app_semantic: Vec<u8>,
    app_id: ObjectId,
    genesis_commit: CommitRecord,
    gen2_commit: CommitRecord,
}

fn graph() -> Graph {
    let empty_catalog = Catalog { entries: vec![] }.encode().unwrap();
    let empty_catalog_id = id(1, 1, &empty_catalog);
    let app_semantic: Vec<u8> = (0u8..16).collect();
    let app_id = id(3, 1, &app_semantic);
    let one_entry = CatalogEntry {
        object_id: app_id,
        kind: 3,
        version: 1,
        first_unit: 4,
        byte_length: 16,
        unit_count: 1,
        flags: 0,
    };
    let one_catalog = Catalog {
        entries: vec![one_entry],
    }
    .encode()
    .unwrap();
    let one_catalog_id = id(1, 1, &one_catalog);
    let genesis_commit = CommitRecord {
        store_uuid: UUID,
        region_units: 16,
        generation: 1,
        previous_generation: 0,
        previous_commit_id: ObjectId([0; 32]),
        previous_catalog_id: ObjectId([0; 32]),
        catalog_id: empty_catalog_id,
        catalog_first_unit: 2,
        catalog_byte_length: empty_catalog.len() as u64,
        catalog_unit_count: 1,
        catalog_entry_count: 0,
        committed_high_water: 4,
    };
    let gen2_commit = CommitRecord {
        store_uuid: UUID,
        region_units: 16,
        generation: 2,
        previous_generation: 1,
        previous_commit_id: genesis_commit.object_id().unwrap(),
        previous_catalog_id: empty_catalog_id,
        catalog_id: one_catalog_id,
        catalog_first_unit: 5,
        catalog_byte_length: one_catalog.len() as u64,
        catalog_unit_count: 1,
        catalog_entry_count: 1,
        committed_high_water: 7,
    };
    Graph {
        empty_catalog,
        empty_catalog_id,
        one_entry,
        one_catalog,
        one_catalog_id,
        app_semantic,
        app_id,
        genesis_commit,
        gen2_commit,
    }
}

fn superblock(slot: u32, commit: &CommitRecord, commit_unit: u64) -> Superblock {
    Superblock {
        store_uuid: commit.store_uuid,
        slot_id: slot,
        region_units: commit.region_units,
        generation: commit.generation,
        commit_record_id: commit.object_id().unwrap(),
        commit_record_unit: commit_unit,
        catalog_id: commit.catalog_id,
        catalog_first_unit: commit.catalog_first_unit,
        catalog_byte_length: commit.catalog_byte_length,
        catalog_unit_count: commit.catalog_unit_count,
        catalog_entry_count: commit.catalog_entry_count,
        committed_high_water: commit.committed_high_water,
    }
}

/// Encode a superblock, prove it round-trips and that its stored CRC is the
/// kernel CRC32C of the unit with the CRC field zeroed.
fn encode_superblock(sb: &Superblock) -> Vec<u8> {
    let bytes = sb.encode().unwrap().to_vec();
    assert_eq!(Superblock::decode(&bytes, sb.slot_id).unwrap(), *sb);
    assert!(
        Superblock::decode(&bytes, 1 - sb.slot_id).is_err(),
        "slot id is bound into the superblock"
    );
    let mut zeroed = bytes.clone();
    zeroed[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4].fill(0);
    let stored = u32::from_le_bytes(
        bytes[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    assert_eq!(crc32c(&zeroed), stored, "superblock CRC domain");
    bytes
}

fn crc_field(bytes: &[u8]) -> &[u8] {
    &bytes[SUPERBLOCK_CRC_OFFSET..SUPERBLOCK_CRC_OFFSET + 4]
}

#[test]
fn top_level_is_the_frozen_schema() {
    let v = vectors();
    assert_eq!(v["schema"], "AIENOS-STORE-V1-GOLDEN-VECTORS-1");
    assert_eq!(v["source_contract"], "ADR 0015, format layout tables");
    let keys: BTreeSet<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = [
        "schema",
        "source_contract",
        "object_id",
        "empty_catalog",
        "one_entry_catalog",
        "crc32c",
        "genesis",
        "adjacent_generations",
        "equivalent_roots",
    ]
    .into_iter()
    .collect();
    assert_eq!(keys, expected, "top-level sections");
}

#[test]
fn object_id() {
    let v = vectors();
    let s = Section::new(&v, "object_id");
    let (kind, version) = (0x1234u16, 0x5678u16);
    let semantic: Vec<u8> = (0u8..16).collect();
    let oid = id(kind, version, &semantic);
    let pre = preimage(kind, version, &semantic);

    s.bytes("kind_u16le", &kind.to_le_bytes());
    s.bytes("version_u16le", &version.to_le_bytes());
    s.bytes("semantic_bytes_hex", &semantic);
    s.bytes("preimage_hex", &pre);
    s.bytes("object_id_hex", &oid.0);
    s.digest("preimage_sha256", &pre);
    s.digest("semantic_sha256", &semantic);
    assert_eq!(sha256(&pre), oid.0, "ObjectId is SHA-256 of the preimage");
    s.finish();
}

#[test]
fn empty_catalog() {
    let v = vectors();
    let g = graph();
    let s = Section::new(&v, "empty_catalog");
    assert_eq!(g.empty_catalog.len(), CATALOG_HEADER_BYTES);
    s.bytes("semantic_bytes_hex", &g.empty_catalog);
    s.bytes("object_id_hex", &g.empty_catalog_id.0);
    s.bytes("unit_hex", &unit(&g.empty_catalog));
    s.digest("unit_sha256", &unit(&g.empty_catalog));
    s.digest("semantic_sha256", &g.empty_catalog);
    assert!(Catalog::decode(&g.empty_catalog)
        .unwrap()
        .entries
        .is_empty());
    s.finish();
}

#[test]
fn one_entry_catalog() {
    let v = vectors();
    let g = graph();
    let s = Section::new(&v, "one_entry_catalog");
    let entry = g.one_entry.encode().unwrap();
    assert_eq!(g.one_catalog.len(), 80);
    assert_eq!(&g.one_catalog[CATALOG_HEADER_BYTES..], &entry[..]);

    s.bytes("entry_object_id_hex", &entry[0..32]);
    s.bytes("entry_kind_u16le", &entry[32..34]);
    s.bytes("entry_version_u16le", &entry[34..36]);
    s.bytes("entry_first_unit_u64le", &entry[36..44]);
    s.bytes("entry_byte_length_u64le", &entry[44..52]);
    s.bytes("entry_unit_count_u32le", &entry[52..56]);
    s.bytes("entry_flags_u16le", &entry[56..58]);
    s.bytes("entry_reserved_hex", &entry[58..64]);
    assert_eq!(&entry[0..32], &g.app_id.0);
    s.bytes("semantic_bytes_hex", &g.one_catalog);
    s.bytes("object_id_hex", &g.one_catalog_id.0);
    s.bytes("unit_hex", &unit(&g.one_catalog));
    s.digest("unit_sha256", &unit(&g.one_catalog));
    s.digest("semantic_sha256", &g.one_catalog);

    assert_eq!(CatalogEntry::decode(&entry).unwrap(), g.one_entry);
    assert_eq!(
        Catalog::decode(&g.one_catalog).unwrap().entries,
        vec![g.one_entry]
    );
    s.finish();
}

#[test]
fn crc32c_check_value() {
    let v = vectors();
    let s = Section::new(&v, "crc32c");
    let input = s.str("check_input_ascii");
    assert_eq!(input, "123456789");
    let crc = crc32c(input.as_bytes());
    let numeric = s.str("check_output_numeric");
    let parsed = u32::from_str_radix(numeric.trim_start_matches("0x"), 16).unwrap();
    assert_eq!(crc, parsed, "check_output_numeric");
    assert_eq!(crc, 0xe306_9283);
    s.bytes("check_output_u32le", &crc.to_le_bytes());
    assert_eq!(
        s.str("algorithm"),
        "reflected Castagnoli polynomial 0x82f63b78, init/xorout 0xffffffff"
    );
    s.finish();
}

#[test]
fn genesis() {
    let v = vectors();
    let g = graph();
    let s = Section::new(&v, "genesis");
    let c = &g.genesis_commit;

    s.bytes("store_uuid_hex", &UUID);
    s.bytes("region_units_u64le", &c.region_units.to_le_bytes());
    assert_eq!(s.u64("catalog_first_unit"), c.catalog_first_unit);
    assert_eq!(s.u64("commit_record_unit_number"), 3);
    let map = s.raw("unit_map");
    for (unit_no, what) in [
        ("0", "superblock A"),
        ("1", "superblock B"),
        ("2", "genesis catalog"),
        ("3", "genesis CommitRecord"),
    ] {
        assert_eq!(map[unit_no], what, "genesis.unit_map[{unit_no}]");
    }
    assert_eq!(map.as_object().unwrap().len(), 4);

    s.bytes("catalog_semantic_hex", &g.empty_catalog);
    s.bytes("catalog_unit_hex", &unit(&g.empty_catalog));
    s.bytes("catalog_object_id_hex", &g.empty_catalog_id.0);

    let sem = c.encode().unwrap();
    let cid = c.object_id().unwrap();
    let pre = preimage(2, 1, &sem);
    s.bytes("commit_record_semantic_hex", &sem);
    s.bytes("commit_record_object_id_hex", &cid.0);
    s.bytes("commit_record_unit_hex", &unit(&sem));
    s.digest("commit_record_unit_sha256", &unit(&sem));
    s.bytes("commit_record_crc_domain_preimage_hex", &pre);
    assert_eq!(
        sha256(&pre),
        cid.0,
        "CommitRecord id is SHA-256 of preimage"
    );
    assert_eq!(CommitRecord::decode(&sem).unwrap(), *c);

    let a = encode_superblock(&superblock(0, c, 3));
    let b = encode_superblock(&superblock(1, c, 3));
    s.bytes("superblock_a_unit_hex", &a);
    s.digest("superblock_a_unit_sha256", &a);
    s.bytes("superblock_a_crc_u32le", crc_field(&a));
    s.bytes("superblock_b_unit_hex", &b);
    s.digest("superblock_b_unit_sha256", &b);
    s.bytes("superblock_b_crc_u32le", crc_field(&b));
    assert_ne!(a, b);
    assert_ne!(crc_field(&a), crc_field(&b));

    assert_eq!(
        s.str("expected_root_classification"),
        "redundant valid copies; equivalent logical roots"
    );
    let (da, db) = (
        Superblock::decode(&a, 0).unwrap(),
        Superblock::decode(&b, 1).unwrap(),
    );
    assert!(da.equivalent_root(&db), "genesis A/B are equivalent roots");
    da.validate_commit(cid, c)
        .expect("superblock A binds genesis commit");
    db.validate_commit(cid, c)
        .expect("superblock B binds genesis commit");
    s.finish();
}

#[test]
fn adjacent_generations() {
    let v = vectors();
    let g = graph();
    let s = Section::new(&v, "adjacent_generations");
    let g1 = &g.genesis_commit;
    let g2 = &g.gen2_commit;
    let g1_id = g1.object_id().unwrap();

    s.bytes("generation_1_commit_record_object_id_hex", &g1_id.0);
    s.bytes("generation_1_catalog_object_id_hex", &g.empty_catalog_id.0);
    assert_eq!(
        s.u64("generation_1_committed_high_water"),
        g1.committed_high_water
    );
    let map = s.raw("unit_map");
    for (unit_no, what) in [
        ("0", "generation 2 superblock A"),
        ("1", "generation 1 superblock B"),
        ("2", "generation 1 catalog"),
        ("3", "generation 1 CommitRecord"),
        ("4", "generation 2 application object"),
        ("5", "generation 2 catalog"),
        ("6", "generation 2 CommitRecord"),
    ] {
        assert_eq!(
            map[unit_no], what,
            "adjacent_generations.unit_map[{unit_no}]"
        );
    }
    assert_eq!(map.as_object().unwrap().len(), 7);

    s.bytes("application_object_semantic_hex", &g.app_semantic);
    s.bytes("application_object_id_hex", &g.app_id.0);
    s.bytes("application_object_unit_hex", &unit(&g.app_semantic));
    s.digest("application_object_unit_sha256", &unit(&g.app_semantic));

    s.bytes("generation_2_catalog_semantic_hex", &g.one_catalog);
    s.bytes("generation_2_catalog_object_id_hex", &g.one_catalog_id.0);
    s.bytes("generation_2_catalog_unit_hex", &unit(&g.one_catalog));
    s.digest("generation_2_catalog_unit_sha256", &unit(&g.one_catalog));

    let sem = g2.encode().unwrap();
    let g2_id = g2.object_id().unwrap();
    let pre = preimage(2, 1, &sem);
    s.bytes("generation_2_commit_record_semantic_hex", &sem);
    s.bytes("generation_2_commit_record_object_id_hex", &g2_id.0);
    s.bytes("generation_2_commit_record_unit_hex", &unit(&sem));
    s.digest("generation_2_commit_record_unit_sha256", &unit(&sem));
    s.bytes("generation_2_commit_record_preimage_hex", &pre);
    assert_eq!(sha256(&pre), g2_id.0);
    assert_eq!(CommitRecord::decode(&sem).unwrap(), *g2);

    let sb_value = superblock(0, g2, 6);
    sb_value
        .validate_commit(g2_id, g2)
        .expect("generation 2 superblock binds its commit");
    let sb = encode_superblock(&sb_value);
    s.bytes("generation_2_superblock_a_unit_hex", &sb);
    s.digest("generation_2_superblock_a_unit_sha256", &sb);
    s.bytes("generation_2_superblock_a_crc_u32le", crc_field(&sb));
    assert_eq!(
        s.u64("generation_2_committed_high_water"),
        g2.committed_high_water
    );

    assert_eq!(
        s.str("expected_root_classification"),
        "normal adjacent history; generation 2 follows generation 1 exactly"
    );
    assert!(g2.identifies_predecessor(g1, g1_id));
    assert_eq!(&sem[72..104], &g1_id.0, "previous_commit_id links genesis");
    assert_eq!(&sem[104..136], &g.empty_catalog_id.0);
    s.finish();
}

#[test]
fn equivalent_roots() {
    let v = vectors();
    let g = graph();
    let s = Section::new(&v, "equivalent_roots");
    let a_sb = superblock(0, &g.genesis_commit, 3);
    let b_sb = superblock(1, &g.genesis_commit, 3);
    let a = encode_superblock(&a_sb);
    let b = encode_superblock(&b_sb);

    s.bytes("superblock_a_unit_hex", &a);
    s.digest("superblock_a_unit_sha256", &a);
    s.bytes("superblock_b_unit_hex", &b);
    s.digest("superblock_b_unit_sha256", &b);
    s.bytes("superblock_a_crc_u32le", crc_field(&a));
    s.bytes("superblock_b_crc_u32le", crc_field(&b));
    assert_eq!(
        s.str("expected_root_classification"),
        "same generation and equivalent logical root; redundant valid copies"
    );
    assert!(a_sb.equivalent_root(&b_sb));
    assert_ne!(a, b, "slot id and CRC differ between redundant copies");
    s.finish();
}
