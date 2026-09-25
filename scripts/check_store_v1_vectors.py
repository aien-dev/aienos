import hashlib, json, struct
from pathlib import Path

UNIT = 4096
UUID = bytes(range(16))


def oid(kind, version, semantic):
    preimage = b"AIENOS-STORE-OBJECT-V1\0" + struct.pack("<HHQ", kind, version, len(semantic)) + semantic
    return hashlib.sha256(preimage).digest(), preimage


def crc32c(data):
    crc = 0xffffffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def catalog(entries):
    out = bytearray(b"AIENCAT1" + struct.pack("<HHI", 1, 64, len(entries)))
    for obj_id, kind, version, first_unit, payload in entries:
        unit_count = (len(payload) + UNIT - 1) // UNIT
        out += obj_id
        out += struct.pack("<HHQQIH", kind, version, first_unit, len(payload), unit_count, 0)
        out += bytes(6)
    return bytes(out)


def record(*, generation, previous_generation, previous_commit_id, previous_catalog_id,
           catalog_id, catalog_first_unit, catalog_bytes, entry_count, commit_unit):
    semantic = bytearray(200)
    semantic[0:8] = b"AIENCMT1"
    struct.pack_into("<HHHHQQ", semantic, 8, 1, 200, 1, 0, 0, 0)
    semantic[32:48] = UUID
    struct.pack_into("<QQQ", semantic, 48, 16, generation, previous_generation)
    semantic[72:104] = previous_commit_id
    semantic[104:136] = previous_catalog_id
    semantic[136:168] = catalog_id
    catalog_units = (len(catalog_bytes) + UNIT - 1) // UNIT
    struct.pack_into("<QQIIQ", semantic, 168, catalog_first_unit, len(catalog_bytes),
                     catalog_units, entry_count, commit_unit + 1)
    record_id, preimage = oid(2, 1, bytes(semantic))
    unit = bytes(semantic) + bytes(UNIT - len(semantic))
    return bytes(semantic), unit, record_id, preimage


def superblock(*, slot, generation, commit_id, commit_unit, catalog_id,
               catalog_first_unit, catalog_bytes, entry_count, high_water):
    out = bytearray(UNIT)
    out[0:8] = b"AIENSTR1"
    struct.pack_into("<HHQQ", out, 8, 1, 0, 0, 0)
    out[28:44] = UUID
    struct.pack_into("<IQQ", out, 44, slot, 16, generation)
    out[64:96] = commit_id
    struct.pack_into("<Q", out, 96, commit_unit)
    out[104:136] = catalog_id
    units = (len(catalog_bytes) + UNIT - 1) // UNIT
    struct.pack_into("<QQIIQ", out, 136, catalog_first_unit, len(catalog_bytes), units,
                     entry_count, high_water)
    # CRC field bytes 168:172 remain zero while calculating.
    checksum = crc32c(out)
    struct.pack_into("<I", out, 168, checksum)
    return bytes(out), checksum


def unit(payload):
    assert 0 < len(payload) <= UNIT
    return payload + bytes(UNIT - len(payload))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def h(data):
    return data.hex()


# Canonical standalone ObjectId example and common CRC check.
object_semantic = bytes(range(16))
object_id, object_preimage = oid(0x1234, 0x5678, object_semantic)
empty_catalog_bytes = catalog([])
empty_catalog_id, empty_catalog_preimage = oid(1, 1, empty_catalog_bytes)

# Genesis: empty application catalog at unit 2, CommitRecord at unit 3.
genesis_commit_sem, genesis_commit_unit, genesis_commit_id, genesis_commit_preimage = record(
    generation=1, previous_generation=0, previous_commit_id=bytes(32),
    previous_catalog_id=bytes(32), catalog_id=empty_catalog_id,
    catalog_first_unit=2, catalog_bytes=empty_catalog_bytes, entry_count=0,
    commit_unit=3)
genesis_sb_a, genesis_crc_a = superblock(slot=0, generation=1,
    commit_id=genesis_commit_id, commit_unit=3, catalog_id=empty_catalog_id,
    catalog_first_unit=2, catalog_bytes=empty_catalog_bytes, entry_count=0,
    high_water=4)
genesis_sb_b, genesis_crc_b = superblock(slot=1, generation=1,
    commit_id=genesis_commit_id, commit_unit=3, catalog_id=empty_catalog_id,
    catalog_first_unit=2, catalog_bytes=empty_catalog_bytes, entry_count=0,
    high_water=4)

# Adjacent generation: add one 16-byte application object at unit 4, full catalog at 5,
# CommitRecord at 6; the previous CommitRecord/catalog IDs link to genesis exactly.
app_semantic = bytes(range(16))
app_id, app_preimage = oid(3, 1, app_semantic)
one_catalog_bytes = catalog([(app_id, 3, 1, 4, app_semantic)])
one_catalog_id, one_catalog_preimage = oid(1, 1, one_catalog_bytes)
gen2_commit_sem, gen2_commit_unit, gen2_commit_id, gen2_commit_preimage = record(
    generation=2, previous_generation=1, previous_commit_id=genesis_commit_id,
    previous_catalog_id=empty_catalog_id, catalog_id=one_catalog_id,
    catalog_first_unit=5, catalog_bytes=one_catalog_bytes, entry_count=1,
    commit_unit=6)
gen2_sb_a, gen2_crc_a = superblock(slot=0, generation=2,
    commit_id=gen2_commit_id, commit_unit=6, catalog_id=one_catalog_id,
    catalog_first_unit=5, catalog_bytes=one_catalog_bytes, entry_count=1,
    high_water=7)

# Single-root vectors (full 4096-byte units) and classification labels are fixed here.
blob = {
  "schema": "AIENOS-STORE-V1-GOLDEN-VECTORS-1",
  "source_contract": "ADR 0015, format layout tables",
  "object_id": {
    "kind_u16le": "3412", "version_u16le": "7856",
    "semantic_bytes_hex": h(object_semantic), "preimage_hex": h(object_preimage),
    "object_id_hex": h(object_id), "preimage_sha256": digest(object_preimage),
    "semantic_sha256": digest(object_semantic)
  },
  "empty_catalog": {
    "semantic_bytes_hex": h(empty_catalog_bytes), "object_id_hex": h(empty_catalog_id),
    "unit_hex": h(unit(empty_catalog_bytes)), "unit_sha256": digest(unit(empty_catalog_bytes)),
    "semantic_sha256": digest(empty_catalog_bytes)
  },
  "one_entry_catalog": {
    "entry_object_id_hex": h(app_id), "entry_kind_u16le": "0300",
    "entry_version_u16le": "0100", "entry_first_unit_u64le": "0400000000000000",
    "entry_byte_length_u64le": "1000000000000000", "entry_unit_count_u32le": "01000000",
    "entry_flags_u16le": "0000", "entry_reserved_hex": "000000000000",
    "semantic_bytes_hex": h(one_catalog_bytes), "object_id_hex": h(one_catalog_id),
    "unit_hex": h(unit(one_catalog_bytes)), "unit_sha256": digest(unit(one_catalog_bytes)),
    "semantic_sha256": digest(one_catalog_bytes)
  },
  "crc32c": {
    "check_input_ascii": "123456789", "check_output_numeric": "0xe3069283",
    "check_output_u32le": "839206e3",
    "algorithm": "reflected Castagnoli polynomial 0x82f63b78, init/xorout 0xffffffff"
  },
  "genesis": {
    "store_uuid_hex": h(UUID), "region_units_u64le": "1000000000000000",
    "catalog_first_unit": 2, "commit_record_unit_number": 3,
    "unit_map": {"0": "superblock A", "1": "superblock B", "2": "genesis catalog", "3": "genesis CommitRecord"},
    "catalog_semantic_hex": h(empty_catalog_bytes),
    "catalog_unit_hex": h(unit(empty_catalog_bytes)), "catalog_object_id_hex": h(empty_catalog_id),
    "commit_record_semantic_hex": h(genesis_commit_sem),
    "commit_record_object_id_hex": h(genesis_commit_id),
    "commit_record_unit_hex": h(genesis_commit_unit),
    "commit_record_unit_sha256": digest(genesis_commit_unit),
    "commit_record_crc_domain_preimage_hex": h(genesis_commit_preimage),
    "superblock_a_unit_hex": h(genesis_sb_a), "superblock_a_unit_sha256": digest(genesis_sb_a),
    "superblock_a_crc_u32le": struct.pack("<I", genesis_crc_a).hex(),
    "superblock_b_unit_hex": h(genesis_sb_b), "superblock_b_unit_sha256": digest(genesis_sb_b),
    "superblock_b_crc_u32le": struct.pack("<I", genesis_crc_b).hex(),
    "expected_root_classification": "redundant valid copies; equivalent logical roots"
  },
  "adjacent_generations": {
    "generation_1_commit_record_object_id_hex": h(genesis_commit_id),
    "generation_1_catalog_object_id_hex": h(empty_catalog_id),
    "generation_1_committed_high_water": 4,
    "unit_map": {"0": "generation 2 superblock A", "1": "generation 1 superblock B",
      "2": "generation 1 catalog", "3": "generation 1 CommitRecord",
      "4": "generation 2 application object", "5": "generation 2 catalog",
      "6": "generation 2 CommitRecord"},
    "application_object_semantic_hex": h(app_semantic), "application_object_id_hex": h(app_id),
    "application_object_unit_hex": h(unit(app_semantic)),
    "application_object_unit_sha256": digest(unit(app_semantic)),
    "generation_2_catalog_semantic_hex": h(one_catalog_bytes),
    "generation_2_catalog_object_id_hex": h(one_catalog_id),
    "generation_2_catalog_unit_hex": h(unit(one_catalog_bytes)),
    "generation_2_catalog_unit_sha256": digest(unit(one_catalog_bytes)),
    "generation_2_commit_record_semantic_hex": h(gen2_commit_sem),
    "generation_2_commit_record_object_id_hex": h(gen2_commit_id),
    "generation_2_commit_record_unit_hex": h(gen2_commit_unit),
    "generation_2_commit_record_unit_sha256": digest(gen2_commit_unit),
    "generation_2_commit_record_preimage_hex": h(gen2_commit_preimage),
    "generation_2_superblock_a_unit_hex": h(gen2_sb_a),
    "generation_2_superblock_a_unit_sha256": digest(gen2_sb_a),
    "generation_2_superblock_a_crc_u32le": struct.pack("<I", gen2_crc_a).hex(),
    "generation_2_committed_high_water": 7,
    "expected_root_classification": "normal adjacent history; generation 2 follows generation 1 exactly"
  },
  "equivalent_roots": {
    "superblock_a_unit_hex": h(genesis_sb_a), "superblock_a_unit_sha256": digest(genesis_sb_a),
    "superblock_b_unit_hex": h(genesis_sb_b), "superblock_b_unit_sha256": digest(genesis_sb_b),
    "superblock_a_crc_u32le": struct.pack("<I", genesis_crc_a).hex(),
    "superblock_b_crc_u32le": struct.pack("<I", genesis_crc_b).hex(),
    "expected_root_classification": "same generation and equivalent logical root; redundant valid copies"
  }
}

# Guard construction against accidental layout drift and document-independent error.
assert len(empty_catalog_bytes) == 16
assert len(one_catalog_bytes) == 80
assert len(genesis_commit_sem) == len(gen2_commit_sem) == 200
assert len(genesis_commit_unit) == len(gen2_commit_unit) == UNIT
assert len(genesis_sb_a) == len(genesis_sb_b) == len(gen2_sb_a) == UNIT
assert genesis_sb_a != genesis_sb_b and genesis_sb_a[:168] != genesis_sb_b[:168]
assert genesis_crc_a != genesis_crc_b
assert genesis_commit_sem[56:64] == struct.pack("<Q", 1)
assert gen2_commit_sem[56:64] == struct.pack("<Q", 2)
assert gen2_commit_sem[64:72] == struct.pack("<Q", 1)
assert gen2_commit_sem[72:104] == genesis_commit_id
assert gen2_commit_sem[104:136] == empty_catalog_id
assert gen2_commit_sem[192:200] == struct.pack("<Q", 7)
assert crc32c(b"123456789") == 0xe3069283

root = Path(__file__).resolve().parents[1]
out = root / 'docs/adr/0015-golden-vectors.json'
expected = json.dumps(blob, indent=2) + "\n"
actual = out.read_text()
assert actual == expected, f"golden vector manifest differs: {out}"

# The fixture graph uses a fixed test UUID; the random provisioning requirement
# applies to real provisioning, not to reproducible vectors.
def root_identity(sb):
    return (sb[28:44], sb[8:28], sb[56:64], sb[64:96])

assert root_identity(genesis_sb_a) == root_identity(genesis_sb_b)
assert genesis_sb_a[44:48] == struct.pack('<I', 0)
assert genesis_sb_b[44:48] == struct.pack('<I', 1)
assert genesis_sb_a[96:104] == genesis_sb_b[96:104] == struct.pack('<Q', 3)
assert crc32c(genesis_sb_a[:168] + bytes(4) + genesis_sb_a[172:]) == genesis_crc_a
assert crc32c(genesis_sb_b[:168] + bytes(4) + genesis_sb_b[172:]) == genesis_crc_b
assert crc32c(gen2_sb_a[:168] + bytes(4) + gen2_sb_a[172:]) == gen2_crc_a
assert gen2_commit_sem[56:64] == struct.pack('<Q', 2)
assert gen2_commit_sem[64:72] == struct.pack('<Q', 1)
assert gen2_commit_sem[72:104] == genesis_commit_id
assert gen2_commit_sem[104:136] == empty_catalog_id
assert gen2_commit_sem[192:200] == struct.pack('<Q', 7)
assert gen2_sb_a[56:64] == struct.pack('<Q', 2)
assert gen2_sb_a[96:104] == struct.pack('<Q', 6)
assert gen2_sb_a[160:168] == struct.pack('<Q', 7)
assert genesis_commit_sem[192:200] == struct.pack('<Q', 4)
assert genesis_sb_a[96:104] == struct.pack('<Q', 3)
assert root_identity(genesis_sb_a)[2] == root_identity(genesis_sb_b)[2]
assert struct.unpack_from('<Q', gen2_commit_sem, 56)[0] == struct.unpack_from('<Q', genesis_commit_sem, 56)[0] + 1

print(f'PASS: {out.relative_to(root)} ({out.stat().st_size} bytes)')
print('PASS: ObjectId, catalogs, CommitRecord, superblocks, CRC32C, genesis, adjacency, equivalent roots')
for k, v in [('object_id', object_id), ('empty_catalog', empty_catalog_id),
             ('one_entry_catalog', one_catalog_id), ('genesis_commit', genesis_commit_id),
             ('generation_2_commit', gen2_commit_id)]:
    print(k, v.hex())
