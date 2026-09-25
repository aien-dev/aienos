#!/usr/bin/env python3
"""
Unit tests for the host-side read-only Store inspector and verification oracle.
"""

import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from inspector import (
    CATALOG_ENTRY_BYTES,
    CATALOG_HEADER_BYTES,
    CATALOG_MAGIC,
    COMMIT_BYTES,
    COMMIT_MAGIC,
    KIND_CATALOG,
    KIND_COMMIT,
    STORE_UNIT_BYTES,
    SUPERBLOCK_CRC_OFFSET,
    SUPERBLOCK_MAGIC,
    StoreInspector,
    calculate_crc32c,
    calculate_entropy,
    calculate_object_id,
)


def create_mock_object(kind: int, version: int, payload: bytes) -> tuple[bytes, str]:
    """Helper to return payload and canonical hex ObjectId."""
    obj_id = calculate_object_id(kind, version, payload).hex()
    return payload, obj_id


def create_mock_catalog_entry(
    object_id_bytes: bytes,
    kind: int,
    version: int,
    first_unit: int,
    byte_length: int,
) -> bytes:
    """Encode 64-byte Catalog ObjectDescriptor."""
    unit_count = (byte_length + STORE_UNIT_BYTES - 1) // STORE_UNIT_BYTES
    flags = 0
    reserved = b"\x00" * 6
    return (
        object_id_bytes
        + struct.pack("<HHQQIH", kind, version, first_unit, byte_length, unit_count, flags)
        + reserved
    )


def create_mock_catalog(
    entries_data: list[tuple[bytes, int, int, int, int]], sort_entries: bool = True
) -> tuple[bytes, str]:
    """
    Encode Catalog (header + entries) and calculate its ObjectId.
    entries_data: list of (obj_id_bytes, kind, version, first_unit, byte_length)
    """
    if sort_entries:
        sorted_entries = sorted(entries_data, key=lambda x: x[0])
    else:
        sorted_entries = entries_data
    entry_count = len(sorted_entries)
    header = struct.pack("<8sHHI", CATALOG_MAGIC, 1, CATALOG_ENTRY_BYTES, entry_count)
    body = bytearray(header)
    for obj_id, kind, ver, funit, blen in sorted_entries:
        body.extend(create_mock_catalog_entry(obj_id, kind, ver, funit, blen))
    cat_bytes = bytes(body)
    cat_id = calculate_object_id(KIND_CATALOG, 1, cat_bytes).hex()
    return cat_bytes, cat_id


def create_mock_commit(
    store_uuid: bytes,
    region_units: int,
    generation: int,
    previous_generation: int,
    previous_commit_id: bytes,
    previous_catalog_id: bytes,
    catalog_id: bytes,
    catalog_first_unit: int,
    catalog_byte_length: int,
    catalog_entry_count: int,
    committed_high_water_unit: int,
    published_manifest_id: bytes = b"\x00" * 32,
) -> tuple[bytes, str]:
    """Encode 232-byte CommitRecord and calculate its ObjectId."""
    catalog_unit_count = (catalog_byte_length + STORE_UNIT_BYTES - 1) // STORE_UNIT_BYTES
    data = bytearray(COMMIT_BYTES)
    data[0:8] = COMMIT_MAGIC
    struct.pack_into("<HH", data, 8, 1, COMMIT_BYTES)  # version=1, len=232
    struct.pack_into("<HH", data, 12, 1, 0)  # format_major=1, format_minor=0
    struct.pack_into("<QQ", data, 16, 0, 0)  # req, comp features
    data[32:48] = store_uuid
    struct.pack_into("<QQQ", data, 48, region_units, generation, previous_generation)
    data[72:104] = previous_commit_id
    data[104:136] = previous_catalog_id
    data[136:168] = catalog_id
    struct.pack_into("<QQIIQ", data, 168, catalog_first_unit, catalog_byte_length, catalog_unit_count, catalog_entry_count, committed_high_water_unit)
    data[200:232] = published_manifest_id
    commit_bytes = bytes(data)
    commit_id = calculate_object_id(KIND_COMMIT, 1, commit_bytes).hex()
    return commit_bytes, commit_id


def create_mock_superblock(
    slot: int,
    store_uuid: bytes,
    region_units: int,
    generation: int,
    commit_record_id: bytes,
    commit_record_unit: int,
    catalog_id: bytes,
    catalog_first_unit: int,
    catalog_byte_length: int,
    catalog_entry_count: int,
    committed_high_water_unit: int,
) -> bytes:
    """Encode 4096-byte Superblock with valid CRC32C."""
    catalog_unit_count = (catalog_byte_length + STORE_UNIT_BYTES - 1) // STORE_UNIT_BYTES
    sb = bytearray(STORE_UNIT_BYTES)
    sb[0:8] = SUPERBLOCK_MAGIC
    struct.pack_into("<HH", sb, 8, 1, 0)  # format_major=1, format_minor=0
    struct.pack_into("<QQ", sb, 12, 0, 0)  # req, comp features
    sb[28:44] = store_uuid
    struct.pack_into("<I", sb, 44, slot)
    struct.pack_into("<QQ", sb, 48, region_units, generation)
    sb[64:96] = commit_record_id
    struct.pack_into("<Q", sb, 96, commit_record_unit)
    sb[104:136] = catalog_id
    struct.pack_into("<QQIIQ", sb, 136, catalog_first_unit, catalog_byte_length, catalog_unit_count, catalog_entry_count, committed_high_water_unit)
    # bytes 168..172 remain 0 for CRC calculation
    crc = calculate_crc32c(bytes(sb))
    struct.pack_into("<I", sb, SUPERBLOCK_CRC_OFFSET, crc)
    return bytes(sb)


class TestStoreInspector(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_crc32c_standard_vectors(self):
        """Verify CRC32-C (Castagnoli) known test vectors."""
        self.assertEqual(calculate_crc32c(b""), 0)
        self.assertEqual(calculate_crc32c(b"123456789"), 0xE3069283)
        self.assertEqual(calculate_crc32c(b"\x00" * 32), 0x8A9136AA)

    def test_entropy_calculation(self):
        """Test Shannon entropy calculation on known distributions."""
        all_zeros = b"\x00" * 4096
        self.assertEqual(calculate_entropy(all_zeros), 0.0)

        # High entropy: all byte values equally distributed
        uniform_bytes = bytes(range(256)) * 16  # 4096 bytes
        self.assertAlmostEqual(calculate_entropy(uniform_bytes), 8.0, places=3)

        # Half zeros, half ones
        half_and_half = (b"\x00" * 2048) + (b"\x01" * 2048)
        self.assertAlmostEqual(calculate_entropy(half_and_half), 1.0, places=3)

    def test_unformatted_blank_image(self):
        """A freshly zeroed image should report UNFORMATTED and unrecoverable."""
        img_path = self.temp_path / "blank.img"
        img_size = STORE_UNIT_BYTES * 8
        img_path.write_bytes(b"\x00" * img_size)

        inspector = StoreInspector(img_path)
        report = inspector.full_inspection(include_block_table=True, non_zero_only=False)

        self.assertFalse(report["verdict"]["is_recoverable"])
        self.assertEqual(report["verdict"]["recovery_status"], "UNRECOVERABLE")
        self.assertEqual(report["store_v1"]["slot_a"]["status"], "UNFORMATTED")
        self.assertEqual(report["store_v1"]["slot_b"]["status"], "UNFORMATTED")
        self.assertEqual(report["block_analysis"]["stats"]["zero_units_count"], 8)
        self.assertEqual(report["block_analysis"]["stats"]["non_zero_units_count"], 0)

    def test_foreign_or_random_image(self):
        """An image filled with pseudorandom data should report BAD_MAGIC and unrecoverable."""
        img_path = self.temp_path / "noise.img"
        # Deterministic noise
        noise = bytearray()
        for i in range(STORE_UNIT_BYTES * 6):
            noise.append((i * 37 + 13) % 256)
        img_path.write_bytes(bytes(noise))

        inspector = StoreInspector(img_path)
        report = inspector.full_inspection()

        self.assertFalse(report["verdict"]["is_recoverable"])
        self.assertEqual(report["verdict"]["recovery_status"], "UNRECOVERABLE")
        self.assertEqual(report["store_v1"]["slot_a"]["status"], "BAD_MAGIC")
        self.assertEqual(report["store_v1"]["slot_b"]["status"], "BAD_MAGIC")
        self.assertGreater(report["block_analysis"]["stats"]["mean_entropy"], 7.0)

    def test_valid_store_v1_consistent_generation_1(self):
        """A fully valid Store v1 image where Slot A and Slot B match at Gen 1."""
        img_path = self.temp_path / "valid_store.img"
        total_units = 16
        image = bytearray(total_units * STORE_UNIT_BYTES)

        store_uuid = bytes.fromhex("112233445566778899aabbccddeeff00")

        # Object 1 at unit 4
        payload1 = b"TEST-OBJECT-PAYLOAD-001"
        obj1_id_bytes = calculate_object_id(10, 1, payload1)
        image[4 * STORE_UNIT_BYTES : 4 * STORE_UNIT_BYTES + len(payload1)] = payload1

        # Catalog at unit 3
        cat_entries = [(obj1_id_bytes, 10, 1, 4, len(payload1))]
        cat_bytes, cat_id_hex = create_mock_catalog(cat_entries)
        image[3 * STORE_UNIT_BYTES : 3 * STORE_UNIT_BYTES + len(cat_bytes)] = cat_bytes

        # CommitRecord at unit 2
        cmt_bytes, cmt_id_hex = create_mock_commit(
            store_uuid=store_uuid,
            region_units=total_units,
            generation=1,
            previous_generation=0,
            previous_commit_id=b"\x00" * 32,
            previous_catalog_id=b"\x00" * 32,
            catalog_id=bytes.fromhex(cat_id_hex),
            catalog_first_unit=3,
            catalog_byte_length=len(cat_bytes),
            catalog_entry_count=len(cat_entries),
            committed_high_water_unit=5,
        )
        image[2 * STORE_UNIT_BYTES : 2 * STORE_UNIT_BYTES + len(cmt_bytes)] = cmt_bytes

        # Superblock Slot 0 (A)
        sb0 = create_mock_superblock(
            slot=0,
            store_uuid=store_uuid,
            region_units=total_units,
            generation=1,
            commit_record_id=bytes.fromhex(cmt_id_hex),
            commit_record_unit=2,
            catalog_id=bytes.fromhex(cat_id_hex),
            catalog_first_unit=3,
            catalog_byte_length=len(cat_bytes),
            catalog_entry_count=len(cat_entries),
            committed_high_water_unit=5,
        )
        image[0 : STORE_UNIT_BYTES] = sb0

        # Superblock Slot 1 (B) - logically identical
        sb1 = create_mock_superblock(
            slot=1,
            store_uuid=store_uuid,
            region_units=total_units,
            generation=1,
            commit_record_id=bytes.fromhex(cmt_id_hex),
            commit_record_unit=2,
            catalog_id=bytes.fromhex(cat_id_hex),
            catalog_first_unit=3,
            catalog_byte_length=len(cat_bytes),
            catalog_entry_count=len(cat_entries),
            committed_high_water_unit=5,
        )
        image[STORE_UNIT_BYTES : 2 * STORE_UNIT_BYTES] = sb1

        img_path.write_bytes(bytes(image))

        inspector = StoreInspector(img_path)
        report = inspector.full_inspection(include_block_table=True)

        self.assertTrue(report["verdict"]["is_recoverable"])
        self.assertEqual(report["verdict"]["recovery_status"], "CONSISTENT")
        self.assertEqual(report["verdict"]["selected_generation"], 1)
        self.assertFalse(report["verdict"]["rollback_occurred"])
        self.assertEqual(report["store_v1"]["slot_a"]["status"], "VALID")
        self.assertEqual(report["store_v1"]["slot_b"]["status"], "VALID")
        self.assertEqual(report["store_v1"]["active_commit"]["calculated_id"], cmt_id_hex)
        self.assertEqual(report["store_v1"]["active_catalog"]["calculated_id"], cat_id_hex)
        self.assertEqual(len(report["store_v1"]["active_catalog"]["entries"]), 1)
        self.assertEqual(report["store_v1"]["active_catalog"]["entries"][0]["object_id"], obj1_id_bytes.hex())

    def test_forward_progress_selection(self):
        """Slot B (gen 2) > Slot A (gen 1), both valid on media -> selects Slot B."""
        img_path = self.temp_path / "forward_store.img"
        total_units = 16
        image = bytearray(total_units * STORE_UNIT_BYTES)
        store_uuid = bytes.fromhex("112233445566778899aabbccddeeff00")

        # Gen 1 at units 2 (commit) and 3 (catalog)
        cat1_entries = [(calculate_object_id(10, 1, b"GEN1"), 10, 1, 4, 4)]
        cat1_bytes, cat1_id = create_mock_catalog(cat1_entries)
        image[3 * STORE_UNIT_BYTES : 3 * STORE_UNIT_BYTES + len(cat1_bytes)] = cat1_bytes

        cmt1_bytes, cmt1_id = create_mock_commit(
            store_uuid=store_uuid,
            region_units=total_units,
            generation=1,
            previous_generation=0,
            previous_commit_id=b"\x00" * 32,
            previous_catalog_id=b"\x00" * 32,
            catalog_id=bytes.fromhex(cat1_id),
            catalog_first_unit=3,
            catalog_byte_length=len(cat1_bytes),
            catalog_entry_count=1,
            committed_high_water_unit=5,
        )
        image[2 * STORE_UNIT_BYTES : 2 * STORE_UNIT_BYTES + len(cmt1_bytes)] = cmt1_bytes

        sb0 = create_mock_superblock(
            slot=0,
            store_uuid=store_uuid,
            region_units=total_units,
            generation=1,
            commit_record_id=bytes.fromhex(cmt1_id),
            commit_record_unit=2,
            catalog_id=bytes.fromhex(cat1_id),
            catalog_first_unit=3,
            catalog_byte_length=len(cat1_bytes),
            catalog_entry_count=1,
            committed_high_water_unit=5,
        )
        image[0 : STORE_UNIT_BYTES] = sb0

        # Gen 2 at units 5 (commit) and 6 (catalog)
        cat2_entries = [
            (calculate_object_id(10, 1, b"GEN1"), 10, 1, 4, 4),
            (calculate_object_id(20, 1, b"GEN2"), 20, 1, 7, 4),
        ]
        cat2_bytes, cat2_id = create_mock_catalog(cat2_entries)
        image[6 * STORE_UNIT_BYTES : 6 * STORE_UNIT_BYTES + len(cat2_bytes)] = cat2_bytes

        cmt2_bytes, cmt2_id = create_mock_commit(
            store_uuid=store_uuid,
            region_units=total_units,
            generation=2,
            previous_generation=1,
            previous_commit_id=bytes.fromhex(cmt1_id),
            previous_catalog_id=bytes.fromhex(cat1_id),
            catalog_id=bytes.fromhex(cat2_id),
            catalog_first_unit=6,
            catalog_byte_length=len(cat2_bytes),
            catalog_entry_count=2,
            committed_high_water_unit=8,
        )
        image[5 * STORE_UNIT_BYTES : 5 * STORE_UNIT_BYTES + len(cmt2_bytes)] = cmt2_bytes

        sb1 = create_mock_superblock(
            slot=1,
            store_uuid=store_uuid,
            region_units=total_units,
            generation=2,
            commit_record_id=bytes.fromhex(cmt2_id),
            commit_record_unit=5,
            catalog_id=bytes.fromhex(cat2_id),
            catalog_first_unit=6,
            catalog_byte_length=len(cat2_bytes),
            catalog_entry_count=2,
            committed_high_water_unit=8,
        )
        image[STORE_UNIT_BYTES : 2 * STORE_UNIT_BYTES] = sb1

        img_path.write_bytes(bytes(image))

        inspector = StoreInspector(img_path)
        report = inspector.full_inspection()

        self.assertTrue(report["verdict"]["is_recoverable"])
        self.assertEqual(report["verdict"]["recovery_status"], "FORWARD_PROGRESS")
        self.assertEqual(report["verdict"]["selected_generation"], 2)
        self.assertEqual(report["store_v1"]["selected_recoverable_root"]["selected_slot"], 1)
        self.assertFalse(report["verdict"]["rollback_occurred"])
        self.assertEqual(report["store_v1"]["active_commit"]["calculated_id"], cmt2_id)

    def test_crash_rollback_when_slot_b_corrupted(self):
        """
        Crash Scenario: Power lost while writing Slot B (Gen 2) Superblock.
        Slot B has torn write / invalid CRC.
        Oracle must rollback and recover to Slot A (Gen 1).
        """
        img_path = self.temp_path / "crash_torn_sb.img"
        total_units = 16
        image = bytearray(total_units * STORE_UNIT_BYTES)
        store_uuid = bytes.fromhex("112233445566778899aabbccddeeff00")

        # Valid Gen 1 in Slot A
        cat1_entries = [(calculate_object_id(10, 1, b"GEN1"), 10, 1, 4, 4)]
        cat1_bytes, cat1_id = create_mock_catalog(cat1_entries)
        image[3 * STORE_UNIT_BYTES : 3 * STORE_UNIT_BYTES + len(cat1_bytes)] = cat1_bytes

        cmt1_bytes, cmt1_id = create_mock_commit(
            store_uuid=store_uuid,
            region_units=total_units,
            generation=1,
            previous_generation=0,
            previous_commit_id=b"\x00" * 32,
            previous_catalog_id=b"\x00" * 32,
            catalog_id=bytes.fromhex(cat1_id),
            catalog_first_unit=3,
            catalog_byte_length=len(cat1_bytes),
            catalog_entry_count=1,
            committed_high_water_unit=5,
        )
        image[2 * STORE_UNIT_BYTES : 2 * STORE_UNIT_BYTES + len(cmt1_bytes)] = cmt1_bytes

        sb0 = create_mock_superblock(
            slot=0,
            store_uuid=store_uuid,
            region_units=total_units,
            generation=1,
            commit_record_id=bytes.fromhex(cmt1_id),
            commit_record_unit=2,
            catalog_id=bytes.fromhex(cat1_id),
            catalog_first_unit=3,
            catalog_byte_length=len(cat1_bytes),
            catalog_entry_count=1,
            committed_high_water_unit=5,
        )
        image[0 : STORE_UNIT_BYTES] = sb0

        # Slot B was partially written: magic is there, but CRC is invalid due to tear
        corrupt_sb1 = bytearray(STORE_UNIT_BYTES)
        corrupt_sb1[0:8] = SUPERBLOCK_MAGIC
        corrupt_sb1[44:48] = struct.pack("<I", 1)  # slot 1
        corrupt_sb1[56:64] = struct.pack("<Q", 2)  # generation 2
        corrupt_sb1[SUPERBLOCK_CRC_OFFSET : SUPERBLOCK_CRC_OFFSET + 4] = b"\xde\xad\xbe\xef"  # Bad CRC
        image[STORE_UNIT_BYTES : 2 * STORE_UNIT_BYTES] = corrupt_sb1

        img_path.write_bytes(bytes(image))

        inspector = StoreInspector(img_path)
        report = inspector.full_inspection()

        self.assertTrue(report["verdict"]["is_recoverable"])
        self.assertEqual(report["verdict"]["recovery_status"], "RECOVERED_ROLLBACK")
        self.assertEqual(report["verdict"]["selected_generation"], 1)
        self.assertEqual(report["store_v1"]["selected_recoverable_root"]["selected_slot"], 0)
        self.assertTrue(report["verdict"]["rollback_occurred"])
        self.assertEqual(report["store_v1"]["slot_b"]["status"], "BAD_CRC")
        self.assertEqual(report["store_v1"]["active_commit"]["calculated_id"], cmt1_id)

    def test_crash_rollback_when_gen2_commit_truncated(self):
        """
        Crash Scenario: Superblock B points to Gen 2, but the CommitRecord
        on media was truncated/corrupted by a crash.
        Oracle must detect invalid commit for Gen 2 and fallback to Gen 1.
        """
        img_path = self.temp_path / "crash_commit_truncated.img"
        total_units = 16
        image = bytearray(total_units * STORE_UNIT_BYTES)
        store_uuid = bytes.fromhex("112233445566778899aabbccddeeff00")

        # Valid Gen 1 in Slot A
        cat1_entries = [(calculate_object_id(10, 1, b"GEN1"), 10, 1, 4, 4)]
        cat1_bytes, cat1_id = create_mock_catalog(cat1_entries)
        image[3 * STORE_UNIT_BYTES : 3 * STORE_UNIT_BYTES + len(cat1_bytes)] = cat1_bytes

        cmt1_bytes, cmt1_id = create_mock_commit(
            store_uuid=store_uuid,
            region_units=total_units,
            generation=1,
            previous_generation=0,
            previous_commit_id=b"\x00" * 32,
            previous_catalog_id=b"\x00" * 32,
            catalog_id=bytes.fromhex(cat1_id),
            catalog_first_unit=3,
            catalog_byte_length=len(cat1_bytes),
            catalog_entry_count=1,
            committed_high_water_unit=5,
        )
        image[2 * STORE_UNIT_BYTES : 2 * STORE_UNIT_BYTES + len(cmt1_bytes)] = cmt1_bytes

        sb0 = create_mock_superblock(
            slot=0,
            store_uuid=store_uuid,
            region_units=total_units,
            generation=1,
            commit_record_id=bytes.fromhex(cmt1_id),
            commit_record_unit=2,
            catalog_id=bytes.fromhex(cat1_id),
            catalog_first_unit=3,
            catalog_byte_length=len(cat1_bytes),
            catalog_entry_count=1,
            committed_high_water_unit=5,
        )
        image[0 : STORE_UNIT_BYTES] = sb0

        # Slot B was written with gen 2 pointing to commit unit 5
        fake_cmt2_id = b"\xca\xfe" * 16
        sb1 = create_mock_superblock(
            slot=1,
            store_uuid=store_uuid,
            region_units=total_units,
            generation=2,
            commit_record_id=fake_cmt2_id,
            commit_record_unit=5,
            catalog_id=bytes.fromhex(cat1_id),
            catalog_first_unit=3,
            catalog_byte_length=len(cat1_bytes),
            catalog_entry_count=1,
            committed_high_water_unit=6,
        )
        image[STORE_UNIT_BYTES : 2 * STORE_UNIT_BYTES] = sb1
        # But commit unit 5 was never written (all zeroes)!

        img_path.write_bytes(bytes(image))

        inspector = StoreInspector(img_path)
        report = inspector.full_inspection()

        self.assertTrue(report["verdict"]["is_recoverable"])
        self.assertEqual(report["verdict"]["recovery_status"], "RECOVERED_ROLLBACK")
        self.assertEqual(report["verdict"]["selected_generation"], 1)
        self.assertEqual(report["store_v1"]["selected_recoverable_root"]["selected_slot"], 0)
        self.assertTrue(report["verdict"]["rollback_occurred"])

    def test_superblock_nonzero_reserved_bytes_fails(self):
        """ADR 0015: Non-zero bytes in reserved area of superblock must trigger MALFORMED."""
        img_path = self.temp_path / "sb_nonzero_reserved.img"
        total_units = 8
        image = bytearray(total_units * STORE_UNIT_BYTES)
        store_uuid = bytes.fromhex("112233445566778899aabbccddeeff00")

        sb0 = bytearray(create_mock_superblock(
            slot=0,
            store_uuid=store_uuid,
            region_units=total_units,
            generation=1,
            commit_record_id=b"\x01" * 32,
            commit_record_unit=2,
            catalog_id=b"\x02" * 32,
            catalog_first_unit=3,
            catalog_byte_length=64,
            catalog_entry_count=1,
            committed_high_water_unit=4,
        ))
        # Inject non-zero into reserved area (offset 172+)
        sb0[200] = 0xAA
        # Recompute CRC over the modified buffer
        sb0[SUPERBLOCK_CRC_OFFSET : SUPERBLOCK_CRC_OFFSET + 4] = b"\x00\x00\x00\x00"
        crc = calculate_crc32c(bytes(sb0))
        struct.pack_into("<I", sb0, SUPERBLOCK_CRC_OFFSET, crc)

        image[0 : STORE_UNIT_BYTES] = sb0
        img_path.write_bytes(bytes(image))

        inspector = StoreInspector(img_path)
        sb_info = inspector.decode_superblock(0, 0)
        self.assertFalse(sb_info.reserved_zeroed)
        self.assertEqual(sb_info.status, "MALFORMED")
        self.assertIn("reserved", sb_info.error_reason.lower())

    def test_catalog_unsorted_order_fails(self):
        """ADR 0015: Catalog entries must be strictly sorted by ObjectId."""
        img_path = self.temp_path / "cat_unsorted.img"
        total_units = 8
        image = bytearray(total_units * STORE_UNIT_BYTES)

        # Create two entries out of order
        id1 = b"\xbb" * 32
        id2 = b"\xaa" * 32  # id2 < id1
        unsorted_entries = [
            (id1, 10, 1, 4, 100),
            (id2, 10, 1, 5, 100),
        ]
        cat_bytes, cat_id = create_mock_catalog(unsorted_entries, sort_entries=False)
        image[3 * STORE_UNIT_BYTES : 3 * STORE_UNIT_BYTES + len(cat_bytes)] = cat_bytes

        img_path.write_bytes(bytes(image))
        inspector = StoreInspector(img_path)
        cat_info = inspector.decode_catalog(3, len(cat_bytes), 1, cat_id)

        self.assertEqual(cat_info.status, "MALFORMED")
        self.assertIn("strictly sorted", cat_info.error_reason.lower())

    def test_catalog_object_exceeding_high_water_fails(self):
        """Catalog entry pointing beyond high-water mark must trigger error."""
        img_path = self.temp_path / "cat_out_of_bounds.img"
        total_units = 8
        image = bytearray(total_units * STORE_UNIT_BYTES)

        # Object at unit 6 with length 4096 (ends at unit 7), but high water is 6
        id1 = b"\x11" * 32
        entries = [(id1, 10, 1, 6, 4096)]
        cat_bytes, cat_id = create_mock_catalog(entries)
        image[3 * STORE_UNIT_BYTES : 3 * STORE_UNIT_BYTES + len(cat_bytes)] = cat_bytes

        img_path.write_bytes(bytes(image))
        inspector = StoreInspector(img_path)
        cat_info = inspector.decode_catalog(3, len(cat_bytes), 1, cat_id, high_water=6)

        self.assertEqual(cat_info.status, "MALFORMED")
        self.assertIn("high-water", cat_info.error_reason.lower())

    def test_partitioned_disk_image_detection(self):
        """Test MBR partition detection and slicing."""
        img_path = self.temp_path / "partitioned.img"
        sector_size = 512
        total_sectors = 2048 + 64  # Partition starts at LBA 2048 (1 MiB offset)
        image = bytearray(total_sectors * sector_size)

        # Write MBR at sector 0
        image[510:512] = b"\x55\xaa"
        # Partition 1: active (0x80), type Linux (0x83), start LBA 2048, count 64
        entry1 = struct.pack("<BBBBBBBBII", 0x80, 0, 0, 0, 0x83, 0, 0, 0, 2048, 64)
        image[446:462] = entry1

        img_path.write_bytes(bytes(image))

        inspector = StoreInspector(img_path, sector_size=sector_size)
        partitions = inspector.inspect_partitions()

        self.assertEqual(len(partitions), 1)
        self.assertEqual(partitions[0].scheme, "MBR")
        self.assertEqual(partitions[0].start_lba, 2048)
        self.assertEqual(partitions[0].sector_count, 64)
        self.assertEqual(partitions[0].start_byte_offset, 2048 * 512)
        self.assertTrue(partitions[0].bootable)

    def test_hex_dump_formatting(self):
        """Verify hex dump output format."""
        img_path = self.temp_path / "dummy.img"
        img_path.write_bytes(b"\x00" * STORE_UNIT_BYTES)

        inspector = StoreInspector(img_path)
        sample_data = b"Hello, World!\x00\x01\x02"
        dump = inspector.format_hex_dump(sample_data, base_addr=0x1000)

        self.assertIn("00001000", dump)
        self.assertIn("Hello, World!", dump)

    def test_cli_execution_and_json_schema(self):
        """Verify standalone CLI execution produces machine-readable JSON."""
        img_path = self.temp_path / "cli_test.img"
        img_path.write_bytes(b"\x00" * (STORE_UNIT_BYTES * 4))

        inspector_script = Path(__file__).parent / "inspector.py"
        result = subprocess.run(
            [sys.executable, str(inspector_script), str(img_path), "--pretty", "--include-blocks"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        self.assertEqual(report["schema_version"], "1.0.0")
        self.assertIn("target_image", report)
        self.assertIn("store_v1", report)
        self.assertIn("block_analysis", report)
        self.assertIn("verdict", report)

    def test_cli_strict_mode(self):
        """Verify --strict exits with 1 on unrecoverable image and 0 on valid image."""
        blank_path = self.temp_path / "blank_strict.img"
        blank_path.write_bytes(b"\x00" * (STORE_UNIT_BYTES * 4))

        inspector_script = Path(__file__).parent / "inspector.py"
        # Blank image -> exit code 1 with --strict
        res_fail = subprocess.run(
            [sys.executable, str(inspector_script), str(blank_path), "--strict"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_fail.returncode, 1)


if __name__ == "__main__":
    unittest.main()
