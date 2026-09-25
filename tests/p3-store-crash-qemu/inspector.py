#!/usr/bin/env python3
"""
Host-side read-only block image inspector for AIENOS crash/reboot qualification.

This tool acts as an independent verification oracle:
- Examines raw block images resulting from crashes and hard reboots.
- Does NOT reuse or import guest kernel mount code.
- Inspects raw Store units, partition boundaries, block-level sha256 digests,
  Shannon entropy, and raw block dumps.
- Decodes canonical ADR 0015 Store v1 structures:
  - Superblock A/B status (Slot 0 / Slot 1 or configured offsets)
  - Generation counters
  - CommitRecord identity and SHA-256 / CRC32C verification
  - Catalog identity, roots, entry order, and boundary checks
  - High-water mark accounting
  - Selected recoverable root decision oracle
- Produces machine-readable JSON output for verify_evidence.sh and aien-proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import struct
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ADR 0015 Constants
STORE_UNIT_BYTES: int = 4096
SUPERBLOCK_MAGIC: bytes = b"AIENSTR1"
CATALOG_MAGIC: bytes = b"AIENCAT1"
COMMIT_MAGIC: bytes = b"AIENCMT1"
OBJECT_DOMAIN: bytes = b"AIENOS-STORE-OBJECT-V1\0"
SUPERBLOCK_CRC_OFFSET: int = 168
SUPERBLOCK_USED_BYTES: int = 172
COMMIT_BYTES: int = 232
CATALOG_HEADER_BYTES: int = 16
CATALOG_ENTRY_BYTES: int = 64
MAX_CATALOG_ENTRIES: int = 4096
MAX_OBJECT_BYTES: int = 67_108_864  # 64 MiB
MAX_OBJECT_UNITS: int = 16_384
MAX_REGION_UNITS: int = 4_294_967_296  # 2^32
KIND_CATALOG: int = 1
KIND_COMMIT: int = 2

# Legacy Prototype Constants (ADR 0003)
LEGACY_STORE_MAGIC: bytes = b"AIENST01"
LEGACY_WAL_MAGIC: bytes = b"AIENWL01"

# CRC-32C (Castagnoli, reflected polynomial 0x82F63B78) lookup table
CRC32C_TABLE: List[int] = []


def _init_crc32c_table() -> List[int]:
    table = []
    poly = 0x82F63B78
    for i in range(256):
        c = i
        for _ in range(8):
            if c & 1:
                c = (c >> 1) ^ poly
            else:
                c = c >> 1
        table.append(c)
    return table


CRC32C_TABLE = _init_crc32c_table()


def calculate_crc32c(data: bytes) -> int:
    """Calculate CRC-32C (Castagnoli) checksum with reflected polynomial 0x82F63B78."""
    crc = 0xFFFFFFFF
    for b in data:
        crc = (crc >> 8) ^ CRC32C_TABLE[(crc ^ b) & 0xFF]
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF


def calculate_object_id(kind: int, version: int, semantic: bytes) -> bytes:
    """
    Calculate 32-byte canonical ObjectId per ADR 0015:
    Sha256(OBJECT_DOMAIN + kind(u16 le) + version(u16 le) + byte_length(u64 le) + semantic)
    """
    byte_length = len(semantic)
    hasher = hashlib.sha256()
    hasher.update(OBJECT_DOMAIN)
    hasher.update(struct.pack("<HHQ", kind, version, byte_length))
    hasher.update(semantic)
    return hasher.digest()


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


@dataclass
class PartitionInfo:
    scheme: str  # "MBR" or "GPT"
    index: int
    start_lba: int
    sector_count: int
    start_byte_offset: int
    size_bytes: int
    partition_type: str
    bootable: bool = False
    name: Optional[str] = None
    guid: Optional[str] = None


@dataclass
class SuperblockInfo:
    slot: int
    unit_index: int
    byte_offset: int
    status: str  # "VALID", "BAD_MAGIC", "BAD_CRC", "MALFORMED", "UNFORMATTED"
    magic: str
    format_major: Optional[int] = None
    format_minor: Optional[int] = None
    required_features: Optional[int] = None
    compatible_features: Optional[int] = None
    store_uuid: Optional[str] = None
    region_units: Optional[int] = None
    generation: Optional[int] = None
    commit_record_id: Optional[str] = None
    commit_record_unit: Optional[int] = None
    catalog_id: Optional[str] = None
    catalog_first_unit: Optional[int] = None
    catalog_byte_length: Optional[int] = None
    catalog_unit_count: Optional[int] = None
    catalog_entry_count: Optional[int] = None
    committed_high_water_unit: Optional[int] = None
    stored_crc: Optional[str] = None
    calculated_crc: Optional[str] = None
    crc_matches: Optional[bool] = None
    reserved_zeroed: Optional[bool] = None
    error_reason: Optional[str] = None


@dataclass
class CommitRecordInfo:
    unit_index: int
    byte_offset: int
    status: str  # "VALID", "BAD_MAGIC", "HASH_MISMATCH", "MALFORMED"
    calculated_id: str
    referenced_id: Optional[str] = None
    id_matches: bool = False
    format_major: Optional[int] = None
    format_minor: Optional[int] = None
    required_features: Optional[int] = None
    compatible_features: Optional[int] = None
    store_uuid: Optional[str] = None
    region_units: Optional[int] = None
    generation: Optional[int] = None
    previous_generation: Optional[int] = None
    previous_commit_id: Optional[str] = None
    previous_catalog_id: Optional[str] = None
    catalog_id: Optional[str] = None
    catalog_first_unit: Optional[int] = None
    catalog_byte_length: Optional[int] = None
    catalog_unit_count: Optional[int] = None
    catalog_entry_count: Optional[int] = None
    committed_high_water_unit: Optional[int] = None
    published_manifest_id: Optional[str] = None
    error_reason: Optional[str] = None


@dataclass
class CatalogEntryInfo:
    index: int
    object_id: str
    kind: int
    version: int
    first_unit: int
    byte_length: int
    unit_count: int
    flags: int
    valid: bool
    error_reason: Optional[str] = None


@dataclass
class CatalogInfo:
    first_unit: int
    byte_offset: int
    status: str  # "VALID", "BAD_MAGIC", "HASH_MISMATCH", "MALFORMED", "OUT_OF_BOUNDS"
    calculated_id: str
    referenced_id: Optional[str] = None
    id_matches: bool = False
    entry_count: int = 0
    entries: List[CatalogEntryInfo] = field(default_factory=list)
    error_reason: Optional[str] = None


@dataclass
class RecoverableRootInfo:
    selected_slot: Optional[int]
    status: str  # "CONSISTENT", "FORWARD_PROGRESS", "RECOVERED_ROLLBACK", "CONFLICTING_ROOTS", "UNRECOVERABLE"
    generation: Optional[int]
    committed_high_water_unit: Optional[int]
    commit_record_id: Optional[str]
    commit_record_unit: Optional[int]
    catalog_id: Optional[str]
    catalog_entry_count: Optional[int]
    published_manifest_id: Optional[str]
    verified_commit: bool
    verified_catalog: bool
    rollback_occurred: bool
    explanation: str


@dataclass
class BlockUnitSummary:
    unit_index: int
    byte_offset: int
    sha256: str
    entropy: float
    is_zero: bool
    tag: str


class StoreInspector:
    """Read-only inspector and independent verification oracle for raw block images."""

    def __init__(
        self,
        image_path: str | Path,
        unit_size: int = STORE_UNIT_BYTES,
        sector_size: int = 512,
        base_offset: int = 0,
        length: Optional[int] = None,
        slot_a_unit: int = 0,
        slot_b_unit: int = 1,
    ):
        self.image_path = Path(image_path)
        self.unit_size = unit_size
        self.sector_size = sector_size
        self.base_offset = base_offset
        self.slot_a_unit = slot_a_unit
        self.slot_b_unit = slot_b_unit

        if not self.image_path.exists():
            raise FileNotFoundError(f"Block image not found: {self.image_path}")

        self.file_size = self.image_path.stat().st_size
        if length is not None:
            self.usable_length = min(length, max(0, self.file_size - self.base_offset))
        else:
            self.usable_length = max(0, self.file_size - self.base_offset)

        self.total_units = self.usable_length // self.unit_size

    def read_raw_bytes(self, offset: int, length: int) -> bytes:
        """Read raw bytes from the image file safely in read-only mode."""
        if offset < 0 or length < 0:
            return b""
        actual_offset = self.base_offset + offset
        if actual_offset >= self.file_size:
            return b""
        with open(self.image_path, "rb") as f:
            f.seek(actual_offset)
            return f.read(length)

    def read_unit(self, unit_index: int) -> bytes:
        """Read a single Store unit by unit index."""
        if unit_index < 0:
            return b""
        offset = unit_index * self.unit_size
        return self.read_raw_bytes(offset, self.unit_size)

    def compute_image_sha256(self) -> str:
        """Compute the SHA-256 digest of the entire image."""
        hasher = hashlib.sha256()
        with open(self.image_path, "rb") as f:
            while chunk := f.read(1024 * 1024):
                hasher.update(chunk)
        return hasher.hexdigest()

    def inspect_partitions(self) -> List[PartitionInfo]:
        """Detect MBR and GPT partition tables if present."""
        partitions: List[PartitionInfo] = []
        if self.file_size < self.sector_size * 2:
            return partitions

        # Check MBR boot record at sector 0
        mbr = self.read_raw_bytes(0, 512)
        if len(mbr) >= 512 and mbr[510:512] == b"\x55\xaa":
            has_gpt = False
            for i in range(4):
                entry_offset = 446 + i * 16
                entry = mbr[entry_offset : entry_offset + 16]
                bootable = (entry[0] == 0x80)
                part_type = entry[4]
                if part_type == 0:
                    continue
                start_lba, sector_count = struct.unpack("<II", entry[8:16])
                if part_type == 0xEE:  # GPT Protective MBR
                    has_gpt = True
                partitions.append(
                    PartitionInfo(
                        scheme="MBR",
                        index=i,
                        start_lba=start_lba,
                        sector_count=sector_count,
                        start_byte_offset=start_lba * self.sector_size,
                        size_bytes=sector_count * self.sector_size,
                        partition_type=f"0x{part_type:02x}",
                        bootable=bootable,
                    )
                )

            # If GPT is indicated, parse GPT Header at LBA 1
            if has_gpt and self.file_size >= self.sector_size * 34:
                gpt_hdr = self.read_raw_bytes(self.sector_size, self.sector_size)
                if len(gpt_hdr) >= 92 and gpt_hdr[:8] == b"EFI PART":
                    current_lba, backup_lba, first_usable, last_usable = struct.unpack(
                        "<QQQQ", gpt_hdr[24:56]
                    )
                    disk_guid = gpt_hdr[56:72].hex()
                    part_entry_lba, num_entries, entry_size = struct.unpack(
                        "<QII", gpt_hdr[72:88]
                    )
                    table_bytes = self.read_raw_bytes(
                        part_entry_lba * self.sector_size, num_entries * entry_size
                    )
                    for j in range(num_entries):
                        p_off = j * entry_size
                        p_data = table_bytes[p_off : p_off + entry_size]
                        if len(p_data) < 128:
                            break
                        type_guid = p_data[:16]
                        if type_guid == b"\x00" * 16:
                            continue
                        part_guid = p_data[16:32].hex()
                        s_lba, e_lba, flags = struct.unpack("<QQQ", p_data[32:56])
                        sec_cnt = (e_lba - s_lba + 1) if e_lba >= s_lba else 0
                        raw_name = p_data[56:128]
                        part_name = raw_name.decode("utf-16-le", errors="ignore").split("\x00")[0]
                        partitions.append(
                            PartitionInfo(
                                scheme="GPT",
                                index=j,
                                start_lba=s_lba,
                                sector_count=sec_cnt,
                                start_byte_offset=s_lba * self.sector_size,
                                size_bytes=sec_cnt * self.sector_size,
                                partition_type=type_guid.hex(),
                                name=part_name,
                                guid=part_guid,
                            )
                        )
        return partitions

    def decode_superblock(self, slot: int, unit_index: int) -> SuperblockInfo:
        """Decode and validate a Superblock (Slot A or Slot B) per ADR 0015."""
        byte_offset = unit_index * self.unit_size
        raw = self.read_unit(unit_index)

        if len(raw) < STORE_UNIT_BYTES:
            return SuperblockInfo(
                slot=slot,
                unit_index=unit_index,
                byte_offset=byte_offset,
                status="UNFORMATTED",
                magic="",
                error_reason=f"Unit read incomplete ({len(raw)} bytes)",
            )

        if raw == b"\x00" * STORE_UNIT_BYTES:
            return SuperblockInfo(
                slot=slot,
                unit_index=unit_index,
                byte_offset=byte_offset,
                status="UNFORMATTED",
                magic="ALL_ZERO",
                error_reason="Unit is completely all-zero",
            )

        magic = raw[:8]
        if magic != SUPERBLOCK_MAGIC:
            return SuperblockInfo(
                slot=slot,
                unit_index=unit_index,
                byte_offset=byte_offset,
                status="BAD_MAGIC",
                magic=magic.decode("latin1", errors="replace"),
                error_reason=f"Magic mismatch: expected {SUPERBLOCK_MAGIC.decode()} got {magic.hex()}",
            )

        # ADR 0015 check: reserved bytes (172..4096) must be all zero
        reserved = raw[SUPERBLOCK_USED_BYTES:]
        reserved_zeroed = (reserved == b"\x00" * len(reserved))

        # Check CRC32C: zero out CRC field [168..172] and compute CRC32C over the full 4096 bytes
        stored_crc = struct.unpack("<I", raw[SUPERBLOCK_CRC_OFFSET : SUPERBLOCK_CRC_OFFSET + 4])[0]
        canonical = bytearray(raw)
        canonical[SUPERBLOCK_CRC_OFFSET : SUPERBLOCK_CRC_OFFSET + 4] = b"\x00\x00\x00\x00"
        calculated_crc = calculate_crc32c(bytes(canonical))
        crc_matches = (stored_crc == calculated_crc)

        format_major, format_minor = struct.unpack("<HH", raw[8:12])
        required_features, compatible_features = struct.unpack("<QQ", raw[12:28])
        store_uuid = raw[28:44].hex()
        slot_id = struct.unpack("<I", raw[44:48])[0]
        region_units, generation = struct.unpack("<QQ", raw[48:64])
        commit_record_id = raw[64:96].hex()
        commit_record_unit = struct.unpack("<Q", raw[96:104])[0]
        catalog_id = raw[104:136].hex()
        catalog_first_unit, catalog_byte_length = struct.unpack("<QQ", raw[136:152])
        catalog_unit_count, catalog_entry_count = struct.unpack("<II", raw[152:160])
        committed_high_water_unit = struct.unpack("<Q", raw[160:168])[0]

        errors = []
        if not crc_matches:
            errors.append(f"CRC32C mismatch: stored 0x{stored_crc:08x} != calculated 0x{calculated_crc:08x}")
        if not reserved_zeroed:
            errors.append("Non-zero bytes found in reserved superblock area (bytes 172..4096)")
        if slot_id != slot:
            errors.append(f"Slot ID mismatch: expected {slot}, found {slot_id}")
        if format_major != 1:
            errors.append(f"Unsupported format_major: {format_major} (expected 1)")
        if region_units < 4 or region_units > MAX_REGION_UNITS:
            errors.append(f"Invalid region_units: {region_units}")
        if committed_high_water_unit < 4 or committed_high_water_unit > region_units:
            errors.append(f"Invalid high-water mark: {committed_high_water_unit} (region={region_units})")
        if generation == 0:
            errors.append("Generation counter is zero")

        status = "VALID" if not errors else ("BAD_CRC" if not crc_matches else "MALFORMED")

        return SuperblockInfo(
            slot=slot,
            unit_index=unit_index,
            byte_offset=byte_offset,
            status=status,
            magic=magic.decode("latin1", errors="replace"),
            format_major=format_major,
            format_minor=format_minor,
            required_features=required_features,
            compatible_features=compatible_features,
            store_uuid=store_uuid,
            region_units=region_units,
            generation=generation,
            commit_record_id=commit_record_id,
            commit_record_unit=commit_record_unit,
            catalog_id=catalog_id,
            catalog_first_unit=catalog_first_unit,
            catalog_byte_length=catalog_byte_length,
            catalog_unit_count=catalog_unit_count,
            catalog_entry_count=catalog_entry_count,
            committed_high_water_unit=committed_high_water_unit,
            stored_crc=f"0x{stored_crc:08x}",
            calculated_crc=f"0x{calculated_crc:08x}",
            crc_matches=crc_matches,
            reserved_zeroed=reserved_zeroed,
            error_reason="; ".join(errors) if errors else None,
        )

    def decode_commit_record(
        self, unit_index: int, referenced_id: Optional[str] = None
    ) -> CommitRecordInfo:
        """Decode and verify a CommitRecord per ADR 0015."""
        byte_offset = unit_index * self.unit_size
        raw = self.read_unit(unit_index)

        if len(raw) < COMMIT_BYTES:
            return CommitRecordInfo(
                unit_index=unit_index,
                byte_offset=byte_offset,
                status="MALFORMED",
                calculated_id="",
                referenced_id=referenced_id,
                error_reason=f"Unit read incomplete ({len(raw)} bytes)",
            )

        commit_bytes = raw[:COMMIT_BYTES]
        magic = commit_bytes[:8]
        if magic != COMMIT_MAGIC:
            return CommitRecordInfo(
                unit_index=unit_index,
                byte_offset=byte_offset,
                status="BAD_MAGIC",
                calculated_id="",
                referenced_id=referenced_id,
                error_reason=f"Commit magic mismatch: expected {COMMIT_MAGIC.decode()} got {magic.hex()}",
            )

        calc_id_bytes = calculate_object_id(KIND_COMMIT, 1, commit_bytes)
        calculated_id = calc_id_bytes.hex()
        id_matches = (referenced_id is None or calculated_id.lower() == referenced_id.lower())

        version, record_len = struct.unpack("<HH", commit_bytes[8:12])
        format_major, format_minor = struct.unpack("<HH", commit_bytes[12:16])
        required_features, compatible_features = struct.unpack("<QQ", commit_bytes[16:32])
        store_uuid = commit_bytes[32:48].hex()
        region_units, generation, prev_generation = struct.unpack("<QQQ", commit_bytes[48:72])
        prev_commit_id = commit_bytes[72:104].hex()
        prev_catalog_id = commit_bytes[104:136].hex()
        catalog_id = commit_bytes[136:168].hex()
        catalog_first_unit, catalog_byte_length = struct.unpack("<QQ", commit_bytes[168:184])
        catalog_unit_count, catalog_entry_count = struct.unpack("<II", commit_bytes[184:192])
        committed_high_water_unit = struct.unpack("<Q", commit_bytes[192:200])[0]
        published_manifest_id = commit_bytes[200:232].hex()

        errors = []
        if version != 1 or record_len != COMMIT_BYTES:
            errors.append(f"Unexpected commit header version={version}, len={record_len}")
        if generation == 0 or region_units > MAX_REGION_UNITS:
            errors.append(f"Malformed commit generation={generation}, region_units={region_units}")
        if not id_matches:
            errors.append(f"Identity hash mismatch: expected {referenced_id} != calculated {calculated_id}")

        status = "VALID" if not errors else ("HASH_MISMATCH" if not id_matches else "MALFORMED")

        return CommitRecordInfo(
            unit_index=unit_index,
            byte_offset=byte_offset,
            status=status,
            calculated_id=calculated_id,
            referenced_id=referenced_id,
            id_matches=id_matches,
            format_major=format_major,
            format_minor=format_minor,
            required_features=required_features,
            compatible_features=compatible_features,
            store_uuid=store_uuid,
            region_units=region_units,
            generation=generation,
            previous_generation=prev_generation,
            previous_commit_id=prev_commit_id,
            previous_catalog_id=prev_catalog_id,
            catalog_id=catalog_id,
            catalog_first_unit=catalog_first_unit,
            catalog_byte_length=catalog_byte_length,
            catalog_unit_count=catalog_unit_count,
            catalog_entry_count=catalog_entry_count,
            committed_high_water_unit=committed_high_water_unit,
            published_manifest_id=published_manifest_id,
            error_reason="; ".join(errors) if errors else None,
        )

    def decode_catalog(
        self,
        first_unit: int,
        byte_length: int,
        unit_count: int,
        referenced_id: Optional[str] = None,
        high_water: Optional[int] = None,
    ) -> CatalogInfo:
        """Decode and verify Catalog and its ObjectDescriptors per ADR 0015."""
        byte_offset = first_unit * self.unit_size
        total_read = unit_count * self.unit_size
        raw = self.read_raw_bytes(byte_offset, total_read)

        if len(raw) < byte_length or byte_length < CATALOG_HEADER_BYTES:
            return CatalogInfo(
                first_unit=first_unit,
                byte_offset=byte_offset,
                status="MALFORMED",
                calculated_id="",
                referenced_id=referenced_id,
                error_reason=f"Catalog byte slice incomplete: requested {byte_length}, read {len(raw)}",
            )

        catalog_slice = raw[:byte_length]
        magic = catalog_slice[:8]
        if magic != CATALOG_MAGIC:
            return CatalogInfo(
                first_unit=first_unit,
                byte_offset=byte_offset,
                status="BAD_MAGIC",
                calculated_id="",
                referenced_id=referenced_id,
                error_reason=f"Catalog magic mismatch: expected {CATALOG_MAGIC.decode()} got {magic.hex()}",
            )

        calc_id_bytes = calculate_object_id(KIND_CATALOG, 1, catalog_slice)
        calculated_id = calc_id_bytes.hex()
        id_matches = (referenced_id is None or calculated_id.lower() == referenced_id.lower())

        version, entry_bytes, entry_count = struct.unpack("<HHI", catalog_slice[8:16])
        expected_bytes = CATALOG_HEADER_BYTES + entry_count * CATALOG_ENTRY_BYTES

        errors = []
        if version != 1 or entry_bytes != CATALOG_ENTRY_BYTES:
            errors.append(f"Unsupported catalog version={version}, entry_bytes={entry_bytes}")
        if byte_length != expected_bytes:
            errors.append(f"Catalog length mismatch: header expects {expected_bytes}, given {byte_length}")
        if entry_count > MAX_CATALOG_ENTRIES:
            errors.append(f"Catalog entry count {entry_count} exceeds maximum {MAX_CATALOG_ENTRIES}")
        if not id_matches:
            errors.append(f"Catalog ID hash mismatch: expected {referenced_id} != calculated {calculated_id}")

        entries: List[CatalogEntryInfo] = []
        last_id_bytes: Optional[bytes] = None

        if not errors:
            for idx in range(entry_count):
                start = CATALOG_HEADER_BYTES + idx * CATALOG_ENTRY_BYTES
                edata = catalog_slice[start : start + CATALOG_ENTRY_BYTES]
                obj_id_bytes = edata[:32]
                obj_id_hex = obj_id_bytes.hex()

                kind, ver = struct.unpack("<HH", edata[32:36])
                e_first_unit, e_byte_len = struct.unpack("<QQ", edata[36:52])
                e_unit_count, flags = struct.unpack("<IH", edata[52:58])
                reserved = edata[58:64]

                entry_errs = []
                if reserved != b"\x00" * 6:
                    entry_errs.append("Non-zero reserved bytes in descriptor")
                if kind in (KIND_CATALOG, KIND_COMMIT) or kind == 0:
                    entry_errs.append(f"Invalid object kind: {kind}")
                if ver == 0 or flags != 0 or e_byte_len == 0:
                    entry_errs.append("Invalid version, flags, or zero byte_length")
                if e_byte_len > MAX_OBJECT_BYTES:
                    entry_errs.append(f"Object too large: {e_byte_len}")

                calc_units = (e_byte_len + STORE_UNIT_BYTES - 1) // STORE_UNIT_BYTES
                if calc_units != e_unit_count or e_unit_count > MAX_OBJECT_UNITS:
                    entry_errs.append(f"Unit count mismatch: calculated {calc_units} != descriptor {e_unit_count}")

                if e_first_unit < 2:
                    entry_errs.append(f"Object starts in reserved superblock area (unit {e_first_unit})")

                if high_water is not None and (e_first_unit + e_unit_count > high_water):
                    entry_errs.append(
                        f"Object extends beyond high-water mark: {e_first_unit}+{e_unit_count} > {high_water}"
                    )

                if last_id_bytes is not None and last_id_bytes >= obj_id_bytes:
                    entry_errs.append("Catalog entries are not strictly sorted in ascending ObjectId order")

                last_id_bytes = obj_id_bytes
                entries.append(
                    CatalogEntryInfo(
                        index=idx,
                        object_id=obj_id_hex,
                        kind=kind,
                        version=ver,
                        first_unit=e_first_unit,
                        byte_length=e_byte_len,
                        unit_count=e_unit_count,
                        flags=flags,
                        valid=(len(entry_errs) == 0),
                        error_reason="; ".join(entry_errs) if entry_errs else None,
                    )
                )
                if entry_errs:
                    errors.append(f"Entry {idx} invalid: {'; '.join(entry_errs)}")

        status = "VALID" if not errors else ("HASH_MISMATCH" if not id_matches else "MALFORMED")

        return CatalogInfo(
            first_unit=first_unit,
            byte_offset=byte_offset,
            status=status,
            calculated_id=calculated_id,
            referenced_id=referenced_id,
            id_matches=id_matches,
            entry_count=entry_count,
            entries=entries,
            error_reason="; ".join(errors) if errors else None,
        )

    def evaluate_recoverable_root(
        self,
        sb_a: SuperblockInfo,
        sb_b: SuperblockInfo,
    ) -> Tuple[RecoverableRootInfo, Optional[CommitRecordInfo], Optional[CatalogInfo]]:
        """
        Decision Oracle for ADR 0015 Store v1 recoverable root selection.

        Rules:
        - If both Superblocks are VALID:
          - If generations are equal and logical properties match -> CONSISTENT.
          - If generations are equal but properties mismatch -> CONFLICTING_ROOTS.
          - If generations differ -> try candidate with higher generation first.
            Verify candidate CommitRecord and Catalog on disk.
            If verified -> FORWARD_PROGRESS (select higher generation).
            If candidate commit or catalog is corrupt (e.g. crash during commit) ->
              Check if lower generation is fully intact -> RECOVERED_ROLLBACK (select lower generation).
        - If only one Superblock is VALID:
          - Verify its referenced CommitRecord and Catalog.
          - If verified -> select it.
        - If neither is valid or verification fails -> UNRECOVERABLE.
        """
        # Helper to verify a superblock's backing structures
        def verify_sb(sb: SuperblockInfo) -> Tuple[bool, Optional[CommitRecordInfo], Optional[CatalogInfo]]:
            if sb.status != "VALID" or sb.commit_record_unit is None or sb.catalog_first_unit is None:
                return False, None, None
            cmt = self.decode_commit_record(sb.commit_record_unit, sb.commit_record_id)
            if cmt.status != "VALID":
                return False, cmt, None
            cat = self.decode_catalog(
                sb.catalog_first_unit,
                sb.catalog_byte_length or 0,
                sb.catalog_unit_count or 0,
                sb.catalog_id,
                sb.committed_high_water_unit,
            )
            return (cat.status == "VALID"), cmt, cat

        a_valid = (sb_a.status == "VALID")
        b_valid = (sb_b.status == "VALID")

        if a_valid and b_valid:
            if sb_a.generation == sb_b.generation:
                # Compare logical equality
                fields_match = (
                    sb_a.region_units == sb_b.region_units
                    and sb_a.committed_high_water_unit == sb_b.committed_high_water_unit
                    and sb_a.commit_record_id == sb_b.commit_record_id
                    and sb_a.catalog_id == sb_b.catalog_id
                    and sb_a.store_uuid == sb_b.store_uuid
                )
                if fields_match:
                    ok, cmt, cat = verify_sb(sb_a)
                    if ok:
                        return (
                            RecoverableRootInfo(
                                selected_slot=0,
                                status="CONSISTENT",
                                generation=sb_a.generation,
                                committed_high_water_unit=sb_a.committed_high_water_unit,
                                commit_record_id=sb_a.commit_record_id,
                                commit_record_unit=sb_a.commit_record_unit,
                                catalog_id=sb_a.catalog_id,
                                catalog_entry_count=sb_a.catalog_entry_count,
                                published_manifest_id=cmt.published_manifest_id if cmt else None,
                                verified_commit=True,
                                verified_catalog=True,
                                rollback_occurred=False,
                                explanation="Both superblocks valid and consistent with identical generation",
                            ),
                            cmt,
                            cat,
                        )
                return (
                    RecoverableRootInfo(
                        selected_slot=None,
                        status="CONFLICTING_ROOTS",
                        generation=sb_a.generation,
                        committed_high_water_unit=None,
                        commit_record_id=None,
                        commit_record_unit=None,
                        catalog_id=None,
                        catalog_entry_count=None,
                        published_manifest_id=None,
                        verified_commit=False,
                        verified_catalog=False,
                        rollback_occurred=False,
                        explanation=f"Both superblocks valid at gen {sb_a.generation} but contain conflicting metadata",
                    ),
                    None,
                    None,
                )

            # Different generations: pick candidate with higher generation
            high_sb, low_sb = (sb_a, sb_b) if (sb_a.generation or 0) > (sb_b.generation or 0) else (sb_b, sb_a)
            high_ok, high_cmt, high_cat = verify_sb(high_sb)

            if high_ok:
                return (
                    RecoverableRootInfo(
                        selected_slot=high_sb.slot,
                        status="FORWARD_PROGRESS",
                        generation=high_sb.generation,
                        committed_high_water_unit=high_sb.committed_high_water_unit,
                        commit_record_id=high_sb.commit_record_id,
                        commit_record_unit=high_sb.commit_record_unit,
                        catalog_id=high_sb.catalog_id,
                        catalog_entry_count=high_sb.catalog_entry_count,
                        published_manifest_id=high_cmt.published_manifest_id if high_cmt else None,
                        verified_commit=True,
                        verified_catalog=True,
                        rollback_occurred=False,
                        explanation=f"Selected higher generation {high_sb.generation} (Slot {high_sb.slot}); commit and catalog verified",
                    ),
                    high_cmt,
                    high_cat,
                )

            # High generation failed verification! Fallback to lower generation
            low_ok, low_cmt, low_cat = verify_sb(low_sb)
            if low_ok:
                return (
                    RecoverableRootInfo(
                        selected_slot=low_sb.slot,
                        status="RECOVERED_ROLLBACK",
                        generation=low_sb.generation,
                        committed_high_water_unit=low_sb.committed_high_water_unit,
                        commit_record_id=low_sb.commit_record_id,
                        commit_record_unit=low_sb.commit_record_unit,
                        catalog_id=low_sb.catalog_id,
                        catalog_entry_count=low_sb.catalog_entry_count,
                        published_manifest_id=low_cmt.published_manifest_id if low_cmt else None,
                        verified_commit=True,
                        verified_catalog=True,
                        rollback_occurred=True,
                        explanation=f"Higher generation {high_sb.generation} corrupt; successfully rolled back to verified lower generation {low_sb.generation} (Slot {low_sb.slot})",
                    ),
                    low_cmt,
                    low_cat,
                )

        elif a_valid:
            a_ok, cmt, cat = verify_sb(sb_a)
            if a_ok:
                rollback = (sb_b.status != "UNFORMATTED")
                status = "RECOVERED_ROLLBACK" if rollback else "FORWARD_PROGRESS"
                return (
                    RecoverableRootInfo(
                        selected_slot=0,
                        status=status,
                        generation=sb_a.generation,
                        committed_high_water_unit=sb_a.committed_high_water_unit,
                        commit_record_id=sb_a.commit_record_id,
                        commit_record_unit=sb_a.commit_record_unit,
                        catalog_id=sb_a.catalog_id,
                        catalog_entry_count=sb_a.catalog_entry_count,
                        published_manifest_id=cmt.published_manifest_id if cmt else None,
                        verified_commit=True,
                        verified_catalog=True,
                        rollback_occurred=rollback,
                        explanation=f"Slot A is valid (gen {sb_a.generation}); Slot B is {sb_b.status}",
                    ),
                    cmt,
                    cat,
                )

        elif b_valid:
            b_ok, cmt, cat = verify_sb(sb_b)
            if b_ok:
                rollback = (sb_a.status != "UNFORMATTED")
                status = "RECOVERED_ROLLBACK" if rollback else "FORWARD_PROGRESS"
                return (
                    RecoverableRootInfo(
                        selected_slot=1,
                        status=status,
                        generation=sb_b.generation,
                        committed_high_water_unit=sb_b.committed_high_water_unit,
                        commit_record_id=sb_b.commit_record_id,
                        commit_record_unit=sb_b.commit_record_unit,
                        catalog_id=sb_b.catalog_id,
                        catalog_entry_count=sb_b.catalog_entry_count,
                        published_manifest_id=cmt.published_manifest_id if cmt else None,
                        verified_commit=True,
                        verified_catalog=True,
                        rollback_occurred=rollback,
                        explanation=f"Slot B is valid (gen {sb_b.generation}); Slot A is {sb_a.status}",
                    ),
                    cmt,
                    cat,
                )

        return (
            RecoverableRootInfo(
                selected_slot=None,
                status="UNRECOVERABLE",
                generation=None,
                committed_high_water_unit=None,
                commit_record_id=None,
                commit_record_unit=None,
                catalog_id=None,
                catalog_entry_count=None,
                published_manifest_id=None,
                verified_commit=False,
                verified_catalog=False,
                rollback_occurred=False,
                explanation=f"No valid recoverable root found (Slot A: {sb_a.status}, Slot B: {sb_b.status})",
            ),
            None,
            None,
        )

    def scan_block_units(
        self,
        max_units: Optional[int] = None,
        non_zero_only: bool = False,
    ) -> Tuple[Dict[str, Any], List[BlockUnitSummary]]:
        """Compute block-level sha256 digests, Shannon entropy, and classification."""
        units_to_scan = self.total_units if max_units is None else min(self.total_units, max_units)

        zero_count = 0
        entropies: List[float] = []
        block_summaries: List[BlockUnitSummary] = []

        all_zero_block = b"\x00" * self.unit_size
        zero_sha256 = hashlib.sha256(all_zero_block).hexdigest()

        for idx in range(units_to_scan):
            data = self.read_unit(idx)
            is_zero = (data == all_zero_block)

            if is_zero:
                zero_count += 1
                sha = zero_sha256
                ent = 0.0
                tag = "ZERO"
            else:
                sha = hashlib.sha256(data).hexdigest()
                ent = calculate_entropy(data)
                magic = data[:8]
                if magic == SUPERBLOCK_MAGIC:
                    tag = "SUPERBLOCK_CANDIDATE"
                elif magic == COMMIT_MAGIC:
                    tag = "COMMIT_CANDIDATE"
                elif magic == CATALOG_MAGIC:
                    tag = "CATALOG_CANDIDATE"
                elif magic == LEGACY_STORE_MAGIC:
                    tag = "LEGACY_STORE_CANDIDATE"
                elif magic == LEGACY_WAL_MAGIC:
                    tag = "LEGACY_WAL_CANDIDATE"
                else:
                    tag = "DATA_OR_METADATA"

            entropies.append(ent)
            summary = BlockUnitSummary(
                unit_index=idx,
                byte_offset=idx * self.unit_size,
                sha256=sha,
                entropy=ent,
                is_zero=is_zero,
                tag=tag,
            )

            if not non_zero_only or not is_zero:
                block_summaries.append(summary)

        stats = {
            "total_units_scanned": units_to_scan,
            "zero_units_count": zero_count,
            "non_zero_units_count": units_to_scan - zero_count,
            "min_entropy": min(entropies) if entropies else 0.0,
            "max_entropy": max(entropies) if entropies else 0.0,
            "mean_entropy": round(sum(entropies) / len(entropies), 4) if entropies else 0.0,
        }

        return stats, block_summaries

    def format_hex_dump(self, data: bytes, base_addr: int = 0) -> str:
        """Produce standard 16-bytes-per-line formatted hex dump with ASCII."""
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            hex_bytes = " ".join(f"{b:02x}" for b in chunk)
            ascii_chars = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{base_addr + i:08x}  {hex_bytes:<48}  |{ascii_chars}|")
        return "\n".join(lines)

    def full_inspection(
        self,
        include_block_table: bool = False,
        non_zero_only: bool = True,
        max_block_scan: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Perform full end-to-end read-only inspection and emit evidence-ready JSON."""
        partitions = self.inspect_partitions()

        sb_a = self.decode_superblock(0, self.slot_a_unit)
        sb_b = self.decode_superblock(1, self.slot_b_unit)

        root_info, active_commit, active_catalog = self.evaluate_recoverable_root(sb_a, sb_b)

        block_stats, block_summaries = self.scan_block_units(
            max_units=max_block_scan,
            non_zero_only=non_zero_only,
        )

        detected = (
            sb_a.status != "UNFORMATTED"
            or sb_b.status != "UNFORMATTED"
            or any(s.tag.startswith("SUPERBLOCK") for s in block_summaries)
        )

        # Build evidence JSON
        report: Dict[str, Any] = {
            "schema_version": "1.0.0",
            "tool": {
                "name": "aienos-store-inspector",
                "version": "0.1.0",
                "description": "Host-side read-only block image inspector and verification oracle",
            },
            "target_image": {
                "path": str(self.image_path.resolve()),
                "file_size_bytes": self.file_size,
                "unit_size_bytes": self.unit_size,
                "total_units": self.total_units,
                "base_offset": self.base_offset,
                "usable_length": self.usable_length,
            },
            "partitions": [asdict(p) for p in partitions],
            "store_v1": {
                "detected": detected,
                "slot_a": asdict(sb_a),
                "slot_b": asdict(sb_b),
                "selected_recoverable_root": asdict(root_info),
                "active_commit": asdict(active_commit) if active_commit else None,
                "active_catalog": asdict(active_catalog) if active_catalog else None,
            },
            "block_analysis": {
                "stats": block_stats,
            },
            "verdict": {
                "is_recoverable": (root_info.selected_slot is not None),
                "recovery_status": root_info.status,
                "selected_generation": root_info.generation,
                "rollback_occurred": root_info.rollback_occurred,
                "explanation": root_info.explanation,
            },
        }

        if include_block_table:
            report["block_analysis"]["blocks"] = [asdict(b) for b in block_summaries]

        return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Host-side read-only block image inspector for AIENOS crash/reboot qualification."
    )
    parser.add_argument("image", help="Path to raw block device or image file")
    parser.add_argument("--unit-size", type=int, default=STORE_UNIT_BYTES, help="Store unit size in bytes (default: 4096)")
    parser.add_argument("--sector-size", type=int, default=512, help="Sector size for partition detection (default: 512)")
    parser.add_argument("--offset", type=int, default=0, help="Base byte offset to begin inspection (default: 0)")
    parser.add_argument("--length", type=int, default=None, help="Length in bytes to inspect (default: full image)")
    parser.add_argument("--slot-a-unit", type=int, default=0, help="Unit index for Superblock Slot A (default: 0)")
    parser.add_argument("--slot-b-unit", type=int, default=1, help="Unit index for Superblock Slot B (default: 1)")
    parser.add_argument("--include-blocks", action="store_true", help="Include per-block unit details in JSON output")
    parser.add_argument("--all-blocks", action="store_true", help="Include zero blocks in block analysis table")
    parser.add_argument("--max-scan-units", type=int, default=None, help="Maximum units to scan for block statistics")
    parser.add_argument("--dump-unit", type=int, default=None, help="Dump hex view of specified unit index to stderr")
    parser.add_argument("--pretty", action="store_true", help="Format JSON with indentation")
    parser.add_argument("--output", "-o", default=None, help="Write JSON report to specified file path instead of stdout")
    parser.add_argument("--strict", action="store_true", help="Exit with code 1 if image is unrecoverable")

    args = parser.parse_args()

    try:
        inspector = StoreInspector(
            image_path=args.image,
            unit_size=args.unit_size,
            sector_size=args.sector_size,
            base_offset=args.offset,
            length=args.length,
            slot_a_unit=args.slot_a_unit,
            slot_b_unit=args.slot_b_unit,
        )

        if args.dump_unit is not None:
            data = inspector.read_unit(args.dump_unit)
            sys.stderr.write(f"=== Raw Dump: Unit {args.dump_unit} ({len(data)} bytes) ===\n")
            sys.stderr.write(inspector.format_hex_dump(data, args.dump_unit * args.unit_size))
            sys.stderr.write("\n")

        report = inspector.full_inspection(
            include_block_table=args.include_blocks,
            non_zero_only=not args.all_blocks,
            max_block_scan=args.max_scan_units,
        )

        indent = 2 if args.pretty else None
        json_output = json.dumps(report, indent=indent)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(json_output + "\n")
        else:
            print(json_output)

        if args.strict and not report["verdict"]["is_recoverable"]:
            return 1
        return 0

    except Exception as exc:
        sys.stderr.write(f"Error inspecting image: {exc}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
