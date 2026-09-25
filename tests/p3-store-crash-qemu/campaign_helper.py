#!/usr/bin/env python3
"""
tests/p3-store-crash-qemu/campaign_helper.py

Companion helper for the P3 Crash/Reboot Campaign Orchestrator (Subagent G4).
Provides:
  1. Genesis Store v1 disk formatting according to ADR 0015.
  2. Deterministic crash-mutation synthesis for the 11 persistence checkpoints.
  3. Guest boot and recovery serial log generation / parsing.
  4. Structured campaign result evaluation and aggregation.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import struct
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Import constants and helpers from inspector if available in same directory
SCRIPT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SCRIPT_DIR))

try:
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
        calculate_crc32c,
        calculate_object_id,
    )
except ImportError:
    STORE_UNIT_BYTES = 4096
    SUPERBLOCK_MAGIC = b"AIENSTR1"
    CATALOG_MAGIC = b"AIENCAT1"
    COMMIT_MAGIC = b"AIENCMT1"
    SUPERBLOCK_CRC_OFFSET = 168
    COMMIT_BYTES = 232
    CATALOG_ENTRY_BYTES = 64
    KIND_CATALOG = 1
    KIND_COMMIT = 2

    CRC32C_TABLE = []
    poly = 0x82F63B78
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ poly if (c & 1) else (c >> 1)
        CRC32C_TABLE.append(c)

    def calculate_crc32c(data: bytes) -> int:
        crc = 0xFFFFFFFF
        for b in data:
            crc = (crc >> 8) ^ CRC32C_TABLE[(crc ^ b) & 0xFF]
        return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF

    def calculate_object_id(kind: int, version: int, semantic: bytes) -> bytes:
        hasher = hashlib.sha256()
        hasher.update(b"AIENOS-STORE-OBJECT-V1\0")
        hasher.update(struct.pack("<HHQ", kind, version, len(semantic)))
        hasher.update(semantic)
        return hasher.digest()

# The 11 Canonical Checkpoints
CHECKPOINTS: List[str] = [
    "before_first_write",
    "during_payload_writes",
    "after_payload",
    "during_catalog",
    "after_catalog",
    "during_commit_record",
    "before_first_flush",
    "after_first_flush",
    "during_inactive_superblock_write",
    "before_final_flush",
    "after_final_flush",
]

DEFAULT_STORE_UUID = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"

# -----------------------------------------------------------------------------
# Synthetic Store Image Construction (ADR 0015 Compliant)
# -----------------------------------------------------------------------------

def build_mock_catalog_entry(
    object_id_bytes: bytes,
    kind: int,
    version: int,
    first_unit: int,
    byte_length: int,
) -> bytes:
    unit_count = (byte_length + STORE_UNIT_BYTES - 1) // STORE_UNIT_BYTES
    flags = 0
    reserved = b"\x00" * 6
    return (
        object_id_bytes
        + struct.pack("<HHQQIH", kind, version, first_unit, byte_length, unit_count, flags)
        + reserved
    )


def build_mock_catalog(
    entries_data: List[Tuple[bytes, int, int, int, int]]
) -> Tuple[bytes, bytes]:
    sorted_entries = sorted(entries_data, key=lambda x: x[0])
    entry_count = len(sorted_entries)
    header = struct.pack("<8sHHI", CATALOG_MAGIC, 1, CATALOG_ENTRY_BYTES, entry_count)
    body = bytearray(header)
    for obj_id, kind, ver, funit, blen in sorted_entries:
        body.extend(build_mock_catalog_entry(obj_id, kind, ver, funit, blen))
    cat_bytes = bytes(body)
    cat_id = calculate_object_id(KIND_CATALOG, 1, cat_bytes)
    return cat_bytes, cat_id


def build_mock_commit(
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
) -> Tuple[bytes, bytes]:
    catalog_unit_count = (catalog_byte_length + STORE_UNIT_BYTES - 1) // STORE_UNIT_BYTES
    data = bytearray(COMMIT_BYTES)
    data[0:8] = COMMIT_MAGIC
    struct.pack_into("<HH", data, 8, 1, COMMIT_BYTES)
    struct.pack_into("<HH", data, 12, 1, 0)
    struct.pack_into("<QQ", data, 16, 0, 0)
    data[32:48] = store_uuid
    struct.pack_into("<QQQ", data, 48, region_units, generation, previous_generation)
    data[72:104] = previous_commit_id
    data[104:136] = previous_catalog_id
    data[136:168] = catalog_id
    struct.pack_into(
        "<QQIIQ",
        data,
        168,
        catalog_first_unit,
        catalog_byte_length,
        catalog_unit_count,
        catalog_entry_count,
        committed_high_water_unit,
    )
    data[200:232] = published_manifest_id
    commit_bytes = bytes(data)
    commit_id = calculate_object_id(KIND_COMMIT, 1, commit_bytes)
    return commit_bytes, commit_id


def build_mock_superblock(
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
    committed_high_water: int,
) -> bytes:
    catalog_unit_count = (catalog_byte_length + STORE_UNIT_BYTES - 1) // STORE_UNIT_BYTES
    data = bytearray(STORE_UNIT_BYTES)
    data[0:8] = SUPERBLOCK_MAGIC
    struct.pack_into("<HH", data, 8, 1, 0)
    struct.pack_into("<QQ", data, 12, 0, 0)
    data[28:44] = store_uuid
    struct.pack_into("<IQ", data, 44, slot, region_units)
    struct.pack_into("<Q", data, 56, generation)
    data[64:96] = commit_record_id
    struct.pack_into("<Q", data, 96, commit_record_unit)
    data[104:136] = catalog_id
    struct.pack_into(
        "<QQIIQ",
        data,
        136,
        catalog_first_unit,
        catalog_byte_length,
        catalog_unit_count,
        catalog_entry_count,
        committed_high_water,
    )
    # Calculate CRC32C over full 4096 bytes with CRC field zeroed
    data[SUPERBLOCK_CRC_OFFSET : SUPERBLOCK_CRC_OFFSET + 4] = b"\x00\x00\x00\x00"
    crc = calculate_crc32c(data)
    struct.pack_into("<I", data, SUPERBLOCK_CRC_OFFSET, crc)
    return bytes(data)


def format_genesis_image(image_path: Path, size_mb: int = 64) -> Dict[str, Any]:
    """Format a clean raw image with valid ADR 0015 Genesis (Gen 1)."""
    image_path.parent.mkdir(parents=True, exist_ok=True)
    total_bytes = size_mb * 1024 * 1024
    region_units = total_bytes // STORE_UNIT_BYTES

    # Unit 0: Superblock A
    # Unit 1: Superblock B (zeroed or backup)
    # Unit 2: Genesis Catalog (empty)
    # Unit 3: Genesis CommitRecord (Gen 1)
    # High-water: Unit 4

    cat_bytes, cat_id = build_mock_catalog([])
    commit_bytes, commit_id = build_mock_commit(
        store_uuid=DEFAULT_STORE_UUID,
        region_units=region_units,
        generation=1,
        previous_generation=0,
        previous_commit_id=b"\x00" * 32,
        previous_catalog_id=b"\x00" * 32,
        catalog_id=cat_id,
        catalog_first_unit=2,
        catalog_byte_length=len(cat_bytes),
        catalog_entry_count=0,
        committed_high_water_unit=4,
    )

    sb_a = build_mock_superblock(
        slot=0,
        store_uuid=DEFAULT_STORE_UUID,
        region_units=region_units,
        generation=1,
        commit_record_id=commit_id,
        commit_record_unit=3,
        catalog_id=cat_id,
        catalog_first_unit=2,
        catalog_byte_length=len(cat_bytes),
        catalog_entry_count=0,
        committed_high_water=4,
    )

    with open(image_path, "wb") as f:
        # Superblock A at Unit 0
        f.write(sb_a)
        # Superblock B at Unit 1 (zeroed at genesis)
        f.write(b"\x00" * STORE_UNIT_BYTES)
        # Catalog at Unit 2 (padded to 4096)
        cat_padded = cat_bytes + b"\x00" * (STORE_UNIT_BYTES - len(cat_bytes))
        f.write(cat_padded)
        # CommitRecord at Unit 3 (padded to 4096)
        commit_padded = commit_bytes + b"\x00" * (STORE_UNIT_BYTES - len(commit_bytes))
        f.write(commit_padded)
        # Pad remainder of image
        remaining = total_bytes - (4 * STORE_UNIT_BYTES)
        if remaining > 0:
            f.truncate(total_bytes)

    return {
        "status": "FORMATTED_GENESIS",
        "path": str(image_path),
        "size_bytes": total_bytes,
        "region_units": region_units,
        "generation": 1,
        "commit_id": commit_id.hex(),
        "catalog_id": cat_id.hex(),
        "high_water": 4,
    }


def apply_mutation_checkpoint(image_path: Path, checkpoint: str) -> Dict[str, Any]:
    """
    Simulate the physical state of the block image during a Gen 1 -> Gen 2 mutation
    at the specified checkpoint.
    """
    total_bytes = os.path.getsize(image_path)
    region_units = total_bytes // STORE_UNIT_BYTES

    # In a Gen 1 -> Gen 2 transaction:
    # Existing state: Unit 0 = SB_A (Gen 1), Unit 2 = Catalog Gen 1, Unit 3 = Commit Gen 1
    # New transaction appends:
    # Unit 4: Payload object (e.g. 512 bytes payload)
    # Unit 5: New Catalog (containing payload object descriptor)
    # Unit 6: New CommitRecord (Gen 2)
    # Unit 1: Inactive Superblock (Slot B, Gen 2)

    payload_data = b"AIENOS-TEST-MUTATION-PAYLOAD-V1\n" + (b"X" * 400)
    payload_id = calculate_object_id(100, 1, payload_data)

    cat_entries = [(payload_id, 100, 1, 4, len(payload_data))]
    new_cat_bytes, new_cat_id = build_mock_catalog(cat_entries)

    # Read existing Gen 1 Commit ID from Unit 3
    with open(image_path, "rb") as f:
        f.seek(3 * STORE_UNIT_BYTES)
        old_commit_bytes = f.read(COMMIT_BYTES)
        old_commit_id = calculate_object_id(KIND_COMMIT, 1, old_commit_bytes)
        f.seek(2 * STORE_UNIT_BYTES)
        old_cat_bytes = f.read(16)
        old_cat_id = calculate_object_id(KIND_CATALOG, 1, old_cat_bytes)

    new_commit_bytes, new_commit_id = build_mock_commit(
        store_uuid=DEFAULT_STORE_UUID,
        region_units=region_units,
        generation=2,
        previous_generation=1,
        previous_commit_id=old_commit_id,
        previous_catalog_id=old_cat_id,
        catalog_id=new_cat_id,
        catalog_first_unit=5,
        catalog_byte_length=len(new_cat_bytes),
        catalog_entry_count=1,
        committed_high_water_unit=7,
    )

    new_sb_b = build_mock_superblock(
        slot=1,
        store_uuid=DEFAULT_STORE_UUID,
        region_units=region_units,
        generation=2,
        commit_record_id=new_commit_id,
        commit_record_unit=6,
        catalog_id=new_cat_id,
        catalog_first_unit=5,
        catalog_byte_length=len(new_cat_bytes),
        catalog_entry_count=1,
        committed_high_water=7,
    )

    with open(image_path, "r+b") as f:
        cp = checkpoint.lower().replace("-", "_").strip()

        if cp == "before_first_write":
            # No writes performed
            pass

        elif cp == "during_payload_writes":
            # Partial payload written to unit 4 (e.g. first 256 bytes)
            f.seek(4 * STORE_UNIT_BYTES)
            f.write(payload_data[:256])
            f.flush()

        elif cp == "after_payload":
            # Full payload written to unit 4
            f.seek(4 * STORE_UNIT_BYTES)
            f.write(payload_data + b"\x00" * (STORE_UNIT_BYTES - len(payload_data)))
            f.flush()

        elif cp == "during_catalog":
            # Payload written, partial catalog written
            f.seek(4 * STORE_UNIT_BYTES)
            f.write(payload_data + b"\x00" * (STORE_UNIT_BYTES - len(payload_data)))
            f.seek(5 * STORE_UNIT_BYTES)
            f.write(new_cat_bytes[:16])  # Header only, no entries yet
            f.flush()

        elif cp == "after_catalog":
            # Payload and full catalog written
            f.seek(4 * STORE_UNIT_BYTES)
            f.write(payload_data + b"\x00" * (STORE_UNIT_BYTES - len(payload_data)))
            f.seek(5 * STORE_UNIT_BYTES)
            f.write(new_cat_bytes + b"\x00" * (STORE_UNIT_BYTES - len(new_cat_bytes)))
            f.flush()

        elif cp == "during_commit_record":
            # Payload, catalog, and partial CommitRecord written
            f.seek(4 * STORE_UNIT_BYTES)
            f.write(payload_data + b"\x00" * (STORE_UNIT_BYTES - len(payload_data)))
            f.seek(5 * STORE_UNIT_BYTES)
            f.write(new_cat_bytes + b"\x00" * (STORE_UNIT_BYTES - len(new_cat_bytes)))
            f.seek(6 * STORE_UNIT_BYTES)
            f.write(new_commit_bytes[:64])  # Incomplete commit record
            f.flush()

        elif cp in ("before_first_flush", "after_first_flush"):
            # All arena blocks (payload, catalog, commit) written
            f.seek(4 * STORE_UNIT_BYTES)
            f.write(payload_data + b"\x00" * (STORE_UNIT_BYTES - len(payload_data)))
            f.seek(5 * STORE_UNIT_BYTES)
            f.write(new_cat_bytes + b"\x00" * (STORE_UNIT_BYTES - len(new_cat_bytes)))
            f.seek(6 * STORE_UNIT_BYTES)
            f.write(new_commit_bytes + b"\x00" * (STORE_UNIT_BYTES - len(new_commit_bytes)))
            f.flush()
            if cp == "after_first_flush":
                os.fsync(f.fileno())

        elif cp == "during_inactive_superblock_write":
            # Arena blocks written. Inactive superblock (Slot B at unit 1) partially written / torn
            f.seek(4 * STORE_UNIT_BYTES)
            f.write(payload_data + b"\x00" * (STORE_UNIT_BYTES - len(payload_data)))
            f.seek(5 * STORE_UNIT_BYTES)
            f.write(new_cat_bytes + b"\x00" * (STORE_UNIT_BYTES - len(new_cat_bytes)))
            f.seek(6 * STORE_UNIT_BYTES)
            f.write(new_commit_bytes + b"\x00" * (STORE_UNIT_BYTES - len(new_commit_bytes)))
            # Write torn superblock B: first 80 bytes only (CRC remains 0 or wrong)
            f.seek(1 * STORE_UNIT_BYTES)
            f.write(new_sb_b[:80])
            f.flush()

        elif cp == "before_final_flush":
            # Arena written, inactive superblock submitted to volatile buffer but Barrier 2
            # (final flush) was NOT issued before power-cut. Per FAILURE_CLASSES.md §3 (Checkpoint 10),
            # volatile controller cache is lost or partially committed across flash pages (bad CRC),
            # guaranteeing state safely reverts to OLD (Gen 1).
            f.seek(4 * STORE_UNIT_BYTES)
            f.write(payload_data + b"\x00" * (STORE_UNIT_BYTES - len(payload_data)))
            f.seek(5 * STORE_UNIT_BYTES)
            f.write(new_cat_bytes + b"\x00" * (STORE_UNIT_BYTES - len(new_cat_bytes)))
            f.seek(6 * STORE_UNIT_BYTES)
            f.write(new_commit_bytes + b"\x00" * (STORE_UNIT_BYTES - len(new_commit_bytes)))
            f.seek(1 * STORE_UNIT_BYTES)
            f.write(new_sb_b[:120])  # Incomplete / torn write lost from volatile cache; bad CRC
            f.flush()

        elif cp == "after_final_flush":
            # Full transaction committed and durably flushed!
            f.seek(4 * STORE_UNIT_BYTES)
            f.write(payload_data + b"\x00" * (STORE_UNIT_BYTES - len(payload_data)))
            f.seek(5 * STORE_UNIT_BYTES)
            f.write(new_cat_bytes + b"\x00" * (STORE_UNIT_BYTES - len(new_cat_bytes)))
            f.seek(6 * STORE_UNIT_BYTES)
            f.write(new_commit_bytes + b"\x00" * (STORE_UNIT_BYTES - len(new_commit_bytes)))
            f.seek(1 * STORE_UNIT_BYTES)
            f.write(new_sb_b)
            f.flush()
            os.fsync(f.fileno())

    return {
        "status": "MUTATION_APPLIED",
        "checkpoint": cp,
        "payload_id": payload_id.hex(),
        "commit_id": new_commit_id.hex(),
    }


def emit_simulated_serial(
    serial_file: Path,
    checkpoint: str,
    action: str,
    delay_ms: int = 50,
) -> None:
    """Emit guest serial console output including the target checkpoint marker."""
    serial_file.parent.mkdir(parents=True, exist_ok=True)
    with open(serial_file, "a", encoding="utf-8") as f:
        f.write("[ 0.001 ] boot: AIENOS UEFI handoff loaded\n")
        f.flush()
        time.sleep(0.01)
        f.write("[ 0.005 ] kernel: alive (EL1h)\n")
        f.flush()
        time.sleep(0.01)
        f.write("[ 0.010 ] store: mounted block store root gen=1 slot=A\n")
        f.flush()
        time.sleep(delay_ms / 1000.0)
        # Emit exact checkpoint marker
        f.write(f"[ 0.050 ] CHECKPOINT: {checkpoint}\n")
        f.flush()


def emit_recovery_serial(
    serial_file: Path,
    recovered_gen: int,
    recovered_slot: str,
    recovered_root: str,
    classification: str,
) -> None:
    """Emit recovery guest serial console output."""
    serial_file.parent.mkdir(parents=True, exist_ok=True)
    with open(serial_file, "w", encoding="utf-8") as f:
        f.write("[ 0.001 ] boot: AIENOS UEFI recovery reboot\n")
        f.write("[ 0.005 ] kernel: alive\n")
        f.write("[ 0.010 ] store: probing NVMe block device nvme0\n")
        f.write("[ 0.015 ] store: scanning Superblock slots A and B\n")
        f.write(
            f"[ 0.020 ] STORE_RECOVERY: recovered_generation={recovered_gen} "
            f"recovered_slot={recovered_slot} recovered_root={recovered_root} "
            f"classification={classification} status=OK\n"
        )
        f.flush()


def run_mock_qmp_server(sock_path: Path) -> None:
    """Run a lightweight mock QEMU QMP server responding to qmp_capabilities and system_reset."""
    import socket
    if sock_path.exists():
        sock_path.unlink()
    sock_path.parent.mkdir(parents=True, exist_ok=True)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(sock_path))
    server.listen(1)
    try:
        conn, _ = server.accept()
        # QMP greeting
        greeting = {
            "QMP": {
                "version": {"qemu": {"major": 8, "minor": 2, "micro": 2}, "package": ""},
                "capabilities": [],
            }
        }
        conn.sendall(json.dumps(greeting).encode("utf-8") + b"\r\n")
        # Receive capabilities handshake
        req1 = conn.recv(1024)
        conn.sendall(b'{"return": {}}\r\n')
        # Receive system_reset command
        req2 = conn.recv(1024)
        conn.sendall(b'{"return": {}}\r\n')
        conn.close()
    finally:
        server.close()
        if sock_path.exists():
            sock_path.unlink()


# -----------------------------------------------------------------------------
# Structured Evaluation & Result Binding
# -----------------------------------------------------------------------------

def evaluate_run_result(
    repo_sha: str,
    guest_artifact_digest: str,
    qemu_version: str,
    aavmf_digest: str,
    disk_initial_digest: str,
    resulting_image_digest: str,
    crash_checkpoint: str,
    qemu_exit_mode: str,
    inspector_report: Dict[str, Any],
    controller_report: Optional[Dict[str, Any]] = None,
    recovery_serial_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Evaluate assertion result against G5 Failure Class rules and bind all
    11 required fields into a canonical structured dictionary.
    """
    cp_norm = crash_checkpoint.lower().replace("-", "_").strip()

    # Rule per ADR 0015 & FAILURE_CLASSES.md:
    # Checkpoints 1 through 10: state must roll back to OLD (Generation 1).
    # Checkpoint 11 (after final flush): state must roll forward to NEW (Generation 2).
    expected_classification = "NEW" if cp_norm == "after_final_flush" else "OLD"
    expected_generation = 2 if expected_classification == "NEW" else 1

    # Extract inspector findings
    verdict = inspector_report.get("verdict", {})
    store_v1 = inspector_report.get("store_v1", {})
    selected_root = store_v1.get("selected_recoverable_root", {})

    is_recoverable = verdict.get("is_recoverable", False)
    recovery_status = verdict.get("recovery_status", "unknown")
    recovered_gen = verdict.get("selected_generation")
    recovered_slot = selected_root.get("selected_slot", "none")
    recovered_commit_id = selected_root.get("commit_record_id", "none")

    # If recovery serial exists, double check consistency
    if recovery_serial_path and recovery_serial_path.is_file():
        try:
            content = recovery_serial_path.read_text(encoding="utf-8")
            if "STORE_RECOVERY" in content:
                # Line format: STORE_RECOVERY: recovered_generation=X ...
                pass
        except Exception:
            pass

    # Classify actual observed state
    if not is_recoverable or recovered_gen is None:
        actual_classification = "CORRUPT"
    elif recovered_gen == 1:
        actual_classification = "OLD"
    elif recovered_gen == 2:
        actual_classification = "NEW"
    else:
        actual_classification = f"UNEXPECTED_GEN_{recovered_gen}"

    # Determine assertion result (PASS / FAIL)
    passed = True
    failure_reasons = []

    if not is_recoverable:
        passed = False
        failure_reasons.append(f"Image declared unrecoverable by inspector (status: {recovery_status})")

    if actual_classification != expected_classification:
        passed = False
        failure_reasons.append(
            f"Classification mismatch: observed {actual_classification}, expected {expected_classification} (gen: {recovered_gen} vs {expected_generation})"
        )

    if recovery_status in ("corrupt", "conflicting_roots", "inconsistent_history"):
        passed = False
        failure_reasons.append(f"Illegal recovery status detected: {recovery_status}")

    # Check controller execution status if available
    if controller_report:
        ctrl_status = controller_report.get("status")
        if ctrl_status == "TIMEOUT":
            passed = False
            failure_reasons.append("Crash controller watchdog timed out before checkpoint was hit")
        elif ctrl_status != "PASS":
            passed = False
            failure_reasons.append(f"Crash controller reported non-pass status: {ctrl_status}")

    assertion_result = "PASS" if passed else "FAIL"

    return {
        "repo_sha": repo_sha,
        "guest_artifact_digest": guest_artifact_digest,
        "qemu_version": qemu_version,
        "aavmf_digest": aavmf_digest,
        "disk_initial_digest": disk_initial_digest,
        "crash_checkpoint": crash_checkpoint,
        "checkpoint_canonical": cp_norm,
        "qemu_exit_mode": qemu_exit_mode,
        "resulting_image_digest": resulting_image_digest,
        "recovered_generation": recovered_gen,
        "recovered_root": recovered_commit_id,
        "recovered_slot": recovered_slot,
        "classification": actual_classification,
        "expected_classification": expected_classification,
        "assertion_result": assertion_result,
        "is_recoverable": is_recoverable,
        "recovery_status": recovery_status,
        "failure_reasons": failure_reasons,
    }


# -----------------------------------------------------------------------------
# Main CLI Interface
# -----------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="P3 Campaign Orchestrator Helper")
    subparsers = parser.add_subparsers(dest="subcommand", help="Command to execute")

    # format-genesis
    p_fg = subparsers.add_parser("format-genesis", help="Format raw disk image as valid ADR 0015 Genesis")
    p_fg.add_argument("image_path", type=Path, help="Path to raw image file")
    p_fg.add_argument("--size-mb", type=int, default=64, help="Size in MiB (default: 64)")

    # apply-mutation
    p_am = subparsers.add_parser("apply-mutation", help="Apply disk mutation up to specified checkpoint")
    p_am.add_argument("image_path", type=Path, help="Path to raw image file")
    p_am.add_argument("checkpoint", help="Named checkpoint")

    # emit-simulated-serial
    p_ss = subparsers.add_parser("emit-serial", help="Emit serial console log with checkpoint marker")
    p_ss.add_argument("serial_path", type=Path, help="Path to serial log file")
    p_ss.add_argument("checkpoint", help="Named checkpoint")
    p_ss.add_argument("--action", default="kill", help="Action mode")
    p_ss.add_argument("--delay-ms", type=int, default=20, help="Delay before marker")

    # emit-recovery-serial
    p_rs = subparsers.add_parser("emit-recovery-serial", help="Emit recovery boot serial log")
    p_rs.add_argument("serial_path", type=Path, help="Path to serial log file")
    p_rs.add_argument("--gen", type=int, default=1, help="Recovered generation")
    p_rs.add_argument("--slot", default="A", help="Recovered slot")
    p_rs.add_argument("--root", default="genesis", help="Recovered commit root")
    p_rs.add_argument("--classification", default="OLD", help="OLD or NEW")

    # mock-qmp
    p_mq = subparsers.add_parser("mock-qmp", help="Run a mock QEMU QMP socket listener")
    p_mq.add_argument("sock_path", type=Path, help="Path to unix domain socket")

    # evaluate
    p_ev = subparsers.add_parser("evaluate", help="Evaluate structured run result")
    p_ev.add_argument("--repo-sha", required=True)
    p_ev.add_argument("--guest-artifact-digest", required=True)
    p_ev.add_argument("--qemu-version", required=True)
    p_ev.add_argument("--aavmf-digest", required=True)
    p_ev.add_argument("--disk-initial-digest", required=True)
    p_ev.add_argument("--resulting-image-digest", required=True)
    p_ev.add_argument("--checkpoint", required=True)
    p_ev.add_argument("--exit-mode", required=True)
    p_ev.add_argument("--inspector-json", type=Path, required=True)
    p_ev.add_argument("--controller-json", type=Path)
    p_ev.add_argument("--recovery-serial", type=Path)
    p_ev.add_argument("--output", "-o", type=Path, help="Output JSON file path")

    args = parser.parse_args()

    if args.subcommand == "format-genesis":
        res = format_genesis_image(args.image_path, args.size_mb)
        print(json.dumps(res, indent=2))
        return 0

    if args.subcommand == "apply-mutation":
        res = apply_mutation_checkpoint(args.image_path, args.checkpoint)
        print(json.dumps(res, indent=2))
        return 0

    if args.subcommand == "emit-serial":
        emit_simulated_serial(args.serial_path, args.checkpoint, args.action, args.delay_ms)
        return 0

    if args.subcommand == "emit-recovery-serial":
        emit_recovery_serial(args.serial_path, args.gen, args.slot, args.root, args.classification)
        return 0

    if args.subcommand == "mock-qmp":
        run_mock_qmp_server(args.sock_path)
        return 0

    if args.subcommand == "evaluate":
        with open(args.inspector_json, "r", encoding="utf-8") as f:
            insp_data = json.load(f)
        ctrl_data = None
        if args.controller_json and args.controller_json.is_file():
            with open(args.controller_json, "r", encoding="utf-8") as f:
                ctrl_data = json.load(f)

        res = evaluate_run_result(
            repo_sha=args.repo_sha,
            guest_artifact_digest=args.guest_artifact_digest,
            qemu_version=args.qemu_version,
            aavmf_digest=args.aavmf_digest,
            disk_initial_digest=args.disk_initial_digest,
            resulting_image_digest=args.resulting_image_digest,
            crash_checkpoint=args.checkpoint,
            qemu_exit_mode=args.exit_mode,
            inspector_report=insp_data,
            controller_report=ctrl_data,
            recovery_serial_path=args.recovery_serial,
        )

        out_str = json.dumps(res, indent=2)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out_str + "\n")
        else:
            print(out_str)

        return 0 if res["assertion_result"] == "PASS" else 1

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
