#!/usr/bin/env python3
"""Check the built image has an AArch64 EFI application PE header."""

from pathlib import Path
import struct
import sys


def verify(path):
    data = Path(path).read_bytes()
    if len(data) < 0x100 or data[:2] != b"MZ":
        raise ValueError("missing DOS image header")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 4 + 20 + 70 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        raise ValueError("missing PE header")
    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    optional_header = pe_offset + 4 + 20
    magic = struct.unpack_from("<H", data, optional_header)[0]
    subsystem = struct.unpack_from("<H", data, optional_header + 68)[0]
    if (machine, magic, subsystem) != (0xAA64, 0x20B, 10):
        raise ValueError(f"unexpected machine/PE/subsystem: {machine:#x}/{magic:#x}/{subsystem}")
    print(f"AArch64 PE32+ EFI application verified: {path}")


if __name__ == "__main__":
    try:
        verify(sys.argv[1])
    except (IndexError, OSError, ValueError) as error:
        raise SystemExit(f"UEFI image verification failed: {error}") from error
