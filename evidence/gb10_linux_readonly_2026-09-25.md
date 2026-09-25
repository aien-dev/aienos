# GB10 read-only characterization evidence (2026-09-25)

This report records what is known about the Machine 1 GB10 after the read-only
characterization phase. It separates observation classes explicitly. A Linux
observation is never written as a native AIENOS proof, and no emulator result
is written as GB10 hardware behaviour.

Governing: issue [#36](https://github.com/aien-dev/aienos/issues/36),
[GB10_HARDWARE_PROFILE.md](../docs/GB10_HARDWARE_PROFILE.md),
[GB10_PLATFORM_TOPOLOGY.md](../docs/GB10_PLATFORM_TOPOLOGY.md),
[GB10_HARDWARE_QUALIFICATION.md](../docs/GB10_HARDWARE_QUALIFICATION.md).

## Artifacts

| Artifact | SHA-256 |
| --- | --- |
| `evidence/gb10_linux_profile_2026-09-25.json` | `774e342a979ea9a514f5a2c1f5f7551ae6620af1331b73ba00a5d156ec553605` |
| `evidence/gb10_linux_report_2026-09-25.txt` | `71eb09a2f508e8c8d43031a5ddb500ad3362dc0f39d98d0d46015b21338b2d3e` |

Collection: `bash scripts/gb10_profile.sh --allow-sudo`, read-only, on
Machine 1 (`NVIDIA_DGX_Spark`), at 2026-09-25T11:58:06Z. The collector used the
documented `sudo -n` reads for the 256-byte configuration space and the ACPI
table copies only. It performed no write.

## 1. Linux-observed facts

Source: `scripts/gb10_profile.sh`, reading sysfs, a 256-byte raw configuration
read decoded by this project, and ACPI table copies. These are Linux
observations. None of them is a native AIENOS proof.

| Fact | Value |
| --- | --- |
| Device | NVIDIA `0x10de:0x2e12` at `000f:01:00.0` |
| Location | segment 15, bus 1, device 0, function 0 |
| Subsystem | `0x10de:0x0000` |
| Class / revision | `0x030000` / `0xa1` |
| Command / status | `0x0407` / `0x0010` (raw config, decoded here) |
| BAR0 | 64-bit prefetchable memory, base `0x24000000`, size 64 MiB |
| Capabilities | PM `0x40`, MSI `0x48`, PCIe `0x60`, vendor `0x9c`, MSI-X `0xb0` |
| PCIe link | current 2.5 GT/s x1, max 2.5 GT/s x16, max payload 256 bytes |
| MSI | present, disabled, 64-bit capable, maskable, 16 vectors |
| MSI-X | enabled, 9 table entries, table BAR0 offset `0xb90000`, PBA BAR0 offset `0xba0000` |
| IOMMU group | 20 (the GB10 alone) |
| NUMA node | `-1` (not exposed) |
| Kernel driver | `nvidia` |
| Firmware node | `.../PNP0A08:0b/device:1b/device:1c` |
| Legacy IRQ | 427 |
| `msi_irqs` entries | 8 (429 to 436) |
| MCFG | 16 segments; segment 15 ECAM `0x29000000`, buses 0 to 1 |
| IORT | present, 3904 bytes |
| ACPI hashes | recorded in the profile `acpi_tables` array |

Every field in the JSON records its source, its collection method, whether
Linux interpreted the value, and `native_verified: false`.

## 2. UEFI-observed facts

Source: the `aienos-handoff` UEFI image.

- On the M2 first native boot (commit `52109bcb334a95bdd33410b4d22c59dee8c917f4`,
  image SHA-256 `79505373088d2464b82181c06f07e18e20e4e9b2b55dbc9fc46e3f0a2e2e3ada`),
  the pre-exit GB10 discovery found no match and reported `gb10: unavailable`,
  even though Linux sees `10de:2e12` at `000f:01:00.0`. No PMC value was read
  through the UEFI path on that boot. See
  [m2_first_boot_2026-09-24.md](m2_first_boot_2026-09-24.md).
- The updated multi-root, bus-range discovery path at baseline
  `71cb1703484cbc9d56eabe43402a6f9bf62b1028` has been built but not booted on
  hardware. Its UEFI observations are therefore unqualified. See
  [GB10_NATIVE_STATUS.md](../docs/GB10_NATIVE_STATUS.md).

## 3. Native-AIENOS-observed facts

There are none for the GB10. No native AIENOS path has observed any GB10
property on hardware.

The only native AIENOS observations from the M2 boot are CPU, exception level,
and memory map facts, not GB10 facts. The register ledger records both PMC
registers as `native_observed: false`.

## 4. QEMU and synthetic-test facts

Source: `crates/aienos-accel/tests/gb10_fixtures.rs` and the unit tests in
`crates/aienos-accel/src/pci.rs`.

The synthetic fixtures prove the decoders and the discovery contract, not GB10
hardware behaviour:

- a valid GB10-like 64-bit BAR layout is accepted;
- a 32-bit BAR0 is rejected as `Bar0Not64Bit`;
- disabled memory decoding is rejected as `MemoryDecodeDisabled`;
- an unprogrammed BAR0 is rejected as `Bar0Missing` or `Bar0Unprogrammed`;
- malformed capability lists, loops, and out-of-bounds pointers are rejected;
- multiple NVIDIA devices resolve to the GB10 by property;
- a correct device behind a secondary bus is reached through a bridge window;
- the GB10 matches under BDF relocation, proving discovery is property-based;
- missing MSI or MSI-X is reported as absent, not as zero;
- large BAR arithmetic and bounds are checked.

These are QEMU or in-memory test facts and are not GB10 hardware facts.

## 5. Inferred and derived relationships

- The GB10's path from MCFG segment 15 ECAM at `0x29000000`, through root
  bridge `000f:00:00.0`, to endpoint `000f:01:00.0` is derived from the
  observed segment, bus, and MCFG window. It is a consistent path, not a
  separately observed transaction.
- The ECAM configuration address for `000f:01:00.0` (`0x29000000 + 0x100000`)
  is derived from the MCFG base and bus, not read from that address.
- BAR0 being large enough for PMC offsets 0 and `0x0a00` is derived from the
  observed 64 MiB size.

## 6. Unresolved unknowns

- The IORT stream ID and SMMUv3 stream table entry for the GB10.
- The disposition of the ninth MSI-X vector (table reports 9, `msi_irqs`
  exposes 8).
- The dynamic PCIe link state. Kernel boot logged an x0 link at
  `000f:00:00.0`; sysfs later read x1 against a maximum of x16. The negotiated
  state is recorded as observed, not explained.
- The PMC `BOOT_0` and `BOOT_42` values and their meaning. Reading them
  natively or through Linux is out of scope for this phase.
- Any GPU behaviour. GSP ownership, GPU initialization, command submission,
  GPU DMA readiness, native Blackwell execution, and native inference are not
  claimed by this phase.
