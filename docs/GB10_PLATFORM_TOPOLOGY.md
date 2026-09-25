# GB10 platform topology and discovery cross-check

This document maps the physical interfaces that reach the GB10 on Machine 1,
and compares them against what the existing AIENOS UEFI discovery path already
assumes. It is a Linux and firmware observation exercise. It does not
initialize the GPU or submit a command.

Governing: issue [#36](https://github.com/aien-dev/aienos/issues/36),
[GB10_HARDWARE_PROFILE.md](GB10_HARDWARE_PROFILE.md),
[GB10_NATIVE_STATUS.md](GB10_NATIVE_STATUS.md).

All values below are Linux observed (sysfs and ACPI tables read read-only) on
the current Machine 1 Linux boot. They are not native AIENOS observations.

## Observed platform path

```
ACPI MCFG segment 15
        |
        v
PCI root bridge 000f:00:00.0   (ACPI PNP0A08:0b)
        |
        v
GB10 endpoint 000f:01:00.0     (ACPI device, firmware_node
                                .../PNP0A08:0b/device:1b/device:1c)
```

| Item | Observed value | Source |
| --- | --- | --- |
| ACPI root bridge path | `PNP0A08:0b` | `firmware_node` sysfs, Linux |
| Root bridge function | `000f:00:00.0`, class `0x060400` | sysfs, Linux |
| GB10 endpoint | `000f:01:00.0` | sysfs, Linux |
| Segment / domain | 15 (`0x000f`) | sysfs path, Linux |
| Bus / device / function | 1 / 0 / 0 | sysfs path, Linux |
| Vendor / device | `0x10de` / `0x2e12` | config, Linux |
| Subsystem | `0x10de:0x0000` | config, Linux |
| Class / revision | `0x030000` display controller / `0xa1` | config, Linux |
| Command / status | `0x0407` / `0x0010` | raw config, decoded by this project |
| BAR0 | 64-bit prefetchable memory at `0x24000000`, 64 MiB | `resource`, Linux |
| IOMMU group | 20 (only `000f:01:00.0`) | sysfs, Linux |
| NUMA node | `-1` (not exposed) | sysfs, Linux |
| Kernel driver | `nvidia` | sysfs, Linux |
| Legacy IRQ | 427 | sysfs, Linux |
| MSI-X vectors | 9 (table), 8 exposed in `msi_irqs` | config, sysfs, Linux |
| PCIe link | current 2.5 GT/s x1, max 2.5 GT/s x16 | sysfs and config, Linux |

## ACPI MCFG / ECAM

The MCFG table is 300 bytes and declares 16 PCI segments, each with an ECAM
window and bus range. Segments 0 to 14 use base `0xF300000000` plus a
`0x10000000` stride and cover buses 0 to 15. Segment 15, the GB10 segment, has
ECAM base `0x29000000` and covers buses 0 to 1:

| Segment | ECAM base | Bus range |
| --- | --- | --- |
| 0 to 10 | `0xF300000000` to `0xF3A0000000` | 0 to 15 |
| 11 to 14 | `0xF3B0000000` to `0xF3E0000000` | 0 to 255 |
| 15 (GB10) | `0x29000000` | 0 to 1 |

The GB10 is on segment 15 bus 1, inside the declared window. A native AIENOS
ECAM mapper would compute the configuration address as
`ecam_base + (bus - start_bus) * 1 MiB + device * 32 KiB + function * 4 KiB`,
so `000f:01:00.0` maps to `0x29000000 + 0x100000`.

Provenance: `MCFG` ACPI table, parsed read-only by
`scripts/gb10_profile.sh`; SHA-256 recorded in the evidence JSON.

## IORT / SMMUv3

The IORT table is present (3904 bytes). The kernel reports an Arm SMMUv3 with
40-bit output address size, a 2-level stream table covering 25 of 32 stream ID
bits, and a default DMA domain type of Translated (`iommu.passthrough=0`). The
GB10 sits alone in IOMMU group 20, so its stream is isolated from every other
endpoint in the observed group listing.

Provenance: `IORT` ACPI table presence and size, kernel command line, and the
kernel IOMMU group layout, all Linux observed. The IORT stream-to-SID mapping
for the GB10 is not yet decoded by this project, and is listed as an unknown
below.

## Interrupt topology

The GB10 exposes one legacy interrupt (427) and an enabled MSI-X capability
with a 9-entry vector table at BAR0 offset `0x00b90000` and a PBA at BAR0
offset `0x00ba0000`, both in BAR0 (BIR 0). MSI is present, 64-bit capable, and
maskable, but disabled; MSI-X is enabled.

One discrepancy is recorded rather than smoothed over: the MSI-X table size
field reports 9 vectors, and the kernel exposes 8 entries under `msi_irqs`
(429 to 436). The ninth vector's disposition is an unresolved unknown.

## NUMA and proximity

`numa_node` reads `-1` for the GB10. Linux does not expose a NUMA association
for this device. This is recorded as an observed value (`-1`), not converted
into node 0.

## What AIENOS must own after ExitBootServices

To discover, map, isolate, and eventually interrupt-drive this GB10 natively,
AIENOS must own exactly these physical interfaces:

1. **ECAM discovery.** The MCFG segment 15 window at `0x29000000` covering
   buses 0 to 1, to reach `000f:01:00.0` and its root bridge without firmware
   services.
2. **Configuration access.** Read access to the endpoint header and capability
   list, decoded by `aienos-accel` pure functions.
3. **MMIO mapping authority.** A kernel-owned mapping of the BAR0 64 MiB
   region at `0x24000000`, granted through a capability, not ambient physical
   memory access. Reading or writing it is outside this characterization phase.
4. **SMMU / DMA authority.** The stream table entry that maps the GB10's
   stream ID to a translation context. AIENOS must program this through the
   SMMUv3, bound to a capability, before any DMA. It must not bypass the SMMU.
5. **Interrupt resource.** The MSI-X table and PBA in BAR0, plus the GIC ITS/MSI
   path that delivers the vectors. This is a separate capability from MMIO.
6. **Firmware objects.** The GB10 firmware image and the GSP transport once a
   later milestone authorizes them.

## Cross-check against existing AIENOS discovery

The existing UEFI handoff discovery (`crates/aienos-boot/src/handoff.rs`) and
`aienos-accel` were checked against the observed profile.

| Existing expectation | Observed on Machine 1 | Status |
| --- | --- | --- |
| Vendor/device `10de:2e12` | `10de:2e12` | matches |
| BDF fast path segment 15 bus 1 device 0 function 0 | `000f:01:00.0` | matches |
| Programmed 64-bit memory BAR0 | 64-bit prefetchable at `0x24000000` | matches |
| PCI memory decoding enabled | command bit 1 set (`0x0407`) | matches |
| BAR0 large enough for PMC offsets 0 and `0x0a00` | BAR0 is 64 MiB | offsets in range |
| Firmware bus range covers the device bus | ECAM segment 15 covers buses 0 to 1 | matches |

### Hard-coded assumptions found

1. `handoff.rs` compares `vendor_device` against the literal `0x2e12_10de`
   rather than the named constants in `aienos-accel`. Behaviourally correct,
   but a second source of truth.
2. `handoff.rs::scan_root` tries segment 15, bus 1, device 0, function 0 first
   as a shortcut before scanning firmware bus ranges. The fallback scan makes
   this an optimization rather than a hard dependency, but it encodes the
   current Machine 1 BDF.
3. The pre-exit discovery reads only config offsets 0x00, 0x04, 0x10, and 0x14.
   It cannot report capability presence, PCIe link state, IOMMU grouping, or
   MSI/MSI-X, so the boot report is silent on interrupt and isolation facts.
4. `Gb10Bar::from_config` requires `physical_base != 0` and a 64-bit memory
   BAR0. Both hold, and the rejection reasons are now typed in
   `profile::Gb10Bar::from_header`.

### Scoped follow-ups, not edits to shared boot files

These are proposed as separate changes to avoid conflicting with active lanes
on the boot and handoff code:

- Have `read_candidate` use `NVIDIA_VENDOR_ID` and `GB10_DEVICE_ID` from
  `aienos-accel`.
- Replace the inline BAR validation in `probe_gb10` with
  `Gb10Bar::from_header`, keeping the same raw values in
  `rejected_candidate` so diagnostics are unchanged.
- Extend native discovery to decode the capability list with `pci.rs` and
  carry MSI-X presence, table offset, and vector count across handoff, once a
  lane owns `handoff.rs`.

## Unresolved unknowns

- The IORT stream ID and SMMUv3 stream table entry for the GB10.
- The disposition of the ninth MSI-X vector.
- Whether the negotiated PCIe width stays at x1 after link training settles,
  and why the current speed reads 2.5 GT/s while the link can go wider. Kernel
  boot logged `0.000 Gb/s available PCIe bandwidth, limited by Unknown x0 link`
  at `000f:00:00.0`; sysfs later read x1. The negotiated state is dynamic and
  is recorded as observed, not derived.
- The PMC register values. They are read only through the UEFI handoff path,
  never through Linux in this phase.
