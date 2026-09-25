# GB10 hardware profile v1

This document defines the typed GB10 characterization used by AIENOS and the
read-only Linux collector that fills it. It is characterization only. Nothing
here initializes the GPU, talks to GSP, submits a command, allocates GPU
memory, executes a kernel, or performs inference.

Governing: issue [#36](https://github.com/aien-dev/aienos/issues/36),
[GB10_NATIVE_STATUS.md](GB10_NATIVE_STATUS.md),
[GB10_PLATFORM_TOPOLOGY.md](GB10_PLATFORM_TOPOLOGY.md),
[GB10_NATIVE_ACCELERATOR_BOUNDARY.md](GB10_NATIVE_ACCELERATOR_BOUNDARY.md).

## Evidence classes

Every fact in the profile is one of three states, never collapsed into a
default:

- `Observed`: a value read from a named source.
- `Derived`: a value computed from observed values, not read directly.
- `Unknown`: no value was obtained. Absence of evidence is not a zero, not a
  default, and not a hardware property.

Every observed value also records:

- its `source` (UEFI firmware service, native AIENOS PCI enumeration, Linux
  sysfs, Linux procfs, Linux ACPI, a synthetic fixture, or derived);
- whether Linux interpreted the value (`true` for a kernel sysfs attribute that
  the kernel decoded, `false` for raw configuration bytes this project decodes
  itself);
- whether native AIENOS has independently verified the value.

`BAR0 base observed through Linux sysfs` and `BAR0 base independently decoded
by native AIENOS PCI enumeration` are different claims, and the type keeps
them different.

## Where it lives

| Item | Location |
| --- | --- |
| Pure PCI configuration decoders | `crates/aienos-accel/src/pci.rs` |
| Typed profile, provenance, GB10 contract match | `crates/aienos-accel/src/profile.rs` |
| Register knowledge ledger | `crates/aienos-accel/src/registers.rs` |
| Read-only Linux collector | `scripts/gb10_profile.sh` |
| Synthetic fixture tests | `crates/aienos-accel/tests/gb10_fixtures.rs` |

## Representable facts

The profile can represent at least the following, with `Fact<T>` carrying the
state, source, and native-verification flag. A value configuration space cannot
answer stays `Unknown` rather than zero.

| Fact | Type | Source when known |
| --- | --- | --- |
| PCI segment / domain, bus, device, function | `PciLocation` | enumeration path |
| Vendor ID, device ID | `Fact<u16>` | config 0x00 |
| Subsystem vendor / device | `Fact<u16>` | config 0x2c |
| Class, subclass, programming interface | `Fact<ClassCode>` | config 0x0b |
| Revision | `Fact<u8>` | config 0x08 |
| PCI command and status | `Fact<u16>` | config 0x04 |
| BAR count, type, base, prefetchability, 32 vs 64 bit | `Fact<BarFacts>` and `Fact<u64>` sizes | config 0x10, `resource` |
| BAR size when reliably observable | `Fact<u64>` | Linux `resource`; a probe is never performed |
| PCIe capability presence | `Fact<PcieFacts>` | config capability list |
| Negotiated and maximum link width and speed | inside `PcieFacts` | PCIe capability registers, sysfs |
| MSI and MSI-X capability presence | `Fact<MsiFacts>`, `Fact<MsixFacts>` | config capability list |
| MSI-X table and PBA BAR indicator and offsets | inside `MsixFacts` | MSI-X capability |
| IOMMU / SMMU grouping | `Fact<u32>` | `iommu_group` sysfs |
| NUMA association | `Fact<i32>` | `numa_node` sysfs |
| Firmware / ACPI relationship | `Fact<&'static str>` | `firmware_node` sysfs |
| Known safe PMC observation values | `Fact<u32>` | UEFI handoff only, see the register ledger |
| Provenance for every observation | `Source`, collection method | always recorded |

BAR size deserves a note. A PCI BAR size is normally found by writing all ones
and reading the mask back. That is a configuration-space write and lies outside
the read-only characterization boundary. The profile therefore reports a size
only when a source supplies one (the Linux kernel already sized the BAR and
exposes it in the `resource` file) or when a synthetic fixture supplies a probe
result to the pure `memory_bar_size` decoder. It is never produced by baking a
default.

## Native contract match

`profile::match_gb10` validates a decoded endpoint header against the GB10
contract using device properties only:

- vendor `0x10de`, device `0x2e12`;
- memory decoding enabled;
- BAR0 present, memory (not IO), programmed, and 64-bit.

It returns the exact rejection reason otherwise
(`NotNvidia`, `WrongDevice`, `MemoryDecodeDisabled`, `Bar0Missing`,
`Bar0NotMemory`, `Bar0Unprogrammed`, `Bar0Not64Bit`). No bus, device, or
function number is assumed, so a relocated GB10 matches exactly as the observed
one does. `Gb10Bar::from_header` applies the same contract to the legacy
register values the boot handoff already reads.

## Read-only Linux collector

```
bash scripts/gb10_profile.sh [--json PATH] [--report PATH] [--allow-sudo] [--generated-at S]
```

The collector only reads. It never writes configuration space, changes a PCI
command bit, resizes a BAR, resets a device, unbinds or rebinds a driver, writes
MMIO, or opens `/dev/mem`.

- Default: unprivileged. It reads sysfs attributes, `/proc/cmdline`, and the
  first 64 bytes of configuration space, which excludes the capability list.
- `--allow-sudo` or `GB10_PROFILE_ALLOW_SUDO=1`: performs two specific,
  strictly read-only privileged reads through `sudo -n`: the 256-byte
  configuration space (for the capability list) and the ACPI table copies
  (for presence, size, and SHA-256). This privilege is required because the
  kernel exposes only 64 config bytes to unprivileged readers and marks the
  ACPI table copies root-only. Each field records whether this was used.
- `--generated-at` fixes the timestamp. Without it the timestamp is omitted so
  repeated runs on unchanged hardware are byte-identical.

Output is a deterministic structured profile (JSON) and a human report. It
records only the GB10 device, its PCIe topology, IOMMU grouping, and the
firmware tables relevant to reaching it. It does not collect secrets or
unrelated machine data.

An example committed run on Machine 1 is
`evidence/gb10_linux_profile_2026-09-25.json`, summarized in
[`evidence/gb10_linux_readonly_2026-09-25.md`](../evidence/gb10_linux_readonly_2026-09-25.md).

## What this is not

The Linux collector observes facts through Linux. Those facts are Linux
observations, not native AIENOS proofs. The current UEFI discovery path
observes a subset (identity, BAR0, and two PMC registers); those are UEFI
observations. Nothing here claims GSP ownership, GPU initialization, command
submission, GPU DMA readiness, native Blackwell execution, or native inference.
