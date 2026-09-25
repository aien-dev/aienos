# GB10 native accelerator boundary

This document freezes the layering a future native GB10 driver must fit into.
It does not design the driver. It defines the boundary so that GPU work can be
built against a capability-bound contract instead of ambient hardware access.

Governing: issue [#36](https://github.com/aien-dev/aienos/issues/36),
[GB10_HARDWARE_PROFILE.md](GB10_HARDWARE_PROFILE.md),
[GB10_PLATFORM_TOPOLOGY.md](GB10_PLATFORM_TOPOLOGY.md),
[ARCHITECTURE.md](ARCHITECTURE.md).

## Frozen layering

```
PCI/ACPI discovery
        |
        v
device identity/profile
        |
        v
kernel MMIO mapping authority
        |
        v
SMMU/DMA authority
        |
        v
interrupt resource
        |
        v
GB10 device lifecycle
        |
        v
GSP transport          [FUTURE]
        |
        v
GPU memory manager     [FUTURE]
        |
        v
channel/queue submit   [FUTURE]
        |
        v
compute execution      [FUTURE]
```

The upper six layers are the subject of this characterization phase and the
milestone that follows it. The lower four are marked future and must not be
claimed until each has hardware evidence.

## The key contract

`aienos-accel` must never obtain ambient physical-memory or DMA authority.

Today `aienos-accel` is pure decoding: it turns byte slices into typed facts
and validates the GB10 contract. That property is permanent. When accelerator
code eventually needs MMIO, interrupts, or DMA, it receives them as explicit
capabilities granted through AEGIS, exactly like every other AIENOS physical
resource. There is to be no global "map physical memory" call, no
`/dev/mem`-style escape, and no untyped physical address that a device driver
can dereference on its own.

Concretely:

- Discovery produces a `Gb10Profile`, not a mapped pointer. The profile is
  immutable facts.
- Mapping MMIO is a separate, capability-gated kernel service. The discovery
  layer cannot map.
- DMA is a separate, capability-gated SMMU service. A device cannot DMA until
  AIENOS programs its stream table entry.
- An interrupt line or MSI-X vector is an interrupt capability, distinct from
  the MMIO capability that contains the MSI-X table.

## Required future capabilities

These are described conceptually so the eventual implementation has a target.
Only the generic capability substrate, if it already exists, is reused; none of
these accelerator capabilities is implemented in this phase.

| Capability | Grants | Does not grant |
| --- | --- | --- |
| Accelerator MMIO region | read/write of a bounded BAR window | DMA, interrupts, execution |
| Accelerator interrupt | receive one device interrupt or vector | MMIO, DMA |
| Accelerator DMA domain | participate in an SMMU translation context | MMIO, execution |
| Firmware object | load a named, verified firmware image | MMIO, DMA, execution |
| Compute queue | create and submit a queue | authority over other queues |

Each is resource-specific and revocable. A compute queue capability without a
DMA domain cannot move data. A DMA domain without an MMIO region cannot be
programmed. Composition is explicit.

## Layer responsibilities

- **PCI/ACPI discovery.** Enumerate firmware-declared ECAM ranges, find the
  GB10 by property, decode identity and capabilities. No side effects. This is
  implemented in `aienos-accel` (pure) and, later, a native enumerator.
- **device identity/profile.** `Gb10Profile` with provenance. Read only.
- **kernel MMIO mapping authority.** Create a bounded mapping for a granted
  accelerator MMIO region. The mapping is the only path to device registers.
- **SMMU/DMA authority.** Program the GB10 stream table entry under a granted
  DMA domain. No bypass mode.
- **interrupt resource.** Bind the MSI-X vector or legacy interrupt through the
  GIC/ITS to the owner. Distinct capability.
- **GB10 device lifecycle.** Reset, power, and firmware-load state machine
  under operator and AEGIS policy. This is the first layer that mutates the
  device, and it requires a later milestone.
- **GSP transport (future).** The command/RPC channel to GSP. Requires the
  lifecycle layer and the firmware object.
- **GPU memory manager (future).** VRAM allocation and mappings. Requires the
  DMA domain.
- **channel/queue submit (future).** Requires the compute queue capability.
- **compute execution (future).** Requires the queue and memory manager.

## Safety boundary for this phase

This characterization phase stops at layer two. It does not initialize the
GPU, communicate with GSP, submit commands, allocate GPU memory, execute
kernels, or perform inference. It does not write PCI configuration space,
change command bits, resize BARs, reset the GPU, perform FLR, rebind the
NVIDIA driver, change power state, write BAR/MMIO registers, access `/dev/mem`,
issue GSP RPC, load alternate firmware, create GPU channels, or map GPU
memory.

The step from layer two to layer three is the next device-ownership milestone
and needs its own authorization, evidence, and rollback plan.
