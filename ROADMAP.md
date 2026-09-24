# AIENOS Roadmap

AIENOS is an agent-native operating system built in the open. This file is the
public map: where the project is, what is next, and where you can help.
**Live progress** is on the GitHub milestone pages linked below: each progress
bar moves as issues close. This file is updated at every gate.

## Status (updated 2026-09-24)

```text
M0  PARTIAL  Reference freeze
    reference snapshot        PASS
    benchmark evidence        PASS   54.2 tokens/s CPU decode baseline
    native-boot rollback      PASS
    bootable recovery media   PENDING

M1  IN PROGRESS  Emulator boot
    automated QEMU boot       IN PROGRESS

M2  PASS  First native Spark boot (2026-09-24)
    follow-ups: observability, console, GB10 discovery, keyboard, test rig

NEXT HARD GATE:
recovery media -> QEMU regression boot -> M3 kernel isolation
```

The first native boot on the NVIDIA DGX Spark ("Machine 1") passed on
2026-09-24: the machine left firmware, ran AIENOS code at EL2 with no Linux
underneath (`kernel: alive`), left a report that Linux read after the reset,
and returned to Linux undamaged. Full record:
[evidence/m2_first_boot_2026-09-24.md](evidence/m2_first_boot_2026-09-24.md).

## Critical path

```text
M0 Reference freeze
 -> M1 Emulator boot
 -> M2 Spark bring-up
 -> M3 Kernel isolation
 -> M4 Storage and recovery
 -> M5 Encryption and identity
 -> M6 Minimal networking
 -> M7 Native CPU inference
 -> M8 Persistent agent        first vision proven
```

The first public demonstration is M8: power on, AIENOS boots, you talk to the
local agent, power off, power on, and it remembers.

## Gates

| Gate | Milestone (live progress) | Open work | Done so far |
| --- | --- | --- | --- |
| M0 Reference freeze | [M0](https://github.com/aien-dev/aienos/milestone/1) | [#17](https://github.com/aien-dev/aienos/issues/17) recovery media | [#12](https://github.com/aien-dev/aienos/pull/12) Rust evidence tooling and clean snapshot ([9bd233d](https://github.com/aien-dev/aienos/commit/9bd233d)) |
| M1 Emulator boot | [M1](https://github.com/aien-dev/aienos/milestone/2) | [#18](https://github.com/aien-dev/aienos/issues/18) QEMU boot, [#19](https://github.com/aien-dev/aienos/issues/19) CI | QEMU 8.2 and AAVMF chosen as the emulator |
| M2 Spark bring-up | [M2](https://github.com/aien-dev/aienos/milestone/3) | [#20](https://github.com/aien-dev/aienos/issues/20) pre-exit file, [#21](https://github.com/aien-dev/aienos/issues/21) screen evidence, [#22](https://github.com/aien-dev/aienos/issues/22) UART via SPCR, [#23](https://github.com/aien-dev/aienos/issues/23) GB10 discovery, [#24](https://github.com/aien-dev/aienos/issues/24) USB keyboard, [#25](https://github.com/aien-dev/aienos/issues/25) test rig | Gate passed: [#10](https://github.com/aien-dev/aienos/pull/10) memory handoff, [#11](https://github.com/aien-dev/aienos/pull/11) GB10 identity, [#13](https://github.com/aien-dev/aienos/pull/13) visible report ([a22b1d8](https://github.com/aien-dev/aienos/commit/a22b1d8)), [#14](https://github.com/aien-dev/aienos/pull/14) CPU topology ([44fcba7](https://github.com/aien-dev/aienos/commit/44fcba7)), [#15](https://github.com/aien-dev/aienos/pull/15) first-boot image ([52109bc](https://github.com/aien-dev/aienos/commit/52109bc)), [#16](https://github.com/aien-dev/aienos/pull/16) evidence ([f376589](https://github.com/aien-dev/aienos/commit/f376589)) |
| M3 Kernel isolation | [M3](https://github.com/aien-dev/aienos/milestone/4) | [#26](https://github.com/aien-dev/aienos/issues/26) vectors, [#27](https://github.com/aien-dev/aienos/issues/27) MMU, [#28](https://github.com/aien-dev/aienos/issues/28) timer and GIC, [#29](https://github.com/aien-dev/aienos/issues/29) topology-aware scheduler, [#30](https://github.com/aien-dev/aienos/issues/30) IPC and capabilities | Frame allocator, bounded UART, fault capture used on the first boot |
| M4 Storage and recovery | [M4](https://github.com/aien-dev/aienos/milestone/5) | [#31](https://github.com/aien-dev/aienos/issues/31) NVMe and System Store | Host-tested store and WAL recovery |
| M5 Encryption and identity | [M5](https://github.com/aien-dev/aienos/milestone/6) | [#32](https://github.com/aien-dev/aienos/issues/32) | Host-tested agent identity (ADR 0007) |
| M6 Minimal networking | [M6](https://github.com/aien-dev/aienos/milestone/7) | [#33](https://github.com/aien-dev/aienos/issues/33) | |
| M7 Native CPU inference | [M7](https://github.com/aien-dev/aienos/milestone/8) | [#34](https://github.com/aien-dev/aienos/issues/34) | Linux baseline recorded in M0 |
| M8 Persistent agent | [M8](https://github.com/aien-dev/aienos/milestone/9) | [#35](https://github.com/aien-dev/aienos/issues/35) | Host-tested Cortex store |

Separate lanes that never block the critical path:
[#36](https://github.com/aien-dev/aienos/issues/36) GB10 characterization (no GPU
execution yet) and [#37](https://github.com/aien-dev/aienos/issues/37) Fabric
(after native networking; early design in
[ADR 0010](docs/adr/0010-fabric-machine-identity-and-capability-advertisement.md)).

Related repositories: [aien-sovereign-core](https://github.com/aien-dev/aien-sovereign-core)
holds the AIEN runtime, Cortex, AEGIS and `aien-proof`, the shared test board
and hardware-test ledger ([#124](https://github.com/aien-dev/aien-sovereign-core/pull/124),
[#126](https://github.com/aien-dev/aien-sovereign-core/pull/126)).

## Help build it

AIENOS is a lot of low-level Rust, and most of it does not need our hardware.
Everything labelled [`emulator-ok`](https://github.com/aien-dev/aienos/labels/emulator-ok)
can be built and tested in QEMU on any machine. Good places to start:

- [`good first issue`](https://github.com/aien-dev/aienos/labels/good%20first%20issue):
  small, self-contained changes.
- [`help wanted`](https://github.com/aien-dev/aienos/labels/help%20wanted):
  kernel, boot, evidence and tooling work that is ready for a contributor.
- M3 kernel isolation (exceptions, MMU, GICv3, scheduler, IPC) is the next
  large body of work, and all of it runs in the emulator.

Work labelled [`needs-hardware`](https://github.com/aien-dev/aienos/labels/needs-hardware)
runs on Machine 1; maintainers execute it and publish the evidence. Read
[CONTRIBUTING.md](CONTRIBUTING.md) before your first pull request.

## Ground rules

- Rust throughout, with small amounts of AArch64 assembly where the hardware
  requires it. No Python, no CUDA, and no CUDA-shaped APIs.
- The trusted base builds from inspectable source, offline, with an
  independently obtainable toolchain.
- Evidence earns claims: a boot, benchmark or fix counts when its output is
  recorded and reproducible.
- Experimental and pre-alpha: no support, stability or compatibility promises.
