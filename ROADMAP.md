# AIENOS Roadmap

AIENOS is an agent-native operating system built in the open. This file is the
public map: where the project is, what is next, and where you can help.
**Live progress** is on the GitHub milestone pages linked below: each progress
bar moves as issues close. This file is updated at every gate.

## Status (updated 2026-09-25)

```text
M0  PARTIAL  Reference freeze
    reference snapshot        PASS
    benchmark evidence        PASS   54.2 tokens/s CPU decode baseline
    native-boot rollback (QEMU) PASS   M0_NATIVE_ROLLBACK_QEMU: PASS (AAVMF BootNext/NVRAM verified)
    native-boot rollback (HW)   BLOCKED M0_NATIVE_ROLLBACK_MACHINE1: BLOCKED
                                (reason = HARDWARE_QUALIFICATION_BLOCKED_BY_TRUST_CHAIN)
    bootable recovery media   PASS: attended USB boot, read-only root/ESP
                              inspection, tools present, return to Linux
                              (issue #17; evidence/recovery_boot_machine1.md)

M1  PASS  Emulator boot
    automated QEMU boot       PASS   CI automation (#44)

M2  PASS  First native Spark boot (2026-09-24)
    follow-ups: observability, console, GB10 discovery, keyboard,
    test rig (design: docs/HARDWARE_TEST_RIG.md)

M3  PASS  Kernel isolation, in QEMU (2026-09-24; not run on Machine 1)
    EL1h on own page tables, MMU on       PASS (#108)
    GICv3 timer interrupts at EL1         PASS (#95)
    preemptive scheduler                  PASS (#105, closes #29)
    SMMUv3 DMA confinement in QEMU        PASS (#103, #110)
    EL0 tasks, capability-checked calls   PASS (#104)
    ABI v1 frozen (ADR 0013), IPC         PASS (#106, #107, #109, closes #30)
    verify_all green on main              PASS (6ef8dde)

SEED-0B  PASS  Native capability admission, in QEMU (2026-09-25; TEST-ONLY keys)
    SEED_0B_QEMU: PASS                    (#118-#122, #124, #127, #128, #138;
                                           evidence/seed0b_qemu_2026-09-25.md)
    P2-9 Machine 1 qualification          prepared, not run; blocked on
                                          TRUST-1 (docs/SEED0B_MACHINE1_QUALIFICATION.md)

M4  PARTIAL  Storage and recovery (QEMU only so far)
    NVMe read                   QEMU_NVME: PASS (#129)
    NVMe write + flush          QEMU_NVME_RW: PASS (#132)
    4K root-write atomicity     QEMU_NVME_ATOMICITY_4K: PASS (#133); the Machine 1
                                SSD is 512-byte LBA and does not meet it
                                (NATIVE_GB10_STORE_ROOT_ATOMICITY: FAIL)
    Store v1 format + engine    ADR 0015 frozen (#130), engine host-tested (#131),
                                STORE_MALFORMED_PEER_RECOVERY: PASS (#135)
    Store over NVMe crash/reboot STORE_V1_QEMU: PASS (#134, 4K LBA)
                                STORE_512B_CRASH_RECOVERY_QEMU: PASS (#136)
    gated in verify_all         step 6e (#137)
    open: continuity objects over Store v1, Recovery Core (ADR 0006),
          anything on Machine 1

NEXT:
M4 continuity: Generation + agent identity/state + Cortex checkpoint/WAL +
artifact references over Store v1, proven by a QEMU cold restart
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
 -> SEED-0A Self-construction lab    agent-built candidates proven in QEMU, never admitted
 -> M3 Kernel isolation             the enforcement substrate
 -> SEED-0B Native capability admission
 -> M4 Storage and recovery
 -> M5 Encryption and identity
 -> M6 Minimal networking
 -> M7 Native CPU inference
 -> M8 Persistent agent        first vision proven
```

SEED-0A and SEED-0B come from [ADR 0012](docs/adr/0012-self-construction-capability-growth-and-generations.md):
each machine grows the capabilities it needs as reversible, numbered
Generations admitted by deterministic gates. Generated native code reaches the
physical machine only after M3 can confine it. SEED-0A experiment #1 is
`input.keyboard.usb` ([#58](https://github.com/aien-dev/aienos/pull/58)).

The first public demonstration is M8: power on, AIENOS boots, you talk to the
local agent, power off, power on, and it remembers.

## Gates

| Gate | Milestone (live progress) | Open work | Done so far |
| --- | --- | --- | --- |
| M0 Reference freeze | [M0](https://github.com/aien-dev/aienos/milestone/1) | native boot rollback proven in QEMU (M0_NATIVE_ROLLBACK_QEMU: PASS); physical qualification BLOCKED (M0_NATIVE_ROLLBACK_MACHINE1: BLOCKED, reason = HARDWARE_QUALIFICATION_BLOCKED_BY_TRUST_CHAIN, docs/NATIVE_BOOT_ONE_TIME.md); recovery media is PASS ([procedure](docs/RECOVERY_MEDIA_MACHINE1.md), [evidence](evidence/recovery_boot_machine1.md)) | [#12](https://github.com/aien-dev/aienos/pull/12) Rust evidence tooling and clean snapshot ([9bd233d](https://github.com/aien-dev/aienos/commit/9bd233d)) |
| M1 Emulator boot | [M1](https://github.com/aien-dev/aienos/milestone/2) | [#18](https://github.com/aien-dev/aienos/issues/18) QEMU boot, [#19](https://github.com/aien-dev/aienos/issues/19) CI | QEMU 8.2 and AAVMF chosen as the emulator |
| M2 Spark bring-up | [M2](https://github.com/aien-dev/aienos/milestone/3) | [#20](https://github.com/aien-dev/aienos/issues/20) pre-exit file, [#21](https://github.com/aien-dev/aienos/issues/21) screen evidence, [#22](https://github.com/aien-dev/aienos/issues/22) UART via SPCR, [#23](https://github.com/aien-dev/aienos/issues/23) GB10 discovery, [#24](https://github.com/aien-dev/aienos/issues/24) USB keyboard, [#25](https://github.com/aien-dev/aienos/issues/25) test rig ([design](docs/HARDWARE_TEST_RIG.md)) | Gate passed: [#10](https://github.com/aien-dev/aienos/pull/10) memory handoff, [#11](https://github.com/aien-dev/aienos/pull/11) GB10 identity, [#13](https://github.com/aien-dev/aienos/pull/13) visible report ([a22b1d8](https://github.com/aien-dev/aienos/commit/a22b1d8)), [#14](https://github.com/aien-dev/aienos/pull/14) CPU topology ([44fcba7](https://github.com/aien-dev/aienos/commit/44fcba7)), [#15](https://github.com/aien-dev/aienos/pull/15) first-boot image ([52109bc](https://github.com/aien-dev/aienos/commit/52109bc)), [#16](https://github.com/aien-dev/aienos/pull/16) evidence ([f376589](https://github.com/aien-dev/aienos/commit/f376589)) |
| M3 Kernel isolation | [M3](https://github.com/aien-dev/aienos/milestone/4) | none; #26 vectors, #27 MMU, #28 timer and GIC, #29 scheduler, #30 IPC and capabilities all closed | Frame allocator, bounded UART, fault capture used on the first boot; M3 merged as #103 SMMU, #104 EL0, #105 preemption, #106 IPC, #107 ABI freeze plus ADR 0013, #108 MMU and timer reconcile, #109 ABI unification, #110 fail-closed DMA, #111 and #114 device authority, #112 PCI ECAM, #113 strict verify, #115 ABI conformance; receipts in evidence/m3_canonical_receipt.md; verify_all green at 6ef8dde |
| M4 Storage and recovery | [M4](https://github.com/aien-dev/aienos/milestone/5) | [#31](https://github.com/aien-dev/aienos/issues/31) NVMe and System Store: continuity objects over Store v1 (Generation, agent identity and state, Cortex checkpoint/WAL, artifact references; proven by a QEMU cold restart), Recovery Core deterministic scenarios ([ADR 0006](docs/adr/0006-deterministic-recovery-core-and-offline-operator-authority.md)), and everything on Machine 1 (its SSD is 512-byte LBA: `NATIVE_GB10_STORE_ROOT_ATOMICITY: FAIL`, [evidence](evidence/p3_nvme_atomicity_2026-09-25.md)). `P3_STORE_QEMU` and `P3_STORE_NATIVE` are not claimed | In QEMU: [#129](https://github.com/aien-dev/aienos/pull/129) NVMe read (`QEMU_NVME: PASS`, [evidence](evidence/p3_nvme_read_qemu_2026-09-25.md)), [#132](https://github.com/aien-dev/aienos/pull/132) write and flush (`QEMU_NVME_RW: PASS`, [evidence](evidence/p3_nvme_write_flush_qemu_2026-09-25.md)), [#133](https://github.com/aien-dev/aienos/pull/133) 4K root-write atomicity (`QEMU_NVME_ATOMICITY_4K: PASS`), [#134](https://github.com/aien-dev/aienos/pull/134) Store over NVMe crash/reboot (`STORE_V1_QEMU: PASS`, [evidence](evidence/store_nvme_qemu_2026-09-25.md)), [#136](https://github.com/aien-dev/aienos/pull/136) 512-byte LBA campaign (`STORE_512B_CRASH_RECOVERY_QEMU: PASS`, [evidence](evidence/store_512b_qemu_2026-09-25.md)), all gated by [#137](https://github.com/aien-dev/aienos/pull/137) (`verify_all` step 6e). Host-tested: [#130](https://github.com/aien-dev/aienos/pull/130) Store v1 format frozen in [ADR 0015](docs/adr/0015-system-store-v1-format.md), [#131](https://github.com/aien-dev/aienos/pull/131) mount and transaction engine, [#135](https://github.com/aien-dev/aienos/pull/135) malformed-peer amendment (`STORE_MALFORMED_PEER_RECOVERY: PASS`) |
| M5 Encryption and identity | [M5](https://github.com/aien-dev/aienos/milestone/6) | [#32](https://github.com/aien-dev/aienos/issues/32) | Host-tested agent identity (ADR 0007) |
| M6 Minimal networking | [M6](https://github.com/aien-dev/aienos/milestone/7) | [#33](https://github.com/aien-dev/aienos/issues/33) | |
| M7 Native CPU inference | [M7](https://github.com/aien-dev/aienos/milestone/8) | [#34](https://github.com/aien-dev/aienos/issues/34) | Linux baseline recorded in M0 |
| M8 Persistent agent | [M8](https://github.com/aien-dev/aienos/milestone/9) | [#35](https://github.com/aien-dev/aienos/issues/35) | Host-tested Cortex store |

Separate lanes that never block the critical path:
[#36](https://github.com/aien-dev/aienos/issues/36) GB10 characterization (read-only
Linux characterization merged in [#125](https://github.com/aien-dev/aienos/pull/125);
no native GB10 observation and no GPU execution yet) and [#37](https://github.com/aien-dev/aienos/issues/37) Fabric
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
- Phase 2 executable identity: SEED-0B is qualified in QEMU
  (`SEED_0B_QEMU: PASS`): Binary Artifact v0, Ed25519 trust, admission
  policy, the P2-5 loader, Admission Receipt v0 (P2-6A), the first SEED-0B
  capability artifact with kernel receipts (P2-6B) and the negative matrix
  (P2-7); see
  [evidence/seed0b_qemu_2026-09-25.md](evidence/seed0b_qemu_2026-09-25.md).
  Machine 1 qualification (P2-9) is prepared, not run, and blocked on the
  TRUST-1 owner-signed boot chain
  ([procedure](docs/SEED0B_MACHINE1_QUALIFICATION.md)). M3 kernel
  isolation is done in QEMU; see the M3 row above.
- M4 storage: the native NVMe driver and System Store v1 are qualified in
  QEMU (see the M4 row above). Next is continuity over Store v1: Generation,
  agent identity and state, Cortex checkpoint/WAL and artifact references,
  proven by a QEMU cold restart. All of it runs in QEMU.

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
