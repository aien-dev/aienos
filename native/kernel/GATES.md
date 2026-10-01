# C kernel (CK) gate parity with the Rust QEMU gates

This table maps every check made by the Rust-kernel QEMU gates that
`scripts/verify_all.sh` runs (M0, M1, M3, SEED-0B/P2-5, SEED-0A keyboard,
SMMU, M4 NVMe/Store/continuity/recovery, TRUST-1 Gate 4) to the C kernel
gate that covers it. `scripts/ck_gates.sh` runs the C gates and writes a
content-addressed receipt `evidence/ck_gates_<sha256>.json`.

QEMU qualifies nothing physical. Every row below is emulator evidence at
best; no row says anything about Machine 1 or the GB10.

Status vocabulary:

- **IDENTICAL**: the C gate greps the same pattern with the same logic.
- **DIFFERS**: the C gate checks the same property with a different
  observable or a weaker/stronger condition (the difference is stated).
- **NOT_RUN**: no C implementation exists (MISSING_IMPLEMENTATION, reason
  given). `ck_gates.sh` prints NOT_RUN for these; never PASS.

C gates (one line each from `ck_gates.sh`): `M1` (from
`scripts/qemu_ck_boot_test.sh`), `M4_NVME`, `M4_STORE`, `ARGUS1_REVOKE`
`SMMU` (from `scripts/qemu_ck_store_test.sh`; rows 21-24b, 47-72, 76 and
96-98 were checked against its exact grep patterns), and the NOT_RUN gates
`M3`, `P2_ARTIFACT`, `M0_ROLLBACK`, `M4_STORE_CRASH`,
`M4_CONTINUITY`, `M4_RECOVERY`, `KEYBOARD`.

`M4_NVME` and `SMMU` PASS in the SMMU-confined mode (default `make full`
image, QEMU `iommu=smmuv3`). The unconfined bypass build
(`make full CK_QEMU_UNSAFE_DMA=1`) is TEST-ONLY: one boot per geometry checks
that it announces itself; it never counts toward a PASS. QEMU only.

## M1 boot: scripts/qemu_boot_test.sh -> CK `M1` (scripts/qemu_ck_boot_test.sh)

Same QEMU command line (virt, EL2, GICv3, single-thread TCG, -smp 4, 2 GiB,
same AAVMF files, virtio-blk ESP, -no-reboot, 180 s timeout). The C script
builds with make instead of cargo and takes the machine quiet flag itself.

| # | Rust check (pattern) | CK gate | Status |
| --- | --- | --- | --- |
| 1 | pre-exit report (`report_kind: pre_exit`) | M1 | IDENTICAL |
| 2 | image is this commit (`aienos_commit: <HEAD>`) | M1 | IDENTICAL |
| 3 | entered the kernel (`kernel: alive`) | M1 | IDENTICAL |
| 4 | kernel at EL1h (`kernel_el: EL1h`) | M1 | IDENTICAL |
| 5 | MMU and caches on (`mmu: enabled`) | M1 | IDENTICAL |
| 6 | GICv3 (`gic: v3`) | M1 | IDENTICAL |
| 7 | timer IRQ >= 5 ticks (`timer_irq: N ticks`) | M1 | IDENTICAL |
| 8 | MMU switch re-checked from register values (`mmu_switch: ... switched=yes`, aienos_root == ttbr0_el1 != firmware_ttbr0) | M1 | IDENTICAL |
| 9 | GIC from MADT (`gic_madt: gicd=... gicr=... arch_rev=3 icc_sre=1`) | M1 | IDENTICAL |
| 10 | tick statistics consistent (`timer_stats: intid=30 ...`, 2*min >= period, min <= avg <= max) | M1 | IDENTICAL |
| 11 | final report (`report_kind: final`, checked twice) | M1 | IDENTICAL |
| 12 | no panic or fault (`report_kind: (panic\|fault)` absent) | M1 | IDENTICAL |
| 13 | no timeout (QEMU status 124 is FAIL) | M1 | DIFFERS (stricter: scripts/lib_ck_m1_checks.sh fails on status 124 and on any other non-zero QEMU status, every boot) |
| 14 | (none in Rust) guard pages fault and are contained (`guard_page: ok fault=contained`) | M1 | DIFFERS (added check, C only; stricter) |
| 15 | final verdict line `QEMU_BOOT: PASS` | M1 | DIFFERS (`AIENOS_CK_M1: PASS`; quiet flag held -> `AIENOS_CK_M1: NOT_RUN`, exit 3) |

## M3: scripts/qemu_boot_test.sh M3 lines -> CK `M3`

| # | Rust check (pattern) | CK gate | Status |
| --- | --- | --- | --- |
| 16 | cooperative threads (`threads: ok`) | M3 | NOT_RUN (MISSING_IMPLEMENTATION: no threads/scheduler in the C kernel) |
| 17 | EL0 isolation (`el0: ok write=granted forged=denied fault=contained exit=0`) | M3 | NOT_RUN (MISSING_IMPLEMENTATION: no EL0 tasks) |
| 18 | timer preemption (`preempt: ok`) | M3 | NOT_RUN (MISSING_IMPLEMENTATION: no preemptive scheduler) |
| 19 | MADT placement (`placement: worker0=class0/core0 worker1=class0/core1`) | M3 | NOT_RUN (MISSING_IMPLEMENTATION: only the boot CPU is brought up) |
| 20 | typed IPC (`ipc: ok message=delivered cap=delegated rights=attenuated forged=denied revoked=denied`) | M3 | NOT_RUN (MISSING_IMPLEMENTATION: no IPC; the stage `caps:` line mirrors the capability semantics in-kernel but is not IPC) |

`qemu_ck_boot_test.sh` prints these five as `NOT_RUN` and they do not count
toward `AIENOS_CK_M1`.

## SMMU: scripts/qemu_smmu_test.sh (= keyboard test, SMMU on, bypass forced off) -> CK `SMMU`

The Rust gate proves the SMMU on the xHCI stream (keyboard). The C kernel has
no xHCI driver, so the C `SMMU` gate proves the same properties on the NVMe
stream instead (boots 1-4 of `scripts/qemu_ck_store_test.sh`, default
`make full` image, QEMU `iommu=smmuv3`, both geometries). Every row below
therefore DIFFERS in the device named; the property checked is the same.
The C SMMU service is `core/smmu.c` (port of `crates/aienos-kernel/src/smmu.rs`:
linear stream table, stage 1 only, global abort set first and never cleared,
every stream in abort until installed) plus `core/smmu_svc.c` (IORT lookup,
per-stream page tables, `ck_dma_confine` / `ck_dma_unconfine` /
`ck_dma_faults` in ck.h); host tests in `tests/test_smmu.c`.

| # | Rust check (pattern) | CK gate | Status |
| --- | --- | --- | --- |
| 21 | IORT stream configured (`smmu: enabled`) | SMMU | DIFFERS (same prefix; C: `smmu: enabled base=.. stream_id=..` for the NVMe stream) |
| 22 | DMA window translated (`smmu_dma_window: xhci only, translation active`) | SMMU | DIFFERS (C: `smmu_dma_window: nvme only, translation active iova=.. len=.. rid=..`) |
| 23 | DMA granted only as confined (`dma_gate: xhci granted (Confined), bus master on`) | SMMU | DIFFERS (C: `dma_gate: nvme granted (Confined), bus master on`; absent `dma_gate: nvme granted (UnsafeBypass)`) |
| 24 | no unsafe bypass in the image (`UNSAFE DMA BYPASS` absent) | SMMU | DIFFERS (C: `UNSAFE NVME DMA BYPASS` absent in boots 1-5) |
| 24a | (C only) DMA outside the window is faulted | SMMU | C only: the controller is pointed at a page outside its window; `smmu_negative: refused dma outside window ... faults>=1 type=0x10 (F_TRANSLATION) sid=<nvme> addr=<that page> page=intact ... recovery_read=ok` |
| 24b | (C only) stream returned to abort after use | SMMU | C only: `smmu: nvme stream 0x.. returned to abort (rc=0)` after `dma_gate: nvme bus master revoked` |

## SEED-0A keyboard: scripts/qemu_keyboard_test.sh (SMMU=1 and SMMU=0) -> CK `KEYBOARD`

| # | Rust check (pattern) | CK gate | Status |
| --- | --- | --- | --- |
| 25 | xHCI found before exit (`keyboard: xhci `) | KEYBOARD | NOT_RUN (MISSING_IMPLEMENTATION: no xHCI/USB HID driver in the C kernel) |
| 26 | bus-master sweep after exit (`dma_sweep: seg `, no `dma_sweep: bme STUCK`) | KEYBOARD | NOT_RUN (MISSING_IMPLEMENTATION: no post-exit bus-master sweep) |
| 27 | xHCI bus master off before the DMA gate (`xhci_pci: command=0x.. bus_master=off`) | KEYBOARD | NOT_RUN (MISSING_IMPLEMENTATION) |
| 28 | fail-closed without SMMU (`dma_gate: xhci denied (NoSmmu)...`, `keyboard: unavailable (...)`, no grant, no `keyboard: ready`) | KEYBOARD | NOT_RUN (MISSING_IMPLEMENTATION) |
| 29 | keyboard attached and typed line echoed (`keyboard: ready`, `keyboard_echo:`, `keyboard_line:`, `keyboard: done (enter)`) | KEYBOARD | NOT_RUN (MISSING_IMPLEMENTATION) |
| 30 | shell commands (`commands: help mem el report uptime exit`, `EL1`, `conventional_memory_kb:`, `keyboard: done (exit)`) | KEYBOARD | NOT_RUN (MISSING_IMPLEMENTATION: no console shell) |
| 31 | xHCI bus master revoked after the phase (`dma_gate: xhci bus master revoked`) | KEYBOARD | NOT_RUN (MISSING_IMPLEMENTATION) |
| 32 | no panic or fault | KEYBOARD | NOT_RUN (MISSING_IMPLEMENTATION) |

## SEED-0B / P2-5 artifact loader: scripts/qemu_artifact_test.sh -> CK `P2_ARTIFACT`

| # | Rust check (pattern) | CK gate | Status |
| --- | --- | --- | --- |
| 33 | common: kernel alive + M3 threads/el0/ipc proofs unchanged | P2_ARTIFACT | NOT_RUN (MISSING_IMPLEMENTATION: no artifact loader; M3 also missing) |
| 34 | firmware read all candidates (`^artifact_candidates: N$`), report not truncated, final report | P2_ARTIFACT | NOT_RUN (MISSING_IMPLEMENTATION) |
| 35 | frames reclaimed (`artifact_frames_free_before` == `_after`) | P2_ARTIFACT | NOT_RUN (MISSING_IMPLEMENTATION) |
| 36 | qualification build labelled TEST ONLY, receipt tier line | P2_ARTIFACT | NOT_RUN (MISSING_IMPLEMENTATION) |
| 37 | P26SEED read via grant, write/forged denied, granted subset of requested, exactly one capability, receipt | P2_ARTIFACT | NOT_RUN (MISSING_IMPLEMENTATION) |
| 38 | P25EXEC / P25WX (W^X fault) / P25SPIN (time budget) / P25TAMP (BadSignature) outcomes + receipts | P2_ARTIFACT | NOT_RUN (MISSING_IMPLEMENTATION: no EL0 loader, no signature verify of artifacts) |
| 39 | hostile set: each refused at its stage or admitted-and-contained, receipts checked by the host tool | P2_ARTIFACT | NOT_RUN (MISSING_IMPLEMENTATION) |
| 40 | H29 READ\|WRITE requested -> READ granted | P2_ARTIFACT | NOT_RUN (MISSING_IMPLEMENTATION) |
| 41 | production build refuses every candidate, zero admitted | P2_ARTIFACT | NOT_RUN (MISSING_IMPLEMENTATION) |

## M0 rollback: scripts/qemu_native_rollback_test.sh -> CK `M0_ROLLBACK`

| # | Rust check (marker) | CK gate | Status |
| --- | --- | --- | --- |
| 42 | `AAVMF_BOOTNEXT_NVRAM` / `NATIVE_ROLLBACK_NORMAL` | M0_ROLLBACK | NOT_RUN (MISSING_IMPLEMENTATION: C loader BootNext/A-B/rollback parked, native/boot/README.md) |
| 43 | `NATIVE_ROLLBACK_FAULT` (faulted candidate returns to Default) | M0_ROLLBACK | NOT_RUN (MISSING_IMPLEMENTATION: parked) |
| 44 | `NATIVE_ROLLBACK_TIMEOUT` (hung candidate) | M0_ROLLBACK | NOT_RUN (MISSING_IMPLEMENTATION: parked) |
| 45 | `NATIVE_ROLLBACK_REJECTED` (malformed image) and absent-image fallback | M0_ROLLBACK | NOT_RUN (MISSING_IMPLEMENTATION: parked) |
| 46 | `NATIVE_ROLLBACK_BOOTNEXT_CONSUMED` / `_DEFAULT_UNCHANGED` | M0_ROLLBACK | NOT_RUN (MISSING_IMPLEMENTATION: parked) |

## M4 NVMe read: scripts/qemu_nvme_test.sh (SMMU=1 and SMMU=0) -> CK `M4_NVME`

The C NVMe path (native/disk via the stage `devices`) does I/O SMMU-confined:
the default `make full` image with QEMU `iommu=smmuv3` (boots 1-4). The same
image without an SMMU denies NVMe DMA and is checked as the fail-closed case
(boot 5). The TEST-ONLY bypass image (`make full CK_QEMU_UNSAFE_DMA=1`) is
booted once more (boot 6) only to check its warnings; the Rust gate never
runs a bypass build. The C
observables are free-form lines, not the Rust `NVME_*_QEMU: PASS` markers.
qemu_ck_store_test.sh runs every check on a 512 B and a 4096 B namespace.

**M4_NVME note:** a PASS of `M4_NVME` means the SMMU-confined NVMe mode
passed in QEMU (row 53); an SMMU check failure fails `M4_NVME` too. ck_gates.sh
prints this on the PASS line and records `nvme_dma_mode` in the receipt.

| # | Rust check (pattern) | CK gate | Status |
| --- | --- | --- | --- |
| 47 | ECAM discovery (`NVME_DISCOVERY_QEMU: PASS`) | M4_NVME | DIFFERS (C: `nvme: discovery `, both geometries, and also in the safe image) |
| 48 | identify (`NVME_IDENTIFY_QEMU: PASS`) | M4_NVME | DIFFERS (C: `nvme: identify ok `) |
| 49 | geometry matches image (`NVME_GEOMETRY_QEMU: PASS (nsid=1 block_count=.. block_size=..)`) | M4_NVME | DIFFERS (C: `nvme: geometry nsid=1 block_count=N block_size=B$` with N and B computed from the 64 MiB image, B = 512) |
| 50 | sentinel LBA read with exact SHA-256 (`NVME_READ_QEMU: PASS (... sha256=..)`) | M4_NVME | DIFFERS (C: `nvme: read lba=0 blocks=1 ok`; no host-planted sentinel hash, weaker) |
| 51 | read past namespace end rejected (`NVME_BOUNDS_QEMU: PASS`) | M4_NVME | DIFFERS (C: `nvme: bounds read lba=N -> refused` with N = block_count) |
| 52 | device-reported command error surfaced (`NVME_ERROR_QEMU: PASS`) | M4_NVME | NOT_RUN (MISSING_IMPLEMENTATION: no C error-injection probe) |
| 53 | SMMU mode: `smmu: enabled`, `smmu_dma_window: nvme only`, `dma_gate: nvme granted (Confined)` | M4_NVME | IDENTICAL prefixes (C appends base/stream/window values), boots 1-4, both geometries; plus the C-only out-of-window fault check (row 24a) |
| 54 | fail-closed mode: `dma_gate: nvme denied (NoSmmu)...`, `nvme: unavailable (SMMU DMA isolation not active)`, no grant/identify/read | M4_NVME | DIFFERS (boot 5, default `make full` image: the two lines and absent `dma_gate: nvme granted` are IDENTICAL; "no identify" is absent `nvme: identify`; no explicit no-read check, but Store is refused `proof=io step="no boot disk"` and the image sha256 is unchanged) |
| 55 | bus master revoked after the phase (`dma_gate: nvme bus master revoked`) | M4_NVME | IDENTICAL (same line, confined boots 1-4 and bypass boot 6, both geometries) |
| 56 | no `UNSAFE NVME DMA BYPASS` in the image | M4_NVME | IDENTICAL for the default image (boots 1-5 check `UNSAFE NVME DMA BYPASS` absent). The TEST-ONLY bypass image (boot 6) instead must print `WARNING: UNSAFE NVME DMA BYPASS BUILD`, `... ACTIVE` and `dma_gate: nvme granted (UnsafeBypass)` (same text as the Rust bypass build, which verify_all never runs); ck_gates.sh records nvme_dma_mode in the receipt |
| 57 | no panic or fault | M4_NVME | IDENTICAL (`report_kind: (panic\|fault)` absent, via scripts/lib_ck_m1_checks.sh on every one of the 6 boots per geometry) |

## M4 NVMe write/flush: scripts/qemu_nvme_rw_test.sh -> CK `M4_NVME` / `M4_STORE`

| # | Rust check (pattern) | CK gate | Status |
| --- | --- | --- | --- |
| 58 | discovery / identify / geometry (as rows 47-49) | M4_NVME | DIFFERS (same as rows 47-49) |
| 59 | atomicity Identify fields (`NVME_ATOMICITY_IDENTIFY_QEMU:`) | M4_NVME | NOT_RUN (MISSING_IMPLEMENTATION: native/disk prints `nvme: atomicity ...` raw fields, but no gate checks that line) |
| 60 | write past namespace end rejected (`NVME_WRITE_BOUNDS_QEMU: PASS`) | M4_NVME | NOT_RUN (MISSING_IMPLEMENTATION: no C write-bounds probe line; host tests cover it) |
| 61 | write + flush + read-back exact (`NVME_WRITE_QEMU`, `NVME_FLUSH_QEMU`, `NVME_DURABILITY_QEMU` with sha256) | M4_NVME | DIFFERS (C: `nvme: rw probe lba=N bytes=4096 write+flush+readback match` on the scratch unit, restored afterwards; no sha256 printed) |
| 62 | invalid-namespace write error surfaced (`NVME_WRITE_ERROR_QEMU: PASS`) | M4_NVME | NOT_RUN (MISSING_IMPLEMENTATION: no C error probe) |
| 63 | SMMU confined grant + revoke | M4_NVME | DIFFERS (confined grant row 53, `dma_gate: nvme bus master revoked`, then `smmu: nvme stream .. returned to abort`; the rw probe runs inside the confined window) |
| 64 | host read-back of the image after power off equals written bytes | M4_STORE | DIFFERS (C: durability shown by Store boot_count read back across 3 boots, not a host dd of one LBA) |
| 65 | boot 2 observes the persisted pattern (`NVME_DURABILITY_QEMU: PASS (persisted lba=..)`) | M4_STORE | DIFFERS (C: `store: opened generation= boot_count=` then `committed boot_count=N+1` on the next boot) |
| 66 | fail-closed: no write/flush/durability markers without DMA | M4_NVME | DIFFERS (safe image, boot 5: absent `nvme: identify`, Store refused `proof=io`, image sha256 unchanged; no explicit absent rw-probe check) |

## M4 atomicity: scripts/qemu_nvme_atomicity_test.sh -> CK `M4_NVME`

| # | Rust check (pattern) | CK gate | Status |
| --- | --- | --- | --- |
| 67 | identify on a 4096-byte LBA namespace | M4_NVME | DIFFERS (4096 B run of qemu_ck_store_test.sh: `nvme: identify ok `) |
| 68 | geometry is 4096-byte LBA | M4_NVME | DIFFERS (C: `nvme: geometry nsid=1 block_count=N block_size=4096$`) |
| 69 | atomicity identify `block_size=4096 lbads=12` | M4_NVME | NOT_RUN (MISSING_IMPLEMENTATION: C prints raw fields only, no lbads) |
| 70 | Store root write power-fail atomic (`NVME_STORE_ROOT_ATOMICITY_QEMU: PASS`) | M4_NVME | NOT_RUN (MISSING_IMPLEMENTATION: no C atomic-root predicate verdict) |

## M4 Store crash: scripts/qemu_store_crash_test.sh -> CK `M4_STORE` / `M4_STORE_CRASH`

| # | Rust check (marker) | CK gate | Status |
| --- | --- | --- | --- |
| 71 | `STORE_NVME_INTEGRATION_QEMU` + `STORE_CHECKPOINT_QEMU` (Store over the native NVMe driver) | M4_STORE | DIFFERS (C: sealed C Store (native/store + native/m5, TEST keys) over native/disk, 512 B and 4096 B; blank -> `store: blank disk ... formatted TEST store`, `stage store: ok`, `store: committed generation= boot_count=`) |
| 72 | `STORE_REOPEN_QEMU` (reopen from media) | M4_STORE | DIFFERS (C: reopen across boots 1-3, boot_count 1 -> 2 -> 3, generation +1 each boot, prev_commit none then the previous commit) |
| 73 | `STORE_CHECKPOINT_CRASH_QEMU` (kill QEMU at each checkpoint, recover N or N+1) | M4_STORE_CRASH | NOT_RUN (MISSING_IMPLEMENTATION: no C crash/kill campaign) |
| 74 | `STORE_SLOT_REUSE_QEMU` | M4_STORE_CRASH | NOT_RUN (MISSING_IMPLEMENTATION: C Store is append-only, no reclaim/slot reuse) |
| 75 | `STORE_V1_QEMU` summary | M4_STORE_CRASH | NOT_RUN (MISSING_IMPLEMENTATION) |

## M4 Store 512 B: scripts/qemu_store_512b_crash_test.sh -> CK `M4_STORE_CRASH`

| # | Rust check (marker) | CK gate | Status |
| --- | --- | --- | --- |
| 76 | `STORE_NVME_INTEGRATION_512B_QEMU` | M4_STORE | DIFFERS (the 512 B geometry run of qemu_ck_store_test.sh; integration only, no 512B-named marker, no crash campaign) |
| 77 | `STORE_512B_CRASH_OBSERVED_QEMU` (tier 1 kills) | M4_STORE_CRASH | NOT_RUN (MISSING_IMPLEMENTATION: no 512B crash campaign) |
| 78 | `STORE_512B_ROOT_TEAR_CLOSURE` (tier 2a) | M4_STORE_CRASH | NOT_RUN (MISSING_IMPLEMENTATION) |
| 79 | `STORE_512B_INJECTED_ROOT_RECOVERY_QEMU` (tier 2b, degraded read-only / refuse) | M4_STORE_CRASH | NOT_RUN (MISSING_IMPLEMENTATION; nearest: C structural refusal of a corrupt superblock, host + QEMU, which is in M4_STORE) |
| 80 | `STORE_512B_CRASH_RECOVERY_QEMU` summary | M4_STORE_CRASH | NOT_RUN (MISSING_IMPLEMENTATION) |

## M4 continuity: scripts/qemu_continuity_test.sh -> CK `M4_CONTINUITY`

| # | Rust check | CK gate | Status |
| --- | --- | --- | --- |
| 81 | resume on blank media stops, writes nothing | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION: no continuity core (ADR 0016 agent identity/memory) in the C kernel) |
| 82 | unprovisioned store stops UNPROVISIONED | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 83 | provision agent; second provisioning refused; RNDR gives a different identity | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 84 | resume + remember (incarnation 2, Cortex fact, forked branch) | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 85 | cold restarts keep agent/memory/lineage | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 86 | kill at each checkpoint keeps agent and memory | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 87 | malformed peer superblock: read-only, nothing written | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION) |

## M4 recovery: scripts/qemu_recovery_test.sh -> CK `M4_RECOVERY`

| # | Rust check | CK gate | Status |
| --- | --- | --- | --- |
| 88 | inspection enters the Recovery Core (Degraded(Malformed)), writes nothing | M4_RECOVERY | NOT_RUN (MISSING_IMPLEMENTATION: no Recovery Core (ADR 0006) in the C kernel) |
| 89 | repair with bad responses refused; authorised repair; resume after repair; replay is a no-op | M4_RECOVERY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 90 | unprovisioned: only provisioning offered; wrong key refused; operator provisioning resumes | M4_RECOVERY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 91 | identity loss: no action offered, all modes refused, normal boot neither resumes nor mints | M4_RECOVERY | NOT_RUN (MISSING_IMPLEMENTATION) |

## TRUST-1 Gate 4: scripts/qemu_security_suite.sh, scripts/qemu_secureboot_signing_test.sh

These boot the Rust loader image. No C-kernel wrapper exists and
`ck_gates.sh` has no gate for them; they are listed so the parity is
complete.

| # | Rust check | CK gate | Status |
| --- | --- | --- | --- |
| 92 | swTPM attached boot reaches `kernel: alive` + `report_kind: final` | (none) | NOT_RUN (MISSING_IMPLEMENTATION: no CK swTPM run; the C kernel has no TPM path) |
| 93 | soak: N clean boots and resets | (none) | NOT_RUN (MISSING_IMPLEMENTATION: no CK soak harness; M1 ran twice only) |
| 94 | corrupted binary rejected before `kernel: alive` | (none) | NOT_RUN (MISSING_IMPLEMENTATION: no CK corruption test) |
| 95 | Secure Boot: signed boots, unsigned / tampered / wrong-key refused (Access Denied) | (none) | NOT_RUN (MISSING_IMPLEMENTATION: CK BOOTAA64.EFI never signed or booted under Secure Boot) |

## C-only gate

| # | C check | CK gate | Status |
| --- | --- | --- | --- |
| 96 | ARGUS-1 narrow revoke in-kernel (`argus: ok narrow_revoke=1 revoked=denied unrelated=granted authority=unchanged$`) | ARGUS1_REVOKE | DIFFERS (no Rust QEMU gate exists for it; checked on all 5 boots of both geometries, with `caps: ok granted=yes attenuated=yes amplify=denied forged=denied revoked=denied office_token=rndr$`) |
| 97 | corrupt Store superblock (XOR 0xa5 over 2 x 4096 bytes) refused, disk untouched | M4_STORE | DIFFERS (C-only, boot 4: `store: REFUSED proof=structural `, `disk left as found, not reformatted`, `stage store: FAIL`, absent `store: committed`, image sha256 unchanged; nearest Rust check is row 79) |
| 98 | no disk without DMA: Store refuses | M4_STORE | DIFFERS (C-only, boot 5 safe image: `store: REFUSED proof=io step="no boot disk"`, image sha256 unchanged) |

## Summary counts

Rows 1-98: IDENTICAL 15, DIFFERS 22, NOT_RUN 61 (rows 92-95 have no CK gate at all; rows 97-98 are C-only). Rows 13, 24, 47-72, 76 and 96-98 were re-verified against scripts/qemu_ck_store_test.sh and scripts/lib_ck_m1_checks.sh at the commit that adds this line.

`scripts/trust1_m5_qualify.sh --with-qemu` also runs three of these gates as
qemu rows: `ck_m1_boot_qemu` (M1), `ck_store_kernel_qemu` (M4_STORE) and
`ck_argus1_revoke_qemu` (ARGUS1_REVOKE). Its `m5_store_kernel_binding` row
stays MISSING_IMPLEMENTATION: it asks for the binding on a real device, which
QEMU cannot show.
