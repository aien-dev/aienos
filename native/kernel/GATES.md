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

C gates (one line each from `ck_gates.sh`): `M1` and `M3` (from
`scripts/qemu_ck_boot_test.sh`), `M4_NVME`, `M4_STORE`, `ARGUS1_REVOKE`
`SMMU`, `NVME_SHUTDOWN` (from `scripts/qemu_ck_store_test.sh`; rows 21-24b, 47-72, 76 and
96-101 were checked against its exact grep patterns), `P2_ARTIFACT` (from
`scripts/qemu_ck_artifact_test.sh`, rows 33-41), `NET` (C-only, from
`scripts/qemu_ck_net_test.sh`; rows 102-106 and 110-112; the script now also checks the virtio-net SMMU fence (ACCESS_PLATFORM required, out-of-window device DMA refused), rows 102 and 110-112 are QEMU PASS on this branch from the committed forge log `evidence/ck_net_qemu_8bdbc2e46b85d04c422f9d2830c1c4b263e254b3cfecfe21ff0063c9e33c86e8.log`, hardware NOT_RUN), the kernel entropy rows 107-109 (M1 via `scripts/lib_ck_m1_checks.sh`, ARGUS1_REVOKE and M4_STORE via the Store gate boot 7), and the NOT_RUN gates
`M0_ROLLBACK`, `M4_STORE_CRASH`,
`M4_CONTINUITY`, `M4_RECOVERY`, `KEYBOARD`.

`M4_NVME` and `SMMU` PASS in the SMMU-confined mode (default `make full`
image, QEMU `iommu=smmuv3`). The unconfined bypass build
(`make full CK_QEMU_UNSAFE_DMA=1`) is TEST-ONLY: one boot per geometry checks
that it announces itself; it never counts toward a PASS. QEMU only.

Store keys: every gate image (default and QEMU builds) uses the labelled TEST
Store keys, TEST store uuid and TEST machine id. The hardware staging image
(`make full CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS=... CK_MACHINE_ID=...`)
embeds none of them and its Store stage refuses (production Store key source
BLOCKED_OPERATOR on the TRUST-1 key ceremony; native/kernel/README.md "Owner
provisioning"). That is a build-only property checked by
`scripts/ck_owner_keys_check.sh` (`CK_OWNER_KEYS_CHECK`), not a gate in this
table or the receipt; no hardware staging image is booted anywhere.

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

## M3: scripts/qemu_boot_test.sh M3 lines -> CK `M3` (scripts/qemu_ck_boot_test.sh)

| # | Rust check (pattern) | CK gate | Status |
| --- | --- | --- | --- |
| 16 | cooperative threads (`threads: ok`) | M3 | IDENTICAL |
| 17 | EL0 isolation (`el0: ok write=granted forged=denied fault=contained exit=0`) | M3 | IDENTICAL |
| 18 | timer preemption (`preempt: ok`) | M3 | IDENTICAL |
| 19 | MADT placement (`placement: worker0=class0/core0 worker1=class0/core1`) | M3 | IDENTICAL (same pattern; like the Rust kernel this is computed from the MADT GICC entries and no secondary core is started) |
| 20 | typed IPC (`ipc: ok message=delivered cap=delegated rights=attenuated forged=denied revoked=denied`) | M3 | IDENTICAL |

`scripts/lib_ck_m1_checks.sh` (`ck_m3_checks`) greps the same five patterns
as `qemu_boot_test.sh` lines 63-67 on the same boot. `AIENOS_CK_M3` is PASS
only if all five pass and every M1 check of that boot passes (no fault or
panic, QEMU exit 0); the quiet flag held prints `AIENOS_CK_M3: NOT_RUN`.
The C code is `native/kernel/core/m3.c`, `core/sched.c`, `core/ipc.c`,
`arch/m3.S` (ports of the Rust thread.rs, scheduler.rs, ipc.rs, caps.rs,
user.rs and acpi.rs placement). How the C kernel does the work differs, not
the observable:

- one extra line `ipc_detail: exit_a=.. exit_b0=.. exit_b1=.. child=.. revoke=..`
  that no check reads;
- the return from EL0 to the kernel uses SPSR 0x3c5 (EL1h, DAIF masked; Rust 0x5)
  and every EL0 entry zeroes x0-x30, TPIDR_EL0 and TPIDRRO_EL0 (the Rust
  kernel enters EL0 with kernel register values); every exception return
  zeroes TPIDRRO_EL0;
- the EL0 window uses ASID 0 and a full `tlbi vmalle1` on each TTBR0 swap
  (Rust: ASID 1); the code page is EL0 read-only and PXN, the stack page EL0
  read-write, PXN and UXN;
- threads and preempt workers save x19-x30 and sp only (the kernel is built
  without FP/SIMD); EL0 runs with CPACR FPEN=01 so EL0 FP/SIMD traps to the
  kernel and is contained, never saved.

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

## SEED-0B / P2-5 artifact loader: scripts/qemu_artifact_test.sh -> CK `P2_ARTIFACT` (scripts/qemu_ck_artifact_test.sh)

The C loader is `native/kernel/core/artifact_loader.c` with the format,
signature, admission and receipt code in `native/kernel/artifact/` and the
host tool `native/kernel/tools/ck_artifact_tool.c` (C ports of
aienos-artifact, admission.rs, receipt.rs and aienos-artifact-tool; the tool's
pack, sign, negative corpus and expected.txt are byte-identical to the Rust
tool's). Three boots of the full image (`make full`, with the device,
security and Store stages): `make full CK_SEED0B_TEST_ANCHOR=1` (trusts the
RFC 8032 TEST 1 public key only, labelled TEST ONLY), the ordinary build (no
anchors), and the TEST ONLY build again on a copy of the boot disk with one
byte of a sealed artifact flipped. Same QEMU command line plus
`iommu=smmuv3` and the NVMe boot disk; no `-fw_cfg`.

How the C gate differs from the Rust gate (all apply to rows 33-41):

- **Candidate source**: the sealed C Store on the NVMe boot disk instead of
  `\EFI\AIENOS\ARTIFACTS\*.AIEN` read by the UEFI loader (the C boot stub,
  native/boot, reads no files). At image build time the host tool
  `native/kernel/tools/ck_store_image.c` (`make store-image`) writes each
  signed artifact into the Store as ordinary sealed objects (chunks of kind
  0x0A02 plus one index of kind 0x0A01, format in
  `native/kernel/svc/artifact_store.h`); no second disk format. At boot the
  store stage reads them over the SMMU-confined NVMe driver before the NVMe
  DMA revoke and prints `artifact_disk: NAME bytes=N sha256=H` per artifact;
  the gate requires each H to equal the host's SHA-256 of the file, the line
  `artifact_source: nvme_store generation=G candidates=N`, and the order disk
  read < `dma_gate: nvme bus master revoked` < loader. The Store's keys are
  TEST keys, so the bytes stay untrusted: format, signature, digest and
  admission checks run unchanged on them. The 640 KiB per-file limit and a
  missing artifact (FirmwareRead) are applied at the same stage
  (`received`). Hostile disk cases: `D01-DISK-MISSING.AIEN` is named in the
  disk index with no bytes (refused at `received`, FirmwareRead, receipt
  checked); index entries and chunks carry the artifact's SHA-256, so chunks
  of different writes are never spliced (host test); boot 3 flips one byte of P26SEED's sealed envelope, and the
  Store is refused at open (`store: REFUSED`, `artifact_disk: none (Store
  refused: ..)`, `artifact_source: none (..)`, zero candidates, nothing
  admitted). The old QEMU fw_cfg side channel survives only as a TEST build
  (`make CK_TEST_FWCFG_ARTIFACTS=1`, own output directory, prints
  `artifact_source_mode: TEST-ONLY ...` and never counts toward a PASS); the
  Makefile and the gate check that no default image contains its strings or
  symbols.
- **Build and tools**: make + gcc and the in-tree C tool, not cargo and the
  Rust tool; the probe programs are the same committed fixtures packed by
  the same `pack.sh`. No Machine 1 captured-log mode (stays with the Rust gate).
- **Address space**: the task runs on ASID 0 with a full TLB flush on every
  TTBR0 switch (Rust: ASID 2). EL0 FP/SIMD use traps (fault) instead of
  running with zeroed FP state. One loaded task at a time.
- **Frames**: content + page-table frames come as one contiguous batch, and
  the private code-alias (shadow) tables as a second one; absolute free-frame
  counts differ from the Rust kernel's, the before == after check is the same.
- **Capabilities**: a 16-slot loader capability table (generation-checked
  handles `gen << 32 | index`), not the Rust CapabilityTable type.
- **Signatures**: the C Ed25519 (native/sig) also rejects small-order and
  non-canonical public keys and R points; no corpus case depends on this.
- **QEMU exit**: any status other than 0 fails (Rust: only timeout 124).
- Verdict line `AIENOS_CK_P2_ARTIFACT`; the Rust per-category markers
  (ARTIFACT_PARSE ... HOSTILE_MATRIX) are not printed, every check counts
  toward the one verdict.

| # | Rust check (pattern) | CK gate | Status |
| --- | --- | --- | --- |
| 33 | common: kernel alive + M3 threads/el0/ipc proofs unchanged | P2_ARTIFACT | IDENTICAL |
| 34 | firmware read all candidates (`^artifact_candidates: N$`), report not truncated, final report | P2_ARTIFACT | DIFFERS (the store stage reads the candidates from the sealed Store on the NVMe boot disk, not firmware files; same line and count; also requires `artifact_source: nvme_store`, one `artifact_disk:` line per artifact whose SHA-256 equals the host file, disk read before the NVMe DMA revoke, the heap copies released after the loader, no TEST-ONLY fw_cfg source, and fails on `artifact_bundle: malformed`) |
| 35 | frames reclaimed (`artifact_frames_free_before` == `_after`) | P2_ARTIFACT | IDENTICAL (absolute counts differ; verifies execution page frames are reclaimed; candidate heap buffers are also released via ck_stage_disk_artifacts_free) |
| 36 | qualification build labelled TEST ONLY, receipt tier line | P2_ARTIFACT | IDENTICAL |
| 37 | P26SEED read via grant, write/forged denied, granted subset of requested, exactly one capability, receipt | P2_ARTIFACT | IDENTICAL |
| 38 | P25EXEC / P25WX (W^X fault) / P25SPIN (time budget) / P25TAMP (BadSignature) outcomes + receipts | P2_ARTIFACT | IDENTICAL |
| 39 | hostile set: each refused at its stage or admitted-and-contained, receipts checked by the host tool | P2_ARTIFACT | DIFFERS (same expected.txt and checks, receipts checked by the C tool; also requires at least 29 cases, plus two hostile disk cases: an artifact named in the disk index without bytes refused at `received` FirmwareRead with its receipt, and a boot on a disk with one sealed artifact byte flipped where the Store is refused and nothing is read or admitted) |
| 40 | H29 READ\|WRITE requested -> READ granted | P2_ARTIFACT | IDENTICAL |
| 41 | production build refuses every candidate, zero admitted | P2_ARTIFACT | IDENTICAL |

## M0 rollback: scripts/qemu_native_rollback_test.sh -> CK `M0_ROLLBACK`

Every M0 rollback check is about UEFI one-time boot: BootNext dispatch of
the candidate, fallback to Default after a fault, hang, malformed or absent
candidate, BootNext consumed and Default unchanged. No A/B slot logic exists
in the script or in crates/aienos-boot. ADR 0024 Q3 (aien-architecture) freezes loader expansion: no A/B
slots will be added. Rollback is the one-time BootNext rule; under
`docs/BOOT_HANDOFF_CONTRACT.md` section 7.1 these rows run the script with the C kernel image as the candidate, after the script and TEST-build changes listed there. Until a forge receipt covers them they stay NOT_RUN.

| # | Rust check (marker) | CK gate | Status |
| --- | --- | --- | --- |
| 42 | `AAVMF_BOOTNEXT_NVRAM` / `NATIVE_ROLLBACK_NORMAL` | M0_ROLLBACK | NOT_RUN (MISSING_IMPLEMENTATION: C image not yet wired as the BootNext candidate, docs/BOOT_HANDOFF_CONTRACT.md 7.1) |
| 43 | `NATIVE_ROLLBACK_FAULT` (faulted candidate returns to Default) | M0_ROLLBACK | NOT_RUN (MISSING_IMPLEMENTATION: needs TEST-only bad-magic C image, contract 7.1) |
| 44 | `NATIVE_ROLLBACK_TIMEOUT` (hung candidate) | M0_ROLLBACK | NOT_RUN (MISSING_IMPLEMENTATION: needs TEST-only hang C image, contract 7.1) |
| 45 | `NATIVE_ROLLBACK_REJECTED` (malformed image) and absent-image fallback | M0_ROLLBACK | NOT_RUN (MISSING_IMPLEMENTATION: C image as candidate path, contract 7.1) |
| 46 | `NATIVE_ROLLBACK_BOOTNEXT_CONSUMED` / `_DEFAULT_UNCHANGED` | M0_ROLLBACK | NOT_RUN (MISSING_IMPLEMENTATION: C image as candidate, contract 7.1) |

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

Contract: `native/kernel/CONTINUITY_RECOVERY_CONTRACT.md` (SPEC, NOT_RUN). One row per Rust check: rows 81-87 are the
QEMU PASS lines of `scripts/qemu_continuity_test.sh` (receipt `evidence/continuity_qemu_2026-09-25.md`), rows
87a-87i are the host tests `cargo test -p aienos-kernel --lib continuity`
(`crates/aienos-kernel/src/continuity_tests.rs`). No C continuity code exists, so every row is NOT_RUN.

| # | Rust check | CK gate | Status |
| --- | --- | --- | --- |
| 81 | resume on blank media: `CONTINUITY: STOP (store Unformatted)`, image unchanged (script :92-98) | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION: no continuity core (ADR 0016 agent identity/memory) in the C kernel) |
| 82 | formatted store, no agent root: `CONTINUITY: UNPROVISIONED`, image unchanged (:100-108) | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 83 | provision: `CONTINUITY: PROVISIONED agent=<64 hex> incarnation=1 sequence=1 cortex=0 branches=1` (:111-119) | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 83a | second provisioning: `CONTINUITY: STOP (AlreadyProvisioned)`, image unchanged (:122-127) | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 83b | independent provisioning draws a different agent from RNDR (:129-136) | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 84 | resume + remember: `RESUMED .. incarnation=2 sequence=2 cortex=0 branches=1`, `REMEMBERED .. incarnation=2 sequence=3 cortex=1 branches=2` (:139-147) | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 85 | cold restart 1: same agent, same `memory=`, `incarnation=3 sequence=4 cortex=1 branches=2` (:149-160) | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 85a | cold restart 2: same agent and memory, `incarnation=4 sequence=5` (:149-160) | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 86 | SIGKILL at `CHECKPOINT: before_first_write`: same agent, old memory (:163-194) | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 86a | SIGKILL at `after_payloads`: same agent, old memory | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION; C name `after_payload_objects`) |
| 86b | SIGKILL at `after_catalog`: same agent, old memory | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 86c | SIGKILL at `after_commit_record`: same agent, old memory | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 86d | SIGKILL at `after_first_flush`: same agent, old memory | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 86e | SIGKILL at `after_superblock_write`: same agent, old or new memory | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION; C name `after_inactive_superblock`; the sealed Store adds two anchor checkpoints, contract section 6.1) |
| 86f | SIGKILL at `after_final_flush`: same agent, new memory | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 87 | malformed peer superblock: `CONTINUITY: RESUMED_READONLY`, same agent and memory, image unchanged (:196-205) | M4_CONTINUITY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 87a | host `unprovisioned_store_never_mints_an_identity` (continuity_tests.rs:84) | M4_CONTINUITY (host) | NOT_RUN (MISSING_IMPLEMENTATION) |
| 87b | host `provision_then_cold_restart_returns_the_same_identity_and_memory` (:97) | M4_CONTINUITY (host) | NOT_RUN (MISSING_IMPLEMENTATION) |
| 87c | host `provisioning_twice_is_refused` (:142) | M4_CONTINUITY (host) | NOT_RUN (MISSING_IMPLEMENTATION) |
| 87d | host `two_roots_stop_with_conflict` (:152) | M4_CONTINUITY (host) | NOT_RUN (MISSING_IMPLEMENTATION) |
| 87e | host `forked_or_gapped_manifest_chains_are_corrupt` (:178) | M4_CONTINUITY (host) | NOT_RUN (MISSING_IMPLEMENTATION) |
| 87f | host `degraded_mount_resumes_read_only` (:221) | M4_CONTINUITY (host) | NOT_RUN (MISSING_IMPLEMENTATION) |
| 87g | host `a_crash_at_every_write_of_a_commit_leaves_old_or_new_never_a_third_state` (:242) | M4_CONTINUITY (host) | NOT_RUN (MISSING_IMPLEMENTATION) |
| 87h | host `encodings_round_trip_and_reject_tampering` (:286) | M4_CONTINUITY (host) | NOT_RUN (MISSING_IMPLEMENTATION) |
| 87i | host `branch_table_validation_rejects_broken_lineage` (:328) | M4_CONTINUITY (host) | NOT_RUN (MISSING_IMPLEMENTATION) |

## M4 recovery: scripts/qemu_recovery_test.sh -> CK `M4_RECOVERY`

Contract: `native/kernel/CONTINUITY_RECOVERY_CONTRACT.md` (SPEC, NOT_RUN). Rows 88-91c are the QEMU PASS lines of
`scripts/qemu_recovery_test.sh` (receipt `evidence/recovery_core_qemu_2026-09-25.md`), rows 91d-91k the host tests
`cargo test -p aienos-kernel --lib recovery_core` (`crates/aienos-kernel/src/recovery_core_tests.rs`), rows
91l-91p the operator-auth tests in `crates/aienos-kernel/src/recovery.rs`. No C Recovery Core exists, so every
row is NOT_RUN. Operator key is TEST-ONLY in the oracle.

| # | Rust check | CK gate | Status |
| --- | --- | --- | --- |
| 88 | inspection: `RECOVERY_OPERATOR_KEY: TEST-ONLY`, `RECOVERY_CORE: ENTERED reason=Degraded(Malformed)`, same agent in `RECOVERY_RECORD:`, image unchanged, repair challenge offered (script :94-103) | M4_RECOVERY | NOT_RUN (MISSING_IMPLEMENTATION: no Recovery Core (ADR 0006) in the C kernel) |
| 88a | repair with zero response: `RECOVERY_REFUSED (Unauthorised)`, image unchanged (:105-117) | M4_RECOVERY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 88b | repair with wrong-key response: `RECOVERY_REFUSED (Unauthorised)`, image unchanged | M4_RECOVERY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 88c | repair with a response to another challenge: `RECOVERY_REFUSED (Unauthorised)`, image unchanged | M4_RECOVERY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 89 | authorised repair: `RECOVERY_ACTION: repair-degraded-peer DONE`, image changed (:119-125) | M4_RECOVERY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 89a | after repair a cold boot `CONTINUITY: RESUMED` writable, same agent and memory (:126-132) | M4_RECOVERY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 89b | replaying the repair response: `RECOVERY_REFUSED (NotApplicable)`, image unchanged (:133-138) | M4_RECOVERY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 90 | unprovisioned store: `ENTERED reason=Unprovisioned`, only the provision challenge, image unchanged (:141-149) | M4_RECOVERY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 90a | provisioning with a wrong key: `RECOVERY_REFUSED (Unauthorised)`, image unchanged (:150-155) | M4_RECOVERY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 90b | authorised provisioning: `RECOVERY_ACTION: provision-identity DONE agent=..`, a cold boot resumes that agent (:156-163) | M4_RECOVERY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 91 | corrupted agent root: `RECOVERY_CORE: ENTERED`, no `RECOVERY_CHALLENGE`, image unchanged (:166-174) | M4_RECOVERY | NOT_RUN (MISSING_IMPLEMENTATION; in the sealed C Store the flip is expected to be refused at the keyed proof instead, UNVERIFIED, contract K-3) |
| 91a | mode 10 (repair) after identity loss with a forged response: refused, no action, image unchanged (:175-183) | M4_RECOVERY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 91b | mode 11 (provision) after identity loss with a forged response: refused, no action, image unchanged (:175-183) | M4_RECOVERY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 91c | normal boot after identity loss neither resumes nor mints, image unchanged (:184-189) | M4_RECOVERY | NOT_RUN (MISSING_IMPLEMENTATION) |
| 91d | host `inspection_never_writes_and_names_the_reason` (recovery_core_tests.rs:89) | M4_RECOVERY (host) | NOT_RUN (MISSING_IMPLEMENTATION) |
| 91e | host `degraded_repair_needs_the_operator_and_restores_a_writable_store` (:111) | M4_RECOVERY (host) | NOT_RUN (MISSING_IMPLEMENTATION) |
| 91f | host `provisioning_is_operator_only_and_only_on_an_unprovisioned_store` (:154) | M4_RECOVERY (host) | NOT_RUN (MISSING_IMPLEMENTATION) |
| 91g | host `identity_lost_in_the_newest_root_never_looks_unprovisioned` (:178) | M4_RECOVERY (host) | NOT_RUN (MISSING_IMPLEMENTATION) |
| 91h | host `malformed_peer_without_a_resolvable_identity_is_not_repaired` (:222) | M4_RECOVERY (host) | NOT_RUN (MISSING_IMPLEMENTATION) |
| 91i | host `orphaned_continuity_objects_are_corrupt_not_unprovisioned` (:236) | M4_RECOVERY (host) | NOT_RUN (MISSING_IMPLEMENTATION) |
| 91j | host `identity_loss_through_corruption_offers_no_action_that_mints` (:267) | M4_RECOVERY (host) | NOT_RUN (MISSING_IMPLEMENTATION) |
| 91k | host `challenges_bind_state_and_action` (:300) | M4_RECOVERY (host) | NOT_RUN (MISSING_IMPLEMENTATION) |
| 91l | host `hmac_primitive_rfc4231_case_2` (recovery.rs:238) | M4_RECOVERY (host) | NOT_RUN (MISSING_IMPLEMENTATION: no C operator-auth wrapper; the C HMAC primitive itself is `aienos_hmac_sha256` in native/crypto) |
| 91m | host `operator_auth_known_answer_accepted` (recovery.rs:251) | M4_RECOVERY (host) | NOT_RUN (MISSING_IMPLEMENTATION) |
| 91n | host `operator_auth_rejects_any_single_bit_flip` (recovery.rs:269) | M4_RECOVERY (host) | NOT_RUN (MISSING_IMPLEMENTATION) |
| 91o | host `operator_auth_rejects_legacy_bare_sha256_response` (recovery.rs:299) | M4_RECOVERY (host) | NOT_RUN (MISSING_IMPLEMENTATION) |
| 91p | host `operator_auth_rejects_undomained_hmac_and_zero_response` (recovery.rs:311) | M4_RECOVERY (host) | NOT_RUN (MISSING_IMPLEMENTATION) |

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

## C-only gates

| # | C check | CK gate | Status |
| --- | --- | --- | --- |
| 96 | ARGUS-1 narrow revoke in-kernel (`argus: ok narrow_revoke=1 revoked=denied unrelated=granted authority=unchanged$`) | ARGUS1_REVOKE | DIFFERS (no Rust QEMU gate exists for it; checked on all 5 boots of both geometries, with `caps: ok granted=yes attenuated=yes amplify=denied forged=denied revoked=denied office_token=rndr$`) |
| 97 | corrupt Store superblock (XOR 0xa5 over 2 x 4096 bytes) refused, disk untouched | M4_STORE | DIFFERS (C-only, boot 4: `store: REFUSED proof=structural `, `disk left as found, not reformatted`, `stage store: FAIL`, absent `store: committed`, image sha256 unchanged; nearest Rust check is row 79) |
| 98 | no disk without DMA: Store refuses | M4_STORE | DIFFERS (C-only, boot 5 safe image: `store: REFUSED proof=io step="no boot disk"`, image sha256 unchanged) |
| 99 | NVMe normal shutdown before bus-master disable (CC.SHN = 01b, then wait CSTS.SHST = 10b) | NVME_SHUTDOWN | DIFFERS (C-only; the Rust kernel has no NVMe shutdown. Boots 1-4 and 6, both geometries: exactly one `nvme: shutdown normal cc=0x..->0x.. csts=0x.. shst=complete waited_us=N` line with CC.SHN read back as 01b and CSTS.SHST as 10b, printed before `dma_gate: nvme bus master revoked`, and no `nvme: shutdown fallback disable` line. Host tests cover CFS, not-ready, already-shut, timeout and the CC.EN = 0 fallback) |
| 100 | QEMU device trace shows the shutdown while bus master is on | NVME_SHUTDOWN | DIFFERS (C-only: QEMU `-trace` of `pci_nvme_mmio_shutdown_set` and `pci_cfg_write` on the NVMe command register; the shutdown must land between the guest's BME-set and BME-clear writes) |
| 101 | reset path quiesces DMA first; no shutdown without a bound controller | NVME_SHUTDOWN | DIFFERS (C-only: `devices: quiesce before reset nvme=already-released` on every boot (`ck_reset` hook, also covers panic/fault resets); boot 5 safe image: absent `nvme: shutdown normal`) |
| 102 | virtio-net attach behind an SMMU window (`virtio_net: .. caps ok`, `smmu_dma_window: virtio_net only iova=.. len=.. rid=.. stream_id=..`, `dma_gate: virtio_net granted (Confined), bus master on`, `virtio_net: attached .. mac=52:54:00:12:34:56 features=0x300000020 access_platform=yes`, ARP reply from the slirp gateway `52:55:0a:00:02:02`) | NET | QEMU PASS (receipt `evidence/ck_net_qemu_8bdbc2e46b85d04c422f9d2830c1c4b263e254b3cfecfe21ff0063c9e33c86e8.log`, forge log of `scripts/qemu_ck_net_test.sh` at 6816358, ends `AIENOS_CK_NET: PASS`; hardware NOT_RUN: no physical NIC or SMMU. no Rust counterpart: the Rust kernel has no virtio-net queue driver. Boot 1, `iommu=smmuv3`, NIC `virtio-net-pci,disable-legacy=on,iommu_platform=on`, QEMU user networking (slirp) `restrict=off`, driver `native/net/aienos_virtio_net.c` via `native/kernel/dev/net_bind.c`. The driver negotiates VIRTIO_F_ACCESS_PLATFORM (bit 33; features = VERSION_1 + ACCESS_PLATFORM + MAC) and the kernel requires it, so QEMU is expected to send every ring and buffer access of the NIC through the smmuv3 vIOMMU, which rows 110-111 test. The receipt log line 23 shows the `access_platform=yes` attach (features VERSION_1|ACCESS_PLATFORM|MAC); the older NET receipt `evidence/ck_gates_929f287e9c950c45c7dcd569c7caa03709ea62ecfe393635b435058afa969c54.json` predates this change and was taken with `access_platform=no`. Hosted `native/net` test `VNET_ACCESS_PLATFORM_SIM` PASS in the forge run `make -C native/net test` (log HIVE-L31NET-173414.log, not committed; simulated device only)) |
| 103 | one UDP frame sent (TX) | NET | DIFFERS (C-only: guest `net: udp tx 10.0.2.15:47030 -> 10.0.2.2:47029 .. payload="AIENOS-CK-NET ping nonce=<8 hex>" .. completed=yes` AND the in-tree host helper `native/kernel/tools/ck_udp_echo.c` (`make udp-echo`) logs the same nonce arriving on 127.0.0.1:47029 through slirp) |
| 104 | one UDP frame received (RX) and parsed by M6-A | NET | DIFFERS (C-only: guest `net: udp rx 10.0.2.2:47029 -> 10.0.2.15:47030 .. udp_csum=verified parsed=m6a echo_of_ours=yes payload="AIENOS-CK-NET pong token=<per-run random token> echo=<the guest's own ping>"`; the token is generated by the script per run, so the line cannot pass without the helper's reply reaching the guest; plus `net: udp round trip ok`, `net: selftest PASS (rc=0)` and `devices: pci=ok nvme=bound virtio_net=selftest-ok`) |
| 105 | virtio-net released after the round trip | NET | DIFFERS (C-only: `virtio_net: device reset status=0x00 (stopped)`, `dma_gate: virtio_net bus master revoked`, `smmu: virtio_net stream 0x.. returned to abort (rc=0)`; line order grant < round trip < reset < revoke < abort, as in the last receipt; the longer order with the fault (row 110) and recovery (row 111) before the reset is checked by the script and passed in the QEMU receipt line 45, hardware NOT_RUN) |
| 106 | virtio-net fails closed without an SMMU | NET | DIFFERS (C-only: boot 2 without `iommu=smmuv3`: `dma_gate: virtio_net denied (NoSmmu rc=-1), bus master stays off`, `virtio_net: not bound (SMMU DMA isolation not active)`, absent `dma_gate: virtio_net granted` and `net: udp tx`, and the host helper receives nothing. Host test `stage_test` also checks the fail-closed bind leaves the command register without MEM/BME) |
| 107 | kernel entropy is the RNDR instruction or nothing: FEAT_RNG checked first (ID_AA64ISAR0_EL1.RNDR), each 64-bit word retried at most 64 times (NZCV.Z = failure), stuck-output test, refusal latched and the buffer zeroed; no timer or other fallback source exists (`entropy: rndr feat_rng=yes probe_words=2 retries=N stuck_test=ok$`, absent `entropy: unavailable` and `entropy: refused`) | M1 (and every M1-checked boot of the Store and NET gates, via scripts/lib_ck_m1_checks.sh) | DIFFERS (C-only addition; no Rust M1 counterpart. Host test `tests/test_entropy.c` drives the selection logic with a mocked RNDR: absent, always failing, failing 63 then succeeding, failing exactly 64 (refused), dying mid-fill, stuck, never probed, latched refusal. QEMU -cpu max has FEAT_RNG; GB10 RNDR availability is UNVERIFIED) |
| 108 | without RNDR the security services fail closed: the office token read is refused, caps and ARGUS never start, `stage security: FAIL` | ARGUS1_REVOKE (and M1 for that boot, with the refusal expected instead of `entropy: rndr`) | DIFFERS (C-only, Store gate boot 7 on QEMU `-cpu neoverse-n1` (no FEAT_RNG): `entropy: unavailable reason=absent (ID_AA64ISAR0_EL1.RNDR=0, no FEAT_RNG); ...`, `entropy: refused consumer=/dev/urandom (capability office token) reason=absent; service fails closed`, `security: REFUSED kernel entropy absent ...`, `caps: failed ... office_token=none`, `argus: FAIL step=cap_start`, `stage security: FAIL`, absent `caps: ok` and `argus: ok`. ARGUS1_REVOKE cannot PASS unless this boot refuses) |
| 109 | the Store needs no entropy (its envelope ids and nonces are keyed functions, native/store/store_sealed.h) and still opens without RNDR | M4_STORE | DIFFERS (C-only, Store gate boot 7: `stage store: ok`) |
| 110 | virtio-net device DMA outside its SMMU window refused | NET | QEMU PASS (receipt `evidence/ck_net_qemu_8bdbc2e46b85d04c422f9d2830c1c4b263e254b3cfecfe21ff0063c9e33c86e8.log`, forge log of `scripts/qemu_ck_net_test.sh` at 6816358, ends `AIENOS_CK_NET: PASS`; hardware NOT_RUN: no physical NIC or SMMU. Receipt lines 32-35 (fence section). C-only, boot 1 after the round trip: every RX descriptor the NIC holds is pointed at a 0x5a page outside the window and one probe datagram (`AIENOS-CK-NET ping smmu-probe nonce=<8 hex>`, logged and answered by the host helper) draws a reply the NIC must write. `net_smmu_negative: refused rx dma outside window iova=.. faults=N type=0x10 sid=.. addr=.. page=intact rx_completed=N device_status=0x.. needs_reset=.. faults_during_roundtrip=0 overflow=0`: the fields are read from the SMMU event queue (F_TRANSLATION) and the script re-checks them itself: page outside the `smmu_dma_window` range, event stream id equal to the NIC's, event address inside that page. Earlier lane-branch observation, now matched by the committed receipt (2026-10-01, QEMU 8.2.2): 16 F_TRANSLATION records for the NIC stream at the page, no NEEDS_RESET, and QEMU completed the RX through its internal bounce buffer (rx_completed=1, write dropped, page intact); rx_completed and needs_reset are reported, not judged. The kernel does not panic) |
| 111 | virtio-net recovers inside the window after the refused DMA | NET | QEMU PASS (receipt `evidence/ck_net_qemu_8bdbc2e46b85d04c422f9d2830c1c4b263e254b3cfecfe21ff0063c9e33c86e8.log`, forge log of `scripts/qemu_ck_net_test.sh` at 6816358, ends `AIENOS_CK_NET: PASS`; hardware NOT_RUN: no physical NIC or SMMU. Receipt lines 36-38. C-only, boot 1, what the script checks: `net_smmu_recovery: device reset + reinit ok (Ok) access_platform=yes late_probe_faults=N` (status 0 written and read back before the rings are rebuilt; probe events that land after the negative test are drained and reported here) and `net_smmu_recovery: round trip after the fault ok (rc=0 new_faults=0)`, a second ARP + UDP round trip with this run's helper token, then the normal release order of row 105. To be shown: recovery by device reset + re-init; not covered even when run: a NIC that keeps running through the fault (the kernel discards the redirected descriptors and resets)) |
| 112 | virtio-net without ACCESS_PLATFORM refused (fail closed) | NET | QEMU PASS (receipt `evidence/ck_net_qemu_8bdbc2e46b85d04c422f9d2830c1c4b263e254b3cfecfe21ff0063c9e33c86e8.log`, forge log of `scripts/qemu_ck_net_test.sh` at 6816358, ends `AIENOS_CK_NET: PASS`; hardware NOT_RUN: no physical NIC or SMMU. Receipt lines 86-93 (boot net-noap). C-only, boot 3, what the script checks: `iommu=smmuv3` but the NIC modern-only (`disable-legacy=on`) without `iommu_platform=on`, so QEMU offers no ACCESS_PLATFORM and would DMA around the vIOMMU: `virtio_net: init FAIL (NoAccessPlatform)` before FEATURES_OK, absent `virtio_net: attached` and `net: udp tx`, stream returned to abort, host helper receives nothing) |

## DISK_LAYOUT: partition-aware disk footprint (C-only, audit R2) -> CK `DISK_LAYOUT` (scripts/qemu_ck_disk_layout_test.sh)

No Rust QEMU gate exists for this; the Rust Store writes the whole disk. The C
kernel parses the GPT read-only (UEFI 2.10 section 5.3: protective MBR,
primary header at LBA 1, entry array, backup entry array and backup header at
the end; CRC32 of both headers and both entry arrays) and selects the one
partition whose type GUID is the AIENOS type
`38DAAC89-5EAD-4B40-8B1E-3687A7418061` (dev/disk_part.h). The Store,
torn-slot device and NVMe rw probe receive only that partition's view; every
read, write and flush goes through the bounds-checked translation
`ck_part_xlate` (partition LBA -> disk LBA). Without exactly one valid AIENOS
partition the kernel prints `disk: no AIENOS partition, refusing writes (gpt:
<reason>, rc=N)` and never writes; there is no whole-disk fallback. The only
way around the translation is the TEST-ONLY mutation build
`make full CK_TEST_DISK_XLATE_BYPASS=1` (refused with `CK_HARDWARE_STAGING`
by the Makefile and by an `#error`). The Store, NET and artifact gates now
boot GPT images from `native/kernel/tools/ck_gpt_image.c` (AIENOS partition
[9,57) MiB of 64 MiB, filled sentinel partitions on both sides).

Firmware caveat: EDK2/AAVMF may repair a GPT whose primary or backup copy
alone is bad, so the QEMU hostile images corrupt both copies; single-copy
corruption is covered only by the host test `dev/tests/disk_part_test.c`
(`make -C native/kernel stage-test`, target `disk-part-test`).

| # | C check | CK gate | Status |
| --- | --- | --- | --- |
| 113 | GPT parsed with CRC32 on both headers and both entry arrays; the AIENOS partition is found exactly where the image tool wrote it (`disk: gpt ok primary+backup crc32 entries=128 used=3 aienos_index=1 first_lba=F last_lba=L `), 512 B (2 boots) and 4096 B (1 boot) | DISK_LAYOUT | NOT_RUN (pending forge receipt) |
| 114 | translation layer: partition LBA 0 -> partition start, past-end / straddling / overflowing LBAs refused (`disk: xlate part_lba=0 -> disk_lba=F (rc=0)`, `disk: write past partition end part_lba=N -> refused `); rw probe disk LBA inside [F,L] | DISK_LAYOUT | NOT_RUN (pending forge receipt) |
| 115 | footprint: Store formats and commits inside the partition; every byte outside it (MBR, both GPT copies, both sentinels) unchanged (sha256 with the partition cut out), the partition itself written. Also checked on boots 1-3 of both geometries by `scripts/qemu_ck_store_test.sh` | DISK_LAYOUT (and M4_STORE) | NOT_RUN (pending forge receipt) |
| 116 | hostile disks refused, image byte-identical, Store refused `step="no boot disk"`, no rw probe: no GPT, bad CRC32 on both headers, bad entry-array CRC32 on both arrays, AIENOS partition ending past the disk, no AIENOS partition; the host tool's own parser (`ck_gpt_image find`) must give the same reason | DISK_LAYOUT | NOT_RUN (pending forge receipt) |
| 117 | mutation: the TEST-ONLY translation-bypass image announces itself and FAILs rows 113-115 (its translation self-check prints `NOT REFUSED`); the default image contains no bypass text | DISK_LAYOUT | NOT_RUN (pending forge receipt) |
| 118 | host test: CRC32 known answer, good layouts at 512/4096, writes through the view never change bytes outside the partition, full Store boot on the view, single-copy corruption, header field patches, backup disagreement, overlap, two AIENOS partitions, too many entries; the bypass build of the same test must FAIL (`CK_DISK_PART_MUTANT: PASS`) | DISK_LAYOUT (host, `make stage-test`) | NOT_RUN (pending forge receipt) |

## Summary counts

**C kernel receipt tally (QEMU only, no physical run):** this branch adds a 15th CK gate, `DISK_LAYOUT`, NOT_RUN (pending forge receipt); no receipt covers 15 gates yet, and the Store, NET and artifact gates now boot GPT images, so their PASS below is from receipts taken before that change until `ck_gates.sh` is rerun. Last receipt: 9 of 14 CK gates PASS, 5 NOT_RUN (M0_ROLLBACK, M4_STORE_CRASH, M4_CONTINUITY, M4_RECOVERY, KEYBOARD), 0 FAIL, matching `evidence/ck_gates_929f287e9c950c45c7dcd569c7caa03709ea62ecfe393635b435058afa969c54.json` (run at 41aa0e6, which adds the kernel entropy rows 107-109; that commit was then rebased onto #210, which changed only README.md and CONTRIBUTING.md). The row counts below are per Rust-parity row, not per gate.

Rows 113-118 (DISK_LAYOUT, C-only, CK-4) are all NOT_RUN (pending forge receipt), so with them: IDENTICAL 28, DIFFERS 39, NOT_RUN 92 (the main-branch figures next, not recounted by CK-4, plus 6 NOT_RUN). Rows 1-112 plus the M4 continuity/recovery sub-rows 83a-87i and 88a-91p: IDENTICAL 28, DIFFERS 39, NOT_RUN 86, counted from the table (the CK-5 contract branch split rows 81-91, 11 NOT_RUN rows, into 52 NOT_RUN rows, one per Rust QEMU check and host test, see `native/kernel/CONTINUITY_RECOVERY_CONTRACT.md`; that adds 41 NOT_RUN rows and changes no other row or gate; the CK gate tally is unchanged; rows 107-109, kernel entropy, are C-only and DIFFERS; row 102, virtio-net attach with ACCESS_PLATFORM, and rows 110-112, virtio-net SMMU fence, recovery and ACCESS_PLATFORM fail-closed, are C-only and NOT_RUN on this branch until a forge receipt covers them; the CK gate tally above and its receipt `ck_gates_929f...` predate them; no full `ck_gates.sh` run happened on this branch, only `scripts/qemu_ck_net_test.sh` alone, so rows 102 and 110-112 are shown as QEMU PASS (receipt `evidence/ck_net_qemu_8bdbc2e46b85d04c422f9d2830c1c4b263e254b3cfecfe21ff0063c9e33c86e8.log`, hardware NOT_RUN) and the NOT_RUN count still includes them as originally counted, not recounted); rows 34 and 39 now also cover the NVMe boot-disk source and its hostile disk cases (statuses unchanged) (the previous summary, 20/30/56, was miscounted: the table on main had 21/35/50; rows 33-41 then moved from NOT_RUN to 7 IDENTICAL + 2 DIFFERS with the C artifact loader; rows 92-95 have no CK gate at all; rows 96-112 are C-only). Rows 33-41 were checked against scripts/qemu_ck_artifact_test.sh. Rows 102-106 and 110-112 were checked against scripts/qemu_ck_net_test.sh (text only; rows 102 and 110-112 then run by the forge, see their rows). Rows 13, 24, 47-72, 76 and 96-101 were re-verified against scripts/qemu_ck_store_test.sh and scripts/lib_ck_m1_checks.sh at the commit that adds this line.

`scripts/trust1_m5_qualify.sh --with-qemu` also runs three of these gates as
qemu rows: `ck_m1_boot_qemu` (M1), `ck_store_kernel_qemu` (M4_STORE) and
`ck_argus1_revoke_qemu` (ARGUS1_REVOKE). Its `m5_store_kernel_binding` row
stays MISSING_IMPLEMENTATION: it asks for the binding on a real device, which
QEMU cannot show.
