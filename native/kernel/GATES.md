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
`scripts/qemu_ck_net_test.sh`; rows 102-106 and 110-112; the script now also checks the virtio-net SMMU fence (ACCESS_PLATFORM required, out-of-window device DMA refused), rows 102 and 110-112 are QEMU PASS on this branch from the committed forge log `evidence/ck_net_qemu_8bdbc2e46b85d04c422f9d2830c1c4b263e254b3cfecfe21ff0063c9e33c86e8.log`, hardware NOT_RUN), the kernel entropy rows 107-109 (M1 via `scripts/lib_ck_m1_checks.sh`, ARGUS1_REVOKE and M4_STORE via the Store gate boot 7),
`DISK_LAYOUT` (C-only, from `scripts/qemu_ck_disk_layout_test.sh`, rows 118-123: QEMU PASS at 741b2b8 before the merge with main 8555049, rerun pending at the merged head; row 123 host test), and the NOT_RUN gates
`SMP` (C-only, from `scripts/qemu_ck_smp_test.sh`, rows 113-117, NOT_RUN pending forge receipt), `M0_ROLLBACK`, `M4_STORE_CRASH` (now read from `scripts/qemu_ck_store_crash_test.sh`, rows 73-80; NOT_RUN until a forge receipt exists),
`M4_CONTINUITY`, `M4_RECOVERY`, `M4_ALLEN` (C-only, from `scripts/qemu_ck_allen_test.sh`, rows A1-A30; QEMU PASS, hardware NOT_RUN), `KEYBOARD` (from `scripts/qemu_ck_keyboard_test.sh`, rows 25-32 and C-only 30a-30c and 32a; QEMU PASS; C-only row 32b and all hardware NOT_RUN), `FPU` (C-only, from `scripts/qemu_ck_fpu_test.sh`, rows 124-128; QEMU PASS, hardware NOT_RUN), `INFER` (C-only, from `scripts/qemu_ck_infer_test.sh`, rows 129-139; QEMU PASS, hardware NOT_RUN), and `SCREEN` (C-only, from `scripts/qemu_ck_screen_test.sh`, rows 140-145; QEMU PASS, hardware NOT_RUN).

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

C child script: `scripts/qemu_ck_keyboard_test.sh`. Three boots in one run,
same devices as the Rust gate (`qemu-xhci` + `usb-kbd`, plus an NVMe disk for
the normal full boot): `kbd-smmu` with QEMU `iommu=smmuv3`, `kbd-nosmmu`
without, and `kbd-recovery` (SMMU on). Keys are injected by the script through
the QEMU monitor (`sendkey`, as the Rust gate does); the kernel never fakes the
device. Boot `kbd-smmu` sends no key in the recovery window, then the lines
`abc`, `help`, `el`, `mem`, 65 `x` keys (one past the 64-key line bound) and
`exit`. Boot `kbd-recovery` sends `r` in the recovery window. It prints one
`KEYBOARD_ROW <n>: PASS|FAIL|NOT_RUN` line per row, then
`AIENOS_CK_KEYBOARD_DMA: PASS|FAIL (rows 25-28,31,32)` and
`AIENOS_CK_KEYBOARD: PASS|FAIL|NOT_RUN` (NOT_RUN with exit 3 while the QEMU
gate lock is held, while the quiet flag exists, or when `AIENOS_QEMU_SMMU`
selects only one mode). `scripts/ck_gates.sh` takes KEYBOARD from this child
only.

C code: the post-exit bus-master sweep `pci_sweep_bus_master`
(native/kernel/dev/pci.c), the xHCI DMA fence `native/kernel/dev/xhci_fence.c`
(`ck_dma_confine` window first, then memory decode + bus master; no SMMU means
no DMA, no bypass build; controller halted, bus master revoked, stream back to
abort), and inside that fence the polled keyboard driver
`native/kernel/dev/usb_kbd.c` (xHCI reset, command and event rings, Enable
Slot, Address Device, configuration descriptor, Configure Endpoint,
SET_PROTOCOL boot, interrupt IN transfers; port of the Rust
`crates/aienos-kernel/src/usb/xhci` and `crates/aienos-boot/src/usb_keyboard.rs`)
with its pure logic in `native/kernel/dev/usb_hid.c` (boot report decode to a
fixed US keymap, descriptor walk, bounded line editor, the Rust shell commands,
the recovery-access decision and identity digest). Every ring, context and
buffer lives in the fence's DMA region, the controller stream's only SMMU
window. The recovery choice is acted on by `native/kernel/dev/devices.c`
after the xHCI revoke: virtio-net and NVMe DMA released, then the recovery
console stub prints the identity digest and halts. Operator-facing
description and the physical attended-boot procedure:
`native/kernel/README.md`, section "Operator input and recovery access (C
kernel)".

Mutation self-test: `scripts/qemu_ck_keyboard_test.sh --mutation` builds
`make full CK_TEST_XHCI_MUTATION=<m>` (TEST-ONLY, refused with
`CK_HARDWARE_STAGING=1` and with `CK_QEMU_UNSAFE_DMA=1`, by the Makefile and by
an `#error`; the default image is checked to carry no mutation banner) and
requires bm-left-on -> row 27, no-revoke -> row 31, grant-no-smmu -> row 28,
no-sweep -> row 26 to FAIL. Host tests (`stage_test`): sweep on a fake ECAM,
the fence fail-closed paths, and the operator input logic (keymap, report
decode with held keys and rollover, descriptor walk with malformed lengths,
line editor overflow refusal, shell output texts, recovery decision, identity
digest). One deliberate difference from Rust: the Rust shell drops keys past
its 64-byte line; the C editor refuses the whole line (row 30c). Hardware
NOT_RUN: no physical xHCI, keyboard or SMMU run.

Platform xHCI (NEXT-PHASE-3 cut 2, C only): when no PCI xHCI exists, or the
PCI one has no keyboard, the fence tries the ACPI platform controllers that
`native/kernel/core/acpi_dev.c` finds in the DSDT/SSDTs (`_HID`/`_CID`
NVDA8000, NVDA8001, PNP0D10, PNP0D15), each confined by its IORT named
component stream (`ck_dma_confine_named`), fail closed otherwise. QEMU virt
has no such controller, so QEMU proves the walker on QEMU's own tables (row
32a) and that the PCI path is unchanged (rows 25-32); the platform grant path
itself has no QEMU run. Host tests: `tests/test_acpi_dev.c` (string and
EisaId ids, Name and Method `_CRS`, Memory32Fixed and QWord ranges, nested
devices, malformed packages and descriptors, IORT named components found,
absent, ambiguous, malformed, behind another SMMU), and `make acpi-dev-mutant`
requires it to FAIL against three walker mutants (table signature check,
checksum check, length-versus-buffer check removed). `make acpi-scan` builds
`tools/ck_acpi_scan.c`, which runs the same scan over firmware tables dumped
under Linux and prints the kernel's lines; its output for this Spark is
`tests/fixtures/spark_xhci_acpi_expected.txt` (row 32b).

| # | Rust check (pattern) | CK gate | Status |
| --- | --- | --- | --- |
| 25 | xHCI found before exit (`keyboard: xhci `) | KEYBOARD | QEMU PASS, DIFFERS: found after exit on the ECAM walk, class 0x0c0330, `keyboard: xhci 0000:BB:DD.F mmio 0x.. (found post-exit on the ECAM walk)`, all three boots |
| 26 | bus-master sweep after exit (`dma_sweep: seg `, no `dma_sweep: bme STUCK`) | KEYBOARD | QEMU PASS, DIFFERS: same line text as Rust, and stricter: the sweep must come before the first `dma_gate: ` line and before `keyboard: xhci `; all three boots; mutation no-sweep |
| 27 | xHCI bus master off before the DMA gate (`xhci_pci: command=0x.. bus_master=off`) | KEYBOARD | QEMU PASS, IDENTICAL prefix `xhci_pci: command=0x.... bus_master=off`, plus the order check: before `dma_gate: xhci `; all three boots; mutation bm-left-on |
| 28 | fail-closed without SMMU (`dma_gate: xhci denied (NoSmmu)...`, `keyboard: unavailable (...)`, no grant, no `keyboard: ready`) | KEYBOARD | QEMU PASS, IDENTICAL lines `dma_gate: xhci denied (NoSmmu), bus master stays off` and `keyboard: unavailable (SMMU DMA isolation not active)`, absent `dma_gate: xhci granted` and `keyboard: ready`, plus C-only: COMMAND read back after the deny `bus_master=off`, no xHCI SMMU window; boot kbd-nosmmu; mutation grant-no-smmu |
| 29 | keyboard attached and typed line echoed (`keyboard: ready`, `keyboard_echo:`, `keyboard_line:`, `keyboard: done (enter)`) | KEYBOARD | QEMU PASS, DIFFERS: same four line prefixes (`keyboard: ready (port P, slot S, endpoint 0x81)`, `keyboard_echo: abc`, `keyboard_line: abc`, `keyboard: done (enter)`), plus C-only order checks: attached after `dma_gate: xhci granted (Confined)` and the line before the revoke; boots kbd-smmu (and attach in kbd-recovery) |
| 30 | shell commands (`commands: help mem el report uptime exit`, `EL1`, `conventional_memory_kb:`, `keyboard: done (exit)`) | KEYBOARD | QEMU PASS, IDENTICAL output texts (`commands: help mem el report uptime exit`, `EL1`, `conventional_memory_kb: N`, `keyboard: done (exit)`), plus exit before the revoke; boot kbd-smmu |
| 30a | (C only) recovery window: no key means normal boot | KEYBOARD | C only, QEMU PASS: `recovery_access: waiting 5000 ms ...` after `keyboard: ready`, `recovery_access: choice=normal reason=timeout` before the shell, no recovery console (boot kbd-smmu); without an SMMU `recovery_access: unavailable (no operator keyboard: xhci=denied); choice=normal reason=no-keyboard` and no wait (boot kbd-nosmmu) |
| 30b | (C only) key `r` selects the recovery console stub | KEYBOARD | C only, QEMU PASS: `recovery_access: choice=recovery reason=key-r` before the xHCI revoke, `devices: recovery halt nvme=released virtio_net=released xhci=released`, `recovery_console: identity build_sha256=<hex>` equal to the digest the script recomputes from the commit, `recovery_console: halted`, no shell, no Store stage, no final report, no panic, QEMU still running 3 s later (halted, not reset); boot kbd-recovery |
| 30c | (C only) overlong line fails closed | KEYBOARD | C only, QEMU PASS: 65 keys then Enter gives `keyboard_line: overflow (line refused: 65 keys typed, limit 64)` and `keyboard: done (overflow)`; no `keyboard_line:` with that text and no command run from it; boot kbd-smmu (Rust silently truncates instead) |
| 31 | xHCI bus master revoked after the phase (`dma_gate: xhci bus master revoked`) | KEYBOARD | QEMU PASS, DIFFERS (stronger): the same line after `smmu_dma_window: xhci only, translation active ...` and `dma_gate: xhci granted (Confined), bus master on`, controller halted first (`xhci: halt before revoke ... halted=yes`), COMMAND read back `xhci_pci: after phase command=0x.... bus_master=off`, `smmu: xhci stream 0x.. returned to abort (rc=0)`, in that order and before the end of the xHCI phase; boots kbd-smmu and kbd-recovery; mutation no-revoke |
| 32 | no panic or fault | KEYBOARD | QEMU PASS, IDENTICAL: `report_kind: (panic\|fault)` absent, plus `report_kind: final`, QEMU exit 0 and every M1 check of scripts/lib_ck_m1_checks.sh; boots kbd-smmu and kbd-nosmmu |
| 32a | (C only) ACPI platform walker on QEMU's own tables, PCI path kept | KEYBOARD | C only, QEMU PASS: `acpi_scan: tables=N refused=0 first_refusal=0 devices=M (static scan; _STA not evaluated)` with N, M > 0 (QEMU: tables=1 devices=46), positive control `acpi_scan: control ARMH0011 COM0 mmio=0x9000000+0x1000` (the QEMU virt UART), `xhci_acpi: 0 platform controller(s)`, and no `xhci_plat:` line or platform fallback; all three boots |
| 32b | (C only) DGX Spark platform xHCI expectation | KEYBOARD | C only, hardware NOT_RUN (never counted): the lines in `native/kernel/tests/fixtures/spark_xhci_acpi_expected.txt`, predicted by `tools/ck_acpi_scan.c` from this Spark's DSDT/SSDT/IORT: six controllers `xhci_acpi: USB0..USB5`, IORT streams 0x0-0x5 on the first SMMUv3 (0x13800000), each then denied `dma_gate: xhci USBn denied (SmmuNotReady), controller left halted` because the SMMU service refuses the Spark IORT (15 root-complex mappings to that SMMU, limit 8; stream ids up to 0xfffff, linear table 0x0-0xfff) |

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
| 73 | `STORE_CHECKPOINT_CRASH_QEMU` (kill QEMU at each checkpoint, recover N or N+1) | M4_STORE_CRASH | NOT_RUN (pending forge receipt). Implemented, not yet run, by `scripts/qemu_ck_store_crash_test.sh`; will be DIFFERS (C: all 9 commit checkpoints of `st_transact` + `ss_commit_prepared` (before_first_write .. after_final_flush, before_anchor, after_anchor), settle 0 and 3, 4096 B and 512 B; a TEST-ONLY hook image (`make full CK_TEST_STORE_CRASH=1`, svc/store_crash.c) runs the Store on a volatile write cache, lands drop/all/newest/torn of the unflushed writes at the planned checkpoint, prints `store_crash: HALT at`, the host SIGKILLs QEMU; the default image must then open N before the root write, N+1 after the final flush (Rust N / NP1 / N_NP1), with boot_count, prev_commit and anchor of that generation, no refusal, no reformat, and commit on top) |
| 74 | `STORE_SLOT_REUSE_QEMU` | M4_STORE_CRASH | NOT_RUN (MISSING_IMPLEMENTATION: C Store is append-only, no reclaim/slot reuse; the crash script prints `CK_STORE_SLOT_REUSE: NOT_RUN` and does not count it) |
| 75 | `STORE_V1_QEMU` summary | M4_STORE_CRASH | NOT_RUN (pending forge receipt; C summary line `AIENOS_CK_M4_STORE_CRASH: PASS\|FAIL\|NOT_RUN` from `scripts/qemu_ck_store_crash_test.sh`, read by `scripts/ck_gates.sh`; will be DIFFERS: no slot reuse part) |

## M4 Store 512 B: scripts/qemu_store_512b_crash_test.sh -> CK `M4_STORE_CRASH`

| # | Rust check (marker) | CK gate | Status |
| --- | --- | --- | --- |
| 76 | `STORE_NVME_INTEGRATION_512B_QEMU` | M4_STORE | DIFFERS (the 512 B geometry run of qemu_ck_store_test.sh; integration only, no 512B-named marker, no crash campaign) |
| 77 | `STORE_512B_CRASH_OBSERVED_QEMU` (tier 1 kills) | M4_STORE_CRASH | NOT_RUN (pending forge receipt; the 512 B half of the row 73 campaign, line `CK_STORE_CRASH_512B_QEMU`; will be DIFFERS: crash point chosen by an in-guest plan, not a serial-triggered kill) |
| 78 | `STORE_512B_ROOT_TEAR_CLOSURE` (tier 2a) | M4_STORE_CRASH | NOT_RUN (pending forge receipt; `CK_STORE_ROOT_TEAR_CLOSURE_QEMU`: on the QEMU images, both geometries, the after_inactive_superblock crash changes exactly one superblock slot, only inside its first 512 bytes, and that slot holds generation N+1; will be DIFFERS: checked on the crashed images, not a host-only unit test) |
| 79 | `STORE_512B_INJECTED_ROOT_RECOVERY_QEMU` (tier 2b, degraded read-only / refuse) | M4_STORE_CRASH | NOT_RUN (pending forge receipt; `CK_STORE_INJECTED_ROOT_QEMU`: one byte of the new root's CRC flipped, both geometries; the verify boot must not open N+1, must print `store: REFUSED` and "disk left as found", commit nothing, image sha256 unchanged; will be DIFFERS: one injection (CRC), not the Rust 9 cases) |
| 80 | `STORE_512B_CRASH_RECOVERY_QEMU` summary | M4_STORE_CRASH | NOT_RUN (pending forge receipt; folded into `AIENOS_CK_M4_STORE_CRASH`) |

Mutation and refusal checks for `M4_STORE_CRASH` (all NOT_RUN, pending forge
receipt): `bash scripts/qemu_ck_store_crash_test.sh --mutant skip_root_flush`
builds a TEST-ONLY Store with the data flush before the root write removed
(`CK_TEST_STORE_MUTANT_SKIP_ROOT_FLUSH`, native/store/store_engine.c) and must
print `KILLED` (a newest/torn root landing then recovers wrong); `--mutant
accept_bad_root_crc` builds a Store that accepts a bad superblock CRC
(`CK_TEST_STORE_MUTANT_ACCEPT_BAD_ROOT_CRC`, native/store/store_v1.c) and must
print `KILLED` (the injected root is opened). `--self-test` runs the judges on
canned serial text and images (wrong generation, reformat, refusal, skipped
checkpoint, change past sector 0, two slots changed) and checks with `make -n`
that the hook is refused with `CK_HARDWARE_STAGING` and `CK_QEMU_UNSAFE_DMA`.
The default `make full` image must carry no crash hook string (Makefile
`crash_check`). QEMU only; hardware NOT_RUN.

## M4 continuity: scripts/qemu_continuity_test.sh -> CK `M4_CONTINUITY`

Contract: `native/kernel/CONTINUITY_RECOVERY_CONTRACT.md` (IMPLEMENTED host PASS, QEMU NOT_RUN, hardware NOT_RUN). One row per Rust check: rows 81-87 are the
QEMU PASS lines of `scripts/qemu_continuity_test.sh` (receipt `evidence/continuity_qemu_2026-09-25.md`), rows
87a-87i are the host tests `cargo test -p aienos-kernel --lib continuity`
(`crates/aienos-kernel/src/continuity_tests.rs`). The C continuity codec (`svc/continuity_codec.c`, cuts 1-2) and the C resolve + challenge/HMAC code (`svc/continuity_resolve.c`, cut 3, run over the real sealed Store in a file) have host tests only, with no kernel wiring and no QEMU run (cut 4 adds provision, commit and resume, `svc/continuity_commit.c`, same host-only status): rows 87a-87i, 91i, 91k and 91m-91p below say HOST PASS (for the half that has code, where stated) for those host tests; no gate row is QEMU PASS and `M4_CONTINUITY` stays NOT_RUN. Every other row is NOT_RUN.

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
| 87a | host `unprovisioned_store_never_mints_an_identity` (continuity_tests.rs:84) | M4_CONTINUITY (host) | HOST PASS for the resolve half (cut 3, `test_continuity_resolve` (`make -C native/kernel test`, real sealed Store in a file): empty formatted store is Unprovisioned, kind 19 and unrelated kinds ignored, resolve writes no block; resume on an Unprovisioned store returns Unprovisioned, writes no block and mints nothing, `test_continuity_commit` cut 4, mutant MC-1 `CM_MUTANT_RESUME_PROVISIONS` killed); gate NOT_RUN |
| 87b | host `provision_then_cold_restart_returns_the_same_identity_and_memory` (:97) | M4_CONTINUITY (host) | HOST PASS (cut 4, `test_continuity_commit` (`make -C native/kernel test`, real sealed Store in a file, 4096 and 512 byte blocks): provision, remember (fork + record in one transaction), then 6 cold restarts return the same agent, the same `memory=`, 2 branches, incarnation and sequence growing by one each; markers PROVISIONED, RESUMED, REMEMBERED, RESUMED_READONLY match the format of nvme_read.rs:1118-1143; mutants MC-3 `CM_MUTANT_RESUME_NO_COMMIT`, MC-10 `CM_MUTANT_FIXED_AGENT` killed); gate NOT_RUN |
| 87c | host `provisioning_twice_is_refused` (:142) | M4_CONTINUITY (host) | HOST PASS (cut 4, `test_continuity_commit`: second provision is AlreadyProvisioned (also with two roots), image byte for byte unchanged; provision over orphans is Corrupt (C is stricter than Rust, contract 9.2), no entropy is NO_ENTROPY with nothing written; mutant MC-7 `CM_MUTANT_PROVISION_WITH_ROOT` killed); gate NOT_RUN |
| 87d | host `two_roots_stop_with_conflict` (:152) | M4_CONTINUITY (host) | HOST PASS (cut 3, `test_continuity_resolve` (`make -C native/kernel test`, real sealed Store in a file): two roots give Conflict, mutant MC-12 `CR_MUTANT_SKIP_CONFLICT` killed); gate NOT_RUN (no QEMU, no kernel wiring) |
| 87e | host `forked_or_gapped_manifest_chains_are_corrupt` (:178) | M4_CONTINUITY (host) | HOST PASS (cut 3, `test_continuity_resolve` (`make -C native/kernel test`, real sealed Store in a file): wrong previous, absent previous, sequence gap, fork, foreign root, root without manifest are Corrupt with the Rust reason text; mutant MC-4 `CR_MUTANT_IGNORE_PREVIOUS` killed); gate NOT_RUN |
| 87f | host `degraded_mount_resumes_read_only` (:221) | M4_CONTINUITY (host) | HOST PASS for the resolve half (cut 3, `test_continuity_resolve` (`make -C native/kernel test`, real sealed Store in a file): K-5 answered, ss_open returns 0 on a malformed-peer mount, resolve returns the same agent and memory, `cr_writable` is read-only; on a degraded mount resume returns the verified view with committed=0 (`RESUMED_READONLY`), commit and provision return ReadOnly, image unchanged, `test_continuity_commit` cut 4; mutant MC-9 `CM_MUTANT_NO_WRITABLE_CHECK` killed); gate NOT_RUN |
| 87g | host `a_crash_at_every_write_of_a_commit_leaves_old_or_new_never_a_third_state` (:242) | M4_CONTINUITY (host) | HOST PASS (cut 4, `test_continuity_commit`: power cut at all 9 checkpoints (ST_CP_* 0-6, SS_CP_BEFORE_ANCHOR, SS_CP_AFTER_ANCHOR) and at every block boundary (10 at 4096 byte blocks, 73 at 512) of a commit AND of provisioning; after every cut the store reopens and resolves to exactly the old or exactly the new state, and keeps working; checkpoints 0-4 old, 5 and 6 and both anchor points new; mutant MC-8 `CM_MUTANT_SPLIT_TXN` killed); gate NOT_RUN |
| 87h | host `encodings_round_trip_and_reject_tampering` (:286) | M4_CONTINUITY (host) | HOST PASS for the C codec twin (`make -C native/kernel test`, `test_continuity_codec`: round trips, one refusal per rule, every single-bit flip of every golden vector decodes as in Rust, D-2); gate NOT_RUN (no QEMU, no kernel wiring) |
| 87i | host `branch_table_validation_rejects_broken_lineage` (:328) | M4_CONTINUITY (host) | HOST PASS for the C codec twin (`cc_state_validate`, incl. the checked fork-count sum and hostile fork counts); gate NOT_RUN (no QEMU, no kernel wiring) |
| 87j | D-1 golden vectors (contract 6.3): Rust-emitted canonical bytes and ObjectIds for 22 vectors, reproduced by C from `native/kernel/tests/fixtures/continuity_vectors.txt`; tampered bytes, ObjectId and verdicts are refused (`cargo test -p aienos-kernel --lib continuity_vectors` fails on fixture drift) | M4_CONTINUITY (host) | HOST PASS (`make -C native/kernel test`, `continuity-mutants`: golden and skip-D1 mutants killed); challenges and HMAC responses (4 fixture lines) are now reproduced byte for byte by C (cut 3, `test_continuity_resolve`); gate NOT_RUN |
| 87k | D-2 decode agreement (contract 6.3): every single-bit flip of every vector, C and Rust agree on accept/refuse and error class and text (86598 verdicts, 0 divergences) | M4_CONTINUITY (host) | HOST PASS (`make -C native/kernel test`; skip-D2 mutant killed); gate NOT_RUN |

## M4 recovery: scripts/qemu_recovery_test.sh -> CK `M4_RECOVERY`

Contract: `native/kernel/CONTINUITY_RECOVERY_CONTRACT.md` (host PASS for rows 91d-91k; gate M4_RECOVERY QEMU PASS at 640522a, hardware NOT_RUN). Rows 88-91c are the QEMU PASS lines of
`scripts/qemu_recovery_test.sh` (receipt `evidence/recovery_core_qemu_2026-09-25.md`), rows 91d-91k the host tests
`cargo test -p aienos-kernel --lib recovery_core` (`crates/aienos-kernel/src/recovery_core_tests.rs`), rows
91l-91p the operator-auth tests in `crates/aienos-kernel/src/recovery.rs`. The C Recovery Core (`svc/continuity_recovery.c`, cut 5) has host tests (rows 91d-91k, and 91l-91p from cut 3) and, since #241, is wired into the C kernel and run by `scripts/qemu_ck_recovery_test.sh` (gate `M4_RECOVERY`): the full `ck_gates.sh` receipt `evidence/ck_gates_1ecf5bcd303bf88422dd0542f14851c931f5d52276838fa182c812f3c73f3c1b.json` at 640522a records `AIENOS_CK_M4_RECOVERY: PASS` in QEMU (hardware NOT_RUN), so rows 88-91c are QEMU PASS (per-row result INFERRED from the gate verdict, not kept as a per-row log in the tree) and the gate is no longer NOT_RUN. The C script also checks a fourth repair-refusal variant (flipped last byte, `88.4`) that the Rust table has no row for. Rows 91d-91k say HOST PASS, and the
C-only rows are as stated. Operator key is TEST-ONLY in the oracle.

| # | Rust check | CK gate | Status |
| --- | --- | --- | --- |
| 88 | inspection: `RECOVERY_OPERATOR_KEY: TEST-ONLY`, `RECOVERY_CORE: ENTERED reason=Degraded(Malformed)`, same agent in `RECOVERY_RECORD:`, image unchanged, repair challenge offered (script :94-103) | M4_RECOVERY | QEMU PASS (gate M4_RECOVERY PASS in `evidence/ck_gates_1ecf5bcd303bf88422dd0542f14851c931f5d52276838fa182c812f3c73f3c1b.json` at 640522a, OBSERVED; this row's result is INFERRED from that gate verdict, because `scripts/qemu_ck_recovery_test.sh` prints pass line `88` and any bad row fails the gate, and the per-row log is not kept in the tree; hardware NOT_RUN; host code since cut 5) |
| 88a | repair with zero response: `RECOVERY_REFUSED (Unauthorised)`, image unchanged (:105-117) | M4_RECOVERY | QEMU PASS (gate M4_RECOVERY PASS in `evidence/ck_gates_1ecf5bcd303bf88422dd0542f14851c931f5d52276838fa182c812f3c73f3c1b.json` at 640522a, OBSERVED; this row's result is INFERRED from that gate verdict, because `scripts/qemu_ck_recovery_test.sh` prints pass line `88.1` and any bad row fails the gate, and the per-row log is not kept in the tree; hardware NOT_RUN; host code since cut 5) |
| 88b | repair with wrong-key response: `RECOVERY_REFUSED (Unauthorised)`, image unchanged | M4_RECOVERY | QEMU PASS (gate M4_RECOVERY PASS in `evidence/ck_gates_1ecf5bcd303bf88422dd0542f14851c931f5d52276838fa182c812f3c73f3c1b.json` at 640522a, OBSERVED; this row's result is INFERRED from that gate verdict, because `scripts/qemu_ck_recovery_test.sh` prints pass line `88.2` and any bad row fails the gate, and the per-row log is not kept in the tree; hardware NOT_RUN; host code since cut 5) |
| 88c | repair with a response to another challenge: `RECOVERY_REFUSED (Unauthorised)`, image unchanged | M4_RECOVERY | QEMU PASS (gate M4_RECOVERY PASS in `evidence/ck_gates_1ecf5bcd303bf88422dd0542f14851c931f5d52276838fa182c812f3c73f3c1b.json` at 640522a, OBSERVED; this row's result is INFERRED from that gate verdict, because `scripts/qemu_ck_recovery_test.sh` prints pass line `88.3` and any bad row fails the gate, and the per-row log is not kept in the tree; hardware NOT_RUN; host code since cut 5) |
| 89 | authorised repair: `RECOVERY_ACTION: repair-degraded-peer DONE`, image changed (:119-125) | M4_RECOVERY | QEMU PASS (gate M4_RECOVERY PASS in `evidence/ck_gates_1ecf5bcd303bf88422dd0542f14851c931f5d52276838fa182c812f3c73f3c1b.json` at 640522a, OBSERVED; this row's result is INFERRED from that gate verdict, because `scripts/qemu_ck_recovery_test.sh` prints pass line `89` and any bad row fails the gate, and the per-row log is not kept in the tree; hardware NOT_RUN; host code since cut 5) |
| 89a | after repair a cold boot `CONTINUITY: RESUMED` writable, same agent and memory (:126-132) | M4_RECOVERY | QEMU PASS (gate M4_RECOVERY PASS in `evidence/ck_gates_1ecf5bcd303bf88422dd0542f14851c931f5d52276838fa182c812f3c73f3c1b.json` at 640522a, OBSERVED; this row's result is INFERRED from that gate verdict, because `scripts/qemu_ck_recovery_test.sh` prints pass line `89a` and any bad row fails the gate, and the per-row log is not kept in the tree; hardware NOT_RUN; host code since cut 5) |
| 89b | replaying the repair response: `RECOVERY_REFUSED (NotApplicable)`, image unchanged (:133-138) | M4_RECOVERY | QEMU PASS (gate M4_RECOVERY PASS in `evidence/ck_gates_1ecf5bcd303bf88422dd0542f14851c931f5d52276838fa182c812f3c73f3c1b.json` at 640522a, OBSERVED; this row's result is INFERRED from that gate verdict, because `scripts/qemu_ck_recovery_test.sh` prints pass line `89b` and any bad row fails the gate, and the per-row log is not kept in the tree; hardware NOT_RUN; host code since cut 5) |
| 90 | unprovisioned store: `ENTERED reason=Unprovisioned`, only the provision challenge, image unchanged (:141-149) | M4_RECOVERY | QEMU PASS (gate M4_RECOVERY PASS in `evidence/ck_gates_1ecf5bcd303bf88422dd0542f14851c931f5d52276838fa182c812f3c73f3c1b.json` at 640522a, OBSERVED; this row's result is INFERRED from that gate verdict, because `scripts/qemu_ck_recovery_test.sh` prints pass line `90` and any bad row fails the gate, and the per-row log is not kept in the tree; hardware NOT_RUN; host code since cut 5) |
| 90a | provisioning with a wrong key: `RECOVERY_REFUSED (Unauthorised)`, image unchanged (:150-155) | M4_RECOVERY | QEMU PASS (gate M4_RECOVERY PASS in `evidence/ck_gates_1ecf5bcd303bf88422dd0542f14851c931f5d52276838fa182c812f3c73f3c1b.json` at 640522a, OBSERVED; this row's result is INFERRED from that gate verdict, because `scripts/qemu_ck_recovery_test.sh` prints pass line `90a` and any bad row fails the gate, and the per-row log is not kept in the tree; hardware NOT_RUN; host code since cut 5) |
| 90b | authorised provisioning: `RECOVERY_ACTION: provision-identity DONE agent=..`, a cold boot resumes that agent (:156-163) | M4_RECOVERY | QEMU PASS (gate M4_RECOVERY PASS in `evidence/ck_gates_1ecf5bcd303bf88422dd0542f14851c931f5d52276838fa182c812f3c73f3c1b.json` at 640522a, OBSERVED; this row's result is INFERRED from that gate verdict, because `scripts/qemu_ck_recovery_test.sh` prints pass line `90b` and any bad row fails the gate, and the per-row log is not kept in the tree; hardware NOT_RUN; host code since cut 5) |
| 91 | corrupted agent root: `RECOVERY_CORE: ENTERED`, no `RECOVERY_CHALLENGE`, image unchanged (:166-174) | M4_RECOVERY | QEMU PASS (gate M4_RECOVERY PASS in `evidence/ck_gates_1ecf5bcd303bf88422dd0542f14851c931f5d52276838fa182c812f3c73f3c1b.json` at 640522a, OBSERVED; this row's result is INFERRED from that gate verdict, because `scripts/qemu_ck_recovery_test.sh` prints pass line `91` and any bad row fails the gate, and the per-row log is not kept in the tree; hardware NOT_RUN; host code since cut 5; in the sealed C Store the flip is refused at mount with SS_E_ROLLBACK, host test, contract K-3) |
| 91a | mode 10 (repair) after identity loss with a forged response: refused, no action, image unchanged (:175-183) | M4_RECOVERY | QEMU PASS (gate M4_RECOVERY PASS in `evidence/ck_gates_1ecf5bcd303bf88422dd0542f14851c931f5d52276838fa182c812f3c73f3c1b.json` at 640522a, OBSERVED; this row's result is INFERRED from that gate verdict, because `scripts/qemu_ck_recovery_test.sh` prints pass line `91.m10` and any bad row fails the gate, and the per-row log is not kept in the tree; hardware NOT_RUN; host code since cut 5) |
| 91b | mode 11 (provision) after identity loss with a forged response: refused, no action, image unchanged (:175-183) | M4_RECOVERY | QEMU PASS (gate M4_RECOVERY PASS in `evidence/ck_gates_1ecf5bcd303bf88422dd0542f14851c931f5d52276838fa182c812f3c73f3c1b.json` at 640522a, OBSERVED; this row's result is INFERRED from that gate verdict, because `scripts/qemu_ck_recovery_test.sh` prints pass line `91.m11` and any bad row fails the gate, and the per-row log is not kept in the tree; hardware NOT_RUN; host code since cut 5) |
| 91c | normal boot after identity loss neither resumes nor mints, image unchanged (:184-189) | M4_RECOVERY | QEMU PASS (gate M4_RECOVERY PASS in `evidence/ck_gates_1ecf5bcd303bf88422dd0542f14851c931f5d52276838fa182c812f3c73f3c1b.json` at 640522a, OBSERVED; this row's result is INFERRED from that gate verdict, because `scripts/qemu_ck_recovery_test.sh` prints pass line `91c` and any bad row fails the gate, and the per-row log is not kept in the tree; hardware NOT_RUN; host code since cut 5) |
| 91d | host `inspection_never_writes_and_names_the_reason` (recovery_core_tests.rs:89) | M4_RECOVERY (host) | HOST PASS (cut 5, `test_continuity_recovery` (`make -C native/kernel test` and `sanitize`, real sealed Store in a file, 4096 and 512 byte blocks): blank, unprovisioned, healthy and degraded stores inspected, image byte for byte unchanged, reasons StoreUnformatted, Unprovisioned, none, Degraded(Malformed); mutant MR-1 `RC_MUTANT_INSPECT_WRITES` killed); gate NOT_RUN (no kernel wiring, no QEMU) |
| 91e | host `degraded_repair_needs_the_operator_and_restores_a_writable_store` (:111) | M4_RECOVERY (host) | HOST PASS (cut 5, `test_continuity_recovery` (`make -C native/kernel test` and `sanitize`, real sealed Store in a file, 4096 and 512 byte blocks): zero, wrong-key, wrong-action and stale-state responses refused with the image unchanged, authorised repair zeroes only the inactive slot, same agent and memory, writable again, replay NotApplicable; mutant MR-6 `RC_MUTANT_REPAIR_ACTIVE` killed); gate NOT_RUN (no kernel wiring, no QEMU) |
| 91f | host `provisioning_is_operator_only_and_only_on_an_unprovisioned_store` (:154) | M4_RECOVERY (host) | HOST PASS (cut 5, `test_continuity_recovery` (`make -C native/kernel test` and `sanitize`, real sealed Store in a file, 4096 and 512 byte blocks): wrong key or response refused, no-entropy refused with nothing written, authorised provisioning writes source Operator and a cold resume returns that agent, replay NotApplicable; mutant MR-9 `RC_MUTANT_PROVISION_QUALIFICATION` killed); gate NOT_RUN (no kernel wiring, no QEMU) |
| 91g | host `identity_lost_in_the_newest_root_never_looks_unprovisioned` (:178) | M4_RECOVERY (host) | HOST PASS, DIFFERS (cut 5, `test_continuity_recovery`: a flipped byte of the newest AgentRoot is refused by the sealed mount with `SS_E_ROLLBACK`, entry reason `SealedRefusal(-303)`, no action applicable, forged and valid-form responses refused, image unchanged; Rust shows `Degraded(GraphBadNewer)`, contract K-3, K-4); the Degraded-without-identity half is row 91h; gate NOT_RUN (no kernel wiring, no QEMU) |
| 91h | host `malformed_peer_without_a_resolvable_identity_is_not_repaired` (:222) | M4_RECOVERY (host) | HOST PASS (cut 5, `test_continuity_recovery` (`make -C native/kernel test` and `sanitize`, real sealed Store in a file, 4096 and 512 byte blocks): garbage in the inactive slot of an identity-less formatted store reads Degraded(Malformed), never Unprovisioned, no action offered; mutants MR-5 `RC_MUTANT_DEGRADED_IS_UNPROVISIONED` and MR-7 `RC_MUTANT_REPAIR_NO_IDENTITY` killed); gate NOT_RUN (no kernel wiring, no QEMU) |
| 91i | host `orphaned_continuity_objects_are_corrupt_not_unprovisioned` (:236) | M4_RECOVERY (host) | HOST PASS for the resolve half (cut 3, `test_continuity_resolve` (`make -C native/kernel test`, real sealed Store in a file): orphan manifest, orphan agent state and orphan WAL are Corrupt `continuity objects without an agent root`; mutant MC-2 `CR_MUTANT_NO_ORPHAN_CHECK` killed); Recovery Core entry reason ContinuityCorrupt "continuity objects without an agent root", no action, image unchanged: cut 5, `test_continuity_recovery`, host PASS; gate NOT_RUN |
| 91j | host `identity_loss_through_corruption_offers_no_action_that_mints` (:267) | M4_RECOVERY (host) | HOST PASS, DIFFERS (cut 5, `test_continuity_recovery`: a corrupted AgentRoot of a provisioned store is a sealed refusal, no challenge, forged responses refused for both actions, image unchanged; contract K-3); gate NOT_RUN (no kernel wiring, no QEMU) |
| 91k | host `challenges_bind_state_and_action` (:300) | M4_RECOVERY (host) | HOST PASS for the primitive (cut 3, `test_continuity_resolve` (`make -C native/kernel test`, real sealed Store in a file): `cr_challenge` binds action, state digest, generation and uuid, a response for one action is refused on the other; mutants MR-2 and MR-3 killed); the system record that carries them, `rc_challenge`: different on-disk state, different action or a stale response change or refuse the authorisation: cut 5, `test_continuity_recovery`, host PASS; gate NOT_RUN |
| 91l | host `hmac_primitive_rfc4231_case_2` (recovery.rs:238) | M4_RECOVERY (host) | NOT_RUN (MISSING_IMPLEMENTATION: no C operator-auth wrapper; the C HMAC primitive itself is `aienos_hmac_sha256` in native/crypto) |
| 91m | host `operator_auth_known_answer_accepted` (recovery.rs:251) | M4_RECOVERY (host) | HOST PASS (cut 3, `test_continuity_resolve` (`make -C native/kernel test`, real sealed Store in a file): `cr_operator_response` reproduces the Rust known answer and the four Rust-emitted fixture lines byte for byte); gate NOT_RUN |
| 91n | host `operator_auth_rejects_any_single_bit_flip` (recovery.rs:269) | M4_RECOVERY (host) | HOST PASS (cut 3, `test_continuity_resolve` (`make -C native/kernel test`, real sealed Store in a file): every single-bit flip of response, challenge and key is refused; mutant MR-4 `CR_MUTANT_COMPARE_16` killed); gate NOT_RUN |
| 91o | host `operator_auth_rejects_legacy_bare_sha256_response` (recovery.rs:299) | M4_RECOVERY (host) | HOST PASS (cut 3, `test_continuity_resolve` (`make -C native/kernel test`, real sealed Store in a file): bare SHA-256 response refused; mutant MR-8 `CR_MUTANT_BARE_SHA256` killed); gate NOT_RUN |
| 91p | host `operator_auth_rejects_undomained_hmac_and_zero_response` (recovery.rs:311) | M4_RECOVERY (host) | HOST PASS (cut 3, `test_continuity_resolve` (`make -C native/kernel test`, real sealed Store in a file): undomained HMAC and zero response refused; mutant MR-8 `CR_MUTANT_NO_DOMAIN` killed); gate NOT_RUN |

## M4 ALLEN: C-only -> CK `M4_ALLEN` (scripts/qemu_ck_allen_test.sh; OS-0018 / ARCH-0035, both PROPOSED)

No Rust-kernel counterpart. The TEST continuity image (`make full CK_TEST_CONTINUITY=1`), a 4096-byte-LBA emulated NVMe image, one new `qemu-system-aarch64` process per boot (ESP folder and UEFI vars rebuilt every boot; only the image carries state). Plan mode 5 with `lineage=` provisions identity and genesis subject in one sealed Store transaction; `intent=` adds one standing intent; mode 6 restores. Status for every row: QEMU PASS (receipts `evidence/allen_native_qemu_cfe9aecffb8b20e0c1ff51fad54c46c522ec7d6c56c6cba7661e4b8cda1ee25a.json` and `evidence/ck_gates_1ecf5bcd303bf88422dd0542f14851c931f5d52276838fa182c812f3c73f3c1b.json`, full `ck_gates.sh` at `640522a`), hardware NOT_RUN. QEMU is not a physical cold reboot.

| row | check | gate | status |
|---|---|---|---|
| A1 | default image carries no ALLEN TEST markers | M4_ALLEN | QEMU PASS |
| A2 | G7 blank image, then kernel provisioning prints `PROVISIONED` and `ALLEN: GENESIS subject=<64> sequence=1 agent=<that agent> lineage=<request lineage>` | M4_ALLEN | QEMU PASS |
| A3 | G7 standing intent: `ALLEN: INTENDED .. sequence=2 .. intents=1 active=1` and `ALLEN: INTENT .. kind=1 regime=7 target_ns=1000 since=2` | M4_ALLEN | QEMU PASS |
| A4 | G7 independent host reader (`ck_cont_tool subject-dump`, on a copy) finds one genesis and one successor on the image, head = serial head | M4_ALLEN | QEMU PASS |
| A5 | G8 provisioning a provisioned image: `CONTINUITY: STOP (AlreadyProvisioned)`, no genesis, image unchanged | M4_ALLEN | QEMU PASS |
| A6-A8 | G9 two cold restores (new QEMU process each): `ALLEN: RESTORED` with the same subject, intent and lineage, incarnation 2 then 3; afterwards still one genesis, head object byte-identical | M4_ALLEN | QEMU PASS |
| A9-A11 | G10 restore plan is only `AIENCONT v1 mode=6`; a second image restores its own, different subject; the host reader decodes the head from the sealed Store | M4_ALLEN | QEMU PASS |
| A12-A14 | G11a forked chain (second genesis planted): `ALLEN: CORRUPT (subject chain fork)` on two boots, no resume, nothing minted, image unchanged | M4_ALLEN | QEMU PASS |
| A15 | G11b flipped byte in a subject envelope: refused by the Store, nothing restored or minted, image unchanged | M4_ALLEN | QEMU PASS |
| A16-A18 | G11c identity provisioned without a subject: `ALLEN: ABSENT` on two boots, none minted (kills `subject_restore_mints`) | M4_ALLEN | QEMU PASS |
| A19-A20 | G12 another installation's subject chain, beside ours or on a subjectless identity: `ALLEN: CORRUPT (subject object belongs to another agent)`, never adopted (kills `subject_accept_foreign`) | M4_ALLEN | QEMU PASS |
| A21-A30 | power loss: SIGKILL at each of the 9 Store checkpoints of the genesis transaction, then a cold boot finds unprovisioned with no subject (before_first_write .. after_first_flush), either (after_inactive_superblock), or identity with its genesis subject (after_final_flush, before_anchor, after_anchor); never identity without subject; an interrupted provisioning that committed nothing provisions again | M4_ALLEN | QEMU PASS |

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

## SMP: secondary cores through PSCI CPU_ON -> CK `SMP` (scripts/qemu_ck_smp_test.sh)

C-only: the Rust kernel starts no secondary core, so there is no Rust row to
match. QEMU `-M virt,virtualization=on,gic-version=3 -cpu max -smp 4`, single
threaded TCG, the default core image (`make`), same machine as `M1`. The
kernel (`core/smp.c`, `arch/smp_entry.S`) reads the MPIDR of every enabled or
online-capable core from the ACPI MADT GICC entries (`ck_madt_mpidrs`, host
test in `tests/test_acpi.c`), calls PSCI CPU_ON (SMC64 0xC4000003) on the
conduit the FADT names (SMC under `virtualization=on`), and each secondary
goes through the boot core's own EL2 -> EL1h path (`ck_enter_el1`; QEMU 8.2.2
`target/arm/tcg/psci.c:144` starts it at EL2 when EL2 exists). The boot core
waits at most 5 s and never panics; the script re-checks every line itself.
No PASS without a forge receipt; hardware NOT_RUN (no GB10 core was started).

| # | C check | CK gate | Status |
| --- | --- | --- | --- |
| 113 | PSCI CPU_ON issued once per secondary core and returns SUCCESS (`smp_cpu_on: target=0x.. psci_rc=0 (SUCCESS)`, N-1 lines; any PSCI error code or a skipped call FAILs) | SMP | NOT_RUN (pending forge receipt) |
| 114 | every secondary checks in on EL1 with the MMU on the boot core's tables and its own stack, then parks in WFE (`smp_cpu: target=0x.. checked_in=yes seen_mpidr=0x.. el=1 mmu=on ttbr0_match=yes stack_ok=yes parked=wfe`); a core that never checks in within the bounded wait (`checked_in=no`) FAILs | SMP | NOT_RUN (pending forge receipt) |
| 115 | per-core MPIDRs distinct and complete: MADT core count equals `-smp N`, each secondary reports the MPIDR it was started for, boot + secondaries give N distinct values (duplicate or missing MPIDR FAILs) | SMP | NOT_RUN (pending forge receipt) |
| 116 | summary `smp: cpus=N started=N checked_in=N psci_errors=0 distinct_mpidrs=N wait_us=.. result=ok`, no `smp: FAIL`, kernel reaches `report_kind: final`, no panic or fault, QEMU exit 0, image is not the TEST-ONLY mutation | SMP | NOT_RUN (pending forge receipt) |
| 117 | mutation: `make CK_TEST_SMP_SKIP_CPU=1` (TEST-ONLY, own OUT, announces itself, never calls CPU_ON for the last MADT secondary) must make the gate checks FAIL (`scripts/qemu_ck_smp_test.sh --mutation` ends `AIENOS_CK_SMP_MUTATION: PASS` when they do); the flag is refused with `CK_HARDWARE_STAGING` (Makefile `$(error)` and a `#error` in `core/smp.c`) and default images are checked to carry no trace of it (Makefile `smp_check`); canned-log failure modes in `scripts/qemu_ck_smp_test.sh --self-test` | SMP | NOT_RUN (pending forge receipt) |

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
| 118 | GPT parsed with CRC32 on both headers and both entry arrays; the AIENOS partition is found exactly where the image tool wrote it (`disk: gpt ok primary+backup crc32 entries=128 used=3 aienos_index=1 first_lba=F last_lba=L `), 512 B (2 boots) and 4096 B (1 boot) | DISK_LAYOUT | QEMU PASS (receipt `evidence/ck_gates_d80363cc871372963743ae85fc08c6fa4608f9870c4e06e8988f21950c73ace6.json`, full `ck_gates.sh` run at 741b2b8, log CK-4-184524.log; standalone `scripts/qemu_ck_disk_layout_test.sh` PASS with the bypass mutant killed, log CK-4-184423.log; hardware NOT_RUN) |
| 119 | translation layer: partition LBA 0 -> partition start, past-end / straddling / overflowing LBAs refused (`disk: xlate part_lba=0 -> disk_lba=F (rc=0)`, `disk: write past partition end part_lba=N -> refused `); rw probe disk LBA inside [F,L] | DISK_LAYOUT | QEMU PASS (receipt `evidence/ck_gates_d80363cc871372963743ae85fc08c6fa4608f9870c4e06e8988f21950c73ace6.json`, full `ck_gates.sh` run at 741b2b8, log CK-4-184524.log; standalone `scripts/qemu_ck_disk_layout_test.sh` PASS with the bypass mutant killed, log CK-4-184423.log; hardware NOT_RUN) |
| 120 | footprint: Store formats and commits inside the partition; every byte outside it (MBR, both GPT copies, both sentinels) unchanged (sha256 with the partition cut out), the partition itself written. Also checked on boots 1-3 of both geometries by `scripts/qemu_ck_store_test.sh` | DISK_LAYOUT (and M4_STORE) | QEMU PASS (receipt `evidence/ck_gates_d80363cc871372963743ae85fc08c6fa4608f9870c4e06e8988f21950c73ace6.json`, full `ck_gates.sh` run at 741b2b8, log CK-4-184524.log; standalone `scripts/qemu_ck_disk_layout_test.sh` PASS with the bypass mutant killed, log CK-4-184423.log; hardware NOT_RUN) |
| 121 | hostile disks refused, image byte-identical, Store refused `step="no boot disk"`, no rw probe: no GPT, bad CRC32 on both headers, bad entry-array CRC32 on both arrays, AIENOS partition ending past the disk, no AIENOS partition; the host tool's own parser (`ck_gpt_image find`) must give the same reason | DISK_LAYOUT | QEMU PASS (receipt `evidence/ck_gates_d80363cc871372963743ae85fc08c6fa4608f9870c4e06e8988f21950c73ace6.json`, full `ck_gates.sh` run at 741b2b8, log CK-4-184524.log; standalone `scripts/qemu_ck_disk_layout_test.sh` PASS with the bypass mutant killed, log CK-4-184423.log; hardware NOT_RUN) |
| 122 | mutation: the TEST-ONLY translation-bypass image announces itself and FAILs rows 118-120 (its translation self-check prints `NOT REFUSED`); the default image contains no bypass text | DISK_LAYOUT | QEMU PASS (receipt `evidence/ck_gates_d80363cc871372963743ae85fc08c6fa4608f9870c4e06e8988f21950c73ace6.json`, full `ck_gates.sh` run at 741b2b8, log CK-4-184524.log; standalone `scripts/qemu_ck_disk_layout_test.sh` PASS with the bypass mutant killed, log CK-4-184423.log; hardware NOT_RUN) |
| 123 | host test: CRC32 known answer, good layouts at 512/4096, writes through the view never change bytes outside the partition, full Store boot on the view, single-copy corruption, header field patches, backup disagreement, overlap, two AIENOS partitions, too many entries; the bypass build of the same test must FAIL (`CK_DISK_PART_MUTANT: PASS`) | DISK_LAYOUT (host, `make stage-test`) | PASS (host test, `CK_DISK_PART_HOST: PASS` and `CK_DISK_PART_MUTANT: PASS`, log CK-4-light-181557.log at 25db390; not rerun at 741b2b8, but no file under native/kernel/dev or native/kernel/tools changed since; the bypass image's QEMU FAIL is row 122, receipt `evidence/ck_gates_d80363cc871372963743ae85fc08c6fa4608f9870c4e06e8988f21950c73ace6.json`; inspector note (non-blocking): since 25db390 the only change near this code is from main, `native/kernel/svc/security.c` +3 lines (#218, a TEST-only `argus: TEST machine id` print under `#ifndef CK_HARDWARE_STAGING`); `native/kernel/svc/security.h` is unchanged, and no file under native/kernel/dev, native/kernel/tools or the disk_part test changed; hardware NOT_RUN) |


## Summary counts

**C kernel receipt tally (QEMU only, no physical run):** Newest: `evidence/ck_gates_bc306a04d8ba513b2364fbee644f37375dc686ccead97c8759191b76ebec94eb.json` (full `ck_gates.sh` at f921666, NEXT-PHASE-3 cut 1 branch, KEYBOARD from its own child): 19 PASS, 0 FAIL, 1 NOT_RUN (M0_ROLLBACK: MISSING_IMPLEMENTATION); KEYBOARD PASS (rows 25-32 and C-only 30a-30c, QEMU only, hardware NOT_RUN). Baseline for that change, same runner on main 2058747: `evidence/ck_gates_79a843817161b68d71889201bd4407a3b4e432ac808503b017836f71abc3f2db.json`: 18 PASS, 0 FAIL, 2 NOT_RUN (M0_ROLLBACK, KEYBOARD: MISSING_IMPLEMENTATION). Rows 25-32 move from NOT_RUN to QEMU PASS (8 rows: IDENTICAL 4, DIFFERS 4 by their parity labels) and C-only rows 30a-30c are added as QEMU PASS; the older row recounts below predate this change. Before it: `evidence/ck_gates_1ecf5bcd303bf88422dd0542f14851c931f5d52276838fa182c812f3c73f3c1b.json` (full `ck_gates.sh` at 640522a, ALLEN native genesis branch, 20 CK gates with `M4_ALLEN`): 15 PASS, 0 FAIL, 5 NOT_RUN (M0_ROLLBACK, KEYBOARD: MISSING_IMPLEMENTATION; FPU, INFER, SCREEN: the shared QEMU gate lock was held by another run). Before it: `evidence/ck_gates_ad05e004e30237e57e72fc1d3362cfe2b31af9b99451d9d2bb2414238e4d6590.json` (full `ck_gates.sh` at 2e44c0b, L6-C branch, 19 CK gates with `SCREEN`): 17 PASS, 0 FAIL, 2 NOT_RUN (M0_ROLLBACK, KEYBOARD: MISSING_IMPLEMENTATION). Earlier: 16 CK gates since the merge of main 8555049 (#224 adds `SMP`, #226 moves `M4_STORE_CRASH` to its own child script) into the CK-4 branch. The newest full receipt, `evidence/ck_gates_d80363cc871372963743ae85fc08c6fa4608f9870c4e06e8988f21950c73ace6.json` (full `ck_gates.sh` run at 741b2b8, the CK-4 branch after merging main #221 and #225; log CK-4-184524.log, `AIENOS_CK_GATES: NOT_ALL_GATES_PASS (pass=10 fail=0 not_run=5 of 15; physical NOT_RUN)`), predates that merge: by it, 10 of 16 CK gates PASS (the 9 of the earlier receipt plus `DISK_LAYOUT`), 6 NOT_RUN (M0_ROLLBACK, M4_STORE_CRASH, M4_CONTINUITY, M4_RECOVERY, KEYBOARD; and SMP, not in that receipt, NOT_RUN pending forge receipt), 0 FAIL. No `ck_gates.sh` run exists at the merged head yet; `M4_STORE_CRASH` stays NOT_RUN until a forge receipt. `DISK_LAYOUT` also PASSed alone (log CK-4-184423.log, translation-bypass mutant killed); the Store, NET and artifact gates boot GPT images now and PASS in the same receipt. The receipt before it was 9 of 14 CK gates PASS, 5 NOT_RUN, 0 FAIL (`evidence/ck_gates_929f287e9c950c45c7dcd569c7caa03709ea62ecfe393635b435058afa969c54.json`, run at 41aa0e6, which adds the kernel entropy rows 107-109; that commit was then rebased onto #210, which changed only README.md and CONTRIBUTING.md). The row counts below are per Rust-parity row, not per gate.

Rows 118-123 (DISK_LAYOUT, C-only, CK-4; numbered 113-118 on the CK-4 branch before the merge with main, which gave 113-117 to SMP) are 5 QEMU PASS (118-122, receipt `ck_gates_d80363...` at 741b2b8, before the merge with main 8555049) and 1 host-test PASS (123), none NOT_RUN. With them, rows 1-123 plus the M4 continuity/recovery sub-rows: IDENTICAL 28, DIFFERS 39, NOT_RUN 91, PASS 6 (C-only DISK_LAYOUT, hardware NOT_RUN) (91 from the SMP line next; recounted from the table at the merge commit, status = each row's first status cell, escaped pipes read as text: 28 IDENTICAL, 39 DIFFERS, 87 NOT_RUN (82 + SMP 113-117), 9 QEMU PASS (NET 102, 110-112, counted as NOT_RUN as below, and DISK_LAYOUT 118-122), 1 PASS (123); sub-rows 24a and 24b not counted).

Rows 113-117 (SMP, C-only, new in this change): 5 NOT_RUN (pending forge receipt), so rows 1-117 plus the M4 continuity/recovery sub-rows: IDENTICAL 28, DIFFERS 39, NOT_RUN 91 (86 from the line below plus these 5).

Rows 1-112 plus the M4 continuity/recovery sub-rows 83a-87i and 88a-91p: IDENTICAL 28, DIFFERS 39, NOT_RUN 86, counted from the table (the CK-5 contract branch split rows 81-91, 11 NOT_RUN rows, into 52 NOT_RUN rows, one per Rust QEMU check and host test, see `native/kernel/CONTINUITY_RECOVERY_CONTRACT.md`; that adds 41 NOT_RUN rows and changes no other row or gate; the CK gate tally is unchanged; recounted again after merging the KEYBOARD DMA-fence branch: 28 IDENTICAL, 39 DIFFERS, 82 NOT_RUN and 4 QEMU PASS rows (102, 110-112) counted as NOT_RUN as below, so 86, unchanged, with sub-rows 24a and 24b (C only) not counted; rows 25-28, 31 and 32 now have a C implementation and a child script, scripts/qemu_ck_keyboard_test.sh, but stay NOT_RUN (pending forge receipt), rows 29-30 stay NOT_RUN (MISSING_IMPLEMENTATION: no USB HID driver, no console shell), and the KEYBOARD gate stays NOT_RUN; rows 107-109, kernel entropy, are C-only and DIFFERS; row 102, virtio-net attach with ACCESS_PLATFORM, and rows 110-112, virtio-net SMMU fence, recovery and ACCESS_PLATFORM fail-closed, are C-only and NOT_RUN on this branch until a forge receipt covers them; the CK gate tally above and its receipt `ck_gates_929f...` predate them; no full `ck_gates.sh` run happened on this branch, only `scripts/qemu_ck_net_test.sh` alone, so rows 102 and 110-112 are shown as QEMU PASS (receipt `evidence/ck_net_qemu_8bdbc2e46b85d04c422f9d2830c1c4b263e254b3cfecfe21ff0063c9e33c86e8.log`, hardware NOT_RUN) and the NOT_RUN count still includes them as originally counted, not recounted); rows 34 and 39 now also cover the NVMe boot-disk source and its hostile disk cases (statuses unchanged) (the previous summary, 20/30/56, was miscounted: the table on main had 21/35/50; rows 33-41 then moved from NOT_RUN to 7 IDENTICAL + 2 DIFFERS with the C artifact loader; rows 92-95 have no CK gate at all; rows 96-112 are C-only). Rows 33-41 were checked against scripts/qemu_ck_artifact_test.sh. Rows 102-106 and 110-112 were checked against scripts/qemu_ck_net_test.sh (text only; rows 102 and 110-112 then run by the forge, see their rows). Rows 13, 24, 47-72, 76 and 96-101 were re-verified against scripts/qemu_ck_store_test.sh and scripts/lib_ck_m1_checks.sh at the commit that adds this line. Rows 73, 75 and 77-80 now have a C implementation (`scripts/qemu_ck_store_crash_test.sh`, TEST-only hook `native/kernel/svc/store_crash.c`) but no receipt yet, so they stay NOT_RUN and the 28/39/86 count is unchanged by that commit (recounted from the table after rebasing onto main 2ee61b4, #224 SMP, status read from each row's last cell with an escaped pipe inside a cell read as text: 28 IDENTICAL, 39 DIFFERS, 82 NOT_RUN + rows 102 and 110-112, QEMU PASS counted as NOT_RUN as above, = 86, sub-rows 24a and 24b not counted; the SMP rows 113-117 add 5 NOT_RUN for the 91 above). The CK gate tally above is unchanged: `M4_STORE_CRASH` stays NOT_RUN until a forge receipt.

`scripts/trust1_m5_qualify.sh --with-qemu` also runs three of these gates as
qemu rows: `ck_m1_boot_qemu` (M1), `ck_store_kernel_qemu` (M4_STORE) and
`ck_argus1_revoke_qemu` (ARGUS1_REVOKE). Its `m5_store_kernel_binding` row
stays MISSING_IMPLEMENTATION: it asks for the binding on a real device, which
QEMU cannot show.

## FPU: scripts/qemu_ck_fpu_test.sh -> CK `FPU` (aienos#34 lane 0, C-only, no Rust-kernel counterpart)

One floating-point/SIMD-enabled Rust unit (`crates/aienos-fpu-probe`, a no_std staticlib) is linked into a
QEMU-only probe image (`make -C native/kernel CK_RUST_LIBS=<libaienos_fpu_probe.a>`, which adds
`-DCK_FPU_PROBE=1` for `core/fpu.c`) and called from the C kernel, which stays `-mgeneral-regs-only`. The
default image is unchanged (no Rust, no FP code). The kernel runs at EL1h; `ck_fpu_enable()` sets
`CPACR_EL1.FPEN = 0b11` + `isb` (vectors.S already did at the EL2 -> EL1 drop; CPTR_EL2 is set to no-trap
there). The unit runs with DAIF masked: the kernel saves no FP state. The gate is NOT_RUN (never a silent
pass) when cargo, the `aarch64-unknown-none` target, QEMU or AAVMF is missing. Not required in CI (the
runner is not known to have the Rust target); required list in `ck-kernel.yml` skips it.

| # | check | gate | status |
|---|---|---|---|
| 124 | probe returns 0; f32 dot product of two 16-element arrays = 68.0 exactly (`dot_bits=0x42880000`) | FPU | QEMU PASS (aienos-ni-fp branch; hardware NOT_RUN) |
| 125 | f32 exp approximation: exp(1) within 1e-4 of e (bits checked by the script, not the kernel) | FPU | QEMU PASS (hardware NOT_RUN) |
| 126 | NEON `vaddq_f32` lanes = 11,22,33,44 via `core::arch::aarch64` | FPU | QEMU PASS (hardware NOT_RUN) |
| 127 | `CPACR_EL1.FPEN = 0b11` read back at EL1 after `ck_fpu_enable()` | FPU | QEMU PASS (hardware NOT_RUN) |
| 128 | negative control: with FPEN cleared in `ck_fpu_enable()` the first FP instruction traps and the gate FAILs (kernel fault report, no result line); canned-log self-test (`--self-test`) rejects wrong dot/exp/NEON/rc/FPEN/missing lines | FPU | QEMU PASS (control killed; hardware NOT_RUN) |

## INFER: scripts/qemu_ck_infer_test.sh -> CK `INFER` (aienos#34 lane 4 cut 1 + lane 5 cut 2, C-only, no Rust-kernel counterpart)

The kernel ingests the 807,694,368-byte Llama-3.2-1B-Instruct Q4_K_M GGUF into its own RAM and calls the Rust
crate `crates/aienos-infer` from C through `crates/aienos-infer-kernel` (a no_std staticlib: the `extern "C"`
entry `aienos_infer_run` plus a documented bump allocator over one 256 MiB region). It parses the GGUF header,
binds the `Model`, tokenizes the fixed chat prompt "What is the capital of France?", runs prefill and greedy
decode until `<|eot_id|>` (128009) or 16 tokens on the same code path as the host test
(`crates/aienos-infer/tests/forward.rs`: `DecodeState`, `prefill`, `argmax`, `forward`), and hands ids, decoded
bytes and per-token microseconds (`ck_time_us`) back for the kernel to print (`infer: tokens=`, `infer: text=`,
`infer: tok_us=`, `infer: decode_tokens=N mean_tok_us=`). The weights stay quantised in the ingested bytes
(Q4_K/Q6_K dequantised per block inside each dot product); only norms, the KV cache (64 positions) and
activations live on the unit's heap. Unload: the unit keeps nothing past its return, the kernel forgets the heap
region (`aienos_infer_heap_init(0, 0)`: every later allocation fails closed) and returns every frame of the model
and the heap; `infer: unloaded heap_live_kib=.. frames_free_before=.. frames_free_after=..` must show the free-frame
count back at its pre-ingest value, and the kernel then continues to M3, the stages, the final report and the PSCI
reset. FP registers are left dirty after the unit (nothing else in the kernel reads them; EL0 traps on FP).
QEMU-only probe image:
`make -C native/kernel CK_INFER_LIB=<libaienos_infer_kernel.a>` (adds `-DCK_INFER_PROBE=1` for `core/infer.c`;
refused together with `CK_RUST_LIBS` or `CK_HARDWARE_STAGING`). The default image is unchanged; the probe image
must carry its own TEST-ONLY fw_cfg announcement (the default-image fw_cfg ban in `fwcfg_check` stays).

Ingest path: QEMU fw_cfg DMA (QEMU `docs/specs/fw_cfg.rst`, "Guest-side DMA Interface", qemu 8.2.2), model passed as
`-fw_cfg name=opt/aienos/model,file=<gguf>`, QEMU `-m 4096`; frames come from `ck_mm_frames_alloc`. The fw_cfg
window is found in the ACPI DSDT (QEMU0002) as in the artifact loader. The C kernel has no virtio-blk driver, so a
disk image would need a new driver; fw_cfg DMA needed none. The byte-wise data register was not used: the DMA read
of the whole file takes ~40 ms, the kernel's SHA-256 of it ~8.6 s under TCG. FP/SIMD is enabled
(`CPACR_EL1.FPEN = 0b11`) and DAIF is masked around the Rust unit, as in `core/fpu.c`. The gate is NOT_RUN (never
a silent pass) when the model file, cargo, the `aarch64-unknown-none` target, QEMU or AAVMF is missing; not
required in CI (the runner has neither the model nor the target).

| # | check | gate | status |
|---|---|---|---|
| 129 | kernel ingests exactly the host file's size (fw_cfg size and ingest bytes = `stat`) | INFER | QEMU PASS (hardware NOT_RUN) |
| 130 | kernel-computed SHA-256 of the ingested bytes = host `sha256sum` = pinned model hash `3f5a2242...62dcc1` | INFER | QEMU PASS (hardware NOT_RUN) |
| 131 | probe rc = 0; 147 tensors (`golden.rs:112`), vocab 128256, 16 layers | INFER | QEMU PASS (hardware NOT_RUN) |
| 132 | first four prompt ids = 128000 128006 882 128007 and prompt length 17, both read from `crates/aienos-infer/tests/fixtures/ref_fr.txt` by the script | INFER | QEMU PASS (hardware NOT_RUN) |
| 133 | kernel alive, no panic/fault, final report, QEMU exit 0 (PSCI reset); M1/M3 boot gate unchanged PASS | INFER | QEMU PASS (hardware NOT_RUN) |
| 134 | negative control: `--negative-control` overwrites the GGUF magic in a host copy -> probe rc=-2, every probe check FAILs, control prints PASS; `--self-test` canned logs reject 33 mutations, each by its own FAIL line | INFER | QEMU PASS (control caught; hardware NOT_RUN) |
| 135 | generated ids = the llama.cpp greedy sequence of `ref_fr.txt` "step" lines, exact: 791 6864 315 9822 374 12366 13 128009 (EOT included), read from the fixture by the script and also hard-coded in `core/infer.c` for the kernel verdict | INFER | QEMU PASS (hardware NOT_RUN) |
| 136 | decoded text contains "Paris" (`infer: text=The capital of France is Paris.`) | INFER | QEMU PASS (hardware NOT_RUN) |
| 137 | per-token timing line present: 7 decode forwards, mean > 0 us. First native CPU number: 40.40 s per decode token, prefill 553.9 s for 17 tokens, whole Rust call 837.8 s, under QEMU TCG single core (not hardware; host test on one Grace core is 0.59 s per forward) | INFER | QEMU PASS (hardware NOT_RUN) |
| 138 | clean unload: `infer: unloaded` line present before the final report, frame-return rc 0,0, free frames after = before the ingest (1021097 = 1021097; 262728 frames returned), kernel then reaches M3, stages, final report, PSCI reset (QEMU exit 0) | INFER | QEMU PASS (hardware NOT_RUN) |
| 139 | live control: the same serial log re-checked against a mutated expected-id list (second-to-last id + 1) must FAIL on the token check, else the gate FAILs; `--self-test` also covers wrong/short/swapped tokens, missing tokens/text/timing/unload lines, missing "Paris", leaked frames, refused frame return, unload after the final report | INFER | QEMU PASS (control caught; hardware NOT_RUN) |

## SCREEN: scripts/qemu_ck_screen_test.sh -> CK `SCREEN` (L6-C prerequisite, C-only, no Rust-kernel counterpart)

The UEFI stub finds the Graphics Output Protocol (UEFI 2.10 section 12.9) before ExitBootServices and passes the
linear framebuffer (base, size, width, height, pitch in pixels, format RGBX or BGRX) in the CHANDOF3 handoff
(`docs/BOOT_HANDOFF_CONTRACT.md`, offsets 192-231). The kernel refuses older records (`unsupported version N`),
maps the framebuffer with `ck_mmio_map` (Device-nGnRE) unless it overlaps RAM, and mirrors every console byte on
screen in white on black with the public-domain 8x8 font (`core/font8x8.h`, cell 8x10 times a scale of
height/540 clamped to 1..4 and lowered until 80 columns fit). Scrolling mode is half-scroll: when the screen is
full, it is cleared and the newest half of the rows is redrawn from a text copy (no read-back of device memory).
Without a GOP the kernel still boots and says `screen: none` on the UART.

The gate boots the default image under QEMU with `-device ramfb` (AAVMF gives an 800x600 BGRX GOP on it), lets the
PSCI reset pause the VM (`-action reboot=shutdown,shutdown=pause`) and takes a QMP `screendump`. The host tool
`ck_fb_check` (`make -C native/kernel fb-check`) renders the serial log from the `screen: gop` line onward with the
same `core/fbcon.c` code and compares every pixel with the dump, then decodes every cell back to text. The gate is
NOT_RUN (never a silent pass) when QEMU, AAVMF, socat or the cross compiler is missing.

| # | check | gate | status |
|---|---|---|---|
| 140 | stub prints a `gop: ok` line; the kernel prints exactly one `screen: gop` line whose geometry equals the screendump (800x600 BGRX on ramfb), reaches `kernel: alive`, no panic or fault | SCREEN | QEMU PASS (receipt `evidence/ck_gates_ad05e004e30237e57e72fc1d3362cfe2b31af9b99451d9d2bb2414238e4d6590.json`, full `ck_gates.sh` at 2e44c0b, 17 PASS 0 FAIL 2 NOT_RUN of 19; hardware NOT_RUN) |
| 141 | screendump = the expected rendering of the serial log, pixel for pixel (`mismatched=0`), every cell decodes to a font glyph (`undecodable=0`) | SCREEN | QEMU PASS (same receipt; hardware NOT_RUN) |
| 142 | the decoded screen holds the final verdict rows `report_kind: final` and `note: QEMU qualifies nothing physical` | SCREEN | QEMU PASS (same receipt; hardware NOT_RUN) |
| 143 | negative boot: the TEST-ONLY stale image (`make CK_TEST_STALE_HANDOFF=2`, announces itself, refused with `CK_HARDWARE_STAGING`) passes a CHANDOF2 record; the kernel panics with `handoff: unsupported version 2 (kernel reads CHANDOF3 only)`, draws nothing, and the pixel check on its dump FAILs; the default image contains no stale text | SCREEN | QEMU PASS (control caught, same receipt; hardware NOT_RUN) |
| 144 | host tests: `test_handoff` framebuffer cases (Spark-like 1920x1080 BGRX, padded pitch, every refusal reason, version refusals) and `test_fbcon` (glyphs, scale, refusals, pixels, lazy newline, wrap, half-scroll, unprintable bytes) | SCREEN (host, `make test`) | PASS (host test, `CK_CORE_HOST: PASS`) |
| 145 | `--self-test`: 12 canned logs, each wrong or missing line rejected by its own FAIL | SCREEN | PASS (script self-test) |

Evidence: red on main a93e27b (`AIENOS_CK_SCREEN: FAIL`, gate script and branch-built checker copied in), green at 2e44c0b standalone and in the full receipt above, green again at c2232ef (CodeQL widening fix in fbcon.c): `fb_check: PASS 800x600 format=bgrx scale=1 grid=100x60 scrolls=1 pixels=480000 mismatched=0 undecodable=0`. Logs: `~/workspace/evidence-out/L6C/` on the Spark (not committed).
