# Fix chain: SMMUv3 xHCI DMA confinement (branch fix/m3-smmuv3-ste-cd-layout)

Base: 675d8c4 (forensic snapshot, branch wip/m3-smmu-c-bad-ste-635111c).
This note is appended to per commit; the original snapshot evidence is left
untouched in wip_m3_smmuv3_c_bad_ste_2026-09-24.md.

## Commit 1: fix(smmu): runtime-align linear stream table for QEMU SMMUv3

### Build blocker (root cause)

The snapshot tree did not build for aarch64-unknown-uefi. `cargo check` passes,
but the real `cargo build` traps rustc (SIGTRAP) in the COFF object writer.
A/B on the static alignment attribute:

    align(8192)    BUILD OK
    align(16384)   SIGTRAP
    align(262144)  SIGTRAP

COFF/PE cannot encode section alignment above 8192, so `repr(C, align(262144))`
on SMMU_TABLES was unbuildable. This is why the alignment fix had never been
re-run; the reported C_BAD_STE run came from the older align(4096) image.

### Change

- Removed `repr(C, align(262144))` from SMMU_TABLES.
- Allocate the tables at runtime: `Layout::from_size_align(size_of::<SmmuTables>(),
  262144)`, zeroed, cached in a shared `AtomicUsize`; one accessor
  `smmu_tables()` feeds both the configure path and the fault-dump path.
- Kept 4096 stream table entries.
- Added explicit geometry asserts: table size == 262144, LOG2SIZE == 12,
  SID < 4096, and the aligned base % 262144 == 0.

### Verification

    cargo fmt --check                                        OK
    cargo build --release -p aienos-boot --target aarch64-unknown-uefi \
        --features usb-keyboard                              OK

### QEMU result (AIENOS_QEMU_SMMU=1)

    smmu_ste: base=0xbbf40000 cfg=0xc sid=0x10 addr=0xbbf40400 words=[0xbbf8030b,0x0]

- base 0xbbf40000 is 256 KiB aligned; cfg 0xc is LOG2SIZE=12, FMT=0 (linear).
- STE address == base + 0x10 * 64. STE is valid (V=1, Config=5, S1Fmt=0,
  CTXPTR=0xbbf80300).
- C_BAD_STE (0x04) is eliminated. The next event was C_BAD_CD (0x0a): the STE
  is accepted, the CD is fetched, and QEMU rejected the CD.

## Commit 2: fix(smmu): correct AArch64 context descriptor layout

### Root cause

ContextDescriptor::stage1 placed the CD control fields one 64-bit word too
high. QEMU and Linux define them inside CD word 0:

    CD_0: T0SZ[5:0] TG0[7:6] IRGN0[9:8] ORGN0[11:10] SH0[13:12] EPD0[14]
          ENDI[15] T1SZ[21:16] TG1[23:22] EPD1[30] V[31] IPS[34:32]
          AA64[41] R[45] A[46] ASID[63:48]
    CD_1: TTBR0
    CD_2: TTBR1
    CD_3: MAIR

The old code put IPS/AA64/R/A/ASID in word 1 and TTBR0 in word 2, so QEMU read
CD_AARCH64=0 and CD_A=0 and rejected the descriptor (C_BAD_CD). It also set
word 0 bit 14 = EPD0, disabling the TTBR0 walk, and put MAIR in word 4.

### Change

- CD word 0 now holds T0SZ/TG0/IRGN0/ORGN0/SH0, EPD1, V, IPS, AA64, R, A and
  ASID; EPD0 is clear so the TTBR0 stage-1 walk runs.
- CD word 1 is TTBR0, word 2 is TTBR1 (unused, EPD1 set), word 3 is MAIR.
- descriptor_layouts and policy_maps_only_allowed_windows updated to the new
  layout (TTBR0 now cd.0[1], MAIR now cd.0[3]).

Note: MAIR is CD word 3 per the SMMUv3 spec and Linux
(arm_smmu_write_ctx_desc writes cdptr[3] = cd->mair), not word 2.

### Verification

    cargo fmt --check                                        OK
    cargo test -p aienos-kernel smmu                         5 passed
    cargo build --release -p aienos-boot --target aarch64-unknown-uefi \
        --features usb-keyboard                              OK
    AIENOS_QEMU_TIMEOUT=90 bash scripts/qemu_smmu_test.sh    QEMU_KEYBOARD: PASS

### QEMU smmuv3 trace (config decoded once, then cached)

    smmuv3_get_ste      STE addr: 0xbbf40400
    smmuv3_get_cd       CD addr:  0xbbf80300
    smmuv3_decode_cd    oas=44
    smmuv3_decode_cd_tt TT[0]:tsz:16 ttb:0xbc32f000 granule_sz:12 had:0
    smmuv3_translate_success  583
    smmuv3_config_cache_hit   582
    smmuv3_translate_disable  192   (pre-enable bypass)
    smmuv3_get_ste / get_cd / decode_cd = 1 each (accepted, then cached)
    no smmuv3_record_event, no fault events

### AIENOS serial proof

    smmu: enabled base=0x9050000 stream_id=0x10
    smmu_dma_window: xhci only, translation active
    keyboard: ready (port 5, slot 1, endpoint 0x81)
    keyboard_echo: abc / help / el / mem / exit
    keyboard: done (exit)

### Acceptance progression

    C_BAD_STE gone              PROVEN
    C_BAD_CD gone               PROVEN
    CD accepted                 PROVEN
    stage-1 PT walk reached     PROVEN (TT[0] tsz16 granule12, 583 translate_success)
    DMA translation succeeds    PROVEN
    xHCI Enable Slot completes  PROVEN (keyboard: ready)
    keyboard attaches           PROVEN
    typed-input proof           PROVEN (keyboard_echo: abc ... exit)

SMMUv3 DMA confinement for the xHCI controller is now demonstrated in QEMU.
Emulator only; this says nothing about Machine 1 hardware.
