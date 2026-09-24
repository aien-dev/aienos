# WIP snapshot: SMMUv3 xHCI DMA confinement, stuck at C_BAD_STE for SID 0x10

Status: WORK IN PROGRESS. This commit preserves a failing experiment on purpose.
The failure is the evidence. Do not merge. Supersedes the earlier
"SMMU DMA window translated" claim, which is not proven.

## Snapshot provenance

- Base commit: 635111c (feat(kernel): preemptive multi-threading via timer IRQ)
- Source branch: codex/complete-m3 (worktree ~/workspace/aienos_m3_codex)
- Snapshot branch: wip/m3-smmu-c-bad-ste-635111c
- Host: spark-b87b
- QEMU: 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18)
- rustc: 1.98.1 (48a229cea 2026-09-01)
- Excluded from this commit: crates/aienos-boot/src/handoff.rs.orig,
  crates/aienos-boot/src/usb_keyboard.rs.orig (editor backups).

## What this snapshot contains

- EL0 capability / fault isolation work (crates/aienos-kernel/src/user.rs, new)
- SMMUv3 boot integration in the boot handoff
- xHCI DMA window integration
- debug-xhci-without-smmu feature (crates/aienos-boot/Cargo.toml)
- xHCI timeout tracing and SMMU EVENTQ / STE readback tracing
- SMMU_TABLES aligned to 256 KiB (repr(C, align(262144))), was align(4096)
- scripts/qemu_smmu_test.sh reproduction entry point

## Empirical result as reported (not re-captured in this snapshot)

- Identity DMA / SMMU bypass: PASS. xHCI initializes, keyboard attaches,
  typed input works, shell checks work.
- SMMU enabled: SID = 0x10, FAIL at Enable Slot, no xHCI completion.
  EVENTQ_PROD = 8, EVENTQ_CONS = 0, eight event records of type 0x04.
- Reported software STE address: 0xbc3fc400.
  Reported QEMU STE fetch address: 0xbc3c0400.
  (These two addresses came from the interactive session; they are recorded
  here as reported, not independently re-captured in this commit.)

## Event code 0x04 is C_BAD_STE in QEMU (verified)

QEMU v8.2.2 hw/arm/smmuv3-internal.h defines the event enum as:
  0x01 F_UUT, 0x02 C_BAD_STREAMID, 0x03 F_STE_FETCH, 0x04 C_BAD_STE, ...
So the eight 0x04 records are C_BAD_STE, not F_TRANSLATION (0x10). QEMU's
numbering differs from the ARM SMMUv3 spec list; use QEMU's enum here.

## Mechanism (verified against QEMU v8.2.2 hw/arm/smmuv3.c)

Linear stream table path in smmu_find_ste():

    strtab_size_shift = log2size + 5;
    strtab_base = s->strtab_base & SMMU_BASE_ADDR_MASK
                  & ~MAKE_64BIT_MASK(0, strtab_size_shift);
    addr = strtab_base + sid * sizeof(*ste);

QEMU aligns the stream-table base DOWN to the size implied by LOG2SIZE before
computing the STE address. If software's stream-table base is not aligned to
that size, QEMU silently truncates the base, reads an unrelated (uninitialized)
64-byte word, sees STE_VALID == 0, and decode_ste() sets SMMU_EVT_C_BAD_STE
(smmuv3.c:562). That is a C_BAD_STE at Enable Slot, before any CD fetch.

Note the shift is log2size + 5 in 8.2.2, while an STE is 64 bytes = 2^6, so
+6 is what the layout implies. This +5 vs +6 is version sensitive; aligning
the base to 262144 (2^18) satisfies both 2^17 and 2^18.

## Current tree state vs the reported addresses

- SMMU_TABLES is now repr(C, align(262144)); the .orig had align(4096).
- LOG2SIZE is sid_bits = stream_entries.trailing_zeros() (= 12 for 4096),
  which is correct in this tree.
Therefore the reported base 0xbc3fc400 predates both fixes; it is not
256 KiB aligned and does not reflect the current source.

## Predicted next fault: ContextDescriptor EPD0

QEMU defines CD_EPD(x, sel) = extract32((x)->word[0], 16*sel + 14, 1), i.e.
CD word 0 bit 14 = EPD0. ContextDescriptor::stage1 sets:

    ... | (1 << 14); // Access flag enabled

Bit 14 of CD word 0 is EPD0 in QEMU's decode, so EPD0 = 1 disables the TTBR0
stage-1 walk. CD_A (access flag) is CD word 1 bit 14, not word 0 bit 14, so the
comment is wrong. Expected result once the STE is accepted: the event becomes
SMMU_EVT_F_TRANSLATION (0x10) instead of C_BAD_STE (0x04).

## Not proven

- Correct/accepted STE for SID 0x10
- Context descriptor fetch
- Stage-1 DMA translation
- xHCI DMA confinement

## Reproduction

    scripts/qemu_smmu_test.sh
    # => AIENOS_QEMU_SMMU=1 bash scripts/qemu_keyboard_test.sh
