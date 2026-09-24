# ADR 0008: Temporary Bring-Up Exception for a Post-Handoff Firmware Report

Status: accepted by the operator, 2026-09-24, as a **temporary bootstrap
exception to escalation trigger 11**. It does not change the architecture.
Governing: [ADR 0003](0003-bootstrap-firmware-handoff-and-minimal-object-store.md), [MILESTONES.md section 0 and section 3](../MILESTONES.md), [NATIVE_BOOT_ONE_TIME.md](../NATIVE_BOOT_ONE_TIME.md).

## Context

ADR 0003 makes firmware handoff one-way: after `ExitBootServices`, firmware
runtime storage is not part of AIENOS operation. The first native boot on
Machine 1 has no proven native console, external capture or native persistent
storage. If that boot fails, a small report that survives the reset is the
only reliable evidence of how far the kernel got.

## Decision

The explicit bring-up and test image (`aienos-handoff`) may write a small
diagnostic report into UEFI variable storage after handoff, under these
conditions set by the operator:

1. Only the bring-up/test image may do it.
2. Only diagnostic and evidence data may be written. Never credentials,
   personal data, model state, Cortex state, or agent identity state.
3. The variable is namespaced and versioned: `AienosBootReportV1` under vendor
   GUID `a1e05b0e-7c3d-4f51-9b6a-2d8e4c1f0a37`, so it cannot overwrite
   unrelated firmware state.
4. Writes are bounded: at most 3 per boot (progress, final or fault) and at
   most 3072 bytes each.
5. A failed write never prevents boot; the result is reported and boot
   continues.
6. Normal AIENOS operation does not depend on UEFI runtime variable services.
7. Every write is in the hardware-test ledger. Each report states its own
   `nvram_write_index`, and `scripts/collect_boot_report.sh` runs under
   `aien-proof hold --resource machine-1`, which records the collected report
   as an `audit` event.
8. The exception is removed once a reliable native console, external capture
   or native persistent evidence path exists.

**Reset after handoff.** The image resets through PSCI `SYSTEM_RESET`, the
architected Arm interface, which is not a UEFI runtime service. UEFI
`ResetSystem` is called only if PSCI returns without resetting. That fallback
is part of this bring-up exception and is removed with it.

## Target boundary (unchanged)

UEFI performs boot handoff, then `ExitBootServices`, then AIENOS owns the
machine. Firmware runtime storage is no longer part of normal OS operation.

## Consequences

- A failed first boot still leaves the last boot stage, fault registers, or
  panic message in a place Linux can read after the reset.
- Removing the exception means deleting `save_report_var`, the
  `AienosBootReportV1` variable, and the UEFI reset fallback from
  `crates/aienos-boot/src/handoff.rs`, and replacing the collector's variable
  check with the native evidence path.
