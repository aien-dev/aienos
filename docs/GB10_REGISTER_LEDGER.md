# GB10 register knowledge ledger

This is a source-backed inventory of GB10 registers AIENOS can point at a
source for. It is not a driver and it does not read any register. Unknown
registers stay unknown. Meanings are not inferred from register names or from
Linux driver behaviour.

The repository supports exactly two GB10 registers today: PMC `BOOT_0` and PMC
`BOOT_42`. There are no others. If a future milestone establishes more, they
are added here with their own evidence.

Governing: issue [#36](https://github.com/aien-dev/aienos/issues/36),
[GB10_HARDWARE_PROFILE.md](GB10_HARDWARE_PROFILE.md),
[GB10_NATIVE_ACCELERATOR_BOUNDARY.md](GB10_NATIVE_ACCELERATOR_BOUNDARY.md).

The machine-readable form is `GB10_REGISTERS` in
`crates/aienos-accel/src/registers.rs`.

## Ledger

| Block | Register | Offset | Width | Access | Evidence source | Observed value | Confidence / status | Safe to read | Native AIENOS observed | Semantics known |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| GB10 PMC | `BOOT_0` | `0x0000` | 32 bit | read only (per current use) | `crates/aienos-accel` offset used by the UEFI handoff | none recorded here | offset established in the repository; meaning not established | established read through the UEFI handoff path | no | no |
| GB10 PMC | `BOOT_42` | `0x0a00` | 32 bit | read only (per current use) | `crates/aienos-accel` offset used by the UEFI handoff | none recorded here | offset established in the repository; meaning not established | established read through the UEFI handoff path | no | no |

## Notes on each column

- **Offset.** The absolute offset from BAR0. The UEFI handoff reads
  `bar.physical_base + offset` before `ExitBootServices`.
- **Access.** The repository only ever reads these two. No write path exists,
  and none is proposed here.
- **Observed value.** Left empty. The register values are read at boot into the
  handoff report and the firmware variable, but no native AIENOS observation of
  them exists yet, so there is nothing verified to record. A Linux read was
  deliberately not performed: reading BAR MMIO outside the established safe set
  needs separate approval.
- **Confidence / status.** The offsets are established in this repository. The
  meaning of each register is not.
- **Safe to read.** Both are inside the set the existing handoff already reads
  through the UEFI root bridge memory protocol. A read outside this set would
  need explicit, separate approval, on the principle that a register being
  readable is not evidence that it is safe to read.
- **Native AIENOS observed.** False for both. Only UEFI firmware services have
  read them so far.

## Rules for adding a register

1. Cite a source. A source is a repository file, a public specification whose
   licensing and provenance are clear, or recorded hardware evidence. A name
   that looks meaningful is not a source.
2. Never copy proprietary documentation or incompatibly licensed source into
   the trusted base.
3. Record the access type. If it is unknown, say unknown.
4. Mark safe-to-read separately from the offset. An offset is not a safety
   argument.
5. Leave semantics unknown until there is evidence to establish them. Do not
   guess a bit layout from a downstream driver's use.
6. Set native-observed only after a native AIENOS path actually reads the
   register on hardware.
