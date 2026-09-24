# M2 first native boot on Machine 1: evidence (2026-09-24)

**Result: `M2_GATE: PASS`.** Machine 1 (DGX Spark, spark-b87b) left firmware,
ran native AIENOS code at EL2 with no Linux underneath (`kernel: alive`),
left a report in firmware variable storage that Linux read after the reset
(ADR 0008), and returned to the existing Linux system undamaged.

| Item | Value |
| --- | --- |
| AIENOS commit | `52109bcb334a95bdd33410b4d22c59dee8c917f4` |
| Boot image sha256 | `79505373088d2464b82181c06f07e18e20e4e9b2b55dbc9fc46e3f0a2e2e3ada` |
| Machine 1 lease holder | `claude-code` (aien-proof hold, stage and collect) |
| Operator at the machine | Drake (Secure Boot off, reboot, observation) |
| Staged | 2026-09-24T01:50:27Z, one-time entry Boot0000 via BootNext |
| Previous Linux stopped | 2026-09-23 20:52:35 CDT |
| Next Linux started | 2026-09-23 20:53:50 CDT (75 s gap: firmware, AIENOS, 30 s countdown, reset, firmware) |

## Hardware facts observed by native AIENOS code

- CPU: 20 cores in the firmware MADT, 10 in efficiency class 0 and 10 in
  efficiency class 1. The boot core is listed with class 0; MIDR `0x410fd871`
  (part `0xd87`, Cortex-A725). The boot path runs on an efficiency core.
- Exception level at handoff: EL2.
- Memory map: 184 descriptors, 36 conventional regions, 0 rejected,
  130073720 KiB conventional. Largest region at `0x323800000`, 30776318 pages.
  The early allocator reserved its first frame there.
- Timing: 64 ms from UEFI entry to handoff, 0 ms from handoff to kernel entry.
- Firmware variable writes: progress record (write 1) and final report (write 2
  of 3); attributes `0x07` (NV, BS, RT).

## Gaps (not gate failures; next iteration)

- `gb10: unavailable`: pre-exit GB10 discovery found no match through the UEFI
  PCI root bridge protocol, although Linux sees `10de:2e12` at
  `000f:01:00.0`. Because the UART path runs only when the GB10 was found, no
  UART output was attempted.
- The pre-exit report file `\EFI\AIENOS\BOOTREPORT.TXT` was not saved. The
  reason printed on the firmware console is recorded only in the operator's
  photograph, if taken.
- Post-exit screen drawing is not recorded in the variable (the final report
  is written after the kernel stage but its `last_stage` precedes drawing);
  the operator's photograph is the evidence for it.
- Firmware appended `Boot0004` (the attached USB stick) to BootOrder on its
  own; the original entries `0001,0003` keep their order.
- No bootable recovery media: the only USB stick holds a key backup, not a
  recovery system.

## Hardware-test ledger

| Index | Action | Target | Intent |
| --- | --- | --- | --- |
| 83 | audit | stage-native-boot | pass exit=0 resources=machine-1 |
| 84 | audit | collect-native-boot | fail exit=1 (collector bug: efivarfs cannot seek; boot order check too strict) |
| 85 | audit | collect-native-boot | pass exit=0, hash `3120ca800f79cfbd1ef52d28e3b36cfd9c09e2cb76777a6b9e1ffd86676a8faf` |

## Ledger payload of event 85 (verbatim)

```text
== staging record (/boot/efi/EFI/AIENOS/STAGED.TXT)
aienos_commit: 52109bcb334a95bdd33410b4d22c59dee8c917f4
image_sha256: 79505373088d2464b82181c06f07e18e20e4e9b2b55dbc9fc46e3f0a2e2e3ada
staged_by: claude-code
staged_at_utc: 2026-09-24T01:50:27Z
boot_current_before: 0001
boot_order_before: 0001,0003
linux_kernel_before: 7.0.0-1019-nvidia
aienos_boot_entry: 0000
== staged image
sha256: 79505373088d2464b82181c06f07e18e20e4e9b2b55dbc9fc46e3f0a2e2e3ada
== pre-exit report (/boot/efi/EFI/AIENOS/BOOTREPORT.TXT)
missing
== native firmware-variable report
report_version: 1
aienos_commit: 52109bcb334a95bdd33410b4d22c59dee8c917f4
report_kind: final
last_stage: kernel_entered
nvram_write_index: 2 of 3
AIENOS
arch: aarch64
boot: native
conventional_memory_kb: 130073720
memory_map_descriptors: 184
memory_map_conventional_regions: 36
memory_map_rejected_regions: 0
memory_map_largest_region: 0x323800000 pages 30776318
gb10: unavailable
cpu_cores: 20
cpu_efficiency_class_0: 10
cpu_efficiency_class_1: 10
cpu_boot_core_listed: yes
cpu_boot_core_class: 0
boot_cpu_midr: 0x410fd871 (part 0xd87)
allocator_managed_frames: 4096
allocator_reserved_frame_phys: 0x323800000
uefi_entry_to_handoff_ms: 64
handoff_to_kernel_entry_ms: 0
exception_level: EL2
kernel: alive
progress_record: saved
== current boot state
BootCurrent: 0001
Timeout: 1 seconds
BootOrder: 0001,0003,0004
Boot0000* AIENOS handoff (one-time)	HD(1,GPT,7c2b24e9-0ceb-4ad7-a401-9bf3c92c26ee,0x800,0x95000)/File(\EFI\AIENOS\aienos-handoff.efi)
kernel: 7.0.0-1019-nvidia
root: rw
== verdict
PASS  image_unchanged: staged 52109bcb334a, image 79505373088d2464
PASS  left_firmware_into_aienos: pre-exit file: missing, native report: present
PASS  native_code_after_firmware_exit: firmware variable written by AIENOS after ExitBootServices (kind final)
PASS  kernel_alive: last stage kernel_entered
PASS  boot_next_consumed: no pending one-time boot
PASS  boot_order_preserved: before 0001,0003, now 0001,0003,0004 (added by firmware: 0004)
PASS  linux_entry_booted: BootCurrent 0001
PASS  linux_kernel_unchanged: 7.0.0-1019-nvidia
PASS  root_filesystem_writable: /
M2_GATE: PASS
```
