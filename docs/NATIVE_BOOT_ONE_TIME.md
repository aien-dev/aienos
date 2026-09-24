# First native boot on Machine 1: attended, one time

This procedure boots the `aienos-handoff` image on the DGX Spark exactly once
and brings the machine back to Linux on its own. It is the M2 hardware gate and
the rollback test that closes M0.

## What the image does

1. **Before firmware exit:** finds the GB10 and the display mode the firmware
   set up, prints a pre-exit report on screen, and saves it to
   `\EFI\AIENOS\BOOTREPORT.TXT` on the EFI system partition.
2. **After firmware exit:** the AIENOS kernel takes over, sets up its early
   allocator, and writes its report three ways:
   - drawn directly on the screen with a built-in font (no GPU driver),
   - stored in the `AienosBootReport` firmware variable,
   - sent to the Spark UART at `0x16A00000`, with a time limit so a missing
     serial path cannot hang the boot.
3. Counts down 30 seconds on screen, then asks the firmware for a cold reset.

The image does not touch the Linux installation, its partitions, or BootOrder.

## Before you start

- **Secure Boot must be off.** On 2026-09-24 it was on (Ubuntu boots through
  `shimaa64.efi`). The firmware refuses an unsigned image while it is on. The
  staging script checks this and stops. Alternative: sign the image with your
  own key and enroll it (the later owner-signed boot milestone).
- **Be at the machine** with a monitor and keyboard attached.
- **Have recovery media** (a Linux USB stick) in case the firmware misbehaves.
- **Everything running on this Linux install stops** for the reboot: agents,
  model servers, the website waitlist API, and remote access.

## Steps

```bash
bash scripts/stage_one_time_boot.sh            # dry run: prints the plan
bash scripts/stage_one_time_boot.sh --apply    # needs sudo; sets BootNext only
sudo reboot
```

Expect: the firmware logo, the AIENOS pre-exit report, then a dark screen with
`AIENOS NATIVE BOOT REPORT` and a countdown. After the reset, Linux boots
normally. Then:

```bash
bash scripts/collect_boot_report.sh
```

`NATIVE_BOOT_OK` means the kernel ran and its report survived the reset.

## If something goes wrong

- **Screen stays black or frozen:** hold the power button until the machine
  turns off, then power on. BootNext was used up by the failed attempt, so the
  machine boots Linux. Anything already saved (the pre-exit file) is still
  readable afterwards.
- **Firmware says the image is not allowed:** Secure Boot is still on.
- **Linux does not come back:** boot the recovery media, or choose `ubuntu` in
  the firmware boot menu. The AIENOS entry is not in BootOrder, so it never runs
  unless BootNext is set again.

## What each outcome proves

| Evidence | Proves |
| --- | --- |
| Pre-exit file present | Firmware accepted and ran the image; GB10 and display were discovered through firmware services |
| Report on screen after exit | The firmware framebuffer stays writable after `ExitBootServices` |
| `NATIVE_BOOT_OK` from the firmware variable | The AIENOS kernel ran on Machine 1 and runtime variable writes work |
| `uart_report: sent` on screen | The UART at `0x16A00000` accepts output (whether a cable can reach it is separate) |
| Machine returned to Linux by itself | Firmware reset works, and the one-time path rolls back cleanly |

Record the collected output in the evidence bundle before claiming the M2 gate
or marking the M0 recovery procedure verified.
