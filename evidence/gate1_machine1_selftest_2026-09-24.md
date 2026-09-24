# TRUST-1 Gate 1: recovery stick boots on Machine 1 (2026-09-24)

Result: **partial PASS on hardware.** The dedicated recovery stick boots on
Machine 1 with Secure Boot on, runs entirely from RAM, finds the keyboard,
the stick and the internal NVMe, reads Secure Boot state and TPM PCRs, saves
its report, and returns to Linux on its own. The unlock, reinstall and
restore items (9 to 14) and the test-artifact round trip are not done yet.

## What ran

- Media: `AIENOSRECOV` (1 GB USB stick, USB serial 5D0344B4, vfat UUID
  3511-E686, GPT PARTUUID f227357c-1e80-4fd0-a55e-2efbef1dd25c), written by
  `scripts/build_recovery_media.sh` at main 0379b2f (#53). This is the former
  ATLAS_RECOV stick; the operator authorized wiping it on 2026-09-24.
- Trigger: `aienos-selftest-once` flag on the stick, `efibootmgr -n 0004`,
  `shutdown -r` at 08:07:31 CDT. No keyboard input.
- Boot chain: firmware -> `EFI/BOOT/BOOTAA64.EFI` (Ubuntu shim, identical to
  the internal `EFI/ubuntu/shimaa64.efi`) -> signed GRUB -> signed kernel
  7.0.0-1019-nvidia -> RAM initrd.

| File on the stick | SHA-256 |
|---|---|
| `EFI/BOOT/BOOTAA64.EFI` | `706f15b9578f780a2fddda8ee0806cd15b59124692cc297db320414a5a40fe44` |
| `EFI/BOOT/grubaa64.efi` | `b9d9dd81845d68a1f1867b5bcf26393908a9a349e749ce8ea944a1066d9abfcc` |
| `EFI/BOOT/mmaa64.efi` | `afc533e2ccc208cd1fa6e1e88a3d6a79faa1de5eb0f2d58eab2fdd228b0021df` |
| `EFI/BOOT/grub.cfg`, `EFI/ubuntu/grub.cfg` | `e551c5175c8b62de98cf6fbffb11c8702d451c751060062b92eff8123c9b7b91` |
| `aienos-recovery/vmlinuz` | `ddd5a25c2326fbfdf7e03809c614fafe5a953416bbb1b80f9c2258f7260e44e3` |
| `aienos-recovery/initrd.img` | `d04ede86813c347a41ec7f24674c3a07555fae5719c0202c0361b5c0b3f2b390` |

## Evidence

- Report written by the recovery environment to the stick, copied verbatim:
  [gate1_machine1_selftest_report_2026-09-24.txt](gate1_machine1_selftest_report_2026-09-24.txt)
  (SHA-256 `3a4a6deb894e61527557968c3591fbfb31029779921d428921235caca7b89486`).
- Operator photograph of the Machine 1 screen at 13:09:48Z showing the same
  report and the self-test countdown. Kept offline because phone photos carry
  location metadata; SHA-256
  `01f77ba2a06620de2ceaab9d196b1948d3063f907a67f65ef69222fa39e0dfa6`.
- After return: `BootCurrent: 0001`, BootNext consumed, BootOrder unchanged
  (`0001,0003,0004`), flag removed from the stick, `mokutil --sb-state`
  enabled, `atlas-private-storage` active.

## Gate 1 acceptance (TRUST-1 plan, all with Secure Boot on)

| # | Test | Result |
|---|---|---|
| 1 | Firmware accepts recovery image | PASS: `BootCurrent: 0004` inside the recovery report |
| 2 | Starts without internal Linux | PASS: RAM root, internal NVMe never mounted |
| 3 | No network required | PASS: the image has no network configuration or network tools |
| 4 | No model required | PASS |
| 5 | No Cortex required | PASS |
| 6 | Identifies NVMe and encrypted volumes | PARTIAL: NVMe and partitions identified; the gocryptfs private store lives inside the ext4 root and is not identified |
| 7 | Inspects Secure Boot state | PASS: `Secure Boot: enabled`, lockdown `integrity` |
| 8 | Inspects PCRs | PASS: PCR 0 and 7 equal the Gate 0 baseline values |
| 9 | Shows AIENOS A/B slots and manifests | PENDING: A/B slots do not exist yet |
| 10 | Verifies signatures/hashes | PENDING |
| 11 | Independent recovery only when authorized | PENDING |
| 12 | Mounts recovered storage safely | PENDING |
| 13 | Reinstalls known-good loader/slot | PENDING |
| 14 | Restores documented boot config | PENDING (boot entries are read; efivarfs is mounted read-only) |
| 15 | Returns to known-good Linux | PASS: restarted unattended, Linux default boot |
| 16 | No destructive overwrite | PASS: the only write was the report and flag removal on the stick |
| - | Test-artifact round trip | PENDING |
| - | Keyboard | PASS for detection (HP Wired Desktop 320K and Logitech devices bound); typing not exercised in this unattended run |

## Findings

- **First attempt failed with "Secure Boot Violation".** A firmware boot entry
  `Boot0000 "AIENOS"` had been created outside Linux pointing directly at
  `\aienos-recovery\vmlinuz`, bypassing shim; the firmware db does not trust
  the Ubuntu kernel signature directly. The stick itself was not at fault.
  The entry was deleted with operator approval.
- **Existing Linux boot race.** On this boot and the previous normal boot,
  the first `atlas-private-storage` unseal failed with TPM error 0x128
  (`TPM_RC_PCR_CHANGED`) and the automatic retry succeeded. It predates the
  recovery boot; PCR 7 is unchanged.
- **Tooling defects fixed in #53:** no kernel modules in the initrd (no USB,
  keyboard or NVMe), shell on the unreachable serial console, and `/bin/blkid`
  silently missing from the initrd (the earlier Gate 1 receipt lists it).

## Offline key custody (Gate 0 follow-up)

`atlas-forge-state-luks-recovery-key.txt.age` (age recipient tag `+4nykQ`,
the operator's MacBook SSH key) now exists as ciphertext on Machine 1 and on
the operator MacBook. Decryption has still not been exercised; Gate 0's
independent-access proof remains open.
