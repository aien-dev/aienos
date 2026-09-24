# First native boot on Machine 1: attended, one time

This procedure boots the `aienos-handoff` first-boot evidence image on the DGX
Spark exactly once and brings the machine back to Linux on its own. It is the
M2 hardware gate and the rollback test that closes M0.

**Gate:** Machine 1 leaves firmware, enters native AIENOS code with no Linux
underneath, produces independently recoverable evidence that it did so, and
returns to the existing system without damaging it.

## What the image does

1. **Before firmware exit:** discovers the GB10 (PCI identity, BAR0, PMC boot
   registers), the CPU topology from the ACPI MADT (cores per efficiency class
   and the boot core's class), and the firmware display mode. It prints this
   pre-exit report on screen and saves it to `\EFI\AIENOS\BOOTREPORT.TXT`.
2. **After firmware exit:** installs AIENOS exception vectors, writes an early
   progress record, validates the firmware memory map, and enters the kernel.
   The final report goes to the screen, the `AienosBootReportV1` firmware
   variable ([ADR 0008](adr/0008-temporary-bring-up-firmware-report-exception.md))
   and the Spark UART (bounded).
3. **On a panic or CPU fault:** reports the last boot stage, the panic message
   or the fault registers (ESR, ELR, FAR, SPSR) the same three ways.
4. Counts down 30 seconds, then resets (PSCI first). BootNext is used up, so
   the machine returns to Linux.

The image does not touch the Linux installation, its partitions, or BootOrder.

## Before you start (at the machine)

1. **Recovery media:** plug in a bootable Linux USB stick. As of 2026-09-24 no
   removable media was attached. The internal fallbacks are present: the
   `ubuntu` boot entry (shim + GRUB), the firmware fallback loader
   `\EFI\BOOT\BOOTAA64.EFI`, and three installed kernels.
2. **Monitor and keyboard** attached to the Spark.
3. **Everything on this Linux install stops** for each reboot: agents, model
   servers, the aienos.com waitlist API, and remote access.

> **Paused (operator decision 2026-09-24).** Do not run this procedure again
> yet. Turning Secure Boot off changes TPM PCR 7, and Machine 1 seals its
> private-storage key and vault credential to that state: on the first boot,
> those secrets would not unseal, the encrypted storage stayed locked, and
> dependent services failed. Secure Boot is back on. Real-hardware AIENOS
> boots resume only after the owner-controlled boot chain exists: operator
> signing key, signed AIENOS loader and kernel, a defined TPM PCR policy, an
> independent recovery key, a tested recovery path, and secrets re-sealed to
> that policy. Until then, develop and test in QEMU.

## Step 1: turn Secure Boot off (operator decision 2026-09-24, since reversed)

```bash
sudo systemctl reboot --firmware-setup   # reboots straight into firmware setup
```

In the setup screen, disable **Secure Boot** only. Change nothing else. Save,
exit, and let Linux boot.

## Step 2: stage one boot

```bash
cd ~/workspace/hive-worktrees/aienos-main && git pull --ff-only
bash scripts/stage_one_time_boot.sh            # dry run: commit, digest, plan
sudo -v                                        # hold gives the command no stdin
aien-proof hold --resource machine-1 --job stage-native-boot -- \
    bash scripts/stage_one_time_boot.sh --apply
sudo reboot
```

The script refuses a dirty checkout (the boot must map to one commit) and
refuses while Secure Boot is on. It records `\EFI\AIENOS\STAGED.TXT`: commit,
image sha256, who staged it, and the boot state before.

Expect: the firmware logo, the pre-exit report, then a dark screen headed
`AIENOS NATIVE BOOT REPORT` (or `AIENOS BOOT STOPPED` in red), and a countdown.
**Photograph the screen** before the countdown ends; it is the only record of
the post-exit screen.

## Step 3: collect after Linux returns

```bash
aien-proof hold --resource machine-1 --job collect-native-boot -- \
    bash scripts/collect_boot_report.sh
```

The full output becomes an `audit` event in the hardware-test ledger.
`M2_GATE: PASS` requires every check below to pass.

| Evidence asked for | Where it comes from |
| --- | --- |
| Exact AIENOS commit | `aienos_commit` in STAGED.TXT, the pre-exit report and the native report, all compared |
| Exact boot image digest | `image_sha256` in STAGED.TXT, compared with the image on the ESP |
| Machine 1 lease holder | `aien-proof hold` records the agent in both ledger events; `staged_by` in STAGED.TXT |
| Firmware handoff data | Pre-exit report: firmware vendor/revision, counter frequency; kernel report: handoff timing |
| Heterogeneous CPU counts, boot-core class | `cpu_efficiency_class_*`, `cpu_boot_core_class`, `boot_cpu_midr` |
| Memory-map validation | `memory_map_descriptors`, `_conventional_regions`, `_rejected_regions`, `_largest_region` |
| GB10 PCI identity and BAR | `gb10_pci`, `gb10_bar0_phys`, `gb10_pmc_boot_0`, `gb10_pmc_boot_42` |
| Framebuffer/GOP observations | `framebuffer:` line pre-exit; the screen photo shows whether post-exit drawing worked |
| Console/UART observations | `uart_report: sent / no response` on screen |
| Last successful boot stage | `last_stage` in every report |
| Panic/fault data | `report_kind: panic` or `fault` with message or ESR/ELR/FAR/SPSR |
| Firmware-variable report contents | Printed in full; `nvram_write_index` shows which bounded write it was |
| Complete test output | The ledger payload of both `hold` events |
| Linux/recovery intact | BootNext consumed, BootOrder unchanged, same boot entry and kernel, root writable |

## If something goes wrong

- **Screen stays black or frozen:** hold the power button until the machine
  turns off, then power on. BootNext was used up, so Linux boots. The pre-exit
  file and any saved variable report remain readable; collect as in step 3.
- **Firmware says the image is not allowed:** Secure Boot is still on.
- **Linux does not come back:** choose `ubuntu` in the firmware boot menu, or
  boot the recovery USB stick. The AIENOS entry is not in BootOrder, so it
  never runs unless BootNext is set again.
