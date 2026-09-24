# Bootable recovery media for Machine 1

This procedure builds and proves the bootable recovery USB that closes
[issue #17](https://github.com/aien-dev/aienos/issues/17) and satisfies
TRUST-1 Gate 1. The physical boot is operator-run (physical access, Secure
Boot custody); everything up to the boot and everything after it is scripted
here so one attended exercise produces a recorded verdict.

**Done when (issue #17):** a USB drive boots the Spark into a rescue
environment that can mount the NVMe root, repair `/boot/efi`, and restore
boot entries, and that boot is recorded as evidence.

## What ships

- `scripts/build_recovery_media.sh /dev/sdX1` writes a Secure Boot-compatible
  recovery USB (signed shim + GRUB fallback, signed production kernel, and a
  standalone RAM initrd). It refuses to overwrite ATLAS_RECOV, the internal
  NVMe, or anything currently mounted.
- `scripts/build_standalone_recovery_initrd.sh` builds a 100% RAM rescue
  environment with busybox, cryptsetup, efibootmgr/efivar, mkfs.vfat, tar,
  chroot, lvm (when present), and `aienos-efi-repair`. Internal storage stays
  unmounted until the operator asks.
- GRUB on the media offers two entries: an interactive rescue menu and an
  automated `aienos.repair=1` mode that runs `aienos-efi-repair` and reboots.
- `scripts/verify_recovery_tools.sh` checks on any host that the initrd ships
  every tool and init hook the "done when" clause needs.
- `scripts/qemu_verify_recovery_media.sh` proves the environment boots with
  zero disks attached (existing Gate 1 invariant).
- `scripts/collect_recovery_boot_evidence.sh` runs on Machine 1 during the
  recovery boot and prints `RECOVERY_BOOT_GATE: PASS` only when the media
  booted, the NVMe root mounted, `/boot/efi` accepted a write round-trip, and
  boot entries are restorable.

## Step 0: build host preparation (on Machine 1, Linux up)

Use a dedicated USB stick. Do not use ATLAS_RECOV: it holds the offline key
backup and the builder refuses it. The stick needs one FAT32 partition.

```bash
cd ~/workspace/hive-worktrees/aienos-main && git pull --ff-only
lsblk -f                                   # identify the target stick
bash scripts/verify_recovery_tools.sh       # initrd ships the required tools
```

## Step 1: write the media (operator)

```bash
sudo -v
aien-proof hold --resource machine-1 --job build-recovery-media -- \
    sudo bash scripts/build_recovery_media.sh /dev/sdX1
```

The builder mounts the target, copies the signed shim and GRUB, the newest
signed production kernel, the freshly built standalone initrd, and a GRUB
config, then unmounts.

## Step 2: verify before booting (no reboot needed)

```bash
bash scripts/qemu_verify_recovery_media.sh   # zero-disk RAM boot proof (aarch64 host)
```

## Step 3: boot the recovery USB once (operator, at the machine)

Monitor and keyboard attached. Boot the stick once without changing the
default boot order, either from the firmware boot menu or with a one-time
BootNext:

```bash
sudo efibootmgr --bootnext "$(efibootmgr | sed -n 's/^Boot\([0-9A-Fa-f]\{4\}\).*\(USB\|UEFI OS\).*/\1/p' | head -1)"
sudo reboot
```

Expect the AIENOS GRUB menu, then the rescue banner: `AIENOS Standalone
Hardware Recovery Core`, `Root filesystem: 100% RAM disk`. Internal NVMe is
still unmounted.

## Step 4: exercise the three "done when" capabilities

From the rescue menu:

1. **Mount the NVMe root:** option `2`. The init activates LVM if present and
   mounts the root read-only at `/mnt/root` (it prefers the recorded host
   root UUID `d27bfd26-ff30-400e-9eca-9cdf73de9406`).
2. **Repair `/boot/efi`:** option `3` runs `aienos-efi-repair`, which mounts
   the ESP, confirms the shim+GRUB fallback chain, and reports usage.
3. **Restore boot entries:** option `3` also re-registers the `ubuntu` shim
   entry with `efibootmgr` when it is missing; option `4` shows the result.

For an unattended pass, boot the GRUB entry `AIENOS Standalone Recovery
System (Automated EFI Repair)`: it runs `aienos-efi-repair` and reboots back
to Linux on its own.

## Step 5: record the evidence (operator, still in the recovery boot)

With the NVMe root mounted at `/mnt/root`:

```bash
aien-proof hold --resource machine-1 --job recovery-boot-evidence -- \
    bash scripts/collect_recovery_boot_evidence.sh /mnt/root
```

The collector performs read-only checks plus a harmless marker-file
round-trip on the ESP (created, verified, removed). It never formats, never
deletes, and never changes BootOrder. `RECOVERY_BOOT_GATE: PASS` requires all
of: booted from removable media, Secure Boot state recorded, NVMe root
mounted from internal storage, ESP write round-trip, EFI variables present,
`efibootmgr` lists entries.

## Step 6: return to Linux and file the record

Choose `power off` or `reboot` from the menu; the machine returns to the
normal BootOrder (Linux). Then copy the collector output into
`evidence/recovery_boot_machine1.md`, set the gate row to PASS, and close
issue #17.

## Mapping to the gates

| Issue #17 "done when" | Where it is proven |
| --- | --- |
| USB boots the Spark into a rescue environment | Step 3 banner; collector `booted_from_removable_media` |
| Mount the NVMe root | Step 4.1; collector `nvme_root_mounted` + `nvme_root_is_internal` |
| Repair `/boot/efi` | Step 4.2; collector `esp_mounted` + `esp_write_roundtrip` |
| Restore boot entries | Step 4.3; collector `efibootmgr_readable` |
| Boot recorded as evidence | Step 5 ledger event + Step 6 `evidence/recovery_boot_machine1.md` |

TRUST-1 Gate 1 acceptance tests that this procedure exercises: firmware
accepts the image (3), environment starts without internal Linux (banner),
no network/model/Cortex required (RAM initrd), identifies NVMe and encrypted
volumes (menu 1), inspects Secure Boot state and PCRs (collector,
`tpm2_pcrread`), mounts recovered storage safely (4.1), reinstalls/restores
documented boot config (4.2-4.3), returns the machine to known-good Linux
(6), and no destructive overwrite without explicit operator choice
(everything above is non-destructive).
