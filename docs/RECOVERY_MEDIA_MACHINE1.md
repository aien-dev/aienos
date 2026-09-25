# Bootable recovery media for Machine 1

This procedure builds and exercises the bootable recovery USB for
[issue #17](https://github.com/aien-dev/aienos/issues/17) and TRUST-1 Gate 1.
The physical run on 2026-09-25 booted the USB once, mounted the internal root
and ESP read-only, checked the fallback loader and recovery tools, and
returned to Ubuntu. It made no filesystem or firmware changes. The evidence
is in [recovery_boot_machine1.md](../evidence/recovery_boot_machine1.md).

**Issue #17 done state:** Machine 1 has booted the USB recovery environment;
the environment mounted the NVMe root and ESP read-only, confirmed repair and
boot-entry tools are present, and the boot was recorded. Actual filesystem
repair and boot-entry mutation are intentionally outside this read-only
exercise.

## What ships

- `scripts/build_recovery_media.sh /dev/sdX1` writes a Secure Boot-compatible
  recovery USB (signed shim + GRUB fallback, signed production kernel, and a
  standalone RAM initrd). It refuses the internal NVMe and mounted targets.
- `scripts/build_standalone_recovery_initrd.sh` builds the RAM rescue
  environment with BusyBox, filesystem check/repair tools, `chroot`,
  `efibootmgr`, `findmnt`, and the Machine 1 xHCI/HID/USB-storage/NVMe/dm-crypt
  modules. Internal storage remains unmounted until the operator mounts it.
- The build copies the attended collector into the image at
  `/usr/local/sbin/collect_recovery_boot_evidence`; it does not depend on a
  repository checkout being present in the rescue shell.
- `scripts/verify_recovery_tools.sh` extracts the built initrd and checks
  that the tools and collector are present. It is wired into
  `scripts/verify_all.sh`.
- `scripts/qemu_verify_recovery_media.sh` verifies a zero-disk RAM boot in
  QEMU.

The builder creates a unique initrd temporary path with `mktemp` and removes
it on exit, including failed builds.

## Build and verify

On Machine 1 in Linux, identify the dedicated USB target. Do not target the
internal NVMe or EFI System Partition; the builder rejects them.

```bash
cd ~/workspace/aienos-recovery-gate
git pull --ff-only
lsblk -f
bash scripts/verify_recovery_tools.sh
bash scripts/qemu_verify_recovery_media.sh
sudo -v
aien-proof hold --resource machine-1 --job build-recovery-media -- \
    sudo bash scripts/build_recovery_media.sh /dev/sdX1
```

The builder copies the signed shim and GRUB, the current signed production
kernel, the standalone initrd, and the GRUB menu, then unmounts the USB.

## Boot the USB once

Use the firmware boot menu or set a one-time BootNext. Do not change the
default boot order. The attended run observed the USB as `BootCurrent: 0004`
and `BootOrder: 0001,0003,0004`.

```bash
sudo efibootmgr --bootnext 0004
sudo reboot
```

Expect the AIENOS GRUB menu and the rescue banner `AIENOS Standalone Hardware
Recovery Core` / `Root filesystem: 100% RAM disk`. The shell reports Secure
Boot, PCRs, devices, and firmware entries. The NVMe is initially unmounted.

## Inspect internal storage read-only

The Machine 1 root is ext4 UUID
`d27bfd26-ff30-400e-9eca-9cdf73de9406` on `/dev/nvme0n1p2`. Check and mount it
read-only:

```sh
blkid /dev/nvme0n1p2
fsck.ext4 -n /dev/nvme0n1p2
mkdir -p /mnt/root
mount -o ro /dev/nvme0n1p2 /mnt/root
```

The ESP is vfat UUID `9DA2-3597` on `/dev/nvme0n1p1`. Check and mount it
read-only at `/mnt/esp`:

```sh
blkid /dev/nvme0n1p1
fsck.vfat -n /dev/nvme0n1p1
mkdir -p /mnt/esp
mount -o ro /dev/nvme0n1p1 /mnt/esp
ls -l /mnt/esp/EFI/BOOT/BOOTAA64.EFI
```

`fsck.vfat`, `mkfs.vfat`, `fsck.ext4`, and `chroot` are present for a
separately authorized repair workflow. Do not use repair or format options
during this evidence exercise. `efibootmgr` can list firmware entries; this
exercise only reads entries and does not change efivars or BootOrder.

## Capture the recovery evidence

Run the collector packaged on the USB, not a copy assumed to exist in the
repository checkout. Use the exact mount locations above:

```sh
aien-proof hold --resource machine-1 --job recovery-boot-evidence -- \
    env AIENOS_ESP_MNT=/mnt/esp \
    /usr/local/sbin/collect_recovery_boot_evidence /mnt/root
```

The collector is read-only. A PASS checks removable-media boot, Secure Boot
byte readability, internal root mount, ESP mount and fallback loader,
efivarfs presence, and readable boot entries. Preserve its complete output.

## Return to Linux and complete the record

Exit any chroot, unmount `/mnt/esp` and `/mnt/root`, then reboot or power off.
Confirm Linux returns and record its root/ESP mounts. Record the recovery
`BootCurrent` and `BootOrder`, the return-to-Linux proof, tool results,
Secure Boot observations before and after the boot, and the aien-proof events
in the evidence file. If an abbreviated collector or receipt omitted the
Secure Boot byte or post-return state, say so explicitly; do not infer it.

For the 2026-09-25 run, the recovery entry was `Boot0004* UEFI: USB USB Hard
Drive, Partition 1`; BootCurrent was `0004` and BootOrder remained
`0001,0003,0004`. The root and ESP were mounted read-only, the fallback
loader was present, the listed repair tools were present, and Ubuntu
returned. Secure Boot was observed enabled immediately before the run. The
abbreviated receipt omitted the EFI byte and the supplied return output did
not capture a second Secure Boot observation. See the evidence record for
full values and limits.

## Issue #17 mapping

| Requirement | Evidence |
| --- | --- |
| USB boots Machine 1 into rescue | Recovery `BootCurrent: 0004`, Linux kernel and command line in the evidence record |
| Mount the NVMe root | Root UUID and read-only `/mnt/root` mount |
| Repair `/boot/efi` capability | `fsck.vfat`, `mkfs.vfat`, and `chroot` are present; no repair was performed |
| Restore boot-entry capability | `efibootmgr` is present and boot entries are readable; no entry was changed |
| Record boot and recovery | Attended output and return-to-Linux observations in the evidence record |

The QEMU zero-disk boot and the earlier unattended self-test are separate
supporting evidence. They do not replace the attended mount and return
evidence recorded for this exercise.
