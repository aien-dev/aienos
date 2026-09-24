# Bootable recovery media for Machine 1

This procedure builds and proves the bootable recovery USB that closes
[issue #17](https://github.com/aien-dev/aienos/issues/17) and advances
TRUST-1 Gate 1 items 12-14. The physical boot is operator-run (physical
access, Secure Boot custody); everything up to the boot and everything after
it is scripted here so one attended exercise produces a recorded verdict.

**Done when (issue #17):** a USB drive boots the Spark into a rescue
environment that can mount the NVMe root, repair `/boot/efi`, and restore
boot entries, and that boot is recorded as evidence.

**Where this stands (2026-09-24):** the stick (`AIENOSRECOV`) already boots
on Machine 1 with Secure Boot on, runs entirely from RAM, and returns to
Linux on its own ([#53](https://github.com/aien-dev/aienos/pull/53),
[Gate 1 selftest evidence](../evidence/gate1_machine1_selftest_2026-09-24.md)).
What was still missing from the initrd were the tools to actually repair
`/boot/efi` and check the mounted root: `fsck.vfat`, `mkfs.vfat`,
`fsck.ext4`, and `chroot`. This change adds them. **The stick must be
rebuilt with `scripts/build_recovery_media.sh` and the attended boot below
re-run before issue #17 can close** -- the currently-written stick predates
this change and does not have these tools yet.

## What ships

- `scripts/build_recovery_media.sh /dev/sdX1` writes a Secure Boot-compatible
  recovery USB (signed shim + GRUB fallback, signed production kernel, and a
  standalone RAM initrd). It refuses to overwrite the internal NVMe or
  anything currently mounted. Unchanged by this PR.
- `scripts/build_standalone_recovery_initrd.sh` builds the 100% RAM rescue
  environment: busybox, cryptsetup, blkid, lsblk, mount, efibootmgr, the
  xHCI/HID/USB-storage/NVMe/dm-crypt kernel modules Machine 1 needs, and (new
  in this change) `fsck.vfat`, `mkfs.vfat`, `fsck.ext4`, and `chroot` for
  repairing `/boot/efi` and the mounted root. Internal storage stays
  unmounted until the operator mounts it by hand from the shell.
- `scripts/verify_recovery_tools.sh` (new) checks on any host, without real
  devices or root, that the built initrd ships every tool the "done when"
  clause needs. It is wired into `scripts/verify_all.sh`.
- `scripts/qemu_verify_recovery_media.sh` proves the environment boots with
  zero disks attached (existing Gate 1 invariant, unchanged).
- `scripts/collect_recovery_boot_evidence.sh` (new) runs on Machine 1 during
  the attended recovery boot and prints `RECOVERY_BOOT_GATE: PASS` once the
  media booted from removable storage, the NVMe root is mounted, `/boot/efi`
  is accessible, and boot entries are readable. It is strictly read-only: it
  never writes to the ESP, the NVMe root, or BootOrder.

## Step 0: build host preparation (on Machine 1, Linux up)

Use the existing `AIENOSRECOV` stick, or another dedicated USB stick. Do not
target the internal NVMe or EFI system partition; the builder refuses both.

```bash
cd ~/workspace/hive-worktrees/aienos-main && git pull --ff-only
lsblk -f                                    # identify the target stick
bash scripts/verify_recovery_tools.sh       # initrd ships the required tools
```

## Step 1: rebuild the media with the new tools (operator)

```bash
sudo -v
aien-proof hold --resource machine-1 --job build-recovery-media -- \
    sudo bash scripts/build_recovery_media.sh /dev/sdX1
```

The builder mounts the target, copies the signed shim and GRUB, the newest
signed production kernel, the freshly built standalone initrd (now including
`fsck.vfat`, `mkfs.vfat`, `fsck.ext4`, `chroot`), and a GRUB config, then
unmounts.

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
Hardware Recovery Core`, `Root filesystem: 100% RAM disk`. The environment
loads its kernel modules, prints a report (Secure Boot state, TPM PCRs,
block devices, firmware boot entries) to the screen, then drops into an
interactive shell. Internal NVMe is still unmounted at this point.

## Step 4: exercise the three "done when" capabilities (operator, from the shell)

All the tools below are on `PATH` inside the recovery shell.

1. **Mount the NVMe root.** Identify the root partition (Machine 1's is
   `UUID=d27bfd26-ff30-400e-9eca-9cdf73de9406`, ext4), check it, then mount
   it read-only:
   ```sh
   blkid | grep d27bfd26-ff30-400e-9eca-9cdf73de9406
   fsck.ext4 -n /dev/nvme0n1pN         # replace N; -n: check only, no repair
   mkdir -p /mnt/root
   mount -o ro /dev/nvme0n1pN /mnt/root
   ```
2. **Repair `/boot/efi`.** Identify and check the EFI system partition
   (Machine 1's is `UUID=9DA2-3597`, vfat), then mount it:
   ```sh
   blkid | grep 9DA2-3597
   fsck.vfat -a /dev/nvme0n1pM         # replace M; -a: auto-repair
   mkdir -p /mnt/esp
   mount /dev/nvme0n1pM /mnt/esp
   ```
   `mkfs.vfat` is available if the ESP needs to be rebuilt from scratch
   (destructive; only with explicit operator authorization per the TRUST-1
   plan).
3. **Restore boot entries.** With `/mnt/root` mounted, `chroot /mnt/root`
   gives access to the installed `grub-install`/`update-grub` and to
   `efibootmgr` running against the real installation, so a missing boot
   entry can be re-created from the chroot. `efibootmgr` (no chroot needed)
   lists and edits boot entries directly against `/sys/firmware/efi/efivars`.

## Step 5: record the evidence (operator, still in the recovery boot)

With the NVMe root mounted at `/mnt/root`:

```bash
aien-proof hold --resource machine-1 --job recovery-boot-evidence -- \
    bash scripts/collect_recovery_boot_evidence.sh /mnt/root
```

The collector performs read-only checks only: it never writes to the ESP,
the NVMe root, or BootOrder. `RECOVERY_BOOT_GATE: PASS` requires all of:
booted from removable media, Secure Boot state recorded, NVMe root mounted
from internal storage, `/boot/efi` accessible with the fallback bootloader
present, EFI variables present, `efibootmgr` lists entries.

## Step 6: return to Linux and file the record

`exit` the chroot if used, unmount `/mnt/esp` and `/mnt/root`, then `reboot`
or `poweroff`; the machine returns to the normal BootOrder (Linux). Copy the
collector output into `evidence/recovery_boot_machine1.md`, set the gate row
to PASS, and close issue #17.

## Mapping to the gates

| Issue #17 "done when" | Where it is proven |
| --- | --- |
| USB boots the Spark into a rescue environment | Step 3 banner; collector `booted_from_removable_media` |
| Mount the NVMe root | Step 4.1; collector `nvme_root_mounted` + `nvme_root_is_internal` |
| Repair `/boot/efi` | Step 4.2; collector `esp_mounted` + `esp_fallback_bootloader_present` |
| Restore boot entries | Step 4.3; collector `efibootmgr_readable` |
| Boot recorded as evidence | Step 5 ledger event + Step 6 `evidence/recovery_boot_machine1.md` |

TRUST-1 Gate 1 acceptance tests this procedure exercises: firmware accepts
the image (already PASS, #53), environment starts without internal Linux
(already PASS), no network/model/Cortex required (already PASS), identifies
NVMe and encrypted volumes (already PASS/PARTIAL), inspects Secure Boot
state and PCRs (already PASS), mounts recovered storage safely (Step 4.1,
new), restores documented boot config (Step 4.2-4.3, new), returns the
machine to known-good Linux (Step 6, already PASS), and no destructive
overwrite without explicit operator choice (`mkfs.vfat`/`chroot` are present
but never invoked automatically).
