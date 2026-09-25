# Recovery media attended boot on Machine 1

**Result: `RECOVERY_BOOT_GATE: PASS` on physical Machine 1.** The USB rescue
environment booted, exposed the expected internal root and EFI System
Partition read-only, showed the fallback bootloader and recovery tools, and
the machine returned to Ubuntu. No filesystem repair or firmware mutation
was performed.

Procedure: [RECOVERY_MEDIA_MACHINE1.md](../docs/RECOVERY_MEDIA_MACHINE1.md).
Related issue: [#17](https://github.com/aien-dev/aienos/issues/17).

## Attended recovery boot

| Item | Observed value |
| --- | --- |
| Receipt timestamp | `Fri Sep 25 00:26:25 UTC 2026` |
| Machine | Machine 1 (DGX Spark) |
| Recovery entry | `Boot0004* UEFI: USB USB Hard Drive, Partition 1` |
| `BootCurrent` | `0004` (USB recovery entry) |
| `BootOrder` | `0001,0003,0004` |
| Kernel | `Linux (none) 7.0.0-1019-nvidia`, `aarch64` |
| Command line | `BOOT_IMAGE=/aienos-recovery/vmlinuz rdinit=/init console=ttyAMA0,115200n8 console=tty0 quiet` |
| Secure Boot before boot | `mokutil --sb-state`: `SecureBoot enabled` |
| Secure Boot byte in attended receipt | Not recorded |
| Secure Boot after return | Not captured in the supplied receipt/output |
| Recovery verdict | `RECOVERY_BOOT_GATE: PASS` |

The boot variables show the recovery USB was the current boot while the
recorded BootOrder stayed `0001,0003,0004`. The preboot baseline had Ubuntu
as `BootCurrent: 0001` with that same BootOrder. The abbreviated receipt did
not include the EFI Secure Boot byte, so this record does not claim a byte
value for the attended boot. Secure Boot was explicitly observed enabled
immediately before the exercise; no post-return observation was supplied.

## Read-only storage inspection

Root partition:

```text
/dev/nvme0n1p2:
LABEL="root"
UUID="d27bfd26-ff30-400e-9eca-9cdf73de9406"
TYPE="ext4"
PARTUUID="49c2c0c1-9a21-4a53-a43a-95ab7d996027"

/dev/nvme0n1p2 on /mnt/root type ext4 (ro,relatime)
```

EFI System Partition:

```text
/dev/nvme0n1p1:
LABEL="EFI"
UUID="9DA2-3597"
TYPE="vfat"
PARTUUID="7c2b24e9-0ceb-4ad7-a401-9bf3c92c26ee"

/dev/nvme0n1p1 on /mnt/esp type vfat
(ro,relatime,fmask=0022,dmask=0022,codepage=437,
iocharset=iso8859-1,shortname=mixed,errors=remount-ro)
```

The fallback loader was present at `/mnt/esp/EFI/BOOT/BOOTAA64.EFI`
(987336 bytes). Both partitions were mounted read-only. Repair and restore
capabilities were checked for availability; neither filesystem contents nor
firmware variables were changed.

## Recovery tools and return to Linux

The attended receipt reported all required tools present:

```text
/bin/fsck.ext4
/bin/fsck.vfat
/bin/mkfs.vfat
/bin/chroot
/bin/efibootmgr
```

After the recovery shell exited, the machine returned to its normal Ubuntu
environment. The root partition was mounted at `/` and the ESP at
`/boot/efi`:

```text
/dev/nvme0n1p1  vfat  EFI   9DA2-3597  mounted at /boot/efi
/dev/nvme0n1p2  ext4  root  d27bfd26-ff30-400e-9eca-9cdf73de9406  mounted at /
```

The supplied return evidence confirms Linux returned, but contains no second
`mokutil --sb-state` result and no post-return `BootCurrent`/`BootOrder`
capture.

## Hardware-test ledger

```text
#86  build-recovery-media — FAILED
     cause: stale fixed /tmp initrd path / permission denied

#87  build-recovery-media — PASS
     resource: machine-1
     exit: 0
     duration: 20363 ms
```

No separate `aien-proof` event ID for the attended physical recovery boot
was captured in the supplied evidence. The PASS receipt is recorded here;
the ledger event list is not inferred.

## Scope and limitations

- Physical Machine 1 evidence covers the USB boot, read-only root/ESP
  inspection, fallback loader presence, tool availability, and return to
  Linux.
- The filesystem repair tools and boot-entry tools were available, but no
  repair or boot-entry restore operation was performed.
- `BootCurrent: 0004` and `BootOrder: 0001,0003,0004` are the recorded
  recovery-boot values. The prior Linux baseline had `BootCurrent: 0001` and
  the same BootOrder.
- Secure Boot was observed enabled immediately before the boot. The
  abbreviated attended receipt omitted the Secure Boot efivar byte, and no
  post-return Secure Boot observation was supplied.
