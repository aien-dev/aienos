# iMac hardware run, 2026-10-16: AIENOS-IMAC-KERNEL-0

The first run of the AIENOS C kernel on an x86_64 machine: `IMACKERN.EFI`
(PR #405, `native/kernel/x86`) started from a SanDisk USB stick on the owner's
2017 iMac (iMac18,3, see `evidence/imac_boot0_2026-10-16`) through the
Option-key boot picker. The iMac has no serial port and the kernel writes no file,
so the only record is the screen. The owner sent a photo of it; the lines below
are transcribed from that photo. The photo itself is not stored here.

| Item | Value |
| --- | --- |
| Image | `EFI/BOOT/BOOTX64.EFI` = `IMACKERN.EFI`, sha256 `8618285bb00d3a1a657b4ebf5b747c6a178bd7fa9580344ce692bfaa77481d9d`, built from d8257aa |
| Source of the lines | owner's photo of the iMac screen (4K panel, font scale 4) |
| Serial numbers | none: the kernel never reads SMBIOS |

## What the screen showed (transcribed)

```
firmware_vendor: Apple
firmware_revision: 0x10000
gop: ok 3840x2160 pitch=3840 format=1 base=0xc0300000 size=0x1fa4000
acpi_rsdp: 0x8affe014
image: 0x84f56000-0x84f9f000
exit_boot_services: ok attempts=1
cpu: GenuineIntel Intel(R) Core(TM) i5-7500 CPU @ 3.40GHz
descriptors: ok
handoff: CHANDOF3 ok
screen: map=wc scale=4 grid=120x54
paging: root=0x1000 firmware_cr3=0x84000000 switched=yes top_gib=18 pages_2m_wb=8143 pages_2m_wc=17 pages_2m_uc=1055 pt_frames=21 fb=wc pat1=wc
memory: frame_ranges=14 free_bytes=16858255360 heap=0x100000+1048576 heap_test=ok
stack: 0x84f75000-0x84f85000 guard=0x84f74000
guard_page: ok fault=contained (#PF cr2=0x84f74000 error=0x0)
timebase: hpet period_fs=41666667 tsc_hz=3408331676
apic: mode=xapic id=0 version=0x1060015 timer_hz=1500200
madt: cpus=4 ioapics=1 ioapic_lines_masked=24
timer_irq: 20 ticks in 200 ms
timer_stats: min/avg/max 10000 us stray_irqs=0
kernel: alive
AIENOS-IMAC-KERNEL-0 DONE
power: holding the screen 60 s, then ACPI S5
```

Lines are condensed where the photo wrapped them; values are as shown.

## What this proves and what it does not

Proven on this machine: the kernel left the firmware on the first try, switched
to its own page tables (16 GB of RAM write-back, the screen write-combining),
caught a deliberate fault on its stack guard page, timed the CPU clock against
the HPET (3.408 GHz, matching the i5-7500), saw the four cores in the ACPI MADT,
masked every interrupt line it does not drive, and took 20 local APIC timer
interrupts at exactly 10 ms each with no stray interrupts.

Not shown: whether the ACPI S5 power-off after the 60 s hold switched the iMac
off (the photo was taken during the hold). Not attempted: other CPU cores, NVMe,
SATA, network, the AMD GPU.
