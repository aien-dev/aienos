# iMac kernel batch run, 2026-10-17

IMACKERN.EFI built from 84464940ff96b9b98660d03d09d7d07b24773ead (PR #407,
sha256 `cdbaab3ccdd615236f5a0d512a83fe26755936794e2b61aab9f95a310e8406c8`),
booted from the SanDisk stick on the owner's 2017 iMac through the Option-key
boot picker. The kernel writes no file; the owner sent a photo of the screen and
the lines below are transcribed from it. The photo itself is not stored here.

Result: every item in the batch ran on real hardware, nothing was written.

```
cpu: GenuineIntel Intel(R) Core(TM) i5-7500 CPU @ 3.40GHz
timebase: hpet period_fs=41666667 tsc_hz=3408335805
madt: cpus=4 ioapics=1 ioapic_lines_masked=24
timer_stats: vector=0x40 period_us=10000 min_us=10000 avg_us=10000 max_us=10000 stray_irqs=0
smp: cpus=4 started=3 failed=0 bsp_id=0 ap_ids=2,4,6 trampoline=0x1000 state=halted
pci: ahci 00:17.0 id=8086:a102 bar5=0x9272b800
ahci: ctrl=0 abar=0x9272b800 version=1.31 ports=1 implemented=0x1 s64a=1 polled=yes
ahci_disk: ctrl=0 disk=0 port=0 link=gen3 model="APPLE HDD ST1000DM003" blocks=1953525168 block=512 mib=953869 access=read-only
ahci_read: ctrl=0 disk=0 lba=0 bytes=512 boot_sig=55aa first=00000000
ahci_gpt: ctrl=0 disk=0 gpt=valid used=1 last_lba=1953525167, no AIENOS partition, nothing written
pci: nvme 02:00.0 id=144d:a806 bar0=0x92500000
nvme_disk: ctrl=0 disk=0 version=1.2 nsid=1 blocks=6835938 block=4096 mib=26702 access=read-only
nvme_read: ctrl=0 disk=0 lba=0 bytes=4096 boot_sig=0000 first=00000000
nvme_gpt: ctrl=0 disk=0 refused: no protective MBR
net: 04:00.0 id=14e4:1686 bar0=0xd0200000 mem_decode=1 bus_master=1 power=D0
net: phy_id=0362:5e41 bmsr=0x7949 link=down autoneg_done=0
storage: pci_functions=26 ahci_controllers=1 disks=1 nvme_controllers=1 nvme_disks=1 gpt_valid=1 writes=none
kernel: alive
summary: cores=4/4 timer=ok sata_disks=1 nvme_disks=1 gpt_valid=1 writes=none net=link-down
AIENOS-IMAC-KERNEL-0 DONE
```

Findings:
- The CPU is a 4-core i5-7500 (not an i7). The other three cores have APIC IDs
  2, 4, 6 and all checked in.
- The 1 TB hard disk (half of the Fusion drive) has a valid GPT with one
  partition and no AIENOS partition.
- The 28 GB flash part (Samsung NVMe, 4096-byte blocks) has an empty first
  block: no partition table on it.
- The Ethernet chip is a Broadcom BCM57766 (14e4:1686), awake (D0), PHY ID
  0362:5e41. The link read down with auto-negotiation not complete: either no
  cable was plugged in or the PHY waits for a driver to start negotiation.
  These are the facts a network driver will be written against.
- The screen banner still reads AIENOS-IMAC-KERNEL-0; only the comment in
  smp_x86.S calls this build KERNEL-1.
