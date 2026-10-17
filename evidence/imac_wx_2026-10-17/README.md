# iMac physical run: W^X (#409) + report opt-in (#410), 2026-10-17

The 2017 iMac (iMac18,3, Core i5-7500) started the combined image of PR #413 (W^X) and
PR #412 (network report opt-in, default off) from the SanDisk USB stick on the owner's
Option-key boot picker. The iMac has no serial port and the default image sends nothing,
so the only record is the screen. The owner sent a photo; the lines below are
transcribed from it. The photo itself is not stored here.

| Field | Value |
|---|---|
| Image | `EFI/BOOT/BOOTX64.EFI` sha256 `ea12b2ab0a9b05a49e5a090ad10502b2cb4272747d2ce5e390cf6107a5add35f` |
| Source | local merge of #413 (9c8ce2b) and #412 (4031c13) + crumb recompile, commit e0c033a55039663f5e524fd7915635c5e7952817 (shown on screen as aienos_commit) |
| Same image in QEMU | `AIENOS_IMAC_KERNEL: PASS` (both CPU models, mutations 1 and 2 caught) |
| Photo sha256 | `4e9ac2fc2bf3a96067599ad644d45557dc72afb6283897600ca434687bdb437a` (kept by the operator, not in this repo) |
| Network | cable connected, link up 1000 Mb/s full duplex |

## Lines (as shown)
```
aienos_commit: e0c033a55039663f5e524fd7915635c5e7952817
cpu: GenuineIntel Intel(R) Core(TM) i5-7500 CPU @ 3.40GHz
paging: root=0x2000 firmware_cr3=0x84000000 switched=yes top_gib=18 pages_2m_wb=8142 pages_2m_wc=17 pages_2m_uc=1055 pt_frames=22 fb=wc pat1=wc
guard_page: ok fault=contained (#PF cr2=0x7e5ae000 error=0x0, not present)
wx: ok nx=on wp=on text=rx ro=r data=rw-nx text_write=fault ro_write=fault heap_exec=fault stack_exec=fault
timebase: hpet period_fs=41666667 tsc_hz=3408333528
wx_audit: ok wx_leaves=0 exec_pages=15 text_pages=15 pages_4k=1024 trampoline=retired
smp: cpus=4 started=3 failed=0 bsp_id=0 ap_ids=2,4,6 trampoline=0x1000 state=halted
net_tg3: link up 1000 Mb/s full duplex
storage: pci_functions=26 ahci_controllers=1 disks=1 nvme_controllers=1 nvme_disks=1 gpt_valid=1 writes=none
kernel: alive
summary: cores=4/4 timer=ok sata_disks=1 nvme_disks=1 gpt_valid=1 writes=none net=link-up
AIENOS-IMAC-KERNEL-0 DONE
power: holding the screen 60 s, then ACPI S5
```

## What this shows
- #409 on real hardware: NX and CR0.WP on; writing code, writing read-only data, executing
  the heap and executing the stack each fault and are contained; the audit finds zero
  writable+executable leaves and exactly the code pages executable; all three secondary
  cores start through the NXE/WP trampoline, which is then retired.
- #410 on real hardware: with the link up, no `report:` line appears; the default image
  links no report code, so nothing was broadcast.

## Limits
- One run, one machine. The photo was taken during the hold; power-off is not in it.
- The mutation (negative) builds ran in QEMU only, not on the iMac.
- W^X is not process isolation. VT-d DMA confinement (#411) is not done.
- The NVMe GPT is refused (no protective MBR), as in earlier runs; unrelated to this change.
