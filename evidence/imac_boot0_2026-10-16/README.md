# iMac hardware run, 2026-10-16: AIENOS-IMAC-BOOT-0

The first run of AIENOS code on an x86_64 machine: `IMACDIAG.EFI` (PR #404,
`native/boot/diag_main.c` + `diag_x86.c`) started from a SanDisk USB stick on the
owner's 2017 iMac through the Option-key boot picker ("EFI Boot"). The owner
reported that it worked; the files below were read back from the stick afterwards.
Every file here is a byte-for-byte copy of the file of the same name in
`\EFI\AIENOS\` on that stick, except that `ACPI/VFCT.BIN` (61,572 bytes, AMD's
video BIOS image for the Radeon, vendor firmware) is listed in `IMACBOOT.TXT` but
not stored in this repository.

Check the copies: `cd evidence/imac_boot0_2026-10-16 && sha256sum -c SHA256SUMS`
(SHA256SUMS covers every file in this folder except itself and this README).

| Item | Value |
| --- | --- |
| Image | `EFI/BOOT/BOOTX64.EFI`, sha256 `5e97882111151d546f805847c551c24f69bfac1219fbfd26211d957b4de3bb99`, built from bfea771 |
| Report file time | 2026-10-17 04:38:28Z (FAT time written by the iMac firmware clock) |
| Serial numbers | none: SMBIOS serial fields are never read; no file here matches `serial` |

## What the report shows (quoted lines from IMACBOOT.TXT)

- Machine: `smbios_system: manufacturer=Apple Inc. product=iMac18,3 version=1.0` (27-inch Retina 5K, 2017), board `Mac-BE088AF8C5EB4FA2`, firmware `Apple` `529.140.2.0.0`, UEFI 2.40.
- CPU: `Intel(R) Core(TM) i5-7500 CPU @ 3.40GHz`, family 6 model 0x9e stepping 9 (Kaby Lake), 4 cores, 1 thread per core, AVX2 and FMA, no AVX-512, `invariant_tsc`, `rdrand`/`rdseed`, x2APIC.
- CPU mode at entry: `cpl=0 paging=1 long_mode=1`.
- Memory: `conventional_mib=16078` (about 16 GB free for use).
- Graphics: AMD `1002:67df` rev c5 at 01:00.0 (Polaris 10/20, a Radeon Pro 570/575/580; which one is not decided by this report) with its HDMI audio `1002:aaf0`, plus the Intel HD 630 `8086:5912` at 00:02.0. Screen: GOP `3840x2160`, framebuffer at `0xc0300000`.
- Storage: Fusion Drive halves as two devices: NVMe `144d:a806` (Samsung) = `block 1`, 4096-byte blocks, 26,702 MiB; SATA AHCI `8086:a102` = `block 0`, 512-byte blocks, 953,869 MiB (1 TB HDD). The stick is `block 3`.
- Network: Ethernet Broadcom `14e4:1686` (BCM57766), Wi-Fi Broadcom `14e4:43ba` (BCM4360), SD reader `14e4:16bc`.
- USB: xHCI `8086:a12f`; Thunderbolt 3 (Alpine Ridge `8086:1578`, `15d3`, `15d2`, xHCI `15d4`).
- ACPI: 24 tables, all checksums ok, including `DMAR` (Intel VT-d: an IOMMU exists to confine device DMA) and `MCFG` (ECAM).

Nothing here qualifies a kernel on this machine. It is the hardware inventory an
x86_64 port is planned from.
