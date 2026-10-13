# native/disk: AIENOS disk layer in C

- `disk.h` / `disk.c`: the `disk_dev` contract (512 or 4096 byte blocks),
  bounds checks, splitting by `max_blocks_per_io`, and an ordered 32-entry
  queue with flush barriers and fail-stop.
- `disk_file.c`: hosted file backend (pread/pwrite) with a power-cut
  injector, used by the tests. It is not part of the freestanding library.
- `disk_nvme.h` / `disk_nvme.c`: freestanding polled NVMe driver ported from
  `crates/aienos-kernel/src/nvme*.rs` and `docs/P3_NVME_*.md`. It does not use
  libc or a heap. Platform access goes through `nvme_ops`, and DMA goes
  through one caller region carved into fixed pages plus a bounce buffer.
- `disk_sdhci.h` / `disk_sdhci.c`: freestanding polled SD Host Controller
  driver for the Raspberry Pi 5 microSD slot (BCM2712 `brcm,bcm2712-sdhci`,
  a standard SDHCI). PIO only: no DMA, no heap, no libc, aligned 32-bit
  register access only. SD 2.0+ cards (SDSC and SDHC/SDXC), 3.3 V, 25 MHz
  default speed, 1- or 4-bit bus.
- `qemu/`: bare-metal AArch64 payloads that run the NVMe driver against
  QEMU's emulated NVMe (`scripts/qemu_native_nvme_test.sh`) and the SD
  driver against QEMU's `sdhci-pci` + `sd-card`
  (`scripts/qemu_native_sdhci_test.sh`: spec 2.00 with a 64 MiB SDSC card,
  spec 3.00 with a 4 GiB SDHC card). `STORE_OBJS=` links
  extra objects (for example native/store) later.

```
make              # out/libaienos_disk.a (disk.c, disk_nvme.c, disk_sdhci.c) + out/disk_file.o
make test         # last line: AIENOS_DISK_NATIVE: PASS
make freestanding # nm -u of the linked library objects must be empty
make sanitize     # ASan + UBSan
make mutants      # each GUARD line deleted in turn; AIENOS_DISK_MUTANTS: PASS
```

Host tests run against software NVMe and SDHCI + SD card models written in
`tests/nvme_test.c` and `tests/sdhci_test.c`. QEMU runs against QEMU's
models. None of them qualifies any physical controller; the Pi 5 run is
separate evidence.

## Unsafe assumptions: what is now checked

Items [UA] come from `docs/P3_NVME_UNSAFE_ASSUMPTIONS.md`. "Mutant" is the
GUARD tag that `make mutants` deletes. All tests named are in `tests/nvme_test.c`
unless they say otherwise.

| Item | Check or limit (mutant) | Error | Covering test |
|---|---|---|---|
| [UA P0] CAP.MPSMIN/MPSMAX ignored | MPSMIN (bits 51:48) must be 0; 4 KiB pages only (nvme-mpsmin). MPSMAX >= 0 always holds once MPSMIN is 0 | NVME_EMPS | test_cap_checks (MPSMIN 1, 15) |
| [UA P0] CAP.MQES not enforced | admin depth 8 <= MQES+1 (nvme-mqes-admin); I/O depth <= MQES+1 (nvme-mqes-io) | NVME_EMQES | test_cap_checks (MQES 3 with I/O depth 2, MQES 7 with depth 16) |
| [UA P1] CAP.CSS not validated | bit 37 (NVM) required (nvme-css) | NVME_ECSS | test_cap_checks |
| [UA P1] hard-coded NSID 1 | NSID comes from Identify CNS 02h, or the caller NSID must be 1..NN (nvme-nsid); NSZE != 0 (nvme-nsze) | NVME_ENSID / ENSZE | test_namespace (empty list, CNS 02h unsupported, active NSID 3, NSID > NN, inactive NSID) |
| [UA P1] LBADS lower bound | only 9 or 12 accepted (nvme-lbads); metadata must be 0 (nvme-meta); FLBAS <= NLBAF and bits 6:5 clear (nvme-flbas) | NVME_ELBADS / EMETA / EFLBAS | test_lbads (all 0..31), test_namespace |
| [UA P2] CAP.AMS | documented limit: round robin is mandatory, so CC.AMS = 0 always | none | test_init_ok asserts CC.AMS = 0 |
| [UA P2] readiness off-by-one vs CAP.TO | wait gives up after exactly TO x 500 ms (nvme-ready-bound); CSTS.CFS stops the wait (nvme-cfs-ready) | NVME_ETIMEOUT / ECFS | test_readiness_timeouts (exact 500000 us, TO=0, TO=4, ready after 200 ms, CFS) |
| [UA P2] completion SQID unverified | SQID must match the queue (nvme-sqid), CID must match (nvme-cid), then fail-stop | NVME_ESQID / ECID | test_completion_faults |
| [UA P3] VS never read | major version must be 1 or 2 (nvme-vs) | NVME_EVS | test_cap_checks (0.1, 3.0, 1.0, 2.0) |
| command poll unbounded | max(1000 ms, TO x 500 ms) budget (nvme-cmd-bound); CFS during a command (nvme-cfs-cmd); fail-stop until re-init (nvme-failstop) | NVME_ETIMEOUT / ECFS / ESTATE | test_completion_faults, test_flush_and_reopen |
| queue entry sizes | Identify SQES/CQES must allow 64 B / 16 B (nvme-sqes, nvme-cqes) | NVME_EQES | test_cap_checks |
| transfer size / MDTS | min(128 KiB, 4 KiB << MDTS, bounce) (nvme-xfer); LBA range (nvme-range); a refused request rings no doorbell | NVME_ERANGE | test_mdts_and_range |
| PRP construction | length/offset overflow (prp-len-wrap), address wrap (prp-addr-wrap), list capacity (prp-list-cap); lists chain through the last entry | NVME_EARG / ERANGE | test_prps |
| power-fail atomicity | NAWUPF/AWUPF unit (atomic-unit), NABSPF/NABO boundary (atomic-boundary) | n/a | test_atomicity |
| disk_dev bounds | zero count (disk-zero), LBA (disk-lba), end overflow (disk-end), queue depth (queue-bound), queue fail-stop (queue-failstop) | DISK_E* | tests/disk_test.c |

Other limits: one command in flight at a time; every request goes through
the bounce buffer; doorbells use the CAP.DSTRD stride (tested with DSTRD=2);
a command that completes with a non-zero status returns DISK_EIO and the
queue stays usable.

## Errors found in the reference material

- `docs/P3_NVME_CONTROLLER_AUDIT.md` gives some CAP bit positions wrong. CSS
  is bits 44:37, not `(cap>>45)&0xff`. MPSMIN is the 4-bit field 51:48, not
  `&0xff`. CAP.AMS bit 0 is not "round robin": AMS (bits 18:17) only
  advertises WRR and vendor-specific arbitration.
- The Rust `atomicity.rs` boundary uses `(nabspf + 1) as u16`, which wraps to
  0 when NABSPF is 0xffff. The C port computes in 64 bits, and
  test_atomicity covers that case.
- The Rust readiness loop sleeps one more step than CAP.TO allows. The C port
  stops at exactly TO x 500 ms.

## SD host driver: what is checked

Each check below is a GUARD line that `make mutants` deletes; a test in
`tests/sdhci_test.c` fails for every one. The software model also flags any
command issued while CMD/DATA inhibit is set, any data command while the card
is still programming, a wrong response type, a wrong address mode (byte for
SDSC, block for SDHC), and any unaligned or out-of-window register access.

| Check (mutant) | Error |
|---|---|
| any error bit in INT_STATUS ends the wait (sdhci-err-int) | SDHCI_ECMD / SDHCI_EDATA |
| command line (and data line for data/busy commands) idle before issue (sdhci-inhibit) | SDHCI_ETIMEOUT |
| R1 card-status error bits 0xfdf98008 (sdhci-r1) | SDHCI_ESTATUS |
| HOST_VERSION spec 2.00 or later (sdhci-ver) | SDHCI_EVER |
| software reset clears within 100 ms (sdhci-reset) | SDHCI_ERESET |
| controller supports 3.3 V (sdhci-volt) | SDHCI_EVOLT |
| a base clock, from CAPABILITIES or the caller (sdhci-clock0) | SDHCI_ECLOCK |
| card present (sdhci-nocard) | SDHCI_ENOCARD |
| CMD8 echo 0x1aa: SD 2.0+ cards only (sdhci-cmd8) | SDHCI_ECARD |
| ACMD41 power-up bounded to 100 polls (sdhci-acmd41-bound) | SDHCI_ETIMEOUT |
| CSD capacity non-zero (sdhci-csd-zero) | SDHCI_ECSD |
| no I/O after a failure until init runs again (sdhci-ready, sdhci-failstop) | DISK_ESTATE |
| lba/count inside the card, refused before any command (sdhci-range) | DISK_ERANGE |
| after a write, CMD13 until the card is back in transfer state (sdhci-tran) | SDHCI_ETIMEOUT |

Not done yet: high-speed (50 MHz) and UHS modes, 1.8 V signalling, ADMA, card
removal while running, and the Pi 5 binding (base address and base clock come
from the ACPI tables dumped by AIENOS-PI5-ACPI-0).
