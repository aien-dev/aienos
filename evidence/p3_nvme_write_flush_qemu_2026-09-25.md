# P3 native NVMe write + flush durability qualification (2026-09-25)

Result: **`QEMU_NVME_RW: PASS`** in SMMU-confined and fail-closed modes.

Emulator qualification only. It is not Machine 1 evidence and does not touch
Store. QEMU disposable media only; the drive is a fresh raw file rebuilt each
run.

Base: `aien-dev/aienos` @ `ef359ec` plus this branch. Commands:
`bash scripts/qemu_nvme_rw_test.sh` (SMMU) and
`AIENOS_QEMU_SMMU=0 bash scripts/qemu_nvme_rw_test.sh` (fail-closed).

## Media and payloads

- 64 MiB raw image, 131072 LBAs of 512 bytes.
- Read sentinel at LBA 2048: `AIENOS-NVME-SENT` x32,
  sha256 `8b688adcb13bef657e868313fb149e7e92e664b5f09fbd32f99d9cabf756fdf1`.
- Write target at LBA 4096, seeded OLD (`AIENOS-NVME-OLD0` x32), written NEW
  (`AIENOS-NVME-RW01` x32),
  sha256 `76fa34c132173497a7bcd0c9618ebdcf0629f550934c164adf81cfa05e6a4451`.
- Bounds write at LBA 131072 (== block_count); error write at NSID `0xffffffff`.

## Boot 1 (SMMU confined): write, flush, read-back

```text
NVME_DISCOVERY_QEMU: PASS (class=0x0108 seg=0000 bus=00 device=02 function=00 bar0=0x8000004000)
smmu: enabled base=0x9050000 stream_id=0x10
smmu_dma_window: nvme only, translation active
dma_gate: nvme granted (Confined), bus master on
NVME_IDENTIFY_QEMU: PASS (vid=0x1b36 did=0x0010 nsid=1)
NVME_GEOMETRY_QEMU: PASS (nsid=1 block_count=131072 block_size=512)
NVME_READ_QEMU: PASS (lba=2048 blocks=1 bytes=512 sha256=8b688adcb13bef657e868313fb149e7e92e664b5f09fbd32f99d9cabf756fdf1)
NVME_BOUNDS_QEMU: PASS (lba=131072 rejected OutOfRange no_command)
NVME_ERROR_QEMU: PASS (identify nsid=0xffffffff rejected status=nonzero sct=0 sc=11)
NVME_WRITE_BOUNDS_QEMU: PASS (lba=131072 rejected OutOfRange no_command)
NVME_WRITE_QEMU: PASS (lba=4096 blocks=1 bytes=512 sha256=76fa34c132173497a7bcd0c9618ebdcf0629f550934c164adf81cfa05e6a4451)
NVME_FLUSH_QEMU: PASS (nsid=1)
NVME_DURABILITY_QEMU: PASS (lba=4096 blocks=1 bytes=512 sha256=76fa34c132173497a7bcd0c9618ebdcf0629f550934c164adf81cfa05e6a4451)
NVME_WRITE_ERROR_QEMU: PASS (write nsid=0xffffffff rejected status=nonzero)
dma_gate: nvme bus master revoked
QEMU_NVME_RW: PASS (smmu)
```

Host check after the guest stopped: reading LBA 4096 from the image file
returns the written bytes, sha256
`76fa34c132173497a7bcd0c9618ebdcf0629f550934c164adf81cfa05e6a4451` (power-off
persistence).

## Boot 2 (same image, restart): persisted read

```text
NVME_READ_QEMU: PASS (lba=2048 ... sha256=8b688adc...)
NVME_DURABILITY_QEMU: PASS (persisted lba=4096 blocks=1 bytes=512 sha256=76fa34c1...)
dma_gate: nvme bus master revoked
```

`persisted` means the phase read the target before writing and found the bytes
an earlier boot wrote, so the data survived the restart and the host-visible
media. The harness requires this marker on boot 2.

## Fail-closed (no SMMU, normal build)

```text
NVME_DISCOVERY_QEMU: PASS (...)
dma_gate: nvme denied (NoSmmu), bus master stays off
nvme: unavailable (SMMU DMA isolation not active)
QEMU_NVME_RW: PASS (fail-closed)
```

`NVME_WRITE_QEMU`, `NVME_FLUSH_QEMU`, and `NVME_DURABILITY_QEMU` are absent.
No SMMU confinement means no DMA, so no write reaches the device.

## What this proves and does not prove

- Proves, in QEMU: native NVMe write command construction and completion,
  a real NVMe Flush (opcode 0, no-op prohibited), flush-gated durability,
  client-side write bounds, an invalid-namespace write error surfaced as a
  device error, host-visible persistence after power off, and native read-back
  after restart, all with DMA confined by the SMMU to the driver arena.
- Does not prove: any Machine 1 or GB10 behavior, Store behavior, multi-queue
  I/O, FUA, or power-loss atomicity beyond a completed Flush. It makes no
  Store v1 dependency and touches no Store file. No media is written outside
  the disposable QEMU image.
