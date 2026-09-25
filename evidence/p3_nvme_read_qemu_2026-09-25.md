# P3 native NVMe read substrate: QEMU qualification (2026-09-25)

Result: **`QEMU_NVME: PASS`** in both SMMU-confined and fail-closed modes.

This is an emulator qualification only. It is not Machine 1 evidence. The
substrate issues Identify and Read commands only; write and flush are not
claimed, implemented, or exercised.

Baseline: `aien-dev/aienos` @ `ff5de9c` plus this branch. Command:
`bash scripts/qemu_nvme_test.sh` (SMMU mode) and
`AIENOS_QEMU_SMMU=0 bash scripts/qemu_nvme_test.sh` (fail-closed mode).

## Disposable media

- 64 MiB raw image, 131072 LBAs of 512 bytes, rebuilt per run.
- Sentinel at LBA 2048, one 512-byte block: the 16-byte magic
  `AIENOS-NVME-SENT` repeated 32 times.
- Sentinel SHA-256:
  `8b688adcb13bef657e868313fb149e7e92e664b5f09fbd32f99d9cabf756fdf1`.
- Attached as `-drive if=none,id=nvme0,... -device nvme,drive=nvme0,serial=aienos-nvme-test`.

## SMMU-confined run (`-M virt,...,iommu=smmuv3`)

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
dma_gate: nvme bus master revoked
QEMU_NVME: PASS (smmu)
```

The read SHA-256 the kernel computes natively equals the host-computed
sentinel SHA-256, so a wrong or stale image cannot pass.

## Fail-closed run (no SMMU, normal build)

```text
NVME_DISCOVERY_QEMU: PASS (class=0x0108 seg=0000 bus=00 device=02 function=00 bar0=0x8000004000)
dma_sweep: seg 0000 bus 00-ff functions=3 bridges=0 bridges_bme=0 endpoints_bme_found=2 still_enabled=0
dma_gate: nvme denied (NoSmmu), bus master stays off
nvme: unavailable (SMMU DMA isolation not active)
QEMU_NVME: PASS (fail-closed)
```

`NVME_IDENTIFY_QEMU` and `NVME_READ_QEMU` are absent. Discovery runs before the
DMA gate and is DMA-free; the controller is never enabled and no read happens.
This proves the M3 rule holds for the NVMe path: no SMMU confinement means no
DMA.

## What this proves and does not prove

- Proves, in QEMU: ECAM discovery of an NVMe class device, controller reset and
  ready handshake, Identify Controller and Namespace, polled I/O queues, a
  one-LBA read over PRPs, client-side bounds rejection, and device error
  surfacing, all with DMA confined to the driver's arena by the SMMU.
- Does not prove: any GB10 or Machine 1 behavior, GPU/accelerator behavior,
  write, flush, namespace management, format, interrupt-driven I/O, or Store
  interaction. It makes no Store v1 dependency and touches no Store file.
- The unsafe bypass feature exists for debugging only; no bypass run was needed
  for this qualification.
