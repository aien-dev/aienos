# P3 NVMe power-fail atomicity evidence (2026-09-25)

Basis for the later recovery-architecture investigation. These results are
preserved as-is; they must NOT be "fixed" in the Store-over-NVMe integration
lane.

## Native DGX Spark NVMe (read-only Identify; no writes/format/reconfig)

Device: SAMSUNG MZALC4T0HBL1-00B07, FW NXHB202Q, PCI 0004:01:00.0 (a810), 4.10 TB.
Commands: `sudo nvme id-ctrl /dev/nvme0`, `sudo nvme id-ns /dev/nvme0n1` (plus raw `-b`).

```text
awun=1023  awupf=0  ; mdts byte 77 = 7 ; nn = 1
namespace: nsze=8,001,573,552  flbas=0  nlbaf=0  lbads=9 (512 B)
           nawupf=0  nabsn=0  nabo=0  nabspf=0
decoded:   effective power-fail atomic unit = 1 x 512 B ; no atomic boundary
Store root: 4096 B = 8 blocks @ 512 B ; 8 > 1
NATIVE_GB10_STORE_ROOT_ATOMICITY: FAIL (ExceedsAtomicUnit { required: 8, guaranteed: 1 })
```
Only one LBA format (512-byte) is advertised (`nlbaf=0`), so no 4K-LBA path.

## QEMU, 512-byte LBA (default harness geometry)

```text
NVME_ATOMICITY_IDENTIFY_QEMU: block_size=512 lbads=9 awupf_raw=0 nawupf_raw=0 nabspf_raw=0 nabo_blocks=0 effective_pf_blocks=1 boundary_blocks=-1
NVME_STORE_ROOT_ATOMICITY_QEMU: FAIL (slot0=not_atomic(ExceedsAtomicUnit { required_blocks: 8, guaranteed_blocks: 1 }) slot1=...)
```
`QEMU_NVME_RW: PASS (smmu)` and `PASS (fail-closed)` are unaffected.

## QEMU, 4096-byte LBA (compliant geometry)

Device: `-device nvme,...,logical_block_size=4096,physical_block_size=4096`.

```text
NVME_GEOMETRY_QEMU: PASS (nsid=1 block_count=16384 block_size=4096)
NVME_ATOMICITY_IDENTIFY_QEMU: block_size=4096 lbads=12 awupf_raw=0 nawupf_raw=0 nabspf_raw=0 nabo_blocks=0 effective_pf_blocks=1 boundary_blocks=-1
NVME_STORE_ROOT_ATOMICITY_QEMU: PASS (slot0=atomic(effective=1) slot1=atomic(effective=1))
QEMU_NVME_ATOMICITY_4K: PASS
```

## Reproduce

```bash
bash scripts/qemu_nvme_rw_test.sh                    # 512-byte: RW PASS, atomicity FAIL
bash scripts/qemu_nvme_atomicity_test.sh             # 4096-byte: atomicity PASS
```

## Consequence

AIEN's System Store v1 commit design is correct under its stated storage
contract (a 4096-byte root write that cannot tear). The native Spark SSD
(512-byte LBA, AWUPF=0 -> 1 block) and the default QEMU namespace do not meet
that contract. A compliant 4096-byte-LBA namespace does. Native adaptation
requires either a compliant device or a recovery-design change for a torn
inactive superblock; ADR 0015 is not revised by this evidence.
