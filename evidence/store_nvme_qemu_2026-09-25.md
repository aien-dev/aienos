# Store-over-NVMe QEMU crash/reboot qualification (2026-09-25)

Lane: `feat/p3-store-nvme-qemu`, base canonical `main` `c851d01`.
Test-only. QEMU only. No ADR 0015, recovery, Store-format, NVMe-policy, or
Machine 1 changes.

## Integration path

`NvmeController` -> `BoundedNvme` (base LBA 64, 256 blocks) ->
`StoreDeviceAdapter` -> `Store`, exercised in-guest by
`run_store_phase` under feature `store-qual`.

- Geometry: 4096-byte LBA (atomic-root qualified namespace).
- Atomic-root predicate required PASS before any Store media write.
- Genesis: canonical v1, Superblock A only (slot B left zero), empty catalog at
  unit 2, CommitRecord at unit 3, high-water 4.
- Checkpoint hook emits `CHECKPOINT: <name>` and holds ~0.5 s (observation only;
  no flush, no write, no ordering change) so the host can kill at the marker.

## Result: STORE_V1_QEMU: PASS

Integration smoke: provision + one transaction + reopen all PASS.

Crash campaign (host kills QEMU with SIGKILL at the checkpoint marker, reboots,
reopens through the real NVMe path):

| settle | checkpoint | recovered | state | expected |
|---:|---|---:|---|---|
| 0 | before_first_write | 1 | Valid | {1,2} |
| 0 | after_payloads | 1 | Valid | {1,2} |
| 0 | after_catalog | 1 | Valid | {1,2} |
| 0 | after_commit_record | 1 | Valid | {1,2} |
| 0 | after_first_flush | 1 | Valid | {1,2} |
| 0 | after_superblock_write | 2 | Valid | {1,2} |
| 0 | after_final_flush | 2 | Valid | {1,2} |
| 3 | before_first_write | 4 | Valid | {4,5} |
| 3 | after_payloads | 4 | Valid | {4,5} |
| 3 | after_catalog | 4 | Valid | {4,5} |
| 3 | after_commit_record | 4 | Valid | {4,5} |
| 3 | after_first_flush | 4 | Valid | {4,5} |
| 3 | after_superblock_write | 5 | Valid | {4,5} |
| 3 | after_final_flush | 5 | Valid | {4,5} |

Recovery is N before the inactive-superblock write and N+1 after it; every
recovered root is a fully valid generation with its application object intact.
`settle=3` cycles both Superblock slots A -> B -> A -> B.

## Markers

```
STORE_NVME_INTEGRATION_QEMU: PASS
STORE_CHECKPOINT_CRASH_QEMU: PASS
STORE_REOPEN_QEMU: PASS
STORE_SLOT_REUSE_QEMU: PASS
STORE_V1_QEMU: PASS
P3_STORE_QEMU: NOT CLAIMED
```

`P3_STORE_QEMU` is not claimed: it requires the native-NVMe persistence
conditions, which the Spark SSD does not meet (512-byte LBA, 1-block guarantee).

## Reproduce

```bash
bash scripts/qemu_store_crash_test.sh
```
