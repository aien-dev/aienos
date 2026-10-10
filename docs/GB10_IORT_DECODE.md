# GB10 IORT decode: stream id, SMMU node, reserved regions (aienos#286, cut B5)

Report only. Host only. Read-only. No kernel code was changed, no hardware
register was touched, no QEMU run was made. Base commit of aienos read:
`be514b5` (main). Firmware table read on the Spark on 2026-10-10
(`/sys/firmware/acpi/tables/IORT`, 3904 bytes, sha256
`5e0096a2be83ce2025c5c6395455c6814c16e01ff433791e8057c245f4939cb1`).

Tags: [SOURCE file:line] read in the named file or table. [INFERRED] reasoned
from sources, not directly shown. [UNKNOWN] nothing read answers it.
Paths without a repo prefix are in aienos. `actbl2.h` is
`/usr/src/linux-headers-6.11.0-1014-nvidia/include/acpi/actbl2.h` on the Spark
(ACPICA layout of the IORT, ARM DEN 0049). `linux iort.c` is
`drivers/acpi/arm64/iort.c` at torvalds/linux master, fetched 2026-10-10.

## 1. Short answer

- The GB10 (PCI segment 15, requester id 0x0100 = bus 1, device 0, function 0)
  resolves to the SMMUv3 at base `0x13000000` with **StreamID 0x100**, and
  from there to ITS group 0 with **MSI DeviceID 0x100**. [SOURCE IORT node
  offsets 0x72c, 0xa0, 0x30; section 4]
- That SMMU is the **second** SMMUv3 node in the table (node offset 0xa0). The
  first SMMUv3 node (offset 0x48, base `0x13800000`) serves PCI segments 0 to 14
  and the USB named components. [SOURCE IORT; section 3]
- aienos keeps only the first SMMUv3 node and only the root-complex mappings
  that point at it, so the segment 15 mapping is dropped at parse time and
  `ck_dma_confine(15, 0x0100, ...)` returns `CK_SMMU_NOSTREAM` on this
  machine. It fails closed, which is right, but it means **no GB10 DMA can be
  confined until the kernel drives a second SMMUv3 instance**.
  [SOURCE native/kernel/core/acpi.c:368-375,384-387; native/kernel/core/smmu_svc.c:110,142-143]
- StreamID 0x100 is inside the 4096-entry stream table aienos allocates
  (`STE_N`), so table size is not the obstacle. [SOURCE native/kernel/core/smmu_svc.c:14]
- The table carries one RMR node (reserved memory ranges) for stream ids 0x0
  to 0x100 inclusive on the GB10's SMMU, so it covers the GB10. Three physical
  ranges must stay identity-mapped (Normal Non-cacheable, remap not
  permitted) for those streams: `0x280000000` + 2 GiB, `0x300000000` + 48 MiB,
  `0xa1600000` + 386 MiB. Linux exposes exactly these as `direct` reserved
  regions of the GB10's IOMMU group. [SOURCE IORT node 0xc18; /sys/kernel/iommu_groups/20/reserved_regions]
  What those ranges hold is [UNKNOWN] (`/proc/iomem` lists
  `280000000-3237fffff : reserved`, no owner name).
- Segment 15 is the only root complex with ATS marked supported. Its DMA
  address limit is 40 bits and it is marked cache coherent. [SOURCE IORT node 0x72c]

## 2. Method

1. Read the layout first: `actbl2.h` structs `acpi_iort_node` (:470),
   `acpi_iort_id_mapping` (:492), `acpi_iort_root_complex` (:549),
   `acpi_iort_smmu_v3` (:603), `acpi_iort_rmr` and `acpi_iort_rmr_desc`
   (:640-651), and the id-range rule from `linux iort.c:361`
   (`rid_in > map->input_base + map->id_count` means ranges are inclusive;
   `id_count` is the number of ids minus one). Both recorded with `docs-read`.
2. Dumped the table (root read of `/sys/firmware/acpi/tables/IORT`) and decoded
   it with `scripts/iort_decode.rs` (Rust, standard library only, reads a file,
   touches no hardware). `scripts/gb10_iort_decode.sh` does both steps.
3. Ground check against Linux (section 5) before trusting the decode.

## 3. What the table contains

68 nodes, revision 6, OEM `MEDTEK`. [SOURCE IORT header]

| Node | Offset | What | Mappings |
|---|---|---|---|
| ITS group 0 | 0x30 | ITS id 0 | none (terminal) |
| SMMUv3 A | 0x48 | base `0x13800000`, flags 0x1 (COHACC override), event/pri/gerr/sync GSIV 342/347/340/341 | stream 0x10000..=0x110000 to ITS group, DeviceID = stream + 0x200000 |
| SMMUv3 B | 0xa0 | base `0x13000000`, flags 0x1, GSIV 366/371/364/365 | stream 0x0..=0x10000 to ITS group, DeviceID = stream |
| SMMUv3 C | 0xf8 | base `0x14900000`, flags 0x1, GSIV 397/0/395/396 | none (no MSI path) |
| Named USB0..USB5, UBF0..UBF3 | 0x150..0x36c | platform USB controllers | single stream 0x0..0x9 on SMMUv3 A |
| Root complex seg 0..14 | 0x3a8..0x6f0 | ATS 0, 40-bit, coherent | rid 0x0..=0xffff to SMMUv3 A, stream base 0x10000 * (seg + 1) |
| Root complex seg 15 | 0x72c | **ATS 1**, 40-bit, coherent | rid 0x0..=0xffff to **SMMUv3 B**, stream = rid |
| Named HDA0 | 0x768 | audio | single stream 0x500 on SMMUv3 B |
| Named ROT0/1, DSP1..3, CNT0, ASD0, I2C0..6, SPI0/2/3, PMU0, DMA0 | 0x7a4..0xbdc | platform peripherals | single streams on SMMUv3 C |
| RMR | 0xc18 | flags 0x10: remap NOT permitted, unprivileged, attributes Normal NC; 3 ranges (section 1) | stream 0x0..=0x100 on SMMUv3 B |
| PMCG x17 | 0xc98..0xf18 | performance monitor pages per SMMU | none |

[SOURCE IORT decode, full listing reproduced by `scripts/gb10_iort_decode.sh`]

## 4. Resolution walk for the GB10

```
segment 15, rid 0x0100
  root complex @0x72c  map in 0x0..=0xffff out 0x0  -> SMMUv3 B @0xa0   StreamID 0x100
  SMMUv3 B   @0xa0   map in 0x0..=0x10000 out 0x0 -> ITS group @0x30  DeviceID 0x100
```

The PCIe root port of that segment (`000f:00:00.0`, rid 0x0000) is StreamID
0x0 on the same SMMU. [INFERRED from the same mapping]

## 5. Ground checks (Linux on the same machine, read-only)

| Check | Decode says | Linux says | Result |
|---|---|---|---|
| GB10 SMMU | SMMUv3 B, base 0x13000000 | `/sys/bus/pci/devices/000f:01:00.0/iommu` -> `smmu3.0x0000000013000000` | match |
| Negative control: segments 0 to 9 devices (8 functions) | SMMUv3 A, base 0x13800000 | every `/sys/bus/pci/devices/000[0-9]:*/iommu` -> `smmu3.0x0000000013800000` | match |
| Number of SMMUs | 3 | `/sys/class/iommu`: 0x13000000, 0x13800000, 0x14900000 | match |
| RMR covers the GB10 stream | yes (0x0..=0x100 inclusive) | group 20 `reserved_regions`: `a1600000-b97fffff direct`, `280000000-302ffffff direct` (= RMR ranges 2, 1+0 merged) | match |
| MSI doorbell | ITS group 0 | group 20 `reserved_regions`: `8000000-80fffff msi` | consistent |

The inclusive id-range rule is what makes the RMR cover the GB10: with an
exclusive reading the RMR would stop at 0xff and Linux would not list those
regions for group 20. [SOURCE linux iort.c:361; sysfs above]

## 6. What this means for aienos

| Fact | Where in the kernel | Consequence |
|---|---|---|
| Parser keeps only the first SMMUv3 node (`pass == 0 && type == IORT_NODE_SMMUV3 && !found`) | native/kernel/core/acpi.c:368-375 | SMMUv3 A is the only SMMU aienos can bring up; SMMUv3 B (GB10) is never programmed |
| Root-complex mappings whose output is another SMMU are skipped (`rd32(e + 12) != s.node_off`) | native/kernel/core/acpi.c:386-387 | segment 15 has no mapping in `g.iort`; `ck_iort_stream_id(15, 0x100)` returns -1 |
| `ck_dma_confine` then returns `CK_SMMU_NOSTREAM` | native/kernel/core/smmu_svc.c:142-143 | fail closed: a GB10 DMA window is refused today, never granted unconfined |
| Only the named-component path knows the "other SMMU" case (`CK_SMMU_OTHER`) | native/kernel/core/smmu_svc.c:162-167; native/kernel/include/ck.h:116 | the PCI path reports NOSTREAM where OTHER is the truth; a report-only mismatch, not a safety hole |
| Range test `rel > m->id_count` | native/kernel/core/acpi.c:430 | inclusive, agrees with Linux; no change needed |
| `STE_N 4096` | native/kernel/core/smmu_svc.c:14 | StreamID 0x100 fits |
| Window leaf is Normal Non-cacheable | native/kernel/core/smmu_svc.c:16-19 | same attribute the RMR demands (Normal NC), so the RMR ranges could be expressed as windows [INFERRED] |
| One contiguous span per stream | native/kernel/core/smmu_svc.c:15-19 (B4 report section 1) | the three RMR ranges plus a ring/completion window need at least four spans for StreamID 0x100 [INFERRED] |

Gaps a future cut would have to close before any GB10 DMA (design facts, not a plan):
1. Bring up SMMUv3 B (base 0x13000000) in addition to or instead of A: own
   stream table, command and event queues, GSIVs 366/371/364/365.
2. Select the SMMU per root complex, not "the first node"; `ck_iort_parse`
   would have to carry several SMMU nodes or be called per node.
3. Honour the RMR for StreamID 0x100: identity windows for the three ranges
   with Normal NC, or the GPU's firmware traffic into them faults. [INFERRED;
   what the ranges hold is UNKNOWN]
4. Keep DMA addresses under 40 bits for segment 15 (address limit 40).
5. MSI: DeviceID 0x100 at ITS 0 if interrupts are ever used instead of polling.

## 7. Unknowns

- What lives in the three RMR ranges (GPU firmware carveout is a guess, not a
  reading). [UNKNOWN]
- Whether SMMUv3 B shares the stream table format and feature set of A (the
  table says model 0, generic, for all three; the hardware ID registers were
  not read in this cut). [UNKNOWN]
- Whether Linux's stream table entry for 0x100 uses stage 1, stage 2 or
  bypass (not decoded; needs a register read, out of scope here). [UNKNOWN]

## 8. Cut B6 (done, QEMU/host only)

`ck_iort_parse` now remembers every SMMUv3 node and the root-complex mappings
that target one other than the first (`struct ck_iort_other`,
`ck_iort_other_stream`), and `ck_dma_confine` returns `CK_SMMU_OTHER` with that
SMMU and stream named (len 0, never granted) instead of `CK_SMMU_NOSTREAM`.
Host checks: test_smmu Spark-shape case (segment 15 rid 0x100 -> stream 0x100
on 0x13000000), `iort-mutants` with the new `CK_IORT_MUTANT_OTHER_BLIND`
killed, and `ck_acpi_scan --iort` on the real table printing the segment 15
mapping as not driven. The second SMMU is still not brought up; that is a
later cut with its own approval.
