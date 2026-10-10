# GB10 DMA route and confinement inventory (aienos#286, cut B4)

Report only. Host only. No code was changed, no hardware was touched, no QEMU
run was made. Base commit of aienos read: `a9b15b9` (main).

Tags: [SOURCE file:line] read in the named file. [INFERRED] reasoned from sources,
not directly shown. [UNKNOWN] nothing read answers it.
Paths without a repo prefix are in aienos. `physics:` is the local checkout of
aien-dev/physics at `e95e3ed` (the dependency map pins `6d7cf0d`; the nvrm.c
lines cited below match the pinned lines in that map).

## 1. Short answer

- Today the native kernel has one DMA confinement mechanism: an SMMUv3 stage-1
  window of one contiguous span, per stream, identity-mapped, Normal
  Non-cacheable. It is used by the USB keyboard and the virtual NIC path.
  Nothing connects it to the GB10. [SOURCE native/kernel/core/smmu_svc.c:15-19,172-208]
- No GB10 DMA route exists in aienos today. The GB10 is discovered
  (vendor/device, BAR) and its BAR0 can be read through a capability-bound
  read-only window. It has no SMMU stream, no DMA memory, no completion flag,
  no ring. [SOURCE native/kernel/dev/mmio_window.h:1-47; native/kernel/svc/tests/stage_test.c:265,297]
  Searching the kernel `core/` and `dev/` directories finds no `2e12` or `gb10`. [SOURCE grep, native/kernel/core, native/kernel/dev]
- The biggest open fact: whether the GB10's memory traffic goes through the SMMU
  window this kernel can program at all is not established. [UNKNOWN]
  (dependency map section 8 item 6, docs/GB10_NATIVE_DEPENDENCY_MAP.md:248.)

## 2. What the platform tells us about the GB10 stream

| Fact | Tag |
|---|---|
| GB10 is `000f:01:00.0`, 10de:2e12, BAR0 64 MiB at 0x24000000, ECAM segment 15 at 0x29000000 | [SOURCE docs/GB10_PLATFORM_TOPOLOGY.md:35,60-66,121] |
| IORT table is present (3904 bytes); Linux reports one Arm SMMUv3, 40-bit output, 2-level stream table covering 25 of 32 stream-ID bits, default domain Translated | [SOURCE docs/GB10_PLATFORM_TOPOLOGY.md:68-74] (Linux observed) |
| GB10 is alone in IOMMU group 20 | [SOURCE docs/GB10_PLATFORM_TOPOLOGY.md:73-74] |
| The GB10's IORT stream ID and stream table entry are not decoded by this project | [SOURCE docs/GB10_PLATFORM_TOPOLOGY.md:76-78,165] |
| Resolved in cut B5: GB10 = StreamID 0x100 on the IORT's second SMMUv3 node (base 0x13000000); the kernel today drives only the first (0x13800000) | [SOURCE docs/GB10_IORT_DECODE.md] |
| Which SMMU node the GB10's IORT mapping points at (the kernel drives only the IORT's first SMMUv3 node) | [UNKNOWN] |
| Whether the GB10's stream ID is below the 4096 stream IDs the aienos stream table covers (`STE_N`) | [UNKNOWN] |
| Number of SMMUs on the machine, beyond "an Arm SMMUv3" | [UNKNOWN] (platform USB nodes may sit behind a second one; see `CK_SMMU_OTHER`, native/kernel/include/ck.h:99-100) |

Note: the kernel's lookup is `ck_iort_stream_id(segment, rid)`. For the GB10 the
inputs would be segment 15 and rid 0x0100 (bus 1, device 0, function 0).
[INFERRED] from rid = bus<<8|dev<<3|fn (native/kernel/include/ck.h:~120-125)
and the topology address. Whether the IORT has a mapping for segment 15 is [UNKNOWN].

## 3. Route table (device, system memory, and back)

"Confinement" is what restrains the route in aienos today.

| # | Route | Exists in aienos today? | What confines it today | Missing |
|---|---|---|---|---|
| R1 | CPU to GB10 registers (BAR0 reads) | Yes, read only. [SOURCE native/kernel/dev/mmio_window.c:63-95] | A capability with READ, DERIVE, REVOKE only; WRITE, MAP, GRANT refused at creation. Pages are owned by the window, mapped exclusively, unmapped on revoke. Mapping is Device RW even though the accessor is read only. [SOURCE native/kernel/dev/mmio_window.h:17-47] | Any write accessor. Any doorbell mapping (USERMODE 64 KiB region). Read-only mapping type. |
| R2 | GB10 to system memory (device reads/writes host RAM: ring contents, pushbuffer, data, completion flag writes) | No. | Mechanism exists in general: `ck_dma_confine(segment, rid, phys, len)` gives that requester one stage-1 table mapping only [phys, phys+len); everything else faults and aborts. [SOURCE native/kernel/include/ck.h:98-126; native/kernel/core/smmu_svc.c:134-145,172-208] | Stream id for the GB10 [UNKNOWN]; a caller; a capability tie (below); a decision whether this route should be the SMMU at all. |
| R3 | CPU to GB10-visible memory (CPU fills GPFIFO, pushbuffer, QMD; polls completion flag) | Only as the generic DMA pool `ck_dma_alloc`: contiguous, zeroed, Normal Non-cacheable, never freed, 8 MiB. [SOURCE native/kernel/include/ck.h:38-42; native/kernel/mm/mmu.c:198-211,319-336] | The pool is fixed; confinement window must be a sub-range of it by convention of the existing callers (xhci_fence.c:261-268, net_bind.c:27-30). Nothing enforces that a window lies inside the pool. [INFERRED] ck_dma_confine accepts any 4 KiB aligned phys/len (smmu_svc.c:134-139) | A pool large enough for GPU use [UNKNOWN: required size], freeing, per-capability ownership of pages. |
| R4 | GB10 internal page tables (GPU VA to physical) | No. | Linux RM/UVM builds these; our code only asks. [SOURCE docs/GB10_NATIVE_DEPENDENCY_MAP.md:136] | Whole thing. GPU MMU format [UNKNOWN] (map section 8 item 2). |
| R5 | GPFIFO ring and USERD | No native. In the Linux path: one allocation, ring 1024 entries x 8 bytes, USERD at offset 8192 in the same allocation, handed to RM as system memory. [SOURCE physics:nvrm/nvrm.c:631-640] | n/a natively | Layout owner, doorbell/work-submit token derivation [UNKNOWN] (map item 3). |
| R6 | Pushbuffer and kernel/QMD buffers | No native. Linux path: ordinary `nvrm_alloc` buffers. [INFERRED] from physics:nvrm/nvrm.c:465-467 | n/a natively | As R3. |
| R7 | Completion flags (host-polled markers) | No native. Linux path: GPU writes a marker via release methods; host polls with usleep; a second marker follows an L2 flush; no interrupt. [SOURCE docs/GB10_NATIVE_DEPENDENCY_MAP.md:139] | n/a natively | Wait service, and the cache rule in section 5. |
| R8 | GB10 interrupts (MSI-X into GIC ITS) | No. This is a device-to-memory-or-interrupt-controller write, so it is also an outbound DMA write path. [INFERRED] | n/a | MSI-X table and PBA live in BAR0 (offsets 0x00b90000 / 0x00ba0000) [SOURCE docs/GB10_PLATFORM_TOPOLOGY.md:80-83]; ITS doorbell address would need to be inside the window or in a SMMU bypass for MSIs [UNKNOWN]. Polling is the current assumption. |
| R9 | Peer or P2P DMA (GB10 to another PCI device) | No. | n/a | Not examined. [UNKNOWN] |

## 4. What confines a route, and what does not

Present in aienos:

1. SMMU comes up with global abort set, every stream aborts, until a stream is
   explicitly given a window. Any bring-up failure leaves it aborting. [SOURCE native/kernel/core/smmu.c:340-350; native/kernel/core/smmu_svc.c:94-128; native/kernel/include/ck.h:98-112]
2. Window shape: single span, identity IOVA, Normal Non-cacheable, read/write,
   never executable, unprivileged device accesses allowed. [SOURCE native/kernel/core/smmu_svc.c:15-19,187]
3. Limits: at most 8 confined streams (`CK_DMA_MAX_STREAMS`), one window per
   stream, stage 1 only (S2 bypass in the STE config). [SOURCE native/kernel/include/ck.h:117; native/kernel/core/smmu.c:113]
4. Faults are readable per stream through the event queue
   (`ck_dma_faults`). [SOURCE native/kernel/core/smmu_svc.c:223-247]
5. Unconfine returns the stream to abort. It does not free the pool pages and
   does not itself require bus mastering to be off: the header says the caller
   turns bus mastering off first. [SOURCE native/kernel/include/ck.h:160-163]
6. Streams behind a different SMMU are refused, never granted unconfined (named
   components path). [SOURCE native/kernel/core/smmu_svc.c:147-170] For PCI
   requesters via `ck_dma_confine` the lookup only uses maps parsed for the
   first SMMU. [INFERRED] from `g.iort` use at smmu_svc.c:134-145 and `ck_iort_stream_id` core/acpi.c:417-434

Not present, relevant to the GB10:

- Capability binding for DMA. The MMIO window has a capability (rights, revoke,
  unmap). The SMMU window does not: `ck_dma_confine` is a plain function; nothing
  ties a confinement to a capability handle, revoke, or page ownership. [SOURCE native/kernel/include/ck.h:98-136 shows no handle argument; native/kernel/dev/mmio_window.h:1-47 for the MMIO side]
- Multiple discontiguous spans per stream (a GPU working set is many buffers). [SOURCE one `ck_pt_map` call, smmu_svc.c:187]
- Window growth, shrink or page-granular revoke while the stream is live. [INFERRED] no such function exists in ck.h
- Freeing DMA pages: the pool is never freed. [SOURCE native/kernel/include/ck.h:41-42]
- Substream IDs, ATS/PRI, stalls: no references found in the aienos SMMU code. [SOURCE grep, native/kernel/core/smmu.c]. Whether the GB10 needs any of them: [UNKNOWN]
- Any link between B3b's page ownership (exclusive MMIO ranges) and DMA RAM pages. The two ownership tables are different mechanisms. [INFERRED]

## 5. Cache rule on GB10 and what aienos does with it

Rule (vendor header, local): `NVOS32_ATTR2_GPU_CACHEABLE`: "DEFAULT - Highest
performance cache policy that is coherent with the highest performance CPU
mapping. Typically this is gpu cached for video memory and gpu uncached for
system memory. YES - Enable gpu caching if supported on this surface type. For
system memory this will not be coherent with direct CPU mappings."
[SOURCE nvidia-open-580.173.02/src/common/sdk/nvidia/inc/nvos.h:1113-1126]

Our layer: `nvrm_alloc` forces `GPU_CACHEABLE_YES`; `nvrm_alloc_gpu_uncached`
forces `NO` and says it is "for memory both sides poll, not for bulk data".
[SOURCE physics:nvrm/nvrm.c:465-474,500] On physics main `9f96f25` the GPFIFO
ring plus USERD are allocated with `nvrm_alloc_gpu_uncached` (comment: a
GPU-cached allocation can retain their previous contents on GB10; CPU store
barriers alone do not invalidate that cached copy), so the Linux path already
honours the project rule for them (CHIPWAIT root cause, omega HD-16, physics#28).
The error notifier is still allocated with `nvrm_alloc`, GPU-cacheable YES.
[SOURCE physics:nvrm/nvrm.c:628-632 at 9f96f25, read from GitHub by the reviewer;
an older local checkout e95e3ed predates the fix and showed both cached] Whether
the cached notifier matters depends on who reads it and when; not examined here.
[UNKNOWN] The native backend must make the same choice explicitly for every
host-polled word. [INFERRED]

What aienos does today:

- It has no concept of GPU cacheability, since it has no GPU memory. [SOURCE grep for "cacheab"/"uncach" in native/, crates/, docs/: only CPU-side Normal Non-cacheable DMA pool references]
- Its DMA pool and the SMMU window are both CPU/stream Normal Non-cacheable. That
  is the CPU side and the SMMU translation attribute. It does not control the
  GPU's own L2: whether GPU L2 caching applies to traffic that passes an SMMU
  window is [UNKNOWN]. So the existing "Non-cacheable" setting neither honours nor
  ignores the GPU-L2 rule; it is about different caches. [INFERRED]
- Consequence for native: every host-polled word needs a GPU-side uncached
  attribute set in the GPU's own page tables (R4), which aienos does not own yet.
  Also the proven release sequence is an L2 flush plus a second uncached marker
  (docs/GB10_NATIVE_DEPENDENCY_MAP.md:139). Both belong to the GPU MMU/method layer.

## 6. Linux RM behaviours the native backend must reproduce or refuse

| Behaviour (Linux) | Source | Native stance |
|---|---|---|
| All GB10 allocations are system memory (no local video memory) | physics:nvrm/nvrm.c:498 (comment "GB10 has no local video memory") | Reproduce: one memory class. |
| Cache policy chosen per allocation (attr2 GPU_CACHEABLE), with CPU mapping uncached | nvos.h:1113-1126; physics:nvrm/nvrm.c:470-472 | Reproduce as an explicit per-buffer flag; refuse default-YES for anything the host polls. |
| Non-contiguous physical allocations allowed (`PHYSICALITY_ALLOW_NONCONTIGUOUS`) | physics:nvrm/nvrm.c:499 | Decide. Today's SMMU window is one contiguous span, so non-contiguous needs either contiguous backing or multi-span windows. |
| RM may or may not put an SMMU mapping on GPU physical allocations ("SMMU mapping for GPU physical allocation decided internally by RM"; override attribute `NVOS32_ATTR2_SMMU_ON_GPU` DEFAULT/DISABLE/ENABLE, documented for Tegra) | nvos.h:1154-1162 | Linux GB10 decides this internally; the policy for GB10 specifically is [UNKNOWN] (the header names Tegra, and the local vendor tree has no RM implementation, see section 8). Native must not assume bypass: topology doc says it must not bypass the SMMU (docs/GB10_PLATFORM_TOPOLOGY.md:111-113). |
| IOMMU virtual address space index is chosen by RM for Tegra VA spaces | nvos.h:3045 | Not obviously relevant to GB10 PCI. [UNKNOWN] |
| Page-table build and teardown done by UVM/RM (`UVM_CREATE_EXTERNAL_RANGE`, `NV_ESC_RM_MAP_MEMORY_DMA`, `UVM_MAP_EXTERNAL_ALLOCATION`, `UVM_FREE`, `NV_ESC_RM_UNMAP_MEMORY_DMA`) | docs/GB10_NATIVE_DEPENDENCY_MAP.md:136 | Must reproduce (R4). Largest gap. |
| Channel creation, runlist, work-submit token, schedule | physics:nvrm/nvrm.c:631-650 | Reproduce; token derivation [UNKNOWN]. |
| Quarantine on failed map (a VA is not recycled when driver state is unknown) | physics:nvrm/nvrm.c:515,520 | Reproduce: never reuse a DMA window or VA after an unknown failure. [INFERRED] sensible; not required by any source |
| Completion is host polling, no driver interrupt | docs/GB10_NATIVE_DEPENDENCY_MAP.md:139 | Deliberately keep polling first. |
| GSP firmware load, reset, power | docs/GB10_NATIVE_DEPENDENCY_MAP.md:244 | Out of scope for this inventory. |

## 7. Proposed shape for the next cuts (INFERRED, for review, not a decision)

1. Decode the GB10's IORT mapping read-only (segment 15, rid 0x0100): which SMMU
   node, which stream ID, within `STE_N`. Host parser test on the recorded IORT, then
   one read-only log line on the Spark. This answers the top unknown.
2. Only after (1): extend the SMMU window to a capability-bound object that
   mirrors the MMIO window (rights, exclusive pages, unmap and abort on revoke),
   and add a multi-span or per-buffer variant.
3. Pool size and freeing for GPU use.
4. GPU page-table and cache attributes belong to the cut that owns the GPU MMU.

Cut D-style actions that program the SMMU for the real GB10 would be operator
steps on the physical machine and are not part of this report.

## 8. What was read and limits

Vendor sources (local `nvidia-open-580.173.02`, recorded with `docs-read`):
`nvos.h:1113-1119` (cache policy), `nvos.h:1154-1162` (SMMU_ON_GPU), `nvos.h:196-207`
(NVOS02 coherency and cacheable flags), `nvos.h:3045` (Tegra IOMMU VA space index).

DOCS SILENT: the local vendor tree holds headers only (`kernel-open/common`,
`kernel-open/nvidia-uvm`, `src/common/sdk`, `src/nvidia/arch`); a search for SMMU
and IOMMU finds hits only in `nvos.h`. The RM and kernel code that decides how
GB10 system memory is DMA-mapped is not present locally, so the real Linux
behaviour for SMMU mapping on GB10 is not shown by any source I read. The Context7
vendor docs were not queried in this cut; the DGX Spark user guide is not known to
cover this (spark-hardware-manual section 2).

Not done: omega's evidence for the uncached rule was not re-read; physics was read
at its local commit `e95e3ed`, not the pinned `6d7cf0d`; no hardware or QEMU run;
the actual IORT of the Spark was not decoded.
