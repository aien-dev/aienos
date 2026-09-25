# D1  -  NVMe Controller-State Audit (AIENOS P3 Native NVMe Read Substrate)

Repo: `aien-dev/aienos` @ baseline `ff5de9c`
Mirror (read-only): `/Users/drakestapleton/aienos-p3`
Scope: `crates/aienos-kernel/src/nvme.rs`, `crates/aienos-kernel/src/nvme/driver.rs`, `crates/aienos-kernel/src/block.rs`
Reference model: NVMe Base Specification (CAP / VS / CC / CSTS / AQA / ASQ / ACQ register layout; Identify Controller/Namespace layouts).

Status legend:
- **SUPPORTED**  -  matches the base register model (or is a safe, self-imposed policy).
- **UNSAFE-IF-DEVIATES**  -  correct only for the common 4 KiB / single-controller case; breaks (or overflows/under-waits) on a spec-legal controller that deviates.
- **UNSUPPORTED**  -  an assumption the code makes that is not derived from or validated against the register model.

## Register / behavior table

| # | Assumption | file:line | What the code does | Spec-correct? | Risk | Recommended minimal fix | Status |
|---|-----------|-----------|--------------------|---------------|------|-------------------------|--------|
| 1 | 64-bit CAP assembly | `nvme/driver.rs:107` | `Cap((read32(4) as u64) << 32) \| read32(0) as u64` | Yes  -  high dword at 0x04, low at 0x00 | None | None | SUPPORTED |
| 2 | CAP.MQES enforcement | `nvme.rs:37-39`; `driver.rs:115-118`, `174-196` | MQES decoded (`mqes()`) but never compared to `ADMIN_DEPTH` (8) or caller I/O depth; AQA/QSIZE written unconditionally | Only if `depth-1 <= MQES` | A spec-legal controller with small MQES gets an out-of-range AQA/QSIZE → command abort / undefined behavior | Reject at `init` if `ADMIN_DEPTH > cap.mqes()`, and in `create_io_queues` if `depth > cap.mqes()` | UNSAFE-IF-DEVIATES |
| 3 | CAP.TO units (500 ms) | `nvme.rs:40-42`; `driver.rs:108` | `timeout_ms = cap.timeout_units().max(1) * 500` | Yes  -  TO is bits 31:24 in 500 ms units; `TO==0` treated as 500 ms default | None material; `TO=0` means "not reported", a host default is reasonable | None | SUPPORTED |
| 4 | CAP.DSTRD / doorbell math | `nvme.rs:31-36`, `45-47` | `stride = 4 << DSTRD`; `offset = 0x1000 + (2*qid + completion)*stride` | Yes  -  SQqTDBL at 0x1000+2q·stride, CQqHDBL at +1·stride | `u32` math can overflow only for absurd qid·stride; no real path | Optionally use `u64` in `doorbell_offset` | SUPPORTED |
| 5 | CAP.MPSMIN / CAP.MPSMAX / MPS | `nvme.rs:27-43`; `driver.rs:12,43,123` | MPSMIN/MPSMAX never read; `CC.MPS=0` (4 KiB) and `PAGE_SIZE=4096` hard-coded | No  -  if `CAP.MPSMIN>0` the controller requires MPS ≥ `2^(12+MPSMIN)`; programming MPS=0 is illegal | **High**: on a controller with MPSMIN>0 the enable sequence is non-conformant and ASQ/ACQ/PRP alignments are wrong | Extract MPSMIN (`(cap>>48)&0xff`) / MPSMAX; require `MPSMIN==0` else program the correct MPS and align to `2^(12+MPSMIN)` | UNSUPPORTED |
| 6 | CAP.CSS / CC.CSS | `driver.rs:42,123` | `CC.CSS=0` (NVM) hard-coded; CAP.CSS never checked | Only if NVM command set supported (`CAP.CSS` bit 0) | Low on real NVMe drives; non-conformant on a device not advertising NVM CSS | Read CAP.CSS (bits 52:45); fail init if bit 0 clear | UNSUPPORTED |
| 7 | CAP.AMS / CC.AMS | `driver.rs:42,123` | `CC.AMS=0` (Round Robin) hard-coded; CAP.AMS never checked | Round Robin is the base mechanism, but not validated | Low | Read CAP.AMS (bits 18:17); assert bit 0 set or select a supported mechanism | UNSAFE-IF-DEVIATES |
| 8 | VS (0x08) read/validated | `nvme.rs:9` (constant only) | `REG_VS` defined; never read. No version gate | Base register model compatible across 1.x/2.x; reading VS is not required to init | Low / informational; a future major-version incompatibility goes undetected | Optionally read VS, log/reject unsupported major | UNSUPPORTED |
| 9 | CC reset → configure → enable order | `driver.rs:109-125` | Clear `CC.EN`, wait RDY=0, program AQA/ASQ/ACQ, write CC(EN=1), wait RDY=1 | Yes  -  admin queues programmed before EN; correct sequencing | None | None | SUPPORTED |
| 10 | CSTS.CFS handling | `nvme.rs:70-72`; `driver.rs:32-34` | Any poll that sees CFS returns `Failed` immediately | Yes  -  CFS = fatal controller status | None | None | SUPPORTED |
| 11 | CSTS.SHST |  -  | Never read | Not required for bring-up | None | None | SUPPORTED |
| 12 | Readiness poll bound / off-by-one | `driver.rs:30-39` | `for _ in 0..=timeout_ms { read; if ready return; delay(1ms) }` | Bounded, but delays once after the final read → total `(TO+1)*1ms` | Trivial extra ms past CAP.TO | `for _ in 0..timeout_ms` (or check-after-delay) | UNSAFE-IF-DEVIATES |
| 13 | AQA field packing | `driver.rs:115-118` | `((DEPTH-1)<<16) \| (DEPTH-1)` = `0x0007_0007` | Yes  -  ASQS bits 11:0, ACQS bits 27:16 | Field width not masked; only safe because DEPTH=8 | Mask with `0xfff` / `0xfff<<16` if depth ever exceeds 4096 | SUPPORTED (conditional on #2) |
| 14 | ASQ/ACQ 64-bit writes | `driver.rs:119-122` | Low dword at 0x28/0x30, high dword at +4; before EN | Yes | None | None | SUPPORTED |
| 15 | ASQ/ACQ alignment | `driver.rs:112-114` | Allocated with alignment `PAGE_SIZE` (4 KiB) | Only if MPSMIN=0; spec requires alignment to min memory page size `2^(12+MPSMIN)` | Tied to finding #5 | Align ASQ/ACQ (and all DMA used in PRPs) to `2^(12+MPSMIN)` | UNSAFE-IF-DEVIATES |
| 16 | Queue entry sizes 64/16, PAGE=4096 | `nvme.rs:81,159`; `driver.rs:12,44-45,123` | `CC.IOSQES=6`→64 B, `CC.IOCQES=4`→16 B; matching buffers | Yes for SQ/CQ sizes; MPS assumption is #5 | SQ/CQ sizes correct; page size tied to #5 | None beyond #5 | SUPPORTED |
| 17 | Admin completion poll bound | `driver.rs:15,222,228` | Fixed `ADMIN_TIMEOUT_MS=1000` × 1 ms, independent of CAP.TO | Bounded; CAP.TO governs readiness but not command wait | A slow but conformant admin command could exceed 1 s | Derive from CAP.TO (e.g. `cap.timeout_units()*500`) | SUPPORTED (note) |
| 18 | I/O completion poll bound | `driver.rs:362,369` | `for _ in 0..=1000` with 1 ms delay | Bounded; fixed policy | Same as #17 | Make configurable / CAP.TO-derived | SUPPORTED (note) |
| 19 | MDTS handling | `driver.rs:150,291-302` | MDTS byte 77; `limit = (PAGE_SIZE<<MDTS).min(128KiB)`, `MDTS=0` → 128 KiB | Units under-stated if MPSMIN>0 (safe: more splitting); MDTS=0 self-capped (safe) | Conservative in the safe direction; no overflow | Use `2^(12+MPSMIN)` as the MDTS unit; keep the 128 KiB self-cap | SUPPORTED (conservative) |
| 20 | Identify Controller MDTS offset | `driver.rs:150` | `bytes[77]` | Yes  -  MDTS at byte 77 | None | None | SUPPORTED |
| 21 | Identify Namespace block count | `driver.rs:156` | `NSZE = u64 le bytes[0..8]` | Yes  -  NSZE bytes 0-7 | None (uses NSZE not NCAP; correct as last-address + 1) | None | SUPPORTED |
| 22 | FLBAS index | `driver.rs:157` | `bytes[26] & 0x0f` | Yes  -  FLBAS byte 26, low 4 bits = format index | None | None | SUPPORTED |
| 23 | LBA format descriptor | `driver.rs:158-159` | `descriptor = 128 + flbas*4`; `lbads = bytes[descriptor+2]` | Yes  -  LBAF array at 128, LBADS at +2 | None | None | SUPPORTED |
| 24 | LBADS lower bound | `driver.rs:162` | Rejects only `lbads >= 32`; accepts `lbads` 0..8 | No  -  valid LBA data sizes are `2^9`…`2^31` (LBADS 9..31) | A malformed identify yields a 1-byte block size and a huge block_count; silent miscompute | Require `9 <= lbads < 32` | UNSUPPORTED |
| 25 | Command layouts | `nvme.rs:96-156` | Identify CDW10=CNS, NSID=CDW1; R/W opcodes 0x02/0x01, NLB-1 in CDW12, LBA in CDW10-11, PRP1/2 in DW6-9 | Yes | None | None | SUPPORTED |
| 26 | CID handling | `driver.rs:212,353` | CID in CDW0 bits 31:16, low 16 preserved; wrapped modulo 16 bits | Yes | None | None | SUPPORTED |
| 27 | Completion status decode | `nvme.rs:173-175`; `driver.rs:234-239` | `status>>1`, SCT=(status>>8)&7, SC=status&0xff; phase=bit0 | Yes | None (More/DNR bits not inspected) | Optionally surface More/DNR | SUPPORTED |
| 28 | Phase tracking | `nvme.rs:219-254`; `driver.rs:136,227,368` | CQ consumer starts phase=1, toggles on ring wrap | Yes | None | None | SUPPORTED |
| 29 | Hard-coded NSID 1 | `driver.rs:145,150,156`, `184-185`, `333-335`, `419` | All identify/read/write/flush use namespace 1 | Assumes NSID 1 exists and is the target | **Medium**: a controller whose active namespace is not 1 (or multi-namespace) fails or targets the wrong store | Enumerate active NSIDs (Identify CNS=2) and use the discovered NSID | UNSUPPORTED |
| 30 | Queue-create CDW11 (PC/IEN/CQID) | `nvme.rs:106-127` | CQ: `CDW11=1` (PC=1, IEN=0, IV=0); SQ: `CDW11=1\|(cqid<<16)` | Yes | None | None | SUPPORTED |
| 31 | CQ head doorbell after consume | `driver.rs:246-249,380-381` | Advances `cq_head`, writes CQqHDBL | Yes | None | None | SUPPORTED |
| 32 | Completion SQID not checked | `driver.rs:231,372` | Only `command_id` matched; SQID ignored | Spec requires matching SQID+CID | Low robustness; a stale/misrouted completion could be accepted | Also compare `completion.sq_id()` (0 admin / 1 I/O) | UNSAFE-IF-DEVIATES |
| 33 | Flush command | `driver.rs:415-422` | Opcode 0, NSID 1, via I/O queue | Yes (aside from NSID assumption #29) | Tied to #29 | None | SUPPORTED |
| 34 | PRP list capacity | `driver.rs:314-331`; `nvme.rs:258-303` | One 4 KiB list page allocated when `len/PAGE > 2`; max chunk 128 KiB ⇒ ≤512 entries | Yes for the self-imposed 128 KiB cap | None | None | SUPPORTED |
| 35 | DMA 64-bit address width | `driver.rs:119-122`, `nvme.rs:90-91` | Always writes full 64-bit PRP/ASQ/ACQ addresses | Yes for 64-bit-capable controllers; no check | Low; base NVMe ASQ/ACQ are 64-bit by definition | None | SUPPORTED |

## Summary of non-SUPPORTED items

| Finding | Status | Severity |
|---------|--------|----------|
| CAP.MPSMIN/MPSMAX ignored; MPS + PAGE_SIZE + ASQ/ACQ alignment hard-coded to 4 KiB | UNSUPPORTED | High |
| CAP.MQES not enforced for admin/I/O queue depths | UNSAFE-IF-DEVIATES | High |
| CAP.CSS not validated; CC.CSS hard-coded NVM | UNSUPPORTED | Medium |
| Hard-coded NSID 1 (no active-namespace enumeration) | UNSUPPORTED | Medium |
| LBADS lower bound not validated (accepts 0..8) | UNSUPPORTED | Medium |
| CAP.AMS not validated; CC.AMS hard-coded Round Robin | UNSAFE-IF-DEVIATES | Low |
| Readiness poll delays once after the final read (off-by-one vs CAP.TO) | UNSAFE-IF-DEVIATES | Low |
| Completion SQID not verified against expected queue | UNSAFE-IF-DEVIATES | Low |
| VS (0x08) never read/validated | UNSUPPORTED | Informational |
