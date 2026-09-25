# D1  -  Unsupported / Unsafe Assumptions (prioritized)

Repo: `aien-dev/aienos` @ `ff5de9c`. Read-only audit; no repo edits, no cargo, no hardware.

Only assumptions that are **UNSUPPORTED** or **UNSAFE-IF-DEVIATES** are listed. Each entry gives the minimal change.

---

## P0  -  CAP.MPSMIN / MPSMAX ignored; MPS, PAGE_SIZE and ASQ/ACQ alignment hard-coded to 4 KiB
- **file:line**: `crates/aienos-kernel/src/nvme/driver.rs:12,43,123`; `crates/aienos-kernel/src/nvme.rs:27-43`
- **Assumption**: `CC.MPS=0` (4 KiB), `PAGE_SIZE=4096`, and `PAGE_SIZE`-aligned ASQ/ACQ are always valid.
- **Why unsafe**: `CAP.MPSMIN` (CAP bits 55:48) sets the minimum memory page size `2^(12+MPSMIN)`. A spec-legal controller with `MPSMIN>0` requires `CC.MPS >= MPSMIN` and page-size-aligned admin queues; programming MPS=0 is non-conformant and the ASQ/ACQ/PRP page math is wrong.
- **Minimal change**: Extract MPSMIN from CAP (`(cap >> 48) & 0xff`) and MPSMAX (`(cap >> 56) & 0xf`). If `MPSMIN != 0`, either fail init loudly or program `CC.MPS = MPSMIN` and use `page_size = 1 << (12 + MPSMIN)` for allocations/alignment/PRP math instead of the `PAGE_SIZE` constant.

## P0  -  CAP.MQES not enforced for admin or I/O queue depths
- **file:line**: `crates/aienos-kernel/src/nvme/driver.rs:115-118` (admin), `174-196` (I/O); decode at `crates/aienos-kernel/src/nvme.rs:37-39`
- **Assumption**: `ADMIN_DEPTH=8` and any caller I/O `depth >= 2` are accepted without checking the controller's maximum (`CAP.MQES+1`).
- **Why unsafe**: The controller may support fewer entries; AQA (`0x0007_0007`) or a create-queue QSIZE above `MQES` is out of range and aborts/undefined.
- **Minimal change**: At the top of `init`, return an error if `ADMIN_DEPTH > cap.mqes()`; in `create_io_queues`, reject `depth > cap.mqes()` before allocating.

## P1  -  CAP.CSS not validated; CC.CSS hard-coded to NVM
- **file:line**: `crates/aienos-kernel/src/nvme/driver.rs:42,123`
- **Assumption**: The controller supports the NVM command set (`CC.CSS=0`).
- **Why unsafe**: If `CAP.CSS` bit 0 is clear, selecting CSS 0 is invalid and the enable sequence is non-conformant. Rare but spec-legal.
- **Minimal change**: Read `CAP.CSS` (`(cap >> 45) & 0xff`); fail init with a dedicated error if bit 0 is 0.

## P1  -  Hard-coded NSID 1; no active-namespace enumeration
- **file:line**: `crates/aienos-kernel/src/nvme/driver.rs:145,150,156`, `184-185`, `333-335`, `419`
- **Assumption**: Namespace ID 1 always exists and is the intended storage.
- **Why unsafe**: A controller may expose a different active NSID or multiple namespaces; reads/writes/flush could fail or target the wrong store. (Note: `nsid` is a parameter to `identify_namespace` but every caller passes 1.)
- **Minimal change**: Enumerate active namespaces with Identify (CNS=2) and use the first active NSID, or thread a caller-supplied NSID through `identify_namespace`, `transfer`, and `flush`.

## P1  -  LBADS lower bound not validated
- **file:line**: `crates/aienos-kernel/src/nvme/driver.rs:162`
- **Assumption**: Any `lbads < 32` is a usable LBA data size.
- **Why unsafe**: Valid LBA data sizes are `2^9`..`2^31` (LBADS 9..31). Accepting `lbads` 0..8 yields block sizes below 512 B and a correspondingly inflated `block_count`, silently miscomputing addresses.
- **Minimal change**: Change the guard to reject `lbads < 9 || lbads >= 32`.

## P2  -  CAP.AMS not validated; CC.AMS hard-coded Round Robin
- **file:line**: `crates/aienos-kernel/src/nvme/driver.rs:42,123`
- **Assumption**: Round Robin arbitration (`CC.AMS=0`) is always supported.
- **Why unsafe**: Round Robin is normally supported, but the capability (`CAP.AMS` bit 0) is never checked before selecting it.
- **Minimal change**: Read `CAP.AMS` (`(cap >> 17) & 0x3`); if bit 0 is clear, fail init or select a supported mechanism.

## P2  -  Readiness poll off-by-one vs CAP.TO
- **file:line**: `crates/aienos-kernel/src/nvme/driver.rs:30-39`
- **Assumption**: `for _ in 0..=timeout_ms` with a post-read 1 ms delay bounds the wait at `timeout_ms` ms.
- **Why unsafe**: It delays once after the final read, making the real bound `(timeout_ms+1)` ms  -  one poll past CAP.TO. Low impact, trivially wrong.
- **Minimal change**: Use `for _ in 0..timeout_ms` or move `delay_us(1000)` before the last iteration.

## P2  -  Completion SQID not verified
- **file:line**: `crates/aienos-kernel/src/nvme/driver.rs:231,372`
- **Assumption**: Matching `command_id` alone identifies the completion.
- **Why unsafe**: The spec keys completion to `(SQID, CID)`. A stale or misrouted CQE with a reused CID could be consumed.
- **Minimal change**: After `command_id` matches, also assert `completion.sq_id()` equals the expected SQ ID (0 admin / 1 I/O), else treat as error.

## P3  -  VS (0x08) never read or validated
- **file:line**: `crates/aienos-kernel/src/nvme.rs:9`
- **Assumption**: The controller's major/minor version is irrelevant.
- **Why unsafe**: The base register layout is stable across NVMe 1.x/2.x, so risk is informational today; there is no version gate for a future incompatible major.
- **Minimal change** (optional): Read `REG_VS` during `init` and reject unsupported major versions, or log the version for field diagnostics.
