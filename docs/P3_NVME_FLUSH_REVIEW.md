# D2 Flush Review  -  AIENOS P3 NVMe Flush lane

Base: `aien-dev/aienos` @ `ef359ec` (read-only mirror `/Users/drakestapleton/aienos-nvme-rw`).
Files read in full: `crates/aienos-kernel/src/nvme.rs`,
`crates/aienos-kernel/src/nvme/driver.rs`, `crates/aienos-kernel/src/block.rs`.
Companion tests: `nvme-rw-subagents/d2/nvme_flush.rs` (target `crates/aienos-kernel/tests/nvme_flush.rs`).

## 1. Is `flush()` a correct NVMe Flush command?

Implementation (driver.rs:432 - 439) builds a zeroed `Submission`, sets CDW0 opcode = `0`
and CDW1 NSID = `1`, then hands it to `submit_io` (driver.rs:364 - 406).

- **Opcode**  -  `0x00` (NVM Flush) in CDW0 bits 7:0. `submit_io` ORs the CID into CDW0
  bits 31:16 (driver.rs:370), leaving opcode/FUSE intact. Correct.
- **NSID**  -  CDW1 = 1. Correct for the single namespace the driver identifies
  (`identify_namespace(1)`), but hardcoded (see NEEDS-FIX 1).
- **CDW10..CDW15**  -  left zero. Correct; Flush defines no command-specific fields
  (no LBA, no NLB, no FUA).
- **Data pointers**  -  PRP1/PRP2 are zero. Flush is a data-less command; PRPs are
  reserved, so requiring none is correct and the tests assert `(prp1, prp2) == (0, 0)`.
- **Queue**  -  submitted on the polled I/O SQ/CQ (QID 1), which is the correct command
  set for an NVM I/O command.
- **CID**  -  drawn from the shared `next_cid` (driver.rs:368 - 369), so a Flush never
  aliases the preceding Write's CID; the test asserts monotonic `+1`.
- **Completion semantics**  -  `status = c.status() >> 1`; `0 -> Ok(())`, nonzero ->
  `BlockError::DeviceError` (driver.rs:392 - 403), and the poll budget is bounded
  (1001 iterations) -> `BlockError::Timeout`. This is the honest mapping: durability
  is exposed only through a successful completion.

Verdict: the command layout and completion handling are a correct NVMe Flush.

## 2. Are `BlockDevice::flush` semantics honest?

`BlockDevice` (block.rs:11 - 17) declares `flush(&mut self) -> Result<(), BlockError>`
with no documented durability contract. Two implementors differ sharply:

- `NvmeController::flush` (driver.rs:432)  -  **honest**: it actually issues the Flush
  command and reports backend failure/timeout as an error. It is not a no-op.
- `RamDisk::flush` (block.rs:129 - 131)  -  **unconditional `Ok(())`**, a literal no-op.
  For a purely volatile in-memory disk this is defensible (there is no media to
  persist to), but it must be understood as "no durability guarantee", not as a
  successful flush. It is the exact pattern that must **not** be copied into a
  real-device driver.

Additional honesty concerns:

- `write_blocks` never sets the FUA bit (CDW12 bit 14) and never auto-flushes
  (driver.rs:428 - 431, 349 - 353). Durability is only obtained if the caller explicitly
  calls `flush()`; callers must not assume `write_blocks` is durable.
- The trait does not state whether `flush` is a cache-flush barrier, an ordering
  barrier, or both, nor which namespace(s) it covers. The NVMe impl flushes NSID 1
  only.
- All nonzero completion statuses (including DNR, SCT/SC detail) collapse to
  `DeviceError`, losing diagnostic detail (acceptable for the coarse `BlockError`
  enum, but worth noting).

## 3. What does QEMU's emulated NVMe do with Flush?

QEMU does **not** ignore it. In `hw/nvme/ctrl.c` (upstream, v1.4-capable):

- I/O dispatch routes `NVME_CMD_FLUSH` (opcode `0x00`) to `nvme_flush()`
  (`nvme_io_cmd` path, `ctrl.c:4748`).
- `nvme_flush()` validates the NSID (`NVME_INVALID_NSID | NVME_DNR` if invalid,
  `NVME_INVALID_FIELD | NVME_DNR` if the namespace is absent), supports
  `NVME_NSID_BROADCAST` (`0xFFFFFFFF`) to flush every namespace, then calls
  `nvme_do_flush()` (`ctrl.c:3622 - 3659`).
- `nvme_flush_ns_cb()` issues `blk_aio_flush(ns->blkconf.blk, ...)` against the
  namespace's `BlockBackend` (`ctrl.c:3582`). If the backend returns an error,
  `nvme_flush_ns_cb` sets `req->status = NVME_WRITE_FAULT` (`ctrl.c:3570 - 3573`),
  which is returned as a **nonzero completion status**  -  exactly what our driver
  maps to `BlockError::DeviceError`.

So a successful Flush completion in QEMU means the flush reached the block backend
and the backend reported success. Whether that persists to the host file depends on
the drive's cache mode:

- `cache=writeback` (QEMU default): `blk_aio_flush` propagates to the format/protocol
  driver and typically results in an `fsync`/`fdatasync` of the backing file  -  the
  data reaches the host file.
- `cache=none` / `cache=directsync`: writes are already synchronous, so the flush may
  be a no-op at the file layer but still completes successfully.
- `cache=unsafe`: QEMU is explicitly told to ignore flushes / not use `O_DSYNC`; a
  successful Flush then does **not** guarantee host persistence.

Net: emulated Flush is real and reaches the backend; host-level durability is only as
strong as the drive's cache configuration. Our driver correctly treats a nonzero
completion as failure.

## 4. Flush must not be faked as a no-op

A silent `flush() -> Ok(())` in a real NVMe driver is a durability bug: it reports
success without ever telling the controller to commit its volatile write cache, so a
power loss can lose acknowledged writes. The current `NvmeController::flush` avoids
this by issuing opcode `0x00` and requiring a zero-status completion. The tests in
`nvme_flush.rs` enforce this directly: they assert an I/O SQ doorbell write occurs,
that the parsed command reaches the simulator, that a nonzero status yields
`DeviceError`, and that a missing completion yields `Timeout`  -  i.e. flush can never
silently succeed. The `RamDisk` no-op is acceptable only because RAM is inherently
volatile and must never be treated as the pattern for a persistent device.

## NEEDS-FIX / observations

1. **Hardcoded NSID 1** (driver.rs:437). `flush()` should target the active
   namespace ID (or support `NVME_NSID_BROADCAST` like QEMU) rather than a literal
   `1`, or the trait should document the single-namespace restriction. Currently
   consistent only because the driver identifies/uses NSID 1 exclusively.
2. **No durability contract on `BlockDevice::flush`** (block.rs:11 - 17). Document that
   `flush` is a cache-commit barrier, that `write_blocks` is not implicitly durable,
   and that `RamDisk::flush` is a deliberate no-op with no persistence claim.
3. **`write_blocks` has no FUA path** (driver.rs:349 - 353). Either document that
   callers must `flush()` for durability or add an FUA option for single-write
   durability.
4. **Flush uses the same 1001×1 ms poll budget as data I/O** (driver.rs:379). Real
   media flushes can take longer; consider a dedicated (longer) flush budget.
5. **Status detail is lost** (driver.rs:399 - 403). `DeviceError` discards DNR/SCT/SC;
   acceptable for the coarse enum but consider preserving it for diagnostics.
6. **No regression test in-repo yet.** `nvme_flush.rs` should be dropped into
   `crates/aienos-kernel/tests/` and run with `cargo test -p aienos-kernel` (not run
   here per constraints).

## Test coverage added (`nvme_flush.rs`)

- `flush_submits_opcode_zero_nsid_one_without_data_pointer`
- `successful_flush_completion_returns_ok`
- `nonzero_flush_completion_status_returns_device_error`
- `flush_timeout_returns_timeout_and_is_bounded`
- `flush_is_not_a_silent_no_op_doorbell_and_command_reach_device`
- `flush_after_write_in_same_session_uses_fresh_cid`
