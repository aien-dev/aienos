# D5  -  QEMU native NVMe Write + Flush durability harness (P3)

> **Status: implemented and passing in QEMU (2026-09-25).** The merged
> implementation keeps the read phase in `crates/aienos-boot/src/nvme_read.rs`
> and adds the write/flush phase there under the `nvme-write` feature (whose
> harness is `scripts/qemu_nvme_rw_test.sh`), rather than a separate
> `nvme_write.rs` module or a mode file. The phase is content-adaptive: on a
> boot where the target LBA already holds the expected pattern it reports
> cross-restart durability; otherwise it writes, flushes, and reads back. See
> [`evidence/p3_nvme_write_flush_qemu_2026-09-25.md`](../evidence/p3_nvme_write_flush_qemu_2026-09-25.md).
> The design below remains the rationale and mode contract.

Target placement: `scripts/qemu_nvme_rw_test.sh` (this lane authors a candidate
at `nvme-rw-subagents/d5/qemu_nvme_rw_test.sh`). Companion to the merged read
qualification `scripts/qemu_nvme_test.sh` and follows the mode conventions of
`scripts/qemu_keyboard_test.sh`.

Base: `aien-dev/aienos` @ `ef359ec`. Read-only against the repo; no repo edits,
no `cargo`, no `qemu`, no hardware, no Python.

## 1. What is being proved

The read lane (`crates/aienos-boot/src/nvme_read.rs`) deliberately issues only
Identify (`0x06`) and Read (`0x02`) and states that "write and flush are not
claimed, proven, or exercised" (`nvme_read.rs:9-11`, `docs/P3_NVME_READ_SUBSTRATE.md:21-25`).
This lane proves the next two things:

1. **Write + flush reaches durable media.** The native driver writes a known
   pattern to a known LBA and issues an NVM Flush (`BlockDevice::flush`,
   `crates/aienos-kernel/src/nvme/driver.rs:432-439`). After QEMU is gone, the
   **host image file** at that LBA holds exactly the expected bytes and hash.
2. **Durability across a restart.** A second QEMU run over the same image file
   reads that LBA back through the native driver and reports the exact bytes
   and SHA-256 (guest hash), which must equal the host's hash.

The kernel already exposes the primitives this lane needs:
`BlockDevice::write_blocks`/`flush` (`crates/aienos-kernel/src/block.rs:15-16`)
and the NVMe implementation `write_blocks` (`driver.rs:428-431`) and `flush`
(`driver.rs:432-439`). The write module reuses the read module's pre-exit
discovery and post-exit scaffolding: `find_nvme` (`nvme_read.rs:83`),
`take_over_dma` (`nvme_read.rs:203`), the `Ecam` adapter (`nvme_read.rs:170`),
`NativeRegisters`/`NativeDma`/`NativeDelay`, the DMA gate
(`nvme_read.rs:413-461`), and `revoke_dma` (`nvme_read.rs:232`).

## 2. Image geometry, target LBA and payloads

Built only with `dd` / `od` / `printf` / `truncate` / `sha256sum`, exactly like
`qemu_nvme_test.sh:94-131`; no Python.

| Property | Value |
|---|---|
| Image size | 64 MiB = `67108864` bytes |
| LBA size | 512 bytes |
| LBA count / bounds LBA | `131072` (`== block_count`) |
| **Target LBA** | **4096** (offset **2097152**) |
| Read-lane sentinel LBA (untouched here) | 2048 (offset 1048576) |

Target LBA 4096 is deliberately distinct from the read sentinel LBA 2048
(`nvme_read.rs:41`, `qemu_nvme_test.sh:107`) so a write can never be confused
with a read-lane sentinel check.

Payloads are one 512-byte LBA: a 16-byte magic repeated 32 times, no newline
(the read lane uses `AIENOS-NVME-SENT` x32 at `nvme_read.rs:40` and
`qemu_nvme_test.sh:104,113-116`).

| Name | Magic (x32 = 512 B) | SHA-256 |
|---|---|---|
| **OLD** (host seed, pre-existing bytes) | `AIENOS-NVME-OLD0` | `46fe054d5bfa8bf3b14ce240830da7445b26ebebe273349f9af22e6454244379` |
| **NEW** (guest writes, expected durable bytes) | `AIENOS-NVME-RW01` | `76fa34c132173497a7bcd0c9618ebdcf0629f550934c164adf81cfa05e6a4451` |

The host seeds OLD at LBA 4096, then `od`-checks the first 16 bytes and
`sha256sum`s the seeded block before boot (`qemu_nvme_rw_test.sh` image build,
mirroring `qemu_nvme_test.sh:118-129`).

## 3. Restart simulation and per-boot modes

Restart is **two QEMU runs over the same `nvme.img` file**. The image is built
once and is never rebuilt between boots; `cache=writethrough` on the NVMe
`-drive` keeps the host file coherent with each guest flush. QEMU is asked to
exit cleanly via the HMP monitor (`quit`) before any signal, so block backends
flush to the host file (`qemu_nvme_rw_test.sh` `stop_qemu`).

The guest reads its mode from an ESP file, because the handoff image has no
runtime environment and `AIENOS_RESTART_SECS` is a **compile-time** env var
(`qemu_nvme_test.sh:78`). Contract:

- File: `\EFI\AIENOS\NVME_RW_MODE.TXT` on the ESP.
- Exact bytes, no trailing newline: `write` or `verify`.
- Read **before** `ExitBootServices` (boot services still live) and passed into
  the post-exit phase; post-exit code cannot use the file protocol.

| Boot | Mode file | Guest action | Host action |
|---|---|---|---|
| 1 | `write` | Discover, identify, write NEW at LBA 4096, `flush()`, run write bounds + device-error probes | After QEMU exits, read image at LBA 4096; require NEW bytes and `new_sha` |
| 2 | `verify` | Discover, identify, `read_blocks(4096)`; report guest hash and durability | Cross-check guest hash == `new_sha`; require it to match the host hash |

Each boot copies a fresh `vars.fd` from `AAVMF_VARS`, exactly as
`qemu_nvme_test.sh:157`. A boot with no AIENOS output is retried (firmware hang,
issue #61, `qemu_nvme_test.sh:25-26,185-189`); a failure after AIENOS output
fails immediately. Retrying boot 1 is safe because the mode is explicit
(`write` rewrites NEW idempotently); it does not depend on image state.

## 4. Exact markers per boot

Markers follow the read lane's `NVME_*_QEMU: PASS` style
(`nvme_read.rs:392,481,491,516,541,557`). The write module must emit:

**Boot 1 (`write`), granted-DMA modes (`smmu`, `unsafe-bypass`):**

- `NVME_DISCOVERY_QEMU: PASS`  -  ECAM walk found class `0x0108`.
- `NVME_IDENTIFY_QEMU: PASS`  -  controller + namespace identify completed.
- `NVME_WRITE_QEMU: PASS (lba=4096 blocks=1 bytes=512 sha256=76fa34c1…)`  - 
  `write_blocks(TARGET_LBA, NEW)` returned `Ok`, and the module hashed the NEW
  buffer it submitted.
- `NVME_FLUSH_QEMU: PASS (nsid=1)`  -  `flush()` returned `Ok`.
- `NVME_WRITE_BOUNDS_QEMU: PASS (lba=131072 rejected OutOfRange no_command)`  - 
  `write_blocks(block_count, …)` rejected client-side with no doorbell write,
  the write-side analogue of `NVME_BOUNDS_QEMU` (`nvme_read.rs:536-548`).
- `NVME_WRITE_ERROR_QEMU: PASS`  -  a device-reported error is surfaced, not
  swallowed. Normal path: an unallocated namespace identify
  (`identify_namespace(0xffff_ffff)` → `NvmeError::CompletionStatus`, as
  `nvme_read.rs:552-564`). Error-injection path: see §5.

In every path where DMA was granted the module must revoke it
(`dma_gate: nvme bus master revoked`, `nvme_read.rs:232-247,566`)  -  including
when the write itself fails in `write-error` mode  -  so the host's revoke check
holds in all granted-DMA modes.

**Boot 2 (`verify`):**

- `NVME_DISCOVERY_QEMU: PASS`, `NVME_IDENTIFY_QEMU: PASS`.
- `NVME_READ_QEMU: PASS (lba=4096 blocks=1 bytes=512 sha256=76fa34c1…)`  -  the
  guest's own SHA-256 of the block it read natively (**guest hash**); it must
  equal `new_sha`.
- `NVME_DURABILITY_QEMU: PASS (lba=4096 restarted guest_sha256=76fa34c1…)`  - 
  guest asserts the readback bytes equal NEW after restart.

The host emits the final `QEMU_NVME_RW: PASS (${mode})`, mirroring
`QEMU_NVME: PASS` (`qemu_nvme_test.sh:278`). The required marker set is
therefore: `NVME_DISCOVERY_QEMU`, `NVME_IDENTIFY_QEMU`, `NVME_READ_QEMU`,
`NVME_WRITE_QEMU`, `NVME_FLUSH_QEMU`, `NVME_WRITE_BOUNDS_QEMU`,
`NVME_WRITE_ERROR_QEMU`, `NVME_DURABILITY_QEMU`, `QEMU_NVME_RW: PASS`.

## 5. Modes

Selected by the same env conventions as `qemu_nvme_test.sh:48-73` /
`qemu_keyboard_test.sh:37-61`.

- **`smmu` (default)**  -  `-M virt,…,iommu=smmuv3`; feature `nvme-write`. Full
  two-boot write → flush → persist → restart-read proof. Requires
  `smmu: enabled`, `smmu_dma_window: nvme only, translation active`,
  `dma_gate: nvme granted (Confined), bus master on`, and
  `dma_gate: nvme bus master revoked` (`nvme_read.rs:233-247,430-461`).
- **`fail-closed`**  -  `AIENOS_QEMU_SMMU=0`, no SMMU. The controller must stay
  unavailable (`dma_gate: nvme denied (NoSmmu), bus master stays off` and
  `nvme: unavailable (SMMU DMA isolation not active)`, `nvme_read.rs:419-428`).
  No write/read/flush/durability marker may appear, and the host must still see
  OLD at LBA 4096.
- **`write-error`**  -  `AIENOS_NVME_WRITE_ERROR=1`. SMMU on, but the backend is
  attached with `-drive …,readonly=on`. QEMU rejects the media write, so the
  driver must surface a device-reported WRITE error:
  `NVME_WRITE_ERROR_QEMU: PASS`, with **no** `NVME_WRITE_QEMU: PASS` and no
  `NVME_FLUSH_QEMU`, and the host must still see OLD at LBA 4096. This is the
  required dedicated error-injection mode.
- **`unsafe-bypass`**  -  `AIENOS_UNSAFE_DMA_BYPASS=1`. Same as `smmu` but the
  unsafe debug build lets NVMe DMA run unconfined; announces
  `WARNING: UNSAFE NVME DMA BYPASS BUILD` / `… ACTIVE`
  (`nvme_read.rs:34-36,443-450`). QEMU debugging only; never in `verify_all.sh`.

## 6. Host-vs-guest hash agreement

- Host builds OLD and NEW, hashing both with `sha256sum` (values in §2).
- After boot 1, host runs
  `dd if=nvme.img bs=512 skip=4096 count=1 | sha256sum` and requires it to equal
  `new_sha`; this is the power-off persistence check.
- Boot 2's guest prints the SHA-256 of its own native readback in
  `NVME_READ_QEMU` and asserts byte equality in `NVME_DURABILITY_QEMU`. The host
  greps the exact expected string, so `guest_sha256 == new_sha == host_sha`.
  Agreement across all three is the durability proof.

## 7. Integration prerequisites (owned by the integration lane)

This harness assumes the write lane adds, mirroring the read lane:

1. Feature `nvme-write = ["handoff"]` in `crates/aienos-boot/Cargo.toml` (next
   to `nvme-read` at `Cargo.toml:23`).
2. Module `nvme_write` gated in `crates/aienos-boot/src/handoff.rs` and a
   post-exit `nvme_write::run(...)` call next to the read call
   (`handoff.rs:560-561`, `handoff.rs:2110-2119`).
3. The `\EFI\AIENOS\NVME_RW_MODE.TXT` reader described in §3.
4. If `unsafe-bypass` is kept: `unsafe-debug-nvme-dma-without-smmu` currently
   depends on `["nvme-read"]` (`Cargo.toml:48`); it must additionally enable
   `nvme-write`, or the bypass build will not contain the write module.

`scripts/verify_all.sh` is **not** edited by this lane. Wiring this harness in
(a two-boot RW QEMU step plus the aarch64 clippy feature loop in step 3b) is a
follow-up, exactly as the read harness notes at `qemu_nvme_test.sh:30-33`.