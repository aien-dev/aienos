# D1 Write-Path Correctness Review  -  AIENOS P3 Native NVMe Write + Flush

Repo: aien-dev/aienos @ `ef359ec` (mirror `/Users/drakestapleton/aienos-nvme-rw`, read-only).
Scope: `crates/aienos-kernel/src/nvme.rs` (`Submission::write`, `io_command`,
`build_prps`, `Completion`) and `crates/aienos-kernel/src/nvme/driver.rs`
(`transfer`, `submit_io`, `write_blocks`/`read_blocks`/`flush`).

Verdict: the write lane is functionally correct for the read substrate it reuses.
One latent defect is flagged (unreachable under the current MDTS cap) plus one
non-blocking resource observation.

---

## 1. CDW layout (opcode / NSID / PRP / LBA / NLB)

`io_command` (`nvme.rs:148-160`) writes, for a write (`opcode 0x01`):

| Field | Dword | Source | Line |
|---|---|---|---|
| OPCODE | CDW0[7:0] | `0x01` | `nvme.rs:150` |
| CID | CDW0[31:16] | overlaid in `submit_io` | `driver.rs:370` |
| NSID | CDW1 | `1` | `nvme.rs:151` |
| PRP1 | CDW6/CDW7 | `p1` lo/hi | `nvme.rs:152-153` |
| PRP2 | CDW8/CDW9 | `p2` lo/hi | `nvme.rs:154-155` |
| LBA | CDW10/CDW11 | `lba` lo/hi | `nvme.rs:156-157` |
| NLB | CDW12[15:0] | `blocks - 1` | `nvme.rs:158` |

**OK.** Layout matches NVMe Base Spec I/O Write. `Submission::write`
(`nvme.rs:135-137`) only selects opcode `0x01`, so write and read share the
same encoder and CDW12 semantics.

## 2. Command ID lifecycle

`submit_io` takes the next CID (monotonic `next_cid`), overlays it into
CDW0[31:16] preserving the opcode low half, and consumes only a completion whose
`command_id()` equals that CID (`driver.rs:368-370`, `389-390`). A mismatch is
reported rather than silently matched. **OK.** Covered by tests
`each_io_command_gets_a_new_cid_and_completion_is_consumed` and
`nonzero_write_completion_maps_to_device_error`.

## 3. NLB = blocks - 1

`set_u32(12, (blocks as u32).wrapping_sub(1))` (`nvme.rs:158`). NVMe NLB is
0-based, so one block -> 0, eight -> 7. `transfer` guarantees `blocks >= 1`
because `data.is_empty()` is rejected and each chunk length is `>= block_size`
(`driver.rs:296-298`, `322-323`), so the `wrapping_sub` cannot underflow on the
write path. **OK.**

## 4. LBA split across CDW10 / CDW11

`set_u32(10, lba as u32)` / `set_u32(11, (lba >> 32) as u32)`
(`nvme.rs:156-157`). Transfer passes `lba + offset/block_size`
(`driver.rs:350`). Because the range check bounds `lba + blocks <= block_count`,
the per-chunk LBA cannot overflow `u64`. **OK.**

## 5. PRP1 / PRP2 / page-list construction reused from read

The write path is the read path with an extra DMA pre-fill, so the PRP
construction is genuinely shared:

- data region allocated at `PAGE_SIZE` alignment (`driver.rs:324`),
- `list_pages = len.div_ceil(PAGE_SIZE)`; a list region is allocated only when
  more than two pages are spanned (`driver.rs:331-336`),
- `build_prps(region.physical, len, PAGE_SIZE, list_address, &mut list)` returns
  `(p1, p2, used)` and those are passed unchanged to `Submission::write`
  (`driver.rs:339-353`).

Because the data region is page-aligned, `build_prps`' internal page count
(`nvme.rs:272-277`, offset = 0) exactly equals `list_pages`, so the ">2 pages"
test never disagrees with the encoder. PRP1 is the raw buffer address, PRP2 the
second page or the list address, and the list entries are the remaining data
pages  -  identical to the read path. **OK.**

## 6. MDTS chunking

`mdts_limit` is `128 KiB` when `mdts == 0`, else `PAGE_SIZE << mdts` clamped to
`128 KiB` (`driver.rs:308-315`); `chunk_limit` is floored to a whole block
(`driver.rs:316`). This is a deliberate conservative cap: MDTS=0 means
"no limit" in the spec, but capping is always safe. MDTS units are the minimum
page size, and `init` refuses `CAP.MPSMIN != 0` (`driver.rs:118-120`), so the
`PAGE_SIZE` base is correct. `checked_shl` + `unwrap_or(usize::MAX)` avoids the
`mdts = 255` shift panic. **OK.**

### NEEDS-FIX (latent): the single-page PRP list is only safe because MDTS is capped
- **Where:** `driver.rs:331-337` (one `PAGE_SIZE` list region and a
  `PAGE_SIZE / 8 = 512`-entry list buffer).
- **Why:** `build_prps` supports chaining across contiguous list pages
  (`nvme.rs:295-316`), but the driver allocates exactly one list page. A chunk
  needing more than 511 data-page entries (i.e. `> 2 MiB` at 4 KiB pages) would
  fail `build_prps` with `ListTooSmall`, which `transfer` maps to
  `BlockError::InvalidInput` (`driver.rs:341`), failing every large transfer. This
  is unreachable today only because `mdts_limit` is hard-capped at `128 KiB`
  (`driver.rs:314`). The cap is load-bearing and undocumented.
- **Minimal fix:** size the list allocation and buffer from the page count, e.g.
  `let entries = (list_pages - 1).max(1); let list_pages_needed = entries.div_ceil(PAGE_SIZE / 8);`
  allocate `list_pages_needed * PAGE_SIZE` bytes and
  `alloc::vec![0u64; list_pages_needed * (PAGE_SIZE / 8)]`. Alternatively, add a
  comment asserting the 128 KiB cap is what keeps the list within one page.

## 7. Per-chunk commands

The chunk loop advances by whole blocks and recomputes the LBA from the block
offset (`driver.rs:320-360`), submitting exactly one I/O command per chunk via
`submit_io` (`driver.rs:349-353`). Each chunk gets its own CID and its own
completion (synchronous poll), and the next chunk's DMA is not allocated until
the previous command has completed, so no buffer is freed while the device may
still be reading it. **OK.** Covered by
`mdts_chunking_submits_per_chunk_commands_with_correct_lba_and_nlb`
(300 blocks -> 256 + 44, NLB 255 and 43, LBA 20 and 276).

## 8. Transfer bounds (no I/O on rejection)

`lba.checked_add(blocks).filter(|end| *end <= block_count)` rejects overflowing
or past-end ranges with `BlockError::OutOfRange` (`driver.rs:301-307`) *before*
any allocation or `submit_io`. **OK.** Covered by
`write_past_block_count_is_out_of_range_without_io_submission`, which asserts
the command count, I/O doorbell count, and DMA region count are all unchanged.

## 9. Empty / non-block-multiple input

`data.is_empty() || !data.len().is_multiple_of(block_size)` -> `InvalidInput`
(`driver.rs:296-298`) before bounds and before I/O. **OK.** Covered by
`empty_and_non_block_multiple_buffers_are_invalid_input`.

## 10. Write completion status -> DeviceError

`submit_io` advances the completion head (and phase on wrap), rings the CQ
doorbell, then returns `BlockError::DeviceError` for any nonzero status
(`driver.rs:392-403`). **OK.** Covered by
`nonzero_write_completion_maps_to_device_error`.

## 11. Flush

`flush` submits opcode `0x00` with NSID 1 and no PRP (`driver.rs:432-439`);
`submit_io` handles it identically to a payload command and the device replies
with a normal completion. **OK.**

## 12. Observation (non-blocking): redundant copy in `write_blocks`

`write_blocks` does `buffer.to_vec()` (`driver.rs:429`) solely to satisfy
`transfer`'s `&mut [u8]` parameter, which the write path never mutates. For a
128 KiB chunk this doubles transient kernel memory. Not a correctness defect;
a write-specific path taking `&[u8]` would remove it.

---

## Required corrections

- **NEEDS-FIX (latent, §6):** single-page PRP list allocation is correct only
  under the 128 KiB MDTS cap; make the list sizing derive from the page count
  (or document the invariant). No runtime impact at `ef359ec`.
- All other reviewed items: **OK**.
