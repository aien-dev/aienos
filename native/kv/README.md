# native/kv: persistent-KV codec and slab store (cuts N1 and N2 of aienos#367)

The C twin of the Rust crate `aien-kv-store` in sovereign-core (ADR 0003,
persistent KV identity, storage contract and ownership).

Scope of N1 (`kv_record.h`, `kv_record.c`):
- Encodes, decodes and validates the 256-byte KV record header, the 4096-byte
  header region (header, segment digest table, zero padding), the
  compute-config-aware namespace id, the prefix-chained chunk keys, and the
  native 4096-byte slot header unit with its mapping into M5 (envelope id and
  nonce prefix).

Scope of N2 (`kv_slab.h`, `kv_slab.c`):
- `kv_disk_bind`: binds a contiguous region of 4096-byte units on a `disk_dev`
  (512-byte or 4096-byte sectors) and refuses any LBA overlap with the Store or
  Anchor regions (`KV_E_SLAB_OVERLAP`) or invalid geometry (`KV_E_SLAB_GEOMETRY`).
- `kv_slab_format`: zeroes all `N` slot header units (unit 0 of each slot) and
  issues `disk_flush`.
- `kv_slab_recover`: bounded header-only recovery (`N` reads of 4 KiB at unit 0
  of each slot, zero payload reads, zero writes, zero flushes). Validates each
  slot header without key material, treats any torn or corrupt header as an
  empty slot, and counts `used_bytes = slot_units * 4096` for every valid slot
  across all namespaces while `kv_slab_lookup` serves only `local_namespace`.
- `kv_slot_writer` (`kv_slot_write_begin`, `kv_slot_write_step`,
  `kv_slot_write_cancel`, `kv_slab_write_slot`, `kv_slab_read_slot`):
  command-stepped header-last write order (`ZERO_HDR` -> `FLUSH_ZERO` ->
  `WRITE_PAYLOAD` -> `FLUSH_PAYLOAD` (`KV_STAGE_COMPLETED`) -> `WRITE_HDR`
  (`KV_STAGE_PUBLISHED`) -> `FLUSH_HDR` (`KV_STAGE_DURABLE`)) and slot readback
  with trailing zero-padding enforcement (`KV_E_SLOT_PADDING`).

Nothing here touches physical hardware (`aienos#336`). Host tests run over
memory buffers and `native/disk/disk_file.c`.

## Build and test

    make -C native/kv test          # pin check, slot vector regen, 36 record + 9 slab tests
    make -C native/kv sanitize      # same tests under ASan + UBSan (Linux)
    make -C native/kv mutants       # delete each GUARD rule in turn; 78 of 78 killed
    make -C native/kv freestanding  # no libc: nm -u of the combined relocatable is empty

Pass markers: `AIENOS_KV_RECORD_NATIVE`, `AIENOS_KV_SLAB_NATIVE`,
`AIENOS_KV_SANITIZE`, `AIENOS_KV_MUTANTS`, `AIENOS_KV_FREESTANDING`
(each `: PASS`).

## Files

- `kv_record.h`, `kv_record.c`: N1 codec and slot header unit. No heap, clock,
  I/O, float or static state.
- `kv_slab.h`, `kv_slab.c`: N2 slab partition binding, format, bounded
  recovery, lookup, and header-last slot writer/reader over `native/disk/disk.h`.
  No heap, clock, direct libc I/O, float or static state.
- `tests/kv_record_test.c`, `tests/json_min.h`: N1 codec and golden vector tests.
- `tests/kv_slab_test.c`: N2 slab tests over `disk_file` (512B and 4096B blocks),
  including block-boundary power-cut sweeps and D3 Sealed Store coexistence.
- `tests/golden/kv_record_v1.json`: byte-for-byte copy of sovereign-core's
  `crates/aien-kv-store/tests/golden/kv_record_v1.json`.
- `tests/golden/kv_slot_v1.json`, `tests/gen_slot_vectors.sh`: the slot header
  vectors, produced by an independent shell generator (printf, xxd, sha256sum,
  openssl HMAC), not by the C code. `make test` regenerates and compares.
- `CONTRACT.lock`: the pin (sc commit, vectors_sha256, slot_vectors_sha256).

## Claims and their status

- VERIFIED: header, region, namespace id (including compute_config_digest as
  field 14), chunk key chain and payload root reproduce every vector in
  `kv_record_v1.json` bit for bit.
- VERIFIED: validation, `kv_disk_bind`, and `kv_slab_recover` perform zero heap
  allocations (proven both by GNU ld `--wrap` counters over `malloc`, `calloc`,
  `realloc` and by `nm -u` on `kv_record.o` and `kv_slab.o`).
- VERIFIED: `kv_disk_bind` refuses any LBA overlap between the KV slab, Store,
  and Anchor regions across both 512-byte and 4096-byte block devices.
- VERIFIED: `kv_slab_recover` issues exactly `N` 4 KiB reads at the `N` slot
  header LBAs and zero payload reads, zero writes, and zero flushes; any torn
  or corrupt header unit is recovered as an empty slot; `used_bytes` counts
  `slot_units * 4096` physical bytes across all valid slots regardless of
  namespace while `kv_slab_lookup` never returns foreign-namespace slots.
- VERIFIED: power cut at every block boundary (`0 .. total_blocks + 1`) during
  initial slot write and during overwrite of a valid slot never exposes a
  partial or mixed record on subsequent recovery.
- VERIFIED: D3 host coexistence (`n2_existing_store_gates_pass_with_slab_present`):
  formatting, writing, power-cutting, recovering, and reformatting a KV slab on
  the tail of a disk image leaves the Anchor and Sealed Store regions byte-for-byte
  untouched and Store open/read/transact operations intact.
- INFERRED: slot rules ADR 2.5 states but does not spell out as an algorithm:
  a slot must carry `backend_format == 2` (native f32 decode state); the slot
  decode check order; `slot_incarnation != 0` and `sealed_units <= slot_units - 1`
  for a valid occupied slot.
- UNKNOWN: behaviour against a real NVMe or SD device (`aienos#336` untouched).

## DOCS SILENT on

- DOCS SILENT on the exact NUL count in the HKDF info labels and the envelope
  id domain label; the code uses the label plus one NUL, as the ADR writes
  `\0`. Pinned only by `kv_slot_v1.json`, which this directory generates, so
  sovereign-core should confirm.
- DOCS SILENT on the slot decode check order (see INFERRED above).
- DOCS SILENT on the `backend_format == 2` requirement for slots.
- The Rust `FieldTooLong` variants carry a field name; the C error code drops
  the name.
- C-only policy: `KV_E_ARG`, `KV_E_CRYPTO`, and `KV_E_IO`..`KV_E_LATE_CANCEL`
  (`-31`..`-36`).

## Bumping the pin

1. Read the new sovereign-core commit's `README.md` for the new `vectors_sha256`.
2. Copy `kv_record_v1.json` byte for byte; check with `cmp` and `sha256sum`.
3. Update `sc_commit` and `vectors_sha256` in `CONTRACT.lock`.
4. Run `bash tests/gen_slot_vectors.sh tests/golden/kv_record_v1.json >
   tests/golden/kv_slot_v1.json`, then update `slot_vectors_sha256`.
5. `make test sanitize mutants freestanding`. The test refuses to run if either
   hash disagrees with the lock.

Current pin: sovereign-core `cd5be4c` (branch `pkv/484-persistent-kv`).
