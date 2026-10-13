# native/kv: persistent-KV record codec (cut N1 of aienos#367)

The C twin of the Rust crate `aien-kv-store` in sovereign-core (ADR 0003,
persistent KV identity, storage contract and ownership). It encodes, decodes
and validates the 256-byte KV record header, the 4096-byte header region
(header, segment digest table, zero padding), the compute-config-aware
namespace id, the prefix-chained chunk keys, and the native 4096-byte slot
header unit with its mapping into M5 (envelope id and nonce prefix).

Scope of N1: the codec only. No disk I/O, no store, no scheduler. Nothing here
touches hardware, QEMU images or the hardware gate (aienos#336).

## Build and test

    make -C native/kv test          # pin check, shell regeneration of slot vectors, 36 tests
    make -C native/kv sanitize      # same tests under ASan + UBSan (Linux)
    make -C native/kv mutants       # delete each GUARD rule in turn; the tests must fail
    make -C native/kv freestanding  # no libc: nm -u of the combined relocatable is empty

Pass markers: `AIENOS_KV_RECORD_NATIVE`, `AIENOS_KV_SANITIZE`,
`AIENOS_KV_MUTANTS`, `AIENOS_KV_FREESTANDING` (each `: PASS`). They run in
`.github/workflows/native-suites.yml`. These are host runs over memory buffers,
not a disk or device qualification.

## Files

- `kv_record.h`, `kv_record.c`: the codec. No heap, clock, I/O, float or static
  state. SHA-256 is `native/argus/sha256.c` (no new hash); HKDF is `native/m5`;
  HMAC is `native/crypto`.
- `tests/kv_record_test.c`, `tests/json_min.h`: hosted tests and a strict
  minimal JSON reader for the vector files.
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
- VERIFIED: validation refuses before any allocation. Two proofs: a GNU ld
  `--wrap` counter over malloc, calloc and realloc during 26 corrupted-record
  cases (with a negative control that the counter does fire), and `nm -u` on
  the library object showing no heap symbol. The counter is Linux/GNU ld only.
- VERIFIED: the check order follows `validate.rs`: length, magic, version,
  kind, header_len, checksum, flags, namespace, key, parent, position, token
  range, token mismatch, geometry, partial flag, payload_len, segment count,
  padding, root, file size.
- VERIFIED: the slot envelope header (offsets 256..320) equals what
  `m5_envelope` itself writes, and the slot bounds table equals M5's.
- INFERRED: slot rules ADR 2.5 states but does not spell out as an algorithm:
  a slot must carry `backend_format == 2` (native f32 decode state); the slot
  decode check order (length, unit checksum, padding, record header, backend,
  envelope header fields, total_plaintext_len, sealed_units, envelope_len,
  slot index).
- UNKNOWN: behaviour against a real NVMe or SD device. N1 never touches one.

## DOCS SILENT on

- DOCS SILENT on the exact NUL count in the HKDF info labels and the envelope
  id domain label; the code uses the label plus one NUL, as the ADR writes
  `\0`. Pinned only by `kv_slot_v1.json`, which this directory generates, so
  sovereign-core should confirm.
- DOCS SILENT on the slot decode check order (see INFERRED above).
- DOCS SILENT on the `backend_format == 2` requirement for slots.
- The Rust `FieldTooLong` variants carry a field name; the C error code drops
  the name.
- C-only policy: `KV_E_ARG` (NULL pointers, enum values the Rust types cannot
  hold, short output capacity) and `KV_E_CRYPTO`. Rust has no equivalent.
- `kv_slot_v1.json` is owned by this directory, not by sovereign-core. The
  header part is derived from the sc vector `native-f32-partial-tail`.

## Bumping the pin

1. Read the new sovereign-core commit's `README.md` for the new `vectors_sha256`.
2. Copy `kv_record_v1.json` byte for byte; check with `cmp` and `sha256sum`.
3. Update `sc_commit` and `vectors_sha256` in `CONTRACT.lock`.
4. Run `bash tests/gen_slot_vectors.sh tests/golden/kv_record_v1.json >
   tests/golden/kv_slot_v1.json`, then update `slot_vectors_sha256`.
5. `make test sanitize mutants freestanding`. The test refuses to run if either
   hash disagrees with the lock.

Current pin: sovereign-core `cd5be4c` (branch `pkv/484-persistent-kv`). That
commit was not yet on sovereign-core main when N1 was written.
