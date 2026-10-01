# native/store: torn_slot, Store v1 C twin, sealed store

All C (gnu11), no outside library, offline. Library objects use no heap, no
clock and no I/O except through `disk_dev` / `st_dev` / `ts_device`; every
buffer is a caller-provided workspace (`st_workspace` about 0.9 MiB,
`ss_workspace` about 2.0 MiB, both meant for static storage).

| file | what |
|---|---|
| `torn_slot.c/.h` | dual-slot torn-write-safe 4096-byte record (unchanged) |
| `store_v1.c/.h` | Store v1 format (ADR 0015): ObjectId, CRC32C, catalog, commit record, superblock, genesis |
| `store_engine.c/.h` | `Store::open` / `transact` / `read_object` twin of `crates/aienos-kernel/src/store/engine.rs` |
| `store_disk.c` | unit adapter over `native/disk`: 512-byte blocks = 8 per unit, 4096 = 1, base LBA, no read-modify-write |
| `store_sealed.c/.h` | M5 sealed store (envelopes + transaction records + anchor) |
| `store_mem.c` | `mem*` for the freestanding build only |

## What the C twin covers

* Format primitives and genesis, byte for byte.
* Open: Valid and DegradedRecovery; every MountError (Io, Unformatted,
  Foreign, UnsupportedVersion, CorruptRecoveryRequired, ConflictingRoots,
  InconsistentHistory) and every PeerCondition (Zero, Valid, Malformed,
  GraphBadNewer, GraphBadOlder); `select_two` and the append-transition rules.
* Transact with the exact Rust write and flush order and checkpoint hook:
  objects, catalog, commit record, flush, inactive superblock, flush. Every
  StoreError, including poisoned -> NeedsReopen.
* Adapter refuses other block sizes, unaligned bases and regions past the end.

## Byte-identity evidence

* Golden vectors (`docs/adr/0015-golden-vectors.json`): all 89 JSON rows are
  turned into a C table by `tests/gen_golden.sh` (POSIX sh + awk) and every
  row is checked in both directions. A C transaction from the genesis vector
  reproduces the `adjacent_generations` units byte for byte.
* All Rust negative tests ported: `store_v1_negative.rs` (10), the
  `v1.rs` malformed cases and the 14 `engine.rs` tests, plus C-only cases.
* C -> Rust (`tests/rust_crosscheck.sh`, 48 checks, 512 and 4096 geometry):
  the Rust `aienos-store-tool` runs `tear-closure`, `corrupt-kind` and all 8
  `inject` cases on images the C engine wrote; the C engine then gives the
  same mount or refusal as Rust's own `Store::open`. Tool built from aienos
  7b023f6; the store and tool sources are identical at origin/main 913b962.
* Rust -> C: no Rust-written image is used. That direction is covered by the
  golden vectors only.
* Discrepancy found by reading (not run in Rust): Rust `preflight`
  binary-searches the catalog after appending unsorted new entries, so a
  request of [new X with a smaller id, existing Y] can miss Y and append it
  twice. C searches only the old catalog and deduplicates; tested in C.

## Sealed store layout (`store_sealed.h`)

* Device: anchor region of 4 units (torn_slot) outside the Store region.
* Kind `0x0510` = M5 envelope (AES-256-GCM-SIV, 4096-byte chunks, at most
  16 KiB plaintext, 8 objects per transaction). Kind `0x0511` = sealed
  transaction record. Existing kinds are 1, 2 and 16 to 23; no collision.
* Record `AIENSTX1`: version (2; a version-1 record is refused with
  `SS_E_FORMAT_VERSION`, reformat), identity class, count, store uuid, Store
  generation, counter (= generation), key generation, SHA-256 of the previous
  record (zero at generation 2), then per object the Store ObjectId and the
  144-byte M5 commit record (binds uuid, kind, envelope id, generation,
  counter, sequence, SHA-256 of the envelope), then
  HMAC(k_root_auth, "AIENOS-STORE-SEALED-TX-V1\0" || body).
* Envelope id (16 bytes) and nonce prefix (8 bytes), record version 2 =
  the first 24 bytes of HMAC(k_envid, "AIENOS-SEALED-ENVID-V2\0" || uuid ||
  generation u64 || index u32 || kind u16 || version u16 || key_generation
  u64 || identity_class u8 || plaintext_len u64 || SHA-256(plaintext)),
  k_envid = HKDF-Expand(k_domain, "AIENOS-SEALED-ENVID-KEY-V2\0"). The
  envelope id also feeds the per-object key, so the AES-GCM-SIV (key, nonce)
  pair of every chunk is a keyed function of the plaintext.
  Why (Lane 26, 2026-10-01): version 1 used SHA-256(uuid || generation ||
  index), so after a whole-disk rollback (undetected without TPM NV) a
  rewrite of the same generation with different bytes reused the (key,
  nonce) pair. GCM-SIV keeps confidentiality under that reuse except for
  equal messages, but the store promised unique nonces and the margin was
  not worth keeping. Now only the identical object at the same place gives
  the identical envelope (a retried generation after a crash, or a rewrite
  after rollback), which shows nothing the old image did not already show.
  No entropy source is needed, so the library stays clock-, heap- and
  RNG-free and the kernel call sites are unchanged. `ss_read` recomputes
  the rule after decrypting and refuses an envelope whose id or nonce
  prefix does not match it (`SS_E_ENVELOPE`).
* Anchor record `AIENSAN1`: class, uuid, then the 120-byte `m5_anchor`
  (counter = Store generation, digest = SHA-256 of the newest record).

Mount: `st_open` -> `ts_recover` -> verify every record (class, uuid, MAC,
exactly one per generation 2..G, linked digests, every envelope claimed once
with a matching digest, no other kinds) -> `m5_evaluate_anti_rollback`.
An empty anchor is accepted only at generation 1.

Commit order: (1) if the anchor lags, write the anchor for the current
generation; (2) seal envelopes and the record; (3) `st_transact` (Store
generation G+1 durable); (4) `ts_commit` the anchor for G+1. A crash between
(3) and (4) mounts as "prepared advance" (anchor one behind) and step (1) of
the next transaction catches it up. Proven by a power cut at every block
boundary.

Refused: Store rolled back under the anchor, anchor two behind, a missing
anchor, a forked anchor, two anchor slots with one sequence, PRODUCTION/TEST
mix, another store's anchor, other volume key, swapped / unclaimed / tampered
envelopes, plaintext objects, generation skip, stale commit record, replayed
record, broken chain, two records for one generation, an envelope claimed twice,
a version-1 transaction record (`SS_E_FORMAT_VERSION`) and, at read, an
envelope whose id or nonce prefix does not follow the version-2 rule.

## Tests

`make test` (ends with `AIENOS_STORE_NATIVE: PASS|FAIL`), `make sanitize`
(ASan + UBSan over all tests), `make mutants` (`TORN_SLOT_MUTANTS` and
`AIENOS_STORE_MUTANTS`), `make freestanding` (`nm -u` closes over the sibling
native objects), `make lib-checks`. All runs are host emulation over files.

Every `/* GUARD:name */` line in the four store sources is a mutant: `make
mutants` deletes it and requires some store test to fail. Three Rust-parity
checks are deliberately untagged because no input can reach them alone:
the engine's root commit-id comparison (the superblock-to-commit match
refuses the same case first), the adjacent-generations check (the
predecessor check requires the same thing) and DuplicateObjectConflict inside one request
(equal ObjectIds with different kind, version or bytes need a SHA-256
collision).

## Not done

* Kernel binding: nothing here is linked into the kernel or a boot path.
* Physical NVMe qualification: not run; nothing here claims it.
* Whole-disk rollback: the anchor is on the same disk, so rolling back both
  regions together is not detected (a test records this). That needs TPM NV
  (TRUST-1).
* Key rotation, more than 8 objects or 16 KiB per sealed transaction, and
  repair of a DegradedRecovery mount (it stays read-only, as in Rust).
