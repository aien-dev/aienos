# native/m5: M5 encrypted objects and security layer in C

C port (gnu11, no outside libraries, no heap/clock/I/O in the library) of the
M5 reference in `crates/aienos-kernel/src/crypto/envelope.rs` and
`crates/aienos-kernel/src/security.rs`, built on `native/crypto`
(AES-256-GCM-SIV, HMAC-SHA-256, constant-time compare, wipe) and
`native/argus/sha256.c`. Target: the M5 table in
`docs/TRUST-1-M5-GATE-MATRIX.md` and the Q rows of
`docs/M5_KEY_HIERARCHY_DESIGN_TREE.md`.

```
make test       # rule tests, corruption matrix, header fuzz; last line M5_NATIVE: PASS
make sanitize   # same under ASan + UBSan
make mutants    # each GUARD-tagged refusal removed in turn; tests must fail
make clean
```

All tests are host-only (hosted libc test program); nothing here runs in QEMU
or on the Spark, and nothing measures time or energy.

## What is covered

| Requirement | Code | Tests |
|---|---|---|
| Owner-controlled key hierarchy | `m5_derive_subkeys` (K_vol -> identity/owner-generation root -> K_cortex, K_agent, K_artifact, K_root_auth), `m5_derive_object_key`, `m5_keyslot_wrap/unwrap`, `m5_secman_seal/open` (root-auth MAC, `owner_hierarchy_generation` field) | `t_hkdf_rfc5869_case1`, `t_subkeys_deterministic_and_separated`, `t_object_key_binds_every_field`, `t_keyslot_wrap_unwrap`, `t_keyslot_refusals`, `t_secman_*` (incl. `t_secman_distinct_from_rust_v1`) |
| AES-256-GCM-SIV object envelopes | `m5_envelope_seal/open/parse_header` | `t_env_roundtrip_sizes`, `t_env_header_bounds_each_field`, `t_env_hostile_header_fuzz` (20 000 random/edge headers, exact-size heap buffers under ASan) |
| All-or-nothing open | `m5_envelope_open`, `m5_recover_object` zero the whole caller buffer on every error | `t_all_or_nothing_late_chunk_failure_zeroes_output`; every refusal test asserts an all-zero buffer |
| Corruption matrix | | `t_corrupt_header`, `t_corrupt_first_chunk`, `t_corrupt_middle_chunk`, `t_corrupt_last_chunk`, `t_corrupt_commit_record`, `t_corrupt_rollback_anchor`, `t_corrupt_key_generation`, `t_corrupt_store_generation`, `t_truncate_drop_last_chunk`, `t_extend_append_chunk`, `t_reorder_chunks`, `t_splice_cross_object` |
| Anti-rollback anchors | `m5_anchor_seal/open`, `m5_evaluate_anti_rollback` | `t_anchor_caller_buffer_roundtrip`, `t_rb_*` |
| Production/test identity separation | identity class in key derivation, envelope header, chunk key, SecurityManifest, commit record, anchor and migration MACs; open/verify take a mode | `t_identity_production_refuses_test`, `t_identity_test_refuses_production`, `t_identity_relabel_breaks_mac` |
| Migration authorization (MAC-bound) | `m5_migration_seal/authorize` | `t_mig_*` |
| Deterministic recovery (object level) | `m5_recover_object` | `t_recovery_*` |

## Formats and where they differ from the Rust reference

All integers little-endian, all reserved bytes must be zero, every MAC is
HMAC-SHA-256 under K_root_auth over `domain || bytes`, compared in constant time.

- **Subkeys.** `m5_derive_subkeys_v1` is byte-compatible with Rust
  `derive_subkeys` (HKDF-Expand of K_vol with the same labels). The M5 path,
  `m5_derive_subkeys`, first derives
  `K_class = HKDF-Expand(K_vol, "AIENOS/M5/OWNER-HIERARCHY-V2\0" || class || owner_hierarchy_generation)`
  and applies the v1 labels to K_class. Rust has no identity class or owner
  generation.
- **Per-object keys** (new): `HKDF-Expand(domain subkey, "AIENOS/M5/OBJECT-KEY-V2\0" || store_uuid || kind || version || object_id || key_generation || store_generation || class)`.
- **Keyslot descriptor**: same 128-byte layout and decode bounds as Rust.
  The wrap AAD is stronger: `"AIENOS-M5-KEYSLOT-V2\0" || store_uuid || slot_id || slot_type || key_epoch`
  (Rust: `slot_id` only). Decode and unwrap also refuse a wrap_suite other than
  0x01 (Empty may hold 0), kdf_suite above 0x02 and any flag bit (ADR 0017;
  Rust does not check these). KeySlotManifest (kind 21) itself is not ported.
- **SecurityManifest**: a separate C v2 format, magic `AIENSEC2`, 264 bytes
  (Rust kind-22 v1: `AIENSEC1`, 256 bytes). Byte 12 is the identity class
  (Rust: reserved), `owner_hierarchy_generation` at 224, MAC at 232 with domain
  `"AIENOS-M5-ROOT-AUTH-V2\0"`. The two formats never cross-read: each reader
  refuses the other by size and magic (`t_secman_distinct_from_rust_v1`).
  Compatibility path: an existing v1 manifest must be re-sealed as v2 under the
  owner root-auth key; that converter is not written yet, and which format the
  store adopts is a lead decision.
- **Envelope**: magic `AIENENV1`, version 2, 80-byte header (Rust v1: 64).
  Adds `store_generation` (60), explicit `chunk_count` (68, must equal the
  value implied by length and chunk size) and identity class (72); `envelope_id`
  is the object id, `key_epoch` is the key generation. Nonce is unchanged
  (`nonce_prefix || chunk_index`). Chunk AAD is
  `"AIENOS-M5-CHUNK-V2\0" || store_uuid || kind || version || header || index || count || last_flag || chunk_len`
  and the chunk key is the per-object key, so chunks cannot be reordered,
  truncated, extended or spliced across objects, stores or generations.
  Bounds before use: chunk size 1..65536, plaintext <= 64 MiB, at most 4096
  chunks, total length must match exactly. Like Rust, each chunk is decrypted into a private
  64 KiB stack scratchpad and copied out only after its tag verifies; on any
  failure the whole caller buffer is wiped as well, so a verified prefix never
  survives as partial success.
- **Commit record** (new, 144 bytes, `AIENCMT1`): object binding, counter,
  object sequence, SHA-256 of the envelope, MAC (`"AIENOS-M5-COMMIT-V1\0"`).
- **Rollback anchor** (120 bytes, `AIENRBA1`): store generation, key
  generation, monotonic counter, SHA-256 of the commit record, MAC
  (`"AIENOS-M5-ANCHOR-V1\0"`). Rust `RollbackAnchor` was an unauthenticated
  in-memory struct keyed on epoch only. `m5_evaluate_anti_rollback` refuses a
  forged anchor, an older store or key generation, a lower counter, a fork at
  the anchored counter, and a counter more than one ahead; a missing anchor is
  a rollback unless the caller explicitly allows genesis.
- **MigrationManifest**: version 2, 192 bytes, magic `AIENMIG1`. Binds
  identity class, agent root, genesis/source/destination store, source store
  generation, source anchor counter, migration counter, owner hierarchy
  generation and source commit digest under the source K_root_auth
  (`"AIENOS-M5-MIGRATION-V2\0"`). Refuses wrong key, any binding mismatch,
  source == destination, and a counter not above the last accepted one. The
  Rust 64-byte `offline_signature` field is dropped (see below).

## Host-only, and what remains

- **Anchor persistence** is a caller-provided buffer only. On hardware it
  must be TPM NV, which is blocked on TRUST-1 Gate 6.
- **Sealed volume keys**: keyslot wrap/unwrap is done in software with a
  caller KEK. Real TPM sealing of K_vol (PolicyAuthorize) is TRUST-1 Gate 6
  (policy from Gate 5).
- **Owner-signature binding: MISSING_IMPLEMENTATION, needs an in-house
  signature primitive (e.g. Ed25519 in C).** There is none in `native/` or
  `crates/aienos-crypto` (the artifact tool uses the outside `ed25519_dalek`
  crate). Migration is MAC-bound only, which proves the holder of the source
  K_root_auth approved it, not the owner's offline key.
- **Binding to the Gate 3 Owner Root**: the hierarchy carries an owner
  hierarchy generation, but nothing ties K_vol to the Gate 3 Owner Root yet.
- **Store integration** needs the C disk layer: recovery here works on a
  commit record, an anchor and in-memory candidate envelopes; it does not read
  or repair a disk and does not touch `native/store`.
- Recovery KDF (Argon2id / WebAuthn PRF) and KeySlotManifest lineage are not
  ported.

## Recorded discrepancy with repo AGENTS.md section 3 (for the lead)

AGENTS.md section 3 says never to put the content hash (`ObjectId`) or the
Store `generation` into AAD, and fixes the V1 chunk AAD. The M5 lane brief
requires binding object id, key generation and store generation into the
chunk AAD/key so cross-generation splices are refused. This port follows the
brief and keeps the doctrine's intent as far as it can:

- `object_id` here is the caller-chosen logical id (Rust `envelope_id`), not
  the Store `ObjectId = SHA256(ciphertext)`, so there is no circularity.
- `store_generation` is the **write generation** of that object version,
  carried in its commit record. An immutable object sealed at generation 9 is
  still opened at Store generation 12 with the binding from its commit record;
  nothing is re-encrypted per generation.

The chunk AAD is therefore V2, not the V1 text in AGENTS.md. If the lead
decides V1 is binding, drop `store_generation` from the header, AAD and object
key (the store-generation corruption test then relies on the commit record
only).
