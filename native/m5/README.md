# native/m5: M5 encrypted objects and security layer in C

C port (gnu11, no outside libraries, no heap/clock/I/O in the library) of the
M5 reference in `crates/aienos-kernel/src/crypto/envelope.rs` and
`crates/aienos-kernel/src/security.rs`, built on `native/crypto`
(AES-256-GCM-SIV, HMAC-SHA-256, constant-time compare, wipe) and
`native/argus/sha256.c`. Target: the M5 table in
`docs/TRUST-1-M5-GATE-MATRIX.md` and the Q rows of
`docs/M5_KEY_HIERARCHY_DESIGN_TREE.md`.

```
make test       # rule tests, corruption matrix, header fuzz, owner-signed migration
                # (AIENOS_M5_MIGRATION_SIG: PASS, M5_MIGSIG_TOOL: PASS); last line M5_NATIVE: PASS
make sanitize   # same, and the tool test, under ASan + UBSan
make mutants    # each GUARD-tagged refusal removed in turn; tests must fail
make clean
```

All tests are host-only (hosted libc test program); nothing here runs in QEMU
or on the Spark, and nothing measures time or energy.

## What is covered

| Requirement | Code | Tests |
|---|---|---|
| Owner-controlled key hierarchy | `m5_derive_subkeys` (K_vol -> identity/owner-generation root -> K_cortex, K_agent, K_artifact, K_root_auth), `m5_derive_object_key`, `m5_keyslot_wrap/unwrap`, `m5_secman_seal/open` (root-auth MAC, `owner_hierarchy_generation` field) | `t_hkdf_rfc5869_case1`, `t_subkeys_deterministic_and_separated`, `t_object_key_binds_every_field`, `t_keyslot_wrap_unwrap`, `t_keyslot_refusals`, `t_secman_*` (incl. `t_secman_roundtrip_rust_v1_layout`) |
| AES-256-GCM-SIV object envelopes | `m5_envelope_seal/open/parse_header` | `t_env_roundtrip_sizes`, `t_env_rust_v1_header_and_standard_aad`, `t_env_header_bounds_each_field`, `t_env_hostile_header_fuzz` (20 000 random/edge headers, exact-size heap buffers under ASan) |
| All-or-nothing open | `m5_envelope_open`, `m5_recover_object` zero the whole caller buffer on every error | `t_all_or_nothing_late_chunk_failure_zeroes_output`; every refusal test asserts an all-zero buffer |
| Corruption matrix | | `t_corrupt_header`, `t_corrupt_first_chunk`, `t_corrupt_middle_chunk`, `t_corrupt_last_chunk`, `t_corrupt_commit_record`, `t_corrupt_rollback_anchor`, `t_corrupt_key_generation`, `t_corrupt_store_generation`, `t_commit_check_object`, `t_truncate_drop_last_chunk`, `t_extend_append_chunk`, `t_reorder_chunks`, `t_splice_cross_object` |
| Anti-rollback anchors | `m5_anchor_seal/open`, `m5_evaluate_anti_rollback` | `t_anchor_caller_buffer_roundtrip`, `t_rb_*` |
| Production/test identity separation | identity class in the hierarchy key (so in every object key and K_root_auth MAC), plus an explicit class byte in commit record, anchor and migration; open/verify take a mode | `t_identity_production_refuses_test`, `t_identity_test_refuses_production`, `t_identity_relabel_breaks_mac` |
| Migration authorization (MAC-bound) | `m5_migration_seal/authorize` | `t_mig_*` |
| Migration authorization (owner-signed, Ed25519) | `m5_owner_migration_body/sign_body/sign/verify`, `m5_envelope_set_digest`, `m5_migration_authorize_owner`; CLI `tools/m5_migsig.c` | `tests/m5_migsig_test.c` (13 tests, `AIENOS_M5_MIGRATION_SIG: PASS`), `tests/m5_migsig_tool_test.sh` (`M5_MIGSIG_TOOL: PASS`) |
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
- **Per-object keys** (C only; Rust `seal_envelope` takes the key directly):
  `HKDF-Expand(domain subkey, "AIENOS/M5/OBJECT-KEY-V2\0" || store_uuid || kind || version || envelope_id || key_generation || class)`.
  No ObjectId and no Store generation, per AGENTS.md section 3.
- **Keyslot descriptor**: same 128-byte layout and decode bounds as Rust.
  The wrap AAD is stronger: `"AIENOS-M5-KEYSLOT-V2\0" || store_uuid || slot_id || slot_type || key_epoch`
  (Rust: `slot_id` only). Decode and unwrap also refuse a wrap_suite other than
  0x01 (Empty may hold 0), kdf_suite above 0x02 and any flag bit (ADR 0017;
  Rust does not check these). KeySlotManifest (kind 21) itself is not ported.
- **SecurityManifest**: byte-compatible with Rust kind-22 v1 (`AIENSEC1`,
  version 1, 256 bytes, fields 16..224, MAC at 224 with domain
  `"AIENOS-M5-ROOT-AUTH-V1\0"`; `t_secman_roundtrip_rust_v1_layout` checks the
  layout and recomputes the MAC by hand). Decision: a separate `AIENSEC2` is
  not needed, because the two M5 additions (identity class and owner hierarchy
  generation) are already bound by the key: K_root_auth is derived from
  `class || owner_hierarchy_generation`, so a manifest from the other class or
  another owner generation fails its MAC (`t_identity_*`).
- **Envelope**: byte-compatible with Rust V1. 64-byte header (`AIENENV1`,
  version 1, suite 1, flags 0, chunk_size at 16, total at 20, envelope_id at
  28, nonce_prefix at 44, key_epoch = key generation at 52, reserved at 60),
  nonce `nonce_prefix || chunk_index`, chunk count derived from length and
  chunk size. Chunk AAD is exactly the AGENTS.md Standard Envelope AAD (111
  bytes, `t_env_rust_v1_header_and_standard_aad`):
  `"AIENOS-M5-CHUNK-V1\0" || store_uuid || kind u16 || version u16 || 64-byte header || chunk_index u32 || chunk_len u32`.
  The whole header (total length, envelope id, key generation) sits in every
  chunk's AAD and the key is per object, so reorder, truncate, extend, header
  edits and splices across objects, kinds, stores, classes or key generations
  fail. Bounds before use: chunk size 1..65536, plaintext <= 64 MiB, at most
  4096 chunks (C-only cap; Rust has none), total length must match exactly.
  Like Rust, each chunk is decrypted into a private 64 KiB stack scratchpad
  and copied out only after its tag verifies; on any failure the whole caller
  buffer is wiped, so a verified prefix never survives as partial success.
- **Commit record** (C only, `AIENCMT1` version 2, 144 bytes): binds, after
  sealing, the object binding (class, kind, version, store, envelope id, key
  generation), the **Store generation**, counter, object sequence and the
  **ObjectId = SHA-256 of the encrypted bytes**, MAC
  `"AIENOS-M5-COMMIT-V2\0"`. `m5_commit_check_object` refuses bytes whose
  digest differs (TORN) or whose header names another envelope id or key
  generation (BINDING). Store and key generation corruption is refused here
  and by the anchor (`t_corrupt_key_generation`, `t_corrupt_store_generation`,
  `t_commit_check_object`). An immutable envelope can be referenced by a
  commit of a later Store generation without re-encryption.
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
  (`"AIENOS-M5-MIGRATION-V2\0"`). This is a post-seal attestation, so the
  store generation in it does not conflict with AGENTS.md section 3. Refuses
  wrong key, any binding mismatch, source == destination, and a counter not
  above the last accepted one. The Rust 64-byte `offline_signature` field is
  dropped; the owner signature is the separate record below.
- **Owner-signed migration record** (C only, `AIENOMG1` version 1, 272
  bytes, layout in `m5.h`): identity class, owner key id (SHA-256 of the
  owner public key), agent root, source and destination store, source store
  generation, store format version, envelope count and envelope-set digest
  (`SHA-256("AIENOS-M5-ENVSET-V1\0" || n || ObjectIds in strictly ascending
  order)`), SHA-256 of the MAC'd migration manifest, migration counter, owner
  hierarchy generation, then a pure Ed25519 signature (native/sig) over
  `"AIENOS-M5-OWNER-MIGRATION-V1\0" || bytes[0..208]`. Verification refuses
  a wrong length (BOUNDS), bad magic/version/flags/reserved/class (FORMAT,
  even under a valid signature), another class (IDENTITY), another key, a
  key id that does not match the trusted key, an unsigned or tampered record
  (AUTH), any field the verifier does not expect or source == destination
  (BINDING), and a counter not above the last accepted one (REPLAY).
  `m5_migration_authorize_owner` requires both records: the manifest MAC
  under the source K_root_auth and an owner record naming that exact
  manifest digest and the same counter, stores, agent root and generations.
- **`tools/m5_migsig`** (hosted CLI): `pubkey`, `body` (from a key=value
  spec), `sign SECRET_KEY_FILE BODY OUT`, `verify PUBLIC_KEY_FILE RECORD
  SPEC LAST_COUNTER`. It never creates a key. The secret key is read only
  from the given path (32 raw bytes, 64 hex digits or unencrypted Ed25519
  PKCS#8 DER, mode 0600 or tighter), so the real signature can be made only
  in the offline Gate 3 ceremony, for example after
  `openssl pkey -in owner_root.pem -outform DER -out <file on tmpfs>`.
  Tests use freshly generated random keys named `TEST-ONLY-*` and delete
  them; the tool test also cross-checks the public key and the signature
  against openssl when it is installed (an outside tool used only as a test
  oracle, never linked).

## Host-only, and what remains

- **Anchor persistence** is a caller-provided buffer only. On hardware it
  must be TPM NV, which is blocked on TRUST-1 Gate 6.
- **Sealed volume keys**: keyslot wrap/unwrap is done in software with a
  caller KEK. Real TPM sealing of K_vol (PolicyAuthorize) is TRUST-1 Gate 6
  (policy from Gate 5).
- **Owner-signature binding: host-tested with TEST keys only; the real
  owner signature is BLOCKED_OPERATOR on the Gate 3 offline key ceremony.**
  The signature primitive is `native/sig` (in-house Ed25519, #188). The
  record and the tool exist and are tested, but no record has been signed
  with the real owner key, nothing in the Store or boot path calls
  `m5_migration_authorize_owner` yet (needs the C disk layer), and no
  trusted owner public key is provisioned anywhere.
- **Binding to the Gate 3 Owner Root**: the hierarchy carries an owner
  hierarchy generation, but nothing ties K_vol to the Gate 3 Owner Root yet.
- **Store integration** needs the C disk layer: recovery here works on a
  commit record, an anchor and in-memory candidate envelopes; it does not read
  or repair a disk and does not touch `native/store`.
- Recovery KDF (Argon2id / WebAuthn PRF) and KeySlotManifest lineage are not
  ported.

## AGENTS.md section 3 (resolved)

Chunk AAD is the V1 Standard Envelope AAD, and no ObjectId or Store generation
enters any chunk AAD, object key or MAC body before sealing. Store and key
generation are bound after sealing by the commit record and the anchor;
ObjectId is the SHA-256 of the encrypted bytes and is referenced from the
commit record.
