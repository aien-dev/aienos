# AIEN OS Recovery Gate — Agent Directives & Architectural Invariants

This document codifies mandatory architectural invariants, cryptographic boundaries, and coding standards for all agents modifying `aienos-recovery-gate`.

---

## 1. The Separation of Proofs Doctrine

Any validation or recovery flow must strictly separate and independently evaluate three distinct integrity boundaries:

1. **Store v1 Structural Integrity (Unkeyed)**:
   - Evaluated by `Store::open()` and Store v1 DAG verification (superblocks, CommitRecords, Catalogs, CRC32C, SHA-256 graph).
   - Validates that bytes form a crash-consistent, non-corrupted Store history.
   - Must operate with zero key material. Informs Recovery Core whether the physical device is valid, degraded, torn, or foreign.
2. **M5 Keyed Authentication (`K_root_auth` / `K_vol`)**:
   - Evaluated after key unseal using `SecurityManifest` (kind 22) HMAC-SHA256 and chunked AEAD envelope Polyval tags.
   - Validates that the Store history and application objects were authorized by the holder of the volume encryption key.
3. **Anti-Rollback Freshness (`AntiRollbackSource` / `RollbackAnchor`)**:
   - Evaluated against hardware-backed monotonic state (TPM NV counter / platform security anchor).
   - Validates that an authorized Store history is not an unauthorized replay of an older state.

**Mandate**: Never merge, shortcut, or conflate these three proofs. A Store that fails structural integrity is physical corruption; a Store that fails keyed authentication is malicious tampering or wrong key; a Store that fails anti-rollback is replay.

---

## 2. Store v1 Format Immutability (ADR 0015 Permanence)

- **Frozen Superblock**: Bytes 172–4095 of the Store v1 superblock are permanently frozen as zero.
- **No In-Band Superblock Tags**: Never place authentication tags, MACs, or encryption headers into the physical superblock.
- **Application Object Encapsulation**: Cryptographic metadata must always reside in standard Store objects:
  - `KeySlotManifest` (`kind = 21`, unencrypted bootstrap descriptor)
  - `SecurityManifest` (`kind = 22`, 256-byte fixed authenticated root)
  - `MigrationManifest` (`kind = 23`, cross-store lineage attestation)
  - Application payloads (`kind = 10..20`) encapsulated in M5 chunked authenticated envelopes.

---

## 3. Elimination of Content-Addressing Circularities

- **No Self-Referential AAD**: Never include an entity's content hash (`ObjectId`) or Store `generation` in the Additional Authenticated Data (AAD) or MAC body before the object is sealed.
  - `ObjectId` is `SHA256(encrypted_object_bytes)`. It does not exist prior to encryption.
  - Store objects are immutable across generations; binding per-object encryption to a single Store generation invalidates cross-generation reuse.
- **Standard Envelope AAD**:
  Every chunk's AEAD AAD must strictly adhere to:
  ```text
  "AIENOS-M5-CHUNK-V1\0"
  || store_uuid: [u8; 16]
  || object_kind: u16le
  || object_version: u16le
  || complete_64_byte_envelope_header: [u8; 64]
  || chunk_index: u32le
  || chunk_plaintext_length: u32le
  ```

---

## 4. Private Scratchpad Verification Invariant

- **Zero Plaintext Leakage**: Streaming authenticated decryption must **never** decrypt ciphertext directly into caller-provided buffers or yield unauthenticated plaintext slices.
- **Scratchpad Flow**:
  1. Decrypt chunk into an internal, isolated scratchpad.
  2. Compute and verify the Polyval authentication tag against the expected tag using constant-time comparison.
  3. Only copy to caller output buffer after tag verification passes.
  4. On tag failure, immediately scrub/zeroize the scratchpad and return `CryptoError::AuthenticationFailed`.

---

## 5. Identity-Preserving Store Migration

- **Immutable `AgentRoot`**: `genesis_store_uuid`, `LogicalAgentId`, `root_branch`, `provisioning_generation`, and `provision_source` never change across migrations.
- **Lineage Boundary**: When migrating to a fresh physical store, `ContinuityManifest` defines a migration boundary:
  - Normal successor: `previous_manifest_id != 0`, `migration_parent_id == 0`.
  - Migration successor: `previous_manifest_id == 0`, `migration_parent_id != 0` (referencing `MigrationManifest`).
  - Chain validation terminates at a cryptographically verified migration boundary without requiring access to old storage.

---

## 6. Engineering & Implementation Standards

- **Zero Interpreter Policy**: The entire kernel, Store, and crypto stack is pure native Rust (`#![no_std]`, no external runtime, zero Python/Node dependencies).
- **Constant-Time Verification**: All cryptographic tag, MAC, and key comparisons must execute in constant time (`subtle::ConstantTimeEq` or constant-time loop).
- **Zeroization**: Cryptographic keys, key schedules, derived subkeys, and scratchpads must be securely zeroized on drop.
- **Idiomatic Rust 2021**:
  - Prefer `as_chunks::<N>()` over `chunks_exact(N)` when chunk length is a const.
  - Prefer `len.is_multiple_of(N)` over `len % N == 0`.
  - Avoid index loops over arrays containing non-Copy / zeroizing elements; use `iter_mut().enumerate()`.
- **Validation Discipline**:
  - All changes must pass `AIENOS_STRICT=1 ./scripts/verify_all.sh` with zero warnings (`cargo clippy --all-targets -- -D warnings`, clean `cargo fmt`).
