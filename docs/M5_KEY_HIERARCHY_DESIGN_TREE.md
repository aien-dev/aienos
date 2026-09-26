# M5: Key Hierarchy, Envelope Encryption, and Identity Design Tree

> **Status:** Architectural Decision Tree & Specification Progress  
> **Milestone:** M5 (Encryption and Identity)  
> **Prerequisites:** M1–M3, SEED-0B, M4 Continuity ([ADR 0016](adr/0016-continuity-objects-over-store-v1.md)), Recovery Core ([ADR 0006](adr/0006-deterministic-recovery-core-and-offline-operator-authority.md), [ADR 0007](adr/0007-continuous-existence-provisioning-once.md)), Store v1 ([ADR 0015](adr/0015-system-store-v1-format.md))  

---

## 1. Executive Summary & Problem Formulation

M4 established that AIEN identity, lineage, and committed memory survive cold restarts over System Store v1 in QEMU. However, all objects on media are currently stored in plaintext.

M5 governs the **confidentiality, integrity sealing, and cryptographic identity** of the persistent agent and machine state:
1. **Confidentiality at rest**: Agent memories, Cortex observations, checkpoints, model parameters, and credentials must be unreadable without authorization.
2. **Hardware binding & sealing**: Unattended boot must verify that the platform firmware and kernel match authorized measurements before decrypting storage.
3. **Emergency break-glass**: An authorized human operator must retain recovery capability even if hardware measurements fail, without relying on persistent manufacturer backdoors.
4. **Anti-rollback enforcement**: An attacker who obtains a bit-for-bit physical disk image from generation $N$ must not be able to rewind state after generation $N+k$ has committed.
5. **Preservation of Recovery Invariants**: Storage encryption must not prevent deterministic inspection or offline repair of a degraded store as proven in ADR 0006.

---

## 2. Settled Architecture (Rounds 1 & 2)

### 2.1 The M5 System Stack

```text
Store v1
    Structural crash integrity (superblocks, dual slots, CRC32C, unmutated v1 format)
        ↓
KeySlotManifest (kind = 21, plaintext)
    Unlock bootstrap (Slot 0: TPM PolicyAuthorize; Slot 1: Recovery KEK wrap)
        ↓
K_vol / Key Epochs
    Independent 256-bit random master volume secret; subkeys derived via HKDF-SHA256
        ↓
AES-256-GCM-SIV Envelopes (64 KiB chunks)
    Confidentiality + per-object streaming authentication
        ↓
SecurityManifest (kind = 22)
    Keyed authentication of logical commit roots, catalogs, and epochs under K_root_auth
        ↓
AntiRollbackSource
    Hardware off-disk replay boundary {store_uuid, epoch, security_root_digest}
        ↓
Recovery Core
    Key recovery, authorization ceremony, migration, and failure authority
```

### 2.2 Settled Decisions Table

| Decision | Verdict | Normative Architectural Specification |
|---|---|---|
| **Q1: Boundary** | **Option C′** | Store v1 format (ADR 0015) superblocks, CommitRecords, Catalogs, CRC32C, and generation semantics remain 100% frozen. No authentication tags in superblocks. Application objects are wrapped in authenticated AEAD envelopes. Keyed `SecurityManifest` (kind = 22) authenticates commit graph. Unkeyed inspection works in Recovery Core. |
| **Q2: Hierarchy** | **Option B′** | `K_vol` is an independent 256-bit random secret generated at genesis. Dual keyslots: Slot 0 (TPM `PolicyAuthorize` owner-updatable unseal), Slot 1 (Operator break-glass `K_recovery`). Domain-separated subkeys derived via HKDF-SHA256 (`K_cortex`, `K_agent`, `K_artifact`, `K_root_auth`). Strict independence between `K_operator_auth`, `K_recovery`, and `K_vol`. |
| **Q3: Cipher Suite** | **Option D** | AES-256-GCM-SIV (RFC 8452). Nonce-misuse-resistant AEAD (256-bit key, 96-bit random nonce, 128-bit tag). Defense-in-depth across power loss, retries, cold boots, and branching. Target hardware: ARMv9.2-A Cortex-A725/X925 on DGX Spark. Software implementation first; assembly/POLYVAL backend later. |
| **Q4: Rollback Abstraction** | **Option C′** | Kernel defines `trait AntiRollbackSource` with `RollbackAnchor { store_uuid, epoch, commit_record_id, security_root_digest }`. Hardware-independent qualification in QEMU via mocks/swTPM. Physical backend deferred until DGX Spark characterization under TRUST-1. Replay failure halts as `RecoveryRequired::RollbackDetected`. |
| **Q5: Chunked Envelope** | **Modified 64 KiB** | 64-byte envelope header (`AIENENV1`, version=1, AES-256-GCM-SIV, chunk_size=65536, total_plaintext_len, 16B envelope_id, 8B nonce_prefix, key_epoch). Nonce: `nonce_prefix[8] \|\| chunk_index:u32le`. Per-chunk AAD: `"AIENOS-M5-CHUNK-V1\0" \|\| store_uuid \|\| kind:u16le \|\| version:u16le \|\| header_64B \|\| chunk_index:u32le \|\| chunk_len:u32le`. Store `ObjectId` is computed over the final ciphertext envelope. Invariant: scratch buffer authenticated before releasing plaintext to caller. |
| **Q6: KeySlotManifest** | **Option A′** | Store v1 object `kind = 21: KeySlotManifest` (plaintext M5 bootstrap object). Contains deterministic lineage (`manifest_sequence`, `previous_keyslot_manifest_id`, `store_uuid`, `active_key_epoch`, `slot_count`, `slots[]`). Evaluated as untrusted-but-structurally-valid input until `K_vol` unwrapped and `SecurityManifest` verified. |
| **Q7: Recovery KDF** | **Option C′** | Dual-mode: Direct high-entropy secret / WebAuthn PRF via HKDF-SHA256 (`AIENOS/M5/RECOVERY-KEK-V1`). Passphrases via Argon2id profile `KDF_ARGON2ID_V1` ($m=64\text{ MiB}, t=3, p=4$, 16B salt). Parameters encoded explicitly in keyslot with strict decoder bounds check. Reserved memory arena; zeroed immediately after derivation; no transparent fallback. |
| **Q8: Security Epochs** | **Option B′** | A Security Epoch is the smallest group of Class-A commits permitted to become externally authoritative before their root is anchored outside replayable storage. Order: 1. Commit Store generation with {epoch E+1, digest H}; 2. Flush durably; 3. Advance `AntiRollbackSource`; 4. Release external effects. Replay check validates `{store_uuid, epoch, digest}`. |
| **Q9: Key Rotation** | **Option C′** | Credential/policy rotation executes as $O(1)$ `KeySlotManifest` rewrap (no object re-encryption). `K_vol` compromise requires out-of-band store migration ceremony to fresh storage (decrypt validated live state, encrypt to fresh Store under fresh `K_vol'`, anchor new storage root). No in-place rekey can revoke historical ciphertext confidentiality. |

---

## 3. The Active Frontier (Round 3)

```text
Round 3 Frontier
 ├── Q10: Identity-Preserving Store Migration & AgentRoot Store-UUID Semantics (ADR 0016 amendment)
 ├── Q11: SecurityManifest (kind = 22) Exact Structure & Keyed Authentication
 ├── Q12: KeySlot Struct Layout inside KeySlotManifest (kind = 21)
 └── Q13: TPM PolicyAuthorize Ceremony & Owner Root PCR Binding
```
