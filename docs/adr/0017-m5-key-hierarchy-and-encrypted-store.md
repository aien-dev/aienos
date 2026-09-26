# ADR 0017: M5 Key Hierarchy, Encrypted Envelopes, and Storage Security Roots

Status: **Proposed.** Normative specification for Milestone M5 (Encryption and Identity).  
Related: [ADR 0006](0006-deterministic-recovery-core-and-offline-operator-authority.md) (Recovery Core), [ADR 0007](0007-continuous-existence-provisioning-once.md) (Provisioning Once), [ADR 0015](0015-system-store-v1-format.md) (System Store v1), [ADR 0016](0016-continuity-objects-over-store-v1.md) (Continuity Objects), [TRUST-1-IMPLEMENTATION-PLAN.md](../TRUST-1-IMPLEMENTATION-PLAN.md).

---

## 1. Context

Milestone M4 established persistent agent continuity across cold restarts in QEMU over System Store v1 ([ADR 0015](0015-system-store-v1-format.md), [ADR 0016](0016-continuity-objects-over-store-v1.md)) and qualified deterministic Recovery Core inspection and offline repair ([ADR 0006](0006-deterministic-recovery-core-and-offline-operator-authority.md)). However, Store v1 provides only structural crash integrity over raw NVMe; all application payloads currently reside in plaintext on disk, and Store v1 explicitly disclaims anti-rollback protection against a malicious raw-disk adversary.

Milestone M5 establishes the cryptographic security architecture of AIENOS:
1. **Confidentiality at rest**: Agent state, Cortex memories, checkpoints, credentials, and artifacts must be unreadable without authorization.
2. **Hardware-sealed unattended boot**: Unattended boots unseal storage keys strictly when firmware and kernel measurements satisfy an authorized TPM 2.0 policy.
3. **Attended break-glass recovery**: An offline operator must retain cryptographic recovery capability without compromising unattended boot security or relying on vendor backdoors.
4. **Hardware anti-rollback**: Replay of a valid earlier raw disk image must be detected and halted.
5. **Preservation of recovery invariants**: Storage encryption must never prevent unkeyed Recovery Core diagnosis of a degraded or corrupted physical store.

---

## 2. Decision

### 2.1 The Separation of Proofs

AIENOS strictly decouples physical consistency, keyed authorization, and hardware freshness into three independent verification stages:

```text
1. Store v1 Structural Validation (Unkeyed)
   "These on-disk bytes form a self-consistent Store v1 transaction history."
   Evaluates: Dual superblocks, active generation, CommitRecords, Catalogs, CRC32C checksums.
   Guarantees: Crash safety, tear closure, degraded peer recovery.
        ↓
2. M5 Keyed Authentication (Requires K_vol)
   "This Store history was committed by an authorized holder of K_vol."
   Evaluates: KeySlotManifest (kind 21) unwrap, SecurityManifest (kind 22) HMAC-SHA256 root tag,
              AES-256-GCM-SIV per-object chunk authentication.
   Guarantees: Authenticity and confidentiality of application payloads.
        ↓
3. Anti-Rollback Freshness Validation (Requires AntiRollbackSource)
   "This authorized Store history is not an older replay."
   Evaluates: Hardware off-disk anchor {store_uuid, epoch, security_root_digest}.
   Guarantees: Replay protection bounded to the last anchored security epoch.
```

Store v1 superblocks, CommitRecords, Catalogs, CRC32C, and generation semantics remain 100% frozen and unmutated as defined in [ADR 0015](0015-system-store-v1-format.md).

---

### 2.2 Key Hierarchy & Separation of Authority

1. **Volume Master Secret (`K_vol`)**:
   - An independent, high-entropy 256-bit random secret generated once during initial store provisioning.
   - `K_vol` is never written to persistent media in plaintext.
2. **Keyslots**:
   - `Slot 0 (Automated TPM Boot)`: `K_vol` wrapped under `K_tpm_kek` via AES-256-GCM-SIV. `K_tpm_kek` is sealed to the TPM 2.0 Storage Root Key (SRK) under an authorized PCR policy.
   - `Slot 1 (Operator Break-Glass)`: `K_vol` wrapped under `K_recovery_kek` via AES-256-GCM-SIV. `K_recovery_kek` is derived from an offline recovery secret or passphrase.
3. **Subkey Derivation via HKDF-SHA256**:
   All operational keys derive deterministically from `K_vol` with strict domain separation:
   ```text
   K_cortex    = HKDF-Expand(K_vol, "AIENOS/M5/CORTEX-V1", 32)
   K_agent     = HKDF-Expand(K_vol, "AIENOS/M5/AGENT-STATE-V1", 32)
   K_artifact  = HKDF-Expand(K_vol, "AIENOS/M5/ARTIFACT-V1", 32)
   K_root_auth = HKDF-Expand(K_vol, "AIENOS/M5/ROOT-AUTH-V1", 32)
   ```
4. **Three Independent Cryptographic Roles**:
   - `K_operator_auth`: Proves operator authority to execute Recovery Core commands ([ADR 0006](0006-deterministic-recovery-core-and-offline-operator-authority.md)).
   - `K_recovery`: Cryptographic break-glass secret used to derive `K_recovery_kek` and unwrap storage.
   - `K_vol`: Internal volume master key protecting encrypted Store objects.
   Possessing one credential never grants automatic possession of the others.

---

### 2.3 Cipher Suite: AES-256-GCM-SIV Chunked Envelopes

To prevent catastrophic confidentiality failure under power loss, retries, cold boots, and branch-native execution incarnations, AIENOS standardizes on **AES-256-GCM-SIV** (RFC 8452) as its primary at-rest AEAD suite.

#### Envelope Framing
Each encrypted object payload is wrapped in a chunked envelope:
```text
Offset  Size  Field
0       8     magic = "AIENENV1"
8       2     envelope_version = 1
10      2     cipher_suite = 0x0001 (AES_256_GCM_SIV)
12      4     flags = 0
16      4     chunk_size = 65536 (64 KiB)
20      8     total_plaintext_len (u64le)
28      16    envelope_id (128-bit random identifier)
44      8     nonce_prefix (64-bit random prefix)
52      8     key_epoch (u64le)
60      4     reserved = 0
```

Followed sequentially by $N$ encrypted chunks:
```text
[Chunk 0 Ciphertext][Chunk 0 Tag: 16 B] ... [Chunk N Ciphertext][Chunk N Tag: 16 B]
```

#### Deterministic Nonce Derivation
For each chunk index $i \in [0, N]$:
$$\text{nonce}_i = \text{nonce\_prefix}[8] \parallel i\text{:u32le}$$

#### Per-Chunk Additional Authenticated Data (AAD)
To prevent cross-object splicing, chunk reordering, truncation, and cross-store replay:
$$\text{AAD}_i = \text{"AIENOS-M5-CHUNK-V1\0"} \parallel \text{store\_uuid} \parallel \text{object\_kind:u16le} \parallel \text{object\_version:u16le} \parallel \text{header\_64B} \parallel i\text{:u32le} \parallel \text{chunk\_plaintext\_len}_i\text{:u32le}$$

Store v1 content-addresses the object by computing its standard `ObjectId = SHA-256(complete_ciphertext_envelope)`.

**Security Invariant**: The kernel must verify each 64 KiB chunk's 16-byte authentication tag in a private scratchpad before releasing decrypted plaintext to callers. The scratchpad is securely zeroed on tag verification failure.

---

### 2.4 KeySlotManifest (`kind = 21`)

`KeySlotManifest` is a plaintext Store v1 system object that bootstraps storage decryption. It is not encrypted under `K_vol`.

```text
Offset  Size  Field
0       8     magic = "AIENKSL1"
8       2     format_version = 1
10      2     flags = 0
12      16    store_uuid
28      8     manifest_sequence (u64le)
36      32    previous_keyslot_manifest_id (ObjectId, 0 for genesis)
68      8     active_key_epoch (u64le)
76      4     slot_count (u32le, max 4)
80      48    reserved = 0
128     4×128 KeySlotDescriptors (512 B total)
640     var   Payload Arena (max 32 KiB)
```

Each 128-byte `KeySlotDescriptor`:
```text
slot_type (u8): 0=Empty, 1=TPM2_PolicyAuthorize, 2=Recovery_Argon2id, 3=Recovery_RawSecret
wrap_suite (u8): 0x01 = AES_256_GCM_SIV
kdf_suite (u8):  0x00 = None, 0x01 = KDF_ARGON2ID_V1, 0x02 = HKDF_SHA256
flags (u8)
slot_id (u32le)
key_epoch (u64le)
salt (16 B)
argon_m_kib (u32le)
argon_t_cost (u32le)
argon_p_cost (u32le)
wrap_nonce (12 B)
wrapped_k_vol (32 B)
wrap_tag (16 B)
payload_offset (u32le, relative to start of Payload Arena)
payload_length (u32le)
reserved (16 B)
```

#### Recovery KDF Profiles
1. **Passphrase Profile (`KDF_ARGON2ID_V1`)**:
   - $m = 65536\text{ KiB}$ (64 MiB), $t = 3$, $p = 4$, salt = 16 bytes, output = 32 bytes (RFC 9106).
   - Executed inside a reserved Recovery Core memory arena; memory is explicitly zeroed immediately after derivation.
   - Decoders strictly validate that $m \le 131072\text{ KiB}$ and $t \le 10$ to prevent denial-of-service.
2. **High-Entropy / WebAuthn PRF Profile**:
   $$\text{K\_recovery\_kek} = \text{HKDF-SHA256}(\text{salt} = \text{slot.salt}, \text{ikm} = \text{raw\_secret}, \text{info} = \text{"AIENOS/M5/RECOVERY-KEK-V1"}, \text{len} = 32)$$

---

### 2.5 SecurityManifest (`kind = 22`)

`SecurityManifest` is a 256-byte fixed-size Store v1 object that authenticates authorized logical state under `K_root_auth`:

```text
Offset    Size  Field
0..8      8     magic = "AIENSEC1"
8..10     2     format_version = 1
10..12    2     flags = 0
12..16    4     reserved = 0
16..32    16    store_uuid
32..40    8     generation (u64le, equals Store superblock generation)
40..48    8     security_sequence (u64le, strictly monotonic)
48..56    8     epoch (u64le, anti-rollback security epoch)
56..64    8     key_epoch (u64le)
64..96    32    previous_security_manifest_id (ObjectId, 0 for first)
96..128   32    keyslot_manifest_id (ObjectId)
128..160  32    agent_root_id (ObjectId)
160..192  32    continuity_manifest_id (ObjectId)
192..224  32    migration_manifest_id (ObjectId, 0 if unmigrated)
224..256  32    root_mac (HMAC-SHA256)
```

$$\text{root\_mac} = \text{HMAC-SHA256}(K_{\text{root\_auth}}, \text{"AIENOS-M5-ROOT-AUTH-V1\0"} \parallel \text{bytes}[0..224])$$

To break the content-addressing dependency cycle, `SecurityManifest` intentionally omits the current generation's `commit_record_id`. The Store transaction engine links `SecurityManifest` into the Catalog, whose root is referenced by the CommitRecord.

---

### 2.6 Anti-Rollback Semantics & Security Epochs

**Theorem**: *To detect replay of committed state against a malicious raw-disk adversary, trusted state outside the replayable disk must advance for every protected commit boundary.*

1. **Security Epoch**: The smallest group of Class-A commits that AIENOS permits to become externally authoritative before their root is anchored outside replayable storage.
2. **Commit Ordering**:
   ```text
   Step 1: Commit Store v1 generation G with epoch E+1 and SecurityManifest digest H.
   Step 2: Flush Store v1 durably to media (NVMe FLUSH).
   Step 3: Advance AntiRollbackSource to {store_uuid, E+1, H}.
   Step 4: Release external effects (Effect Broker dispatch, external observation).
   ```
3. **Boot Validation Protocol**:
   - $\text{disk\_epoch} == \text{anchor\_epoch} \land \text{disk\_digest} == \text{anchor\_digest} \implies \text{Normal resume}$.
   - $\text{disk\_epoch} == \text{anchor\_epoch} + 1 \implies \text{Prepared unanchored epoch; freeze external observation, complete anchor update}$.
   - $\text{disk\_epoch} < \text{anchor\_epoch} \implies \text{Halt with RecoveryRequired::RollbackDetected}$.
   - $\text{disk\_epoch} == \text{anchor\_epoch} \land \text{disk\_digest} \ne \text{anchor\_digest} \implies \text{Halt with RecoveryRequired::RollbackDetected}$.
   - $\text{disk\_epoch} > \text{anchor\_epoch} + 1 \implies \text{Halt with RecoveryRequired::InconsistentEpoch}$.

Replay detection halts into `RecoveryRequired::RollbackDetected`, strictly prohibiting automatic agent continuation.

---

### 2.7 Key Rotation vs. Store Migration

1. **Policy / Credential Rotation ($O(1)$)**:
   Updating PCR policy or changing operator passphrases unwraps `K_vol`, writes a new `KeySlotManifest` with updated wrapped keyslots, increments `security_sequence`, and commits a new `SecurityManifest`. No encrypted application objects are re-encrypted.
2. **`K_vol` Compromise (Out-of-Band Migration)**:
   In-place re-encryption cannot revoke confidentiality because Store v1's append-only design leaves historical ciphertext on disk. When `K_vol` is compromised:
   - Live state is decrypted from the source Store.
   - Transferred to a fresh Store container with a new `store_uuid` and new $K_{\text{vol}}'$.
   - An authorized `MigrationManifest` (kind = 23) is signed by the TRUST-1 offline Owner Authority.
   - The target Store imports the identical `AgentRoot` (`genesis_store_uuid` preserved) and resumes continuity at `migration_parent_id`.

---

### 2.8 TPM 2.0 `PolicyAuthorize` Integration

Slot 0 unsealing uses TPM 2.0 `PolicyAuthorize` to allow firmware and kernel measurements to evolve without invalidating the sealed key:

1. **Dedicated Policy Signing Key**:
   The offline TRUST-1 Owner Root issues an authorized credential for a dedicated TPM Policy Authorization Key whose public area Name is pinned in Slot 0.
2. **Offline Authorization**:
   The operator computes the approved `PolicyPCR` digest for an update bundle, signs the policy digest with the Policy Authorization Key, and embeds the signature, approved policy digest, and `policyRef` (`"AIENOS/M5/STORE-UNLOCK/POLICY-V1" || store_uuid || slot_id`).
3. **Runtime Verification**:
   ```text
   TPM Policy Session Started
         ↓
   TPM2_PolicyPCR(actual PCRs)
         ↓
   TPM2_VerifySignature(keySign, approvedPolicy, signature) → checkTicket
         ↓
   TPM2_PolicyAuthorize(approvedPolicy, policyRef, keySign, checkTicket)
         ↓
   TPM2_Unseal(Slot 0) → K_tpm_kek
         ↓
   AES-256-GCM-SIV unwrap K_vol
   ```
4. **Empirical PCR Policy**:
   The exact PCR selection mask is not hard-coded; it is determined empirically by the TRUST-1 Gate 2 measurement campaign on Machine 1 hardware.
