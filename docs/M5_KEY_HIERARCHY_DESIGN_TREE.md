# M5: Key Hierarchy, Envelope Encryption, and Identity Design Tree

> **Status:** Architectural Decision Tree / Grilling Round Scaffold  
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

## 2. The M5 Design Tree

```text
M5 Root
 ├── 1. Encryption Boundary & Layering
 │    ├── Option A: Object-level AEAD envelope (Payloads encrypted, metadata plaintext)
 │    ├── Option B: Full virtual block-level encryption (LUKS/dm-crypt style)
 │    └── Option C: Hybrid (AEAD payloads + Superblock-authenticated catalog AAD) [RECOMMENDED]
 │
 ├── 2. Key Hierarchy & Root of Trust
 │    ├── Option A: Pure TPM 2.0 sealed boot key
 │    ├── Option B: Dual-path hierarchy (TPM seal + Operator break-glass KEK) [RECOMMENDED]
 │    └── Option C: Attended passphrase on every cold start
 │
 ├── 3. Symmetric Cipher Suite
 │    ├── Option A: ChaCha20-Poly1305 (RFC 8439, pure software, constant-time) [RECOMMENDED]
 │    ├── Option B: AES-256-GCM (ARMv8-A Cryptography Extensions / PMULL)
 │    └── Option C: Dual-mode (ChaCha20 for bootstrap/QEMU, AES-GCM accelerated for bulk)
 │
 ├── 4. Anti-Rollback Binding
 │    ├── Option A: TPM 2.0 Monotonic NV Counter increment per Store commit
 │    ├── Option B: Dynamic PCR extension / policy re-sealing per commit
 │    └── Option C: Abstracted kernel interface; swTPM in QEMU, active under TRUST-1 [RECOMMENDED]
 │
 ├── 5. Key Derivation & Stretching (Round 2 Frontier)
 │    ├── Algorithm: Argon2id vs. HKDF-SHA256 vs. PBKDF2-HMAC-SHA256
 │    └── Salt Sources: Store UUID + Hardware Entropy (RNDR / TPM RNG)
 │
 └── 6. Keyslot Metadata & On-Disk Format (Round 3 Frontier)
      ├── Superblock v2 vs. Dedicated Crypto Header Region
      └── Maximum keyslots and key retirement policy
```

---

## 3. Round 1 Frontier: Foundational Architecture

### Decision 1: Encryption Boundary & Layering
- **Option A (Object AEAD Envelope)**: Payloads encrypted with a symmetric AEAD cipher; object descriptors, kinds, and superblocks remain plaintext.
- **Option B (Full Block Encryption)**: Virtual disk layer encrypting every block. Completely conceals metadata, but breaks unkeyed Recovery Core inspection.
- **Option C (Hybrid)**: Store v1 dual superblocks and catalog indexing remain unencrypted for deterministic inspection and tear recovery. All object payloads are AEAD-encrypted. Superblock commits bind an HMAC/AEAD authentication tag over the entire catalog using generation-dependent AAD.
- **Recommendation**: **Option C**.

### Decision 2: Root-of-Trust & Key Hierarchy Separation
- **Master Storage Key (MSK)**: 256-bit symmetric key that never touches persistent disk in plaintext.
- **Key Slots**:
  - `Slot 0 (Automated TPM Boot)`: MSK encrypted with `K_tpm`, sealed to TPM 2.0 Storage Root Key under PCR policy {PCR 0, PCR 7, PCR 11, PCR 12}.
  - `Slot 1 (Operator Break-Glass)`: MSK encrypted with `K_recovery`, derived from an operator-held passphrase/seed using a hardened KDF.
- **Recommendation**: **Option B (Dual-Path)**.

### Decision 3: Cipher Suite Selection
- **ChaCha20-Poly1305** requires zero hardware coprocessors, runs constant-time in pure `no_std` Rust, and avoids microarchitectural side-channels on shared cores.
- **AES-256-GCM** provides maximum throughput when ARMv8 Crypto Extensions are present, but adds complexity in bootstrap EL2/EL1 transitions.
- **Recommendation**: **Option A (ChaCha20-Poly1305)** as format baseline; optional AES-GCM cipher ID in object headers for bulk acceleration later.

### Decision 4: Hardware Anti-Rollback Binding
- Store v1 generation counter increments monotonically in software, but physical NVMe media can be overwritten with an old raw image.
- Physical anti-rollback requires hardware state outside the disk: a TPM 2.0 NV counter index or RPMB (Replay Protected Memory Block).
- **Recommendation**: **Option C**. Define `AntiRollback` trait in kernel; verify in QEMU with swTPM NV indices; enforce as a hard gate on Machine 1 under TRUST-1.

---

## 4. Operational Invariants for M5

1. **Zero Interpreter Policy**: All cryptographic primitives and KDFs must compile as native `no_std` Rust within `aienos-kernel` or `aienos-crypto`.
2. **Deterministic Halt on Bad Unseal**: If TPM unseal fails (due to PCR mismatch or tampering), the boot must immediately halt into the read-only Recovery Core (ADR 0006). It must never boot into an unkeyed fallback state with write capability.
3. **Commit-Before-Observation**: Any update to keyslots or crypto metadata must follow Store v1 two-phase commit rules.
