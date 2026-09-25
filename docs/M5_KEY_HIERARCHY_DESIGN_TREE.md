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

## 2. Settled Decisions (Round 1)

| Question | Decision | Core Architectural Invariant |
|---|---|---|
| **Q1: Encryption Boundary** | **Option C′ (Object Envelopes + Keyed SecurityManifest)** | Store v1 superblocks, CommitRecords, Catalogs, CRC32C, and generation semantics remain 100% frozen and unmodified. Application objects are wrapped in authenticated AEAD envelopes. A keyed `SecurityManifest` / `RootAuth` object authenticates the commit graph. Unkeyed inspection works in Recovery Core. |
| **Q2: Key Hierarchy** | **Option B′ (Independent `K_vol` + Multi-Slot Wrapping)** | `K_vol` is generated as an independent 256-bit random secret during provisioning. Slot 0 wraps `K_vol` via TPM 2.0 PCR authorization (owner-updatable via `PolicyAuthorize`). Slot 1 wraps `K_vol` via operator break-glass `K_recovery`. Domain-separated keys (`K_cortex`, `K_agent`, `K_artifact`, `K_root_auth`) derive from `K_vol` via HKDF-SHA256. `K_operator_auth` (ADR 0006 command authority), `K_recovery` (data decryption break-glass), and `K_vol` remain strictly separated. |
| **Q3: Cipher Suite** | **Option D (AES-256-GCM-SIV, RFC 8452)** | Nonce-misuse-resistant AEAD across cold boots, power loss, retries, and branching. 256-bit keys, 96-bit random nonces, 128-bit authentication tags. Streaming chunked authenticated envelope to avoid buffering large payloads in kernel memory. Software baseline first; ARMv9.2-A AES/POLYVAL acceleration later. |
| **Q4: Anti-Rollback** | **Option C′ (`AntiRollbackSource` Abstraction)** | Kernel introduces `trait AntiRollbackSource` with explicit `RollbackAnchor` semantics. Hardware-independent qualification in QEMU via mocks/swTPM. Physical NV / RPMB backend deferred until DGX Spark hardware characterization under TRUST-1. Rollback detection halts into `RecoveryRequired::RollbackDetected`, prohibiting normal agent continuation. |

---

## 3. The Active Frontier (Round 2)

```text
Round 2 Frontier
 ├── Q5: Chunked Authenticated Envelope Layout & Streaming AAD
 ├── Q6: Keyslot Object Representation in Store v1
 ├── Q7: KDF Parameterization for Operator Break-Glass (K_recovery)
 ├── Q8: Anti-Rollback Epoch Cadence & Anchor Granularity
 └── Q9: Key Re-wrapping vs. Full Re-encryption Semantics
```
