# AIENOS: Technical Specification & Contracts (Phases 3 – 5)

> **Status:** Architecture Blueprint Extension
> **Target:** Native Agent Wakeup, Epistemic Memory, Capability Enforcement, and C1 Branch-Native Compute
> **Authority:** AIENOS Final Architectural Blueprint §§ 9–14, 17–19, 28

---

## 1. Overview & Phased Roadmap

This specification establishes the formal data structures, interface boundaries, and invariant contracts for the three evolutionary phases succeeding Native Bare-Metal Boot (Phase 2):

```text
Phase 2 (Substrate)      Phase 3 (Continuity)       Phase 4 (Intelligence)      Phase 5 (Sovereignty)
┌─────────────────┐      ┌─────────────────────┐    ┌─────────────────────┐     ┌─────────────────────┐
│  AIENOS Kernel  │ ───► │  Persistent Agent   │──► │ AEGIS & J-Worlds    │ ──► │ Direct GB10 Path    │
│  no_std aarch64 │      │  Agent State ABI    │    │ Capability Graph    │     │ Hardware C1 VMM     │
│  UART / MMIO    │      │  Cortex Epistemic   │    │ C1 Prefix Tree (§28)│     │ A/B/C Benchmarks    │
└─────────────────┘      └─────────────────────┘    └─────────────────────┘     └─────────────────────┘
```

---

## 2. Phase 3: The Persistent Agent Wakes Up

### 2.1 The Agent State ABI (§9)

The foundational principle dictates: **Losing physical inference state costs computation, not identity.**
The Agent State ABI separates persistent semantic identity from ephemeral execution incarnations.

```text
LogicalAgentId (UUID v7 / Ed25519 public key)
      │
      ├── LogicalBranchId (Deterministic UUID / SHA-256 derivation)
      │     ├── ParentBranchId: Option<LogicalBranchId>
      │     ├── TokenHistory: Append-only log of token sequence IDs & hashes
      │     ├── Lineage: Tree path from root Genesis Agent
      │     └── EpistemicRefs: Set of Cortex observation/fact UUIDs
      │
      ▼
Execution Incarnation (Ephemeral per boot/process)
      │
      ├── IncarnationId: u64 (Monotonic boot counter)
      ├── SequenceId: u32 (Scheduler slot)
      └── PhysicalInferenceState:
            ├── KVPageTableRef: Option<PhysicalPageTablePtr>
            ├── AcceleratorBufferRef: Option<BufferHandle>
            └── ComputeState: Idle | Prefilling | Decoding | Suspended | Evicted
```

#### Core ABI Operations
```rust
pub trait AgentStateAbi {
    /// Fork an existing logical branch into an isolated child branch
    fn fork_branch(&self, parent: LogicalBranchId) -> Result<LogicalBranchId, StateError>;

    /// Checkpoint logical agent state to durable storage
    fn checkpoint(&self, agent_id: LogicalAgentId) -> Result<CheckpointHash, StateError>;

    /// Suspend execution incarnation without mutating logical state
    fn suspend(&mut self, branch_id: LogicalBranchId) -> Result<(), StateError>;

    /// Resume execution, re-instantiating physical state via recompute or cache
    fn resume(&mut self, branch_id: LogicalBranchId) -> Result<SequenceId, StateError>;

    /// Reconstruct lost physical state from TokenHistory and EpistemicRefs
    fn reconstruct_physical(&mut self, branch_id: LogicalBranchId) -> Result<(), StateError>;
}
```

### 2.2 Model ABI (§14)

Models are swappable intelligence components, not the operating system or root of trust.

```rust
pub trait ModelAbi {
    type Token;
    type Logits;

    /// Query static architecture metadata
    fn metadata(&self) -> ModelMetadata;

    /// Initialize prompt prefill context
    fn prefill(&mut self, tokens: &[Self::Token], state: &mut PhysicalInferenceState) -> Result<(), ModelError>;

    /// Decode the next token step
    fn step(&mut self, state: &mut PhysicalInferenceState) -> Result<Self::Logits, ModelError>;

    /// Tokenize text to internal token IDs
    fn tokenize(&self, text: &str) -> Vec<Self::Token>;

    /// Detokenize IDs back to UTF-8
    fn detokenize(&self, tokens: &[Self::Token]) -> String;
}
```

### 2.3 Cortex Epistemic Store (§11)

Cortex preserves knowledge with verifiable provenance, preventing self-reinforcing hallucination.

```rust
#[repr(u8)]
pub enum EpistemicStatus {
    DirectObservation = 1, // Raw sensor / hardware / file input
    VerifiedFact      = 2, // Mathematically / cryptographically proven
    Inference         = 3, // Model deduction from observations
    Hypothesis        = 4, // Tentative exploration branch
    Contradiction     = 5, // Detected epistemic conflict
    OperatorDecision  = 6, // Canonical directive from operator
}

pub struct EpistemicRecord {
    pub id: Uuid,
    pub status: EpistemicStatus,
    pub statement: String,
    pub provenance_source: String,
    pub evidence_hash: [u8; 32],
    pub created_at_utc: u64,
    pub confidence: f32,
    pub verified_by: Option<String>,
}
```

---

## 3. Phase 4: Native System Intelligence (AEGIS, Worlds & Capabilities)

### 3.1 The Capability Graph (§13)

Traditional process permissions are replaced with unforgeable capability tokens arranged in a directed acyclic capability graph.

```text
root.authority (Operator)
   │
   ├── cap::filesystem [scope: /projects, mode: rw]
   ├── cap::network    [scope: local-fabric, port: 8080]
   ├── cap::model      [model: Llama-3.2-1B, max_tokens: 4096]
   ├── cap::device     [device: MMIO_UART, access: read_write]
   └── cap::world      [action: create, max_depth: 4]
```

### 3.2 AEGIS Effect Intent Pipeline (§5)

Intelligence proposes; deterministic authority disposes. The model cannot authorize itself.

```text
AIEN Reasoning Loop
        │
        ▼ (Proposes action)
   EffectIntent {
       action: "publish_code",
       parameters: { repo: "aienos-repo", commit: "..." },
       claimed_capability: "cap::git::publish"
   }
        │
        ▼
   AEGIS Evaluator
   ├── 1. Cryptographic validation of capability token
   ├── 2. Verification of operator policy (Is action reversible?)
   │       ├── Reversible (Inside World)  ──► Auto-Approve
   │       └── Irreversible (External)    ──► Solicit Operator Approval
   │
   ▼ (Approved)
   EffectBroker
        │ (Dispatches to native device / driver)
        ▼
   Hardware / Network / Disk Effect
```

### 3.3 J-Space Worlds (§12)

A World is an isolated, transactional sandbox with copy-on-write semantics:
- Modifications to files, memory, and runtime state are isolated to a delta layer.
- Rollback is instantaneous via pointer drop.
- Promotion to canonical state requires an explicit `PromoteWorldIntent` verified by AEGIS.

---

## 4. Phase 5: Native Hardware Acceleration & Hardware-Bound C1 Compute

### 4.1 Hardware-Accelerated C1 Copy-On-Write Engine (§10, §19, §28)
> *Note:* The algorithmic C1 Copy-On-Write prefix tree data structure and §28 invariants are established in Phase 4 (`crates/aienos-c1-tree`); Phase 5 binds physical KV page frames directly to the NVIDIA Blackwell GB10 accelerator over NVLink-C2C.

Instead of replicating common prefix KV states across $N$ parallel reasoning branches, AIENOS maintains a shared physical prefix tree:

```text
Root Prefix: System Prompt + Codebase Context (100K Tokens)
Physical Address: [Page 0x1000 .. 0x4000] (RefCount: 3)
                     │
         ┌───────────┼───────────┐
         ▼           ▼           ▼
      Branch 1    Branch 2    Branch 3
      (Plan A)    (Plan B)    (Plan C)
      [Private]   [Private]   [Private]
      Page 0x5000 Page 0x6000 Page 0x7000
```

#### Invariant Matrix:
1. **Zero Duplication**: Shared prompt tokens map to identical physical KV pages.
2. **Deterministic Divergence**: Allocation of private pages occurs strictly upon divergent token generation.
3. **Eviction Independence**: Children preserve semantic identity even if physical KV pages are evicted to RAM or disk; reconstruction re-executes deterministically from the last checkpoint.

### 4.2 Hardware Sovereignty: 3-Way Benchmark Suite (§19)

Performance is measured systematically across three configurations:
- **Config A**: Reference baseline on Ubuntu 24.04 LTS (frozen in Phase 1).
- **Config B**: Minimal Linux compatibility island.
- **Config C**: Native AIENOS bare-metal substrate.

```text
Benchmark Metrics:
1. Power-On to Agent Ready (ms)
2. Agent Ready to Model Inference Ready (ms)
3. Time-to-First-Token (TTFT) across 1K, 16K, 128K context
4. Sustained Token Generation (tokens/sec)
5. Branch Fork Overhead (microseconds to branch 100K context)
6. Scheduler Jitter (microseconds at 99.9th percentile)
7. Physical Memory Overhead per Concurrent Agent Branch (MiB)
```

---

## 5. Verification & Acceptance Criteria for Next Phases

- [ ] `AgentStateAbi` supports deterministic serialization and deserialization across reboot.
- [ ] Epistemic store detects and rejects ungrounded self-reinforcing assertions.
- [ ] AEGIS sandbox rejects any irreversible effect originating from an unapproved intent.
- [ ] C1 COW tree demonstrates zero memory increase when branching a 10,000-token prefix across 10 concurrent exploratory branches.
- [ ] Machine-readable evidence logs accompany all measured performance claims.
