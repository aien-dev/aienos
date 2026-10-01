# C kernel contract: continuity objects and Recovery Core

Status: **SPEC, NOT_RUN.** What has C code (all **host PASS**, QEMU n/a, nothing wired into the kernel):
the codec (cuts 1-2: `svc/continuity_codec.c`, golden vectors, C/Rust decode agreement) and, new in
cut 3, boot **resolution** (`svc/continuity_resolve.c`: P-3 lookup, INV-5 orphan/Conflict, INV-6 chain,
INV-7 references, read-only check), the Recovery Core **challenge**, **state digest** and **operator
HMAC** (same file), and the sealed-Store binding `svc/continuity_resolve_sealed.c`, all run by
`make -C native/kernel test`, `sanitize` and `continuity-mutants` against the REAL sealed Store in a file.
No provision, commit or resume (cut 4), no Recovery Core inspection or actions (cut 5), no wiring. Every C
gate named here stays `NOT_RUN (MISSING_IMPLEMENTATION)` until a forge receipt covers it.
QEMU qualifies nothing physical; nothing here says anything about Machine 1.

Authority:

- aien-architecture ADR 0024, decision Q2 (Accepted 2026-10-01, file
  `docs/adr/0024-rust-scaffolding-omega-destination.md`, fetched at
  aien-architecture commit `64b800b`): continuity and the Recovery Core are
  implemented in C inside the C kernel; "write the contract first, use the
  existing Rust `continuity.rs` and `recovery_core` plus their QEMU campaigns as
  the oracle, then require differential agreement." This file is that contract.
- aienos ADR 0016 (continuity objects, **Proposed**, format version 0 on
  disposable media) and ADR 0006 (Recovery Core, accepted 2026-09-23).
- Ground truth is the Rust code at aienos `4a116e5`. Where ADR 0016 text and
  the Rust code disagree, the code is the oracle and the difference is listed
  in section 9.

Labels used below:

- **CODE** (with `file:line`): what the Rust kernel does today. The C port must
  match it.
- **PROPOSED**: not in any code. A design choice for the C port that a later
  PR or the operator must confirm. Nothing marked PROPOSED is a fact.
- **UNVERIFIED**: a claim about existing C code that this spec did not prove
  by a test; confidence given.

Paths are relative to the aienos repo root. `continuity.rs` means
`crates/aienos-kernel/src/continuity.rs`; `recovery_core.rs` means
`crates/aienos-kernel/src/recovery_core.rs`; `nvme_read.rs` means
`crates/aienos-boot/src/nvme_read.rs`.

---

## 1. On-disk objects the Rust code writes (CODE)

All four kinds are Store v1 objects with Store `version = 1`
(`STORE_OBJECT_VERSION`, continuity.rs:24). Each object starts with a 16-byte
continuity header and the body follows. All integers are little-endian unless
stated. `id` = 32 raw bytes.

### 1.1 Continuity header (16 bytes), continuity.rs:90-95, 105-122

| off | size | field | rule |
|---|---|---|---|
| 0 | 8 | magic | per kind, below |
| 8 | 2 | format_version (u16) | must be `0` (`FORMAT_VERSION`, continuity.rs:26; checked :110) |
| 10 | 2 | reserved (u16) | must be `0` (:115) |
| 12 | 4 | body_len (u32) | must equal total length minus 16 (:118) |

Decoders are strict (continuity.rs:97-166): every read is bounds checked
("truncated object"), every reserved byte must be zero ("nonzero reserved"),
and the whole input must be consumed ("trailing bytes").

### 1.2 Kinds written

| Store kind | const | magic | name | written by |
|---|---|---|---|---|
| 16 | `KIND_AGENT_ROOT` (continuity.rs:19) | `AIENROOT` (:34) | AgentRoot | `provision` only (:721-772) |
| 17 | `KIND_MANIFEST` (:20) | `AIENMANI` (:35) | ContinuityManifest | `provision`, `commit_with_hook` (:837-845) |
| 18 | `KIND_AGENT_STATE` (:21) | `AIENBRAN` (:36) | AgentStateCheckpoint (branch table) | `provision`, `commit_with_hook` when `update.state` is set (:802-812) |
| 20 | `KIND_CORTEX_WAL` (:22) | `AIENCWAL` (:37) | CortexWalSegment | `commit_with_hook` when `update.cortex` is non-empty (:815-826) |

Kinds 19 (`CortexCheckpoint`) and 23 (`MigrationManifest`) appear in ADR 0016
(docs/adr/0016-continuity-objects-over-store-v1.md:40, :42) but **no Rust code
writes or reads them**. They are PROPOSED and out of scope for the C port (section 8).

### 1.3 AgentRoot, kind 16 (body 96 bytes, total 112), continuity.rs:202-247

| off | size | field |
|---|---|---|
| 16 | 32 | agent_id (`LogicalAgentId`) |
| 48 | 16 | store_uuid |
| 64 | 32 | root_branch |
| 96 | 8 | provisioned_generation (u64) = Store generation + 1 at provisioning (:738) |
| 104 | 1 | source: 1 = Operator, 2 = Qualification (:186-191, :224-228) |
| 105 | 7 | reserved, zero |

Decode also refuses `agent_id == 0` ("zero agent id", :231) and
`root_branch != root_branch_id(agent_id)` (:234).

### 1.4 ContinuityManifest, kind 17 (body 120 + 32·n, n ≤ 64), continuity.rs:253-315

| off | size | field |
|---|---|---|
| 16 | 32 | root: AgentRoot ObjectId |
| 48 | 32 | previous: previous manifest ObjectId, zero when none |
| 80 | 8 | sequence (u64) |
| 88 | 8 | incarnation (u64) |
| 96 | 32 | agent_state: AgentState ObjectId, zero when none |
| 128 | 2 | cortex_wal count n (u16), n ≤ `MAX_WAL_SEGMENTS` = 64 (:28, :265, :293) |
| 130 | 6 | reserved, zero |
| 136 | 32·n | cortex_wal: CortexWalSegment ObjectIds, in commit order |

Decode refuses `sequence == 0` and any manifest where `(sequence == 1)` is not
the same as `previous == zero` (:301-305). Largest manifest: 2184 bytes.

### 1.5 AgentState, kind 18 (body 48 + 80·n, 1 ≤ n ≤ 256), continuity.rs:321-482

| off | size | field |
|---|---|---|
| 16 | 32 | agent_id |
| 48 | 8 | written_at (u64): manifest sequence it was written in (:334, set at :808; genesis uses 1, :743) |
| 56 | 4 | branch count n (u32), 1 ≤ n ≤ `MAX_BRANCHES` = 256 (:29, :417) |
| 60 | 4 | reserved, zero |
| 64 | 80·n | branches, strictly ascending by id |

Each branch (80 bytes, `BRANCH_BYTES`, :340, encode :401-407):

| off | size | field |
|---|---|---|
| 0 | 32 | id |
| 32 | 32 | parent id, zero for the root branch |
| 64 | 4 | depth (u32) |
| 68 | 4 | reserved, zero |
| 72 | 8 | forks (u64): children forked so far |

`validate` (:447-481), run by both encode (:393) and decode (:440):
1. 1 ≤ n ≤ 256; ids strictly ascending.
2. Exactly one branch with zero parent; its id is `root_branch_id(agent_id)` and depth 0.
3. Every child: parent present; `id == child_branch_id(parent, i)` for some
   `i < parent.forks`; `depth == parent.depth + 1` (checked add).
4. Sum of all `forks` equals the number of children ("fork indexes are not contiguous").
   **DECIDED (CODE, Rust #232; C agrees): the sum is checked.** A sum that overflows
   u64 is refused with the same class and text, because it can never equal the
   child count (<= 255). Without the check a table with root forks = 2^64-1 and
   one child with forks = 2 wraps to 1 and is accepted. C: `cc_state_validate`
   (`continuity_codec.c`, the `over` flag); vector `state_forksum_overflow`; mutant MC-13.
   The child-index scan is also capped at `MAX_BRANCHES` hashes in both (no outcome
   changes for a table that passes the sum check).

`fork` (:365-390): refuses at 256 branches (Limit), absent parent (Corrupt),
depth overflow (Limit), id collision (Corrupt); child index = parent.forks,
then parent.forks += 1; insert keeps sort order. Largest object: 20544 bytes.

### 1.6 CortexWalSegment, kind 20, continuity.rs:488-582

| off | size | field |
|---|---|---|
| 16 | 8 | sequence (u64): manifest sequence it was committed in |
| 24 | 4 | record count n (u32), 1 ≤ n ≤ `MAX_WAL_RECORDS` = 64 (:30, :529, :559) |
| 28 | 4 | reserved, zero |
| 32 | … | n records |

Each record (:545-549): status u8 (1 DirectObservation, 2 VerifiedFact,
3 Inference, 4 Hypothesis, 5 Contradiction, 6 OperatorDecision; :490-511),
reserved u8 zero, statement length u16 (1 ≤ len ≤ `MAX_STATEMENT_BYTES` = 1024,
:31, :534, :568), evidence_hash 32 bytes, statement bytes. Largest object:
67872 bytes.

### 1.7 Derived values (CODE, must be bit-identical)

| value | definition | source |
|---|---|---|
| ObjectId | SHA-256(`"AIENOS-STORE-OBJECT-V1\0"` ‖ kind u16 LE ‖ version u16 LE ‖ len u64 LE ‖ bytes) | crates/aienos-kernel/src/store/v1.rs:27, :63-78; C twin `sv1_object_id` native/store/store_v1.h:132 |
| root branch id | SHA-256(`"AIENOS_ROOT_BRANCH_v1:"` ‖ agent_id) | continuity.rs:69-75 |
| child branch id | SHA-256(`"AIENOS_CHILD_BRANCH_v1:"` ‖ parent ‖ index u64 **big-endian**) | continuity.rs:77-84 |
| QEMU `memory=` digest | first 8 bytes of SHA-256 over every committed record in order of (statement len u32 LE ‖ statement) | nvme_read.rs:1119-1124, :1138-1140 |
| provisioning agent id | four `RNDR` words, each stored little-endian, word 0 first; no fallback | nvme_read.rs:1184-1193; `rndr` crates/aienos-kernel/src/arch/aarch64.rs:173-183 (FEAT_RNG check, 16 tries) |
| recovery challenge | SHA-256(`"AIENOS-RECOVERY-CHALLENGE-v1\0"` ‖ store_uuid ‖ generation u64 LE ‖ action u8 ‖ state_digest) | recovery_core.rs:94-104 |
| state_digest | SHA-256(raw superblock unit 0 ‖ raw superblock unit 1) of the Store region, read errors leave that buffer zero | recovery_core.rs:109-133 |
| operator response | HMAC-SHA256(key, `"AIENOS-RECOVERY-OPERATOR-AUTH-v1\0"` ‖ challenge), compared in constant time | crates/aienos-kernel/src/recovery.rs:103, :124-140; C has `aienos_hmac_sha256` and `aienos_ct_equal` (native/crypto/aienos_crypto.h:112, :116) |
| action byte | RepairDegradedPeer = 1, ProvisionIdentity = 2 | recovery_core.rs:38-44 |

---

## 2. Invariants the C port must hold bit-for-bit

Each invariant names the Rust code it comes from. "Bit-for-bit" means: for the
same inputs, the C encoder produces the same bytes, the C decoder accepts
exactly the inputs the Rust decoder accepts and yields the same values, and
the same error class is returned.

- **INV-1 Encodings.** Sections 1.1-1.6, byte for byte, including zero reserved
  bytes and the strict decoder rules (continuity.rs:97-166).
- **INV-2 Version gate.** Continuity header `format_version` is 0 and Store
  object version is 1 for every continuity object; anything else is Corrupt
  (continuity.rs:24-26, :110, :627). Changing either is an operator decision
  (ADR 0016 status), not a C port decision.
- **INV-3 Identity derivations.** Section 1.7, including the big-endian index in
  `child_branch_id` (continuity.rs:82), which differs from every other integer.
- **INV-4 Never mint.** No code path except an explicit provisioning request
  writes an AgentRoot. Resolve and resume never create an identity
  (continuity.rs:635-637, :859-868; ADR 0016:69-71).
- **INV-5 Root count.** 0 roots with no other continuity object: Unprovisioned.
  0 roots with any manifest, agent-state or WAL object: Corrupt("continuity
  objects without an agent root"). More than 1 root: Conflict
  (continuity.rs:638-653). Order of these checks is part of the contract.
- **INV-6 Manifest chain.** Every manifest in the catalog decodes, names this
  root, and the set sorted by sequence is exactly 1..n with each `previous`
  equal to the ObjectId of the manifest before it (continuity.rs:656-678).
  Current manifest = the one with sequence n. A fork, a gap, a foreign root
  or a missing manifest is Corrupt.
- **INV-7 Referenced objects.** A referenced id must exist in the catalog with
  the expected kind and Store version 1, else Corrupt (continuity.rs:619-633).
  The current manifest must name an agent state (:681-683) whose agent_id is the
  root's (:685-689). WAL segments must have strictly increasing `sequence`
  ≤ manifest.sequence (:693-700).
- **INV-8 Atomic commit.** Provisioning writes AgentRoot + AgentState(genesis,
  written_at 1) + Manifest(sequence 1, incarnation 1, no previous, no WAL) in
  **one** Store transaction (continuity.rs:734-770). Every later commit writes
  its optional AgentState, optional WAL segment and the new Manifest in **one**
  transaction (:799-855). Object order in the transaction is AgentState, WAL,
  Manifest (:799-845).
- **INV-9 Commit rules.** New sequence = previous + 1 (checked); AgentState's
  `written_at` is overwritten with the new sequence (:808); a state for another
  agent is Corrupt (:803-807); a WAL segment is appended only when the update
  has records, refused at 64 segments as Limit("cortex WAL needs compaction")
  (:815-818); incarnation + 1 only on resume (:828-836).
- **INV-10 Commit-before-observation.** `resume` commits incarnation + 1
  before returning the view the caller acts on (continuity.rs:859-868).
- **INV-11 Read-only degraded mount.** On a mount that is not Valid, provision
  and commit return ReadOnly before any write (continuity.rs:712-717, :727,
  :793); resume returns the verified view and `committed = false` (:864-866).
- **INV-12 Old or new, never a third state.** A power cut at any unit write of
  a continuity commit reopens to the old manifest or the new one, same agent
  (continuity_tests.rs:242-283; QEMU campaign section 4).
- **INV-13 Inspection never writes.** `inspect` performs reads only
  (recovery_core.rs:107-187; recovery_core_tests.rs:89-108).
- **INV-14 Degraded wins.** On a DegradedRecovery mount the entry reason is
  `Degraded(peer)` whatever continuity resolves to (recovery_core.rs:172-176).
- **INV-15 Applicable action** (recovery_core.rs:79-90): RepairDegradedPeer only
  for `Degraded(Malformed)` **and** a resolved identity on the valid root;
  ProvisionIdentity only for `Unprovisioned` on a Valid mount; otherwise none.
  A degraded mount is never unprovisioned (the fe2c2bd finding,
  evidence/recovery_core_qemu_2026-09-25.md "Finding fixed during qualification").
- **INV-16 Authorisation before write.** Each action re-inspects the device,
  requires `applicable() == action` (else NotApplicable), then a verifying
  operator response (else Unauthorised), and only then writes
  (recovery_core.rs:219-235, :244-245, :267-268).
- **INV-17 Repair writes one unit.** Repair zeroes the inactive superblock slot
  (1 - active slot), flushes, and re-inspects (recovery_core.rs:246-256).
- **INV-18 Operator provisioning.** Uses the Store uuid from the inspection and
  `ProvisionSource::Operator` (recovery_core.rs:269-272).

---

## 3. Boot resolution and Recovery Core entry (CODE, behaviour to port)

Continuity, in this order (continuity.rs:637-710):

1. List catalog entries by kind. Apply INV-5.
2. Decode the AgentRoot through a kind-checked read (INV-7).
3. Decode every manifest; apply INV-6.
4. Decode the current manifest's AgentState; check its agent.
5. Decode each WAL segment in manifest order; check ordering; concatenate records.

Corrupt reasons the Rust code can return (the `why` text appears in serial
markers; matching it exactly is PROPOSED so C markers can be grepped the same
way): "bad magic", "unsupported continuity format version", "nonzero header
reserved", "body length mismatch", "truncated object", "nonzero reserved",
"trailing bytes", "unknown provisioning source", "zero agent id", "root branch
does not derive from agent", "too many cortex WAL segments", "manifest
sequence/previous mismatch", "branch count out of range", "branches not
strictly sorted", "unexpected root branch", "parent branch is absent", "branch
lineage is inconsistent", "fork indexes are not contiguous", "unknown epistemic
status", "statement length", "WAL segment record count", "referenced object is
absent", "referenced object has the wrong kind", "continuity objects without an
agent root", "manifest names a foreign root", "agent root has no manifest",
"manifest sequence gap or fork", "manifest chain is broken", "manifest has no
agent state", "agent state belongs to another agent", "WAL segments out of
order", "fork parent is absent", "child branch id collision" (all in
continuity.rs:97-857).

Recovery Core (recovery_core.rs:107-187):

1. Read Store-region units 0 and 1 raw; classify each slot Zero /
   Superblock{generation} / Undecodable(err) / ReadError; take the store uuid
   from the first decodable slot; compute `state_digest`.
2. Open the Store without writing. Unformatted: reason StoreUnformatted. Other
   mount error: StoreMount(err).
3. Record (mount state, peer condition, generation) and catalog counts
   (roots, manifests, other).
4. Resolve continuity. Reason: Degraded(peer) if the mount is degraded, else
   none / Unprovisioned / Conflict / ContinuityCorrupt(why); any other
   continuity error is ContinuityCorrupt("continuity unreadable").

Serial markers the QEMU oracle greps (CODE, nvme_read.rs):

| marker | source |
|---|---|
| `CONTINUITY: <PROVISIONED\|RESUMED\|RESUMED_READONLY\|REMEMBERED\|COMMITTED> agent=<64 hex> incarnation=N sequence=S cortex=K branches=B memory=<16 hex>` | :1118-1143 |
| `CONTINUITY: UNPROVISIONED`, `CONTINUITY: CONFLICT`, `CONTINUITY: CORRUPT (<why>)`, `CONTINUITY: STOP (<Debug of error>)`, `CONTINUITY: NO_ENTROPY`, `CONTINUITY: STOP (fork)` | :1144-1155, :1178, :1189, :1229 |
| `CHECKPOINT: <name>` (crash mode) | :1241-1253; names crates/aienos-kernel/src/store/checkpoint.rs:79-88 |
| `RECOVERY_OPERATOR_KEY: TEST-ONLY` | :1287 |
| `RECOVERY_RECORD: slot0=… slot1=… mount=… peer=… generation=… roots=… manifests=… other=… agent=<hex\|none>` | :1290-1322 |
| `RECOVERY_CORE: ENTERED reason=<Debug>` / `RECOVERY_CORE: NOT_NEEDED` | :1324-1333 |
| `RECOVERY_CHALLENGE: action=<name> challenge=<64 hex>` | :1335-1343 |
| `RECOVERY_ACTION: <name> DONE[ agent=<hex>]`, `RECOVERY_REFUSED (<Debug>)`, `RECOVERY_REFUSED (NoEntropy)` | :1356, :1377-1391 |

PROPOSED: the C kernel prints these exact strings (same field order, same
Debug spellings such as `Degraded(Malformed)`), so the C gate scripts can use
the Rust scripts' grep patterns and the rows can be IDENTICAL rather than
DIFFERS.

---

## 4. What the Recovery Core may do without a model

CODE (recovery_core.rs:1-8, ADR 0006): no model, no network, no clock.

Allowed:

- Read both superblock slots, mount the Store read-only, resolve continuity,
  print the raw system record, compute a challenge. Never writes (INV-13).
- With a verifying operator response bound to the exact state and action:
  RepairDegradedPeer (zero one inactive superblock unit) or ProvisionIdentity
  (one AgentRoot + genesis state + first manifest, one transaction). Nothing
  else.

Refused by design (CODE):

- Mint an identity after identity loss, on a degraded mount, on a store with
  orphaned continuity objects, or on a store with two roots (INV-5, INV-15).
- Discard a CRC-valid newer root whose graph is broken (roll back committed
  state): out-of-band operator decision (recovery_core.rs:74-75;
  evidence/recovery_core_qemu_2026-09-25.md "Not claimed").
- Reuse an authorisation on another state or for another action (challenge
  binding, recovery_core_tests.rs:146-150, :300-315).

Operator key today is TEST-ONLY (`TEST_ONLY_OPERATOR_KEY = [0x0f; 32]`,
crates/aienos-boot/src/store_qual.rs:59-63). The real credential (Argon2id
passphrase, FIDO key) is undecided (ADR 0006 / M5). PROPOSED: the C port keeps
the key behind a TEST-only build flag, prints `RECOVERY_OPERATOR_KEY:
TEST-ONLY` on every boot that uses it, and refuses the TEST key in a
`CK_HARDWARE_STAGING` build the same way `ck_store_keys_admissible` refuses
TEST Store keys (native/kernel/svc/store_boot.h:66).

Other ADR 0006 items are out of scope (section 8). Rust has an A/B `SlotManager`
and a Cortex `WalRecovery::recover_and_truncate` (crates/aienos-kernel/src/recovery.rs:37-90,
:144-200; tests :329, :346, :380), but neither is part of the continuity or
Recovery Core QEMU campaigns this contract ports. Crash records and model-weight
hash checks have no Rust code.

---

## 5. Interfaces to the C Store (PROPOSED unless marked CODE)

The C kernel does not use a plain Store v1. It mounts the **sealed** Store:
every application object is an M5 envelope of Store kind `SS_KIND_ENVELOPE`
(0x0510), with the application kind and version carried in the M5 binding, plus
one sealed transaction record per transaction and an anti-rollback anchor
outside the Store region (CODE: native/store/store_sealed.h:1-31, :43-51;
boot stage native/kernel/svc/store_boot.c, `store_boot_run_policy`). The Rust
oracle wrote continuity objects as plaintext Store v1 objects. That gap is the
main design point of this contract.

### 5.1 Placement

- **P-1 (PROPOSED).** Continuity objects are stored through `ss_transact` as
  `ss_object{kind = 16|17|18|20, version = 1, bytes = canonical plaintext}`.
  **Read side IMPLEMENTED, host PASS (cut 3); write side (provision, commit) is cut 4.** Evidence:
  `test_continuity_resolve.c` writes all four kinds with `ss_transact` at version 1 and `cr_resolve`
  reads them back through the claims (`t_resolved`, `t_orphans`, `t_references`, at 512 and 4096 byte
  blocks).
  The kinds do not collide with existing C application kinds (CODE:
  `CK_BOOT_KIND` 0x0B00, store_boot.h:30; `CK_ART_INDEX_KIND` 0x0A01 and
  `CK_ART_CHUNK_KIND` 0x0A02, native/kernel/svc/artifact_store.h:38-39).
- **P-2 (PROPOSED).** Every cross-reference inside a continuity object (manifest
  `root`, `previous`, `agent_state`, `cortex_wal[]`) is the **logical
  ObjectId** = `sv1_object_id(kind, 1, plaintext)`, exactly the Rust
  `ObjectId::calculate` value. Then the plaintext bytes of every continuity
  object are bit-identical to Rust's for the same inputs, and the differential
  compares bytes directly. The sealed envelope's own Store ObjectId (SHA-256
  of the envelope, keyed by the store keys; m5.h:171-181, store_sealed.c:334-345)
  is never written into a continuity object.
  **IMPLEMENTED on the read side, host PASS (cut 3):** `cr_resolve` computes every logical id with
  `sv1_object_id` over the decrypted plaintext (`continuity_resolve.c:113`) and follows only logical ids
  (`read_kind`, :64-82), re-hashing each object it reads so a reference can never reach different
  bytes (`t_references`, `t_chain`). Bytes stay bit-identical to Rust (D-1).
- **P-3 (PROPOSED).** Lookup: after `ss_open`, the verified claims
  (`ws->claims[0..nclaims)`, store_sealed.h:92-118) give each envelope's
  application kind and version (`c.obj.object_kind`, `object_version`) without
  decryption (CODE pattern: store_boot.c, latest boot record loop). The C
  continuity layer builds a table of (kind, version, logical id, sid) once per
  resolve by `ss_read` of each claim of kinds 16-20 and `sv1_object_id` over the
  plaintext. "Catalog entry of kind K" (Rust `ids_of_kind`, continuity.rs:609-617)
  becomes "claim of application kind K". A logical id that maps to two claims is
  Corrupt (PROPOSED: Rust cannot see this because Store v1 dedups identical
  objects; the sealed store gives each write its own envelope).
  **IMPLEMENTED, host PASS (cut 3):** `continuity_resolve.c:100-130` (`build_table`; duplicate check :115-118,
  reason `duplicate logical object id`, checked before the root count so it is Corrupt, not Conflict);
  test `t_duplicate_id` writes the same root bytes twice into the real sealed Store. Kind 19 and every
  non-continuity kind are never read (`t_unprovisioned`, `t_fake`), as Rust ignores them.

### 5.2 Calls the continuity and recovery code needs

| need | C Store call | status |
|---|---|---|
| mount without writing | `ss_open` (store_sealed.h:141-143), which runs `st_open` first | CODE |
| mount state, peer condition | `s->st.state` (`ST_VALID`, `ST_DEGRADED_RECOVERY`), `s->st.peer` (store_engine.h:22-26, :134-141) | CODE |
| generation, active slot | `ss_generation`, `st_active_slot` (store_sealed.h:151, store_engine.h:153-155) | CODE |
| list by kind | claims loop (P-3), `cr_bind_sealed` in `continuity_resolve_sealed.c` | CODE (cut 3, host PASS) |
| read one object | `ss_read(s, sid, out, cap, &len, &kind)` (store_sealed.h:149-150) | CODE |
| commit ≤ 3 objects atomically | `ss_transact(s, objs, n, hook, arg, ids_out)` (store_sealed.h:146-147), n ≤ `SS_MAX_OBJECTS` = 8 | CODE |
| read-only refusal | `ss_prepare` returns `ST_E_READ_ONLY_DEGRADED` when not Valid (store_sealed.c:379) | CODE; continuity still checks first (INV-11) |
| crash checkpoints | `st_hook` with `ST_CP_*` 0-6 (store_engine.h:58-69) plus `SS_CP_BEFORE_ANCHOR` 100, `SS_CP_AFTER_ANCHOR` 101 (store_sealed.h:76) | CODE |
| raw superblock units for inspection | `st_dev.read_unit(ctx, 0/1, buf)` on the Store region, `sv1_superblock_decode` (store_engine.h:71-78, store_v1.h:184) | CODE |
| repair write | `st_dev.write_unit(ctx, 1 - active, zeros)` then `flush` | CODE calls; use PROPOSED |
| entropy for provisioning | `ck_rng_fill` (native/kernel/core/entropy.h:53), refuses with no fallback | CODE; use PROPOSED |
| HMAC + constant-time compare | `aienos_hmac_sha256`, `aienos_ct_equal` (native/crypto/aienos_crypto.h:112, :116) | CODE |

### 5.3 Known conflicts between the oracle and the sealed Store

- **K-1 Size.** **Cap IMPLEMENTED in the C codec, host PASS (cut 1, kept in cut 2); policy still PROPOSED** (the chunking alternative needs an operator decision). Evidence: `continuity_codec.c` decode cap at `rd_open` (`len > CC_MAX_OBJECT_BYTES`) and encode cap at `enc_begin`; `test_continuity_codec.c` K-1 checks (204 branches = 16384 bytes encodes, 205 is Limit with nothing written; 64 x 1024 WAL is Limit, never truncated; decode of 16385 bytes is Limit; mutant MC-11). Cap 16384 and 204 branches are unchanged by cut 2. `SS_MAX_PLAINTEXT` is 16384 bytes per object
  (store_sealed.h:46). Rust allows an AgentState up to 20544 bytes (256
  branches) and a WAL segment up to 67872 bytes (section 1). PROPOSED: the C
  port enforces the Rust bounds and an extra byte bound of 16384, returning
  Limit (never truncating) when an encoding exceeds it; the differential covers
  inputs inside both bounds, and a C test proves a Rust-legal but oversize input
  is refused as Limit with nothing written. That caps the C branch table at 204
  branches ((16384 - 64) / 80). The alternative (chunking one object across
  envelopes) changes the object model and needs an operator decision.
- **K-2 Catalog bound.** Each sealed transaction adds the payload envelopes plus
  one transaction record, so the Store v1 catalog bound (4096 entries,
  store/v1.rs:12) is reached in fewer continuity commits than in Rust. ADR 0016
  already defers compaction; the C gate must report the count, not hide it.
- **K-3 Identity loss looks different.** The Rust campaign flips byte 20 of the
  AgentRoot's first unit (crates/aienos-store-tool/src/main.rs:177-201,
  qemu_recovery_test.sh:168). In the sealed Store that byte is ciphertext, so
  the C mount is expected to refuse at the keyed proof (`SS_E_ENVELOPE`) before
  continuity runs. UNVERIFIED (confidence medium: from store_sealed.h:61 and
  store_boot.h:5-11, not tested). PROPOSED: the C Recovery Core adds an entry
  reason for a sealed refusal (keyed / rollback proof) that admits no action,
  and the identity-loss rows stay DIFFERS with that observable stated.
- **K-4 GraphBadNewer.** When the newest root is graph-broken, Rust mounts
  degraded on the older generation (recovery_core_tests.rs:178-219). In the
  sealed Store the anchor holds the newer generation, so `ss_open` is expected to
  refuse with `SS_E_ROLLBACK` (store_sealed.h:57). UNVERIFIED (confidence
  medium). Either way no action may be applicable (INV-15).
- **K-5 Degraded mount through ss_open. DECIDED by running it (cut 3, host PASS).** The question was whether
  `ss_open` returns 0 on a `DegradedRecovery` mount with a malformed peer (needed for INV-11 and repair).
  **Answer: yes.** `test_continuity_resolve.c` `t_degraded` (:716, printed at :751) commits two generations
  to the real sealed Store, fills the inactive superblock slot with garbage, reopens: `ss_open` rc=0,
  `st.state` = `ST_DEGRADED_RECOVERY`, `st.peer` = `ST_PEER_MALFORMED`, generation unchanged (3 -> 3), the
  anchor accepts it. On that mount `cr_resolve` still returns the verified view (same agent, incarnation and
  `memory=`), `cr_writable` returns `CR_READ_ONLY` (INV-11), and `cr_state_digest_dev` hashes the garbage
  unit as it lies. Run at 512 and 4096 byte blocks. Not tested here: a malformed peer combined with
  other mount or anchor damage, and repair itself (cuts 4-5).
- **K-6 Region geometry.** The Rust qualification Store region is 256 units at
  LBA 64 with a control block at LBA 32 (crates/aienos-boot/src/store_qual.rs:13-16).
  The C layout is anchor units 0-3, Store region 4..U-2, probe unit U-1
  (native/kernel/dev/disk_layout.h). Raw superblock "units 0 and 1" in the
  challenge (section 1.7) mean the first two units of the **Store region** in
  both. PROPOSED: the C challenge does not also bind the anchor record; adding it
  would make C challenges differ from Rust ones and needs a decision.
- **K-7 Mode selection.** The Rust qualification picks a mode from a control
  block on the NVMe disk (store_qual.rs:27-48; store-tool `cfg`,
  crates/aienos-store-tool/src/main.rs:108-122; response at bytes 16..48). The C
  disk layout has no control block. PROPOSED: a TEST-only C mechanism with the
  same mode numbers (5-11), refused in `CK_HARDWARE_STAGING`. Its exact form is
  left to the first wiring cut.

---

## 6. Oracle map: Rust check -> C gate

Gate `M4_CONTINUITY` and gate `M4_RECOVERY` in `scripts/ck_gates.sh` (today
`missing`, ck_gates.sh:55-56). Every row below is listed in
`native/kernel/GATES.md` sections "M4 continuity" and "M4 recovery" with status
`NOT_RUN (MISSING_IMPLEMENTATION)`.

### 6.1 M4_CONTINUITY

QEMU oracle: `scripts/qemu_continuity_test.sh` (PASS line
`CONTINUITY_QEMU: PASS`, :210; receipt evidence/continuity_qemu_2026-09-25.md
at Rust commit 3df62b2).

| GATES row | Rust check | script lines |
|---|---|---|
| 81 | blank media, resume: `CONTINUITY: STOP (store Unformatted)`, image unchanged | :92-98 |
| 82 | formatted store, no root, resume: `CONTINUITY: UNPROVISIONED`, image unchanged | :100-108 |
| 83 | provision: `PROVISIONED`, 64-hex agent, `incarnation=1 sequence=1 cortex=0 branches=1` | :111-119 |
| 83a | second provision: `STOP (AlreadyProvisioned)`, image unchanged | :122-127 |
| 83b | independent provisioning gives a different agent (RNDR) | :129-136 |
| 84 | mode 7: `RESUMED … incarnation=2 sequence=2 cortex=0 branches=1`, then `REMEMBERED … incarnation=2 sequence=3 cortex=1 branches=2` | :139-147 |
| 85, 85a | cold restarts 1 and 2: same agent, same `memory=`, incarnation 3 then 4, sequence 4 then 5, cortex 1, branches 2 | :149-160 |
| 86-86f | kill at each checkpoint (before_first_write, after_payloads, after_catalog, after_commit_record, after_first_flush, after_superblock_write = either, after_final_flush = new); marker seen; same agent | :163-194 |
| 87 | malformed peer (`inject … inactive seeded_garbage`): `RESUMED_READONLY`, same agent and memory, image unchanged | :196-205 |

Host oracle: `cargo test -p aienos-kernel --lib continuity` (9 tests,
crates/aienos-kernel/src/continuity_tests.rs):

| GATES row | Rust test | line |
|---|---|---|
| 87a | `unprovisioned_store_never_mints_an_identity` | :84 |
| 87b | `provision_then_cold_restart_returns_the_same_identity_and_memory` | :97 |
| 87c | `provisioning_twice_is_refused` | :142 |
| 87d | `two_roots_stop_with_conflict` | :152 |
| 87e | `forked_or_gapped_manifest_chains_are_corrupt` | :178 |
| 87f | `degraded_mount_resumes_read_only` | :221 |
| 87g | `a_crash_at_every_write_of_a_commit_leaves_old_or_new_never_a_third_state` | :242 |
| 87h | `encodings_round_trip_and_reject_tampering` | :286 |
| 87i | `branch_table_validation_rejects_broken_lineage` | :328 |

C-side differences already known (PROPOSED observables, to be stated in the
rows when the C gate exists): the crash campaign has 9 checkpoints in C
(7 Store + 2 anchor, section 5.2); the Rust "either" point
`after_superblock_write` is `after_inactive_superblock` in C
(native/store/store_engine.c:43-55); the anchor points need their own expected
outcome, derived from the sealed-store rule that a crash between Store commit
and anchor commit resumes at `SS_RB_PREPARED_ADVANCE` (store_sealed.h:16-21),
so both anchor points are expected to show the **new** memory.

### 6.2 M4_RECOVERY

QEMU oracle: `scripts/qemu_recovery_test.sh` (PASS line
`RECOVERY_CORE_QEMU: PASS`, :194; receipt
evidence/recovery_core_qemu_2026-09-25.md at Rust commit e5b44d8).

| GATES row | Rust check | script lines |
|---|---|---|
| 88 | inspect degraded store: `RECOVERY_OPERATOR_KEY: TEST-ONLY`, `RECOVERY_CORE: ENTERED reason=Degraded(Malformed)`, record shows the same agent, image unchanged; repair challenge offered | :94-103 |
| 88a, 88b, 88c | repair with zero / wrong-key / wrong-challenge response: `RECOVERY_REFUSED (Unauthorised)`, image unchanged | :105-117 |
| 89 | authorised repair: `RECOVERY_ACTION: repair-degraded-peer DONE`, image changed | :119-125 |
| 89a | resume after repair: `CONTINUITY: RESUMED`, same agent and memory | :126-132 |
| 89b | replay of the repair response: `RECOVERY_REFUSED (NotApplicable)`, image unchanged | :133-138 |
| 90 | unprovisioned store: `ENTERED reason=Unprovisioned`, provision challenge offered, image unchanged | :141-149 |
| 90a | provisioning with wrong key: `Unauthorised`, image unchanged | :150-155 |
| 90b | authorised provisioning: `RECOVERY_ACTION: provision-identity DONE agent=…`, a cold resume returns that agent | :156-163 |
| 91 | corrupted agent root: `ENTERED`, no `RECOVERY_CHALLENGE`, image unchanged | :166-174 |
| 91a, 91b | modes 10 and 11 with a forged response: `RECOVERY_REFUSED (…)`, no action, image unchanged | :175-183 |
| 91c | normal boot after identity loss: no `RESUMED`/`PROVISIONED`, image unchanged | :184-189 |

Host oracle: `cargo test -p aienos-kernel --lib recovery_core` (8 tests,
crates/aienos-kernel/src/recovery_core_tests.rs) and the operator-auth tests in
crates/aienos-kernel/src/recovery.rs:

| GATES row | Rust test | line |
|---|---|---|
| 91d | `inspection_never_writes_and_names_the_reason` | recovery_core_tests.rs:89 |
| 91e | `degraded_repair_needs_the_operator_and_restores_a_writable_store` | :111 |
| 91f | `provisioning_is_operator_only_and_only_on_an_unprovisioned_store` | :154 |
| 91g | `identity_lost_in_the_newest_root_never_looks_unprovisioned` | :178 |
| 91h | `malformed_peer_without_a_resolvable_identity_is_not_repaired` | :222 |
| 91i | `orphaned_continuity_objects_are_corrupt_not_unprovisioned` | :236 |
| 91j | `identity_loss_through_corruption_offers_no_action_that_mints` | :267 |
| 91k | `challenges_bind_state_and_action` | :300 |
| 91l | `hmac_primitive_rfc4231_case_2` | recovery.rs:238 |
| 91m | `operator_auth_known_answer_accepted` | recovery.rs:251 |
| 91n | `operator_auth_rejects_any_single_bit_flip` | recovery.rs:269 |
| 91o | `operator_auth_rejects_legacy_bare_sha256_response` | recovery.rs:299 |
| 91p | `operator_auth_rejects_undomained_hmac_and_zero_response` | recovery.rs:311 |

### 6.3 Differential agreement (D-1, D-2 DECIDED and IMPLEMENTED, host PASS; D-3 PROPOSED)

ADR 0024 Q2 requires differential agreement, not just parallel tests.

- **D-1 Golden vectors.** A test-only Rust emitter (no change to Rust kernel
  behaviour; the Rust kernel is frozen as reference) writes canonical bytes and
  ObjectIds for a fixed set of inputs: AgentRoot (both sources), manifests with
  0/1/64 WAL ids, AgentState genesis and after forks at depth 1 and 2,
  WAL segments with each epistemic status and statement lengths 1 and 1024,
  root/child branch ids (index 0, 1, 2^32, 2^64-1), challenges for both actions,
  and HMAC responses with the TEST key. Committed as fixture files (no Python,
  no new dependency) under `native/kernel/tests/fixtures/`. The C host test
  must reproduce every byte and refuse the same tampered vectors.
  **DECIDED and IMPLEMENTED (cut 2, host PASS).** Emitter: `crates/aienos-kernel/src/continuity_vectors.rs`
  (test-only, `cfg(test)`; no kernel behaviour change). Fixtures:
  `native/kernel/tests/fixtures/continuity_vectors.txt` (22 vectors, 5 branch ids, 4 deferred lines).
  Regenerate: `AIENOS_CONTINUITY_VECTORS_REGEN=1 cargo test -p aienos-kernel --lib continuity_vectors`;
  without the variable the Rust test fails if a committed fixture differs from freshly emitted bytes.
  C: `test_continuity_codec.c` (`test_golden`, `test_tampered`; fixture dir = argv[1] or the Makefile
  `CC_FIXTURE_DIR`) reproduces every byte and both ObjectIds (`cc_object_id` and `sv1_object_id`),
  decode then encode is the identity, and tampered bytes, ObjectIds and verdicts are refused.
  Added vector: `state_forksum_overflow` (hostile fork counts, refused by both).
  **DONE in the resolve cut (cut 3, host PASS):** the recovery challenges (both actions) and HMAC responses
  with the TEST key (0x0f x32) are the four `deferred` fixture lines. `test_continuity_resolve.c`
  `test_fixture` reproduces all four byte for byte from `cr_challenge` and `cr_operator_response`
  (system record: uuid 0x5a x16, generation 7, state digest 0x33 x32). The fixture file header and the
  emitter text still say "C does not implement these yet": stale wording, left as is because changing it
  means regenerating the Rust fixtures; the lines themselves are unchanged.
- **D-2 Decode agreement.** For every single-bit flip of every vector, C and
  Rust agree on accept / refuse and on the error class.
  **DECIDED and IMPLEMENTED (cut 2, host PASS).** `continuity_verdicts.txt` holds the Rust verdict of each
  vector and of each of its single-bit flips (class and reason text, one letter per distinct reason); C replays
  and compares: 22 vectors, 86598 verdicts, **0 divergences** (C and Rust agree on accept/refuse, class and
  reason text for every flip). The emitter panics on a Rust reason missing from its table, so a new reason
  cannot be dropped silently. The K-1 cap (C-only Limit) cannot appear in a flip because flips keep the length.
- **D-3 Cross-store agreement** is not possible byte-for-byte (sealed vs
  plaintext Store, section 5). Agreement is on resolved values: agent id,
  sequence, incarnation, branch table bytes, Cortex records, `memory=` digest.

---

## 7. Failure modes each gate must catch, with a mutation

Each C gate and host test needs a mutation that makes it FAIL, wired as a
TEST-only build flag refused by `CK_HARDWARE_STAGING` or as a `--self-test`
case (LT-KERNEL rule). PROPOSED flag names; the behaviour is what matters.

M4_CONTINUITY:

| id | mutation | must turn FAIL |
|---|---|---|
| MC-1 | resume provisions when Unprovisioned | 82, 87a |
| MC-2 | drop the orphan check (INV-5): orphan objects read as Unprovisioned: `CR_MUTANT_NO_ORPHAN_CHECK`, IMPLEMENTED, killed (cut 3) | 91i (and the C twin of 87a with an orphan manifest) |
| MC-3 | resume skips the commit (no incarnation + 1) | 84, 85, 85a, 87b |
| MC-4 | manifest chain check ignores `previous`: `CR_MUTANT_IGNORE_PREVIOUS`, IMPLEMENTED, killed (cut 3) | 87e |
| MC-5 | accept `format_version != 0` or nonzero reserved bytes | 87h, D-2 |
| MC-6 | `child_branch_id` index little-endian | D-1, 87i |
| MC-7 | provision allowed when a root exists | 83a, 87c |
| MC-8 | provision or commit split into two transactions (manifest after payload) | 86-86f, 87g |
| MC-9 | `writable` check removed (commit on degraded mount) | 87, 87f |
| MC-10 | agent id from a fixed value instead of RNDR | 83b |
| MC-11 | WAL segment truncated silently at the size bound (K-1) instead of Limit | C size-bound test (PROPOSED) |
| MC-12 | Conflict check skipped (first root used): `CR_MUTANT_SKIP_CONFLICT`, IMPLEMENTED, killed (cut 3) | 87d |
| MC-13 | fork-count sum unchecked (wraps): `CC_MUTANT_UNCHECKED_FORK_SUM`, IMPLEMENTED, killed | 87i, `state_forksum_overflow` (D-1, D-2) |
| MC-14 | golden mismatch only the vectors see (manifest WAL id 63 replaced by id 0): `CC_MUTANT_MANIFEST_LAST_WAL_ZERO`, IMPLEMENTED, killed | D-1 |
| MC-15 | golden comparison skipped: `CC_MUTANT_SKIP_D1` (the test counts comparisons), IMPLEMENTED, killed | D-1 |
| MC-16 | decode-agreement comparison skipped: `CC_MUTANT_SKIP_D2`, IMPLEMENTED, killed | D-2 |

M4_RECOVERY:

| id | mutation | must turn FAIL |
|---|---|---|
| MR-1 | inspection writes (for example repairs on inspect) | 88, 90, 91, 91d |
| MR-2 | challenge omits `state_digest`: `CR_MUTANT_CHALLENGE_NO_DIGEST`, IMPLEMENTED, killed (cut 3) | 89b, 91k |
| MR-3 | challenge omits the action byte: `CR_MUTANT_CHALLENGE_NO_ACTION`, IMPLEMENTED, killed (cut 3) | 88c, 91k |
| MR-4 | response compare checks only 16 bytes (`CR_MUTANT_COMPARE_16`, IMPLEMENTED, killed, cut 3), or is not constant time (not mutated: timing is not observable on the host) | 91n (bit flips in bytes 16-31) |
| MR-5 | `applicable()` treats a degraded mount with no identity as Unprovisioned (the fe2c2bd bug) | 91g, 91 |
| MR-6 | repair zeroes the active slot | 89, 89a |
| MR-7 | repair offered without a resolved identity | 91h |
| MR-8 | operator auth uses bare SHA-256 (`CR_MUTANT_BARE_SHA256`) or omits the domain (`CR_MUTANT_NO_DOMAIN`): both IMPLEMENTED, killed (cut 3) | 91o, 91p |
| MR-9 | operator provisioning writes source Qualification | 91f |

Known oracle gap (CODE, not covered by any Rust test): no power-cut campaign
runs on **provisioning** itself; only commits are cut
(continuity_tests.rs:242-283, qemu_continuity_test.sh:163-194). PROPOSED: the C
gate adds one.

---

## 8. Out of scope

- Kinds 19 (CortexCheckpoint) and 23 (MigrationManifest), manifest fields
  `migration_parent_id` and admission receipts, migration boundaries
  (ADR 0016:38-42, :57-61): no Rust code.
- Catalog compaction and WAL compaction (ADR 0016:96-98).
- Freezing format version 0 to 1 (operator decision, ADR 0016:3-7, :89-91).
- The real operator credential (Argon2id, FIDO), TRUST-1, TPM NV anchor, any
  Machine 1 claim.
- Other ADR 0006 items: the A/B `SlotManager` and Cortex
  `WalRecovery::recover_and_truncate` exist in Rust (recovery.rs:37-90,
  :144-200; tests :329, :346, :380) but are outside the continuity and Recovery
  Core campaigns; crash records and model-weight hash checks have no Rust code.
- Rolling back to an older root when the newer one is graph-broken (refused
  in-band on purpose).
- The richer host crates `aienos-agent-state` and `aienos-cortex`; the C port
  covers only the kernel objects above.
- Any change to the Rust kernel other than a test-only vector emitter (D-1).
- `scripts/*qualify*.sh` and `native/capability/**` (owned by aienos#213).

---

## 9. Differences between ADR 0016 text and the Rust code (code wins)

| ADR 0016 says | Rust code does | effect on the C port |
|---|---|---|
| Manifest carries `migration_parent_id`, Cortex checkpoint id, admission receipts (:38) | none of these fields exist (continuity.rs:253-315) | port the code layout only |
| Degraded mount reports `CONTINUITY: DEGRADED` (:46-48) | prints `CONTINUITY: RESUMED_READONLY …` (nvme_read.rs:1211-1213) | use the code marker |
| Current manifest = the one no other names as previous (:57-61) | all catalog manifests must form exactly 1..n (continuity.rs:656-678) | port the stricter code rule |
| Kinds 19 and 23 listed (:40, :42) | not written or read | out of scope |
| Provisioning on a store with zero roots (:50-53) | also refused when orphan continuity objects exist (continuity.rs:642-649) | port the code rule |
| Branch-table validation sums `forks` (not specified in the ADR text; section 1.5 item 4) | Rust #232: the sum is checked, an overflowing sum is refused as Corrupt("fork indexes are not contiguous"); before #232 a release build wrapped and accepted {root forks = 2^64-1, child forks = 2} | DECIDED: C refuses on overflow (`cc_state_validate`), Rust and C agree; vector `state_forksum_overflow`, mutant MC-13 |


### 9.1 Cut 3 (resolve): C versus the Rust `resolve`, and what C does on purpose

Where code and contract differ, the safer behaviour (refuse) was chosen. Host evidence:
`test_continuity_resolve.c`.

| item | Rust | C (cut 3) | effect |
|---|---|---|---|
| Cortex records in the view | `Continuity.cortex` keeps every record (continuity.rs:726-736) | `cr_view` keeps `cortex_count` and the streamed `memory` digest only (`continuity_resolve.h`); no record is stored | bounded memory (a view could hold 4 MiB); the QEMU markers and a resume need only count and digest; compare D-3 on resolved values |
| order of failures | reads objects lazily, root count first (:638-653) | `build_table` reads and hashes every object of kinds 16, 17, 18, 20 first (:100-130) | a Store read error, an oversize object or a duplicate logical id on ANY continuity object is reported before the root count; always a refusal, never a resolve |
| duplicate logical id | impossible (Store v1 dedups) | Corrupt `duplicate logical object id` (P-3) | C-only reason |
| oversize object | n/a | Limit `continuity object exceeds the size bound` (K-1), before decode | C-only; a Rust-legal object over 16384 bytes cannot exist in the sealed Store, so the real-Store test refuses at the write (`t_size_bound`) and the resolve Limit is tested with a fake source (`t_fake`) |
| table bound | catalog bound 4096 over all objects (store/v1.rs:12) | Limit `too many continuity objects` above `CR_TABLE_CAP` = 4096 objects of kinds 16/17/18/20 | untested at the bound (UNVERIFIED), refusal either way |
| empty or id-less object | n/a | Corrupt `continuity object has no valid id` | C-only; the sealed Store refused a zero-length write in the test run, so this is also unreached through the real Store |
| re-read check | n/a | `read_kind` re-hashes the plaintext and compares with the logical id (`object changed since lookup`) | C-only defence; unreachable with the real Store |
| manifest iteration order | catalog order | claim order | when several manifests are broken the first reported reason can differ; the class (Corrupt) is the same |
| mount state | resolve works on a degraded mount | same (`t_degraded`), `cr_writable` gives `CR_READ_ONLY` | matches INV-11 |
| outcome set | `Store, Unprovisioned, Conflict, AlreadyProvisioned, ReadOnly, Corrupt, Limit` | same names (`CR_*`), plus C-only `CR_E_ARG`; `CR_ALREADY_PROVISIONED` exists but resolve never returns it (cut 4) | |

D-2 result (cut 2, host PASS): no C/Rust decode divergence was found over 86598
verdicts (every single-bit flip of 22 vectors, plus the untouched vectors).
The only known C/Rust difference in the codecs is the C-only K-1 size cap
(section 5.3), which the flips cannot reach because they keep the length, and
the C-only `CC_E_ARG` caller-bug class, which no decoder input reaches.
