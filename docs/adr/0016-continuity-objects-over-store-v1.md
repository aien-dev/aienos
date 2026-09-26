# ADR 0016: Continuity objects over System Store v1

Status: **Proposed.** Implemented as a QEMU qualification only. The object
encodings below are a durable data format, so they are not frozen until the
operator approves (escalation trigger: irreversible data formats). Until then
every object carries format version 0 and every store holding them is
disposable test media.

Related: ADR 0003 (minimal object store), ADR 0006 (Recovery Core),
ADR 0007 (provisioning once), ADR 0015 (System Store v1 format),
docs/CONTINUOUS_EXISTENCE_AMENDMENT.md (Class A state, commit-before-observation).

## Context

System Store v1 (ADR 0015) gives AIENOS a crash-safe, generation-numbered,
content-addressed object store over the native NVMe driver, qualified in
QEMU at 4096- and 512-byte LBA (#134, #136). It stores opaque objects; it does
not know what AIEN is. ADR 0007 requires that a normal boot locate, verify
and resume one durable `LogicalAgentId`, and never mint a replacement. M4 is
not done when storage works; it is done when a cold restart returns the same
identity and the same committed memory.

## Decision

Continuity state is a small set of Store v1 objects with canonical,
fixed-layout little-endian encodings (no serde, no JSON, `no_std`), defined in
`aienos_kernel::continuity`. Every Store transaction that changes Class A
state also writes a new `ContinuityManifest`, so each Store generation has
exactly one continuity view.

Object kinds (Store v1 `kind`; Store `version` is 1 because Store v1 rejects
version 0; each object's own 16-byte header carries `format_version = 0`
while this ADR is Proposed, and decoders reject any other value):

| kind | name | written | content |
|---|---|---|---|
| 16 | `AgentRoot` | once, at provisioning | magic, `LogicalAgentId` (32 B), `genesis_store_uuid` (16 B) it was provisioned into, root `LogicalBranchId`, provisioning generation, provisioning source (operator / test) |
| 17 | `ContinuityManifest` | every Class A commit | magic, `AgentRoot` ObjectId, `previous_manifest_id` (zero for the first or migration boundary), `migration_parent_id` (zero normally; points to `MigrationManifest` on the first manifest of a migrated store), sequence (previous + 1), incarnation (boot counter), ObjectIds of: agent-state checkpoint, Cortex checkpoint, Cortex WAL segments (bounded list), admission receipts (bounded list) |
| 18 | `AgentStateCheckpoint` | when branch state changes | canonical branch table: branch id, parent, agent id, depth, fork counter |
| 19 | `CortexCheckpoint` | when Cortex compacts | canonical committed records |
| 20 | `CortexWalSegment` | on each committed Cortex update | append-only records since the checkpoint |
| 23 | `MigrationManifest` | once, on store migration | magic, `AgentRoot` ObjectId, `genesis_store_uuid`, `origin_store_uuid`, `target_store_uuid`, origin `SecurityManifest` and `ContinuityManifest` IDs, origin sequence/incarnation/epoch, origin rollback-anchor digest, migration sequence, offline owner authorization signature |

Boot resolution (deterministic, no model, no network):

1. Open the Store (ADR 0015). A `DegradedRecovery` mount is read-only: resume
   is allowed for inspection, but no new incarnation is committed; report
   `CONTINUITY: DEGRADED`.
2. Count `AgentRoot` objects in the catalog.
   - 0 and provisioning was explicitly requested for this boot: create one
     `LogicalAgentId` from the boot entropy source, commit `AgentRoot` and the
     first manifest in one transaction, report `CONTINUITY: PROVISIONED`.
   - 0 otherwise: **stop** with `CONTINUITY: UNPROVISIONED` (Recovery Core).
     Never mint.
   - more than 1: **stop** with `CONTINUITY: CONFLICT` (Recovery Core).
   - exactly 1: continue.
3. The current manifest is the unique catalog manifest that no other manifest
   names as previous, whose chain reaches either the genesis first manifest
   (`previous_manifest_id = 0, migration_parent_id = 0`) or a validated migration
   boundary (`previous_manifest_id = 0, migration_parent_id = MigrationManifest ID`)
   with strictly consecutive sequence numbers and the same `AgentRoot` id.
   Anything else (fork, gap, dangling reference, foreign root, undecodable object)
   stops with `CONTINUITY: CORRUPT` (Recovery Core), never with a new identity.
4. Resume: verify every object the manifest names decodes; commit a new
   manifest with `incarnation + 1` (commit-before-observation: the new
   incarnation is durable before AIEN acts on it); report
   `CONTINUITY: RESUMED agent=<id> incarnation=<n> sequence=<s>`.

Provisioning is only reachable from an explicit request (QEMU control block
today; an operator-authenticated Recovery Core action on hardware later,
ADR 0006). The normal boot path contains no code that writes an `AgentRoot`.

## Qualification (QEMU)

`CONTINUITY_QEMU: PASS` requires, over the real NVMe path at 4096-byte LBA:

- provision → commit Cortex facts and a branch fork → cold restart → same
  `LogicalAgentId`, same facts, same branch lineage, incarnation + 1;
- a second restart advances the incarnation again and changes nothing else;
- SIGKILL at every Store checkpoint of a continuity commit → reopen resumes
  the old or the new manifest, never a third state, same identity;
- identity-loss refusal: an unprovisioned store booted normally stops with
  `UNPROVISIONED` and writes nothing; a store with two roots stops with
  `CONFLICT`; a broken manifest chain stops with `CORRUPT`;
- `DegradedRecovery` mounts resume read-only and commit nothing.

## Consequences

- M4 continuity is proven in QEMU without freezing the encodings; freezing is a
  separate operator decision that turns version 0 into version 1 with golden
  vectors, as ADR 0015 did.
- The host crates `aienos-agent-state` and `aienos-cortex` remain the richer
  std models; their persisted form becomes these canonical objects.
- Encryption (M5) wraps these objects later; this ADR fixes structure, not
  confidentiality.
- The Store v1 catalog is append-only and bounded (4096 entries), and every
  Class A commit adds a manifest, so continuity needs catalog compaction before
  long-running use. Out of scope here; tracked as follow-up.
- Provisioning entropy is `RNDR` (FEAT_RNG). If the CPU does not implement it,
  provisioning fails closed (`CONTINUITY: NO_ENTROPY`); it never falls back to
  a predictable identity. Whether Machine 1's cores implement FEAT_RNG is a
  hardware fact to record at the qualification wave.
