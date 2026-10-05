# ADR 0018: ALLEN Subject State Object (Continuity Kind 24)

Status: **Proposed.** Companion to [ARCH-0035](https://github.com/aien-dev/aien-architecture/blob/main/docs/adr/0035-persistent-cognitive-entity-boundary-allen.md) (Persistent Cognitive Entity Boundary, PROPOSED). Format freeze needs operator approval, as for [ADR 0016](0016-continuity-objects-over-store-v1.md).  
Related: [ADR 0007](0007-continuous-existence-provisioning-once.md) (Provisioning Once), [ADR 0015](0015-system-store-v1-format.md) (System Store v1), [ADR 0016](0016-continuity-objects-over-store-v1.md) (Continuity Objects), [ADR 0017](0017-m5-key-hierarchy-and-encrypted-store.md) (Sealed Store), omega ARCH-0022 (Cortex), omega R16 (orchestrator retirement).

---

## 1. Context

The ALLEN investigation (aien-architecture, 2026-10-04) found that AIENOS already keeps the organism's identity across restarts (AgentRoot, kind 16; ContinuityManifest, kind 17; branch table, kind 18), that omega's Cortex keeps its memory, and that the resident World keeps its cognition, but that **nothing durable says what the subject currently intends**. A standing goal lives only in a World object; a restart loses it even though the Cortex journal recorded it (the negative control in omega `tests/allen/run.sh` shows a restarted World with 0 goals and a journal with 15 records).

The word "AIEN" was carrying four meanings. ARCH-0035 keeps two (the organism; the cognitive faculty) and names the third, the durable subject inside the organism, **ALLEN**. This ADR is the AIENOS half of that boundary: the smallest durable, typed, versioned state object for the subject, over the persistence mechanism AIENOS already has.

What was rejected before this design (recorded in the investigation delta note):

- *Payload of kind 18.* Kind 18 is the branch table (`cc_state`), already taken; a subject record inside it would couple intent to branch bookkeeping.
- *A slot in the ContinuityManifest.* The manifest (kind 17) has no free slot and its format is frozen pending operator approval; a new field would bump its version for every Store.
- *A new `AllenId`.* The subject is the agent the AgentRoot already names. A second identity would have to be kept in step with the first and would let the two drift. The subject object **carries** the LogicalAgentId and the AgentRoot id; it never mints one.
- *Keeping the standing goal in Cortex.* Cortex is memory: an append-only record of what happened. A standing intent is a claim about the present, resolved by the kernel, not a recollection replayed by a faculty.

## 2. Decision

### 2.1 One new continuity kind

Kind **24, SubjectState** (`CC_KIND_SUBJECT`), a Store v1 object (claim version 1) like the kinds of ADR 0016. It is additive: the existing resolver ignores kinds it does not track, so a Store with no kind-24 object resolves exactly as before. The reference implementation is `native/kernel/svc/continuity_subject.{h,c}`.

### 2.2 Layout (little-endian, fixed, 16-byte header as ADR 0016)

| field | bytes | meaning |
|---|---|---|
| header | 16 | magic `AIENSUBJ`, format_version u16 = **0**, reserved u16 = 0, body length u32 |
| root | 32 | logical ObjectId of the AgentRoot this subject belongs to |
| agent | 32 | LogicalAgentId; must equal that AgentRoot's |
| previous | 32 | ObjectId of the prior subject object; zero only for sequence 1 |
| sequence | 8 | previous.sequence + 1; 1 for the first (genesis) subject object |
| cortex | 32 | Cortex lineage reference: digest of the journal's record 1; zero = unbound |
| provenance | 32 | who or what established this object (operator key id or receipt digest); nonzero |
| origin | 1 | 1 operator, 2 promoted |
| reserved | 7 | zero |
| n_intents, n_knowledge | 2 + 2 | 0..64 each |
| reserved | 4 | zero |
| intents | n × 96 | strictly ascending by id |
| knowledge | n × 48 | strictly ascending by digest |

Largest object: 9416 bytes, inside the K-1 cap (16384). The logical ObjectId is `cc_object_id(24, bytes, len)`; the same bytes give the same id on any machine, under any model, in any process.

**Intent (96 bytes):** id 32, supersedes 32 (zero = none), kind u32, state u8 (1 ACTIVE, 2 INACTIVE, 3 SUPERSEDED), reserved 3, since u64 (the subject sequence that created it), payload 2 × u64. `id = SHA-256("AIENOS_INTENT_v0:" || agent || kind || since || payload[0] || payload[1])`, recomputed on decode. v0 defines one kind, **1 = GOAL_LATENCY** (payload: regime, target ns), the one goal shape the resident AIEN faculty reads today (omega `rx_aien.h`). Rules: at most one ACTIVE intent per (kind, payload[0]) slot; a SUPERSEDED intent is named by exactly one newer intent; `supersedes` must name an older, SUPERSEDED intent in the same table; `since <= sequence`.

**Knowledge (48 bytes):** digest 32 of a Cortex promotion record, record u64 (informative), since u64. Knowledge is held by digest only; the record itself stays in Cortex.

### 2.3 What the object does not hold

No capability, no weight, no model digest, no machine, process, queue or faculty reference. Model independence is structural: there is no field in which a model could be named. The model that happens to be loaded is provenance a host tool may print; it is stored nowhere in the subject.

### 2.4 Resolution and commit

`cs_resolve` runs over the same `cr_source` as the other continuity objects: every kind-24 object must name this Store's AgentRoot and LogicalAgentId (a foreign one is CORRUPT, never adopted); the chain must be gap-free, fork-free and link-correct from sequence 1 to the head; an undecodable object or an unknown claim version is CORRUPT. A Store with a root and no subject object is **ABSENT**: the kernel reports it; it never mints a subject on its own.

`cs_commit` writes one kind-24 object in its own Store transaction and only if it continues the chain the caller just resolved (the head id must equal `previous`; a stale successor and a second genesis are refused, nothing is written).

### 2.5 Authority

The subject object is state, not authority. Nothing in `continuity_subject.c` mints, grants, dispatches, waits, sleeps, polls or schedules; the file compiles for the host test and the no_std kernel without a thread or a clock. How a standing intent becomes a goal the organism acts on is the omega side (ARCH-0035 §R16): ALLEN publishes typed state through the World's external publication path, and the World's dependency machinery wakes the faculty. No AIENOS code calls a faculty.

### 2.6 Mutants

Four mutants (`CS_MUTANT_ACCEPT_FOREIGN`, `CS_MUTANT_ACCEPT_TWO_ACTIVE`, `CS_MUTANT_SKIP_INTENT_ID`, `CS_MUTANT_ACCEPT_FORK`) are test-only, each must turn the host test red, and each is refused by `#error` under `CK_HARDWARE_STAGING`.


### 2.7 Native genesis and restore (two paths)

**PROVISION** is the only path that creates a subject. `cs_provision` (`native/kernel/svc/continuity_subject_provision.c`) wraps the Store sink that `cr_provision` (ADR 0016) already uses: inside that single `cr_sink.transact` call it decodes the AgentRoot being written, builds the genesis subject (sequence 1, provenance, origin, the Cortex lineage reference from the provisioning request) and appends it as one more object of the **same** transaction. The barrier is the existing sealed Store commit (`ss_transact`, ADR 0017: payload objects, catalog, commit record, flush, inactive superblock, flush, anchor); there is no second WAL, no second database and no other write path. A crash anywhere leaves either an unprovisioned Store or an identity with exactly one genesis subject; "identity without subject" cannot be produced by a power cut. After the commit it resolves the Store again and refuses unless the subject on media is the genesis it sent. A Store that is already provisioned is refused (`AlreadyProvisioned`, nothing written); an image with subject objects but no root is CORRUPT. A standing intent given at provisioning is written afterwards with `cs_commit` (sequence 2), through the same Store.

**RESTORE** never creates one. On every resume the kernel resolves identity read-only, then `cs_resolve`: RESOLVED prints the subject and resume continues; ABSENT is reported and resume continues with no subject minted; CORRUPT (fork, gap, foreign root or agent, undecodable object) stops before anything is written, so a damaged subject is never replaced by a fresh one. The restore plan carries only the mode: the subject, its intents and its lineage come from the disk.

In the kernel the two paths live in the TEST continuity image (`make full CK_TEST_CONTINUITY=1`), the only image that provisions an identity today; the default image provisions no identity and therefore no subject. Two more TEST-only mutants (`CS_MUTANT_RESTORE_MINTS`, `CS_MUTANT_ACCEPT_FOREIGN` in the kernel image) and one host mutant (`CS_MUTANT_PROVISION_SPLIT_TXN`) must be killed by the gates; each is refused under `CK_HARDWARE_STAGING`.

## 3. Qualification

Status vocabulary: IMPLEMENTED / TESTED / QUALIFIED / NOT_RUN / FUTURE.

| claim | status | evidence |
|---|---|---|
| codec, rules, resolver, committer | IMPLEMENTED, TESTED (host) | `make -C native/kernel test`: `test_continuity_subject: PASS (150 checks)`, inside `CK_CORE_HOST: PASS` |
| known-answer layout | TESTED | hand-written bytes and `sv1_object_id` twin agree |
| refusals (version, reserved, lengths, zero ids, origin, intent id, states, supersession, order, fork, gap, link, foreign root/agent) | TESTED | `t_refusals`, `t_intents`, `t_resolve` |
| sealed Store: provision, genesis commit, stale successor refused, second genesis refused, reopen, resume, same id | TESTED | `t_sealed_store` (real `disk_file` image, M5 test keys, mocked RNDR) |
| **process restart over one sealed Store image** (writer process exits; a second process resolves the same subject id, sequence 2, one intent regime 7 / 1000 ns) | TESTED (host) | `make -C native/kernel test-continuity-subject-restart`: `CK_CONTINUITY_SUBJECT_RESTART: PASS` |
| mutants load-bearing and refused in hardware staging | TESTED | `make -C native/kernel continuity-subject-mutants`: `CK_CONTINUITY_SUBJECT_MUTANTS: PASS` |
| sanitizer build | TESTED | host-san target of the same test |
| native genesis inside the provisioning transaction; exactly once; refusals; power cut at 9 checkpoints and every block boundary (4096 and 512 byte blocks) leaves unprovisioned or identity + one genesis, never one without the other | IMPLEMENTED, TESTED (host) | `make -C native/kernel test`: `test_continuity_subject_provision: PASS`; `make -C native/kernel continuity-mutants`: `CK_CONTINUITY_SUBJECT_PROVISION_MUTANTS: PASS` (split-transaction mutant killed) |
| **QEMU cold restart over emulated NVMe** (gate `M4_ALLEN`, `scripts/qemu_ck_allen_test.sh`): G7 kernel genesis + one standing intent during provisioning; G8 second provisioning refused; G9 two restores, each a new QEMU process with the same image, same subject, intent and lineage; G10 the subject comes from the disk only; G11 fork, flipped envelope and missing subject never re-provision; G12 a foreign subject chain is refused; SIGKILL at all 9 checkpoints of the genesis transaction then a cold boot | TESTED (QEMU) | receipts `evidence/allen_native_qemu_cfe9aecffb8b20e0c1ff51fad54c46c522ec7d6c56c6cba7661e4b8cda1ee25a.json` and `evidence/ck_gates_1ecf5bcd303bf88422dd0542f14851c931f5d52276838fa182c812f3c73f3c1b.json` (full `ck_gates.sh` at `640522a`), gate log `evidence/allen_native_m4_allen_f50447aa35e01c30deaf5508bc88e5fa3e011ae49d34fd2010f6eefe280a35bb.log`, omega cross-check `evidence/allen_native_omega_xcheck_d0f88c96c7785db00c4a97bc09a6204e8fc5fcff32dbf6cde4a993f155b91111.log`; mutants `subject_restore_mints` and `subject_accept_foreign` KILLED |
| hardware (Spark NVMe, Secure Boot chain, physical cold reboot) | NOT_RUN | host tests and an emulator are not hardware qualification |
| OS reboot, machine migration | NOT_RUN | not claimed |
| multi-subject Stores | FUTURE | the format does not preclude it (root + agent per object); v0 resolves one chain per root |
| manifest link to the subject head | FUTURE | the manifest (kind 17) is frozen; v0 resolves the subject chain by scan |

## 4. Consequences

- A restart now has somewhere to read what the subject intends; whether it does is the omega side (ARCH-0035 gates G2 and G6).
- `docs/ARCHITECTURE.md` §10 and `CONTEXT.md` ("AIEN Agent") are corrected in this change: AIEN is the continuous organism; ALLEN is the durable subject it sustains. `docs/BLUEPRINT.md` and the Continuous-Existence Amendment keep their historical wording until ARCH-0035 is accepted.
- The resolver gains one pass per kind-24 object; the kernel's recovery and repair tools do not yet display kind 24 (FUTURE, with the manifest link).
- Nothing changes for Stores without a kind-24 object.

## 5. Open questions for the operator

1. Freeze format_version 0 of kind 24 together with ADR 0016, or keep both open until hardware qualification (the QEMU cold-restart run for kind 24 now exists, §3).
2. Whether `origin = promoted` (a subject object written from a Cortex promotion rather than by the operator) is allowed before AEGIS review of the promotion path.
