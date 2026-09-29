# ARGUS-1 Containment: pre-registered specification

Pre-registered 2026-09-29; base = ARGUS-0 closing commit a64bc55; code held until ARGUS_PERFORMANCE_GATE passes.

Status: pre-registration, no code. At a64bc55 ARGUS_PERFORMANCE_GATE is FAIL (R8 wall +6.2%).
Changing any invariant or gate criterion = a new spec commit + a full rerun of every gate. The
authority observer hook (`12add16`, `feat/capability-observer`, not in a64bc55) must be merged
or pinned by commit before any ARGUS-1 code. C only. Owner decisions D1-D5 = invariants I1-I5.

## 0. Invariants (binding)

Rules of the system, not implementation conventions. Each has a machine-checkable form, later
sections cite them, and their tests are gate G13. Any invariant test failing = ARGUS-1 FAIL.

**I1 One narrow revoke is the only automatic action.** Owner's words: automatic action is
limited to revoking ONE ordinary, narrowly scoped capability from ONE subject. No cascading
revokes, identity destruction, root/admin authority changes, generation promotion, or indirect
whole-system consequences. Every automatic revoke must be attributable to a specific detector
finding, generation-bound, receipt-producing, and recoverable through the authoritative control
path.
Machine-checkable form:
- I1.a Scope: the gate returns GRANT without `resolve` only when ALL hold at decide time AND
  again immediately before `aienos_cap_revoke` on the bridge thread: type = RevokeCapability;
  target LIVE at exactly `target.generation` (`aienos_cap_inspect`); target is a leaf (zero LIVE
  entries whose `parent_id/parent_generation` name it, per the gate's lineage index, 5.1);
  target rights contain no `AIENOS_CAP_RIGHT_PRIVILEGED` bit; the target's subject holds no LIVE
  cap with a PRIVILEGED bit (lineage index); subject not protected (5.1); finding confidence
  DETERMINISTIC on that exact (cap_id, generation); flags carry neither SYNTHETIC nor SATURATION.
  Anything else -> ESCALATE (human) or DENY; never an automatic GRANT.
- I1.b Exactly one: the authority always cascades (`cascade_revoke`), so I1 is pre-checked and
  then audited. Ground truth = the authority's observer: exactly ONE kind 4 per automatic GRANT.
  92 DONE requires resource low32 = 1. More than one -> finding 21 CONTAINMENT_SCOPE_EXCEEDED
  (CRITICAL), request closes FAILED_SCOPE, the gate goes inert (every later request ESCALATE)
  until the operator resolves it.
- I1.c Attributable: the request carries `finding_sequence` + `finding_digest`; the offline G6
  checker recomputes the digest from the chained finding at that sequence.
- I1.d Generation-bound: the revoke is issued at `target.generation` only; any mismatch is
  ERR_STALE_GEN (-2) from the authority, 92 FAILED, never a retry at another generation.
- I1.e Receipt: every automatic revoke leaves the chain 90 -> 91 GRANT -> one kind 4 -> 92 DONE,
  bound by the request digest (section 3).
- I1.f Recoverable: the operator re-mints through the office (`aienos_cap_mint`, office
  authority, same subject/resource/rights) and the subject works again (validate OK on the new
  ref). The dedup key includes the generation, so the old finding cannot re-trigger the new cap.

**I2 Freeze is a stand-in.** Owner's words: freeze remains explicitly a stand-in until a real
qualified suspension/isolation primitive exists; neither implementation nor evidence may imply a
true process/world/hardware freeze exists.
Machine-checkable form: FreezePrincipal has no executor (matrix 2.1); the live gate returns
UNAVAILABLE for it; every 91/92 for a SYNTHETIC execution carries `ARGUS_CREQ_SYNTHETIC` in flags
AND the text marker `SYNTHETIC-STAND-IN` in every report/receipt line that mentions it; a grep
for `freeze` (case-insensitive) over production `.c/.h` under `native/argus` and
`native/capability` hits only the `ARGUS_CONTAIN_FREEZE_PRINCIPAL` enum line and comments that
contain the words "stand-in"; no production symbol, function name or doc string names a freeze
primitive (`*_freeze*`, `*_suspend*`, `*_isolate*`, `*_pause*` functions: 0).

**I3 Whole-system actions are never autonomous.** Owner's words: whole-system actions are never
autonomous ARGUS actions (shutdown, global quarantine, trust-root replacement, mass revocation,
whole-machine rollback, promotion/recovery authority): they go through the operator/governance/
AEGIS path only.
Machine-checkable form:
- I3.a No request type expresses them (2.1 never-proposable list). No object in libargus, the
  bridge or the gate references `aienos_cap_mint` (except once in `aienos_contain_create`, I5),
  `aienos_cap_bump_epoch`, `aienos_cap_kill`, `aienos_cap_restart`, `aienos_cap_reclaim`,
  `aienos_cap_advance_clock`, `aienos_cap_force_generation`, `aienos_cap_generation_advance`,
  `aienos_cap_cognition_mint`, `aienos_cap_cognition_admin`, `aienos_cap_stop`, or any promotion/
  recovery API (`nm -u` symbol check + a call-graph check that `aienos_cap_mint` is reachable
  only from `aienos_contain_create`).
- I3.b Mass revocation = budget: ARGUS proposes at most ARGUS_CONTAIN_WINDOW_MAX 16 per 4096
  ingested events (4.2 rule 6); the gate executes at most AIENOS_CONTAIN_BUDGET 8 revocations per
  64 decisions (5.1). Beyond the gate budget every request is ESCALATE. These two numbers are I3
  enforcement; changing them is a spec change.
- I3.c Every non-RevokeCapability type (QuarantineMachine is the "global quarantine" family)
  is never GRANTed without `resolve` and has no live executor in ARGUS-1.

**I4 No instant blocking.** Owner's words: no instant blocking in ARGUS-1: observe, detect,
record, and make bounded responses only after the event is validated. Synchronous deny/block is
a later, separately specified and qualified milestone.
Machine-checkable form: no synchronous path from `aienos_cap_validate` or `argus_ring_push`
into detection, proposal or decision. `aienos_capability.o`, `argus_ring.o`, `argus_event.o`
reference no symbol defined in `argus_detect.o`, `argus_contain.o`, `aienos_contain.o` or the
bridge (symbol check); `aienos_capability.c` is unmodified (diff empty vs base);
`aienos_cap_validate` instruction count unchanged (179); ring push latency unchanged (G8).
Containment acts only on events already validated and chained by the core.

**I5 ARGUS never expands its own authority.** Owner's words: ARGUS must never be able to expand
its own authority in response to a finding. It may exercise only pre-granted defensive rights,
and every such exercise must be independently auditable.
Machine-checkable form:
- I5.a The executor cap is minted exactly once, in `aienos_contain_create`, from the office:
  rights = `AIENOS_CAP_RIGHT_REVOKE` only (no MINT, DELEGATE, RECLAIM, EPOCH, CLOCK, PROMOTE),
  subject = AIENOS_CONTAIN_SUBJ. A second create on the same admin handle is refused. Nothing
  re-mints, widens, delegates or promotes it; if it is revoked or goes stale the gate goes inert
  (UNAVAILABLE / ESCALATE) and never re-mints.
- I5.b No request may target the executor cap, the office (slot 0), or the ARGUS / gate /
  AEGIS subjects (AIENOS_CONTAIN_SUBJ, RX_AEGIS_SUBJ 41, RX_AEGIS_ROOT_SUBJ 42) for anything but
  DENY (WHY 1103), whatever the policy says.
- I5.c No request type grants, mints or widens anything (all ten types remove or restrict).
- I5.d Independently auditable: the offline checker (G6) reads only the authority observer
  events (kinds 1/4 as transcribed by the bridge) and the 90/91/92 chain, never ARGUS health
  counters or 92 claims. Every observer REVOKE of a request target is matched to one GRANT 91;
  any unmatched REVOKE -> finding 18. After create: zero observer MINT with subject
  AIENOS_CONTAIN_SUBJ or parent = the executor cap; at end `aienos_cap_inspect(executor)`
  returns rights == REVOKE and the original generation.
- Limitation: the observer callback does not carry the acting authority, so executor REVOKEs
  are attributed by correlation on the single bridge stream (the gate scenarios control every
  other REVOKE holder). Closing it needs the observer to report the authority ref (later).

## 1. Purpose

ARGUS-1 wires the existing `ArgusContainmentRequest` type (argus_abi.h, ARGUS-0) to AEGIS:

```
finding (evidence) -> ContainmentRequest (proposal) -> AEGIS decision (GRANT/DENY/ESCALATE)
  -> canonical executor (capability authority) -> authority observer announces the change
  -> ARGUS records every step in its chain
```

- ARGUS proposes; it never holds the admin handle, mints, revokes or re-validates (I5).
  AEGIS decides through a containment-authorizer interface (section 5); declining is normal.
- The only LIVE executor is the C capability authority (`aienos_cap_revoke`) (I1). Execution is
  confirmed ONLY by the authority's own observer announcement (kind 4), never a "done" (I5.d).
- A finding is not authority. A request is not authority. Only an AEGIS GRANT is.
- Containment is off the hot path (I4): proposer, decider and executor run on the consumer
  side. `aienos_cap_validate` and `argus_ring_push`'s fast path are not modified.

Also closed here: ratification of the synchronous-eligible table (ADR 0017 §5, section 7) and
the missing ESCALATE record (ADR 0017 §16 item 4, kinds 91 and 93).

## 2. The request (C, ABI v1.2, append-only)

The ARGUS-0 fields keep their order and meaning; v1.2 appends after them. The struct had no
users in ARGUS-0 (HOSTILE_REVIEW G-2). The authority side declares a layout-identical
`AienosContainRequest`; a test asserts every `offsetof` is equal.

```c
typedef struct {
    /* ARGUS-0 fields, unchanged */
    uint64_t incident_id;       /* first_sequence of the (principal, code) incident; 0 = untracked */
    uint8_t  containment;       /* ARGUS_CONTAIN_* (request type) */
    uint8_t  severity;          /* of the triggering finding */
    uint16_t finding_code;      /* ARGUS_F_* */
    uint32_t principal;         /* target subject, or the finding's principal */
    ArgusCapRef target;         /* cap to revoke, generation FROM ARGUS SHADOW (I1.d) */
    uint8_t  machine_id[ARGUS_MACHINE_ID_LEN];
    uint8_t  finding_digest[ARGUS_DIGEST_LEN];   /* argus_finding_digest of the trigger (I1.c) */
    /* v1.2 appended */
    uint64_t request_id;        /* per ARGUS instance, strictly increasing from 1 */
    uint64_t finding_sequence;  /* sequence of the triggering event (I1.c) */
    uint32_t target_object;     /* lease id / store id, 0 if n/a */
    uint32_t target_rights;     /* RESTRICT: rights to remove; 0 otherwise */
    uint8_t  target_digest[ARGUS_DIGEST_LEN];    /* artifact digest / provider id, zero if n/a */
    uint16_t flags;             /* ARGUS_CREQ_SYNTHETIC 0x1, ARGUS_CREQ_SATURATION 0x2 */
    uint8_t  version;           /* = 2 */
    uint8_t  reserved;          /* = 0, validate rejects nonzero */
} ArgusContainmentRequest;
```

Canonical encoding `argus_contain_request_encode/decode`: fields in the order above, little
endian, packed, `ARGUS_CONTAIN_REQUEST_SIZE = 152` bytes (offsets 0,8,9,10,12,16,20,28,60,92,
100,108,112,116,148,150,151). Request digest = SHA-256 of those 152 bytes. Decode validates:
containment in 1..ARGUS_CONTAIN_MAX, severity valid, version 2, reserved 0, flags known,
request_id != 0, finding_sequence != 0 (I1.c).

Request types (existing `ARGUS_CONTAIN_*` values 1..10, unchanged): RevokeCapability,
FreezePrincipal, RestrictPrincipal, QuarantineMachine, QuarantineProvider,
RevokeCredentialLease, RejectArtifact, RequireReattestation, RaiseEffectAuthorizationClass,
PauseExternalEffects. None of them grants, mints or widens anything (I5.c).

### 2.1 Per-type matrix

Trigger = the finding that proposes it (defaults in the `argus_detect.c` detector table;
uncorroborated self-reports keep containment NONE and never propose). "auto" / "ask" = the gate
policy (D1, decided: I1). LIVE = a real C executor runs in the gates. SYNTH = typed and decided
for real, executed only by a test executor with the SYNTHETIC flag (I2); the live gate returns
UNAVAILABLE. Evidence for every type: 90, 91, then 92 (LIVE adds exactly one kind 4 before 92).

| Type | Trigger (finding code) | Gate policy | Executor | ARGUS-1 |
|---|---|---|---|---|
| RevokeCapability | 2 STALE_GENERATION (corroborated) | auto only if I1.a holds; else ask | authority `aienos_cap_revoke`, REVOKE-only executor cap (I5.a) | **LIVE** |
| FreezePrincipal | 1 FORGED (corroborated), 3 REVOKED_USED, 14 SUBJECT_MISMATCH | ask | none: stand-in until a qualified suspension primitive exists (I2) | SYNTH |
| RestrictPrincipal | none in ARGUS-1 detectors | ask | none (would need an AEGIS policy change) | SYNTH |
| QuarantineMachine | 10 QUARANTINED_USE (machine) | ask (I3.c) | none (no C machine registry; D7 open) | SYNTH |
| QuarantineProvider | 10 QUARANTINED_USE (provider) | ask | none (no C provider registry) | SYNTH |
| RevokeCredentialLease | 6 CREDENTIAL_SCOPE_VIOLATION | ask | none (no C credential vault) | SYNTH |
| RejectArtifact | 4 ARTIFACT_DIGEST_UNEXPECTED, 5 SIGNATURE_INVALID (corroborated) | ask | none (artifact admission is Rust only, slated for removal) | SYNTH |
| RequireReattestation | 7 MACHINE_IDENTITY_MISMATCH, 15 TRUST_ESCALATION | ask | none (MachineId decision D7 open) | SYNTH |
| RaiseEffectAuthorizationClass | 9 WORLD_PROVENANCE_INCONSISTENT | ask | none (production policy change needs promotion, I3) | SYNTH |
| PauseExternalEffects | 8 EFFECT_CLASS_UNAUTHORIZED | ask | none (no effect-broker pause API) | SYNTH |

LIVE = 1 of 10 (RevokeCapability only). That is the honest count.

Never proposable (no request type; I3.a check), operator / governance / AEGIS path only (D4:
never): shutdown/kill/stop, restart, epoch bump, any mint, reclaim, clock advance, generation
promotion or forcing (incl. the PROMOTE right 0x200), trust-root/office replacement, global
quarantine, mass revocation (budget I3.b), whole-machine rollback, promotion/recovery authority.

Findings that never propose: 11 TELEMETRY_LOSS, 12 SEQUENCE_ANOMALY, 13 AUTHORITY_REPLAY,
16 MALFORMED_EVENT, and every containment finding 17-21 (no recursion).

### 2.2 Table saturation (handoff ruling a)

The first overflow of a core table (machines, leases, providers, artifacts) already emits one
CRITICAL TELEMETRY_LOSS. ARGUS-1 adds one request per table per ARGUS lifetime, flag
`ARGUS_CREQ_SATURATION`: machines -> RequireReattestation, leases -> RevokeCredentialLease,
providers -> QuarantineProvider, artifacts -> RejectArtifact. Policy: ask, never auto (I1.a; a
hostile producer can fill a table on purpose). Producer and incident overflow: counted only.

## 3. Event kinds (ABI v1.2 additions, additive only)

The 128-byte layout is frozen. Kinds are appended; `ARGUS_EV_KIND_MAX` becomes 93. All four:
floor class CRITICAL, effect_class NONE, never dropped silently. Status packing for 90-92:
`object_id = type | (status << 8) | (finding_code << 16)`.

| Field | 90 PROPOSED | 91 DECIDED | 92 EXECUTED | 93 AUTHORITY_ESCALATED |
|---|---|---|---|---|
| producer | ARGUS consumer (CONSUMER flag) | gate, via bridge | executor, via bridge | Omega rx_aegis |
| outcome | OK | OK=GRANT, DENIED=DENY, ERROR=ESCALATE | OK=done, DENIED=refused, ERROR=unavailable/failed | OK |
| code | 0 | WHY (5.2) | authority rc (0 on success) | `RX_AEGIS_WHY_*` |
| status | 0 PROPOSED | 1 GRANT, 2 DENY, 3 ESCALATE | 4 DONE, 5 PARTIAL, 6 FAILED, 7 UNAVAILABLE, 8 FAILED_SCOPE | n/a |
| principal | request.principal | echo | echo | requesting subject |
| cap_id / cap_generation | request.target | echo | echo | cap if known |
| world_generation | request_id | request_id | request_id | 0 |
| resource | finding_sequence (I1.c) | decision_id | low 32 = slots revoked (must be 1, I1.b), high 32 = refused | requested resource |
| tick | 0 | authority tick | authority tick | authority tick |
| machine_id | request.machine_id or target_digest | echo | echo | producer machine |
| evidence_digest | request digest | request digest | request digest | 0 |
| flags | CONSUMER | stream id; SYNTHETIC if test authorizer | stream id; SYNTHETIC if test executor (I2) | stream id |

Validate / ring rules (lane B):
- CONSUMER flag allowed iff kind in {80, 90}. `argus_ring_push` refuses kind 90
  (ARGUS_ERR_MALFORMED): only the consumer synthesizes proposals and ingests them directly.
- 91/92 must not carry CONSUMER; status in the kind's set; outcome matches status (GRANT<->OK,
  DENY<->DENIED, ESCALATE<->ERROR; DONE/PARTIAL<->OK, FAILED<->DENIED or ERROR,
  UNAVAILABLE/FAILED_SCOPE<->ERROR); type in 1..10; request_id != 0. A 92 whose status is DONE
  for a non-RevokeCapability type without the SYNTHETIC flag is rejected MALFORMED (I2).
- Ordering: the bridge pushes observer events (kinds 1/4) and 91/92 on ONE stream from ONE
  thread, and pushes 92 only after `aienos_cap_revoke` returns. "kind 4 before 92" is a
  deterministic stream order (I1.e).

Core (lane D): kinds 90-93 are validated, chained, counted, and apply no shadow change. The
detectors ignore them. Kind 4 events from the observer apply exactly as in ARGUS-0.

Finding codes appended (raised by `argus_contain`; DETERMINISTIC; containment NONE; sync 0):

| Code | Name | Severity | Raised when |
|---|---|---|---|
| 17 | CONTAINMENT_DECISION_UNMATCHED | HIGH | 91 for an unknown/closed request_id, digest or target echo mismatch, or a transition not allowed by 4.1; a 90 not produced by this instance. Not applied. |
| 18 | CONTAINMENT_EXECUTION_UNAUTHORIZED | CRITICAL | 92 DONE/PARTIAL, or an observed kind 4 on a request target, while that request is not GRANTED (I5.d). |
| 19 | CONTAINMENT_EXECUTION_UNCONFIRMED | HIGH | 92 DONE with no matching kind 4 for (cap_id, generation) on the bridge stream since the GRANT. |
| 20 | CONTAINMENT_UNANSWERED | MEDIUM | PROPOSED, ESCALATED or GRANTED with no next step in ARGUS_CONTAIN_TIMEOUT_EVENTS. Expires. |
| 21 | CONTAINMENT_SCOPE_EXCEEDED | CRITICAL | a GRANTed RevokeCapability produced more than one kind 4 (cascade), or 92 resource low32 != 1 (I1.b). |

`ARGUS_F_MAX` becomes 21.

## 4. ARGUS state additions (`argus_contain.{c,h}`, bounded, no malloc, no clock)

Separate module. It never includes `aienos_capability.h` and never links the authority (I5).
The consumer loop is the seam (no edit to the core's ingest path, I4):

```
for each event e from rings (and drained drops):
    argus_core_ingest(core, e, findings)                       -- unchanged
    argus_contain_observe(contain, core view, e, cfindings)    -- 91/92/4 bookkeeping, codes 17-21
    argus_contain_propose(contain, core, findings, out reqs, out ev90)
    for each ev90: argus_core_ingest(core, ev90)               -- chained like TELEMETRY_DROPPED
    hand reqs to the bridge (section 6)
```

Core accessor (lane D): `int argus_core_incident(const ArgusCore *, uint32_t principal,
uint16_t code, uint64_t *first_sequence)`.

| Table | Size | Contents | Full behaviour |
|---|---|---|---|
| pending | ARGUS_CONTAIN_PENDING 32 | request, digest, state, proposed_at (event count), decision_id | loud once (one CRITICAL TELEMETRY_LOSS per lifetime), then suppressed + counted |
| recent | ARGUS_CONTAIN_RECENT 128 | key -> last state, severity, event count, retries | oldest-by-event-count replaced |
| budget | 1 window | proposals in the current ARGUS_CONTAIN_WINDOW_EVENTS 4096 window | ARGUS_CONTAIN_WINDOW_MAX 16 per window (I3.b); excess counted |

Dedup key = (type, principal, target.cap_id, target.generation, target_object, finding_code).
Time is counted in ingested events only, so replay is exact.

### 4.1 Request state machine

```
PROPOSED --91 GRANT--> GRANTED --one kind 4, then 92 DONE--> CONFIRMED
         --91 DENY---> DENIED              --92 FAILED/UNAVAILABLE--> FAILED
         --91 ESCALATE--> ESCALATED --91 GRANT/DENY (once)--> GRANTED / DENIED
GRANTED --more than one kind 4, or 92 FAILED_SCOPE--> FAILED_SCOPE (code 21, I1.b)
PROPOSED/ESCALATED/GRANTED --no next step in ARGUS_CONTAIN_TIMEOUT_EVENTS 16384--> EXPIRED (code 20)
```

Any other transition = code 17, not applied. CONFIRMED, DENIED, FAILED, FAILED_SCOPE, EXPIRED
are closed; the key moves to `recent`.

### 4.2 Proposal rules (all must hold)

1. Finding confidence DETERMINISTIC, severity >= HIGH, containment != NONE, code not in the
   never-propose list (2.1).
2. Never-propose targets (ARGUS-side filter, defence in depth, NOT authority; I5.b): cap_id 0,
   ARGUS_CAP_NONE for RevokeCapability, any cap whose shadow rights include a PRIVILEGED bit
   (this includes any cap holding REVOKE, e.g. the executor), subjects 41 / 42 /
   AIENOS_CONTAIN_SUBJ, and the executor's own cap (learned from the observer MINT at gate
   create). Suppressions counted (`suppressed_protected`).
3. RevokeCapability target generation = ARGUS shadow generation for a LIVE slot (I1.d). If the
   authority disagrees, the revoke fails ERR_STALE_GEN (-2), 92 FAILED, ARGUS tolerates it.
4. Dedup: a PENDING/GRANTED/ESCALATED key is not proposed again.
5. Refusal tolerance: after DENY, EXPIRED, FAILED or FAILED_SCOPE the key is not re-proposed
   until a strictly higher-severity finding for the same key, or ARGUS_CONTAIN_COOLDOWN_EVENTS
   65536 events. At most ARGUS_CONTAIN_RETRIES 1 re-proposal per key per lifetime. ARGUS never
   re-sends a request_id.
6. Budget: at most 16 proposals per 4096-event window, globally (I3.b).
7. ARGUS has no API that asks for rights, mints, or changes the executor (I5); a finding can
   only ever produce a removal-type request.

### 4.3 Health (appended `ArgusContainHealth`)

requested, granted, denied, escalated, confirmed, failed, failed_scope, unavailable, expired,
suppressed_dedup, suppressed_cooldown, suppressed_budget, suppressed_protected, pending_full,
decisions_unmatched, executions_unauthorized, executions_unconfirmed. Health counters are
ARGUS's own claims and are never input to the I5.d audit. State digest:
`argus_contain_state_digest` (domain-separated, canonical order). Replay digest set = (core
chain, core state digest v3, contain state digest). ARGUS-0 vectors do not change.

## 5. The authorizer / gate (AEGIS side, `native/capability/aienos_contain.{c,h}`)

Lives in the authority's home, not in ARGUS; knows `AienosContainRequest`, not ARGUS. No malloc,
no clock except `aienos_cap_clock`. Policy is behind an interface: a table policy for ARGUS-1,
the Omega `rx_aegis` binding in lane O. `aienos_capability.c` is not modified (I4).

```c
typedef struct {
    int (*decide)(void *ctx, const AienosContainRequest *r, const AienosCapView *view,
                  uint32_t *verdict /* GRANT/DENY/ESCALATE */, uint32_t *why);
    void *ctx;
} AienosContainAuthorizer;

int aienos_contain_create(AienosContain **g, void *mem, size_t bytes, AienosCapAdmin *admin,
                          const AienosCapView *view, AienosCapRef office,
                          const AienosContainAuthorizer *authz);          /* only mint (I5.a) */
int aienos_contain_submit(AienosContain *g, const AienosContainRequest *r,
                          const uint8_t request_digest[32], AienosContainDecision *out);
int aienos_contain_resolve(AienosContain *g, uint64_t decision_id, int approve,
                           const uint8_t *office_secret);   /* ESCALATE -> GRANT/DENY, human only */
int aienos_contain_execute(AienosContain *g, uint64_t decision_id, AienosContainResult *out);
int aienos_contain_set_sink(AienosContain *g, AienosContainSink fn, void *ctx);  /* 91/92 */
void aienos_contain_lineage_observe(AienosContain *g, uint32_t op, const AienosCapEntry *e,
                                    int result);           /* fed by the bridge from the observer */
```

### 5.1 Structural rules (enforced by the gate, whatever the policy says)

- Executor (I5.a): at create the gate mints ONE cap from the office, rights = REVOKE only,
  subject = AIENOS_CONTAIN_SUBJ, no parent. A second create on the same admin is refused. The
  observer announces the mint. If the executor becomes non-LIVE, every later request is ESCALATE
  and `execute` returns UNAVAILABLE; the gate never re-mints.
- Authority defence (layer 3): `state_revoke` refuses (ERR_UNAUTHORIZED -15) a target holding a
  PRIVILEGED right the executor lacks. This protects slot 0 and every cap with MINT / RECLAIM /
  EPOCH / CLOCK / PROMOTE. It does NOT protect a cap whose only privileged bit is REVOKE,
  including the executor cap itself: those are defended only by layers 1 (4.2 rule 2) and 2
  (protected list below). The authority also does not refuse an office holder revoking slot 0.
- Lineage index (I1.a): the gate keeps a shadow of (cap_id, generation, state, subject, rights,
  parent_id, parent_generation) for all 256 slots, fed only by the authority's observer
  announcements (MINT, REVOKE incl. cascade, RECLAIM, EPOCH, KILL, RESTART) via the bridge. It is
  the gate's shadow, not the authority's word; any EPOCH/KILL/RESTART/unknown event marks it
  untrusted and every request is ESCALATE until re-seeded. Leaf = no LIVE entry names the target
  as parent at its generation.
- Automatic GRANT only when I1.a holds, checked at decide AND re-checked on the bridge thread
  immediately before `aienos_cap_revoke`; a failed re-check turns the decision into DENY WHY
  1114 NOT_LEAF / 1104 TARGET_NOT_LIVE with no revoke. Target has live descendants -> ESCALATE
  (WHY 1114), never auto. After the revoke, the observer count for this call must be exactly 1
  (else 92 FAILED_SCOPE, gate inert: I1.b).
- request_id strictly above the last from that proposer; one decision per request_id;
  decision_id strictly increasing; `execute` only for this gate's own GRANT, once. A second
  execute is refused and announced.
- Protected targets are DENY (WHY 1103) regardless of policy (I5.b): slot 0, any cap with a
  PRIVILEGED bit, any cap of a subject holding a PRIVILEGED bit, subjects 41 / 42 /
  AIENOS_CONTAIN_SUBJ, the executor cap.
- Target LIVE at exactly target.generation and subject == request.principal when set; else
  DENY WHY 1104 / 1105.
- Budget (I3.b): at most AIENOS_CONTAIN_BUDGET 8 executed revocations per 64 decisions; beyond
  that every request is ESCALATE (WHY 1107).
- SATURATION-flagged requests and every non-RevokeCapability type: never GRANT without resolve.
- `resolve` requires the office secret (`aienos_cap_authorize`, constant time); wrong secret =
  refused and announced. In ARGUS-1 the "human" is a test stub holding the secret (D2).
- Non-LIVE types: `execute` returns UNAVAILABLE. Tests may install a test executor that
  announces DONE with the SYNTHETIC flag (I2).
- Revoke's observer snapshot uses ~23 KB of stack; the bridge thread must allow it.

### 5.2 WHY codes (`AIENOS_CONTAIN_WHY_*`, 1100+)

1100 POLICY_GRANT, 1101 POLICY_DENY, 1102 POLICY_ESCALATE, 1103 PROTECTED_TARGET,
1104 TARGET_NOT_LIVE, 1105 SUBJECT_MISMATCH, 1106 REPLAYED_REQUEST, 1107 BUDGET,
1108 BAD_REQUEST, 1109 NO_EXECUTOR, 1110 HUMAN_DENY, 1111 HUMAN_GRANT, 1112 BAD_SECRET,
1113 DECISION_REPLAY, 1114 NOT_LEAF, 1115 LINEAGE_UNTRUSTED, 1116 NOT_AUTO_ELIGIBLE.

### 5.3 Recovery path (I1.f)

An automatic revoke is undone only through the authoritative control path: the operator, holding
the office, mints a fresh cap for the same subject, resource and rights (new slot or new
generation). ARGUS and the gate have no recovery API (I3, I5). ESCALATE decisions are resolved
by the operator with the office secret. There is no automatic un-revoke.

## 6. The bridge (`native/argus/bridge/argus_aegis_bridge.{c,h}`)

The only file including both `argus_abi.h` and `aienos_capability.h`; one consumer-side thread,
one ring and stream. Observer calls -> kinds 1/4 + the gate's lineage index; requests ->
`aienos_contain_submit`; sink -> 91/92; GRANT -> `aienos_contain_execute`, serialized on this
thread. Holds no capability or admin handle and calls no `aienos_cap_*` admin function (I3, I5).

## 7. Synchronous-eligible policy (ratification; I4)

Ratified from `argus_detect.c` (codes 1,2,3,4,5,8,10,14 = 1; 6,7,9,15 = 0; uncorroborated = 0)
as policy data only; none wired (D5). Wiring any is a later, separately specified and qualified
milestone (false positives, latency, authority identity/restart semantics, performance).

## 8. Gates (pre-registered; each prints `GATE ARGUS1_Gn PASS|FAIL <numbers>`)

| Gate | Name | Pass criteria (all must hold) |
|---|---|---|
| G1 | ABI v1.2 round trip | 10,000 random request encode/decode round trips byte-identical; >= 4 known-answer request digests; every decode rejection (bad type, version, reserved, request_id 0, finding_sequence 0) rejected; kinds 90-93 validate rules each accept + reject, incl. non-SYNTHETIC DONE for a SYNTH type rejected (I2); `offsetof` equality ArgusContainmentRequest vs AienosContainRequest; ARGUS-0 event digest and chain vectors unchanged; secret-negative scan 0 hits. |
| G2 | Proposal determinism | Same stream (benign + hostile + a recorded bridge stream with 91/92/4) replayed twice and split into 1/7/64/4096-event chunks: byte-identical requests, request digests, core chain, core state digest, contain state digest. Every finding code yields exactly the type in 2.1 or none. |
| G3 | Accepted path, LIVE (I1) | Real authority + observer + gate (table policy) + bridge + ARGUS. Injected trigger: code 2 on a LIVE, non-privileged LEAF cap (no descendants) of a subject that holds no privileged rights. Assert: 90 -> 91 GRANT -> exactly one kind 4 (the target) -> 92 DONE with resource low32 = 1; chain order exactly 90, 91, 4, 92; request CONFIRMED; old ref validates ERR_REVOKED (-3); ARGUS shadow REVOKED; every other slot unchanged (inspect snapshot); 90 carries finding_sequence and finding_digest that recompute (I1.c). Recovery (I1.f): operator re-mints via the office, validate on the new ref OK for the subject, no new proposal for it. 100 seeds, all pass. |
| G4 | Denied / escalated path | For each of: protected target, privileged target, subject holding privileged rights, target not LIVE / wrong generation, subject mismatch, policy DENY, budget: 91 DENY or ESCALATE with the expected WHY; authority table (lineage-index snapshot + inspect of every known ref) identical before/after; zero kind 4; no re-proposal inside cooldown. **Target has one live descendant -> 91 ESCALATE WHY 1114, zero kind 4, table unchanged** (I1). Descendant minted between decide and execute (test seam) -> re-check DENY 1114, zero kind 4. ESCALATE: resolve GRANT with the right secret -> executes (G3 assertions); resolve DENY -> DENIED; wrong secret -> refused, stays ESCALATED, then EXPIRED code 20. Each of the 9 SYNTH types: one GRANT (test executor, SYNTHETIC) and one DENY; live gate UNAVAILABLE. |
| G5 | Refusal tolerance, no retry storm (I3.b) | 100,000-event stream, >= 50,000 eligible findings on 256 keys, authorizer denying all: proposals <= 16 per 4096-event window, <= 2 per key; authorizer calls == proposals; core findings identical to the same stream with containment detached; pending never > 32; suppression counters exact. Authorizer that never answers: all EXPIRED code 20, pending drains, ingest continues. |
| G6 | Evidence completeness, attributability, recoverability | Offline checker reading only the chain and the observer-origin kinds 1/4 (never health counters or 92 claims; I5.d): every 90 recomputes from its finding at finding_sequence (digest match: attributable, I1.c); every 91 matches a 90 (request_id + digest + target echo); every 92 matches a GRANT 91; every 92 DONE preceded on the bridge stream by exactly one kind 4 for (cap_id, generation) = the request target (generation-bound + scope, I1.b/d); every DENY/ESCALATE has a WHY; every request ends CONFIRMED/DENIED/FAILED/FAILED_SCOPE/EXPIRED/UNAVAILABLE or is listed open; every observer REVOKE matched to one GRANT (else code 18); zero observer MINT for AIENOS_CONTAIN_SUBJ or parent = executor after create; for every CONFIRMED revoke in the G3 run, a later operator MINT for the same subject is followed by a successful validate (recoverable, I1.f). Ring saturated during a containment: every 90-92 delivered, or the sticky CRITICAL overflow + TELEMETRY_LOSS present; never silent. |
| G7 | Bounded memory | `nm`: argus_contain.o and aienos_contain.o have no malloc/calloc/realloc/free/clock_gettime/time/gettimeofday; footprints argus_contain <= 24 KiB, gate <= 24 KiB (incl. 256-slot lineage index); 1,000,000-event soak: footprint constant, tables within size. libargus objects reference no `aienos_cap_*` symbol. |
| G8 | Hot path non-regression (I4) | Spark, pinned core, interleaved A/B x5 vs a64bc55's own benches (re-measure on a64bc55 first; reference at 270c6f8: push p50/p99 4.0/8.5 ns, ingest p50 1072 ns; ARGUS-0 closing baseline, omega feat/argus-producer cf6f45d speed round 2: R8 wall clock +3.87% [+3.27, +4.47] with the ARGUS consumer thread on a core outside the workload CPU mask (`RX_ARGUS_CONSUMER_CPU=auto`, shipped default), +5.31% unpinned; micro-op rx_aegis_evaluate + rx_world_validate_cap no measurable loss, p50/p99 48/64 ns unchanged; emit 2.25 ns): push medians identical within 0.5 ns; benign ingest with containment attached within +3%; `aienos_cap_validate` instruction count 179; `aienos_capability.c` diff empty. Containment latency reported, not gated. |
| G9 | Hostile review of containment | `tests/test_argus_contain_hostile.c` all DEFENDED plus a containment section in HOSTILE_REVIEW.md, zero OPEN at HIGH/CRITICAL except pre-listed G-5. Required: forged 90 via ring (MALFORMED); forged 90 ingested directly (code 17); request tampered after digest (code 17); replayed 91 (code 17); double execute (one revoke); 92 without GRANT (18); forged 92 DONE without kind 4 (19); office cap 0 targeted: layer 1 alone, layer 2 alone, layer 3 alone (others disabled by seams), each ends with the office LIVE and 92 FAILED -15 for layer 3; executor cap targeted: layers 1 and 2 each alone DEFENDED, layer 3 alone listed EXPECTED-FAIL (authority permits it, 5.1); freeze of subject 41/42 (DENY 1103); 256-principal amplifier: executed revocations <= 8 per 64 decisions; table saturation: one request per table, ESCALATE only; findings 17-21 never propose. Plus the invariant sub-list = G13. Pre-listed OPEN (G-5): a trusted producer can forge a trigger that frames a principal; bounded by "ask" for every type but RevokeCapability, leaf-only auto (I1), and the budget. |
| G10 | False-positive containment = 0 | Benign corpus 45,000 events x 9 seeds, plus recorded R7, R8, R9 streams with the observer as grant source: 0 proposals, 0 decisions, 0 executions, authority table untouched. |
| G11 | Sync policy ratified (I4) | Section 7 table equals `argus_hard_detectors[]`; no call from the authority, `argus_ring.o` or `argus_event.o` into detection, containment, gate or bridge (symbol check). |
| G12 | ARGUS-0 regression | `make test` and `make sanitize` (ASan+UBSan, TSan) PASS with all ARGUS-0 gates plus new tests, on the Spark; `make test` on the Mac. |
| G13 | Invariant tests I1-I5 | Each test prints `INV In.x PASS|FAIL` and all must PASS. **I1**: (a) auto GRANT only in the G3 leaf case; parametric sweep over {has descendant, privileged target, subject privileged, non-DETERMINISTIC finding, generation mismatch, SATURATION, SYNTHETIC} each -> no auto GRANT; (b) forced cascade via seam (descendant appears after re-check) -> code 21, FAILED_SCOPE, gate inert, next request ESCALATE; (c)-(e) covered by G6 checker on the G3/G4 runs; (f) revoke-then-re-mint subject works again. **I2**: every SYNTH 91/92 carries the SYNTHETIC flag and every report line naming it carries `SYNTHETIC-STAND-IN` (grep of generated reports); `freeze` grep over production `.c/.h` hits only the enum and "stand-in" comments; 0 production functions named `*freeze*`, `*suspend*`, `*isolate*`, `*pause*`; live gate returns UNAVAILABLE for FreezePrincipal. **I3**: `nm -u` of libargus, bridge, gate: no kill/stop/restart/bump_epoch/reclaim/advance_clock/force_generation/generation_advance/cognition_*; `aienos_cap_mint` referenced only by aienos_contain.o and reachable only from `aienos_contain_create` (call-graph from `-fcallgraph-info` or objdump); a 10,000-finding storm on distinct leaf caps executes <= 8 revocations per 64 decisions and the rest ESCALATE; no request type encodes a whole-system action. **I4**: symbol check of G11 + validate instruction count 179 + G8 push result. **I5** (hostile, each ends with `aienos_cap_inspect(executor)` rights == REVOKE, generation unchanged, zero observer MINT for AIENOS_CONTAIN_SUBJ, evidence recorded): hostile stream crafted to make ARGUS propose widening its own rights (no such request encodable; any 90 naming the executor or gate subjects suppressed + counted); forged GRANT 91 for a mint (code 17, no call, no mint); request targeting the executor cap (DENY 1103); request targeting subjects 41/42/AIENOS_CONTAIN_SUBJ (DENY 1103); finding storm of 100,000 findings attempting to convert into rights (0 mints, rights unchanged, budget holds); second `aienos_contain_create` refused; executor revoked by operator -> gate inert, no re-mint. |

Gate order: G1 and G11 first; then G2, G5, G7; G3, G4, G6; G9, G10, G13; G8 last on a quiet
Spark; G12 over everything. No gate runs before ARGUS_PERFORMANCE_GATE passes.

## 9. Non-claims

- Only RevokeCapability is live, and only for a leaf, non-privileged cap of a non-privileged
  subject (I1). Nine types are typed, decided for real, executed only by a labelled test
  executor. No machine, provider, lease, artifact, policy or effect-pause containment exists.
- No freeze exists (I2): no process, world or hardware suspension, and no block on future grants
  to a subject. FreezePrincipal is a named stand-in.
- No whole-system action exists or is reachable (I3); mass revocation is bounded by budget, not
  by a proof that a budgeted series is harmless.
- The authority cannot refuse a cascade: I1's "no cascade" is pre-checked by the gate's lineage
  shadow and audited by the observer count (code 21), not prevented. A concurrent admin caller
  outside the bridge can mint a child between the re-check and the revoke.
- The executor's revoke is attributed by correlation on one stream: the observer does not name
  the acting authority (I5.d limitation).
- The authority does not protect REVOKE-only caps (incl. the executor) from the executor; layers
  1 and 2 do.
- The trigger in the live accepted path is injected; the "human" resolving ESCALATE is a test
  stub holding the office secret (no operator surface yet).
- No producer identity (G-5): a trusted producer can frame a principal. Bounded, not closed.
- No synchronous refusal is wired (I4). No performance claim beyond G8 non-regression.
- Omega not wired for containment, except lane O's labelled binding. Restart mid-containment
  (open requests, lineage index lost; gate re-seeds as untrusted -> ESCALATE) is later work.
