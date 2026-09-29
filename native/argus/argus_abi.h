/*
 * argus_abi.h -- ARGUS security event ABI and core defensive types, version 1.
 *
 * ARGUS observes, detects, contains (by request), and defends. It never
 * authorizes. Nothing in this header, or in anything that includes it, may
 * mint, validate, or re-check a capability: the authority (native/capability)
 * already decided, and the producer copies that decision's result code into
 * the event. ARGUS cross-checks decisions against its own shadow state.
 *
 * Rules fixed by this header (see docs/adr/0017 in aien-architecture):
 *   - C only, freestanding-friendly: <stdint.h>/<stddef.h> only, no libc I/O.
 *   - Fixed 128-byte event, version byte first, no pointers, no variable
 *     length fields, no secret-sized field. Digests only.
 *   - Deterministic: no wall clock in any hashed field. Time = sequence +
 *     the authority's logical tick (aienos_cap_clock).
 *   - Capability reference = AienosCapRef layout (u32 id, u64 generation).
 *     The Omega stand-in rx_caproot (u32 generation) is NOT a source.
 *   - Principal = the authority's subject (u32). No parallel principal type.
 *   - Object = RxGenObject id (u32) + digest; World generation = the 64-bit
 *     rx_generation id. Object generation, when needed, travels in `resource`.
 *   - MachineId is a PROVISIONAL opaque 32-byte slot. Fabric identity is not
 *     designed here (cryptographic identity is on the operator's escalation list).
 *    - A Finding is evidence, never authority. A ContainmentRequest is a
 *     proposal to AEGIS, never an action.
 *   - Conventions fixed at integration (lanes B/D/E agree):
 *     CAPABILITY_GRANTED: `resource` = authority resource, `object_id` = rights
 *       mask (AIENOS_CAP_RIGHT_*), `principal` = subject.
 *     Producer sequence streams are keyed by (machine_id, CONSUMER flag bit);
 *       the core reports a repeat/decrease as ARGUS_F_SEQUENCE_ANOMALY and
 *       still applies the event. ARGUS_ERR_SEQUENCE is reserved for producers/ring.
 *     argus_event_encode and argus_chain_extend never validate their input
 *       (the core reuses chain_extend for its state digest); only decode/validate do.
 *     argus_core_ingest may return ARGUS_ERR_FULL or ARGUS_ERR_OVERFLOW after the
 *       event has already been applied; MALFORMED means nothing was applied.
 *     Detectors never raise ARGUS_F_TELEMETRY_LOSS for TELEMETRY_DROPPED; the core does.
 *   - Hostile-review rules (docs/HOSTILE_REVIEW.md, applied after the first review):
 *     Producer trust boundary (v1): argus_ring_push is reachable only from AEGIS/runtime
 *       code inside the trusted process, never from cognition (same split as the
 *       authority admin/view). Cryptographic producer attestation is ARGUS-3 work.
 *     validate rejects: ARGUS_FLAG_CONSUMER on any kind but TELEMETRY_DROPPED;
 *       cap_id >= ARGUS_CAP_MAX; sequence == UINT64_MAX; a class weaker than
 *       argus_event_min_class(kind) (producers may strengthen, never weaken);
 *       EXTERNAL_EFFECT_* with effect_class != EXTERNAL. argus_ring_push also
 *       refuses (ARGUS_ERR_MALFORMED) a class weaker than the kind minimum.
 *     Apply rules (core): an event that raises SEQUENCE_ANOMALY or AUTHORITY_REPLAY is
 *       detected but NOT applied. GRANTED applies only when the slot is UNSEEN or the
 *       generation is strictly above the shadow generation; otherwise AUTHORITY_REPLAY.
 *       REVOKED on an UNSEEN slot is AUTHORITY_REPLAY and creates no entry.
 *       LEASE_CREATED on a LIVE or REVOKED lease id is a finding (code 6, prior_sequence set)
 *       and is not applied: lease ids are never reused. WORLD_COMMITTED applies only when
 *       generation == shadow+1 (or shadow 0); a flagged commit is not adopted.
 *       Malformed events raise MALFORMED_EVENT (core) and are not applied or chained.
 *     Machine lifecycle: JOINED trust = max(OBSERVED, object_id) by rank (a machine cannot
 *       declare itself TRUSTED); TRUST_CHANGED may only move DOWN the rank order
 *       TRUSTED < OBSERVED < REATTESTATION_REQUIRED < RESTRICTED < QUARANTINED < UNTRUSTED;
 *       an upward move is TRUST_ESCALATION and is ignored (re-entry is ARGUS-1/2 work);
 *       TRUST_CHANGED for an unknown machine is MACHINE_IDENTITY_MISMATCH and creates no
 *       entry; REMOVED keeps a tombstone (state REMOVED, trust preserved, joined_sequence 0).
 *     Self-reported kinds 60-63 without shadow corroboration yield sync_allowed = 0 and
 *       containment NONE (a report is not evidence).
 *     Sequence gaps are expected (ring refusals) and are not findings.
 *     Table sizes: caps ARGUS_CAP_MAX, artifacts 256, incidents 256; every FULL is counted in health.
 *
 * Wire encoding (argus_event_encode/decode): each field in the order below,
 * little-endian, packed to exactly ARGUS_EVENT_SIZE bytes, offsets as noted.
 * Event digest = SHA-256 of those 128 bytes. Chain digest =
 * SHA-256(previous chain digest || event bytes).
 */
#ifndef ARGUS_ABI_H
#define ARGUS_ABI_H
#include <stddef.h>
#include <stdint.h>

#define ARGUS_ABI_VERSION     1u
#define ARGUS_EVENT_SIZE      128u
#define ARGUS_DIGEST_LEN      32u
#define ARGUS_MACHINE_ID_LEN  32u   /* PROVISIONAL opaque identity slot */
#define ARGUS_CAP_MAX         256u  /* == AIENOS_CAP_MAX; cap_id >= this is MALFORMED, never "table full" */

/* Result codes. Negative, distinct from AIENOS_CAP_* (-1..-17) and RX_GEN_* (-40..-49). */
#define ARGUS_OK                 0
#define ARGUS_ERR_ARG          (-60)
#define ARGUS_ERR_VERSION      (-61)
#define ARGUS_ERR_MALFORMED    (-62)   /* unknown class/kind/outcome, reserved bits set */
#define ARGUS_ERR_FULL         (-63)   /* ring or table at capacity */
#define ARGUS_ERR_SEQUENCE     (-64)   /* non-monotonic or replayed sequence */
#define ARGUS_ERR_STATE        (-65)
#define ARGUS_ERR_OVERFLOW     (-66)   /* output buffer too small */

/* Event class: what happens when the consumer falls behind. */
enum {
    ARGUS_CLASS_CRITICAL      = 1,  /* never dropped silently: full ring capacity, sticky overflow flag */
    ARGUS_CLASS_SECURITY      = 2,  /* refused above the SECURITY watermark, counted */
    ARGUS_CLASS_AUDIT         = 3,  /* refused above the AUDIT watermark, counted */
    ARGUS_CLASS_INFORMATIONAL = 4,  /* first to be refused, counted */
    ARGUS_CLASS_MAX           = 4
};

/* Event kinds. Values are stable forever; append only, never renumber. */
enum {
    ARGUS_EV_NONE                    = 0,
    ARGUS_EV_CAPABILITY_GRANTED      = 1,   /* cap = NEW ref; object_id = rights; resource = resource; no parent ref in v1 */
    ARGUS_EV_CAPABILITY_USED         = 2,
    ARGUS_EV_CAPABILITY_DENIED       = 3,
    ARGUS_EV_CAPABILITY_REVOKED      = 4,
    ARGUS_EV_CREDENTIAL_LEASE_CREATED = 10, /* object_id = lease id; resource = scope (USED: requested bits) */
    ARGUS_EV_CREDENTIAL_LEASE_USED   = 11,
    ARGUS_EV_CREDENTIAL_LEASE_REVOKED = 12,
    ARGUS_EV_ARTIFACT_ADMITTED       = 20,  /* evidence_digest = artifact digest (all ARTIFACT_*) */
    ARGUS_EV_ARTIFACT_REJECTED       = 21,
    ARGUS_EV_ARTIFACT_ACTIVATED      = 22,  /* an admitted artifact began executing */
    ARGUS_EV_MACHINE_JOINED          = 30,  /* object_id = initial ARGUS_TRUST_* (1..6); 0 => OBSERVED */
    ARGUS_EV_MACHINE_TRUST_CHANGED   = 31,  /* object_id = new ARGUS_TRUST_* (1..6); other values ignored */
    ARGUS_EV_MACHINE_REMOVED         = 32,
    ARGUS_EV_PROVIDER_DISCOVERED     = 40,  /* evidence_digest = provider id (all PROVIDER_*) */
    ARGUS_EV_PROVIDER_CHANGED        = 41,
    ARGUS_EV_PROVIDER_QUARANTINED    = 42,
    ARGUS_EV_PROVIDER_USED           = 43,
    ARGUS_EV_EXTERNAL_EFFECT_REQUESTED = 50,
    ARGUS_EV_EXTERNAL_EFFECT_DENIED  = 51,
    ARGUS_EV_EXTERNAL_EFFECT_COMMITTED = 52,
    ARGUS_EV_INTEGRITY_VIOLATION     = 60,
    ARGUS_EV_SIGNATURE_FAILURE       = 61,
    ARGUS_EV_STALE_GENERATION        = 62,
    ARGUS_EV_FORGED_CAPABILITY       = 63,
    ARGUS_EV_WORLD_COMMITTED         = 70,
    ARGUS_EV_POLICY_CHANGED          = 71,
    ARGUS_EV_RUNTIME_BUILD_CHANGED   = 72,
    ARGUS_EV_TELEMETRY_DROPPED       = 80,  /* synthesized by the ring consumer: object_id = class, resource = count */
    ARGUS_EV_KIND_MAX                = 80
};

/* Effect class of the operation the event describes. Mirrors RX_WORK_* + none. */
enum {
    ARGUS_EFFECT_NONE       = 0,
    ARGUS_EFFECT_EPHEMERAL  = 1,   /* reversible, inside a World */
    ARGUS_EFFECT_EVIDENCE   = 2,   /* durable evidence write */
    ARGUS_EFFECT_EXTERNAL   = 3,   /* irreversible, leaves the system */
    ARGUS_EFFECT_MAX        = 3
};

/* Outcome as decided by the producer's authority; `code` carries its result code. */
enum {
    ARGUS_OUTCOME_OK      = 1,
    ARGUS_OUTCOME_DENIED  = 2,
    ARGUS_OUTCOME_ERROR   = 3,
    ARGUS_OUTCOME_MAX     = 3
};

/* Flags. Reserved bits must be zero or the event is malformed. */
#define ARGUS_FLAG_SYNTHETIC   0x0001u  /* produced by a test or replay, not a live producer */
#define ARGUS_FLAG_CONSUMER    0x0002u  /* synthesized by ARGUS itself (e.g. TELEMETRY_DROPPED) */
#define ARGUS_FLAG_KNOWN       0x0003u

/* Layout-identical to AienosCapRef in native/capability/aienos_capability.h. */
typedef struct {
    uint32_t cap_id;
    uint64_t generation;
} ArgusCapRef;

/* Exactly ARGUS_EVENT_SIZE bytes on the wire, in this order. */
typedef struct {
    uint8_t  version;            /* off 0   = ARGUS_ABI_VERSION */
    uint8_t  class_;             /* off 1   ARGUS_CLASS_* */
    uint16_t kind;               /* off 2   ARGUS_EV_* */
    uint8_t  effect_class;       /* off 4   ARGUS_EFFECT_* */
    uint8_t  outcome;            /* off 5   ARGUS_OUTCOME_* */
    uint16_t flags;              /* off 6   ARGUS_FLAG_* */
    uint64_t sequence;           /* off 8   producer-local, strictly increasing from 1 */
    uint64_t tick;               /* off 16  authority logical clock (aienos_cap_clock), 0 if unknown */
    uint32_t principal;          /* off 24  authority subject */
    int32_t  code;               /* off 28  authority/producer result code (AIENOS_CAP_*, RX_GEN_*, 0) */
    uint32_t cap_id;             /* off 32  0 = none */
    uint32_t object_id;          /* off 36  RxGenObject id, lease id, or 0 */
    uint64_t cap_generation;     /* off 40 */
    uint64_t world_generation;   /* off 48  rx_generation World generation id (64-bit), 0 = unknown */
    uint64_t resource;           /* off 56  authority resource, rights mask, or count */
    uint8_t  machine_id[ARGUS_MACHINE_ID_LEN];      /* off 64  PROVISIONAL */
    uint8_t  evidence_digest[ARGUS_DIGEST_LEN];     /* off 96  digest of the referenced object/artifact/policy, or zero */
} ArgusEvent;                                       /* end 128 */

/* ---- Findings: evidence, never authority ---------------------------------- */

enum {
    ARGUS_SEV_INFO = 1, ARGUS_SEV_LOW, ARGUS_SEV_MEDIUM, ARGUS_SEV_HIGH, ARGUS_SEV_CRITICAL
};
enum {
    ARGUS_CONF_DETERMINISTIC = 1,   /* the only class permitted in ARGUS-0 */
    ARGUS_CONF_STATISTICAL   = 2,   /* reserved for ARGUS-5+, must not appear in ARGUS-0 */
    ARGUS_CONF_HYPOTHESIS    = 3    /* reserved for ARGUS Hunt */
};

/* Stable finding codes. One per hard invariant. Append only. */
enum {
    ARGUS_F_NONE                          = 0,
    ARGUS_F_FORGED_CAPABILITY             = 1,   /* used/granted ref never minted in shadow state, or authority said forged */
    ARGUS_F_STALE_GENERATION              = 2,   /* ref generation older than the shadow's current generation for that slot */
    ARGUS_F_REVOKED_CAPABILITY_USED       = 3,   /* shadow says revoked, event says outcome OK */
    ARGUS_F_ARTIFACT_DIGEST_UNEXPECTED    = 4,   /* activated/used digest not admitted, or admitted digest changed */
    ARGUS_F_SIGNATURE_INVALID             = 5,   /* producer reported a signature failure on a trusted-path object */
    ARGUS_F_CREDENTIAL_SCOPE_VIOLATION    = 6,   /* lease used by other subject or outside its scope, outcome OK */
    ARGUS_F_MACHINE_IDENTITY_MISMATCH     = 7,   /* event machine_id not the one recorded at join, or unknown machine */
    ARGUS_F_EFFECT_CLASS_UNAUTHORIZED     = 8,   /* effect class exceeds what the capability's rights permit, outcome OK */
    ARGUS_F_WORLD_PROVENANCE_INCONSISTENT = 9,   /* WorldCommitted generation not prior+1, or digest conflicts */
    ARGUS_F_QUARANTINED_USE               = 10,  /* provider/machine used after quarantine, outcome OK */
    ARGUS_F_TELEMETRY_LOSS                = 11,  /* CRITICAL/SECURITY events were dropped: evidence gap */
    ARGUS_F_SEQUENCE_ANOMALY              = 12,  /* replayed or out-of-order sequence from a producer */
    ARGUS_F_AUTHORITY_REPLAY              = 13,  /* GRANTED not above shadow generation, or REVOKED of an unseen slot (core) */
    ARGUS_F_SUBJECT_MISMATCH              = 14,  /* capability used with outcome OK by a principal other than the granted subject */
    ARGUS_F_TRUST_ESCALATION              = 15,  /* TRUST_CHANGED/JOINED attempted to raise trust; ignored */
    ARGUS_F_MALFORMED_EVENT               = 16,  /* validate rejected the event; core-raised, not applied */
    ARGUS_F_MAX                           = 16
};

/* Recommended containment class. Advisory. AEGIS decides. */
enum {
    ARGUS_CONTAIN_NONE = 0,
    ARGUS_CONTAIN_REVOKE_CAPABILITY,
    ARGUS_CONTAIN_FREEZE_PRINCIPAL,
    ARGUS_CONTAIN_RESTRICT_PRINCIPAL,
    ARGUS_CONTAIN_QUARANTINE_MACHINE,
    ARGUS_CONTAIN_QUARANTINE_PROVIDER,
    ARGUS_CONTAIN_REVOKE_CREDENTIAL_LEASE,
    ARGUS_CONTAIN_REJECT_ARTIFACT,
    ARGUS_CONTAIN_REQUIRE_REATTESTATION,
    ARGUS_CONTAIN_RAISE_EFFECT_CLASS,
    ARGUS_CONTAIN_PAUSE_EXTERNAL_EFFECTS,
    ARGUS_CONTAIN_MAX = ARGUS_CONTAIN_PAUSE_EXTERNAL_EFFECTS
};

typedef struct {
    uint16_t code;              /* ARGUS_F_* */
    uint8_t  severity;          /* ARGUS_SEV_* */
    uint8_t  confidence;        /* ARGUS_CONF_DETERMINISTIC in ARGUS-0 */
    uint8_t  sync_allowed;      /* 1 only if pre-established policy permits synchronous refusal at the boundary */
    uint8_t  containment;       /* ARGUS_CONTAIN_* recommendation */
    uint16_t detector;          /* detector id (== code for hard invariants) */
    uint64_t sequence;          /* the triggering event */
    uint64_t prior_sequence;    /* the earlier evidence event (e.g. the revocation), 0 if none */
    uint32_t principal;
    uint32_t cap_id;
    uint64_t cap_generation;
    uint8_t  machine_id[ARGUS_MACHINE_ID_LEN];
    uint8_t  event_digest[ARGUS_DIGEST_LEN];   /* digest of the triggering event bytes */
} ArgusFinding;

/* Typed proposal to AEGIS. ARGUS-0 defines the type only; ARGUS-1 wires it. */
typedef struct {
    uint64_t incident_id;
    uint8_t  containment;       /* ARGUS_CONTAIN_* */
    uint8_t  severity;
    uint16_t finding_code;
    uint32_t principal;
    ArgusCapRef target;         /* capability to revoke, if any */
    uint8_t  machine_id[ARGUS_MACHINE_ID_LEN];
    uint8_t  finding_digest[ARGUS_DIGEST_LEN];
} ArgusContainmentRequest;

/* ---- Shadow state view: what detectors may ask the core ------------------- */

enum { ARGUS_SHADOW_UNSEEN = 0, ARGUS_SHADOW_LIVE = 1, ARGUS_SHADOW_REVOKED = 2, ARGUS_SHADOW_REJECTED = 3, ARGUS_SHADOW_REMOVED = 4 };
enum {
    ARGUS_TRUST_UNKNOWN = 0, ARGUS_TRUST_TRUSTED, ARGUS_TRUST_OBSERVED, ARGUS_TRUST_RESTRICTED,
    ARGUS_TRUST_QUARANTINED, ARGUS_TRUST_UNTRUSTED, ARGUS_TRUST_REATTESTATION_REQUIRED
};

typedef struct {
    uint32_t cap_id;
    uint64_t generation;        /* highest generation seen for this slot */
    uint32_t state;             /* ARGUS_SHADOW_* */
    uint32_t subject;
    uint32_t rights;            /* AIENOS_CAP_RIGHT_* mask as granted */
    uint64_t resource;
    uint64_t granted_sequence;
    uint64_t revoked_sequence;
} ArgusCapShadow;

typedef struct {
    uint8_t  machine_id[ARGUS_MACHINE_ID_LEN];
    uint32_t trust;             /* ARGUS_TRUST_* */
    uint64_t joined_sequence;   /* 0 = not joined (REMOVED drops the entry) */
    uint64_t changed_sequence;
} ArgusMachineShadow;

typedef struct {
    uint8_t  digest[ARGUS_DIGEST_LEN];
    uint32_t state;             /* LIVE = admitted, REJECTED, UNSEEN */
    uint64_t sequence;
} ArgusArtifactShadow;

typedef struct {
    uint32_t lease_id;          /* event object_id */
    uint32_t subject;
    uint64_t scope;             /* event resource at creation */
    uint32_t state;
    uint64_t sequence;
} ArgusLeaseShadow;

typedef struct {
    uint8_t  provider_id[ARGUS_DIGEST_LEN];   /* event evidence_digest at discovery */
    uint32_t state;             /* LIVE, REVOKED = quarantined */
    uint64_t sequence;
} ArgusProviderShadow;

typedef struct {
    uint64_t generation;        /* last committed World generation (64-bit), 0 = none */
    uint8_t  digest[ARGUS_DIGEST_LEN];
    uint64_t sequence;
} ArgusWorldShadow;

typedef struct ArgusStateView ArgusStateView;   /* opaque, owned by argus_core */

/* Lookups return ARGUS_OK and fill *out, or ARGUS_ERR_STATE when unseen.
 * All are O(1) or O(log n) over bounded tables. None allocate. */
typedef struct {
    int (*cap)(const ArgusStateView *v, uint32_t cap_id, ArgusCapShadow *out);
    int (*machine)(const ArgusStateView *v, const uint8_t id[ARGUS_MACHINE_ID_LEN], ArgusMachineShadow *out);
    int (*artifact)(const ArgusStateView *v, const uint8_t digest[ARGUS_DIGEST_LEN], ArgusArtifactShadow *out);
    int (*lease)(const ArgusStateView *v, uint32_t lease_id, ArgusLeaseShadow *out);
    int (*provider)(const ArgusStateView *v, const uint8_t id[ARGUS_DIGEST_LEN], ArgusProviderShadow *out);
    int (*world)(const ArgusStateView *v, ArgusWorldShadow *out);
    /* Expected digest of the trusted policy / runtime build last announced. Zero digest = none. */
    int (*policy_digest)(const ArgusStateView *v, uint8_t out[ARGUS_DIGEST_LEN]);
    int (*runtime_digest)(const ArgusStateView *v, uint8_t out[ARGUS_DIGEST_LEN]);
} ArgusStateOps;

/* A detector sees the event and the shadow state BEFORE the core applies the
 * event's own update. It writes up to `cap` findings and sets *n_out. It must
 * be pure: no allocation, no I/O, no global state, no clock. */
typedef int (*ArgusDetectorFn)(const ArgusStateOps *ops, const ArgusStateView *v,
                               const ArgusEvent *ev, ArgusFinding *out, size_t cap, size_t *n_out);

typedef struct {
    uint16_t id;                /* == ARGUS_F_* it can raise */
    uint8_t  sync_allowed;      /* policy: may a synchronous boundary refusal cite this? */
    uint8_t  containment;       /* default ARGUS_CONTAIN_* */
    const char *name;
    ArgusDetectorFn fn;
} ArgusDetector;

/* ---- Lane entry points (declared here, implemented per lane) --------------- */

/* argus_event.c (lane B): canonical encoding, validation, digests. */
int  argus_event_encode(const ArgusEvent *ev, uint8_t out[ARGUS_EVENT_SIZE]);
int  argus_event_decode(const uint8_t in[ARGUS_EVENT_SIZE], ArgusEvent *out);   /* validates; rejects malformed */
int  argus_event_validate(const ArgusEvent *ev);
uint8_t argus_event_min_class(uint16_t kind);   /* weakest class allowed for a kind (see argus_event.c table) */
void argus_event_digest(const ArgusEvent *ev, uint8_t out[ARGUS_DIGEST_LEN]);
void argus_chain_extend(uint8_t chain[ARGUS_DIGEST_LEN], const ArgusEvent *ev);   /* chain = H(chain || bytes) */
void argus_finding_digest(const ArgusFinding *f, uint8_t out[ARGUS_DIGEST_LEN]);

/* argus_ring.c (lane B): single-producer/single-consumer bounded ring of events. */
typedef struct ArgusRing ArgusRing;
size_t argus_ring_footprint(uint32_t capacity_pow2);                       /* bytes needed for argus_ring_init */
int    argus_ring_init(ArgusRing **ring, void *memory, size_t bytes, uint32_t capacity_pow2);
int    argus_ring_push(ArgusRing *ring, const ArgusEvent *ev);              /* producer; ARGUS_ERR_FULL never blocks */
int    argus_ring_pop(ArgusRing *ring, ArgusEvent *out);                    /* consumer; ARGUS_ERR_STATE when empty */
size_t argus_ring_pop_batch(ArgusRing *ring, ArgusEvent *out, size_t max);
typedef struct {
    uint64_t pushed, popped;
    uint64_t refused[ARGUS_CLASS_MAX + 1];   /* per class, index by class */
    uint64_t critical_overflow;              /* sticky count: evidence gap */
    uint32_t depth, capacity;
} ArgusRingStats;
void   argus_ring_stats(const ArgusRing *ring, ArgusRingStats *out);
/* Consumer-side: turn accumulated refusals into TELEMETRY_DROPPED events (flag CONSUMER); returns count written. */
size_t argus_ring_drain_drops(ArgusRing *ring, ArgusEvent *out, size_t max, uint64_t *next_sequence);
/* Ring depth at which pushes of class_ start being refused (0 if capacity invalid). */
uint32_t argus_ring_saturation_point(uint32_t capacity_pow2, uint8_t class_);

/* argus_detect.c (lane E): the hard-invariant detector table. */
extern const ArgusDetector argus_hard_detectors[];
extern const size_t argus_hard_detector_count;
int argus_detect_run(const ArgusStateOps *ops, const ArgusStateView *v, const ArgusEvent *ev,
                     ArgusFinding *out, size_t cap, size_t *n_out);

/* argus_core.c (lane D): resident deterministic state engine. */
typedef struct ArgusCore ArgusCore;
size_t argus_core_footprint(void);
int    argus_core_init(ArgusCore **core, void *memory, size_t bytes);      /* zero malloc after this */
/* validate -> detect (pre-state) -> apply -> return findings. Deterministic for a given event stream. */
int    argus_core_ingest(ArgusCore *core, const ArgusEvent *ev, ArgusFinding *out, size_t cap, size_t *n_out);
const ArgusStateView *argus_core_view(const ArgusCore *core);
const ArgusStateOps  *argus_core_ops(void);
void   argus_core_state_digest(const ArgusCore *core, uint8_t out[ARGUS_DIGEST_LEN]);   /* canonical digest of all shadow tables */
typedef struct {
    uint64_t events_received, events_rejected, findings_emitted, incidents_open;
    uint64_t detector_ns_total;   /* only when the caller supplies timings; 0 in library */
    uint64_t incidents_untracked; /* (principal, code) pairs beyond the incident table */
    uint64_t producers_untracked; /* sequence streams beyond the producer table */
    uint64_t tables_full;         /* ingest calls that returned ARGUS_ERR_FULL */
    uint64_t events_not_applied;  /* detected but not applied (anomaly, replay, lease reuse, world skip) */
    uint8_t  chain[ARGUS_DIGEST_LEN];
} ArgusCoreHealth;
void   argus_core_health(const ArgusCore *core, ArgusCoreHealth *out);

#endif /* ARGUS_ABI_H */
