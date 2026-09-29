/*
 * argus_core.c -- ARGUS-0 resident deterministic state engine (lane D).
 *
 * The core keeps fixed-capacity shadow tables of what the authority and the
 * other producers have announced, runs the hard-invariant detectors against
 * the state as it was BEFORE each event, then applies the event if the apply
 * rules allow it. It never authorizes anything and never re-checks a capability.
 *
 * Properties: caller-provided memory (argus_core_footprint/argus_core_init),
 * no heap use at all, no I/O, no clock, no mutable globals (only constant
 * tables). The core holds no pointers, so a byte copy of its memory is a valid
 * snapshot. Hashing goes only through header-declared functions
 * (argus_event_validate, argus_event_digest, argus_chain_extend,
 * argus_detect_run), so the lane-B/E implementations swap in transparently.
 *
 * ---- Ingest pipeline (hostile-review rules, argus_abi.h) -------------------
 *
 *  0. Well-formedness: argus_event_validate, plus two core guards that mirror
 *     the header's validate rules (cap_id >= ARGUS_CAP_MAX, sequence ==
 *     UINT64_MAX), so they hold even against an older validate. A malformed
 *     event raises ARGUS_F_MALFORMED_EVENT (MEDIUM, sequence = the event's,
 *     event_digest stamped), is counted in events_rejected, is NOT applied, NOT
 *     chained, does not touch the producer table, and ingest returns
 *     ARGUS_ERR_MALFORMED. A cap_id out of range is therefore never "table full".
 *  1. Sequence check per producer stream, keyed by (machine_id, flags &
 *     ARGUS_FLAG_CONSUMER). A sequence <= the stream's high-water mark raises
 *     ARGUS_F_SEQUENCE_ANOMALY (HIGH, prior_sequence = high-water mark); the
 *     event is detected (lane E runs) but NOT applied; the mark never moves
 *     backwards. Gaps are not findings. With the producer table full, a new
 *     stream is not tracked (producers_untracked counts its events); the FIRST
 *     untracked event returns ARGUS_ERR_FULL + one CRITICAL TELEMETRY_LOSS,
 *     later ones do not (no per-event CRITICAL amplifier), and are applied.
 *  2. Apply verdict (only for an in-order event whose outcome would update
 *     state; decided on the pre-state):
 *       CAPABILITY_GRANTED  applies iff the slot is UNSEEN or cap_generation >
 *                           the shadow generation; otherwise ARGUS_F_AUTHORITY_REPLAY
 *                           (code 13, HIGH, prior_sequence = the slot's revoked
 *                           sequence if REVOKED, else its granted sequence).
 *       CAPABILITY_REVOKED  applies iff the slot is LIVE and cap_generation ==
 *                           the shadow generation. Every other case (UNSEEN, already
 *                           REVOKED, generation above or below) is code 13 and is
 *                           not applied, so a forged REVOKED at UINT64_MAX creates
 *                           nothing and poisons nothing.
 *       LEASE_CREATED       on a LIVE or REVOKED lease id: not applied (lease ids
 *                           are never reused; lane E raises code 6).
 *       LEASE_REVOKED       on an unknown lease id: not applied, no entry.
 *       WORLD_COMMITTED     adopted iff world_generation == shadow+1, or shadow == 0
 *                           (first commit). Same generation + same digest is an
 *                           idempotent no-op. Anything else is not adopted (lane E
 *                           raises code 9). world_generation 0 (= unknown) is a no-op.
 *       MACHINE_TRUST_CHANGED unknown machine: not applied, no entry (lane E: code 7).
 *                           A move UP the rank order is not applied (lane E: code 15);
 *                           equal rank is a no-op; object_id outside 1..6 is ignored.
 *     Code-13 findings come from the core. Every event flagged by step 1 or
 *     not applied by step 2 (13, lease reuse, unknown lease revoke, world not
 *     adopted, trust escalation, unknown machine) counts once in
 *     events_not_applied.
 *  3. Detectors (lane E) on the PRE-update state, into the scratch after the
 *     core's step-1/2 finding (at most one: anomaly and verdict are exclusive).
 *  4. Apply (if allowed). Table full: update dropped, ERR_FULL + one CRITICAL
 *     ARGUS_F_TELEMETRY_LOSS (the shadow can no longer mirror the authority).
 *  5. TELEMETRY_DROPPED class CRITICAL -> TELEMETRY_LOSS CRITICAL, class
 *     SECURITY -> HIGH. Lane E must not raise this code for TELEMETRY_DROPPED.
 *  6. Chain: every well-formed event (applied or not) extends the chain.
 *  7. Stamp event_digest on every finding, note incidents, copy out.
 *
 * Outcome gating. A state update is applied only when outcome == OK, except
 * ARTIFACT_REJECTED, which applies on OK or DENIED (the rejection is itself
 * the authority's decision). ERROR outcomes never change state.
 *
 * ---- Field conventions ------------------------------------------------------
 *   CAPABILITY_GRANTED   resource = authority resource, object_id = rights mask,
 *                        principal = subject, (cap_id, cap_generation) = the ref.
 *                        cap_id 0 = none (no update).
 *   CREDENTIAL_LEASE_*   lease id = object_id (0 = none). CREATED: subject =
 *                        principal, scope = resource, LIVE. REVOKED: REVOKED.
 *   ARTIFACT_*           keyed by evidence_digest (all-zero = none). ADMITTED:
 *                        LIVE only with outcome OK and code 0. REJECTED: REJECTED,
 *                        sticky (a later ADMITTED does not un-reject).
 *   MACHINE_*            keyed by machine_id; table kept sorted by machine_id.
 *                        Trust rank (weakest last): TRUSTED < OBSERVED <
 *                        REATTESTATION_REQUIRED < RESTRICTED < QUARANTINED <
 *                        UNTRUSTED (NOT the enum order). JOINED: trust = the
 *                        weaker of OBSERVED and object_id (0 or out of range =>
 *                        OBSERVED), so a machine can never declare itself TRUSTED.
 *                        A JOINED of a known machine keeps the weaker of its
 *                        current trust and the claim (never upward); if the entry
 *                        is a tombstone it becomes joined again at the event's
 *                        sequence, so a quarantine survives remove + rejoin.
 *                        REMOVED: tombstone = entry kept with trust preserved and
 *                        joined_sequence 0 (ArgusMachineShadow has no state field;
 *                        joined_sequence 0 is the tombstone marker, and the ops
 *                        lookup still returns it so detectors see its trust).
 *   PROVIDER_*           keyed by evidence_digest. DISCOVERED: LIVE if new; a
 *                        rediscovery never clears a quarantine. QUARANTINED:
 *                        REVOKED (created if unseen).
 *   WORLD_COMMITTED      world_generation + evidence_digest (rules above).
 *   POLICY_CHANGED / RUNTIME_BUILD_CHANGED  evidence_digest = expected digest.
 *   TELEMETRY_DROPPED    object_id = class, resource = count.
 *
 * Findings. Core findings: confidence DETERMINISTIC, detector == code,
 * sync_allowed 0, containment NONE. Every finding (core and lane E) gets
 * event_digest = argus_event_digest(ev). Findings are collected in an internal
 * scratch of ARGUS_CORE_MAX_FINDINGS (two slots reserved for the step-4/5 core
 * findings), state is applied regardless of the caller's buffer, then
 * min(n, cap) are copied out. If n > cap, ingest returns ARGUS_ERR_OVERFLOW with
 * *n_out = cap: findings are lost to the caller, state never is.
 * Return precedence: MALFORMED > FULL > OVERFLOW > detector error > OK.
 *
 * Health: incidents_open = tracked (principal, code) pairs with severity >= HIGH
 * (table ARGUS_CORE_INCIDENTS); pairs beyond it count in incidents_untracked.
 * producers_untracked counts events on untracked streams; tables_full counts
 * ingest calls that returned ARGUS_ERR_FULL.
 *
 * Lookups: caps O(1) direct index; machines and producers binary search over
 * sorted tables; artifacts, leases, providers, incidents linear scans over at
 * most 256 entries (bounded, no allocation).
 */
#include "argus_core.h"

#include <string.h>

#if ARGUS_CORE_CAPS != ARGUS_CAP_MAX
#error "ARGUS_CORE_CAPS must equal ARGUS_CAP_MAX (== AIENOS_CAP_MAX)"
#endif

#define CORE_MAGIC 0x3053554752410002ull   /* "ARGUS0" + layout 2 */
#define CORE_RESERVED_SLOTS 2u              /* telemetry-drop + table-full findings */

typedef struct {
    uint8_t  machine_id[ARGUS_MACHINE_ID_LEN];
    uint32_t consumer;          /* 0 = live producer, 1 = ring consumer stream */
    uint64_t last_sequence;
} CoreProducer;

typedef struct {
    uint32_t principal;
    uint16_t code;
    uint8_t  severity;          /* highest seen */
    uint64_t first_sequence;
} CoreIncident;

struct ArgusStateView {
    ArgusCapShadow      caps[ARGUS_CORE_CAPS];
    ArgusMachineShadow  machines[ARGUS_CORE_MACHINES];      /* sorted by machine_id */
    ArgusArtifactShadow artifacts[ARGUS_CORE_ARTIFACTS];
    ArgusLeaseShadow    leases[ARGUS_CORE_LEASES];
    ArgusProviderShadow providers[ARGUS_CORE_PROVIDERS];
    ArgusWorldShadow    world;
    uint8_t  policy_digest[ARGUS_DIGEST_LEN];
    uint8_t  runtime_digest[ARGUS_DIGEST_LEN];
    uint32_t n_caps_live;       /* slots not UNSEEN */
    uint32_t n_machines, n_artifacts, n_leases, n_providers;
};

struct ArgusCore {
    uint64_t magic;
    struct ArgusStateView view;
    CoreProducer producers[ARGUS_CORE_PRODUCERS];           /* sorted by (machine_id, consumer) */
    CoreIncident incidents[ARGUS_CORE_INCIDENTS];
    uint32_t n_producers, n_incidents;
    uint64_t incidents_untracked, producers_untracked;
    uint64_t events_received, events_rejected, findings_emitted;
    uint64_t tables_full, events_not_applied;
    uint8_t  chain[ARGUS_DIGEST_LEN];
    ArgusFinding scratch[ARGUS_CORE_MAX_FINDINGS];
};

/* ---- small helpers -------------------------------------------------------- */

static int digest_is_zero(const uint8_t d[ARGUS_DIGEST_LEN])
{
    uint8_t acc = 0;
    for (unsigned i = 0; i < ARGUS_DIGEST_LEN; i++)
        acc |= d[i];
    return acc == 0;
}

/* Rank of each ARGUS_TRUST_* value; higher = weaker. Index = enum value. */
static const uint8_t trust_rank_tab[ARGUS_TRUST_REATTESTATION_REQUIRED + 1] = {
    [ARGUS_TRUST_UNKNOWN] = 0,
    [ARGUS_TRUST_TRUSTED] = 1,
    [ARGUS_TRUST_OBSERVED] = 2,
    [ARGUS_TRUST_REATTESTATION_REQUIRED] = 3,
    [ARGUS_TRUST_RESTRICTED] = 4,
    [ARGUS_TRUST_QUARANTINED] = 5,
    [ARGUS_TRUST_UNTRUSTED] = 6,
};

static int trust_valid(uint32_t t)
{
    return t >= ARGUS_TRUST_TRUSTED && t <= ARGUS_TRUST_REATTESTATION_REQUIRED;
}

static uint32_t trust_weaker(uint32_t a, uint32_t b)
{
    return trust_rank_tab[a] >= trust_rank_tab[b] ? a : b;
}

/* Binary search: index if found, else -(insertion point) - 1. */
static int find_machine(const struct ArgusStateView *v, const uint8_t id[ARGUS_MACHINE_ID_LEN])
{
    uint32_t lo = 0, hi = v->n_machines;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2u;
        int c = memcmp(v->machines[mid].machine_id, id, ARGUS_MACHINE_ID_LEN);
        if (c == 0)
            return (int)mid;
        if (c < 0)
            lo = mid + 1u;
        else
            hi = mid;
    }
    return -(int)lo - 1;
}

static int find_artifact(const struct ArgusStateView *v, const uint8_t d[ARGUS_DIGEST_LEN])
{
    for (uint32_t i = 0; i < v->n_artifacts; i++)
        if (memcmp(v->artifacts[i].digest, d, ARGUS_DIGEST_LEN) == 0)
            return (int)i;
    return -1;
}

static int find_lease(const struct ArgusStateView *v, uint32_t lease_id)
{
    for (uint32_t i = 0; i < v->n_leases; i++)
        if (v->leases[i].lease_id == lease_id)
            return (int)i;
    return -1;
}

static int find_provider(const struct ArgusStateView *v, const uint8_t id[ARGUS_DIGEST_LEN])
{
    for (uint32_t i = 0; i < v->n_providers; i++)
        if (memcmp(v->providers[i].provider_id, id, ARGUS_DIGEST_LEN) == 0)
            return (int)i;
    return -1;
}

/* ---- ops vtable (what detectors may ask) ---------------------------------- */

static int op_cap(const ArgusStateView *v, uint32_t cap_id, ArgusCapShadow *out)
{
    if (!v || !out)
        return ARGUS_ERR_ARG;
    if (cap_id >= ARGUS_CORE_CAPS || v->caps[cap_id].state == ARGUS_SHADOW_UNSEEN)
        return ARGUS_ERR_STATE;
    *out = v->caps[cap_id];
    return ARGUS_OK;
}

/* Tombstones (joined_sequence 0) are returned too: their trust still matters. */
static int op_machine(const ArgusStateView *v, const uint8_t id[ARGUS_MACHINE_ID_LEN], ArgusMachineShadow *out)
{
    if (!v || !id || !out)
        return ARGUS_ERR_ARG;
    int i = find_machine(v, id);
    if (i < 0)
        return ARGUS_ERR_STATE;
    *out = v->machines[i];
    return ARGUS_OK;
}

static int op_artifact(const ArgusStateView *v, const uint8_t d[ARGUS_DIGEST_LEN], ArgusArtifactShadow *out)
{
    if (!v || !d || !out)
        return ARGUS_ERR_ARG;
    int i = find_artifact(v, d);
    if (i < 0)
        return ARGUS_ERR_STATE;
    *out = v->artifacts[i];
    return ARGUS_OK;
}

static int op_lease(const ArgusStateView *v, uint32_t lease_id, ArgusLeaseShadow *out)
{
    if (!v || !out)
        return ARGUS_ERR_ARG;
    int i = find_lease(v, lease_id);
    if (i < 0)
        return ARGUS_ERR_STATE;
    *out = v->leases[i];
    return ARGUS_OK;
}

static int op_provider(const ArgusStateView *v, const uint8_t id[ARGUS_DIGEST_LEN], ArgusProviderShadow *out)
{
    if (!v || !id || !out)
        return ARGUS_ERR_ARG;
    int i = find_provider(v, id);
    if (i < 0)
        return ARGUS_ERR_STATE;
    *out = v->providers[i];
    return ARGUS_OK;
}

static int op_world(const ArgusStateView *v, ArgusWorldShadow *out)
{
    if (!v || !out)
        return ARGUS_ERR_ARG;
    if (v->world.generation == 0)
        return ARGUS_ERR_STATE;
    *out = v->world;
    return ARGUS_OK;
}

/* Zero digest = none announced; still returns ARGUS_OK with zeros (per header). */
static int op_policy_digest(const ArgusStateView *v, uint8_t out[ARGUS_DIGEST_LEN])
{
    if (!v || !out)
        return ARGUS_ERR_ARG;
    memcpy(out, v->policy_digest, ARGUS_DIGEST_LEN);
    return ARGUS_OK;
}

static int op_runtime_digest(const ArgusStateView *v, uint8_t out[ARGUS_DIGEST_LEN])
{
    if (!v || !out)
        return ARGUS_ERR_ARG;
    memcpy(out, v->runtime_digest, ARGUS_DIGEST_LEN);
    return ARGUS_OK;
}

static const ArgusStateOps core_ops = {
    .cap = op_cap,
    .machine = op_machine,
    .artifact = op_artifact,
    .lease = op_lease,
    .provider = op_provider,
    .world = op_world,
    .policy_digest = op_policy_digest,
    .runtime_digest = op_runtime_digest,
};

const ArgusStateOps *argus_core_ops(void)
{
    return &core_ops;
}

/* ---- lifecycle ------------------------------------------------------------ */

size_t argus_core_footprint(void)
{
    return sizeof(struct ArgusCore);
}

int argus_core_init(ArgusCore **core, void *memory, size_t bytes)
{
    if (!core || !memory || bytes < sizeof(struct ArgusCore))
        return ARGUS_ERR_ARG;
    if (((uintptr_t)memory & (_Alignof(struct ArgusCore) - 1u)) != 0)
        return ARGUS_ERR_ARG;
    struct ArgusCore *c = (struct ArgusCore *)memory;
    memset(c, 0, sizeof *c);
    c->magic = CORE_MAGIC;
    *core = c;
    return ARGUS_OK;
}

const ArgusStateView *argus_core_view(const ArgusCore *core)
{
    if (!core || core->magic != CORE_MAGIC)
        return NULL;
    return &core->view;
}

/* ---- findings ------------------------------------------------------------- */

static void core_finding(ArgusFinding *f, uint16_t code, uint8_t severity,
                         const ArgusEvent *ev, uint64_t prior_sequence)
{
    memset(f, 0, sizeof *f);
    f->code = code;
    f->severity = severity;
    f->confidence = ARGUS_CONF_DETERMINISTIC;
    f->sync_allowed = 0;
    f->containment = ARGUS_CONTAIN_NONE;
    f->detector = code;
    f->sequence = ev->sequence;
    f->prior_sequence = prior_sequence;
    f->principal = ev->principal;
    f->cap_id = ev->cap_id;
    f->cap_generation = ev->cap_generation;
    memcpy(f->machine_id, ev->machine_id, ARGUS_MACHINE_ID_LEN);
}

static void note_incident(struct ArgusCore *c, const ArgusFinding *f)
{
    if (f->severity < ARGUS_SEV_HIGH)
        return;
    for (uint32_t i = 0; i < c->n_incidents; i++) {
        CoreIncident *in = &c->incidents[i];
        if (in->principal == f->principal && in->code == f->code) {
            if (f->severity > in->severity)
                in->severity = f->severity;
            return;
        }
    }
    if (c->n_incidents >= ARGUS_CORE_INCIDENTS) {
        c->incidents_untracked++;
        return;
    }
    CoreIncident *in = &c->incidents[c->n_incidents++];
    in->principal = f->principal;
    in->code = f->code;
    in->severity = f->severity;
    in->first_sequence = f->sequence;
}

/* Stamp, count, copy out. Returns the number copied. */
static size_t deliver(struct ArgusCore *c, const ArgusEvent *ev, size_t n, ArgusFinding *out, size_t cap)
{
    ArgusFinding *sf = c->scratch;
    if (n) {
        uint8_t ed[ARGUS_DIGEST_LEN];
        argus_event_digest(ev, ed);
        for (size_t i = 0; i < n; i++) {
            memcpy(sf[i].event_digest, ed, ARGUS_DIGEST_LEN);
            note_incident(c, &sf[i]);
        }
    }
    c->findings_emitted += n;
    size_t k = n < cap ? n : cap;
    if (k)
        memcpy(out, sf, k * sizeof *sf);
    return k;
}

/* ---- well-formedness ------------------------------------------------------ */

static int event_well_formed(const ArgusEvent *ev)
{
    if (argus_event_validate(ev) != ARGUS_OK)
        return 0;
    if (ev->cap_id >= ARGUS_CAP_MAX)            /* header rule; never "table full" */
        return 0;
    if (ev->sequence == UINT64_MAX)             /* header rule; high-water poison */
        return 0;
    return 1;
}

/* ---- sequence check ------------------------------------------------------- */

static int producer_cmp(const CoreProducer *p, const uint8_t id[ARGUS_MACHINE_ID_LEN], uint32_t consumer)
{
    int c = memcmp(p->machine_id, id, ARGUS_MACHINE_ID_LEN);
    if (c)
        return c;
    return p->consumer < consumer ? -1 : p->consumer > consumer;
}

/* Returns 1 on anomaly (and sets *prior), 0 if in order, -1 if the producer
 * table is full (stream not tracked). Advances the high-water mark. */
static int sequence_check(struct ArgusCore *c, const ArgusEvent *ev, uint64_t *prior)
{
    uint32_t consumer = (ev->flags & ARGUS_FLAG_CONSUMER) ? 1u : 0u;
    uint32_t lo = 0, hi = c->n_producers;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2u;
        int r = producer_cmp(&c->producers[mid], ev->machine_id, consumer);
        if (r == 0) {
            CoreProducer *p = &c->producers[mid];
            if (ev->sequence <= p->last_sequence) {
                *prior = p->last_sequence;
                return 1;
            }
            p->last_sequence = ev->sequence;
            return 0;
        }
        if (r < 0)
            lo = mid + 1u;
        else
            hi = mid;
    }
    if (c->n_producers >= ARGUS_CORE_PRODUCERS)
        return -1;
    if (lo < c->n_producers)
        memmove(&c->producers[lo + 1u], &c->producers[lo], (c->n_producers - lo) * sizeof c->producers[0]);
    c->n_producers++;
    CoreProducer *p = &c->producers[lo];
    memset(p, 0, sizeof *p);
    memcpy(p->machine_id, ev->machine_id, ARGUS_MACHINE_ID_LEN);
    p->consumer = consumer;
    p->last_sequence = ev->sequence;
    return 0;
}

/* ---- apply verdict (pre-state) -------------------------------------------- */

enum { V_APPLY = 0, V_REPLAY = 1, V_SKIP = 2, V_NOOP = 3 };

static int apply_verdict(const struct ArgusStateView *v, const ArgusEvent *ev, uint64_t *prior)
{
    if (ev->outcome != ARGUS_OUTCOME_OK)
        return V_APPLY;                        /* outcome gating in apply_event */
    switch (ev->kind) {
    case ARGUS_EV_CAPABILITY_GRANTED:
    case ARGUS_EV_CAPABILITY_REVOKED: {
        if (ev->cap_id == 0)
            return V_APPLY;
        const ArgusCapShadow *s = &v->caps[ev->cap_id];
        if (ev->kind == ARGUS_EV_CAPABILITY_GRANTED) {
            if (s->state == ARGUS_SHADOW_UNSEEN || ev->cap_generation > s->generation)
                return V_APPLY;
        } else if (s->state == ARGUS_SHADOW_LIVE && ev->cap_generation == s->generation) {
            return V_APPLY;
        }
        *prior = s->state == ARGUS_SHADOW_REVOKED ? s->revoked_sequence : s->granted_sequence;
        return V_REPLAY;
    }
    case ARGUS_EV_CREDENTIAL_LEASE_CREATED:
        if (ev->object_id != 0 && find_lease(v, ev->object_id) >= 0)
            return V_SKIP;                     /* lease ids are never reused */
        return V_APPLY;
    case ARGUS_EV_CREDENTIAL_LEASE_REVOKED:
        if (ev->object_id != 0 && find_lease(v, ev->object_id) < 0)
            return V_SKIP;                     /* unknown lease: no entry */
        return V_APPLY;
    case ARGUS_EV_WORLD_COMMITTED:
        if (ev->world_generation == 0)
            return V_NOOP;
        if (v->world.generation == 0 || ev->world_generation == v->world.generation + 1u)
            return V_APPLY;
        if (ev->world_generation == v->world.generation &&
            memcmp(ev->evidence_digest, v->world.digest, ARGUS_DIGEST_LEN) == 0)
            return V_NOOP;                     /* idempotent repeat */
        return V_SKIP;
    case ARGUS_EV_MACHINE_TRUST_CHANGED: {
        int i = find_machine(v, ev->machine_id);
        if (i < 0)
            return V_SKIP;                     /* unknown machine: no entry */
        if (!trust_valid(ev->object_id))
            return V_NOOP;
        uint32_t cur = v->machines[i].trust;
        if (trust_rank_tab[ev->object_id] > trust_rank_tab[cur])
            return V_APPLY;                    /* downward move */
        return trust_rank_tab[ev->object_id] == trust_rank_tab[cur] ? V_NOOP : V_SKIP;
    }
    default:
        return V_APPLY;
    }
}

/* ---- state update (only called when the verdict allows it) ---------------- */

static int apply_cap(struct ArgusStateView *v, const ArgusEvent *ev, int revoke)
{
    if (ev->cap_id == 0 || ev->cap_id >= ARGUS_CORE_CAPS)
        return ARGUS_OK;                       /* out of range cannot reach here (malformed) */
    ArgusCapShadow *s = &v->caps[ev->cap_id];
    if (revoke) {
        s->state = ARGUS_SHADOW_REVOKED;       /* verdict: slot LIVE at this generation */
        s->revoked_sequence = ev->sequence;
        return ARGUS_OK;
    }
    if (s->state == ARGUS_SHADOW_UNSEEN) {
        memset(s, 0, sizeof *s);
        v->n_caps_live++;
    }
    s->cap_id = ev->cap_id;
    s->generation = ev->cap_generation;
    s->state = ARGUS_SHADOW_LIVE;
    s->subject = ev->principal;
    s->rights = (uint32_t)ev->object_id;
    s->resource = ev->resource;
    s->granted_sequence = ev->sequence;
    s->revoked_sequence = 0;
    return ARGUS_OK;
}

static int apply_lease(struct ArgusStateView *v, const ArgusEvent *ev, int revoke)
{
    if (ev->object_id == 0)
        return ARGUS_OK;
    int i = find_lease(v, ev->object_id);
    if (revoke) {
        if (i >= 0) {
            v->leases[i].state = ARGUS_SHADOW_REVOKED;
            v->leases[i].sequence = ev->sequence;
        }
        return ARGUS_OK;
    }
    if (i >= 0)
        return ARGUS_OK;                       /* verdict already refused reuse */
    if (v->n_leases >= ARGUS_CORE_LEASES)
        return ARGUS_ERR_FULL;
    ArgusLeaseShadow *s = &v->leases[v->n_leases++];
    memset(s, 0, sizeof *s);
    s->lease_id = ev->object_id;
    s->state = ARGUS_SHADOW_LIVE;
    s->subject = ev->principal;
    s->scope = ev->resource;
    s->sequence = ev->sequence;
    return ARGUS_OK;
}

static int apply_artifact(struct ArgusStateView *v, const ArgusEvent *ev, int reject)
{
    if (digest_is_zero(ev->evidence_digest))
        return ARGUS_OK;
    int i = find_artifact(v, ev->evidence_digest);
    if (i < 0) {
        if (v->n_artifacts >= ARGUS_CORE_ARTIFACTS)
            return ARGUS_ERR_FULL;
        i = (int)v->n_artifacts++;
        ArgusArtifactShadow *n = &v->artifacts[i];
        memset(n, 0, sizeof *n);
        memcpy(n->digest, ev->evidence_digest, ARGUS_DIGEST_LEN);
    }
    ArgusArtifactShadow *s = &v->artifacts[i];
    if (reject) {
        s->state = ARGUS_SHADOW_REJECTED;
        s->sequence = ev->sequence;
    } else if (s->state != ARGUS_SHADOW_REJECTED) {
        s->state = ARGUS_SHADOW_LIVE;
        s->sequence = ev->sequence;
    }
    return ARGUS_OK;
}

static int apply_machine(struct ArgusStateView *v, const ArgusEvent *ev)
{
    int i = find_machine(v, ev->machine_id);
    if (ev->kind == ARGUS_EV_MACHINE_REMOVED) {
        if (i >= 0) {                          /* tombstone: trust preserved */
            v->machines[i].joined_sequence = 0;
            v->machines[i].changed_sequence = ev->sequence;
        }
        return ARGUS_OK;
    }
    if (ev->kind == ARGUS_EV_MACHINE_TRUST_CHANGED) {
        if (i >= 0) {                          /* verdict: known machine, downward move */
            v->machines[i].trust = ev->object_id;
            v->machines[i].changed_sequence = ev->sequence;
        }
        return ARGUS_OK;
    }
    /* JOINED */
    uint32_t claim = trust_valid(ev->object_id) ? trust_weaker(ARGUS_TRUST_OBSERVED, ev->object_id)
                                                : (uint32_t)ARGUS_TRUST_OBSERVED;
    if (i >= 0) {
        ArgusMachineShadow *m = &v->machines[i];
        uint32_t t = trust_weaker(m->trust, claim);
        if (m->joined_sequence == 0)
            m->joined_sequence = ev->sequence; /* rejoin of a tombstone */
        if (t != m->trust) {
            m->trust = t;
            m->changed_sequence = ev->sequence;
        }
        return ARGUS_OK;
    }
    if (v->n_machines >= ARGUS_CORE_MACHINES)
        return ARGUS_ERR_FULL;
    uint32_t at = (uint32_t)(-(i + 1));
    if (at < v->n_machines)
        memmove(&v->machines[at + 1u], &v->machines[at], (v->n_machines - at) * sizeof v->machines[0]);
    v->n_machines++;
    ArgusMachineShadow *n = &v->machines[at];
    memset(n, 0, sizeof *n);
    memcpy(n->machine_id, ev->machine_id, ARGUS_MACHINE_ID_LEN);
    n->trust = claim;
    n->joined_sequence = ev->sequence;
    n->changed_sequence = ev->sequence;
    return ARGUS_OK;
}

static int apply_provider(struct ArgusStateView *v, const ArgusEvent *ev, int quarantine)
{
    if (digest_is_zero(ev->evidence_digest))
        return ARGUS_OK;
    int i = find_provider(v, ev->evidence_digest);
    if (i >= 0 && !quarantine)
        return ARGUS_OK;                       /* rediscovery never clears quarantine */
    if (i < 0) {
        if (v->n_providers >= ARGUS_CORE_PROVIDERS)
            return ARGUS_ERR_FULL;
        i = (int)v->n_providers++;
        ArgusProviderShadow *n = &v->providers[i];
        memset(n, 0, sizeof *n);
        memcpy(n->provider_id, ev->evidence_digest, ARGUS_DIGEST_LEN);
    }
    v->providers[i].state = quarantine ? ARGUS_SHADOW_REVOKED : ARGUS_SHADOW_LIVE;
    v->providers[i].sequence = ev->sequence;
    return ARGUS_OK;
}

static int apply_event(struct ArgusStateView *v, const ArgusEvent *ev)
{
    int ok = ev->outcome == ARGUS_OUTCOME_OK;
    switch (ev->kind) {
    case ARGUS_EV_CAPABILITY_GRANTED:
        return ok ? apply_cap(v, ev, 0) : ARGUS_OK;
    case ARGUS_EV_CAPABILITY_REVOKED:
        return ok ? apply_cap(v, ev, 1) : ARGUS_OK;
    case ARGUS_EV_CREDENTIAL_LEASE_CREATED:
        return ok ? apply_lease(v, ev, 0) : ARGUS_OK;
    case ARGUS_EV_CREDENTIAL_LEASE_REVOKED:
        return ok ? apply_lease(v, ev, 1) : ARGUS_OK;
    case ARGUS_EV_ARTIFACT_ADMITTED:
        return (ok && ev->code == 0) ? apply_artifact(v, ev, 0) : ARGUS_OK;
    case ARGUS_EV_ARTIFACT_REJECTED:
        return (ok || ev->outcome == ARGUS_OUTCOME_DENIED) ? apply_artifact(v, ev, 1) : ARGUS_OK;
    case ARGUS_EV_MACHINE_JOINED:
    case ARGUS_EV_MACHINE_TRUST_CHANGED:
    case ARGUS_EV_MACHINE_REMOVED:
        return ok ? apply_machine(v, ev) : ARGUS_OK;
    case ARGUS_EV_PROVIDER_DISCOVERED:
        return ok ? apply_provider(v, ev, 0) : ARGUS_OK;
    case ARGUS_EV_PROVIDER_QUARANTINED:
        return ok ? apply_provider(v, ev, 1) : ARGUS_OK;
    case ARGUS_EV_WORLD_COMMITTED:
        if (ok) {                              /* verdict: first commit or shadow+1 */
            v->world.generation = ev->world_generation;
            memcpy(v->world.digest, ev->evidence_digest, ARGUS_DIGEST_LEN);
            v->world.sequence = ev->sequence;
        }
        return ARGUS_OK;
    case ARGUS_EV_POLICY_CHANGED:
        if (ok)
            memcpy(v->policy_digest, ev->evidence_digest, ARGUS_DIGEST_LEN);
        return ARGUS_OK;
    case ARGUS_EV_RUNTIME_BUILD_CHANGED:
        if (ok)
            memcpy(v->runtime_digest, ev->evidence_digest, ARGUS_DIGEST_LEN);
        return ARGUS_OK;
    default:
        return ARGUS_OK;                       /* observation-only kinds */
    }
}

/* ---- ingest --------------------------------------------------------------- */

int argus_core_ingest(ArgusCore *core, const ArgusEvent *ev, ArgusFinding *out, size_t cap, size_t *n_out)
{
    if (!core || core->magic != CORE_MAGIC || !ev || !n_out || (!out && cap != 0))
        return ARGUS_ERR_ARG;
    struct ArgusCore *c = core;
    ArgusFinding *sf = c->scratch;
    *n_out = 0;
    c->events_received++;

    /* 0. malformed: one MEDIUM finding, not applied, not chained. */
    if (!event_well_formed(ev)) {
        c->events_rejected++;
        core_finding(&sf[0], ARGUS_F_MALFORMED_EVENT, ARGUS_SEV_MEDIUM, ev, 0);
        *n_out = deliver(c, ev, 1, out, cap);
        return ARGUS_ERR_MALFORMED;
    }

    size_t n = 0;
    int full = 0, apply = 1;

    /* 1. per-producer sequence check (lane E cannot see history). */
    uint64_t prior = 0;
    int sq = sequence_check(c, ev, &prior);
    if (sq > 0) {
        core_finding(&sf[n++], ARGUS_F_SEQUENCE_ANOMALY, ARGUS_SEV_HIGH, ev, prior);
        apply = 0;
    } else if (sq < 0) {
        if (c->producers_untracked++ == 0)
            full = 1;                          /* reported once, not per event */
    }

    /* 2. apply verdict on the pre-state. */
    if (apply) {
        uint64_t rp = 0;
        int vd = apply_verdict(&c->view, ev, &rp);
        if (vd == V_REPLAY)
            core_finding(&sf[n++], ARGUS_F_AUTHORITY_REPLAY, ARGUS_SEV_HIGH, ev, rp);
        if (vd != V_APPLY)
            apply = 0;
        if (vd == V_REPLAY || vd == V_SKIP)
            c->events_not_applied++;
    } else {
        c->events_not_applied++;
    }

    /* 3. detectors on PRE-update state; two slots stay reserved for the core. */
    size_t dcap = ARGUS_CORE_MAX_FINDINGS - CORE_RESERVED_SLOTS - n;
    size_t dn = 0;
    int drc = argus_detect_run(&core_ops, &c->view, ev, &sf[n], dcap, &dn);
    if (dn > dcap)
        dn = dcap;
    n += dn;

    /* 4. apply the event's own update. */
    if (apply && apply_event(&c->view, ev) == ARGUS_ERR_FULL)
        full = 1;

    /* 5. evidence gaps. */
    if (ev->kind == ARGUS_EV_TELEMETRY_DROPPED &&
        (ev->object_id == ARGUS_CLASS_CRITICAL || ev->object_id == ARGUS_CLASS_SECURITY)) {
        uint8_t sev = ev->object_id == ARGUS_CLASS_CRITICAL ? ARGUS_SEV_CRITICAL : ARGUS_SEV_HIGH;
        core_finding(&sf[n++], ARGUS_F_TELEMETRY_LOSS, sev, ev, 0);
    }
    if (full) {
        core_finding(&sf[n++], ARGUS_F_TELEMETRY_LOSS, ARGUS_SEV_CRITICAL, ev, 0);
        c->tables_full++;
    }

    /* 6. chain. */
    argus_chain_extend(c->chain, ev);

    /* 7. stamp, count, copy out. */
    size_t k = deliver(c, ev, n, out, cap);
    *n_out = k;

    if (full)
        return ARGUS_ERR_FULL;
    if (k < n)
        return ARGUS_ERR_OVERFLOW;
    return drc;
}

/* ---- canonical state digest ---------------------------------------------- *
 * Every table is encoded, in fixed order, into ArgusEvent-shaped records and
 * folded with argus_chain_extend. Domain separation from the event chain is
 * explicit and twofold: (a) the fold starts from STATE_DOMAIN (a fixed
 * non-zero 32-byte tag), while the event chain starts from zeros; (b) every
 * record has version = STATE_REC_VERSION (0xA5), a version no well-formed
 * event can carry. The records therefore deliberately do NOT pass
 * argus_event_validate; argus_chain_extend does not validate (header convention).
 * `code` carries a record tag so records of different tables never collide.
 *   tag 1 header: object_id=n_caps, cap_id=n_machines, principal=n_artifacts,
 *                 cap_generation=(n_leases<<32)|n_providers,
 *                 resource=(n_producers<<32)|n_incidents, tick=incidents_untracked,
 *                 world_generation=producers_untracked
 *   tag 2 cap, 3 machine, 4 artifact, 5 lease, 6 provider, 7 world,
 *   tag 8 policy, 9 runtime, 10 producer, 11 incident
 * Machines are folded in machine_id order (the table is kept sorted), so the
 * digest depends on the set of machines, not on their join order. Producers are
 * sorted likewise. Other tables fold in insertion order (replay-deterministic).
 * Counters (received/rejected/findings/tables_full/not_applied) and the event
 * chain are not state and are excluded. */

#define STATE_REC_VERSION 0xA5u
static const uint8_t STATE_DOMAIN[ARGUS_DIGEST_LEN] = {
    'A', 'R', 'G', 'U', 'S', '-', '0', ' ', 'c', 'o', 'r', 'e', ' ', 's', 't', 'a',
    't', 'e', ' ', 'd', 'i', 'g', 'e', 's', 't', ' ', 'v', '2', 0xA5, 0x5A, 0xA5, 0x5A
};

static void rec_init(ArgusEvent *r, uint16_t kind, int32_t tag)
{
    memset(r, 0, sizeof *r);
    r->version = STATE_REC_VERSION;
    r->class_ = ARGUS_CLASS_CRITICAL;
    r->kind = kind;
    r->effect_class = ARGUS_EFFECT_NONE;
    r->outcome = ARGUS_OUTCOME_OK;
    r->flags = ARGUS_FLAG_CONSUMER;
    r->code = tag;
}

void argus_core_state_digest(const ArgusCore *core, uint8_t out[ARGUS_DIGEST_LEN])
{
    if (!out)
        return;
    memset(out, 0, ARGUS_DIGEST_LEN);
    if (!core || core->magic != CORE_MAGIC)
        return;
    memcpy(out, STATE_DOMAIN, ARGUS_DIGEST_LEN);
    const struct ArgusStateView *v = &core->view;
    ArgusEvent r;

    rec_init(&r, ARGUS_EV_INTEGRITY_VIOLATION, 1);
    r.object_id = v->n_caps_live;
    r.cap_id = v->n_machines;
    r.principal = v->n_artifacts;
    r.cap_generation = ((uint64_t)v->n_leases << 32) | v->n_providers;
    r.resource = ((uint64_t)core->n_producers << 32) | core->n_incidents;
    r.tick = core->incidents_untracked;
    r.world_generation = core->producers_untracked;
    argus_chain_extend(out, &r);

    for (uint32_t i = 0; i < ARGUS_CORE_CAPS; i++) {
        const ArgusCapShadow *s = &v->caps[i];
        if (s->state == ARGUS_SHADOW_UNSEEN)
            continue;
        rec_init(&r, ARGUS_EV_CAPABILITY_GRANTED, 2);
        r.cap_id = s->cap_id;
        r.cap_generation = s->generation;
        r.world_generation = s->state;
        r.principal = s->subject;
        r.object_id = s->rights;
        r.resource = s->resource;
        r.sequence = s->granted_sequence;
        r.tick = s->revoked_sequence;
        argus_chain_extend(out, &r);
    }
    for (uint32_t i = 0; i < v->n_machines; i++) {
        const ArgusMachineShadow *s = &v->machines[i];
        rec_init(&r, ARGUS_EV_MACHINE_JOINED, 3);
        memcpy(r.machine_id, s->machine_id, ARGUS_MACHINE_ID_LEN);
        r.object_id = s->trust;
        r.sequence = s->joined_sequence;
        r.tick = s->changed_sequence;
        argus_chain_extend(out, &r);
    }
    for (uint32_t i = 0; i < v->n_artifacts; i++) {
        const ArgusArtifactShadow *s = &v->artifacts[i];
        rec_init(&r, ARGUS_EV_ARTIFACT_ADMITTED, 4);
        memcpy(r.evidence_digest, s->digest, ARGUS_DIGEST_LEN);
        r.object_id = s->state;
        r.sequence = s->sequence;
        argus_chain_extend(out, &r);
    }
    for (uint32_t i = 0; i < v->n_leases; i++) {
        const ArgusLeaseShadow *s = &v->leases[i];
        rec_init(&r, ARGUS_EV_CREDENTIAL_LEASE_CREATED, 5);
        r.object_id = s->lease_id;
        r.principal = s->subject;
        r.resource = s->scope;
        r.cap_id = s->state;
        r.sequence = s->sequence;
        argus_chain_extend(out, &r);
    }
    for (uint32_t i = 0; i < v->n_providers; i++) {
        const ArgusProviderShadow *s = &v->providers[i];
        rec_init(&r, ARGUS_EV_PROVIDER_DISCOVERED, 6);
        memcpy(r.evidence_digest, s->provider_id, ARGUS_DIGEST_LEN);
        r.object_id = s->state;
        r.sequence = s->sequence;
        argus_chain_extend(out, &r);
    }
    rec_init(&r, ARGUS_EV_WORLD_COMMITTED, 7);
    r.world_generation = v->world.generation;
    memcpy(r.evidence_digest, v->world.digest, ARGUS_DIGEST_LEN);
    r.sequence = v->world.sequence;
    argus_chain_extend(out, &r);

    rec_init(&r, ARGUS_EV_POLICY_CHANGED, 8);
    memcpy(r.evidence_digest, v->policy_digest, ARGUS_DIGEST_LEN);
    argus_chain_extend(out, &r);

    rec_init(&r, ARGUS_EV_RUNTIME_BUILD_CHANGED, 9);
    memcpy(r.evidence_digest, v->runtime_digest, ARGUS_DIGEST_LEN);
    argus_chain_extend(out, &r);

    for (uint32_t i = 0; i < core->n_producers; i++) {
        const CoreProducer *p = &core->producers[i];
        rec_init(&r, ARGUS_EV_STALE_GENERATION, 10);
        memcpy(r.machine_id, p->machine_id, ARGUS_MACHINE_ID_LEN);
        r.object_id = p->consumer;
        r.sequence = p->last_sequence;
        argus_chain_extend(out, &r);
    }
    for (uint32_t i = 0; i < core->n_incidents; i++) {
        const CoreIncident *in = &core->incidents[i];
        rec_init(&r, ARGUS_EV_SIGNATURE_FAILURE, 11);
        r.principal = in->principal;
        r.object_id = in->code;
        r.cap_id = in->severity;
        r.sequence = in->first_sequence;
        argus_chain_extend(out, &r);
    }
}

void argus_core_health(const ArgusCore *core, ArgusCoreHealth *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof *out);
    if (!core || core->magic != CORE_MAGIC)
        return;
    out->events_received = core->events_received;
    out->events_rejected = core->events_rejected;
    out->findings_emitted = core->findings_emitted;
    out->incidents_open = core->n_incidents;
    out->detector_ns_total = 0;
    out->incidents_untracked = core->incidents_untracked;
    out->producers_untracked = core->producers_untracked;
    out->tables_full = core->tables_full;
    out->events_not_applied = core->events_not_applied;
    memcpy(out->chain, core->chain, ARGUS_DIGEST_LEN);
}
