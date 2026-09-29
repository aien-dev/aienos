/*
 * argus_core.c -- ARGUS-0 resident deterministic state engine (lane D).
 *
 * The core keeps fixed-capacity shadow tables of what the authority and the
 * other producers have announced, runs the hard-invariant detectors against
 * the state as it was BEFORE each event, then applies the event. It never
 * authorizes anything and never re-checks a capability.
 *
 * Properties: caller-provided memory (argus_core_footprint/argus_core_init),
 * no heap use at all, no I/O, no clock, no mutable globals (only the constant
 * ops table). The core holds no pointers, so a byte copy of its memory is a valid
 * snapshot. Hashing goes only through header-declared functions
 * (argus_event_validate, argus_event_digest, argus_chain_extend,
 * argus_detect_run), so the lane-B/E implementations swap in transparently.
 *
 * ---- Field conventions (integrator: mirror these into the ABI docs) --------
 *
 * Producer identity (sequence check). The event has no producer field, so a
 * producer stream is keyed by (machine_id, flags & ARGUS_FLAG_CONSUMER). Events
 * the ring consumer synthesizes (TELEMETRY_DROPPED, flag CONSUMER) therefore
 * form their own sequence stream per machine. A sequence <= the last one seen
 * on that stream raises ARGUS_F_SEQUENCE_ANOMALY (HIGH, prior_sequence = the
 * last sequence seen); the event is still detected and applied, the stream's
 * high-water mark never moves backwards, and ingest returns ARGUS_OK.
 *
 * Outcome gating. A state update is applied only when outcome == OK, except
 * ARTIFACT_REJECTED, which applies on OK or DENIED (the rejection is itself
 * the authority's decision). ERROR outcomes never change state.
 *
 *   CAPABILITY_GRANTED   resource = authority resource, object_id = rights
 *                        mask (AIENOS_CAP_RIGHT_*, low 32 bits), principal =
 *                        subject, (cap_id, cap_generation) = the reference.
 *                        cap_id 0 = none (no update). cap_id >= 256 cannot be
 *                        shadowed -> ARGUS_ERR_FULL. A grant whose generation
 *                        is below the slot's stored generation is ignored
 *                        (the shadow keeps the highest generation seen);
 *                        otherwise the slot is overwritten as LIVE.
 *   CAPABILITY_REVOKED   marks the slot REVOKED with revoked_sequence, raising
 *                        the stored generation if the event's is higher. An
 *                        unseen slot is created as REVOKED (subject 0). A
 *                        revocation of a generation below the stored one is
 *                        ignored.
 *   CREDENTIAL_LEASE_*   lease id = object_id (0 = none). CREATED: subject =
 *                        principal, scope = resource, LIVE. REVOKED: REVOKED
 *                        (created as REVOKED if unseen). A CREATED on a revoked
 *                        lease id does not revive it.
 *   ARTIFACT_*           keyed by evidence_digest (all-zero = none). ADMITTED:
 *                        LIVE. REJECTED: REJECTED. Rejection is sticky: a later
 *                        ADMITTED does not un-reject.
 *   MACHINE_JOINED       keyed by machine_id; new -> trust OBSERVED. A rejoin
 *                        of a known machine changes nothing (no trust laundering).
 *   MACHINE_TRUST_CHANGED resource = new ARGUS_TRUST_* (values above
 *                        REATTESTATION_REQUIRED are ignored); an unknown machine
 *                        is created with joined_sequence 0.
 *   MACHINE_REMOVED      deletes the entry (order-preserving).
 *   PROVIDER_*           keyed by evidence_digest. DISCOVERED: LIVE if new; a
 *                        rediscovery never clears a quarantine. QUARANTINED:
 *                        REVOKED (created if unseen).
 *   WORLD_COMMITTED      world_generation + evidence_digest; applied only when
 *                        world_generation > the stored generation (no regress).
 *   POLICY_CHANGED / RUNTIME_BUILD_CHANGED  evidence_digest = expected digest.
 *   TELEMETRY_DROPPED    object_id = class, resource = count (header). Class
 *                        CRITICAL -> ARGUS_F_TELEMETRY_LOSS CRITICAL, class
 *                        SECURITY -> HIGH. Lane E must not raise this code for
 *                        TELEMETRY_DROPPED, or it is reported twice.
 *
 * Table full (or cap_id >= 256): the update is dropped, ingest returns
 * ARGUS_ERR_FULL, and one CRITICAL ARGUS_F_TELEMETRY_LOSS finding is emitted,
 * because the shadow can no longer mirror the authority. The event still
 * extends the chain and its other findings are still delivered.
 *
 * Findings. Core findings: confidence DETERMINISTIC, detector == code,
 * sync_allowed 0, containment NONE. Every finding (core and lane E) gets
 * event_digest = argus_event_digest(ev). Findings are collected in an internal
 * scratch of ARGUS_CORE_MAX_FINDINGS (two slots reserved for core findings),
 * state is applied regardless of the caller's buffer, then min(n, cap) are
 * copied out. If n > cap, ingest returns ARGUS_ERR_OVERFLOW with *n_out = cap:
 * findings are lost to the caller, state never is. findings_emitted counts all.
 * Return precedence: MALFORMED > FULL > OVERFLOW > detector error > OK.
 *
 * Incidents (ARGUS-0): distinct (principal, finding code) pairs with severity
 * >= HIGH, in a 64-entry table; pairs beyond that are counted as untracked and
 * not in incidents_open.
 *
 * Lookups: caps are O(1) direct index. Machines, artifacts, leases, providers
 * are linear scans over at most 64 entries (bounded, no allocation).
 */
#include "argus_core.h"

#include <string.h>

#if ARGUS_CORE_CAPS != 256u
#error "ARGUS_CORE_CAPS must equal AIENOS_CAP_MAX (256)"
#endif

#define CORE_MAGIC 0x3053554752410001ull   /* "ARGUS0" + layout 1 */
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
    ArgusMachineShadow  machines[ARGUS_CORE_MACHINES];
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
    CoreProducer producers[ARGUS_CORE_PRODUCERS];
    CoreIncident incidents[ARGUS_CORE_INCIDENTS];
    uint32_t n_producers, n_incidents;
    uint64_t incidents_untracked;
    uint64_t events_received, events_rejected, findings_emitted;
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

static int find_machine(const struct ArgusStateView *v, const uint8_t id[ARGUS_MACHINE_ID_LEN])
{
    for (uint32_t i = 0; i < v->n_machines; i++)
        if (memcmp(v->machines[i].machine_id, id, ARGUS_MACHINE_ID_LEN) == 0)
            return (int)i;
    return -1;
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

/* ---- sequence check ------------------------------------------------------- */

/* Returns 1 on anomaly (and sets *prior), 0 if in order, -1 if the producer
 * table is full (stream cannot be tracked). Advances the high-water mark. */
static int sequence_check(struct ArgusCore *c, const ArgusEvent *ev, uint64_t *prior)
{
    uint32_t consumer = (ev->flags & ARGUS_FLAG_CONSUMER) ? 1u : 0u;
    for (uint32_t i = 0; i < c->n_producers; i++) {
        CoreProducer *p = &c->producers[i];
        if (p->consumer == consumer && memcmp(p->machine_id, ev->machine_id, ARGUS_MACHINE_ID_LEN) == 0) {
            if (ev->sequence <= p->last_sequence) {
                *prior = p->last_sequence;
                return 1;
            }
            p->last_sequence = ev->sequence;
            return 0;
        }
    }
    if (c->n_producers >= ARGUS_CORE_PRODUCERS)
        return -1;
    CoreProducer *p = &c->producers[c->n_producers++];
    memcpy(p->machine_id, ev->machine_id, ARGUS_MACHINE_ID_LEN);
    p->consumer = consumer;
    p->last_sequence = ev->sequence;
    return 0;
}

/* ---- state update --------------------------------------------------------- */

static int apply_cap(struct ArgusStateView *v, const ArgusEvent *ev, int revoke)
{
    if (ev->cap_id == 0)
        return ARGUS_OK;
    if (ev->cap_id >= ARGUS_CORE_CAPS)
        return ARGUS_ERR_FULL;
    ArgusCapShadow *s = &v->caps[ev->cap_id];
    int seen = s->state != ARGUS_SHADOW_UNSEEN;
    if (seen && ev->cap_generation < s->generation)
        return ARGUS_OK;                       /* stale: shadow keeps highest generation */
    if (!seen) {
        memset(s, 0, sizeof *s);
        v->n_caps_live++;
    }
    s->cap_id = ev->cap_id;
    s->generation = ev->cap_generation;
    if (revoke) {
        s->state = ARGUS_SHADOW_REVOKED;
        s->revoked_sequence = ev->sequence;
    } else {
        s->state = ARGUS_SHADOW_LIVE;
        s->subject = ev->principal;
        s->rights = (uint32_t)ev->object_id;
        s->resource = ev->resource;
        s->granted_sequence = ev->sequence;
        s->revoked_sequence = 0;
    }
    return ARGUS_OK;
}

static int apply_lease(struct ArgusStateView *v, const ArgusEvent *ev, int revoke)
{
    if (ev->object_id == 0)
        return ARGUS_OK;
    int i = find_lease(v, ev->object_id);
    if (i < 0) {
        if (v->n_leases >= ARGUS_CORE_LEASES)
            return ARGUS_ERR_FULL;
        i = (int)v->n_leases++;
        ArgusLeaseShadow *n = &v->leases[i];
        memset(n, 0, sizeof *n);
        n->lease_id = ev->object_id;
        n->state = ARGUS_SHADOW_UNSEEN;
    }
    ArgusLeaseShadow *s = &v->leases[i];
    if (revoke) {
        s->state = ARGUS_SHADOW_REVOKED;
        s->sequence = ev->sequence;
    } else if (s->state != ARGUS_SHADOW_REVOKED) {
        s->state = ARGUS_SHADOW_LIVE;
        s->subject = ev->principal;
        s->scope = ev->resource;
        s->sequence = ev->sequence;
    }
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
        if (i >= 0) {
            uint32_t tail = v->n_machines - (uint32_t)i - 1u;
            if (tail)
                memmove(&v->machines[i], &v->machines[i + 1], tail * sizeof v->machines[0]);
            v->n_machines--;
            memset(&v->machines[v->n_machines], 0, sizeof v->machines[0]);
        }
        return ARGUS_OK;
    }
    if (ev->kind == ARGUS_EV_MACHINE_TRUST_CHANGED && ev->resource > ARGUS_TRUST_REATTESTATION_REQUIRED)
        return ARGUS_OK;
    if (i < 0) {
        if (v->n_machines >= ARGUS_CORE_MACHINES)
            return ARGUS_ERR_FULL;
        i = (int)v->n_machines++;
        ArgusMachineShadow *n = &v->machines[i];
        memset(n, 0, sizeof *n);
        memcpy(n->machine_id, ev->machine_id, ARGUS_MACHINE_ID_LEN);
        if (ev->kind == ARGUS_EV_MACHINE_JOINED) {
            n->trust = ARGUS_TRUST_OBSERVED;
            n->joined_sequence = ev->sequence;
            n->changed_sequence = ev->sequence;
            return ARGUS_OK;
        }
    } else if (ev->kind == ARGUS_EV_MACHINE_JOINED) {
        return ARGUS_OK;                       /* rejoin never launders trust */
    }
    v->machines[i].trust = (uint32_t)ev->resource;
    v->machines[i].changed_sequence = ev->sequence;
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
        return ok ? apply_artifact(v, ev, 0) : ARGUS_OK;
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
        if (ok && ev->world_generation > v->world.generation) {
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
    *n_out = 0;
    c->events_received++;

    if (argus_event_validate(ev) != ARGUS_OK) {
        c->events_rejected++;
        return ARGUS_ERR_MALFORMED;
    }

    ArgusFinding *sf = c->scratch;
    size_t n = 0;
    int full = 0;

    /* 1. per-producer sequence check (lane E cannot see history). */
    uint64_t prior = 0;
    int sq = sequence_check(c, ev, &prior);
    if (sq > 0)
        core_finding(&sf[n++], ARGUS_F_SEQUENCE_ANOMALY, ARGUS_SEV_HIGH, ev, prior);
    else if (sq < 0)
        full = 1;

    /* 2. detectors on PRE-update state; two slots stay reserved for the core. */
    size_t dcap = ARGUS_CORE_MAX_FINDINGS - CORE_RESERVED_SLOTS - n;
    size_t dn = 0;
    int drc = argus_detect_run(&core_ops, &c->view, ev, &sf[n], dcap, &dn);
    if (dn > dcap)
        dn = dcap;
    n += dn;

    /* 3. apply the event's own update. */
    if (apply_event(&c->view, ev) == ARGUS_ERR_FULL)
        full = 1;

    /* 4. evidence gaps. */
    if (ev->kind == ARGUS_EV_TELEMETRY_DROPPED &&
        (ev->object_id == ARGUS_CLASS_CRITICAL || ev->object_id == ARGUS_CLASS_SECURITY)) {
        uint8_t sev = ev->object_id == ARGUS_CLASS_CRITICAL ? ARGUS_SEV_CRITICAL : ARGUS_SEV_HIGH;
        core_finding(&sf[n++], ARGUS_F_TELEMETRY_LOSS, sev, ev, 0);
    }
    if (full)
        core_finding(&sf[n++], ARGUS_F_TELEMETRY_LOSS, ARGUS_SEV_CRITICAL, ev, 0);

    /* 5. chain. */
    argus_chain_extend(c->chain, ev);

    /* 6. stamp, count, copy out. */
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
    *n_out = k;

    if (full)
        return ARGUS_ERR_FULL;
    if (k < n)
        return ARGUS_ERR_OVERFLOW;
    return drc;
}

/* ---- canonical state digest ---------------------------------------------- *
 * Every table is encoded, in fixed order, into ArgusEvent-shaped records that
 * pass argus_event_validate (version 1, class CRITICAL, effect NONE, outcome
 * OK, flags CONSUMER) and folded with argus_chain_extend from a zero digest.
 * `code` carries a record tag so records of different tables never collide.
 *   tag 1 header: object_id=n_caps, cap_id=n_machines, principal=n_artifacts,
 *                 cap_generation=(n_leases<<32)|n_providers,
 *                 resource=(n_producers<<32)|n_incidents, tick=incidents_untracked
 *   tag 2 cap, 3 machine, 4 artifact, 5 lease, 6 provider, 7 world,
 *   tag 8 policy, 9 runtime, 10 producer, 11 incident
 * Counters (received/rejected/findings) and the event chain are not state and
 * are excluded. */

static void rec_init(ArgusEvent *r, uint16_t kind, int32_t tag)
{
    memset(r, 0, sizeof *r);
    r->version = ARGUS_ABI_VERSION;
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
    const struct ArgusStateView *v = &core->view;
    ArgusEvent r;

    rec_init(&r, ARGUS_EV_INTEGRITY_VIOLATION, 1);
    r.object_id = v->n_caps_live;
    r.cap_id = v->n_machines;
    r.principal = v->n_artifacts;
    r.cap_generation = ((uint64_t)v->n_leases << 32) | v->n_providers;
    r.resource = ((uint64_t)core->n_producers << 32) | core->n_incidents;
    r.tick = core->incidents_untracked;
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
    memcpy(out->chain, core->chain, ARGUS_DIGEST_LEN);
}
