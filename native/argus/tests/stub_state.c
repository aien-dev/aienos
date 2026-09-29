/*
 * stub_state.c -- test-only in-memory shadow state + deterministic corpora (lane E).
 *
 * Reference apply rules (stub_state_apply). They follow the apply rules and
 * machine lifecycle fixed in argus_abi.h (4cd73cc) so that a stream that is
 * clean against this stub is also clean against the real core (lane D).
 * Only events with outcome OK change state, except ARTIFACT_REJECTED, which
 * records the rejection at any outcome.
 *   CAPABILITY_GRANTED   applies only when the slot is UNSEEN or cap_generation
 *                        is strictly above the shadow generation: state LIVE,
 *                        generation, subject = principal, rights = object_id,
 *                        resource, granted_sequence. Otherwise not applied.
 *   CAPABILITY_REVOKED   seen slot: state REVOKED, revoked_sequence. An UNSEEN
 *                        slot creates no entry.
 *   CREDENTIAL_LEASE_CREATED  new lease id only: LIVE, subject = principal,
 *                        scope = resource, sequence. A LIVE or REVOKED id is
 *                        not applied (lease ids are never reused, ruling A).
 *   CREDENTIAL_LEASE_REVOKED  lease[object_id]: REVOKED, sequence.
 *   ARTIFACT_ADMITTED    (code 0 only) LIVE, sequence; a rejection is sticky.
 *   ARTIFACT_REJECTED    REJECTED, sequence.
 *   MACHINE_JOINED       not currently joined: trust = the worse (by rank) of
 *                        max(OBSERVED, object_id) and a tombstone's preserved
 *                        trust; joined_sequence = changed_sequence = sequence.
 *                        A joined machine is unchanged.
 *   MACHINE_TRUST_CHANGED joined machine, valid value (1..6), downward or equal
 *                        by rank only: trust, changed_sequence. Unknown
 *                        machines get no entry; upward moves are ignored.
 *   MACHINE_REMOVED      tombstone: joined_sequence 0, trust preserved.
 *   PROVIDER_DISCOVERED  new provider: LIVE; rediscovery never clears quarantine.
 *   PROVIDER_QUARANTINED provider: REVOKED (quarantined), sequence.
 *   WORLD_COMMITTED      adopted only when shadow generation is 0 or
 *                        world_generation == shadow + 1.
 *   POLICY_CHANGED / RUNTIME_BUILD_CHANGED  expected digest = evidence_digest.
 *
 * The corpora also follow the validate rules of argus_abi.h: class never
 * weaker than the per-kind minimum (stub_min_class below, a local copy of
 * lane B's argus_event_min_class table until integration), no CONSUMER flag,
 * cap_id < ARGUS_CAP_MAX, EXTERNAL_EFFECT_* with effect_class EXTERNAL.
 */
#include "stub_state.h"
#include "../argus_detect.h"

#include <string.h>

/* ---- lookups ---------------------------------------------------------------- */

static const StubState *S(const ArgusStateView *v) { return (const StubState *)(const void *)v; }

static int op_cap(const ArgusStateView *v, uint32_t id, ArgusCapShadow *out)
{
    const StubState *s = S(v);
    for (size_t i = 0; i < s->n_caps; i++)
        if (s->caps[i].cap_id == id) { *out = s->caps[i]; return ARGUS_OK; }
    return ARGUS_ERR_STATE;
}

static int op_machine(const ArgusStateView *v, const uint8_t id[ARGUS_MACHINE_ID_LEN], ArgusMachineShadow *out)
{
    const StubState *s = S(v);
    for (size_t i = 0; i < s->n_machines; i++)
        if (memcmp(s->machines[i].machine_id, id, ARGUS_MACHINE_ID_LEN) == 0) { *out = s->machines[i]; return ARGUS_OK; }
    return ARGUS_ERR_STATE;
}

static int op_artifact(const ArgusStateView *v, const uint8_t d[ARGUS_DIGEST_LEN], ArgusArtifactShadow *out)
{
    const StubState *s = S(v);
    for (size_t i = 0; i < s->n_artifacts; i++)
        if (memcmp(s->artifacts[i].digest, d, ARGUS_DIGEST_LEN) == 0) { *out = s->artifacts[i]; return ARGUS_OK; }
    return ARGUS_ERR_STATE;
}

static int op_lease(const ArgusStateView *v, uint32_t id, ArgusLeaseShadow *out)
{
    const StubState *s = S(v);
    for (size_t i = 0; i < s->n_leases; i++)
        if (s->leases[i].lease_id == id) { *out = s->leases[i]; return ARGUS_OK; }
    return ARGUS_ERR_STATE;
}

static int op_provider(const ArgusStateView *v, const uint8_t id[ARGUS_DIGEST_LEN], ArgusProviderShadow *out)
{
    const StubState *s = S(v);
    for (size_t i = 0; i < s->n_providers; i++)
        if (memcmp(s->providers[i].provider_id, id, ARGUS_DIGEST_LEN) == 0) { *out = s->providers[i]; return ARGUS_OK; }
    return ARGUS_ERR_STATE;
}

static int op_world(const ArgusStateView *v, ArgusWorldShadow *out)
{
    const StubState *s = S(v);
    if (s->world.generation == 0 && s->world.sequence == 0)
        return ARGUS_ERR_STATE;
    *out = s->world;
    return ARGUS_OK;
}

static int op_policy(const ArgusStateView *v, uint8_t out[ARGUS_DIGEST_LEN])
{
    memcpy(out, S(v)->policy, ARGUS_DIGEST_LEN);
    return ARGUS_OK;
}

static int op_runtime(const ArgusStateView *v, uint8_t out[ARGUS_DIGEST_LEN])
{
    memcpy(out, S(v)->runtime, ARGUS_DIGEST_LEN);
    return ARGUS_OK;
}

static const ArgusStateOps stub_ops = {
    op_cap, op_machine, op_artifact, op_lease, op_provider, op_world, op_policy, op_runtime,
};

void stub_state_init(StubState *s) { memset(s, 0, sizeof *s); }
const ArgusStateOps *stub_state_ops(void) { return &stub_ops; }
const ArgusStateView *stub_state_view(const StubState *s) { return (const ArgusStateView *)(const void *)s; }

/* ---- population ------------------------------------------------------------- */

int stub_put_cap(StubState *s, const ArgusCapShadow *c)
{
    for (size_t i = 0; i < s->n_caps; i++)
        if (s->caps[i].cap_id == c->cap_id) { s->caps[i] = *c; return ARGUS_OK; }
    if (s->n_caps >= STUB_MAX_CAPS) return ARGUS_ERR_FULL;
    s->caps[s->n_caps++] = *c;
    return ARGUS_OK;
}

int stub_put_machine(StubState *s, const ArgusMachineShadow *m)
{
    for (size_t i = 0; i < s->n_machines; i++)
        if (memcmp(s->machines[i].machine_id, m->machine_id, ARGUS_MACHINE_ID_LEN) == 0) { s->machines[i] = *m; return ARGUS_OK; }
    if (s->n_machines >= STUB_MAX_MACHINES) return ARGUS_ERR_FULL;
    s->machines[s->n_machines++] = *m;
    return ARGUS_OK;
}

int stub_put_artifact(StubState *s, const ArgusArtifactShadow *a)
{
    for (size_t i = 0; i < s->n_artifacts; i++)
        if (memcmp(s->artifacts[i].digest, a->digest, ARGUS_DIGEST_LEN) == 0) { s->artifacts[i] = *a; return ARGUS_OK; }
    if (s->n_artifacts >= STUB_MAX_ARTIFACTS) return ARGUS_ERR_FULL;
    s->artifacts[s->n_artifacts++] = *a;
    return ARGUS_OK;
}

int stub_put_lease(StubState *s, const ArgusLeaseShadow *l)
{
    for (size_t i = 0; i < s->n_leases; i++)
        if (s->leases[i].lease_id == l->lease_id) { s->leases[i] = *l; return ARGUS_OK; }
    if (s->n_leases >= STUB_MAX_LEASES) return ARGUS_ERR_FULL;
    s->leases[s->n_leases++] = *l;
    return ARGUS_OK;
}

int stub_put_provider(StubState *s, const ArgusProviderShadow *p)
{
    for (size_t i = 0; i < s->n_providers; i++)
        if (memcmp(s->providers[i].provider_id, p->provider_id, ARGUS_DIGEST_LEN) == 0) { s->providers[i] = *p; return ARGUS_OK; }
    if (s->n_providers >= STUB_MAX_PROVIDERS) return ARGUS_ERR_FULL;
    s->providers[s->n_providers++] = *p;
    return ARGUS_OK;
}

void stub_set_world(StubState *s, uint64_t generation, const uint8_t digest[ARGUS_DIGEST_LEN], uint64_t sequence)
{
    s->world.generation = generation;
    memcpy(s->world.digest, digest, ARGUS_DIGEST_LEN);
    s->world.sequence = sequence;
}


/* ---- per-kind minimum class (local copy of lane B's table) ----------------- *
 * CRITICAL: 4, 12, 21, 31, 32, 42, 52, 60-63, 71, 72, 80
 * SECURITY: 1, 3, 10, 20, 22, 30, 40, 41, 50, 51, 70
 * AUDIT:    2, 11, 43
 * Anything else (not a kind in ABI v1): 0, as in lane B's table. */
uint8_t stub_min_class(uint16_t kind)
{
    switch (kind) {
    case ARGUS_EV_CAPABILITY_REVOKED:
    case ARGUS_EV_CREDENTIAL_LEASE_REVOKED:
    case ARGUS_EV_ARTIFACT_REJECTED:
    case ARGUS_EV_MACHINE_TRUST_CHANGED:
    case ARGUS_EV_MACHINE_REMOVED:
    case ARGUS_EV_PROVIDER_QUARANTINED:
    case ARGUS_EV_EXTERNAL_EFFECT_COMMITTED:
    case ARGUS_EV_INTEGRITY_VIOLATION:
    case ARGUS_EV_SIGNATURE_FAILURE:
    case ARGUS_EV_STALE_GENERATION:
    case ARGUS_EV_FORGED_CAPABILITY:
    case ARGUS_EV_POLICY_CHANGED:
    case ARGUS_EV_RUNTIME_BUILD_CHANGED:
    case ARGUS_EV_TELEMETRY_DROPPED:
        return ARGUS_CLASS_CRITICAL;
    case ARGUS_EV_CAPABILITY_GRANTED:
    case ARGUS_EV_CAPABILITY_DENIED:
    case ARGUS_EV_CREDENTIAL_LEASE_CREATED:
    case ARGUS_EV_ARTIFACT_ADMITTED:
    case ARGUS_EV_ARTIFACT_ACTIVATED:
    case ARGUS_EV_MACHINE_JOINED:
    case ARGUS_EV_PROVIDER_DISCOVERED:
    case ARGUS_EV_PROVIDER_CHANGED:
    case ARGUS_EV_EXTERNAL_EFFECT_REQUESTED:
    case ARGUS_EV_EXTERNAL_EFFECT_DENIED:
    case ARGUS_EV_WORLD_COMMITTED:
        return ARGUS_CLASS_SECURITY;
    case ARGUS_EV_CAPABILITY_USED:
    case ARGUS_EV_CREDENTIAL_LEASE_USED:
    case ARGUS_EV_PROVIDER_USED:
        return ARGUS_CLASS_AUDIT;
    default:
        return 0;
    }
}

static int rank_or(uint32_t trust, int dflt)
{
    int r = argus_trust_rank(trust);
    return r < 0 ? dflt : r;
}

int stub_state_apply(StubState *s, const ArgusEvent *ev)
{
    const StubState *cs = s;
    const ArgusStateView *v = stub_state_view(cs);
    if (ev->kind == ARGUS_EV_ARTIFACT_REJECTED) {
        ArgusArtifactShadow a = {0};
        memcpy(a.digest, ev->evidence_digest, ARGUS_DIGEST_LEN);
        a.state = ARGUS_SHADOW_REJECTED;
        a.sequence = ev->sequence;
        return stub_put_artifact(s, &a);
    }
    if (ev->outcome != ARGUS_OUTCOME_OK)
        return ARGUS_OK;
    switch (ev->kind) {
    case ARGUS_EV_CAPABILITY_GRANTED: {
        ArgusCapShadow c = {0};
        int seen = op_cap(v, ev->cap_id, &c) == ARGUS_OK && c.state != ARGUS_SHADOW_UNSEEN;
        if (seen && ev->cap_generation <= c.generation) return ARGUS_OK;   /* replay: not applied */
        memset(&c, 0, sizeof c);
        c.cap_id = ev->cap_id;
        c.generation = ev->cap_generation;
        c.state = ARGUS_SHADOW_LIVE;
        c.subject = ev->principal;
        c.rights = (uint32_t)ev->object_id;
        c.resource = ev->resource;
        c.granted_sequence = ev->sequence;
        return stub_put_cap(s, &c);
    }
    case ARGUS_EV_CAPABILITY_REVOKED: {
        ArgusCapShadow c;
        if (op_cap(v, ev->cap_id, &c) != ARGUS_OK || c.state == ARGUS_SHADOW_UNSEEN) return ARGUS_OK;
        c.state = ARGUS_SHADOW_REVOKED;
        c.revoked_sequence = ev->sequence;
        return stub_put_cap(s, &c);
    }
    case ARGUS_EV_CREDENTIAL_LEASE_CREATED: {
        ArgusLeaseShadow l = {0};
        if (op_lease(v, ev->object_id, &l) == ARGUS_OK && l.state != ARGUS_SHADOW_UNSEEN) return ARGUS_OK;
        memset(&l, 0, sizeof l);
        l.lease_id = ev->object_id; l.subject = ev->principal; l.scope = ev->resource;
        l.state = ARGUS_SHADOW_LIVE; l.sequence = ev->sequence;
        return stub_put_lease(s, &l);
    }
    case ARGUS_EV_CREDENTIAL_LEASE_REVOKED: {
        ArgusLeaseShadow l;
        if (op_lease(v, ev->object_id, &l) != ARGUS_OK) return ARGUS_OK;
        l.state = ARGUS_SHADOW_REVOKED; l.sequence = ev->sequence;
        return stub_put_lease(s, &l);
    }
    case ARGUS_EV_ARTIFACT_ADMITTED: {
        if (ev->code != 0) return ARGUS_OK;
        ArgusArtifactShadow a = {0};
        if (op_artifact(v, ev->evidence_digest, &a) == ARGUS_OK && a.state == ARGUS_SHADOW_REJECTED) return ARGUS_OK;
        memset(&a, 0, sizeof a);
        memcpy(a.digest, ev->evidence_digest, ARGUS_DIGEST_LEN);
        a.state = ARGUS_SHADOW_LIVE; a.sequence = ev->sequence;
        return stub_put_artifact(s, &a);
    }
    case ARGUS_EV_MACHINE_JOINED: {
        ArgusMachineShadow m = {0};
        int found = op_machine(v, ev->machine_id, &m) == ARGUS_OK;
        if (found && m.joined_sequence != 0) return ARGUS_OK;          /* already joined */
        int obs = argus_trust_rank(ARGUS_TRUST_OBSERVED);
        uint32_t trust = ARGUS_TRUST_OBSERVED;
        if (rank_or(ev->object_id, obs) > obs) trust = ev->object_id;   /* capped at OBSERVED */
        if (found && rank_or(m.trust, obs) > rank_or(trust, obs)) trust = m.trust;   /* tombstone keeps worse */
        memcpy(m.machine_id, ev->machine_id, ARGUS_MACHINE_ID_LEN);
        m.trust = trust;
        m.joined_sequence = m.changed_sequence = ev->sequence;
        return stub_put_machine(s, &m);
    }
    case ARGUS_EV_MACHINE_TRUST_CHANGED: {
        ArgusMachineShadow m;
        if (op_machine(v, ev->machine_id, &m) != ARGUS_OK || m.joined_sequence == 0) return ARGUS_OK;
        int to = argus_trust_rank(ev->object_id);
        if (to < 0 || to < rank_or(m.trust, argus_trust_rank(ARGUS_TRUST_OBSERVED))) return ARGUS_OK;   /* upward: ignored */
        m.trust = ev->object_id; m.changed_sequence = ev->sequence;
        return stub_put_machine(s, &m);
    }
    case ARGUS_EV_MACHINE_REMOVED: {
        ArgusMachineShadow m;
        if (op_machine(v, ev->machine_id, &m) != ARGUS_OK) return ARGUS_OK;
        m.joined_sequence = 0;                                           /* tombstone, trust kept */
        return stub_put_machine(s, &m);
    }
    case ARGUS_EV_PROVIDER_DISCOVERED:
    case ARGUS_EV_PROVIDER_QUARANTINED: {
        ArgusProviderShadow p = {0};
        int found = op_provider(v, ev->evidence_digest, &p) == ARGUS_OK;
        if (ev->kind == ARGUS_EV_PROVIDER_DISCOVERED && found) return ARGUS_OK;   /* rediscovery changes nothing */
        memcpy(p.provider_id, ev->evidence_digest, ARGUS_DIGEST_LEN);
        p.state = ev->kind == ARGUS_EV_PROVIDER_DISCOVERED ? ARGUS_SHADOW_LIVE : ARGUS_SHADOW_REVOKED;
        p.sequence = ev->sequence;
        return stub_put_provider(s, &p);
    }
    case ARGUS_EV_WORLD_COMMITTED:
        if (s->world.generation == 0 ||
            (s->world.generation != UINT64_MAX && ev->world_generation == s->world.generation + 1u))
            stub_set_world(s, ev->world_generation, ev->evidence_digest, ev->sequence);
        return ARGUS_OK;
    case ARGUS_EV_POLICY_CHANGED:
        memcpy(s->policy, ev->evidence_digest, ARGUS_DIGEST_LEN);
        return ARGUS_OK;
    case ARGUS_EV_RUNTIME_BUILD_CHANGED:
        memcpy(s->runtime, ev->evidence_digest, ARGUS_DIGEST_LEN);
        return ARGUS_OK;
    default:
        return ARGUS_OK;
    }
}

/* ---- corpus generator ------------------------------------------------------- *
 * One generator keeps its own model of the legal state and only emits events
 * that are legal against it (and against the argus_abi.h apply/validate rules).
 * The hostile variant injects one violation every ARGUS_CORPUS_HOSTILE_EVERY
 * events; each injection is built so exactly one detector fires. An injection
 * that the core does not apply (world skip, trust escalation, lease re-create)
 * leaves the model unchanged; one that it applies (a capped JOINED) is
 * followed by the model, so later legal events stay legal.
 * Cap/right/result numbers below mirror native/capability (see argus_detect.h). */

#define G_SLOTS          48    /* cap ids 1..48; ids 200..255 are never granted */
#define G_UNSEEN_CAP    200u
#define G_LEASES         12    /* concurrent lease slots */
#define G_LEASE_IDS      56    /* distinct lease ids per stream, below the core's 64-entry table */
#define G_MACHINES        5    /* M0..M3 always joined; M4 cycles join/remove */
#define G_PROVIDERS       4
#define G_ARTIFACTS      96    /* ruling B: core artifact table is 256 */
#define G_QM              3    /* machine quarantined from 2/5 of the day on (no legal release in v1) */
#define G_QP              2    /* provider quarantined in the second half */
#define G_DOWN            1    /* machine whose trust steps down during the day */

#define R_READ   0x1u
#define R_WRITE  0x2u
#define R_EFFECT 0x4u
#define C_ERR_BOUNDS       (-1)
#define C_ERR_STALE_GEN    (-2)
#define C_ERR_REVOKED      (-3)
#define C_ERR_SUBJECT      (-5)
#define C_ERR_RIGHTS       (-7)
#define C_ERR_UNAUTHORIZED (-15)

typedef struct {
    uint64_t rng;
    ArgusEvent *out;
    size_t max, n;
    struct { uint64_t gen; uint32_t state; uint32_t subject; uint32_t rights; uint64_t resource; } slot[G_SLOTS];
    struct { uint32_t id; uint32_t state; uint32_t subject; uint64_t scope; } lease[G_LEASES];
    uint32_t next_lease_id;
    uint8_t  machine[G_MACHINES][ARGUS_MACHINE_ID_LEN];
    int      m_joined[G_MACHINES];
    uint32_t m_trust[G_MACHINES];
    uint8_t  provider[G_PROVIDERS][ARGUS_DIGEST_LEN];
    int      p_quar[G_PROVIDERS];
    uint8_t  artifact[G_ARTIFACTS][ARGUS_DIGEST_LEN];
    uint32_t a_state[G_ARTIFACTS];
    size_t   n_art;
    uint64_t world_gen;
    uint8_t  world_digest[ARGUS_DIGEST_LEN];
    uint8_t  policy[ARGUS_DIGEST_LEN];
    uint8_t  runtime[ARGUS_DIGEST_LEN];
    int      policy_tampered;
    uint64_t digest_ctr;
    int      m3_quarantined_done, p2_quarantined_done;
    /* hostile */
    int hostile;
    ArgusExpectedFinding *expect;
    size_t expect_max, n_expect;
    size_t next_inject;
    unsigned inject_type;
} Gen;

static uint64_t rnd(Gen *g)
{
    uint64_t z = (g->rng += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

static uint32_t rn(Gen *g, uint32_t n) { return (uint32_t)(rnd(g) % n); }

/* Deterministic, unique 32-byte value (tag keeps namespaces apart). */
static void fresh_digest(Gen *g, uint8_t tag, uint8_t out[ARGUS_DIGEST_LEN])
{
    uint64_t c = ++g->digest_ctr;
    for (size_t i = 0; i < ARGUS_DIGEST_LEN; i++) {
        uint64_t z = c * 0x9E3779B97F4A7C15ull + i * 0xD1B54A32D192ED03ull + tag;
        z = (z ^ (z >> 29)) * 0xBF58476D1CE4E5B9ull;
        out[i] = (uint8_t)(z >> 32);
    }
    out[0] = tag;
    out[1] = (uint8_t)c;
    out[2] = (uint8_t)(c >> 8);
}

static ArgusEvent *emit_ev(Gen *g, uint16_t kind, uint8_t outcome, int32_t code)
{
    if (g->n >= g->max)
        return NULL;
    ArgusEvent *e = &g->out[g->n++];
    memset(e, 0, sizeof *e);
    e->version = ARGUS_ABI_VERSION;
    e->class_ = stub_min_class(kind);
    e->kind = kind;
    e->outcome = outcome;
    e->code = code;
    e->flags = ARGUS_FLAG_SYNTHETIC;
    e->sequence = (uint64_t)g->n;   /* 1-based, strictly increasing */
    e->tick = (uint64_t)g->n;
    return e;
}

/* Attribute to a joined, non-quarantined machine. Every corpus event carries a
 * machine_id (M0..M2 are always joined and never quarantined). */
static void attach_ok(Gen *g, ArgusEvent *e)
{
    uint32_t start = rn(g, G_MACHINES);
    for (uint32_t k = 0; k < G_MACHINES; k++) {
        uint32_t i = (start + k) % G_MACHINES;
        if (g->m_joined[i] && g->m_trust[i] != ARGUS_TRUST_QUARANTINED) {
            memcpy(e->machine_id, g->machine[i], ARGUS_MACHINE_ID_LEN);
            return;
        }
    }
}

static int find_slot(Gen *g, uint32_t state, uint32_t need_rights, uint32_t lack_rights, uint64_t min_gen)
{
    uint32_t start = rn(g, G_SLOTS);
    for (uint32_t k = 0; k < G_SLOTS; k++) {
        uint32_t i = (start + k) % G_SLOTS;
        if (g->slot[i].state == state && (g->slot[i].rights & need_rights) == need_rights &&
            (g->slot[i].rights & lack_rights) == 0 && g->slot[i].gen >= min_gen)
            return (int)i;
    }
    return -1;
}

static void fill_cap(ArgusEvent *e, Gen *g, int i, uint64_t gen)
{
    e->cap_id = (uint32_t)i + 1u;
    e->cap_generation = gen;
    e->principal = g->slot[i].subject;
    e->resource = g->slot[i].resource;
}

/* ---- legal operations ---- */

static void gop_grant(Gen *g)
{
    uint32_t start = rn(g, G_SLOTS);
    for (uint32_t k = 0; k < G_SLOTS; k++) {
        uint32_t i = (start + k) % G_SLOTS;
        if (g->slot[i].state == ARGUS_SHADOW_LIVE)
            continue;
        ArgusEvent *e = emit_ev(g, ARGUS_EV_CAPABILITY_GRANTED, ARGUS_OUTCOME_OK, 0);
        if (!e) return;
        g->slot[i].gen += 1;                    /* strictly above the last grant of this slot */
        g->slot[i].state = ARGUS_SHADOW_LIVE;
        g->slot[i].subject = 1u + rn(g, 8);
        g->slot[i].rights = R_READ | (rn(g, 4) ? R_WRITE : 0u) | (rn(g, 2) ? R_EFFECT : 0u);
        g->slot[i].resource = 0x1000u + i;
        fill_cap(e, g, (int)i, g->slot[i].gen);
        e->object_id = g->slot[i].rights;
        attach_ok(g, e);
        return;
    }
}

static void gop_use(Gen *g)
{
    int i = find_slot(g, ARGUS_SHADOW_LIVE, 0, 0, 0);
    if (i < 0) { gop_grant(g); return; }
    ArgusEvent *e = emit_ev(g, ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0);
    if (!e) return;
    fill_cap(e, g, i, g->slot[i].gen);
    if ((g->slot[i].rights & R_EFFECT) && rn(g, 3) == 0)
        e->effect_class = ARGUS_EFFECT_EXTERNAL;
    else if ((g->slot[i].rights & R_WRITE) && rn(g, 4) == 0)
        e->effect_class = ARGUS_EFFECT_EVIDENCE;
    else
        e->effect_class = ARGUS_EFFECT_EPHEMERAL;
    attach_ok(g, e);
}

static void gop_denied(Gen *g)
{
    int i;
    ArgusEvent *e;
    switch (rn(g, 6)) {
    case 0:   /* correct refusal of a revoked reference */
        if ((i = find_slot(g, ARGUS_SHADOW_REVOKED, 0, 0, 1)) >= 0) {
            if (!(e = emit_ev(g, ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_DENIED, C_ERR_REVOKED))) return;
            fill_cap(e, g, i, g->slot[i].gen);
            attach_ok(g, e);
            return;
        }
        break;
    case 1:   /* correct refusal of an old generation */
        if ((i = find_slot(g, ARGUS_SHADOW_LIVE, 0, 0, 2)) >= 0) {
            if (!(e = emit_ev(g, ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_DENIED, C_ERR_STALE_GEN))) return;
            fill_cap(e, g, i, g->slot[i].gen - 1);
            attach_ok(g, e);
            return;
        }
        break;
    case 3:   /* wrong subject refused */
        if ((i = find_slot(g, ARGUS_SHADOW_LIVE, 0, 0, 0)) >= 0) {
            if (!(e = emit_ev(g, ARGUS_EV_CAPABILITY_DENIED, ARGUS_OUTCOME_DENIED, C_ERR_SUBJECT))) return;
            fill_cap(e, g, i, g->slot[i].gen);
            e->principal += 100u;
            attach_ok(g, e);
            return;
        }
        break;
    case 4:   /* bogus (never granted, in range) reference refused by bounds */
        if (!(e = emit_ev(g, ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_DENIED, C_ERR_BOUNDS))) return;
        e->cap_id = G_UNSEEN_CAP + rn(g, ARGUS_CAP_MAX - G_UNSEEN_CAP);
        e->cap_generation = 1;
        e->principal = 1u + rn(g, 8);
        attach_ok(g, e);
        return;
    case 5:   /* quarantined machine tries and is refused */
        if (g->m_trust[G_QM] == ARGUS_TRUST_QUARANTINED && (i = find_slot(g, ARGUS_SHADOW_LIVE, 0, 0, 0)) >= 0) {
            if (!(e = emit_ev(g, ARGUS_EV_CAPABILITY_DENIED, ARGUS_OUTCOME_DENIED, C_ERR_UNAUTHORIZED))) return;
            fill_cap(e, g, i, g->slot[i].gen);
            memcpy(e->machine_id, g->machine[G_QM], ARGUS_MACHINE_ID_LEN);
            return;
        }
        break;
    default:
        break;
    }
    /* rights refused on a live reference */
    if ((i = find_slot(g, ARGUS_SHADOW_LIVE, 0, 0, 0)) < 0) { gop_grant(g); return; }
    if (!(e = emit_ev(g, ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_DENIED, C_ERR_RIGHTS))) return;
    fill_cap(e, g, i, g->slot[i].gen);
    attach_ok(g, e);
}

static void gop_revoke(Gen *g)
{
    int i = find_slot(g, ARGUS_SHADOW_LIVE, 0, 0, 0);
    if (i < 0) { gop_grant(g); return; }
    ArgusEvent *e = emit_ev(g, ARGUS_EV_CAPABILITY_REVOKED, ARGUS_OUTCOME_OK, 0);
    if (!e) return;
    fill_cap(e, g, i, g->slot[i].gen);          /* at the granted generation */
    attach_ok(g, e);
    g->slot[i].state = ARGUS_SHADOW_REVOKED;
}

static void gop_effect(Gen *g)
{
    ArgusEvent *e;
    int i = find_slot(g, ARGUS_SHADOW_LIVE, R_EFFECT, 0, 0);
    if (i >= 0 && rn(g, 3) != 0) {
        if (!(e = emit_ev(g, ARGUS_EV_EXTERNAL_EFFECT_REQUESTED, ARGUS_OUTCOME_OK, 0))) return;
        fill_cap(e, g, i, g->slot[i].gen);
        e->effect_class = ARGUS_EFFECT_EXTERNAL;
        attach_ok(g, e);
        if (!(e = emit_ev(g, ARGUS_EV_EXTERNAL_EFFECT_COMMITTED, ARGUS_OUTCOME_OK, 0))) return;
        fill_cap(e, g, i, g->slot[i].gen);
        e->effect_class = ARGUS_EFFECT_EXTERNAL;
        attach_ok(g, e);
        return;
    }
    /* a reference without the effect right asks and is refused */
    if ((i = find_slot(g, ARGUS_SHADOW_LIVE, 0, R_EFFECT, 0)) < 0) { gop_use(g); return; }
    uint16_t kind = rn(g, 2) ? ARGUS_EV_EXTERNAL_EFFECT_REQUESTED : ARGUS_EV_EXTERNAL_EFFECT_DENIED;
    if (!(e = emit_ev(g, kind, ARGUS_OUTCOME_DENIED, C_ERR_RIGHTS))) return;
    fill_cap(e, g, i, g->slot[i].gen);
    e->effect_class = ARGUS_EFFECT_EXTERNAL;
    attach_ok(g, e);
}

/* World generations advance by exactly one; no repeats (header apply rule). */
static void gop_world(Gen *g)
{
    ArgusEvent *e = emit_ev(g, ARGUS_EV_WORLD_COMMITTED, ARGUS_OUTCOME_OK, 0);
    if (!e) return;
    g->world_gen += 1;
    fresh_digest(g, 0x57, g->world_digest);
    e->world_generation = g->world_gen;
    memcpy(e->evidence_digest, g->world_digest, ARGUS_DIGEST_LEN);
    attach_ok(g, e);
}

static void lease_fill(ArgusEvent *e, Gen *g, uint32_t i)
{
    e->object_id = g->lease[i].id;
    e->principal = g->lease[i].subject;
    e->resource = g->lease[i].scope;
}

/* Lease ids are never reused (ruling A): a slot whose lease was revoked gets a
 * fresh id on its next creation; once G_LEASE_IDS ids are used, revoked slots
 * stay revoked and only see refused uses. */
static void gop_lease(Gen *g)
{
    uint32_t i = rn(g, G_LEASES);
    ArgusEvent *e;
    if (g->lease[i].state != ARGUS_SHADOW_LIVE) {
        int exhausted = g->next_lease_id > G_LEASE_IDS;
        if (g->lease[i].state == ARGUS_SHADOW_REVOKED && (exhausted || rn(g, 2))) {
            /* use of a revoked lease, correctly refused */
            if (!(e = emit_ev(g, ARGUS_EV_CREDENTIAL_LEASE_USED, ARGUS_OUTCOME_DENIED, C_ERR_REVOKED))) return;
            lease_fill(e, g, i);
            attach_ok(g, e);
            return;
        }
        if (exhausted) { gop_use(g); return; }
        if (!(e = emit_ev(g, ARGUS_EV_CREDENTIAL_LEASE_CREATED, ARGUS_OUTCOME_OK, 0))) return;
        g->lease[i].id = g->next_lease_id++;
        g->lease[i].state = ARGUS_SHADOW_LIVE;
        g->lease[i].subject = 1u + rn(g, 8);
        g->lease[i].scope = (rnd(g) & 0xFFFFu) | 0x1u;
        lease_fill(e, g, i);
        attach_ok(g, e);
        return;
    }
    switch (rn(g, 5)) {
    case 0:   /* revoke */
        if (!(e = emit_ev(g, ARGUS_EV_CREDENTIAL_LEASE_REVOKED, ARGUS_OUTCOME_OK, 0))) return;
        e->object_id = g->lease[i].id; e->principal = g->lease[i].subject;
        attach_ok(g, e);
        g->lease[i].state = ARGUS_SHADOW_REVOKED;
        return;
    case 1:   /* out of scope, correctly refused */
        if (!(e = emit_ev(g, ARGUS_EV_CREDENTIAL_LEASE_USED, ARGUS_OUTCOME_DENIED, C_ERR_RIGHTS))) return;
        lease_fill(e, g, i);
        e->resource = g->lease[i].scope | (1ull << 40);
        attach_ok(g, e);
        return;
    default:  /* in scope, by its subject */
        if (!(e = emit_ev(g, ARGUS_EV_CREDENTIAL_LEASE_USED, ARGUS_OUTCOME_OK, 0))) return;
        lease_fill(e, g, i);
        e->resource = g->lease[i].scope & rnd(g);
        attach_ok(g, e);
        return;
    }
}

static void gop_artifact(Gen *g)
{
    ArgusEvent *e;
    uint32_t r = rn(g, 4);
    if ((r == 0 || g->n_art == 0) && g->n_art < G_ARTIFACTS) {
        size_t a = g->n_art++;
        fresh_digest(g, 0xA7, g->artifact[a]);
        int reject = rn(g, 4) == 0;
        if (!(e = emit_ev(g, reject ? ARGUS_EV_ARTIFACT_REJECTED : ARGUS_EV_ARTIFACT_ADMITTED,
                          reject ? ARGUS_OUTCOME_DENIED : ARGUS_OUTCOME_OK, reject ? C_ERR_RIGHTS : 0))) return;
        memcpy(e->evidence_digest, g->artifact[a], ARGUS_DIGEST_LEN);
        attach_ok(g, e);
        g->a_state[a] = reject ? ARGUS_SHADOW_REJECTED : ARGUS_SHADOW_LIVE;
        return;
    }
    if (g->n_art == 0) return;
    size_t a = rn(g, (uint32_t)g->n_art);
    int live = g->a_state[a] == ARGUS_SHADOW_LIVE;
    if (!(e = emit_ev(g, ARGUS_EV_ARTIFACT_ACTIVATED, live ? ARGUS_OUTCOME_OK : ARGUS_OUTCOME_DENIED,
                      live ? 0 : C_ERR_UNAUTHORIZED))) return;
    memcpy(e->evidence_digest, g->artifact[a], ARGUS_DIGEST_LEN);
    attach_ok(g, e);
}

static void gop_provider(Gen *g)
{
    uint32_t p = rn(g, G_PROVIDERS);
    ArgusEvent *e;
    if (g->p_quar[p]) {
        if (!(e = emit_ev(g, ARGUS_EV_PROVIDER_USED, ARGUS_OUTCOME_DENIED, C_ERR_UNAUTHORIZED))) return;
    } else if (rn(g, 8) == 0) {
        if (!(e = emit_ev(g, ARGUS_EV_PROVIDER_CHANGED, ARGUS_OUTCOME_OK, 0))) return;
    } else {
        if (!(e = emit_ev(g, ARGUS_EV_PROVIDER_USED, ARGUS_OUTCOME_OK, 0))) return;
    }
    memcpy(e->evidence_digest, g->provider[p], ARGUS_DIGEST_LEN);
    e->principal = 1u + rn(g, 8);
    attach_ok(g, e);
}

/* Trust only ever moves down (header machine lifecycle). */
static void set_trust(Gen *g, uint32_t m, uint32_t trust)
{
    ArgusEvent *e = emit_ev(g, ARGUS_EV_MACHINE_TRUST_CHANGED, ARGUS_OUTCOME_OK, 0);
    if (!e) return;
    memcpy(e->machine_id, g->machine[m], ARGUS_MACHINE_ID_LEN);
    e->object_id = trust;
    g->m_trust[m] = trust;
}

/* JOINED with object_id 0: the core records OBSERVED (a joiner never declares trust). */
static void join_machine(Gen *g, uint32_t m)
{
    ArgusEvent *e = emit_ev(g, ARGUS_EV_MACHINE_JOINED, ARGUS_OUTCOME_OK, 0);
    if (!e) return;
    memcpy(e->machine_id, g->machine[m], ARGUS_MACHINE_ID_LEN);
    g->m_joined[m] = 1;
    g->m_trust[m] = ARGUS_TRUST_OBSERVED;
}

static void gop_machine(Gen *g)
{
    if (rn(g, 2) == 0) {
        /* M1 steps down: OBSERVED -> REATTESTATION_REQUIRED -> RESTRICTED, then stays */
        if (g->m_trust[G_DOWN] == ARGUS_TRUST_OBSERVED) { set_trust(g, G_DOWN, ARGUS_TRUST_REATTESTATION_REQUIRED); return; }
        if (g->m_trust[G_DOWN] == ARGUS_TRUST_REATTESTATION_REQUIRED) { set_trust(g, G_DOWN, ARGUS_TRUST_RESTRICTED); return; }
    }
    if (g->m_joined[4]) {
        ArgusEvent *e = emit_ev(g, ARGUS_EV_MACHINE_REMOVED, ARGUS_OUTCOME_OK, 0);
        if (!e) return;
        memcpy(e->machine_id, g->machine[4], ARGUS_MACHINE_ID_LEN);
        g->m_joined[4] = 0;                       /* tombstone keeps OBSERVED */
    } else {
        join_machine(g, 4);                       /* re-join after removal is legal */
    }
}

/* Policy / runtime digests are announced once at start of day; later events
 * re-announce the stored digest (a changed digest is a code 5 finding). */
static void gop_misc(Gen *g)
{
    int policy = !g->policy_tampered && rn(g, 2);
    ArgusEvent *e = emit_ev(g, policy ? ARGUS_EV_POLICY_CHANGED : ARGUS_EV_RUNTIME_BUILD_CHANGED, ARGUS_OUTCOME_OK, 0);
    if (!e) return;
    memcpy(e->evidence_digest, policy ? g->policy : g->runtime, ARGUS_DIGEST_LEN);
    attach_ok(g, e);
}

/* ---- hostile injections: each triggers exactly one detector ---- */

static void expect_code(Gen *g, uint64_t seq, uint16_t code)
{
    if (g->n_expect < g->expect_max) {
        g->expect[g->n_expect].sequence = seq;
        g->expect[g->n_expect].code = code;
    }
    g->n_expect++;
}

static int find_lease(Gen *g, int live_only)
{
    uint32_t start = rn(g, G_LEASES);
    for (uint32_t k = 0; k < G_LEASES; k++) {
        uint32_t i = (start + k) % G_LEASES;
        if (g->lease[i].state == ARGUS_SHADOW_LIVE ||
            (!live_only && g->lease[i].state == ARGUS_SHADOW_REVOKED))
            return (int)i;
    }
    return -1;
}

/* Returns 1 if an injection of this type was emitted. */
static int inject(Gen *g, unsigned type)
{
    ArgusEvent *e;
    int i;
    switch (type) {
    case 0:   /* 1: use of a reference ARGUS never saw granted, outcome OK */
        if (!(e = emit_ev(g, ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0))) return 0;
        e->cap_id = G_UNSEEN_CAP + rn(g, ARGUS_CAP_MAX - G_UNSEEN_CAP); e->cap_generation = 1; e->principal = 1u + rn(g, 8);
        attach_ok(g, e);
        expect_code(g, e->sequence, ARGUS_F_FORGED_CAPABILITY);
        return 1;
    case 1:   /* 1: producer reports a forgery attempt (self-report: sync 0) */
        if (!(e = emit_ev(g, ARGUS_EV_FORGED_CAPABILITY, ARGUS_OUTCOME_DENIED, C_ERR_BOUNDS))) return 0;
        e->principal = 1u + rn(g, 8);
        attach_ok(g, e);
        expect_code(g, e->sequence, ARGUS_F_FORGED_CAPABILITY);
        return 1;
    case 2:   /* 2: old generation accepted */
        if ((i = find_slot(g, ARGUS_SHADOW_LIVE, 0, 0, 2)) < 0) return 0;
        if (!(e = emit_ev(g, ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0))) return 0;
        fill_cap(e, g, i, g->slot[i].gen - 1);
        attach_ok(g, e);
        expect_code(g, e->sequence, ARGUS_F_STALE_GENERATION);
        return 1;
    case 3:   /* 3: revoked reference accepted (current generation) */
        if ((i = find_slot(g, ARGUS_SHADOW_REVOKED, 0, 0, 1)) < 0) return 0;
        if (!(e = emit_ev(g, ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0))) return 0;
        fill_cap(e, g, i, g->slot[i].gen);
        attach_ok(g, e);
        expect_code(g, e->sequence, ARGUS_F_REVOKED_CAPABILITY_USED);
        return 1;
    case 4:   /* 4: never-admitted artifact activated */
        if (!(e = emit_ev(g, ARGUS_EV_ARTIFACT_ACTIVATED, ARGUS_OUTCOME_OK, 0))) return 0;
        fresh_digest(g, 0xBD, e->evidence_digest);
        attach_ok(g, e);
        expect_code(g, e->sequence, ARGUS_F_ARTIFACT_DIGEST_UNEXPECTED);
        return 1;
    case 5:   /* 5: signature failure on the trusted path */
        if (!(e = emit_ev(g, ARGUS_EV_SIGNATURE_FAILURE, ARGUS_OUTCOME_DENIED, 0))) return 0;
        fresh_digest(g, 0x5F, e->evidence_digest);
        attach_ok(g, e);
        expect_code(g, e->sequence, ARGUS_F_SIGNATURE_INVALID);
        return 1;
    case 6:   /* 6: lease used by a different subject */
        if ((i = find_lease(g, 1)) < 0) return 0;
        if (!(e = emit_ev(g, ARGUS_EV_CREDENTIAL_LEASE_USED, ARGUS_OUTCOME_OK, 0))) return 0;
        lease_fill(e, g, (uint32_t)i);
        e->principal = g->lease[i].subject + 1000u; e->resource = g->lease[i].scope & 1u;
        attach_ok(g, e);
        expect_code(g, e->sequence, ARGUS_F_CREDENTIAL_SCOPE_VIOLATION);
        return 1;
    case 7:   /* 6: lease used outside its scope */
        if ((i = find_lease(g, 1)) < 0) return 0;
        if (!(e = emit_ev(g, ARGUS_EV_CREDENTIAL_LEASE_USED, ARGUS_OUTCOME_OK, 0))) return 0;
        lease_fill(e, g, (uint32_t)i);
        e->resource = g->lease[i].scope | (1ull << 41);
        attach_ok(g, e);
        expect_code(g, e->sequence, ARGUS_F_CREDENTIAL_SCOPE_VIOLATION);
        return 1;
    case 8:   /* 7: event from a machine that never joined (refused, so only 7 fires) */
        if (!(e = emit_ev(g, ARGUS_EV_CAPABILITY_DENIED, ARGUS_OUTCOME_DENIED, C_ERR_RIGHTS))) return 0;
        e->principal = 1u + rn(g, 8);
        fresh_digest(g, 0xEE, e->machine_id);
        expect_code(g, e->sequence, ARGUS_F_MACHINE_IDENTITY_MISMATCH);
        return 1;
    case 9:   /* 7: joined machine joins again without removal (core: unchanged) */
        if (!(e = emit_ev(g, ARGUS_EV_MACHINE_JOINED, ARGUS_OUTCOME_OK, 0))) return 0;
        memcpy(e->machine_id, g->machine[0], ARGUS_MACHINE_ID_LEN);
        expect_code(g, e->sequence, ARGUS_F_MACHINE_IDENTITY_MISMATCH);
        return 1;
    case 10:  /* 8: external effect committed on a reference without the effect right */
        if ((i = find_slot(g, ARGUS_SHADOW_LIVE, 0, R_EFFECT, 0)) < 0) return 0;
        if (!(e = emit_ev(g, ARGUS_EV_EXTERNAL_EFFECT_COMMITTED, ARGUS_OUTCOME_OK, 0))) return 0;
        fill_cap(e, g, i, g->slot[i].gen);
        e->effect_class = ARGUS_EFFECT_EXTERNAL;
        attach_ok(g, e);
        expect_code(g, e->sequence, ARGUS_F_EFFECT_CLASS_UNAUTHORIZED);
        return 1;
    case 11:  /* 9: World generation skipped; the core does not adopt it, nor does the model */
        if (g->world_gen == 0) return 0;
        if (!(e = emit_ev(g, ARGUS_EV_WORLD_COMMITTED, ARGUS_OUTCOME_OK, 0))) return 0;
        e->world_generation = g->world_gen + 2;
        fresh_digest(g, 0x58, e->evidence_digest);
        attach_ok(g, e);
        expect_code(g, e->sequence, ARGUS_F_WORLD_PROVENANCE_INCONSISTENT);
        return 1;
    case 12:  /* 10: quarantined provider used with outcome OK */
        if (!g->p_quar[G_QP]) return 0;
        if (!(e = emit_ev(g, ARGUS_EV_PROVIDER_USED, ARGUS_OUTCOME_OK, 0))) return 0;
        memcpy(e->evidence_digest, g->provider[G_QP], ARGUS_DIGEST_LEN);
        e->principal = 1u + rn(g, 8);
        attach_ok(g, e);
        expect_code(g, e->sequence, ARGUS_F_QUARANTINED_USE);
        return 1;
    case 13:  /* 10: quarantined machine acts with outcome OK */
        if (g->m_trust[G_QM] != ARGUS_TRUST_QUARANTINED) return 0;
        if ((i = find_slot(g, ARGUS_SHADOW_LIVE, 0, 0, 0)) < 0) return 0;
        if (!(e = emit_ev(g, ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0))) return 0;
        fill_cap(e, g, i, g->slot[i].gen);
        memcpy(e->machine_id, g->machine[G_QM], ARGUS_MACHINE_ID_LEN);
        expect_code(g, e->sequence, ARGUS_F_QUARANTINED_USE);
        return 1;
    case 14:  /* 1: use at a generation above the shadow's (never minted), G-4 */
        if ((i = find_slot(g, ARGUS_SHADOW_LIVE, 0, 0, 0)) < 0) return 0;
        if (!(e = emit_ev(g, ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0))) return 0;
        fill_cap(e, g, i, g->slot[i].gen + 1);
        attach_ok(g, e);
        expect_code(g, e->sequence, ARGUS_F_FORGED_CAPABILITY);
        return 1;
    case 15:  /* 14: live reference used OK by a principal other than its subject, G-3 */
        if ((i = find_slot(g, ARGUS_SHADOW_LIVE, 0, 0, 0)) < 0) return 0;
        if (!(e = emit_ev(g, ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0))) return 0;
        fill_cap(e, g, i, g->slot[i].gen);
        e->principal = g->slot[i].subject + 1000u;
        attach_ok(g, e);
        expect_code(g, e->sequence, ARGUS_F_SUBJECT_MISMATCH);
        return 1;
    case 16: { /* 15: joined machine announces an upward trust move (core ignores it) */
        uint32_t m = g->m_trust[G_QM] == ARGUS_TRUST_QUARANTINED ? G_QM : G_DOWN;
        if (!(e = emit_ev(g, ARGUS_EV_MACHINE_TRUST_CHANGED, ARGUS_OUTCOME_OK, 0))) return 0;
        memcpy(e->machine_id, g->machine[m], ARGUS_MACHINE_ID_LEN);
        e->object_id = ARGUS_TRUST_TRUSTED;
        expect_code(g, e->sequence, ARGUS_F_TRUST_ESCALATION);
        return 1;
    }
    case 17:  /* 15: removed machine re-joins declaring itself TRUSTED (core caps at OBSERVED) */
        if (g->m_joined[4]) return 0;
        if (!(e = emit_ev(g, ARGUS_EV_MACHINE_JOINED, ARGUS_OUTCOME_OK, 0))) return 0;
        memcpy(e->machine_id, g->machine[4], ARGUS_MACHINE_ID_LEN);
        e->object_id = ARGUS_TRUST_TRUSTED;
        g->m_joined[4] = 1;
        g->m_trust[4] = ARGUS_TRUST_OBSERVED;
        expect_code(g, e->sequence, ARGUS_F_TRUST_ESCALATION);
        return 1;
    case 18:  /* 6: CREATED re-uses an existing lease id for another subject, G-26 (not applied) */
        if ((i = find_lease(g, 0)) < 0) return 0;
        if (!(e = emit_ev(g, ARGUS_EV_CREDENTIAL_LEASE_CREATED, ARGUS_OUTCOME_OK, 0))) return 0;
        e->object_id = g->lease[i].id; e->principal = g->lease[i].subject + 1000u; e->resource = UINT64_MAX;
        attach_ok(g, e);
        expect_code(g, e->sequence, ARGUS_F_CREDENTIAL_SCOPE_VIOLATION);
        return 1;
    case 19:  /* 10: provider never discovered used with outcome OK, G-9 */
        if (!(e = emit_ev(g, ARGUS_EV_PROVIDER_USED, ARGUS_OUTCOME_OK, 0))) return 0;
        fresh_digest(g, 0xDF, e->evidence_digest);
        e->principal = 1u + rn(g, 8);
        attach_ok(g, e);
        expect_code(g, e->sequence, ARGUS_F_QUARANTINED_USE);
        return 1;
    case 20:  /* 8: durable EVIDENCE write under a reference without WRITE, G-24 */
        if ((i = find_slot(g, ARGUS_SHADOW_LIVE, 0, R_WRITE, 0)) < 0) return 0;
        if (!(e = emit_ev(g, ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0))) return 0;
        fill_cap(e, g, i, g->slot[i].gen);
        e->effect_class = ARGUS_EFFECT_EVIDENCE;
        attach_ok(g, e);
        expect_code(g, e->sequence, ARGUS_F_EFFECT_CLASS_UNAUTHORIZED);
        return 1;
    case 21:  /* 5: producer reports an integrity violation, G-14 */
        if (!(e = emit_ev(g, ARGUS_EV_INTEGRITY_VIOLATION, ARGUS_OUTCOME_ERROR, 0))) return 0;
        fresh_digest(g, 0x60, e->evidence_digest);
        attach_ok(g, e);
        expect_code(g, e->sequence, ARGUS_F_SIGNATURE_INVALID);
        return 1;
    case 22:  /* 5: stored policy digest replaced, G-14; once per stream, no policy events after */
        if (g->policy_tampered) return 0;
        if (!(e = emit_ev(g, ARGUS_EV_POLICY_CHANGED, ARGUS_OUTCOME_OK, 0))) return 0;
        fresh_digest(g, 0x9D, e->evidence_digest);
        attach_ok(g, e);
        g->policy_tampered = 1;
        expect_code(g, e->sequence, ARGUS_F_SIGNATURE_INVALID);
        return 1;
    case 23:  /* 7: TRUST_CHANGED for a machine that never joined (core creates no entry), G-10 */
        if (!(e = emit_ev(g, ARGUS_EV_MACHINE_TRUST_CHANGED, ARGUS_OUTCOME_OK, 0))) return 0;
        fresh_digest(g, 0xEF, e->machine_id);
        e->object_id = ARGUS_TRUST_RESTRICTED;
        expect_code(g, e->sequence, ARGUS_F_MACHINE_IDENTITY_MISMATCH);
        return 1;
    default:
        return 0;
    }
}
#define G_INJECT_TYPES 24u

static void maybe_inject(Gen *g)
{
    if (!g->hostile || g->n < g->next_inject)
        return;
    g->next_inject += ARGUS_CORPUS_HOSTILE_EVERY;
    for (unsigned k = 0; k < G_INJECT_TYPES; k++) {
        unsigned t = (g->inject_type + k) % G_INJECT_TYPES;
        if (inject(g, t)) {
            g->inject_type = t + 1;
            return;
        }
    }
}

static size_t generate(Gen *g, uint64_t seed)
{
    g->rng = seed ^ 0xA5A5A5A55A5A5A5Aull;
    g->next_lease_id = 1;
    for (uint32_t m = 0; m < G_MACHINES; m++)
        fresh_digest(g, (uint8_t)(0xC0 + m), g->machine[m]);
    for (uint32_t p = 0; p < G_PROVIDERS; p++)
        fresh_digest(g, (uint8_t)(0xD0 + p), g->provider[p]);
    fresh_digest(g, 0x9C, g->policy);
    fresh_digest(g, 0x9B, g->runtime);

    /* start of day: machines join, providers are discovered, policy and
     * runtime announced, first World */
    for (uint32_t m = 0; m < G_MACHINES; m++)
        join_machine(g, m);
    for (uint32_t p = 0; p < G_PROVIDERS; p++) {
        ArgusEvent *e = emit_ev(g, ARGUS_EV_PROVIDER_DISCOVERED, ARGUS_OUTCOME_OK, 0);
        if (!e) break;
        memcpy(e->evidence_digest, g->provider[p], ARGUS_DIGEST_LEN);
        attach_ok(g, e);
    }
    for (int k = 0; k < 2; k++) {
        ArgusEvent *e = emit_ev(g, k ? ARGUS_EV_RUNTIME_BUILD_CHANGED : ARGUS_EV_POLICY_CHANGED, ARGUS_OUTCOME_OK, 0);
        if (!e) break;
        memcpy(e->evidence_digest, k ? g->runtime : g->policy, ARGUS_DIGEST_LEN);
        attach_ok(g, e);
    }
    gop_world(g);
    g->next_inject = g->n + ARGUS_CORPUS_HOSTILE_EVERY / 2;

    while (g->n < g->max) {
        maybe_inject(g);
        if (!g->m3_quarantined_done && g->n >= g->max * 2 / 5) {
            g->m3_quarantined_done = 1;
            set_trust(g, G_QM, ARGUS_TRUST_QUARANTINED);
            continue;
        }
        if (!g->p2_quarantined_done && g->n >= g->max / 2) {
            g->p2_quarantined_done = 1;
            ArgusEvent *e = emit_ev(g, ARGUS_EV_PROVIDER_QUARANTINED, ARGUS_OUTCOME_OK, 0);
            if (e) {
                memcpy(e->evidence_digest, g->provider[G_QP], ARGUS_DIGEST_LEN);
                attach_ok(g, e);
                g->p_quar[G_QP] = 1;
            }
            continue;
        }
        uint32_t r = rn(g, 100);
        if (r < 15) gop_grant(g);
        else if (r < 40) gop_use(g);
        else if (r < 50) gop_denied(g);
        else if (r < 55) gop_revoke(g);
        else if (r < 62) gop_effect(g);
        else if (r < 67) gop_world(g);
        else if (r < 76) gop_lease(g);
        else if (r < 84) gop_artifact(g);
        else if (r < 91) gop_provider(g);
        else if (r < 96) gop_machine(g);
        else gop_misc(g);
    }
    return g->n;
}

size_t argus_corpus_benign(ArgusEvent *out, size_t max, uint64_t seed)
{
    static Gen g;   /* test-only helper; not reentrant */
    if (out == NULL || max == 0)
        return 0;
    memset(&g, 0, sizeof g);
    g.out = out;
    g.max = max;
    return generate(&g, seed);
}

size_t argus_corpus_hostile(ArgusEvent *out, size_t max, uint64_t seed,
                            ArgusExpectedFinding *expect, size_t expect_max, size_t *n_expect)
{
    static Gen g;   /* test-only helper; not reentrant */
    if (n_expect) *n_expect = 0;
    if (out == NULL || max == 0 || n_expect == NULL || (expect == NULL && expect_max != 0))
        return 0;
    memset(&g, 0, sizeof g);
    g.out = out;
    g.max = max;
    g.hostile = 1;
    g.expect = expect;
    g.expect_max = expect_max;
    size_t n = generate(&g, seed);
    *n_expect = g.n_expect;
    return n;
}
