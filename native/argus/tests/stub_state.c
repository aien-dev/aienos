/*
 * stub_state.c -- test-only in-memory shadow state + deterministic corpora (lane E).
 *
 * Reference apply rules (stub_state_apply), proposed as the convention for the
 * real core (lane D). Only events with outcome OK change state, except
 * ARTIFACT_REJECTED, which records the rejection at any outcome.
 *   CAPABILITY_GRANTED   cap[cap_id]: generation = max(old, cap_generation),
 *                        state LIVE, subject = principal, rights = object_id,
 *                        resource = resource, granted_sequence = sequence.
 *   CAPABILITY_REVOKED   cap[cap_id] (if seen): state REVOKED, revoked_sequence.
 *                        Generation unchanged; a re-grant carries generation+1.
 *   CREDENTIAL_LEASE_CREATED  lease[object_id]: LIVE, subject = principal,
 *                        scope = resource, sequence.
 *   CREDENTIAL_LEASE_REVOKED  lease[object_id]: REVOKED, sequence.
 *   ARTIFACT_ADMITTED    (code 0 only) artifact[evidence_digest]: LIVE, sequence.
 *   ARTIFACT_REJECTED    artifact[evidence_digest]: REJECTED, sequence.
 *   MACHINE_JOINED       machine[machine_id]: trust = object_id if nonzero else
 *                        TRUSTED, joined_sequence = changed_sequence = sequence.
 *   MACHINE_TRUST_CHANGED machine[machine_id]: trust = object_id, changed_sequence.
 *   MACHINE_REMOVED      machine entry dropped (lookup becomes unseen).
 *   PROVIDER_DISCOVERED  provider[evidence_digest]: LIVE, sequence.
 *   PROVIDER_QUARANTINED provider[evidence_digest]: REVOKED, sequence.
 *   WORLD_COMMITTED      world = {world_generation, evidence_digest, sequence}.
 *   POLICY_CHANGED / RUNTIME_BUILD_CHANGED  expected digest = evidence_digest.
 */
#include "stub_state.h"

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

static void drop_machine(StubState *s, const uint8_t id[ARGUS_MACHINE_ID_LEN])
{
    for (size_t i = 0; i < s->n_machines; i++) {
        if (memcmp(s->machines[i].machine_id, id, ARGUS_MACHINE_ID_LEN) == 0) {
            for (size_t j = i + 1; j < s->n_machines; j++)
                s->machines[j - 1] = s->machines[j];
            s->n_machines--;
            memset(&s->machines[s->n_machines], 0, sizeof s->machines[0]);
            return;
        }
    }
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
        if (op_cap(v, ev->cap_id, &c) != ARGUS_OK) { memset(&c, 0, sizeof c); c.cap_id = ev->cap_id; }
        if (ev->cap_generation > c.generation) c.generation = ev->cap_generation;
        c.state = ARGUS_SHADOW_LIVE;
        c.subject = ev->principal;
        c.rights = (uint32_t)ev->object_id;
        c.resource = ev->resource;
        c.granted_sequence = ev->sequence;
        return stub_put_cap(s, &c);
    }
    case ARGUS_EV_CAPABILITY_REVOKED: {
        ArgusCapShadow c;
        if (op_cap(v, ev->cap_id, &c) != ARGUS_OK) return ARGUS_OK;
        c.state = ARGUS_SHADOW_REVOKED;
        c.revoked_sequence = ev->sequence;
        return stub_put_cap(s, &c);
    }
    case ARGUS_EV_CREDENTIAL_LEASE_CREATED: {
        ArgusLeaseShadow l = {0};
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
        memcpy(a.digest, ev->evidence_digest, ARGUS_DIGEST_LEN);
        a.state = ARGUS_SHADOW_LIVE; a.sequence = ev->sequence;
        return stub_put_artifact(s, &a);
    }
    case ARGUS_EV_MACHINE_JOINED: {
        ArgusMachineShadow m = {0};
        memcpy(m.machine_id, ev->machine_id, ARGUS_MACHINE_ID_LEN);
        m.trust = ev->object_id ? ev->object_id : ARGUS_TRUST_TRUSTED;
        m.joined_sequence = m.changed_sequence = ev->sequence;
        return stub_put_machine(s, &m);
    }
    case ARGUS_EV_MACHINE_TRUST_CHANGED: {
        ArgusMachineShadow m;
        if (op_machine(v, ev->machine_id, &m) != ARGUS_OK) return ARGUS_OK;
        m.trust = ev->object_id; m.changed_sequence = ev->sequence;
        return stub_put_machine(s, &m);
    }
    case ARGUS_EV_MACHINE_REMOVED:
        drop_machine(s, ev->machine_id);
        return ARGUS_OK;
    case ARGUS_EV_PROVIDER_DISCOVERED:
    case ARGUS_EV_PROVIDER_QUARANTINED: {
        ArgusProviderShadow p = {0};
        memcpy(p.provider_id, ev->evidence_digest, ARGUS_DIGEST_LEN);
        p.state = ev->kind == ARGUS_EV_PROVIDER_DISCOVERED ? ARGUS_SHADOW_LIVE : ARGUS_SHADOW_REVOKED;
        p.sequence = ev->sequence;
        return stub_put_provider(s, &p);
    }
    case ARGUS_EV_WORLD_COMMITTED:
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
 * that are legal against it. The hostile variant injects one violation every
 * ARGUS_CORPUS_HOSTILE_EVERY events; each injection is built so exactly one
 * detector fires, and the model follows any state the injection changes
 * (e.g. a World generation skip) so later legal events stay legal.
 * Cap/right/result numbers below mirror native/capability (see argus_detect.h). */

#define G_SLOTS     48
#define G_LEASES    12
#define G_MACHINES   5    /* M0..M3 always joined; M4 cycles join/remove */
#define G_PROVIDERS  4
#define G_ARTIFACTS 96
#define G_QM         3    /* machine quarantined for part of the day */
#define G_QP         2    /* provider quarantined in the second half */

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
    struct { uint32_t state; uint32_t subject; uint64_t scope; } lease[G_LEASES];
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
    uint64_t digest_ctr;
    int      m3_quarantined_done, m3_released_done, p2_quarantined_done;
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
    if (kind >= ARGUS_EV_INTEGRITY_VIOLATION && kind <= ARGUS_EV_FORGED_CAPABILITY)
        e->class_ = ARGUS_CLASS_CRITICAL;
    else if (kind >= ARGUS_EV_WORLD_COMMITTED)
        e->class_ = ARGUS_CLASS_AUDIT;
    else
        e->class_ = ARGUS_CLASS_SECURITY;
    e->kind = kind;
    e->outcome = outcome;
    e->code = code;
    e->flags = ARGUS_FLAG_SYNTHETIC;
    e->sequence = (uint64_t)g->n;   /* 1-based, strictly increasing */
    e->tick = (uint64_t)g->n;
    return e;
}

/* Attribute to a joined, non-quarantined machine (or none, 1 in 5). */
static void attach_ok(Gen *g, ArgusEvent *e)
{
    if (rn(g, 5) == 0)
        return;
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
        g->slot[i].gen += 1;
        g->slot[i].state = ARGUS_SHADOW_LIVE;
        g->slot[i].subject = 1u + rn(g, 8);
        g->slot[i].rights = R_READ | R_WRITE | (rn(g, 2) ? R_EFFECT : 0u);
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
    e->effect_class = (g->slot[i].rights & R_EFFECT) && rn(g, 3) == 0 ? ARGUS_EFFECT_EXTERNAL : ARGUS_EFFECT_EPHEMERAL;
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
    case 4:   /* bogus reference refused by bounds */
        if (!(e = emit_ev(g, ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_DENIED, C_ERR_BOUNDS))) return;
        e->cap_id = 500u + rn(g, 100);
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
    fill_cap(e, g, i, g->slot[i].gen);
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

static void gop_world(Gen *g)
{
    ArgusEvent *e = emit_ev(g, ARGUS_EV_WORLD_COMMITTED, ARGUS_OUTCOME_OK, 0);
    if (!e) return;
    if (g->world_gen != 0 && rn(g, 20) == 0) {
        /* idempotent replay: same generation, same digest */
    } else {
        g->world_gen += 1;
        fresh_digest(g, 0x57, g->world_digest);
    }
    e->world_generation = g->world_gen;
    memcpy(e->evidence_digest, g->world_digest, ARGUS_DIGEST_LEN);
    attach_ok(g, e);
}

static void gop_lease(Gen *g)
{
    uint32_t i = rn(g, G_LEASES);
    ArgusEvent *e;
    if (g->lease[i].state != ARGUS_SHADOW_LIVE) {
        if (g->lease[i].state == ARGUS_SHADOW_REVOKED && rn(g, 2)) {
            /* use of a revoked lease, correctly refused */
            if (!(e = emit_ev(g, ARGUS_EV_CREDENTIAL_LEASE_USED, ARGUS_OUTCOME_DENIED, C_ERR_REVOKED))) return;
            e->object_id = i + 1u; e->principal = g->lease[i].subject; e->resource = g->lease[i].scope;
            attach_ok(g, e);
            return;
        }
        if (!(e = emit_ev(g, ARGUS_EV_CREDENTIAL_LEASE_CREATED, ARGUS_OUTCOME_OK, 0))) return;
        g->lease[i].state = ARGUS_SHADOW_LIVE;
        g->lease[i].subject = 1u + rn(g, 8);
        g->lease[i].scope = (rnd(g) & 0xFFFFu) | 0x1u;
        e->object_id = i + 1u; e->principal = g->lease[i].subject; e->resource = g->lease[i].scope;
        attach_ok(g, e);
        return;
    }
    switch (rn(g, 5)) {
    case 0:   /* revoke */
        if (!(e = emit_ev(g, ARGUS_EV_CREDENTIAL_LEASE_REVOKED, ARGUS_OUTCOME_OK, 0))) return;
        e->object_id = i + 1u; e->principal = g->lease[i].subject;
        attach_ok(g, e);
        g->lease[i].state = ARGUS_SHADOW_REVOKED;
        return;
    case 1:   /* out of scope, correctly refused */
        if (!(e = emit_ev(g, ARGUS_EV_CREDENTIAL_LEASE_USED, ARGUS_OUTCOME_DENIED, C_ERR_RIGHTS))) return;
        e->object_id = i + 1u; e->principal = g->lease[i].subject; e->resource = g->lease[i].scope | (1ull << 40);
        attach_ok(g, e);
        return;
    default:  /* in scope, by its subject */
        if (!(e = emit_ev(g, ARGUS_EV_CREDENTIAL_LEASE_USED, ARGUS_OUTCOME_OK, 0))) return;
        e->object_id = i + 1u; e->principal = g->lease[i].subject; e->resource = g->lease[i].scope & rnd(g);
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

static void set_trust(Gen *g, uint32_t m, uint32_t trust)
{
    ArgusEvent *e = emit_ev(g, ARGUS_EV_MACHINE_TRUST_CHANGED, ARGUS_OUTCOME_OK, 0);
    if (!e) return;
    memcpy(e->machine_id, g->machine[m], ARGUS_MACHINE_ID_LEN);
    e->object_id = trust;
    g->m_trust[m] = trust;
}

static void join_machine(Gen *g, uint32_t m)
{
    ArgusEvent *e = emit_ev(g, ARGUS_EV_MACHINE_JOINED, ARGUS_OUTCOME_OK, 0);
    if (!e) return;
    memcpy(e->machine_id, g->machine[m], ARGUS_MACHINE_ID_LEN);
    g->m_joined[m] = 1;
    g->m_trust[m] = ARGUS_TRUST_TRUSTED;
}

static void gop_machine(Gen *g)
{
    if (rn(g, 2)) {
        if (g->m_joined[4]) {
            ArgusEvent *e = emit_ev(g, ARGUS_EV_MACHINE_REMOVED, ARGUS_OUTCOME_OK, 0);
            if (!e) return;
            memcpy(e->machine_id, g->machine[4], ARGUS_MACHINE_ID_LEN);
            g->m_joined[4] = 0;
        } else {
            join_machine(g, 4);   /* re-join after removal is legal */
        }
    } else {
        set_trust(g, 1, g->m_trust[1] == ARGUS_TRUST_TRUSTED ? ARGUS_TRUST_OBSERVED : ARGUS_TRUST_TRUSTED);
    }
}

static void gop_misc(Gen *g)
{
    ArgusEvent *e = emit_ev(g, rn(g, 2) ? ARGUS_EV_POLICY_CHANGED : ARGUS_EV_RUNTIME_BUILD_CHANGED, ARGUS_OUTCOME_OK, 0);
    if (!e) return;
    fresh_digest(g, 0x9C, e->evidence_digest);
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

/* Returns 1 if an injection of this type was emitted. */
static int inject(Gen *g, unsigned type)
{
    ArgusEvent *e;
    int i;
    uint32_t l;
    switch (type) {
    case 0:   /* 1: use of a reference ARGUS never saw granted, outcome OK */
        if (!(e = emit_ev(g, ARGUS_EV_CAPABILITY_USED, ARGUS_OUTCOME_OK, 0))) return 0;
        e->cap_id = 900u + rn(g, 100); e->cap_generation = 1; e->principal = 1u + rn(g, 8);
        attach_ok(g, e);
        expect_code(g, e->sequence, ARGUS_F_FORGED_CAPABILITY);
        return 1;
    case 1:   /* 1: producer reports a forgery attempt */
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
        for (l = 0; l < G_LEASES && g->lease[l].state != ARGUS_SHADOW_LIVE; l++) {}
        if (l == G_LEASES) return 0;
        if (!(e = emit_ev(g, ARGUS_EV_CREDENTIAL_LEASE_USED, ARGUS_OUTCOME_OK, 0))) return 0;
        e->object_id = l + 1u; e->principal = g->lease[l].subject + 1000u; e->resource = g->lease[l].scope & 1u;
        attach_ok(g, e);
        expect_code(g, e->sequence, ARGUS_F_CREDENTIAL_SCOPE_VIOLATION);
        return 1;
    case 7:   /* 6: lease used outside its scope */
        for (l = 0; l < G_LEASES && g->lease[l].state != ARGUS_SHADOW_LIVE; l++) {}
        if (l == G_LEASES) return 0;
        if (!(e = emit_ev(g, ARGUS_EV_CREDENTIAL_LEASE_USED, ARGUS_OUTCOME_OK, 0))) return 0;
        e->object_id = l + 1u; e->principal = g->lease[l].subject; e->resource = g->lease[l].scope | (1ull << 41);
        attach_ok(g, e);
        expect_code(g, e->sequence, ARGUS_F_CREDENTIAL_SCOPE_VIOLATION);
        return 1;
    case 8:   /* 7: event from a machine that never joined (refused, so only 7 fires) */
        if (!(e = emit_ev(g, ARGUS_EV_CAPABILITY_DENIED, ARGUS_OUTCOME_DENIED, C_ERR_RIGHTS))) return 0;
        e->principal = 1u + rn(g, 8);
        fresh_digest(g, 0xEE, e->machine_id);
        expect_code(g, e->sequence, ARGUS_F_MACHINE_IDENTITY_MISMATCH);
        return 1;
    case 9:   /* 7: joined machine joins again without removal */
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
    case 11:  /* 9: World generation skipped; the model follows the new value */
        if (g->world_gen == 0) return 0;
        if (!(e = emit_ev(g, ARGUS_EV_WORLD_COMMITTED, ARGUS_OUTCOME_OK, 0))) return 0;
        g->world_gen += 2;
        fresh_digest(g, 0x57, g->world_digest);
        e->world_generation = g->world_gen;
        memcpy(e->evidence_digest, g->world_digest, ARGUS_DIGEST_LEN);
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
    default:
        return 0;
    }
}
#define G_INJECT_TYPES 14u

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
    for (uint32_t m = 0; m < G_MACHINES; m++)
        fresh_digest(g, (uint8_t)(0xC0 + m), g->machine[m]);
    for (uint32_t p = 0; p < G_PROVIDERS; p++)
        fresh_digest(g, (uint8_t)(0xD0 + p), g->provider[p]);

    /* start of day: machines join, providers are discovered, first World */
    for (uint32_t m = 0; m < G_MACHINES; m++)
        join_machine(g, m);
    for (uint32_t p = 0; p < G_PROVIDERS; p++) {
        ArgusEvent *e = emit_ev(g, ARGUS_EV_PROVIDER_DISCOVERED, ARGUS_OUTCOME_OK, 0);
        if (!e) break;
        memcpy(e->evidence_digest, g->provider[p], ARGUS_DIGEST_LEN);
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
        if (!g->m3_released_done && g->n >= g->max * 3 / 4) {
            g->m3_released_done = 1;
            set_trust(g, G_QM, ARGUS_TRUST_TRUSTED);
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
