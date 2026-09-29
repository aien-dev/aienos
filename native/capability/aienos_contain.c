/*
 * aienos_contain.c -- AEGIS containment gate (ARGUS-1 lane G).
 * See aienos_contain.h and native/argus/docs/ARGUS1_SPEC.md section 5.
 *
 * Authority calls made here, and only here: aienos_cap_mint (once, in
 * aienos_contain_create), aienos_cap_revoke (in execute, with the executor),
 * aienos_cap_inspect, aienos_cap_office, aienos_cap_clock,
 * aienos_cap_authorize. Nothing else from the authority is referenced (I3.a).
 */
#include "aienos_contain.h"

#include <pthread.h>
#include <stdbool.h>
#include <string.h>

/* ---- SHA-256 (FIPS 180-4), self-contained so the gate never links libargus ---- */

static const uint32_t K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha_block(uint32_t h[8], const uint8_t *p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 |
               (uint32_t)p[4 * i + 2] << 8 | (uint32_t)p[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = k + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        k = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += k;
}

void aienos_contain_sha256(const uint8_t *data, size_t len, uint8_t out[AIENOS_CONTAIN_DIGEST_LEN]) {
    uint32_t h[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                     0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    size_t full = len / 64;
    for (size_t i = 0; i < full; i++) sha_block(h, data + 64 * i);
    uint8_t tail[128];
    size_t rem = len - 64 * full;
    memset(tail, 0, sizeof tail);
    if (rem) memcpy(tail, data + 64 * full, rem);
    tail[rem] = 0x80;
    size_t tl = rem + 1 + 8 <= 64 ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8u;
    for (int i = 0; i < 8; i++) tail[tl - 1 - i] = (uint8_t)(bits >> (8 * i));
    sha_block(h, tail);
    if (tl == 128) sha_block(h, tail + 64);
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(h[i] >> 24);
        out[4 * i + 1] = (uint8_t)(h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(h[i] >> 8);
        out[4 * i + 3] = (uint8_t)h[i];
    }
}

/* ---- Canonical request encoding (spec 2) ---- */

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static void put64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t get32(const uint8_t *p) {
    uint32_t v = 0;
    for (int i = 3; i >= 0; i--) v = v << 8 | p[i];
    return v;
}
static uint64_t get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = v << 8 | p[i];
    return v;
}

void aienos_contain_request_encode(const AienosContainRequest *r,
                                   uint8_t out[AIENOS_CONTAIN_REQUEST_SIZE]) {
    put64(out + 0, r->incident_id);
    out[8] = r->containment;
    out[9] = r->severity;
    put16(out + 10, r->finding_code);
    put32(out + 12, r->principal);
    put32(out + 16, r->target.cap_id);
    put64(out + 20, r->target.generation);
    memcpy(out + 28, r->machine_id, AIENOS_CONTAIN_MACHINE_ID_LEN);
    memcpy(out + 60, r->finding_digest, AIENOS_CONTAIN_DIGEST_LEN);
    put64(out + 92, r->request_id);
    put64(out + 100, r->finding_sequence);
    put32(out + 108, r->target_object);
    put32(out + 112, r->target_rights);
    memcpy(out + 116, r->target_digest, AIENOS_CONTAIN_DIGEST_LEN);
    put16(out + 148, r->flags);
    out[150] = r->version;
    out[151] = r->reserved;
}

static bool request_well_formed(const AienosContainRequest *r) {
    return r->containment >= 1 && r->containment <= AIENOS_CONTAIN_TYPE_MAX &&
           r->severity >= 1 && r->severity <= 5 &&
           r->version == AIENOS_CONTAIN_REQUEST_VERSION && r->reserved == 0 &&
           (r->flags & ~AIENOS_CREQ_KNOWN) == 0 && r->request_id != 0 &&
           r->finding_sequence != 0;
}

int aienos_contain_request_decode(const uint8_t in[AIENOS_CONTAIN_REQUEST_SIZE],
                                  AienosContainRequest *out) {
    if (!in || !out) return AIENOS_CONTAIN_ERR_ARG;
    AienosContainRequest r;
    memset(&r, 0, sizeof r);
    r.incident_id = get64(in + 0);
    r.containment = in[8];
    r.severity = in[9];
    r.finding_code = get16(in + 10);
    r.principal = get32(in + 12);
    r.target.cap_id = get32(in + 16);
    r.target.generation = get64(in + 20);
    memcpy(r.machine_id, in + 28, AIENOS_CONTAIN_MACHINE_ID_LEN);
    memcpy(r.finding_digest, in + 60, AIENOS_CONTAIN_DIGEST_LEN);
    r.request_id = get64(in + 92);
    r.finding_sequence = get64(in + 100);
    r.target_object = get32(in + 108);
    r.target_rights = get32(in + 112);
    memcpy(r.target_digest, in + 116, AIENOS_CONTAIN_DIGEST_LEN);
    r.flags = get16(in + 148);
    r.version = in[150];
    r.reserved = in[151];
    *out = r;
    return request_well_formed(&r) ? AIENOS_CONTAIN_OK : AIENOS_CONTAIN_ERR_ARG;
}

void aienos_contain_request_digest(const AienosContainRequest *r,
                                   uint8_t out[AIENOS_CONTAIN_DIGEST_LEN]) {
    uint8_t b[AIENOS_CONTAIN_REQUEST_SIZE];
    aienos_contain_request_encode(r, b);
    aienos_contain_sha256(b, sizeof b, out);
}

/* ---- Gate state ---- */

/* Lineage shadow of one authority slot, fed only by observer announcements. */
typedef struct {
    uint64_t generation;
    uint64_t parent_generation;
    uint32_t subject;
    uint32_t rights;
    uint32_t parent_id;
    uint8_t state;   /* AIENOS_CAP_STATE_* */
    uint8_t known;   /* 1: every change to this slot since the gate existed was seen */
    uint8_t pad[2];
} Lin;

enum { D_FREE = 0, D_GRANTED, D_DENIED, D_ESCALATED, D_EXECUTED };

typedef struct {
    AienosContainRequest req;
    uint8_t digest[AIENOS_CONTAIN_DIGEST_LEN];
    uint64_t decision_id;
    uint8_t state;
    uint8_t human;
    uint8_t pad[6];
} Dec;

struct AienosContain {
    pthread_mutex_t lock;
    AienosCapAdmin *admin;
    const AienosCapView *view;
    AienosCapRef office;
    AienosCapRef executor;
    AienosContainAuthorizer authz;
    AienosContainSink sink;
    void *sink_ctx;
    AienosContainSeams seams;
    uint32_t seams_on;
    uint64_t seq;
    uint64_t last_decision_id;
    uint64_t last_request_id;
    uint64_t window;
    uint32_t window_grants;
    uint8_t inert;           /* I1.b: scope exceeded; sticky */
    uint8_t lineage_trusted; /* saw the executor's own MINT; cleared by EPOCH/KILL/RESTART/unknown */
    uint8_t executor_dead;
    uint8_t counting;
    uint32_t revokes_seen;
    uint8_t target_seen;
    AienosCapRef exec_target;
    Lin lin[AIENOS_CAP_MAX];
    Dec dec[AIENOS_CONTAIN_DECISIONS];
};

_Static_assert(sizeof(struct AienosContain) <= 24u * 1024u, "gate footprint over 24 KiB (G7)");

size_t aienos_contain_footprint(void) { return sizeof(struct AienosContain); }

/* Authorities that already have a gate: (admin handle, office generation).
 * The office generation is unique per authority instance in a process. */
typedef struct {
    const AienosCapAdmin *admin;
    uint64_t office_generation;
} RegEntry;
static pthread_mutex_t reg_lock = PTHREAD_MUTEX_INITIALIZER;
static RegEntry reg[AIENOS_CONTAIN_REGISTRY];
static uint32_t reg_n;

static int reg_claim(const AienosCapAdmin *admin, uint64_t gen) {
    int rc = AIENOS_CONTAIN_OK;
    pthread_mutex_lock(&reg_lock);
    for (uint32_t i = 0; i < reg_n; i++)
        if (reg[i].admin == admin && reg[i].office_generation == gen) rc = AIENOS_CONTAIN_ERR_EXISTS;
    if (rc == AIENOS_CONTAIN_OK) {
        if (reg_n >= AIENOS_CONTAIN_REGISTRY) rc = AIENOS_CONTAIN_ERR_FULL;
        else reg[reg_n++] = (RegEntry){admin, gen};
    }
    pthread_mutex_unlock(&reg_lock);
    return rc;
}

static void reg_release(const AienosCapAdmin *admin, uint64_t gen) {
    pthread_mutex_lock(&reg_lock);
    for (uint32_t i = 0; i < reg_n; i++)
        if (reg[i].admin == admin && reg[i].office_generation == gen) {
            reg[i] = reg[--reg_n];
            break;
        }
    pthread_mutex_unlock(&reg_lock);
}

/* ---- Table policy ---- */

int aienos_contain_table_decide(void *ctx, const AienosContainRequest *r,
                                const AienosCapView *view, uint32_t *verdict, uint32_t *why) {
    (void)view;
    const AienosContainTablePolicy *t = ctx;
    uint32_t v = AIENOS_CONTAIN_ESCALATE;
    if (t && r && r->containment >= 1 && r->containment <= AIENOS_CONTAIN_TYPE_MAX)
        v = t->verdict[r->containment];
    *verdict = v;
    *why = v == AIENOS_CONTAIN_GRANT  ? AIENOS_CONTAIN_WHY_POLICY_GRANT
           : v == AIENOS_CONTAIN_DENY ? AIENOS_CONTAIN_WHY_POLICY_DENY
                                      : AIENOS_CONTAIN_WHY_POLICY_ESCALATE;
    return 0;
}

/* ---- Helpers (gate lock held) ---- */

static bool is_protected_subject(uint32_t s) {
    return s == AIENOS_CONTAIN_SUBJ || s == AIENOS_CONTAIN_SUBJ_AEGIS ||
           s == AIENOS_CONTAIN_SUBJ_AEGIS_ROOT;
}

static bool subject_privileged(const AienosContain *g, uint32_t subject) {
    for (uint32_t i = 0; i < AIENOS_CAP_MAX; i++) {
        const Lin *l = &g->lin[i];
        if (l->state == AIENOS_CAP_STATE_LIVE && l->subject == subject &&
            (l->rights & AIENOS_CAP_RIGHT_PRIVILEGED))
            return true;
    }
    return false;
}

static bool has_live_child(const AienosContain *g, uint32_t id, uint64_t gen) {
    for (uint32_t i = 0; i < AIENOS_CAP_MAX; i++) {
        const Lin *l = &g->lin[i];
        if (l->state == AIENOS_CAP_STATE_LIVE && l->parent_id == id && l->parent_generation == gen)
            return true;
    }
    return false;
}

/* Layer 2: protected targets (I5.b), whatever the policy says. */
static bool is_protected(const AienosContain *g, const AienosContainRequest *r) {
    if (g->seams_on && (g->seams.flags & AIENOS_CONTAIN_SEAM_NO_PROTECTED)) return false;
    if (is_protected_subject(r->principal)) return true;
    if (r->principal != 0 && subject_privileged(g, r->principal)) return true;
    uint32_t id = r->target.cap_id;
    if (id == AIENOS_CONTAIN_CAP_NONE) return false;
    if (id == 0 || id == g->executor.cap_id || id == g->office.cap_id) return true;
    AienosCapEntry e;
    if (aienos_cap_inspect(g->view, r->target, &e) == AIENOS_CAP_OK) {
        if (e.rights & AIENOS_CAP_RIGHT_PRIVILEGED) return true;
        if (is_protected_subject(e.subject) || subject_privileged(g, e.subject)) return true;
    }
    if (id < AIENOS_CAP_MAX) {
        const Lin *l = &g->lin[id];
        if (l->generation == r->target.generation && (l->rights & AIENOS_CAP_RIGHT_PRIVILEGED))
            return true;
    }
    return false;
}

static bool executor_live(AienosContain *g) {
    if (g->executor_dead) return false;
    AienosCapEntry e;
    if (aienos_cap_inspect(g->view, g->executor, &e) != AIENOS_CAP_OK ||
        e.state != AIENOS_CAP_STATE_LIVE || e.rights != AIENOS_CAP_RIGHT_REVOKE ||
        e.subject != AIENOS_CONTAIN_SUBJ) {
        g->executor_dead = 1;
        return false;
    }
    return true;
}

/* The I1.a target conditions that the authority can answer plus the
 * lineage: 0 if eligible, else the WHY and *status_escalate for "ask". */
static uint16_t revoke_target_check(AienosContain *g, const AienosContainRequest *r, bool *ask) {
    *ask = false;
    AienosCapEntry e;
    if (aienos_cap_inspect(g->view, r->target, &e) != AIENOS_CAP_OK ||
        e.state != AIENOS_CAP_STATE_LIVE)
        return AIENOS_CONTAIN_WHY_TARGET_NOT_LIVE;
    if (r->principal != 0 && e.subject != r->principal) return AIENOS_CONTAIN_WHY_SUBJECT_MISMATCH;
    const Lin *l = &g->lin[r->target.cap_id];
    if (!l->known || l->generation != r->target.generation || l->state != AIENOS_CAP_STATE_LIVE) {
        *ask = true;
        return AIENOS_CONTAIN_WHY_LINEAGE_UNTRUSTED;
    }
    if (has_live_child(g, r->target.cap_id, r->target.generation)) {
        *ask = true;
        return AIENOS_CONTAIN_WHY_NOT_LEAF;
    }
    return 0;
}

static void receipt_base(AienosContain *g, AienosContainReceipt *o, const AienosContainRequest *r,
                         const uint8_t *digest, uint8_t kind) {
    memset(o, 0, sizeof *o);
    o->seq = ++g->seq;
    o->kind = kind;
    o->actor = AIENOS_CONTAIN_ACTOR_GATE;
    o->executor.cap_id = g->executor.cap_id; /* field by field: padding stays zero */
    o->executor.generation = g->executor.generation;
    o->tick = aienos_cap_clock(g->view);
    if (r) {
        o->request_id = r->request_id;
        o->finding_sequence = r->finding_sequence;
        o->target.cap_id = r->target.cap_id;
        o->target.generation = r->target.generation;
        o->principal = r->principal;
        o->finding_code = r->finding_code;
        o->flags = r->flags;
        o->type = r->containment;
    }
    if (digest) memcpy(o->request_digest, digest, AIENOS_CONTAIN_DIGEST_LEN);
    if (g->seams_on) o->gate_flags |= AIENOS_CONTAIN_RF_SEAM;
}

static void emit(AienosContain *g, const AienosContainReceipt *o) {
    /* Called with the lock released. */
    AienosContainSink fn;
    void *ctx;
    pthread_mutex_lock(&g->lock);
    fn = g->sink;
    ctx = g->sink_ctx;
    pthread_mutex_unlock(&g->lock);
    if (fn) fn(ctx, o);
}

static Dec *dec_find(AienosContain *g, uint64_t id) {
    if (id == 0) return NULL;
    for (uint32_t i = 0; i < AIENOS_CONTAIN_DECISIONS; i++)
        if (g->dec[i].state != D_FREE && g->dec[i].decision_id == id) return &g->dec[i];
    return NULL;
}

static Dec *dec_slot(AienosContain *g) {
    Dec *best = &g->dec[0];
    for (uint32_t i = 0; i < AIENOS_CONTAIN_DECISIONS; i++) {
        if (g->dec[i].state == D_FREE) return &g->dec[i];
        if (g->dec[i].decision_id < best->decision_id) best = &g->dec[i];
    }
    return best; /* oldest decision is forgotten: it can no longer be resolved or executed */
}

/* ---- Create / destroy ---- */

int aienos_contain_create(AienosContain **gp, void *mem, size_t bytes, AienosCapAdmin *admin,
                          const AienosCapView *view, AienosCapRef office,
                          const AienosContainAuthorizer *authz) {
    if (!gp || !mem || !admin || !view || !authz || !authz->decide) return AIENOS_CONTAIN_ERR_ARG;
    if (bytes < sizeof(struct AienosContain)) return AIENOS_CONTAIN_ERR_SPACE;
    if ((uintptr_t)mem % _Alignof(struct AienosContain) != 0) return AIENOS_CONTAIN_ERR_ARG;
    AienosCapRef cur;
    if (aienos_cap_office(admin, &cur) != AIENOS_CAP_OK || cur.cap_id != office.cap_id ||
        cur.generation != office.generation)
        return AIENOS_CONTAIN_ERR_ARG;
    AienosCapEntry oe;
    if (aienos_cap_inspect(view, office, &oe) != AIENOS_CAP_OK ||
        oe.state != AIENOS_CAP_STATE_LIVE || !(oe.rights & AIENOS_CAP_RIGHT_MINT))
        return AIENOS_CONTAIN_ERR_ARG;
    int rc = reg_claim(admin, office.generation);
    if (rc != AIENOS_CONTAIN_OK) return rc;

    AienosContain *g = mem;
    memset(g, 0, sizeof *g);
    if (pthread_mutex_init(&g->lock, NULL) != 0) {
        reg_release(admin, office.generation);
        return AIENOS_CONTAIN_ERR_ARG;
    }
    g->admin = admin;
    g->view = view;
    g->office = office;
    g->executor = (AienosCapRef){AIENOS_CONTAIN_CAP_NONE, 0};
    g->authz = *authz;
    for (uint32_t i = 0; i < AIENOS_CAP_MAX; i++) g->lin[i].parent_id = AIENOS_CAP_PARENT_NONE;
    Lin *ol = &g->lin[office.cap_id];
    *ol = (Lin){oe.generation, oe.parent_generation, oe.subject, oe.rights, oe.parent_id,
                (uint8_t)oe.state, 1, {0, 0}};
    *gp = g; /* before the mint: an observer routed through *gp sees it */

    /* The only mint (I5.a): REVOKE only, subject AIENOS_CONTAIN_SUBJ, no parent, no lease. */
    AienosCapMint m = {oe.subject, AIENOS_CONTAIN_SUBJ, AIENOS_CAP_RES_AUTHORITY,
                       AIENOS_CAP_RIGHT_REVOKE, 0, {AIENOS_CAP_PARENT_NONE, 0}, office};
    AienosCapRef ex;
    if (aienos_cap_mint(admin, &m, &ex) != AIENOS_CAP_OK) {
        *gp = NULL;
        pthread_mutex_destroy(&g->lock);
        memset(g, 0, sizeof *g);
        reg_release(admin, office.generation);
        return AIENOS_CONTAIN_ERR_AUTHORITY;
    }
    pthread_mutex_lock(&g->lock);
    g->executor = ex;
    const Lin *xl = &g->lin[ex.cap_id];
    g->lineage_trusted = (uint8_t)(xl->known && xl->generation == ex.generation &&
                                   xl->state == AIENOS_CAP_STATE_LIVE &&
                                   xl->subject == AIENOS_CONTAIN_SUBJ);
    pthread_mutex_unlock(&g->lock);
    return AIENOS_CONTAIN_OK;
}

void aienos_contain_destroy(AienosContain *g) {
    if (!g) return;
    if (g->admin) reg_release(g->admin, g->office.generation);
    pthread_mutex_destroy(&g->lock);
    memset(g, 0, sizeof *g);
}

int aienos_contain_set_sink(AienosContain *g, AienosContainSink fn, void *ctx) {
    if (!g) return AIENOS_CONTAIN_ERR_ARG;
    pthread_mutex_lock(&g->lock);
    g->sink = fn;
    g->sink_ctx = fn ? ctx : NULL;
    pthread_mutex_unlock(&g->lock);
    return AIENOS_CONTAIN_OK;
}

int aienos_contain_executor(const AienosContain *g, AienosCapRef *out) {
    if (!g || !out) return AIENOS_CONTAIN_ERR_ARG;
    *out = g->executor;
    return AIENOS_CONTAIN_OK;
}

int aienos_contain_inert(const AienosContain *g) { return g ? g->inert : 1; }

int aienos_contain_set_seams(AienosContain *g, const AienosContainSeams *s, AienosCapAdmin *admin,
                             AienosCapRef office) {
    if (!g || admin != g->admin) return AIENOS_CONTAIN_ERR_REFUSED;
    AienosCapEntry e;
    if (aienos_cap_inspect(g->view, office, &e) != AIENOS_CAP_OK ||
        e.state != AIENOS_CAP_STATE_LIVE || !(e.rights & AIENOS_CAP_RIGHT_MINT))
        return AIENOS_CONTAIN_ERR_REFUSED;
    pthread_mutex_lock(&g->lock);
    if (s) {
        g->seams = *s;
        g->seams_on = 1;
    } else {
        memset(&g->seams, 0, sizeof g->seams);
        g->seams_on = 0;
    }
    pthread_mutex_unlock(&g->lock);
    return AIENOS_CONTAIN_OK;
}

/* ---- Lineage feed ---- */

void aienos_contain_lineage_observe(AienosContain *g, uint32_t op, const AienosCapEntry *e,
                                    int result) {
    if (!g) return;
    pthread_mutex_lock(&g->lock);
    if (g->counting && op == AIENOS_CAP_OBS_REVOKE && e) {
        g->revokes_seen++;
        if (e->cap_id == g->exec_target.cap_id && e->generation == g->exec_target.generation)
            g->target_seen = 1;
    }
    if (!e) {
        /* A refused operation changes nothing; a kill ends trust. */
        if (op == AIENOS_CAP_OBS_KILL) g->lineage_trusted = 0;
        else if (result == AIENOS_CAP_OK) g->lineage_trusted = 0; /* unexpected shape */
        pthread_mutex_unlock(&g->lock);
        return;
    }
    if (e->cap_id >= AIENOS_CAP_MAX) {
        g->lineage_trusted = 0;
        pthread_mutex_unlock(&g->lock);
        return;
    }
    Lin *l = &g->lin[e->cap_id];
    switch (op) {
    case AIENOS_CAP_OBS_MINT:
        *l = (Lin){e->generation, e->parent_generation, e->subject, e->rights, e->parent_id,
                   (uint8_t)e->state, 1, {0, 0}};
        break;
    case AIENOS_CAP_OBS_REVOKE: {
        uint8_t known = (uint8_t)(l->known && l->generation == e->generation);
        *l = (Lin){e->generation, e->parent_generation, e->subject, e->rights, e->parent_id,
                   (uint8_t)e->state, known, {0, 0}};
        if (e->cap_id == g->executor.cap_id && e->generation == g->executor.generation)
            g->executor_dead = 1;
        break;
    }
    case AIENOS_CAP_OBS_RECLAIM:
        /* Free slot on its next generation: the next mint here will be seen. */
        *l = (Lin){e->generation, 0, 0, 0, AIENOS_CAP_PARENT_NONE, (uint8_t)e->state, 1, {0, 0}};
        break;
    case AIENOS_CAP_OBS_CLOCK:
        break;
    default: /* EPOCH, RESTART, anything unknown: the shadow can no longer be trusted */
        g->lineage_trusted = 0;
        break;
    }
    pthread_mutex_unlock(&g->lock);
}

/* ---- Decide ---- */

/* Records a decision (lock held) and fills the receipt. */
static void decide_out(AienosContain *g, const AienosContainRequest *r, const uint8_t *digest,
                       uint8_t status, uint16_t why, bool keep, AienosContainReceipt *o) {
    uint64_t id = ++g->last_decision_id;
    uint64_t window = (id - 1) / AIENOS_CONTAIN_BUDGET_WINDOW;
    if (window != g->window) {
        g->window = window;
        g->window_grants = 0;
    }
    if (status == AIENOS_CONTAIN_GRANT && r && r->containment == AIENOS_CONTAIN_REVOKE_CAPABILITY)
        g->window_grants++;
    receipt_base(g, o, r, digest, AIENOS_CONTAIN_KIND_DECIDED);
    o->decision_id = id;
    o->resource = id;
    o->status = status;
    o->why = why;
    if (g->inert) o->gate_flags |= AIENOS_CONTAIN_RF_INERT;
    if (keep && r) {
        Dec *d = dec_slot(g);
        memset(d, 0, sizeof *d);
        d->req = *r;
        memcpy(d->digest, digest, AIENOS_CONTAIN_DIGEST_LEN);
        d->decision_id = id;
        d->state = status == AIENOS_CONTAIN_GRANT      ? D_GRANTED
                   : status == AIENOS_CONTAIN_ESCALATE ? D_ESCALATED
                                                       : D_DENIED;
    }
}

static bool narrow_shape(const AienosContainRequest *r) {
    uint32_t id = r->target.cap_id;
    if (id != AIENOS_CONTAIN_CAP_NONE && id >= AIENOS_CAP_MAX) return false;
    if (r->containment != AIENOS_CONTAIN_RESTRICT_PRINCIPAL && r->target_rights != 0) return false;
    if (r->containment == AIENOS_CONTAIN_RESTRICT_PRINCIPAL &&
        (r->target_rights & ~AIENOS_CAP_RIGHT_KNOWN) != 0)
        return false;
    if (r->containment == AIENOS_CONTAIN_REVOKE_CAPABILITY)
        return id != AIENOS_CONTAIN_CAP_NONE && r->target_object == 0;
    return true;
}

/* Lock held. Returns the verdict and why. */
static void decide_locked(AienosContain *g, const AienosContainRequest *r, uint8_t *status,
                          uint16_t *why) {
    if (is_protected(g, r)) {
        *status = AIENOS_CONTAIN_DENY;
        *why = AIENOS_CONTAIN_WHY_PROTECTED_TARGET;
        return;
    }
    bool live = r->containment == AIENOS_CONTAIN_REVOKE_CAPABILITY;
    if (live) {
        if (g->inert || !g->lineage_trusted) {
            *status = AIENOS_CONTAIN_ESCALATE;
            *why = AIENOS_CONTAIN_WHY_LINEAGE_UNTRUSTED;
            return;
        }
        if (!executor_live(g)) {
            *status = AIENOS_CONTAIN_ESCALATE;
            *why = AIENOS_CONTAIN_WHY_NO_EXECUTOR;
            return;
        }
        bool ask;
        uint16_t w = revoke_target_check(g, r, &ask);
        if (w) {
            *status = ask ? AIENOS_CONTAIN_ESCALATE : AIENOS_CONTAIN_DENY;
            *why = w;
            return;
        }
    }
    uint32_t verdict = AIENOS_CONTAIN_ESCALATE, pwhy = 0;
    if (g->authz.decide(g->authz.ctx, r, g->view, &verdict, &pwhy) != 0)
        verdict = AIENOS_CONTAIN_ESCALATE;
    if (verdict == AIENOS_CONTAIN_DENY) {
        *status = AIENOS_CONTAIN_DENY;
        *why = AIENOS_CONTAIN_WHY_POLICY_DENY;
        return;
    }
    if (verdict != AIENOS_CONTAIN_GRANT) {
        *status = AIENOS_CONTAIN_ESCALATE;
        *why = AIENOS_CONTAIN_WHY_POLICY_ESCALATE;
        return;
    }
    /* Policy said GRANT. Only a LIVE, auto-eligible revoke inside budget is granted. */
    if (!live || (r->flags & (AIENOS_CREQ_SYNTHETIC | AIENOS_CREQ_SATURATION))) {
        *status = AIENOS_CONTAIN_ESCALATE;
        *why = AIENOS_CONTAIN_WHY_NOT_AUTO_ELIGIBLE;
        return;
    }
    uint64_t next_window = g->last_decision_id / AIENOS_CONTAIN_BUDGET_WINDOW;
    uint32_t used = next_window == g->window ? g->window_grants : 0;
    if (used >= AIENOS_CONTAIN_BUDGET) {
        *status = AIENOS_CONTAIN_ESCALATE;
        *why = AIENOS_CONTAIN_WHY_BUDGET;
        return;
    }
    *status = AIENOS_CONTAIN_GRANT;
    *why = AIENOS_CONTAIN_WHY_POLICY_GRANT;
}

static int submit_checked(AienosContain *g, const AienosContainRequest *r, const uint8_t *digest,
                          bool bad, AienosContainDecision *out) {
    AienosContainReceipt o;
    pthread_mutex_lock(&g->lock);
    if (bad || !request_well_formed(r) || !narrow_shape(r)) {
        decide_out(g, r, digest, AIENOS_CONTAIN_DENY, AIENOS_CONTAIN_WHY_BAD_REQUEST, false, &o);
    } else if (r->request_id <= g->last_request_id) {
        decide_out(g, r, digest, AIENOS_CONTAIN_DENY, AIENOS_CONTAIN_WHY_REPLAYED_REQUEST, false, &o);
    } else {
        g->last_request_id = r->request_id;
        uint8_t status;
        uint16_t why;
        decide_locked(g, r, &status, &why);
        decide_out(g, r, digest, status, why, status != AIENOS_CONTAIN_DENY, &o);
    }
    pthread_mutex_unlock(&g->lock);
    if (out) *out = o;
    emit(g, &o);
    return AIENOS_CONTAIN_OK;
}

int aienos_contain_submit(AienosContain *g, const AienosContainRequest *r,
                          const uint8_t request_digest[AIENOS_CONTAIN_DIGEST_LEN],
                          AienosContainDecision *out) {
    if (!g || !r || !request_digest) return AIENOS_CONTAIN_ERR_ARG;
    uint8_t d[AIENOS_CONTAIN_DIGEST_LEN];
    aienos_contain_request_digest(r, d);
    bool bad = memcmp(d, request_digest, sizeof d) != 0; /* tampered after digest */
    return submit_checked(g, r, d, bad, out);
}

int aienos_contain_submit_bytes(AienosContain *g, const uint8_t *bytes, size_t len,
                                AienosContainDecision *out) {
    if (!g || !bytes) return AIENOS_CONTAIN_ERR_ARG;
    uint8_t d[AIENOS_CONTAIN_DIGEST_LEN];
    aienos_contain_sha256(bytes, len, d);
    AienosContainRequest r;
    memset(&r, 0, sizeof r);
    bool bad = len != AIENOS_CONTAIN_REQUEST_SIZE ||
               aienos_contain_request_decode(bytes, &r) != AIENOS_CONTAIN_OK;
    if (len != AIENOS_CONTAIN_REQUEST_SIZE) memset(&r, 0, sizeof r);
    return submit_checked(g, &r, d, bad, out);
}

/* ---- Resolve (the human, office secret) ---- */

int aienos_contain_resolve(AienosContain *g, uint64_t decision_id, int approve,
                           const uint8_t *office_secret, AienosContainDecision *out) {
    if (!g) return AIENOS_CONTAIN_ERR_ARG;
    AienosContainReceipt o;
    int rc = AIENOS_CONTAIN_OK;
    bool secret_ok = office_secret && aienos_cap_authorize(g->admin, office_secret) == AIENOS_CAP_OK;
    pthread_mutex_lock(&g->lock);
    Dec *d = dec_find(g, decision_id);
    receipt_base(g, &o, d ? &d->req : NULL, d ? d->digest : NULL, AIENOS_CONTAIN_KIND_DECIDED);
    o.decision_id = decision_id;
    o.resource = decision_id;
    o.actor = AIENOS_CONTAIN_ACTOR_OFFICE;
    o.gate_flags |= AIENOS_CONTAIN_RF_HUMAN;
    if (!d) {
        o.status = AIENOS_CONTAIN_DENY;
        o.why = AIENOS_CONTAIN_WHY_DECISION_REPLAY;
        o.gate_flags |= AIENOS_CONTAIN_RF_REFUSED_CALL;
        rc = AIENOS_CONTAIN_ERR_UNKNOWN;
    } else if (!secret_ok) {
        o.status = d->state == D_ESCALATED ? AIENOS_CONTAIN_ESCALATE : AIENOS_CONTAIN_DENY;
        o.why = AIENOS_CONTAIN_WHY_BAD_SECRET;
        o.gate_flags |= AIENOS_CONTAIN_RF_REFUSED_CALL;
        rc = AIENOS_CONTAIN_ERR_REFUSED;
    } else if (d->state != D_ESCALATED) {
        o.status = AIENOS_CONTAIN_DENY;
        o.why = AIENOS_CONTAIN_WHY_DECISION_REPLAY;
        o.gate_flags |= AIENOS_CONTAIN_RF_REFUSED_CALL;
        rc = AIENOS_CONTAIN_ERR_REFUSED;
    } else if (approve) {
        d->state = D_GRANTED;
        d->human = 1;
        if (d->req.containment == AIENOS_CONTAIN_REVOKE_CAPABILITY) g->window_grants++;
        o.status = AIENOS_CONTAIN_GRANT;
        o.why = AIENOS_CONTAIN_WHY_HUMAN_GRANT;
    } else {
        d->state = D_DENIED;
        o.status = AIENOS_CONTAIN_DENY;
        o.why = AIENOS_CONTAIN_WHY_HUMAN_DENY;
    }
    pthread_mutex_unlock(&g->lock);
    if (out) *out = o;
    emit(g, &o);
    return rc;
}

/* ---- Execute ---- */

int aienos_contain_execute(AienosContain *g, uint64_t decision_id, AienosContainResult *out) {
    if (!g) return AIENOS_CONTAIN_ERR_ARG;
    AienosContainReceipt o;
    int rc = AIENOS_CONTAIN_OK;
    pthread_mutex_lock(&g->lock);
    Dec *d = dec_find(g, decision_id);
    receipt_base(g, &o, d ? &d->req : NULL, d ? d->digest : NULL, AIENOS_CONTAIN_KIND_EXECUTED);
    o.decision_id = decision_id;
    if (d && d->human) o.gate_flags |= AIENOS_CONTAIN_RF_HUMAN;
    if (!d || d->state != D_GRANTED) {
        /* Unknown, not granted, or already executed: refused and announced. */
        o.status = AIENOS_CONTAIN_FAILED;
        o.why = AIENOS_CONTAIN_WHY_DECISION_REPLAY;
        o.gate_flags |= AIENOS_CONTAIN_RF_REFUSED_CALL;
        rc = d ? AIENOS_CONTAIN_ERR_REFUSED : AIENOS_CONTAIN_ERR_UNKNOWN;
        pthread_mutex_unlock(&g->lock);
        if (out) *out = o;
        emit(g, &o);
        return rc;
    }
    d->state = D_EXECUTED; /* once, whatever happens next */
    AienosContainRequest req = d->req;

    if (req.containment != AIENOS_CONTAIN_REVOKE_CAPABILITY) {
        /* No executor exists for this type (I2, I3.c). */
        uint32_t (*tx)(void *, const AienosContainRequest *) =
            g->seams_on ? g->seams.test_executor : NULL;
        void *tctx = g->seams.test_executor_ctx;
        pthread_mutex_unlock(&g->lock);
        uint32_t st = AIENOS_CONTAIN_UNAVAILABLE;
        if (tx) {
            st = tx(tctx, &req);
            if (st < AIENOS_CONTAIN_DONE || st > AIENOS_CONTAIN_UNAVAILABLE) st = AIENOS_CONTAIN_FAILED;
            o.flags |= AIENOS_CREQ_SYNTHETIC; /* test executor: always labelled (I2) */
        }
        o.status = (uint8_t)st;
        o.why = st == AIENOS_CONTAIN_UNAVAILABLE ? AIENOS_CONTAIN_WHY_NO_EXECUTOR : 0;
        if (out) *out = o;
        emit(g, &o);
        return AIENOS_CONTAIN_OK;
    }

    /* Re-check I1.a immediately before the revoke. */
    uint16_t why = 0;
    uint8_t status = AIENOS_CONTAIN_FAILED;
    bool ask;
    if (g->inert || !g->lineage_trusted) why = AIENOS_CONTAIN_WHY_LINEAGE_UNTRUSTED;
    else if (!executor_live(g)) {
        why = AIENOS_CONTAIN_WHY_NO_EXECUTOR;
        status = AIENOS_CONTAIN_UNAVAILABLE;
    } else if (is_protected(g, &req)) why = AIENOS_CONTAIN_WHY_PROTECTED_TARGET;
    else why = revoke_target_check(g, &req, &ask);
    if (why) {
        o.status = status;
        o.why = why;
        if (g->inert) o.gate_flags |= AIENOS_CONTAIN_RF_INERT;
        pthread_mutex_unlock(&g->lock);
        if (out) *out = o;
        emit(g, &o);
        return AIENOS_CONTAIN_OK;
    }
    void (*hook)(void *) = g->seams_on ? g->seams.pre_revoke : NULL;
    void *hctx = g->seams.pre_revoke_ctx;
    g->counting = 1;
    g->revokes_seen = 0;
    g->target_seen = 0;
    g->exec_target = req.target;
    AienosCapRef ex = g->executor;
    pthread_mutex_unlock(&g->lock);

    if (hook) hook(hctx);
    int arc = aienos_cap_revoke(g->admin, ex, req.target);

    pthread_mutex_lock(&g->lock);
    g->counting = 0;
    uint32_t seen = g->revokes_seen;
    bool target_seen = g->target_seen;
    o.rc = arc;
    o.tick = aienos_cap_clock(g->view);
    if (arc != AIENOS_CAP_OK) {
        o.status = AIENOS_CONTAIN_FAILED;
        o.resource = 1ull << 32; /* one refused, none revoked */
    } else if (seen == 1 && target_seen) {
        o.status = AIENOS_CONTAIN_DONE;
        o.resource = 1;
    } else {
        /* Cascade, or the observer feed is not wired: I1.b cannot be shown. */
        g->inert = 1;
        o.status = AIENOS_CONTAIN_FAILED_SCOPE;
        o.resource = seen;
        o.gate_flags |= AIENOS_CONTAIN_RF_INERT;
    }
    pthread_mutex_unlock(&g->lock);
    if (out) *out = o;
    emit(g, &o);
    return AIENOS_CONTAIN_OK;
}
