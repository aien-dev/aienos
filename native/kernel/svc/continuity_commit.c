/* continuity_commit.c -- see continuity_commit.h. */
#include <string.h>

#include "continuity_commit.h"
#include "../../store/store_v1.h"

static int map_cc(int rc, const char *why_in, const char **why)
{
    if (rc == CC_OK) return 0;
    if (why) *why = why_in ? why_in : "continuity object";
    if (rc == CC_E_CORRUPT) return CR_CORRUPT;
    if (rc == CC_E_LIMIT) return CR_LIMIT;
    return CR_E_ARG;
}

static int is_zero32(const uint8_t *p)
{
    uint8_t a = 0;
    for (int i = 0; i < 32; i++) a |= p[i];
    return a == 0;
}

/* INV-8: ONE transaction. (MC-8 mutant: the manifest, always last, goes alone.) */
static int do_transact(const struct cr_sink *snk, const struct cr_wobj *o, size_t n, int *store_rc)
{
    int rc;
#ifdef CM_MUTANT_SPLIT_TXN
    if (n > 1) {
        rc = snk->transact(snk->ctx, o, n - 1);
        if (rc == 0) rc = snk->transact(snk->ctx, o + n - 1, 1);
    } else
#endif
        rc = snk->transact(snk->ctx, o, n);
    if (rc != 0) {
        if (store_rc) *store_rc = rc;
        return CR_STORE;
    }
    return 0;
}

static int writable(const struct cr_source *src)
{
#ifdef CM_MUTANT_NO_WRITABLE_CHECK
    (void)src;
    return CR_RESOLVED;
#else
    return cr_writable(src);
#endif
}

static int args_ok(const struct cr_source *src, const struct cr_sink *snk, const struct cr_work *w,
                   const struct cr_txwork *tw, const struct cr_view *out)
{
    return src && snk && snk->transact && w && tw && out;
}

int cr_provision(const struct cr_source *src, const struct cr_sink *snk, struct cr_work *w,
                 struct cr_txwork *tw, struct ck_rng *rng, const uint8_t store_uuid[16],
                 uint8_t source, struct cr_view *out, const char **why, int *store_rc)
{
    if (why) *why = NULL;
    if (store_rc) *store_rc = 0;
    if (!args_ok(src, snk, w, tw, out) || !rng || !store_uuid || !src->generation ||
        (source != CC_SOURCE_OPERATOR && source != CC_SOURCE_QUALIFICATION))
        return CR_E_ARG;
    memset(out, 0, sizeof *out);

    int o = writable(src); /* INV-11: before anything else */
    if (o != CR_RESOLVED) return CR_READ_ONLY;

    /* Provision only from Unprovisioned: a root (also two) is AlreadyProvisioned;
     * orphans, a broken graph or a store error are refused with that outcome. */
    o = cr_resolve(src, w, &tw->tmp, why, store_rc);
#ifdef CM_MUTANT_PROVISION_WITH_ROOT
    if (o == CR_RESOLVED || o == CR_CONFLICT) o = CR_UNPROVISIONED; /* MC-7 */
#endif
    if (o == CR_RESOLVED || o == CR_CONFLICT) return CR_ALREADY_PROVISIONED;
    if (o != CR_UNPROVISIONED) return o;

    uint8_t agent[32];
#ifdef CM_MUTANT_FIXED_AGENT
    memset(agent, 0x42, sizeof agent); /* MC-10 */
    (void)rng;
#else
    if (ck_rng_fill(rng, agent, sizeof agent) != 0) return CR_NO_ENTROPY; /* no fallback */
#endif
    if (is_zero32(agent)) {
        if (why) *why = "zero agent id";
        return CR_CORRUPT;
    }
    uint64_t gen = src->generation(src->ctx);
    if (gen == UINT64_MAX) {
        if (why) *why = "store generation";
        return CR_LIMIT;
    }

    struct cc_root root;
    memset(&root, 0, sizeof root);
    memcpy(root.agent_id, agent, 32);
    memcpy(root.store_uuid, store_uuid, 16);
    cc_root_branch_id(agent, root.root_branch);
    root.provisioned_generation = gen + 1;
    root.source = source;
    uint8_t root_id[32], state_id[32];
    size_t n_root = 0, n_state = 0, n_man = 0;
    const char *y = NULL;
    int rc = cc_root_encode(&root, tw->b[0], sizeof tw->b[0], &n_root, &y);
    if ((o = map_cc(rc, y, why))) return o;
    if (cc_object_id(CC_KIND_AGENT_ROOT, tw->b[0], n_root, root_id) != CC_OK) return CR_E_ARG;
    cc_state_genesis(&tw->state, agent, 1);
    rc = cc_state_encode(&tw->state, tw->b[1], sizeof tw->b[1], &n_state, &y);
    if ((o = map_cc(rc, y, why))) return o;
    if (cc_object_id(CC_KIND_AGENT_STATE, tw->b[1], n_state, state_id) != CC_OK) return CR_E_ARG;

    memset(&tw->man, 0, sizeof tw->man);
    memcpy(tw->man.root, root_id, 32);
    tw->man.sequence = 1;
    tw->man.incarnation = 1;
    memcpy(tw->man.agent_state, state_id, 32);
    rc = cc_manifest_encode(&tw->man, tw->b[2], sizeof tw->b[2], &n_man, &y);
    if ((o = map_cc(rc, y, why))) return o;

    struct cr_wobj objs[3] = {
        {CC_KIND_AGENT_ROOT, CC_STORE_OBJECT_VERSION, tw->b[0], n_root},
        {CC_KIND_AGENT_STATE, CC_STORE_OBJECT_VERSION, tw->b[1], n_state},
        {CC_KIND_MANIFEST, CC_STORE_OBJECT_VERSION, tw->b[2], n_man},
    };
    if ((o = do_transact(snk, objs, 3, store_rc))) return o;
    return cr_resolve(src, w, out, why, store_rc);
}

int cr_commit(const struct cr_source *src, const struct cr_sink *snk, struct cr_work *w,
              struct cr_txwork *tw, const struct cr_view *cur, const struct cr_update *up,
              int new_incarnation, struct cr_view *out, const char **why, int *store_rc)
{
    if (why) *why = NULL;
    if (store_rc) *store_rc = 0;
    if (!args_ok(src, snk, w, tw, out) || !cur || !up || cur == out) return CR_E_ARG;
    if (up->n_rec && !up->rec) return CR_E_ARG;
    memset(out, 0, sizeof *out);

    int o = writable(src);
    if (o != CR_RESOLVED) return CR_READ_ONLY;

    if (cur->manifest.sequence == UINT64_MAX) {
        if (why) *why = "manifest sequence";
        return CR_LIMIT;
    }
    uint64_t seq = cur->manifest.sequence + 1;
    struct cr_wobj objs[3];
    size_t n = 0, lens[3] = {0, 0, 0};
    const char *y = NULL;
    int rc;

    memset(&tw->man, 0, sizeof tw->man);
    memcpy(tw->man.agent_state, cur->manifest.agent_state, 32);
    tw->man.n_wal = cur->manifest.n_wal;
    memcpy(tw->man.wal, cur->manifest.wal, sizeof tw->man.wal);

    if (up->state) {
        if (memcmp(up->state->agent_id, cur->root.agent_id, 32) != 0) {
            if (why) *why = "agent state belongs to another agent";
            return CR_CORRUPT;
        }
        memcpy(&tw->state, up->state, sizeof tw->state);
        tw->state.written_at = seq; /* INV-9 */
        rc = cc_state_encode(&tw->state, tw->b[n], sizeof tw->b[n], &lens[n], &y);
        if ((o = map_cc(rc, y, why))) return o;
        if (cc_object_id(CC_KIND_AGENT_STATE, tw->b[n], lens[n], tw->man.agent_state) != CC_OK)
            return CR_E_ARG;
        objs[n] = (struct cr_wobj){CC_KIND_AGENT_STATE, CC_STORE_OBJECT_VERSION, tw->b[n], lens[n]};
        n++;
    }

    if (up->n_rec) {
        if (cur->manifest.n_wal >= CC_MAX_WAL_SEGMENTS) {
            if (why) *why = "cortex WAL needs compaction";
            return CR_LIMIT;
        }
        if (up->n_rec > CC_MAX_WAL_RECORDS) {
            if (why) *why = "WAL segment record count";
            return CR_LIMIT;
        }
        memset(&tw->wal, 0, sizeof tw->wal);
        tw->wal.sequence = seq;
        tw->wal.n = up->n_rec;
        for (uint32_t i = 0; i < up->n_rec; i++) tw->wal.rec[i] = up->rec[i];
        rc = cc_wal_encode(&tw->wal, tw->b[n], sizeof tw->b[n], &lens[n], &y);
        if ((o = map_cc(rc, y, why))) return o;
        if (cc_object_id(CC_KIND_CORTEX_WAL, tw->b[n], lens[n], tw->man.wal[tw->man.n_wal]) != CC_OK)
            return CR_E_ARG;
        tw->man.n_wal++;
        objs[n] = (struct cr_wobj){CC_KIND_CORTEX_WAL, CC_STORE_OBJECT_VERSION, tw->b[n], lens[n]};
        n++;
    }

    uint64_t inc = cur->manifest.incarnation;
    if (new_incarnation) {
        if (inc == UINT64_MAX) {
            if (why) *why = "incarnation";
            return CR_LIMIT;
        }
        inc++;
    }
    memcpy(tw->man.root, cur->root_id, 32);
    memcpy(tw->man.previous, cur->manifest_id, 32);
    tw->man.sequence = seq;
    tw->man.incarnation = inc;
    rc = cc_manifest_encode(&tw->man, tw->b[n], sizeof tw->b[n], &lens[n], &y);
    if ((o = map_cc(rc, y, why))) return o;
    objs[n] = (struct cr_wobj){CC_KIND_MANIFEST, CC_STORE_OBJECT_VERSION, tw->b[n], lens[n]};
    n++;

    if ((o = do_transact(snk, objs, n, store_rc))) return o;
    return cr_resolve(src, w, out, why, store_rc);
}

int cr_resume(const struct cr_source *src, const struct cr_sink *snk, struct cr_work *w,
              struct cr_txwork *tw, struct cr_view *out, int *committed, const char **why,
              int *store_rc)
{
    if (committed) *committed = 0;
    if (why) *why = NULL;
    if (store_rc) *store_rc = 0;
    if (!args_ok(src, snk, w, tw, out)) return CR_E_ARG;
    struct cr_view *cur = &tw->tmp;
    int o = cr_resolve(src, w, cur, why, store_rc);
#ifdef CM_MUTANT_RESUME_PROVISIONS
    if (o == CR_UNPROVISIONED) { /* MC-1: a resume that mints an identity */
        static const uint8_t fake_uuid[16] = {0};
        uint8_t agent[32];
        memset(agent, 0x99, sizeof agent);
        struct cc_root root;
        memset(&root, 0, sizeof root);
        memcpy(root.agent_id, agent, 32);
        memcpy(root.store_uuid, fake_uuid, 16);
        cc_root_branch_id(agent, root.root_branch);
        root.provisioned_generation = src->generation ? src->generation(src->ctx) + 1 : 1;
        root.source = CC_SOURCE_OPERATOR;
        uint8_t rid[32], sid[32];
        size_t nr = 0, ns = 0, nm = 0;
        cc_root_encode(&root, tw->b[0], sizeof tw->b[0], &nr, NULL);
        cc_object_id(CC_KIND_AGENT_ROOT, tw->b[0], nr, rid);
        cc_state_genesis(&tw->state, agent, 1);
        cc_state_encode(&tw->state, tw->b[1], sizeof tw->b[1], &ns, NULL);
        cc_object_id(CC_KIND_AGENT_STATE, tw->b[1], ns, sid);
        memset(&tw->man, 0, sizeof tw->man);
        memcpy(tw->man.root, rid, 32);
        tw->man.sequence = 1;
        tw->man.incarnation = 1;
        memcpy(tw->man.agent_state, sid, 32);
        cc_manifest_encode(&tw->man, tw->b[2], sizeof tw->b[2], &nm, NULL);
        struct cr_wobj objs[3] = {
            {CC_KIND_AGENT_ROOT, 1, tw->b[0], nr},
            {CC_KIND_AGENT_STATE, 1, tw->b[1], ns},
            {CC_KIND_MANIFEST, 1, tw->b[2], nm},
        };
        if (do_transact(snk, objs, 3, store_rc) == 0) o = cr_resolve(src, w, cur, why, store_rc);
    }
#endif
    if (o != CR_RESOLVED) {
        memset(out, 0, sizeof *out);
        return o; /* INV-4: Unprovisioned stays Unprovisioned, nothing written */
    }
    if (cr_writable(src) != CR_RESOLVED) { /* INV-11: verified view, no commit */
        memcpy(out, cur, sizeof *out);
        return CR_RESOLVED;
    }
#ifdef CM_MUTANT_RESUME_NO_COMMIT
    memcpy(out, cur, sizeof *out); /* MC-3: no incarnation + 1 */
    if (committed) *committed = 1;
    return CR_RESOLVED;
#else
    static const struct cr_update none = {NULL, NULL, 0};
    o = cr_commit(src, snk, w, tw, cur, &none, 1, out, why, store_rc);
    if (o == CR_RESOLVED && committed) *committed = 1;
    return o;
#endif
}

/* ---- markers ---- */
struct mb {
    char *p;
    size_t cap, n;
    int over;
};
static void mb_s(struct mb *b, const char *s)
{
    for (; *s; s++) {
        if (b->n + 1 < b->cap) b->p[b->n] = *s;
        else b->over = 1;
        b->n++;
    }
}
static void mb_u(struct mb *b, uint64_t v)
{
    char t[24];
    int i = 0;
    do t[i++] = (char)('0' + v % 10);
    while ((v /= 10) != 0);
    char o[24];
    for (int k = 0; k < i; k++) o[k] = t[i - 1 - k];
    o[i] = 0;
    mb_s(b, o);
}
static void mb_i(struct mb *b, int v)
{
    if (v < 0) {
        mb_s(b, "-");
        mb_u(b, (uint64_t)0 - (uint64_t)(int64_t)v);
    } else
        mb_u(b, (uint64_t)v);
}
static void mb_hex(struct mb *b, const uint8_t *p, size_t n)
{
    static const char H[] = "0123456789abcdef";
    char t[3] = {0, 0, 0};
    for (size_t i = 0; i < n; i++) {
        t[0] = H[p[i] >> 4];
        t[1] = H[p[i] & 15];
        mb_s(b, t);
    }
}
static size_t mb_done(struct mb *b)
{
    if (!b->cap) return 0;
    if (b->over) {
        b->p[0] = 0;
        return 0;
    }
    b->p[b->n] = 0;
    return b->n;
}

size_t cr_marker_view(char *out, size_t cap, const char *word, const struct cr_view *v)
{
    struct mb b = {out, cap, 0, 0};
    if (!out || !word || !v) return 0;
    mb_s(&b, "CONTINUITY: ");
    mb_s(&b, word);
    mb_s(&b, " agent=");
    mb_hex(&b, v->root.agent_id, 32);
    mb_s(&b, " incarnation=");
    mb_u(&b, v->manifest.incarnation);
    mb_s(&b, " sequence=");
    mb_u(&b, v->manifest.sequence);
    mb_s(&b, " cortex=");
    mb_u(&b, v->cortex_count);
    mb_s(&b, " branches=");
    mb_u(&b, v->state.n);
    mb_s(&b, " memory=");
    mb_hex(&b, v->memory, 8);
    return mb_done(&b);
}

size_t cr_marker_outcome(char *out, size_t cap, int outcome, const char *why, int store_rc)
{
    struct mb b = {out, cap, 0, 0};
    if (!out) return 0;
    switch (outcome) {
    case CR_UNPROVISIONED: mb_s(&b, "CONTINUITY: UNPROVISIONED"); break;
    case CR_CONFLICT: mb_s(&b, "CONTINUITY: CONFLICT"); break;
    case CR_NO_ENTROPY: mb_s(&b, "CONTINUITY: NO_ENTROPY"); break;
    case CR_CORRUPT:
        mb_s(&b, "CONTINUITY: CORRUPT (");
        mb_s(&b, why ? why : "continuity unreadable");
        mb_s(&b, ")");
        break;
    case CR_LIMIT:
        mb_s(&b, "CONTINUITY: STOP (Limit(\"");
        mb_s(&b, why ? why : "");
        mb_s(&b, "\"))");
        break;
    case CR_STORE:
        mb_s(&b, "CONTINUITY: STOP (Store(");
        mb_i(&b, store_rc);
        mb_s(&b, "))");
        break;
    default:
        mb_s(&b, "CONTINUITY: STOP (");
        mb_s(&b, cr_outcome_name(outcome));
        mb_s(&b, ")");
        break;
    }
    return mb_done(&b);
}
