/* continuity_subject_provision.c -- see continuity_subject_provision.h. */
#include "continuity_subject_provision.h"

#include "store_sealed.h"
#include "store_v1.h"

static int fail(const char **why, int cls, const char *w)
{
    if (why) *why = w;
    return cls;
}

static int map_cc(int rc)
{
    return rc == CC_E_LIMIT ? CR_LIMIT : rc == CC_E_ARG ? CR_E_ARG : CR_CORRUPT;
}

/* The genesis sink: forwards cr_provision's one transaction with the genesis
 * subject object appended. It accepts exactly one call carrying exactly one
 * AgentRoot; anything else is refused before the inner sink is touched, so a
 * provisioning write without its subject cannot reach the Store. */
struct gsink {
    const struct cr_sink *inner;
    const struct cs_genesis *g;
    int calls;
    int rc;                 /* 0, or why the sink refused (CR_*) */
    const char *why;
    struct cs_subject subj; /* the genesis object that was sent */
    uint8_t id[32];
    uint8_t buf[CS_MAX_BYTES];
    size_t len;
};

#define GSINK_REFUSED (-7700) /* store-style error code for a refused call */

static int gsink_transact(void *ctx, const struct cr_wobj *objs, size_t n)
{
    struct gsink *k = ctx;
    struct cr_wobj all[SS_MAX_OBJECTS];
    const struct cr_wobj *root = 0;
    static struct cr_view rv; /* only root_id and root.agent_id are used */
    const char *y = 0;
    int rc;
    if (k->calls++ != 0) {
        k->rc = fail(&k->why, CR_E_ARG, "provisioning made a second transaction");
        return GSINK_REFUSED;
    }
    if (n + 1 > SS_MAX_OBJECTS) {
        k->rc = fail(&k->why, CR_LIMIT, "no room for the subject in the provisioning transaction");
        return GSINK_REFUSED;
    }
    for (size_t i = 0; i < n; i++) {
        if (objs[i].kind != CC_KIND_AGENT_ROOT) continue;
        if (root) {
            k->rc = fail(&k->why, CR_CORRUPT, "provisioning transaction carries two agent roots");
            return GSINK_REFUSED;
        }
        root = &objs[i];
    }
    if (!root) {
        k->rc = fail(&k->why, CR_CORRUPT, "provisioning transaction carries no agent root");
        return GSINK_REFUSED;
    }
    sv1_zero(&rv, sizeof rv);
    if ((rc = cc_root_decode(root->bytes, root->len, &rv.root, &y)) != CC_OK) {
        k->rc = fail(&k->why, map_cc(rc), y);
        return GSINK_REFUSED;
    }
    if (cc_object_id(CC_KIND_AGENT_ROOT, root->bytes, root->len, rv.root_id) != CC_OK) {
        k->rc = fail(&k->why, CR_E_ARG, "agent root object id");
        return GSINK_REFUSED;
    }
    cs_subject_genesis(&k->subj, &rv, k->g->provenance, k->g->origin);
    cs_subject_bind_cortex(&k->subj, k->g->cortex);
    if ((rc = cs_subject_encode(&k->subj, k->buf, sizeof k->buf, &k->len, &y)) != CC_OK) {
        k->rc = fail(&k->why, map_cc(rc), y);
        return GSINK_REFUSED;
    }
    if (cc_object_id(CC_KIND_SUBJECT, k->buf, k->len, k->id) != CC_OK) {
        k->rc = fail(&k->why, CR_E_ARG, "subject object id");
        return GSINK_REFUSED;
    }
    for (size_t i = 0; i < n; i++) all[i] = objs[i];
    all[n].kind = CC_KIND_SUBJECT;
    all[n].version = CC_STORE_OBJECT_VERSION;
    all[n].bytes = k->buf;
    all[n].len = k->len;
#ifdef CS_MUTANT_PROVISION_SPLIT_TXN
    /* MUTANT: identity first, subject in a second transaction (a crash
     * between them leaves an identity without its subject). */
    if ((rc = k->inner->transact(k->inner->ctx, all, n))) return rc;
    return k->inner->transact(k->inner->ctx, all + n, 1);
#else
    return k->inner->transact(k->inner->ctx, all, n + 1);
#endif
}

int cs_provision(const struct cr_source *src, const struct cr_sink *snk, struct cr_work *w,
                 struct cr_txwork *tw, struct ck_rng *rng, const uint8_t store_uuid[16],
                 uint8_t source, const struct cs_genesis *g, struct cr_view *out,
                 struct cs_subject *subj, uint8_t subj_id[32], const char **why, int *store_rc)
{
    static struct gsink k;
    struct cr_sink wrap;
    uint32_t n, roots = 0, subjects = 0;
    int rc;
    if (why) *why = 0;
    if (store_rc) *store_rc = 0;
    if (!src || !src->count || !src->entry || !snk || !snk->transact || !w || !tw || !rng ||
        !store_uuid || !g || !out || !subj || !subj_id)
        return fail(why, CR_E_ARG, "null argument");
    if (sv1_all_zero(g->provenance, 32))
        return fail(why, CR_E_ARG, "subject genesis needs a provenance");
    if (sv1_all_zero(g->cortex, 32))
        return fail(why, CR_E_ARG, "subject genesis needs a memory lineage reference");
    if (g->origin != CS_ORIGIN_OPERATOR && g->origin != CS_ORIGIN_PROMOTED)
        return fail(why, CR_E_ARG, "subject genesis origin");

    /* A subject object without an agent root is never provisioned over. */
    n = src->count(src->ctx);
    for (uint32_t i = 0; i < n; i++) {
        uint16_t kind = 0, version = 0;
        if ((rc = src->entry(src->ctx, i, &kind, &version))) {
            if (store_rc) *store_rc = rc;
            return fail(why, CR_STORE, "store entry failed");
        }
        roots += kind == CC_KIND_AGENT_ROOT;
        subjects += kind == CC_KIND_SUBJECT;
    }
    if (subjects && !roots)
        return fail(why, CR_CORRUPT, "subject objects without an agent root");

    sv1_zero(&k, sizeof k);
    k.inner = snk;
    k.g = g;
    wrap.ctx = &k;
    wrap.transact = gsink_transact;
    rc = cr_provision(src, &wrap, w, tw, rng, store_uuid, source, out, why, store_rc);
    if (k.rc) { /* the sink refused: nothing reached the Store */
        if (why) *why = k.why;
        if (store_rc) *store_rc = 0;
        return k.rc;
    }
    if (rc != CR_RESOLVED) return rc;

    /* Post-condition, read back from the Store: one subject, sequence 1,
     * this root and agent, the object that was sent. */
    rc = cs_resolve(src, w, out, subj, subj_id, why, store_rc);
    if (rc == CS_ABSENT) return fail(why, CR_CORRUPT, "identity provisioned without its subject");
    if (rc != CS_RESOLVED) return rc;
    if (subj->sequence != 1 || !sv1_equal(subj_id, k.id, 32))
        return fail(why, CR_CORRUPT, "provisioned subject is not the genesis object");
    return CR_RESOLVED;
}
