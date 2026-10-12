/* continuity_service.c -- production continuity on the resident lifecycle
 * (native v1 plan P05, cut 1). Contract and limits: continuity_service.h. */
#include "continuity_service.h"
#include <string.h>
#include "ck.h"
#include "continuity_resolve_sealed.h"
#include "continuity_subject_provision.h"
#include "entropy.h"
#include "fmt.h"
#include "sha256.h"

#if !defined(CK_SERVICE) && !defined(CK_CONT_SERVICE_HOST_TEST)
#error "continuity_service.c is only part of a CK_SERVICE=1 image (or the host stage test)"
#endif
#if defined(CK_TEST_CONTINUITY)
#error "continuity_service.c is never combined with the TEST-ONLY continuity mode selection"
#endif

/* ---- the entropy source: the kernel's RNDR service or a refusal, no fallback ---- */
static int ent_present(void *ctx)
{
    (void)ctx;
    return ck_entropy_status() == CK_RNG_OK;
}
static int ent_read(void *ctx, uint64_t *out)
{
    (void)ctx;
    uint64_t w = 0;
    if (ck_entropy_fill(&w, sizeof w) != 0) return 0;
    *out = w;
    return 1;
}
static const struct ck_rng_ops k_ent_ops = {ent_present, ent_read, 0};

/* ---- workspace (heap, once; the view is kept for the service lifetime) ---- */
static struct {
    struct cr_work *w;
    struct cr_txwork *tw;
    struct cr_view *v;
    struct cs_subject *subj;
    uint8_t sid[32];
    int state;
    int allocated;
} g;

static int alloc_all(void)
{
    if (g.allocated) return 0;
    g.w = ck_alloc(sizeof *g.w);
    g.tw = ck_alloc(sizeof *g.tw);
    g.v = ck_alloc(sizeof *g.v);
    g.subj = ck_alloc(sizeof *g.subj);
    g.allocated = g.w && g.tw && g.v && g.subj;
    return g.allocated ? 0 : -1;
}

static void hex_into(char *o, const uint8_t *b, size_t n)
{
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        o[2 * i] = hx[b[i] >> 4];
        o[2 * i + 1] = hx[b[i] & 15];
    }
    o[2 * n] = 0;
}

static void view_line(const char *word, const struct cr_view *v)
{
    char ag[65];
    hex_into(ag, v->root.agent_id, 32);
    ck_printf("continuity: %s agent=%s incarnation=%llu sequence=%llu cortex=%llu branches=%u\n", word, ag,
              (unsigned long long)v->manifest.incarnation, (unsigned long long)v->manifest.sequence,
              (unsigned long long)v->cortex_count, (unsigned)v->state.n);
}

static void subject_line(const char *word, const struct cs_subject *s, const uint8_t id[32])
{
    char sub[65], ln[65];
    uint32_t active = 0;
    for (uint32_t i = 0; i < s->n_intents; i++) active += s->in[i].state == CS_ACTIVE;
    hex_into(sub, id, 32);
    hex_into(ln, s->cortex, 32);
    ck_printf("allen: %s subject=%s sequence=%llu lineage=%s intents=%u active=%u knowledge=%u\n", word, sub,
              (unsigned long long)s->sequence, ln, (unsigned)s->n_intents, (unsigned)active, (unsigned)s->n_knowledge);
}

static int refused(const char *step, int outcome, const char *why, int store_rc)
{
    ck_printf("continuity: REFUSED step=\"%s\" outcome=%s%s%s store_rc=%d (nothing written; lifecycle stays locked)\n",
              step, cr_outcome_name(outcome), why ? " why=" : "", why ? why : "", store_rc);
    g.state = CK_CONT_REFUSED;
    return g.state;
}

/* provenance = SHA-256(label || owner pk || store uuid); lineage = SHA-256(label || store uuid). */
static void genesis_inputs(struct cs_genesis *gen, const uint8_t store_uuid[16], const uint8_t *owner_pk,
                           size_t owner_pk_len)
{
    static const char lp[] = "AIENOS/ALLEN/PROVENANCE-V1";
    static const char ll[] = "AIENOS/ALLEN/CORTEX-LINEAGE-V1";
    uint8_t buf[sizeof lp + 64 + 16];
    size_t n = 0;
    memset(gen, 0, sizeof *gen);
    memcpy(buf, lp, sizeof lp - 1);
    n = sizeof lp - 1;
    if (owner_pk && owner_pk_len && owner_pk_len <= 64) {
        memcpy(buf + n, owner_pk, owner_pk_len);
        n += owner_pk_len;
    }
    memcpy(buf + n, store_uuid, 16);
    n += 16;
    sha256_hash(buf, n, gen->provenance);
    memcpy(buf, ll, sizeof ll - 1);
    memcpy(buf + sizeof ll - 1, store_uuid, 16);
    sha256_hash(buf, sizeof ll - 1 + 16, gen->cortex);
    gen->origin = CS_ORIGIN_OPERATOR;
}

int ck_cont_service_start(ss_store *s, const uint8_t store_uuid[16], const uint8_t *owner_pk, size_t owner_pk_len,
                          uint8_t source)
{
    struct cr_source src;
    struct cr_sink snk;
    struct cr_sealed_sink sk = {s, 0, 0};
    const char *why = 0;
    int store_rc = 0;
    g.state = CK_CONT_NONE;
    if (!s || !store_uuid) return refused("arguments", CR_E_ARG, "null", 0);
    if (alloc_all()) return refused("workspace", CR_LIMIT, "heap", 0);
    cr_bind_sealed(&src, s);
    cr_bind_sealed_sink(&snk, &sk);

    int o = cr_resolve(&src, g.w, g.v, &why, &store_rc);
    if (o == CR_UNPROVISIONED) {
        struct ck_rng rng;
        struct cs_genesis gen;
        memset(&rng, 0, sizeof rng);
        if (ck_rng_probe(&rng, &k_ent_ops) != CK_RNG_OK)
            return refused("genesis entropy", CR_NO_ENTROPY, ck_rng_reason(rng.state), 0);
        genesis_inputs(&gen, store_uuid, owner_pk, owner_pk_len);
        o = cs_provision(&src, &snk, g.w, g.tw, &rng, store_uuid, source, &gen, g.v, g.subj, g.sid, &why, &store_rc);
        if (o != CR_RESOLVED) return refused("provision", o, why, store_rc);
        ck_printf("continuity: genesis source=%s provenance=%s (identity and ALLEN subject in one transaction)\n",
                  source == CC_SOURCE_OPERATOR ? "operator" : "qualification",
                  owner_pk && owner_pk_len ? "owner-root-pk+store-uuid" : "store-uuid-only");
        view_line("PROVISIONED", g.v);
        subject_line("GENESIS", g.subj, g.sid);
        g.state = CK_CONT_PROVISIONED;
        return g.state;
    }
    if (o != CR_RESOLVED) return refused("resolve", o, why, store_rc);

    /* Restore the subject read-only before anything is written. */
    int cs = cs_resolve(&src, g.w, g.v, g.subj, g.sid, &why, &store_rc);
    if (cs == CS_ABSENT) return refused("subject", CR_CORRUPT, "provisioned without a subject (never minted here)", store_rc);
    if (cs != CS_RESOLVED) return refused("subject", cs, why, store_rc);
    subject_line("RESTORED", g.subj, g.sid);

    int committed = 0;
    o = cr_resume(&src, &snk, g.w, g.tw, g.v, &committed, &why, &store_rc);
    if (o != CR_RESOLVED) return refused("resume", o, why, store_rc);
    if (!committed) {
        view_line("RESUMED_READONLY", g.v);
        ck_puts("continuity: degraded mount: restored without writing; commits are refused until a valid mount\n");
        g.state = CK_CONT_RESUMED_READONLY;
        return g.state;
    }
    view_line("RESUMED", g.v);
    g.state = CK_CONT_RESUMED;
    return g.state;
}

int ck_cont_service_state(void)
{
    return g.state;
}

int ck_cont_service_writable(void)
{
    return g.state == CK_CONT_PROVISIONED || g.state == CK_CONT_RESUMED;
}

static const char *state_word(int st)
{
    switch (st) {
    case CK_CONT_PROVISIONED: return "provisioned";
    case CK_CONT_RESUMED: return "resumed";
    case CK_CONT_RESUMED_READONLY: return "resumed-readonly";
    case CK_CONT_REFUSED: return "refused";
    default: return "none";
    }
}

void ck_cont_service_status(char *out, size_t cap)
{
    if (!out || !cap) return;
    if (g.state > 0 && g.v && g.subj) {
        char ag[17];
        hex_into(ag, g.v->root.agent_id, 8);
        ck_snprintf(out, cap, "continuity=%s agent=%s incarnation=%llu subject_seq=%llu", state_word(g.state), ag,
                    (unsigned long long)g.v->manifest.incarnation, (unsigned long long)g.subj->sequence);
    } else {
        ck_snprintf(out, cap, "continuity=%s", state_word(g.state));
    }
}

const uint8_t *ck_cont_service_agent(void)
{
    return g.state > 0 && g.v ? g.v->root.agent_id : 0;
}

void ck_cont_service_stop(void)
{
    g.state = CK_CONT_NONE;
    if (g.v) memset(g.v, 0, sizeof *g.v);
    if (g.subj) memset(g.subj, 0, sizeof *g.subj);
    memset(g.sid, 0, sizeof g.sid);
}
