/* continuity_resolve.c -- see continuity_resolve.h. Resolve only; no write. */
#include <string.h>

#include "continuity_resolve.h"
#include "../../argus/sha256.h"
#include "../../crypto/aienos_crypto.h"
#include "../../store/store_v1.h"

const char *cr_outcome_name(int o)
{
    switch (o) {
    case CR_RESOLVED: return "Resolved";
    case CR_UNPROVISIONED: return "Unprovisioned";
    case CR_CONFLICT: return "Conflict";
    case CR_CORRUPT: return "Corrupt";
    case CR_LIMIT: return "Limit";
    case CR_STORE: return "Store";
    case CR_ALREADY_PROVISIONED: return "AlreadyProvisioned";
    case CR_READ_ONLY: return "ReadOnly";
    case CR_E_ARG: return "Arg";
    case CR_NO_ENTROPY: return "NoEntropy";
    }
    return "?";
}

struct ctx {
    const struct cr_source *src;
    struct cr_work *w;
    const char *why;
    int store_rc;
};

static int fail(struct ctx *c, int outcome, const char *why)
{
    c->why = why;
    return outcome;
}

static int is_tracked(uint16_t k)
{
    return k == CC_KIND_AGENT_ROOT || k == CC_KIND_MANIFEST || k == CC_KIND_AGENT_STATE ||
           k == CC_KIND_CORTEX_WAL;
}

static int is_zero32(const uint8_t *p)
{
    uint8_t a = 0;
    for (int i = 0; i < 32; i++) a |= p[i];
    return a == 0;
}

/* Read source object i into w->buf. 0, or a CR_* outcome with c->why / c->store_rc set. */
static int read_obj(struct ctx *c, uint32_t i, size_t *len)
{
    int rc = c->src->read(c->src->ctx, i, c->w->buf, sizeof c->w->buf, len);
    if (rc != 0) {
        c->store_rc = rc;
        return CR_STORE;
    }
    /* K-1 (contract 5.3): never truncate, never decode past the bound. */
    if (*len > CC_MAX_OBJECT_BYTES) return fail(c, CR_LIMIT, "continuity object exceeds the size bound");
    return 0;
}

/* rs read_kind (continuity.rs:619-633): the entry for id must exist with the
 * kind and Store version 1; its plaintext lands in w->buf. */
static int read_kind(struct ctx *c, const uint8_t id[32], uint16_t kind, size_t *len)
{
    const struct cr_entry *e = NULL;
    for (uint32_t i = 0; i < c->w->n; i++)
        if (memcmp(c->w->t[i].id, id, 32) == 0) {
            e = &c->w->t[i];
            break;
        }
    if (!e) return fail(c, CR_CORRUPT, "referenced object is absent");
    if (e->kind != kind || e->version != CC_STORE_OBJECT_VERSION)
        return fail(c, CR_CORRUPT, "referenced object has the wrong kind");
    int r = read_obj(c, e->src, len);
    if (r) return r;
    uint8_t chk[32];
    if (sv1_object_id(e->kind, e->version, c->w->buf, *len, chk) != 0 || memcmp(chk, id, 32) != 0)
        return fail(c, CR_CORRUPT, "object changed since lookup"); /* C only */
    return 0;
}

static int map_cc(struct ctx *c, int rc, const char *why)
{
    if (rc == CC_OK) return 0;
    c->why = why ? why : "continuity object";
    if (rc == CC_E_CORRUPT) return CR_CORRUPT;
    if (rc == CC_E_LIMIT) return CR_LIMIT;
    return CR_E_ARG;
}

static int build_table(struct ctx *c)
{
    struct cr_work *w = c->w;
    uint32_t cnt = c->src->count(c->src->ctx);
    w->n = 0;
    for (uint32_t i = 0; i < cnt; i++) {
        uint16_t k = 0, ver = 0;
        int rc = c->src->entry(c->src->ctx, i, &k, &ver);
        if (rc != 0) {
            c->store_rc = rc;
            return CR_STORE;
        }
        if (!is_tracked(k)) continue;
        if (w->n >= CR_TABLE_CAP) return fail(c, CR_LIMIT, "too many continuity objects");
        size_t len = 0;
        int r = read_obj(c, i, &len);
        if (r) return r;
        struct cr_entry *e = &w->t[w->n];
        memset(e, 0, sizeof *e);
        if (sv1_object_id(k, ver, w->buf, len, e->id) != 0)
            return fail(c, CR_CORRUPT, "continuity object has no valid id"); /* C only: empty */
        /* P-3: a logical id seen twice is Corrupt. */
        for (uint32_t j = 0; j < w->n; j++)
            if (memcmp(w->t[j].id, e->id, 32) == 0)
                return fail(c, CR_CORRUPT, "duplicate logical object id"); /* C only */
        e->kind = k;
        e->version = ver;
        e->src = i;
        w->n++;
    }
    return 0;
}

static uint32_t count_kind(const struct cr_work *w, uint16_t kind)
{
    uint32_t n = 0;
    for (uint32_t i = 0; i < w->n; i++) n += w->t[i].kind == kind;
    return n;
}

static void put32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}

int cr_resolve(const struct cr_source *src, struct cr_work *w, struct cr_view *v, const char **why,
               int *store_rc)
{
    struct ctx c = {src, w, NULL, 0};
    int out;
    if (why) *why = NULL;
    if (store_rc) *store_rc = 0;
    if (!src || !src->count || !src->entry || !src->read || !w || !v) return CR_E_ARG;
    memset(v, 0, sizeof *v);

    out = build_table(&c);
    if (out) goto done;

    /* INV-5, in this order (rs :638-653). */
    uint32_t roots = count_kind(w, CC_KIND_AGENT_ROOT);
    if (roots == 0) {
#ifndef CR_MUTANT_NO_ORPHAN_CHECK
        if (count_kind(w, CC_KIND_MANIFEST) || count_kind(w, CC_KIND_AGENT_STATE) ||
            count_kind(w, CC_KIND_CORTEX_WAL)) {
            out = fail(&c, CR_CORRUPT, "continuity objects without an agent root");
            goto done;
        }
#endif
        out = CR_UNPROVISIONED;
        goto done;
    }
#ifndef CR_MUTANT_SKIP_CONFLICT
    if (roots > 1) {
        out = CR_CONFLICT;
        goto done;
    }
#endif
    const struct cr_entry *re = NULL;
    for (uint32_t i = 0; i < w->n && !re; i++)
        if (w->t[i].kind == CC_KIND_AGENT_ROOT) re = &w->t[i];
    memcpy(v->root_id, re->id, 32);
    size_t len = 0;
    if ((out = read_kind(&c, v->root_id, CC_KIND_AGENT_ROOT, &len))) goto done;
    {
        const char *y = NULL;
        int rc = cc_root_decode(w->buf, len, &v->root, &y);
        if ((out = map_cc(&c, rc, y))) goto done;
    }

    /* INV-6: every manifest names this root; sorted by sequence they are 1..n. */
    uint32_t nm = 0;
    for (uint32_t i = 0; i < w->n; i++) {
        struct cr_entry *e = &w->t[i];
        if (e->kind != CC_KIND_MANIFEST) continue;
        if ((out = read_kind(&c, e->id, CC_KIND_MANIFEST, &len))) goto done;
        const char *y = NULL;
        int rc = cc_manifest_decode(w->buf, len, &v->manifest, &y);
        if ((out = map_cc(&c, rc, y))) goto done;
        if (memcmp(v->manifest.root, v->root_id, 32) != 0) {
            out = fail(&c, CR_CORRUPT, "manifest names a foreign root");
            goto done;
        }
        e->seq = v->manifest.sequence;
        memcpy(e->root, v->manifest.root, 32);
        memcpy(e->previous, v->manifest.previous, 32);
        w->mi[nm++] = i;
    }
    if (nm == 0) {
        out = fail(&c, CR_CORRUPT, "agent root has no manifest");
        goto done;
    }
    for (uint32_t i = 1; i < nm; i++) { /* stable insertion sort by sequence */
        uint32_t x = w->mi[i];
        uint32_t j = i;
        while (j > 0 && w->t[w->mi[j - 1]].seq > w->t[x].seq) {
            w->mi[j] = w->mi[j - 1];
            j--;
        }
        w->mi[j] = x;
    }
    static const uint8_t ZERO[32];
    for (uint32_t i = 0; i < nm; i++) {
        const struct cr_entry *m = &w->t[w->mi[i]];
        if (m->seq != (uint64_t)i + 1) {
            out = fail(&c, CR_CORRUPT, "manifest sequence gap or fork");
            goto done;
        }
        const uint8_t *expect = i ? w->t[w->mi[i - 1]].id : ZERO;
#ifndef CR_MUTANT_IGNORE_PREVIOUS
        if (memcmp(m->previous, expect, 32) != 0) {
            out = fail(&c, CR_CORRUPT, "manifest chain is broken");
            goto done;
        }
#else
        (void)expect;
#endif
    }
    const struct cr_entry *cur = &w->t[w->mi[nm - 1]];
    memcpy(v->manifest_id, cur->id, 32);
    if ((out = read_kind(&c, v->manifest_id, CC_KIND_MANIFEST, &len))) goto done;
    {
        const char *y = NULL;
        int rc = cc_manifest_decode(w->buf, len, &v->manifest, &y);
        if ((out = map_cc(&c, rc, y))) goto done;
    }

    /* INV-7: agent state of the current manifest. */
    if (is_zero32(v->manifest.agent_state)) {
        out = fail(&c, CR_CORRUPT, "manifest has no agent state");
        goto done;
    }
    if ((out = read_kind(&c, v->manifest.agent_state, CC_KIND_AGENT_STATE, &len))) goto done;
    {
        const char *y = NULL;
        int rc = cc_state_decode(w->buf, len, &v->state, &y);
        if ((out = map_cc(&c, rc, y))) goto done;
    }
    if (memcmp(v->state.agent_id, v->root.agent_id, 32) != 0) {
        out = fail(&c, CR_CORRUPT, "agent state belongs to another agent");
        goto done;
    }

    /* WAL segments in manifest order, strictly increasing, <= manifest.sequence. */
    sha256_ctx mem;
    sha256_init(&mem);
    uint64_t last = 0;
    for (uint32_t s = 0; s < v->manifest.n_wal; s++) {
        if ((out = read_kind(&c, v->manifest.wal[s], CC_KIND_CORTEX_WAL, &len))) goto done;
        const char *y = NULL;
        int rc = cc_wal_decode(w->buf, len, &w->wal, &y);
        if ((out = map_cc(&c, rc, y))) goto done;
        if (w->wal.sequence <= last || w->wal.sequence > v->manifest.sequence) {
            out = fail(&c, CR_CORRUPT, "WAL segments out of order");
            goto done;
        }
        last = w->wal.sequence;
        for (uint32_t r = 0; r < w->wal.n; r++) {
            uint8_t l4[4];
            put32(l4, w->wal.rec[r].len);
            sha256_update(&mem, l4, 4);
            sha256_update(&mem, w->wal.rec[r].statement, w->wal.rec[r].len);
            v->cortex_count++;
        }
    }
    sha256_final(&mem, v->memory);
    out = CR_RESOLVED;

done:
    if (out != CR_RESOLVED) memset(v, 0, sizeof *v);
    if (why) *why = c.why;
    if (store_rc) *store_rc = c.store_rc;
    return out;
}

int cr_writable(const struct cr_source *src)
{
    if (!src || !src->mount_state) return CR_READ_ONLY; /* fail closed */
    return src->mount_state(src->ctx) == CR_MOUNT_VALID ? CR_RESOLVED : CR_READ_ONLY;
}

/* ---- challenge and operator response ---- */

void cr_state_digest(const uint8_t unit0[4096], const uint8_t unit1[4096], uint8_t out[32])
{
    sha256_ctx h;
    sha256_init(&h);
    sha256_update(&h, unit0, 4096);
    sha256_update(&h, unit1, 4096);
    sha256_final(&h, out);
}

void cr_challenge(const uint8_t uuid[16], uint64_t generation, uint8_t action,
                  const uint8_t state_digest[32], uint8_t out[32])
{
    static const char D[] = "AIENOS-RECOVERY-CHALLENGE-v1"; /* + NUL: 29 bytes */
    uint8_t g[8];
    for (int i = 0; i < 8; i++) g[i] = (uint8_t)(generation >> (8 * i));
    sha256_ctx h;
    sha256_init(&h);
    sha256_update(&h, (const uint8_t *)D, sizeof D); /* includes the NUL */
    sha256_update(&h, uuid, 16);
    sha256_update(&h, g, 8);
#ifndef CR_MUTANT_CHALLENGE_NO_ACTION
    sha256_update(&h, &action, 1);
#else
    (void)action;
#endif
#ifndef CR_MUTANT_CHALLENGE_NO_DIGEST
    sha256_update(&h, state_digest, 32);
#else
    (void)state_digest;
#endif
    sha256_final(&h, out);
}

void cr_operator_response(const uint8_t key[32], const uint8_t challenge[32], uint8_t out[32])
{
    static const char D[] = "AIENOS-RECOVERY-OPERATOR-AUTH-v1"; /* + NUL: 33 bytes */
    uint8_t msg[sizeof D + 32];
#if defined(CR_MUTANT_BARE_SHA256)
    sha256_ctx h;
    sha256_init(&h);
    sha256_update(&h, key, 32);
    sha256_update(&h, challenge, 32);
    sha256_final(&h, out);
    (void)msg;
    return;
#elif defined(CR_MUTANT_NO_DOMAIN)
    (void)msg;
    aienos_hmac_sha256(key, challenge, 32, out);
    return;
#else
    memcpy(msg, D, sizeof D); /* includes the NUL */
    memcpy(msg + sizeof D, challenge, 32);
    aienos_hmac_sha256(key, msg, sizeof msg, out);
    aienos_wipe(msg, sizeof msg);
#endif
}

int cr_operator_verify(const uint8_t key[32], const uint8_t challenge[32], const uint8_t response[32])
{
    uint8_t expected[32];
    cr_operator_response(key, challenge, expected);
#ifdef CR_MUTANT_COMPARE_16
    int ok = aienos_ct_equal(expected, response, 16);
#else
    int ok = aienos_ct_equal(expected, response, 32);
#endif
    aienos_wipe(expected, sizeof expected);
    return ok;
}
