/* pi5_agent.c -- see pi5_agent.h. */
#include "pi5_agent.h"
#include <stddef.h>
#include "ck.h"
#include "sha256.h"
#include "../core/reply_obj.h"

static const uint32_t golden_ids[CK_AGENT_GOLDEN_NIDS] = {791, 6864, 315, 9822, 374, 12366, 13, 128009};
static const uint32_t golden_head[4] = {128000, 128006, 882, 128007};

/* header + prompt + separator + reply (<= CK_INFER_REPLY_TEXT) + terminator + model/ids trailer */
#define CK_AGENT_OBJ_MAX (24 + 48 + 8 + CK_INFER_REPLY_TEXT + 1 + CK_REPLY_OBJ_TRAILER_MAX)
static uint8_t g_body[SS_MAX_PLAINTEXT];

static void hex(char *out, const uint8_t *b, unsigned n)
{
    static const char d[] = "0123456789abcdef";
    for (unsigned i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[2 * n] = 0;
}

static size_t slen(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static int same(const uint8_t *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (a[i] != (uint8_t)b[i]) return 0;
    return 1;
}

static void show(char *out, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) out[i] = (b[i] >= 0x20 && b[i] <= 0x7e && b[i] != '"') ? (char)b[i] : '?';
    out[n] = 0;
}

/* A parsed agent object. text points into the body; model is 64 hex chars. */
struct parsed {
    const uint8_t *text;
    size_t text_len;
    char model[65];
    uint32_t ids[CK_REPLY_OBJ_MAX_IDS];
    unsigned nids;
};

/* Parse "<R1 header><prompt><sep><reply>\nmodel: <64 hex>\nids: <n n n>\n" from the END (the reply may
 * itself contain newlines). Returns 0 on a well-formed object for the fixed prompt, else a reason code. */
static int parse(const uint8_t *b, size_t len, struct parsed *p)
{
    const size_t hl = sizeof CK_REPLY_OBJ_HDR - 1, pl = slen(CK_AGENT_PROMPT), sl = sizeof CK_REPLY_OBJ_SEP - 1;
    const size_t ml = sizeof CK_REPLY_OBJ_MODEL - 1, il = sizeof CK_REPLY_OBJ_IDS - 1;
    const size_t body0 = hl + pl + sl; /* first byte of the reply text */
    size_t q, i, e;
    unsigned n = 0;
    if (len < body0 + 1 + ml + 64 + il + 2 || !same(b, CK_REPLY_OBJ_HDR, hl) || !same(b + hl, CK_AGENT_PROMPT, pl) ||
        !same(b + hl + pl, CK_REPLY_OBJ_SEP, sl))
        return 1;
    if (b[len - 1] != '\n') return 2;
    /* the last "\nids: " (CK_REPLY_OBJ_IDS starts with the newline) */
    for (q = len - il;; q--) {
        if (same(b + q, CK_REPLY_OBJ_IDS, il)) break;
        if (q == 0) return 3;
    }
    /* "\nmodel: " + 64 hex ends exactly at q; that newline is the reply's terminator */
    if (q < body0 + 1 + ml + 64) return 4;
    if (!same(b + q - 64 - ml, CK_REPLY_OBJ_MODEL, ml) || b[q - 64 - ml - 1] != '\n') return 5;
    for (e = 0; e < 64; e++) {
        uint8_t c = b[q - 64 + e];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 6;
        p->model[e] = (char)c;
    }
    p->model[64] = 0;
    p->text = b + body0;
    p->text_len = (q - 64 - ml - 1) - body0;
    /* ids: digits separated by single spaces, ended by the final newline */
    for (i = q + il; i < len - 1;) {
        uint64_t v = 0;
        size_t d = 0;
        while (i < len - 1 && b[i] >= '0' && b[i] <= '9') {
            v = v * 10 + (b[i] - '0');
            if (v > 0xffffffffull) return 7;
            i++, d++;
        }
        if (!d || n >= CK_REPLY_OBJ_MAX_IDS) return 8;
        p->ids[n++] = (uint32_t)v;
        if (i < len - 1) {
            if (b[i] != ' ') return 9;
            i++;
            if (i >= len - 1) return 10; /* trailing space */
        }
    }
    p->nids = n;
    return n ? 0 : 11;
}

/* The golden checks: the exact llama.cpp token list, the golden text, the golden model digest. */
static int golden_ok(const uint32_t *ids, unsigned nids, const uint8_t *text, size_t tlen, const char *model_hex)
{
    unsigned i;
    if (nids != CK_AGENT_GOLDEN_NIDS || tlen != slen(CK_AGENT_GOLDEN_TEXT) || !same(text, CK_AGENT_GOLDEN_TEXT, tlen)) return 0;
    for (i = 0; i < nids; i++)
        if (ids[i] != golden_ids[i]) return 0;
    for (i = 0; i < 64; i++)
        if (model_hex[i] != CK_AGENT_GOLDEN_MODEL_SHA256[i]) return 0;
    return 1;
}

/* Newest R1 object of the Store that starts with the fixed prompt's header. 0: found (body, len, gen filled);
 * 1: none; <0: an R1 object could not be read (do not guess: refuse). */
static int find_reply(ss_store *s, size_t *len, uint64_t *gen)
{
    const size_t pre = (sizeof CK_REPLY_OBJ_HDR - 1) + slen(CK_AGENT_PROMPT);
    int best = -1;
    uint64_t best_gen = 0, best_seq = 0;
    uint32_t k;
    for (k = 0; k < s->nclaims; k++) {
        const ss_claim *c = &s->ws->claims[k];
        static uint8_t scratch[SS_MAX_PLAINTEXT];
        struct parsed probe;
        size_t l = 0;
        uint16_t kind = 0;
        int rc;
        if (c->c.obj.object_kind != CK_REPLY_OBJ_KIND) continue;
        rc = ss_read(s, c->sid, scratch, sizeof scratch, &l, &kind);
        if (rc) {
            ck_printf("agent: REFUSED a reply object could not be read rc=%d store_gen=%llu\n", rc,
                      (unsigned long long)c->c.store_generation);
            return -1;
        }
        /* An agent reply is an R1 object for the fixed prompt WITH a well-formed model/ids trailer. A lifecycle reply
         * (QEMU service image, no trailer), another prompt or a damaged trailer is not ours and is left alone. */
        if (kind != CK_REPLY_OBJ_KIND || l < pre || !same(scratch, CK_REPLY_OBJ_HDR, sizeof CK_REPLY_OBJ_HDR - 1) ||
            !same(scratch + sizeof CK_REPLY_OBJ_HDR - 1, CK_AGENT_PROMPT, slen(CK_AGENT_PROMPT)) || parse(scratch, l, &probe))
            continue;
        if (best < 0 || c->c.store_generation > best_gen || (c->c.store_generation == best_gen && c->c.object_sequence > best_seq)) {
            best = (int)k;
            best_gen = c->c.store_generation;
            best_seq = c->c.object_sequence;
            for (size_t i = 0; i < l; i++) g_body[i] = scratch[i];
            *len = l;
        }
    }
    if (best < 0) return 1;
    *gen = best_gen;
    return 0;
}

/* Parse, check and print the reply held in g_body (len bytes) at generation gen. */
static int report(const char *how, size_t len, uint64_t gen, struct ck_agent_result *out)
{
    struct parsed p;
    uint8_t dg[SHA256_DIGEST_SIZE];
    char oh[65], shown[CK_INFER_REPLY_TEXT + 1], idl[CK_REPLY_OBJ_MAX_IDS * 11 + 1];
    unsigned i;
    size_t at = 0;
    int pr = parse(g_body, len, &p);
    if (pr) {
        ck_printf("agent: %s FAIL the stored reply object is malformed (reason %d, %u bytes, store_gen=%llu)\n", how, pr,
                  (unsigned)len, (unsigned long long)gen);
        return -1;
    }
    sha256_hash(g_body, len, dg);
    hex(oh, dg, SHA256_DIGEST_SIZE);
    show(shown, p.text, p.text_len > CK_INFER_REPLY_TEXT ? CK_INFER_REPLY_TEXT : p.text_len);
    for (i = 0; i < p.nids; i++) {
        uint32_t v = p.ids[i];
        char d[10];
        unsigned nd = 0;
        if (i) idl[at++] = ' ';
        do { d[nd++] = (char)('0' + v % 10); v /= 10; } while (v);
        while (nd) idl[at++] = d[--nd];
    }
    idl[at] = 0;
    ck_printf("agent: reply store_gen=%llu object_sha256=%s model_sha256=%s tokens=%u ids=%s text=\"%s\"\n",
              (unsigned long long)gen, oh, p.model, p.nids, idl, shown);
    out->store_gen = gen;
    for (i = 0; i < 65; i++) out->object_sha256[i] = oh[i];
#ifdef CK_AGENT_MUTANT_RECOVER_NO_CHECK
    /* TEST-ONLY mutant: a recovered reply is accepted whatever it says. */
    return 0;
#else
    if (!golden_ok(p.ids, p.nids, p.text, p.text_len, p.model)) {
        ck_printf("agent: %s FAIL the stored reply is not the golden reply (tokens, text or model digest differ)\n", how);
        return -1;
    }
    return 0;
#endif
}

static int generate(ss_store *s, struct ck_agent_result *out)
{
    static struct ck_infer_reply r;
    static uint8_t obj[CK_AGENT_OBJ_MAX];
    char mh[65];
    const uint8_t *msha;
    size_t n, len = 0;
    uint64_t gen = 0;
    uint8_t sid[1][32];
    unsigned i = 0;
    int rc, ok;
    (void)i;
    ck_infer_run();
    if (!ck_infer_resident()) {
        out->mode = CK_AGENT_MODE_NOMODEL;
        ck_puts("agent: NOTHING GENERATED: this Store holds no agent reply yet and no model is resident (MODEL.MAP absent or "
                "refused, or the model digest did not match); nothing written\n");
        return -1;
    }
    msha = ck_infer_model_sha256();
    if (!msha) {
        ck_infer_resident_close();
        ck_puts("agent: REFUSED the resident model has no digest; nothing written\n");
        return -1;
    }
    hex(mh, msha, SHA256_DIGEST_SIZE);
    rc = ck_infer_prompt(CK_AGENT_PROMPT, slen(CK_AGENT_PROMPT), 0, &r);
    ck_infer_resident_close(); /* every frame back before the commit */
    if (rc < 0 || r.cancelled) {
        ck_printf("agent: REFUSED the model refused the prompt rc=%d cancelled=%d; nothing written\n", rc, r.cancelled);
        return -1;
    }
    ck_printf("agent: generated tokens=%u prompt_ids=%u steps=%u us=%llu prompt_head=%u,%u,%u,%u\n", r.produced, r.prompt_ids,
              r.steps, (unsigned long long)r.us, r.prompt_head[0], r.prompt_head[1], r.prompt_head[2], r.prompt_head[3]);
    ok = r.produced <= CK_AGENT_MAX_NEW && r.produced <= CK_INFER_REPLY_IDS;
#ifdef CK_AGENT_MUTANT_NO_PROMPT_CHECK
    (void)golden_head; /* TEST-ONLY mutant: the chat-template head is not checked */
#else
    for (i = 0; i < 4; i++) ok = ok && r.prompt_head[i] == golden_head[i];
#endif
#ifndef CK_AGENT_MUTANT_NO_GOLDEN_CHECK
    ok = ok && golden_ok(r.ids, r.produced, r.text, r.text_len, mh);
#endif
    if (!ok) {
        ck_puts("agent: REFUSED the reply is not the golden reply (prompt head, tokens, text or model digest); nothing written\n");
        return -1;
    }
    n = ck_reply_obj_build(obj, CK_AGENT_PROMPT, slen(CK_AGENT_PROMPT), r.text, r.text_len, mh, r.ids, r.produced);
    {
        ss_object o = {CK_REPLY_OBJ_KIND, 1, obj, n};
#ifdef CK_AGENT_MUTANT_NO_COMMIT
        /* TEST-ONLY mutant: skip the commit but still report success. */
        rc = 0;
        (void)sid;
        (void)o;
#else
        rc = ss_transact(s, &o, 1, 0, 0, sid);
#endif
    }
    if (rc) {
        ck_printf("agent: REFUSED the Store did not commit the reply rc=%d; nothing written\n", rc);
        return -1;
    }
    /* Read it back from the sealed Store, the way a cold boot will. */
    rc = find_reply(s, &len, &gen);
    if (rc) {
        ck_puts("agent: FAIL the committed reply is not in the Store\n");
        return -1;
    }
    if (report("readback", len, gen, out)) return -1;
    out->ok = 1;
    ck_printf("agent: committed store_gen=%llu\n", (unsigned long long)gen);
    return 0;
}

int ck_pi5_agent_run(ss_store *s, struct ck_agent_result *out)
{
    size_t len = 0;
    uint64_t gen = 0;
    int rc;
    *out = (struct ck_agent_result){0};
#ifdef CK_AGENT_MUTANT_MODEL_FIRST
    ck_infer_run(); /* TEST-ONLY mutant: the model is read and hashed before the Store is checked */
#endif
    if (!s) {
        out->mode = CK_AGENT_MODE_NOSTORE;
        ck_puts("agent: NOTHING RECOVERED: the Store is not open (recovery secret missing or rejected, or the disk was "
                "refused); the model was not read or hashed, nothing was generated, nothing was written\n");
        ck_puts("AIENOS_PI5_AGENT: NOSTORE\n");
        return 0;
    }
#ifdef CK_AGENT_MUTANT_RECOVER_BLIND
    rc = 1; /* TEST-ONLY mutant: recovery never looks at the Store */
#else
    rc = find_reply(s, &len, &gen);
#endif
    if (rc < 0) {
        ck_puts("AIENOS_PI5_AGENT: FAIL\n");
        return -1;
    }
    if (rc == 0) {
        out->mode = CK_AGENT_MODE_RECOVER;
        rc = report("recovered", len, gen, out);
        out->ok = rc == 0;
        ck_printf("AIENOS_PI5_AGENT: RECOVERED %s\n", rc ? "FAIL" : "PASS");
        return rc;
    }
    out->mode = CK_AGENT_MODE_GENERATE;
    rc = generate(s, out);
    if (out->mode == CK_AGENT_MODE_NOMODEL) {
        ck_puts("AIENOS_PI5_AGENT: NOMODEL\n");
    } else {
        ck_printf("AIENOS_PI5_AGENT: GENERATED %s\n", rc ? "FAIL" : "PASS");
    }
    return rc;
}
