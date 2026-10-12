/* context.c -- see context.h. No kernel calls, no libc. */
#include "context.h"
#include "../third_party/omega/rx_cortex.h"
#include "../../argus/sha256.h"

#if defined(CK_CTX_MUTANT_SKIP_BINDING) && !defined(CK_CTX_HOST_TEST)
#error "CK_CTX_MUTANT_SKIP_BINDING is a host-only TEST mutant (make context-mutant)"
#endif

static const uint8_t k_magic[6] = { 'A', 'M', 'E', 'M', CK_MEM_VERSION, 0 };

static int printable(uint8_t c) { return c >= 0x20 && c <= 0x7e; }

static int has(const uint8_t *t, size_t n, const char *lit)
{
    size_t m = 0, i, j;
    while (lit[m]) m++;
    if (m == 0 || m > n) return 0;
    for (i = 0; i + m <= n; i++) {
        for (j = 0; j < m && t[i + j] == (uint8_t)lit[j]; j++) {}
        if (j == m) return 1;
    }
    return 0;
}

int ck_ctx_text_safe(const uint8_t *t, size_t n)
{
    return !has(t, n, "<|") && !has(t, n, "|>") && !has(t, n, "End of memory") && !has(t, n, "Owner memory") &&
           !has(t, n, "Task:");
}

enum ck_mem_form ck_mem_parse(const uint8_t *b, size_t nb, uint64_t tag, ck_mem_v1 *out)
{
    size_t i;
    if (!b || nb < sizeof k_magic) return CK_MEM_LEGACY;
    for (i = 0; i < sizeof k_magic; i++)
        if (b[i] != k_magic[i]) return CK_MEM_LEGACY;
    if (nb < CK_MEM_HDR_BYTES || tag == 0 || tag > CK_CTX_TEXT_MAX || CK_MEM_HDR_BYTES + tag > nb)
        return CK_MEM_MALFORMED;
    if (b[6] != CK_MEM_TYPE_PREF && b[6] != CK_MEM_TYPE_FACT) return CK_MEM_MALFORMED;
    if (b[7] & ~CK_MEM_PERM_CONTEXT) return CK_MEM_MALFORMED;
    for (i = 0; i < tag; i++)
        if (!printable(b[CK_MEM_HDR_BYTES + i])) return CK_MEM_MALFORMED;
    for (i = CK_MEM_HDR_BYTES + tag; i < nb; i++) /* padding of the last word must be zero */
        if (b[i]) return CK_MEM_MALFORMED;
    if (out) {
        out->type = b[6];
        out->perm = b[7];
        for (i = 0; i < 32; i++) out->binding[i] = b[8 + i];
        out->text = b + CK_MEM_HDR_BYTES;
        out->text_len = (size_t)tag;
    }
    return CK_MEM_V1;
}

uint32_t ck_mem_encode(uint64_t *w, uint8_t type, uint8_t perm, const uint8_t binding[32], const char *text,
                       size_t n)
{
    uint8_t b[CK_MEM_MAX_WORDS * 8];
    size_t i, nb;
    if (n == 0 || n > CK_CTX_TEXT_MAX || !binding || !text) return 0;
    for (i = 0; i < n; i++)
        if (!printable((uint8_t)text[i])) return 0;
    for (i = 0; i < sizeof b; i++) b[i] = 0;
    for (i = 0; i < sizeof k_magic; i++) b[i] = k_magic[i];
    b[6] = type;
    b[7] = perm;
    for (i = 0; i < 32; i++) b[8 + i] = binding[i];
    for (i = 0; i < n; i++) b[CK_MEM_HDR_BYTES + i] = (uint8_t)text[i];
    nb = (CK_MEM_HDR_BYTES + n + 7) / 8;
    for (i = 0; i < nb; i++) {
        uint64_t v = 0;
        size_t k;
        for (k = 0; k < 8; k++) v |= (uint64_t)b[8 * i + k] << (8 * k);
        w[i] = v;
    }
    return (uint32_t)nb;
}

void ck_ctx_begin(ck_ctx *c, const uint8_t *agent)
{
    size_t i;
    uint8_t *p = (uint8_t *)c;
    for (i = 0; i < sizeof *c; i++) p[i] = 0;
    if (agent) {
        for (i = 0; i < 32; i++) c->agent[i] = agent[i];
        c->have_agent = 1;
    }
}

static int refuse(ck_ctx *c, int rc, uint64_t id)
{
    if (!c->refused) {
        c->refused = rc;
        c->bad_id = id;
    }
    return c->refused;
}

int ck_ctx_add(ck_ctx *c, const ck_ctx_rec *r)
{
    ck_mem_v1 m;
    size_t i;
    if (c->refused) return c->refused;
    if (c->finished || !r || (c->seen && r->id <= c->last_id)) return refuse(c, CK_CTX_E_STATE, r ? r->id : 0);
    if (!c->have_agent) return refuse(c, CK_CTX_E_SUBJECT, r->id);
    c->seen++;
    c->last_id = r->id;
    if (!r->verified) return refuse(c, CK_CTX_E_UNVERIFIED, r->id);
    if (r->cls != CX_CLAIM || r->kind != CX_K_CLAIM || r->subject != CK_CTX_OWNER_SUBJECT) {
        c->other++;
        return 0;
    }
    enum ck_mem_form f = ck_mem_parse(r->bytes, r->nbytes, r->tag, &m);
    if (f == CK_MEM_LEGACY) {
        c->legacy++;
        return 0;
    }
    if (f == CK_MEM_MALFORMED) return refuse(c, CK_CTX_E_MALFORMED, r->id);
#ifndef CK_CTX_MUTANT_SKIP_BINDING
    for (i = 0; i < 32; i++)
        if (m.binding[i] != c->agent[i]) return refuse(c, CK_CTX_E_FOREIGN, r->id);
#endif
    if (!(m.perm & CK_MEM_PERM_CONTEXT)) {
        c->unpermitted++;
        return 0;
    }
    if (!ck_ctx_text_safe(m.text, m.text_len)) {
        c->unsafe++;
        return 0;
    }
    c->eligible++;
    if (c->kept == CK_CTX_MAX_RECORDS) c->omitted++; /* the oldest kept one is pushed out */
    else c->kept++;
    {
        uint32_t slot = c->head;
        c->keep[slot].id = r->id;
        c->keep[slot].type = m.type;
        c->keep[slot].len = (uint8_t)m.text_len;
        for (i = 0; i < m.text_len; i++) c->keep[slot].text[i] = (char)m.text[i];
        c->head = (slot + 1) % CK_CTX_MAX_RECORDS;
    }
    return 0;
}

static int put(ck_ctx *c, const char *s, size_t n)
{
    size_t i;
    if (c->len + n > CK_CTX_PROMPT_MAX) return -1;
    for (i = 0; i < n; i++) c->prompt[c->len++] = s[i];
    return 0;
}
static int puts_(ck_ctx *c, const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    return put(c, s, n);
}

int ck_ctx_finish(ck_ctx *c, const char *task, size_t tn)
{
    size_t i;
    if (c->refused) return c->refused;
    if (c->finished) return refuse(c, CK_CTX_E_STATE, 0);
    if (!c->have_agent) return refuse(c, CK_CTX_E_SUBJECT, 0);
    if (!task || tn == 0 || tn > CK_CTX_TASK_MAX) return refuse(c, CK_CTX_E_TASK, 0);
    for (i = 0; i < tn; i++)
        if (!printable((uint8_t)task[i])) return refuse(c, CK_CTX_E_TASK, 0);
    if (has((const uint8_t *)task, tn, "<|") || has((const uint8_t *)task, tn, "|>")) return refuse(c, CK_CTX_E_TASK, 0);
    c->len = 0;
    if (c->kept == 0) {
        if (put(c, task, tn)) return refuse(c, CK_CTX_E_LIMIT, 0);
    } else {
        /* oldest kept first: the ring starts at head when full, else at 0 */
        uint32_t k, start = c->kept == CK_CTX_MAX_RECORDS ? c->head : 0;
        int bad = puts_(c, CK_CTX_HDR);
        for (k = 0; k < c->kept && !bad; k++) {
            uint32_t s = (start + k) % CK_CTX_MAX_RECORDS;
            bad = puts_(c, c->keep[s].type == CK_MEM_TYPE_PREF ? CK_CTX_PREF : CK_CTX_FACT) ||
                  put(c, c->keep[s].text, c->keep[s].len) || put(c, "\n", 1);
        }
        if (!bad) bad = puts_(c, CK_CTX_END) || puts_(c, CK_CTX_TASK) || put(c, task, tn);
        if (bad) {
            c->len = 0;
            return refuse(c, CK_CTX_E_LIMIT, 0);
        }
    }
    c->prompt[c->len] = 0;
    c->selected = c->kept;
    {
        static const char dom[] = "aienos.context.v1";
        sha256_ctx h;
        sha256_init(&h);
        sha256_update(&h, (const uint8_t *)dom, sizeof dom); /* includes the 0x00 separator */
        sha256_update(&h, c->agent, 32);
        sha256_update(&h, (const uint8_t *)c->prompt, c->len);
        sha256_final(&h, c->sha);
    }
    c->finished = 1;
    return 0;
}

const char *ck_ctx_strerror(int rc)
{
    switch (rc) {
    case CK_CTX_OK: return "ok";
    case CK_CTX_E_SUBJECT: return "no provisioned subject";
    case CK_CTX_E_UNVERIFIED: return "memory record not verified";
    case CK_CTX_E_FOREIGN: return "foreign memory: record bound to another agent";
    case CK_CTX_E_MALFORMED: return "malformed memory record";
    case CK_CTX_E_TASK: return "task text out of bounds or unsafe";
    case CK_CTX_E_LIMIT: return "assembled prompt over the context limit";
    case CK_CTX_E_STATE: return "context assembly misuse";
    }
    return "?";
}
