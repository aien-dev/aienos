/* context_proposal.c -- see context_proposal.h. No kernel calls, no libc. */
#include "context_proposal.h"
#include "../../argus/sha256.h"

static const char hx[] = "0123456789abcdef";

void ck_prop_clear(ck_prop *p)
{
    size_t i;
    uint8_t *b = (uint8_t *)p;
    for (i = 0; i < sizeof *p; i++) b[i] = 0;
}

static void le(sha256_ctx *h, uint64_t v, unsigned n)
{
    uint8_t b[8];
    unsigned i;
    for (i = 0; i < n; i++) b[i] = (uint8_t)(v >> (8 * i));
    sha256_update(h, b, n);
}

void ck_prop_bind(ck_prop *p, const uint8_t agent[32], uint64_t inc, uint64_t seq, uint64_t gen, uint16_t kind,
                  const uint8_t *bytes, size_t len)
{
    static const char dom[] = "aienos.commit.key.v1";
    sha256_ctx h;
    ck_prop_clear(p);
    sha256_hash(bytes, len, p->sha);
    p->inc = inc;
    p->seq = seq;
    p->gen = gen;
    p->kind = kind;
    p->len = len;
    sha256_init(&h);
    sha256_update(&h, (const uint8_t *)dom, sizeof dom); /* with its 0x00 */
    sha256_update(&h, agent, 32);
    le(&h, inc, 8);
    le(&h, seq, 8);
    le(&h, gen, 8);
    le(&h, kind, 2);
    sha256_update(&h, p->sha, 32);
    sha256_final(&h, p->key);
    p->active = 1;
}

int ck_prop_check(const ck_prop *p, uint64_t gen_now, uint16_t kind, const uint8_t *bytes, size_t len)
{
    uint8_t d[32];
    unsigned i, diff = 0;
    if (!p->active) return CK_PROP_E_ABSENT;
    if (kind != p->kind || len != p->len) return CK_PROP_E_CHANGED;
    sha256_hash(bytes, len, d);
    for (i = 0; i < 32; i++) diff |= (unsigned)(d[i] ^ p->sha[i]);
    if (diff) return CK_PROP_E_CHANGED;
    if (gen_now != p->gen) return CK_PROP_E_STALE;
    return CK_PROP_OK;
}

static size_t put_s(char *o, size_t n, size_t cap, const char *s)
{
    while (*s) {
        if (n < cap) o[n] = *s;
        n++;
        s++;
    }
    return n;
}
static size_t put_u(char *o, size_t n, size_t cap, uint64_t v)
{
    char t[21];
    int k = 0;
    do { t[k++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (k) {
        if (n < cap) o[n] = t[--k];
        else k--;
        n++;
    }
    return n;
}
static size_t put_h(char *o, size_t n, size_t cap, const uint8_t *b, size_t m)
{
    size_t i;
    for (i = 0; i < m; i++) {
        if (n < cap) o[n] = hx[b[i] >> 4];
        n++;
        if (n < cap) o[n] = hx[b[i] & 15];
        n++;
    }
    return n;
}

size_t ck_prop_trailer(const ck_prop *p, char *o, size_t cap)
{
    size_t n = 0;
    if (!p->active || !o) return 0;
    n = put_s(o, n, cap, "\nrequest: inc=");
    n = put_u(o, n, cap, p->inc);
    n = put_s(o, n, cap, " seq=");
    n = put_u(o, n, cap, p->seq);
    n = put_s(o, n, cap, " gen=");
    n = put_u(o, n, cap, p->gen);
    n = put_s(o, n, cap, "\nsha256: ");
    n = put_h(o, n, cap, p->sha, 32);
    n = put_s(o, n, cap, "\nkey: ");
    n = put_h(o, n, cap, p->key, 32);
    n = put_s(o, n, cap, "\n");
    return n <= cap ? n : 0;
}

int ck_prop_has_key(const uint8_t *obj, size_t len, const uint8_t key[32])
{
    static const char tag[] = "key: ";
    const size_t line = sizeof tag - 1 + 64 + 1;
    size_t i, at;
    if (!obj || len < line) return 0;
    at = len - line;
    if (at > 0 && obj[at - 1] != '\n') return 0; /* the key line starts a line */
    for (i = 0; i < sizeof tag - 1; i++)
        if (obj[at + i] != (uint8_t)tag[i]) return 0;
    at += sizeof tag - 1;
    for (i = 0; i < 32; i++)
        if (obj[at + 2 * i] != (uint8_t)hx[key[i] >> 4] || obj[at + 2 * i + 1] != (uint8_t)hx[key[i] & 15]) return 0;
    return obj[len - 1] == '\n';
}

const char *ck_prop_strerror(int rc)
{
    switch (rc) {
    case CK_PROP_OK: return "ok";
    case CK_PROP_E_ABSENT: return "no proposal bound";
    case CK_PROP_E_CHANGED: return "proposal changed: the bytes differ from the ones shown";
    case CK_PROP_E_STALE: return "stale proposal: the Store generation moved since it was shown (cancel and resubmit)";
    }
    return "?";
}
