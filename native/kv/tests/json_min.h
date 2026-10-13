/* json_min.h -- a small strict JSON reader for the golden vector files, used by
 * the hosted tests only (it allocates). Handles objects, arrays, strings with
 * the usual escapes, unsigned integers up to 2^64-1, true, false and null.
 * Anything else (negative numbers, fractions, exponents) is refused, so a
 * vector file that changes shape fails loudly instead of being half-read. */
#ifndef KV_TESTS_JSON_MIN_H
#define KV_TESTS_JSON_MIN_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } jtype;

typedef struct jv {
    jtype t;
    int b;
    uint64_t num;
    char *s; /* NUL-terminated copy; slen excludes the NUL */
    size_t slen;
    struct jv *kids; /* array elements or object values */
    char **keys;     /* object keys, parallel to kids */
    size_t n;
} jv;

typedef struct {
    const char *p;
    const char *end;
    const char *err;
} jparser;

static void j_ws(jparser *q)
{
    while (q->p < q->end && (*q->p == ' ' || *q->p == '\n' || *q->p == '\t' || *q->p == '\r')) q->p++;
}

static int j_value(jparser *q, jv *out);

static int j_string(jparser *q, char **s, size_t *len)
{
    size_t cap = 16, n = 0;
    char *buf = malloc(cap);
    if (!buf || q->p >= q->end || *q->p != '"') { q->err = "expected string"; free(buf); return -1; }
    q->p++;
    while (q->p < q->end && *q->p != '"') {
        char c = *q->p++;
        if (c == '\\') {
            if (q->p >= q->end) { q->err = "bad escape"; free(buf); return -1; }
            c = *q->p++;
            switch (c) {
            case 'n': c = '\n'; break;
            case 't': c = '\t'; break;
            case 'r': c = '\r'; break;
            case '"': case '\\': case '/': break;
            default: q->err = "unsupported escape"; free(buf); return -1;
            }
        }
        if (n + 2 > cap) {
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) { free(buf); q->err = "oom"; return -1; }
            buf = nb;
        }
        buf[n++] = c;
    }
    if (q->p >= q->end) { q->err = "unterminated string"; free(buf); return -1; }
    q->p++;
    buf[n] = 0;
    *s = buf;
    *len = n;
    return 0;
}

static int j_value(jparser *q, jv *out)
{
    memset(out, 0, sizeof *out);
    j_ws(q);
    if (q->p >= q->end) { q->err = "unexpected end"; return -1; }
    char c = *q->p;
    if (c == '"') { out->t = J_STR; return j_string(q, &out->s, &out->slen); }
    if (c == '{' || c == '[') {
        int obj = c == '{';
        char close = obj ? '}' : ']';
        size_t cap = 0;
        out->t = obj ? J_OBJ : J_ARR;
        q->p++;
        j_ws(q);
        if (q->p < q->end && *q->p == close) { q->p++; return 0; }
        for (;;) {
            if (out->n == cap) {
                cap = cap ? cap * 2 : 8;
                jv *nk = realloc(out->kids, cap * sizeof *nk);
                if (!nk) { q->err = "oom"; return -1; }
                out->kids = nk;
                if (obj) {
                    char **nks = realloc(out->keys, cap * sizeof *nks);
                    if (!nks) { q->err = "oom"; return -1; }
                    out->keys = nks;
                }
            }
            if (obj) {
                size_t kl;
                j_ws(q);
                if (j_string(q, &out->keys[out->n], &kl) != 0) return -1;
                j_ws(q);
                if (q->p >= q->end || *q->p != ':') { q->err = "expected colon"; return -1; }
                q->p++;
            }
            if (j_value(q, &out->kids[out->n]) != 0) return -1;
            out->n++;
            j_ws(q);
            if (q->p < q->end && *q->p == ',') { q->p++; continue; }
            if (q->p < q->end && *q->p == close) { q->p++; return 0; }
            q->err = "expected comma or close";
            return -1;
        }
    }
    if (c >= '0' && c <= '9') {
        uint64_t v = 0;
        out->t = J_NUM;
        while (q->p < q->end && *q->p >= '0' && *q->p <= '9') {
            uint64_t d = (uint64_t)(*q->p - '0');
            if (v > (UINT64_MAX - d) / 10) { q->err = "number over 2^64-1"; return -1; }
            v = v * 10 + d;
            q->p++;
        }
        if (q->p < q->end && (*q->p == '.' || *q->p == 'e' || *q->p == 'E')) { q->err = "fraction or exponent"; return -1; }
        out->num = v;
        return 0;
    }
    if (q->end - q->p >= 4 && memcmp(q->p, "true", 4) == 0) { out->t = J_BOOL; out->b = 1; q->p += 4; return 0; }
    if (q->end - q->p >= 5 && memcmp(q->p, "false", 5) == 0) { out->t = J_BOOL; out->b = 0; q->p += 5; return 0; }
    if (q->end - q->p >= 4 && memcmp(q->p, "null", 4) == 0) { out->t = J_NULL; q->p += 4; return 0; }
    q->err = "unexpected character";
    return -1;
}

/* Read a whole file. Returns a malloc'd NUL-terminated buffer or NULL. */
static char *j_read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 1 << 16, n = 0;
    char *buf = malloc(cap + 1);
    while (buf) {
        size_t r = fread(buf + n, 1, cap - n, f);
        n += r;
        if (n < cap) break;
        cap *= 2;
        char *nb = realloc(buf, cap + 1);
        if (!nb) { free(buf); buf = NULL; }
        else buf = nb;
    }
    fclose(f);
    if (buf) { buf[n] = 0; *len = n; }
    return buf;
}

/* Parse a whole document; *root is filled. Returns 0, or -1 with a message. */
static int j_parse(const char *text, size_t len, jv *root, const char **err)
{
    jparser q = {text, text + len, NULL};
    if (j_value(&q, root) != 0) { *err = q.err; return -1; }
    j_ws(&q);
    if (q.p != q.end) { *err = "trailing data"; return -1; }
    return 0;
}

static const jv *j_get(const jv *o, const char *key)
{
    if (!o || o->t != J_OBJ) return NULL;
    for (size_t i = 0; i < o->n; i++)
        if (strcmp(o->keys[i], key) == 0) return &o->kids[i];
    return NULL;
}

#endif /* KV_TESTS_JSON_MIN_H */
