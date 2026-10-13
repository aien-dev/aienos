/*
 * kv_record_test.c -- tests for native/kv/kv_record.c (aienos#367, cut N1).
 *
 * The C codec is checked against two golden files:
 *   tests/golden/kv_record_v1.json  copied byte for byte from sovereign-core
 *                                   (crates/aien-kv-store/tests/golden), pinned by CONTRACT.lock
 *   tests/golden/kv_slot_v1.json    native slot header unit and envelope id vectors,
 *                                   produced by tests/gen_slot_vectors.sh with shell tools only
 * and against the corruption cases of the Rust crate (tests/validate_tests.rs,
 * identity_tests.rs, record_tests.rs), re-expressed here with the same names.
 *
 * Usage: kv_record_test [golden_dir [lock_file]]   (defaults: tests/golden CONTRACT.lock)
 * The test refuses to run if a vectors file does not match the sha256 in the lock.
 * Hosted libc only in this file; kv_record.c itself imports no heap.
 */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json_min.h"
#include "kv_record.h"

/* ---- allocation counter (GNU ld --wrap) -------------------------------- */
#ifdef KV_WRAP_ALLOC
static int g_armed;
static unsigned long g_allocs;
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
void *__wrap_malloc(size_t n) { if (g_armed) g_allocs++; return __real_malloc(n); }
void *__wrap_calloc(size_t a, size_t b) { if (g_armed) g_allocs++; return __real_calloc(a, b); }
void *__wrap_realloc(void *p, size_t n) { if (g_armed) g_allocs++; return __real_realloc(p, n); }
#define ALLOC_BEGIN() do { g_allocs = 0; g_armed = 1; } while (0)
#define ALLOC_END() (g_armed = 0, g_allocs)
#define HAVE_ALLOC_COUNTER 1
#else
#define ALLOC_BEGIN() ((void)0)
#define ALLOC_END() 0ul
#define HAVE_ALLOC_COUNTER 0
#endif

/* ---- tiny harness ------------------------------------------------------ */
static const char *g_test;
static int g_fails;
static int g_checks;

#define CHECK(cond) do { g_checks++; if (!(cond)) { g_fails++; \
    printf("  FAIL %s: %s (line %d)\n", g_test, #cond, __LINE__); } } while (0)
#define CHECK_RC(got, want) do { int g_ = (got), w_ = (want); g_checks++; if (g_ != w_) { g_fails++; \
    printf("  FAIL %s: %s = %d, want %d (line %d)\n", g_test, #got, g_, w_, __LINE__); } } while (0)
#define CHECK_MEM(a, b, n) CHECK(memcmp((a), (b), (n)) == 0)

static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "kv_record_test: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(2);
}

/* ---- hex and json helpers ---------------------------------------------- */
static int hexv(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static void unhex(const char *s, size_t nbytes, uint8_t *out)
{
    if (strlen(s) != nbytes * 2) die("hex string of length %zu, want %zu bytes", strlen(s), nbytes * 2 / 2);
    for (size_t i = 0; i < nbytes; i++) {
        int h = hexv(s[2 * i]), l = hexv(s[2 * i + 1]);
        if (h < 0 || l < 0) die("bad hex digit");
        out[i] = (uint8_t)(h << 4 | l);
    }
}

/* A codec call that must work for the fixtures but does not (the red stub): count it as a failure and carry on. */
static void soft(const char *what)
{
    g_fails++;
    g_checks++;
    printf("  FAIL %s: %s refused\n", g_test ? g_test : "(setup)", what);
}

static const jv *J(const jv *o, const char *k)
{
    const jv *v = j_get(o, k);
    if (!v) die("golden file lacks key \"%s\"", k);
    return v;
}
static uint64_t JN(const jv *o, const char *k)
{
    const jv *v = J(o, k);
    if (v->t != J_NUM) die("key \"%s\" is not a number", k);
    return v->num;
}
static const char *JS(const jv *o, const char *k)
{
    const jv *v = J(o, k);
    if (v->t != J_STR) die("key \"%s\" is not a string", k);
    return v->s;
}
static size_t JSL(const jv *o, const char *k) { J(o, k); return j_get(o, k)->slen; }
static int JB(const jv *o, const char *k)
{
    const jv *v = J(o, k);
    if (v->t != J_BOOL) die("key \"%s\" is not a bool", k);
    return v->b;
}
static void JH(const jv *o, const char *k, uint8_t *out, size_t n) { unhex(JS(o, k), n, out); }

static uint32_t f32_bits(float f) { uint32_t b; memcpy(&b, &f, 4); return b; }
static uint64_t f64_bits(double d) { uint64_t b; memcpy(&b, &d, 8); return b; }

static void put32(uint8_t *b, size_t off, uint32_t v) { for (int i = 0; i < 4; i++) b[off + i] = (uint8_t)(v >> (8 * i)); }
static void put64(uint8_t *b, size_t off, uint64_t v) { for (int i = 0; i < 8; i++) b[off + i] = (uint8_t)(v >> (8 * i)); }
static uint32_t get32(const uint8_t *b, size_t off) { uint32_t v = 0; for (int i = 3; i >= 0; i--) v = v << 8 | b[off + i]; return v; }
static uint64_t get64(const uint8_t *b, size_t off) { uint64_t v = 0; for (int i = 7; i >= 0; i--) v = v << 8 | b[off + i]; return v; }
static uint16_t get16(const uint8_t *b, size_t off) { return (uint16_t)(b[off] | b[off + 1] << 8); }

static void sha(const void *d, size_t n, uint8_t out[32]) { sha256_hash((const uint8_t *)d, n, out); }

/* Struct equality through the wire encoding (the structs have padding bytes). */
static int rec_eq(const kv_record_header *a, const kv_record_header *b)
{
    uint8_t x[KV_HEADER_LEN], y[KV_HEADER_LEN];
    kv_header_encode(a, x);
    kv_header_encode(b, y);
    return memcmp(x, y, sizeof x) == 0;
}
static int chunk_eq(const kv_chunk_header *a, const kv_chunk_header *b)
{
    kv_record_header x, y;
    memset(&x, 0, sizeof x);
    memset(&y, 0, sizeof y);
    x.chunk = *a;
    y.chunk = *b;
    return rec_eq(&x, &y);
}

/* ---- parse golden inputs ----------------------------------------------- */
static void parse_cc(const jv *v, kv_compute_config *c)
{
    memset(c, 0, sizeof *c);
    c->num_heads = (uint32_t)JN(v, "num_heads");
    c->hidden_dim = JN(v, "hidden_dim");
    c->intermediate_dim = JN(v, "intermediate_dim");
    c->vocab_size = JN(v, "vocab_size");
    c->rms_norm_eps_bits = (uint32_t)JN(v, "rms_norm_eps_f32_bits");
    c->tie_word_embeddings = (uint8_t)JB(v, "tie_word_embeddings");
    c->hidden_act = (uint8_t)JN(v, "hidden_act");
    c->arith_id = JS(v, "arith_id");
    c->arith_id_len = JSL(v, "arith_id");
    c->arith_epoch = (uint32_t)JN(v, "arith_epoch");
}

static void parse_ns(const jv *v, kv_namespace_fields *f)
{
    memset(f, 0, sizeof *f);
    JH(v, "model_sha256", f->model_sha256, 32);
    f->model_digest_kind = JS(v, "model_digest_kind");
    f->model_digest_kind_len = JSL(v, "model_digest_kind");
    f->model_id = JS(v, "model_id");
    f->model_id_len = JSL(v, "model_id");
    f->num_layers = (uint32_t)JN(v, "num_layers");
    f->num_kv_heads = (uint32_t)JN(v, "num_kv_heads");
    f->head_dim = (uint32_t)JN(v, "head_dim");
    f->block_size = (uint32_t)JN(v, "block_size");
    f->rope_theta_bits = (uint32_t)JN(v, "rope_theta_f32_bits");
    const jv *r = J(v, "rope_scaling");
    if (r->t == J_OBJ) {
        f->rope_scaling.present = 1;
        f->rope_scaling.factor_bits = JN(r, "factor_f64_bits");
        f->rope_scaling.low_freq_factor_bits = JN(r, "low_freq_factor_f64_bits");
        f->rope_scaling.high_freq_factor_bits = JN(r, "high_freq_factor_f64_bits");
        f->rope_scaling.original_max_position_embeddings = JN(r, "original_max_position_embeddings");
    } else if (r->t != J_NULL) {
        die("rope_scaling is neither object nor null");
    }
    f->qk_norm = (uint8_t)JB(v, "qk_norm");
    f->dtype = (uint8_t)JN(v, "dtype");
    const jv *l = J(v, "layout");
    f->layout.head_stride = JN(l, "head_stride");
    f->layout.token_stride = JN(l, "token_stride");
    f->layout.kv_plane_stride = JN(l, "kv_plane_stride");
    f->layout.layer_stride = JN(l, "layer_stride");
    f->layout.block_stride = JN(l, "block_stride");
    f->layout.element_bytes = JN(l, "element_bytes");
    f->backend_format = (uint8_t)JN(v, "backend_format");
    f->chunk_tokens = (uint32_t)JN(v, "chunk_tokens");
    f->sharing_namespace = JS(v, "sharing_namespace");
    f->sharing_namespace_len = JSL(v, "sharing_namespace");
    JH(v, "compute_config_digest", f->compute_config_digest, 32);
}

/* ---- the files, loaded once --------------------------------------------- */
static jv g_rec; /* kv_record_v1.json */
static jv g_slot; /* kv_slot_v1.json */
static char *g_rec_text, *g_slot_text;
static size_t g_rec_len, g_slot_len;

static char *slurp_or_die(const char *path, size_t *len)
{
    char *t = j_read_file(path, len);
    if (!t) die("cannot read %s", path);
    return t;
}

/* ---- sample data (tests/common/mod.rs of the Rust crate) ---------------- */
static kv_compute_config sample_compute(void)
{
    kv_compute_config c;
    memset(&c, 0, sizeof c);
    c.num_heads = 32;
    c.hidden_dim = 2048;
    c.intermediate_dim = 8192;
    c.vocab_size = 128256;
    c.rms_norm_eps_bits = f32_bits(1e-5f);
    c.tie_word_embeddings = 1;
    c.hidden_act = KV_HIDDEN_ACT_SILU;
    c.arith_id = "ReferenceCpuBackend";
    c.arith_id_len = 19;
    c.arith_epoch = 1;
    return c;
}

static kv_namespace_fields sample(void)
{
    kv_namespace_fields f;
    memset(&f, 0, sizeof f);
    memset(f.model_sha256, 0xAB, 32);
    f.model_digest_kind = "sha256-file";
    f.model_digest_kind_len = 11;
    f.model_id = "llama-3.2-1b-instruct";
    f.model_id_len = 21;
    f.num_layers = 16;
    f.num_kv_heads = 8;
    f.head_dim = 64;
    f.block_size = 16;
    f.rope_theta_bits = f32_bits(500000.0f);
    f.rope_scaling.present = 1;
    f.rope_scaling.factor_bits = f64_bits(32.0);
    f.rope_scaling.low_freq_factor_bits = f64_bits(1.0);
    f.rope_scaling.high_freq_factor_bits = f64_bits(4.0);
    f.rope_scaling.original_max_position_embeddings = 8192;
    f.qk_norm = 0;
    f.dtype = KV_DTYPE_BF16;
    f.layout.head_stride = 128;
    f.layout.token_stride = 1024;
    f.layout.kv_plane_stride = 16384;
    f.layout.layer_stride = 32768;
    f.layout.block_stride = 524288;
    f.layout.element_bytes = 2;
    f.backend_format = KV_BACKEND_HOST_PAGED_POOL_V1;
    f.chunk_tokens = 256;
    f.sharing_namespace = "default";
    f.sharing_namespace_len = 7;
    kv_compute_config c = sample_compute();
    if (kv_compute_config_digest(&c, f.compute_config_digest) != KV_OK) soft("sample compute digest");
    return f;
}

static kv_namespace_fields small_ns(void)
{
    kv_namespace_fields f = sample();
    f.block_size = 4;
    f.chunk_tokens = 8;
    f.layout.kv_plane_stride = 4 * 1024;
    f.layout.layer_stride = 8 * 1024;
    f.layout.block_stride = 16 * 8 * 1024;
    return f;
}

static void seg_digests(const char *tag, uint32_t n, uint8_t (*out)[32])
{
    char buf[64];
    for (uint32_t j = 0; j < n; j++) {
        int l = snprintf(buf, sizeof buf, "%s/seg/%u", tag, (unsigned)j);
        sha(buf, (size_t)l, out[j]);
    }
}

static kv_chunk_header sample_chunk_header(void)
{
    kv_namespace_fields f = sample();
    uint8_t ns[32], key[32];
    uint32_t tokens[256];
    for (uint32_t i = 0; i < 256; i++) tokens[i] = i;
    if (kv_namespace_id(&f, ns) != KV_OK) soft("sample ns");
    if (kv_chunk_key(ns, NULL, 0, tokens, 256, key) != KV_OK) soft("sample key");
    kv_chunk_header h;
    memset(&h, 0, sizeof h);
    if (kv_chunk_header_build(&f, ns, key, NULL, 0, 256, UINT64_C(1700000000000000000), &h) != KV_OK) soft("sample header");
    return h;
}

static uint8_t g_sample_digests[KV_MAX_SEGMENTS][32];

static kv_record_header sample_record(uint32_t *n_out)
{
    kv_record_header r;
    kv_namespace_fields f = sample();
    r.chunk = sample_chunk_header();
    uint32_t n = 0;
    if (kv_ns_segment_count(&f, r.chunk.token_count, &n) != KV_OK) soft("sample seg count");
    seg_digests("sample", n, g_sample_digests);
    kv_payload_root((const uint8_t(*)[32])g_sample_digests, n, r.payload_sha256);
    *n_out = n;
    return r;
}

/* ======================================================================== */
/* pin                                                                       */
/* ======================================================================== */

static void tohex(const uint8_t *b, size_t n, char *out)
{
    static const char D[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2 * i] = D[b[i] >> 4]; out[2 * i + 1] = D[b[i] & 15]; }
    out[2 * n] = 0;
}

/* Value of "key = value" in the lock, copied into a static buffer (valid until
 * the next call), or NULL. Comment lines start with '#'. */
static const char *lock_value(const char *buf, const char *key)
{
    static char val[256];
    size_t kl = strlen(key);
    for (const char *line = buf; *line;) {
        size_t ll = strcspn(line, "\n");
        if (line[0] != '#' && ll > kl + 3 && strncmp(line, key, kl) == 0 && strncmp(line + kl, " = ", 3) == 0) {
            size_t vl = ll - kl - 3;
            if (vl >= sizeof val) die("CONTRACT.lock: value of %s is too long", key);
            memcpy(val, line + kl + 3, vl);
            val[vl] = 0;
            return val;
        }
        line += ll;
        if (*line == '\n') line++;
    }
    return NULL;
}

/* The gate: runs before anything else and aborts the whole run on a mismatch. */
static void pin_gate(const char *lock_path)
{
    size_t ll;
    char *lock = slurp_or_die(lock_path, &ll);
    uint8_t d[32];
    char hx[65], want[256], sc[256];
    const char *v = lock_value(lock, "format_version");
    if (!v || strcmp(v, "1") != 0) die("CONTRACT.lock: format_version is not 1");
    v = lock_value(lock, "vectors_sha256");
    snprintf(want, sizeof want, "%s", v ? v : "(missing)");
    sha(g_rec_text, g_rec_len, d);
    tohex(d, 32, hx);
    if (strcmp(want, hx) != 0)
        die("REFUSED: kv_record_v1.json sha256 %s differs from CONTRACT.lock vectors_sha256 %s", hx, want);
    v = lock_value(lock, "slot_vectors_sha256");
    snprintf(want, sizeof want, "%s", v ? v : "(missing)");
    sha(g_slot_text, g_slot_len, d);
    tohex(d, 32, hx);
    if (strcmp(want, hx) != 0)
        die("REFUSED: kv_slot_v1.json sha256 %s differs from CONTRACT.lock slot_vectors_sha256 %s", hx, want);
    v = lock_value(lock, "sc_commit");
    snprintf(sc, sizeof sc, "%s", v ? v : "");
    if (strlen(sc) != 40) die("CONTRACT.lock: sc_commit is not a 40-hex commit id");
    for (int i = 0; i < 40; i++)
        if (hexv(sc[i]) < 0) die("CONTRACT.lock: sc_commit is not hex");
    if (!lock_value(lock, "sc_adr")) die("CONTRACT.lock: sc_adr missing");
    printf("pin: kv_record_v1.json and kv_slot_v1.json match CONTRACT.lock (sc_commit %.12s)\n", sc);
    free(lock);
}

/* ======================================================================== */
/* identity                                                                  */
/* ======================================================================== */

static void golden_vectors_include_compute_config_digest(void)
{
    const jv *vs = J(&g_rec, "vectors");
    CHECK(JN(&g_rec, "format_version") == 1);
    CHECK(vs->n == 6);
    for (size_t i = 0; i < vs->n; i++) {
        const jv *ns = J(&vs->kids[i], "namespace");
        kv_compute_config c;
        parse_cc(J(ns, "compute_config"), &c);
        uint8_t got[32], want[32];
        CHECK_RC(kv_compute_config_digest(&c, got), KV_OK);
        JH(ns, "compute_config_digest", want, 32);
        CHECK_MEM(got, want, 32);
    }
}

typedef struct {
    uint8_t seg[KV_MAX_SEGMENTS][32];
} segbuf;

static void identity_vectors_match_golden(void)
{
    const jv *vs = J(&g_rec, "vectors");
    int total_chunks = 0;
    for (size_t vi = 0; vi < vs->n; vi++) {
        const jv *v = &vs->kids[vi];
        const char *name = JS(v, "name");
        kv_namespace_fields f;
        parse_ns(J(v, "namespace"), &f);
        const jv *exp = J(v, "expected");
        uint8_t ns[32], want32[32];
        CHECK_RC(kv_namespace_id(&f, ns), KV_OK);
        JH(exp, "namespace_id", want32, 32);
        CHECK_MEM(ns, want32, 32);

        const jv *tok = J(v, "tokens");
        uint32_t *tokens = malloc(tok->n * sizeof *tokens + 4);
        for (size_t i = 0; i < tok->n; i++) {
            if (tok->kids[i].t != J_NUM || tok->kids[i].num > UINT32_MAX) die("token out of range");
            tokens[i] = (uint32_t)tok->kids[i].num;
        }
        const jv *chunks = J(exp, "chunks");
        uint8_t(*keys)[32] = malloc((chunks->n + 1) * 32);
        size_t nk = 0;
        CHECK_RC(kv_chunk_chain(ns, f.chunk_tokens, tokens, tok->n, keys, chunks->n + 1, &nk), KV_OK);
        CHECK(nk == chunks->n);

        for (size_t ci = 0; ci < chunks->n && ci < nk; ci++) {
            const jv *c = &chunks->kids[ci];
            total_chunks++;
            uint8_t key[32], parent[32], hdr_want[KV_HEADER_LEN], hdr[KV_HEADER_LEN];
            JH(c, "chunk_key", key, 32);
            CHECK_MEM(keys[ci], key, 32);
            JH(c, "parent_key", parent, 32);
            uint32_t start = (uint32_t)JN(c, "first_position");
            uint32_t count = (uint32_t)JN(c, "token_count");
            CHECK(start == ci * f.chunk_tokens);
            uint64_t written = UINT64_C(1700000000000000000) + ci;
            CHECK(JN(c, "written_unix_ns") == written);
            /* a chunk key recomputed on its own, with the parent from the file */
            uint8_t key2[32];
            CHECK_RC(kv_chunk_key(ns, ci ? parent : NULL, start, tokens + start, count, key2), KV_OK);
            CHECK_MEM(key2, key, 32);

            kv_chunk_header h;
            CHECK_RC(kv_chunk_header_build(&f, ns, key, ci ? parent : NULL, start, count, written, &h), KV_OK);
            CHECK(h.payload_len == JN(c, "payload_len"));
            uint32_t nseg = 0;
            uint64_t sbytes = 0;
            CHECK_RC(kv_ns_segment_count(&f, count, &nseg), KV_OK);
            CHECK_RC(kv_segment_bytes(&f, count, &sbytes), KV_OK);
            CHECK(nseg == JN(c, "segment_count"));
            CHECK(sbytes == JN(c, "segment_bytes"));

            /* segment digests: SHA-256 of "<name>/<i>/seg/<j>" */
            const jv *sd = J(c, "segment_digests");
            CHECK(sd->n == nseg);
            char prefix[160];
            snprintf(prefix, sizeof prefix, "%s/%zu/seg/<j>", name, ci);
            CHECK(strcmp(JS(c, "segment_digests_of_ascii"), prefix) == 0);
            segbuf *sb = malloc(sizeof *sb);
            snprintf(prefix, sizeof prefix, "%s/%zu", name, ci);
            seg_digests(prefix, nseg, sb->seg);
            for (uint32_t j = 0; j < nseg && j < sd->n; j++) {
                CHECK(sd->kids[j].t == J_STR);
                unhex(sd->kids[j].s, 32, want32);
                CHECK_MEM(sb->seg[j], want32, 32);
            }
            kv_record_header rec;
            rec.chunk = h;
            kv_payload_root((const uint8_t(*)[32])sb->seg, nseg, rec.payload_sha256);
            JH(c, "payload_sha256", want32, 32);
            CHECK_MEM(rec.payload_sha256, want32, 32);

            /* header bytes, byte for byte, and the decode/re-encode round trip */
            unhex(JS(c, "header_hex"), KV_HEADER_LEN, hdr_want);
            kv_header_encode(&rec, hdr);
            CHECK_MEM(hdr, hdr_want, KV_HEADER_LEN);
            kv_record_header back;
            CHECK_RC(kv_header_decode_struct(hdr_want, KV_HEADER_LEN, &back), KV_OK);
            CHECK_MEM(&back.chunk.namespace_id, ns, 32);
            CHECK(back.chunk.payload_len == h.payload_len && back.chunk.written_unix_ns == written);
            uint8_t again[KV_HEADER_LEN];
            kv_header_encode(&back, again);
            CHECK_MEM(again, hdr_want, KV_HEADER_LEN);

            /* the 4096-byte region and the validator */
            uint8_t region[KV_HEADER_REGION_LEN];
            CHECK_RC(kv_region_encode(&rec, (const uint8_t(*)[32])sb->seg, nseg, region), KV_OK);
            CHECK_MEM(region, hdr_want, KV_HEADER_LEN);
            sha(region, sizeof region, want32);
            uint8_t rs[32];
            JH(c, "region_sha256", rs, 32);
            CHECK_MEM(want32, rs, 32);
            kv_record_header vout;
            CHECK_RC(kv_validate_record(region, sizeof region, KV_PAYLOAD_OFFSET + h.payload_len, &h, sbytes, &vout), KV_OK);
            CHECK(rec_eq(&vout, &rec));
            CHECK_RC(kv_header_decode(region, sizeof region, &back), KV_OK);
            free(sb);
        }
        free(tokens);
        free(keys);
    }
    CHECK(total_chunks == 14);
}

typedef void (*ns_mut)(kv_namespace_fields *);
#define NSM(id, body) static void id(kv_namespace_fields *f) { body }
NSM(m_model_sha, f->model_sha256[31] ^= 1;)
NSM(m_kind, f->model_digest_kind = "blake3-file"; f->model_digest_kind_len = 11;)
NSM(m_model_id, f->model_id = "llama-3.2-3b-instruct"; f->model_id_len = 21;)
NSM(m_layers, f->num_layers += 1;)
NSM(m_kvheads, f->num_kv_heads += 1;)
NSM(m_head_dim, f->head_dim += 1;)
NSM(m_block, f->block_size = 8;)
NSM(m_theta, f->rope_theta_bits = f32_bits(10000.0f);)
NSM(m_rope_none, memset(&f->rope_scaling, 0, sizeof f->rope_scaling);)
NSM(m_rope_factor, f->rope_scaling.factor_bits = f64_bits(8.0);)
NSM(m_rope_low, f->rope_scaling.low_freq_factor_bits = f64_bits(2.0);)
NSM(m_rope_high, f->rope_scaling.high_freq_factor_bits = f64_bits(8.0);)
NSM(m_rope_orig, f->rope_scaling.original_max_position_embeddings = 4096;)
NSM(m_qk, f->qk_norm = 1;)
NSM(m_dtype, f->dtype = KV_DTYPE_FP16;)
NSM(m_l_head, f->layout.head_stride += 2;)
NSM(m_l_token, f->layout.token_stride += 2;)
NSM(m_l_plane, f->layout.kv_plane_stride += 2;)
NSM(m_l_layer, f->layout.layer_stride += 2;)
NSM(m_l_block, f->layout.block_stride += 2;)
NSM(m_l_elem, f->layout.element_bytes = 4;)
NSM(m_backend, f->backend_format = KV_BACKEND_NATIVE_F32_DECODE_STATE_V1;)
NSM(m_chunk_tokens, f->chunk_tokens = 512;)
NSM(m_sharing, f->sharing_namespace = "tenant-b"; f->sharing_namespace_len = 8;)
NSM(m_cfg_digest, f->compute_config_digest[0] ^= 1;)

static void namespace_changes_when_any_field_changes(void)
{
    static const struct { const char *name; ns_mut fn; } M[] = {
        {"model_sha256", m_model_sha}, {"model_digest_kind", m_kind}, {"model_id", m_model_id},
        {"num_layers", m_layers}, {"num_kv_heads", m_kvheads}, {"head_dim", m_head_dim},
        {"block_size", m_block}, {"rope_theta", m_theta}, {"rope_scaling_none", m_rope_none},
        {"rope_factor", m_rope_factor}, {"rope_low", m_rope_low}, {"rope_high", m_rope_high},
        {"rope_original_max", m_rope_orig}, {"qk_norm", m_qk}, {"dtype", m_dtype},
        {"layout_head_stride", m_l_head}, {"layout_token_stride", m_l_token},
        {"layout_kv_plane_stride", m_l_plane}, {"layout_layer_stride", m_l_layer},
        {"layout_block_stride", m_l_block}, {"layout_element_bytes", m_l_elem},
        {"backend_format", m_backend}, {"chunk_tokens", m_chunk_tokens},
        {"sharing_namespace", m_sharing}, {"compute_config_digest", m_cfg_digest},
    };
    enum { N = sizeof M / sizeof M[0] };
    uint8_t seen[N + 1][32];
    kv_namespace_fields b = sample();
    CHECK_RC(kv_namespace_id(&b, seen[0]), KV_OK);
    for (int i = 0; i < N; i++) {
        kv_namespace_fields f = sample();
        M[i].fn(&f);
        CHECK_RC(kv_namespace_id(&f, seen[i + 1]), KV_OK);
        for (int j = 0; j <= i; j++) {
            if (memcmp(seen[i + 1], seen[j], 32) == 0) {
                g_fails++;
                printf("  FAIL %s: %s collides with entry %d\n", g_test, M[i].name, j);
            }
        }
    }
    uint8_t again[32];
    CHECK_RC(kv_namespace_id(&b, again), KV_OK);
    CHECK_MEM(again, seen[0], 32);
    /* 14 field rows expand to 25 mutators; the base is the 26th id. */
    CHECK(N + 1 == 26);
}

static void rope_scaling_presence_is_distinct_from_zeroed_scaling(void)
{
    kv_namespace_fields a = sample(), b = sample();
    uint8_t ia[32], ib[32];
    memset(&a.rope_scaling, 0, sizeof a.rope_scaling);
    memset(&b.rope_scaling, 0, sizeof b.rope_scaling);
    b.rope_scaling.present = 1;
    CHECK_RC(kv_namespace_id(&a, ia), KV_OK);
    CHECK_RC(kv_namespace_id(&b, ib), KV_OK);
    CHECK(memcmp(ia, ib, 32) != 0);
}

static void namespace_refuses_oversized_or_inconsistent_fields(void)
{
    uint8_t id[32];
    static char big[300];
    memset(big, 'x', sizeof big);
    kv_namespace_fields f = sample();
    f.sharing_namespace = big;
    f.sharing_namespace_len = 65;
    CHECK_RC(kv_namespace_id(&f, id), KV_E_FIELD_TOO_LONG);
    f.sharing_namespace_len = 64;
    CHECK_RC(kv_namespace_id(&f, id), KV_OK);

    f = sample();
    f.model_digest_kind = big;
    f.model_digest_kind_len = 256;
    CHECK_RC(kv_namespace_id(&f, id), KV_E_FIELD_TOO_LONG);
    f.model_digest_kind_len = 255;
    CHECK_RC(kv_namespace_id(&f, id), KV_OK);

    static char huge[65537];
    memset(huge, 'y', sizeof huge);
    f = sample();
    f.model_id = huge;
    f.model_id_len = 65536;
    CHECK_RC(kv_namespace_id(&f, id), KV_E_FIELD_TOO_LONG);
    f.model_id_len = 65535;
    CHECK_RC(kv_namespace_id(&f, id), KV_OK);

    f = sample();
    f.chunk_tokens = 250; /* not a multiple of block_size 16 */
    CHECK_RC(kv_namespace_id(&f, id), KV_E_INVALID_GEOMETRY);
    f = sample();
    f.block_size = 0;
    CHECK_RC(kv_namespace_id(&f, id), KV_E_INVALID_GEOMETRY);
    f = sample();
    f.chunk_tokens = 0;
    CHECK_RC(kv_namespace_id(&f, id), KV_E_INVALID_GEOMETRY);
    f = sample();
    f.num_layers = 0;
    CHECK_RC(kv_namespace_id(&f, id), KV_E_INVALID_GEOMETRY);
    f = sample();
    f.layout.block_stride = 0; /* zero byte factor (Rust d690b6e) */
    CHECK_RC(kv_namespace_id(&f, id), KV_E_INVALID_GEOMETRY);
    f = sample();
    f.layout.element_bytes = 0;
    CHECK_RC(kv_namespace_id(&f, id), KV_E_INVALID_GEOMETRY);

    /* C only: values the Rust types cannot hold, and NULL */
    f = sample();
    f.dtype = 0;
    CHECK_RC(kv_namespace_id(&f, id), KV_E_ARG);
    f = sample();
    f.dtype = 6;
    CHECK_RC(kv_namespace_id(&f, id), KV_E_ARG);
    f = sample();
    f.backend_format = 3;
    CHECK_RC(kv_namespace_id(&f, id), KV_E_ARG);
    f = sample();
    f.qk_norm = 2;
    CHECK_RC(kv_namespace_id(&f, id), KV_E_ARG);
    f = sample();
    f.rope_scaling.present = 2;
    CHECK_RC(kv_namespace_id(&f, id), KV_E_ARG);
    f = sample();
    f.model_id = NULL;
    CHECK_RC(kv_namespace_id(&f, id), KV_E_ARG);
    CHECK_RC(kv_namespace_id(NULL, id), KV_E_ARG);
    f = sample();
    CHECK_RC(kv_namespace_id(&f, NULL), KV_E_ARG);
}

static void chunk_key_chain_depends_on_parent_and_position(void)
{
    kv_namespace_fields s = small_ns();
    uint8_t ns[32], k0[32], a[32], b[32], pk1[32], pk2[32];
    uint32_t toks[8];
    for (uint32_t i = 0; i < 8; i++) toks[i] = 100 + i;
    memset(pk1, 1, 32);
    memset(pk2, 2, 32);
    CHECK_RC(kv_namespace_id(&s, ns), KV_OK);
    CHECK_RC(kv_chunk_key(ns, NULL, 0, toks, 8, k0), KV_OK);
    /* parent matters */
    CHECK_RC(kv_chunk_key(ns, pk1, 8, toks, 8, a), KV_OK);
    CHECK_RC(kv_chunk_key(ns, pk2, 8, toks, 8, b), KV_OK);
    CHECK(memcmp(a, b, 32) != 0);
    /* position matters */
    CHECK_RC(kv_chunk_key(ns, pk1, 16, toks, 8, b), KV_OK);
    CHECK(memcmp(a, b, 32) != 0);
    /* namespace matters */
    kv_namespace_fields o = small_ns();
    o.sharing_namespace = "tenant-b";
    o.sharing_namespace_len = 8;
    uint8_t ons[32];
    CHECK_RC(kv_namespace_id(&o, ons), KV_OK);
    CHECK_RC(kv_chunk_key(ons, NULL, 0, toks, 8, b), KV_OK);
    CHECK(memcmp(k0, b, 32) != 0);
    /* tokens and token count matter */
    uint32_t t2[8];
    memcpy(t2, toks, sizeof t2);
    t2[7] += 1;
    CHECK_RC(kv_chunk_key(ns, NULL, 0, t2, 8, b), KV_OK);
    CHECK(memcmp(k0, b, 32) != 0);
    CHECK_RC(kv_chunk_key(ns, NULL, 0, toks, 7, b), KV_OK);
    CHECK(memcmp(k0, b, 32) != 0);
    /* the first chunk uses an all-zero parent */
    uint8_t zero[32] = {0};
    CHECK_RC(kv_chunk_key(ns, zero, 0, toks, 8, b), KV_OK);
    CHECK_MEM(k0, b, 32);
    /* refusals */
    CHECK_RC(kv_chunk_key(ns, NULL, 0, toks, 0, b), KV_E_TOKEN_COUNT_OUT_OF_RANGE);
    CHECK_RC(kv_chunk_key(ns, NULL, UINT32_MAX - 3, toks, 8, b), KV_E_OVERFLOW);
    CHECK_RC(kv_chunk_key(ns, NULL, UINT32_MAX - 8, toks, 8, b), KV_OK);
    CHECK_RC(kv_chunk_key(NULL, NULL, 0, toks, 8, b), KV_E_ARG);
}

static void chunk_chain_links_each_chunk_to_all_earlier_tokens(void)
{
    kv_namespace_fields s = small_ns();
    uint8_t ns[32];
    uint32_t toks[28];
    for (uint32_t i = 0; i < 28; i++) toks[i] = i;
    CHECK_RC(kv_namespace_id(&s, ns), KV_OK);
    uint8_t c[4][32], d[4][32], e[4][32], k[32];
    size_t n = 0;
    CHECK_RC(kv_chunk_chain(ns, 8, toks, 20, c, 4, &n), KV_OK);
    CHECK(n == 3); /* 8, 8, 4 (partial tail) */
    CHECK_RC(kv_chunk_key(ns, NULL, 0, toks, 8, k), KV_OK);
    CHECK_MEM(c[0], k, 32);
    CHECK_RC(kv_chunk_key(ns, c[0], 8, toks + 8, 8, k), KV_OK);
    CHECK_MEM(c[1], k, 32);
    CHECK_RC(kv_chunk_key(ns, c[1], 16, toks + 16, 4, k), KV_OK);
    CHECK_MEM(c[2], k, 32);
    /* one token in chunk 0 changes every later key */
    uint32_t ch[28];
    memcpy(ch, toks, sizeof ch);
    ch[0] = 999;
    CHECK_RC(kv_chunk_chain(ns, 8, ch, 20, d, 4, &n), KV_OK);
    for (int i = 0; i < 3; i++) CHECK(memcmp(c[i], d[i], 32) != 0);
    /* a token in the tail changes only the tail */
    memcpy(ch, toks, sizeof ch);
    ch[19] = 999;
    CHECK_RC(kv_chunk_chain(ns, 8, ch, 20, d, 4, &n), KV_OK);
    CHECK_MEM(c[0], d[0], 32);
    CHECK_MEM(c[1], d[1], 32);
    CHECK(memcmp(c[2], d[2], 32) != 0);
    /* a longer prompt shares the full-chunk prefix keys, not the short tail key */
    CHECK_RC(kv_chunk_chain(ns, 8, toks, 28, e, 4, &n), KV_OK);
    CHECK(n == 4);
    CHECK_MEM(c[0], e[0], 32);
    CHECK_MEM(c[1], e[1], 32);
    CHECK(memcmp(c[2], e[2], 32) != 0);
    /* empty, zero chunk size, small capacity */
    CHECK_RC(kv_chunk_chain(ns, 8, toks, 0, c, 4, &n), KV_OK);
    CHECK(n == 0);
    CHECK_RC(kv_chunk_chain(ns, 0, toks, 20, c, 4, &n), KV_E_INVALID_GEOMETRY);
    CHECK_RC(kv_chunk_chain(ns, 8, toks, 20, c, 2, &n), KV_E_ARG);
}

/* ---- compute config ----------------------------------------------------- */

static void manual_digest(const kv_compute_config *c, uint8_t act_byte, uint8_t out[32])
{
    sha256_ctx h;
    uint8_t t[8];
    sha256_init(&h);
    sha256_update(&h, (const uint8_t *)"AIEN-PKV-CFG-V1\0", 16);
    put32(t, 0, c->num_heads);
    sha256_update(&h, t, 4);
    put64(t, 0, c->hidden_dim);
    sha256_update(&h, t, 8);
    put64(t, 0, c->intermediate_dim);
    sha256_update(&h, t, 8);
    put64(t, 0, c->vocab_size);
    sha256_update(&h, t, 8);
    put32(t, 0, c->rms_norm_eps_bits);
    sha256_update(&h, t, 4);
    t[0] = c->tie_word_embeddings;
    sha256_update(&h, t, 1);
    t[0] = act_byte;
    sha256_update(&h, t, 1);
    t[0] = (uint8_t)c->arith_id_len;
    sha256_update(&h, t, 1);
    sha256_update(&h, (const uint8_t *)c->arith_id, c->arith_id_len);
    put32(t, 0, c->arith_epoch);
    sha256_update(&h, t, 4);
    sha256_final(&h, out);
}

typedef void (*cfg_mut)(kv_compute_config *);
#define CFM(id, body) static void id(kv_compute_config *c) { body }
CFM(c_heads, c->num_heads = 24;)
CFM(c_hidden, c->hidden_dim = 3072;)
CFM(c_inter, c->intermediate_dim = 8193;)
CFM(c_vocab, c->vocab_size = 128257;)
CFM(c_eps, c->rms_norm_eps_bits = f32_bits(1e-6f);)
CFM(c_tie, c->tie_word_embeddings = 0;)
CFM(c_arith, c->arith_id = "NativeCpuBackend (Rayon Multi-Core)"; c->arith_id_len = 35;)
CFM(c_epoch, c->arith_epoch = 2;)

static void compute_config_digest_changes_with_each_field(void)
{
    static const struct { const char *name; cfg_mut fn; } M[] = {
        {"num_heads", c_heads}, {"hidden_dim", c_hidden}, {"intermediate_dim", c_inter},
        {"vocab_size", c_vocab}, {"rms_norm_eps", c_eps}, {"tie_word_embeddings", c_tie},
        {"arith_id", c_arith}, {"arith_epoch", c_epoch},
    };
    enum { N = sizeof M / sizeof M[0] };
    uint8_t seen[N + 1][32], man[32];
    kv_compute_config base = sample_compute();
    CHECK_RC(kv_compute_config_digest(&base, seen[0]), KV_OK);
    manual_digest(&base, 1, man);
    CHECK_MEM(seen[0], man, 32); /* the implementation equals the ADR formula */
    for (int i = 0; i < N; i++) {
        kv_compute_config c = sample_compute();
        M[i].fn(&c);
        CHECK_RC(kv_compute_config_digest(&c, seen[i + 1]), KV_OK);
        manual_digest(&c, 1, man);
        CHECK_MEM(seen[i + 1], man, 32);
        for (int j = 0; j <= i; j++)
            if (memcmp(seen[i + 1], seen[j], 32) == 0) { g_fails++; printf("  FAIL %s: %s collides with %d\n", g_test, M[i].name, j); }
    }
    /* ninth field: the activation byte is part of the digest */
    manual_digest(&base, 2, man);
    for (int i = 0; i <= N; i++) CHECK(memcmp(seen[i], man, 32) != 0);
    CHECK(N + 1 == 9);
    kv_compute_config bad = sample_compute();
    bad.hidden_act = 2; /* C only: the Rust enum has no such value */
    uint8_t d[32];
    CHECK_RC(kv_compute_config_digest(&bad, d), KV_E_ARG);
    /* a length-prefixed string cannot alias its neighbour */
    kv_compute_config a = sample_compute(), b = sample_compute();
    uint8_t da[32], db[32];
    a.arith_id = "";
    a.arith_id_len = 0;
    b.arith_id = "x";
    b.arith_id_len = 1;
    CHECK_RC(kv_compute_config_digest(&a, da), KV_OK);
    CHECK_RC(kv_compute_config_digest(&b, db), KV_OK);
    CHECK(memcmp(da, db, 32) != 0);
}

static void compute_config_refuses_oversized_arith_id(void)
{
    static char big[300];
    uint8_t d[32];
    memset(big, 'a', sizeof big);
    kv_compute_config c = sample_compute();
    c.arith_id = big;
    c.arith_id_len = 256;
    CHECK_RC(kv_compute_config_digest(&c, d), KV_E_FIELD_TOO_LONG);
    c.arith_id_len = 255;
    CHECK_RC(kv_compute_config_digest(&c, d), KV_OK);
    c.arith_id = NULL;
    CHECK_RC(kv_compute_config_digest(&c, d), KV_E_ARG);
}

/* Review finding 1: same weights, same fields 1-13, different rms_norm_eps. */
static void rms_norm_eps_alone_changes_the_namespace(void)
{
    uint8_t ns_a[32], ns_b[32], ns_a2[32];
    kv_compute_config c;
    kv_namespace_fields f;
    c = sample_compute();
    c.rms_norm_eps_bits = f32_bits(1e-5f);
    f = sample();
    CHECK_RC(kv_compute_config_digest(&c, f.compute_config_digest), KV_OK);
    CHECK_RC(kv_namespace_id(&f, ns_a), KV_OK);
    c.rms_norm_eps_bits = f32_bits(1e-6f);
    CHECK_RC(kv_compute_config_digest(&c, f.compute_config_digest), KV_OK);
    CHECK_RC(kv_namespace_id(&f, ns_b), KV_OK);
    CHECK(memcmp(ns_a, ns_b, 32) != 0);
    c.rms_norm_eps_bits = f32_bits(1e-5f);
    CHECK_RC(kv_compute_config_digest(&c, f.compute_config_digest), KV_OK);
    CHECK_RC(kv_namespace_id(&f, ns_a2), KV_OK);
    CHECK_MEM(ns_a, ns_a2, 32);
    f = sample();
    uint8_t dig[32];
    CHECK_RC(kv_compute_config_digest(&c, dig), KV_OK);
    CHECK_MEM(dig, f.compute_config_digest, 32); /* sample() already carries the 1e-5 digest */
    /* the chunk keys derived from the two namespaces differ, so no object is found */
    uint32_t toks[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    uint8_t ka[32], kb[32];
    CHECK_RC(kv_chunk_key(ns_a, NULL, 0, toks, 8, ka), KV_OK);
    CHECK_RC(kv_chunk_key(ns_b, NULL, 0, toks, 8, kb), KV_OK);
    CHECK(memcmp(ka, kb, 32) != 0);
    /* and the same pair is in the golden file */
    const jv *vs = J(&g_rec, "vectors");
    const jv *base = NULL, *eps = NULL;
    for (size_t i = 0; i < vs->n; i++) {
        if (strcmp(JS(&vs->kids[i], "name"), "host-small-partial-tail") == 0) base = &vs->kids[i];
        if (strcmp(JS(&vs->kids[i], "name"), "rms-norm-eps-1e-6-only") == 0) eps = &vs->kids[i];
    }
    CHECK(base && eps);
    if (base && eps) {
        uint8_t n1[32], n2[32];
        JH(J(base, "expected"), "namespace_id", n1, 32);
        JH(J(eps, "expected"), "namespace_id", n2, 32);
        CHECK(memcmp(n1, n2, 32) != 0);
        kv_namespace_fields f1, f2;
        parse_ns(J(base, "namespace"), &f1);
        parse_ns(J(eps, "namespace"), &f2);
        CHECK(memcmp(f1.compute_config_digest, f2.compute_config_digest, 32) != 0);
        memcpy(f2.compute_config_digest, f1.compute_config_digest, 32);
        uint8_t n3[32];
        CHECK_RC(kv_namespace_id(&f2, n3), KV_OK);
        CHECK_MEM(n3, n1, 32);
    }
}

/* ADR 1.2: field 14 is appended after field 13, raw 32 bytes. */
static void namespace_id_appends_compute_digest_after_sharing_namespace(void)
{
    kv_namespace_fields f = sample();
    sha256_ctx h;
    uint8_t t[8], want[32], got[32];
    sha256_init(&h);
    sha256_update(&h, (const uint8_t *)"AIEN-PKV-NS-V1\0", 15);
    t[0] = 1; t[1] = 0;
    sha256_update(&h, t, 2);
    sha256_update(&h, f.model_sha256, 32);
    t[0] = (uint8_t)f.model_digest_kind_len;
    sha256_update(&h, t, 1);
    sha256_update(&h, (const uint8_t *)f.model_digest_kind, f.model_digest_kind_len);
    t[0] = (uint8_t)f.model_id_len; t[1] = (uint8_t)(f.model_id_len >> 8);
    sha256_update(&h, t, 2);
    sha256_update(&h, (const uint8_t *)f.model_id, f.model_id_len);
    uint32_t v4[4] = {f.num_layers, f.num_kv_heads, f.head_dim, f.block_size};
    for (int i = 0; i < 4; i++) { put32(t, 0, v4[i]); sha256_update(&h, t, 4); }
    put32(t, 0, f.rope_theta_bits);
    sha256_update(&h, t, 4);
    t[0] = 1;
    sha256_update(&h, t, 1);
    uint64_t r[4] = {f.rope_scaling.factor_bits, f.rope_scaling.low_freq_factor_bits,
                     f.rope_scaling.high_freq_factor_bits, f.rope_scaling.original_max_position_embeddings};
    for (int i = 0; i < 4; i++) { put64(t, 0, r[i]); sha256_update(&h, t, 8); }
    t[0] = f.qk_norm; sha256_update(&h, t, 1);
    t[0] = f.dtype; sha256_update(&h, t, 1);
    uint64_t l[6] = {f.layout.head_stride, f.layout.token_stride, f.layout.kv_plane_stride,
                     f.layout.layer_stride, f.layout.block_stride, f.layout.element_bytes};
    for (int i = 0; i < 6; i++) { put64(t, 0, l[i]); sha256_update(&h, t, 8); }
    t[0] = f.backend_format; sha256_update(&h, t, 1);
    put32(t, 0, f.chunk_tokens); sha256_update(&h, t, 4);
    t[0] = (uint8_t)f.sharing_namespace_len; t[1] = (uint8_t)(f.sharing_namespace_len >> 8);
    sha256_update(&h, t, 2);
    sha256_update(&h, (const uint8_t *)f.sharing_namespace, f.sharing_namespace_len);
    sha256_update(&h, f.compute_config_digest, 32); /* field 14 */
    sha256_final(&h, want);
    CHECK_RC(kv_namespace_id(&f, got), KV_OK);
    CHECK_MEM(got, want, 32);
}

static void segments_follow_the_backend_format(void)
{
    kv_namespace_fields f = sample();
    uint64_t sb;
    uint32_t n;
    CHECK_RC(kv_segment_bytes(&f, 256, &sb), KV_OK);
    CHECK(sb == 524288);
    CHECK_RC(kv_ns_segment_count(&f, 256, &n), KV_OK);
    CHECK(n == 16);
    CHECK_RC(kv_ns_segment_count(&f, 17, &n), KV_OK);
    CHECK(n == 2);
    CHECK_RC(kv_ns_segment_count(&f, 1, &n), KV_OK);
    CHECK(n == 1);
    CHECK_RC(kv_ns_segment_count(&f, 0, &n), KV_E_TOKEN_COUNT_OUT_OF_RANGE);
    CHECK_RC(kv_ns_segment_count(&f, 257, &n), KV_E_TOKEN_COUNT_OUT_OF_RANGE);
    uint64_t plen;
    CHECK_RC(kv_expected_payload_len(&f, 0, &plen), KV_E_TOKEN_COUNT_OUT_OF_RANGE);
    CHECK_RC(kv_expected_payload_len(&f, 257, &plen), KV_E_TOKEN_COUNT_OUT_OF_RANGE);
    {
        uint8_t ns_[32] = {1}, key_[32] = {2};
        kv_chunk_header hb;
        CHECK_RC(kv_chunk_header_build(&f, ns_, key_, NULL, 100, 256, 0, &hb), KV_E_POSITION_MISMATCH);
        CHECK_RC(kv_chunk_header_build(&f, ns_, key_, NULL, 256, 256, 0, &hb), KV_OK);
    }
    kv_namespace_fields nat = sample();
    nat.backend_format = KV_BACKEND_NATIVE_F32_DECODE_STATE_V1;
    nat.dtype = KV_DTYPE_FP32;
    nat.layout.element_bytes = 4;
    nat.chunk_tokens = 64;
    uint64_t pl;
    CHECK_RC(kv_segment_bytes(&nat, 64, &sb), KV_OK);
    CHECK_RC(kv_expected_payload_len(&nat, 64, &pl), KV_OK);
    CHECK(sb == pl);
    CHECK(pl == UINT64_C(16) * 2 * 64 * 8 * 64 * 4); /* layers x 2 x tokens x kv_dim x f32 */
    CHECK_RC(kv_ns_segment_count(&nat, 64, &n), KV_OK);
    CHECK(n == 1);
    CHECK_RC(kv_ns_segment_count(&nat, 3, &n), KV_OK);
    CHECK(n == 1);
    /* host payload = ceil(tokens / block) * block_stride */
    CHECK_RC(kv_expected_payload_len(&f, 17, &pl), KV_OK);
    CHECK(pl == 2 * 524288);
    /* overflow is a refusal, not a wrap */
    kv_namespace_fields o = sample();
    o.layout.block_stride = UINT64_MAX / 2 + 1;
    CHECK_RC(kv_expected_payload_len(&o, 17, &pl), KV_E_OVERFLOW);
    o = nat;
    o.layout.element_bytes = UINT64_MAX;
    CHECK_RC(kv_expected_payload_len(&o, 64, &pl), KV_E_OVERFLOW);
}

static void host_chunk_blocks_are_capped_at_120(void)
{
    kv_namespace_fields f = sample();
    uint8_t id[32];
    uint32_t n;
    f.chunk_tokens = 120 * f.block_size;
    CHECK_RC(kv_namespace_id(&f, id), KV_OK);
    CHECK_RC(kv_ns_segment_count(&f, f.chunk_tokens, &n), KV_OK);
    CHECK(n == 120);
    f.chunk_tokens = 121 * f.block_size;
    CHECK_RC(kv_namespace_id(&f, id), KV_E_TOO_MANY_SEGMENTS);
    f.backend_format = KV_BACKEND_NATIVE_F32_DECODE_STATE_V1; /* one segment: no block cap */
    CHECK_RC(kv_namespace_id(&f, id), KV_OK);
}

/* ======================================================================== */
/* record header                                                             */
/* ======================================================================== */

static kv_record_header plain_record(void)
{
    kv_record_header r;
    r.chunk = sample_chunk_header();
    memset(r.payload_sha256, 0x5A, 32);
    return r;
}

static void header_roundtrip_256_bytes(void)
{
    kv_record_header r = plain_record(), back;
    uint8_t b[KV_HEADER_LEN + 3], again[KV_HEADER_LEN];
    kv_header_encode(&r, b);
    CHECK(KV_HEADER_LEN == 256);
    CHECK_RC(kv_header_decode_struct(b, KV_HEADER_LEN, &back), KV_OK);
    CHECK(rec_eq(&back, &r));
    kv_header_encode(&back, again);
    CHECK_MEM(again, b, KV_HEADER_LEN);
    /* extra trailing bytes do not matter to the struct decode */
    b[256] = 1; b[257] = 2; b[258] = 3;
    CHECK_RC(kv_header_decode_struct(b, sizeof b, &back), KV_OK);
    CHECK(rec_eq(&back, &r));
}

static void header_fields_sit_at_adr_offsets(void)
{
    kv_record_header r = plain_record();
    const kv_chunk_header *c = &r.chunk;
    uint8_t b[KV_HEADER_LEN], d[32];
    kv_header_encode(&r, b);
    CHECK_MEM(b, "AIENKVC1", 8);
    CHECK(get16(b, 8) == 1);   /* format_version */
    CHECK(get16(b, 10) == 1);  /* record_kind */
    CHECK(get32(b, 12) == 256); /* header_len */
    CHECK_MEM(b + 16, c->namespace_id, 32);
    CHECK_MEM(b + 48, c->chunk_key, 32);
    CHECK_MEM(b + 80, c->parent_key, 32);
    CHECK_MEM(b + 112, c->model_sha256, 32);
    CHECK(get32(b, 144) == c->first_position);
    CHECK(get32(b, 148) == c->token_count);
    CHECK(get32(b, 152) == c->chunk_tokens);
    CHECK(get32(b, 156) == c->block_size);
    CHECK(get32(b, 160) == c->num_layers);
    CHECK(get32(b, 164) == c->num_kv_heads);
    CHECK(get32(b, 168) == c->head_dim);
    CHECK(b[172] == c->dtype);
    CHECK(b[173] == c->backend_format);
    CHECK(get16(b, 174) == c->flags);
    CHECK(get64(b, 176) == c->payload_len);
    CHECK_MEM(b + 184, r.payload_sha256, 32);
    CHECK(get64(b, 216) == c->written_unix_ns);
    sha(b, 224, d);
    CHECK_MEM(b + 224, d, 32); /* header_sha256 covers bytes 0..224 */
    CHECK(c->first_position == 0 && c->token_count == 256 && c->flags == 0);
}

static void decode_refuses_short_input_and_structural_damage(void)
{
    uint32_t n;
    kv_record_header rec = sample_record(&n), out;
    uint8_t region[KV_HEADER_REGION_LEN], bad[KV_HEADER_REGION_LEN];
    CHECK_RC(kv_region_encode(&rec, (const uint8_t(*)[32])g_sample_digests, n, region), KV_OK);
    CHECK_RC(kv_header_decode(region, 4095, &out), KV_E_TRUNCATED);
    CHECK_RC(kv_header_decode(region, 256, &out), KV_E_TRUNCATED);
    CHECK_RC(kv_header_decode(region, 0, &out), KV_E_TRUNCATED);
    CHECK_RC(kv_header_decode_struct(region, 255, &out), KV_E_TRUNCATED);
    memcpy(bad, region, sizeof bad);
    bad[3] ^= 0xFF;
    CHECK_RC(kv_header_decode(bad, sizeof bad, &out), KV_E_BAD_MAGIC);
    memcpy(bad, region, sizeof bad);
    bad[100] ^= 1; /* inside the hashed prefix, magic untouched */
    CHECK_RC(kv_header_decode(bad, sizeof bad, &out), KV_E_HEADER_CHECKSUM);
    memcpy(bad, region, sizeof bad);
    bad[240] ^= 1; /* inside the stored hash itself */
    CHECK_RC(kv_header_decode(bad, sizeof bad, &out), KV_E_HEADER_CHECKSUM);
    CHECK_RC(kv_header_decode(NULL, 4096, &out), KV_E_ARG);
    CHECK_RC(kv_header_decode(region, 4096, NULL), KV_E_ARG);
}

static void header_struct_bytes_0_to_255_unchanged_by_the_region(void)
{
    uint32_t n;
    kv_record_header rec = sample_record(&n);
    uint8_t region[KV_HEADER_REGION_LEN], st[KV_HEADER_LEN];
    CHECK_RC(kv_region_encode(&rec, (const uint8_t(*)[32])g_sample_digests, n, region), KV_OK);
    kv_header_encode(&rec, st);
    CHECK_MEM(region, st, KV_HEADER_LEN);
    /* every one of the 256 bytes is assigned: a header with all fields set
     * and a region with a table produce the same 256 bytes. */
    CHECK_RC(kv_region_encode(&rec, NULL, 0, region), KV_OK);
    CHECK_MEM(region, st, KV_HEADER_LEN);
}

static void header_region_roundtrip_4096(void)
{
    uint32_t n;
    kv_record_header rec = sample_record(&n), back;
    uint8_t region[KV_HEADER_REGION_LEN], st[KV_HEADER_LEN], root[32], again[KV_HEADER_REGION_LEN];
    CHECK(n == 16);
    CHECK(KV_HEADER_REGION_LEN == 4096 && KV_PAYLOAD_OFFSET == 4096 && KV_MAX_SEGMENTS == 120);
    CHECK_RC(kv_region_encode(&rec, (const uint8_t(*)[32])g_sample_digests, n, region), KV_OK);
    kv_header_encode(&rec, st);
    CHECK_MEM(region, st, KV_HEADER_LEN);
    for (uint32_t i = 0; i < n; i++) CHECK_MEM(region + 256 + 32 * i, g_sample_digests[i], 32);
    for (size_t i = 256 + 32 * n; i < sizeof region; i++)
        if (region[i]) { CHECK(region[i] == 0); break; }
    CHECK_RC(kv_header_decode(region, sizeof region, &back), KV_OK);
    CHECK(rec_eq(&back, &rec));
    kv_payload_root((const uint8_t(*)[32])g_sample_digests, n, root);
    CHECK_MEM(back.payload_sha256, root, 32);
    CHECK_RC(kv_region_encode(&back, (const uint8_t(*)[32])g_sample_digests, n, again), KV_OK);
    CHECK_MEM(again, region, sizeof region);
    /* the table can fill the region exactly: 120 digests, no padding left */
    static uint8_t full[121][32];
    seg_digests("full", 120, full);
    CHECK_RC(kv_region_encode(&rec, (const uint8_t(*)[32])full, 120, region), KV_OK);
    CHECK_MEM(region + 256 + 32 * 119, full[119], 32);
    /* 121 digests do not fit */
    seg_digests("over", 121, full);
    CHECK_RC(kv_region_encode(&rec, (const uint8_t(*)[32])full, 121, region), KV_E_TOO_MANY_SEGMENTS);
    CHECK_RC(kv_region_encode(&rec, NULL, 1, region), KV_E_ARG);
}

static void payload_root_is_domain_separated_and_order_dependent(void)
{
    static uint8_t d[3][32];
    uint8_t want[32], got[32], swapped[3][32], bare[32];
    seg_digests("root", 3, d);
    sha256_ctx h;
    sha256_init(&h);
    sha256_update(&h, (const uint8_t *)"AIEN-PKV-PAYLOAD-V1\0", 20);
    for (int i = 0; i < 3; i++) sha256_update(&h, d[i], 32);
    sha256_final(&h, want);
    kv_payload_root((const uint8_t(*)[32])d, 3, got);
    CHECK_MEM(got, want, 32);
    memcpy(swapped, d, sizeof swapped);
    memcpy(swapped[0], d[1], 32);
    memcpy(swapped[1], d[0], 32);
    kv_payload_root((const uint8_t(*)[32])swapped, 3, got);
    CHECK(memcmp(got, want, 32) != 0);
    kv_payload_root((const uint8_t(*)[32])d, 2, got);
    CHECK(memcmp(got, want, 32) != 0);
    sha(d, sizeof d, bare);
    CHECK(memcmp(bare, want, 32) != 0);
}

static void segment_count_is_ceil_and_bounded(void)
{
    uint32_t n;
    CHECK_RC(kv_segment_count(524288, 524288, &n), KV_OK);
    CHECK(n == 1);
    CHECK_RC(kv_segment_count(524289, 524288, &n), KV_OK);
    CHECK(n == 2);
    CHECK_RC(kv_segment_count(120 * 4096, 4096, &n), KV_OK);
    CHECK(n == 120);
    CHECK_RC(kv_segment_count(120 * 4096 + 1, 4096, &n), KV_E_TOO_MANY_SEGMENTS);
    CHECK_RC(kv_segment_count(4096, 0, &n), KV_E_INVALID_GEOMETRY);
    CHECK_RC(kv_segment_count(0, 4096, &n), KV_E_INVALID_GEOMETRY);
    /* a huge payload with a tiny segment must not wrap the count */
    CHECK_RC(kv_segment_count(UINT64_MAX, 1, &n), KV_E_TOO_MANY_SEGMENTS);
}

/* ======================================================================== */
/* validation (tests/validate_tests.rs)                                      */
/* ======================================================================== */

typedef struct {
    kv_chunk_header expect;
    uint8_t bytes[KV_HEADER_REGION_LEN];
    uint64_t file_size;
    uint64_t segment_bytes;
    size_t slice_len;
} fixture;

static void reseal(uint8_t *b)
{
    sha(b, 224, b + 224);
}

static void fx_new(fixture *f)
{
    uint32_t n;
    kv_record_header rec = sample_record(&n);
    kv_namespace_fields s = sample();
    f->expect = rec.chunk;
    if (kv_region_encode(&rec, (const uint8_t(*)[32])g_sample_digests, n, f->bytes) != KV_OK) soft("fixture region");
    f->file_size = KV_PAYLOAD_OFFSET + rec.chunk.payload_len;
    if (kv_segment_bytes(&s, rec.chunk.token_count, &f->segment_bytes) != KV_OK) soft("fixture segment");
    f->slice_len = sizeof f->bytes;
}

static int fx_check(const fixture *f)
{
    return kv_validate_record(f->bytes, f->slice_len, f->file_size, &f->expect, f->segment_bytes, NULL);
}

#define FXC(id, body) static void id(fixture *f) { body }
FXC(x_magic, f->bytes[0] = 'X';)
FXC(x_version, f->bytes[8] = 2; reseal(f->bytes);)
FXC(x_hdrhash, f->bytes[230] ^= 1;)
FXC(x_ns, f->bytes[16] ^= 1; reseal(f->bytes);)
FXC(x_key, f->bytes[48] ^= 1; reseal(f->bytes);)
FXC(x_parent, f->bytes[80] ^= 1; reseal(f->bytes);)
FXC(x_pos, put32(f->bytes, 144, 256); reseal(f->bytes);)
FXC(x_tc0, put32(f->bytes, 148, 0); reseal(f->bytes);)
FXC(x_tcover, put32(f->bytes, 148, 257); reseal(f->bytes);)
FXC(x_geom, put32(f->bytes, 164, 9); reseal(f->bytes);)
FXC(x_plen, f->bytes[176] ^= 1; reseal(f->bytes);)
FXC(x_short, f->file_size -= 1;)
FXC(x_long, f->file_size += 1;)
FXC(x_pad_end, f->bytes[4095] = 1;)
FXC(x_pad_after, f->bytes[256 + 32 * 16] = 1;)
FXC(x_seg_flip, f->bytes[256] ^= 1;)
FXC(x_root_flip, f->bytes[184] ^= 1; reseal(f->bytes);)
FXC(x_121, f->segment_bytes = 69905;)
FXC(x_oldsize, f->file_size = 256 + f->expect.payload_len;)
FXC(x_cutshort, f->slice_len = 4095;)
FXC(x_trunc, f->slice_len = 200;)
FXC(x_kind, f->bytes[10] = 2; reseal(f->bytes);)
FXC(x_hlen, f->bytes[12] = 255; reseal(f->bytes);)
FXC(x_flag_res, f->bytes[175] = 0x80; reseal(f->bytes);)
FXC(x_tcmismatch, put32(f->bytes, 148, 255); reseal(f->bytes);)
FXC(x_zero_seg, f->segment_bytes = 0;)

static void validate_refuses_before_any_allocation(void)
{
    static const struct { const char *name; int want; void (*fn)(fixture *); } C[] = {
        {"wrong magic", KV_E_BAD_MAGIC, x_magic},
        {"wrong version", KV_E_UNSUPPORTED_VERSION, x_version},
        {"wrong record kind", KV_E_BAD_RECORD_KIND, x_kind},
        {"wrong header_len", KV_E_BAD_HEADER_LEN, x_hlen},
        {"wrong header hash", KV_E_HEADER_CHECKSUM, x_hdrhash},
        {"reserved flag bit", KV_E_BAD_FLAGS, x_flag_res},
        {"wrong namespace", KV_E_NAMESPACE_MISMATCH, x_ns},
        {"wrong key", KV_E_KEY_MISMATCH, x_key},
        {"wrong parent", KV_E_PARENT_MISMATCH, x_parent},
        {"wrong position", KV_E_POSITION_MISMATCH, x_pos},
        {"token_count 0", KV_E_TOKEN_COUNT_OUT_OF_RANGE, x_tc0},
        {"token_count over chunk_tokens", KV_E_TOKEN_COUNT_OUT_OF_RANGE, x_tcover},
        {"token_count differs from expected", KV_E_TOKEN_COUNT_MISMATCH, x_tcmismatch},
        {"wrong geometry", KV_E_GEOMETRY_MISMATCH, x_geom},
        {"wrong payload_len", KV_E_PAYLOAD_LEN_MISMATCH, x_plen},
        {"file shorter than header+payload", KV_E_FILE_SIZE_MISMATCH, x_short},
        {"file longer than header+payload", KV_E_FILE_SIZE_MISMATCH, x_long},
        {"nonzero byte at the end of the region", KV_E_BAD_PADDING, x_pad_end},
        {"nonzero byte right after the digest table", KV_E_BAD_PADDING, x_pad_after},
        {"segment digest flipped in the table", KV_E_SEGMENT_ROOT_MISMATCH, x_seg_flip},
        {"root at offset 184 flipped", KV_E_SEGMENT_ROOT_MISMATCH, x_root_flip},
        {"121 segments of the derived size", KV_E_TOO_MANY_SEGMENTS, x_121},
        {"zero segment size", KV_E_INVALID_GEOMETRY, x_zero_seg},
        {"file size of the old 256-byte layout", KV_E_FILE_SIZE_MISMATCH, x_oldsize},
        {"region cut short", KV_E_TRUNCATED, x_cutshort},
        {"truncated header", KV_E_TRUNCATED, x_trunc},
    };
    CHECK(sizeof C / sizeof C[0] >= 19);
    for (size_t i = 0; i < sizeof C / sizeof C[0]; i++) {
        fixture f;
        fx_new(&f);
        C[i].fn(&f);
        ALLOC_BEGIN();
        int got = fx_check(&f);
        unsigned long allocs = ALLOC_END();
        if (got != C[i].want) { g_fails++; printf("  FAIL %s: \"%s\" = %d, want %d\n", g_test, C[i].name, got, C[i].want); }
        if (allocs != 0) { g_fails++; printf("  FAIL %s: \"%s\" allocated %lu times\n", g_test, C[i].name, allocs); }
        g_checks += 2;
    }
    /* NULL arguments are refused, not dereferenced */
    fixture f;
    fx_new(&f);
    CHECK_RC(kv_validate_record(NULL, 4096, f.file_size, &f.expect, f.segment_bytes, NULL), KV_E_ARG);
    CHECK_RC(kv_validate_record(f.bytes, 4096, f.file_size, NULL, f.segment_bytes, NULL), KV_E_ARG);
}

static void counter_detects_allocation(void)
{
#if HAVE_ALLOC_COUNTER
    /* Negative control: the harness would notice a heap use. */
    void *(*volatile mp)(size_t) = malloc;
    ALLOC_BEGIN();
    void *p = mp(64);
    unsigned long n = ALLOC_END();
    free(p);
    CHECK(n >= 1);
#else
    printf("  SKIPPED: allocation counter needs GNU ld --wrap (lib-checks still proves no allocator import)\n");
#endif
}

static void valid_record_passes_with_zero_allocations(void)
{
    fixture f;
    uint32_t n;
    kv_record_header out;
    kv_record_header want = sample_record(&n);
    fx_new(&f);
    ALLOC_BEGIN();
    int rc = kv_validate_record(f.bytes, f.slice_len, f.file_size, &f.expect, f.segment_bytes, &out);
    unsigned long allocs = ALLOC_END();
    CHECK_RC(rc, KV_OK);
    CHECK(allocs == 0);
    CHECK(chunk_eq(&out.chunk, &f.expect));
    CHECK_MEM(out.payload_sha256, want.payload_sha256, 32);
}

static void validation_reports_the_first_failure_in_adr_order(void)
{
    fixture f;
    fx_new(&f); /* magic and namespace both wrong: magic wins */
    f.bytes[0] = 'X'; f.bytes[16] ^= 1; reseal(f.bytes);
    CHECK_RC(fx_check(&f), KV_E_BAD_MAGIC);
    fx_new(&f); /* namespace and key both wrong: namespace wins */
    f.bytes[16] ^= 1; f.bytes[48] ^= 1; reseal(f.bytes);
    CHECK_RC(fx_check(&f), KV_E_NAMESPACE_MISMATCH);
    fx_new(&f); /* padding and root both wrong: padding wins (it is checked first) */
    f.bytes[4095] = 1; f.bytes[256] ^= 1;
    CHECK_RC(fx_check(&f), KV_E_BAD_PADDING);
    fx_new(&f); /* root and file size both wrong: root wins */
    f.bytes[256] ^= 1; f.file_size += 1;
    CHECK_RC(fx_check(&f), KV_E_SEGMENT_ROOT_MISMATCH);
    fx_new(&f); /* too many segments and bad padding: the count wins */
    f.segment_bytes = 69905; f.bytes[4095] = 1;
    CHECK_RC(fx_check(&f), KV_E_TOO_MANY_SEGMENTS);
    fx_new(&f); /* payload_len and file size both wrong: payload_len wins */
    f.bytes[176] ^= 1; reseal(f.bytes); f.file_size += 1;
    CHECK_RC(fx_check(&f), KV_E_PAYLOAD_LEN_MISMATCH);
}

static void partial_flag_must_agree_with_token_count(void)
{
    fixture f;
    fx_new(&f); /* partial_tail claimed on a full chunk */
    f.bytes[174] = 1; reseal(f.bytes);
    CHECK_RC(fx_check(&f), KV_E_BAD_FLAGS);
    fx_new(&f); /* a reserved flag bit */
    f.bytes[175] = 0x80; reseal(f.bytes);
    CHECK_RC(fx_check(&f), KV_E_BAD_FLAGS);
}

static void file_size_is_4096_plus_payload(void)
{
    fixture f;
    fx_new(&f);
    CHECK(f.file_size == 4096 + f.expect.payload_len);
    CHECK_RC(fx_check(&f), KV_OK);
    f.file_size = 256 + f.expect.payload_len; /* the C1 layout */
    CHECK_RC(fx_check(&f), KV_E_FILE_SIZE_MISMATCH);
    /* a file size near 2^64 must not wrap the comparison: one segment, huge payload */
    fx_new(&f);
    kv_record_header rec;
    uint8_t one[1][32];
    seg_digests("wrap", 1, one);
    f.expect.payload_len = UINT64_MAX - 100;
    rec.chunk = f.expect;
    kv_payload_root((const uint8_t(*)[32])one, 1, rec.payload_sha256);
    CHECK_RC(kv_region_encode(&rec, (const uint8_t(*)[32])one, 1, f.bytes), KV_OK);
    f.segment_bytes = f.expect.payload_len;
    f.file_size = KV_PAYLOAD_OFFSET + f.expect.payload_len; /* wraps to 3995 in u64 */
    CHECK_RC(fx_check(&f), KV_E_FILE_SIZE_MISMATCH);
}

static void validate_refuses_nonzero_padding(void)
{
    const size_t table_end = 256 + 32 * 16;
    const size_t offs[] = {table_end, table_end + 1, 1000, 4094, 4095};
    for (size_t i = 0; i < sizeof offs / sizeof offs[0]; i++) {
        fixture f;
        fx_new(&f);
        f.bytes[offs[i]] = 1;
        CHECK_RC(fx_check(&f), KV_E_BAD_PADDING);
    }
    fixture f;
    fx_new(&f); /* a nonzero digest byte inside the table is not padding */
    f.bytes[table_end - 1] ^= 1;
    CHECK_RC(fx_check(&f), KV_E_SEGMENT_ROOT_MISMATCH);
    fx_new(&f);
    CHECK_RC(fx_check(&f), KV_OK);
}

static void validate_refuses_segment_root_mismatch(void)
{
    fixture f;
    uint8_t t[32];
    fx_new(&f); /* swapping two digests keeps the multiset but changes the root */
    memcpy(t, f.bytes + 256, 32);
    memcpy(f.bytes + 256, f.bytes + 288, 32);
    memcpy(f.bytes + 288, t, 32);
    CHECK_RC(fx_check(&f), KV_E_SEGMENT_ROOT_MISMATCH);
    fx_new(&f); /* a root that does not match the table (struct resealed) */
    f.bytes[200] ^= 1;
    reseal(f.bytes);
    CHECK_RC(fx_check(&f), KV_E_SEGMENT_ROOT_MISMATCH);
}

static void validate_refuses_more_than_120_segments(void)
{
    fixture f;
    static uint8_t digests[121][32];
    fx_new(&f);
    CHECK((f.expect.payload_len + 69999) / 70000 == 120);
    seg_digests("edge", 120, digests);
    kv_record_header rec;
    rec.chunk = f.expect;
    kv_payload_root((const uint8_t(*)[32])digests, 120, rec.payload_sha256);
    CHECK_RC(kv_region_encode(&rec, (const uint8_t(*)[32])digests, 120, f.bytes), KV_OK);
    f.segment_bytes = 70000;
    CHECK_RC(fx_check(&f), KV_OK); /* exactly 120 segments is valid */
    f.segment_bytes = 69905;
    CHECK((f.expect.payload_len + 69904) / 69905 == 121);
    ALLOC_BEGIN();
    int rc = fx_check(&f);
    unsigned long allocs = ALLOC_END();
    CHECK_RC(rc, KV_E_TOO_MANY_SEGMENTS); /* refused before the table is read */
    CHECK(allocs == 0);
    f.segment_bytes = 0;
    CHECK_RC(fx_check(&f), KV_E_INVALID_GEOMETRY);
}

/* ======================================================================== */
/* native slot header unit                                                   */
/* ======================================================================== */

static void slot_from_vector(const jv *in, kv_slot_header *s)
{
    uint8_t hdr[KV_HEADER_LEN];
    memset(s, 0, sizeof *s);
    unhex(JS(in, "record_header_hex"), KV_HEADER_LEN, hdr);
    if (kv_header_decode_struct(hdr, KV_HEADER_LEN, &s->rec) != KV_OK) soft("slot vector record header does not decode");
    s->key_epoch = JN(in, "key_generation");
    s->slot_incarnation = JN(in, "slot_incarnation");
    s->slot_index = (uint32_t)JN(in, "slot_index");
}

static void slot_header_golden_vectors_match(void)
{
    const jv *vs = J(&g_slot, "vectors");
    CHECK(JN(&g_slot, "format_version") == 1);
    CHECK(JN(&g_slot, "object_kind") == KV_OBJECT_KIND);
    CHECK(JN(&g_slot, "object_version") == KV_OBJECT_VERSION);
    CHECK(JN(&g_slot, "chunk_size") == KV_SLOT_CHUNK_SIZE);
    CHECK(JN(&g_slot, "max_payload_len") == KV_SLOT_MAX_PAYLOAD);
    CHECK(KV_SLOT_MAX_PAYLOAD == (uint64_t)M5_ENV_MAX_CHUNKS * KV_SLOT_CHUNK_SIZE);
    CHECK(vs->n == 3);
    for (size_t i = 0; i < vs->n; i++) {
        const jv *in = J(&vs->kids[i], "input");
        const jv *ex = J(&vs->kids[i], "expected");
        kv_slot_header s, back;
        slot_from_vector(in, &s);
        uint8_t want[64], got_id[16], got_nonce[8], k_kv[32], k_env[32];
        uint8_t uuid[16], kdom[32], ns[32], ck[32], psha[32];
        JH(in, "store_uuid", uuid, 16);
        JH(in, "k_domain", kdom, 32);
        JH(in, "namespace_id", ns, 32);
        JH(in, "chunk_key", ck, 32);
        JH(in, "payload_sha256", psha, 32);
        CHECK_MEM(s.rec.chunk.namespace_id, ns, 32);
        CHECK_MEM(s.rec.chunk.chunk_key, ck, 32);
        CHECK_MEM(s.rec.payload_sha256, psha, 32);
        CHECK(s.rec.chunk.payload_len == JN(in, "payload_len"));
        uint8_t cls = (uint8_t)JN(in, "identity_class");

        /* keys and envelope id / nonce */
        CHECK_RC(kv_slot_keys(kdom, k_kv, k_env), KV_OK);
        JH(ex, "k_kv", want, 32);
        CHECK_MEM(k_kv, want, 32);
        JH(ex, "k_envid_kv", want, 32);
        CHECK_MEM(k_env, want, 32);
        CHECK_RC(kv_envelope_ids(k_env, uuid, ns, ck, s.slot_index, s.slot_incarnation, s.key_epoch, cls,
                                 s.rec.chunk.payload_len, psha, got_id, got_nonce), KV_OK);
        JH(ex, "envelope_id", want, 16);
        CHECK_MEM(got_id, want, 16);
        JH(ex, "nonce_prefix", want, 8);
        CHECK_MEM(got_nonce, want, 8);
        memcpy(s.envelope_id, got_id, 16);
        memcpy(s.nonce_prefix, got_nonce, 8);

        /* geometry */
        uint32_t su, el;
        CHECK_RC(kv_slot_geometry(s.rec.chunk.payload_len, &su, &el), KV_OK);
        CHECK(su == JN(ex, "sealed_units"));
        CHECK(el == JN(ex, "envelope_len"));
        CHECK(JN(ex, "slot_units") == 1 + (uint64_t)su);
        CHECK(JN(ex, "sealed_len") + 64 == el);

        /* the unit */
        uint8_t unit[KV_SLOT_UNIT], pre[340], digest[32];
        CHECK_RC(kv_slot_encode(&s, unit), KV_OK);
        unhex(JS(ex, "unit_prefix_hex"), 340, pre);
        CHECK_MEM(unit, pre, 340);
        int zero = 1;
        for (size_t b = KV_SLOT_ZERO_OFFSET; b < KV_SLOT_HASH_OFFSET; b++) zero &= unit[b] == 0;
        CHECK(zero);
        JH(ex, "unit_sha256_field", digest, 32);
        CHECK_MEM(unit + KV_SLOT_HASH_OFFSET, digest, 32);
        sha(unit, KV_SLOT_HASH_OFFSET, digest);
        CHECK_MEM(unit + KV_SLOT_HASH_OFFSET, digest, 32);
        sha(unit, KV_SLOT_UNIT, digest);
        JH(ex, "unit_full_sha256", want, 32);
        CHECK_MEM(digest, want, 32);

        /* decode, re-encode byte for byte, validate against the record header */
        CHECK_RC(kv_slot_decode(unit, KV_SLOT_UNIT, s.slot_index, &back), KV_OK);
        CHECK_MEM(back.envelope_id, got_id, 16);
        CHECK_MEM(back.nonce_prefix, got_nonce, 8);
        CHECK(back.key_epoch == s.key_epoch && back.slot_incarnation == s.slot_incarnation);
        CHECK(back.slot_index == s.slot_index && back.sealed_units == su && back.envelope_len == el);
        CHECK(rec_eq(&back.rec, &s.rec));
        uint8_t again[KV_SLOT_UNIT];
        CHECK_RC(kv_slot_encode(&back, again), KV_OK);
        CHECK_MEM(again, unit, KV_SLOT_UNIT);
        CHECK_RC(kv_slot_validate(unit, KV_SLOT_UNIT, s.slot_index, &s.rec.chunk, NULL), KV_OK);
        CHECK_RC(kv_slot_validate(unit, KV_SLOT_UNIT, s.slot_index, NULL, NULL), KV_OK);

        /* the M5 inputs */
        m5_object_binding b;
        kv_slot_binding(uuid, got_id, s.key_epoch, cls, &b);
        CHECK_MEM(b.store_uuid, uuid, 16);
        CHECK(b.object_kind == 0x0520 && b.object_version == 1);
        CHECK_MEM(b.envelope_id, got_id, 16);
        CHECK(b.key_generation == s.key_epoch && b.identity_class == cls);
        /* the envelope length the header carries is the length M5 computes */
        CHECK(m5_envelope_len(s.rec.chunk.payload_len, KV_SLOT_CHUNK_SIZE) == el);
    }
}

/* The bytes of the slot's envelope header are the bytes M5 itself writes. */
static void slot_envelope_header_equals_the_m5_sealed_header(void)
{
    const jv *in = J(&J(&g_slot, "vectors")->kids[0], "input");
    kv_slot_header s;
    slot_from_vector(in, &s);
    uint8_t uuid[16], kdom[32], k_kv[32], k_env[32], pt[5000], leaf[32];
    JH(in, "store_uuid", uuid, 16);
    JH(in, "k_domain", kdom, 32);
    for (size_t i = 0; i < sizeof pt; i++) pt[i] = (uint8_t)(i * 7 + 3);
    sha(pt, sizeof pt, leaf);
    s.rec.chunk.payload_len = sizeof pt;
    kv_payload_root((const uint8_t(*)[32])leaf, 1, s.rec.payload_sha256);
    CHECK_RC(kv_slot_keys(kdom, k_kv, k_env), KV_OK);
    CHECK_RC(kv_envelope_ids(k_env, uuid, s.rec.chunk.namespace_id, s.rec.chunk.chunk_key, s.slot_index,
                             s.slot_incarnation, s.key_epoch, 2, sizeof pt, s.rec.payload_sha256,
                             s.envelope_id, s.nonce_prefix), KV_OK);
    m5_object_binding b;
    kv_slot_binding(uuid, s.envelope_id, s.key_epoch, 2, &b);
    static uint8_t env[16384];
    size_t el = 0;
    CHECK_RC(m5_envelope_seal(k_kv, &b, s.nonce_prefix, KV_SLOT_CHUNK_SIZE, pt, sizeof pt, env, sizeof env, &el), M5_OK);
    uint8_t unit[KV_SLOT_UNIT];
    CHECK_RC(kv_slot_encode(&s, unit), KV_OK);
    CHECK_MEM(unit + KV_SLOT_ENV_OFFSET, env, M5_ENV_HEADER_LEN);
    CHECK(get32(unit, KV_SLOT_ENVELOPE_LEN_OFFSET) == el);
    CHECK(get32(unit, KV_SLOT_SEALED_UNITS_OFFSET) == (el - 64 + 4095) / 4096);
    /* the sealed envelope opens only under the binding the slot implies */
    static uint8_t back[5000];
    size_t bl = 0;
    CHECK_RC(m5_envelope_open(k_kv, 2, &b, env, el, back, sizeof back, &bl), M5_OK);
    CHECK(bl == sizeof pt && memcmp(back, pt, sizeof pt) == 0);
    kv_slot_header other = s;
    other.slot_index ^= 1;
    uint8_t id2[16], n2[8];
    CHECK_RC(kv_envelope_ids(k_env, uuid, s.rec.chunk.namespace_id, s.rec.chunk.chunk_key, other.slot_index,
                             s.slot_incarnation, s.key_epoch, 2, sizeof pt, s.rec.payload_sha256, id2, n2), KV_OK);
    kv_slot_binding(uuid, id2, s.key_epoch, 2, &b);
    CHECK(m5_envelope_open(k_kv, 2, &b, env, el, back, sizeof back, &bl) != M5_OK); /* another slot: wrong binding */
}

static void slot_bounds_match_the_vector_table_and_m5(void)
{
    const jv *bs = J(&g_slot, "bounds");
    CHECK(bs->n == 11);
    for (size_t i = 0; i < bs->n; i++) {
        const jv *r = &bs->kids[i];
        uint64_t pl = JN(r, "payload_len");
        uint32_t su = 0, el = 0;
        CHECK_RC(kv_slot_geometry(pl, &su, &el), KV_OK);
        CHECK(su == JN(r, "sealed_units"));
        CHECK(el == JN(r, "envelope_len"));
        CHECK(JN(r, "slot_units") == 1 + (uint64_t)su);
        CHECK(JN(r, "sealed_len") == JN(r, "envelope_len") - 64);
        CHECK(m5_envelope_len(pl, KV_SLOT_CHUNK_SIZE) == el);
    }
    uint32_t su, el;
    CHECK_RC(kv_slot_geometry(0, &su, &el), KV_E_SLOT_BOUNDS);
    CHECK_RC(kv_slot_geometry(16711681, &su, &el), KV_E_SLOT_BOUNDS);
    CHECK_RC(kv_slot_geometry(UINT64_MAX, &su, &el), KV_E_SLOT_BOUNDS);
    CHECK(m5_envelope_len(16711681, KV_SLOT_CHUNK_SIZE) == 0); /* M5 refuses the same bound */
}

static void put_unit_hash(uint8_t *u) { sha(u, KV_SLOT_HASH_OFFSET, u + KV_SLOT_HASH_OFFSET); }

static void slot_unit_new(uint8_t unit[KV_SLOT_UNIT], uint32_t *slot_index)
{
    kv_slot_header s;
    slot_from_vector(J(&J(&g_slot, "vectors")->kids[0], "input"), &s);
    memset(s.envelope_id, 0x11, 16);
    memset(s.nonce_prefix, 0x22, 8);
    *slot_index = s.slot_index;
    if (kv_slot_encode(&s, unit) != KV_OK) soft("slot unit");
}

/* mutate bytes of the unit, repair the record header hash and/or the unit hash, decode */
static int slot_try(void (*mut)(uint8_t *), int fix_rec, int fix_unit, size_t len)
{
    uint8_t u[KV_SLOT_UNIT];
    uint32_t si;
    slot_unit_new(u, &si);
    mut(u);
    if (fix_rec) reseal(u);
    if (fix_unit) put_unit_hash(u);
    return kv_slot_decode(u, len, si, NULL);
}

#define SM(id, body) static void id(uint8_t *u) { body }
SM(s_none, (void)u;)
SM(s_hash_flip, u[10] ^= 1;)
SM(s_pad_340, u[340] = 1;)
SM(s_pad_4000, u[4000] = 1;)
SM(s_pad_4063, u[4063] = 1;)
SM(s_magic, u[0] = 'X';)
SM(s_rec_hash, u[230] ^= 1;)
SM(s_rec_flags, u[175] = 0x80;)
SM(s_backend, u[173] = 1;)
SM(s_env_magic, u[256] = 'X';)
SM(s_env_version, u[264] = 2;)
SM(s_env_suite, u[266] = 2;)
SM(s_env_flags, u[268] = 1;)
SM(s_env_chunk, put32(u, 272, 4096);)
SM(s_env_reserved, u[316] = 1;)
SM(s_env_total, put64(u, 276, get64(u, 276) + 1);)
SM(s_pl_zero, put64(u, 176, 0); put64(u, 276, 0); reseal(u);)
SM(s_pl_over, put64(u, 176, 16711681); put64(u, 276, 16711681); reseal(u);)
SM(s_pl_max_mismatch, put64(u, 176, 16711680);)
SM(s_units_plus1, put32(u, 328, get32(u, 328) + 1);)
SM(s_units_minus1, put32(u, 328, get32(u, 328) - 1);)
SM(s_envlen_minus1, put32(u, 332, get32(u, 332) - 1);)
SM(s_envlen_plus4096, put32(u, 332, get32(u, 332) + 4096);)
SM(s_index, put32(u, 336, 4);)

static void slot_bounds_refused_before_decrypt(void)
{
    /* Everything below is judged from the 4096-byte unit alone: no key, no
     * payload read, no decrypt. The decode takes no key argument. */
    static const struct { const char *name; void (*mut)(uint8_t *); int fix_rec, fix_unit; int want; } C[] = {
        {"valid", s_none, 0, 1, KV_OK},
        {"unit hash flipped", s_hash_flip, 0, 0, KV_E_SLOT_CHECKSUM},
        {"nonzero at 340", s_pad_340, 0, 1, KV_E_SLOT_PADDING},
        {"nonzero at 4000", s_pad_4000, 0, 1, KV_E_SLOT_PADDING},
        {"nonzero at 4063", s_pad_4063, 0, 1, KV_E_SLOT_PADDING},
        {"record magic", s_magic, 1, 1, KV_E_BAD_MAGIC},
        {"record header hash", s_rec_hash, 0, 1, KV_E_HEADER_CHECKSUM},
        {"record reserved flag", s_rec_flags, 1, 1, KV_E_BAD_FLAGS},
        {"host backend_format in a slot", s_backend, 1, 1, KV_E_SLOT_BACKEND},
        {"envelope magic", s_env_magic, 0, 1, KV_E_SLOT_ENVELOPE},
        {"envelope version", s_env_version, 0, 1, KV_E_SLOT_ENVELOPE},
        {"envelope cipher suite", s_env_suite, 0, 1, KV_E_SLOT_ENVELOPE},
        {"envelope flags", s_env_flags, 0, 1, KV_E_SLOT_ENVELOPE},
        {"envelope chunk_size 4096", s_env_chunk, 0, 1, KV_E_SLOT_ENVELOPE},
        {"envelope reserved", s_env_reserved, 0, 1, KV_E_SLOT_ENVELOPE},
        {"envelope total_plaintext_len differs from payload_len", s_env_total, 0, 1, KV_E_SLOT_BOUNDS},
        {"payload_len 0", s_pl_zero, 0, 1, KV_E_SLOT_BOUNDS},
        {"payload_len 16711681", s_pl_over, 0, 1, KV_E_SLOT_BOUNDS},
        {"payload_len and envelope disagree", s_pl_max_mismatch, 1, 1, KV_E_SLOT_BOUNDS},
        {"sealed_units + 1", s_units_plus1, 0, 1, KV_E_SLOT_BOUNDS},
        {"sealed_units - 1", s_units_minus1, 0, 1, KV_E_SLOT_BOUNDS},
        {"envelope_len - 1", s_envlen_minus1, 0, 1, KV_E_SLOT_BOUNDS},
        {"envelope_len + 4096", s_envlen_plus4096, 0, 1, KV_E_SLOT_BOUNDS},
        {"slot_index is another slot", s_index, 0, 1, KV_E_SLOT_INDEX},
    };
    for (size_t i = 0; i < sizeof C / sizeof C[0]; i++) {
        ALLOC_BEGIN();
        int got = slot_try(C[i].mut, C[i].fix_rec, C[i].fix_unit, KV_SLOT_UNIT);
        unsigned long allocs = ALLOC_END();
        if (got != C[i].want) { g_fails++; printf("  FAIL %s: \"%s\" = %d, want %d\n", g_test, C[i].name, got, C[i].want); }
        if (allocs) { g_fails++; printf("  FAIL %s: \"%s\" allocated\n", g_test, C[i].name); }
        g_checks += 2;
    }
    CHECK_RC(slot_try(s_none, 0, 1, 4095), KV_E_TRUNCATED);
    CHECK_RC(slot_try(s_none, 0, 1, 0), KV_E_TRUNCATED);
    /* a freshly zeroed unit (the provably-empty state) is an empty slot, not a valid one */
    uint8_t z[KV_SLOT_UNIT] = {0};
    CHECK_RC(kv_slot_decode(z, sizeof z, 0, NULL), KV_E_SLOT_CHECKSUM);
    CHECK_RC(kv_slot_decode(NULL, KV_SLOT_UNIT, 0, NULL), KV_E_ARG);
    /* the encoder refuses the same bounds */
    kv_slot_header s;
    slot_from_vector(J(&J(&g_slot, "vectors")->kids[0], "input"), &s);
    uint8_t out[KV_SLOT_UNIT];
    s.rec.chunk.payload_len = 0;
    CHECK_RC(kv_slot_encode(&s, out), KV_E_SLOT_BOUNDS);
    s.rec.chunk.payload_len = 16711681;
    CHECK_RC(kv_slot_encode(&s, out), KV_E_SLOT_BOUNDS);
    s.rec.chunk.payload_len = 16711680;
    CHECK_RC(kv_slot_encode(&s, out), KV_OK);
    CHECK(get32(out, KV_SLOT_SEALED_UNITS_OFFSET) == 4096 && get32(out, KV_SLOT_ENVELOPE_LEN_OFFSET) == 16777280);
}

static void slot_validate_applies_the_identity_checks_when_given_an_expectation(void)
{
    uint8_t u[KV_SLOT_UNIT];
    uint32_t si;
    slot_unit_new(u, &si);
    kv_slot_header s;
    CHECK_RC(kv_slot_decode(u, sizeof u, si, &s), KV_OK);
    kv_chunk_header e = s.rec.chunk;
    CHECK_RC(kv_slot_validate(u, sizeof u, si, &e, NULL), KV_OK);
    e.written_unix_ns += 1; /* informational, ignored */
    CHECK_RC(kv_slot_validate(u, sizeof u, si, &e, NULL), KV_OK);
    e = s.rec.chunk; e.namespace_id[0] ^= 1;
    CHECK_RC(kv_slot_validate(u, sizeof u, si, &e, NULL), KV_E_NAMESPACE_MISMATCH);
    e = s.rec.chunk; e.chunk_key[0] ^= 1;
    CHECK_RC(kv_slot_validate(u, sizeof u, si, &e, NULL), KV_E_KEY_MISMATCH);
    e = s.rec.chunk; e.parent_key[0] ^= 1;
    CHECK_RC(kv_slot_validate(u, sizeof u, si, &e, NULL), KV_E_PARENT_MISMATCH);
    e = s.rec.chunk; e.payload_len += 1;
    CHECK_RC(kv_slot_validate(u, sizeof u, si, &e, NULL), KV_E_PAYLOAD_LEN_MISMATCH);
    e = s.rec.chunk; e.model_sha256[5] ^= 1;
    CHECK_RC(kv_slot_validate(u, sizeof u, si, &e, NULL), KV_E_GEOMETRY_MISMATCH);
    /* a slot of any namespace is valid in the recovery scan (expect NULL) */
    CHECK_RC(kv_slot_validate(u, sizeof u, si, NULL, &s), KV_OK);
    CHECK_RC(kv_slot_validate(u, sizeof u, si + 1, NULL, &s), KV_E_SLOT_INDEX);
}

static void slot_error_order(void)
{
    /* checksum before padding before record structure before backend before envelope before bounds before index */
    CHECK_RC(slot_try(s_pad_340, 0, 0, KV_SLOT_UNIT), KV_E_SLOT_CHECKSUM);
    CHECK_RC(slot_try(s_magic, 0, 0, KV_SLOT_UNIT), KV_E_SLOT_CHECKSUM);
    CHECK_RC(slot_try(s_magic, 0, 1, KV_SLOT_UNIT), KV_E_BAD_MAGIC);
    CHECK_RC(slot_try(s_env_magic, 0, 1, KV_SLOT_UNIT), KV_E_SLOT_ENVELOPE);
    uint8_t u[KV_SLOT_UNIT];
    uint32_t si;
    slot_unit_new(u, &si);
    u[4000] = 1;    /* padding */
    u[173] = 1;     /* backend, after repairing the record hash */
    reseal(u);
    put_unit_hash(u);
    CHECK_RC(kv_slot_decode(u, sizeof u, si, NULL), KV_E_SLOT_PADDING);
    slot_unit_new(u, &si);
    u[173] = 1;
    reseal(u);
    u[256] = 'X';   /* envelope magic wrong too */
    put_unit_hash(u);
    CHECK_RC(kv_slot_decode(u, sizeof u, si, NULL), KV_E_SLOT_BACKEND);
    slot_unit_new(u, &si);
    u[256] = 'X';
    put32(u, 336, si + 1); /* index wrong too */
    put_unit_hash(u);
    CHECK_RC(kv_slot_decode(u, sizeof u, si, NULL), KV_E_SLOT_ENVELOPE);
    slot_unit_new(u, &si);
    put32(u, 328, 0);
    put_unit_hash(u);
    CHECK_RC(kv_slot_decode(u, sizeof u, si + 5, NULL), KV_E_SLOT_BOUNDS);
}

static void envelope_id_changes_with_each_binding_input(void)
{
    const jv *in = J(&J(&g_slot, "vectors")->kids[0], "input");
    uint8_t uuid[16], kdom[32], ns[32], ck[32], ps[32], kk[32], ke[32], base_id[16], base_n[8], id[16], n[8];
    JH(in, "store_uuid", uuid, 16);
    JH(in, "k_domain", kdom, 32);
    JH(in, "namespace_id", ns, 32);
    JH(in, "chunk_key", ck, 32);
    JH(in, "payload_sha256", ps, 32);
    CHECK_RC(kv_slot_keys(kdom, kk, ke), KV_OK);
    CHECK(memcmp(kk, ke, 32) != 0);
    CHECK_RC(kv_envelope_ids(ke, uuid, ns, ck, 3, 7, 2, 2, 4194304, ps, base_id, base_n), KV_OK);
#define DIFFERS(call) do { CHECK_RC(call, KV_OK); CHECK(memcmp(id, base_id, 16) != 0 || memcmp(n, base_n, 8) != 0); } while (0)
    uuid[0] ^= 1;  DIFFERS(kv_envelope_ids(ke, uuid, ns, ck, 3, 7, 2, 2, 4194304, ps, id, n)); uuid[0] ^= 1;
    ns[0] ^= 1;    DIFFERS(kv_envelope_ids(ke, uuid, ns, ck, 3, 7, 2, 2, 4194304, ps, id, n)); ns[0] ^= 1;
    ck[0] ^= 1;    DIFFERS(kv_envelope_ids(ke, uuid, ns, ck, 3, 7, 2, 2, 4194304, ps, id, n)); ck[0] ^= 1;
    ps[0] ^= 1;    DIFFERS(kv_envelope_ids(ke, uuid, ns, ck, 3, 7, 2, 2, 4194304, ps, id, n)); ps[0] ^= 1;
    DIFFERS(kv_envelope_ids(ke, uuid, ns, ck, 4, 7, 2, 2, 4194304, ps, id, n));   /* slot index */
    DIFFERS(kv_envelope_ids(ke, uuid, ns, ck, 3, 8, 2, 2, 4194304, ps, id, n));   /* incarnation */
    DIFFERS(kv_envelope_ids(ke, uuid, ns, ck, 3, 7, 3, 2, 4194304, ps, id, n));   /* key generation */
    DIFFERS(kv_envelope_ids(ke, uuid, ns, ck, 3, 7, 2, 1, 4194304, ps, id, n));   /* identity class */
    DIFFERS(kv_envelope_ids(ke, uuid, ns, ck, 3, 7, 2, 2, 4194303, ps, id, n));   /* payload_len */
    kk[0] ^= 1; ke[0] ^= 1;
    DIFFERS(kv_envelope_ids(ke, uuid, ns, ck, 3, 7, 2, 2, 4194304, ps, id, n));   /* key */
    CHECK_RC(kv_envelope_ids(NULL, uuid, ns, ck, 3, 7, 2, 2, 4194304, ps, id, n), KV_E_ARG);
    CHECK_RC(kv_slot_keys(NULL, kk, ke), KV_E_ARG);
}

/* ======================================================================== */

typedef struct { const char *name; void (*fn)(void); } test_case;
#define T(n) {#n, n}
static const test_case TESTS[] = {
    T(golden_vectors_include_compute_config_digest),
    T(identity_vectors_match_golden),
    T(rms_norm_eps_alone_changes_the_namespace),
    T(compute_config_digest_changes_with_each_field),
    T(compute_config_refuses_oversized_arith_id),
    T(namespace_changes_when_any_field_changes),
    T(namespace_id_appends_compute_digest_after_sharing_namespace),
    T(rope_scaling_presence_is_distinct_from_zeroed_scaling),
    T(namespace_refuses_oversized_or_inconsistent_fields),
    T(chunk_key_chain_depends_on_parent_and_position),
    T(chunk_chain_links_each_chunk_to_all_earlier_tokens),
    T(segments_follow_the_backend_format),
    T(host_chunk_blocks_are_capped_at_120),
    T(header_roundtrip_256_bytes),
    T(header_fields_sit_at_adr_offsets),
    T(decode_refuses_short_input_and_structural_damage),
    T(header_struct_bytes_0_to_255_unchanged_by_the_region),
    T(header_region_roundtrip_4096),
    T(payload_root_is_domain_separated_and_order_dependent),
    T(segment_count_is_ceil_and_bounded),
    T(counter_detects_allocation),
    T(valid_record_passes_with_zero_allocations),
    T(validate_refuses_before_any_allocation),
    T(validation_reports_the_first_failure_in_adr_order),
    T(partial_flag_must_agree_with_token_count),
    T(file_size_is_4096_plus_payload),
    T(validate_refuses_nonzero_padding),
    T(validate_refuses_segment_root_mismatch),
    T(validate_refuses_more_than_120_segments),
    T(slot_header_golden_vectors_match),
    T(slot_envelope_header_equals_the_m5_sealed_header),
    T(slot_bounds_match_the_vector_table_and_m5),
    T(slot_bounds_refused_before_decrypt),
    T(slot_validate_applies_the_identity_checks_when_given_an_expectation),
    T(slot_error_order),
    T(envelope_id_changes_with_each_binding_input),
};

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : "tests/golden";
    const char *lock = argc > 2 ? argv[2] : "CONTRACT.lock";
    char path[512];
    const char *err = NULL;

    snprintf(path, sizeof path, "%s/kv_record_v1.json", dir);
    g_rec_text = slurp_or_die(path, &g_rec_len);
    snprintf(path, sizeof path, "%s/kv_slot_v1.json", dir);
    g_slot_text = slurp_or_die(path, &g_slot_len);
    pin_gate(lock); /* refuses to run on a hash mismatch */
    if (j_parse(g_rec_text, g_rec_len, &g_rec, &err) != 0) die("kv_record_v1.json: %s", err);
    if (j_parse(g_slot_text, g_slot_len, &g_slot, &err) != 0) die("kv_slot_v1.json: %s", err);

    int failed_tests = 0;
    for (size_t i = 0; i < sizeof TESTS / sizeof TESTS[0]; i++) {
        int before = g_fails;
        g_test = TESTS[i].name;
        TESTS[i].fn();
        if (g_fails == before) printf("PASS %s\n", TESTS[i].name);
        else { printf("FAIL %s\n", TESTS[i].name); failed_tests++; }
    }
    printf("%zu tests, %d checks, %d failed\n", sizeof TESTS / sizeof TESTS[0], g_checks, failed_tests);
    if (failed_tests) { printf("AIENOS_KV_RECORD_NATIVE: FAIL\n"); return 1; }
    printf("AIENOS_KV_RECORD_NATIVE: PASS\n");
    return 0;
}
