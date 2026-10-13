/*
 * kv_record.c -- C twin of crates/aien-kv-store identity.rs, record.rs and
 * validate.rs (sovereign-core ADR 0003), plus the native slot header unit
 * (ADR 2.5). See kv_record.h and README.md.
 *
 * No heap, no clock, no I/O, no floating point, no static state. Every check
 * that refuses a record is a single line tagged GUARD:<name> so `make mutants`
 * can delete it and prove a test notices.
 */
#include <string.h>

#include "aienos_crypto.h" /* native/crypto: aienos_hmac_sha256 */
#include "kv_record.h"

/* Domain strings. sizeof includes the one trailing NUL the ADR writes as \0. */
static const char NS_DOMAIN[] = "AIEN-PKV-NS-V1";
static const char CHUNK_DOMAIN[] = "AIEN-PKV-CHUNK-V1";
static const char CFG_DOMAIN[] = "AIEN-PKV-CFG-V1";
static const char PAYLOAD_DOMAIN[] = "AIEN-PKV-PAYLOAD-V1";
static const char SLOT_KEY_INFO[] = "AIENOS-PKV-SLOT-KEY-V1";
static const char ENVID_KEY_INFO[] = "AIENOS-PKV-ENVID-KEY-V1";
static const char ENVID_DOMAIN[] = "AIENOS-PKV-ENVID-V1";

/* Byte offsets of ADR 0003 section 2.1. */
enum {
    O_MAGIC = 0, O_VERSION = 8, O_KIND = 10, O_HEADER_LEN = 12, O_NAMESPACE = 16, O_KEY = 48,
    O_PARENT = 80, O_MODEL = 112, O_FIRST_POS = 144, O_TOKEN_COUNT = 148, O_CHUNK_TOKENS = 152,
    O_BLOCK_SIZE = 156, O_LAYERS = 160, O_KV_HEADS = 164, O_HEAD_DIM = 168, O_DTYPE = 172,
    O_BACKEND = 173, O_FLAGS = 174, O_PAYLOAD_LEN = 176, O_PAYLOAD_SHA = 184, O_WRITTEN_NS = 216,
    O_HEADER_SHA = 224
};

/* ---- little-endian helpers (byte-wise, host order irrelevant) ---- */

static void put16(uint8_t *b, size_t off, uint16_t v)
{
    b[off] = (uint8_t)v;
    b[off + 1] = (uint8_t)(v >> 8);
}
static void put32(uint8_t *b, size_t off, uint32_t v)
{
    for (unsigned i = 0; i < 4; i++) b[off + i] = (uint8_t)(v >> (8 * i));
}
static void put64(uint8_t *b, size_t off, uint64_t v)
{
    for (unsigned i = 0; i < 8; i++) b[off + i] = (uint8_t)(v >> (8 * i));
}
static uint16_t get16(const uint8_t *b, size_t off) { return (uint16_t)(b[off] | (uint16_t)b[off + 1] << 8); }
static uint32_t get32(const uint8_t *b, size_t off)
{
    uint32_t v = 0;
    for (unsigned i = 4; i-- > 0;) v = v << 8 | b[off + i];
    return v;
}
static uint64_t get64(const uint8_t *b, size_t off)
{
    uint64_t v = 0;
    for (unsigned i = 8; i-- > 0;) v = v << 8 | b[off + i];
    return v;
}

/* ---- hashing helpers ---- */

static void h_bytes(sha256_ctx *h, const void *p, size_t n)
{
    if (n) sha256_update(h, (const uint8_t *)p, n);
}
static void h_u8(sha256_ctx *h, uint8_t v) { sha256_update(h, &v, 1); }
static void h_u16(sha256_ctx *h, uint16_t v)
{
    uint8_t t[2];
    put16(t, 0, v);
    sha256_update(h, t, 2);
}
static void h_u32(sha256_ctx *h, uint32_t v)
{
    uint8_t t[4];
    put32(t, 0, v);
    sha256_update(h, t, 4);
}
static void h_u64(sha256_ctx *h, uint64_t v)
{
    uint8_t t[8];
    put64(t, 0, v);
    sha256_update(h, t, 8);
}

static int mul64(uint64_t a, uint64_t b, uint64_t *out)
{
    if (a != 0 && b > UINT64_MAX / a) return 0;
    *out = a * b;
    return 1;
}

static int all_zero(const uint8_t *p, size_t n)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

/* ======================================================================== */
/* identity                                                                  */
/* ======================================================================== */

int kv_compute_config_digest(const kv_compute_config *c, uint8_t out[32])
{
    if (!c || !out || (!c->arith_id && c->arith_id_len)) return KV_E_ARG;
    if (c->hidden_act != KV_HIDDEN_ACT_SILU || c->tie_word_embeddings > 1) return KV_E_ARG;
    if (c->arith_id_len > KV_MAX_ARITH_ID_BYTES) return KV_E_FIELD_TOO_LONG; /* GUARD:arith-id-cap */
    sha256_ctx h;
    sha256_init(&h);
    h_bytes(&h, CFG_DOMAIN, sizeof CFG_DOMAIN);
    h_u32(&h, c->num_heads);                     /* 1 */
    h_u64(&h, c->hidden_dim);                    /* 2 */
    h_u64(&h, c->intermediate_dim);              /* 3 */
    h_u64(&h, c->vocab_size);                    /* 4 */
    h_u32(&h, c->rms_norm_eps_bits);             /* 5 */
    h_u8(&h, c->tie_word_embeddings);            /* 6 */
    h_u8(&h, c->hidden_act);                     /* 7 */
    h_u8(&h, (uint8_t)c->arith_id_len);          /* 8 */
    h_bytes(&h, c->arith_id, c->arith_id_len);
    h_u32(&h, c->arith_epoch);                   /* 9 */
    sha256_final(&h, out);
    return KV_OK;
}

static int check_geometry(const kv_namespace_fields *f)
{
    if (f->block_size == 0 || f->chunk_tokens == 0 || f->num_layers == 0 || f->num_kv_heads == 0 || f->head_dim == 0) return KV_E_INVALID_GEOMETRY; /* GUARD:geometry-zero */
    if (f->chunk_tokens % f->block_size != 0) return KV_E_INVALID_GEOMETRY; /* GUARD:geometry-multiple */
    /* A host chunk is one segment per pool block and the digest table holds at
     * most 120 (ADR 2.1 item 3): chunk_blocks is capped at 120 there. */
    if (f->backend_format == KV_BACKEND_HOST_PAGED_POOL_V1 && f->chunk_tokens / f->block_size > KV_MAX_SEGMENTS) return KV_E_TOO_MANY_SEGMENTS; /* GUARD:host-block-cap */
    return KV_OK;
}

/* Values the Rust types cannot hold, and NULL strings. */
static int check_representable(const kv_namespace_fields *f)
{
    if ((!f->model_digest_kind && f->model_digest_kind_len) || (!f->model_id && f->model_id_len) ||
        (!f->sharing_namespace && f->sharing_namespace_len)) return KV_E_ARG;
    if (f->dtype < KV_DTYPE_FP4 || f->dtype > KV_DTYPE_FP32) return KV_E_ARG;
    if (f->backend_format != KV_BACKEND_HOST_PAGED_POOL_V1 && f->backend_format != KV_BACKEND_NATIVE_F32_DECODE_STATE_V1) return KV_E_ARG;
    if (f->qk_norm > 1 || f->rope_scaling.present > 1) return KV_E_ARG;
    return KV_OK;
}

int kv_namespace_id(const kv_namespace_fields *f, uint8_t out[32])
{
    if (!f || !out) return KV_E_ARG;
    int rc = check_representable(f);
    if (rc != KV_OK) return rc;
    rc = check_geometry(f);
    if (rc != KV_OK) return rc;
    if (f->sharing_namespace_len > KV_MAX_SHARING_NAMESPACE_BYTES) return KV_E_FIELD_TOO_LONG; /* GUARD:sharing-cap */
    if (f->model_digest_kind_len > 255) return KV_E_FIELD_TOO_LONG; /* GUARD:kind-cap */
    if (f->model_id_len > 65535) return KV_E_FIELD_TOO_LONG; /* GUARD:model-id-cap */

    sha256_ctx h;
    sha256_init(&h);
    h_bytes(&h, NS_DOMAIN, sizeof NS_DOMAIN);
    h_u16(&h, KV_FORMAT_VERSION);                              /* 1 */
    h_bytes(&h, f->model_sha256, 32);                          /* 2 */
    h_u8(&h, (uint8_t)f->model_digest_kind_len);               /* 3 */
    h_bytes(&h, f->model_digest_kind, f->model_digest_kind_len);
    h_u16(&h, (uint16_t)f->model_id_len);                      /* 4 */
    h_bytes(&h, f->model_id, f->model_id_len);
    h_u32(&h, f->num_layers);                                  /* 5 */
    h_u32(&h, f->num_kv_heads);
    h_u32(&h, f->head_dim);
    h_u32(&h, f->block_size);
    h_u32(&h, f->rope_theta_bits);                             /* 6 */
    if (!f->rope_scaling.present) {                            /* 7 */
        h_u8(&h, 0);
    } else {
        h_u8(&h, 1);
        h_u64(&h, f->rope_scaling.factor_bits);
        h_u64(&h, f->rope_scaling.low_freq_factor_bits);
        h_u64(&h, f->rope_scaling.high_freq_factor_bits);
        h_u64(&h, f->rope_scaling.original_max_position_embeddings);
    }
    h_u8(&h, f->qk_norm);                                      /* 8 */
    h_u8(&h, f->dtype);                                        /* 9 */
    h_u64(&h, f->layout.head_stride);                          /* 10 */
    h_u64(&h, f->layout.token_stride);
    h_u64(&h, f->layout.kv_plane_stride);
    h_u64(&h, f->layout.layer_stride);
    h_u64(&h, f->layout.block_stride);
    h_u64(&h, f->layout.element_bytes);
    h_u8(&h, f->backend_format);                               /* 11 */
    h_u32(&h, f->chunk_tokens);                                /* 12 */
    h_u16(&h, (uint16_t)f->sharing_namespace_len);             /* 13 */
    h_bytes(&h, f->sharing_namespace, f->sharing_namespace_len);
    h_bytes(&h, f->compute_config_digest, 32);                 /* 14 */
    sha256_final(&h, out);
    return KV_OK;
}

int kv_expected_payload_len(const kv_namespace_fields *f, uint32_t token_count, uint64_t *out)
{
    if (!f || !out) return KV_E_ARG;
    int rc = check_representable(f);
    if (rc != KV_OK) return rc;
    rc = check_geometry(f);
    if (rc != KV_OK) return rc;
    if (token_count == 0 || token_count > f->chunk_tokens) return KV_E_TOKEN_COUNT_OUT_OF_RANGE; /* GUARD:payload-token-range */
    if (f->backend_format == KV_BACKEND_HOST_PAGED_POOL_V1) {
        uint64_t blocks = ((uint64_t)token_count + f->block_size - 1) / f->block_size;
        return mul64(blocks, f->layout.block_stride, out) ? KV_OK : KV_E_OVERFLOW; /* GUARD:payload-overflow-host */
    }
    /* Native: per layer, K rows then V rows of token_count * kv_dim elements. */
    uint64_t kv_dim = (uint64_t)f->num_kv_heads * f->head_dim; /* u32 * u32 fits in u64 */
    uint64_t v = (uint64_t)f->num_layers * 2;
    if (!mul64(v, token_count, &v) || !mul64(v, kv_dim, &v) || !mul64(v, f->layout.element_bytes, &v)) return KV_E_OVERFLOW; /* GUARD:payload-overflow-native */
    *out = v;
    return KV_OK;
}

int kv_segment_bytes(const kv_namespace_fields *f, uint32_t token_count, uint64_t *out)
{
    if (!f || !out) return KV_E_ARG;
    if (f->backend_format == KV_BACKEND_HOST_PAGED_POOL_V1) {
        int rc = check_representable(f);
        if (rc != KV_OK) return rc;
        rc = check_geometry(f);
        if (rc != KV_OK) return rc;
        if (token_count == 0 || token_count > f->chunk_tokens) return KV_E_TOKEN_COUNT_OUT_OF_RANGE;
        *out = f->layout.block_stride;
        return KV_OK;
    }
    return kv_expected_payload_len(f, token_count, out); /* native: one segment, the whole payload */
}

int kv_segment_count(uint64_t payload_len, uint64_t segment_bytes, uint32_t *out)
{
    if (!out) return KV_E_ARG;
    if (payload_len == 0 || segment_bytes == 0) return KV_E_INVALID_GEOMETRY; /* GUARD:segcount-zero */
    uint64_t n = payload_len / segment_bytes + (payload_len % segment_bytes != 0);
    if (n > KV_MAX_SEGMENTS) return KV_E_TOO_MANY_SEGMENTS; /* GUARD:segcount-cap */
    *out = (uint32_t)n;
    return KV_OK;
}

int kv_ns_segment_count(const kv_namespace_fields *f, uint32_t token_count, uint32_t *out)
{
    uint64_t payload_len, sb;
    int rc = kv_expected_payload_len(f, token_count, &payload_len);
    if (rc != KV_OK) return rc;
    rc = kv_segment_bytes(f, token_count, &sb);
    if (rc != KV_OK) return rc;
    return kv_segment_count(payload_len, sb, out);
}

int kv_chunk_key(const uint8_t ns[32], const uint8_t parent[32], uint32_t first_position,
                 const uint32_t *tokens, size_t n_tokens, uint8_t out[32])
{
    if (!ns || !out) return KV_E_ARG;
    if ((uint64_t)n_tokens > UINT32_MAX) return KV_E_OVERFLOW;
    if (n_tokens == 0) return KV_E_TOKEN_COUNT_OUT_OF_RANGE;
    if (!tokens) return KV_E_ARG;
    if ((uint64_t)first_position + (uint64_t)n_tokens > UINT32_MAX) return KV_E_OVERFLOW; /* GUARD:chunk-key-overflow */
    static const uint8_t zero32[32] = {0};
    sha256_ctx h;
    uint8_t buf[256];
    sha256_init(&h);
    h_bytes(&h, CHUNK_DOMAIN, sizeof CHUNK_DOMAIN);
    h_bytes(&h, ns, 32);
    h_bytes(&h, parent ? parent : zero32, 32);
    h_u32(&h, first_position);
    h_u32(&h, (uint32_t)n_tokens);
    for (size_t i = 0; i < n_tokens;) {
        size_t k = 0;
        while (i < n_tokens && k + 4 <= sizeof buf) {
            put32(buf, k, tokens[i++]);
            k += 4;
        }
        sha256_update(&h, buf, k);
    }
    sha256_final(&h, out);
    return KV_OK;
}

int kv_chunk_chain(const uint8_t ns[32], uint32_t chunk_tokens, const uint32_t *tokens, size_t n_tokens,
                   uint8_t (*keys)[32], size_t keys_cap, size_t *n_keys)
{
    if (!ns || !n_keys || (!tokens && n_tokens) || (!keys && keys_cap)) return KV_E_ARG;
    *n_keys = 0;
    if (chunk_tokens == 0) return KV_E_INVALID_GEOMETRY;
    size_t per = chunk_tokens;
    size_t chunks = n_tokens / per + (n_tokens % per != 0);
    if (chunks > keys_cap) return KV_E_ARG;
    for (size_t i = 0; i < chunks; i++) {
        uint64_t first = (uint64_t)i * chunk_tokens;
        if (first > UINT32_MAX) return KV_E_OVERFLOW;
        size_t start = i * per;
        size_t len = n_tokens - start < per ? n_tokens - start : per;
        int rc = kv_chunk_key(ns, i ? keys[i - 1] : NULL, (uint32_t)first, tokens + start, len, keys[i]);
        if (rc != KV_OK) return rc;
        *n_keys = i + 1;
    }
    return KV_OK;
}

/* ======================================================================== */
/* record header                                                             */
/* ======================================================================== */

int kv_chunk_header_build(const kv_namespace_fields *f, const uint8_t ns[32], const uint8_t chunk_key[32],
                          const uint8_t parent[32], uint32_t first_position, uint32_t token_count,
                          uint64_t written_unix_ns, kv_chunk_header *out)
{
    if (!f || !ns || !chunk_key || !out) return KV_E_ARG;
    uint64_t payload_len;
    int rc = kv_expected_payload_len(f, token_count, &payload_len);
    if (rc != KV_OK) return rc;
    if (first_position % f->chunk_tokens != 0) return KV_E_POSITION_MISMATCH; /* GUARD:build-position */
    memset(out, 0, sizeof *out);
    memcpy(out->namespace_id, ns, 32);
    memcpy(out->chunk_key, chunk_key, 32);
    if (parent) memcpy(out->parent_key, parent, 32);
    memcpy(out->model_sha256, f->model_sha256, 32);
    out->first_position = first_position;
    out->token_count = token_count;
    out->chunk_tokens = f->chunk_tokens;
    out->block_size = f->block_size;
    out->num_layers = f->num_layers;
    out->num_kv_heads = f->num_kv_heads;
    out->head_dim = f->head_dim;
    out->dtype = f->dtype;
    out->backend_format = f->backend_format;
    out->flags = token_count < f->chunk_tokens ? KV_FLAG_PARTIAL_TAIL : 0;
    out->payload_len = payload_len;
    out->written_unix_ns = written_unix_ns;
    return KV_OK;
}

void kv_header_encode(const kv_record_header *h, uint8_t out[KV_HEADER_LEN])
{
    const kv_chunk_header *c = &h->chunk;
    memset(out, 0, KV_HEADER_LEN);
    memcpy(out + O_MAGIC, "AIENKVC1", 8);
    put16(out, O_VERSION, KV_FORMAT_VERSION);
    put16(out, O_KIND, KV_RECORD_KIND_CHUNK);
    put32(out, O_HEADER_LEN, KV_HEADER_LEN);
    memcpy(out + O_NAMESPACE, c->namespace_id, 32);
    memcpy(out + O_KEY, c->chunk_key, 32);
    memcpy(out + O_PARENT, c->parent_key, 32);
    memcpy(out + O_MODEL, c->model_sha256, 32);
    put32(out, O_FIRST_POS, c->first_position);
    put32(out, O_TOKEN_COUNT, c->token_count);
    put32(out, O_CHUNK_TOKENS, c->chunk_tokens);
    put32(out, O_BLOCK_SIZE, c->block_size);
    put32(out, O_LAYERS, c->num_layers);
    put32(out, O_KV_HEADS, c->num_kv_heads);
    put32(out, O_HEAD_DIM, c->head_dim);
    out[O_DTYPE] = c->dtype;
    out[O_BACKEND] = c->backend_format;
    put16(out, O_FLAGS, c->flags);
    put64(out, O_PAYLOAD_LEN, c->payload_len);
    memcpy(out + O_PAYLOAD_SHA, h->payload_sha256, 32);
    put64(out, O_WRITTEN_NS, c->written_unix_ns);
    sha256_hash(out, KV_HASHED_PREFIX_LEN, out + O_HEADER_SHA);
}

int kv_header_decode_struct(const uint8_t *buf, size_t len, kv_record_header *out)
{
    if (!buf || !out) return KV_E_ARG;
    if (len < KV_HEADER_LEN) return KV_E_TRUNCATED; /* GUARD:struct-length */
    if (memcmp(buf + O_MAGIC, "AIENKVC1", 8) != 0) return KV_E_BAD_MAGIC; /* GUARD:magic */
    if (get16(buf, O_VERSION) != KV_FORMAT_VERSION) return KV_E_UNSUPPORTED_VERSION; /* GUARD:version */
    if (get16(buf, O_KIND) != KV_RECORD_KIND_CHUNK) return KV_E_BAD_RECORD_KIND; /* GUARD:record-kind */
    if (get32(buf, O_HEADER_LEN) != KV_HEADER_LEN) return KV_E_BAD_HEADER_LEN; /* GUARD:header-len */
    uint8_t digest[32];
    sha256_hash(buf, KV_HASHED_PREFIX_LEN, digest);
    if (memcmp(digest, buf + O_HEADER_SHA, 32) != 0) return KV_E_HEADER_CHECKSUM; /* GUARD:header-checksum */
    uint16_t flags = get16(buf, O_FLAGS);
    if (flags & (uint16_t)~KV_FLAG_PARTIAL_TAIL) return KV_E_BAD_FLAGS; /* GUARD:reserved-flags */
    memset(out, 0, sizeof *out);
    kv_chunk_header *c = &out->chunk;
    memcpy(c->namespace_id, buf + O_NAMESPACE, 32);
    memcpy(c->chunk_key, buf + O_KEY, 32);
    memcpy(c->parent_key, buf + O_PARENT, 32);
    memcpy(c->model_sha256, buf + O_MODEL, 32);
    c->first_position = get32(buf, O_FIRST_POS);
    c->token_count = get32(buf, O_TOKEN_COUNT);
    c->chunk_tokens = get32(buf, O_CHUNK_TOKENS);
    c->block_size = get32(buf, O_BLOCK_SIZE);
    c->num_layers = get32(buf, O_LAYERS);
    c->num_kv_heads = get32(buf, O_KV_HEADS);
    c->head_dim = get32(buf, O_HEAD_DIM);
    c->dtype = buf[O_DTYPE];
    c->backend_format = buf[O_BACKEND];
    c->flags = flags;
    c->payload_len = get64(buf, O_PAYLOAD_LEN);
    c->written_unix_ns = get64(buf, O_WRITTEN_NS);
    memcpy(out->payload_sha256, buf + O_PAYLOAD_SHA, 32);
    return KV_OK;
}

int kv_header_decode(const uint8_t *buf, size_t len, kv_record_header *out)
{
    if (!buf || !out) return KV_E_ARG;
    if (len < KV_HEADER_REGION_LEN) return KV_E_TRUNCATED; /* GUARD:region-length */
    return kv_header_decode_struct(buf, len, out);
}

void kv_payload_root(const uint8_t (*seg_digests)[32], size_t n, uint8_t out[32])
{
    sha256_ctx h;
    sha256_init(&h);
    h_bytes(&h, PAYLOAD_DOMAIN, sizeof PAYLOAD_DOMAIN);
    for (size_t i = 0; i < n; i++) sha256_update(&h, seg_digests[i], 32);
    sha256_final(&h, out);
}

int kv_region_encode(const kv_record_header *h, const uint8_t (*seg_digests)[32], size_t n,
                     uint8_t out[KV_HEADER_REGION_LEN])
{
    if (!h || !out) return KV_E_ARG;
    if (n > KV_MAX_SEGMENTS) return KV_E_TOO_MANY_SEGMENTS; /* GUARD:region-seg-cap */
    if (n && !seg_digests) return KV_E_ARG;
    memset(out, 0, KV_HEADER_REGION_LEN);
    kv_header_encode(h, out);
    for (size_t i = 0; i < n; i++) memcpy(out + KV_SEGMENT_TABLE_OFFSET + 32 * i, seg_digests[i], 32);
    return KV_OK;
}

/* The identity checks of validate_record, in the Rust order, from namespace to
 * payload_len. Shared with kv_slot_validate. */
static int match_expected(const kv_chunk_header *h, const kv_chunk_header *e)
{
    if (memcmp(h->namespace_id, e->namespace_id, 32) != 0) return KV_E_NAMESPACE_MISMATCH; /* GUARD:namespace */
    if (memcmp(h->chunk_key, e->chunk_key, 32) != 0) return KV_E_KEY_MISMATCH; /* GUARD:key */
    if (memcmp(h->parent_key, e->parent_key, 32) != 0) return KV_E_PARENT_MISMATCH; /* GUARD:parent */
    if (h->first_position != e->first_position || h->chunk_tokens == 0 || h->first_position % h->chunk_tokens != 0) return KV_E_POSITION_MISMATCH; /* GUARD:position */
    if (h->token_count == 0 || h->token_count > h->chunk_tokens) return KV_E_TOKEN_COUNT_OUT_OF_RANGE; /* GUARD:token-count-range */
    if (h->token_count != e->token_count) return KV_E_TOKEN_COUNT_MISMATCH; /* GUARD:token-count-mismatch */
    if (memcmp(h->model_sha256, e->model_sha256, 32) != 0 || h->chunk_tokens != e->chunk_tokens || h->block_size != e->block_size || h->num_layers != e->num_layers || h->num_kv_heads != e->num_kv_heads || h->head_dim != e->head_dim || h->dtype != e->dtype || h->backend_format != e->backend_format) return KV_E_GEOMETRY_MISMATCH; /* GUARD:geometry */
    int partial = h->token_count < h->chunk_tokens;
    if (((h->flags & KV_FLAG_PARTIAL_TAIL) != 0) != partial || h->flags != e->flags) return KV_E_BAD_FLAGS; /* GUARD:partial-flag */
    if (h->payload_len != e->payload_len) return KV_E_PAYLOAD_LEN_MISMATCH; /* GUARD:payload-len */
    return KV_OK;
}

int kv_validate_record(const uint8_t *buf, size_t len, uint64_t file_size, const kv_chunk_header *expect,
                       uint64_t segment_bytes, kv_record_header *out)
{
    if (!buf || !expect) return KV_E_ARG;
    kv_record_header rec;
    int rc = kv_header_decode(buf, len, &rec);
    if (rc != KV_OK) return rc;
    rc = match_expected(&rec.chunk, expect);
    if (rc != KV_OK) return rc;

    /* Header region: the segment digest table, zero padding, and the root. */
    uint32_t n_seg;
    rc = kv_segment_count(rec.chunk.payload_len, segment_bytes, &n_seg);
    if (rc != KV_OK) return rc;
    size_t table_end = KV_SEGMENT_TABLE_OFFSET + 32 * (size_t)n_seg;
    if (!all_zero(buf + table_end, KV_HEADER_REGION_LEN - table_end)) return KV_E_BAD_PADDING; /* GUARD:padding */
    uint8_t root[32];
    sha256_ctx h;
    sha256_init(&h);
    h_bytes(&h, PAYLOAD_DOMAIN, sizeof PAYLOAD_DOMAIN);
    sha256_update(&h, buf + KV_SEGMENT_TABLE_OFFSET, table_end - KV_SEGMENT_TABLE_OFFSET);
    sha256_final(&h, root);
    if (memcmp(root, rec.payload_sha256, 32) != 0) return KV_E_SEGMENT_ROOT_MISMATCH; /* GUARD:segment-root */

    if (rec.chunk.payload_len > UINT64_MAX - KV_PAYLOAD_OFFSET || KV_PAYLOAD_OFFSET + rec.chunk.payload_len != file_size) return KV_E_FILE_SIZE_MISMATCH; /* GUARD:file-size */
    if (out) *out = rec;
    return KV_OK;
}

/* ======================================================================== */
/* native slot header unit                                                   */
/* ======================================================================== */

int kv_slot_geometry(uint64_t payload_len, uint32_t *sealed_units, uint32_t *envelope_len)
{
    if (payload_len == 0 || payload_len > KV_SLOT_MAX_PAYLOAD) return KV_E_SLOT_BOUNDS; /* GUARD:slot-payload-bounds */
    uint64_t chunks = (payload_len + KV_SLOT_CHUNK_SIZE - 1) / KV_SLOT_CHUNK_SIZE;
    uint64_t sealed_len = payload_len + (uint64_t)M5_TAG_LEN * chunks;
    if (sealed_units) *sealed_units = (uint32_t)((sealed_len + KV_SLOT_UNIT - 1) / KV_SLOT_UNIT);
    if (envelope_len) *envelope_len = (uint32_t)(M5_ENV_HEADER_LEN + sealed_len);
    return KV_OK;
}

int kv_slot_encode(const kv_slot_header *s, uint8_t out[KV_SLOT_UNIT])
{
    if (!s || !out) return KV_E_ARG;
    uint32_t sealed_units, envelope_len;
    int rc = kv_slot_geometry(s->rec.chunk.payload_len, &sealed_units, &envelope_len);
    if (rc != KV_OK) return rc;
    memset(out, 0, KV_SLOT_UNIT);
    kv_header_encode(&s->rec, out);
    uint8_t *e = out + KV_SLOT_ENV_OFFSET; /* M5 envelope header, m5.h */
    memcpy(e, "AIENENV1", 8);
    put16(e, 8, 1);                          /* version */
    put16(e, 10, 1);                         /* cipher suite */
    put32(e, 12, 0);                         /* flags */
    put32(e, 16, KV_SLOT_CHUNK_SIZE);        /* chunk_size */
    put64(e, 20, s->rec.chunk.payload_len);  /* total_plaintext_len */
    memcpy(e + 28, s->envelope_id, 16);
    memcpy(e + 44, s->nonce_prefix, 8);
    put64(e, 52, s->key_epoch);
    put32(e, 60, 0);                         /* reserved */
    put64(out, KV_SLOT_INCARNATION_OFFSET, s->slot_incarnation);
    put32(out, KV_SLOT_SEALED_UNITS_OFFSET, sealed_units);
    put32(out, KV_SLOT_ENVELOPE_LEN_OFFSET, envelope_len);
    put32(out, KV_SLOT_INDEX_OFFSET, s->slot_index);
    sha256_hash(out, KV_SLOT_HASH_OFFSET, out + KV_SLOT_HASH_OFFSET);
    return KV_OK;
}

int kv_slot_decode(const uint8_t *unit, size_t len, uint32_t slot_index, kv_slot_header *out)
{
    if (!unit) return KV_E_ARG;
    if (len < KV_SLOT_UNIT) return KV_E_TRUNCATED; /* GUARD:slot-length */
    uint8_t digest[32];
    sha256_hash(unit, KV_SLOT_HASH_OFFSET, digest);
    if (memcmp(digest, unit + KV_SLOT_HASH_OFFSET, 32) != 0) return KV_E_SLOT_CHECKSUM; /* GUARD:slot-checksum */
    if (!all_zero(unit + KV_SLOT_ZERO_OFFSET, KV_SLOT_HASH_OFFSET - KV_SLOT_ZERO_OFFSET)) return KV_E_SLOT_PADDING; /* GUARD:slot-padding */
    kv_slot_header s;
    memset(&s, 0, sizeof s);
    int rc = kv_header_decode_struct(unit, KV_HEADER_LEN, &s.rec);
    if (rc != KV_OK) return rc;
    if (s.rec.chunk.backend_format != KV_BACKEND_NATIVE_F32_DECODE_STATE_V1) return KV_E_SLOT_BACKEND; /* GUARD:slot-backend */
    const uint8_t *e = unit + KV_SLOT_ENV_OFFSET;
    if (memcmp(e, "AIENENV1", 8) != 0) return KV_E_SLOT_ENVELOPE; /* GUARD:slot-env-magic */
    if (get16(e, 8) != 1) return KV_E_SLOT_ENVELOPE; /* GUARD:slot-env-version */
    if (get16(e, 10) != 1) return KV_E_SLOT_ENVELOPE; /* GUARD:slot-env-suite */
    if (get32(e, 12) != 0) return KV_E_SLOT_ENVELOPE; /* GUARD:slot-env-flags */
    if (get32(e, 16) != KV_SLOT_CHUNK_SIZE) return KV_E_SLOT_ENVELOPE; /* GUARD:slot-env-chunk-size */
    if (get32(e, 60) != 0) return KV_E_SLOT_ENVELOPE; /* GUARD:slot-env-reserved */
    if (get64(e, 20) != s.rec.chunk.payload_len) return KV_E_SLOT_BOUNDS; /* GUARD:slot-env-total */
    uint32_t sealed_units, envelope_len;
    rc = kv_slot_geometry(s.rec.chunk.payload_len, &sealed_units, &envelope_len);
    if (rc != KV_OK) return rc;
    if (get32(unit, KV_SLOT_SEALED_UNITS_OFFSET) != sealed_units) return KV_E_SLOT_BOUNDS; /* GUARD:slot-sealed-units */
    if (get32(unit, KV_SLOT_ENVELOPE_LEN_OFFSET) != envelope_len) return KV_E_SLOT_BOUNDS; /* GUARD:slot-envelope-len */
    if (get32(unit, KV_SLOT_INDEX_OFFSET) != slot_index) return KV_E_SLOT_INDEX; /* GUARD:slot-index */
    memcpy(s.envelope_id, e + 28, 16);
    memcpy(s.nonce_prefix, e + 44, 8);
    s.key_epoch = get64(e, 52);
    s.slot_incarnation = get64(unit, KV_SLOT_INCARNATION_OFFSET);
    s.slot_index = slot_index;
    s.sealed_units = sealed_units;
    s.envelope_len = envelope_len;
    if (out) *out = s;
    return KV_OK;
}

int kv_slot_validate(const uint8_t *unit, size_t len, uint32_t slot_index, const kv_chunk_header *expect,
                     kv_slot_header *out)
{
    kv_slot_header s;
    int rc = kv_slot_decode(unit, len, slot_index, &s);
    if (rc != KV_OK) return rc;
    if (expect) {
        rc = match_expected(&s.rec.chunk, expect);
        if (rc != KV_OK) return rc;
    }
    if (out) *out = s;
    return KV_OK;
}

/* ======================================================================== */
/* authenticated mapping into M5                                             */
/* ======================================================================== */

int kv_slot_keys(const uint8_t k_domain[32], uint8_t k_kv[32], uint8_t k_envid_kv[32])
{
    if (!k_domain || !k_kv || !k_envid_kv) return KV_E_ARG;
    if (m5_hkdf_expand(k_domain, (const uint8_t *)SLOT_KEY_INFO, sizeof SLOT_KEY_INFO, k_kv, 32) != M5_OK) return KV_E_CRYPTO;
    if (m5_hkdf_expand(k_domain, (const uint8_t *)ENVID_KEY_INFO, sizeof ENVID_KEY_INFO, k_envid_kv, 32) != M5_OK) return KV_E_CRYPTO;
    return KV_OK;
}

int kv_envelope_ids(const uint8_t k_envid_kv[32], const uint8_t store_uuid[16], const uint8_t namespace_id[32],
                    const uint8_t chunk_key[32], uint32_t slot_index, uint64_t slot_incarnation,
                    uint64_t key_generation, uint8_t identity_class, uint64_t payload_len,
                    const uint8_t payload_sha256[32], uint8_t envelope_id[16], uint8_t nonce_prefix[8])
{
    if (!k_envid_kv || !store_uuid || !namespace_id || !chunk_key || !payload_sha256 || !envelope_id || !nonce_prefix) return KV_E_ARG;
    uint8_t m[sizeof ENVID_DOMAIN + 16 + 32 + 32 + 4 + 8 + 8 + 1 + 8 + 32];
    size_t o = 0;
    memcpy(m + o, ENVID_DOMAIN, sizeof ENVID_DOMAIN);
    o += sizeof ENVID_DOMAIN;
    memcpy(m + o, store_uuid, 16);
    o += 16;
    memcpy(m + o, namespace_id, 32);
    o += 32;
    memcpy(m + o, chunk_key, 32);
    o += 32;
    put32(m, o, slot_index);
    o += 4;
    put64(m, o, slot_incarnation);
    o += 8;
    put64(m, o, key_generation);
    o += 8;
    m[o++] = identity_class;
    put64(m, o, payload_len);
    o += 8;
    memcpy(m + o, payload_sha256, 32);
    o += 32;
    uint8_t mac[32];
    aienos_hmac_sha256(k_envid_kv, m, o, mac);
    memcpy(envelope_id, mac, 16);
    memcpy(nonce_prefix, mac + 16, 8);
    return KV_OK;
}

void kv_slot_binding(const uint8_t store_uuid[16], const uint8_t envelope_id[16], uint64_t key_generation,
                     uint8_t identity_class, m5_object_binding *out)
{
    memset(out, 0, sizeof *out);
    memcpy(out->store_uuid, store_uuid, 16);
    out->object_kind = KV_OBJECT_KIND;
    out->object_version = KV_OBJECT_VERSION;
    memcpy(out->envelope_id, envelope_id, 16);
    out->key_generation = key_generation;
    out->identity_class = identity_class;
}
