/* M5 chunked AES-256-GCM-SIV object envelope. Byte-compatible port of
 * crates/aienos-kernel/src/crypto/envelope.rs (V1 header and chunk AAD).
 *
 * Header (64 bytes, little-endian), as EnvelopeHeader::encode:
 *   0 magic "AIENENV1" | 8 version u16 = 1 | 10 cipher_suite u16 = 1
 *   12 flags u32 = 0 | 16 chunk_size u32 | 20 total_plaintext_len u64
 *   28 envelope_id[16] | 44 nonce_prefix[8] | 52 key_epoch u64 | 60 reserved u32 = 0
 * Body: chunks of (ciphertext || 16-byte tag); an empty plaintext is one
 * chunk holding only a tag. Chunk nonce: nonce_prefix[8] || chunk_index u32le.
 * Chunk AAD (AGENTS.md section 3, 111 bytes): "AIENOS-M5-CHUNK-V1\0" ||
 *   store_uuid || kind u16 || version u16 || header[64] || chunk_index u32 ||
 *   chunk_plaintext_length u32.
 * No ObjectId and no Store generation enter the AAD or the key. Truncation
 * and extension are refused because total_plaintext_len is in every chunk's
 * AAD and the length must match it exactly.
 * Chunk key: m5_derive_object_key (store, kind, version, envelope_id,
 * key generation, identity class), so a chunk from another envelope fails.
 */
#include "m5_internal.h"

#define CHUNK_AAD_LABEL "AIENOS-M5-CHUNK-V1"
#define CHUNK_AAD_LEN (sizeof(CHUNK_AAD_LABEL) + 16 + 2 + 2 + M5_ENV_HEADER_LEN + 4 + 4)
_Static_assert(CHUNK_AAD_LEN == 111, "chunk AAD must match envelope.rs CHUNK_AAD_LEN");

static uint64_t chunks_for(uint64_t pt_len, uint32_t chunk_size)
{
    return pt_len == 0 ? 1 : pt_len / chunk_size + (pt_len % chunk_size != 0);
}

size_t m5_envelope_len(uint64_t pt_len, uint32_t chunk_size)
{
    if (chunk_size == 0 || chunk_size > M5_ENV_MAX_CHUNK) return 0;
    if (pt_len > M5_ENV_MAX_PLAINTEXT) return 0;
    uint64_t chunks = chunks_for(pt_len, chunk_size);
    if (chunks > M5_ENV_MAX_CHUNKS) return 0;
    uint64_t len = M5_ENV_HEADER_LEN + pt_len + chunks * M5_TAG_LEN;
    if (len > SIZE_MAX) return 0;
    return (size_t)len;
}

static void header_encode(const m5_env_header *h, uint8_t out[M5_ENV_HEADER_LEN])
{
    memset(out, 0, M5_ENV_HEADER_LEN);
    memcpy(out, "AIENENV1", 8);
    m5_put16(out + 8, h->version);
    m5_put16(out + 10, h->cipher_suite);
    m5_put32(out + 12, h->flags);
    m5_put32(out + 16, h->chunk_size);
    m5_put64(out + 20, h->total_plaintext_len);
    memcpy(out + 28, h->envelope_id, 16);
    memcpy(out + 44, h->nonce_prefix, 8);
    m5_put64(out + 52, h->key_epoch);
}

int m5_envelope_parse_header(const uint8_t *env, size_t env_len, m5_env_header *h)
{
    if (!env || !h) return M5_ERR_ARG;
    memset(h, 0, sizeof *h);
    if (env_len < M5_ENV_HEADER_LEN) return M5_ERR_BOUNDS;
    if (memcmp(env, "AIENENV1", 8) != 0) return M5_ERR_FORMAT;
    h->version = m5_get16(env + 8);
    h->cipher_suite = m5_get16(env + 10);
    h->flags = m5_get32(env + 12);
    h->chunk_size = m5_get32(env + 16);
    h->total_plaintext_len = m5_get64(env + 20);
    memcpy(h->envelope_id, env + 28, 16);
    memcpy(h->nonce_prefix, env + 44, 8);
    h->key_epoch = m5_get64(env + 52);
    if (h->version != 1 || h->cipher_suite != 1 || h->flags != 0) return M5_ERR_FORMAT;
    if (m5_get32(env + 60) != 0) return M5_ERR_FORMAT;
    /* Bound every unauthenticated length before deriving anything from it. */
    if (h->chunk_size == 0 || h->chunk_size > M5_ENV_MAX_CHUNK) return M5_ERR_BOUNDS;
    if (h->total_plaintext_len > M5_ENV_MAX_PLAINTEXT) return M5_ERR_BOUNDS;
    uint64_t count = chunks_for(h->total_plaintext_len, h->chunk_size);
    if (count > M5_ENV_MAX_CHUNKS) return M5_ERR_BOUNDS;
    h->chunk_count = (uint32_t)count;
    size_t want = m5_envelope_len(h->total_plaintext_len, h->chunk_size);
    if (want == 0 || env_len != want) return M5_ERR_BOUNDS; /* GUARD:env-len */
    return M5_OK;
}

static void chunk_aad(const m5_object_binding *b, const uint8_t hdr[M5_ENV_HEADER_LEN],
                      uint32_t idx, uint32_t len, uint8_t aad[CHUNK_AAD_LEN])
{
    uint8_t *p = aad;
    memcpy(p, CHUNK_AAD_LABEL, sizeof(CHUNK_AAD_LABEL)); p += sizeof(CHUNK_AAD_LABEL);
    memcpy(p, b->store_uuid, 16); p += 16;
    m5_put16(p, b->object_kind); p += 2;
    m5_put16(p, b->object_version); p += 2;
    memcpy(p, hdr, M5_ENV_HEADER_LEN); p += M5_ENV_HEADER_LEN;
    m5_put32(p, idx); p += 4;
    m5_put32(p, len);
}

static void chunk_nonce(const uint8_t prefix[8], uint32_t idx, uint8_t nonce[12])
{
    memcpy(nonce, prefix, 8);
    m5_put32(nonce + 8, idx);
}

int m5_envelope_seal(const uint8_t domain_key[32], const m5_object_binding *b,
                     const uint8_t nonce_prefix[8], uint32_t chunk_size,
                     const uint8_t *pt, size_t pt_len,
                     uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (out_len) *out_len = 0;
    if (!domain_key || !b || !nonce_prefix || !out || !out_len || (!pt && pt_len)) return M5_ERR_ARG;
    if (!m5_valid_class(b->identity_class)) return M5_ERR_ARG;
    size_t total = m5_envelope_len(pt_len, chunk_size);
    if (total == 0) return M5_ERR_BOUNDS;
    if (out_cap < total) return M5_ERR_SPACE;

    m5_env_header h;
    memset(&h, 0, sizeof h);
    h.version = 1;
    h.cipher_suite = 1;
    h.chunk_size = chunk_size;
    h.total_plaintext_len = pt_len;
    memcpy(h.envelope_id, b->envelope_id, 16);
    memcpy(h.nonce_prefix, nonce_prefix, 8);
    h.key_epoch = b->key_generation;
    h.chunk_count = (uint32_t)chunks_for(pt_len, chunk_size);
    header_encode(&h, out);

    uint8_t key[32];
    m5_derive_object_key(domain_key, b, key);
    size_t off = M5_ENV_HEADER_LEN, pos = 0;
    int rc = M5_OK;
    for (uint32_t i = 0; i < h.chunk_count; i++) {
        size_t n = pt_len - pos < chunk_size ? pt_len - pos : chunk_size;
        uint8_t aad[CHUNK_AAD_LEN], nonce[12];
        chunk_aad(b, out, i, (uint32_t)n, aad);
        chunk_nonce(nonce_prefix, i, nonce);
        if (aienos_gcmsiv_seal(key, nonce, aad, sizeof aad, n ? pt + pos : NULL, n,
                               out + off, n + M5_TAG_LEN) != AIENOS_CRYPTO_OK) {
            rc = M5_ERR_ARG;
            break;
        }
        pos += n;
        off += n + M5_TAG_LEN;
    }
    aienos_wipe(key, sizeof key);
    if (rc != M5_OK) { aienos_wipe(out, total); return rc; }
    *out_len = total;
    return M5_OK;
}

int m5_envelope_open(const uint8_t domain_key[32], uint8_t mode, const m5_object_binding *expect,
                     const uint8_t *env, size_t env_len,
                     uint8_t *out, size_t out_cap, size_t *out_len)
{
    /* All-or-nothing: the caller's buffer is zero on every error path. */
    if (out && out_cap) aienos_wipe(out, out_cap);
    if (out_len) *out_len = 0;
    if (!domain_key || !expect || !env || !out_len || (!out && out_cap)) return M5_ERR_ARG;

    m5_env_header h;
    int rc = m5_envelope_parse_header(env, env_len, &h);
    if (rc != M5_OK) return rc;
    if (expect->identity_class != mode) return M5_ERR_IDENTITY; /* GUARD:env-mode */
    /* Authenticated header fields (they are in every chunk's AAD) must name
     * the envelope the caller expects. */
    if (memcmp(h.envelope_id, expect->envelope_id, 16) != 0) return M5_ERR_BINDING; /* GUARD:env-envid */
    if (h.key_epoch != expect->key_generation) return M5_ERR_BINDING; /* GUARD:env-keygen */
    if (out_cap < h.total_plaintext_len) return M5_ERR_SPACE;

    /* Private scratchpad: a chunk is decrypted here, its tag checked, and only
     * then copied to the caller (AGENTS.md section 4). Unauthenticated
     * plaintext never reaches the caller buffer. */
    uint8_t key[32], scratch[M5_ENV_MAX_CHUNK];
    m5_derive_object_key(domain_key, expect, key);
    size_t off = M5_ENV_HEADER_LEN, pos = 0;
    for (uint32_t i = 0; i < h.chunk_count; i++) {
        size_t n = h.total_plaintext_len - pos < h.chunk_size ? h.total_plaintext_len - pos : h.chunk_size;
        uint8_t aad[CHUNK_AAD_LEN], nonce[12];
        chunk_aad(expect, env, i, (uint32_t)n, aad);
        chunk_nonce(h.nonce_prefix, i, nonce);
        if (aienos_gcmsiv_open(key, nonce, aad, sizeof aad, env + off, n + M5_TAG_LEN,
                               scratch, n) != AIENOS_CRYPTO_OK) {
            rc = M5_ERR_AUTH;
            break;
        }
        if (n) memcpy(out + pos, scratch, n);
        pos += n;
        off += n + M5_TAG_LEN;
    }
    aienos_wipe(scratch, sizeof scratch);
    aienos_wipe(key, sizeof key);
    if (rc != M5_OK) {
        /* A verified prefix never becomes partial success. */
        aienos_wipe(out, out_cap); /* GUARD:wipe-all */
        return rc;
    }
    *out_len = (size_t)h.total_plaintext_len;
    return M5_OK;
}
