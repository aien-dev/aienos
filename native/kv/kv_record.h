/*
 * kv_record.h -- C twin of the persistent-KV record codec (sovereign-core
 * ADR 0003 sections 1, 2.1, 2.5 and 12; crates/aien-kv-store identity.rs,
 * record.rs, validate.rs), plus the native slot header unit.
 *
 * Pinned to sovereign-core by CONTRACT.lock and the golden vectors in
 * tests/golden. Byte layouts, error order and check order follow the Rust
 * crate line by line, so a malformed input fails with the same error in both
 * languages.
 *
 * No heap, no clock, no I/O, no floating point: floats arrive as their IEEE
 * bit patterns. Every function fills caller memory and returns KV_OK or a
 * negative KV_E_* code. SHA-256 is native/argus/sha256.c; HKDF and HMAC are
 * native/m5 and native/crypto.
 *
 * Values the Rust type system cannot represent (a dtype outside 1..5, a bool
 * byte above 1, a NULL pointer) are refused with KV_E_ARG.
 */
#ifndef AIENOS_KV_RECORD_H
#define AIENOS_KV_RECORD_H

#include <stddef.h>
#include <stdint.h>

#include "m5.h"     /* native/m5: m5_object_binding, envelope bounds */
#include "sha256.h" /* native/argus */

/* ---- record layout (ADR 2.1, 12 H1-H3) ---- */
#define KV_HEADER_LEN 256u
#define KV_HEADER_REGION_LEN 4096u
#define KV_PAYLOAD_OFFSET 4096u
#define KV_MAX_SEGMENTS 120u
#define KV_SEGMENT_TABLE_OFFSET 256u
#define KV_HASHED_PREFIX_LEN 224u
#define KV_FORMAT_VERSION 1u
#define KV_RECORD_KIND_CHUNK 1u
#define KV_FLAG_PARTIAL_TAIL 1u
#define KV_MAX_SHARING_NAMESPACE_BYTES 64u
#define KV_MAX_ARITH_ID_BYTES 255u

/* ADR 1.2 field 9 and 11. */
#define KV_DTYPE_FP4 1u
#define KV_DTYPE_FP8 2u
#define KV_DTYPE_BF16 3u
#define KV_DTYPE_FP16 4u
#define KV_DTYPE_FP32 5u
#define KV_BACKEND_HOST_PAGED_POOL_V1 1u
#define KV_BACKEND_NATIVE_F32_DECODE_STATE_V1 2u
#define KV_HIDDEN_ACT_SILU 1u

/* Errors. KV_E_TRUNCATED .. KV_E_OVERFLOW follow the Rust `KvError` variant
 * order (-1 is the first variant); the Rust payload of FieldTooLong (the field
 * name) is dropped. KV_E_ARG and the KV_E_SLOT_* codes exist only in C. */
enum {
    KV_OK = 0,
    KV_E_TRUNCATED = -1,
    KV_E_BAD_MAGIC = -2,
    KV_E_UNSUPPORTED_VERSION = -3,
    KV_E_BAD_RECORD_KIND = -4,
    KV_E_BAD_HEADER_LEN = -5,
    KV_E_HEADER_CHECKSUM = -6,
    KV_E_BAD_FLAGS = -7,
    KV_E_BAD_PADDING = -8,
    KV_E_SEGMENT_ROOT_MISMATCH = -9,
    KV_E_TOO_MANY_SEGMENTS = -10,
    KV_E_NAMESPACE_MISMATCH = -11,
    KV_E_KEY_MISMATCH = -12,
    KV_E_PARENT_MISMATCH = -13,
    KV_E_POSITION_MISMATCH = -14,
    KV_E_TOKEN_COUNT_OUT_OF_RANGE = -15,
    KV_E_TOKEN_COUNT_MISMATCH = -16,
    KV_E_GEOMETRY_MISMATCH = -17,
    KV_E_PAYLOAD_LEN_MISMATCH = -18,
    KV_E_FILE_SIZE_MISMATCH = -19,
    KV_E_FIELD_TOO_LONG = -20,
    KV_E_INVALID_GEOMETRY = -21,
    KV_E_OVERFLOW = -22,
    /* C only */
    KV_E_ARG = -23,            /* NULL, caller buffer too small, or an unrepresentable value */
    KV_E_CRYPTO = -24,         /* HKDF or HMAC refused its input */
    KV_E_SLOT_CHECKSUM = -25,  /* slot unit_sha256 does not match bytes 0..4064 */
    KV_E_SLOT_PADDING = -26,   /* nonzero byte in slot bytes 340..4064 */
    KV_E_SLOT_BACKEND = -27,   /* slot record is not backend_format 2 (native) */
    KV_E_SLOT_ENVELOPE = -28,  /* M5 envelope header field is not the fixed value */
    KV_E_SLOT_BOUNDS = -29,    /* payload_len / sealed_units / envelope_len out of bounds */
    KV_E_SLOT_INDEX = -30      /* slot_index is not the slot's position in the slab */
};

/* ---- identity inputs (ADR 1.2, 1.2.1) ---- */

typedef struct {
    uint64_t head_stride, token_stride, kv_plane_stride, layer_stride, block_stride, element_bytes;
} kv_layout;

typedef struct {
    uint8_t present; /* 0 none, 1 llama3 */
    uint64_t factor_bits, low_freq_factor_bits, high_freq_factor_bits; /* f64 bit patterns */
    uint64_t original_max_position_embeddings;
} kv_rope_scaling;

/* ComputeConfig (ADR 1.2.1 / 12 I3). Strings are pointer + byte length (no
 * NUL needed, embedded NULs are hashed). */
typedef struct {
    uint32_t num_heads;
    uint64_t hidden_dim, intermediate_dim, vocab_size;
    uint32_t rms_norm_eps_bits; /* f32 bit pattern */
    uint8_t tie_word_embeddings; /* 0 or 1 */
    uint8_t hidden_act;          /* KV_HIDDEN_ACT_SILU */
    const char *arith_id;        /* at most 255 bytes */
    size_t arith_id_len;
    uint32_t arith_epoch;
} kv_compute_config;

/* NamespaceFields (ADR 1.2 fields 2-14; field 1, format_version, is a constant). */
typedef struct {
    uint8_t model_sha256[32];
    const char *model_digest_kind; /* at most 255 bytes */
    size_t model_digest_kind_len;
    const char *model_id; /* at most 65535 bytes */
    size_t model_id_len;
    uint32_t num_layers, num_kv_heads, head_dim, block_size;
    uint32_t rope_theta_bits; /* f32 bit pattern */
    kv_rope_scaling rope_scaling;
    uint8_t qk_norm; /* 0 or 1 */
    uint8_t dtype;   /* KV_DTYPE_* */
    kv_layout layout;
    uint8_t backend_format; /* KV_BACKEND_* */
    uint32_t chunk_tokens;
    const char *sharing_namespace; /* at most 64 bytes */
    size_t sharing_namespace_len;
    uint8_t compute_config_digest[32];
} kv_namespace_fields;

/* SHA-256("AIEN-PKV-CFG-V1\0" || ...) */
int kv_compute_config_digest(const kv_compute_config *c, uint8_t out[32]);
/* SHA-256("AIEN-PKV-NS-V1\0" || fields 1-14). Checks geometry first, as Rust. */
int kv_namespace_id(const kv_namespace_fields *f, uint8_t out[32]);

/* Payload size for token_count positions (ADR 2.2, 2.3), checked arithmetic. */
int kv_expected_payload_len(const kv_namespace_fields *f, uint32_t token_count, uint64_t *out);
/* ADR 12 H8: host = block_stride, native = the whole payload. */
int kv_segment_bytes(const kv_namespace_fields *f, uint32_t token_count, uint64_t *out);
/* ceil(payload_len / segment_bytes) for the namespace, at most KV_MAX_SEGMENTS. */
int kv_ns_segment_count(const kv_namespace_fields *f, uint32_t token_count, uint32_t *out);
/* ceil(payload_len / segment_bytes); INVALID_GEOMETRY for a zero size,
 * TOO_MANY_SEGMENTS above 120. */
int kv_segment_count(uint64_t payload_len, uint64_t segment_bytes, uint32_t *out);

/* ADR 1.3. parent is NULL for the first chunk (hashed as 32 zero bytes).
 * Tokens are hashed as u32 little-endian whatever the host byte order. */
int kv_chunk_key(const uint8_t ns[32], const uint8_t parent[32], uint32_t first_position,
                 const uint32_t *tokens, size_t n_tokens, uint8_t out[32]);
/* Keys for every chunk: full chunks, then an optional partial tail. keys_cap is
 * the capacity of keys in entries; *n_keys receives the count. */
int kv_chunk_chain(const uint8_t ns[32], uint32_t chunk_tokens, const uint32_t *tokens,
                   size_t n_tokens, uint8_t (*keys)[32], size_t keys_cap, size_t *n_keys);

/* ---- the 256-byte record header (ADR 2.1) ---- */

typedef struct {
    uint8_t namespace_id[32];
    uint8_t chunk_key[32];
    uint8_t parent_key[32]; /* all zero for the first chunk */
    uint8_t model_sha256[32];
    uint32_t first_position, token_count, chunk_tokens, block_size;
    uint32_t num_layers, num_kv_heads, head_dim;
    uint8_t dtype, backend_format;
    uint16_t flags;
    uint64_t payload_len;
    uint64_t written_unix_ns; /* informational, not identity */
} kv_chunk_header;

typedef struct {
    kv_chunk_header chunk;
    uint8_t payload_sha256[32];
} kv_record_header;

/* The header a writer emits (and a reader expects) for one chunk. parent is
 * NULL for the first chunk. Sets partial_tail when token_count < chunk_tokens. */
int kv_chunk_header_build(const kv_namespace_fields *f, const uint8_t ns[32],
                          const uint8_t chunk_key[32], const uint8_t parent[32],
                          uint32_t first_position, uint32_t token_count,
                          uint64_t written_unix_ns, kv_chunk_header *out);

/* Serialize to exactly 256 bytes, computing header_sha256. */
void kv_header_encode(const kv_record_header *h, uint8_t out[KV_HEADER_LEN]);
/* Decode the 256-byte struct (len >= 256): length, magic, version, kind,
 * header_len, header checksum, reserved flag bits. */
int kv_header_decode_struct(const uint8_t *buf, size_t len, kv_record_header *out);
/* Decode a header region: needs the whole 4096 bytes (TRUNCATED below). */
int kv_header_decode(const uint8_t *buf, size_t len, kv_record_header *out);

/* SHA-256("AIEN-PKV-PAYLOAD-V1\0" || seg_digest_0 || ...), the value at offset 184. */
void kv_payload_root(const uint8_t (*seg_digests)[32], size_t n, uint8_t out[32]);
/* Struct, then the segment digest table, then zeros. Does not check that
 * payload_sha256 is the root of seg_digests; validation does. */
int kv_region_encode(const kv_record_header *h, const uint8_t (*seg_digests)[32], size_t n,
                     uint8_t out[KV_HEADER_REGION_LEN]);

/* Validation before any allocation or copy (ADR 1.4). buf is the first 4096
 * bytes of a record, file_size the total size, expect the header the caller
 * derived (written_unix_ns ignored), segment_bytes the segment size the caller
 * derived from its own geometry. Order: length, magic, version, kind,
 * header_len, header checksum, reserved flags, namespace, key, parent,
 * position, token count range, token count, geometry, partial flag,
 * payload_len, segment count, padding, segment root, file size. The first
 * failure is returned; nothing is allocated and no payload byte is touched.
 * out may be NULL. */
int kv_validate_record(const uint8_t *buf, size_t len, uint64_t file_size,
                       const kv_chunk_header *expect, uint64_t segment_bytes,
                       kv_record_header *out);

/* ---- native slot header unit (ADR 2.5, finding 12) ---- */

#define KV_SLOT_UNIT 4096u
#define KV_SLOT_ENV_OFFSET 256u        /* M5 envelope header, 64 bytes */
#define KV_SLOT_INCARNATION_OFFSET 320u
#define KV_SLOT_SEALED_UNITS_OFFSET 328u
#define KV_SLOT_ENVELOPE_LEN_OFFSET 332u
#define KV_SLOT_INDEX_OFFSET 336u
#define KV_SLOT_ZERO_OFFSET 340u       /* zero through 4063 */
#define KV_SLOT_HASH_OFFSET 4064u      /* unit_sha256 = SHA-256(bytes 0..4064) */
#define KV_SLOT_CHUNK_SIZE 4080u       /* M5 chunk plaintext size */
#define KV_SLOT_MAX_PAYLOAD 16711680u  /* M5_ENV_MAX_CHUNKS * 4080 */
#define KV_OBJECT_KIND 0x0520u         /* m5_object_binding.object_kind of a slot */
#define KV_OBJECT_VERSION 1u

typedef struct {
    kv_record_header rec; /* record header, payload_sha256 = native root */
    uint8_t envelope_id[16];
    uint8_t nonce_prefix[8];
    uint64_t key_epoch; /* the M5 key_generation */
    uint64_t slot_incarnation;
    uint32_t slot_index;
    /* Derived from rec.chunk.payload_len; set by decode, ignored by encode
     * (encode always writes the derived values). */
    uint32_t sealed_units;
    uint32_t envelope_len;
} kv_slot_header;

/* sealed_len = payload_len + 16 * ceil(payload_len / 4080), sealed_units =
 * ceil(sealed_len / 4096), envelope_len = 64 + sealed_len. KV_E_SLOT_BOUNDS
 * unless payload_len is in 1..=16711680. The unit tests check these against
 * m5_envelope_len(payload_len, 4080). */
int kv_slot_geometry(uint64_t payload_len, uint32_t *sealed_units, uint32_t *envelope_len);
/* Write the 4096-byte slot header unit. KV_E_SLOT_BOUNDS for a payload_len out
 * of bounds. */
int kv_slot_encode(const kv_slot_header *s, uint8_t out[KV_SLOT_UNIT]);
/* Decode and bounds-check a slot header unit without any key material and
 * before any payload read or decrypt. Order: length (TRUNCATED), unit_sha256
 * (SLOT_CHECKSUM), zero region (SLOT_PADDING), record header structure (as
 * kv_header_decode_struct), backend_format 2 (SLOT_BACKEND), M5 envelope
 * header constants (SLOT_ENVELOPE), total_plaintext_len = payload_len and the
 * payload / sealed_units / envelope_len bounds (SLOT_BOUNDS), slot_index
 * (SLOT_INDEX). Any failure means "empty slot" to recovery. */
int kv_slot_decode(const uint8_t *unit, size_t len, uint32_t slot_index, kv_slot_header *out);
/* kv_slot_decode, then, if expect is not NULL, the identity checks of
 * kv_validate_record (namespace .. payload_len; no region or file-size rules,
 * which do not exist in a slot). expect NULL is the recovery scan: a slot is
 * valid whatever its namespace. */
int kv_slot_validate(const uint8_t *unit, size_t len, uint32_t slot_index,
                     const kv_chunk_header *expect, kv_slot_header *out);

/* ---- authenticated mapping from KV identity into M5 inputs (ADR 2.5) ---- */

/* k_kv = HKDF-Expand(k_domain, "AIENOS-PKV-SLOT-KEY-V1\0", 32) and
 * k_envid_kv = HKDF-Expand(k_domain, "AIENOS-PKV-ENVID-KEY-V1\0", 32). */
int kv_slot_keys(const uint8_t k_domain[32], uint8_t k_kv[32], uint8_t k_envid_kv[32]);
/* envelope_id[16] || nonce_prefix[8] = first 24 bytes of
 * HMAC-SHA256(k_envid_kv, "AIENOS-PKV-ENVID-V1\0" || store_uuid || namespace_id
 * || chunk_key || slot_index u32 || slot_incarnation u64 || key_generation u64
 * || identity_class u8 || payload_len u64 || payload_sha256). */
int kv_envelope_ids(const uint8_t k_envid_kv[32], const uint8_t store_uuid[16],
                    const uint8_t namespace_id[32], const uint8_t chunk_key[32],
                    uint32_t slot_index, uint64_t slot_incarnation, uint64_t key_generation,
                    uint8_t identity_class, uint64_t payload_len, const uint8_t payload_sha256[32],
                    uint8_t envelope_id[16], uint8_t nonce_prefix[8]);
/* m5_object_binding of a slot: object_kind 0x0520, object_version 1. */
void kv_slot_binding(const uint8_t store_uuid[16], const uint8_t envelope_id[16],
                     uint64_t key_generation, uint8_t identity_class, m5_object_binding *out);

#endif /* AIENOS_KV_RECORD_H */
