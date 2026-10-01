/*
 * store_v1.h -- C twin of the System Store v1 format primitives (ADR 0015),
 * byte-identical to crates/aienos-kernel/src/store/v1.rs.
 *
 * No heap, no clock, no I/O. Every function either fills caller memory or
 * returns a FormatError code. Error precedence follows the Rust code line by
 * line so a malformed input fails with the same error in both languages.
 */
#ifndef AIENOS_STORE_V1_H
#define AIENOS_STORE_V1_H

#include <stddef.h>
#include <stdint.h>

#include "sha256.h" /* native/argus */

#define SV1_UNIT 4096u
#define SV1_MAX_CATALOG_ENTRIES 4096u
#define SV1_CATALOG_HEADER 16u
#define SV1_CATALOG_ENTRY 64u
#define SV1_MAX_OBJECT_BYTES UINT64_C(67108864)
#define SV1_MAX_OBJECT_UNITS 16384u
#define SV1_MAX_TRANSACTION_OBJECTS 256u
#define SV1_MAX_TRANSACTION_UNITS UINT64_C(32768)
#define SV1_MAX_REGION_UNITS UINT64_C(4294967296)
#define SV1_KIND_CATALOG 1u
#define SV1_KIND_COMMIT 2u
#define SV1_VERSION 1u
#define SV1_COMMIT_BYTES 200u
#define SV1_SB_CRC_OFFSET 168u
#define SV1_SB_RESERVED_OFFSET 172u
/* A full catalog: 16 + 4096 * 64 bytes = 65 units. */
#define SV1_MAX_CATALOG_UNITS 65u

/* FormatError, in the Rust enum order. 0 is success. */
enum {
    SV1_OK = 0,
    SV1_E_INVALID_LENGTH = -1,
    SV1_E_INVALID_OBJECT = -2,
    SV1_E_OBJECT_TOO_LARGE = -3,
    SV1_E_LENGTH_OVERFLOW = -4,
    SV1_E_MALFORMED_DESCRIPTOR = -5,
    SV1_E_OUT_OF_BOUNDS = -6,
    SV1_E_OVERLAP = -7,
    SV1_E_CATALOG_TOO_LARGE = -8,
    SV1_E_CATALOG_ORDER = -9,
    SV1_E_DUPLICATE_OBJECT = -10,
    SV1_E_BAD_CATALOG_MAGIC = -11,
    SV1_E_UNSUPPORTED_VERSION = -12,
    SV1_E_MALFORMED_COMMIT = -13,
    SV1_E_MALFORMED_SUPERBLOCK = -14,
    SV1_E_BAD_SUPERBLOCK_MAGIC = -15,
    SV1_E_BAD_SUPERBLOCK_CRC = -16,
    SV1_E_NONZERO_RESERVED = -17,
    SV1_E_WRONG_SUPERBLOCK_SLOT = -18,
    SV1_E_UNSUPPORTED_FEATURES = -19,
    SV1_E_INTEGRITY = -20,
    SV1_E_INVALID_GENERATION = -21,
    SV1_E_CONFLICTING_ROOTS = -22,
    SV1_E_INCONSISTENT_HISTORY = -23,
    /* C only: a caller buffer is too small or a pointer is NULL. Rust has
     * no equivalent because it allocates. */
    SV1_E_ARG = -24,
};

const char *sv1_strerror(int e);

typedef struct {
    uint8_t object_id[32];
    uint16_t kind;
    uint16_t version;
    uint64_t first_unit;
    uint64_t byte_length;
    uint32_t unit_count;
    uint16_t flags;
} sv1_entry;

typedef struct {
    uint8_t store_uuid[16];
    uint64_t region_units;
    uint64_t generation;
    uint64_t previous_generation;
    uint8_t previous_commit_id[32];
    uint8_t previous_catalog_id[32];
    uint8_t catalog_id[32];
    uint64_t catalog_first_unit;
    uint64_t catalog_byte_length;
    uint32_t catalog_unit_count;
    uint32_t catalog_entry_count;
    uint64_t committed_high_water;
} sv1_commit;

typedef struct {
    uint8_t store_uuid[16];
    uint32_t slot_id;
    uint64_t region_units;
    uint64_t generation;
    uint8_t commit_record_id[32];
    uint64_t commit_record_unit;
    uint8_t catalog_id[32];
    uint64_t catalog_first_unit;
    uint64_t catalog_byte_length;
    uint32_t catalog_unit_count;
    uint32_t catalog_entry_count;
    uint64_t committed_high_water;
} sv1_superblock;

/* (first_unit, end) pair used by the overlap check. */
typedef struct {
    uint64_t first;
    uint64_t end;
} sv1_extent;

/* ---- byte helpers (freestanding) ---- */
void sv1_put16(uint8_t *b, uint16_t v);
void sv1_put32(uint8_t *b, uint32_t v);
void sv1_put64(uint8_t *b, uint64_t v);
uint16_t sv1_get16(const uint8_t *b);
uint32_t sv1_get32(const uint8_t *b);
uint64_t sv1_get64(const uint8_t *b);
void sv1_copy(void *dst, const void *src, size_t n);
void sv1_zero(void *dst, size_t n);
int sv1_equal(const void *a, const void *b, size_t n); /* 1 if equal */
int sv1_all_zero(const void *a, size_t n);             /* 1 if all zero */
int sv1_cmp_id(const uint8_t a[32], const uint8_t b[32]); /* memcmp order */

/* CRC-32C (Castagnoli), reflected 0x82f63b78, init/xorout 0xffffffff. */
uint32_t sv1_crc32c(const uint8_t *bytes, size_t len);

/* ---- ObjectId ---- */
/* ObjectId::calculate. */
int sv1_object_id(uint16_t kind, uint16_t version, const uint8_t *bytes, uint64_t len,
                  uint8_t out[32]);
/* Streaming form: checks kind/version/len like calculate and hashes the
 * domain and descriptor into ctx (an argus sha256_ctx). The caller then
 * feeds exactly len semantic bytes and finalizes. */

int sv1_object_id_begin(sha256_ctx *ctx, uint16_t kind, uint16_t version, uint64_t len);
/* ObjectId::validate_extent. */
int sv1_validate_extent(const uint8_t id[32], uint16_t kind, uint16_t version,
                        uint64_t byte_length, const uint8_t *extent, size_t extent_len);
/* object_unit_count. */
int sv1_unit_count(uint64_t byte_length, uint32_t *units);

/* ---- CatalogEntry ---- */
int sv1_entry_encode(const sv1_entry *e, uint8_t out[64]);
int sv1_entry_decode(const uint8_t *bytes, size_t len, sv1_entry *out);
int sv1_entry_validate_bounds(const sv1_entry *e, uint64_t region_units,
                              uint64_t catalog_first_unit, uint64_t committed_high_water);
int sv1_entry_equal(const sv1_entry *a, const sv1_entry *b);

/* ---- Catalog ---- */
/* Semantic length for n entries (16 + 64n). */
uint64_t sv1_catalog_len(uint64_t n);
int sv1_catalog_encode(const sv1_entry *entries, size_t n, uint8_t *out, size_t cap,
                       size_t *out_len);
int sv1_catalog_decode(const uint8_t *bytes, size_t len, sv1_entry *entries, size_t cap,
                       uint32_t *n_out);
/* Catalog::validate_extents; scratch must hold n extents. */
int sv1_catalog_validate_extents(const sv1_entry *entries, size_t n, uint64_t region_units,
                                 uint64_t catalog_first_unit, uint64_t committed_high_water,
                                 sv1_extent *scratch);
/* Index of id in a sorted catalog, or -1. */
long sv1_catalog_find(const sv1_entry *entries, size_t n, const uint8_t id[32]);
/* In-place sort by ObjectId (heapsort; ids are expected unique). */
void sv1_sort_entries(sv1_entry *entries, size_t n);
/* In-place sort by (first, end). */
void sv1_sort_extents(sv1_extent *x, size_t n);

/* ---- CommitRecord ---- */
int sv1_commit_validate(const sv1_commit *c);
int sv1_commit_encode(const sv1_commit *c, uint8_t out[SV1_COMMIT_BYTES]);
int sv1_commit_decode(const uint8_t *bytes, size_t len, sv1_commit *out);
int sv1_commit_object_id(const sv1_commit *c, uint8_t out[32]);
/* CommitRecord::validates_catalog. The Rust re-encoding of entries is
 * hashed as a stream, so no catalog-sized buffer is needed. */
int sv1_commit_validates_catalog(const sv1_commit *c, const uint8_t catalog_id[32],
                                 const sv1_entry *entries, size_t n);
int sv1_commit_identifies_predecessor(const sv1_commit *self, const sv1_commit *prev,
                                      const uint8_t prev_id[32]);

/* ---- Superblock ---- */
int sv1_superblock_encode(const sv1_superblock *s, uint8_t out[SV1_UNIT]);
int sv1_superblock_decode(const uint8_t *bytes, size_t len, uint32_t expected_slot,
                          sv1_superblock *out);
int sv1_superblock_validate_commit(const sv1_superblock *s, const uint8_t commit_id[32],
                                   const sv1_commit *c);
int sv1_superblock_equivalent(const sv1_superblock *a, const sv1_superblock *b);
int sv1_superblock_crc_ok(const uint8_t b[SV1_UNIT]);

/* ---- genesis (genesis.rs) ---- */
/* Units 0..3: superblock A (slot 0), all-zero slot B, empty catalog at 2,
 * genesis CommitRecord at 3. Fails (format error) for an invalid region. */
int sv1_genesis_units(const uint8_t uuid[16], uint64_t region_units, uint8_t out[4][SV1_UNIT]);

#endif /* AIENOS_STORE_V1_H */
