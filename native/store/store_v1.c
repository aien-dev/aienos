/*
 * store_v1.c -- System Store v1 format primitives, C twin of
 * crates/aienos-kernel/src/store/v1.rs. See store_v1.h.
 *
 * Lines tagged GUARD:<name> are refusal checks that `make mutants` deletes
 * one at a time; the test suite must fail for every such mutant.
 */
#include "store_v1.h"

static const uint8_t OBJECT_DOMAIN[23] = "AIENOS-STORE-OBJECT-V1"; /* + NUL */
static const uint8_t CATALOG_MAGIC[8] = {'A', 'I', 'E', 'N', 'C', 'A', 'T', '1'};
static const uint8_t COMMIT_MAGIC[8] = {'A', 'I', 'E', 'N', 'C', 'M', 'T', '1'};
static const uint8_t SUPERBLOCK_MAGIC[8] = {'A', 'I', 'E', 'N', 'S', 'T', 'R', '1'};

const char *sv1_strerror(int e)
{
    switch (e) {
    case SV1_OK: return "Ok";
    case SV1_E_INVALID_LENGTH: return "InvalidLength";
    case SV1_E_INVALID_OBJECT: return "InvalidObject";
    case SV1_E_OBJECT_TOO_LARGE: return "ObjectTooLarge";
    case SV1_E_LENGTH_OVERFLOW: return "LengthOverflow";
    case SV1_E_MALFORMED_DESCRIPTOR: return "MalformedDescriptor";
    case SV1_E_OUT_OF_BOUNDS: return "OutOfBounds";
    case SV1_E_OVERLAP: return "Overlap";
    case SV1_E_CATALOG_TOO_LARGE: return "CatalogTooLarge";
    case SV1_E_CATALOG_ORDER: return "CatalogOrder";
    case SV1_E_DUPLICATE_OBJECT: return "DuplicateObject";
    case SV1_E_BAD_CATALOG_MAGIC: return "BadCatalogMagic";
    case SV1_E_UNSUPPORTED_VERSION: return "UnsupportedVersion";
    case SV1_E_MALFORMED_COMMIT: return "MalformedCommitRecord";
    case SV1_E_MALFORMED_SUPERBLOCK: return "MalformedSuperblock";
    case SV1_E_BAD_SUPERBLOCK_MAGIC: return "BadSuperblockMagic";
    case SV1_E_BAD_SUPERBLOCK_CRC: return "BadSuperblockCrc";
    case SV1_E_NONZERO_RESERVED: return "NonzeroReserved";
    case SV1_E_WRONG_SUPERBLOCK_SLOT: return "WrongSuperblockSlot";
    case SV1_E_UNSUPPORTED_FEATURES: return "UnsupportedFeatures";
    case SV1_E_INTEGRITY: return "IntegrityFailure";
    case SV1_E_INVALID_GENERATION: return "InvalidGeneration";
    case SV1_E_CONFLICTING_ROOTS: return "ConflictingRoots";
    case SV1_E_INCONSISTENT_HISTORY: return "InconsistentHistory";
    case SV1_E_ARG: return "Arg";
    default: return "Unknown";
    }
}

/* ---- byte helpers ---- */
void sv1_put16(uint8_t *b, uint16_t v)
{
    b[0] = (uint8_t)v;
    b[1] = (uint8_t)(v >> 8);
}
void sv1_put32(uint8_t *b, uint32_t v)
{
    for (int i = 0; i < 4; i++)
        b[i] = (uint8_t)(v >> (8 * i));
}
void sv1_put64(uint8_t *b, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        b[i] = (uint8_t)(v >> (8 * i));
}
uint16_t sv1_get16(const uint8_t *b) { return (uint16_t)(b[0] | (b[1] << 8)); }
uint32_t sv1_get32(const uint8_t *b)
{
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}
uint64_t sv1_get64(const uint8_t *b)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | b[i];
    return v;
}
void sv1_copy(void *dst, const void *src, size_t n)
{
    uint8_t *d = dst;
    const uint8_t *s = src;
    for (size_t i = 0; i < n; i++)
        d[i] = s[i];
}
void sv1_zero(void *dst, size_t n)
{
    volatile uint8_t *d = dst;
    for (size_t i = 0; i < n; i++)
        d[i] = 0;
}
int sv1_equal(const void *a, const void *b, size_t n)
{
    const uint8_t *x = a, *y = b;
    for (size_t i = 0; i < n; i++)
        if (x[i] != y[i])
            return 0;
    return 1;
}
int sv1_all_zero(const void *a, size_t n)
{
    const uint8_t *x = a;
    for (size_t i = 0; i < n; i++)
        if (x[i])
            return 0;
    return 1;
}
int sv1_cmp_id(const uint8_t a[32], const uint8_t b[32])
{
    for (int i = 0; i < 32; i++)
        if (a[i] != b[i])
            return a[i] < b[i] ? -1 : 1;
    return 0;
}

uint32_t sv1_crc32c(const uint8_t *bytes, size_t len)
{
    uint32_t crc = 0xffffffffu;
    for (size_t i = 0; i < len; i++) {
        crc ^= bytes[i];
        for (int k = 0; k < 8; k++) {
            uint32_t mask = 0u - (crc & 1u);
            crc = (crc >> 1) ^ (0x82f63b78u & mask);
        }
    }
    return ~crc;
}

/* ---- ObjectId ---- */
int sv1_object_id_begin(sha256_ctx *ctx, uint16_t kind, uint16_t version, uint64_t len)
{
    if (kind == 0 || version == 0 || len == 0) return SV1_E_INVALID_OBJECT; /* GUARD:id-shape */
    if (len > SV1_MAX_OBJECT_BYTES)
        return SV1_E_OBJECT_TOO_LARGE;
    uint8_t d[12];
    sv1_put16(d, kind);
    sv1_put16(d + 2, version);
    sv1_put64(d + 4, len);
    sha256_init(ctx);
    sha256_update(ctx, OBJECT_DOMAIN, sizeof OBJECT_DOMAIN);
    sha256_update(ctx, d, sizeof d);
    return SV1_OK;
}

int sv1_object_id(uint16_t kind, uint16_t version, const uint8_t *bytes, uint64_t len,
                  uint8_t out[32])
{
    sha256_ctx ctx;
    int e = sv1_object_id_begin(&ctx, kind, version, len);
    if (e)
        return e;
    sha256_update(&ctx, bytes, (size_t)len);
    sha256_final(&ctx, out);
    return SV1_OK;
}

int sv1_unit_count(uint64_t byte_length, uint32_t *units)
{
    if (byte_length == 0)
        return SV1_E_INVALID_OBJECT;
    if (byte_length > SV1_MAX_OBJECT_BYTES)
        return SV1_E_OBJECT_TOO_LARGE;
    uint64_t u = (byte_length + SV1_UNIT - 1) / SV1_UNIT; /* cannot overflow below 2^26 */
    if (u > SV1_MAX_OBJECT_UNITS)
        return SV1_E_OBJECT_TOO_LARGE;
    *units = (uint32_t)u;
    return SV1_OK;
}

int sv1_validate_extent(const uint8_t id[32], uint16_t kind, uint16_t version,
                        uint64_t byte_length, const uint8_t *extent, size_t extent_len)
{
    uint32_t units;
    int e = sv1_unit_count(byte_length, &units);
    if (e)
        return e;
    if ((uint64_t)extent_len != (uint64_t)units * SV1_UNIT)
        return SV1_E_INVALID_LENGTH;
    if (!sv1_all_zero(extent + byte_length, extent_len - (size_t)byte_length)) return SV1_E_NONZERO_RESERVED; /* GUARD:extent-padding */
    uint8_t got[32];
    e = sv1_object_id(kind, version, extent, byte_length, got);
    if (e)
        return e;
    if (!sv1_equal(got, id, 32)) return SV1_E_INTEGRITY; /* GUARD:extent-hash */
    return SV1_OK;
}

/* ---- CatalogEntry ---- */
static int entry_validate_shape(const sv1_entry *e)
{
    if (e->kind < 3 || e->version == 0 || e->flags != 0) return SV1_E_MALFORMED_DESCRIPTOR; /* GUARD:entry-shape */
    uint32_t u;
    int r = sv1_unit_count(e->byte_length, &u);
    if (r)
        return r;
    if (u != e->unit_count) return SV1_E_MALFORMED_DESCRIPTOR; /* GUARD:entry-units */
    return SV1_OK;
}

int sv1_entry_encode(const sv1_entry *e, uint8_t out[64])
{
    int r = entry_validate_shape(e);
    if (r)
        return r;
    sv1_zero(out, 64);
    sv1_copy(out, e->object_id, 32);
    sv1_put16(out + 32, e->kind);
    sv1_put16(out + 34, e->version);
    sv1_put64(out + 36, e->first_unit);
    sv1_put64(out + 44, e->byte_length);
    sv1_put32(out + 52, e->unit_count);
    sv1_put16(out + 56, e->flags);
    return SV1_OK;
}

int sv1_entry_decode(const uint8_t *b, size_t len, sv1_entry *out)
{
    if (len != SV1_CATALOG_ENTRY)
        return SV1_E_INVALID_LENGTH;
    if (!sv1_all_zero(b + 58, 6)) return SV1_E_NONZERO_RESERVED; /* GUARD:entry-reserved */
    sv1_copy(out->object_id, b, 32);
    out->kind = sv1_get16(b + 32);
    out->version = sv1_get16(b + 34);
    out->first_unit = sv1_get64(b + 36);
    out->byte_length = sv1_get64(b + 44);
    out->unit_count = sv1_get32(b + 52);
    out->flags = sv1_get16(b + 56);
    return entry_validate_shape(out);
}

int sv1_entry_validate_bounds(const sv1_entry *e, uint64_t region_units,
                              uint64_t catalog_first_unit, uint64_t hw)
{
    int r = entry_validate_shape(e);
    if (r)
        return r;
    if (region_units < 4 || region_units > SV1_MAX_REGION_UNITS || hw < 4 || hw > region_units)
        return SV1_E_OUT_OF_BOUNDS;
    if (e->first_unit > UINT64_MAX - e->unit_count)
        return SV1_E_LENGTH_OVERFLOW;
    uint64_t end = e->first_unit + e->unit_count;
    int out_of_bounds = e->first_unit < 2 || end > catalog_first_unit || end > hw || end > region_units;
    if (out_of_bounds) return SV1_E_OUT_OF_BOUNDS; /* GUARD:entry-bounds */
    return SV1_OK;
}

int sv1_entry_equal(const sv1_entry *a, const sv1_entry *b)
{
    return sv1_equal(a->object_id, b->object_id, 32) && a->kind == b->kind &&
           a->version == b->version && a->first_unit == b->first_unit &&
           a->byte_length == b->byte_length && a->unit_count == b->unit_count &&
           a->flags == b->flags;
}

/* ---- Catalog ---- */
uint64_t sv1_catalog_len(uint64_t n) { return SV1_CATALOG_HEADER + n * SV1_CATALOG_ENTRY; }

static int check_order(const sv1_entry *entries, size_t n)
{
    for (size_t i = 0; i + 1 < n; i++) {
        int c = sv1_cmp_id(entries[i].object_id, entries[i + 1].object_id);
        if (c == 0) return SV1_E_DUPLICATE_OBJECT; /* GUARD:catalog-duplicate */
        if (c > 0) return SV1_E_CATALOG_ORDER; /* GUARD:catalog-order */
    }
    return SV1_OK;
}

int sv1_catalog_encode(const sv1_entry *entries, size_t n, uint8_t *out, size_t cap,
                       size_t *out_len)
{
    if (n > SV1_MAX_CATALOG_ENTRIES)
        return SV1_E_CATALOG_TOO_LARGE;
    int r = check_order(entries, n);
    if (r)
        return r;
    uint64_t len = sv1_catalog_len(n);
    if (!out || len > cap)
        return SV1_E_ARG;
    sv1_copy(out, CATALOG_MAGIC, 8);
    sv1_put16(out + 8, 1);
    sv1_put16(out + 10, SV1_CATALOG_ENTRY);
    sv1_put32(out + 12, (uint32_t)n);
    for (size_t i = 0; i < n; i++) {
        r = sv1_entry_encode(&entries[i], out + SV1_CATALOG_HEADER + i * SV1_CATALOG_ENTRY);
        if (r)
            return r;
    }
    *out_len = (size_t)len;
    return SV1_OK;
}

int sv1_catalog_decode(const uint8_t *b, size_t len, sv1_entry *entries, size_t cap,
                       uint32_t *n_out)
{
    if (len < SV1_CATALOG_HEADER)
        return SV1_E_INVALID_LENGTH;
    if (!sv1_equal(b, CATALOG_MAGIC, 8)) return SV1_E_BAD_CATALOG_MAGIC; /* GUARD:catalog-magic */
    if (sv1_get16(b + 8) != 1 || sv1_get16(b + 10) != SV1_CATALOG_ENTRY)
        return SV1_E_UNSUPPORTED_VERSION;
    uint32_t count = sv1_get32(b + 12);
    if (count > SV1_MAX_CATALOG_ENTRIES)
        return SV1_E_CATALOG_TOO_LARGE;
    if ((uint64_t)len != sv1_catalog_len(count)) return SV1_E_INVALID_LENGTH; /* GUARD:catalog-length */
    if (count > cap)
        return SV1_E_ARG;
    for (uint32_t i = 0; i < count; i++) {
        int r = sv1_entry_decode(b + SV1_CATALOG_HEADER + (size_t)i * SV1_CATALOG_ENTRY,
                                 SV1_CATALOG_ENTRY, &entries[i]);
        if (r)
            return r;
    }
    int r = check_order(entries, count);
    if (r)
        return r;
    *n_out = count;
    return SV1_OK;
}

static int extent_less(const sv1_extent *a, const sv1_extent *b)
{
    return a->first < b->first || (a->first == b->first && a->end < b->end);
}

static void sift_extents(sv1_extent *x, size_t start, size_t n)
{
    size_t root = start;
    for (;;) {
        size_t child = 2 * root + 1;
        if (child >= n)
            return;
        if (child + 1 < n && extent_less(&x[child], &x[child + 1]))
            child++;
        if (!extent_less(&x[root], &x[child]))
            return;
        sv1_extent t = x[root];
        x[root] = x[child];
        x[child] = t;
        root = child;
    }
}

void sv1_sort_extents(sv1_extent *x, size_t n)
{
    if (n < 2)
        return;
    for (size_t i = n / 2; i-- > 0;)
        sift_extents(x, i, n);
    for (size_t end = n - 1; end > 0; end--) {
        sv1_extent t = x[0];
        x[0] = x[end];
        x[end] = t;
        sift_extents(x, 0, end);
    }
}

int sv1_catalog_validate_extents(const sv1_entry *entries, size_t n, uint64_t region_units,
                                 uint64_t catalog_first_unit, uint64_t hw, sv1_extent *scratch)
{
    if (region_units < 4 || region_units > SV1_MAX_REGION_UNITS || hw < 4 ||
        hw > region_units || catalog_first_unit < 2 || catalog_first_unit >= region_units)
        return SV1_E_OUT_OF_BOUNDS;
    for (size_t i = 0; i < n; i++) {
        int r = sv1_entry_validate_bounds(&entries[i], region_units, catalog_first_unit, hw);
        if (r)
            return r;
        scratch[i].first = entries[i].first_unit;
        scratch[i].end = entries[i].first_unit + entries[i].unit_count;
    }
    sv1_sort_extents(scratch, n);
    for (size_t i = 0; i + 1 < n; i++)
        if (scratch[i].end > scratch[i + 1].first) return SV1_E_OVERLAP; /* GUARD:catalog-overlap */
    return SV1_OK;
}

long sv1_catalog_find(const sv1_entry *entries, size_t n, const uint8_t id[32])
{
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = sv1_cmp_id(entries[mid].object_id, id);
        if (c == 0)
            return (long)mid;
        if (c < 0)
            lo = mid + 1;
        else
            hi = mid;
    }
    return -1;
}

static void swap_entries(sv1_entry *a, sv1_entry *b)
{
    sv1_entry t = *a;
    *a = *b;
    *b = t;
}

static void sift_entries(sv1_entry *x, size_t root, size_t n)
{
    for (;;) {
        size_t child = 2 * root + 1;
        if (child >= n)
            return;
        if (child + 1 < n && sv1_cmp_id(x[child].object_id, x[child + 1].object_id) < 0)
            child++;
        if (sv1_cmp_id(x[root].object_id, x[child].object_id) >= 0)
            return;
        swap_entries(&x[root], &x[child]);
        root = child;
    }
}

void sv1_sort_entries(sv1_entry *x, size_t n)
{
    if (n < 2)
        return;
    for (size_t i = n / 2; i-- > 0;)
        sift_entries(x, i, n);
    for (size_t end = n - 1; end > 0; end--) {
        swap_entries(&x[0], &x[end]);
        sift_entries(x, 0, end);
    }
}

/* ---- CommitRecord ---- */
int sv1_commit_validate(const sv1_commit *c)
{
    if (c->region_units < 4 || c->region_units > SV1_MAX_REGION_UNITS || c->generation == 0) return SV1_E_MALFORMED_COMMIT; /* GUARD:commit-region */
    uint64_t expected = sv1_catalog_len(c->catalog_entry_count);
    if (c->catalog_entry_count > SV1_MAX_CATALOG_ENTRIES || c->catalog_byte_length != expected)
        return SV1_E_MALFORMED_COMMIT;
    uint32_t u;
    int r = sv1_unit_count(c->catalog_byte_length, &u);
    if (r)
        return r;
    if (u != c->catalog_unit_count)
        return SV1_E_MALFORMED_COMMIT;
    if (c->catalog_first_unit > UINT64_MAX - c->catalog_unit_count)
        return SV1_E_LENGTH_OVERFLOW;
    uint64_t end = c->catalog_first_unit + c->catalog_unit_count;
    int bad_layout = c->catalog_first_unit < 2 || end >= c->region_units ||
        c->committed_high_water != end + 1 || c->committed_high_water > c->region_units;
    if (bad_layout) return SV1_E_MALFORMED_COMMIT; /* GUARD:commit-layout */
    if (c->generation == 1) {
        int bad_link = c->previous_generation != 0 || !sv1_all_zero(c->previous_commit_id, 32) ||
            !sv1_all_zero(c->previous_catalog_id, 32);
        if (bad_link) return SV1_E_INVALID_GENERATION; /* GUARD:commit-genesis-link */
    } else {
        int bad_link = c->previous_generation == UINT64_MAX ||
            c->previous_generation + 1 != c->generation ||
            sv1_all_zero(c->previous_commit_id, 32) ||
            sv1_all_zero(c->previous_catalog_id, 32);
        if (bad_link) return SV1_E_INVALID_GENERATION; /* GUARD:commit-link */
    }
    return SV1_OK;
}

int sv1_commit_encode(const sv1_commit *c, uint8_t out[SV1_COMMIT_BYTES])
{
    int r = sv1_commit_validate(c);
    if (r)
        return r;
    sv1_zero(out, SV1_COMMIT_BYTES);
    sv1_copy(out, COMMIT_MAGIC, 8);
    sv1_put16(out + 8, 1);
    sv1_put16(out + 10, SV1_COMMIT_BYTES);
    sv1_put16(out + 12, 1);
    sv1_put16(out + 14, 0);
    sv1_copy(out + 32, c->store_uuid, 16);
    sv1_put64(out + 48, c->region_units);
    sv1_put64(out + 56, c->generation);
    sv1_put64(out + 64, c->previous_generation);
    sv1_copy(out + 72, c->previous_commit_id, 32);
    sv1_copy(out + 104, c->previous_catalog_id, 32);
    sv1_copy(out + 136, c->catalog_id, 32);
    sv1_put64(out + 168, c->catalog_first_unit);
    sv1_put64(out + 176, c->catalog_byte_length);
    sv1_put32(out + 184, c->catalog_unit_count);
    sv1_put32(out + 188, c->catalog_entry_count);
    sv1_put64(out + 192, c->committed_high_water);
    return SV1_OK;
}

int sv1_commit_decode(const uint8_t *b, size_t len, sv1_commit *c)
{
    if (len != SV1_COMMIT_BYTES || !sv1_equal(b, COMMIT_MAGIC, 8)) return SV1_E_MALFORMED_COMMIT; /* GUARD:commit-magic */
    if (sv1_get16(b + 8) != 1 || sv1_get16(b + 10) != SV1_COMMIT_BYTES)
        return SV1_E_UNSUPPORTED_VERSION;
    if (sv1_get16(b + 12) != 1 || sv1_get16(b + 14) != 0)
        return SV1_E_UNSUPPORTED_VERSION;
    if (sv1_get64(b + 16) != 0 || sv1_get64(b + 24) != 0) return SV1_E_UNSUPPORTED_FEATURES; /* GUARD:commit-features */
    sv1_copy(c->store_uuid, b + 32, 16);
    c->region_units = sv1_get64(b + 48);
    c->generation = sv1_get64(b + 56);
    c->previous_generation = sv1_get64(b + 64);
    sv1_copy(c->previous_commit_id, b + 72, 32);
    sv1_copy(c->previous_catalog_id, b + 104, 32);
    sv1_copy(c->catalog_id, b + 136, 32);
    c->catalog_first_unit = sv1_get64(b + 168);
    c->catalog_byte_length = sv1_get64(b + 176);
    c->catalog_unit_count = sv1_get32(b + 184);
    c->catalog_entry_count = sv1_get32(b + 188);
    c->committed_high_water = sv1_get64(b + 192);
    return sv1_commit_validate(c);
}

int sv1_commit_object_id(const sv1_commit *c, uint8_t out[32])
{
    uint8_t b[SV1_COMMIT_BYTES];
    int r = sv1_commit_encode(c, b);
    if (r)
        return r;
    return sv1_object_id(SV1_KIND_COMMIT, SV1_VERSION, b, SV1_COMMIT_BYTES, out);
}

int sv1_commit_validates_catalog(const sv1_commit *c, const uint8_t catalog_id[32],
                                 const sv1_entry *entries, size_t n)
{
    /* Rust: semantic = catalog.encode()?; then the comparisons. The
     * re-encoding is hashed as a stream, so no catalog-sized buffer. */
    if (n > SV1_MAX_CATALOG_ENTRIES)
        return SV1_E_CATALOG_TOO_LARGE;
    int r = check_order(entries, n);
    if (r)
        return r;
    uint8_t enc[SV1_CATALOG_ENTRY];
    for (size_t i = 0; i < n; i++) {
        r = sv1_entry_encode(&entries[i], enc);
        if (r)
            return r;
    }
    uint64_t sem_len = sv1_catalog_len(n);
    int mismatch = !sv1_equal(c->catalog_id, catalog_id, 32) || c->catalog_entry_count != n ||
        c->catalog_byte_length != sem_len;
    if (mismatch) return SV1_E_INTEGRITY; /* GUARD:commit-catalog */
    uint32_t u;
    r = sv1_unit_count(sem_len, &u);
    if (r)
        return r;
    if (u != c->catalog_unit_count)
        return SV1_E_INTEGRITY;
    sha256_ctx ctx;
    r = sv1_object_id_begin(&ctx, SV1_KIND_CATALOG, SV1_VERSION, sem_len);
    if (r)
        return r;
    uint8_t hdr[SV1_CATALOG_HEADER];
    sv1_copy(hdr, CATALOG_MAGIC, 8);
    sv1_put16(hdr + 8, 1);
    sv1_put16(hdr + 10, SV1_CATALOG_ENTRY);
    sv1_put32(hdr + 12, (uint32_t)n);
    sha256_update(&ctx, hdr, sizeof hdr);
    for (size_t i = 0; i < n; i++) {
        (void)sv1_entry_encode(&entries[i], enc);
        sha256_update(&ctx, enc, sizeof enc);
    }
    uint8_t id[32];
    sha256_final(&ctx, id);
    if (!sv1_equal(id, catalog_id, 32)) return SV1_E_INTEGRITY; /* GUARD:catalog-id */
    return SV1_OK;
}

int sv1_commit_identifies_predecessor(const sv1_commit *s, const sv1_commit *p,
                                      const uint8_t prev_id[32])
{
    return s->generation != 0 && s->generation - 1 == p->generation &&
           s->previous_generation == p->generation &&
           sv1_equal(s->previous_commit_id, prev_id, 32) &&
           sv1_equal(s->previous_catalog_id, p->catalog_id, 32) &&
           sv1_equal(s->store_uuid, p->store_uuid, 16) && s->region_units == p->region_units &&
           s->catalog_first_unit >= p->committed_high_water;
}

/* ---- Superblock ---- */
static int superblock_validate_shape(const sv1_superblock *s)
{
    int bad_shape = s->slot_id > 1 || s->region_units < 4 || s->region_units > SV1_MAX_REGION_UNITS ||
        s->generation == 0 || s->committed_high_water > s->region_units ||
        s->committed_high_water < 4;
    if (bad_shape) return SV1_E_MALFORMED_SUPERBLOCK; /* GUARD:sb-shape */
    uint64_t expected = sv1_catalog_len(s->catalog_entry_count);
    if (s->catalog_first_unit > UINT64_MAX - s->catalog_unit_count)
        return SV1_E_LENGTH_OVERFLOW;
    uint64_t end = s->catalog_first_unit + s->catalog_unit_count;
    if (s->catalog_entry_count > SV1_MAX_CATALOG_ENTRIES || s->catalog_byte_length != expected)
        return SV1_E_MALFORMED_SUPERBLOCK;
    uint32_t u;
    int r = sv1_unit_count(s->catalog_byte_length, &u);
    if (r)
        return r;
    if (u != s->catalog_unit_count || s->catalog_first_unit < 2 ||
        end != s->commit_record_unit || s->commit_record_unit == UINT64_MAX ||
        s->commit_record_unit + 1 != s->committed_high_water)
        return SV1_E_MALFORMED_SUPERBLOCK;
    return SV1_OK;
}

int sv1_superblock_encode(const sv1_superblock *s, uint8_t out[SV1_UNIT])
{
    int r = superblock_validate_shape(s);
    if (r)
        return r;
    sv1_zero(out, SV1_UNIT);
    sv1_copy(out, SUPERBLOCK_MAGIC, 8);
    sv1_put16(out + 8, 1);
    sv1_put16(out + 10, 0);
    sv1_copy(out + 28, s->store_uuid, 16);
    sv1_put32(out + 44, s->slot_id);
    sv1_put64(out + 48, s->region_units);
    sv1_put64(out + 56, s->generation);
    sv1_copy(out + 64, s->commit_record_id, 32);
    sv1_put64(out + 96, s->commit_record_unit);
    sv1_copy(out + 104, s->catalog_id, 32);
    sv1_put64(out + 136, s->catalog_first_unit);
    sv1_put64(out + 144, s->catalog_byte_length);
    sv1_put32(out + 152, s->catalog_unit_count);
    sv1_put32(out + 156, s->catalog_entry_count);
    sv1_put64(out + 160, s->committed_high_water);
    sv1_put32(out + SV1_SB_CRC_OFFSET, sv1_crc32c(out, SV1_UNIT));
    return SV1_OK;
}

/* CRC of a superblock unit with the CRC field read as zero. */
static uint32_t sb_crc(const uint8_t *b)
{
    uint32_t crc = 0xffffffffu;
    for (size_t i = 0; i < SV1_UNIT; i++) {
        crc ^= (i >= SV1_SB_CRC_OFFSET && i < SV1_SB_CRC_OFFSET + 4) ? 0u : b[i];
        for (int k = 0; k < 8; k++) {
            uint32_t mask = 0u - (crc & 1u);
            crc = (crc >> 1) ^ (0x82f63b78u & mask);
        }
    }
    return ~crc;
}

/* 1 if the CRC field matches (engine helper crc_valid). */
int sv1_superblock_crc_ok(const uint8_t b[SV1_UNIT])
{
    return sb_crc(b) == sv1_get32(b + SV1_SB_CRC_OFFSET);
}

int sv1_superblock_decode(const uint8_t *b, size_t len, uint32_t expected_slot,
                          sv1_superblock *s)
{
    if (len != SV1_UNIT || !sv1_equal(b, SUPERBLOCK_MAGIC, 8)) return SV1_E_BAD_SUPERBLOCK_MAGIC; /* GUARD:sb-magic */
    if (sb_crc(b) != sv1_get32(b + SV1_SB_CRC_OFFSET)) return SV1_E_BAD_SUPERBLOCK_CRC; /* GUARD:sb-crc */
    if (!sv1_all_zero(b + SV1_SB_RESERVED_OFFSET, SV1_UNIT - SV1_SB_RESERVED_OFFSET)) return SV1_E_NONZERO_RESERVED; /* GUARD:sb-reserved */
    if (sv1_get16(b + 8) != 1 || sv1_get16(b + 10) != 0) return SV1_E_UNSUPPORTED_VERSION; /* GUARD:sb-version */
    if (sv1_get64(b + 12) != 0 || sv1_get64(b + 20) != 0)
        return SV1_E_UNSUPPORTED_FEATURES;
    uint32_t slot = sv1_get32(b + 44);
    if (slot != expected_slot || slot > 1) return SV1_E_WRONG_SUPERBLOCK_SLOT; /* GUARD:sb-slot */
    sv1_copy(s->store_uuid, b + 28, 16);
    s->slot_id = slot;
    s->region_units = sv1_get64(b + 48);
    s->generation = sv1_get64(b + 56);
    sv1_copy(s->commit_record_id, b + 64, 32);
    s->commit_record_unit = sv1_get64(b + 96);
    sv1_copy(s->catalog_id, b + 104, 32);
    s->catalog_first_unit = sv1_get64(b + 136);
    s->catalog_byte_length = sv1_get64(b + 144);
    s->catalog_unit_count = sv1_get32(b + 152);
    s->catalog_entry_count = sv1_get32(b + 156);
    s->committed_high_water = sv1_get64(b + 160);
    return superblock_validate_shape(s);
}

int sv1_superblock_validate_commit(const sv1_superblock *s, const uint8_t commit_id[32],
                                   const sv1_commit *c)
{
    int mismatch = !sv1_equal(s->commit_record_id, commit_id, 32) ||
        !sv1_equal(s->store_uuid, c->store_uuid, 16) || s->region_units != c->region_units ||
        s->generation != c->generation || !sv1_equal(s->catalog_id, c->catalog_id, 32) ||
        s->catalog_first_unit != c->catalog_first_unit ||
        s->catalog_byte_length != c->catalog_byte_length ||
        s->catalog_unit_count != c->catalog_unit_count ||
        s->catalog_entry_count != c->catalog_entry_count ||
        s->committed_high_water != c->committed_high_water;
    if (mismatch) return SV1_E_MALFORMED_SUPERBLOCK; /* GUARD:sb-commit-match */
    if (s->commit_record_unit == UINT64_MAX ||
        s->commit_record_unit + 1 != c->committed_high_water ||
        s->catalog_first_unit > UINT64_MAX - s->catalog_unit_count ||
        s->catalog_first_unit + s->catalog_unit_count != s->commit_record_unit)
        return SV1_E_MALFORMED_SUPERBLOCK;
    return SV1_OK;
}

int sv1_superblock_equivalent(const sv1_superblock *a, const sv1_superblock *b)
{
    return sv1_equal(a->store_uuid, b->store_uuid, 16) && a->region_units == b->region_units &&
           a->generation == b->generation &&
           sv1_equal(a->commit_record_id, b->commit_record_id, 32);
}

/* ---- genesis ---- */
int sv1_genesis_units(const uint8_t uuid[16], uint64_t region_units, uint8_t out[4][SV1_UNIT])
{
    uint8_t cat[SV1_CATALOG_HEADER];
    size_t cat_len;
    int r = sv1_catalog_encode((const sv1_entry *)0, 0, cat, sizeof cat, &cat_len);
    if (r)
        return r;
    sv1_commit c;
    sv1_zero(&c, sizeof c);
    sv1_copy(c.store_uuid, uuid, 16);
    c.region_units = region_units;
    c.generation = 1;
    r = sv1_object_id(SV1_KIND_CATALOG, SV1_VERSION, cat, cat_len, c.catalog_id);
    if (r)
        return r;
    c.catalog_first_unit = 2;
    c.catalog_byte_length = cat_len;
    c.catalog_unit_count = 1;
    c.catalog_entry_count = 0;
    c.committed_high_water = 4;
    sv1_zero(out, 4 * (size_t)SV1_UNIT);
    r = sv1_commit_encode(&c, out[3]);
    if (r)
        return r;
    sv1_superblock s;
    sv1_zero(&s, sizeof s);
    sv1_copy(s.store_uuid, uuid, 16);
    s.slot_id = 0;
    s.region_units = region_units;
    s.generation = 1;
    r = sv1_commit_object_id(&c, s.commit_record_id);
    if (r)
        return r;
    s.commit_record_unit = 3;
    sv1_copy(s.catalog_id, c.catalog_id, 32);
    s.catalog_first_unit = 2;
    s.catalog_byte_length = cat_len;
    s.catalog_unit_count = 1;
    s.catalog_entry_count = 0;
    s.committed_high_water = 4;
    r = sv1_superblock_encode(&s, out[0]);
    if (r)
        return r;
    sv1_copy(out[2], cat, cat_len);
    return SV1_OK;
}
