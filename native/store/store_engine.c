/*
 * store_engine.c -- Store v1 mount and transaction engine, C twin of
 * crates/aienos-kernel/src/store/engine.rs. See store_engine.h.
 *
 * One deliberate difference, recorded in README.md: while planning a
 * transaction, Rust binary-searches a vector that already has the new
 * entries appended (unsorted tail), so an already-stored object requested
 * after a new one can be missed and the transaction then fails with
 * Format(DuplicateObject). This engine searches only the sorted committed
 * catalog, so such a transaction deduplicates as ADR 0015 intends. The
 * written bytes are identical whenever Rust succeeds.
 */
#include "store_engine.h"

enum { RE_OK = 0, RE_IO = 1, RE_GRAPH = 2 };

const char *st_strerror(int e)
{
    switch (e) {
    case ST_M_IO: return "MountError::Io";
    case ST_M_UNFORMATTED: return "MountError::Unformatted";
    case ST_M_FOREIGN: return "MountError::ForeignOrUnknown";
    case ST_M_UNSUPPORTED_VERSION: return "MountError::UnsupportedVersion";
    case ST_M_CORRUPT_RECOVERY_REQUIRED: return "MountError::CorruptRecoveryRequired";
    case ST_M_CONFLICTING_ROOTS: return "MountError::ConflictingRoots";
    case ST_M_INCONSISTENT_HISTORY: return "MountError::InconsistentHistory";
    case ST_E_IO: return "StoreError::Io";
    case ST_E_CORRUPT: return "StoreError::Corrupt";
    case ST_E_READ_ONLY_DEGRADED: return "StoreError::ReadOnlyDegraded";
    case ST_E_DUPLICATE_OBJECT_CONFLICT: return "StoreError::DuplicateObjectConflict";
    case ST_E_NO_SPACE: return "StoreError::NoSpace";
    case ST_E_CATALOG_FULL: return "StoreError::CatalogFull";
    case ST_E_GENERATION_EXHAUSTED: return "StoreError::GenerationExhausted";
    case ST_E_TRANSACTION_LIMIT: return "StoreError::TransactionLimit";
    case ST_E_INVALID_OBJECT: return "StoreError::InvalidObject";
    case ST_E_NEEDS_REOPEN: return "StoreError::NeedsReopen";
    case ST_E_ARG: return "Arg";
    case ST_E_GEOMETRY: return "Geometry";
    default: return sv1_strerror(e);
    }
}

const char *st_checkpoint_name(int cp)
{
    switch (cp) {
    case ST_CP_BEFORE_FIRST_WRITE: return "before_first_write";
    case ST_CP_AFTER_PAYLOAD_OBJECTS: return "after_payload_objects";
    case ST_CP_AFTER_CATALOG: return "after_catalog";
    case ST_CP_AFTER_COMMIT_RECORD: return "after_commit_record";
    case ST_CP_AFTER_FIRST_FLUSH: return "after_first_flush";
    case ST_CP_AFTER_INACTIVE_SUPERBLOCK: return "after_inactive_superblock";
    case ST_CP_AFTER_FINAL_FLUSH: return "after_final_flush";
    default: return "unknown";
    }
}

static int dev_read(const st_dev *d, uint64_t unit, uint8_t *buf)
{
    return d->read_unit(d->ctx, unit, buf);
}
static int dev_write(const st_dev *d, uint64_t unit, const uint8_t *buf)
{
    return d->write_unit(d->ctx, unit, buf);
}

/* read_application_object, streamed one unit at a time through ws->unit.
 * Like Rust, every unit is read first in order (a read failure is RE_IO
 * whatever the bytes are), and only then is the extent judged. If out is
 * set the semantic bytes are copied there (caller checked the size). If cmp
 * is set, *differs reports whether the semantic bytes differ from cmp. */
static int read_app_object(const st_dev *d, st_workspace *ws, const sv1_entry *e, uint8_t *out,
                           const uint8_t *cmp, int *differs)
{
    sha256_ctx ctx;
    int graph = 0;
    uint32_t units;
    if (sv1_unit_count(e->byte_length, &units) || units != e->unit_count)
        graph = 1;
    if (!graph && sv1_object_id_begin(&ctx, e->kind, e->version, e->byte_length))
        graph = 1;
    if (differs)
        *differs = 0;
    for (uint32_t i = 0; i < e->unit_count; i++) {
        if (dev_read(d, e->first_unit + i, ws->unit))
            return RE_IO;
        if (graph)
            continue;
        uint64_t start = (uint64_t)i * SV1_UNIT;
        uint64_t take = e->byte_length > start ? e->byte_length - start : 0;
        if (take > SV1_UNIT)
            take = SV1_UNIT;
        sha256_update(&ctx, ws->unit, (size_t)take);
        if (!sv1_all_zero(ws->unit + take, SV1_UNIT - (size_t)take)) graph = 1; /* GUARD:object-padding */
        if (out)
            sv1_copy(out + start, ws->unit, (size_t)take);
        if (cmp && differs && !sv1_equal(cmp + start, ws->unit, (size_t)take))
            *differs = 1;
    }
    if (graph)
        return RE_GRAPH;
    uint8_t id[32];
    sha256_final(&ctx, id);
    if (!sv1_equal(id, e->object_id, 32)) return RE_GRAPH; /* GUARD:object-hash */
    return RE_OK;
}

static int validate_root(const st_dev *d, st_workspace *ws, const sv1_superblock *sb,
                         uint32_t cat_index, st_root *root)
{
    if (sb->region_units != d->region_units)
        return RE_GRAPH;
    if (dev_read(d, sb->commit_record_unit, ws->unit))
        return RE_IO;
    if (!sv1_all_zero(ws->unit + SV1_COMMIT_BYTES, SV1_UNIT - SV1_COMMIT_BYTES)) return RE_GRAPH; /* GUARD:commit-unit-padding */
    uint8_t cid[32];
    if (sv1_object_id(SV1_KIND_COMMIT, SV1_VERSION, ws->unit, SV1_COMMIT_BYTES, cid))
        return RE_GRAPH;
    /* Rust order; not a mutation guard: sb-commit-match refuses the same case */
    if (!sv1_equal(cid, sb->commit_record_id, 32))
        return RE_GRAPH;
    sv1_commit c;
    if (sv1_commit_decode(ws->unit, SV1_COMMIT_BYTES, &c))
        return RE_GRAPH;
    if (sv1_superblock_validate_commit(sb, cid, &c))
        return RE_GRAPH;
    /* commit decode bounds the catalog to SV1_MAX_CATALOG_UNITS units */
    for (uint32_t i = 0; i < c.catalog_unit_count; i++)
        if (dev_read(d, c.catalog_first_unit + i, ws->catbuf + (size_t)i * SV1_UNIT))
            return RE_IO;
    if (sv1_validate_extent(c.catalog_id, SV1_KIND_CATALOG, SV1_VERSION, c.catalog_byte_length,
                            ws->catbuf, (size_t)c.catalog_unit_count * SV1_UNIT))
        return RE_GRAPH;
    sv1_entry *entries = ws->cat[cat_index];
    uint32_t n;
    if (sv1_catalog_decode(ws->catbuf, (size_t)c.catalog_byte_length, entries, ST_CAT_CAP, &n))
        return RE_GRAPH;
    if (sv1_commit_validates_catalog(&c, c.catalog_id, entries, n))
        return RE_GRAPH;
    if (sv1_catalog_validate_extents(entries, n, c.region_units, c.catalog_first_unit,
                                     c.committed_high_water, ws->ext))
        return RE_GRAPH;
    for (uint32_t i = 0; i < n; i++) {
        int r = read_app_object(d, ws, &entries[i], (uint8_t *)0, (const uint8_t *)0, (int *)0);
        if (r)
            return r;
    }
    root->sb = *sb;
    root->commit = c;
    sv1_copy(root->commit_id, cid, 32);
    root->cat_index = cat_index;
    root->n = n;
    return RE_OK;
}

static int verify_append_transition(st_workspace *ws, const st_root *older, const st_root *newer)
{
    const sv1_entry *o = ws->cat[older->cat_index];
    const sv1_entry *nw = ws->cat[newer->cat_index];
    for (uint32_t i = 0; i < older->n; i++) {
        long j = sv1_catalog_find(nw, newer->n, o[i].object_id);
        /* one line: with j < 0 the second test would read nw[-1] */
        if (j < 0 || !sv1_entry_equal(&nw[j], &o[i])) return ST_M_INCONSISTENT_HISTORY; /* GUARD:append-keeps-old */
    }
    size_t k = 0;
    for (uint32_t i = 0; i < newer->n; i++) {
        long j = sv1_catalog_find(o, older->n, nw[i].object_id);
        if (j >= 0) {
            if (!sv1_entry_equal(&o[j], &nw[i]))
                return ST_M_INCONSISTENT_HISTORY;
            continue;
        }
        ws->ext[k].first = nw[i].first_unit;
        ws->ext[k].end = nw[i].unit_count;
        k++;
    }
    sv1_sort_extents(ws->ext, k);
    uint64_t next = older->commit.committed_high_water;
    for (size_t i = 0; i < k; i++) {
        if (ws->ext[i].first != next) return ST_M_INCONSISTENT_HISTORY; /* GUARD:append-contiguous */
        if (next > UINT64_MAX - ws->ext[i].end)
            return ST_M_INCONSISTENT_HISTORY;
        next += ws->ext[i].end;
    }
    if (next != newer->commit.catalog_first_unit) return ST_M_INCONSISTENT_HISTORY; /* GUARD:append-ends-at-catalog */
    return 0;
}

static int select_two(st_workspace *ws, const st_root *a, const st_root *b, st_root *out)
{
    if (a->commit.generation == b->commit.generation) {
        if (!sv1_superblock_equivalent(&a->sb, &b->sb)) return ST_M_CONFLICTING_ROOTS; /* GUARD:same-gen-equivalent */
        *out = *a;
        return 0;
    }
    const st_root *older = a->commit.generation < b->commit.generation ? a : b;
    const st_root *newer = older == a ? b : a;
    /* Rust parity; not a mutation guard: the predecessor check below also
     * requires newer generation == older generation + 1 */
    if (older->commit.generation == UINT64_MAX ||
        older->commit.generation + 1 != newer->commit.generation)
        return ST_M_INCONSISTENT_HISTORY;
    if (!sv1_commit_identifies_predecessor(&newer->commit, &older->commit, older->commit_id)) return ST_M_INCONSISTENT_HISTORY; /* GUARD:predecessor */
    int r = verify_append_transition(ws, older, newer);
    if (r)
        return r;
    *out = *newer;
    return 0;
}

static int unsupported_sb(const uint8_t *b, int magic, int crc_ok)
{
    return magic && crc_ok &&
           (sv1_get16(b + 8) != 1 || sv1_get16(b + 10) != 0 || !sv1_all_zero(b + 12, 16));
}

static const uint8_t SB_MAGIC[8] = {'A', 'I', 'E', 'N', 'S', 'T', 'R', '1'};

int st_open(st_store *s, const st_dev *dev, st_workspace *ws)
{
    if (!s || !dev || !ws)
        return ST_E_ARG;
    uint64_t units = dev->region_units;
    if (units < 4 || units > SV1_MAX_REGION_UNITS)
        return ST_M_CORRUPT_RECOVERY_REQUIRED;
    uint8_t *raw[2] = {ws->unit, ws->unit2};
    /* validate_root reuses ws->unit, so slot 0's bytes move to plan_sb. */
    raw[0] = ws->plan_sb;
    if (dev_read(dev, 0, raw[0]))
        return ST_M_IO;
    if (dev_read(dev, 1, raw[1]))
        return ST_M_IO;
    int zero[2], magic[2], crc_ok[2], unsup[2];
    uint64_t gen_of[2];
    for (int i = 0; i < 2; i++) {
        zero[i] = sv1_all_zero(raw[i], SV1_UNIT);
        magic[i] = sv1_equal(raw[i], SB_MAGIC, 8);
        crc_ok[i] = sv1_superblock_crc_ok(raw[i]);
        unsup[i] = unsupported_sb(raw[i], magic[i], crc_ok[i]);
        gen_of[i] = sv1_get64(raw[i] + 56);
    }
    if (zero[0] && zero[1])
        return ST_M_UNFORMATTED;
    if (!magic[0] && !magic[1])
        return ST_M_FOREIGN;
    for (int i = 0; i < 2; i++) {
        if (crc_ok[i] && unsup[i]) return ST_M_UNSUPPORTED_VERSION; /* GUARD:unsupported-root */
    }

    sv1_superblock sbs[2];
    int decoded[2] = {0, 0}, malformed[2] = {0, 0}, crc_supported[2] = {0, 0};
    for (int i = 0; i < 2; i++) {
        if (zero[i])
            continue;
        if (!magic[i] || !crc_ok[i] || unsup[i]) {
            malformed[i] = 1;
            continue;
        }
        crc_supported[i] = 1;
        if (sv1_superblock_decode(raw[i], SV1_UNIT, (uint32_t)i, &sbs[i]) ||
            sbs[i].region_units != units) {
            malformed[i] = 1;
            continue;
        }
        decoded[i] = 1;
    }
    st_root roots[2];
    int have[2] = {0, 0}, graph_bad[2] = {0, 0};
    for (int i = 0; i < 2; i++) {
        if (!decoded[i])
            continue;
        int r = validate_root(dev, ws, &sbs[i], (uint32_t)i, &roots[i]);
        if (r == RE_IO)
            return ST_M_IO;
        if (r == RE_GRAPH)
            graph_bad[i] = 1;
        else
            have[i] = 1;
    }

    s->dev = *dev;
    s->ws = ws;
    s->poisoned = 0;
    if (have[0] && have[1]) {
        int r = select_two(ws, &roots[0], &roots[1], &s->root);
        if (r)
            return r;
        s->state = ST_VALID;
        s->peer = ST_PEER_VALID;
        return 0;
    }
    if (have[0] || have[1]) {
        int good = have[0] ? 0 : 1;
        int other = 1 - good;
        s->root = roots[good];
        if (zero[other]) {
            s->state = ST_VALID;
            s->peer = ST_PEER_ZERO;
            return 0;
        }
        if (malformed[other]) {
            if (unsup[other] && crc_ok[other])
                return ST_M_UNSUPPORTED_VERSION;
            s->state = ST_DEGRADED_RECOVERY; /* GUARD:malformed-peer-degrades */
            s->peer = ST_PEER_MALFORMED;
            return 0;
        }
        if (graph_bad[other] && crc_supported[other]) {
            if (gen_of[other] > roots[good].sb.generation) {
                s->state = ST_DEGRADED_RECOVERY; /* GUARD:newer-bad-peer-degrades */
                s->peer = ST_PEER_GRAPH_BAD_NEWER;
                return 0;
            }
            if (gen_of[other] < roots[good].sb.generation) {
                s->state = ST_VALID;
                s->peer = ST_PEER_GRAPH_BAD_OLDER;
                return 0;
            }
            return ST_M_CORRUPT_RECOVERY_REQUIRED;
        }
        return ST_M_CORRUPT_RECOVERY_REQUIRED;
    }
    return ST_M_CORRUPT_RECOVERY_REQUIRED;
}

static int write_object(const st_dev *d, st_workspace *ws, uint64_t first, uint32_t units,
                        const uint8_t *bytes, uint64_t len)
{
    for (uint32_t i = 0; i < units; i++) {
        uint64_t start = (uint64_t)i * SV1_UNIT;
        uint64_t take = len > start ? len - start : 0;
        if (take > SV1_UNIT)
            take = SV1_UNIT;
        sv1_zero(ws->unit, SV1_UNIT);
        sv1_copy(ws->unit, bytes + start, (size_t)take);
        if (dev_write(d, first + i, ws->unit))
            return ST_E_IO;
    }
    return 0;
}

typedef struct {
    size_t nreq;
    size_t cat_len;
    uint32_t cat_units;
    uint64_t catalog_first;
    uint64_t commit_unit;
    st_root root;
} st_plan;

static int preflight(st_store *s, const st_object *objects, size_t n, st_plan *p)
{
    st_workspace *ws = s->ws;
    if (n > SV1_MAX_TRANSACTION_OBJECTS) return ST_E_TRANSACTION_LIMIT; /* GUARD:tx-object-limit */
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        const st_object *o = &objects[i];
        uint8_t id[32];
        int r = sv1_object_id(o->kind, o->version, o->bytes, o->len, id);
        if (r)
            return r;
        uint32_t units;
        r = sv1_unit_count(o->len, &units);
        if (r)
            return r;
        size_t j;
        for (j = 0; j < k; j++)
            if (sv1_equal(ws->req[j].id, id, 32))
                break;
        if (j < k) {
            const st_req *x = &ws->req[j];
            int same = x->kind == o->kind && x->version == o->version && x->len == o->len &&
                       sv1_equal(x->bytes, o->bytes, (size_t)o->len);
            /* Rust parity; not a mutation guard: equal ObjectIds with different
             * kind, version or bytes need a SHA-256 collision */
            if (!same)
                return ST_E_DUPLICATE_OBJECT_CONFLICT;
            continue;
        }
        st_req *x = &ws->req[k++];
        sv1_copy(x->id, id, 32);
        x->kind = o->kind;
        x->version = o->version;
        x->bytes = o->bytes;
        x->len = o->len;
        x->units = units;
        x->first_unit = 0;
        x->append = 0;
    }

    const sv1_entry *old = ws->cat[s->root.cat_index];
    uint32_t on = s->root.n;
    uint32_t spare = 1 - s->root.cat_index;
    sv1_entry *e = ws->cat[spare];
    for (uint32_t i = 0; i < on; i++)
        e[i] = old[i];
    size_t m = on;
    uint64_t app_units = 0;
    uint64_t next = s->root.commit.committed_high_water;
    for (size_t i = 0; i < k; i++) {
        st_req *x = &ws->req[i];
        long j = sv1_catalog_find(old, on, x->id);
        if (j >= 0) {
            const sv1_entry *oe = &old[j];
            int same = oe->kind == x->kind && oe->version == x->version &&
                       oe->byte_length == x->len && oe->unit_count == x->units;
            if (!same) return ST_E_DUPLICATE_OBJECT_CONFLICT; /* GUARD:dedup-descriptor */
            int differs = 0;
            int r = read_app_object(&s->dev, ws, oe, (uint8_t *)0, x->bytes, &differs);
            if (r == RE_IO)
                return ST_E_IO;
            if (r == RE_GRAPH) return ST_E_CORRUPT; /* GUARD:dedup-verify */
            if (differs)
                return ST_E_DUPLICATE_OBJECT_CONFLICT;
            continue;
        }
        if (app_units > UINT64_MAX - x->units)
            return ST_E_NO_SPACE;
        app_units += x->units;
        sv1_entry *ne = &e[m++];
        sv1_copy(ne->object_id, x->id, 32);
        ne->kind = x->kind;
        ne->version = x->version;
        ne->first_unit = next;
        ne->byte_length = x->len;
        ne->unit_count = x->units;
        ne->flags = 0;
        x->first_unit = next;
        x->append = 1;
        if (next > UINT64_MAX - x->units)
            return ST_E_NO_SPACE;
        next += x->units;
    }
    sv1_sort_entries(e, m);
    if (m > SV1_MAX_CATALOG_ENTRIES) return ST_E_CATALOG_FULL; /* GUARD:catalog-full */
    if (app_units > SV1_MAX_TRANSACTION_UNITS) return ST_E_TRANSACTION_LIMIT; /* GUARD:tx-unit-limit */
    size_t cat_len;
    int r = sv1_catalog_encode(e, m, ws->catbuf, sizeof ws->catbuf, &cat_len);
    if (r)
        return r;
    uint32_t cat_units;
    r = sv1_unit_count(cat_len, &cat_units);
    if (r)
        return r;
    uint64_t catalog_first = next;
    if (catalog_first > UINT64_MAX - cat_units)
        return ST_E_NO_SPACE;
    uint64_t commit_unit = catalog_first + cat_units;
    if (commit_unit == UINT64_MAX)
        return ST_E_NO_SPACE;
    uint64_t hw = commit_unit + 1;
    if (hw > s->dev.region_units || hw > SV1_MAX_REGION_UNITS) return ST_E_NO_SPACE; /* GUARD:no-space */
    if (s->root.commit.generation == UINT64_MAX) return ST_E_GENERATION_EXHAUSTED; /* GUARD:generation-exhausted */
    uint64_t gen = s->root.commit.generation + 1;

    st_root *nr = &p->root;
    sv1_commit *c = &nr->commit;
    sv1_zero(c, sizeof *c);
    sv1_copy(c->store_uuid, s->root.commit.store_uuid, 16);
    c->region_units = s->root.commit.region_units;
    c->generation = gen;
    c->previous_generation = s->root.commit.generation;
    sv1_copy(c->previous_commit_id, s->root.commit_id, 32);
    sv1_copy(c->previous_catalog_id, s->root.commit.catalog_id, 32);
    r = sv1_object_id(SV1_KIND_CATALOG, SV1_VERSION, ws->catbuf, cat_len, c->catalog_id);
    if (r)
        return r;
    c->catalog_first_unit = catalog_first;
    c->catalog_byte_length = cat_len;
    c->catalog_unit_count = cat_units;
    c->catalog_entry_count = (uint32_t)m;
    c->committed_high_water = hw;
    sv1_zero(ws->plan_commit, SV1_UNIT);
    r = sv1_commit_encode(c, ws->plan_commit);
    if (r)
        return r;
    r = sv1_object_id(SV1_KIND_COMMIT, SV1_VERSION, ws->plan_commit, SV1_COMMIT_BYTES,
                      nr->commit_id);
    if (r)
        return r;
    sv1_superblock *sb = &nr->sb;
    sv1_zero(sb, sizeof *sb);
    sv1_copy(sb->store_uuid, c->store_uuid, 16);
    sb->slot_id = 1 - s->root.sb.slot_id;
    sb->region_units = c->region_units;
    sb->generation = gen;
    sv1_copy(sb->commit_record_id, nr->commit_id, 32);
    sb->commit_record_unit = commit_unit;
    sv1_copy(sb->catalog_id, c->catalog_id, 32);
    sb->catalog_first_unit = catalog_first;
    sb->catalog_byte_length = c->catalog_byte_length;
    sb->catalog_unit_count = cat_units;
    sb->catalog_entry_count = c->catalog_entry_count;
    sb->committed_high_water = hw;
    r = sv1_superblock_encode(sb, ws->plan_sb);
    if (r)
        return r;
    nr->cat_index = spare;
    nr->n = (uint32_t)m;
    p->nreq = k;
    p->cat_len = cat_len;
    p->cat_units = cat_units;
    p->catalog_first = catalog_first;
    p->commit_unit = commit_unit;
    return 0;
}

static void hook_at(st_hook hook, void *arg, int cp)
{
    if (hook)
        hook(arg, cp);
}

int st_transact(st_store *s, const st_object *objects, size_t n, st_hook hook, void *arg)
{
    if (!s || (n && !objects))
        return ST_E_ARG;
    if (s->poisoned) return ST_E_NEEDS_REOPEN; /* GUARD:poisoned */
    if (s->state == ST_DEGRADED_RECOVERY) return ST_E_READ_ONLY_DEGRADED; /* GUARD:degraded-read-only */
    st_plan p;
    int r = preflight(s, objects, n, &p);
    if (r)
        return r;
    st_workspace *ws = s->ws;
    hook_at(hook, arg, ST_CP_BEFORE_FIRST_WRITE);
    for (size_t i = 0; i < p.nreq; i++) {
        st_req *x = &ws->req[i];
        if (!x->append)
            continue;
        if (write_object(&s->dev, ws, x->first_unit, x->units, x->bytes, x->len)) {
            s->poisoned = 1;
            return ST_E_IO;
        }
    }
    hook_at(hook, arg, ST_CP_AFTER_PAYLOAD_OBJECTS);
    if (write_object(&s->dev, ws, p.catalog_first, p.cat_units, ws->catbuf, p.cat_len)) {
        s->poisoned = 1;
        return ST_E_IO;
    }
    hook_at(hook, arg, ST_CP_AFTER_CATALOG);
    if (dev_write(&s->dev, p.commit_unit, ws->plan_commit)) {
        s->poisoned = 1;
        return ST_E_IO;
    }
    hook_at(hook, arg, ST_CP_AFTER_COMMIT_RECORD);
    if (s->dev.flush(s->dev.ctx)) {
        s->poisoned = 1;
        return ST_E_IO;
    }
    hook_at(hook, arg, ST_CP_AFTER_FIRST_FLUSH);
    if (dev_write(&s->dev, p.root.sb.slot_id, ws->plan_sb)) {
        s->poisoned = 1;
        return ST_E_IO;
    }
    hook_at(hook, arg, ST_CP_AFTER_INACTIVE_SUPERBLOCK);
    if (s->dev.flush(s->dev.ctx)) {
        s->poisoned = 1;
        return ST_E_IO;
    }
    hook_at(hook, arg, ST_CP_AFTER_FINAL_FLUSH);
    s->root = p.root;
    s->peer = ST_PEER_VALID;
    return 0;
}

int st_read_object(st_store *s, const uint8_t id[32], uint8_t *out, size_t cap, size_t *len)
{
    if (!s || !id || !len)
        return ST_E_ARG;
    *len = 0;
    const sv1_entry *cat = s->ws->cat[s->root.cat_index];
    long j = sv1_catalog_find(cat, s->root.n, id);
    if (j < 0)
        return ST_E_INVALID_OBJECT;
    const sv1_entry *e = &cat[j];
    if (!out || e->byte_length > cap)
        return ST_E_ARG;
    int r = read_app_object(&s->dev, s->ws, e, out, (const uint8_t *)0, (int *)0);
    if (r) {
        sv1_zero(out, cap);
        return r == RE_IO ? ST_E_IO : ST_E_CORRUPT;
    }
    *len = (size_t)e->byte_length;
    return 0;
}

int st_format(const st_dev *dev, const uint8_t uuid[16])
{
    static const uint8_t zero_unit[SV1_UNIT];
    uint8_t g[4][SV1_UNIT];
    if (!dev || !uuid)
        return ST_E_ARG;
    int r = sv1_genesis_units(uuid, dev->region_units, g);
    if (r)
        return r;
    /* Clear both slots first so a cut never leaves an old root pointing at
     * the new units; then the genesis graph; then superblock A. */
    if (dev_write(dev, 0, zero_unit) || dev_write(dev, 1, zero_unit) || dev->flush(dev->ctx))
        return ST_E_IO;
    if (dev_write(dev, 2, g[2]) || dev_write(dev, 3, g[3]) || dev->flush(dev->ctx))
        return ST_E_IO;
    if (dev_write(dev, 0, g[0]) || dev->flush(dev->ctx))
        return ST_E_IO;
    return 0;
}
