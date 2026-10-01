/*
 * store_engine_test.c -- port of every engine test in
 * crates/aienos-kernel/src/store/engine.rs (mount classification, history,
 * transaction errors, checkpoint order, fail-closed I/O, peer conditions)
 * plus C-only cases (GraphBadOlder, equal-generation graph damage,
 * TransactionLimit, read_object, flush failure) and the disk adapter.
 */
#include "store_test_util.h"
#include "disk_file.h"

static st_workspace ws;

static const uint8_t U5A[16] = {0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
                                0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a};

static void seed_genesis(memdev *m)
{
    static uint8_t g[4][SV1_UNIT];
    if (sv1_genesis_units(U5A, m->n, g)) {
        fprintf(stderr, "genesis failed\n");
        exit(2);
    }
    memcpy(m->units[0], g[0], SV1_UNIT);
    memcpy(m->units[2], g[2], SV1_UNIT);
    memcpy(m->units[3], g[3], SV1_UNIT);
}

static st_object one(const char *s)
{
    st_object o = {3, 1, (const uint8_t *)s, strlen(s)};
    return o;
}

static int open_mem(st_store *s, memdev *m)
{
    st_dev d = mem_dev(m);
    return st_open(s, &d, &ws);
}

static void seed_generation_two(memdev *m)
{
    st_store s;
    mem_init(m, 32);
    seed_genesis(m);
    CHECK_EQ(open_mem(&s, m), 0, "setup open");
    st_object o = one("next generation");
    CHECK_EQ(st_transact(&s, &o, 1, NULL, NULL), 0, "seed gen 2");
    mem_clear_log(m);
}

static void write_commit_unit(memdev *m, uint64_t unit, const sv1_commit *c)
{
    memset(m->units[unit], 0, SV1_UNIT);
    sv1_commit_encode(c, m->units[unit]);
}

static void rewrite_commit(memdev *m, uint32_t slot, uint64_t unit, const sv1_commit *c)
{
    sv1_superblock sb;
    write_commit_unit(m, unit, c);
    sv1_superblock_decode(m->units[slot], SV1_UNIT, slot, &sb);
    sb.generation = c->generation;
    sv1_commit_object_id(c, sb.commit_record_id);
    sv1_superblock_encode(&sb, m->units[slot]);
}

static void sb_from_commit(const sv1_commit *c, uint32_t slot, uint64_t cu, uint8_t *out)
{
    sv1_superblock sb;
    memset(&sb, 0, sizeof sb);
    memcpy(sb.store_uuid, c->store_uuid, 16);
    sb.slot_id = slot;
    sb.region_units = c->region_units;
    sb.generation = c->generation;
    sv1_commit_object_id(c, sb.commit_record_id);
    sb.commit_record_unit = cu;
    memcpy(sb.catalog_id, c->catalog_id, 32);
    sb.catalog_first_unit = c->catalog_first_unit;
    sb.catalog_byte_length = c->catalog_byte_length;
    sb.catalog_unit_count = c->catalog_unit_count;
    sb.catalog_entry_count = c->catalog_entry_count;
    sb.committed_high_water = c->committed_high_water;
    sv1_superblock_encode(&sb, out);
}

static void empty_catalog_at(memdev *m, uint64_t unit, uint8_t id[32])
{
    size_t len;
    memset(m->units[unit], 0, SV1_UNIT);
    sv1_catalog_encode(NULL, 0, m->units[unit], SV1_UNIT, &len);
    sv1_object_id(1, 1, m->units[unit], len, id);
}

static void t_open_side_effect_free(void)
{
    memdev m;
    st_store s;
    mem_init(&m, 32);
    seed_genesis(&m);
    CHECK_EQ(open_mem(&s, &m), 0, "open genesis");
    CHECK(m.nwrites == 0 && m.flushes == 0, "open writes nothing");
    int r0 = 0, r1 = 0;
    for (size_t i = 0; i < m.nreads; i++) {
        r0 |= m.reads[i] == 0;
        r1 |= m.reads[i] == 1;
    }
    CHECK(r0 && r1, "open reads both slots");
    mem_free(&m);
}

static void t_full_graph_validation(void)
{
    memdev m;
    st_store s;
    mem_init(&m, 32);
    const char *value = "payload";
    sv1_entry e;
    memset(&e, 0, sizeof e);
    sv1_object_id(3, 1, (const uint8_t *)value, 7, e.object_id);
    e.kind = 3;
    e.version = 1;
    e.first_unit = 2;
    e.byte_length = 7;
    e.unit_count = 1;
    size_t cl;
    sv1_catalog_encode(&e, 1, m.units[3], SV1_UNIT, &cl);
    sv1_commit c;
    memset(&c, 0, sizeof c);
    memcpy(c.store_uuid, U5A, 16);
    c.region_units = 32;
    c.generation = 1;
    sv1_object_id(1, 1, m.units[3], cl, c.catalog_id);
    c.catalog_first_unit = 3;
    c.catalog_byte_length = cl;
    c.catalog_unit_count = 1;
    c.catalog_entry_count = 1;
    c.committed_high_water = 5;
    memcpy(m.units[2], value, 7);
    write_commit_unit(&m, 4, &c);
    sb_from_commit(&c, 0, 4, m.units[0]);
    CHECK_EQ(open_mem(&s, &m), 0, "one-object genesis mounts");
    m.units[2][SV1_UNIT - 1] = 1;
    CHECK_EQ(open_mem(&s, &m), ST_M_CORRUPT_RECOVERY_REQUIRED, "damaged payload padding");
    m.fail_read = 4;
    CHECK_EQ(open_mem(&s, &m), ST_M_IO, "I/O stays distinct");
    mem_free(&m);
}

static void t_history_matrix(void)
{
    memdev m;
    st_store s;
    /* conflicting same-generation roots */
    mem_init(&m, 32);
    seed_genesis(&m);
    {
        uint8_t id[32];
        empty_catalog_at(&m, 4, id);
        sv1_commit c;
        memset(&c, 0, sizeof c);
        memset(c.store_uuid, 0x6b, 16);
        c.region_units = 32;
        c.generation = 1;
        memcpy(c.catalog_id, id, 32);
        c.catalog_first_unit = 4;
        c.catalog_byte_length = 16;
        c.catalog_unit_count = 1;
        c.committed_high_water = 6;
        write_commit_unit(&m, 5, &c);
        sb_from_commit(&c, 1, 5, m.units[1]);
    }
    CHECK_EQ(open_mem(&s, &m), ST_M_CONFLICTING_ROOTS, "conflicting roots");
    mem_free(&m);

    /* equivalent peer, then a transaction, then reopen */
    mem_init(&m, 32);
    seed_genesis(&m);
    {
        sv1_superblock sb;
        sv1_superblock_decode(m.units[0], SV1_UNIT, 0, &sb);
        sb.slot_id = 1;
        sv1_superblock_encode(&sb, m.units[1]);
    }
    CHECK_EQ(open_mem(&s, &m), 0, "equivalent roots");
    CHECK(st_generation(&s) == 1 && s.peer == ST_PEER_VALID, "equivalent: gen 1, peer valid");
    st_object o = one("next");
    CHECK_EQ(st_transact(&s, &o, 1, NULL, NULL), 0, "transact after equivalent");
    CHECK_EQ(open_mem(&s, &m), 0, "reopen");
    CHECK(st_generation(&s) == 2, "reopen gen 2");
    mem_free(&m);

    /* wrong previous commit id */
    sv1_commit rec;
    seed_generation_two(&m);
    sv1_commit_decode(m.units[6], SV1_COMMIT_BYTES, &rec);
    memset(rec.previous_commit_id, 0x33, 32);
    rewrite_commit(&m, 1, 6, &rec);
    CHECK_EQ(open_mem(&s, &m), ST_M_INCONSISTENT_HISTORY, "wrong previous");
    mem_free(&m);

    /* non-adjacent generation */
    seed_generation_two(&m);
    sv1_commit_decode(m.units[6], SV1_COMMIT_BYTES, &rec);
    rec.generation = 3;
    rec.previous_generation = 2;
    rewrite_commit(&m, 1, 6, &rec);
    CHECK_EQ(open_mem(&s, &m), ST_M_INCONSISTENT_HISTORY, "non adjacent");
    mem_free(&m);

    /* damaged new payload: degraded read-only, peer GraphBadNewer */
    seed_generation_two(&m);
    m.units[4][0] ^= 1;
    CHECK_EQ(open_mem(&s, &m), 0, "damaged new mounts");
    CHECK(s.state == ST_DEGRADED_RECOVERY && s.peer == ST_PEER_GRAPH_BAD_NEWER,
          "damaged new: degraded, peer GraphBadNewer");
    o = one("read only");
    CHECK_EQ(st_transact(&s, &o, 1, NULL, NULL), ST_E_READ_ONLY_DEGRADED, "read only degraded");
    CHECK(m.nwrites == 0, "degraded: no writes");
    mem_free(&m);

    /* damaged old catalog: valid gen 2, peer GraphBadOlder */
    seed_generation_two(&m);
    m.units[2][0] ^= 1;
    CHECK_EQ(open_mem(&s, &m), 0, "damaged old mounts");
    CHECK(s.state == ST_VALID && st_generation(&s) == 2 && s.peer == ST_PEER_GRAPH_BAD_OLDER,
          "damaged old: valid gen 2, peer GraphBadOlder");
    mem_free(&m);

    /* C only: equal-generation graph-bad peer is not a recovery choice */
    mem_init(&m, 32);
    seed_genesis(&m);
    {
        sv1_superblock sb;
        sv1_superblock_decode(m.units[0], SV1_UNIT, 0, &sb);
        sb.slot_id = 1;
        sv1_superblock_encode(&sb, m.units[1]);
        sv1_commit c;
        sv1_commit_decode(m.units[3], SV1_COMMIT_BYTES, &c);
        c.committed_high_water = 6;
        c.catalog_first_unit = 4;
        uint8_t id[32];
        empty_catalog_at(&m, 4, id);
        write_commit_unit(&m, 5, &c);
        sb_from_commit(&c, 1, 5, m.units[1]);
        m.units[4][0] ^= 1; /* B's catalog is damaged, same generation as A */
    }
    CHECK_EQ(open_mem(&s, &m), ST_M_CORRUPT_RECOVERY_REQUIRED, "equal generation graph-bad peer");
    mem_free(&m);
}

static void t_history_deleting_entry(void)
{
    memdev m;
    st_store s;
    sv1_commit prev, c;
    uint8_t id[32];
    seed_generation_two(&m);
    sv1_commit_decode(m.units[6], SV1_COMMIT_BYTES, &prev);
    empty_catalog_at(&m, 7, id);
    memset(&c, 0, sizeof c);
    memcpy(c.store_uuid, prev.store_uuid, 16);
    c.region_units = prev.region_units;
    c.generation = 3;
    c.previous_generation = 2;
    sv1_commit_object_id(&prev, c.previous_commit_id);
    memcpy(c.previous_catalog_id, prev.catalog_id, 32);
    memcpy(c.catalog_id, id, 32);
    c.catalog_first_unit = 7;
    c.catalog_byte_length = 16;
    c.catalog_unit_count = 1;
    c.committed_high_water = 9;
    write_commit_unit(&m, 8, &c);
    sb_from_commit(&c, 0, 8, m.units[0]);
    CHECK_EQ(open_mem(&s, &m), ST_M_INCONSISTENT_HISTORY, "deleting an old entry");
    mem_free(&m);

    /* C only: a gap between old high water and the new objects */
    seed_generation_two(&m);
    {
        st_store t;
        CHECK_EQ(open_mem(&t, &m), 0, "setup open");
        /* hand-build gen 3 with the object at unit 8 instead of 7 */
        const char *v = "gap";
        sv1_entry e[2];
        sv1_entry *old = ws.cat[t.root.cat_index];
        e[0] = old[0];
        memset(&e[1], 0, sizeof e[1]);
        sv1_object_id(3, 1, (const uint8_t *)v, 3, e[1].object_id);
        e[1].kind = 3;
        e[1].version = 1;
        e[1].first_unit = 8;
        e[1].byte_length = 3;
        e[1].unit_count = 1;
        sv1_sort_entries(e, 2);
        memset(m.units[8], 0, SV1_UNIT);
        memcpy(m.units[8], v, 3);
        size_t cl;
        memset(m.units[9], 0, SV1_UNIT);
        sv1_catalog_encode(e, 2, m.units[9], SV1_UNIT, &cl);
        sv1_commit_decode(m.units[6], SV1_COMMIT_BYTES, &prev);
        memset(&c, 0, sizeof c);
        memcpy(c.store_uuid, prev.store_uuid, 16);
        c.region_units = 32;
        c.generation = 3;
        c.previous_generation = 2;
        sv1_commit_object_id(&prev, c.previous_commit_id);
        memcpy(c.previous_catalog_id, prev.catalog_id, 32);
        sv1_object_id(1, 1, m.units[9], cl, c.catalog_id);
        c.catalog_first_unit = 9;
        c.catalog_byte_length = cl;
        c.catalog_unit_count = 1;
        c.catalog_entry_count = 2;
        c.committed_high_water = 11;
        write_commit_unit(&m, 10, &c);
        sb_from_commit(&c, 0, 10, m.units[0]);
    }
    CHECK_EQ(open_mem(&s, &m), ST_M_INCONSISTENT_HISTORY, "gap before new objects");
    mem_free(&m);
}

/* C only: hand-built generation 3 over seed_generation_two (gen 2 high water
 * 7) with one new 1-unit object at obj_unit and the catalog at cat_unit. */
static void build_gen3(memdev *m, uint64_t obj_unit, uint64_t cat_unit)
{
    st_store t;
    sv1_commit prev, c;
    seed_generation_two(m);
    CHECK_EQ(open_mem(&t, m), 0, "setup open");
    const char *v = "lay";
    sv1_entry e[2];
    e[0] = ws.cat[t.root.cat_index][0];
    memset(&e[1], 0, sizeof e[1]);
    sv1_object_id(3, 1, (const uint8_t *)v, 3, e[1].object_id);
    e[1].kind = 3;
    e[1].version = 1;
    e[1].first_unit = obj_unit;
    e[1].byte_length = 3;
    e[1].unit_count = 1;
    sv1_sort_entries(e, 2);
    memset(m->units[obj_unit], 0, SV1_UNIT);
    memcpy(m->units[obj_unit], v, 3);
    size_t cl;
    memset(m->units[cat_unit], 0, SV1_UNIT);
    sv1_catalog_encode(e, 2, m->units[cat_unit], SV1_UNIT, &cl);
    sv1_commit_decode(m->units[6], SV1_COMMIT_BYTES, &prev);
    memset(&c, 0, sizeof c);
    memcpy(c.store_uuid, prev.store_uuid, 16);
    c.region_units = 32;
    c.generation = 3;
    c.previous_generation = 2;
    sv1_commit_object_id(&prev, c.previous_commit_id);
    memcpy(c.previous_catalog_id, prev.catalog_id, 32);
    sv1_object_id(1, 1, m->units[cat_unit], cl, c.catalog_id);
    c.catalog_first_unit = cat_unit;
    c.catalog_byte_length = cl;
    c.catalog_unit_count = 1;
    c.catalog_entry_count = 2;
    c.committed_high_water = cat_unit + 2;
    write_commit_unit(m, cat_unit + 1, &c);
    sb_from_commit(&c, 0, cat_unit + 1, m->units[0]);
}

static void t_append_layout(void)
{
    memdev m;
    st_store s;
    build_gen3(&m, 7, 8);
    CHECK_EQ(open_mem(&s, &m), 0, "hand-built gen 3 (control)");
    CHECK(st_generation(&s) == 3 && s.state == ST_VALID, "control: valid gen 3");
    mem_free(&m);
    build_gen3(&m, 7, 9);
    CHECK_EQ(open_mem(&s, &m), ST_M_INCONSISTENT_HISTORY, "gap between new objects and catalog");
    mem_free(&m);
    build_gen3(&m, 2, 8);
    CHECK_EQ(open_mem(&s, &m), ST_M_INCONSISTENT_HISTORY, "new object below old high water, hole at 7");
    mem_free(&m);
    /* bytes after the commit record in its unit */
    seed_generation_two(&m);
    m.units[6][SV1_COMMIT_BYTES + 5] = 1;
    CHECK_EQ(open_mem(&s, &m), 0, "dirty commit padding mounts the older root");
    CHECK(s.state == ST_DEGRADED_RECOVERY && s.peer == ST_PEER_GRAPH_BAD_NEWER,
          "dirty commit padding: degraded, peer GraphBadNewer");
    mem_free(&m);
}

static void t_classification(void)
{
    memdev m;
    st_store s;
    mem_init(&m, 8);
    CHECK_EQ(open_mem(&s, &m), ST_M_UNFORMATTED, "blank");
    m.units[0][0] = 0x77;
    CHECK_EQ(open_mem(&s, &m), ST_M_FOREIGN, "foreign");
    mem_free(&m);
    mem_init(&m, 8);
    seed_genesis(&m);
    sv1_put16(m.units[0] + 8, 2);
    rechecksum(m.units[0]);
    CHECK_EQ(open_mem(&s, &m), ST_M_UNSUPPORTED_VERSION, "unsupported");
    mem_free(&m);
    mem_init(&m, 8);
    seed_genesis(&m);
    m.units[0][168] ^= 1;
    CHECK_EQ(open_mem(&s, &m), ST_M_CORRUPT_RECOVERY_REQUIRED, "bad crc");
    mem_free(&m);
    /* C only: region outside 4..=2^32 */
    mem_init(&m, 3);
    CHECK_EQ(open_mem(&s, &m), ST_M_CORRUPT_RECOVERY_REQUIRED, "region too small");
    mem_free(&m);
    /* C only: superblock region differs from the device */
    mem_init(&m, 16);
    seed_genesis(&m);
    m.n = 15;
    CHECK_EQ(open_mem(&s, &m), ST_M_CORRUPT_RECOVERY_REQUIRED, "region mismatch");
    m.n = 16;
    mem_free(&m);
}

static void t_zero_write_errors(void)
{
    memdev m;
    st_store s;
    st_object o;
    mem_init(&m, 6);
    seed_genesis(&m);
    CHECK_EQ(open_mem(&s, &m), 0, "setup open");
    o = one("cannot fit");
    CHECK_EQ(st_transact(&s, &o, 1, NULL, NULL), ST_E_NO_SPACE, "no space");
    CHECK(m.nwrites == 0 && m.flushes == 0, "no space: zero writes");
    mem_free(&m);

    /* full catalog */
    uint64_t region = 4168;
    mem_init(&m, region);
    sv1_entry *e = calloc(SV1_MAX_CATALOG_ENTRIES, sizeof *e);
    for (uint32_t i = 0; i < SV1_MAX_CATALOG_ENTRIES; i++) {
        uint16_t kind = (uint16_t)(3 + i);
        uint8_t sem = (uint8_t)kind;
        sv1_object_id(kind, 1, &sem, 1, e[i].object_id);
        e[i].kind = kind;
        e[i].version = 1;
        e[i].first_unit = 2 + i;
        e[i].byte_length = 1;
        e[i].unit_count = 1;
        m.units[2 + i][0] = sem;
    }
    sv1_sort_entries(e, SV1_MAX_CATALOG_ENTRIES);
    size_t cl;
    uint64_t cf = 2 + SV1_MAX_CATALOG_ENTRIES;
    sv1_catalog_encode(e, SV1_MAX_CATALOG_ENTRIES, m.units[cf], 65 * SV1_UNIT, &cl);
    uint32_t cu;
    sv1_unit_count(cl, &cu);
    CHECK_EQ(cu, 65, "full catalog spans 65 units");
    sv1_commit c;
    memset(&c, 0, sizeof c);
    memcpy(c.store_uuid, U5A, 16);
    c.region_units = region;
    c.generation = 1;
    sv1_object_id(1, 1, m.units[cf], cl, c.catalog_id);
    c.catalog_first_unit = cf;
    c.catalog_byte_length = cl;
    c.catalog_unit_count = cu;
    c.catalog_entry_count = SV1_MAX_CATALOG_ENTRIES;
    c.committed_high_water = cf + cu + 1;
    write_commit_unit(&m, cf + cu, &c);
    sb_from_commit(&c, 0, cf + cu, m.units[0]);
    free(e);
    CHECK_EQ(open_mem(&s, &m), 0, "full catalog mounts");
    mem_clear_log(&m);
    o = one("new object");
    CHECK_EQ(st_transact(&s, &o, 1, NULL, NULL), ST_E_CATALOG_FULL, "catalog full");
    CHECK(m.nwrites == 0 && m.flushes == 0, "catalog full: zero writes");
    /* the same full catalog dedups an existing object without growing */
    uint8_t sem3 = 3;
    st_object ex = {3, 1, &sem3, 1};
    CHECK_EQ(st_transact(&s, &ex, 1, NULL, NULL), ST_E_NO_SPACE, "full region: dedup still needs units");
    mem_free(&m);

    /* generation exhausted */
    mem_init(&m, 32);
    seed_genesis(&m);
    CHECK_EQ(open_mem(&s, &m), 0, "setup open");
    mem_clear_log(&m);
    s.root.commit.generation = UINT64_MAX;
    s.root.sb.generation = UINT64_MAX;
    o = one("overflow");
    CHECK_EQ(st_transact(&s, &o, 1, NULL, NULL), ST_E_GENERATION_EXHAUSTED, "generation exhausted");
    CHECK(m.nwrites == 0 && m.flushes == 0, "exhausted: zero writes");
    mem_free(&m);

    /* C only: TransactionLimit by count and by units */
    mem_init(&m, 8);
    {
        static uint8_t g[4][SV1_UNIT];
        sv1_genesis_units(U5A, 40000, g);
        memcpy(m.units[0], g[0], SV1_UNIT);
        memcpy(m.units[2], g[2], SV1_UNIT);
        memcpy(m.units[3], g[3], SV1_UNIT);
    }
    st_dev d = mem_dev(&m);
    d.region_units = 40000;
    CHECK_EQ(st_open(&s, &d, &ws), 0, "large-region genesis mounts");
    mem_clear_log(&m);
    static st_object many[SV1_MAX_TRANSACTION_OBJECTS + 1];
    static uint8_t bytes[SV1_MAX_TRANSACTION_OBJECTS + 1][2];
    for (int i = 0; i <= (int)SV1_MAX_TRANSACTION_OBJECTS; i++) {
        bytes[i][0] = (uint8_t)i;
        bytes[i][1] = (uint8_t)(i >> 8);
        many[i].kind = 3;
        many[i].version = 1;
        many[i].bytes = bytes[i];
        many[i].len = 2;
    }
    CHECK_EQ(st_transact(&s, many, SV1_MAX_TRANSACTION_OBJECTS + 1, NULL, NULL),
             ST_E_TRANSACTION_LIMIT, "257 objects");
    size_t big = (size_t)SV1_MAX_OBJECT_BYTES + 1;
    uint8_t *buf = malloc(big);
    for (size_t i = 0; i < big; i++)
        buf[i] = (uint8_t)(i * 7 + (i >> 12));
    st_object huge[3] = {{3, 1, buf, SV1_MAX_OBJECT_BYTES},
                         {3, 1, buf + 1, SV1_MAX_OBJECT_BYTES},
                         {3, 1, buf, 1}};
    CHECK_EQ(st_transact(&s, huge, 3, NULL, NULL), ST_E_TRANSACTION_LIMIT, "32769 units");
    st_object toolarge = {3, 1, buf, big};
    CHECK_EQ(st_transact(&s, &toolarge, 1, NULL, NULL), SV1_E_OBJECT_TOO_LARGE, "object too large");
    st_object empty = {3, 1, buf, 0};
    CHECK_EQ(st_transact(&s, &empty, 1, NULL, NULL), SV1_E_INVALID_OBJECT, "empty object");
    st_object kind0 = {0, 1, buf, 1};
    CHECK_EQ(st_transact(&s, &kind0, 1, NULL, NULL), SV1_E_INVALID_OBJECT, "kind zero");
    CHECK(m.nwrites == 0 && m.flushes == 0, "limits: zero writes");
    free(buf);
    mem_free(&m);
}

static void t_dedup_and_tail_reuse(void)
{
    memdev m;
    st_store s;
    mem_init(&m, 32);
    seed_genesis(&m);
    memset(m.units[4], 0xa5, SV1_UNIT);
    CHECK_EQ(open_mem(&s, &m), 0, "setup open");
    const char *value = "committed payload";
    st_object o = one(value);
    CHECK_EQ(st_transact(&s, &o, 1, NULL, NULL), 0, "first commit");
    CHECK(st_generation(&s) == 2, "gen 2");
    int w4 = 0;
    for (size_t i = 0; i < m.nwrites; i++)
        w4 |= m.writes[i] == 4;
    CHECK(w4 && m.flushes == 2, "tail unit reused, two flushes");
    CHECK_EQ(open_mem(&s, &m), 0, "reopen");
    mem_clear_log(&m);
    CHECK_EQ(st_transact(&s, &o, 1, NULL, NULL), 0, "dedup commit");
    CHECK(m.nwrites == 3 && m.writes[0] == 7 && m.writes[1] == 8 && m.writes[2] == 0,
          "dedup writes catalog, commit record, inactive root only");
    uint8_t id[32], out[64];
    size_t len;
    sv1_object_id(3, 1, (const uint8_t *)value, strlen(value), id);
    CHECK_EQ(st_read_object(&s, id, out, sizeof out, &len), 0, "read object");
    CHECK(len == strlen(value) && memcmp(out, value, len) == 0, "read object bytes");
    id[0] ^= 1;
    CHECK_EQ(st_read_object(&s, id, out, sizeof out, &len), ST_E_INVALID_OBJECT, "unknown object");
    id[0] ^= 1;
    CHECK_EQ(st_read_object(&s, id, out, 4, &len), ST_E_ARG, "small buffer");
    m.units[4][1] ^= 1;
    CHECK_EQ(st_read_object(&s, id, out, sizeof out, &len), ST_E_CORRUPT, "read corrupt");
    m.units[4][1] ^= 1;
    m.fail_read = 4;
    CHECK_EQ(st_read_object(&s, id, out, sizeof out, &len), ST_E_IO, "read io");
    mem_free(&m);

    /* in-request duplicates: identical is folded, different kind conflicts */
    mem_init(&m, 32);
    seed_genesis(&m);
    CHECK_EQ(open_mem(&s, &m), 0, "setup open");
    st_object two[2] = {one("same"), one("same")};
    CHECK_EQ(st_transact(&s, two, 2, NULL, NULL), 0, "identical duplicates fold");
    CHECK(s.root.n == 1, "one entry");
    /* Rust quirk (see store_engine.c): [new, existing] dedups in C */
    st_object mixed[2] = {one("brand new"), one("same")};
    CHECK_EQ(st_transact(&s, mixed, 2, NULL, NULL), 0, "new + existing");
    CHECK(s.root.n == 2, "existing object not appended twice");
    CHECK_EQ(open_mem(&s, &m), 0, "reopen after mixed");
    mem_free(&m);
}

static int cps[16], ncps;
static void record_cp(void *arg, int cp)
{
    (void)arg;
    if (ncps < 16)
        cps[ncps++] = cp;
}

static void t_checkpoint_order(void)
{
    memdev a, b;
    st_store s;
    mem_init(&a, 32);
    seed_genesis(&a);
    mem_clone(&b, &a);
    CHECK_EQ(open_mem(&s, &a), 0, "setup open");
    st_object o = one("checkpointed");
    CHECK_EQ(st_transact(&s, &o, 1, NULL, NULL), 0, "setup transaction");
    CHECK_EQ(open_mem(&s, &b), 0, "setup open");
    mem_clear_log(&a);
    ncps = 0;
    CHECK_EQ(st_transact(&s, &o, 1, record_cp, NULL), 0, "hooked transact");
    int ordered = ncps == 7;
    for (int i = 0; i < ncps && ordered; i++)
        ordered = cps[i] == i;
    CHECK(ordered, "checkpoints in Rust order");
    CHECK(memcmp(a.units, b.units, 32 * SV1_UNIT) == 0, "hook does not change bytes");
    for (int i = 0; i < 7; i++)
        CHECK(strcmp(st_checkpoint_name(i), "unknown") != 0, "checkpoint name %d", i);
    mem_free(&a);
    mem_free(&b);
}

static void t_dedup_corruption_conflict(void)
{
    memdev m;
    st_store s;
    mem_init(&m, 32);
    seed_genesis(&m);
    CHECK_EQ(open_mem(&s, &m), 0, "setup open");
    st_object o = one("dedup target");
    CHECK_EQ(st_transact(&s, &o, 1, NULL, NULL), 0, "setup transaction");
    CHECK_EQ(open_mem(&s, &m), 0, "setup open");
    mem_clear_log(&m);
    m.units[4][0] ^= 1;
    CHECK_EQ(st_transact(&s, &o, 1, NULL, NULL), ST_E_CORRUPT, "dedup corruption");
    CHECK(m.nwrites == 0 && m.flushes == 0, "corrupt: zero writes");
    m.units[4][0] ^= 1;
    m.fail_read = 4;
    CHECK_EQ(st_transact(&s, &o, 1, NULL, NULL), ST_E_IO, "dedup read io");
    m.fail_read = -1;
    mem_free(&m);

    seed_generation_two(&m);
    CHECK_EQ(open_mem(&s, &m), 0, "setup open");
    mem_clear_log(&m);
    sv1_entry *e = &ws.cat[s.root.cat_index][0];
    uint8_t id[32];
    memcpy(id, e->object_id, 32);
    e->kind++;
    o = one("next generation");
    CHECK_EQ(st_transact(&s, &o, 1, NULL, NULL), ST_E_DUPLICATE_OBJECT_CONFLICT, "descriptor conflict");
    CHECK(memcmp(ws.cat[s.root.cat_index][0].object_id, id, 32) == 0, "catalog untouched");
    CHECK(m.nwrites == 0 && m.flushes == 0, "conflict: zero writes");
    mem_free(&m);

    /* C only: same id, stored bytes differ (hash collision stand-in) */
    seed_generation_two(&m);
    CHECK_EQ(open_mem(&s, &m), 0, "setup open");
    e = &ws.cat[s.root.cat_index][0];
    const char *other = "next generatioN";
    sv1_object_id(3, 1, (const uint8_t *)other, 15, e->object_id);
    st_object o2 = one(other);
    mem_clear_log(&m);
    int r = st_transact(&s, &o2, 1, NULL, NULL);
    CHECK(r == ST_E_CORRUPT || r == ST_E_DUPLICATE_OBJECT_CONFLICT, "forged id refused (%d)", r);
    CHECK(m.nwrites == 0, "forged id: zero writes");
    mem_free(&m);
}

static void t_io_fail_closed(void)
{
    memdev m;
    st_store s;
    mem_init(&m, 32);
    seed_genesis(&m);
    m.fail_read = 3;
    CHECK_EQ(open_mem(&s, &m), ST_M_IO, "open io");
    m.fail_read = -1;
    CHECK_EQ(open_mem(&s, &m), 0, "open");
    m.fail_write = 4;
    st_object o = one("fault");
    CHECK_EQ(st_transact(&s, &o, 1, NULL, NULL), ST_E_IO, "write io");
    o = one("again");
    CHECK_EQ(st_transact(&s, &o, 1, NULL, NULL), ST_E_NEEDS_REOPEN, "needs reopen");
    m.fail_write = -1;
    m.fail_flush = 1;
    CHECK_EQ(open_mem(&s, &m), 0, "reopen");
    CHECK_EQ(st_transact(&s, &o, 1, NULL, NULL), ST_E_IO, "flush io");
    CHECK_EQ(st_transact(&s, &o, 1, NULL, NULL), ST_E_NEEDS_REOPEN, "needs reopen after flush");
    m.fail_flush = 0;
    CHECK_EQ(open_mem(&s, &m), 0, "reopen after failed flush");
    CHECK(st_generation(&s) == 1, "failed flush before root: still gen 1");
    mem_free(&m);
}

static void t_peer_condition(void)
{
    memdev m;
    st_store s;
    mem_init(&m, 32);
    seed_genesis(&m);
    CHECK_EQ(open_mem(&s, &m), 0, "setup open");
    CHECK(s.peer == ST_PEER_ZERO, "peer zero");
    st_object o = one("second generation");
    CHECK_EQ(st_transact(&s, &o, 1, NULL, NULL), 0, "setup transaction");
    CHECK(s.peer == ST_PEER_VALID, "peer valid after commit");
    CHECK_EQ(open_mem(&s, &m), 0, "setup open");
    CHECK(s.state == ST_VALID && s.peer == ST_PEER_VALID, "reopen valid/valid");
    sv1_superblock nb;
    sv1_superblock_decode(m.units[1], SV1_UNIT, 1, &nb);
    CHECK(nb.generation == 2, "newer in slot 1");
    memset(m.units[nb.commit_record_unit], 0, SV1_UNIT);
    CHECK_EQ(open_mem(&s, &m), 0, "open with lost newer commit");
    CHECK(st_generation(&s) == 1 && s.state == ST_DEGRADED_RECOVERY &&
              s.peer == ST_PEER_GRAPH_BAD_NEWER,
          "older root, degraded, GraphBadNewer");
    mem_free(&m);
}

static void t_malformed_peer_matrix(void)
{
    memdev m;
    st_store s;
    st_object o;
    /* 1 bad CRC peer */
    mem_init(&m, 32);
    seed_genesis(&m);
    memcpy(m.units[1], "AIENSTR1", 8);
    m.units[1][168] ^= 1;
    CHECK_EQ(open_mem(&s, &m), 0, "bad crc peer");
    CHECK(s.state == ST_DEGRADED_RECOVERY && s.peer == ST_PEER_MALFORMED && st_generation(&s) == 1,
          "bad crc peer: degraded/malformed");
    mem_free(&m);
    /* 2 wrong magic peer */
    mem_init(&m, 32);
    seed_genesis(&m);
    memcpy(m.units[1], "BADMAGIC", 8);
    CHECK_EQ(open_mem(&s, &m), 0, "wrong magic peer");
    CHECK(s.state == ST_DEGRADED_RECOVERY && s.peer == ST_PEER_MALFORMED, "wrong magic: malformed");
    /* 7 transact on degraded */
    o = one("blocked mutation");
    CHECK_EQ(st_transact(&s, &o, 1, NULL, NULL), ST_E_READ_ONLY_DEGRADED, "degraded transact");
    mem_free(&m);
    /* 3 nonzero reserved peer */
    mem_init(&m, 32);
    seed_genesis(&m);
    {
        sv1_superblock sb;
        sv1_superblock_decode(m.units[0], SV1_UNIT, 0, &sb);
        sb.slot_id = 1;
        sv1_superblock_encode(&sb, m.units[1]);
        m.units[1][200] = 0xff;
        rechecksum(m.units[1]);
    }
    CHECK_EQ(open_mem(&s, &m), 0, "reserved peer");
    CHECK(s.state == ST_DEGRADED_RECOVERY && s.peer == ST_PEER_MALFORMED, "reserved: malformed");
    /* 4 unsupported version peer */
    sv1_put16(m.units[1] + 8, 2);
    m.units[1][200] = 0;
    rechecksum(m.units[1]);
    CHECK_EQ(open_mem(&s, &m), ST_M_UNSUPPORTED_VERSION, "unsupported peer");
    mem_free(&m);
    /* 5 io on peer */
    mem_init(&m, 32);
    seed_genesis(&m);
    m.fail_read = 1;
    CHECK_EQ(open_mem(&s, &m), ST_M_IO, "peer read io");
    mem_free(&m);
    /* 6 two bad roots */
    mem_init(&m, 32);
    seed_genesis(&m);
    m.units[0][168] ^= 1;
    memcpy(m.units[1], "AIENSTR1", 8);
    m.units[1][168] ^= 1;
    CHECK_EQ(open_mem(&s, &m), ST_M_CORRUPT_RECOVERY_REQUIRED, "two bad roots");
    mem_free(&m);
}

/* ---- disk adapter over native/disk disk_file ---- */
static void t_disk_adapter(const char *dir)
{
    char path[512];
    snprintf(path, sizeof path, "%s/adapter.img", dir);
    uint32_t sizes[2] = {512, 4096};
    for (int k = 0; k < 2; k++) {
        disk_file f;
        disk_dev d;
        st_disk a;
        st_dev sd;
        st_store s;
        uint32_t bpu = SV1_UNIT / sizes[k];
        uint64_t base = 2 * bpu, units = 16;
        CHECK_EQ(disk_file_open(&f, &d, path, sizes[k], base + units * bpu + bpu, 1), 0, "disk open");
        CHECK_EQ(st_disk_bind(&a, &d, base, units, &sd), 0, "bind");
        CHECK(a.blocks_per_unit == bpu && sd.region_units == units, "geometry %u", sizes[k]);
        CHECK_EQ(st_format(&sd, U5A), 0, "format");
        CHECK_EQ(st_open(&s, &sd, &ws), 0, "open formatted");
        uint64_t before = f.blocks_written;
        st_object o = one("on disk");
        CHECK_EQ(st_transact(&s, &o, 1, NULL, NULL), 0, "disk transact");
        CHECK(f.blocks_written - before == 4 * (uint64_t)bpu, "whole units only (no RMW): %llu blocks",
              (unsigned long long)(f.blocks_written - before));
        CHECK_EQ(st_open(&s, &sd, &ws), 0, "reopen");
        CHECK(st_generation(&s) == 2, "disk gen 2");
        /* region 0 = rest of the device */
        CHECK_EQ(st_disk_bind(&a, &d, base, 0, &sd), 0, "bind rest");
        CHECK(sd.region_units == units + 1, "rest of device");
        CHECK_EQ(st_disk_bind(&a, &d, base, units + 2, &sd), ST_E_GEOMETRY, "region past end");
        if (bpu > 1)
            CHECK_EQ(st_disk_bind(&a, &d, 1, 4, &sd), ST_E_GEOMETRY, "unaligned base");
        CHECK_EQ(st_disk_bind(&a, &d, d.block_count, 0, &sd), ST_E_GEOMETRY, "base at end");
        disk_dev odd = d;
        odd.block_size = 1024;
        CHECK_EQ(st_disk_bind(&a, &odd, 0, 0, &sd), ST_E_GEOMETRY, "1024-byte blocks refused");
        disk_file_close(&f);
    }
    remove(path);
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : ".";
    t_open_side_effect_free();
    t_full_graph_validation();
    t_history_matrix();
    t_history_deleting_entry();
    t_append_layout();
    t_classification();
    t_zero_write_errors();
    t_dedup_and_tail_reuse();
    t_checkpoint_order();
    t_dedup_corruption_conflict();
    t_io_fail_closed();
    t_peer_condition();
    t_malformed_peer_matrix();
    t_disk_adapter(dir);
    printf("store_engine_test: %d checks, %d failed\n", g_checks, g_failed);
    printf("STORE_ENGINE: %s\n", g_failed ? "FAIL" : "PASS");
    return g_failed ? 1 : 0;
}
