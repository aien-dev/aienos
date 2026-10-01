/*
 * store_v1_test.c -- byte identity of the C Store v1 format against
 * docs/adr/0015-golden-vectors.json, plus a port of every Rust negative test
 * (crates/aienos-kernel/tests/store_v1_negative.rs and the malformed-vector
 * unit tests in crates/aienos-kernel/src/store/v1.rs).
 *
 * Golden rule (same as the Rust test): every row of the frozen JSON must be
 * produced by the C encoders and match exactly, and every value this test
 * produces must be a row in the JSON. A new vector without a C assertion
 * fails the test.
 */
#include "store_test_util.h"
#include "golden_vectors.h"

/* ---- computed golden rows ---- */
#define MAX_COMPUTED 128
static struct {
    const char *section, *key;
    char *value;
    int matched;
} comp[MAX_COMPUTED];
static int ncomp;

static void put_text(const char *section, const char *key, const char *text)
{
    if (ncomp >= MAX_COMPUTED) {
        fprintf(stderr, "too many computed rows\n");
        exit(2);
    }
    comp[ncomp].section = section;
    comp[ncomp].key = key;
    comp[ncomp].value = strdup(text);
    ncomp++;
}
static void put_hex(const char *section, const char *key, const void *b, size_t n)
{
    char *h = malloc(2 * n + 1);
    to_hex(b, n, h);
    put_text(section, key, h);
    free(h);
}
static void put_sha(const char *section, const char *key, const void *b, size_t n)
{
    uint8_t d[32];
    sha256_hash(b, n, d);
    put_hex(section, key, d, 32);
}
static void put_num(const char *section, const char *key, uint64_t v)
{
    char t[32];
    snprintf(t, sizeof t, "%llu", (unsigned long long)v);
    put_text(section, key, t);
}
static void put_le16(const char *s, const char *k, uint16_t v)
{
    uint8_t b[2];
    sv1_put16(b, v);
    put_hex(s, k, b, 2);
}
static void put_le64(const char *s, const char *k, uint64_t v)
{
    uint8_t b[8];
    sv1_put64(b, v);
    put_hex(s, k, b, 8);
}

static const uint8_t UUID[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

static size_t preimage(uint16_t kind, uint16_t ver, const uint8_t *sem, size_t n, uint8_t *out)
{
    static const char dom[] = "AIENOS-STORE-OBJECT-V1"; /* + NUL */
    size_t o = sizeof dom; /* includes the NUL */
    memcpy(out, dom, sizeof dom);
    sv1_put16(out + o, kind);
    sv1_put16(out + o + 2, ver);
    sv1_put64(out + o + 4, n);
    memcpy(out + o + 12, sem, n);
    return o + 12 + n;
}

static void unit_of(const uint8_t *sem, size_t n, uint8_t u[SV1_UNIT])
{
    memset(u, 0, SV1_UNIT);
    memcpy(u, sem, n);
}

static void make_sb(uint32_t slot, const sv1_commit *c, uint64_t commit_unit, sv1_superblock *sb)
{
    memset(sb, 0, sizeof *sb);
    memcpy(sb->store_uuid, c->store_uuid, 16);
    sb->slot_id = slot;
    sb->region_units = c->region_units;
    sb->generation = c->generation;
    sv1_commit_object_id(c, sb->commit_record_id);
    sb->commit_record_unit = commit_unit;
    memcpy(sb->catalog_id, c->catalog_id, 32);
    sb->catalog_first_unit = c->catalog_first_unit;
    sb->catalog_byte_length = c->catalog_byte_length;
    sb->catalog_unit_count = c->catalog_unit_count;
    sb->catalog_entry_count = c->catalog_entry_count;
    sb->committed_high_water = c->committed_high_water;
}

/* encode + round trip + slot binding + CRC domain (Rust encode_superblock) */
static void encode_sb(const sv1_superblock *sb, uint8_t out[SV1_UNIT])
{
    sv1_superblock back;
    CHECK_EQ(sv1_superblock_encode(sb, out), 0, "superblock encode");
    CHECK_EQ(sv1_superblock_decode(out, SV1_UNIT, sb->slot_id, &back), 0, "superblock decode");
    CHECK(memcmp(&back, sb, sizeof back) == 0 || (sv1_superblock_equivalent(&back, sb) &&
                                                  back.slot_id == sb->slot_id),
          "superblock round trip");
    CHECK(sv1_superblock_decode(out, SV1_UNIT, 1 - sb->slot_id, &back) != 0, "slot bound");
    uint8_t z[SV1_UNIT];
    memcpy(z, out, SV1_UNIT);
    memset(z + SV1_SB_CRC_OFFSET, 0, 4);
    CHECK(sv1_crc32c(z, SV1_UNIT) == sv1_get32(out + SV1_SB_CRC_OFFSET), "superblock CRC domain");
}

typedef struct {
    uint8_t empty_cat[16];
    uint8_t empty_cat_id[32];
    sv1_entry one_entry;
    uint8_t one_cat[80];
    uint8_t one_cat_id[32];
    uint8_t app[16];
    uint8_t app_id[32];
    sv1_commit g1, g2;
} graph_t;

static void build_graph(graph_t *g)
{
    size_t len;
    memset(g, 0, sizeof *g);
    CHECK_EQ(sv1_catalog_encode(NULL, 0, g->empty_cat, sizeof g->empty_cat, &len), 0, "empty cat");
    CHECK_EQ(len, 16, "empty catalog length");
    sv1_object_id(1, 1, g->empty_cat, 16, g->empty_cat_id);
    for (int i = 0; i < 16; i++)
        g->app[i] = (uint8_t)i;
    sv1_object_id(3, 1, g->app, 16, g->app_id);
    memcpy(g->one_entry.object_id, g->app_id, 32);
    g->one_entry.kind = 3;
    g->one_entry.version = 1;
    g->one_entry.first_unit = 4;
    g->one_entry.byte_length = 16;
    g->one_entry.unit_count = 1;
    CHECK_EQ(sv1_catalog_encode(&g->one_entry, 1, g->one_cat, sizeof g->one_cat, &len), 0, "one cat");
    CHECK_EQ(len, 80, "one-entry catalog length");
    sv1_object_id(1, 1, g->one_cat, 80, g->one_cat_id);
    sv1_commit *c = &g->g1;
    memcpy(c->store_uuid, UUID, 16);
    c->region_units = 16;
    c->generation = 1;
    memcpy(c->catalog_id, g->empty_cat_id, 32);
    c->catalog_first_unit = 2;
    c->catalog_byte_length = 16;
    c->catalog_unit_count = 1;
    c->committed_high_water = 4;
    sv1_commit *d = &g->g2;
    *d = *c;
    d->generation = 2;
    d->previous_generation = 1;
    sv1_commit_object_id(c, d->previous_commit_id);
    memcpy(d->previous_catalog_id, g->empty_cat_id, 32);
    memcpy(d->catalog_id, g->one_cat_id, 32);
    d->catalog_first_unit = 5;
    d->catalog_byte_length = 80;
    d->catalog_entry_count = 1;
    d->committed_high_water = 7;
}

static void golden(void)
{
    graph_t g;
    build_graph(&g);
    uint8_t u[SV1_UNIT], pre[512], sem[SV1_COMMIT_BYTES], id[32];
    size_t pn;

    put_text("", "schema", "AIENOS-STORE-V1-GOLDEN-VECTORS-1");
    put_text("", "source_contract", "ADR 0015, format layout tables");

    /* object_id */
    {
        const char *S = "object_id";
        uint8_t semantic[16];
        for (int i = 0; i < 16; i++)
            semantic[i] = (uint8_t)i;
        sv1_object_id(0x1234, 0x5678, semantic, 16, id);
        pn = preimage(0x1234, 0x5678, semantic, 16, pre);
        put_le16(S, "kind_u16le", 0x1234);
        put_le16(S, "version_u16le", 0x5678);
        put_hex(S, "semantic_bytes_hex", semantic, 16);
        put_hex(S, "preimage_hex", pre, pn);
        put_hex(S, "object_id_hex", id, 32);
        put_sha(S, "preimage_sha256", pre, pn);
        put_sha(S, "semantic_sha256", semantic, 16);
        uint8_t d[32];
        sha256_hash(pre, pn, d);
        CHECK(memcmp(d, id, 32) == 0, "ObjectId is SHA-256 of the preimage");
    }
    /* empty_catalog */
    {
        const char *S = "empty_catalog";
        sv1_entry tmp[1];
        uint32_t n = 99;
        put_hex(S, "semantic_bytes_hex", g.empty_cat, 16);
        put_hex(S, "object_id_hex", g.empty_cat_id, 32);
        unit_of(g.empty_cat, 16, u);
        put_hex(S, "unit_hex", u, SV1_UNIT);
        put_sha(S, "unit_sha256", u, SV1_UNIT);
        put_sha(S, "semantic_sha256", g.empty_cat, 16);
        CHECK(sv1_catalog_decode(g.empty_cat, 16, tmp, 1, &n) == 0 && n == 0, "empty decode");
    }
    /* one_entry_catalog */
    {
        const char *S = "one_entry_catalog";
        uint8_t e[64];
        sv1_entry back[2];
        uint32_t n = 0;
        CHECK_EQ(sv1_entry_encode(&g.one_entry, e), 0, "entry encode");
        CHECK(memcmp(g.one_cat + 16, e, 64) == 0, "catalog body is the entry");
        put_hex(S, "entry_object_id_hex", e, 32);
        put_hex(S, "entry_kind_u16le", e + 32, 2);
        put_hex(S, "entry_version_u16le", e + 34, 2);
        put_hex(S, "entry_first_unit_u64le", e + 36, 8);
        put_hex(S, "entry_byte_length_u64le", e + 44, 8);
        put_hex(S, "entry_unit_count_u32le", e + 52, 4);
        put_hex(S, "entry_flags_u16le", e + 56, 2);
        put_hex(S, "entry_reserved_hex", e + 58, 6);
        CHECK(memcmp(e, g.app_id, 32) == 0, "entry id is the app id");
        put_hex(S, "semantic_bytes_hex", g.one_cat, 80);
        put_hex(S, "object_id_hex", g.one_cat_id, 32);
        unit_of(g.one_cat, 80, u);
        put_hex(S, "unit_hex", u, SV1_UNIT);
        put_sha(S, "unit_sha256", u, SV1_UNIT);
        put_sha(S, "semantic_sha256", g.one_cat, 80);
        CHECK(sv1_entry_decode(e, 64, &back[0]) == 0 && sv1_entry_equal(&back[0], &g.one_entry),
              "entry decode");
        CHECK(sv1_catalog_decode(g.one_cat, 80, back, 2, &n) == 0 && n == 1 &&
                  sv1_entry_equal(&back[0], &g.one_entry),
              "catalog decode");
    }
    /* crc32c */
    {
        const char *S = "crc32c";
        uint32_t crc = sv1_crc32c((const uint8_t *)"123456789", 9);
        char t[16];
        uint8_t b[4];
        put_text(S, "check_input_ascii", "123456789");
        snprintf(t, sizeof t, "0x%08x", crc);
        put_text(S, "check_output_numeric", t);
        CHECK(crc == 0xe3069283u, "crc32c check value");
        sv1_put32(b, crc);
        put_hex(S, "check_output_u32le", b, 4);
        put_text(S, "algorithm", "reflected Castagnoli polynomial 0x82f63b78, init/xorout 0xffffffff");
    }
    /* genesis */
    uint8_t ga[SV1_UNIT], gb[SV1_UNIT];
    {
        const char *S = "genesis";
        sv1_commit back;
        sv1_superblock sa, sbb, da, db;
        put_hex(S, "store_uuid_hex", UUID, 16);
        put_le64(S, "region_units_u64le", g.g1.region_units);
        put_num(S, "catalog_first_unit", g.g1.catalog_first_unit);
        put_num(S, "commit_record_unit_number", 3);
        put_text(S, "unit_map.0", "superblock A");
        put_text(S, "unit_map.1", "superblock B");
        put_text(S, "unit_map.2", "genesis catalog");
        put_text(S, "unit_map.3", "genesis CommitRecord");
        put_hex(S, "catalog_semantic_hex", g.empty_cat, 16);
        unit_of(g.empty_cat, 16, u);
        put_hex(S, "catalog_unit_hex", u, SV1_UNIT);
        put_hex(S, "catalog_object_id_hex", g.empty_cat_id, 32);
        CHECK_EQ(sv1_commit_encode(&g.g1, sem), 0, "genesis commit encode");
        sv1_commit_object_id(&g.g1, id);
        pn = preimage(2, 1, sem, SV1_COMMIT_BYTES, pre);
        put_hex(S, "commit_record_semantic_hex", sem, SV1_COMMIT_BYTES);
        put_hex(S, "commit_record_object_id_hex", id, 32);
        unit_of(sem, SV1_COMMIT_BYTES, u);
        put_hex(S, "commit_record_unit_hex", u, SV1_UNIT);
        put_sha(S, "commit_record_unit_sha256", u, SV1_UNIT);
        put_hex(S, "commit_record_crc_domain_preimage_hex", pre, pn);
        uint8_t d[32];
        sha256_hash(pre, pn, d);
        CHECK(memcmp(d, id, 32) == 0, "commit id is SHA-256 of preimage");
        CHECK(sv1_commit_decode(sem, SV1_COMMIT_BYTES, &back) == 0 &&
                  memcmp(&back, &g.g1, sizeof back) == 0,
              "commit round trip");
        make_sb(0, &g.g1, 3, &sa);
        make_sb(1, &g.g1, 3, &sbb);
        encode_sb(&sa, ga);
        encode_sb(&sbb, gb);
        put_hex(S, "superblock_a_unit_hex", ga, SV1_UNIT);
        put_sha(S, "superblock_a_unit_sha256", ga, SV1_UNIT);
        put_hex(S, "superblock_a_crc_u32le", ga + SV1_SB_CRC_OFFSET, 4);
        put_hex(S, "superblock_b_unit_hex", gb, SV1_UNIT);
        put_sha(S, "superblock_b_unit_sha256", gb, SV1_UNIT);
        put_hex(S, "superblock_b_crc_u32le", gb + SV1_SB_CRC_OFFSET, 4);
        CHECK(memcmp(ga, gb, SV1_UNIT) != 0, "A != B");
        CHECK(memcmp(ga + 168, gb + 168, 4) != 0, "CRC A != CRC B");
        put_text(S, "expected_root_classification", "redundant valid copies; equivalent logical roots");
        CHECK(sv1_superblock_decode(ga, SV1_UNIT, 0, &da) == 0 &&
                  sv1_superblock_decode(gb, SV1_UNIT, 1, &db) == 0 &&
                  sv1_superblock_equivalent(&da, &db),
              "genesis A/B equivalent");
        CHECK(sv1_superblock_validate_commit(&da, id, &g.g1) == 0, "A binds genesis");
        CHECK(sv1_superblock_validate_commit(&db, id, &g.g1) == 0, "B binds genesis");

        /* the C genesis writer produces exactly the vector's units 0, 2, 3 */
        static uint8_t gu[4][SV1_UNIT];
        CHECK_EQ(sv1_genesis_units(UUID, 16, gu), 0, "genesis units");
        CHECK(memcmp(gu[0], ga, SV1_UNIT) == 0, "genesis unit 0 = vector superblock A");
        CHECK(sv1_all_zero(gu[1], SV1_UNIT), "genesis unit 1 is zero (B written later)");
        unit_of(g.empty_cat, 16, u);
        CHECK(memcmp(gu[2], u, SV1_UNIT) == 0, "genesis unit 2 = vector catalog unit");
        unit_of(sem, SV1_COMMIT_BYTES, u);
        CHECK(memcmp(gu[3], u, SV1_UNIT) == 0, "genesis unit 3 = vector commit unit");

        /* the engine classifies the vector image as the vector says */
        memdev m;
        st_store s;
        static st_workspace ws;
        mem_init(&m, 16);
        memcpy(m.units[0], ga, SV1_UNIT);
        memcpy(m.units[1], gb, SV1_UNIT);
        memcpy(m.units[2], gu[2], SV1_UNIT);
        memcpy(m.units[3], gu[3], SV1_UNIT);
        st_dev dv = mem_dev(&m);
        CHECK_EQ(st_open(&s, &dv, &ws), 0, "open genesis vector image");
        CHECK(s.state == ST_VALID && s.peer == ST_PEER_VALID && st_generation(&s) == 1,
              "genesis vector: equivalent roots mount Valid");
        mem_free(&m);
    }
    /* adjacent_generations */
    {
        const char *S = "adjacent_generations";
        uint8_t g1id[32], g2id[32], sb2[SV1_UNIT];
        sv1_commit back;
        sv1_superblock s2;
        sv1_commit_object_id(&g.g1, g1id);
        put_hex(S, "generation_1_commit_record_object_id_hex", g1id, 32);
        put_hex(S, "generation_1_catalog_object_id_hex", g.empty_cat_id, 32);
        put_num(S, "generation_1_committed_high_water", g.g1.committed_high_water);
        put_text(S, "unit_map.0", "generation 2 superblock A");
        put_text(S, "unit_map.1", "generation 1 superblock B");
        put_text(S, "unit_map.2", "generation 1 catalog");
        put_text(S, "unit_map.3", "generation 1 CommitRecord");
        put_text(S, "unit_map.4", "generation 2 application object");
        put_text(S, "unit_map.5", "generation 2 catalog");
        put_text(S, "unit_map.6", "generation 2 CommitRecord");
        put_hex(S, "application_object_semantic_hex", g.app, 16);
        put_hex(S, "application_object_id_hex", g.app_id, 32);
        unit_of(g.app, 16, u);
        put_hex(S, "application_object_unit_hex", u, SV1_UNIT);
        put_sha(S, "application_object_unit_sha256", u, SV1_UNIT);
        put_hex(S, "generation_2_catalog_semantic_hex", g.one_cat, 80);
        put_hex(S, "generation_2_catalog_object_id_hex", g.one_cat_id, 32);
        unit_of(g.one_cat, 80, u);
        put_hex(S, "generation_2_catalog_unit_hex", u, SV1_UNIT);
        put_sha(S, "generation_2_catalog_unit_sha256", u, SV1_UNIT);
        CHECK_EQ(sv1_commit_encode(&g.g2, sem), 0, "gen2 commit encode");
        sv1_commit_object_id(&g.g2, g2id);
        pn = preimage(2, 1, sem, SV1_COMMIT_BYTES, pre);
        put_hex(S, "generation_2_commit_record_semantic_hex", sem, SV1_COMMIT_BYTES);
        put_hex(S, "generation_2_commit_record_object_id_hex", g2id, 32);
        unit_of(sem, SV1_COMMIT_BYTES, u);
        put_hex(S, "generation_2_commit_record_unit_hex", u, SV1_UNIT);
        put_sha(S, "generation_2_commit_record_unit_sha256", u, SV1_UNIT);
        put_hex(S, "generation_2_commit_record_preimage_hex", pre, pn);
        uint8_t d[32];
        sha256_hash(pre, pn, d);
        CHECK(memcmp(d, g2id, 32) == 0, "gen2 id is SHA-256 of preimage");
        CHECK(sv1_commit_decode(sem, SV1_COMMIT_BYTES, &back) == 0 &&
                  memcmp(&back, &g.g2, sizeof back) == 0,
              "gen2 commit round trip");
        make_sb(0, &g.g2, 6, &s2);
        CHECK(sv1_superblock_validate_commit(&s2, g2id, &g.g2) == 0, "gen2 sb binds commit");
        encode_sb(&s2, sb2);
        put_hex(S, "generation_2_superblock_a_unit_hex", sb2, SV1_UNIT);
        put_sha(S, "generation_2_superblock_a_unit_sha256", sb2, SV1_UNIT);
        put_hex(S, "generation_2_superblock_a_crc_u32le", sb2 + SV1_SB_CRC_OFFSET, 4);
        put_num(S, "generation_2_committed_high_water", g.g2.committed_high_water);
        put_text(S, "expected_root_classification",
                 "normal adjacent history; generation 2 follows generation 1 exactly");
        CHECK(sv1_commit_identifies_predecessor(&g.g2, &g.g1, g1id), "gen2 identifies gen1");
        CHECK(memcmp(sem + 72, g1id, 32) == 0, "previous_commit_id links genesis");
        CHECK(memcmp(sem + 104, g.empty_cat_id, 32) == 0, "previous_catalog_id links genesis");

        /* engine: the vector's 7-unit map mounts as generation 2, peer valid;
         * and a C transaction from genesis writes exactly these units. */
        memdev m, m2;
        st_store s;
        static st_workspace ws;
        mem_init(&m, 16);
        memcpy(m.units[0], sb2, SV1_UNIT);
        memcpy(m.units[1], gb, SV1_UNIT);
        unit_of(g.empty_cat, 16, m.units[2]);
        static uint8_t gu[4][SV1_UNIT];
        sv1_genesis_units(UUID, 16, gu);
        memcpy(m.units[3], gu[3], SV1_UNIT);
        unit_of(g.app, 16, m.units[4]);
        unit_of(g.one_cat, 80, m.units[5]);
        unit_of(sem, SV1_COMMIT_BYTES, m.units[6]);
        st_dev dv = mem_dev(&m);
        CHECK_EQ(st_open(&s, &dv, &ws), 0, "open adjacent vector image");
        CHECK(s.state == ST_VALID && s.peer == ST_PEER_VALID && st_generation(&s) == 2,
              "adjacent vector: generation 2 selected, peer valid");

        /* from a genesis whose active slot is B (so the new root lands in A) */
        mem_init(&m2, 16);
        memcpy(m2.units[1], gb, SV1_UNIT);
        memcpy(m2.units[2], gu[2], SV1_UNIT);
        memcpy(m2.units[3], gu[3], SV1_UNIT);
        st_dev dv2 = mem_dev(&m2);
        CHECK_EQ(st_open(&s, &dv2, &ws), 0, "open genesis(B)");
        st_object o = {3, 1, g.app, 16};
        CHECK_EQ(st_transact(&s, &o, 1, NULL, NULL), 0, "transact app object");
        int same = 1;
        for (int i = 0; i < 16; i++)
            if (i != 1 && memcmp(m.units[i], m2.units[i], SV1_UNIT))
                same = 0;
        CHECK(same && memcmp(m2.units[1], gb, SV1_UNIT) == 0,
              "C transaction writes the adjacent_generations vector byte for byte");
        mem_free(&m);
        mem_free(&m2);
    }
    /* equivalent_roots */
    {
        const char *S = "equivalent_roots";
        put_hex(S, "superblock_a_unit_hex", ga, SV1_UNIT);
        put_sha(S, "superblock_a_unit_sha256", ga, SV1_UNIT);
        put_hex(S, "superblock_b_unit_hex", gb, SV1_UNIT);
        put_sha(S, "superblock_b_unit_sha256", gb, SV1_UNIT);
        put_hex(S, "superblock_a_crc_u32le", ga + SV1_SB_CRC_OFFSET, 4);
        put_hex(S, "superblock_b_crc_u32le", gb + SV1_SB_CRC_OFFSET, 4);
        put_text(S, "expected_root_classification",
                 "same generation and equivalent logical root; redundant valid copies");
        CHECK(memcmp(ga, gb, SV1_UNIT) != 0, "redundant copies differ in slot and CRC");
    }

    /* bidirectional match */
    int matched_rows = 0;
    for (size_t r = 0; r < GOLDEN_ROWS; r++) {
        int found = 0;
        for (int i = 0; i < ncomp; i++) {
            if (strcmp(comp[i].section, GOLDEN[r].section) || strcmp(comp[i].key, GOLDEN[r].key))
                continue;
            found = 1;
            comp[i].matched++;
            CHECK(strcmp(comp[i].value, GOLDEN[r].value) == 0, "golden %s.%s differs",
                  GOLDEN[r].section, GOLDEN[r].key);
        }
        CHECK(found, "golden %s.%s not asserted by the C test", GOLDEN[r].section, GOLDEN[r].key);
        matched_rows += found;
    }
    for (int i = 0; i < ncomp; i++) {
        CHECK(comp[i].matched == 1, "computed %s.%s missing from JSON (or duplicated)",
              comp[i].section, comp[i].key);
        free(comp[i].value);
    }
    printf("golden vectors: %d of %zu JSON rows covered\n", matched_rows,
           (size_t)GOLDEN_ROWS);
}

/* ---- negative tests (store_v1_negative.rs) ---- */
static void ent(uint64_t first, const char *data, sv1_entry *e)
{
    size_t n = strlen(data);
    memset(e, 0, sizeof *e);
    sv1_object_id(3, 1, (const uint8_t *)data, n, e->object_id);
    e->kind = 3;
    e->version = 1;
    e->first_unit = first;
    e->byte_length = n;
    e->unit_count = 1;
}
static void neg_genesis(sv1_commit *c)
{
    uint8_t cat[16];
    size_t len;
    memset(c, 0, sizeof *c);
    sv1_catalog_encode(NULL, 0, cat, 16, &len);
    memset(c->store_uuid, 0x11, 16);
    c->region_units = 8;
    c->generation = 1;
    sv1_object_id(1, 1, cat, 16, c->catalog_id);
    c->catalog_first_unit = 2;
    c->catalog_byte_length = 16;
    c->catalog_unit_count = 1;
    c->committed_high_water = 4;
}

static void neg_catalog_header(void)
{
    uint8_t v[17];
    size_t len;
    sv1_entry e[2];
    uint32_t n;
    sv1_catalog_encode(NULL, 0, v, 16, &len);
    const struct { int off; uint8_t val; } cases[] = {{0, 'X'}, {8, 2}, {10, 63}};
    for (size_t i = 0; i < 3; i++) {
        uint8_t m[16];
        memcpy(m, v, 16);
        m[cases[i].off] = cases[i].val;
        CHECK(sv1_catalog_decode(m, 16, e, 2, &n) != 0, "catalog header offset %d", cases[i].off);
    }
    uint8_t m[17];
    memcpy(m, v, 16);
    sv1_put32(m + 12, 1);
    CHECK_EQ(sv1_catalog_decode(m, 16, e, 2, &n), SV1_E_INVALID_LENGTH, "wrong count");
    CHECK_EQ(sv1_catalog_decode(v, 15, e, 2, &n), SV1_E_INVALID_LENGTH, "short catalog");
    memcpy(m, v, 16);
    m[16] = 0;
    CHECK_EQ(sv1_catalog_decode(m, 17, e, 2, &n), SV1_E_INVALID_LENGTH, "trailing byte");
    memcpy(m, v, 16);
    sv1_put32(m + 12, SV1_MAX_CATALOG_ENTRIES + 1);
    CHECK_EQ(sv1_catalog_decode(m, 16, e, 2, &n), SV1_E_CATALOG_TOO_LARGE, "over limit");
    /* v1.rs: bad magic is BadCatalogMagic exactly */
    memcpy(m, v, 16);
    m[0] ^= 1;
    CHECK_EQ(sv1_catalog_decode(m, 16, e, 2, &n), SV1_E_BAD_CATALOG_MAGIC, "bad catalog magic");
}

static void neg_entry_reserved(void)
{
    sv1_entry e, back;
    uint8_t enc[64], m[64];
    ent(2, "x", &e);
    sv1_entry_encode(&e, enc);
    for (int off = 58; off < 64; off++) {
        memcpy(m, enc, 64);
        m[off] = 1;
        CHECK_EQ(sv1_entry_decode(m, 64, &back), SV1_E_NONZERO_RESERVED, "entry reserved");
    }
    memcpy(m, enc, 64);
    m[56] = 1;
    CHECK_EQ(sv1_entry_decode(m, 64, &back), SV1_E_MALFORMED_DESCRIPTOR, "entry flags");
    const struct { int off; uint64_t val; } cases[] = {
        {32, 0}, {34, 0}, {44, 0}, {44, 67108865}, {52, 0}, {52, 2}};
    for (size_t i = 0; i < 6; i++) {
        memcpy(m, enc, 64);
        int w = cases[i].off == 44 ? 8 : cases[i].off == 52 ? 4 : 2;
        uint8_t b[8];
        sv1_put64(b, cases[i].val);
        memcpy(m + cases[i].off, b, (size_t)w);
        CHECK(sv1_entry_decode(m, 64, &back) != 0, "entry offset %d value %llu", cases[i].off,
              (unsigned long long)cases[i].val);
    }
    uint8_t id[32];
    CHECK_EQ(sv1_object_id(3, 1, (const uint8_t *)"", 0, id), SV1_E_INVALID_OBJECT, "empty object");
    CHECK_EQ(sv1_object_id(0, 1, (const uint8_t *)"xxxxxxxxxxxxxxxx", 16, id), SV1_E_INVALID_OBJECT,
             "kind zero object");
    e.flags = 1;
    CHECK_EQ(sv1_entry_encode(&e, enc), SV1_E_MALFORMED_DESCRIPTOR, "encode bad flags");
}

static void neg_catalog_order(void)
{
    sv1_entry a, b, low, high, list[2], back[2];
    uint8_t buf[160];
    size_t len;
    uint32_t n;
    ent(2, "a", &a);
    ent(3, "b", &b);
    if (sv1_cmp_id(a.object_id, b.object_id) < 0) {
        low = a;
        high = b;
    } else {
        low = b;
        high = a;
    }
    list[0] = low;
    list[1] = high;
    CHECK_EQ(sv1_catalog_encode(list, 2, buf, sizeof buf, &len), 0, "sorted encode");
    CHECK_EQ(sv1_catalog_decode(buf, len, back, 2, &n), 0, "sorted decode");
    list[0] = high;
    list[1] = low;
    CHECK_EQ(sv1_catalog_encode(list, 2, buf, sizeof buf, &len), SV1_E_CATALOG_ORDER, "descending");
    list[0] = low;
    list[1] = low;
    CHECK_EQ(sv1_catalog_encode(list, 2, buf, sizeof buf, &len), SV1_E_DUPLICATE_OBJECT, "duplicate");
    /* decoder side: hand-built descending bytes */
    list[0] = low;
    list[1] = high;
    sv1_catalog_encode(list, 2, buf, sizeof buf, &len);
    uint8_t t[64];
    memcpy(t, buf + 16, 64);
    memcpy(buf + 16, buf + 80, 64);
    memcpy(buf + 80, t, 64);
    CHECK_EQ(sv1_catalog_decode(buf, len, back, 2, &n), SV1_E_CATALOG_ORDER, "decode descending");
    memcpy(buf + 16, buf + 80, 64);
    CHECK_EQ(sv1_catalog_decode(buf, len, back, 2, &n), SV1_E_DUPLICATE_OBJECT, "decode duplicate");
}

static void neg_bounds(void)
{
    sv1_entry e;
    ent(2, "x", &e);
    CHECK_EQ(sv1_entry_validate_bounds(&e, 8, 4, 5), 0, "valid bounds");
    ent(0, "x", &e);
    CHECK_EQ(sv1_entry_validate_bounds(&e, 8, 4, 5), SV1_E_OUT_OF_BOUNDS, "unit 0");
    ent(1, "x", &e);
    CHECK_EQ(sv1_entry_validate_bounds(&e, 8, 4, 5), SV1_E_OUT_OF_BOUNDS, "unit 1");
    ent(4, "x", &e);
    CHECK_EQ(sv1_entry_validate_bounds(&e, 8, 4, 5), SV1_E_OUT_OF_BOUNDS, "into catalog");
    ent(2, "x", &e);
    CHECK_EQ(sv1_entry_validate_bounds(&e, 8, 4, 2), SV1_E_OUT_OF_BOUNDS, "past high water");
    ent(3, "x", &e);
    CHECK_EQ(sv1_entry_validate_bounds(&e, 2, 8, 8), SV1_E_OUT_OF_BOUNDS, "past region");
    ent(2, "x", &e);
    e.first_unit = UINT64_MAX;
    CHECK_EQ(sv1_entry_validate_bounds(&e, 8, 8, 8), SV1_E_LENGTH_OVERFLOW, "overflow");
    /* v1.rs: */
    ent(2, "x", &e);
    CHECK_EQ(sv1_entry_validate_bounds(&e, 8, 2, 8), SV1_E_OUT_OF_BOUNDS, "at catalog first");
}

static void neg_extents(void)
{
    sv1_entry l[2];
    sv1_extent scratch[2];
    ent(2, "first", &l[0]);
    ent(2, "second", &l[1]);
    sv1_sort_entries(l, 2);
    CHECK_EQ(sv1_catalog_validate_extents(l, 2, 16, 4, 8, scratch), SV1_E_OVERLAP, "overlap");
    ent(3, "third", &l[0]);
    CHECK_EQ(sv1_catalog_validate_extents(l, 1, 16, 3, 8, scratch), SV1_E_OUT_OF_BOUNDS,
             "metadata overlap");
}

static void neg_extent_identity(void)
{
    const char *sem = "payload";
    size_t n = strlen(sem);
    uint8_t id[32], x[SV1_UNIT], y[SV1_UNIT];
    sv1_object_id(3, 1, (const uint8_t *)sem, n, id);
    unit_of((const uint8_t *)sem, n, x);
    CHECK_EQ(sv1_validate_extent(id, 3, 1, n, x, SV1_UNIT), 0, "valid extent");
    memcpy(y, x, SV1_UNIT);
    y[0] ^= 1;
    CHECK_EQ(sv1_validate_extent(id, 3, 1, n, y, SV1_UNIT), SV1_E_INTEGRITY, "semantic mutation");
    memcpy(y, x, SV1_UNIT);
    y[SV1_UNIT - 1] = 1;
    CHECK_EQ(sv1_validate_extent(id, 3, 1, n, y, SV1_UNIT), SV1_E_NONZERO_RESERVED, "padding");
    CHECK_EQ(sv1_validate_extent(id, 4, 1, n, x, SV1_UNIT), SV1_E_INTEGRITY, "wrong kind");
    CHECK_EQ(sv1_validate_extent(id, 3, 2, n, x, SV1_UNIT), SV1_E_INTEGRITY, "wrong version");
    CHECK_EQ(sv1_validate_extent(id, 3, 1, n + 1, x, SV1_UNIT), SV1_E_INTEGRITY, "wrong length");
    CHECK_EQ(sv1_validate_extent(id, 3, 1, n, x, SV1_UNIT - 1), SV1_E_INVALID_LENGTH, "short extent");
}

static void neg_superblock(void)
{
    sv1_commit c;
    sv1_superblock sb, out;
    uint8_t v[SV1_UNIT], m[SV1_UNIT];
    CHECK(sv1_crc32c((const uint8_t *)"123456789", 9) == 0xe3069283u, "crc kat");
    neg_genesis(&c);
    make_sb(0, &c, 3, &sb);
    CHECK_EQ(sv1_superblock_encode(&sb, v), 0, "sb encode");
    CHECK_EQ(sv1_superblock_decode(v, SV1_UNIT, 0, &out), 0, "sb decode");
    memcpy(m, v, SV1_UNIT);
    m[56] ^= 1;
    CHECK_EQ(sv1_superblock_decode(m, SV1_UNIT, 0, &out), SV1_E_BAD_SUPERBLOCK_CRC, "field corrupt");
    memcpy(m, v, SV1_UNIT);
    m[168] ^= 1;
    CHECK_EQ(sv1_superblock_decode(m, SV1_UNIT, 0, &out), SV1_E_BAD_SUPERBLOCK_CRC, "crc corrupt");
    int bad = 0;
    for (int off = 172; off < (int)SV1_UNIT; off++) {
        memcpy(m, v, SV1_UNIT);
        m[off] = 1;
        rechecksum(m);
        if (sv1_superblock_decode(m, SV1_UNIT, 0, &out) != SV1_E_NONZERO_RESERVED)
            bad++;
    }
    CHECK(bad == 0, "reserved bytes 172..4096: %d not refused as NonzeroReserved", bad);
    g_checks += (int)SV1_UNIT - 172 - 1;
    CHECK_EQ(sv1_superblock_decode(v, SV1_UNIT, 1, &out), SV1_E_WRONG_SUPERBLOCK_SLOT, "wrong slot");
    const struct { int off; uint64_t val; } cases[] = {{48, 3}, {56, 0}, {160, 5}};
    for (int i = 0; i < 3; i++) {
        memcpy(m, v, SV1_UNIT);
        sv1_put64(m + cases[i].off, cases[i].val);
        rechecksum(m);
        CHECK_EQ(sv1_superblock_decode(m, SV1_UNIT, 0, &out), SV1_E_MALFORMED_SUPERBLOCK, "sb shape");
    }
    memcpy(m, v, SV1_UNIT);
    m[12] = 1;
    rechecksum(m);
    CHECK_EQ(sv1_superblock_decode(m, SV1_UNIT, 0, &out), SV1_E_UNSUPPORTED_FEATURES, "sb features");
    memcpy(m, v, SV1_UNIT);
    m[0] ^= 1;
    rechecksum(m);
    CHECK_EQ(sv1_superblock_decode(m, SV1_UNIT, 0, &out), SV1_E_BAD_SUPERBLOCK_MAGIC, "sb magic");
}

static void neg_commit(void)
{
    sv1_commit good, back, t;
    uint8_t enc[SV1_COMMIT_BYTES], m[SV1_COMMIT_BYTES + 1];
    neg_genesis(&good);
    CHECK_EQ(sv1_commit_encode(&good, enc), 0, "commit encode");
    CHECK(sv1_commit_decode(enc, SV1_COMMIT_BYTES, &back) == 0 &&
              memcmp(&back, &good, sizeof back) == 0,
          "commit round trip");
    memset(m, 0, sizeof m);
    CHECK(sv1_commit_decode(m, SV1_COMMIT_BYTES - 1, &back) != 0, "short commit");
    CHECK(sv1_commit_decode(m, SV1_COMMIT_BYTES + 1, &back) != 0, "long commit");
    const struct { int off; uint64_t val; } cases[] = {{56, 0}, {64, 1},  {176, 15}, {184, 2},
                                                      {188, 1}, {192, 3}, {192, 5}};
    for (int i = 0; i < 7; i++) {
        memcpy(m, enc, SV1_COMMIT_BYTES);
        sv1_put64(m + cases[i].off, cases[i].val);
        CHECK(sv1_commit_decode(m, SV1_COMMIT_BYTES, &back) != 0, "commit offset %d value %llu",
              cases[i].off, (unsigned long long)cases[i].val);
    }
    memcpy(m, enc, SV1_COMMIT_BYTES);
    sv1_put64(m + 48, UINT64_C(4294967297));
    CHECK(sv1_commit_decode(m, SV1_COMMIT_BYTES, &back) != 0, "oversized region");
    memcpy(m, enc, SV1_COMMIT_BYTES);
    m[16] = 1;
    CHECK_EQ(sv1_commit_decode(m, SV1_COMMIT_BYTES, &back), SV1_E_UNSUPPORTED_FEATURES, "features");
    uint8_t id[32], pad[SV1_UNIT];
    sv1_commit_object_id(&good, id);
    unit_of(enc, SV1_COMMIT_BYTES, pad);
    CHECK_EQ(sv1_validate_extent(id, 2, 1, SV1_COMMIT_BYTES, pad, SV1_UNIT), 0, "padded commit");
    pad[SV1_UNIT - 1] = 1;
    CHECK_EQ(sv1_validate_extent(id, 2, 1, SV1_COMMIT_BYTES, pad, SV1_UNIT), SV1_E_NONZERO_RESERVED,
             "commit padding");
    t = good;
    t.previous_generation = 1;
    CHECK_EQ(sv1_commit_encode(&t, enc), SV1_E_INVALID_GENERATION, "genesis prev gen");
    t = good;
    t.committed_high_water = 5;
    CHECK_EQ(sv1_commit_encode(&t, enc), SV1_E_MALFORMED_COMMIT, "genesis high water");
}

static void neg_generation_link(void)
{
    sv1_commit prev, next, ov;
    uint8_t pid[32], enc[SV1_COMMIT_BYTES];
    neg_genesis(&prev);
    sv1_commit_object_id(&prev, pid);
    next = prev;
    next.generation = 2;
    next.previous_generation = 1;
    memcpy(next.previous_commit_id, pid, 32);
    memcpy(next.previous_catalog_id, prev.catalog_id, 32);
    next.catalog_first_unit = 4;
    next.committed_high_water = 6;
    CHECK_EQ(sv1_commit_encode(&next, enc), 0, "next encode");
    CHECK(sv1_commit_identifies_predecessor(&next, &prev, pid), "identifies predecessor");
    next.previous_catalog_id[0] ^= 1;
    CHECK(!sv1_commit_identifies_predecessor(&next, &prev, pid), "wrong prev catalog");
    memcpy(next.previous_catalog_id, prev.catalog_id, 32);
    next.previous_commit_id[0] ^= 1;
    CHECK(!sv1_commit_identifies_predecessor(&next, &prev, pid), "wrong prev commit");
    memcpy(next.previous_commit_id, pid, 32);
    next.previous_generation = 0;
    CHECK_EQ(sv1_commit_encode(&next, enc), SV1_E_INVALID_GENERATION, "non-adjacent");
    ov = next;
    ov.generation = UINT64_MAX;
    ov.previous_generation = UINT64_MAX - 1;
    memset(ov.previous_commit_id, 1, 32);
    memset(ov.previous_catalog_id, 1, 32);
    CHECK_EQ(sv1_commit_encode(&ov, enc), 0, "max generation");
    ov.previous_generation = UINT64_MAX;
    CHECK_EQ(sv1_commit_encode(&ov, enc), SV1_E_INVALID_GENERATION, "generation overflow");
}

static void neg_sb_binding(void)
{
    sv1_commit c;
    sv1_superblock sb, w;
    uint8_t id[32];
    neg_genesis(&c);
    make_sb(0, &c, 3, &sb);
    sv1_commit_object_id(&c, id);
    CHECK_EQ(sv1_superblock_validate_commit(&sb, id, &c), 0, "sb binds commit");
    w = sb;
    w.commit_record_unit = 2;
    CHECK_EQ(sv1_superblock_validate_commit(&w, id, &c), SV1_E_MALFORMED_SUPERBLOCK, "commit unit");
    w = sb;
    w.catalog_first_unit = 1;
    CHECK_EQ(sv1_superblock_validate_commit(&w, id, &c), SV1_E_MALFORMED_SUPERBLOCK, "catalog");
    w = sb;
    w.committed_high_water = 3;
    CHECK_EQ(sv1_superblock_validate_commit(&w, id, &c), SV1_E_MALFORMED_SUPERBLOCK, "high water");
    CHECK_EQ(sv1_commit_validates_catalog(&c, c.catalog_id, NULL, 0), 0, "validates empty catalog");
    uint8_t other[32];
    memset(other, 7, 32);
    CHECK(sv1_commit_validates_catalog(&c, other, NULL, 0) != 0, "wrong catalog id refused");
}

/* C only: each refusal reached on its own, with its exact code (mutation
 * coverage for checks that a combined negative case reaches first). */
static void neg_exact_refusals(void)
{
    sv1_commit good, back, c;
    sv1_superblock sb, out;
    uint8_t enc[SV1_COMMIT_BYTES], v[SV1_UNIT], cat[SV1_UNIT], real[32], bogus[32];
    neg_genesis(&good);
    CHECK_EQ(sv1_commit_encode(&good, enc), 0, "commit encode");
    enc[0] ^= 1;
    CHECK_EQ(sv1_commit_decode(enc, SV1_COMMIT_BYTES, &back), SV1_E_MALFORMED_COMMIT, "commit magic");
    make_sb(0, &good, 3, &sb);
    CHECK_EQ(sv1_superblock_encode(&sb, v), 0, "sb encode");
    v[8] = 2;
    rechecksum(v);
    CHECK_EQ(sv1_superblock_decode(v, SV1_UNIT, 0, &out), SV1_E_UNSUPPORTED_VERSION, "sb version");
    /* empty catalog: commit and caller must name the catalog the entries hash to */
    size_t len;
    memset(cat, 0, sizeof cat);
    CHECK_EQ(sv1_catalog_encode(NULL, 0, cat, sizeof cat, &len), 0, "empty catalog");
    CHECK_EQ(sv1_object_id(SV1_KIND_CATALOG, SV1_VERSION, cat, len, real), 0, "catalog id");
    memset(bogus, 0x3c, 32);
    c = good;
    memcpy(c.catalog_id, real, 32);
    c.catalog_entry_count = 0;
    c.catalog_byte_length = sv1_catalog_len(0);
    c.catalog_unit_count = 1;
    CHECK_EQ(sv1_commit_validates_catalog(&c, real, NULL, 0), 0, "catalog matches");
    memcpy(c.catalog_id, bogus, 32);
    CHECK_EQ(sv1_commit_validates_catalog(&c, real, NULL, 0), SV1_E_INTEGRITY, "commit names another catalog");
    CHECK_EQ(sv1_commit_validates_catalog(&c, bogus, NULL, 0), SV1_E_INTEGRITY, "entries hash to another catalog");
}

int main(int argc, char **argv)
{
    int rules_only = argc > 1 && strcmp(argv[1], "--rules-only") == 0;
    (void)rules_only;
    golden();
    neg_catalog_header();
    neg_entry_reserved();
    neg_catalog_order();
    neg_bounds();
    neg_extents();
    neg_extent_identity();
    neg_superblock();
    neg_commit();
    neg_exact_refusals();
    neg_generation_link();
    neg_sb_binding();
    printf("store_v1_test: %d checks, %d failed\n", g_checks, g_failed);
    printf("STORE_V1_FORMAT: %s\n", g_failed ? "FAIL" : "PASS");
    return g_failed ? 1 : 0;
}
