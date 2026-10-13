/*
 * kv_slab_test.c - tests for native/kv/kv_slab.c (aienos#367, cut N2).
 *
 * Covers:
 *   - bind_refuses_overlap_with_store_and_anchor
 *   - recover_reads_exactly_n_header_units
 *   - power_cut_at_every_unit_boundary_never_exposes_partial_record
 *   - torn_header_is_empty_slot
 *   - used_bytes_counts_foreign_namespace_slots
 *   - slot_write_stage_progression_and_cancel_rules
 *   - last_payload_unit_nonzero_padding_refused
 *   - io_and_flush_failures_fail_stop_slab
 *   - n2_existing_store_gates_pass_with_slab_present
 *
 * Hosted libc is used only in this test file; kv_slab.c imports no heap, clock
 * or direct libc I/O.
 */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "kv_slab.h"
#include "../disk/disk_file.h"
#include "../argus/sha256.h"
#include "../m5/m5.h"
#include "../store/store_sealed.h"

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
#else
#define ALLOC_BEGIN() ((void)0)
#define ALLOC_END() 0ul
#endif

/* ---- tiny harness ------------------------------------------------------ */
static const char *g_test;
static const char *g_out_dir = "out";
static int g_fails;
static int g_checks;

#define CHECK(cond) do { g_checks++; if (!(cond)) { g_fails++; \
    printf("  FAIL %s: %s (line %d)\n", g_test, #cond, __LINE__); } } while (0)
#define CHECK_RC(got, want) do { int g_ = (got), w_ = (want); g_checks++; if (g_ != w_) { g_fails++; \
    printf("  FAIL %s: %s = %d, want %d (line %d)\n", g_test, #got, g_, w_, __LINE__); } } while (0)
#define CHECK_MEM(a, b, n) CHECK(memcmp((a), (b), (n)) == 0)

/* ---- deterministic record / slot fixture builder ----------------------- */
static void fill_bytes(uint8_t *buf, size_t len, uint8_t seed)
{
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(seed + (uint8_t)(i * 37u + (i >> 8)));
    }
}

static void build_test_slot(uint32_t slot_index,
                            uint64_t incarnation,
                            const uint8_t ns[32],
                            uint8_t key_seed,
                            uint64_t payload_len,
                            uint8_t body_seed,
                            kv_slot_header *hdr_out,
                            uint8_t *sealed_body_out,
                            size_t body_cap,
                            size_t *sealed_len_out)
{
    memset(hdr_out, 0, sizeof *hdr_out);
    kv_chunk_header *c = &hdr_out->rec.chunk;
    memcpy(c->namespace_id, ns, 32);
    fill_bytes(c->chunk_key, 32, key_seed);
    memset(c->parent_key, 0, 32);
    fill_bytes(c->model_sha256, 32, 0x42);
    c->first_position = 0;
    c->token_count = 64;
    c->chunk_tokens = 64;
    c->block_size = 16;
    c->num_layers = 16;
    c->num_kv_heads = 8;
    c->head_dim = 64;
    c->dtype = KV_DTYPE_FP32;
    c->backend_format = KV_BACKEND_NATIVE_F32_DECODE_STATE_V1;
    c->flags = 0;
    c->payload_len = payload_len;
    c->written_unix_ns = 1700000000000000000ULL + incarnation;

    uint8_t seg_digest[1][32];
    fill_bytes(seg_digest[0], 32, (uint8_t)(body_seed ^ 0x5c));
    kv_payload_root(seg_digest, 1, hdr_out->rec.payload_sha256);

    fill_bytes(hdr_out->envelope_id, 16, (uint8_t)(key_seed + 1));
    fill_bytes(hdr_out->nonce_prefix, 8, (uint8_t)(key_seed + 2));
    hdr_out->key_epoch = 1;
    hdr_out->slot_incarnation = incarnation;
    hdr_out->slot_index = slot_index;

    uint32_t su = 0, env_len = 0;
    CHECK_RC(kv_slot_geometry(payload_len, &su, &env_len), KV_OK);
    hdr_out->sealed_units = su;
    hdr_out->envelope_len = env_len;

    size_t sealed_len = (size_t)env_len - M5_ENV_HEADER_LEN;
    CHECK(sealed_len <= body_cap);
    fill_bytes(sealed_body_out, sealed_len, body_seed);
    if (sealed_len_out) *sealed_len_out = sealed_len;
}

/* ---- counting & fault-injecting disk wrapper --------------------------- */
#define LOG_CAP 256

typedef struct {
    disk_dev *inner;
    uint64_t read_lbas[LOG_CAP];
    uint32_t read_counts[LOG_CAP];
    uint32_t read_calls;
    uint64_t blocks_read;
    uint32_t write_calls;
    uint64_t blocks_written;
    uint32_t flush_calls;
    int32_t fail_read_call;   /* -1 = never, else 0-based call index */
    int32_t fail_write_call;  /* -1 = never, else 0-based call index */
    int32_t fail_flush_call;  /* -1 = never, else 0-based call index */
} spy_disk;

static int spy_read(void *ctx, uint64_t lba, uint32_t count, uint8_t *buf)
{
    spy_disk *s = (spy_disk *)ctx;
    uint32_t idx = s->read_calls++;
    if (idx < LOG_CAP) {
        s->read_lbas[idx] = lba;
        s->read_counts[idx] = count;
    }
    s->blocks_read += count;
    if (s->fail_read_call >= 0 && (int32_t)idx == s->fail_read_call) return DISK_EIO;
    return s->inner->read(s->inner->ctx, lba, count, buf);
}

static int spy_write(void *ctx, uint64_t lba, uint32_t count, const uint8_t *buf)
{
    spy_disk *s = (spy_disk *)ctx;
    uint32_t idx = s->write_calls++;
    s->blocks_written += count;
    if (s->fail_write_call >= 0 && (int32_t)idx == s->fail_write_call) return DISK_EIO;
    return s->inner->write(s->inner->ctx, lba, count, buf);
}

static int spy_flush(void *ctx)
{
    spy_disk *s = (spy_disk *)ctx;
    uint32_t idx = s->flush_calls++;
    if (s->fail_flush_call >= 0 && (int32_t)idx == s->fail_flush_call) return DISK_EIO;
    return s->inner->flush(s->inner->ctx);
}

static void spy_wrap(spy_disk *s, disk_dev *inner, disk_dev *out)
{
    memset(s, 0, sizeof *s);
    s->inner = inner;
    s->fail_read_call = -1;
    s->fail_write_call = -1;
    s->fail_flush_call = -1;
    *out = *inner;
    out->ctx = s;
    out->read = spy_read;
    out->write = spy_write;
    out->flush = spy_flush;
}

static void spy_reset_counts(spy_disk *s)
{
    s->read_calls = 0;
    s->blocks_read = 0;
    s->write_calls = 0;
    s->blocks_written = 0;
    s->flush_calls = 0;
}

static int file_load_bytes(const char *path, uint8_t *buf, size_t n)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t got = fread(buf, 1, n, f);
    fclose(f);
    return got == n ? 0 : -1;
}

static int file_save_bytes(const char *path, const uint8_t *buf, size_t n)
{
    FILE *f = fopen(path, "r+b");
    if (!f) f = fopen(path, "wb");
    if (!f) return -1;
    size_t put = fwrite(buf, 1, n, f);
    fclose(f);
    return put == n ? 0 : -1;
}

/* ======================================================================== */
/* 1. bind_refuses_overlap_with_store_and_anchor                             */
/* ======================================================================== */
static void test_bind_refuses_overlap_with_store_and_anchor(void)
{
    for (int bi = 0; bi < 2; bi++) {
        uint32_t bs = bi == 0 ? 512u : 4096u;
        uint32_t bpu = KV_SLOT_UNIT / bs;
        char path[256];
        snprintf(path, sizeof path, "%s/kv_bind_%u.img", g_out_dir, bs);
        unlink(path);

        disk_file df;
        disk_dev d;
        /* 100 units total: anchor [0, 4), store [4, 68), slab [68, 100). */
        uint64_t total_units = 100u;
        CHECK_RC(disk_file_open(&df, &d, path, bs, total_units * bpu, 1), 0);

        kv_lba_range anchor = { 0u, 4u * bpu };
        kv_lba_range store  = { 4u * bpu, 64u * bpu };
        uint64_t slab_base  = 68u * bpu;
        uint64_t slab_units = 32u;
        kv_disk kd;
        memset(&kd, 0, sizeof kd);

        /* Valid disjoint bind at the tail of the partition. */
        ALLOC_BEGIN();
        CHECK_RC(kv_disk_bind(&kd, &d, slab_base, slab_units, store, anchor), KV_OK);
        CHECK(ALLOC_END() == 0ul);
        CHECK(kd.disk == &d);
        CHECK(kd.base_lba == slab_base);
        CHECK(kd.blocks_per_unit == bpu);
        CHECK(kd.region_units == slab_units);

        /* Valid disjoint bind when slab sits between anchor and store. */
        kv_lba_range store_tail = { 36u * bpu, 64u * bpu };
        CHECK_RC(kv_disk_bind(&kd, &d, 4u * bpu, 32u, store_tail, anchor), KV_OK);

        /* Valid disjoint bind when slab sits at LBA 0 before anchor and store. */
        kv_lba_range anchor_mid = { 32u * bpu, 4u * bpu };
        CHECK_RC(kv_disk_bind(&kd, &d, 0u, 32u, store_tail, anchor_mid), KV_OK);

        /* NULL arguments. */
        CHECK_RC(kv_disk_bind(NULL, &d, slab_base, slab_units, store, anchor), KV_E_ARG);
        CHECK_RC(kv_disk_bind(&kd, NULL, slab_base, slab_units, store, anchor), KV_E_ARG);

        /* Bad disk block_size (1024) or max_blocks_per_io smaller than 1 unit. */
        disk_dev bad_d = d;
        bad_d.block_size = 1024u;
        CHECK_RC(kv_disk_bind(&kd, &bad_d, slab_base, slab_units, store, anchor), KV_E_SLAB_GEOMETRY);
        if (bs == 512u) {
            bad_d = d;
            bad_d.max_blocks_per_io = 4u; /* less than 8 blocks per 4096B unit */
            CHECK_RC(kv_disk_bind(&kd, &bad_d, slab_base, slab_units, store, anchor), KV_E_SLAB_GEOMETRY);
            /* Unaligned base_lba on 512-byte disk. */
            CHECK_RC(kv_disk_bind(&kd, &d, slab_base + 1u, slab_units - 1u, store, anchor), KV_E_SLAB_GEOMETRY);
            CHECK_RC(kv_disk_bind(&kd, &d, slab_base + 7u, slab_units - 1u, store, anchor), KV_E_SLAB_GEOMETRY);
        }

        /* Zero units, past end of disk, or u64 overflow in units. */
        CHECK_RC(kv_disk_bind(&kd, &d, slab_base, 0u, store, anchor), KV_E_SLAB_GEOMETRY);
        CHECK_RC(kv_disk_bind(&kd, &d, total_units * bpu, 1u, store, anchor), KV_E_SLAB_GEOMETRY);
        CHECK_RC(kv_disk_bind(&kd, &d, slab_base, slab_units + 1u, store, anchor), KV_E_SLAB_GEOMETRY);
        CHECK_RC(kv_disk_bind(&kd, &d, slab_base, UINT64_MAX, store, anchor), KV_E_SLAB_GEOMETRY);

        /* Empty or out-of-bounds store_range / anchor_range. */
        kv_lba_range empty_r = { 0u, 0u };
        kv_lba_range oob_r   = { 90u * bpu, 20u * bpu };
        kv_lba_range ovf_r   = { 10u * bpu, UINT64_MAX - 5u };
        CHECK_RC(kv_disk_bind(&kd, &d, slab_base, slab_units, empty_r, anchor), KV_E_SLAB_GEOMETRY);
        CHECK_RC(kv_disk_bind(&kd, &d, slab_base, slab_units, store, empty_r), KV_E_SLAB_GEOMETRY);
        CHECK_RC(kv_disk_bind(&kd, &d, slab_base, slab_units, oob_r, anchor), KV_E_SLAB_GEOMETRY);
        CHECK_RC(kv_disk_bind(&kd, &d, slab_base, slab_units, store, oob_r), KV_E_SLAB_GEOMETRY);
        CHECK_RC(kv_disk_bind(&kd, &d, slab_base, slab_units, ovf_r, anchor), KV_E_SLAB_GEOMETRY);

        /* Overlap with Store: exact match, 1-unit overlap at tail, 1-unit overlap at head,
         * slab inside Store, Store inside slab, and 1-block overlap into Store. */
        CHECK_RC(kv_disk_bind(&kd, &d, store.base_lba, 64u, store, anchor), KV_E_SLAB_OVERLAP);
        CHECK_RC(kv_disk_bind(&kd, &d, 67u * bpu, 32u, store, anchor), KV_E_SLAB_OVERLAP);
        CHECK_RC(kv_disk_bind(&kd, &d, 10u * bpu, 16u, store, anchor), KV_E_SLAB_OVERLAP);
        kv_lba_range small_store = { 70u * bpu, 4u * bpu };
        CHECK_RC(kv_disk_bind(&kd, &d, 68u * bpu, 16u, small_store, anchor), KV_E_SLAB_OVERLAP);
        kv_lba_range shifted_store = { 4u * bpu, 64u * bpu + 1u };
        CHECK_RC(kv_disk_bind(&kd, &d, 68u * bpu, 16u, shifted_store, anchor), KV_E_SLAB_OVERLAP);

        /* Overlap with Anchor: exact match, partial overlap, containment, 1-block overlap. */
        CHECK_RC(kv_disk_bind(&kd, &d, anchor.base_lba, 4u, store, anchor), KV_E_SLAB_OVERLAP);
        CHECK_RC(kv_disk_bind(&kd, &d, 3u * bpu, 1u, store, anchor), KV_E_SLAB_OVERLAP);
        CHECK_RC(kv_disk_bind(&kd, &d, 1u * bpu, 2u, store, anchor), KV_E_SLAB_OVERLAP);
        kv_lba_range big_anchor = { 0u, 68u * bpu + 1u };
        CHECK_RC(kv_disk_bind(&kd, &d, 68u * bpu, 16u, store, big_anchor), KV_E_SLAB_OVERLAP);
        kv_lba_range mid_anchor = { 72u * bpu, 2u * bpu };
        CHECK_RC(kv_disk_bind(&kd, &d, 68u * bpu, 16u, store, mid_anchor), KV_E_SLAB_OVERLAP);

        /* Store and Anchor overlapping each other is also refused. */
        kv_lba_range bad_anchor = { 0u, 5u * bpu };
        CHECK_RC(kv_disk_bind(&kd, &d, slab_base, slab_units, store, bad_anchor), KV_E_SLAB_OVERLAP);

        disk_file_close(&df);
        unlink(path);
    }
}

/* ======================================================================== */
/* 2. recover_reads_exactly_n_header_units                                   */
/* ======================================================================== */
static void test_recover_reads_exactly_n_header_units(void)
{
    enum { N_SLOTS = 8, SLOT_UNITS = 5 };
    static uint8_t body_buf[SLOT_UNITS * KV_SLOT_UNIT];
    static kv_slab_entry entries[N_SLOTS];
    static uint8_t scratch[KV_SLOT_UNIT];

    uint8_t ns[32];
    fill_bytes(ns, 32, 0x11);

    for (int bi = 0; bi < 2; bi++) {
        uint32_t bs = bi == 0 ? 512u : 4096u;
        uint32_t bpu = KV_SLOT_UNIT / bs;
        char path[256];
        snprintf(path, sizeof path, "%s/kv_rec_n_%u.img", g_out_dir, bs);
        unlink(path);

        disk_file df;
        disk_dev raw_d, d;
        spy_disk spy;
        uint64_t anchor_u = 4u, store_u = 16u, slab_u = (uint64_t)N_SLOTS * SLOT_UNITS;
        uint64_t total_u = anchor_u + store_u + slab_u;

        CHECK_RC(disk_file_open(&df, &raw_d, path, bs, total_u * bpu, 1), 0);
        spy_wrap(&spy, &raw_d, &d);

        kv_lba_range anchor = { 0u, anchor_u * bpu };
        kv_lba_range store  = { anchor_u * bpu, store_u * bpu };
        uint64_t slab_base  = (anchor_u + store_u) * bpu;

        kv_disk kd;
        memset(&kd, 0, sizeof kd);
        CHECK_RC(kv_disk_bind(&kd, &d, slab_base, slab_u, store, anchor), KV_OK);

        kv_slab slab;
        memset(&slab, 0, sizeof slab);
        CHECK_RC(kv_slab_init(&slab, &kd, N_SLOTS, SLOT_UNITS, ns, entries, scratch), KV_OK);
        CHECK_RC(kv_slab_format(&slab), KV_OK);

        /* Populate 3 slots (slots 1, 4, 6) with 3-unit payloads (10000 bytes). */
        uint32_t pop_slots[3] = { 1u, 4u, 6u };
        for (int i = 0; i < 3; i++) {
            kv_slot_header hdr;
            size_t slen = 0;
            build_test_slot(pop_slots[i], (uint64_t)(i + 10), ns, (uint8_t)(0x20 + i),
                            10000u, (uint8_t)(0x70 + i), &hdr, body_buf, sizeof body_buf, &slen);
            CHECK_RC(kv_slab_write_slot(&slab, pop_slots[i], &hdr, body_buf, slen), KV_OK);
        }

        /* Re-initialize slab state and measure recovery reads. */
        kv_slab rec_slab;
        memset(&rec_slab, 0, sizeof rec_slab);
        CHECK_RC(kv_slab_init(&rec_slab, &kd, N_SLOTS, SLOT_UNITS, ns, entries, scratch), KV_OK);
        spy_reset_counts(&spy);

        ALLOC_BEGIN();
        CHECK_RC(kv_slab_recover(&rec_slab), KV_OK);
        CHECK(ALLOC_END() == 0ul);

        /* Recovery must issue exactly N_SLOTS reads of 1 unit (bpu blocks) each,
         * at slot header LBAs only, with zero writes and zero flushes. */
        CHECK(spy.read_calls == (uint32_t)N_SLOTS);
        CHECK(spy.blocks_read == (uint64_t)N_SLOTS * bpu);
        CHECK(spy.write_calls == 0u);
        CHECK(spy.flush_calls == 0u);
        for (uint32_t s = 0; s < (uint32_t)N_SLOTS; s++) {
            uint64_t want_lba = slab_base + (uint64_t)s * SLOT_UNITS * bpu;
            CHECK(spy.read_lbas[s] == want_lba);
            CHECK(spy.read_counts[s] == bpu);
        }

        CHECK(rec_slab.valid_slots == 3u);
        CHECK(rec_slab.empty_slots == (uint32_t)(N_SLOTS - 3));
        CHECK(rec_slab.foreign_slots == 0u);
        CHECK(rec_slab.used_bytes == 3ULL * SLOT_UNITS * KV_SLOT_UNIT);
        CHECK(rec_slab.next_incarnation == 13u);

        disk_file_close(&df);
        unlink(path);
    }
}

/* ======================================================================== */
/* 3. power_cut_at_every_unit_boundary_never_exposes_partial_record          */
/* ======================================================================== */
static void test_power_cut_at_every_unit_boundary_never_exposes_partial_record(void)
{
    enum { N_SLOTS = 4, SLOT_UNITS = 4 };
    enum { IMG_UNITS = 4 + 8 + N_SLOTS * SLOT_UNITS };
    static uint8_t snap_empty[IMG_UNITS * KV_SLOT_UNIT];
    static uint8_t snap_r1[IMG_UNITS * KV_SLOT_UNIT];
    static uint8_t body_r1[SLOT_UNITS * KV_SLOT_UNIT];
    static uint8_t body_r2[SLOT_UNITS * KV_SLOT_UNIT];
    static uint8_t body_keep[SLOT_UNITS * KV_SLOT_UNIT];
    static uint8_t body_read[SLOT_UNITS * KV_SLOT_UNIT];
    static kv_slab_entry entries[N_SLOTS];
    static uint8_t scratch[KV_SLOT_UNIT];

    uint8_t ns[32];
    fill_bytes(ns, 32, 0x33);

    kv_slot_header hdr_r1, hdr_r2, hdr_keep;
    size_t slen_r1 = 0, slen_r2 = 0, slen_keep = 0;
    /* R1: 3 payload units (payload_len = 9000), incarnation 1, in slot 0. */
    build_test_slot(0u, 1u, ns, 0x41, 9000u, 0xa5, &hdr_r1, body_r1, sizeof body_r1, &slen_r1);
    /* R2: 2 payload units (payload_len = 5000), incarnation 2, overwrites slot 0. */
    build_test_slot(0u, 2u, ns, 0x42, 5000u, 0x5a, &hdr_r2, body_r2, sizeof body_r2, &slen_r2);
    /* R_keep: 2 payload units (payload_len = 6000), incarnation 5, in slot 2. */
    build_test_slot(2u, 5u, ns, 0x43, 6000u, 0x3c, &hdr_keep, body_keep, sizeof body_keep, &slen_keep);

    for (int bi = 0; bi < 2; bi++) {
        uint32_t bs = bi == 0 ? 512u : 4096u;
        uint32_t bpu = KV_SLOT_UNIT / bs;
        char path[256];
        snprintf(path, sizeof path, "%s/kv_pcut_%u.img", g_out_dir, bs);
        unlink(path);

        disk_file df;
        disk_dev d;
        CHECK_RC(disk_file_open(&df, &d, path, bs, (uint64_t)IMG_UNITS * bpu, 1), 0);

        kv_lba_range anchor = { 0u, 4u * bpu };
        kv_lba_range store  = { 4u * bpu, 8u * bpu };
        kv_disk kd;
        memset(&kd, 0, sizeof kd);
        CHECK_RC(kv_disk_bind(&kd, &d, 12u * bpu, (uint64_t)N_SLOTS * SLOT_UNITS, store, anchor), KV_OK);

        kv_slab slab;
        memset(&slab, 0, sizeof slab);
        CHECK_RC(kv_slab_init(&slab, &kd, N_SLOTS, SLOT_UNITS, ns, entries, scratch), KV_OK);
        CHECK_RC(kv_slab_format(&slab), KV_OK);
        /* Also write R_keep in slot 2 so every cut verifies neighbor slots stay intact. */
        CHECK_RC(kv_slab_write_slot(&slab, 2u, &hdr_keep, body_keep, slen_keep), KV_OK);
        CHECK_RC(file_load_bytes(path, snap_empty, sizeof snap_empty), 0);

        /* Measure blocks written for R1 into empty slot 0:
         * 1 zero-header unit + 3 payload units + 1 header unit = 5 units = 5 * bpu blocks. */
        uint64_t w0 = df.blocks_written;
        CHECK_RC(kv_slab_write_slot(&slab, 0u, &hdr_r1, body_r1, slen_r1), KV_OK);
        uint64_t w_r1 = df.blocks_written - w0;
        uint64_t want_w_r1 = (uint64_t)(1u + hdr_r1.sealed_units + 1u) * bpu;
        CHECK(w_r1 == want_w_r1);
        CHECK_RC(file_load_bytes(path, snap_r1, sizeof snap_r1), 0);
        disk_file_close(&df);
        if (w_r1 != want_w_r1) {
            unlink(path);
            continue;
        }

        /* Sweep A: every block boundary cut = 0..w_r1+1 when writing R1 into empty slot 0. */
        for (uint64_t cut = 0; cut <= w_r1 + 1u; cut++) {
            CHECK_RC(file_save_bytes(path, snap_empty, sizeof snap_empty), 0);
            CHECK_RC(disk_file_open(&df, &d, path, bs, (uint64_t)IMG_UNITS * bpu, 0), 0);
            CHECK_RC(kv_disk_bind(&kd, &d, 12u * bpu, (uint64_t)N_SLOTS * SLOT_UNITS, store, anchor), KV_OK);
            CHECK_RC(kv_slab_init(&slab, &kd, N_SLOTS, SLOT_UNITS, ns, entries, scratch), KV_OK);
            CHECK_RC(kv_slab_recover(&slab), KV_OK);

            disk_file_arm_cut(&df, cut);
            int wrc = kv_slab_write_slot(&slab, 0u, &hdr_r1, body_r1, slen_r1);
            disk_file_disarm(&df);

            if (cut <= w_r1) {
                CHECK_RC(wrc, KV_E_IO);
            } else {
                CHECK_RC(wrc, KV_OK);
            }

            /* Reboot recovery on the post-cut image. */
            kv_slab rec;
            memset(&rec, 0, sizeof rec);
            CHECK_RC(kv_slab_init(&rec, &kd, N_SLOTS, SLOT_UNITS, ns, entries, scratch), KV_OK);
            CHECK_RC(kv_slab_recover(&rec), KV_OK);

            /* Neighbor slot 2 must always remain valid and readable. */
            uint32_t found_slot = 99u;
            CHECK_RC(kv_slab_lookup(&rec, hdr_keep.rec.chunk.chunk_key, &found_slot), KV_OK);
            CHECK(found_slot == 2u);

            if (cut < w_r1) {
                /* Before the final block of the header unit lands, slot 0 is empty. */
                CHECK(rec.entries != NULL && rec.entries[0].valid == 0u);
                CHECK(rec.valid_slots == 1u);
                CHECK_RC(kv_slab_lookup(&rec, hdr_r1.rec.chunk.chunk_key, &found_slot), KV_E_EMPTY_SLOT);
            } else {
                /* At cut == w_r1, R1 is complete and verified. */
                CHECK(rec.entries != NULL && rec.entries[0].valid == 1u);
                CHECK(rec.valid_slots == 2u);
                CHECK_RC(kv_slab_lookup(&rec, hdr_r1.rec.chunk.chunk_key, &found_slot), KV_OK);
                CHECK(found_slot == 0u);
                kv_slot_header got_hdr;
                size_t got_len = 0;
                CHECK_RC(kv_slab_read_slot(&rec, 0u, &got_hdr, body_read, sizeof body_read, &got_len), KV_OK);
                CHECK(got_len == slen_r1);
                CHECK_MEM(body_read, body_r1, slen_r1);
            }
            disk_file_close(&df);
        }

        /* Sweep B: overwriting valid R1 in slot 0 with R2 across every block boundary. */
        uint64_t w_r2 = (uint64_t)(1u + hdr_r2.sealed_units + 1u) * bpu;
        for (uint64_t cut = 0; cut <= w_r2 + 1u; cut++) {
            CHECK_RC(file_save_bytes(path, snap_r1, sizeof snap_r1), 0);
            CHECK_RC(disk_file_open(&df, &d, path, bs, (uint64_t)IMG_UNITS * bpu, 0), 0);
            CHECK_RC(kv_disk_bind(&kd, &d, 12u * bpu, (uint64_t)N_SLOTS * SLOT_UNITS, store, anchor), KV_OK);
            CHECK_RC(kv_slab_init(&slab, &kd, N_SLOTS, SLOT_UNITS, ns, entries, scratch), KV_OK);
            CHECK_RC(kv_slab_recover(&slab), KV_OK);

            disk_file_arm_cut(&df, cut);
            int wrc = kv_slab_write_slot(&slab, 0u, &hdr_r2, body_r2, slen_r2);
            disk_file_disarm(&df);

            if (cut <= w_r2) {
                CHECK_RC(wrc, KV_E_IO);
            } else {
                CHECK_RC(wrc, KV_OK);
            }

            kv_slab rec;
            memset(&rec, 0, sizeof rec);
            CHECK_RC(kv_slab_init(&rec, &kd, N_SLOTS, SLOT_UNITS, ns, entries, scratch), KV_OK);
            CHECK_RC(kv_slab_recover(&rec), KV_OK);

            /* Neighbor slot 2 is untouched at every cut. */
            uint32_t found_slot = 99u;
            CHECK_RC(kv_slab_lookup(&rec, hdr_keep.rec.chunk.chunk_key, &found_slot), KV_OK);
            CHECK(found_slot == 2u);

            if (cut == 0u) {
                /* Cut before the first block of ZERO_HDR: R1 is still whole. */
                CHECK(rec.entries != NULL && rec.entries[0].valid == 1u);
                CHECK(rec.entries != NULL && rec.entries[0].hdr.slot_incarnation == 1u);
                kv_slot_header got_hdr;
                size_t got_len = 0;
                CHECK_RC(kv_slab_read_slot(&rec, 0u, &got_hdr, body_read, sizeof body_read, &got_len), KV_OK);
                CHECK(got_len == slen_r1);
                CHECK_MEM(body_read, body_r1, slen_r1);
            } else if (cut < w_r2) {
                /* Cut during ZERO_HDR, after ZERO_HDR during WRITE_PAYLOAD, or during
                 * a torn WRITE_HDR: slot 0 is provably empty (never R1+R2 mix). */
                CHECK(rec.entries != NULL && rec.entries[0].valid == 0u);
                CHECK(rec.valid_slots == 1u);
                CHECK_RC(kv_slab_lookup(&rec, hdr_r1.rec.chunk.chunk_key, &found_slot), KV_E_EMPTY_SLOT);
                CHECK_RC(kv_slab_lookup(&rec, hdr_r2.rec.chunk.chunk_key, &found_slot), KV_E_EMPTY_SLOT);
            } else {
                /* Cut after all blocks of R2's header landed: R2 is whole. */
                CHECK(rec.entries != NULL && rec.entries[0].valid == 1u);
                CHECK(rec.entries != NULL && rec.entries[0].hdr.slot_incarnation == 2u);
                kv_slot_header got_hdr;
                size_t got_len = 0;
                CHECK_RC(kv_slab_read_slot(&rec, 0u, &got_hdr, body_read, sizeof body_read, &got_len), KV_OK);
                CHECK(got_len == slen_r2);
                CHECK_MEM(body_read, body_r2, slen_r2);
            }
            disk_file_close(&df);
        }
        unlink(path);
    }
}

/* ======================================================================== */
/* 4. torn_header_is_empty_slot                                              */
/* ======================================================================== */
static void test_torn_header_is_empty_slot(void)
{
    enum { N_SLOTS = 6, SLOT_UNITS = 3 };
    static uint8_t body[SLOT_UNITS * KV_SLOT_UNIT];
    static kv_slab_entry entries[N_SLOTS];
    static uint8_t scratch[KV_SLOT_UNIT];
    static uint8_t hdr_bytes[KV_SLOT_UNIT];
    static uint8_t torn_bytes[KV_SLOT_UNIT];

    uint8_t ns[32];
    fill_bytes(ns, 32, 0x55);

    char path[256];
    snprintf(path, sizeof path, "%s/kv_torn.img", g_out_dir);
    unlink(path);

    disk_file df;
    disk_dev d;
    uint32_t bs = 512u, bpu = 8u;
    uint64_t total_u = 4u + 8u + (uint64_t)N_SLOTS * SLOT_UNITS;
    CHECK_RC(disk_file_open(&df, &d, path, bs, total_u * bpu, 1), 0);

    kv_lba_range anchor = { 0u, 4u * bpu };
    kv_lba_range store  = { 4u * bpu, 8u * bpu };
    kv_disk kd;
    memset(&kd, 0, sizeof kd);
    CHECK_RC(kv_disk_bind(&kd, &d, 12u * bpu, (uint64_t)N_SLOTS * SLOT_UNITS, store, anchor), KV_OK);

    kv_slab slab;
    memset(&slab, 0, sizeof slab);
    CHECK_RC(kv_slab_init(&slab, &kd, N_SLOTS, SLOT_UNITS, ns, entries, scratch), KV_OK);
    CHECK_RC(kv_slab_format(&slab), KV_OK);

    /* Write a valid control record into slot 5 and a target record into slot 1. */
    kv_slot_header hdr_ctrl, hdr_target;
    size_t slen = 0;
    build_test_slot(5u, 7u, ns, 0x60, 4080u, 0x12, &hdr_ctrl, body, sizeof body, &slen);
    CHECK_RC(kv_slab_write_slot(&slab, 5u, &hdr_ctrl, body, slen), KV_OK);

    build_test_slot(1u, 8u, ns, 0x61, 4080u, 0x34, &hdr_target, body, sizeof body, &slen);
    CHECK_RC(kv_slab_write_slot(&slab, 1u, &hdr_target, body, slen), KV_OK);
    CHECK_RC(kv_disk_read_units(&kd, 1u * SLOT_UNITS, 1u, hdr_bytes), KV_OK);

    /* Case A: 512-byte sector-torn headers (1..7 sectors of hdr_bytes, rest zeros). */
    for (uint32_t k = 1; k <= 7; k++) {
        memset(torn_bytes, 0, sizeof torn_bytes);
        memcpy(torn_bytes, hdr_bytes, (size_t)k * 512u);
        CHECK_RC(kv_disk_write_units(&kd, 1u * SLOT_UNITS, 1u, torn_bytes), KV_OK);

        CHECK_RC(kv_slab_recover(&slab), KV_OK);
        CHECK(slab.entries != NULL && slab.entries[1].valid == 0u);
        CHECK(slab.entries != NULL && slab.entries[5].valid == 1u);
        CHECK(slab.valid_slots == 1u);
    }

    /* Case B: bit flip in unit_sha256, record header, envelope header, or zero region. */
    size_t flip_offsets[4] = { 0u, 260u, 350u, 4095u };
    for (int i = 0; i < 4; i++) {
        memcpy(torn_bytes, hdr_bytes, sizeof torn_bytes);
        torn_bytes[flip_offsets[i]] ^= 0x01u;
        CHECK_RC(kv_disk_write_units(&kd, 1u * SLOT_UNITS, 1u, torn_bytes), KV_OK);

        CHECK_RC(kv_slab_recover(&slab), KV_OK);
        CHECK(slab.entries != NULL && slab.entries[1].valid == 0u);
        CHECK(slab.entries != NULL && slab.entries[5].valid == 1u);
        CHECK(slab.valid_slots == 1u);
    }

    /* Case C: valid slot 5 header copied into slot 1's header LBA (slot_index mismatch). */
    uint8_t slot5_hdr[KV_SLOT_UNIT];
    CHECK_RC(kv_disk_read_units(&kd, 5u * SLOT_UNITS, 1u, slot5_hdr), KV_OK);
    CHECK_RC(kv_disk_write_units(&kd, 1u * SLOT_UNITS, 1u, slot5_hdr), KV_OK);
    CHECK_RC(kv_slab_recover(&slab), KV_OK);
    CHECK(slab.entries != NULL && slab.entries[1].valid == 0u);
    CHECK(slab.entries != NULL && slab.entries[5].valid == 1u);

    /* Case D: valid slot header whose sealed_units (3) exceeds slab.slot_units - 1 (2). */
    kv_slot_header hdr_oversize;
    build_test_slot(1u, 9u, ns, 0x62, 10000u, 0x56, &hdr_oversize, body, sizeof body, &slen);
    CHECK(hdr_oversize.sealed_units == 3u); /* > SLOT_UNITS - 1 (2) */
    CHECK_RC(kv_slot_encode(&hdr_oversize, torn_bytes), KV_OK);
    CHECK_RC(kv_disk_write_units(&kd, 1u * SLOT_UNITS, 1u, torn_bytes), KV_OK);
    CHECK_RC(kv_slab_recover(&slab), KV_OK);
    CHECK(slab.entries != NULL && slab.entries[1].valid == 0u);
    CHECK(slab.entries != NULL && slab.entries[5].valid == 1u);
    CHECK(slab.valid_slots == 1u);

    disk_file_close(&df);
    unlink(path);
}

/* ======================================================================== */
/* 5. used_bytes_counts_foreign_namespace_slots                              */
/* ======================================================================== */
static void test_used_bytes_counts_foreign_namespace_slots(void)
{
    enum { N_SLOTS = 6, SLOT_UNITS = 4 };
    static uint8_t body[SLOT_UNITS * KV_SLOT_UNIT];
    static kv_slab_entry entries[N_SLOTS];
    static uint8_t scratch[KV_SLOT_UNIT];

    uint8_t ns_local[32], ns_foreign[32];
    fill_bytes(ns_local, 32, 0xaa);
    fill_bytes(ns_foreign, 32, 0xbb);

    char path[256];
    snprintf(path, sizeof path, "%s/kv_foreign_ns.img", g_out_dir);
    unlink(path);

    disk_file df;
    disk_dev d;
    uint32_t bs = 4096u, bpu = 1u;
    uint64_t total_u = 4u + 8u + (uint64_t)N_SLOTS * SLOT_UNITS;
    CHECK_RC(disk_file_open(&df, &d, path, bs, total_u * bpu, 1), 0);

    kv_lba_range anchor = { 0u, 4u * bpu };
    kv_lba_range store  = { 4u * bpu, 8u * bpu };
    kv_disk kd;
    memset(&kd, 0, sizeof kd);
    CHECK_RC(kv_disk_bind(&kd, &d, 12u * bpu, (uint64_t)N_SLOTS * SLOT_UNITS, store, anchor), KV_OK);

    kv_slab slab;
    memset(&slab, 0, sizeof slab);
    CHECK_RC(kv_slab_init(&slab, &kd, N_SLOTS, SLOT_UNITS, ns_local, entries, scratch), KV_OK);
    CHECK_RC(kv_slab_format(&slab), KV_OK);

    /* Write 2 local-namespace slots (slots 0, 2) and 2 foreign-namespace slots (slots 1, 3). */
    kv_slot_header h0, h1, h2, h3;
    size_t slen = 0;
    build_test_slot(0u, 10u, ns_local,   0x70, 4080u, 0x01, &h0, body, sizeof body, &slen);
    CHECK_RC(kv_slab_write_slot(&slab, 0u, &h0, body, slen), KV_OK);
    build_test_slot(1u, 15u, ns_foreign, 0x71, 8000u, 0x02, &h1, body, sizeof body, &slen);
    CHECK_RC(kv_slab_write_slot(&slab, 1u, &h1, body, slen), KV_OK);
    build_test_slot(2u, 12u, ns_local,   0x72, 5000u, 0x03, &h2, body, sizeof body, &slen);
    CHECK_RC(kv_slab_write_slot(&slab, 2u, &h2, body, slen), KV_OK);
    build_test_slot(3u, 25u, ns_foreign, 0x73, 9000u, 0x04, &h3, body, sizeof body, &slen);
    CHECK_RC(kv_slab_write_slot(&slab, 3u, &h3, body, slen), KV_OK);

    uint64_t want_phys = 4ULL * SLOT_UNITS * KV_SLOT_UNIT;
    uint64_t want_pay  = 4080ULL + 8000ULL + 5000ULL + 9000ULL;
    CHECK(slab.valid_slots == 4u);
    CHECK(slab.foreign_slots == 2u);
    CHECK(slab.empty_slots == 2u);
    CHECK(slab.used_bytes == want_phys);
    CHECK(slab.payload_bytes == want_pay);
    CHECK(slab.next_incarnation == 26u);

    /* Reopen and recover under ns_local: used_bytes must count all 4 valid slots
     * (ADR 4.2: "used_bytes counts slot_units * 4096 physical bytes for every
     * valid slot regardless of namespace"), while lookup serves only ns_local. */
    kv_slab rec;
    memset(&rec, 0, sizeof rec);
    CHECK_RC(kv_slab_init(&rec, &kd, N_SLOTS, SLOT_UNITS, ns_local, entries, scratch), KV_OK);
    CHECK_RC(kv_slab_recover(&rec), KV_OK);

    CHECK(rec.valid_slots == 4u);
    CHECK(rec.foreign_slots == 2u);
    CHECK(rec.empty_slots == 2u);
    CHECK(rec.used_bytes == want_phys);
    CHECK(rec.payload_bytes == want_pay);
    CHECK(rec.next_incarnation == 26u);
    CHECK(rec.entries != NULL && rec.entries[0].valid == 1u && rec.entries[0].foreign_namespace == 0u);
    CHECK(rec.entries != NULL && rec.entries[1].valid == 1u && rec.entries[1].foreign_namespace == 1u);
    CHECK(rec.entries != NULL && rec.entries[2].valid == 1u && rec.entries[2].foreign_namespace == 0u);
    CHECK(rec.entries != NULL && rec.entries[3].valid == 1u && rec.entries[3].foreign_namespace == 1u);

    uint32_t slot = 99u;
    CHECK_RC(kv_slab_lookup(&rec, h0.rec.chunk.chunk_key, &slot), KV_OK);
    CHECK(slot == 0u);
    CHECK_RC(kv_slab_lookup(&rec, h2.rec.chunk.chunk_key, &slot), KV_OK);
    CHECK(slot == 2u);
    /* Foreign-namespace keys and all-zero keys in empty slots are never returned by lookup. */
    uint8_t zero_key[32];
    memset(zero_key, 0, sizeof zero_key);
    CHECK_RC(kv_slab_lookup(&rec, zero_key, &slot), KV_E_EMPTY_SLOT);
    CHECK_RC(kv_slab_lookup(&rec, h1.rec.chunk.chunk_key, &slot), KV_E_EMPTY_SLOT);
    CHECK_RC(kv_slab_lookup(&rec, h3.rec.chunk.chunk_key, &slot), KV_E_EMPTY_SLOT);

    disk_file_close(&df);
    unlink(path);
}

/* ======================================================================== */
/* 6. slot_write_stage_progression_and_cancel_rules                          */
/* ======================================================================== */
static void test_slot_write_stage_progression_and_cancel_rules(void)
{
    enum { N_SLOTS = 4, SLOT_UNITS = 4 };
    static uint8_t body[SLOT_UNITS * KV_SLOT_UNIT];
    static kv_slab_entry entries[N_SLOTS];
    static uint8_t scratch[KV_SLOT_UNIT];

    uint8_t ns[32];
    fill_bytes(ns, 32, 0xc1);

    char path[256];
    snprintf(path, sizeof path, "%s/kv_stages.img", g_out_dir);
    unlink(path);

    disk_file df;
    disk_dev raw_d, d;
    spy_disk spy;
    CHECK_RC(disk_file_open(&df, &raw_d, path, 4096u, 32u, 1), 0);
    /* Cap max_blocks_per_io to 1 unit (4096 bytes) so each payload unit takes 1 step. */
    raw_d.max_blocks_per_io = 1u;
    spy_wrap(&spy, &raw_d, &d);

    kv_lba_range anchor = { 0u, 4u };
    kv_lba_range store  = { 4u, 12u };
    kv_disk kd;
    memset(&kd, 0, sizeof kd);
    CHECK_RC(kv_disk_bind(&kd, &d, 16u, (uint64_t)N_SLOTS * SLOT_UNITS, store, anchor), KV_OK);

    kv_slab slab;
    memset(&slab, 0, sizeof slab);
    CHECK_RC(kv_slab_init(&slab, &kd, N_SLOTS, SLOT_UNITS, ns, entries, scratch), KV_OK);
    CHECK_RC(kv_slab_format(&slab), KV_OK);

    kv_slot_header hdr;
    size_t slen = 0;
    /* 2 payload units (payload_len = 5000). */
    build_test_slot(1u, 1u, ns, 0x80, 5000u, 0x99, &hdr, body, sizeof body, &slen);
    CHECK(hdr.sealed_units == 2u);

    spy_reset_counts(&spy);
    kv_slot_writer w;
    memset(&w, 0, sizeof w);
    CHECK_RC(kv_slot_write_begin(&w, &slab, 1u, &hdr, body, slen), KV_OK);
    CHECK(w.stage == KV_STAGE_SUBMITTED);
    CHECK(w.phase == KV_SLOT_PHASE_ZERO_HDR);
    CHECK(spy.write_calls == 0u && spy.flush_calls == 0u);

    /* Step 1: zero header unit write -> still Submitted. */
    CHECK_RC(kv_slot_write_step(&w), KV_OK);
    CHECK(w.stage == KV_STAGE_SUBMITTED);
    CHECK(w.phase == KV_SLOT_PHASE_FLUSH_ZERO);
    CHECK(spy.write_calls == 1u && spy.flush_calls == 0u);

    /* Step 2: flush after zero header -> still Submitted. */
    CHECK_RC(kv_slot_write_step(&w), KV_OK);
    CHECK(w.stage == KV_STAGE_SUBMITTED);
    CHECK(w.phase == KV_SLOT_PHASE_WRITE_PAYLOAD);
    CHECK(spy.write_calls == 1u && spy.flush_calls == 1u);

    /* Step 3: payload unit 1 write -> still Submitted. */
    CHECK_RC(kv_slot_write_step(&w), KV_OK);
    CHECK(w.stage == KV_STAGE_SUBMITTED);
    CHECK(w.phase == KV_SLOT_PHASE_WRITE_PAYLOAD);
    CHECK(spy.write_calls == 2u && spy.flush_calls == 1u);

    /* Step 4: payload unit 2 write -> still Submitted (not Completed until flush). */
    CHECK_RC(kv_slot_write_step(&w), KV_OK);
    CHECK(w.stage == KV_STAGE_SUBMITTED);
    CHECK(w.phase == KV_SLOT_PHASE_FLUSH_PAYLOAD);
    CHECK(spy.write_calls == 3u && spy.flush_calls == 1u);

    /* Step 5: flush after payload -> reaches KV_STAGE_COMPLETED; still invisible to lookup. */
    uint32_t found = 99u;
    CHECK_RC(kv_slot_write_step(&w), KV_OK);
    CHECK(w.stage == KV_STAGE_COMPLETED);
    CHECK(w.phase == KV_SLOT_PHASE_WRITE_HDR);
    CHECK(spy.write_calls == 3u && spy.flush_calls == 2u);
    CHECK_RC(kv_slab_lookup(&slab, hdr.rec.chunk.chunk_key, &found), KV_E_EMPTY_SLOT);

    /* Step 6: write slot header -> reaches KV_STAGE_PUBLISHED; now visible to lookup;
     * too late to cancel. */
    CHECK_RC(kv_slot_write_step(&w), KV_OK);
    CHECK(w.stage == KV_STAGE_PUBLISHED);
    CHECK(w.phase == KV_SLOT_PHASE_FLUSH_HDR);
    CHECK(spy.write_calls == 4u && spy.flush_calls == 2u);
    CHECK_RC(kv_slab_lookup(&slab, hdr.rec.chunk.chunk_key, &found), KV_OK);
    CHECK(found == 1u);
    CHECK_RC(kv_slot_write_cancel(&w), KV_E_LATE_CANCEL);

    /* Step 7: final flush after header -> reaches KV_STAGE_DURABLE and DONE. */
    CHECK_RC(kv_slot_write_step(&w), KV_OK);
    CHECK(w.stage == KV_STAGE_DURABLE);
    CHECK(w.phase == KV_SLOT_PHASE_DONE);
    CHECK(spy.write_calls == 4u && spy.flush_calls == 3u);

    /* Cancel at KV_STAGE_COMPLETED on slot 2 leaves slot 2 empty on disk and in index. */
    kv_slot_header hdr2;
    build_test_slot(2u, 2u, ns, 0x81, 5000u, 0x77, &hdr2, body, sizeof body, &slen);
    CHECK_RC(kv_slot_write_begin(&w, &slab, 2u, &hdr2, body, slen), KV_OK);
    for (int step_i = 0; step_i < 16 && w.stage != KV_STAGE_COMPLETED; step_i++) {
        int s_rc = kv_slot_write_step(&w);
        CHECK_RC(s_rc, KV_OK);
        if (s_rc != KV_OK) break;
    }
    CHECK_RC(kv_slot_write_cancel(&w), KV_OK);
    CHECK(w.phase == KV_SLOT_PHASE_CANCELLED);
    CHECK_RC(kv_slab_lookup(&slab, hdr2.rec.chunk.chunk_key, &found), KV_E_EMPTY_SLOT);
    CHECK_RC(kv_slab_recover(&slab), KV_OK);
    CHECK(slab.entries != NULL && slab.entries[2].valid == 0u);
    CHECK(slab.entries != NULL && slab.entries[1].valid == 1u);

    disk_file_close(&df);
    unlink(path);
}

/* ======================================================================== */
/* 7. last_payload_unit_nonzero_padding_refused                              */
/* ======================================================================== */
static void test_last_payload_unit_nonzero_padding_refused(void)
{
    enum { N_SLOTS = 2, SLOT_UNITS = 4 };
    static uint8_t body[SLOT_UNITS * KV_SLOT_UNIT];
    static uint8_t read_buf[SLOT_UNITS * KV_SLOT_UNIT];
    static kv_slab_entry entries[N_SLOTS];
    static uint8_t scratch[KV_SLOT_UNIT];

    uint8_t ns[32];
    fill_bytes(ns, 32, 0xd2);

    char path[256];
    snprintf(path, sizeof path, "%s/kv_tailpad.img", g_out_dir);
    unlink(path);

    disk_file df;
    disk_dev d;
    CHECK_RC(disk_file_open(&df, &d, path, 4096u, 24u, 1), 0);

    kv_lba_range anchor = { 0u, 4u };
    kv_lba_range store  = { 4u, 8u };
    kv_disk kd;
    memset(&kd, 0, sizeof kd);
    CHECK_RC(kv_disk_bind(&kd, &d, 12u, (uint64_t)N_SLOTS * SLOT_UNITS, store, anchor), KV_OK);

    kv_slab slab;
    memset(&slab, 0, sizeof slab);
    CHECK_RC(kv_slab_init(&slab, &kd, N_SLOTS, SLOT_UNITS, ns, entries, scratch), KV_OK);
    CHECK_RC(kv_slab_format(&slab), KV_OK);

    kv_slot_header hdr, got_hdr;
    size_t slen = 0, got_len = 0;
    /* payload_len = 5000 -> sealed_len = 5032 (unit 1 = 4096B, unit 2 = 936B + 3160B zero pad). */
    build_test_slot(0u, 1u, ns, 0x90, 5000u, 0x44, &hdr, body, sizeof body, &slen);
    CHECK_RC(kv_slab_write_slot(&slab, 0u, &hdr, body, slen), KV_OK);
    CHECK_RC(kv_slab_read_slot(&slab, 0u, &got_hdr, read_buf, sizeof read_buf, &got_len), KV_OK);
    CHECK(got_len == slen);
    CHECK_MEM(read_buf, body, slen);

    /* Corrupt 1 byte in the trailing zero padding of the last payload unit (unit 2 of slot 0). */
    uint8_t last_unit[KV_SLOT_UNIT];
    CHECK_RC(kv_disk_read_units(&kd, 2u, 1u, last_unit), KV_OK);
    last_unit[KV_SLOT_UNIT - 1u] = 0x01u;
    CHECK_RC(kv_disk_write_units(&kd, 2u, 1u, last_unit), KV_OK);

    CHECK_RC(kv_slab_read_slot(&slab, 0u, &got_hdr, read_buf, sizeof read_buf, &got_len), KV_E_SLOT_PADDING);

    disk_file_close(&df);
    unlink(path);
}

/* ======================================================================== */
/* 8. io_and_flush_failures_fail_stop_slab                                   */
/* ======================================================================== */
static void test_io_and_flush_failures_fail_stop_slab(void)
{
    enum { N_SLOTS = 2, SLOT_UNITS = 3 };
    static uint8_t body[SLOT_UNITS * KV_SLOT_UNIT];
    static kv_slab_entry entries[N_SLOTS];
    static uint8_t scratch[KV_SLOT_UNIT];

    uint8_t ns[32];
    fill_bytes(ns, 32, 0xe3);

    char path[256];
    snprintf(path, sizeof path, "%s/kv_failstop.img", g_out_dir);
    unlink(path);

    disk_file df;
    disk_dev raw_d, d;
    spy_disk spy;
    CHECK_RC(disk_file_open(&df, &raw_d, path, 4096u, 24u, 1), 0);
    spy_wrap(&spy, &raw_d, &d);

    kv_lba_range anchor = { 0u, 4u };
    kv_lba_range store  = { 4u, 8u };
    kv_disk kd;
    memset(&kd, 0, sizeof kd);
    CHECK_RC(kv_disk_bind(&kd, &d, 12u, (uint64_t)N_SLOTS * SLOT_UNITS, store, anchor), KV_OK);

    kv_slab slab;
    memset(&slab, 0, sizeof slab);
    CHECK_RC(kv_slab_init(&slab, &kd, N_SLOTS, SLOT_UNITS, ns, entries, scratch), KV_OK);
    CHECK_RC(kv_slab_format(&slab), KV_OK);

    kv_slot_header hdr;
    size_t slen = 0;
    build_test_slot(0u, 1u, ns, 0xa0, 4080u, 0x55, &hdr, body, sizeof body, &slen);

    /* Fail each of the 3 flushes in turn (flush 0 = after zero header,
     * flush 1 = after payload, flush 2 = after final header). */
    for (int f_idx = 0; f_idx < 3; f_idx++) {
        CHECK_RC(kv_slab_format(&slab), KV_OK);
        spy_reset_counts(&spy);
        spy.fail_flush_call = f_idx;

        CHECK_RC(kv_slab_write_slot(&slab, 0u, &hdr, body, slen), KV_E_IO);
        CHECK(slab.fail_stop == 1u);

        spy.fail_flush_call = -1;
        /* Subsequent writes are refused at begin while fail_stop is active until recover/format. */
        kv_slot_writer w_fs;
        CHECK_RC(kv_slot_write_begin(&w_fs, &slab, 0u, &hdr, body, slen), KV_E_IO);
        CHECK_RC(kv_slab_write_slot(&slab, 0u, &hdr, body, slen), KV_E_IO);

        CHECK_RC(kv_slab_recover(&slab), KV_OK);
        CHECK(slab.fail_stop == 0u);
        if (f_idx < 2) {
            /* Flush failed before header write: slot 0 is still empty on disk. */
            CHECK(slab.entries != NULL && slab.entries[0].valid == 0u);
        } else {
            /* Flush failed after header write landed: header is on disk. */
            CHECK(slab.entries != NULL && slab.entries[0].valid == 1u);
        }
    }

    disk_file_close(&df);
    unlink(path);
}

/* ======================================================================== */
/* 9. n2_existing_store_gates_pass_with_slab_present (D3)                    */
/* ======================================================================== */
static void test_n2_existing_store_gates_pass_with_slab_present(void)
{
    enum { ANCHOR_U = 4, STORE_U = 64, SLAB_SLOTS = 4, SLAB_SLOT_U = 4 };
    enum { SLAB_U = SLAB_SLOTS * SLAB_SLOT_U };
    enum { TOTAL_U = ANCHOR_U + STORE_U + SLAB_U };
    static ss_workspace ws;
    static ss_store ss;
    static uint8_t store_snap[(ANCHOR_U + STORE_U) * KV_SLOT_UNIT];
    static uint8_t full_img[TOTAL_U * KV_SLOT_UNIT];
    static uint8_t body[SLAB_SLOT_U * KV_SLOT_UNIT];
    static kv_slab_entry entries[SLAB_SLOTS];
    static uint8_t scratch[KV_SLOT_UNIT];

    static const uint8_t uuid[16] = {
        0x5e, 0xa1, 0xed, 0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc
    };

    uint8_t kvol[32];
    memset(kvol, 0x42, 32);
    m5_subkeys sk;
    m5_derive_subkeys(kvol, M5_ID_TEST, 0, &sk);
    ss_keys keys;
    memset(&keys, 0, sizeof keys);
    keys.identity_class = M5_ID_TEST;
    keys.key_generation = 1;
    memcpy(keys.k_root_auth, sk.k_root_auth, 32);
    memcpy(keys.k_domain, sk.k_artifact, 32);
    m5_subkeys_wipe(&sk);

    uint8_t ns[32];
    fill_bytes(ns, 32, 0xf0);

    for (int bi = 0; bi < 2; bi++) {
        uint32_t bs = bi == 0 ? 512u : 4096u;
        uint32_t bpu = KV_SLOT_UNIT / bs;
        char path[256];
        snprintf(path, sizeof path, "%s/kv_d3_coexist_%u.img", g_out_dir, bs);
        unlink(path);

        disk_file df;
        disk_dev d;
        CHECK_RC(disk_file_open(&df, &d, path, bs, (uint64_t)TOTAL_U * bpu, 1), 0);

        /* Bind Store and Anchor on [0, 68) units. */
        st_disk sd;
        st_dev sdev;
        ts_device tdev;
        CHECK_RC(st_disk_bind(&sd, &d, (uint64_t)ANCHOR_U * bpu, STORE_U, &sdev), 0);
        ss_ts_device(&d, &tdev);

        /* Format Sealed Store, mount it, and commit a transaction. */
        CHECK_RC(ss_format(&sdev, &tdev, 0u, uuid, &keys, &ws), 0);
        memset(&ss, 0, sizeof ss);
        CHECK_RC(ss_open(&ss, &sdev, &tdev, 0u, &keys, &ws), 0);
        CHECK(ss.rb == SS_RB_VALID_RESUME);

        const uint8_t payload1[] = "state-record-chain-head-v1";
        ss_object obj1 = { 0x0501u, 1u, payload1, sizeof payload1 };
        uint8_t sid1[1][32];
        CHECK_RC(ss_transact(&ss, &obj1, 1u, NULL, NULL, sid1), 0);
        CHECK(ss_generation(&ss) == 2u);

        /* Snapshot Anchor + Store bytes before any KV slab operation. */
        CHECK_RC(file_load_bytes(path, full_img, sizeof full_img), 0);
        memcpy(store_snap, full_img, sizeof store_snap);

        /* Bind KV slab at the tail [68, 84) units, passing Store and Anchor ranges. */
        kv_lba_range anchor_r = { 0u, (uint64_t)ANCHOR_U * bpu };
        kv_lba_range store_r  = { (uint64_t)ANCHOR_U * bpu, (uint64_t)STORE_U * bpu };
        kv_disk kd;
        memset(&kd, 0, sizeof kd);
        CHECK_RC(kv_disk_bind(&kd, &d, (uint64_t)(ANCHOR_U + STORE_U) * bpu, SLAB_U, store_r, anchor_r), KV_OK);

        kv_slab slab;
        memset(&slab, 0, sizeof slab);
        CHECK_RC(kv_slab_init(&slab, &kd, SLAB_SLOTS, SLAB_SLOT_U, ns, entries, scratch), KV_OK);
        CHECK_RC(kv_slab_format(&slab), KV_OK);

        /* Write all slots, overwrite slot 0, inject a mid-slot power cut, recover, and reformat. */
        for (uint32_t s = 0; s < SLAB_SLOTS; s++) {
            kv_slot_header hdr;
            size_t slen = 0;
            build_test_slot(s, (uint64_t)(s + 1), ns, (uint8_t)(0xb0 + s), 8000u, (uint8_t)(0x10 + s),
                            &hdr, body, sizeof body, &slen);
            CHECK_RC(kv_slab_write_slot(&slab, s, &hdr, body, slen), KV_OK);
        }
        kv_slot_header hdr_ow;
        size_t slen_ow = 0;
        build_test_slot(0u, 99u, ns, 0xbf, 8000u, 0xee, &hdr_ow, body, sizeof body, &slen_ow);
        disk_file_arm_cut(&df, 2u * bpu);
        CHECK_RC(kv_slab_write_slot(&slab, 0u, &hdr_ow, body, slen_ow), KV_E_IO);
        disk_file_disarm(&df);
        CHECK_RC(kv_slab_recover(&slab), KV_OK);
        CHECK(slab.valid_slots == (uint32_t)(SLAB_SLOTS - 1));
        CHECK_RC(kv_slab_format(&slab), KV_OK);

        /* Verify every byte of the Anchor + Store region is untouched. */
        CHECK_RC(file_load_bytes(path, full_img, sizeof full_img), 0);
        CHECK_MEM(full_img, store_snap, sizeof store_snap);

        /* Reopen the Sealed Store, read back the committed object, and commit generation 3. */
        memset(&ss, 0, sizeof ss);
        CHECK_RC(ss_open(&ss, &sdev, &tdev, 0u, &keys, &ws), 0);
        CHECK(ss.rb == SS_RB_VALID_RESUME);
        CHECK(ss_generation(&ss) == 2u);

        uint8_t read_obj[64];
        size_t read_len = 0;
        uint16_t read_kind = 0;
        CHECK_RC(ss_read(&ss, sid1[0], read_obj, sizeof read_obj, &read_len, &read_kind), 0);
        CHECK(read_len == sizeof payload1 && read_kind == 0x0501u);
        CHECK_MEM(read_obj, payload1, sizeof payload1);

        const uint8_t payload2[] = "state-record-chain-head-v2";
        ss_object obj2 = { 0x0501u, 1u, payload2, sizeof payload2 };
        CHECK_RC(ss_transact(&ss, &obj2, 1u, NULL, NULL, NULL), 0);
        CHECK(ss_generation(&ss) == 3u);

        disk_file_close(&df);
        unlink(path);
    }
}

/* ---- test table -------------------------------------------------------- */
struct test_entry {
    const char *name;
    void (*fn)(void);
};

static const struct test_entry TESTS[] = {
    { "bind_refuses_overlap_with_store_and_anchor", test_bind_refuses_overlap_with_store_and_anchor },
    { "recover_reads_exactly_n_header_units", test_recover_reads_exactly_n_header_units },
    { "power_cut_at_every_unit_boundary_never_exposes_partial_record", test_power_cut_at_every_unit_boundary_never_exposes_partial_record },
    { "torn_header_is_empty_slot", test_torn_header_is_empty_slot },
    { "used_bytes_counts_foreign_namespace_slots", test_used_bytes_counts_foreign_namespace_slots },
    { "slot_write_stage_progression_and_cancel_rules", test_slot_write_stage_progression_and_cancel_rules },
    { "last_payload_unit_nonzero_padding_refused", test_last_payload_unit_nonzero_padding_refused },
    { "io_and_flush_failures_fail_stop_slab", test_io_and_flush_failures_fail_stop_slab },
    { "n2_existing_store_gates_pass_with_slab_present", test_n2_existing_store_gates_pass_with_slab_present },
};

int main(int argc, char **argv)
{
    if (argc > 1 && argv[1][0] != '\0') {
        g_out_dir = argv[1];
    }
    size_t n = sizeof TESTS / sizeof TESTS[0];
    for (size_t i = 0; i < n; i++) {
        g_test = TESTS[i].name;
        int before = g_fails;
        TESTS[i].fn();
        printf("  %-64s %s\n", g_test, g_fails == before ? "ok" : "FAIL");
    }
    printf("kv_slab_test: %zu tests, %d checks, %d failed\n", n, g_checks, g_fails);
    if (g_fails == 0) {
        printf("AIENOS_KV_SLAB_NATIVE: PASS\n");
        return 0;
    }
    printf("AIENOS_KV_SLAB_NATIVE: FAIL\n");
    return 1;
}
