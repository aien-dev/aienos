/* test_smmu.c -- core/smmu.c against a model SMMUv3, and the IORT parser
 * (core/acpi.c) on a crafted table shaped like QEMU virt's with
 * iommu=smmuv3. Ported in spirit from the Rust smmu.rs unit tests: bring-up
 * keeps GBPA.ABORT through SMMUEN, every failure fails closed (CR0 = 0),
 * STE install/abort invalidate the stream, queues wrap, events decode. */
#include <stdint.h>
#include <string.h>
#include "ck_test.h"
#include "acpi.h"
#include "smmu.h"

/* ---- model SMMU ---------------------------------------------------------- */
#define LOGN 256
struct model {
    uint32_t idr0, idr1, cr0, gbpa, cmdq_prod, cmdq_cons, evtq_prod, evtq_cons, strtab_cfg, cr1;
    uint64_t strtab, cmdq_base, evtq_base;
    int gbpa_stuck;      /* UPDATE never clears */
    int abort_ignored;   /* ABORT never latches */
    int ack_stuck_en;    /* CR0ACK never shows SMMUEN */
    int cmdq_stuck;      /* CONS never advances */
    int cmdq_err;        /* CONS reports an error */
    uint32_t wlog_off[LOGN], wlog_val[LOGN];
    int wn;
    uint64_t cmds[64][2];
    int ncmd;
    int barriers;
};
static struct model M;

static uint32_t m_rd(void *ctx, uint32_t off)
{
    struct model *m = ctx;
    switch (off) {
    case CK_SMMU_IDR0: return m->idr0;
    case CK_SMMU_IDR1: return m->idr1;
    case CK_SMMU_CR0ACK: return m->ack_stuck_en ? (m->cr0 & ~CK_SMMU_CR0_SMMUEN) : m->cr0;
    case CK_SMMU_GBPA: return m->gbpa;
    case CK_SMMU_CMDQ_PROD: return m->cmdq_prod;
    case CK_SMMU_CMDQ_CONS: return m->cmdq_cons | (m->cmdq_err ? (1u << 24) : 0);
    case CK_SMMU_EVENTQ_PROD: return m->evtq_prod;
    case CK_SMMU_EVENTQ_CONS: return m->evtq_cons;
    }
    return 0;
}
static void m_consume(struct model *m)
{
    uint32_t n = 1u << (m->cmdq_base & 0x1f);
    uint64_t *q = (uint64_t *)(uintptr_t)(m->cmdq_base & ~0x1full);
    while (m->cmdq_cons != m->cmdq_prod) {
        uint32_t idx = m->cmdq_cons & (n - 1);
        if (m->ncmd < 64) {
            m->cmds[m->ncmd][0] = q[idx * 2];
            m->cmds[m->ncmd][1] = q[idx * 2 + 1];
            m->ncmd++;
        }
        uint32_t wrap = m->cmdq_cons & n;
        idx++;
        if (idx == n) { idx = 0; wrap ^= n; }
        m->cmdq_cons = idx | wrap;
    }
}
static void m_wr(void *ctx, uint32_t off, uint32_t v)
{
    struct model *m = ctx;
    if (m->wn < LOGN) { m->wlog_off[m->wn] = off; m->wlog_val[m->wn] = v; m->wn++; }
    switch (off) {
    case CK_SMMU_CR0: m->cr0 = v; break;
    case CK_SMMU_CR1: m->cr1 = v; break;
    case CK_SMMU_GBPA:
        if (m->gbpa_stuck) { m->gbpa = v; break; }
        m->gbpa = v & ~CK_SMMU_GBPA_UPDATE;
        if (m->abort_ignored) m->gbpa &= ~CK_SMMU_GBPA_ABORT;
        break;
    case CK_SMMU_CMDQ_PROD:
        m->cmdq_prod = v;
        if (!m->cmdq_stuck && !m->cmdq_err) m_consume(m);
        break;
    case CK_SMMU_CMDQ_CONS: m->cmdq_cons = v; break;
    case CK_SMMU_EVENTQ_PROD: m->evtq_prod = v; break;
    case CK_SMMU_EVENTQ_CONS: m->evtq_cons = v; break;
    case CK_SMMU_STRTAB_BASE_CFG: m->strtab_cfg = v; break;
    }
}
static void m_wr64(void *ctx, uint32_t off, uint64_t v)
{
    struct model *m = ctx;
    if (m->wn < LOGN) { m->wlog_off[m->wn] = off; m->wlog_val[m->wn] = (uint32_t)v; m->wn++; }
    if (off == CK_SMMU_CMDQ_BASE) m->cmdq_base = v;
    if (off == CK_SMMU_EVENTQ_BASE) m->evtq_base = v;
    if (off == CK_SMMU_STRTAB_BASE) m->strtab = v;
}
static void m_bar(void *ctx) { ((struct model *)ctx)->barriers++; }
static const struct ck_smmu_regs R = { &M, m_rd, m_wr, m_wr64, m_bar };

#define SIDS 16u
#define QN 16u
static struct {
    uint64_t ste[SIDS * 8] __attribute__((aligned(1024)));
    uint64_t cmd[QN * 2] __attribute__((aligned(256)));
    uint64_t evt[QN * 4] __attribute__((aligned(512)));
} mem;
static struct ck_smmu_tables T;

static void reset(void)
{
    memset(&M, 0, sizeof M);
    memset(&T, 0, sizeof T);
    memset(&mem, 0xee, sizeof mem);
    M.idr0 = CK_SMMU_IDR0_S1P;
    M.idr1 = 16u | (19u << 16) | (19u << 21);
    T.strtab = mem.ste; T.ste_n = SIDS;
    T.cmdq = mem.cmd; T.cmd_n = QN;
    T.evtq = mem.evt; T.evt_n = QN;
}
static int first_write(uint32_t off, uint32_t mask, uint32_t val)
{
    for (int i = 0; i < M.wn; i++)
        if (M.wlog_off[i] == off && (M.wlog_val[i] & mask) == val) return i;
    return -1;
}
static uint32_t last_cr0(void)
{
    uint32_t v = 0xffffffffu;
    for (int i = 0; i < M.wn; i++)
        if (M.wlog_off[i] == CK_SMMU_CR0) v = M.wlog_val[i];
    return v;
}

static void test_layouts(void)
{
    uint64_t s[8], cd[8], c[2];
    ck_smmu_ste_abort(s);
    CHECK(s[0] == 1 && s[1] == 0 && s[7] == 0);
    ck_smmu_ste_stage1(s, 0x40001040ull);
    CHECK(s[0] == (1ull | (5ull << 1) | 0x40001040ull));
    ck_smmu_ste_stage1(s, 0x40001047ull); /* low bits never leak into control bits */
    CHECK((s[0] & 0x3f) == 0xb);
    CHECK(ck_smmu_cd_stage1(cd, 0x80000000ull, 3, 0x4404ff, 16) == 0);
    CHECK((cd[0] & 0x3f) == 16);                 /* T0SZ */
    CHECK(((cd[0] >> 6) & 3) == 0);              /* TG0 4 KiB */
    CHECK(((cd[0] >> 8) & 0x3f) == 0);           /* IRGN0/ORGN0/SH0: Non-cacheable */
    CHECK(((cd[0] >> 14) & 1) == 0);             /* EPD0 clear: TTBR0 walks */
    CHECK((cd[0] >> 30) & 1);                    /* EPD1 */
    CHECK((cd[0] >> 31) & 1);                    /* V */
    CHECK(((cd[0] >> 32) & 7) == 5);             /* IPS 48-bit */
    CHECK((cd[0] >> 41) & 1);                    /* AA64 */
    CHECK(((cd[0] >> 45) & 3) == 3);             /* R and A */
    CHECK((cd[0] >> 48) == 3);                   /* ASID */
    CHECK(cd[1] == 0x80000000ull && cd[2] == 0 && cd[3] == 0x4404ff);
    CHECK(ck_smmu_cd_stage1(cd, 0x80000800ull, 1, 0, 16) == CK_SMMU_EINVAL);
    CHECK(ck_smmu_cd_stage1(cd, 0x80000000ull, 1, 0, 40) == CK_SMMU_EINVAL);
    ck_smmu_cmd(c, CK_SMMU_CMD_CFGI_ALL, 0, 0);
    CHECK(c[0] == 0x04 && c[1] == 31);
    ck_smmu_cmd(c, CK_SMMU_CMD_CFGI_STE, 0x10, 1);
    CHECK(c[0] == (0x03ull | (0x10ull << 32)) && c[1] == 1);
    CHECK(ck_smmu_q_encode(3, 0, 16) == 3 && ck_smmu_q_encode(3, 1, 16) == 0x13 && ck_smmu_q_encode(17, 0, 16) == 1);
}

static void test_tables_check(void)
{
    reset();
    CHECK(ck_smmu_tables_check(&T) == 0);
    struct ck_smmu_tables b = T;
    b.ste_n = 12;
    CHECK(ck_smmu_tables_check(&b) == CK_SMMU_EINVAL);
    b = T;
    b.cmd_n = 1;
    CHECK(ck_smmu_tables_check(&b) == CK_SMMU_EINVAL);
    b = T;
    b.strtab = mem.ste + 8; /* 64-byte aligned, not 1 KiB */
    CHECK(ck_smmu_tables_check(&b) == CK_SMMU_EINVAL);
    b = T;
    b.evtq = 0;
    CHECK(ck_smmu_tables_check(&b) == CK_SMMU_EINVAL);
    reset();
    T.strtab = mem.ste + 8;
    CHECK(ck_smmu_enable(&R, &T, 100) == CK_SMMU_EINVAL);
    CHECK(M.wn == 0); /* nothing touched */
}

static void test_enable_ok(void)
{
    reset();
    CHECK(ck_smmu_enable(&R, &T, 100) == 0);
    int abort_at = first_write(CK_SMMU_GBPA, CK_SMMU_GBPA_ABORT, CK_SMMU_GBPA_ABORT);
    int en_at = first_write(CK_SMMU_CR0, CK_SMMU_CR0_SMMUEN, CK_SMMU_CR0_SMMUEN);
    CHECK(abort_at >= 0 && en_at > abort_at);
    CHECK(M.wlog_off[0] == CK_SMMU_GBPA);       /* abort is the very first write */
    CHECK(M.gbpa & CK_SMMU_GBPA_ABORT);          /* and never cleared */
    CHECK(M.cr0 == (CK_SMMU_CR0_SMMUEN | CK_SMMU_CR0_CMDQEN | CK_SMMU_CR0_EVENTQEN));
    CHECK(M.cr1 == 0);
    CHECK(M.strtab_cfg == 4 && M.strtab == (uint64_t)(uintptr_t)mem.ste);
    CHECK(M.cmdq_base == ((uint64_t)(uintptr_t)mem.cmd | 4) && M.evtq_base == ((uint64_t)(uintptr_t)mem.evt | 4));
    int all_abort = 1;
    for (unsigned i = 0; i < SIDS; i++)
        for (unsigned w = 0; w < 8; w++)
            if (mem.ste[i * 8 + w] != (w == 0 ? 1u : 0u)) all_abort = 0;
    CHECK(all_abort);
    CHECK(M.ncmd == 3 && (M.cmds[0][0] & 0xff) == CK_SMMU_CMD_CFGI_ALL &&
          (M.cmds[1][0] & 0xff) == CK_SMMU_CMD_TLBI_NSNH_ALL && (M.cmds[2][0] & 0xff) == CK_SMMU_CMD_SYNC);
    /* SMMUEN only after the invalidation commands were consumed. */
    CHECK(first_write(CK_SMMU_CMDQ_PROD, 0xffffffffu, 3) < en_at);
    CHECK(M.barriers > 0);
}

static void test_enable_fail_closed(void)
{
    reset();
    M.gbpa = CK_SMMU_GBPA_UPDATE;
    M.gbpa_stuck = 1;
    CHECK(ck_smmu_enable(&R, &T, 50) == CK_SMMU_ETIMEOUT);
    CHECK(first_write(CK_SMMU_CR0, 0, 0) < 0); /* CR0 never touched */

    reset();
    M.abort_ignored = 1;
    CHECK(ck_smmu_enable(&R, &T, 50) == CK_SMMU_ENOABORT);
    CHECK(first_write(CK_SMMU_CR0, 0, 0) < 0);

    reset();
    M.ack_stuck_en = 1;
    CHECK(ck_smmu_enable(&R, &T, 50) == CK_SMMU_ETIMEOUT);
    CHECK(last_cr0() == 0 && (M.gbpa & CK_SMMU_GBPA_ABORT));

    reset();
    M.cmdq_err = 1;
    CHECK(ck_smmu_enable(&R, &T, 50) == CK_SMMU_ECMDQ);
    CHECK(last_cr0() == 0);
    CHECK(first_write(CK_SMMU_CR0, CK_SMMU_CR0_SMMUEN, CK_SMMU_CR0_SMMUEN) < 0);

    reset();
    M.cmdq_stuck = 1;
    CHECK(ck_smmu_enable(&R, &T, 50) == CK_SMMU_ETIMEOUT);
    CHECK(last_cr0() == 0);

    reset();
    M.idr0 = 0; /* no stage 1 */
    CHECK(ck_smmu_enable(&R, &T, 50) == CK_SMMU_EUNSUP);
    CHECK(last_cr0() == 0);

    reset();
    M.idr1 = 3u | (19u << 16) | (19u << 21); /* 8 stream ids < 16 */
    CHECK(ck_smmu_enable(&R, &T, 50) == CK_SMMU_EUNSUP);
    reset();
    M.idr1 = 16u | (19u << 16) | (3u << 21); /* command queue too small */
    CHECK(ck_smmu_enable(&R, &T, 50) == CK_SMMU_EUNSUP);
}

static void test_install_abort(void)
{
    reset();
    CHECK(ck_smmu_enable(&R, &T, 100) == 0);
    M.ncmd = 0;
    uint64_t ste[8];
    ck_smmu_ste_stage1(ste, 0x12345640ull);
    CHECK(ck_smmu_install_ste(&R, &T, 5, ste, 100) == 0);
    CHECK(mem.ste[5 * 8] == ste[0] && mem.ste[4 * 8] == 1 && mem.ste[6 * 8] == 1);
    /* abort+invalidate, then install+invalidate: two CFGI_STE(5) batches */
    CHECK(M.ncmd == 8 && (M.cmds[0][0] & 0xff) == CK_SMMU_CMD_CFGI_STE && (M.cmds[0][0] >> 32) == 5 &&
          M.cmds[0][1] == 1 && (M.cmds[1][0] & 0xff) == CK_SMMU_CMD_CFGI_CD_ALL && (M.cmds[1][0] >> 32) == 5 &&
          (M.cmds[4][0] & 0xff) == CK_SMMU_CMD_CFGI_STE && (M.cmds[5][0] & 0xff) == CK_SMMU_CMD_CFGI_CD_ALL &&
          (M.cmds[6][0] & 0xff) == CK_SMMU_CMD_TLBI_NSNH_ALL && (M.cmds[7][0] & 0xff) == CK_SMMU_CMD_SYNC);
    CHECK(ck_smmu_install_ste(&R, &T, SIDS, ste, 100) == CK_SMMU_EINVAL);
    CHECK(ck_smmu_abort_ste(&R, &T, SIDS, 100) == CK_SMMU_EINVAL);
    M.ncmd = 0;
    CHECK(ck_smmu_abort_ste(&R, &T, 5, 100) == 0);
    CHECK(mem.ste[5 * 8] == 1 && mem.ste[5 * 8 + 1] == 0);
    CHECK(M.ncmd == 4 && (M.cmds[0][0] >> 32) == 5 && (M.cmds[1][0] >> 32) == 5);
    /* A stuck queue on install leaves the stream in abort. */
    M.cmdq_stuck = 1;
    CHECK(ck_smmu_install_ste(&R, &T, 7, ste, 50) == CK_SMMU_ETIMEOUT);
    CHECK(mem.ste[7 * 8] == 1);
}

static void test_queue_wrap(void)
{
    reset();
    CHECK(ck_smmu_enable(&R, &T, 100) == 0);
    M.ncmd = 0;
    uint64_t c[20][2];
    for (int i = 0; i < 20; i++)
        ck_smmu_cmd(c[i], CK_SMMU_CMD_SYNC, (uint32_t)i, 0);
    CHECK(ck_smmu_submit(&R, &T, (const uint64_t (*)[2])c, 20, 100) == 0);
    CHECK(M.ncmd == 20 && (M.cmds[19][0] >> 32) == 19);
    /* 3 (enable) + 20 = 23 = one wrap of 16 + index 7 */
    CHECK(M.cmdq_prod == (7u | 16u) && M.cmdq_cons == M.cmdq_prod);
    /* A full queue that never drains times out. */
    M.cmdq_stuck = 1;
    CHECK(ck_smmu_submit(&R, &T, (const uint64_t (*)[2])c, 20, 50) == CK_SMMU_ETIMEOUT);
}

static void test_events(void)
{
    reset();
    CHECK(ck_smmu_enable(&R, &T, 100) == 0);
    mem.evt[0] = 0x10 | (0x10ull << 32);
    mem.evt[2] = 0x7000;
    mem.evt[4] = 0x06 | (0x20ull << 32);
    mem.evt[6] = 0;
    M.evtq_prod = 2;
    struct ck_smmu_event ev[4];
    int ovf = -1;
    CHECK(ck_smmu_read_events(&R, &T, ev, 4, &ovf) == 2);
    CHECK(ev[0].type == 0x10 && ev[0].sid == 0x10 && ev[0].addr == 0x7000 && ev[1].type == 0x06 && ev[1].sid == 0x20);
    CHECK(ovf == 0 && M.evtq_cons == 2);
    CHECK(ck_smmu_read_events(&R, &T, ev, 4, &ovf) == 0);
    /* Wrapped producer with overflow flag: acknowledged once. */
    M.evtq_prod = 1u | 16u | (1u << 31);
    M.evtq_cons = 15;
    CHECK(ck_smmu_read_events(&R, &T, ev, 1, &ovf) == 1 && ovf == 1);
    CHECK(M.evtq_cons == (0u | 16u | (1u << 31)));
    CHECK(ck_smmu_read_events(&R, &T, ev, 4, &ovf) == 1 && ovf == 0);
}

/* ---- IORT -------------------------------------------------------------- */
static void w16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void w32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static void w64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }

/* header(48) | ITS group (24 bytes, type 0) | SMMUv3 node (68 bytes, one
 * mapping to the ITS) | root complex (36 + 20*2 bytes, mappings to SMMU
 * and to the ITS) */
static uint32_t build_iort(uint8_t *t, int smmu_present)
{
    memset(t, 0, 512);
    memcpy(t, "IORT", 4);
    uint32_t at = 48, its = at, smmu, rc;
    t[at] = 0; w16(t + at + 1, 24); w32(t + at + 16, 1); at += 24;
    smmu = at;
    t[at] = smmu_present ? 4 : 1; w16(t + at + 1, 88);
    w32(t + at + 8, 1); w32(t + at + 12, 68);
    w64(t + at + 16, 0x09050000ull);
    w32(t + at + 68 + 4, 0xffff); w32(t + at + 68 + 12, its);
    at += 88;
    rc = at;
    t[at] = 2; w16(t + at + 1, 36 + 40);
    w32(t + at + 8, 2); w32(t + at + 12, 36);
    w32(t + at + 36 + 0, 0); w32(t + at + 36 + 4, 0xffff); w32(t + at + 36 + 8, 0); w32(t + at + 36 + 12, smmu);
    w32(t + at + 56 + 0, 0x10000); w32(t + at + 56 + 4, 0xff); w32(t + at + 56 + 8, 0); w32(t + at + 56 + 12, its);
    at += 76;
    w32(t + 4, at);
    w32(t + 36, 3);
    w32(t + 40, 48);
    (void)rc;
    return at;
}

static void test_iort(void)
{
    static uint8_t t[512];
    struct ck_iort_smmu s;
    uint32_t sid = 0;
    build_iort(t, 1);
    CHECK(ck_iort_parse(t, &s) == 1);
    CHECK(s.base == 0x09050000ull && s.nmaps == 1 && s.map[0].id_count == 0xffff);
    CHECK(ck_iort_stream_id(&s, 0, 0x0010, &sid) == 0 && sid == 0x10);
    CHECK(ck_iort_stream_id(&s, 0, 0xffff, &sid) == 0 && sid == 0xffff);
    CHECK(ck_iort_stream_id(&s, 0, 0x10000, &sid) == -1); /* the ITS-only mapping is not an SMMU stream */
    /* ... and not an "other SMMU" entry either: only SMMUv3 nodes count. */
    uint64_t ob = 0;
    CHECK(s.nother == 0 && ck_iort_other_stream(&s, 0, 0x10000, &sid, &ob) == -1);
    build_iort(t, 0);
    CHECK(ck_iort_parse(t, &s) == 0);
    /* Malformed: node length past the table, mapping array past the node,
     * SMMU base 0, bad signature. */
    build_iort(t, 1);
    w16(t + 48 + 24 + 1, 400);
    CHECK(ck_iort_parse(t, &s) == -1);
    build_iort(t, 1);
    w32(t + 48 + 24 + 88 + 8, 9);
    CHECK(ck_iort_parse(t, &s) == -1);
    build_iort(t, 1);
    w64(t + 48 + 24 + 16, 0);
    CHECK(ck_iort_parse(t, &s) == -1);
    build_iort(t, 1);
    t[0] = 'X';
    CHECK(ck_iort_parse(t, &s) == -1);
    build_iort(t, 1);
    w32(t + 36, 9); /* more nodes than fit */
    CHECK(ck_iort_parse(t, &s) == -1);
    build_iort(t, 1);
    w32(t + 40, 40); /* node array inside the 48-byte IORT header */
    CHECK(ck_iort_parse(t, &s) == -1);
    /* A mapping whose output would wrap is never a stream. */
    struct ck_iort_smmu w = { .base = 1, .nmaps = 1, .map = { { 0, 0, 0xffff, 0xfffffff0u } } };
    CHECK(ck_iort_stream_id(&w, 0, 0x20, &sid) == -1);
}

/* ---- IORT on the DGX Spark's shape (MEASURED from its IORT, 2026-10-06:
 * 15 root complexes for PCI segments 0..14, each mapping requester ids
 * 0..0xffff to streams 0x10000*(segment+1) on the first SMMUv3
 * (0x13800000); segment 15's root complex maps to the second SMMUv3
 * (0x13000000) instead). ------------------------------------------------ */
static uint32_t iort_begin(uint8_t *t, size_t cap)
{
    memset(t, 0, cap);
    memcpy(t, "IORT", 4);
    w32(t + 40, 48);
    return 48;
}
static uint32_t iort_smmu(uint8_t *t, uint32_t at, uint64_t base)
{
    t[at] = 4; w16(t + at + 1, 88);
    w64(t + at + 16, base);
    return at + 88;
}
/* Root complex for `seg` with `n` mappings: mapping i covers
 * [in + i*step, in + i*step + cnt] -> out + i*step, to node `ref`. */
static uint32_t iort_rc(uint8_t *t, uint32_t at, uint32_t seg, uint32_t n, uint32_t in, uint32_t cnt, uint32_t step,
                        uint32_t out, uint32_t ref)
{
    t[at] = 2; w16(t + at + 1, (uint16_t)(36 + 20 * n));
    w32(t + at + 8, n); w32(t + at + 12, 36);
    w32(t + at + 28, seg);
    for (uint32_t i = 0; i < n; i++) {
        uint8_t *e = t + at + 36 + 20 * i;
        w32(e, in + i * step); w32(e + 4, cnt); w32(e + 8, out + i * step); w32(e + 12, ref);
    }
    return at + 36 + 20 * n;
}
static void iort_end(uint8_t *t, uint32_t at, uint32_t nodes)
{
    w32(t + 4, at);
    w32(t + 36, nodes);
}

static void test_iort_spark_shape(void)
{
    static uint8_t t[2048];
    struct ck_iort_smmu s;
    uint32_t sid = 0;
    uint32_t at = iort_begin(t, sizeof t), a = at;
    at = iort_smmu(t, at, 0x13800000ull);
    uint32_t b = at;
    at = iort_smmu(t, at, 0x13000000ull);
    for (uint32_t seg = 0; seg < 15; seg++)
        at = iort_rc(t, at, seg, 1, 0, 0xffff, 0, 0x10000u * (seg + 1), a);
    uint32_t rc15 = at;
    at = iort_rc(t, at, 15, 1, 0, 0xffff, 0, 0, b);
    iort_end(t, at, 18);
    CHECK(ck_iort_parse(t, &s) == 1);
    CHECK(s.base == 0x13800000ull && s.node_off == a && s.nmaps == 15);
    CHECK(s.map[4].segment == 4 && s.map[4].output_base == 0x50000);
    /* GB10 000f:01:00.0 (MEASURED 2026-10-10, docs/GB10_IORT_DECODE.md):
     * segment 15 maps rid 0..0xffff one-to-one onto the second SMMUv3
     * (0x13000000), so rid 0x100 is stream 0x100 behind an SMMU this
     * kernel does not drive. The first-SMMU lookup must refuse it and
     * the other-SMMU lookup must name it. */
    uint64_t ob = 0;
    CHECK(s.nother == 1 && s.other[0].map.segment == 15 && s.other[0].smmu_off == b &&
          s.other[0].smmu_base == 0x13000000ull && s.other[0].map.id_count == 0xffff);
    CHECK(ck_iort_other_stream(&s, 15, 0x100, &sid, &ob) == 0 && sid == 0x100 && ob == 0x13000000ull);
    CHECK(ck_iort_other_stream(&s, 15, 0x0, &sid, &ob) == 0 && sid == 0x0);
    CHECK(ck_iort_other_stream(&s, 15, 0x10000, &sid, &ob) == -1); /* past the range */
    CHECK(ck_iort_other_stream(&s, 4, 0x100, &sid, &ob) == -1);    /* on the first SMMU, not "other" */
    CHECK(ck_iort_other_stream(&s, 16, 0x100, &sid, &ob) == -1);   /* no such segment */
    /* NVMe 0004:01:00.0 (MEASURED: segment 4, behind smmu 0x13800000):
     * rid = bus 1 << 8 | dev 0 << 3 | fn 0 = 0x100; segment 4's mapping
     * starts at stream 0x50000, so 0x50000 + 0x100 = 0x50100. */
    CHECK(ck_iort_stream_id(&s, 4, 0x100, &sid) == 0 && sid == 0x50100);
    CHECK(ck_iort_stream_id(&s, 0, 0x100, &sid) == 0 && sid == 0x10100);
    CHECK(ck_iort_stream_id(&s, 0, 0x0, &sid) == 0 && sid == 0x10000);
    CHECK(ck_iort_stream_id(&s, 14, 0xffff, &sid) == 0 && sid == 0xfffff);
    /* Wrong segment: segment 15 belongs to the second SMMU, segment 16
     * does not exist; a segment-blind lookup would hand out segment 0's
     * stream 0x10000 / 0x10100 here. */
    sid = 0xdead;
    CHECK(ck_iort_stream_id(&s, 15, 0x0, &sid) == -1 && sid == 0xdead);
    CHECK(ck_iort_stream_id(&s, 16, 0x100, &sid) == -1);
    CHECK(ck_iort_stream_id(&s, 4, 0x10000, &sid) == -1);
    /* Segment 15's mappings never land on the first SMMU's list. */
    for (uint32_t i = 0; i < s.nmaps; i++)
        CHECK(s.map[i].segment != 15);
    /* A root complex node too short to carry its segment is refused. */
    w16(t + rc15 + 1, 24); w32(t + rc15 + 8, 0); w32(t + rc15 + 12, 0);
    iort_end(t, rc15 + 24, 18);
    CHECK(ck_iort_parse(t, &s) == -1);
}

static void test_iort_cap_overlap(void)
{
    static uint8_t t[2048];
    struct ck_iort_smmu s;
    uint32_t sid = 0;
    /* Exactly CK_IORT_MAX_MAPS mappings: accepted, all kept. */
    uint32_t at = iort_begin(t, sizeof t), a = at;
    at = iort_smmu(t, at, 0x13800000ull);
    at = iort_rc(t, at, 0, CK_IORT_MAX_MAPS, 0, 0xff, 0x100, 0x1000, a);
    iort_end(t, at, 2);
    CHECK(ck_iort_parse(t, &s) == 1 && s.nmaps == CK_IORT_MAX_MAPS);
    CHECK(ck_iort_stream_id(&s, 0, 0x1f05, &sid) == 0 && sid == 0x2f05);
    /* One more: the whole table is refused, not truncated. */
    at = iort_begin(t, sizeof t);
    at = iort_smmu(t, at, 0x13800000ull);
    at = iort_rc(t, at, 0, CK_IORT_MAX_MAPS + 1, 0, 0xff, 0x100, 0x1000, a);
    iort_end(t, at, 2);
    CHECK(ck_iort_parse(t, &s) == -1);
    /* Overlapping input ranges in one segment: refused. */
    at = iort_begin(t, sizeof t);
    at = iort_smmu(t, at, 0x13800000ull);
    at = iort_rc(t, at, 0, 2, 0, 0xff, 0x80, 0x1000, a);
    iort_end(t, at, 2);
    CHECK(ck_iort_parse(t, &s) == -1);
    /* Overlap split over two root complexes of the same segment: refused. */
    at = iort_begin(t, sizeof t);
    at = iort_smmu(t, at, 0x13800000ull);
    at = iort_rc(t, at, 3, 1, 0x10, 0xff, 0, 0x1000, a);
    at = iort_rc(t, at, 3, 1, 0x10f, 0, 0, 0x2000, a);
    iort_end(t, at, 3);
    CHECK(ck_iort_parse(t, &s) == -1);
    /* Adjacent ranges, and the same range in two segments: accepted. */
    at = iort_begin(t, sizeof t);
    at = iort_smmu(t, at, 0x13800000ull);
    at = iort_rc(t, at, 0, 2, 0, 0xff, 0x100, 0x1000, a);
    at = iort_rc(t, at, 1, 1, 0, 0xff, 0, 0x5000, a);
    iort_end(t, at, 3);
    CHECK(ck_iort_parse(t, &s) == 1 && s.nmaps == 3);
    CHECK(ck_iort_stream_id(&s, 0, 0x100, &sid) == 0 && sid == 0x1100);
    CHECK(ck_iort_stream_id(&s, 1, 0x10, &sid) == 0 && sid == 0x5010);
}

/* ---- two-level stream table (Arm IHI 0070 H.a 6.3.25, 5.1) ------------- */
#define L2_SID_BITS 20u
#define L1_N (1u << (L2_SID_BITS - CK_SMMU_SPLIT))
#define POOL_N 4
static struct {
    uint64_t l1[L1_N + 16] __attribute__((aligned(L1_N * 8)));
    uint64_t page[POOL_N][CK_SMMU_L2_STES * 8] __attribute__((aligned(CK_SMMU_L2_BYTES)));
} l2mem;
static int pool_next, pool_misalign;
static int pool_alloc(void *ctx, uint64_t **page)
{
    (void)ctx;
    if (pool_next >= POOL_N) return -1;
    *page = l2mem.page[pool_next++] + (pool_misalign ? 8 : 0);
    return 0;
}

/* Independent model of the SMMU's stream table walk (IHI 0070 3.3.1,
 * 5.1.1): -1 terminated (out of range, invalid span, outside the span,
 * STE.V = 0), -2 a valid span whose L2 table is at address 0, else the STE
 * Config (0 abort, 5 stage-1 translate). */
static int walk(uint32_t sid)
{
    uint32_t cfg = M.strtab_cfg, split = (cfg >> 6) & 0x1f, log2size = cfg & 0x3f;
    if (((cfg >> 16) & 3) != 1 || (sid >> log2size)) return -1;
    const uint64_t *l1 = (const uint64_t *)(uintptr_t)(M.strtab & 0x00ffffffffffffc0ull);
    uint64_t d = l1[sid >> split];
    uint32_t span = (uint32_t)(d & 0x1f);
    if (span == 0 || span > 11 || span > split + 1) return -1;
    uint32_t idx = sid & ((1u << split) - 1u);
    if (idx >= (1u << (span - 1))) return -1;
    uint64_t l2 = d & 0x00ffffffffffffc0ull & ~((1ull << (6 + span - 1)) - 1ull);
    if (l2 == 0) return -2; /* the SMMU would fetch STEs from physical address 0 */
    const uint64_t *ste = (const uint64_t *)(uintptr_t)l2 + (uint64_t)idx * 8u;
    if (!(ste[0] & 1)) return -1;
    return (int)((ste[0] >> 1) & 7);
}
static void reset_l2(void)
{
    reset();
    memset(&l2mem, 0xff, sizeof l2mem); /* dirty pages: the attach must fill them */
    pool_next = 0;
    pool_misalign = 0;
    M.idr0 = CK_SMMU_IDR0_S1P | (1u << CK_SMMU_IDR0_ST_LEVEL_SHIFT);
    M.idr1 = L2_SID_BITS | (19u << 16) | (19u << 21);
    T.strtab = 0; T.ste_n = 0;
    T.l1 = l2mem.l1; T.sid_bits = L2_SID_BITS;
    T.l2_alloc = pool_alloc; T.l2_ctx = 0;
}
static int saw_cmd(uint8_t op, uint32_t sid, uint64_t w1)
{
    for (int i = 0; i < M.ncmd; i++)
        if ((M.cmds[i][0] & 0xff) == op && (uint32_t)(M.cmds[i][0] >> 32) == sid && M.cmds[i][1] == w1) return 1;
    return 0;
}

static void test_two_level(void)
{
    uint64_t ste[8];
    ck_smmu_ste_stage1(ste, 0x40001000ull);
    reset_l2();
    CHECK(ck_smmu_tables_check(&T) == 0);
    CHECK(ck_smmu_enable(&R, &T, 100) == 0);
    CHECK(M.strtab_cfg == ((1u << 16) | (6u << 6) | 20u)); /* FMT 2-level, SPLIT 6, LOG2SIZE 20 */
    CHECK(M.strtab == (uint64_t)(uintptr_t)l2mem.l1);
    int all_invalid = 1;
    for (uint32_t i = 0; i < L1_N; i++)
        if (l2mem.l1[i] != 0) all_invalid = 0;
    CHECK(all_invalid);
    CHECK(pool_next == 0); /* lazy: no L2 table before the first grant */
    CHECK(walk(0x0) == -1 && walk(0x50100) == -1);
    /* Grant 0x0-0x5 (the USB named components) and 0x50100 (the NVMe). */
    for (uint32_t sid = 0; sid <= 5; sid++)
        CHECK(ck_smmu_install_ste(&R, &T, sid, ste, 100) == 0);
    CHECK(pool_next == 1); /* one span covers 0x0-0x3f */
    M.ncmd = 0;
    CHECK(ck_smmu_install_ste(&R, &T, 0x50100, ste, 100) == 0);
    CHECK(pool_next == 2);
    CHECK(ck_smmu_l1std(&T, 0x50100) == ((uint64_t)(uintptr_t)l2mem.page[1] | 7u)); /* Span 7 = 64 STEs */
    CHECK(l2mem.l1[0x50100 >> 6] == ck_smmu_l1std(&T, 0x50100));
    CHECK(saw_cmd(CK_SMMU_CMD_CFGI_STE, 0x50100, 0)); /* non-leaf: the L1STD */
    CHECK(saw_cmd(CK_SMMU_CMD_CFGI_STE, 0x50100, 1)); /* leaf: the STE */
    for (uint32_t sid = 0; sid <= 5; sid++)
        CHECK(walk(sid) == 5);
    CHECK(walk(0x50100) == 5);
    /* Refused: the neighbour in the same span aborts, other spans and
     * out-of-range ids are terminated. */
    CHECK(walk(0x50101) == 0);
    CHECK(walk(0x6) == 0 && walk(0x3f) == 0);
    CHECK(walk(0x40) == -1 && walk(0x50140) == -1 && walk(0x500ff) == -1);
    CHECK(walk(0x100000) == -1);
    CHECK(ck_smmu_sid_in_range(&T, 0xfffff) == 1 && ck_smmu_sid_in_range(&T, 0x100000) == 0);
    CHECK(ck_smmu_install_ste(&R, &T, 0x100000, ste, 100) == CK_SMMU_EINVAL);
    CHECK(pool_next == 2);
    /* Revoke: back to abort; aborting an unattached span allocates nothing. */
    CHECK(ck_smmu_abort_ste(&R, &T, 0x50100, 100) == 0 && walk(0x50100) == 0);
    CHECK(ck_smmu_abort_ste(&R, &T, 0x80, 100) == 0 && walk(0x80) == -1 && pool_next == 2);
    /* A descriptor the kernel did not write is refused, never overwritten. */
    l2mem.l1[2] = 0x1234;
    CHECK(ck_smmu_install_ste(&R, &T, 0x80, ste, 100) == CK_SMMU_EINVAL && l2mem.l1[2] == 0x1234);
    CHECK(ck_smmu_abort_ste(&R, &T, 0x80, 100) == CK_SMMU_EINVAL);
    CHECK(pool_next == 2);
}

static void test_two_level_refusals(void)
{
    uint64_t ste[8];
    ck_smmu_ste_stage1(ste, 0x40001000ull);
    /* Bad L1 pointer: not aligned to the L1 size (128 KiB here). */
    reset_l2();
    T.l1 = l2mem.l1 + 1;
    CHECK(ck_smmu_tables_check(&T) == CK_SMMU_EINVAL);
    CHECK(ck_smmu_enable(&R, &T, 100) == CK_SMMU_EINVAL && M.cr0 == 0 && M.wn == 0);
    reset_l2();
    T.l1 = l2mem.l1 + 8; /* 64-byte aligned only */
    CHECK(ck_smmu_enable(&R, &T, 100) == CK_SMMU_EINVAL);
    /* LOG2SIZE bounds and a missing allocator. */
    reset_l2();
    T.sid_bits = CK_SMMU_L2_MAX_BITS + 1;
    CHECK(ck_smmu_tables_check(&T) == CK_SMMU_EINVAL);
    T.sid_bits = CK_SMMU_SPLIT;
    CHECK(ck_smmu_tables_check(&T) == CK_SMMU_EINVAL);
    reset_l2();
    T.l2_alloc = 0;
    CHECK(ck_smmu_tables_check(&T) == CK_SMMU_EINVAL);
    /* The SMMU must report 2-level support and enough StreamID bits. */
    reset_l2();
    M.idr0 = CK_SMMU_IDR0_S1P;
    CHECK(ck_smmu_enable(&R, &T, 100) == CK_SMMU_EUNSUP && last_cr0() == 0);
    reset_l2();
    M.idr1 = 16u | (19u << 16) | (19u << 21);
    CHECK(ck_smmu_enable(&R, &T, 100) == CK_SMMU_EUNSUP);
    /* Bad L2 pointer from the allocator: refused, span stays invalid. */
    reset_l2();
    CHECK(ck_smmu_enable(&R, &T, 100) == 0);
    pool_misalign = 1;
    CHECK(ck_smmu_install_ste(&R, &T, 0x50100, ste, 100) == CK_SMMU_EINVAL);
    CHECK(ck_smmu_l1std(&T, 0x50100) == 0 && walk(0x50100) == -1);
    /* Allocator exhausted: refused, span stays invalid. */
    pool_misalign = 0;
    pool_next = POOL_N;
    CHECK(ck_smmu_install_ste(&R, &T, 0x50100, ste, 100) == CK_SMMU_EINVAL && walk(0x50100) == -1);
    /* The linear path is unchanged by the two-level fields being zero. */
    reset();
    CHECK(ck_smmu_enable(&R, &T, 100) == 0 && M.strtab_cfg == 4u && M.strtab == (uint64_t)(uintptr_t)mem.ste);
}

int main(void)
{
    test_layouts();
    test_tables_check();
    test_enable_ok();
    test_enable_fail_closed();
    test_install_abort();
    test_queue_wrap();
    test_events();
    test_iort();
    test_iort_spark_shape();
    test_iort_cap_overlap();
    test_two_level();
    test_two_level_refusals();
    return ck_t_verdict("test_smmu");
}
