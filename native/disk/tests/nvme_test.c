/*
 * nvme_test.c -- hosted tests for disk_nvme.c against a software NVMe
 * controller model (registers, admin and I/O queues, PRP walking, a volatile
 * write cache, fault injection). The model is a test stand-in: passing here
 * says the driver follows the register/queue protocol as modelled, not that
 * any real controller or QEMU accepts it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../disk.h"
#include "../disk_nvme.h"

static int failures, checks;
#define CHECK(cond)                                                                      \
    do {                                                                                 \
        checks++;                                                                        \
        if (!(cond)) {                                                                   \
            failures++;                                                                  \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);              \
        }                                                                                \
    } while (0)

/* ------------------------------------------------------------------ model */

#define PHYS_BASE 0x123456000ull /* above 4 GiB: high dwords must be written */
#define MAXLOG 1024

typedef struct {
    uint8_t opc;
    uint16_t cid;
    uint32_t nsid, nlb;
    uint64_t lba, prp1, prp2;
} iolog;

typedef struct {
    /* configuration */
    uint64_t cap;
    uint32_t vs;
    uint8_t sqes, cqes, mdts, vwc;
    uint32_t nn, active_nsid;
    uint64_t nsze;
    uint8_t nlbaf, flbas, lbads;
    uint16_t ms;
    uint16_t awupf, nawupf, nabo, nabspf;
    int ready_after_reads, never_ready, cfs_on_enable;
    int stuck, cfs_on_stuck, bad_sqid, bad_cid, cns2_unsupported;
    uint16_t inject_sc; /* status code for the next I/O command (one shot) */
    /* register state */
    uint32_t cc, csts, aqa, cc_at_enable;
    uint64_t asq, acq;
    uint16_t asq_head, acq_tail, acq_phase;
    uint64_t iosq, iocq;
    uint32_t iosq_size, iocq_size;
    uint16_t iosq_head, iocq_tail, iocq_phase;
    int cq_ok, sq_ok;
    /* memory */
    uint8_t *mem;
    uint64_t mem_bytes;
    uint8_t *media, *cache, *dirty;
    /* observation */
    iolog log[MAXLOG];
    int nlog, nadmin, protocol_errors, doorbells;
    uint64_t delay_total;
    long barriers;
    uint32_t last_cq_db[2];
} model;

static model M;

static void perr(const char *why)
{
    M.protocol_errors++;
    if (getenv("NVME_TEST_VERBOSE"))
        fprintf(stderr, "model protocol error: %s\n", why);
}

static uint8_t *ptr(uint64_t phys, uint64_t len)
{
    if (phys < PHYS_BASE || phys - PHYS_BASE > M.mem_bytes || len > M.mem_bytes - (phys - PHYS_BASE)) {
        perr("DMA address outside region");
        return NULL;
    }
    return M.mem + (phys - PHYS_BASE);
}

static uint32_t g32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t g64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
static void p16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void p32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static void p64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }

static uint32_t stride(void) { return 4u << ((M.cap >> 32) & 0xf); }
static uint32_t mqes1(void) { return (uint32_t)(M.cap & 0xffff) + 1; }
static uint32_t bsz(void) { return 1u << M.lbads; }

static void post(uint64_t cqbase, uint16_t *tail, uint32_t size, uint16_t *phase, uint16_t sqid,
                 uint16_t sqhd, uint16_t cid, uint16_t sc)
{
    if (M.stuck)
        return;
    uint8_t *e = ptr(cqbase + (uint64_t)*tail * 16, 16);
    if (!e)
        return;
    p32(e, 0);
    p32(e + 4, 0);
    p16(e + 8, sqhd);
    p16(e + 10, M.bad_sqid ? (uint16_t)(sqid + 7) : sqid);
    p16(e + 12, M.bad_cid ? (uint16_t)(cid ^ 0x1234) : cid);
    p16(e + 14, (uint16_t)(*phase | (sc << 1)));
    if (++*tail == size) {
        *tail = 0;
        *phase ^= 1;
    }
}

static void admin_cmd(const uint8_t *c)
{
    uint8_t opc = c[0];
    uint16_t cid = (uint16_t)(g32(c) >> 16);
    uint32_t nsid = g32(c + 4), cdw10 = g32(c + 40), cdw11 = g32(c + 44);
    uint64_t prp1 = g64(c + 24);
    uint16_t sc = 0;
    M.nadmin++;
    if (opc == 0x06) {
        uint8_t *d = ptr(prp1, 4096);
        if (!d || (prp1 & 0xfff)) {
            sc = 0x02;
        } else if ((cdw10 & 0xff) == 1) {
            memset(d, 0, 4096);
            d[77] = M.mdts;
            d[512] = M.sqes;
            d[513] = M.cqes;
            p32(d + 516, M.nn);
            d[525] = M.vwc;
            p16(d + 528, M.awupf);
        } else if ((cdw10 & 0xff) == 2) {
            if (M.cns2_unsupported)
                sc = 0x02;
            else {
                memset(d, 0, 4096);
                if (M.active_nsid > nsid)
                    p32(d, M.active_nsid);
            }
        } else if ((cdw10 & 0xff) == 0) {
            if (nsid == 0 || nsid != M.active_nsid)
                sc = 0x0b; /* invalid namespace */
            else {
                memset(d, 0, 4096);
                p64(d, M.nsze);
                p64(d + 8, M.nsze);
                d[25] = M.nlbaf;
                d[26] = M.flbas;
                p16(d + 36, M.nawupf);
                p16(d + 42, M.nabo);
                p16(d + 44, M.nabspf);
                for (int i = 0; i < 16; i++)
                    p32(d + 128 + i * 4, (uint32_t)M.ms | ((uint32_t)M.lbads << 16));
            }
        } else {
            sc = 0x02;
        }
    } else if (opc == 0x05) { /* create I/O CQ */
        uint32_t qid = cdw10 & 0xffff, qs = (cdw10 >> 16) + 1;
        if (qid != 1 || qs < 2 || qs > mqes1() || !(cdw11 & 1) || (prp1 & 0xfff) || !ptr(prp1, qs * 16))
            sc = 0x02;
        else {
            M.iocq = prp1;
            M.iocq_size = qs;
            M.iocq_tail = 0;
            M.iocq_phase = 1;
            M.cq_ok = 1;
        }
    } else if (opc == 0x01) { /* create I/O SQ */
        uint32_t qid = cdw10 & 0xffff, qs = (cdw10 >> 16) + 1;
        if (!M.cq_ok || (cdw11 >> 16) != 1)
            sc = 0x100 | 0x00; /* SCT 1, completion queue invalid */
        else if (qid != 1 || qs < 2 || qs > mqes1() || !(cdw11 & 1) || (prp1 & 0xfff) || !ptr(prp1, qs * 64))
            sc = 0x02;
        else {
            M.iosq = prp1;
            M.iosq_size = qs;
            M.iosq_head = 0;
            M.sq_ok = 1;
        }
    } else {
        sc = 0x01;
    }
    post(M.acq, &M.acq_tail, (M.aqa >> 16) + 1, &M.acq_phase, 0, M.asq_head, cid, sc);
}

/* Walk the PRPs of a transfer; returns 0 and fills addresses, or -1. */
static int prp_walk(uint64_t prp1, uint64_t prp2, uint64_t len, uint64_t *addr, uint64_t *n_out)
{
    uint64_t n = 0;
    if (prp1 & 3)
        return -1;
    addr[n++] = prp1;
    uint64_t first = 4096 - (prp1 & 4095);
    if (first >= len) {
        *n_out = n;
        return 0;
    }
    uint64_t left = len - first;
    if (left <= 4096) {
        if (prp2 & 4095 || prp2 == 0)
            return -1;
        addr[n++] = prp2;
        *n_out = n;
        return 0;
    }
    uint64_t list = prp2;
    if (list & 4095)
        return -1;
    while (left) {
        uint8_t *lp = ptr(list, 4096);
        if (!lp)
            return -1;
        for (int i = 0; i < 512 && left; i++) {
            uint64_t a = g64(lp + i * 8);
            if (i == 511 && left > 4096) {
                if (a & 4095)
                    return -1;
                list = a;
                break;
            }
            if (a & 4095)
                return -1;
            addr[n++] = a;
            left = left > 4096 ? left - 4096 : 0;
        }
    }
    *n_out = n;
    return 0;
}

static void io_cmd(const uint8_t *c)
{
    uint8_t opc = c[0];
    uint16_t cid = (uint16_t)(g32(c) >> 16);
    uint32_t nsid = g32(c + 4);
    uint64_t prp1 = g64(c + 24), prp2 = g64(c + 32), lba = g64(c + 40);
    uint32_t nlb = (g32(c + 48) & 0xffff) + 1;
    uint16_t sc = 0;
    if (M.nlog < MAXLOG) {
        iolog *l = &M.log[M.nlog];
        l->opc = opc;
        l->cid = cid;
        l->nsid = nsid;
        l->nlb = opc == 0 ? 0 : nlb;
        l->lba = lba;
        l->prp1 = prp1;
        l->prp2 = prp2;
    }
    M.nlog++;
    if (nsid != M.active_nsid) {
        sc = 0x0b;
    } else if (opc == 0x00) {
        for (uint64_t b = 0; b < M.nsze; b++)
            if (M.dirty[b]) {
                memcpy(M.media + b * bsz(), M.cache + b * bsz(), bsz());
                M.dirty[b] = 0;
            }
    } else if (opc == 0x01 || opc == 0x02) {
        uint64_t len = (uint64_t)nlb * bsz();
        static uint64_t addr[2048];
        uint64_t n = 0;
        if (lba >= M.nsze || nlb > M.nsze - lba)
            sc = 0x80; /* LBA out of range */
        else if (prp_walk(prp1, prp2, len, addr, &n))
            sc = 0x13; /* invalid PRP offset */
        else {
            uint64_t done = 0;
            for (uint64_t i = 0; i < n && done < len; i++) {
                uint64_t chunk = 4096 - (addr[i] & 4095);
                if (chunk > len - done)
                    chunk = len - done;
                uint8_t *p = ptr(addr[i], chunk);
                if (!p) {
                    sc = 0x13;
                    break;
                }
                for (uint64_t j = 0; j < chunk; j++) {
                    uint64_t off = lba * bsz() + done + j, b = off / bsz();
                    if (opc == 0x01) {
                        if (M.vwc) {
                            if (!M.dirty[b]) {
                                memcpy(M.cache + b * bsz(), M.media + b * bsz(), bsz());
                                M.dirty[b] = 1;
                            }
                            M.cache[off] = p[j];
                        } else {
                            M.media[off] = p[j];
                        }
                    } else {
                        p[j] = M.dirty[b] ? M.cache[off] : M.media[off];
                    }
                }
                done += chunk;
            }
        }
    } else {
        sc = 0x01;
    }
    if (M.inject_sc) {
        sc = M.inject_sc;
        M.inject_sc = 0;
    }
    post(M.iocq, &M.iocq_tail, M.iocq_size, &M.iocq_phase, 1, M.iosq_head, cid, sc);
}

static void reset_queues(void)
{
    M.asq_head = M.acq_tail = 0;
    M.acq_phase = 1;
    M.cq_ok = M.sq_ok = 0;
    M.iosq_head = M.iocq_tail = 0;
}

static uint32_t m_read32(void *ctx, uint32_t off)
{
    (void)ctx;
    switch (off) {
    case 0x00: return (uint32_t)M.cap;
    case 0x04: return (uint32_t)(M.cap >> 32);
    case 0x08: return M.vs;
    case 0x14: return M.cc;
    case 0x1c:
        if (M.ready_after_reads > 0 && (M.cc & 1) && !M.cfs_on_enable) {
            M.ready_after_reads--;
            return M.csts & ~1u;
        }
        return M.csts;
    case 0x24: return M.aqa;
    default: perr("read of unmodelled register"); return 0;
    }
}

static void m_write32(void *ctx, uint32_t off, uint32_t v)
{
    (void)ctx;
    if (off >= 0x1000) {
        M.doorbells++;
        uint32_t idx = (off - 0x1000) / stride();
        if ((off - 0x1000) % stride()) {
            perr("doorbell offset not on DSTRD stride");
            return;
        }
        if (!(M.csts & 1)) {
            perr("doorbell while controller not ready");
            return;
        }
        uint32_t qid = idx / 2;
        if (idx & 1) {
            if (qid < 2)
                M.last_cq_db[qid] = v;
            return;
        }
        if (qid == 0) {
            uint32_t size = (M.aqa & 0xfff) + 1;
            if (v >= size) { perr("admin SQ tail out of range"); return; }
            while (M.asq_head != v) {
                uint8_t *c = ptr(M.asq + (uint64_t)M.asq_head * 64, 64);
                M.asq_head = (uint16_t)((M.asq_head + 1) % size);
                if (c) admin_cmd(c);
            }
        } else if (qid == 1 && M.sq_ok) {
            if (v >= M.iosq_size) { perr("I/O SQ tail out of range"); return; }
            while (M.iosq_head != v) {
                uint8_t *c = ptr(M.iosq + (uint64_t)M.iosq_head * 64, 64);
                M.iosq_head = (uint16_t)((M.iosq_head + 1) % M.iosq_size);
                if (c) io_cmd(c);
            }
        } else {
            perr("doorbell for a queue that does not exist");
        }
        if (M.stuck && M.cfs_on_stuck)
            M.csts |= 2;
        return;
    }
    switch (off) {
    case 0x14: {
        uint32_t old = M.cc;
        M.cc = v;
        if ((v & 1) && !(old & 1)) {
            M.cc_at_enable = v;
            if (!M.aqa || !M.asq || !M.acq)
                perr("enable before admin queues programmed");
            reset_queues();
            M.csts = M.cfs_on_enable ? 2u : (M.never_ready ? 0u : 1u);
        } else if (!(v & 1)) {
            reset_queues();
            M.csts = 0;
        }
        break;
    }
    case 0x24: M.aqa = v; break;
    case 0x28: M.asq = (M.asq & ~0xffffffffull) | v; break;
    case 0x2c: M.asq = (M.asq & 0xffffffffull) | ((uint64_t)v << 32); break;
    case 0x30: M.acq = (M.acq & ~0xffffffffull) | v; break;
    case 0x34: M.acq = (M.acq & 0xffffffffull) | ((uint64_t)v << 32); break;
    case 0x0c: break;
    default: perr("write of unmodelled register");
    }
}

static void m_barrier(void *ctx) { (void)ctx; M.barriers++; }
static void m_delay(void *ctx, uint32_t us) { (void)ctx; M.delay_total += us; }

static const nvme_ops OPS = {NULL, m_read32, m_write32, NULL, NULL, m_barrier, m_delay};

static uint8_t *dma_mem;
#define DMA_BYTES (6u * 4096u + 128u * 1024u)

/* Default healthy controller: MQES 1023, TO 1 (500 ms), DSTRD 0, CSS NVM,
 * MPSMIN 0 / MPSMAX 4, VS 1.4, 512-byte LBAs, 4096 blocks, NSID 1, VWC. */
static void model_reset(void)
{
    free(M.media);
    free(M.cache);
    free(M.dirty);
    memset(&M, 0, sizeof M);
    M.cap = 1023ull | (1ull << 24) | (1ull << 37) | (4ull << 52);
    M.vs = 0x00010400;
    M.sqes = 0x66;
    M.cqes = 0x44;
    M.mdts = 0;
    M.vwc = 1;
    M.nn = 1;
    M.active_nsid = 1;
    M.nsze = 4096;
    M.nlbaf = 0;
    M.flbas = 0;
    M.lbads = 9;
    M.mem = dma_mem;
    M.mem_bytes = DMA_BYTES;
    memset(dma_mem, 0xEE, DMA_BYTES); /* garbage: driver must zero its queues */
}

static void model_alloc_media(void)
{
    uint64_t bytes = M.nsze * bsz();
    M.media = calloc(1, bytes);
    M.cache = calloc(1, bytes);
    M.dirty = calloc(1, M.nsze);
}

/* Lose power: unflushed cache contents vanish, controller resets. */
static void model_power_loss(void)
{
    memset(M.dirty, 0, M.nsze);
    M.cc = 0;
    M.csts = 0;
    reset_queues();
}

static nvme_ctrl C;

static int init_with(uint32_t nsid, uint16_t depth)
{
    if (!M.media)
        model_alloc_media();
    nvme_dma d = {dma_mem, PHYS_BASE, DMA_BYTES};
    nvme_config cfg = {nsid, depth};
    return nvme_init(&C, &OPS, &d, &cfg);
}

static int init_default(void) { return init_with(0, 0); }

static void fill(uint8_t *b, size_t n, unsigned seed)
{
    for (size_t i = 0; i < n; i++)
        b[i] = (uint8_t)(seed * 37u + i * 13u + (i >> 8));
}

/* ------------------------------------------------------------------ tests */

static void test_init_ok(void)
{
    model_reset();
    CHECK(init_default() == NVME_OK);
    CHECK(C.ready == 1 && C.failed == 0);
    CHECK(M.aqa == 0x00070007);
    CHECK(M.cc_at_enable == ((6u << 16) | (4u << 20) | 1u)); /* CSS=0 MPS=0 AMS=0 */
    CHECK(((M.cc_at_enable >> 4) & 7) == 0);  /* CSS NVM */
    CHECK(((M.cc_at_enable >> 7) & 15) == 0); /* MPS 4 KiB */
    CHECK(((M.cc_at_enable >> 11) & 7) == 0); /* AMS round robin */
    CHECK(M.asq == PHYS_BASE && M.acq == PHYS_BASE + 4096);
    CHECK(C.block_size == 512 && C.block_count == 4096 && C.nsid == 1);
    CHECK(C.max_xfer_bytes == 128 * 1024);
    CHECK(M.cq_ok && M.sq_ok && M.iocq_size == NVME_IO_DEPTH_DEFAULT && M.iosq_size == NVME_IO_DEPTH_DEFAULT);
    CHECK(M.iocq == PHYS_BASE + 4 * 4096 && M.iosq == PHYS_BASE + 3 * 4096);
    CHECK(M.nadmin == 5); /* id ctrl, active ns list, id ns, create cq, create sq */
    CHECK(C.vwc == 1 && C.nn == 1);
    CHECK(M.protocol_errors == 0);
    CHECK(M.barriers > 0);
    disk_dev d;
    CHECK(nvme_disk(&C, &d) == DISK_OK);
    CHECK(d.block_size == 512 && d.block_count == 4096 && d.max_blocks_per_io == 256);

    /* controller left enabled: init must clear EN first and still succeed */
    CHECK(init_default() == NVME_OK);
    CHECK(M.protocol_errors == 0);
}

static void test_roundtrip(uint8_t lbads)
{
    model_reset();
    M.lbads = lbads;
    M.nsze = lbads == 12 ? 512 : 4096;
    CHECK(init_default() == NVME_OK);
    uint32_t bs = 1u << lbads;
    CHECK(C.block_size == bs);
    static uint8_t w[1u << 20], r[1u << 20];
    uint32_t counts[] = {1, 2, 8, 9, 31, 32};
    for (unsigned i = 0; i < sizeof counts / sizeof counts[0]; i++) {
        uint32_t n = counts[i] * (lbads == 9 ? 8 : 1); /* 512 B: up to 256 blocks */
        if ((uint64_t)n * bs > C.max_xfer_bytes)
            continue;
        fill(w, (size_t)n * bs, i);
        int before = M.nlog;
        CHECK(nvme_write(&C, 10 + i, n, w) == NVME_OK);
        memset(r, 0, (size_t)n * bs);
        CHECK(nvme_read(&C, 10 + i, n, r) == NVME_OK);
        CHECK(memcmp(w, r, (size_t)n * bs) == 0);
        CHECK(M.nlog == before + 2);
        iolog *l = &M.log[before];
        CHECK(l->opc == 0x01 && l->nsid == 1 && l->lba == 10 + i && l->nlb == n);
        uint64_t bytes = (uint64_t)n * bs;
        if (bytes <= 4096)
            CHECK(l->prp2 == 0);
        else if (bytes <= 8192)
            CHECK(l->prp2 == l->prp1 + 4096);
        else
            CHECK(l->prp2 == PHYS_BASE + 5 * 4096); /* PRP list page */
    }
    /* through disk_dev: 300 KiB spans several commands (split by disk.c) */
    disk_dev d;
    CHECK(nvme_disk(&C, &d) == DISK_OK);
    uint32_t n = (300u * 1024u) / bs;
    fill(w, (size_t)n * bs, 77);
    int before = M.nlog;
    CHECK(disk_write(&d, 100, n, w) == DISK_OK);
    CHECK(M.nlog - before == (int)((n + d.max_blocks_per_io - 1) / d.max_blocks_per_io));
    memset(r, 0, (size_t)n * bs);
    CHECK(disk_read(&d, 100, n, r) == DISK_OK);
    CHECK(memcmp(w, r, (size_t)n * bs) == 0);
    /* each command got a fresh CID */
    for (int i = before + 1; i < M.nlog && i < MAXLOG; i++)
        CHECK(M.log[i].cid != M.log[i - 1].cid);
    CHECK(M.protocol_errors == 0);
}

static void test_flush_and_reopen(void)
{
    model_reset();
    CHECK(init_default() == NVME_OK);
    disk_dev d;
    CHECK(nvme_disk(&C, &d) == DISK_OK);
    static uint8_t a[64 * 512], b[64 * 512], r[64 * 512];
    fill(a, sizeof a, 1);
    fill(b, sizeof b, 2);
    CHECK(disk_write(&d, 0, 64, a) == DISK_OK);
    int before = M.nlog;
    CHECK(disk_flush(&d) == DISK_OK);
    CHECK(M.nlog == before + 1);
    iolog *f = &M.log[before];
    CHECK(f->opc == 0x00 && f->nsid == 1 && f->prp1 == 0 && f->prp2 == 0);
    CHECK(f->cid != M.log[before - 1].cid);
    /* unflushed write, then power loss: the flushed data survives, the
     * unflushed data is gone (the model has a volatile write cache) */
    CHECK(disk_write(&d, 0, 64, b) == DISK_OK);
    CHECK(disk_read(&d, 0, 64, r) == DISK_OK && memcmp(r, b, sizeof r) == 0);
    model_power_loss();
    CHECK(init_default() == NVME_OK); /* reopen */
    CHECK(nvme_disk(&C, &d) == DISK_OK);
    CHECK(disk_read(&d, 0, 64, r) == DISK_OK && memcmp(r, a, sizeof r) == 0);
    /* write + flush + disable + re-init: data intact */
    CHECK(disk_write(&d, 0, 64, b) == DISK_OK && disk_flush(&d) == DISK_OK);
    CHECK(nvme_disable(&C) == NVME_OK);
    CHECK(M.csts == 0 && !(M.cc & 1));
    CHECK(nvme_read(&C, 0, 1, r) == NVME_ESTATE); /* disabled: no I/O */
    model_power_loss();
    CHECK(init_default() == NVME_OK);
    CHECK(nvme_read(&C, 0, 64, r) == NVME_OK && memcmp(r, b, sizeof r) == 0);
    CHECK(M.protocol_errors == 0);
}

static void test_lbads(void)
{
    for (int l = 0; l < 32; l++) {
        model_reset();
        M.lbads = (uint8_t)l;
        M.nsze = 64;
        if (l >= 9 && l <= 12)
            model_alloc_media();
        else
            M.media = calloc(1, 1), M.cache = calloc(1, 1), M.dirty = calloc(1, 64);
        int rc = init_default();
        if (l == 9 || l == 12)
            CHECK(rc == NVME_OK);
        else
            CHECK(rc == NVME_ELBADS);
    }
}

static void test_cap_checks(void)
{
    /* MPSMIN > 0 (controller needs 8 KiB pages) */
    model_reset();
    M.cap |= 1ull << 48;
    CHECK(init_default() == NVME_EMPS);
    CHECK(M.cc == 0); /* refused before touching CC */
    model_reset();
    M.cap |= 15ull << 48;
    CHECK(init_default() == NVME_EMPS);

    /* MQES too small for the 8-entry admin queue */
    model_reset();
    M.cap = (M.cap & ~0xffffull) | 3;
    CHECK(init_default() == NVME_EMQES);
    CHECK(init_with(0, 2) == NVME_EMQES); /* I/O depth 2 fits: the admin check must refuse */
    /* MQES 7: admin fits, I/O depth 16 does not, depth 8 does */
    model_reset();
    M.cap = (M.cap & ~0xffffull) | 7;
    CHECK(init_with(0, 16) == NVME_EMQES);
    CHECK(init_with(0, 8) == NVME_OK);
    CHECK(M.iosq_size == 8);
    CHECK(init_with(0, 1) == NVME_EARG);
    CHECK(init_with(0, NVME_IO_DEPTH_MAX + 1) == NVME_EARG);

    /* CSS without the NVM command set */
    model_reset();
    M.cap &= ~(1ull << 37);
    M.cap |= 1ull << 44;
    CHECK(init_default() == NVME_ECSS);

    /* VS major version */
    model_reset();
    M.vs = 0x00000100;
    CHECK(init_default() == NVME_EVS);
    model_reset();
    M.vs = 0x00030000;
    CHECK(init_default() == NVME_EVS);
    model_reset();
    M.vs = 0x00020000;
    CHECK(init_default() == NVME_OK);
    model_reset();
    M.vs = 0x00010000;
    CHECK(init_default() == NVME_OK);

    /* SQES / CQES */
    model_reset();
    M.sqes = 0x77;
    CHECK(init_default() == NVME_EQES);
    model_reset();
    M.sqes = 0x55;
    CHECK(init_default() == NVME_EQES);
    model_reset();
    M.cqes = 0x55;
    CHECK(init_default() == NVME_EQES);
    model_reset();
    M.cqes = 0x33;
    CHECK(init_default() == NVME_EQES);
    model_reset();
    M.sqes = 0xf6;
    M.cqes = 0xf4;
    CHECK(init_default() == NVME_OK);

    /* DSTRD = 2: doorbells 16 bytes apart */
    model_reset();
    M.cap |= 2ull << 32;
    CHECK(init_default() == NVME_OK);
    uint8_t w[4096], r[4096];
    fill(w, sizeof w, 9);
    CHECK(nvme_write(&C, 3, 8, w) == NVME_OK && nvme_read(&C, 3, 8, r) == NVME_OK);
    CHECK(memcmp(w, r, sizeof w) == 0);
    CHECK(C.io.sq_db == 0x1000 + 2 * 16 && C.io.cq_db == 0x1000 + 3 * 16);
    CHECK(M.protocol_errors == 0);
}

static void test_readiness_timeouts(void)
{
    /* CAP.TO = 1: never ready gives up after exactly 500 ms of delay */
    model_reset();
    M.never_ready = 1;
    CHECK(init_default() == NVME_ETIMEOUT);
    CHECK(M.delay_total == 500000);
    CHECK(C.failed == 1);
    /* CAP.TO = 0 is treated as 500 ms */
    model_reset();
    M.cap &= ~(0xffull << 24);
    M.never_ready = 1;
    CHECK(init_default() == NVME_ETIMEOUT);
    CHECK(M.delay_total == 500000);
    /* CAP.TO = 4: 2 s */
    model_reset();
    M.cap = (M.cap & ~(0xffull << 24)) | (4ull << 24);
    M.never_ready = 1;
    CHECK(init_default() == NVME_ETIMEOUT);
    CHECK(M.delay_total == 2000000);
    /* ready after 200 polls (~200 ms): succeeds, a fixed short budget would not */
    model_reset();
    M.ready_after_reads = 200;
    CHECK(init_default() == NVME_OK);
    CHECK(M.delay_total >= 200000 && M.delay_total <= 201000);
    /* CSTS.CFS during enable */
    model_reset();
    M.cfs_on_enable = 1;
    CHECK(init_default() == NVME_ECFS);
    CHECK(M.delay_total == 0);
}

static void test_completion_faults(void)
{
    uint8_t buf[4096];
    fill(buf, sizeof buf, 4);

    /* phase tag never flips: bounded timeout, then fail-stop */
    model_reset();
    CHECK(init_default() == NVME_OK);
    uint64_t d0 = M.delay_total;
    M.stuck = 1;
    CHECK(nvme_write(&C, 0, 1, buf) == NVME_ETIMEOUT);
    uint64_t waited = M.delay_total - d0;
    CHECK(waited >= 1000000 && waited <= 1000020); /* max(1000 ms, CAP.TO) */
    CHECK(C.failed == 1);
    M.stuck = 0;
    int n = M.nlog;
    CHECK(nvme_write(&C, 0, 1, buf) == NVME_ESTATE);
    CHECK(nvme_read(&C, 0, 1, buf) == NVME_ESTATE);
    CHECK(nvme_flush(&C) == NVME_ESTATE);
    CHECK(M.nlog == n); /* nothing reached the device */
    disk_dev dd;
    CHECK(nvme_disk(&C, &dd) == DISK_ESTATE);
    CHECK(init_default() == NVME_OK); /* re-init recovers */
    CHECK(nvme_write(&C, 0, 1, buf) == NVME_OK);

    /* stuck admin queue during init */
    model_reset();
    M.stuck = 1;
    CHECK(init_default() == NVME_ETIMEOUT);

    /* CSTS.CFS while waiting for a completion: stops at once, not at timeout */
    model_reset();
    CHECK(init_default() == NVME_OK);
    d0 = M.delay_total;
    M.stuck = 1;
    M.cfs_on_stuck = 1;
    CHECK(nvme_read(&C, 0, 1, buf) == NVME_ECFS);
    CHECK(M.delay_total - d0 < 1000);
    CHECK(C.failed == 1);

    /* wrong SQID in the completion */
    model_reset();
    CHECK(init_default() == NVME_OK);
    M.bad_sqid = 1;
    CHECK(nvme_write(&C, 0, 1, buf) == NVME_ESQID);
    CHECK(C.failed == 1);
    model_reset();
    M.bad_sqid = 1;
    CHECK(init_default() == NVME_ESQID); /* admin queue too */

    /* wrong CID */
    model_reset();
    CHECK(init_default() == NVME_OK);
    M.bad_cid = 1;
    CHECK(nvme_read(&C, 0, 1, buf) == NVME_ECID);
    CHECK(C.failed == 1);
    model_reset();
    M.bad_cid = 1;
    CHECK(init_default() == NVME_ECID);

    /* error status: surfaced, queue stays usable */
    model_reset();
    CHECK(init_default() == NVME_OK);
    disk_dev d;
    CHECK(nvme_disk(&C, &d) == DISK_OK);
    M.inject_sc = 0x06; /* internal error */
    CHECK(disk_write(&d, 0, 1, buf) == DISK_EIO);
    CHECK(C.failed == 0);
    M.inject_sc = 0x281; /* SCT 2 (media error) */
    CHECK(disk_flush(&d) == DISK_EIO);
    CHECK(disk_write(&d, 0, 1, buf) == DISK_OK);
    CHECK(disk_flush(&d) == DISK_OK);

    /* I/O CQ wrap-around with the minimum depth of 2: phase flips */
    model_reset();
    CHECK(init_with(0, 2) == NVME_OK);
    for (int i = 0; i < 9; i++) {
        uint8_t r[512];
        buf[0] = (uint8_t)i;
        CHECK(nvme_write(&C, (uint64_t)i, 1, buf) == NVME_OK);
        CHECK(nvme_read(&C, (uint64_t)i, 1, r) == NVME_OK && r[0] == (uint8_t)i);
    }
    CHECK(M.last_cq_db[1] == 0); /* 18 completions on depth 2 */
    CHECK(M.protocol_errors == 0);
}

static void test_namespace(void)
{
    uint8_t buf[512] = {1};
    /* empty active namespace list */
    model_reset();
    M.active_nsid = 0;
    CHECK(init_default() == NVME_ENSID);
    /* CNS 02h unsupported */
    model_reset();
    M.cns2_unsupported = 1;
    CHECK(init_default() == NVME_ENSID);
    /* active NSID 3 is discovered and used for I/O and flush */
    model_reset();
    M.nn = 4;
    M.active_nsid = 3;
    CHECK(init_default() == NVME_OK);
    CHECK(C.nsid == 3);
    CHECK(nvme_write(&C, 0, 1, buf) == NVME_OK && nvme_flush(&C) == NVME_OK);
    CHECK(M.log[0].nsid == 3 && M.log[1].nsid == 3);
    /* caller NSID above NN */
    model_reset();
    CHECK(init_with(5, 0) == NVME_ENSID);
    /* caller NSID that is not active: identify fails */
    model_reset();
    M.nn = 4;
    M.active_nsid = 3;
    CHECK(init_with(2, 0) == NVME_ENSID);
    CHECK(init_with(3, 0) == NVME_OK);
    /* active list names an NSID above NN */
    model_reset();
    M.nn = 1;
    M.active_nsid = 2;
    CHECK(init_default() == NVME_ENSID);
    /* NSZE 0 */
    model_reset();
    M.nsze = 0;
    M.media = calloc(1, 1), M.cache = calloc(1, 1), M.dirty = calloc(1, 1);
    CHECK(init_default() == NVME_ENSZE);
    /* FLBAS index above NLBAF, and the NVMe 2.0 upper index bits */
    model_reset();
    M.nlbaf = 1;
    M.flbas = 3;
    CHECK(init_default() == NVME_EFLBAS);
    model_reset();
    M.nlbaf = 1;
    M.flbas = 1;
    CHECK(init_default() == NVME_OK);
    model_reset();
    M.nlbaf = 15;
    M.flbas = 0x20;
    CHECK(init_default() == NVME_EFLBAS);
    model_reset();
    M.nlbaf = 15;
    M.flbas = 0x1f; /* bit 4 (extended LBA) with format 15, no metadata */
    CHECK(init_default() == NVME_OK);
    /* metadata in the LBA format */
    model_reset();
    M.ms = 8;
    CHECK(init_default() == NVME_EMETA);
}

static void test_mdts_and_range(void)
{
    static uint8_t w[64 * 512], r[64 * 512];
    model_reset();
    M.mdts = 1; /* 8 KiB per command */
    CHECK(init_default() == NVME_OK);
    CHECK(C.max_xfer_bytes == 8192);
    disk_dev d;
    CHECK(nvme_disk(&C, &d) == DISK_OK && d.max_blocks_per_io == 16);
    fill(w, sizeof w, 5);
    CHECK(disk_write(&d, 7, 64, w) == DISK_OK);
    CHECK(M.nlog == 4);
    for (int i = 0; i < 4; i++)
        CHECK(M.log[i].lba == 7u + 16u * (unsigned)i && M.log[i].nlb == 16);
    CHECK(disk_read(&d, 7, 64, r) == DISK_OK && memcmp(w, r, sizeof w) == 0);
    CHECK(nvme_write(&C, 0, 17, w) == NVME_ERANGE); /* above max transfer */

    model_reset();
    M.mdts = 255; /* huge shift must not overflow */
    CHECK(init_default() == NVME_OK && C.max_xfer_bytes == 128 * 1024);
    model_reset();
    M.mdts = 5; /* 128 KiB exactly */
    CHECK(init_default() == NVME_OK && C.max_xfer_bytes == 128 * 1024);

    /* range checks never reach the device */
    model_reset();
    CHECK(init_default() == NVME_OK);
    int n = M.nlog, db = M.doorbells;
    CHECK(nvme_write(&C, 4096, 1, w) == NVME_ERANGE);
    CHECK(nvme_write(&C, 4095, 2, w) == NVME_ERANGE);
    CHECK(nvme_read(&C, UINT64_MAX, 1, r) == NVME_ERANGE);
    CHECK(nvme_read(&C, 5000, 1, r) == NVME_ERANGE);
    CHECK(nvme_read(&C, 0, 0, r) == NVME_EARG);
    CHECK(nvme_read(&C, 0, 1, NULL) == NVME_EARG);
    CHECK(nvme_write(&C, 0, 257, w) == NVME_ERANGE);
    CHECK(M.nlog == n && M.doorbells == db);
    CHECK(nvme_write(&C, 4095, 1, w) == NVME_OK);
}

static void test_dma_args(void)
{
    model_reset();
    model_alloc_media();
    nvme_dma d = {dma_mem, PHYS_BASE + 8, DMA_BYTES};
    CHECK(nvme_init(&C, &OPS, &d, NULL) == NVME_EARG);
    d.phys = PHYS_BASE;
    d.bytes = NVME_DMA_MIN_BYTES - 1;
    CHECK(nvme_init(&C, &OPS, &d, NULL) == NVME_EARG);
    d.bytes = DMA_BYTES;
    d.virt = NULL;
    CHECK(nvme_init(&C, &OPS, &d, NULL) == NVME_EARG);
    d.virt = dma_mem;
    d.phys = 0xfffffffffffff000ull;
    CHECK(nvme_init(&C, &OPS, &d, NULL) == NVME_EARG);
    nvme_ops bad = OPS;
    bad.delay_us = NULL;
    d.phys = PHYS_BASE;
    CHECK(nvme_init(&C, &bad, &d, NULL) == NVME_EARG);
    CHECK(M.cc == 0);
    /* smallest region: one bounce page -> 4 KiB transfers */
    d.bytes = NVME_DMA_MIN_BYTES;
    CHECK(nvme_init(&C, &OPS, &d, NULL) == NVME_OK);
    CHECK(C.max_xfer_bytes == 4096);
    /* not initialized */
    nvme_ctrl z;
    memset(&z, 0, sizeof z);
    disk_dev dd;
    uint8_t b[512];
    CHECK(nvme_disk(&z, &dd) == DISK_ESTATE);
    CHECK(nvme_read(&z, 0, 1, b) == NVME_ESTATE);
    CHECK(nvme_write_is_power_fail_atomic(&z, 0, 1) == NVME_ATOMIC_UNKNOWN);
}

static void test_prps(void)
{
    uint64_t list[1100], p1, p2;
    uint32_t used;
    CHECK(nvme_build_prps(0x1000, 0, 4096, 0x8000, list, 4, &p1, &p2, &used) == NVME_EARG);
    CHECK(nvme_build_prps(0x1000, 10, 0, 0x8000, list, 4, &p1, &p2, &used) == NVME_EARG);
    CHECK(nvme_build_prps(0x1000, 10, 3000, 0x8000, list, 4, &p1, &p2, &used) == NVME_EARG);
    /* offset + length overflow */
    CHECK(nvme_build_prps(0x1fff, UINT64_MAX - 10, 4096, 0x8000, list, 4, &p1, &p2, &used) == NVME_EARG);
    /* address near the top: second page would wrap */
    CHECK(nvme_build_prps(UINT64_MAX - 100, 200, 4096, 0x8000, list, 4, &p1, &p2, &used) == NVME_EARG);
    CHECK(nvme_build_prps(UINT64_MAX - 100, 50, 4096, 0x8000, list, 4, &p1, &p2, &used) == NVME_OK);
    /* single page, aligned and unaligned */
    CHECK(nvme_build_prps(0x1000, 4096, 4096, 0, list, 0, &p1, &p2, &used) == NVME_OK &&
          p1 == 0x1000 && p2 == 0 && used == 0);
    CHECK(nvme_build_prps(0x1080, 100, 4096, 0, list, 0, &p1, &p2, &used) == NVME_OK &&
          p1 == 0x1080 && p2 == 0);
    /* crossing one boundary uses PRP2 */
    CHECK(nvme_build_prps(0x1080, 4096, 4096, 0, list, 0, &p1, &p2, &used) == NVME_OK &&
          p1 == 0x1080 && p2 == 0x2000 && used == 0);
    CHECK(nvme_build_prps(0x1000, 8192, 4096, 0, list, 0, &p1, &p2, &used) == NVME_OK && p2 == 0x2000);
    /* three pages need a list, which must be aligned and non-zero */
    CHECK(nvme_build_prps(0x1080, 9000, 4096, 0, list, 4, &p1, &p2, &used) == NVME_EARG);
    CHECK(nvme_build_prps(0x1080, 9000, 4096, 0x8008, list, 4, &p1, &p2, &used) == NVME_EARG);
    CHECK(nvme_build_prps(0x1080, 9000, 4096, 0x8000, list, 4, &p1, &p2, &used) == NVME_OK &&
          p1 == 0x1080 && p2 == 0x8000 && used == 2 && list[0] == 0x2000 && list[1] == 0x3000);
    /* list too small is refused, not overrun */
    CHECK(nvme_build_prps(0x1000, 12000, 4096, 0x8000, list, 1, &p1, &p2, &used) == NVME_ERANGE);
    /* chaining at 4 KiB pages: 1 + 512 data pages fit one list page exactly */
    uint64_t L = 0x800000;
    CHECK(nvme_build_prps(0x1000, 513ull * 4096, 4096, L, list, 1024, &p1, &p2, &used) == NVME_OK &&
          used == 512 && list[511] == 0x2000 + 511ull * 4096);
    CHECK(nvme_build_prps(0x1000, 514ull * 4096, 4096, L, list, 1024, &p1, &p2, &used) == NVME_OK &&
          used == 514 && list[511] == L + 4096 && list[510] == 0x2000 + 510ull * 4096 &&
          list[512] == 0x2000 + 511ull * 4096 && list[513] == 0x2000 + 512ull * 4096);
    CHECK(nvme_build_prps(0x1000, 514ull * 4096, 4096, L, list, 512, &p1, &p2, &used) == NVME_ERANGE);
    /* 64 KiB pages: 8192 entries per list page */
    static uint64_t big[8200];
    uint64_t P = 65536;
    CHECK(nvme_build_prps(0x10000, (2 + 8192ull) * P, P, 0x40000000, big, 8200, &p1, &p2, &used) == NVME_OK &&
          used == 8194 && big[8191] == 0x40000000 + P && big[8192] == 0x20000 + 8191 * P);
    /* PRP values are full 64-bit addresses */
    CHECK(nvme_build_prps(0x123456789000ull, 3 * 4096, 4096, 0xabc000000000ull, list, 4, &p1, &p2, &used) == NVME_OK &&
          p1 == 0x123456789000ull && p2 == 0xabc000000000ull && list[0] == 0x12345678a000ull &&
          list[1] == 0x12345678b000ull);
}

static void test_atomicity(void)
{
    model_reset();
    M.awupf = 7;  /* 8 blocks */
    M.nawupf = 3; /* 4 blocks: namespace value wins */
    M.nabspf = 7; /* boundary every 8 blocks */
    CHECK(init_default() == NVME_OK);
    CHECK(C.awupf_raw == 7 && C.nawupf_raw == 3 && C.nabspf_raw == 7 && C.nabo_blocks == 0);
    CHECK(nvme_write_is_power_fail_atomic(&C, 0, 0) == NVME_NOT_ATOMIC);
    CHECK(nvme_write_is_power_fail_atomic(&C, 0, 4) == NVME_ATOMIC);
    CHECK(nvme_write_is_power_fail_atomic(&C, 0, 5) == NVME_NOT_ATOMIC);
    CHECK(nvme_write_is_power_fail_atomic(&C, 8, 8) == NVME_NOT_ATOMIC); /* store unit slot 1 */
    CHECK(nvme_write_is_power_fail_atomic(&C, 6, 4) == NVME_NOT_ATOMIC); /* crosses 8 */
    CHECK(nvme_write_is_power_fail_atomic(&C, 4, 4) == NVME_ATOMIC);
    model_reset();
    M.awupf = 7;
    M.nawupf = 0; /* controller value applies */
    CHECK(init_default() == NVME_OK);
    CHECK(nvme_write_is_power_fail_atomic(&C, 0, 8) == NVME_ATOMIC);
    CHECK(nvme_write_is_power_fail_atomic(&C, 3, 8) == NVME_ATOMIC); /* no boundary */
    CHECK(nvme_write_is_power_fail_atomic(&C, 0, 9) == NVME_NOT_ATOMIC);
    model_reset();
    M.awupf = 15;
    M.nabspf = 3; /* boundary 4 */
    M.nabo = 2;
    CHECK(init_default() == NVME_OK);
    CHECK(nvme_write_is_power_fail_atomic(&C, 0, 2) == NVME_ATOMIC);
    CHECK(nvme_write_is_power_fail_atomic(&C, 0, 3) == NVME_NOT_ATOMIC);
    CHECK(nvme_write_is_power_fail_atomic(&C, 2, 4) == NVME_ATOMIC);
    CHECK(nvme_write_is_power_fail_atomic(&C, 3, 4) == NVME_NOT_ATOMIC);
    model_reset();
    M.awupf = 0xffff;
    M.nabspf = 0xffff; /* 65536-block boundary: no division by zero */
    M.nabo = 5;
    CHECK(init_default() == NVME_OK);
    CHECK(nvme_write_is_power_fail_atomic(&C, 5, 65536) == NVME_ATOMIC);
    CHECK(nvme_write_is_power_fail_atomic(&C, 4, 2) == NVME_NOT_ATOMIC);
}

int main(void)
{
    dma_mem = aligned_alloc(4096, DMA_BYTES);
    if (!dma_mem)
        return 2;
    test_init_ok();
    test_roundtrip(9);
    test_roundtrip(12);
    test_flush_and_reopen();
    test_lbads();
    test_cap_checks();
    test_readiness_timeouts();
    test_completion_faults();
    test_namespace();
    test_mdts_and_range();
    test_dma_args();
    test_prps();
    test_atomicity();
    printf("nvme_test: %d checks, %d failures\n", checks, failures);
    free(M.media);
    free(M.cache);
    free(M.dirty);
    free(dma_mem);
    return failures ? 1 : 0;
}
