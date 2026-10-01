/*
 * disk_nvme.c -- freestanding polled NVMe driver (see disk_nvme.h).
 * No libc, no heap, no clock: platform access only through nvme_ops.
 * Assumes a little-endian CPU (NVMe structures are little-endian).
 */
#include "disk_nvme.h"

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "disk_nvme.c assumes a little-endian CPU"
#endif

#define CC_EN 1u
#define CC_IOSQES_64 (6u << 16)
#define CC_IOCQES_16 (4u << 20)
#define CSTS_RDY 1u
#define CSTS_CFS 2u
#define POLL_STEP_US 10u
#define SQE_BYTES 64u
#define CQE_BYTES 16u

/* ---- small freestanding helpers (volatile so the compiler cannot turn them
 * into memset/memcpy calls) ---- */

static void zero_bytes(uint8_t *p, uint64_t n)
{
    volatile uint8_t *q = p;
    while (n--)
        *q++ = 0;
}

static void copy_bytes(uint8_t *d, const uint8_t *s, uint64_t n)
{
    volatile uint8_t *q = d;
    const volatile uint8_t *r = s;
    while (n--)
        *q++ = *r++;
}

static uint16_t ld16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t ld32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t ld64(const uint8_t *p)
{
    return (uint64_t)ld32(p) | ((uint64_t)ld32(p + 4) << 32);
}

static uint32_t rd32(nvme_ctrl *c, uint32_t off)
{
    return c->ops.read32(c->ops.ctx, off);
}

static void wr32(nvme_ctrl *c, uint32_t off, uint32_t v)
{
    c->ops.write32(c->ops.ctx, off, v);
}

static uint64_t rd64(nvme_ctrl *c, uint32_t off)
{
    if (c->ops.read64)
        return c->ops.read64(c->ops.ctx, off);
    uint64_t lo = rd32(c, off);
    return lo | ((uint64_t)rd32(c, off + 4) << 32);
}

static void wr64(nvme_ctrl *c, uint32_t off, uint64_t v)
{
    if (c->ops.write64) {
        c->ops.write64(c->ops.ctx, off, v);
        return;
    }
    wr32(c, off, (uint32_t)v);
    wr32(c, off + 4, (uint32_t)(v >> 32));
}

static void barrier(nvme_ctrl *c)
{
    c->ops.barrier(c->ops.ctx);
}

static int fail(nvme_ctrl *c, int err)
{
    c->failed = 1;
    c->last_err = err;
    return err;
}

/* Wait for CSTS.RDY == want. Reads CSTS, then delays 1 ms, at most
 * timeout_ms delays in total: the bound is exactly CAP.TO (P2 audit fix). */
static int wait_ready(nvme_ctrl *c, int want)
{
    for (uint32_t i = 0;; i++) {
        uint32_t s = rd32(c, NVME_REG_CSTS);
        if (s & CSTS_CFS) return NVME_ECFS; /* GUARD:nvme-cfs-ready */
        if (((s & CSTS_RDY) != 0) == (want != 0))
            return NVME_OK;
        if (i >= c->timeout_ms) return NVME_ETIMEOUT; /* GUARD:nvme-ready-bound */
        c->ops.delay_us(c->ops.ctx, 1000);
    }
}

/* ---- queue pair submission and polled completion ---- */

static void qpair_setup(nvme_ctrl *c, nvme_qpair *q, uint16_t sqid, uint16_t depth, uint8_t *sq,
                        uint64_t sq_phys, uint8_t *cq, uint64_t cq_phys)
{
    q->tail = 0;
    q->head = 0;
    q->depth = depth;
    q->sqid = sqid;
    q->phase = 1;
    q->sq = sq;
    q->cq = cq;
    q->sq_phys = sq_phys;
    q->cq_phys = cq_phys;
    q->sq_db = NVME_REG_DOORBELL + (2u * sqid) * c->dstrd_stride;
    q->cq_db = NVME_REG_DOORBELL + (2u * sqid + 1u) * c->dstrd_stride;
}

/* Submit one command (16 dwords; CID is filled in) and poll for its
 * completion. Returns NVME_OK, NVME_ESTATUS (queue still usable), or a
 * fail-stop error. */
static int submit(nvme_ctrl *c, nvme_qpair *q, uint32_t *sqe, uint32_t *result)
{
    if (c->failed)
        return NVME_ESTATE;
    uint16_t cid = c->next_cid++;
    sqe[0] = (sqe[0] & 0xffffu) | ((uint32_t)cid << 16);
    volatile uint32_t *slot = (volatile uint32_t *)(q->sq + (uint64_t)q->tail * SQE_BYTES);
    for (int i = 0; i < 16; i++)
        slot[i] = sqe[i];
    barrier(c); /* command and data visible before the doorbell */
    q->tail = (uint16_t)((q->tail + 1u) % q->depth);
    wr32(c, q->sq_db, q->tail);

    volatile uint32_t *cqe = (volatile uint32_t *)(q->cq + (uint64_t)q->head * CQE_BYTES);
    uint64_t budget = (uint64_t)c->cmd_timeout_ms * (1000u / POLL_STEP_US);
    uint32_t dw3;
    for (uint64_t i = 0;; i++) {
        barrier(c);
        dw3 = cqe[3];
        if (((dw3 >> 16) & 1u) == q->phase)
            break;
        if (rd32(c, NVME_REG_CSTS) & CSTS_CFS) return fail(c, NVME_ECFS); /* GUARD:nvme-cfs-cmd */
        if (i >= budget) return fail(c, NVME_ETIMEOUT); /* GUARD:nvme-cmd-bound */
        c->ops.delay_us(c->ops.ctx, POLL_STEP_US);
    }
    barrier(c); /* completion seen before reading its fields or data */
    uint32_t dw0 = cqe[0];
    uint32_t dw2 = cqe[2];
    q->head = (uint16_t)(q->head + 1u);
    if (q->head == q->depth) {
        q->head = 0;
        q->phase ^= 1u;
    }
    wr32(c, q->cq_db, q->head);
    if ((dw3 & 0xffffu) != cid) return fail(c, NVME_ECID); /* GUARD:nvme-cid */
    if ((dw2 >> 16) != q->sqid) return fail(c, NVME_ESQID); /* GUARD:nvme-sqid */
    if ((dw3 >> 17) & 0x7ffu) { /* SC (bits 24:17) and SCT (27:25) */
        c->last_err = NVME_ESTATUS;
        return NVME_ESTATUS;
    }
    if (result)
        *result = dw0;
    return NVME_OK;
}

static void sqe_clear(uint32_t *sqe)
{
    for (int i = 0; i < 16; i++)
        sqe[i] = 0;
}

static int identify(nvme_ctrl *c, uint32_t cns, uint32_t nsid)
{
    uint32_t sqe[16];
    zero_bytes(c->identify, NVME_PAGE);
    sqe_clear(sqe);
    sqe[0] = 0x06;
    sqe[1] = nsid;
    sqe[6] = (uint32_t)c->identify_phys;
    sqe[7] = (uint32_t)(c->identify_phys >> 32);
    sqe[10] = cns;
    return submit(c, &c->admin, sqe, 0);
}

/* ---- init ---- */

int nvme_init(nvme_ctrl *c, const nvme_ops *ops, const nvme_dma *dma, const nvme_config *cfg)
{
    if (!c || !ops || !dma || !ops->read32 || !ops->write32 || !ops->barrier || !ops->delay_us)
        return NVME_EARG;
    zero_bytes((uint8_t *)c, sizeof *c);
    /* field by field: a struct copy may become a memcpy call (e.g. -mstrict-align) */
    c->ops.ctx = ops->ctx;
    c->ops.read32 = ops->read32;
    c->ops.write32 = ops->write32;
    c->ops.read64 = ops->read64;
    c->ops.write64 = ops->write64;
    c->ops.barrier = ops->barrier;
    c->ops.delay_us = ops->delay_us;
    c->last_err = NVME_EARG;
    uint32_t want_nsid = cfg ? cfg->nsid : 0;
    uint16_t io_depth = (cfg && cfg->io_depth) ? cfg->io_depth : NVME_IO_DEPTH_DEFAULT;
    if (io_depth < 2 || io_depth > NVME_IO_DEPTH_MAX)
        return NVME_EARG;
    if (!dma->virt || ((uintptr_t)dma->virt & (NVME_PAGE - 1)) || (dma->phys & (NVME_PAGE - 1)) || dma->bytes < NVME_DMA_MIN_BYTES)
        return NVME_EARG;
    if (dma->phys + dma->bytes < dma->phys) /* bus address wraps */
        return NVME_EARG;
    c->dma.virt = dma->virt;
    c->dma.phys = dma->phys;
    c->dma.bytes = dma->bytes;

    c->cap = rd64(c, NVME_REG_CAP);
    c->vs = rd32(c, NVME_REG_VS);
    uint32_t major = c->vs >> 16;
    if (major < 1 || major > 2) return c->last_err = NVME_EVS; /* GUARD:nvme-vs */
    /* MPSMIN == 0 means 4 KiB is the minimum page; MPSMAX >= 0 always holds,
     * so 4 KiB is then within [MPSMIN, MPSMAX]. */
    if ((c->cap >> 48) & 0xfu) return c->last_err = NVME_EMPS; /* GUARD:nvme-mpsmin */
    uint32_t mqes1 = (uint32_t)(c->cap & 0xffffu) + 1u;
    if (NVME_ADMIN_DEPTH > mqes1) return c->last_err = NVME_EMQES; /* GUARD:nvme-mqes-admin */
    if (io_depth > mqes1) return c->last_err = NVME_EMQES; /* GUARD:nvme-mqes-io */
    if (!((c->cap >> 37) & 1u)) return c->last_err = NVME_ECSS; /* GUARD:nvme-css */
    uint32_t to = (uint32_t)((c->cap >> 24) & 0xffu);
    c->timeout_ms = (to ? to : 1u) * 500u;
    c->cmd_timeout_ms = c->timeout_ms > 1000u ? c->timeout_ms : 1000u;
    c->dstrd_stride = 4u << ((c->cap >> 32) & 0xfu);

    /* Reset: clear EN, wait for RDY = 0. */
    uint32_t cc = rd32(c, NVME_REG_CC);
    wr32(c, NVME_REG_CC, cc & ~CC_EN);
    int rc = wait_ready(c, 0);
    if (rc)
        return c->last_err = rc;

    /* Carve the DMA region. */
    uint8_t *v = dma->virt;
    uint64_t p = dma->phys;
    uint8_t *asq = v, *acq = v + NVME_PAGE, *iosq = v + 3 * NVME_PAGE, *iocq = v + 4 * NVME_PAGE;
    c->identify = v + 2 * NVME_PAGE;
    c->identify_phys = p + 2 * NVME_PAGE;
    c->prp_list = v + 5 * NVME_PAGE;
    c->prp_list_phys = p + 5 * NVME_PAGE;
    c->bounce = v + NVME_FIXED_PAGES * NVME_PAGE;
    c->bounce_phys = p + NVME_FIXED_PAGES * NVME_PAGE;
    c->bounce_bytes = (dma->bytes - NVME_FIXED_PAGES * NVME_PAGE) & ~(uint64_t)(NVME_PAGE - 1);
    zero_bytes(v, NVME_FIXED_PAGES * NVME_PAGE);
    barrier(c);

    qpair_setup(c, &c->admin, 0, NVME_ADMIN_DEPTH, asq, p, acq, p + NVME_PAGE);
    wr32(c, NVME_REG_AQA, ((NVME_ADMIN_DEPTH - 1u) << 16) | (NVME_ADMIN_DEPTH - 1u));
    wr64(c, NVME_REG_ASQ, c->admin.sq_phys);
    wr64(c, NVME_REG_ACQ, c->admin.cq_phys);
    /* CSS = 0 (NVM), MPS = 0 (4 KiB), AMS = 0 (round robin, mandatory). */
    wr32(c, NVME_REG_CC, CC_IOSQES_64 | CC_IOCQES_16 | CC_EN);
    rc = wait_ready(c, 1);
    if (rc)
        return fail(c, rc);
    c->next_cid = 1;

    /* Identify Controller (CNS 01h). */
    if ((rc = identify(c, 1, 0)) != NVME_OK)
        return fail(c, rc);
    const uint8_t *id = c->identify;
    barrier(c);
    uint8_t sqes = id[512], cqes = id[513];
    if ((sqes & 0xf) > 6 || (sqes >> 4) < 6) return fail(c, NVME_EQES); /* GUARD:nvme-sqes */
    if ((cqes & 0xf) > 4 || (cqes >> 4) < 4) return fail(c, NVME_EQES); /* GUARD:nvme-cqes */
    c->mdts = id[77];
    c->nn = ld32(id + 516);
    c->vwc = id[525] & 1u;
    c->awupf_raw = ld16(id + 528);

    /* Namespace: caller's, or the first active one (CNS 02h). */
    if (want_nsid == 0) {
        if ((rc = identify(c, 2, 0)) != NVME_OK)
            return fail(c, rc == NVME_ESTATUS ? NVME_ENSID : rc);
        barrier(c);
        want_nsid = ld32(c->identify);
    }
    if (want_nsid == 0 || want_nsid > c->nn) return fail(c, NVME_ENSID); /* GUARD:nvme-nsid */
    c->nsid = want_nsid;

    /* Identify Namespace (CNS 00h). */
    if ((rc = identify(c, 0, c->nsid)) != NVME_OK)
        return fail(c, rc == NVME_ESTATUS ? NVME_ENSID : rc);
    barrier(c);
    uint64_t nsze = ld64(id);
    uint8_t nlbaf = id[25], flbas = id[26];
    if (nsze == 0) return fail(c, NVME_ENSZE); /* GUARD:nvme-nsze */
    if ((flbas & 0x60) || (flbas & 0xf) > nlbaf) return fail(c, NVME_EFLBAS); /* GUARD:nvme-flbas */
    uint32_t lbaf = ld32(id + 128 + (flbas & 0xfu) * 4u);
    uint32_t lbads = (lbaf >> 16) & 0xffu;
    if (lbaf & 0xffffu) return fail(c, NVME_EMETA); /* GUARD:nvme-meta */
    if (lbads != 9 && lbads != 12) return fail(c, NVME_ELBADS); /* GUARD:nvme-lbads */
    c->block_size = 1u << lbads;
    c->block_count = nsze;
    c->nawupf_raw = ld16(id + 36);
    c->nabo_blocks = ld16(id + 42);
    c->nabspf_raw = ld16(id + 44);

    /* Transfer limit. */
    uint64_t lim = NVME_MAX_XFER;
    if (c->mdts && c->mdts < 20 && ((uint64_t)NVME_PAGE << c->mdts) < lim)
        lim = (uint64_t)NVME_PAGE << c->mdts;
    if (c->bounce_bytes < lim)
        lim = c->bounce_bytes;
    lim = lim / c->block_size * c->block_size;
    if (lim < c->block_size)
        return fail(c, NVME_EARG);
    c->max_xfer_bytes = (uint32_t)lim;

    /* I/O queue pair, QID 1: completion queue first (polled: PC=1, IEN=0). */
    qpair_setup(c, &c->io, 1, io_depth, iosq, p + 3 * NVME_PAGE, iocq, p + 4 * NVME_PAGE);
    uint32_t sqe[16];
    sqe_clear(sqe);
    sqe[0] = 0x05;
    sqe[6] = (uint32_t)c->io.cq_phys;
    sqe[7] = (uint32_t)(c->io.cq_phys >> 32);
    sqe[10] = 1u | ((uint32_t)(io_depth - 1u) << 16);
    sqe[11] = 1u;
    if ((rc = submit(c, &c->admin, sqe, 0)) != NVME_OK)
        return fail(c, rc);
    sqe_clear(sqe);
    sqe[0] = 0x01;
    sqe[6] = (uint32_t)c->io.sq_phys;
    sqe[7] = (uint32_t)(c->io.sq_phys >> 32);
    sqe[10] = 1u | ((uint32_t)(io_depth - 1u) << 16);
    sqe[11] = 1u | (1u << 16);
    if ((rc = submit(c, &c->admin, sqe, 0)) != NVME_OK)
        return fail(c, rc);
    c->ready = 1;
    c->last_err = NVME_OK;
    return NVME_OK;
}

int nvme_disable(nvme_ctrl *c)
{
    if (!c || !c->ops.read32)
        return NVME_EARG;
    c->ready = 0;
    wr32(c, NVME_REG_CC, rd32(c, NVME_REG_CC) & ~CC_EN);
    return wait_ready(c, 0);
}

/* ---- PRP construction (port of Rust build_prps) ---- */

int nvme_build_prps(uint64_t addr, uint64_t len, uint64_t page_size, uint64_t list_addr,
                    uint64_t *list, uint32_t list_cap, uint64_t *prp1, uint64_t *prp2,
                    uint32_t *used)
{
    if (!prp1 || !prp2 || !used)
        return NVME_EARG;
    if (len == 0 || page_size < 8 || (page_size & (page_size - 1)))
        return NVME_EARG;
    uint64_t off = addr & (page_size - 1);
    uint64_t covered = off + len;
    if (covered < off) return NVME_EARG; /* GUARD:prp-len-wrap */
    uint64_t pages = covered / page_size + ((covered % page_size) != 0);
    *prp1 = addr;
    *prp2 = 0;
    *used = 0;
    if (pages == 1)
        return NVME_OK;
    uint64_t second = (addr & ~(page_size - 1)) + page_size;
    if (second < addr) return NVME_EARG; /* GUARD:prp-addr-wrap */
    if (pages == 2) {
        *prp2 = second;
        return NVME_OK;
    }
    if (list_addr == 0 || (list_addr & (page_size - 1)) || !list)
        return NVME_EARG;
    uint64_t per = page_size / 8, count = pages - 1, data = 0, slot = 0;
    while (data < count) {
        if (slot >= list_cap) return NVME_ERANGE; /* GUARD:prp-list-cap */
        uint64_t e;
        if (slot % per == per - 1 && count - data > 1) {
            e = list_addr + (slot / per + 1) * page_size; /* chain to next list page */
            if (e < list_addr)
                return NVME_EARG;
        } else {
            e = second + data * page_size;
            if (e < second)
                return NVME_EARG;
            data++;
        }
        list[slot++] = e;
    }
    *prp2 = list_addr;
    *used = (uint32_t)slot;
    return NVME_OK;
}

/* ---- block I/O ---- */

static int check_io(nvme_ctrl *c, uint64_t lba, uint32_t count, const void *buf)
{
    if (!c)
        return NVME_EARG;
    if (!c->ready || c->failed) return NVME_ESTATE; /* GUARD:nvme-failstop */
    if (!buf || count == 0)
        return NVME_EARG;
    if ((uint64_t)count * c->block_size > c->max_xfer_bytes) return NVME_ERANGE; /* GUARD:nvme-xfer */
    if (lba >= c->block_count || count > c->block_count - lba) return NVME_ERANGE; /* GUARD:nvme-range */
    return NVME_OK;
}

static int rw(nvme_ctrl *c, uint32_t opc, uint64_t lba, uint32_t count)
{
    uint64_t bytes = (uint64_t)count * c->block_size, prp1, prp2;
    uint32_t used;
    int rc = nvme_build_prps(c->bounce_phys, bytes, NVME_PAGE, c->prp_list_phys,
                             (uint64_t *)(void *)c->prp_list, NVME_PAGE / 8, &prp1, &prp2, &used);
    if (rc)
        return rc;
    uint32_t sqe[16];
    sqe_clear(sqe);
    sqe[0] = opc;
    sqe[1] = c->nsid;
    sqe[6] = (uint32_t)prp1;
    sqe[7] = (uint32_t)(prp1 >> 32);
    sqe[8] = (uint32_t)prp2;
    sqe[9] = (uint32_t)(prp2 >> 32);
    sqe[10] = (uint32_t)lba;
    sqe[11] = (uint32_t)(lba >> 32);
    sqe[12] = count - 1u; /* NLB is 0-based */
    return submit(c, &c->io, sqe, 0);
}

int nvme_read(nvme_ctrl *c, uint64_t lba, uint32_t count, uint8_t *buf)
{
    int rc = check_io(c, lba, count, buf);
    if (rc)
        return rc;
    if ((rc = rw(c, 0x02, lba, count)) != NVME_OK)
        return rc;
    barrier(c);
    copy_bytes(buf, c->bounce, (uint64_t)count * c->block_size);
    return NVME_OK;
}

int nvme_write(nvme_ctrl *c, uint64_t lba, uint32_t count, const uint8_t *buf)
{
    int rc = check_io(c, lba, count, buf);
    if (rc)
        return rc;
    copy_bytes(c->bounce, buf, (uint64_t)count * c->block_size);
    return rw(c, 0x01, lba, count);
}

int nvme_flush(nvme_ctrl *c)
{
    if (!c)
        return NVME_EARG;
    if (!c->ready || c->failed)
        return NVME_ESTATE;
    uint32_t sqe[16];
    sqe_clear(sqe);
    sqe[0] = 0x00;
    sqe[1] = c->nsid;
    return submit(c, &c->io, sqe, 0);
}

/* ---- disk_dev backend ---- */

static int to_disk(int rc)
{
    switch (rc) {
    case NVME_OK: return DISK_OK;
    case NVME_ERANGE: return DISK_ERANGE;
    case NVME_EARG: return DISK_EARG;
    case NVME_ESTATE: return DISK_ESTATE;
    default: return DISK_EIO;
    }
}

static int d_read(void *ctx, uint64_t lba, uint32_t count, uint8_t *buf)
{
    return to_disk(nvme_read((nvme_ctrl *)ctx, lba, count, buf));
}

static int d_write(void *ctx, uint64_t lba, uint32_t count, const uint8_t *buf)
{
    return to_disk(nvme_write((nvme_ctrl *)ctx, lba, count, buf));
}

static int d_flush(void *ctx)
{
    return to_disk(nvme_flush((nvme_ctrl *)ctx));
}

int nvme_disk(nvme_ctrl *c, disk_dev *out)
{
    if (!c || !out)
        return DISK_EARG;
    if (!c->ready || c->failed)
        return DISK_ESTATE;
    out->ctx = c;
    out->block_size = c->block_size;
    out->block_count = c->block_count;
    out->read = d_read;
    out->write = d_write;
    out->flush = d_flush;
    out->max_blocks_per_io = c->max_xfer_bytes / c->block_size;
    return disk_check(out);
}

/* ---- power-fail atomicity (port of atomicity.rs) ---- */

int nvme_write_is_power_fail_atomic(const nvme_ctrl *c, uint64_t start_lba, uint64_t lba_count)
{
    if (!c || !c->ready)
        return NVME_ATOMIC_UNKNOWN;
    if (lba_count == 0)
        return NVME_NOT_ATOMIC;
    uint64_t unit = c->nawupf_raw ? (uint64_t)c->nawupf_raw + 1 : (uint64_t)c->awupf_raw + 1;
    if (lba_count > unit) return NVME_NOT_ATOMIC; /* GUARD:atomic-unit */
    if (c->nabspf_raw) {
        uint64_t size = (uint64_t)c->nabspf_raw + 1, off = c->nabo_blocks % size;
        uint64_t end = start_lba + lba_count - 1;
        if (end < start_lba)
            return NVME_NOT_ATOMIC;
        /* region index shifted by one so blocks before the offset are region 0 */
        uint64_t r0 = start_lba < off ? 0 : (start_lba - off) / size + 1;
        uint64_t r1 = end < off ? 0 : (end - off) / size + 1;
        if (r0 != r1) return NVME_NOT_ATOMIC; /* GUARD:atomic-boundary */
    }
    return NVME_ATOMIC;
}
