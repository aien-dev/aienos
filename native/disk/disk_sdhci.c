/* disk_sdhci.c -- AIENOS freestanding SD card driver over SDHCI; see
 * disk_sdhci.h for the contract, sources and refusals. No libc. */
#include "disk_sdhci.h"

/* PRESENT_STATE */
#define PS_CMD_INHIBIT 0x00000001u
#define PS_DATA_INHIBIT 0x00000002u
#define PS_CARD_PRESENT 0x00010000u
/* INT_STATUS */
#define INT_CMD_DONE 0x00000001u
#define INT_XFER_DONE 0x00000002u
#define INT_BUF_WR 0x00000010u
#define INT_BUF_RD 0x00000020u
#define INT_ERROR 0x00008000u
#define INT_ERR_MASK 0xffff8000u
/* COMMAND (upper half of the 0x0C word) */
#define CMD_RESP_NONE 0x00u
#define CMD_RESP_LONG 0x01u
#define CMD_RESP_SHORT 0x02u
#define CMD_RESP_BUSY 0x03u
#define CMD_CRC 0x08u
#define CMD_INDEX 0x10u
#define CMD_DATA 0x20u
/* TRANSFER_MODE (lower half of the 0x0C word) */
#define TM_BLK_CNT_EN 0x02u
#define TM_AUTO_CMD12 0x04u
#define TM_READ 0x10u
#define TM_MULTI 0x20u
/* CLOCK word at 0x2C */
#define CLK_INT_EN 0x0001u
#define CLK_INT_STABLE 0x0002u
#define CLK_CARD_EN 0x0004u
#define RST_ALL (1u << 24)
#define RST_CMD (1u << 25)
#define RST_DATA (1u << 26)
/* HOST word at 0x28 */
#define HOST_4BIT 0x02u
#define PWR_330 (0x0eu << 8)
#define PWR_ON (0x01u << 8)

/* Response kinds (SD Physical Layer 4.9). */
enum { R_NONE, R1, R1B, R2, R3, R6, R7 };

/* R1 card status error bits: OUT_OF_RANGE..WP_VIOLATION (31:26),
 * LOCK_UNLOCK_FAILED (24), COM_CRC_ERROR..ERROR (23:19), CSD_OVERWRITE (16),
 * WP_ERASE_SKIP (15), AKE_SEQ_ERROR (3). */
#define R1_ERRORS 0xfdf98008u
#define R1_READY_FOR_DATA 0x00000100u
#define R1_STATE(s) (((s) >> 9) & 0xfu)
#define STATE_TRAN 4u

#define BLOCK 512u

static uint32_t rd(sdhci_card *c, uint32_t off) { return c->ops.r32(c->ops.ctx, off); }
static void wr(sdhci_card *c, uint32_t off, uint32_t v) { c->ops.w32(c->ops.ctx, off, v); }
static void delay(sdhci_card *c, uint32_t us) { c->ops.delay_us(c->ops.ctx, us); }

static int fail(sdhci_card *c, int cmd, int err)
{
    c->last_cmd = cmd;
    c->last_err = err;
    return err;
}

/* Poll until (reg & mask) == want, every 10 us, at most ms milliseconds. */
static int wait_reg(sdhci_card *c, uint32_t off, uint32_t mask, uint32_t want, uint32_t ms)
{
    for (uint32_t i = 0; i <= ms * 100u; i++) {
        if ((rd(c, off) & mask) == want)
            return 0;
        delay(c, 10);
    }
    return -1;
}

/* Software reset of the CMD/DATA lines (bits 25/26 of the 0x2C word). */
static void line_reset(sdhci_card *c, uint32_t bits)
{
    uint32_t v = rd(c, SDHCI_R_CLOCK);
    if (v & (RST_ALL | RST_CMD | RST_DATA)) /* a reset still running: do not re-trigger */
        (void)wait_reg(c, SDHCI_R_CLOCK, RST_ALL | RST_CMD | RST_DATA, 0, 100);
    v = rd(c, SDHCI_R_CLOCK) & 0x00ffffffu;
    wr(c, SDHCI_R_CLOCK, v | bits);
    (void)wait_reg(c, SDHCI_R_CLOCK, bits, 0, 100);
}

/* Wait for any of `mask` or an error bit in INT_STATUS. 0 ok (the mask bits
 * seen are cleared), -1 error bit, -2 timeout. */
static int wait_int(sdhci_card *c, uint32_t mask, uint32_t ms)
{
    for (uint32_t i = 0; i <= ms * 100u; i++) {
        uint32_t s = rd(c, SDHCI_R_INT);
        c->last_int = s;
        if (s & (INT_ERROR | INT_ERR_MASK)) return -1; /* GUARD:sdhci-err-int */
        if (s & mask) {
            wr(c, SDHCI_R_INT, s & mask);
            return 0;
        }
        delay(c, 10);
    }
    c->last_int = rd(c, SDHCI_R_INT);
    return -2;
}

static uint32_t cmd_flags(int kind)
{
    switch (kind) {
    case R1:
    case R6:
    case R7:
        return CMD_RESP_SHORT | CMD_CRC | CMD_INDEX;
    case R1B:
        return CMD_RESP_BUSY | CMD_CRC | CMD_INDEX;
    case R2:
        return CMD_RESP_LONG | CMD_CRC;
    case R3:
        return CMD_RESP_SHORT;
    default:
        return CMD_RESP_NONE;
    }
}

/* Issue one command; for data commands the caller moves the data and waits
 * for transfer complete. resp gets RESPONSE0..3 (long) or RESPONSE0. */
static int command(sdhci_card *c, uint32_t idx, uint32_t arg, int kind, uint32_t tmode, uint32_t nblocks,
                   uint32_t resp[4])
{
    uint32_t ms = c->cfg.timeout_ms;
    int data = nblocks != 0;
    uint32_t inhibit = PS_CMD_INHIBIT | ((data || kind == R1B) ? PS_DATA_INHIBIT : 0);
    if (wait_reg(c, SDHCI_R_PRESENT, inhibit, 0, ms)) return fail(c, (int)idx, SDHCI_ETIMEOUT); /* GUARD:sdhci-inhibit */
    wr(c, SDHCI_R_INT, 0xffffffffu);
    if (data)
        wr(c, SDHCI_R_BLOCK, BLOCK | (nblocks << 16));
    wr(c, SDHCI_R_ARG, arg);
    uint32_t f = cmd_flags(kind) | (data ? CMD_DATA : 0);
    wr(c, SDHCI_R_CMD, ((idx << 8 | f) << 16) | tmode);
    int w = wait_int(c, INT_CMD_DONE, ms);
    if (w) {
        line_reset(c, RST_CMD | RST_DATA);
        return fail(c, (int)idx, w == -2 ? SDHCI_ETIMEOUT : SDHCI_ECMD);
    }
    if (resp) {
        resp[0] = rd(c, SDHCI_R_RESP0);
        if (kind == R2)
            for (int i = 1; i < 4; i++)
                resp[i] = rd(c, SDHCI_R_RESP0 + 4u * (uint32_t)i);
    }
    if (kind == R1B && wait_int(c, INT_XFER_DONE, ms)) { /* end of busy */
        line_reset(c, RST_CMD | RST_DATA);
        return fail(c, (int)idx, SDHCI_ETIMEOUT);
    }
    if ((kind == R1 || kind == R1B) && resp && (resp[0] & R1_ERRORS)) return fail(c, (int)idx, SDHCI_ESTATUS); /* GUARD:sdhci-r1 */
    return 0;
}

static int app_command(sdhci_card *c, uint32_t idx, uint32_t arg, int kind, uint32_t resp[4])
{
    uint32_t r[4];
    int rc = command(c, 55, (uint32_t)c->rca << 16, R1, 0, 0, r);
    if (rc)
        return rc;
    return command(c, idx, arg, kind, 0, 0, resp);
}

/* SD clock: <= hz from the base clock. Spec 2.00: power-of-two divisor
 * 1..256 (field = divisor / 2); 3.00+: 10-bit N, divisor 2N (N = 0: base). */
static int set_clock(sdhci_card *c, uint32_t hz)
{
    uint32_t base = c->base_hz, field, actual;
    if (c->spec >= 2) {
        uint32_t n = base <= hz ? 0 : (base + 2 * hz - 1) / (2 * hz);
        if (n > 0x3ff)
            return SDHCI_ECLOCK;
        actual = n ? base / (2 * n) : base;
        field = ((n & 0xff) << 8) | ((n >> 8) & 0x3) << 6;
    } else {
        uint32_t div = 1;
        while (div < 256 && base / div > hz)
            div *= 2;
        if (base / div > hz)
            return SDHCI_ECLOCK;
        actual = base / div;
        field = (div / 2) << 8;
    }
    uint32_t v = rd(c, SDHCI_R_CLOCK) & 0xffff0000u;
    wr(c, SDHCI_R_CLOCK, v); /* SD clock and internal clock off */
    wr(c, SDHCI_R_CLOCK, v | field | CLK_INT_EN);
    if (wait_reg(c, SDHCI_R_CLOCK, CLK_INT_STABLE, CLK_INT_STABLE, 100))
        return SDHCI_ECLOCK;
    wr(c, SDHCI_R_CLOCK, v | field | CLK_INT_EN | CLK_CARD_EN);
    c->card_hz = actual;
    return 0;
}

/* Bits [hi:lo] of a long response as the controller stores it (R2 bits
 * 127:8 in RESPONSE bits 119:0), addressed by register bit position. */
static uint32_t rbits(const uint32_t r[4], unsigned hi, unsigned lo)
{
    uint32_t v = 0;
    for (unsigned b = hi + 1; b-- > lo;)
        v = (v << 1) | ((r[b / 32] >> (b % 32)) & 1u);
    return v;
}
#define CSD(r, hi, lo) rbits((r), (hi) - 8, (lo) - 8) /* CSD bit numbers (Physical Layer 5.3) */

static int card_status(sdhci_card *c, uint32_t *st)
{
    uint32_t r[4];
    int rc = command(c, 13, (uint32_t)c->rca << 16, R1, 0, 0, r);
    *st = r[0];
    return rc;
}

/* After a write: wait until the card left programming (READY_FOR_DATA, tran). */
static int wait_tran(sdhci_card *c)
{
    for (uint32_t i = 0; i <= c->cfg.timeout_ms; i++) {
        uint32_t st = 0;
        int rc = card_status(c, &st);
        if (rc)
            return rc;
        if ((st & R1_READY_FOR_DATA) && R1_STATE(st) == STATE_TRAN)
            return 0;
        delay(c, 1000);
    }
    return fail(c, 13, SDHCI_ETIMEOUT);
}

int sdhci_init(sdhci_card *c, const sdhci_ops *ops, const sdhci_cfg *cfg)
{
    if (!c || !ops || !ops->r32 || !ops->w32 || !ops->delay_us || !cfg)
        return SDHCI_EARG;
    for (uint8_t *p = (uint8_t *)c, *e = p + sizeof *c; p < e; p++) /* no memset: no libc */
        *p = 0;
    c->ops = *ops;
    c->cfg = *cfg;
    c->last_cmd = -1;
    if (!c->cfg.timeout_ms)
        c->cfg.timeout_ms = 1000;
    if (!c->cfg.max_blocks)
        c->cfg.max_blocks = 128;
    if (c->cfg.max_blocks > 65535)
        return fail(c, -1, SDHCI_EARG);
    c->spec = (rd(c, SDHCI_R_VERSION) >> 16) & 0xff;
    if (c->spec < 1) return fail(c, -1, SDHCI_EVER); /* GUARD:sdhci-ver */
    wr(c, SDHCI_R_CLOCK, (rd(c, SDHCI_R_CLOCK) & 0x00ffffffu) | RST_ALL);
    if (wait_reg(c, SDHCI_R_CLOCK, RST_ALL, 0, 100)) return fail(c, -1, SDHCI_ERESET); /* GUARD:sdhci-reset */
    uint32_t cap = rd(c, SDHCI_R_CAP);
    if (!(cap & (1u << 24))) return fail(c, -1, SDHCI_EVOLT); /* GUARD:sdhci-volt */
    c->base_hz = c->cfg.base_clock_hz;
    if (!c->base_hz)
        c->base_hz = ((cap >> 8) & (c->spec >= 2 ? 0xffu : 0x3fu)) * 1000000u;
    if (!c->base_hz) return fail(c, -1, SDHCI_ECLOCK); /* GUARD:sdhci-clock0 */
    /* 3.3 V bus power, 1-bit, normal speed. */
    uint32_t host = rd(c, SDHCI_R_HOST) & 0xffff0000u;
    wr(c, SDHCI_R_HOST, host | PWR_330);
    wr(c, SDHCI_R_HOST, host | PWR_330 | PWR_ON);
    delay(c, 10000);
    if (wait_reg(c, SDHCI_R_PRESENT, PS_CARD_PRESENT, PS_CARD_PRESENT, 100)) return fail(c, -1, SDHCI_ENOCARD); /* GUARD:sdhci-nocard */
    wr(c, SDHCI_R_INT_EN, INT_ERR_MASK | INT_BUF_RD | INT_BUF_WR | INT_XFER_DONE | INT_CMD_DONE);
    wr(c, SDHCI_R_SIG_EN, 0);
    wr(c, SDHCI_R_CLOCK, (rd(c, SDHCI_R_CLOCK) & 0x0000ffffu) | (0x0eu << 16)); /* data timeout: max */
    if (set_clock(c, 400000))
        return fail(c, -1, SDHCI_ECLOCK);
    delay(c, 1000); /* >= 74 clocks before CMD0 */

    uint32_t r[4] = { 0 };
    int rc = command(c, 0, 0, R_NONE, 0, 0, 0);
    if (rc)
        return rc;
    if (command(c, 8, 0x1aa, R7, 0, 0, r) || (r[0] & 0xfff) != 0x1aa) return fail(c, 8, SDHCI_ECARD); /* GUARD:sdhci-cmd8 */
    for (uint32_t i = 0;; i++) {
        rc = app_command(c, 41, 0x40ff8000u, R3, r); /* HCS, 2.7-3.6 V */
        if (rc)
            return rc;
        if (r[0] & 0x80000000u)
            break;
        if (i >= 100) return fail(c, 41, SDHCI_ETIMEOUT); /* GUARD:sdhci-acmd41-bound */
        delay(c, 10000);
    }
    c->high_capacity = (r[0] >> 30) & 1;
    if ((rc = command(c, 2, 0, R2, 0, 0, c->cid)))
        return rc;
    if ((rc = command(c, 3, 0, R6, 0, 0, r)))
        return rc;
    c->rca = (uint16_t)(r[0] >> 16);
    if ((rc = command(c, 9, (uint32_t)c->rca << 16, R2, 0, 0, c->csd)))
        return rc;
    uint32_t structure = CSD(c->csd, 127, 126);
    if (structure == 1) {
        c->blocks = ((uint64_t)CSD(c->csd, 69, 48) + 1) * 1024u;
    } else if (structure == 0 && !c->high_capacity) {
        uint64_t bytes = ((uint64_t)CSD(c->csd, 73, 62) + 1) << (CSD(c->csd, 49, 47) + 2) << CSD(c->csd, 83, 80);
        c->blocks = bytes / BLOCK;
    } else {
        return fail(c, 9, SDHCI_ECSD);
    }
    if (!c->blocks) return fail(c, 9, SDHCI_ECSD); /* GUARD:sdhci-csd-zero */
    if (set_clock(c, 25000000))
        return fail(c, -1, SDHCI_ECLOCK);
    if ((rc = command(c, 7, (uint32_t)c->rca << 16, R1B, 0, 0, r)))
        return rc;
    if (c->cfg.bus_4bit) {
        if ((rc = app_command(c, 6, 2, R1, r)))
            return rc;
        wr(c, SDHCI_R_HOST, rd(c, SDHCI_R_HOST) | HOST_4BIT);
    }
    if (!c->high_capacity && (rc = command(c, 16, BLOCK, R1, 0, 0, r)))
        return rc;
    c->dev.ctx = c;
    c->dev.block_size = BLOCK;
    c->dev.block_count = c->blocks;
    c->dev.read = sdhci_read;
    c->dev.write = sdhci_write;
    c->dev.flush = sdhci_flush;
    c->dev.max_blocks_per_io = c->cfg.max_blocks;
    c->ready = 1;
    return 0;
}

static int transfer(sdhci_card *c, uint64_t lba, uint32_t count, uint8_t *buf, int is_read)
{
    if (!c || !buf || !count || count > c->cfg.max_blocks)
        return DISK_EARG;
    if (!c->ready) return DISK_ESTATE; /* GUARD:sdhci-ready */
    if (lba >= c->blocks || count > c->blocks - lba) return DISK_ERANGE; /* GUARD:sdhci-range */
    uint64_t addr = c->high_capacity ? lba : lba * BLOCK;
    if (addr > 0xffffffffu)
        return DISK_ERANGE;
    uint32_t idx, tm = is_read ? TM_READ : 0;
    if (count == 1) {
        idx = is_read ? 17 : 24;
    } else {
        idx = is_read ? 18 : 25;
        tm |= TM_BLK_CNT_EN | TM_MULTI | TM_AUTO_CMD12;
    }
    uint32_t r[4];
    int rc = command(c, idx, (uint32_t)addr, R1, tm, count, r);
    for (uint32_t b = 0; !rc && b < count; b++) {
        int w = wait_int(c, is_read ? INT_BUF_RD : INT_BUF_WR, c->cfg.timeout_ms);
        if (w) {
            rc = fail(c, (int)idx, w == -2 ? SDHCI_ETIMEOUT : SDHCI_EDATA);
            break;
        }
        uint8_t *p = buf + (uint64_t)b * BLOCK;
        for (uint32_t i = 0; i < BLOCK; i += 4) {
            if (is_read) {
                uint32_t v = rd(c, SDHCI_R_BUF);
                p[i] = (uint8_t)v;
                p[i + 1] = (uint8_t)(v >> 8);
                p[i + 2] = (uint8_t)(v >> 16);
                p[i + 3] = (uint8_t)(v >> 24);
            } else {
                wr(c, SDHCI_R_BUF, (uint32_t)p[i] | (uint32_t)p[i + 1] << 8 | (uint32_t)p[i + 2] << 16 |
                                       (uint32_t)p[i + 3] << 24);
            }
        }
    }
    if (!rc) {
        int w = wait_int(c, INT_XFER_DONE, c->cfg.timeout_ms);
        if (w)
            rc = fail(c, (int)idx, w == -2 ? SDHCI_ETIMEOUT : SDHCI_EDATA);
    }
    if (!rc && !is_read) rc = wait_tran(c); /* GUARD:sdhci-tran */
    if (rc) {
        line_reset(c, RST_CMD | RST_DATA);
        c->ready = 0; /* fail closed: the Store sees DISK_ESTATE from now on */ /* GUARD:sdhci-failstop */
        return DISK_EIO;
    }
    return DISK_OK;
}

int sdhci_read(void *ctx, uint64_t lba, uint32_t count, uint8_t *buf)
{
    return transfer(ctx, lba, count, buf, 1);
}

int sdhci_write(void *ctx, uint64_t lba, uint32_t count, const uint8_t *buf)
{
    return transfer(ctx, lba, count, (uint8_t *)buf, 0);
}

int sdhci_flush(void *ctx)
{
    sdhci_card *c = ctx;
    if (!c)
        return DISK_EARG;
    if (!c->ready)
        return DISK_ESTATE;
    uint32_t st = 0;
    if (card_status(c, &st) || !(st & R1_READY_FOR_DATA) || R1_STATE(st) != STATE_TRAN) {
        c->ready = 0;
        return DISK_EIO;
    }
    return DISK_OK;
}

const char *sdhci_strerror(int rc)
{
    switch (rc) {
    case SDHCI_OK: return "ok";
    case SDHCI_EARG: return "bad argument";
    case SDHCI_EVER: return "controller spec 1.00 unsupported";
    case SDHCI_ERESET: return "software reset did not clear";
    case SDHCI_ENOCARD: return "no card present";
    case SDHCI_EVOLT: return "no 3.3 V support";
    case SDHCI_ECLOCK: return "clock: no base clock, divider out of range, or not stable";
    case SDHCI_ECARD: return "CMD8 failed: not a physical layer 2.00+ card";
    case SDHCI_ETIMEOUT: return "timeout";
    case SDHCI_ECSD: return "CSD unsupported";
    case SDHCI_ECMD: return "command error interrupt";
    case SDHCI_EDATA: return "data error interrupt";
    case SDHCI_ESTATUS: return "card status error bits";
    case SDHCI_ESTATE: return "card not ready (failed closed)";
    default: return "unknown";
    }
}
