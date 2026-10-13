/* sdhci_test.c -- disk_sdhci.c against a software SDHCI + SD card model.
 * Hosted test; not QEMU and not hardware. The model offers only aligned
 * 32-bit access, flags every protocol violation it can see (command issued
 * while inhibited, data command while the card is programming, wrong
 * response type, wrong address mode, block size not 512, unaligned or
 * out-of-window access), and injects faults on request. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../disk_sdhci.h"

static int failures;
#define CHECK(x)                                                                                   \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #x);                                    \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

enum { ST_IDLE = 0, ST_READY = 1, ST_IDENT = 2, ST_STBY = 3, ST_TRAN = 4, ST_DATA = 5, ST_RCV = 6, ST_PRG = 7 };

typedef struct {
    uint32_t reg[64];
    /* card */
    uint8_t *mem;
    uint64_t blocks;
    int sdsc, v1_card, present, state, app, acmd41_polls, acmd41_needed, bus4;
    uint16_t rca;
    uint32_t blocklen;
    /* transfer */
    int xfer_dir; /* 0 none, 1 read, 2 write */
    uint64_t xfer_block;
    uint32_t xfer_left, xfer_word;
    int prg_polls, prg_after_write;
    /* timing */
    int cmd_inhibit_reads, data_inhibit_reads;
    uint64_t now_us;
    /* faults */
    int reset_stuck, data_err_at_block, data_err_armed, r1_err_cmd, csd_override;
    uint32_t csd_raw[4];
    /* observations */
    int violations, commands, accesses;
    uint32_t last_arg[64];
} model;

static void violation(model *m, const char *why)
{
    m->violations++;
    printf("  model violation: %s\n", why);
}

static uint32_t r1(model *m) { return (uint32_t)m->state << 9 | (m->state == ST_TRAN ? 0x100u : 0) | (m->app ? 0x20u : 0); }

/* Put an R2 value given as CSD/CID bits 127:8 into RESPONSE 119:0. */
static void set_r2(model *m, const uint32_t v[4])
{
    for (int i = 0; i < 4; i++)
        m->reg[0x10 / 4 + i] = v[i];
}

static void put_bits(uint32_t r[4], unsigned hi, unsigned lo, uint32_t val) /* CSD bit numbers */
{
    for (unsigned b = lo; b <= hi; b++, val >>= 1) {
        unsigned rb = b - 8;
        if (val & 1)
            r[rb / 32] |= 1u << (rb % 32);
        else
            r[rb / 32] &= ~(1u << (rb % 32));
    }
}

static void raise_int(model *m, uint32_t bits) { m->reg[0x30 / 4] |= bits; }
static void next_block_ready(model *m);

static void do_command(model *m, uint32_t word)
{
    uint32_t tmode = word & 0xffff, cmdreg = word >> 16, idx = (cmdreg >> 8) & 0x3f, flags = cmdreg & 0xff;
    uint32_t arg = m->reg[0x08 / 4];
    int app = m->app;
    m->app = 0;
    m->commands++;
    m->last_arg[idx] = arg;
    int data = (flags & 0x20) != 0;
    if (m->cmd_inhibit_reads > 0 || (data && m->data_inhibit_reads > 0))
        violation(m, "command issued while CMD/DATA inhibit set");
    m->cmd_inhibit_reads = 1;
    if (data)
        m->data_inhibit_reads = 1;
    uint32_t want = 0;
    uint32_t resp = 0;
    int error = 0;
    if (app) {
        switch (idx) {
        case 41: /* R3 */
            want = 0x02;
            if (++m->acmd41_polls >= m->acmd41_needed && m->acmd41_needed >= 0) {
                m->state = ST_READY;
                resp = 0x80000000u | (m->sdsc ? 0 : 0x40000000u) | 0x00ff8000u;
            } else {
                resp = 0x00ff8000u;
            }
            break;
        case 6:
            want = 0x1a;
            if (m->state != ST_TRAN || (arg != 0 && arg != 2))
                violation(m, "ACMD6 outside tran or bad width");
            m->bus4 = arg == 2;
            resp = r1(m);
            break;
        default:
            violation(m, "unexpected app command");
        }
    } else {
        switch (idx) {
        case 0:
            want = 0x00;
            m->state = ST_IDLE;
            break;
        case 8:
            want = 0x1a;
            if (m->v1_card)
                error = 0x00018000; /* command timeout */
            else
                resp = arg & 0xfff;
            break;
        case 55:
            want = 0x1a;
            m->app = 1;
            resp = r1(m) | 0x20u;
            break;
        case 2: {
            want = 0x09;
            uint32_t cid[4] = { 0x11223344, 0x55667788, 0x99aabbcc, 0x00ddeeff };
            set_r2(m, cid);
            m->state = ST_IDENT;
            break;
        }
        case 3:
            want = 0x1a;
            m->rca = 0x1234;
            m->state = ST_STBY;
            resp = (uint32_t)m->rca << 16 | 0x0500;
            break;
        case 9: {
            want = 0x09;
            if (arg != (uint32_t)m->rca << 16)
                violation(m, "CMD9 wrong RCA");
            uint32_t csd[4] = { 0 };
            if (m->csd_override) {
                memcpy(csd, m->csd_raw, sizeof csd);
            } else if (m->sdsc) { /* CSD 1.0: C_SIZE, C_SIZE_MULT, READ_BL_LEN = 9 */
                put_bits(csd, 127, 126, 0);
                put_bits(csd, 83, 80, 9);
                uint64_t mult = 7; /* 2^(7+2) = 512 */
                uint64_t csize = m->blocks / 512 - 1;
                put_bits(csd, 73, 62, (uint32_t)csize);
                put_bits(csd, 49, 47, (uint32_t)mult);
            } else {
                put_bits(csd, 127, 126, 1);
                put_bits(csd, 69, 48, (uint32_t)(m->blocks / 1024 - 1));
            }
            set_r2(m, csd);
            break;
        }
        case 7:
            want = 0x1b;
            if (arg != (uint32_t)m->rca << 16)
                violation(m, "CMD7 wrong RCA");
            m->state = ST_TRAN;
            resp = r1(m);
            raise_int(m, 0x2); /* busy end */
            break;
        case 13:
            want = 0x1a;
            if (m->prg_polls > 0 && --m->prg_polls == 0)
                m->state = ST_TRAN;
            resp = r1(m);
            break;
        case 16:
            want = 0x1a;
            m->blocklen = arg;
            resp = r1(m);
            break;
        case 17:
        case 18:
        case 24:
        case 25: {
            want = 0x3a;
            if (m->state != ST_TRAN)
                violation(m, "data command while the card is not in tran (programming?)");
            uint32_t bs = m->reg[0x04 / 4] & 0xfff, bc = m->reg[0x04 / 4] >> 16;
            if (bs != 512)
                violation(m, "block size not 512");
            int multi = idx == 18 || idx == 25;
            if (multi && (tmode & 0x26) != 0x26)
                violation(m, "multi-block without BLK_CNT_EN|MULTI|AUTO_CMD12");
            if (!multi && (tmode & 0x20))
                violation(m, "single-block with MULTI");
            int rd = idx == 17 || idx == 18;
            if (!!(tmode & 0x10) != rd)
                violation(m, "TRANSFER_MODE read bit does not match the command");
            uint64_t blk;
            if (m->sdsc) {
                if (arg % 512)
                    violation(m, "SDSC address not a byte address of a block");
                blk = arg / 512;
            } else {
                blk = arg;
            }
            uint32_t n = multi ? bc : 1;
            resp = r1(m);
            if (blk >= m->blocks || n > m->blocks - blk) {
                resp |= 0x80000000u; /* OUT_OF_RANGE */
                break;
            }
            if ((int)idx == m->r1_err_cmd) {
                resp |= 0x40000000u; /* ADDRESS_ERROR, no data follows */
                break;
            }
            m->xfer_dir = rd ? 1 : 2;
            m->xfer_block = blk;
            m->xfer_left = n;
            m->xfer_word = 0;
            m->state = rd ? ST_DATA : ST_RCV;
            next_block_ready(m);
            break;
        }
        default:
            violation(m, "unexpected command");
        }
    }
    if ((flags & 0x3f) != want) {
        char b[96];
        snprintf(b, sizeof b, "CMD%u flags 0x%02x, want 0x%02x", idx, flags & 0x3f, want);
        violation(m, b);
    }
    if (error) {
        raise_int(m, (uint32_t)error);
        return;
    }
    m->reg[0x10 / 4] = (flags & 3) == 1 ? m->reg[0x10 / 4] : resp;
    raise_int(m, 0x1);
}

/* Make the next block ready, or report the injected data CRC error in its place
 * (real controllers raise the error instead of BUF_RD_READY). */
static void next_block_ready(model *m)
{
    if (m->xfer_dir == 1 && m->data_err_armed && (int64_t)m->xfer_block == m->data_err_at_block) {
        m->data_err_armed = 0;
        m->xfer_dir = 0;
        m->state = ST_TRAN;
        m->data_inhibit_reads = 2;
        raise_int(m, 0x00208000);
        return;
    }
    raise_int(m, m->xfer_dir == 1 ? 0x20 : 0x10);
}

static void block_done(model *m)
{
    m->xfer_word = 0;
    m->xfer_block++;
    if (--m->xfer_left == 0) {
        if (m->xfer_dir == 2) {
            m->state = ST_PRG;
            m->prg_polls = m->prg_after_write ? m->prg_after_write : 1;
        } else {
            m->state = ST_TRAN;
        }
        m->xfer_dir = 0;
        m->data_inhibit_reads = 2;
        raise_int(m, 0x2);
        return;
    }
    next_block_ready(m);
}

static uint32_t m_r32(void *ctx, uint32_t off)
{
    model *m = ctx;
    m->accesses++;
    if (off % 4 || off >= 0x100) {
        violation(m, "unaligned or out-of-window read");
        return 0;
    }
    if (off == 0x24) {
        uint32_t v = (m->present ? 0x00010000u : 0) | (m->cmd_inhibit_reads > 0 ? 1u : 0) |
                     (m->data_inhibit_reads > 0 ? 2u : 0);
        if (m->cmd_inhibit_reads > 0)
            m->cmd_inhibit_reads--;
        if (m->data_inhibit_reads > 0)
            m->data_inhibit_reads--;
        return v;
    }
    if (off == 0x20) {
        if (m->xfer_dir != 1) {
            violation(m, "buffer read with no read transfer");
            return 0;
        }
        const uint8_t *p = m->mem + m->xfer_block * 512 + m->xfer_word * 4;
        uint32_t v = (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
        if (++m->xfer_word == 128)
            block_done(m);
        return v;
    }
    return m->reg[off / 4];
}

static void m_w32(void *ctx, uint32_t off, uint32_t v)
{
    model *m = ctx;
    m->accesses++;
    if (off % 4 || off >= 0x100) {
        violation(m, "unaligned or out-of-window write");
        return;
    }
    switch (off) {
    case 0x0c:
        do_command(m, v);
        return;
    case 0x20: {
        if (m->xfer_dir != 2) {
            violation(m, "buffer write with no write transfer");
            return;
        }
        uint8_t *p = m->mem + m->xfer_block * 512 + m->xfer_word * 4;
        p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
        if (++m->xfer_word == 128)
            block_done(m);
        return;
    }
    case 0x2c: {
        uint32_t old = m->reg[0x2c / 4];
        if ((old >> 24) && (v >> 24))
            violation(m, "SOFTWARE_RESET written while a reset bit is still set");
        if (v & (1u << 24)) { /* reset all */
            uint32_t cap = m->reg[0x40 / 4], ver = m->reg[0xfc / 4];
            memset(m->reg, 0, sizeof m->reg);
            m->reg[0x40 / 4] = cap;
            m->reg[0xfc / 4] = ver;
            m->reg[0x2c / 4] = m->reset_stuck ? (1u << 24) : 0;
            m->xfer_dir = 0;
            return;
        }
        if (v & (3u << 25)) { /* line resets clear at once */
            m->xfer_dir = 0;
            v &= ~(3u << 25);
        }
        if (v & 1)
            v |= 2; /* internal clock stable at once */
        m->reg[0x2c / 4] = v | (m->reset_stuck ? (1u << 24) : 0);
        return;
    }
    case 0x30:
        m->reg[0x30 / 4] &= ~v;
        if (!(m->reg[0x30 / 4] & 0xffff0000u))
            m->reg[0x30 / 4] &= ~0x8000u;
        return;
    case 0x40:
    case 0xfc:
        violation(m, "write to a read-only register");
        return;
    default:
        m->reg[off / 4] = v;
    }
}

static void m_delay(void *ctx, uint32_t us) { ((model *)ctx)->now_us += us; }

static void model_init(model *m, uint64_t blocks, uint32_t version, uint32_t base_mhz)
{
    memset(m, 0, sizeof *m);
    m->mem = calloc(blocks, 512);
    m->blocks = blocks;
    m->present = 1;
    m->acmd41_needed = 3;
    m->data_err_at_block = -1;
    m->r1_err_cmd = -1;
    m->reg[0xfc / 4] = version << 16;
    m->reg[0x40 / 4] = (1u << 24) | ((base_mhz & 0xff) << 8);
}

static sdhci_ops ops_for(model *m)
{
    sdhci_ops o = { m, m_r32, m_w32, m_delay };
    return o;
}

static const sdhci_cfg cfg4 = { 0, 0, 1, 4 };

static void test_sdhc_round_trip(void)
{
    model m;
    sdhci_card c;
    model_init(&m, 8192, 2, 200); /* spec 3.00, 200 MHz base clock (Pi 5 class) */
    sdhci_ops o = ops_for(&m);
    CHECK(sdhci_init(&c, &o, &cfg4) == 0);
    CHECK(c.ready && c.high_capacity == 1 && c.blocks == 8192 && c.rca == 0x1234 && m.bus4 == 1);
    CHECK(c.spec == 2 && c.base_hz == 200000000u && c.card_hz == 25000000u);
    CHECK(c.dev.block_size == 512 && c.dev.block_count == 8192 && c.dev.max_blocks_per_io == 4);
    uint8_t w[10 * 512], r[10 * 512];
    for (size_t i = 0; i < sizeof w; i++)
        w[i] = (uint8_t)(i * 7 + 3);
    CHECK(disk_write(&c.dev, 100, 10, w) == DISK_OK); /* split into 4 + 4 + 2 */
    CHECK(memcmp(m.mem + 100 * 512, w, sizeof w) == 0);
    CHECK(disk_write(&c.dev, 8191, 1, w) == DISK_OK); /* last block, single */
    CHECK(disk_flush(&c.dev) == DISK_OK);
    memset(r, 0, sizeof r);
    CHECK(disk_read(&c.dev, 100, 10, r) == DISK_OK && memcmp(r, w, sizeof w) == 0);
    CHECK(disk_read(&c.dev, 8191, 1, r) == DISK_OK && memcmp(r, w, 512) == 0);
    CHECK(m.last_arg[18] == 108 && m.last_arg[25] == 108); /* block addressing */
    /* Range refused before the card sees it. */
    int before = m.commands;
    CHECK(sdhci_read(&c, 8190, 3, r) == DISK_ERANGE && m.commands == before);
    CHECK(c.ready);
    CHECK(m.violations == 0);
    free(m.mem);
}

static void test_sdsc_and_clock_v2(void)
{
    model m;
    sdhci_card c;
    model_init(&m, 4096, 1, 52); /* spec 2.00, 52 MHz */
    m.sdsc = 1;
    sdhci_ops o = ops_for(&m);
    sdhci_cfg cfg = { 0, 0, 0, 0 };
    CHECK(sdhci_init(&c, &o, &cfg) == 0);
    CHECK(c.high_capacity == 0 && c.blocks == 4096 && m.blocklen == 512 && m.bus4 == 0);
    CHECK(c.card_hz == 13000000u); /* 52 MHz / 4: the largest power-of-two step <= 25 MHz */
    CHECK(c.dev.max_blocks_per_io == 128);
    uint8_t w[3 * 512], r[3 * 512];
    for (size_t i = 0; i < sizeof w; i++)
        w[i] = (uint8_t)(i ^ 0x5a);
    CHECK(disk_write(&c.dev, 7, 3, w) == DISK_OK && m.last_arg[25] == 7 * 512);
    CHECK(disk_read(&c.dev, 7, 3, r) == DISK_OK && memcmp(r, w, sizeof w) == 0 && m.last_arg[18] == 7 * 512);
    CHECK(m.violations == 0);
    free(m.mem);
}

static void test_busy_after_write(void)
{
    model m;
    sdhci_card c;
    model_init(&m, 2048, 2, 100);
    m.prg_after_write = 5; /* card programs for five CMD13 polls */
    sdhci_ops o = ops_for(&m);
    CHECK(sdhci_init(&c, &o, &cfg4) == 0);
    uint8_t w[512] = { 1, 2, 3 }, r[512];
    CHECK(disk_write(&c.dev, 1, 1, w) == DISK_OK);
    CHECK(disk_read(&c.dev, 1, 1, r) == DISK_OK && memcmp(r, w, 512) == 0);
    CHECK(m.violations == 0); /* no data command while programming */
    free(m.mem);
}

static void test_failstop_on_data_error(void)
{
    model m;
    sdhci_card c;
    model_init(&m, 2048, 2, 100);
    sdhci_ops o = ops_for(&m);
    CHECK(sdhci_init(&c, &o, &cfg4) == 0);
    uint8_t r[4 * 512];
    m.data_err_at_block = 11;
    m.data_err_armed = 1;
    CHECK(disk_read(&c.dev, 10, 4, r) == DISK_EIO);
    CHECK(c.last_err == SDHCI_EDATA && c.last_cmd == 18 && (c.last_int & 0x00200000u));
    CHECK(disk_read(&c.dev, 10, 1, r) == DISK_ESTATE); /* failed closed */
    CHECK(disk_flush(&c.dev) == DISK_ESTATE);
    CHECK(m.violations == 0);
    free(m.mem);
}

static void test_r1_error_bits(void)
{
    model m;
    sdhci_card c;
    model_init(&m, 2048, 2, 100);
    m.r1_err_cmd = 17;
    sdhci_ops o = ops_for(&m);
    CHECK(sdhci_init(&c, &o, &cfg4) == 0);
    uint8_t r[512];
    CHECK(disk_read(&c.dev, 3, 1, r) == DISK_EIO && c.last_err == SDHCI_ESTATUS && c.last_cmd == 17);
    CHECK(m.violations == 0);
    free(m.mem);
}

static int init_rc(void (*setup)(model *), uint32_t version, uint32_t base_mhz, uint32_t cfg_hz)
{
    model m;
    sdhci_card c;
    model_init(&m, 2048, version, base_mhz);
    if (setup)
        setup(&m);
    sdhci_ops o = ops_for(&m);
    sdhci_cfg cfg = { cfg_hz, 0, 1, 0 };
    int rc = sdhci_init(&c, &o, &cfg);
    free(m.mem);
    return rc;
}
static void no_volt(model *m) { m->reg[0x40 / 4] &= ~(1u << 24); }
static void no_card(model *m) { m->present = 0; }
static void v1_card(model *m) { m->v1_card = 1; }
static void never_ready(model *m) { m->acmd41_needed = -1; }
static void stuck_reset(model *m) { m->reset_stuck = 1; }
static void zero_csd(model *m)
{
    m->sdsc = 1;
    m->csd_override = 1; /* CSD 1.0 with C_SIZE 0, C_SIZE_MULT 0, READ_BL_LEN 0: 4 bytes */
}

static void test_refusals(void)
{
    CHECK(init_rc(0, 0, 100, 0) == SDHCI_EVER);
    CHECK(init_rc(stuck_reset, 2, 100, 0) == SDHCI_ERESET);
    CHECK(init_rc(no_volt, 2, 100, 0) == SDHCI_EVOLT);
    CHECK(init_rc(0, 2, 0, 0) == SDHCI_ECLOCK);         /* no base clock anywhere */
    CHECK(init_rc(0, 2, 0, 100000000u) == 0);           /* base clock from cfg */
    CHECK(init_rc(no_card, 2, 100, 0) == SDHCI_ENOCARD);
    CHECK(init_rc(v1_card, 2, 100, 0) == SDHCI_ECARD);
    CHECK(init_rc(never_ready, 2, 100, 0) == SDHCI_ETIMEOUT);
    CHECK(init_rc(zero_csd, 2, 100, 0) == SDHCI_ECSD);
    sdhci_card c;
    model m;
    model_init(&m, 16, 2, 100);
    sdhci_ops o = ops_for(&m);
    sdhci_cfg big = { 0, 0, 1, 70000 };
    CHECK(sdhci_init(&c, &o, &big) == SDHCI_EARG);
    CHECK(sdhci_init(&c, 0, &cfg4) == SDHCI_EARG);
    free(m.mem);
}

static void test_clock_math(void)
{
    model m;
    sdhci_card c;
    model_init(&m, 2048, 2, 100); /* 3.00, 100 MHz: 25 MHz is N = 2 */
    sdhci_ops o = ops_for(&m);
    CHECK(sdhci_init(&c, &o, &cfg4) == 0 && c.card_hz == 25000000u);
    CHECK(((m.reg[0x2c / 4] >> 8) & 0xff) == 2 && (m.reg[0x2c / 4] & 0x7) == 0x7);
    free(m.mem);
    model_init(&m, 2048, 1, 48); /* 2.00, 48 MHz: divisor 2 gives 24 MHz */
    CHECK(sdhci_init(&c, &o, &cfg4) == 0 && c.card_hz == 24000000u && ((m.reg[0x2c / 4] >> 8) & 0xff) == 1);
    free(m.mem);
}

int main(void)
{
    setvbuf(stdout, 0, _IONBF, 0);
    printf("- %s\n", "test_sdhc_round_trip");
    test_sdhc_round_trip();
    printf("- %s\n", "test_sdsc_and_clock_v2");
    test_sdsc_and_clock_v2();
    printf("- %s\n", "test_busy_after_write");
    test_busy_after_write();
    printf("- %s\n", "test_failstop_on_data_error");
    test_failstop_on_data_error();
    printf("- %s\n", "test_r1_error_bits");
    test_r1_error_bits();
    printf("- %s\n", "test_refusals");
    test_refusals();
    printf("- %s\n", "test_clock_math");
    test_clock_math();
    if (failures) {
        printf("AIENOS_DISK_SDHCI_MODEL: FAIL (%d)\n", failures);
        return 1;
    }
    printf("AIENOS_DISK_SDHCI_MODEL: PASS\n");
    return 0;
}
