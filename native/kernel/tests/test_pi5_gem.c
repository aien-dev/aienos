/* test_pi5_gem.c -- Pi 5 network lane cut 3 (dev/pi5_gem.c) over a FAKE GEM that behaves like the Cadence
 * descriptor DMA and checks every access it makes: any DMA address outside the bounce window, any DMA while RP1
 * bus-master is off, bus-master dropped while the transmitter still runs, malformed rings, missing tie-offs.
 * Hosted: this proves the decisions and the ORDER of register writes, NOT the hardware. Run under ASan/UBSan
 * and with each CK_GEM_MUTANT_* (make pi5-gem-mutants); every mutant must make it FAIL. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ck_test.h"
#include "pi5_gem.h"

#define WBASE 0x4400000ull
#define WSIZE 0x200000ull
#define OUTBASE 0x6000000ull /* a pretend page outside the window */

struct fk {
    uint8_t *mem;
    uint8_t outside[4096];
    uint32_t r[0x800 / 4];
    uint32_t tbqp_q[8], rbqp_q[8];
    uint16_t phy[32], shadow[32];
    uint32_t shd_sel;
    uint32_t dcfg1, dcfg6;
    int daw64;
    int tgo_delay_cfg, tgo_hold, tgo_cleared_seen;
    int tx_completes, rx_len_lie, expect_gbe;
    /* observations */
    int bme, bme_on_n, bme_off_n, bme_fail_on, bme_fail_off;
    int barrier_n, barrier_at_kick, kicks;
    int dma_without_bme, outside_access, outside_writes;
    int frames_sent, frames_rcvd;
    uint8_t last_tx[1600];
    uint32_t last_tx_len;
    int bad_desc_mode, queue_ptr_outside, rx_nowrap, tx_runaway, tx_no_last, bad_speed;
    int bme_off_while_tgo, bme_off_while_te;
    int gem_writes;
    uint32_t cap_w0, cap_ctrl0, cap_ctrl1, cap_w2;
    char ev[64];
    int nev;
};
static struct fk f;

static void ev(char c)
{
    if (f.nev < 63)
        f.ev[f.nev++] = c;
    f.ev[f.nev] = 0;
}
static int inwin(uint64_t a, uint64_t n) { return a >= WBASE && n <= WSIZE && a - WBASE <= WSIZE - n; }
static uint32_t d_rd(uint64_t a) { uint32_t v; memcpy(&v, f.mem + (a - WBASE), 4); return v; }
static void d_wr(uint64_t a, uint32_t v) { memcpy(f.mem + (a - WBASE), &v, 4); }

static void deliver(const uint8_t *data, uint32_t len)
{
    uint64_t a = ((uint64_t)f.r[CK_GEM_RBQPH / 4] << 32) | f.r[CK_GEM_RBQP / 4];
    uint32_t dsz = f.daw64 ? 16 : 8, i;
    if (!(f.r[CK_GEM_NCR / 4] & CK_GEM_NCR_RE))
        return;
    if (!f.daw64)
        a &= 0xffffffffull;
    for (i = 0; i < 8; i++) {
        uint32_t w0, ctrl, L;
        uint64_t buf;
        if (!inwin(a, dsz)) {
            f.outside_access++;
            return;
        }
        w0 = d_rd(a);
        if (!(w0 & CK_GEMD_RX_USED)) {
            buf = (uint64_t)(w0 & ~3u) | (f.daw64 ? (uint64_t)d_rd(a + 8) << 32 : 0);
            L = len + ((f.r[CK_GEM_NCFGR / 4] & CK_GEM_NCFGR_DRFCS) ? 0u : 4u);
            if (inwin(buf, len)) {
                memcpy(f.mem + (buf - WBASE), data, len);
            } else {
                f.outside_access++;
                f.outside_writes++;
                if (buf >= OUTBASE && buf - OUTBASE + len <= sizeof f.outside)
                    memcpy(f.outside + (buf - OUTBASE), data, len);
            }
            ctrl = L | CK_GEMD_RX_SOF | CK_GEMD_RX_EOF | (1u << 31);
            if (f.rx_len_lie)
                ctrl = 2000u | CK_GEMD_RX_SOF | CK_GEMD_RX_EOF;
            d_wr(a + 4, ctrl);
            d_wr(a, w0 | CK_GEMD_RX_USED);
            f.frames_rcvd++;
            f.r[CK_GEM_RSR / 4] |= CK_GEM_RSR_REC;
            return;
        }
        if (w0 & CK_GEMD_RX_WRAP)
            return;
        a += dsz;
    }
}

static void kick(uint32_t ncr)
{
    uint64_t a;
    uint32_t dsz = f.daw64 ? 16 : 8, i, q;
    ev('K');
    f.kicks++;
    f.barrier_at_kick = f.barrier_n;
    if (!f.bme) {
        f.dma_without_bme++;
        return;
    }
    if (f.daw64 != !!(f.r[CK_GEM_DMACFG / 4] & CK_GEM_DMACFG_ADDR64))
        f.bad_desc_mode++;
    if (f.expect_gbe && !(f.r[CK_GEM_NCFGR / 4] & CK_GEM_NCFGR_GBE))
        f.bad_speed++;
    for (q = 1; q < 8; q++) {
        if (!((f.dcfg6 >> q) & 1u))
            continue;
        if (!inwin(f.tbqp_q[q], dsz) || !inwin(f.rbqp_q[q], dsz) || !(d_rd(f.tbqp_q[q] + 4) & CK_GEMD_TX_USED) ||
            !(d_rd(f.rbqp_q[q]) & CK_GEMD_RX_USED))
            f.queue_ptr_outside++;
    }
    /* RX ring must wrap within 8 slots */
    a = ((uint64_t)f.r[CK_GEM_RBQPH / 4] << 32) | f.r[CK_GEM_RBQP / 4];
    for (i = 0; i < 8; i++) {
        if (!inwin(a, dsz))
            break;
        if (d_rd(a) & CK_GEMD_RX_WRAP)
            break;
        a += dsz;
    }
    if (i == 8 || !inwin(a, dsz))
        f.rx_nowrap++;
    a = ((uint64_t)f.r[CK_GEM_TBQPH / 4] << 32) | f.r[CK_GEM_TBQP / 4];
    for (i = 0; i < 8; i++) {
        uint32_t ctrl, len;
        uint64_t buf;
        uint8_t data[1600];
        if (!inwin(a, dsz)) {
            f.outside_access++;
            return;
        }
        ctrl = d_rd(a + 4);
        if (i == 0) {
            f.cap_w0 = d_rd(a);
            f.cap_ctrl0 = ctrl;
            f.cap_w2 = f.daw64 ? d_rd(a + 8) : 0;
            f.cap_ctrl1 = d_rd(a + dsz + 4);
        }
        if (ctrl & CK_GEMD_TX_USED) {
            f.r[CK_GEM_TSR / 4] |= CK_GEM_TSR_UBR;
            return;
        }
        if (!(ctrl & CK_GEMD_TX_LAST)) {
            f.tx_no_last++;
            return;
        }
        len = ctrl & CK_GEMD_TX_FRMLEN_MASK;
        buf = d_rd(a) | (f.daw64 ? (uint64_t)d_rd(a + 8) << 32 : 0);
        if (len > sizeof data)
            len = sizeof data;
        if (inwin(buf, len)) {
            memcpy(data, f.mem + (buf - WBASE), len);
        } else {
            f.outside_access++;
            memset(data, 0xee, len);
        }
        f.frames_sent++;
        memcpy(f.last_tx, data, len);
        f.last_tx_len = len;
        if (f.tx_completes) {
            d_wr(a + 4, ctrl | CK_GEMD_TX_USED);
            f.r[CK_GEM_TSR / 4] |= CK_GEM_TSR_COMP;
        }
        f.tgo_hold = f.tgo_delay_cfg;
        if ((ncr & CK_GEM_NCR_LLB) || (f.phy[0] & CK_MII_BMCR_LOOPBACK))
            deliver(data, len);
        if (ctrl & CK_GEMD_TX_WRAP)
            a = ((uint64_t)f.r[CK_GEM_TBQPH / 4] << 32) | f.r[CK_GEM_TBQP / 4];
        else
            a += dsz;
    }
    f.tx_runaway++;
}

static void phy_man(uint32_t v)
{
    uint32_t reg = (v >> 18) & 31u, op = (v >> 28) & 3u, data = v & 0xffffu;
    if (op == 2) { /* read */
        if (reg == 0x1c)
            f.phy[reg] = (uint16_t)(f.shadow[f.shd_sel] & 0x3ff);
        f.r[CK_GEM_MAN / 4] = (v & 0xffff0000u) | f.phy[reg];
    } else if (op == 1) { /* write */
        if (reg == 0x1c) {
            if (data & 0x8000u)
                f.shadow[(data >> 10) & 31u] = (uint16_t)(data & 0x3ff);
            else
                f.shd_sel = (data >> 10) & 31u;
        } else if (reg == 0x18) {
            if ((data & 7u) == 7u && ((data >> 12) & 7u) == 7u) {
                /* read-select of MISC: nothing stored */
            } else {
                f.phy[reg] = (uint16_t)data;
            }
        } else {
            f.phy[reg] = (uint16_t)data;
        }
        f.r[CK_GEM_MAN / 4] = v;
    }
}

static uint32_t fk_rd(void *c, uint32_t off)
{
    uint32_t o;
    (void)c;
    if (off < CK_RP1_ETH || off >= CK_RP1_ETH + 0x800u)
        return 0;
    o = off - CK_RP1_ETH;
    if (o == CK_GEM_NSR)
        return CK_GEM_NSR_IDLE;
    if (o == CK_GEM_TSR) {
        uint32_t v = f.r[CK_GEM_TSR / 4];
        if (f.tgo_hold > 0) {
            v |= CK_GEM_TSR_TGO;
            f.tgo_hold--;
        } else {
            f.tgo_cleared_seen = 1;
            ev('g');
        }
        return v;
    }
    if (o == CK_GEM_ISR) {
        uint32_t v = f.r[o / 4];
        f.r[o / 4] = 0;
        return v;
    }
    if (o == CK_GEM_MID)
        return 0x00070109u;
    if (o == CK_GEM_DCFG1)
        return f.dcfg1;
    if (o == CK_GEM_DCFG6)
        return f.dcfg6;
    return f.r[o / 4];
}

static void fk_wr(void *c, uint32_t off, uint32_t v)
{
    uint32_t o;
    (void)c;
    if (off < CK_RP1_ETH || off >= CK_RP1_ETH + 0x800u)
        return;
    o = off - CK_RP1_ETH;
    if (o == CK_GEM_MAN) {
        phy_man(v);
        return;
    }
    f.gem_writes++;
    if (o == CK_GEM_NCR) {
        uint32_t old = f.r[o / 4], nv = v;
        nv &= ~(uint32_t)CK_GEM_NCR_CLRSTAT;
        nv &= ~(uint32_t)CK_GEM_NCR_TSTART;
        if ((old & (CK_GEM_NCR_RE | CK_GEM_NCR_TE)) && !(nv & (CK_GEM_NCR_RE | CK_GEM_NCR_TE)))
            ev('E');
        f.r[o / 4] = nv;
        if (v & CK_GEM_NCR_TSTART)
            kick(nv);
        return;
    }
    if (o == CK_GEM_TSR || o == CK_GEM_RSR) {
        f.r[o / 4] &= ~v;
        return;
    }
    if (o >= 0x440 && o < 0x460) {
        f.tbqp_q[((o - 0x440) >> 2) + 1] = v;
        return;
    }
    if (o >= 0x480 && o < 0x4a0) {
        f.rbqp_q[((o - 0x480) >> 2) + 1] = v;
        return;
    }
    f.r[o / 4] = v;
}
static struct ck_rp1_io fio = {fk_rd, fk_wr, 0, 0};

static int fk_bme(void *c, int on)
{
    (void)c;
    if (on) {
        if (f.bme_fail_on)
            return -1;
        f.bme = 1;
        f.bme_on_n++;
        ev('B');
    } else {
        if (f.bme_fail_off)
            return -1;
        if (f.tgo_hold > 0)
            f.bme_off_while_tgo++;
        if (f.r[CK_GEM_NCR / 4] & (CK_GEM_NCR_TE | CK_GEM_NCR_RE))
            f.bme_off_while_te++;
        f.bme = 0;
        f.bme_off_n++;
        ev('b');
    }
    return 0;
}
static void fk_barrier(void) { f.barrier_n++; }

static struct ck_dmaw dw;
static struct ck_gem g;

static void fresh(void)
{
    uint8_t *keep = f.mem;
    memset(&f, 0, sizeof f);
    f.mem = keep ? keep : calloc(1, WSIZE);
    memset(f.mem, 0, WSIZE);
    f.dcfg1 = 4u << CK_GEM_DCFG1_DBWDEF_SHIFT;
    f.daw64 = 1;
    f.dcfg6 = CK_GEM_DCFG6_DAW64 | 0x0eu; /* queues 1..3 exist besides 0 */
    f.tx_completes = 1;
    f.tgo_delay_cfg = 50;
    f.expect_gbe = 1;
    f.r[CK_GEM_NCR / 4] = CK_GEM_NCR_MPE;
    f.r[CK_GEM_NCFGR / 4] = 0x00540000u;
    f.phy[0] = 0x1140u;
    f.phy[1] = 0x796du;
    f.phy[2] = 0x600du;
    f.phy[3] = 0x84a2u;
    f.phy[4] = 0x01e1u;
    f.phy[5] = 0x45e1u;
    f.phy[9] = 0x0300u;
    f.phy[10] = 0x3800u;
    f.shadow[3] = 0x0010;
    CHECK(ck_dmaw_init(&dw, f.mem, WBASE, WSIZE) == CK_DMAW_OK);
    ck_gem_init(&g, &fio, &dw, f.mem, fk_bme, 0, fk_barrier, 1);
    CHECK(ck_gem_probe(&fio, &g.caps) == 0);
}

static const uint8_t MAC[6] = {0x02, 0x41, 0x49, 0x45, 0x4e, 0x03};

static void mkx(struct ck_gem_xfer *x, int mode, uint8_t *frame, uint32_t seq)
{
    *x = (struct ck_gem_xfer){0};
    ck_gem_frame_build(CK_GEMF_RAW, MAC, seq, 0, frame, 64);
    x->mode = mode;
    x->speed = 1000;
    x->full_duplex = 1;
    memcpy(x->mac, MAC, 6);
    x->frame = frame;
    x->frame_len = 60;
    x->rx_count = 2;
    x->rx_buf_len = 1536;
    x->tx_wait_us = 20000;
    x->rx_wait_us = 20000;
}

static void clean_flags(void)
{
    CHECK(f.dma_without_bme == 0);
    CHECK(f.outside_access == 0);
    CHECK(f.bad_desc_mode == 0);
    CHECK(f.queue_ptr_outside == 0);
    CHECK(f.rx_nowrap == 0);
    CHECK(f.tx_runaway == 0);
    CHECK(f.tx_no_last == 0);
    CHECK(f.bad_speed == 0);
    CHECK(f.bme_off_while_tgo == 0);
    CHECK(f.bme_off_while_te == 0);
}

static void t_probe(void)
{
    struct ck_gem_caps c;
    fresh();
    CHECK(ck_gem_probe(&fio, &c) == 0);
    CHECK(c.is_gem == 1 && c.daw64 == 1 && c.queue_mask == 0x0fu && c.nqueues == 4 && c.desc_bytes == 16 && c.dbw == 2);
    f.dcfg6 = 0; /* 32-bit descriptors, one queue, 64-bit bus */
    f.dcfg1 = 2u << CK_GEM_DCFG1_DBWDEF_SHIFT;
    CHECK(ck_gem_probe(&fio, &c) == 0);
    CHECK(c.daw64 == 0 && c.queue_mask == 1 && c.nqueues == 1 && c.desc_bytes == 8 && c.dbw == 1);
}

static void t_loopback(void)
{
    struct ck_gem_xfer x;
    uint8_t fr[64];
    uint64_t tx_buf;
    fresh();
    mkx(&x, CK_GEMX_LLB, fr, 1);
    CHECK(ck_gem_xfer(&g, &x) == 0);
    CHECK(x.tx_done == 1 && x.rx_done == 1 && x.rx_frames == 1 && x.rx_len == 60);
    CHECK(ck_gem_frame_diff(fr, 60, x.rx_data, x.rx_copied) == 0);
    CHECK(f.frames_sent == 1 && f.frames_rcvd == 1);
    CHECK(f.bme_on_n == 1 && f.bme_off_n == 1 && f.bme == 0 && g.bme_on == 0);
    CHECK(x.bme_enabled_for_us == 1 && x.bme_off_at_end == 1);
    CHECK(strcmp(f.ev, "BKEgb") == 0 || strcmp(f.ev, "BKEgggb") == 0 || (f.ev[0] == 'B' && f.ev[1] == 'K' && f.ev[2] == 'E'));
    /* bus-master on first, then the kick, then the engine off, THEN bus-master off */
    CHECK(f.ev[0] == 'B' && f.ev[1] == 'K' && f.ev[2] == 'E' && f.ev[f.nev - 1] == 'b');
    CHECK(f.barrier_at_kick >= 1);
    CHECK(!(f.r[CK_GEM_NCR / 4] & (CK_GEM_NCR_RE | CK_GEM_NCR_TE | CK_GEM_NCR_LLB)));
    CHECK(f.r[CK_GEM_NCR / 4] & CK_GEM_NCR_MPE); /* MDIO port stays enabled */
    CHECK(!(x.ncr_end & (CK_GEM_NCR_RE | CK_GEM_NCR_TE | CK_GEM_NCR_LLB)));
    CHECK(x.ncr_run & CK_GEM_NCR_LLB);
    /* the descriptors the device saw: address inside the window, length 60, LAST, owned by the device; sentinel USED|WRAP */
    tx_buf = x.tx_bus;
    CHECK(inwin(tx_buf, 64) && f.cap_w0 == (uint32_t)tx_buf && f.cap_w2 == (uint32_t)(tx_buf >> 32));
    CHECK((f.cap_ctrl0 & CK_GEMD_TX_FRMLEN_MASK) == 60 && (f.cap_ctrl0 & CK_GEMD_TX_LAST) && !(f.cap_ctrl0 & CK_GEMD_TX_USED));
    CHECK((f.cap_ctrl1 & CK_GEMD_TX_USED) && (f.cap_ctrl1 & CK_GEMD_TX_WRAP));
    /* DMA configuration: 64-bit descriptors, 1536 byte buffers, burst 16, TXCOEN off */
    CHECK((f.r[CK_GEM_DMACFG / 4] & CK_GEM_DMACFG_ADDR64) && ((f.r[CK_GEM_DMACFG / 4] >> 16) & 0xff) == 24);
    CHECK((f.r[CK_GEM_DMACFG / 4] & 0x1f) == 16 && !(f.r[CK_GEM_DMACFG / 4] & CK_GEM_DMACFG_TXCOEN));
    CHECK((f.r[CK_GEM_NCFGR / 4] & CK_GEM_NCFGR_GBE) && (f.r[CK_GEM_NCFGR / 4] & CK_GEM_NCFGR_FD) &&
          (f.r[CK_GEM_NCFGR / 4] & CK_GEM_NCFGR_DRFCS));
    CHECK(((f.r[CK_GEM_NCFGR / 4] >> 18) & 7u) == 5u); /* MDC divider kept */
    CHECK(f.r[CK_GEM_USRIO / 4] == CK_GEM_USRIO_RGMII);
    CHECK(f.r[CK_GEM_SA1B / 4] == 0x45494102u && f.r[CK_GEM_SA1T / 4] == 0x0000034eu);
    clean_flags();
    /* a second transfer reuses the window cleanly and still sends exactly one more frame */
    mkx(&x, CK_GEMX_LLB, fr, 2);
    CHECK(ck_gem_xfer(&g, &x) == 0 && x.rx_done && ck_gem_frame_diff(fr, 60, x.rx_data, x.rx_copied) == 0);
    CHECK(f.frames_sent == 2);
    CHECK(g.w->next < 0x10000);
    clean_flags();
}

static void t_phy_loopback(void)
{
    struct ck_gem_xfer x;
    uint8_t fr[64];
    uint16_t saved = 0, bmsr = 0;
    fresh();
    CHECK(ck_phy_loopback_enter(&fio, 1, 1000, &saved, &bmsr) == 0);
    CHECK(saved == 0x1140);
    CHECK(f.phy[0] == (CK_MII_BMCR_LOOPBACK | CK_MII_BMCR_FULLDPLX | CK_MII_BMCR_SPEED1000)); /* 0x4140, no autoneg */
    mkx(&x, CK_GEMX_PHYLB, fr, 7);
    CHECK(ck_gem_xfer(&g, &x) == 0 && x.rx_done && ck_gem_frame_diff(fr, 60, x.rx_data, x.rx_copied) == 0);
    CHECK(!(x.ncr_run & CK_GEM_NCR_LLB)); /* the PHY loops, not the MAC */
    CHECK(ck_phy_loopback_exit(&fio, 1, saved) == 0);
    CHECK(f.phy[0] == (0x1140 | CK_MII_BMCR_ANRESTART));
    clean_flags();
    f.phy[1] = 0x7969u; /* link down in loopback: enter reports a timeout, does not claim success */
    CHECK(ck_phy_loopback_enter(&fio, 1, 100, &saved, &bmsr) != 0);
    CHECK(f.phy[0] == (CK_MII_BMCR_LOOPBACK | CK_MII_BMCR_FULLDPLX | CK_MII_BMCR_SPEED100));
}

static void t_wire_no_loop(void)
{
    struct ck_gem_xfer x;
    uint8_t fr[64];
    fresh();
    f.r[CK_GEM_NCR / 4] |= CK_GEM_NCR_LLB; /* left over from an earlier test: the reset must clear it */
    mkx(&x, CK_GEMX_WIRE, fr, 3);
    x.speed = 100;
    f.expect_gbe = 0;
    CHECK(ck_gem_xfer(&g, &x) == 0);
    CHECK(x.tx_done == 1 && x.rx_done == 0 && f.frames_sent == 1 && f.frames_rcvd == 0);
    CHECK(f.r[CK_GEM_NCFGR / 4] & CK_GEM_NCFGR_SPD);
    CHECK(!(f.r[CK_GEM_NCFGR / 4] & CK_GEM_NCFGR_GBE));
    clean_flags();
}

static void hostile(uint64_t tx_addr, uint64_t rx_addr)
{
    struct ck_gem_xfer x;
    uint8_t fr[64];
    int rc;
    fresh();
    mkx(&x, CK_GEMX_LLB, fr, 1);
    x.tx_addr = tx_addr;
    x.rx_addr = rx_addr;
    rc = ck_gem_xfer(&g, &x);
    CHECK(rc == CK_GEM_E_WINDOW);
    CHECK(f.bme_on_n == 0 && f.bme == 0);         /* bus-master never enabled */
    CHECK(f.gem_writes == 0 && f.kicks == 0);      /* the MAC was not even programmed */
    CHECK(f.frames_sent == 0);
    CHECK(g.halted == 1 && ck_dmaw_halted(&dw));   /* latched */
    mkx(&x, CK_GEMX_LLB, fr, 2); /* a good transfer afterwards is refused: sticky until reboot */
    CHECK(ck_gem_xfer(&g, &x) == CK_GEM_E_HALTED);
    CHECK(f.bme_on_n == 0 && f.kicks == 0);
}

static void t_refuse_outside(void)
{
    hostile(WBASE - 64, 0);                 /* just below the window */
    hostile(WBASE + WSIZE, 0);              /* first byte after */
    hostile(WBASE + WSIZE - 32, 0);         /* straddles the end (60 byte frame) */
    hostile(0xfffffffffffffff0ull, 0);      /* wraps when added to a length */
    hostile(OUTBASE, 0);
    hostile(0, WBASE + WSIZE);              /* RX buffer outside */
    hostile(0, WBASE + WSIZE - 1536 + 64);  /* RX buffer overhangs the end */
    hostile(0, 0xfffffffffffffff8ull);
}

static void t_hwwin_gate(void)
{
    struct ck_gem_xfer x;
    uint8_t fr[64];
    fresh();
    g.hw_window_ok = 0;
    mkx(&x, CK_GEMX_LLB, fr, 1);
    CHECK(ck_gem_xfer(&g, &x) == CK_GEM_E_HWWIN);
    CHECK(f.bme_on_n == 0 && f.gem_writes == 0 && f.kicks == 0);
    CHECK(g.halted == 0); /* a refusal here is not a violation: it can be retried once the window is confirmed */
}

static void t_arg_checks(void)
{
    struct ck_gem_xfer x;
    uint8_t fr[64];
    fresh();
    mkx(&x, CK_GEMX_LLB, fr, 1);
    x.frame_len = 1515;
    CHECK(ck_gem_xfer(&g, &x) == CK_GEM_E_ARG);
    x.frame_len = 59;
    CHECK(ck_gem_xfer(&g, &x) == CK_GEM_E_ARG);
    mkx(&x, CK_GEMX_LLB, fr, 1);
    x.speed = 777;
    CHECK(ck_gem_xfer(&g, &x) == CK_GEM_E_ARG);
    mkx(&x, CK_GEMX_LLB, fr, 1);
    x.rx_buf_len = 1537;
    CHECK(ck_gem_xfer(&g, &x) == CK_GEM_E_ARG);
    x.rx_buf_len = 4096;
    CHECK(ck_gem_xfer(&g, &x) == CK_GEM_E_ARG);
    CHECK(f.bme_on_n == 0 && f.gem_writes == 0 && f.kicks == 0 && g.halted == 0);
}

static void t_device_lies(void)
{
    struct ck_gem_xfer x;
    uint8_t fr[64];
    fresh();
    f.rx_len_lie = 1; /* the device claims 2000 bytes in a 1536 byte buffer */
    mkx(&x, CK_GEMX_LLB, fr, 1);
    CHECK(ck_gem_xfer(&g, &x) == CK_GEM_E_DEVICE);
    CHECK(g.halted == 1 && ck_dmaw_halted(&dw));
    CHECK(f.bme == 0 && f.bme_off_n == 1); /* bus-master was already off when the lie was read */
}

static void t_bme_failures(void)
{
    struct ck_gem_xfer x;
    uint8_t fr[64];
    fresh();
    f.bme_fail_on = 1;
    mkx(&x, CK_GEMX_LLB, fr, 1);
    CHECK(ck_gem_xfer(&g, &x) == CK_GEM_E_BME);
    CHECK(f.kicks == 0 && f.frames_sent == 0 && g.halted == 1);
    fresh();
    f.bme_fail_off = 1;
    mkx(&x, CK_GEMX_LLB, fr, 1);
    CHECK(ck_gem_xfer(&g, &x) == CK_GEM_E_BME);
    CHECK(g.halted == 1);
    CHECK(!(f.r[CK_GEM_NCR / 4] & (CK_GEM_NCR_RE | CK_GEM_NCR_TE))); /* the MAC was stopped even though bus-master would not drop */
}

static void t_tieoff_and_queues(void)
{
    struct ck_gem_xfer x;
    uint8_t fr[64];
    uint32_t q;
    fresh();
    mkx(&x, CK_GEMX_LLB, fr, 1);
    CHECK(ck_gem_xfer(&g, &x) == 0);
    for (q = 1; q <= 3; q++) {
        CHECK(inwin(f.tbqp_q[q], 16) && inwin(f.rbqp_q[q], 16));
        CHECK(f.tbqp_q[q] != 0 && f.rbqp_q[q] != 0);
    }
    clean_flags();
}

static void t_quiesce_order(void)
{
    struct ck_gem_xfer x;
    uint8_t fr[64];
    fresh();
    f.tgo_delay_cfg = 200; /* the transmitter stays busy for 200 status reads */
    mkx(&x, CK_GEMX_LLB, fr, 1);
    CHECK(ck_gem_xfer(&g, &x) == 0);
    CHECK(f.bme_off_while_tgo == 0 && f.bme_off_while_te == 0);
    CHECK(f.tgo_cleared_seen == 1);
    clean_flags();
    /* a transmitter that never stops: halted, bus-master still dropped, error reported */
    fresh();
    f.tgo_delay_cfg = 1000000;
    mkx(&x, CK_GEMX_LLB, fr, 1);
    CHECK(ck_gem_xfer(&g, &x) == CK_GEM_E_QUIESCE);
    CHECK(g.halted == 1 && f.bme == 0);
}

static void t_raw_outside_for_hw_test(void)
{
    struct ck_gem_xfer x;
    uint8_t fr[64];
    fresh();
    /* confinement test path: the hardware-visible RX address is OUTSIDE; the shadow stays valid and nothing latches */
    mkx(&x, CK_GEMX_LLB, fr, 4);
    x.rx_count = 1;
    x.rx_buf_len = 64;
    x.raw_rx_outside = OUTBASE;
    memset(f.outside, 0xa5, sizeof f.outside);
    CHECK(ck_gem_xfer(&g, &x) == 0);
    CHECK(g.halted == 0 && !ck_dmaw_halted(&dw));
    CHECK(f.outside_writes == 1);                       /* the fake (no RC window) let it through */
    CHECK(memcmp(f.outside, fr, 60) == 0 && f.outside[60] == 0xa5);
    CHECK(x.rx_len == 60 && x.rx_done);
    CHECK(f.bme_on_n == 1 && f.bme_off_n == 1);
    /* the in-window RX buffer stayed empty: the data went where the raw descriptor said */
    {
        uint32_t i, nz = 0;
        for (i = 0; i < 60; i++) nz += x.rx_data[i] != 0;
        CHECK(nz == 0);
    }
    fresh();
    mkx(&x, CK_GEMX_LLB, fr, 5);
    x.rx_count = 1;
    x.raw_tx_outside = OUTBASE;
    CHECK(ck_gem_xfer(&g, &x) == 0);
    CHECK(f.outside_access >= 1);  /* the fake saw a read outside; the real test reads whether the hardware blocked it */
    CHECK(g.halted == 0);
}

static void t_frames(void)
{
    uint8_t a[64], b[64], c[64];
    uint8_t tpa[4] = {192, 168, 1, 1};
    CHECK(ck_gem_frame_build(CK_GEMF_RAW, MAC, 0x01020304u, 0, a, sizeof a) == 60);
    CHECK(ck_gem_frame_build(CK_GEMF_RAW, MAC, 0x01020305u, 0, b, sizeof b) == 60);
    CHECK(a[0] == 0xff && a[5] == 0xff && memcmp(a + 6, MAC, 6) == 0 && a[12] == 0x88 && a[13] == 0xb5);
    CHECK(memcmp(a + 14, "AIENOS-PI5-NET3", 16) == 0);
    CHECK(a[30] == 1 && a[31] == 2 && a[32] == 3 && a[33] == 4);   /* sequence number, big endian */
    CHECK(ck_gem_frame_diff(a, 60, b, 60) != 0);                    /* different sequence = different frame */
    CHECK(ck_gem_frame_build(CK_GEMF_ARP, MAC, 9, tpa, c, sizeof c) == 60);
    CHECK(c[12] == 0x08 && c[13] == 0x06 && c[14] == 0 && c[15] == 1 && c[16] == 8 && c[17] == 0 && c[18] == 6 && c[19] == 4 && c[21] == 1);
    CHECK(memcmp(c + 22, MAC, 6) == 0 && c[28] == 0 && c[31] == 0 && memcmp(c + 38, tpa, 4) == 0); /* probe: sender IP 0.0.0.0 */
    CHECK(c[50] == 9);
    CHECK(ck_gem_frame_build(99, MAC, 1, 0, a, sizeof a) == 0 && ck_gem_frame_build(CK_GEMF_RAW, MAC, 1, 0, a, 59) == 0);
    /* diff: identical, last byte, length */
    memcpy(b, a, 60);
    CHECK(ck_gem_frame_diff(a, 60, b, 60) == 0);
    b[59] ^= 1;
    CHECK(ck_gem_frame_diff(a, 60, b, 60) == 60);
    b[59] ^= 1;
    b[0] ^= 1;
    CHECK(ck_gem_frame_diff(a, 60, b, 60) == 1);
    b[0] ^= 1;
    CHECK(ck_gem_frame_diff(a, 60, b, 59) == 60);
}

static void t_mdio_phy(void)
{
    struct ck_phy_link l;
    uint16_t aux = 0, clk = 0;
    int link = 0, fd = 0;
    uint32_t sp = 0;
    fresh();
    /* IEEE 802.3 clause 22 write frame: ST=01 OP=01 PHYAD REGAD TA=10 DATA */
    CHECK(ck_gem_mdio_frame_write(1, 0, 0x4140) == (0x40000000u | (1u << 28) | (1u << 23) | (2u << 16) | 0x4140u));
    CHECK(ck_gem_mdio_write(&fio, 1, 0, 0x4140) == 0 && f.phy[0] == 0x4140);
    CHECK(ck_gem_mdio_write(&fio, 32, 0, 0) != 0 && ck_gem_mdio_write(&fio, 1, 32, 0) != 0);
    /* link resolution: 1000 full from the partner's STAT1000 */
    fresh();
    f.phy[0] = 0x1140; f.phy[1] = 0x796d; f.phy[9] = 0x0300; f.phy[10] = 0x0800;
    CHECK(ck_phy_link_read(&fio, 1, &l) == 0 && l.link && l.aneg_done && l.speed == 1000 && l.full_duplex);
    f.phy[10] = 0; f.phy[4] = 0x01e1; f.phy[5] = 0x0100 | 0x0001;
    CHECK(ck_phy_link_read(&fio, 1, &l) == 0 && l.speed == 100 && l.full_duplex);
    f.phy[5] = 0x0020 | 0x0001;
    CHECK(ck_phy_link_read(&fio, 1, &l) == 0 && l.speed == 10 && !l.full_duplex);
    f.phy[1] = 0x7969; /* no link */
    CHECK(ck_phy_link_read(&fio, 1, &l) == 0 && !l.link && l.speed == 0);
    f.phy[1] = 0x794d; /* link, autoneg not complete: unresolved */
    CHECK(ck_phy_link_read(&fio, 1, &l) == 0 && l.link && !l.aneg_done && l.speed == 0);
    /* ETH_CFG STATUS decode */
    ck_eth_cfg_status_decode(0x00000005u, &link, &sp, &fd);
    CHECK(link == 0 || link == 1);
    ck_eth_cfg_status_decode(0x0000000bu, &link, &sp, &fd);
    CHECK(link == 1 && sp == 100 && fd == 1);
    ck_eth_cfg_status_decode(0x00000004u, &link, &sp, &fd);
    CHECK(link == 0 && sp == 1000 && fd == 0);
    ck_eth_cfg_status_decode(0x00000000u, &link, &sp, &fd);
    CHECK(sp == 10);
    /* RGMII-ID clock delays as Linux sets them */
    fresh();
    CHECK(ck_phy_rgmii_id_config(&fio, 1, &aux, &clk) == 0);
    CHECK((f.phy[0x18] & 0x8000u) && (f.phy[0x18] & 0x0100u) && (f.phy[0x18] & 7u) == 7u);
    CHECK(clk == 0x0010 && (f.shadow[3] & (1u << 9)) && (f.shadow[3] & 0x0010));
}

/* ---- bus-master through the root complex config window ---- */
static uint32_t cmd_status, cfg_index, stuck_bme;
static int cfg_writes_status_ones;
static uint32_t rc_rd(void *c, uint32_t off)
{
    (void)c;
    if (off == CK_PI5PCIE_EXT_CFG_INDEX)
        return cfg_index;
    if (off >= 0x8000 && off < 0x9000)
        return (cfg_index == 0x00100000u && off - 0x8000 == CK_PI5NET_PCI_COMMAND) ? cmd_status : 0;
    return 0;
}
static void rc_wr(void *c, uint32_t off, uint32_t v)
{
    (void)c;
    if (off == CK_PI5PCIE_EXT_CFG_INDEX) {
        cfg_index = v;
        return;
    }
    if (off >= 0x8000 && off < 0x9000 && cfg_index == 0x00100000u && off - 0x8000 == CK_PI5NET_PCI_COMMAND) {
        if (v >> 16)
            cfg_writes_status_ones++;
        cmd_status = (cmd_status & 0xffff0000u & ~(v & 0xffff0000u)) | (v & 0xffffu);
        if (stuck_bme)
            cmd_status |= CK_PI5NET_CMD_BME;
    }
}
static struct ck_pi5pcie_io rcio = {rc_rd, rc_wr, 0};

static void t_bme_set(void)
{
    cmd_status = (0x0010u << 16) | 0x0002u;
    cfg_index = 0;
    stuck_bme = 0;
    cfg_writes_status_ones = 0;
    CHECK(ck_pi5gem_bme_set(&rcio, 1) == 0 && (cmd_status & 0xffffu) == 0x0006u);
    CHECK((cmd_status >> 16) == 0x0010u && cfg_writes_status_ones == 0); /* RW1C status never written back as ones */
    CHECK(ck_pi5gem_bme_set(&rcio, 0) == 0 && (cmd_status & 0xffffu) == 0x0002u);
    stuck_bme = 1; /* a device that ignores the clear must be reported, not trusted */
    cmd_status = (0x0010u << 16) | 0x0006u;
    CHECK(ck_pi5gem_bme_set(&rcio, 0) == CK_GEM_E_BME);
}

int main(void)
{
    t_probe();
    t_loopback();
    t_phy_loopback();
    t_wire_no_loop();
    t_refuse_outside();
    t_hwwin_gate();
    t_arg_checks();
    t_device_lies();
    t_bme_failures();
    t_tieoff_and_queues();
    t_quiesce_order();
    t_raw_outside_for_hw_test();
    t_frames();
    t_mdio_phy();
    t_bme_set();
    free(f.mem);
    return ck_t_verdict("test_pi5_gem");
}
