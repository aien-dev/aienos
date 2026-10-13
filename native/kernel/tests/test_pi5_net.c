/* test_pi5_net.c -- Pi 5 network lane cut 2 (dev/pi5_net.c) over FAKE registers: the inbound
 * window plan and its register sequence, the RP1 bus-master quiesce, the outbound window decode,
 * the RP1 clock decisions, the PHY reset line sequence, the GEM MDIO read and the PHY ID decode.
 * Hosted: this proves the decisions and the order of register writes, NOT the hardware. Run under
 * ASan/UBSan and with each CK_NET_MUTANT_* (make pi5-net-mutants); every mutant must make it FAIL. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ck_test.h"
#include "pi5_net.h"

#define MiB (1ull << 20)
#define GiB (1ull << 30)

/* ===================== fake root complex ===================== */
struct frc {
    uint32_t regs[0xa000 / 4];
    uint32_t cmd_status;      /* RP1 config dword 1: status[31:16] | command[15:0] */
    uint32_t cmd_stuck_bme;   /* 1: BME bit ignores clears */
    uint32_t hi_stuck;        /* 1: window 0 HI register ignores writes */
    uint32_t w3_stuck;        /* 1: window 3 cannot be switched off */
    uint32_t index;
    /* write log for window 0 */
    uint32_t nwr, order_violations;
    uint32_t lo_writes[16], nlo;
    uint32_t cfg_writes[8], ncfg;
};
static struct frc fr;

static uint32_t fr_rd(void *c, uint32_t off)
{
    struct frc *f = c;
    if (off == CK_PI5PCIE_EXT_CFG_INDEX)
        return f->index;
    if (off >= 0x8000 && off < 0x9000) {
        if (f->index != 0x00100000u)
            return 0xffffffffu;
        if (off - 0x8000 == CK_PI5NET_PCI_COMMAND)
            return f->cmd_status;
        return 0;
    }
    return f->regs[off / 4];
}

static void fr_wr(void *c, uint32_t off, uint32_t v)
{
    struct frc *f = c;
    f->nwr++;
    if (off == CK_PI5PCIE_EXT_CFG_INDEX) {
        f->index = v;
        return;
    }
    if (off >= 0x8000 && off < 0x9000) {
        if (f->index == 0x00100000u && off - 0x8000 == CK_PI5NET_PCI_COMMAND) {
            uint32_t status = f->cmd_status >> 16;
            if (f->ncfg < 8)
                f->cfg_writes[f->ncfg] = v;
            f->ncfg++;
            status &= ~(v >> 16); /* RW1C */
            f->cmd_status = (status << 16) | (v & 0xffffu);
            if (f->cmd_stuck_bme)
                f->cmd_status |= CK_PI5NET_CMD_BME;
        }
        return;
    }
    if (off == CK_PI5NET_IB0_LO) {
        if (f->nlo < 16)
            f->lo_writes[f->nlo] = v;
        f->nlo++;
    }
    if (off == CK_PI5NET_IB0_HI || off == CK_PI5NET_IB0_REMAP_LO || off == CK_PI5NET_IB0_REMAP_HI) {
        if (f->regs[CK_PI5NET_IB0_LO / 4] & 0x1fu)
            f->order_violations++; /* a half of an ENABLED window changed under traffic */
        if (off == CK_PI5NET_IB0_HI && f->hi_stuck)
            return;
        if (off == CK_PI5NET_IB0_REMAP_LO)
            v &= 0xfffff001u;
        if (off == CK_PI5NET_IB0_REMAP_HI)
            v &= 0xffu;
    }
    if (off == 0x40d4u + 2 * 8u && f->w3_stuck) /* window 3 */
        return;
    f->regs[off / 4] = v;
}
static struct ck_pi5pcie_io fio = {fr_rd, fr_wr, &fr};

static void fr_fresh(void)
{
    memset(&fr, 0, sizeof fr);
    fr.cmd_status = (0x0010u << 16) | 0x0006u; /* status: capability list; command: MEM + BME */
    /* the firmware's window 0: bus 0 -> cpu 0, 64 GiB (size code 21), remap on */
    fr.regs[CK_PI5NET_IB0_LO / 4] = 21;
    fr.regs[CK_PI5NET_IB0_HI / 4] = 0;
    fr.regs[CK_PI5NET_IB0_REMAP_LO / 4] = 1;
    fr.regs[CK_PI5NET_IB0_REMAP_HI / 4] = 0;
}

static void t_size_code(void)
{
    CHECK(ck_pi5net_ib_size_code(4096) == 0x1c);
    CHECK(ck_pi5net_ib_size_code(32768) == 0x1f);
    CHECK(ck_pi5net_ib_size_code(65536) == 1);
    CHECK(ck_pi5net_ib_size_code(2 * MiB) == 6);
    CHECK(ck_pi5net_ib_size_code(64 * GiB) == 21);
    CHECK(ck_pi5net_ib_size_code(0) == 0);
    CHECK(ck_pi5net_ib_size_code(3 * MiB) == 0);      /* not a power of two */
    CHECK(ck_pi5net_ib_size_code(2048) == 0);         /* below 4 KiB */
    CHECK(ck_pi5net_ib_size_code(128 * GiB) == 0);    /* above 64 GiB */
    /* agrees with the decoder cut 1 uses to read the registers back */
    for (uint32_t lg = 12; lg <= 36; lg++) {
        uint64_t sz = 0;
        CHECK(ck_pi5pcie_ib_size_decode(ck_pi5net_ib_size_code(1ull << lg), &sz) == 1 && sz == (1ull << lg));
    }
}

static void t_plan(void)
{
    struct ck_pi5net_ibprog p;
    /* the real Pi run: bounce cpu 0x4400000 size 0x200000 */
    CHECK(ck_pi5net_ib_plan(0x4400000ull, 0x200000ull, &p) == 0);
    CHECK(p.bus_base == 0x4400000ull && p.cpu_base == 0x4400000ull && p.size == 0x200000ull);
    CHECK(p.size_code == 6 && p.extra_bytes == 0);
    CHECK(p.lo == 0x04400006u && p.hi == 0 && p.remap_lo == 0x04400001u && p.remap_hi == 0);
    /* not a power of two: rounds up, the extra is reported */
    CHECK(ck_pi5net_ib_plan(0x4400000ull, 0x180000ull, &p) == 0 && p.size == 0x200000ull && p.extra_bytes == 0x80000ull);
    /* a region that straddles an aligned block of its own size must get the next size up */
    CHECK(ck_pi5net_ib_plan(0x4500000ull, 0x200000ull, &p) == 0);
    CHECK(p.size == 0x400000ull && p.cpu_base == 0x4400000ull && p.extra_bytes == 0x200000ull);
    CHECK(p.cpu_base <= 0x4500000ull && p.cpu_base + p.size >= 0x4700000ull);
    /* high address: the upper halves carry the bits above 32 */
    CHECK(ck_pi5net_ib_plan(0x880000000ull, 0x200000ull, &p) == 0);
    CHECK(p.hi == 8 && p.remap_hi == 8 && p.lo == (0x80000000u | 6) && p.remap_lo == 0x80000001u);
    /* small region: 4 KiB window */
    CHECK(ck_pi5net_ib_plan(0x10000ull, 0x1000ull, &p) == 0 && p.size == 0x1000ull && p.size_code == 0x1c);
    /* refusals */
    CHECK(ck_pi5net_ib_plan(0x4400000ull, 0, &p) == CK_PI5NET_E_ARG);
    CHECK(ck_pi5net_ib_plan(UINT64_MAX - 10, 0x1000, &p) == CK_PI5NET_E_ARG);
    CHECK(ck_pi5net_ib_plan(0, 128 * GiB, &p) == CK_PI5NET_E_RANGE);
    CHECK(ck_pi5net_ib_plan((1ull << 40) - 0x1000, 0x2000, &p) == CK_PI5NET_E_RANGE); /* passes 40 bits */
    CHECK(ck_pi5net_ib_plan(0x4400000ull, 0x200000ull, NULL) == CK_PI5NET_E_ARG);
    /* property: the window always holds the region, is power-of-two sized, aligned, and minimal */
    srand(12345);
    for (int i = 0; i < 20000; i++) {
        uint64_t b = ((uint64_t)rand() << 12) % (1ull << 38);
        uint64_t s = ((uint64_t)(rand() % 0x400) + 1) << (12 + rand() % 14);
        if (ck_pi5net_ib_plan(b, s, &p) != 0)
            continue;
        CHECK(p.size && (p.size & (p.size - 1)) == 0 && (p.cpu_base & (p.size - 1)) == 0);
        CHECK(p.cpu_base <= b && p.cpu_base + p.size >= b + s);
        CHECK(p.extra_bytes == p.size - s);
        if (p.size > 4096) { /* minimality: the half-size aligned block around b does not hold the region */
            uint64_t h = p.size / 2, hb = b & ~(h - 1);
            CHECK(hb + h < b + s);
        }
        CHECK(p.bus_base == p.cpu_base);
    }
}

static void t_plan_then_registers_then_verdict(void)
{
    struct ck_pi5net_ibprog p;
    struct ck_pi5net_ibsaved sv;
    struct ck_pi5pcie_ibwin w[CK_PI5PCIE_IB_WINDOWS];
    struct ck_pi5pcie_dmav dv;
    uint32_t nd = 99;
    fr_fresh();
    for (uint32_t i = 0; i < CK_PI5PCIE_IB_WINDOWS; i++)
        CHECK(ck_pi5pcie_ib_read(&fio, i, &w[i]) == 0);
    CHECK(ck_pi5pcie_ib_verdict(w, CK_PI5PCIE_IB_WINDOWS, 0, 0x4400000ull, 0x200000ull, &dv) == 0);
    CHECK(dv.verdict == CK_PI5PCIE_DMA_WIDER && dv.reach_bytes == 64 * GiB); /* the cut 1 result */
    CHECK(ck_pi5net_confine_label(&dv, NULL) == CK_PI5NET_CONF_NOT_CONFINED);
    CHECK(ck_pi5net_ib_plan(0x4400000ull, 0x200000ull, &p) == 0);
    CHECK(ck_pi5net_ib_apply(&fio, &p, &sv, &nd) == 0 && nd == 0);
    for (uint32_t i = 0; i < CK_PI5PCIE_IB_WINDOWS; i++)
        CHECK(ck_pi5pcie_ib_read(&fio, i, &w[i]) == 0);
    CHECK(w[0].enabled && w[0].size_valid && w[0].remap_en && w[0].size == 0x200000ull);
    CHECK(w[0].bus_base == 0x4400000ull && w[0].cpu_base == 0x4400000ull);
    CHECK(ck_pi5pcie_ib_verdict(w, CK_PI5PCIE_IB_WINDOWS, 0, 0x4400000ull, 0x200000ull, &dv) == 0);
    CHECK(dv.verdict == CK_PI5PCIE_DMA_CONFINED && dv.reach_bytes == 0x200000ull && dv.outside_bytes == 0);
    CHECK(ck_pi5net_confine_label(&dv, &p) == CK_PI5NET_CONF_CONFINED);
    /* a region that needed a bigger block: PARTIAL with exactly the plan's extra, not CONFINED */
    fr_fresh();
    CHECK(ck_pi5net_ib_plan(0x4500000ull, 0x200000ull, &p) == 0);
    CHECK(ck_pi5net_ib_apply(&fio, &p, &sv, &nd) == 0);
    for (uint32_t i = 0; i < CK_PI5PCIE_IB_WINDOWS; i++)
        CHECK(ck_pi5pcie_ib_read(&fio, i, &w[i]) == 0);
    CHECK(ck_pi5pcie_ib_verdict(w, CK_PI5PCIE_IB_WINDOWS, 0, 0x4500000ull, 0x200000ull, &dv) == 0);
    CHECK(dv.verdict == CK_PI5PCIE_DMA_WIDER && dv.outside_bytes == 0x200000ull && dv.inside_bytes == 0x200000ull);
    CHECK(ck_pi5net_confine_label(&dv, &p) == CK_PI5NET_CONF_PARTIAL);
    CHECK(ck_pi5net_confine_label(&dv, NULL) == CK_PI5NET_CONF_NOT_CONFINED); /* without the plan it is just wide */
    /* the other verdicts map to BROKEN / UNKNOWN */
    dv.verdict = CK_PI5PCIE_DMA_MISS;
    CHECK(ck_pi5net_confine_label(&dv, &p) == CK_PI5NET_CONF_BROKEN);
    dv.verdict = CK_PI5PCIE_DMA_UNKNOWN;
    CHECK(ck_pi5net_confine_label(&dv, &p) == CK_PI5NET_CONF_UNKNOWN);
    CHECK(strcmp(ck_pi5net_confine_name(CK_PI5NET_CONF_PARTIAL), "PARTIAL") == 0);
    CHECK(strcmp(ck_pi5net_confine_name(CK_PI5NET_CONF_CONFINED), "CONFINED") == 0);
}

static void t_apply_order(void)
{
    struct ck_pi5net_ibprog p;
    struct ck_pi5net_ibsaved sv;
    uint32_t nd = 0;
    fr_fresh();
    CHECK(ck_pi5net_ib_plan(0x4400000ull, 0x200000ull, &p) == 0);
    CHECK(ck_pi5net_ib_apply(&fio, &p, &sv, &nd) == 0);
    CHECK(fr.nlo == 2);                                  /* off, then on */
    CHECK((fr.lo_writes[0] & 0x1f) == 0);                /* window is OFF before its halves change */
    CHECK(fr.lo_writes[fr.nlo - 1] == p.lo);             /* the size code (enable) is the last write to LO */
    CHECK(fr.order_violations == 0);
    CHECK(sv.lo == 21 && sv.hi == 0 && sv.remap_lo == 1); /* firmware window saved for the restore */
    /* other enabled windows are switched off */
    fr_fresh();
    fr.regs[(0x40d4u) / 4] = 0x10000000u | 6;       /* window 1 */
    fr.regs[(0x40d4u + 3 * 8u) / 4] = 0x20000000u | 1; /* window 4 */
    CHECK(ck_pi5net_ib_apply(&fio, &p, &sv, &nd) == 0 && nd == 2);
    CHECK((fr.regs[0x40d4u / 4] & 0x1f) == 0 && (fr.regs[(0x40d4u + 24u) / 4] & 0x1f) == 0);
    CHECK(fr.regs[0x40d4u / 4] >> 5 == 0x10000000u >> 5); /* base bits kept, only the size code cleared */
}

static void t_apply_failure_restores(void)
{
    struct ck_pi5net_ibprog p;
    struct ck_pi5net_ibsaved sv;
    uint32_t nd = 0;
    CHECK(ck_pi5net_ib_plan(0x4400000ull, 0x200000ull, &p) == 0);
    /* hardware ignores the HI write: readback does not match, firmware window is put back */
    fr_fresh();
    fr.hi_stuck = 1;
    /* make the plan need a non-zero HI so the stuck register matters */
    CHECK(ck_pi5net_ib_plan(0x880000000ull, 0x200000ull, &p) == 0);
    CHECK(ck_pi5net_ib_apply(&fio, &p, &sv, &nd) == CK_PI5NET_E_READBACK);
    CHECK(fr.regs[CK_PI5NET_IB0_LO / 4] == 21 && fr.regs[CK_PI5NET_IB0_HI / 4] == 0 &&
          fr.regs[CK_PI5NET_IB0_REMAP_LO / 4] == 1 && fr.regs[CK_PI5NET_IB0_REMAP_HI / 4] == 0);
    /* another window that refuses to switch off: not confined, so refuse and restore */
    fr_fresh();
    fr.regs[(0x40d4u + 2 * 8u) / 4] = 0x30000000u | 7; /* window 3 */
    fr.w3_stuck = 1;
    CHECK(ck_pi5net_ib_plan(0x4400000ull, 0x200000ull, &p) == 0);
    CHECK(ck_pi5net_ib_apply(&fio, &p, &sv, &nd) == CK_PI5NET_E_READBACK);
    CHECK(fr.regs[CK_PI5NET_IB0_LO / 4] == 21);
    /* arguments */
    CHECK(ck_pi5net_ib_apply(NULL, &p, &sv, &nd) == CK_PI5NET_E_ARG);
    memset(&p, 0, sizeof p);
    CHECK(ck_pi5net_ib_apply(&fio, &p, &sv, &nd) == CK_PI5NET_E_ARG); /* a plan with no size code */
}

static void t_quiesce(void)
{
    uint16_t saved = 0xdead;
    fr_fresh();
    CHECK(ck_pi5net_rp1_quiesce(&fio, &saved) == 0 && saved == 0x0006);
    CHECK((fr.cmd_status & 0xffffu) == 0x0002);           /* BME off, MEM kept */
    CHECK((fr.cmd_status >> 16) == 0x0010);               /* status bits not cleared by writing zeros */
    CHECK(fr.ncfg == 1 && (fr.cfg_writes[0] >> 16) == 0); /* the write carried no status ones */
    CHECK(fr.index == 0x00100000u);
    fr_fresh();
    fr.cmd_stuck_bme = 1;
    CHECK(ck_pi5net_rp1_quiesce(&fio, &saved) == CK_PI5NET_E_QUIESCE);
    CHECK(ck_pi5net_rp1_quiesce(&fio, NULL) == CK_PI5NET_E_ARG);
    /* config write addressing */
    fr_fresh();
    CHECK(ck_pi5net_cfg_write32(&fio, 1, 0, 0, 4, 0x2) == 0);
    CHECK(ck_pi5net_cfg_write32(&fio, 2, 0, 0, 4, 0) == CK_PI5NET_E_ARG);
    CHECK(ck_pi5net_cfg_write32(&fio, 1, 1, 0, 4, 0) == CK_PI5NET_E_ARG);
    CHECK(ck_pi5net_cfg_write32(&fio, 1, 0, 0, 5, 0) == CK_PI5NET_E_ARG);
    CHECK(ck_pi5net_cfg_write32(&fio, 1, 0, 0, 4096, 0) == CK_PI5NET_E_ARG);
    CHECK(ck_pi5net_cfg_write32(&fio, 0, 1, 0, 4, 0) == CK_PI5NET_E_ARG);
}

static void t_outbound(void)
{
    struct ck_pi5net_obwin w;
    /* the values edk2 PcieSetupOutboundWindow writes for CPU 0x1f00000000, 1 GiB, bus 0xc0000000 */
    uint64_t cpu_mb = 0x1f00000000ull / MiB, lim_mb = (0x1f00000000ull + GiB - 1) / MiB;
    fr_fresh();
    fr.regs[CK_PI5NET_OB0_BASE_LIMIT / 4] = (uint32_t)((cpu_mb << 4) | (lim_mb << 20));
    fr.regs[CK_PI5NET_OB0_BASE_HI / 4] = (uint32_t)(cpu_mb >> 12);
    fr.regs[CK_PI5NET_OB0_LIMIT_HI / 4] = (uint32_t)(lim_mb >> 12);
    fr.regs[CK_PI5NET_OB0_BUS_LO / 4] = 0xc0000000u;
    fr.regs[CK_PI5NET_OB0_BUS_HI / 4] = 0;
    CHECK(ck_pi5net_ob_read(&fio, &w) == 0 && w.valid);
    CHECK(w.cpu_base == 0x1f00000000ull && w.bus_base == 0xc0000000ull && w.size == GiB);
    CHECK(ck_pi5net_bus_to_cpu(&w, 0xc0000000ull, 0x108000) == 0x1f00000000ull);
    CHECK(ck_pi5net_bus_to_cpu(&w, 0xc0400000ull, 0x10000) == 0x1f00400000ull);
    CHECK(ck_pi5net_bus_to_cpu(&w, 0xbfffffffull, 0x10) == 0);               /* below the window */
    CHECK(ck_pi5net_bus_to_cpu(&w, 0xc0000000ull + GiB - 0x10, 0x20) == 0); /* runs past the end */
    CHECK(ck_pi5net_bus_to_cpu(&w, 0xc0000000ull + GiB - 0x10, 0x10) != 0); /* exactly to the end */
    CHECK(ck_pi5net_bus_to_cpu(&w, 0xc0000000ull, 2 * GiB) == 0);           /* longer than the window */
    CHECK(ck_pi5net_bus_to_cpu(&w, 0xc0000000ull, 0) == 0);
    CHECK(ck_pi5net_bus_to_cpu(NULL, 0xc0000000ull, 0x10) == 0);
    /* limit below base: not valid */
    fr.regs[CK_PI5NET_OB0_BASE_LIMIT / 4] = (uint32_t)((cpu_mb << 4) | ((lim_mb - 0x1000) << 20));
    fr.regs[CK_PI5NET_OB0_LIMIT_HI / 4] = 0x1e;
    CHECK(ck_pi5net_ob_read(&fio, &w) == 0 && !w.valid);
    CHECK(ck_pi5net_bus_to_cpu(&w, 0xc0000000ull, 0x10) == 0);
}

/* ===================== fake RP1 BAR1 ===================== */
#define NOFF 0x108000u
struct frp {
    uint32_t r[NOFF / 4];
    uint32_t wr_count[NOFF / 4];
    uint64_t t_us;       /* fake time */
    uint32_t order[256], nord;
    int enable_sticks;   /* clock ENABLE bit holds */
    /* GPIO32 pin model */
    int pin_forced;      /* 1: ext fault, pin reads 0 whatever we drive */
    uint64_t low_us;     /* total time the pin was driven low */
    int driven_low_before_oe, drove_low;
    uint64_t low_since;
    int low_now;
    /* GEM / MDIO model */
    uint32_t gem_busy_polls;     /* idle stays 0 for this many NSR reads after a MAN write */
    uint32_t busy_left;
    int phy_addr;                /* -1 none */
    uint32_t phy_ready_polls;    /* PHY returns 0xffff until this many reads happened */
    uint32_t phy_reads;
    uint16_t phy_regs[32];
    int never_idle;
    int bad_frame_seen;
    uint32_t last_man;
    int stuck_ncfg;
};
static struct frp fp;

static int pin_level(void)
{
    uint32_t oe = fp.r[CK_RP1_RIO1_OE / 4] & CK_RP1_GPIO_PIN_BIT, out = fp.r[CK_RP1_RIO1_OUT / 4] & CK_RP1_GPIO_PIN_BIT;
    if (fp.pin_forced)
        return 0;
    if (oe)
        return out ? 1 : 0;
    return 1; /* pulled up */
}

static void pin_track(void)
{
    int lv = pin_level();
    if (!lv && !fp.low_now) {
        fp.low_now = 1;
        fp.low_since = fp.t_us;
        fp.drove_low = 1;
        if (!(fp.r[CK_RP1_RIO1_OE / 4] & CK_RP1_GPIO_PIN_BIT))
            fp.driven_low_before_oe = 1;
    } else if (lv && fp.low_now) {
        fp.low_now = 0;
        fp.low_us += fp.t_us - fp.low_since;
    }
}

static uint32_t rp_rd(void *c, uint32_t off)
{
    (void)c;
    if (off == CK_RP1_RIO1_IN)
        return pin_level() ? CK_RP1_GPIO_PIN_BIT : 0;
    if (off == CK_RP1_ETH + CK_GEM_NSR) {
        if (fp.never_idle)
            return 0;
        if (fp.busy_left) {
            fp.busy_left--;
            return 0;
        }
        return CK_GEM_NSR_IDLE;
    }
    if (off == CK_RP1_ETH + CK_GEM_MAN) {
        /* stale until the transfer finished; the model keeps the data only for a correct read frame */
        if (fp.busy_left)
            return (fp.r[off / 4] & 0xffff0000u) | 0xdeadu;
        return fp.r[off / 4];
    }
    return fp.r[off / 4];
}

static void rp_wr(void *c, uint32_t off, uint32_t v)
{
    (void)c;
    if (fp.nord < 256)
        fp.order[fp.nord++] = off;
    fp.wr_count[off / 4]++;
    if (off >= CK_RP1_RIO1_OUT + CK_RP1_ATOMIC_SET && off < CK_RP1_RIO1_OUT + CK_RP1_ATOMIC_SET + 0x10) {
        uint32_t base = off - CK_RP1_ATOMIC_SET;
        fp.r[base / 4] |= v;
        pin_track();
        return;
    }
    if (off >= CK_RP1_RIO1_OUT + CK_RP1_ATOMIC_CLR && off < CK_RP1_RIO1_OUT + CK_RP1_ATOMIC_CLR + 0x10) {
        uint32_t base = off - CK_RP1_ATOMIC_CLR;
        fp.r[base / 4] &= ~v;
        pin_track();
        return;
    }
    if (off == CK_RP1_CLOCKS + CK_RP1_CLK_ETH_CTRL || off == CK_RP1_CLOCKS + CK_RP1_CLK_TSU_CTRL) {
        if (!fp.enable_sticks)
            v &= ~(uint32_t)CK_RP1_CLK_ENABLE;
    }
    if (off == CK_RP1_ETH + CK_GEM_NCFGR && fp.stuck_ncfg)
        return;
    if (off == CK_RP1_ETH + CK_GEM_MAN) {
        uint32_t phy = (v >> 23) & 31u, reg = (v >> 18) & 31u;
        fp.last_man = v;
        if ((v >> 30) != 1 || ((v >> 28) & 3u) != 2 || ((v >> 16) & 3u) != 2) {
            fp.bad_frame_seen = 1; /* not a clause 22 read: the model returns nothing useful */
            fp.r[off / 4] = v & 0xffff0000u;
        } else {
            uint16_t d = 0xffff;
            if ((int)phy == fp.phy_addr) {
                fp.phy_reads++;
                if (fp.phy_reads > fp.phy_ready_polls)
                    d = fp.phy_regs[reg];
            }
            fp.r[off / 4] = (v & 0xffff0000u) | d;
        }
        fp.busy_left = fp.gem_busy_polls;
        return;
    }
    fp.r[off / 4] = v;
    if (off == CK_RP1_GPIO32_PAD || off == CK_RP1_GPIO32_CTRL)
        pin_track();
}

static void rp_delay(void *c, uint32_t us)
{
    (void)c;
    fp.t_us += us;
}
static struct ck_rp1_io rio = {rp_rd, rp_wr, rp_delay, &fp};

static void rp_fresh(void)
{
    memset(&fp, 0, sizeof fp);
    fp.phy_addr = -1;
    /* clock block as left by a cold boot: PLL locked, secondary running, ETH/TSU off */
    fp.r[(CK_RP1_PLL_SYS + CK_RP1_PLL_CS) / 4] = 0x80000001u;
    fp.r[(CK_RP1_PLL_SYS + CK_RP1_PLL_FBDIV_INT) / 4] = 20;
    fp.r[(CK_RP1_PLL_SYS + CK_RP1_PLL_PRIM) / 4] = (5u << 16) | (1u << 12);
    fp.r[(CK_RP1_PLL_SYS + CK_RP1_PLL_SEC) / 4] = 0x80000000u | (8u << 8);
    fp.r[(CK_RP1_CLOCKS + CK_RP1_CLK_SYS_CTRL) / 4] = 2;
    fp.r[(CK_RP1_CLOCKS + CK_RP1_CLK_SYS_DIV) / 4] = 1;
    fp.r[(CK_RP1_CLOCKS + CK_RP1_CLK_SYS_SEL) / 4] = 4;
    fp.enable_sticks = 1;
}

static void t_clock_rates(void)
{
    struct ck_rp1_clk_regs r;
    rp_fresh();
    ck_rp1_clk_read(&rio, &r);
    CHECK(ck_rp1_pll_core_hz(&r) == 1000000000u);
    CHECK(ck_rp1_pll_sec_hz(&r) == 125000000u);
    CHECK(ck_rp1_pll_pri_hz(&r) == 200000000u);
    CHECK(ck_rp1_clk_sys_hz(&r) == 200000000u);
    CHECK(ck_rp1_clk_eth_hz(&r) == 0 && ck_rp1_clk_tsu_hz(&r) == 0);
    r.pll_cs = 1; /* unlocked */
    CHECK(ck_rp1_pll_core_hz(&r) == 0 && ck_rp1_pll_sec_hz(&r) == 0 && ck_rp1_pll_pri_hz(&r) == 0);
    rp_fresh();
    ck_rp1_clk_read(&rio, &r);
    r.pll_sec |= 1u << 16; /* divider held in reset */
    CHECK(ck_rp1_pll_sec_hz(&r) == 0);
    r.pll_sec = 0x80000000u | (12u << 8); /* divide by 12 */
    CHECK(ck_rp1_pll_sec_hz(&r) == 83333334u);
    r.pll_sec = 0x80000000u | (3u << 8); /* invalid field value defaults to 19 */
    CHECK(ck_rp1_pll_sec_hz(&r) == 52631579u);
    r.pll_sec = (8u << 8); /* divider not implemented (IMPL bit clear) */
    CHECK(ck_rp1_pll_sec_hz(&r) == 0);
    /* clk_sys on xosc: sel bit 0 */
    ck_rp1_clk_read(&rio, &r);
    r.sys_sel = 1;
    CHECK(ck_rp1_clk_sys_hz(&r) == 50000000u);
}

static void t_clock_decide(void)
{
    struct ck_rp1_clk_regs r;
    struct ck_rp1_clk_plan p;
    rp_fresh();
    ck_rp1_clk_read(&rio, &r);
    ck_rp1_clk_decide(&r, &p);
    CHECK(p.eth == CK_RP1_CLK_TO_ENABLE && p.eth_div == 1 && (p.eth_ctrl & CK_RP1_CLK_ENABLE) &&
          (p.eth_ctrl & CK_RP1_CLK_AUXSRC_MASK) == 0);
    CHECK(p.tsu == CK_RP1_CLK_TO_ENABLE && p.tsu_div == 1 && (p.tsu_ctrl & CK_RP1_CLK_ENABLE));
    /* a clock that is already on is left exactly as found, even at an odd rate */
    r.eth_ctrl = CK_RP1_CLK_ENABLE | (1u << CK_RP1_CLK_AUXSRC_SHIFT);
    r.eth_div = 2;
    ck_rp1_clk_decide(&r, &p);
    CHECK(p.eth == CK_RP1_CLK_ALREADY_ON && p.eth_div == 0 && p.eth_ctrl == 0);
    CHECK(ck_rp1_clk_eth_hz(&r) == 100000000u); /* pll_sys (200 MHz) / 2: reported, not changed */
    r.tsu_ctrl = CK_RP1_CLK_ENABLE;
    r.tsu_div = 1;
    ck_rp1_clk_decide(&r, &p);
    CHECK(p.tsu == CK_RP1_CLK_ALREADY_ON && ck_rp1_clk_tsu_hz(&r) == 50000000u);
    /* PLL not locked: ETH blocked, TSU (from xosc) is not */
    ck_rp1_clk_read(&rio, &r);
    r.pll_cs = 1;
    ck_rp1_clk_decide(&r, &p);
    CHECK(p.eth == CK_RP1_CLK_BLOCKED && p.tsu == CK_RP1_CLK_TO_ENABLE);
    /* secondary in reset */
    ck_rp1_clk_read(&rio, &r);
    r.pll_sec |= 1u << 16;
    ck_rp1_clk_decide(&r, &p);
    CHECK(p.eth == CK_RP1_CLK_BLOCKED);
    /* secondary not an exact multiple of 125 MHz (1000/9): refuse rather than run ETH at a wrong rate */
    ck_rp1_clk_read(&rio, &r);
    r.pll_sec = 0x80000000u | (9u << 8);
    ck_rp1_clk_decide(&r, &p);
    CHECK(p.eth == CK_RP1_CLK_BLOCKED);
    ck_rp1_clk_read(&rio, &r);
    r.pll_fbdiv_int = 30; /* core 1.5 GHz, sec 187.5 MHz: ratio 1 but not exact */
    ck_rp1_clk_decide(&r, &p);
    CHECK(p.eth == CK_RP1_CLK_BLOCKED);
    /* a faster secondary that divides exactly: divider = ratio (1000 MHz core / 8 = 125; make core 2000/8 = 250 -> 2) */
    ck_rp1_clk_read(&rio, &r);
    r.pll_fbdiv_int = 40;
    ck_rp1_clk_decide(&r, &p);
    CHECK(p.eth == CK_RP1_CLK_TO_ENABLE && p.eth_div == 2);
    /* and a secondary slower than 125 MHz is refused (ratio 0) */
    ck_rp1_clk_read(&rio, &r);
    r.pll_sec = 0x80000000u | (16u << 8); /* 1000/16 = 62.5 MHz */
    ck_rp1_clk_decide(&r, &p);
    CHECK(p.eth == CK_RP1_CLK_BLOCKED);
}

static void t_clock_apply(void)
{
    struct ck_rp1_clk_regs r;
    struct ck_rp1_clk_plan p;
    uint32_t eth_ctrl = (CK_RP1_CLOCKS + CK_RP1_CLK_ETH_CTRL) / 4, eth_div = (CK_RP1_CLOCKS + CK_RP1_CLK_ETH_DIV) / 4;
    uint32_t tsu_ctrl = (CK_RP1_CLOCKS + CK_RP1_CLK_TSU_CTRL) / 4;
    rp_fresh();
    ck_rp1_clk_read(&rio, &r);
    ck_rp1_clk_decide(&r, &p);
    CHECK(ck_rp1_clk_apply(&rio, &p) == 0);
    ck_rp1_clk_read(&rio, &r);
    CHECK(ck_rp1_clk_eth_hz(&r) == 125000000u && ck_rp1_clk_tsu_hz(&r) == 50000000u);
    /* order: divider, then source with the clock still off, then the enable */
    CHECK(fp.wr_count[eth_div] == 1 && fp.wr_count[eth_ctrl] == 2);
    {
        int i_div = -1, i_c1 = -1, i_c2 = -1;
        for (uint32_t i = 0; i < fp.nord; i++) {
            if (fp.order[i] == CK_RP1_CLOCKS + CK_RP1_CLK_ETH_DIV)
                i_div = (int)i;
            if (fp.order[i] == CK_RP1_CLOCKS + CK_RP1_CLK_ETH_CTRL) {
                if (i_c1 < 0)
                    i_c1 = (int)i;
                else
                    i_c2 = (int)i;
            }
        }
        CHECK(i_div >= 0 && i_div < i_c1 && i_c1 < i_c2);
    }
    /* already-on clocks get no write at all */
    rp_fresh();
    fp.r[eth_ctrl] = CK_RP1_CLK_ENABLE;
    fp.r[eth_div] = 1;
    fp.r[tsu_ctrl] = CK_RP1_CLK_ENABLE | 0x20;
    fp.r[(CK_RP1_CLOCKS + CK_RP1_CLK_TSU_DIV) / 4] = 1;
    ck_rp1_clk_read(&rio, &r);
    ck_rp1_clk_decide(&r, &p);
    fp.nord = 0;
    memset(fp.wr_count, 0, sizeof fp.wr_count);
    CHECK(ck_rp1_clk_apply(&rio, &p) == 0);
    CHECK(fp.nord == 0 && fp.r[eth_ctrl] == CK_RP1_CLK_ENABLE);
    /* enable does not stick: reported */
    rp_fresh();
    fp.enable_sticks = 0;
    ck_rp1_clk_read(&rio, &r);
    ck_rp1_clk_decide(&r, &p);
    CHECK(ck_rp1_clk_apply(&rio, &p) == CK_PI5NET_E_READBACK);
}

static void t_phy_reset(void)
{
    struct ck_rp1_phyreset pr;
    rp_fresh();
    fp.r[CK_RP1_GPIO32_CTRL / 4] = 0x1f | (1u << 20); /* NONE, with an interrupt-enable bit set */
    fp.r[CK_RP1_GPIO32_PAD / 4] = CK_RP1_PAD_OUT_DISABLE | 0x1;
    CHECK(ck_rp1_phy_reset(&rio, &pr) == 0);
    CHECK(fp.drove_low == 1);                             /* reset was really asserted */
    CHECK(fp.driven_low_before_oe == 0);                  /* the pin never went low before we owned it */
    CHECK(fp.low_us >= (uint64_t)CK_RP1_PHY_RESET_MS * 1000u); /* held for the dts reset time */
    CHECK(fp.low_us < 1000u * 1000u);
    CHECK(fp.t_us >= (uint64_t)(CK_RP1_PHY_RESET_MS + CK_RP1_PHY_SETTLE_MS) * 1000u);
    CHECK(pin_level() == 1);                              /* released at the end */
    CHECK((fp.r[CK_RP1_RIO1_OE / 4] & CK_RP1_GPIO_PIN_BIT) != 0);
    CHECK((fp.r[CK_RP1_GPIO32_CTRL / 4] & 0x1f) == CK_RP1_FSEL_GPIO && (fp.r[CK_RP1_GPIO32_CTRL / 4] & (1u << 20)));
    CHECK((fp.r[CK_RP1_GPIO32_PAD / 4] & CK_RP1_PAD_IN_ENABLE) && !(fp.r[CK_RP1_GPIO32_PAD / 4] & CK_RP1_PAD_OUT_DISABLE));
    CHECK((pr.in_low & CK_RP1_GPIO_PIN_BIT) == 0 && (pr.in_high & CK_RP1_GPIO_PIN_BIT) != 0);
    CHECK(pr.ctrl_before == (0x1f | (1u << 20)) && (pr.ctrl_after & 0x1f) == 5);
    /* the register addresses (bank 1 pin 4): see pinctrl-rp1.c bank table */
    CHECK(CK_RP1_GPIO32_CTRL == 0xd4024u && CK_RP1_GPIO32_PAD == 0xf4014u && CK_RP1_RIO1_OUT == 0xe4000u);
    /* a pin stuck low (external fault) is reported, not ignored */
    rp_fresh();
    fp.pin_forced = 1;
    CHECK(ck_rp1_phy_reset(&rio, &pr) == CK_PI5NET_E_READBACK);
}

static void gem_phy(uint32_t polls_busy, int addr, uint32_t ready_polls)
{
    rp_fresh();
    fp.gem_busy_polls = polls_busy;
    fp.phy_addr = addr;
    fp.phy_ready_polls = ready_polls;
    fp.phy_regs[2] = 0x600d;
    fp.phy_regs[3] = 0x84a2;
    fp.r[(CK_RP1_ETH + CK_GEM_NCR) / 4] = 0x00000003u;
    fp.r[(CK_RP1_ETH + CK_GEM_NCFGR) / 4] = 0x00000800u | (1u << 18);
}

static void t_mdio(void)
{
    uint16_t v = 0;
    struct ck_phy_id id;
    uint32_t att = 0;
    int hit = 0;
    CHECK(ck_gem_mdio_frame_read(1, 2) == 0x608a0000u);
    CHECK(ck_gem_mdio_frame_read(31, 31) == (0x60000000u | (31u << 23) | (31u << 18) | 0x20000u));
    CHECK(ck_gem_mdc_div_code(0) == 7 && ck_gem_mdc_div_code(20000000) == 0 && ck_gem_mdc_div_code(20000001) == 1 &&
          ck_gem_mdc_div_code(80000000) == 2 && ck_gem_mdc_div_code(120000000) == 3 &&
          ck_gem_mdc_div_code(160000000) == 4 && ck_gem_mdc_div_code(200000000) == 5 &&
          ck_gem_mdc_div_code(240000000) == 5 && ck_gem_mdc_div_code(320000000) == 6 &&
          ck_gem_mdc_div_code(400000000) == 7);
    /* 200 MHz pclk / 96 = 2.08 MHz MDC, under the 2.5 MHz limit */
    CHECK(200000000u / 96u <= 2500000u);
    gem_phy(3, 1, 0);
    CHECK(ck_gem_mdio_read(&rio, 1, 2, &v) == 0 && v == 0x600d);
    CHECK(ck_gem_mdio_read(&rio, 1, 3, &v) == 0 && v == 0x84a2);
    CHECK(fp.bad_frame_seen == 0 && fp.last_man == ck_gem_mdio_frame_read(1, 3));
    CHECK(ck_gem_mdio_read(&rio, 5, 2, &v) == 0 && v == 0xffff); /* nothing at address 5 */
    CHECK(ck_gem_mdio_read(&rio, 32, 2, &v) == CK_PI5NET_E_ARG && ck_gem_mdio_read(&rio, 1, 32, &v) == CK_PI5NET_E_ARG);
    CHECK(ck_gem_mdio_read(&rio, 1, 2, NULL) == CK_PI5NET_E_ARG);
    /* the management logic never goes idle: bounded wait, then timeout (no hang) */
    gem_phy(0, 1, 0);
    fp.never_idle = 1;
    CHECK(ck_gem_mdio_read(&rio, 1, 2, &v) == CK_PI5NET_E_TIMEOUT);
    CHECK(fp.t_us >= (uint64_t)CK_GEM_MDIO_POLLS * CK_GEM_MDIO_POLL_US);
    /* enable: MPE set, other NCR bits kept, divider replaced and other NCFGR bits kept */
    gem_phy(0, 1, 0);
    fp.r[(CK_RP1_ETH + CK_GEM_NCR) / 4] = 0x00000003u;
    CHECK(ck_gem_mdio_enable(&rio, 200000000u) == 0);
    CHECK(fp.r[(CK_RP1_ETH + CK_GEM_NCR) / 4] == (0x3u | CK_GEM_NCR_MPE));
    CHECK(fp.r[(CK_RP1_ETH + CK_GEM_NCFGR) / 4] == (0x800u | (5u << 18)));
    gem_phy(0, 1, 0);
    fp.stuck_ncfg = 1;
    CHECK(ck_gem_mdio_enable(&rio, 200000000u) == CK_PI5NET_E_READBACK);
    /* find: the PHY answers only after a few polls (still in reset): retries, then reports attempts */
    gem_phy(1, 1, 6); /* the first 6 register reads return 0xffff: 3 attempts of 2 reads fail, the 4th works */
    CHECK(ck_phy_find(&rio, 1, 20, 25, &id, &att, &hit) == 0);
    CHECK(att == 4 && id.id == 0x600d84a2u && id.cls == CK_PHY_BCM54213PE);
    /* never answers at 1, but something answers at 7: reported for the diagnosis */
    gem_phy(0, 7, 0);
    CHECK(ck_phy_find(&rio, 1, 3, 1, &id, &att, &hit) == CK_PI5NET_E_TIMEOUT && att == 3 && hit == 7);
    CHECK(id.cls == CK_PHY_ABSENT);
    gem_phy(0, -1, 0);
    CHECK(ck_phy_find(&rio, 1, 2, 1, &id, &att, &hit) == CK_PI5NET_E_TIMEOUT && hit == -1);
    CHECK(ck_phy_find(&rio, 1, 0, 1, &id, &att, &hit) == CK_PI5NET_E_ARG);
}

static void t_phy_id(void)
{
    struct ck_phy_id d;
    /* BCM54213PE: Linux PHY_ID_BCM54213PE 0x600d84a2; OUI 18-C0-86 is "Broadcom" in the IEEE registry */
    ck_phy_id_decode(0x600d, 0x84a2, &d);
    CHECK(d.id == 0x600d84a2u && d.oui == 0x18c086u && d.model == 0x0a && d.rev == 2 && d.cls == CK_PHY_BCM54213PE);
    /* BCM54210E (0x600d84a0) is Broadcom but NOT this chip: Linux matches the whole 32 bits */
    ck_phy_id_decode(0x600d, 0x84a0, &d);
    CHECK(d.cls == CK_PHY_BROADCOM_OTHER && d.oui == 0x18c086u);
    ck_phy_id_decode(0x600d, 0x84a3, &d); /* a later revision of 54213PE is not exact either */
    CHECK(d.cls == CK_PHY_BROADCOM_OTHER);
    /* independent vector: Realtek RTL8211 0x001cc916, OUI 00-E0-4C */
    ck_phy_id_decode(0x001c, 0xc916, &d);
    CHECK(d.oui == 0x00e04cu && d.cls == CK_PHY_OTHER);
    /* independent vector: Broadcom BCM5421 0x002060e0, OUI 00-10-18 */
    ck_phy_id_decode(0x0020, 0x60e0, &d);
    CHECK(d.oui == 0x001018u && d.cls == CK_PHY_BROADCOM_OTHER);
    ck_phy_id_decode(0xffff, 0xffff, &d);
    CHECK(d.cls == CK_PHY_ABSENT);
    ck_phy_id_decode(0x0000, 0x0000, &d);
    CHECK(d.cls == CK_PHY_ABSENT);
    CHECK(strcmp(ck_phy_class_name(CK_PHY_BCM54213PE), "BCM54213PE") == 0);
}

int main(void)
{
    t_size_code();
    t_plan();
    t_plan_then_registers_then_verdict();
    t_apply_order();
    t_apply_failure_restores();
    t_quiesce();
    t_outbound();
    t_clock_rates();
    t_clock_decide();
    t_clock_apply();
    t_phy_reset();
    t_mdio();
    t_phy_id();
    return ck_t_verdict("test_pi5_net");
}
