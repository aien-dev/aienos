/* pi5_net.c -- see pi5_net.h. The decision and register-sequence logic is hosted-testable
 * (tests/test_pi5_net.c); the MMIO glue at the bottom is the CK_PI5_NET image only. */
#include "pi5_net.h"

/* TEST-only mutants (make pi5-net-mutants): each removes one decision or one step and must
 * make test_pi5_net FAIL. Host builds only; never part of an image. */
#if defined(CK_NET_MUTANT_NO_STRADDLE) || defined(CK_NET_MUTANT_NO_REMAP_EN) || \
    defined(CK_NET_MUTANT_NO_DISABLE_FIRST) || defined(CK_NET_MUTANT_NO_READBACK) || \
    defined(CK_NET_MUTANT_NO_RESTORE) || defined(CK_NET_MUTANT_NO_OTHERS) || \
    defined(CK_NET_MUTANT_NO_STATUS_MASK) || defined(CK_NET_MUTANT_NO_QUIESCE_CHECK) || \
    defined(CK_NET_MUTANT_OB_NO_LIMIT) || defined(CK_NET_MUTANT_NO_ASSERT) || defined(CK_NET_MUTANT_NO_HOLD) || \
    defined(CK_NET_MUTANT_NO_RELEASE) || defined(CK_NET_MUTANT_NO_HIGH_FIRST) || \
    defined(CK_NET_MUTANT_NO_IDLE_AFTER) || defined(CK_NET_MUTANT_NO_MPE) || \
    defined(CK_NET_MUTANT_TOUCH_ON_CLOCK) || defined(CK_NET_MUTANT_NO_EXACT_DIV) || \
    defined(CK_NET_MUTANT_NO_CLK_VERIFY) || defined(CK_NET_MUTANT_OUI_ORDER) || \
    defined(CK_NET_MUTANT_BAD_CLASS) || defined(CK_NET_MUTANT_NO_BOUNDS) || defined(CK_NET_MUTANT_NO_MDC_DIV) || \
    defined(CK_NET_MUTANT_PARTIAL_ANY)
#if !__STDC_HOSTED__
#error "CK_NET_MUTANT_* are host test mutants only"
#endif
#endif

#define IB_SIZE_MASK 0x1fu
#define IB_LO_ADDR_MASK 0xfffff000u
#define GiB64 (1ull << 36)

/* ---------------- A. inbound window ---------------- */

uint32_t ck_pi5net_ib_size_code(uint64_t size)
{
    uint32_t lg = 0;
    if (size == 0 || (size & (size - 1)) != 0)
        return 0;
    while ((1ull << lg) < size)
        lg++;
    if (lg >= 12 && lg <= 15)
        return (lg - 12) + 0x1cu; /* 4 KiB..32 KiB [E1] */
    if (lg >= 16 && lg <= 36)
        return lg - 15; /* 64 KiB..64 GiB [E1] */
    return 0;
}

int ck_pi5net_ib_plan(uint64_t b_cpu, uint64_t b_size, struct ck_pi5net_ibprog *p)
{
    uint64_t blk = 4096, end, base;
    if (!p)
        return CK_PI5NET_E_ARG;
    *p = (struct ck_pi5net_ibprog){0};
    if (b_size == 0 || b_cpu > UINT64_MAX - b_size)
        return CK_PI5NET_E_ARG;
    end = b_cpu + b_size;
    if (end > (1ull << 40)) /* REMAP_HI holds CPU address bits 39:32 */
        return CK_PI5NET_E_RANGE;
    while (blk < b_size && blk <= GiB64)
        blk <<= 1;
    for (;;) {
        if (blk > GiB64)
            return CK_PI5NET_E_RANGE;
        base = b_cpu & ~(blk - 1);
#ifndef CK_NET_MUTANT_NO_STRADDLE
        if (base + blk < end) { /* aligned block does not reach the end: next size up */
            blk <<= 1;
            continue;
        }
#endif
        break;
    }
    p->size_code = ck_pi5net_ib_size_code(blk);
    if (p->size_code == 0)
        return CK_PI5NET_E_RANGE;
    p->bus_base = p->cpu_base = base;
    p->size = blk;
    p->extra_bytes = blk - b_size;
    p->lo = ((uint32_t)base & ~IB_SIZE_MASK) | p->size_code;
    p->hi = (uint32_t)(base >> 32);
    p->remap_lo = (uint32_t)base & CK_PI5NET_REMAP_LO_MASK;
#ifndef CK_NET_MUTANT_NO_REMAP_EN
    p->remap_lo |= CK_PI5NET_REMAP_ENABLE;
#endif
    p->remap_hi = (uint32_t)(base >> 32) & CK_PI5NET_REMAP_HI_MASK;
    return CK_PI5NET_OK;
}

int ck_pi5net_cfg_write32(const struct ck_pi5pcie_io *io, uint8_t bus, uint8_t dev, uint8_t fn, uint32_t reg,
                          uint32_t v)
{
    if (!io || !io->rd || !io->wr)
        return CK_PI5NET_E_ARG;
    if (reg >= 4096u || (reg & 3u) != 0 || fn > 7u)
        return CK_PI5NET_E_ARG;
    if (bus == 0) {
        if (dev != 0 || fn != 0)
            return CK_PI5NET_E_ARG;
        io->wr(io->ctx, reg, v);
        return CK_PI5NET_OK;
    }
    if (bus != 1 || dev != 0)
        return CK_PI5NET_E_ARG;
    io->wr(io->ctx, CK_PI5PCIE_EXT_CFG_INDEX, ((uint32_t)bus << 20) | ((uint32_t)dev << 15) | ((uint32_t)fn << 12));
    io->wr(io->ctx, CK_PI5PCIE_EXT_CFG_DATA + reg, v);
    return CK_PI5NET_OK;
}

int ck_pi5net_rp1_quiesce(const struct ck_pi5pcie_io *io, uint16_t *saved)
{
    uint32_t v, nv;
    if (!saved)
        return CK_PI5NET_E_ARG;
    if (ck_pi5pcie_cfg_read32(io, 1, 0, 0, CK_PI5NET_PCI_COMMAND, &v))
        return CK_PI5NET_E_ARG;
    *saved = (uint16_t)(v & 0xffffu);
#ifdef CK_NET_MUTANT_NO_STATUS_MASK
    nv = v & ~(uint32_t)CK_PI5NET_CMD_BME; /* would write the RW1C status bits back as ones */
#else
    nv = (v & 0xffffu) & ~(uint32_t)CK_PI5NET_CMD_BME; /* status half written as zero: RW1C, nothing cleared */
#endif
    if (ck_pi5net_cfg_write32(io, 1, 0, 0, CK_PI5NET_PCI_COMMAND, nv))
        return CK_PI5NET_E_ARG;
#ifndef CK_NET_MUTANT_NO_QUIESCE_CHECK
    if (ck_pi5pcie_cfg_read32(io, 1, 0, 0, CK_PI5NET_PCI_COMMAND, &v))
        return CK_PI5NET_E_ARG;
    if (v & CK_PI5NET_CMD_BME)
        return CK_PI5NET_E_QUIESCE;
#endif
    return CK_PI5NET_OK;
}

static uint32_t oth_lo(uint32_t i) { return 0x40d4u + (i - 1) * 8u; } /* windows 1..7 [E2] */

static int ib_matches(const struct ck_pi5pcie_io *io, const struct ck_pi5net_ibprog *p)
{
#ifdef CK_NET_MUTANT_NO_READBACK
    (void)io;
    (void)p;
    return 1;
#else
    uint32_t lo = io->rd(io->ctx, CK_PI5NET_IB0_LO), hi = io->rd(io->ctx, CK_PI5NET_IB0_HI);
    uint32_t rlo = io->rd(io->ctx, CK_PI5NET_IB0_REMAP_LO), rhi = io->rd(io->ctx, CK_PI5NET_IB0_REMAP_HI);
    /* bits 11:5 of LO are not part of the window (size code is 4:0, address from bit 12) */
    return (lo & (IB_LO_ADDR_MASK | IB_SIZE_MASK)) == (p->lo & (IB_LO_ADDR_MASK | IB_SIZE_MASK)) && hi == p->hi &&
           (rlo & (CK_PI5NET_REMAP_LO_MASK | CK_PI5NET_REMAP_ENABLE)) == p->remap_lo &&
           (rhi & CK_PI5NET_REMAP_HI_MASK) == p->remap_hi;
#endif
}

static void ib_restore(const struct ck_pi5pcie_io *io, const struct ck_pi5net_ibsaved *s)
{
#ifndef CK_NET_MUTANT_NO_RESTORE
    uint32_t i;
    io->wr(io->ctx, CK_PI5NET_IB0_LO, s->lo & ~IB_SIZE_MASK);
    io->wr(io->ctx, CK_PI5NET_IB0_HI, s->hi);
    io->wr(io->ctx, CK_PI5NET_IB0_REMAP_LO, s->remap_lo);
    io->wr(io->ctx, CK_PI5NET_IB0_REMAP_HI, s->remap_hi);
    io->wr(io->ctx, CK_PI5NET_IB0_LO, s->lo);
    for (i = 1; i < CK_PI5PCIE_IB_WINDOWS; i++)
        io->wr(io->ctx, oth_lo(i), s->other_lo[i]);
#else
    (void)io;
    (void)s;
#endif
}

int ck_pi5net_ib_apply(const struct ck_pi5pcie_io *io, const struct ck_pi5net_ibprog *p,
                       struct ck_pi5net_ibsaved *saved, uint32_t *n_disabled)
{
    uint32_t i, n = 0;
    if (!io || !io->rd || !io->wr || !p || !saved || p->size_code == 0)
        return CK_PI5NET_E_ARG;
    if (n_disabled)
        *n_disabled = 0;
    saved->lo = io->rd(io->ctx, CK_PI5NET_IB0_LO);
    saved->hi = io->rd(io->ctx, CK_PI5NET_IB0_HI);
    saved->remap_lo = io->rd(io->ctx, CK_PI5NET_IB0_REMAP_LO);
    saved->remap_hi = io->rd(io->ctx, CK_PI5NET_IB0_REMAP_HI);
    saved->other_lo[0] = 0;
    for (i = 1; i < CK_PI5PCIE_IB_WINDOWS; i++)
        saved->other_lo[i] = io->rd(io->ctx, oth_lo(i));
#ifndef CK_NET_MUTANT_NO_DISABLE_FIRST
    io->wr(io->ctx, CK_PI5NET_IB0_LO, saved->lo & ~IB_SIZE_MASK); /* window off while its other halves change */
#endif
    io->wr(io->ctx, CK_PI5NET_IB0_HI, p->hi);
    io->wr(io->ctx, CK_PI5NET_IB0_REMAP_LO, p->remap_lo);
    io->wr(io->ctx, CK_PI5NET_IB0_REMAP_HI, p->remap_hi);
    io->wr(io->ctx, CK_PI5NET_IB0_LO, p->lo); /* size code last: the window turns on complete */
#ifndef CK_NET_MUTANT_NO_OTHERS
    for (i = 1; i < CK_PI5PCIE_IB_WINDOWS; i++) {
        if (saved->other_lo[i] & IB_SIZE_MASK) {
            io->wr(io->ctx, oth_lo(i), saved->other_lo[i] & ~IB_SIZE_MASK);
            n++;
        }
    }
#endif
    if (n_disabled)
        *n_disabled = n;
    if (!ib_matches(io, p)) {
        ib_restore(io, saved);
        return CK_PI5NET_E_READBACK;
    }
    for (i = 1; i < CK_PI5PCIE_IB_WINDOWS; i++) {
        if (io->rd(io->ctx, oth_lo(i)) & IB_SIZE_MASK) {
#ifndef CK_NET_MUTANT_NO_READBACK
            ib_restore(io, saved);
            return CK_PI5NET_E_READBACK;
#endif
        }
    }
    return CK_PI5NET_OK;
}

int ck_pi5net_confine_label(const struct ck_pi5pcie_dmav *dv, const struct ck_pi5net_ibprog *plan)
{
    if (!dv)
        return CK_PI5NET_CONF_UNKNOWN;
    switch (dv->verdict) {
    case CK_PI5PCIE_DMA_CONFINED:
        return CK_PI5NET_CONF_CONFINED;
    case CK_PI5PCIE_DMA_WIDER:
#ifdef CK_NET_MUTANT_PARTIAL_ANY
        (void)plan;
        return CK_PI5NET_CONF_PARTIAL; /* would call a 64 GiB window "partial" */
#else
        if (plan && plan->extra_bytes != 0 && dv->outside_bytes == plan->extra_bytes &&
            dv->inside_bytes + dv->outside_bytes == plan->size)
            return CK_PI5NET_CONF_PARTIAL;
        return CK_PI5NET_CONF_NOT_CONFINED;
#endif
    case CK_PI5PCIE_DMA_NO_WINDOW:
    case CK_PI5PCIE_DMA_MISS:
    case CK_PI5PCIE_DMA_PARTIAL:
        return CK_PI5NET_CONF_BROKEN;
    default:
        return CK_PI5NET_CONF_UNKNOWN;
    }
}

const char *ck_pi5net_confine_name(int label)
{
    switch (label) {
    case CK_PI5NET_CONF_CONFINED: return "CONFINED";
    case CK_PI5NET_CONF_PARTIAL: return "PARTIAL";
    case CK_PI5NET_CONF_NOT_CONFINED: return "NOT_CONFINED";
    case CK_PI5NET_CONF_BROKEN: return "BROKEN";
    default: return "UNKNOWN";
    }
}

/* ---------------- B0. outbound window ---------------- */

int ck_pi5net_ob_read(const struct ck_pi5pcie_io *io, struct ck_pi5net_obwin *w)
{
    uint32_t bl, bh, lh, bus_lo, bus_hi;
    uint64_t base_mb, limit_mb;
    if (!io || !io->rd || !w)
        return CK_PI5NET_E_ARG;
    *w = (struct ck_pi5net_obwin){0};
    bl = io->rd(io->ctx, CK_PI5NET_OB0_BASE_LIMIT);
    bh = io->rd(io->ctx, CK_PI5NET_OB0_BASE_HI) & 0xffu;
    lh = io->rd(io->ctx, CK_PI5NET_OB0_LIMIT_HI) & 0xffu;
    bus_lo = io->rd(io->ctx, CK_PI5NET_OB0_BUS_LO);
    bus_hi = io->rd(io->ctx, CK_PI5NET_OB0_BUS_HI);
    base_mb = ((uint64_t)bh << 12) | ((bl >> 4) & 0xfffu);
    limit_mb = ((uint64_t)lh << 12) | ((bl >> 20) & 0xfffu);
    w->bus_base = ((uint64_t)bus_hi << 32) | bus_lo;
    w->cpu_base = base_mb << 20;
#ifdef CK_NET_MUTANT_OB_NO_LIMIT
    w->size = (limit_mb - base_mb) << 20; /* off by one granule */
    w->valid = limit_mb >= base_mb;
#else
    w->valid = limit_mb >= base_mb;
    w->size = w->valid ? (limit_mb - base_mb + 1) << 20 : 0;
#endif
    return CK_PI5NET_OK;
}

uint64_t ck_pi5net_bus_to_cpu(const struct ck_pi5net_obwin *w, uint64_t bus, uint64_t len)
{
    if (!w || !w->valid || len == 0)
        return 0;
#ifndef CK_NET_MUTANT_NO_BOUNDS
    if (bus < w->bus_base || len > w->size || bus - w->bus_base > w->size - len)
        return 0;
#endif
    return w->cpu_base + (bus - w->bus_base);
}

/* ---------------- B1. clocks ---------------- */

static uint32_t div_round_closest(uint64_t a, uint64_t b) { return b ? (uint32_t)((a + (b >> 1)) / b) : 0; }

uint32_t ck_rp1_pll_core_hz(const struct ck_rp1_clk_regs *r)
{
    uint64_t v;
    if (!(r->pll_cs & 0x80000000u)) /* PLL_CS_LOCK [L2] */
        return 0;
    v = ((uint64_t)CK_RP1_XOSC_HZ * (((uint64_t)r->pll_fbdiv_int << 24) + r->pll_fbdiv_frac) + (1u << 23)) >> 24;
    return v > 0xffffffffull ? 0 : (uint32_t)v;
}

static const uint8_t sec_div_tab[32] = {19, 19, 19, 19, 19, 19, 19, 19, 8,  9,  10, 11, 12, 13, 14, 15,
                                        16, 17, 18, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19, 19};

uint32_t ck_rp1_pll_sec_hz(const struct ck_rp1_clk_regs *r)
{
    uint32_t core = ck_rp1_pll_core_hz(r), d;
    if (!core || (r->pll_sec & (1u << 16)) || !(r->pll_sec & 0x80000000u)) /* RST set, or divider not implemented */
        return 0;
    d = sec_div_tab[(r->pll_sec >> 8) & 0x1fu];
    return (uint32_t)(((uint64_t)core + d - 1) / d); /* DIV_ROUND_UP like clk_divider_ops */
}

uint32_t ck_rp1_pll_pri_hz(const struct ck_rp1_clk_regs *r)
{
    uint32_t core = ck_rp1_pll_core_hz(r), d1 = (r->pll_prim >> 16) & 7u, d2 = (r->pll_prim >> 12) & 7u;
    if (!core || !d1 || !d2)
        return 0;
    return div_round_closest(core, (uint64_t)d1 * d2);
}

static uint32_t clk_div(uint32_t div_reg) { return div_reg ? div_reg : 1u << 16; } /* clk-rp1.c recalc: 0 = 2^16 */

uint32_t ck_rp1_clk_sys_hz(const struct ck_rp1_clk_regs *r)
{
    /* SEL is one-hot over the standard parents {xosc, -, pll_sys}; 0 = not switched yet: use CTRL.SRC (clk-rp1.c:1101-1114) */
    uint32_t sel = r->sys_sel, src, parent;
    if (sel)
        src = (uint32_t)__builtin_ctz(sel);
    else
        src = r->sys_ctrl & 0x3u;
    if (src == 0)
        parent = CK_RP1_XOSC_HZ;
    else if (src == 2)
        parent = ck_rp1_pll_pri_hz(r);
    else
        return 0; /* aux source: not modelled */
    return parent / clk_div(r->sys_div);
}

static uint32_t aux_parent_hz(const struct ck_rp1_clk_regs *r, uint32_t aux, int eth)
{
    /* RP1_CLK_ETH aux parents: 0 pll_sys_sec, 1 pll_sys; RP1_CLK_ETH_TSU aux parents: 0 xosc  [L2] */
    if (eth)
        return aux == 0 ? ck_rp1_pll_sec_hz(r) : aux == 1 ? ck_rp1_pll_pri_hz(r) : 0;
    return aux == 0 ? CK_RP1_XOSC_HZ : 0;
}

uint32_t ck_rp1_clk_eth_hz(const struct ck_rp1_clk_regs *r)
{
    uint32_t p;
    if (!(r->eth_ctrl & CK_RP1_CLK_ENABLE))
        return 0;
    p = aux_parent_hz(r, (r->eth_ctrl & CK_RP1_CLK_AUXSRC_MASK) >> CK_RP1_CLK_AUXSRC_SHIFT, 1);
    return p / clk_div(r->eth_div);
}

uint32_t ck_rp1_clk_tsu_hz(const struct ck_rp1_clk_regs *r)
{
    uint32_t p;
    if (!(r->tsu_ctrl & CK_RP1_CLK_ENABLE))
        return 0;
    p = aux_parent_hz(r, (r->tsu_ctrl & CK_RP1_CLK_AUXSRC_MASK) >> CK_RP1_CLK_AUXSRC_SHIFT, 0);
    return p / clk_div(r->tsu_div);
}

void ck_rp1_clk_decide(const struct ck_rp1_clk_regs *r, struct ck_rp1_clk_plan *p)
{
    uint32_t sec;
    *p = (struct ck_rp1_clk_plan){0};
    /* ETH (tx_clk, 125 MHz from pll_sys_sec) */
#ifndef CK_NET_MUTANT_TOUCH_ON_CLOCK
    if (r->eth_ctrl & CK_RP1_CLK_ENABLE) {
        p->eth = CK_RP1_CLK_ALREADY_ON;
        p->eth_why = "already enabled: left as found";
    } else
#endif
    {
        sec = ck_rp1_pll_sec_hz(r);
        if (!sec) {
            p->eth = CK_RP1_CLK_BLOCKED;
            p->eth_why = "pll_sys_sec not running (core unlocked, divider in reset or not implemented)";
#ifndef CK_NET_MUTANT_NO_EXACT_DIV
        } else if (sec % CK_RP1_ETH_HZ != 0 || sec / CK_RP1_ETH_HZ == 0 || sec / CK_RP1_ETH_HZ > 255u) {
#else
        } else if (sec / CK_RP1_ETH_HZ == 0 || sec / CK_RP1_ETH_HZ > 255u) {
#endif
            p->eth = CK_RP1_CLK_BLOCKED;
            p->eth_why = "pll_sys_sec is not an exact multiple (1..255) of 125 MHz";
        } else {
            p->eth = CK_RP1_CLK_TO_ENABLE;
            p->eth_div = sec / CK_RP1_ETH_HZ;
            p->eth_ctrl = (r->eth_ctrl & ~(uint32_t)CK_RP1_CLK_AUXSRC_MASK) | CK_RP1_CLK_ENABLE; /* aux 0 = pll_sys_sec */
            p->eth_why = "disabled: enable from pll_sys_sec at 125 MHz";
        }
    }
    /* ETH_TSU (tsu_clk, 50 MHz from xosc) */
#ifndef CK_NET_MUTANT_TOUCH_ON_CLOCK
    if (r->tsu_ctrl & CK_RP1_CLK_ENABLE) {
        p->tsu = CK_RP1_CLK_ALREADY_ON;
        p->tsu_why = "already enabled: left as found";
    } else
#endif
    {
        p->tsu = CK_RP1_CLK_TO_ENABLE;
        p->tsu_div = CK_RP1_XOSC_HZ / CK_RP1_TSU_HZ;
        p->tsu_ctrl = (r->tsu_ctrl & ~(uint32_t)CK_RP1_CLK_AUXSRC_MASK) | CK_RP1_CLK_ENABLE; /* aux 0 = xosc */
        p->tsu_why = "disabled: enable from xosc at 50 MHz";
    }
}

static uint32_t clk_rd(const struct ck_rp1_io *io, uint32_t off) { return io->rd(io->ctx, CK_RP1_CLOCKS + off); }
static void clk_wr(const struct ck_rp1_io *io, uint32_t off, uint32_t v) { io->wr(io->ctx, CK_RP1_CLOCKS + off, v); }

void ck_rp1_clk_read(const struct ck_rp1_io *io, struct ck_rp1_clk_regs *r)
{
    r->pll_cs = io->rd(io->ctx, CK_RP1_PLL_SYS + CK_RP1_PLL_CS);
    r->pll_fbdiv_int = io->rd(io->ctx, CK_RP1_PLL_SYS + CK_RP1_PLL_FBDIV_INT);
    r->pll_fbdiv_frac = io->rd(io->ctx, CK_RP1_PLL_SYS + CK_RP1_PLL_FBDIV_FRAC);
    r->pll_prim = io->rd(io->ctx, CK_RP1_PLL_SYS + CK_RP1_PLL_PRIM);
    r->pll_sec = io->rd(io->ctx, CK_RP1_PLL_SYS + CK_RP1_PLL_SEC);
    r->sys_ctrl = clk_rd(io, CK_RP1_CLK_SYS_CTRL);
    r->sys_div = clk_rd(io, CK_RP1_CLK_SYS_DIV);
    r->sys_sel = clk_rd(io, CK_RP1_CLK_SYS_SEL);
    r->eth_ctrl = clk_rd(io, CK_RP1_CLK_ETH_CTRL);
    r->eth_div = clk_rd(io, CK_RP1_CLK_ETH_DIV);
    r->eth_sel = clk_rd(io, CK_RP1_CLK_ETH_SEL);
    r->tsu_ctrl = clk_rd(io, CK_RP1_CLK_TSU_CTRL);
    r->tsu_div = clk_rd(io, CK_RP1_CLK_TSU_DIV);
    r->tsu_sel = clk_rd(io, CK_RP1_CLK_TSU_SEL);
}

static int clk_enable_one(const struct ck_rp1_io *io, uint32_t ctrl_off, uint32_t div_off, uint32_t div, uint32_t ctrl)
{
    clk_wr(io, div_off, div);                               /* divider first (clk-rp1.c set_rate_and_parent) */
    clk_wr(io, ctrl_off, ctrl & ~(uint32_t)CK_RP1_CLK_ENABLE); /* source (AUXSRC) while still off */
    clk_wr(io, ctrl_off, ctrl);                             /* then clock on (rp1_clock_on) */
#ifdef CK_NET_MUTANT_NO_CLK_VERIFY
    return 0;
#else
    if (!(clk_rd(io, ctrl_off) & CK_RP1_CLK_ENABLE) || clk_rd(io, div_off) != div)
        return CK_PI5NET_E_READBACK;
    return 0;
#endif
}

int ck_rp1_clk_apply(const struct ck_rp1_io *io, const struct ck_rp1_clk_plan *p)
{
    int rc = 0, e;
    if (p->eth == CK_RP1_CLK_TO_ENABLE) {
        e = clk_enable_one(io, CK_RP1_CLK_ETH_CTRL, CK_RP1_CLK_ETH_DIV, p->eth_div, p->eth_ctrl);
        if (e)
            rc = e;
    }
    if (p->tsu == CK_RP1_CLK_TO_ENABLE) {
        e = clk_enable_one(io, CK_RP1_CLK_TSU_CTRL, CK_RP1_CLK_TSU_DIV, p->tsu_div, p->tsu_ctrl);
        if (e)
            rc = e;
    }
    return rc;
}

/* ---------------- B2. PHY reset ---------------- */

static void delay_ms(const struct ck_rp1_io *io, uint32_t ms)
{
    if (io->delay_us && ms)
        io->delay_us(io->ctx, ms * 1000u);
}

int ck_rp1_phy_reset(const struct ck_rp1_io *io, struct ck_rp1_phyreset *out)
{
    uint32_t ctrl, pad;
    struct ck_rp1_phyreset o = {0};
    int rc = 0;
    o.ctrl_before = io->rd(io->ctx, CK_RP1_GPIO32_CTRL);
    o.pad_before = io->rd(io->ctx, CK_RP1_GPIO32_PAD);
    o.oe_before = io->rd(io->ctx, CK_RP1_RIO1_OE);
    o.out_before = io->rd(io->ctx, CK_RP1_RIO1_OUT);
    o.in_before = io->rd(io->ctx, CK_RP1_RIO1_IN);
    /* 1. level high (reset released) before the pin is ours: no glitch low (pinctrl-rp1.c gpio_direction_output order) */
#ifndef CK_NET_MUTANT_NO_HIGH_FIRST
    io->wr(io->ctx, CK_RP1_RIO1_OUT + CK_RP1_ATOMIC_SET, CK_RP1_GPIO_PIN_BIT);
#endif
    /* 2. pad: input enabled (so we can read the pin), output not disabled */
    pad = io->rd(io->ctx, CK_RP1_GPIO32_PAD);
    pad = (pad | CK_RP1_PAD_IN_ENABLE) & ~(uint32_t)CK_RP1_PAD_OUT_DISABLE;
    io->wr(io->ctx, CK_RP1_GPIO32_PAD, pad);
    /* 3. output enable */
    io->wr(io->ctx, CK_RP1_RIO1_OE + CK_RP1_ATOMIC_SET, CK_RP1_GPIO_PIN_BIT);
    /* 4. function = gpio (RIO), output/oe overrides = peripheral (0) */
    ctrl = io->rd(io->ctx, CK_RP1_GPIO32_CTRL);
    ctrl &= ~(0x1fu | 0x3000u | 0xc000u | 0x30000u);
    ctrl |= CK_RP1_FSEL_GPIO;
    io->wr(io->ctx, CK_RP1_GPIO32_CTRL, ctrl);
    o.ctrl_after = io->rd(io->ctx, CK_RP1_GPIO32_CTRL);
    o.pad_after = io->rd(io->ctx, CK_RP1_GPIO32_PAD);
    if (!(io->rd(io->ctx, CK_RP1_RIO1_IN) & CK_RP1_GPIO_PIN_BIT))
        rc = CK_PI5NET_E_READBACK; /* we drive it high and it does not read high */
    /* 5. assert reset (line low, active low) */
#ifndef CK_NET_MUTANT_NO_ASSERT
    io->wr(io->ctx, CK_RP1_RIO1_OUT + CK_RP1_ATOMIC_CLR, CK_RP1_GPIO_PIN_BIT);
#endif
#ifndef CK_NET_MUTANT_NO_HOLD
    delay_ms(io, CK_RP1_PHY_RESET_MS);
#endif
    o.in_low = io->rd(io->ctx, CK_RP1_RIO1_IN);
    if (o.in_low & CK_RP1_GPIO_PIN_BIT)
        rc = CK_PI5NET_E_READBACK; /* driven low but reads high */
    /* 6. release and let the PHY come up */
#ifndef CK_NET_MUTANT_NO_RELEASE
    io->wr(io->ctx, CK_RP1_RIO1_OUT + CK_RP1_ATOMIC_SET, CK_RP1_GPIO_PIN_BIT);
#endif
    delay_ms(io, CK_RP1_PHY_SETTLE_MS);
    o.in_high = io->rd(io->ctx, CK_RP1_RIO1_IN);
    if (!(o.in_high & CK_RP1_GPIO_PIN_BIT))
        rc = CK_PI5NET_E_READBACK;
    if (out)
        *out = o;
    return rc;
}

/* ---------------- B3. MDIO ---------------- */

uint32_t ck_gem_mdc_div_code(uint32_t pclk_hz)
{
    if (pclk_hz == 0)
        return 7; /* unknown rate: slowest MDC */
#ifdef CK_NET_MUTANT_NO_MDC_DIV
    return 7;
#else
    if (pclk_hz <= 20000000u) return 0;
    if (pclk_hz <= 40000000u) return 1;
    if (pclk_hz <= 80000000u) return 2;
    if (pclk_hz <= 120000000u) return 3;
    if (pclk_hz <= 160000000u) return 4;
    if (pclk_hz <= 240000000u) return 5;
    if (pclk_hz <= 320000000u) return 6;
    return 7;
#endif
}

uint32_t ck_gem_mdio_frame_read(uint32_t phy, uint32_t reg)
{
    return (1u << 30) | (2u << 28) | ((phy & 31u) << 23) | ((reg & 31u) << 18) | (2u << 16);
}

int ck_gem_mdio_enable(const struct ck_rp1_io *io, uint32_t pclk_hz)
{
    uint32_t ncr = io->rd(io->ctx, CK_RP1_ETH + CK_GEM_NCR), cfg = io->rd(io->ctx, CK_RP1_ETH + CK_GEM_NCFGR);
    uint32_t code = ck_gem_mdc_div_code(pclk_hz);
    cfg = (cfg & ~(uint32_t)CK_GEM_NCFGR_CLK_MASK) | (code << CK_GEM_NCFGR_CLK_SHIFT);
    io->wr(io->ctx, CK_RP1_ETH + CK_GEM_NCFGR, cfg); /* divider before the port is enabled */
#ifndef CK_NET_MUTANT_NO_MPE
    io->wr(io->ctx, CK_RP1_ETH + CK_GEM_NCR, ncr | CK_GEM_NCR_MPE);
#else
    (void)ncr;
#endif
    if (!(io->rd(io->ctx, CK_RP1_ETH + CK_GEM_NCR) & CK_GEM_NCR_MPE) ||
        ((io->rd(io->ctx, CK_RP1_ETH + CK_GEM_NCFGR) & CK_GEM_NCFGR_CLK_MASK) >> CK_GEM_NCFGR_CLK_SHIFT) != code)
        return CK_PI5NET_E_READBACK;
    return 0;
}

static int mdio_wait_idle(const struct ck_rp1_io *io)
{
    uint32_t i;
    for (i = 0; i < CK_GEM_MDIO_POLLS; i++) {
        if (io->rd(io->ctx, CK_RP1_ETH + CK_GEM_NSR) & CK_GEM_NSR_IDLE)
            return 0;
        if (io->delay_us)
            io->delay_us(io->ctx, CK_GEM_MDIO_POLL_US);
    }
    return CK_PI5NET_E_TIMEOUT;
}

int ck_gem_mdio_read(const struct ck_rp1_io *io, uint32_t phy, uint32_t reg, uint16_t *val)
{
    if (!io || !val || phy > 31u || reg > 31u)
        return CK_PI5NET_E_ARG;
    if (mdio_wait_idle(io))
        return CK_PI5NET_E_TIMEOUT;
    io->wr(io->ctx, CK_RP1_ETH + CK_GEM_MAN, ck_gem_mdio_frame_read(phy, reg));
#ifndef CK_NET_MUTANT_NO_IDLE_AFTER
    if (mdio_wait_idle(io))
        return CK_PI5NET_E_TIMEOUT;
#endif
    *val = (uint16_t)(io->rd(io->ctx, CK_RP1_ETH + CK_GEM_MAN) & 0xffffu);
    return 0;
}

void ck_phy_id_decode(uint16_t r2, uint16_t r3, struct ck_phy_id *o)
{
    uint8_t b[25] = {0}; /* b[1]..b[24] = OUI bits 1..24 (IEEE 802.3 22.2.4.3.1) */
    uint32_t i, k, oui = 0;
    *o = (struct ck_phy_id){0};
    o->id = ((uint32_t)r2 << 16) | r3;
    /* reg 2 bit 15..0 = OUI bit 3..18; reg 3 bit 15..10 = OUI bit 19..24 */
    for (i = 0; i < 16; i++)
        b[3 + i] = (uint8_t)((r2 >> (15 - i)) & 1u);
    for (i = 0; i < 6; i++)
        b[19 + i] = (uint8_t)((r3 >> (15 - i)) & 1u);
    for (k = 0; k < 3; k++) {
        uint32_t oct = 0;
        for (i = 0; i < 8; i++)
#ifdef CK_NET_MUTANT_OUI_ORDER
            oct |= (uint32_t)b[8 * k + 1 + i] << (7 - i); /* wrong bit order within the octet */
#else
            oct |= (uint32_t)b[8 * k + 1 + i] << i; /* octet's bit 0 is the first transmitted */
#endif
        oui = (oui << 8) | oct;
    }
    o->oui = oui;
    o->model = (uint8_t)((r3 >> 4) & 0x3fu);
    o->rev = (uint8_t)(r3 & 0xfu);
    if (o->id == 0xffffffffu || o->id == 0 || r2 == 0xffffu)
        o->cls = CK_PHY_ABSENT;
#ifndef CK_NET_MUTANT_BAD_CLASS
    else if (o->id == CK_PHY_ID_BCM54213PE)
        o->cls = CK_PHY_BCM54213PE;
#else
    else if ((o->id & 0xfffffff0u) == (CK_PHY_ID_BCM54213PE & 0xfffffff0u))
        o->cls = CK_PHY_BCM54213PE; /* would also accept BCM54210E and any revision: Linux matches exactly */
#endif
    else if (o->oui == 0x18c086u || o->oui == 0x001018u) /* both are "Broadcom" in the IEEE registry */
        o->cls = CK_PHY_BROADCOM_OTHER;
    else
        o->cls = CK_PHY_OTHER;
}

const char *ck_phy_class_name(int cls)
{
    switch (cls) {
    case CK_PHY_ABSENT: return "ABSENT";
    case CK_PHY_BCM54213PE: return "BCM54213PE";
    case CK_PHY_BROADCOM_OTHER: return "BROADCOM_OTHER";
    default: return "OTHER";
    }
}

int ck_phy_find(const struct ck_rp1_io *io, uint32_t addr, uint32_t tries, uint32_t gap_ms, struct ck_phy_id *id,
                uint32_t *attempts, int *scan_hit)
{
    uint32_t t, a;
    uint16_t r2 = 0xffff, r3 = 0xffff;
    if (attempts)
        *attempts = 0;
    if (scan_hit)
        *scan_hit = -1;
    if (!io || !id || addr > 31u || tries == 0)
        return CK_PI5NET_E_ARG;
    ck_phy_id_decode(0xffff, 0xffff, id);
    for (t = 0; t < tries; t++) {
        int e2, e3;
        if (attempts)
            *attempts = t + 1;
        e2 = ck_gem_mdio_read(io, addr, 2, &r2);
        e3 = ck_gem_mdio_read(io, addr, 3, &r3);
        if (e2 || e3)
            return e2 ? e2 : e3;
        if (r2 != 0xffffu && !(r2 == 0 && r3 == 0)) {
            ck_phy_id_decode(r2, r3, id);
            return 0;
        }
        delay_ms(io, gap_ms);
    }
    if (scan_hit) {
        for (a = 0; a < 32u; a++) {
            if (ck_gem_mdio_read(io, a, 2, &r2) == 0 && r2 != 0xffffu && r2 != 0) {
                *scan_hit = (int)a;
                break;
            }
        }
    }
    return CK_PI5NET_E_TIMEOUT;
}

/* ================= image glue (CK_PI5_NET only) ================= */
#ifdef CK_PI5_NET
#include "ck.h"
#include "dma_window.h"
#include "pi5_gem.h"

static volatile uint8_t *rc;
static volatile uint8_t *rp1;

static uint32_t rc_rd(void *c, uint32_t off) { (void)c; return *(volatile uint32_t *)(rc + off); }
static void rc_wr(void *c, uint32_t off, uint32_t v) { (void)c; *(volatile uint32_t *)(rc + off) = v; ck_mb(); }
static uint32_t rp_rd(void *c, uint32_t off) { (void)c; return *(volatile uint32_t *)(rp1 + off); }
static void rp_wr(void *c, uint32_t off, uint32_t v) { (void)c; *(volatile uint32_t *)(rp1 + off) = v; ck_mb(); }
static void rp_delay(void *c, uint32_t us)
{
    (void)c;
    while (us > 1000u) {
        ck_udelay(1000u);
        us -= 1000u;
    }
    if (us)
        ck_udelay(us);
}

static uint32_t cmd_dword(const struct ck_pi5pcie_io *io)
{
    uint32_t v = 0;
    (void)ck_pi5pcie_cfg_read32(io, 1, 0, 0, 4, &v);
    return v;
}

static void print_wins(const char *tag, const struct ck_pi5pcie_io *io, struct ck_pi5pcie_ibwin *win)
{
    uint32_t i;
    for (i = 0; i < CK_PI5PCIE_IB_WINDOWS; i++) {
        if (ck_pi5pcie_ib_read(io, i, &win[i]))
            continue;
        if (win[i].enabled)
            ck_printf("pi5_net: inbound %s win%u bus=0x%llx size=0x%llx cpu=0x%llx remap=%u valid=%u\n", tag, i,
                      (unsigned long long)win[i].bus_base, (unsigned long long)win[i].size,
                      (unsigned long long)win[i].cpu_base, win[i].remap_en, win[i].size_valid);
    }
}

static uint32_t unmodelled_windows(void)
{
    uint32_t u = 0;
    if (rc_rd(0, CK_PI5PCIE_RC_BAR1_LO) & CK_PI5PCIE_BAR_SIZE_MASK)
        u++;
    if (rc_rd(0, CK_PI5PCIE_RC_BAR3_LO) & CK_PI5PCIE_BAR_SIZE_MASK)
        u++;
    return u;
}

static int print_verdict(const char *tag, const struct ck_pi5pcie_ibwin *win, uint32_t unmod, uint64_t b_phys,
                          uint64_t b_size, const struct ck_pi5net_ibprog *plan)
{
    struct ck_pi5pcie_dmav dv;
    int label;
    ck_pi5pcie_ib_verdict(win, CK_PI5PCIE_IB_WINDOWS, unmod, b_phys, b_size, &dv);
    label = ck_pi5net_confine_label(&dv, plan);
    ck_printf("pi5_dma: hw_window %s=%s [%s] reach=0x%llx inside=0x%llx outside=0x%llx\n", tag,
              ck_pi5net_confine_name(label), ck_pi5pcie_verdict_name(dv.verdict), (unsigned long long)dv.reach_bytes,
              (unsigned long long)dv.inside_bytes, (unsigned long long)dv.outside_bytes);
    return label;
}

static void print_clk_rates(const char *tag, const struct ck_rp1_clk_regs *r)
{
    ck_printf("pi5_net: rp1 clocks %s: pll_core=%u pll_sec=%u clk_sys=%u clk_eth=%u clk_eth_tsu=%u Hz (0 = off/unknown)\n",
              tag, ck_rp1_pll_core_hz(r), ck_rp1_pll_sec_hz(r), ck_rp1_clk_sys_hz(r), ck_rp1_clk_eth_hz(r),
              ck_rp1_clk_tsu_hz(r));
}

void ck_pi5net_run(void)
{
    static const struct ck_pi5pcie_io io = {rc_rd, rc_wr, 0};
    static const struct ck_rp1_io rio = {rp_rd, rp_wr, rp_delay, 0};
    struct ck_pi5pcie_func root, rp1f;
    struct ck_pi5pcie_ibwin win[CK_PI5PCIE_IB_WINDOWS];
    struct ck_pi5net_ibprog plan;
    struct ck_pi5net_ibsaved saved;
    struct ck_pi5net_obwin ob;
    struct ck_pi5pcie_bar bar1;
    struct ck_rp1_clk_regs cr;
    struct ck_rp1_clk_plan cp;
    struct ck_rp1_phyreset pr;
    struct ck_phy_id pid;
    struct ck_dmaw dw;
    uint64_t b_phys = 0, bar1_cpu;
    uint32_t unmod, ndis = 0, attempts = 0;
    uint16_t cmd_saved = 0;
    int rrc, rrp1, ver, rc2, scan_hit = -1, confined = 0;
    void *bounce;

    ck_printf("pi5_net: cut 3: hardware DMA confinement, RP1 Ethernet up to the PHY, then one frame through the GEM (descriptors inside the bounce window only)\n");
    ck_printf("pi5_net: software-only DMA confinement (Pi 5, weaker than the Spark) plus the root-complex window below\n");
    rc = (volatile uint8_t *)ck_mmio_try_map(CK_PI5PCIE_RC2_PHYS, CK_PI5PCIE_RC_BYTES);
    if (!rc) {
        ck_printf("pi5_net: FAIL map root complex 0x%llx (refused); nothing done\n",
                  (unsigned long long)CK_PI5PCIE_RC2_PHYS);
        return;
    }
    rrc = ck_pi5pcie_read_func(&io, 0, 0, 0, &root);
    rrp1 = ck_pi5pcie_read_func(&io, 1, 0, 0, &rp1f);
    ver = ck_pi5pcie_rp1_check(rrp1, &rp1f);
    if (rrc == 0)
        ck_printf("pi5_net: root 00:00.0 %04x:%04x class=%06x sec=%u sub=%u\n", root.vendor, root.device,
                  root.class_code, root.secondary, root.subordinate);
    ck_printf("pi5_net: rp1 01:00.0 %04x:%04x %s cmd=0x%04x\n", rp1f.vendor, rp1f.device,
              ver == CK_PI5PCIE_RP1_OK ? "MATCH" : "NOT_RP1", rp1f.command);
    if (ver != CK_PI5PCIE_RP1_OK) {
        ck_printf("pi5_net: STOP rp1 not present at 01:00.0; nothing programmed\n");
        return;
    }

    /* ---------------- A. confine the inbound window ---------------- */
    bounce = ck_dma_alloc(CK_DMAW_MAX_BYTES, CK_DMAW_MAX_BYTES, &b_phys);
    if (!bounce || ck_dmaw_init(&dw, bounce, b_phys, CK_DMAW_MAX_BYTES) != CK_DMAW_OK) {
        ck_printf("pi5_dma: FAIL no bounce window (alloc/init); window left as firmware set it\n");
    } else {
        ck_printf("pi5_dma: bounce cpu=0x%llx size=0x%llx (ADR 0020 rule 1)\n", (unsigned long long)b_phys,
                  (unsigned long long)dw.size);
        unmod = unmodelled_windows();
        print_wins("before", &io, win);
        print_verdict("before", win, unmod, b_phys, dw.size, 0);
        rc2 = ck_pi5net_ib_plan(b_phys, dw.size, &plan);
        if (rc2) {
            ck_printf("pi5_dma: FAIL plan rc=%d; window left as firmware set it\n", rc2);
        } else {
            ck_printf("pi5_dma: plan bus=0x%llx cpu=0x%llx size=0x%llx code=%u extra_beyond_bounce=0x%llx\n",
                      (unsigned long long)plan.bus_base, (unsigned long long)plan.cpu_base,
                      (unsigned long long)plan.size, plan.size_code, (unsigned long long)plan.extra_bytes);
            rc2 = ck_pi5net_rp1_quiesce(&io, &cmd_saved);
            ck_printf("pi5_dma: rp1 bus-master off for the window change: rc=%d cmd_was=0x%04x cmd_now=0x%08x\n", rc2,
                      cmd_saved, cmd_dword(&io));
            if (rc2 == 0) {
                ck_udelay(2000); /* let anything already on the wire finish */
                rc2 = ck_pi5net_ib_apply(&io, &plan, &saved, &ndis);
                ck_printf("pi5_dma: apply rc=%d (0 = window now matches the plan); other_windows_disabled=%u\n", rc2,
                          ndis);
                if (rc2)
                    ck_printf("pi5_dma: readback LO=0x%08x HI=0x%08x REMAP_LO=0x%08x REMAP_HI=0x%08x (firmware window restored)\n",
                              rc_rd(0, CK_PI5NET_IB0_LO), rc_rd(0, CK_PI5NET_IB0_HI),
                              rc_rd(0, CK_PI5NET_IB0_REMAP_LO), rc_rd(0, CK_PI5NET_IB0_REMAP_HI));
            } else {
                ck_printf("pi5_dma: STOP rp1 would not stop bus mastering; window left as firmware set it\n");
            }
            unmod = unmodelled_windows();
            print_wins("after", &io, win);
            confined = print_verdict("after", win, unmod, b_phys, dw.size, &plan) == CK_PI5NET_CONF_CONFINED && rc2 == 0;
            ck_printf("pi5_dma: rp1 bus-master is LEFT OFF (cmd=0x%08x); the GEM driver turns it on when it needs it\n",
                      cmd_dword(&io));
        }
    }

    /* ---------------- B. RP1 Ethernet up to the PHY ---------------- */
    if (ck_pi5net_ob_read(&io, &ob) != 0 || !ob.valid) {
        ck_printf("pi5_net: STOP outbound window 0 unreadable; RP1 not touched\n");
        return;
    }
    ck_printf("pi5_net: outbound win0 bus=0x%llx cpu=0x%llx size=0x%llx\n", (unsigned long long)ob.bus_base,
              (unsigned long long)ob.cpu_base, (unsigned long long)ob.size);
    (void)ck_pi5pcie_bar_decode(rp1f.bar_raw, 1, rp1f.nbars, &bar1);
    if (bar1.kind != CK_PI5PCIE_BAR_MEM32 && bar1.kind != CK_PI5PCIE_BAR_MEM64) {
        ck_printf("pi5_net: STOP rp1 bar1 is not a memory BAR; RP1 not touched\n");
        return;
    }
    bar1_cpu = ck_pi5net_bus_to_cpu(&ob, bar1.addr, CK_RP1_BAR1_MAP_BYTES);
    if (!bar1_cpu) {
        ck_printf("pi5_net: STOP rp1 bar1 bus 0x%llx is outside outbound win0; RP1 not touched\n",
                  (unsigned long long)bar1.addr);
        return;
    }
    rp1 = (volatile uint8_t *)ck_mmio_try_map(bar1_cpu, CK_RP1_BAR1_MAP_BYTES);
    if (!rp1) {
        ck_printf("pi5_net: STOP map rp1 bar1 cpu 0x%llx refused; RP1 not touched\n", (unsigned long long)bar1_cpu);
        return;
    }
    ck_printf("pi5_net: rp1 bar1 bus=0x%llx -> cpu=0x%llx chip_id=0x%08x platform=0x%08x\n",
              (unsigned long long)bar1.addr, (unsigned long long)bar1_cpu, rp_rd(0, CK_RP1_SYSINFO),
              rp_rd(0, CK_RP1_SYSINFO + 4));
    if (rp_rd(0, CK_RP1_SYSINFO) == 0xffffffffu) {
        ck_printf("pi5_net: STOP rp1 reads all ones (link or window problem); nothing programmed\n");
        return;
    }
    ck_printf("pi5_net: gem before: MID=0x%08x NCR=0x%08x NCFGR=0x%08x NSR=0x%08x eth_cfg CONTROL=0x%08x CLKGEN=0x%08x\n",
              rp_rd(0, CK_RP1_ETH + CK_GEM_MID), rp_rd(0, CK_RP1_ETH + CK_GEM_NCR),
              rp_rd(0, CK_RP1_ETH + CK_GEM_NCFGR), rp_rd(0, CK_RP1_ETH + CK_GEM_NSR),
              rp_rd(0, CK_RP1_ETH_CFG + 0x00), rp_rd(0, CK_RP1_ETH_CFG + 0x14));
    ck_rp1_clk_read(&rio, &cr);
    ck_printf("pi5_net: rp1 clock regs: PLL cs=0x%08x fbint=0x%08x frac=0x%08x prim=0x%08x sec=0x%08x | SYS ctrl=0x%08x div=%u sel=0x%x | ETH ctrl=0x%08x div=%u sel=0x%x | TSU ctrl=0x%08x div=%u sel=0x%x\n",
              cr.pll_cs, cr.pll_fbdiv_int, cr.pll_fbdiv_frac, cr.pll_prim, cr.pll_sec, cr.sys_ctrl, cr.sys_div,
              cr.sys_sel, cr.eth_ctrl, cr.eth_div, cr.eth_sel, cr.tsu_ctrl, cr.tsu_div, cr.tsu_sel);
    print_clk_rates("before", &cr);
    ck_rp1_clk_decide(&cr, &cp);
    ck_printf("pi5_net: clk_eth: %s (%s) | clk_eth_tsu: %s (%s)\n",
              cp.eth == CK_RP1_CLK_ALREADY_ON ? "ALREADY_ON" : cp.eth == CK_RP1_CLK_TO_ENABLE ? "ENABLE" : "BLOCKED",
              cp.eth_why, cp.tsu == CK_RP1_CLK_ALREADY_ON ? "ALREADY_ON" : cp.tsu == CK_RP1_CLK_TO_ENABLE ? "ENABLE" : "BLOCKED",
              cp.tsu_why);
    rc2 = ck_rp1_clk_apply(&rio, &cp);
    ck_rp1_clk_read(&rio, &cr);
    print_clk_rates("after", &cr);
    ck_printf("pi5_net: clock apply rc=%d\n", rc2);
    if (cp.eth == CK_RP1_CLK_BLOCKED) {
        ck_printf("pi5_net: STOP clk_eth blocked; PHY not touched\n");
        return;
    }

    rc2 = ck_rp1_phy_reset(&rio, &pr);
    ck_printf("pi5_net: phy reset gpio32 rc=%d ctrl %08x->%08x pad %08x->%08x oe_before=%08x out_before=%08x in: before=%08x low=%08x high=%08x\n",
              rc2, pr.ctrl_before, pr.ctrl_after, pr.pad_before, pr.pad_after, pr.oe_before, pr.out_before,
              pr.in_before, pr.in_low, pr.in_high);
    if (rc2) {
        ck_printf("pi5_net: STOP gpio32 did not follow the reset sequence; PHY not read\n");
        return;
    }
    rc2 = ck_gem_mdio_enable(&rio, ck_rp1_clk_sys_hz(&cr));
    ck_printf("pi5_net: mdio enable rc=%d NCR=0x%08x NCFGR=0x%08x (MDC divider code %u for pclk %u Hz)\n", rc2,
              rp_rd(0, CK_RP1_ETH + CK_GEM_NCR), rp_rd(0, CK_RP1_ETH + CK_GEM_NCFGR),
              ck_gem_mdc_div_code(ck_rp1_clk_sys_hz(&cr)), ck_rp1_clk_sys_hz(&cr));
    if (rc2)
        return;
    rc2 = ck_phy_find(&rio, 1, 20, 25, &pid, &attempts, &scan_hit);
    if (rc2 == 0)
        ck_printf("pi5_net: phy addr=1 id=0x%08x oui=%02x-%02x-%02x model=0x%02x rev=%u class=%s attempts=%u\n", pid.id,
                  (pid.oui >> 16) & 0xff, (pid.oui >> 8) & 0xff, pid.oui & 0xff, pid.model, pid.rev,
                  ck_phy_class_name(pid.cls), attempts);
    else
        ck_printf("pi5_net: phy addr=1 NOT FOUND rc=%d attempts=%u scan_lowest_answering=%d\n", rc2, attempts, scan_hit);
    if (rc2 == 0 && pid.cls == CK_PHY_BCM54213PE) {
        struct ck_pi5gem_ctx gc = {&io, &rio, &dw, bounce, b_phys, confined, 1, ck_rp1_clk_sys_hz(&cr)};
        ck_printf("pi5_net: phy found; handing over to the GEM frame test (hw window confined=%d)\n", confined);
        ck_pi5gem_run(&gc);
    } else {
        ck_printf("pi5_net: no BCM54213PE at addr 1; GEM frame test not run\n");
    }
    ck_printf("pi5_net: done: rp1 bus-master off unless the line above says otherwise\n");
}
#endif
