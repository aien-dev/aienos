/* gic.c -- GICv3 from the ACPI MADT: distributor, this CPU's redistributor
 * (found by GICR_TYPER affinity), system-register CPU interface, and the
 * IRQ enable service for device code. Register offsets: GICv3 spec 12.8-12.11. */
#include "arch.h"
#include "ck_internal.h"

#define GICD_CTLR 0x0000
#define GICD_IGROUPR 0x0080
#define GICD_ISENABLER 0x0100
#define GICD_IPRIORITYR 0x0400
#define GICD_IROUTER 0x6000
#define GICD_PIDR2 0xffe8
#define GICR_TYPER 0x0008
#define GICR_WAKER 0x0014
#define GICR_SGI 0x10000
#define GICR_IGROUPR0 (GICR_SGI + 0x0080)
#define GICR_ISENABLER0 (GICR_SGI + 0x0100)
#define GICR_IPRIORITYR (GICR_SGI + 0x0400)

static volatile uint8_t *gicd, *rd;

static uint32_t r32(volatile uint8_t *b, uint32_t off) { return *(volatile uint32_t *)(b + off); }
static void w32(volatile uint8_t *b, uint32_t off, uint32_t v) { *(volatile uint32_t *)(b + off) = v; }
static uint64_t r64(volatile uint8_t *b, uint32_t off) { return *(volatile uint64_t *)(b + off); }
static void w64(volatile uint8_t *b, uint32_t off, uint64_t v) { *(volatile uint64_t *)(b + off) = v; }

static void set_prio(volatile uint8_t *b, uint32_t base, uint32_t intid, uint8_t prio)
{
    uint32_t off = base + (intid / 4) * 4, sh = (intid % 4) * 8;
    w32(b, off, (r32(b, off) & ~(0xffu << sh)) | ((uint32_t)prio << sh));
}

static void rwp_wait(void)
{
    for (unsigned i = 0; i < 1000000 && (r32(gicd, GICD_CTLR) & (1u << 31)); i++)
        ;
}

static uint64_t my_affinity(void)
{
    uint64_t m = ck_rd(mpidr_el1);
    return (m & 0xffffff) | ((m >> 32) & 0xff) << 24;
}

static void ppi_enable(uint32_t intid, uint8_t prio)
{
    w32(rd, GICR_IGROUPR0, r32(rd, GICR_IGROUPR0) | (1u << intid));
    set_prio(rd, GICR_IPRIORITYR, intid, prio);
    w32(rd, GICR_ISENABLER0, 1u << intid);
}

int ck_gic_init(const struct ck_madt_gic *m, struct ck_gic_report *out)
{
    uint64_t region = m->gicr ? m->gicr : m->gicc_gicr;
    uint64_t len = m->gicr ? m->gicr_len : 0x20000;
    if (!m->gicd || !region || !len)
        return -1;
    gicd = ck_mmio_map(m->gicd, 0x10000);
    volatile uint8_t *r = ck_mmio_map(region, (len + 0xfff) & ~0xfffull);
    uint64_t aff = my_affinity();
    rd = 0;
    for (uint64_t off = 0; off + 0x20000 <= len;) {
        uint64_t typer = r64(r, (uint32_t)off + GICR_TYPER);
        if ((typer >> 32) == aff) {
            rd = r + off;
            break;
        }
        if (typer & (1u << 4)) /* Last */
            break;
        off += (typer & 2) ? 0x40000 : 0x20000; /* VLPIS adds two frames */
    }
    if (!rd)
        return -2;
    /* Wake this redistributor: clear ProcessorSleep, wait ChildrenAsleep. */
    w32(rd, GICR_WAKER, r32(rd, GICR_WAKER) & ~(1u << 1));
    unsigned i;
    for (i = 0; i < 1000000 && (r32(rd, GICR_WAKER) & (1u << 2)); i++)
        ;
    if (i == 1000000)
        return -3;
    /* Distributor: affinity routing, group 1 enabled (as the Rust kernel). */
    w32(gicd, GICD_CTLR, (1u << 4) | (1u << 1));
    rwp_wait();
    /* CPU interface. */
    ck_wr_s(ICC_SRE_EL1, ck_rd_s(ICC_SRE_EL1) | 1);
    ck_isb();
    ck_wr_s(ICC_PMR_EL1, 0xff);
    ck_wr_s(ICC_BPR1_EL1, 0);
    ck_wr_s(ICC_IGRPEN1_EL1, 1);
    ck_isb();
    ppi_enable(30, 0x80); /* EL1 physical timer */
    out->gicd = m->gicd;
    out->gicr = region;
    out->arch_rev = (r32(gicd, GICD_PIDR2) >> 4) & 0xf;
    out->icc_sre = ck_rd_s(ICC_SRE_EL1) & 1;
    out->rd_frame = (uint64_t)(uintptr_t)rd;
    return 0;
}

int ck_irq_enable(uint32_t intid)
{
    if (!gicd || !rd || intid >= 1020)
        return -1;
    if (intid < 32) {
        ppi_enable(intid, 0xa0);
        return 0;
    }
    uint32_t word = intid / 32, bit = 1u << (intid % 32);
    w32(gicd, GICD_IGROUPR + word * 4, r32(gicd, GICD_IGROUPR + word * 4) | bit);
    set_prio(gicd, GICD_IPRIORITYR, intid, 0xa0);
    uint64_t m = ck_rd(mpidr_el1);
    w64(gicd, GICD_IROUTER + intid * 8, (m & 0xffffff) | (m & 0xff00000000ull));
    w32(gicd, GICD_ISENABLER + word * 4, bit);
    return 0;
}
