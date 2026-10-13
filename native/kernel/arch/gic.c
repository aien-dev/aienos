/* gic.c -- the interrupt controller from the ACPI MADT, and the IRQ enable
 * service for device code. Two kinds:
 *  - GICv3 (Spark, QEMU gic-version=3): distributor, this CPU's redistributor
 *    (found by GICR_TYPER affinity), system-register CPU interface. Register
 *    offsets: GICv3 spec 12.8-12.11.
 *  - GICv2 (Raspberry Pi 5 GIC-400, QEMU gic-version=2): distributor and the
 *    memory-mapped CPU interface from the MADT GICC Physical Base Address.
 *    Offsets as Linux include/linux/irqchip/arm-gic.h (GIC_DIST_*, GIC_CPU_*).
 *    Group registers are left as firmware set them: with the Security
 *    Extensions (the Pi) this non-secure view enables Group 1 through bit 0 of
 *    GICD_CTLR/GICC_CTLR and IGROUPR is not ours; without them (QEMU) bit 0
 *    enables Group 0, the reset group, which GICC_IAR acknowledges. Same as
 *    Linux irq-gic.c (GICD_ENABLE, GICC_ENABLE, priority mask 0xf0). */
#include "arch.h"
#include "ck_internal.h"

#define GICD_CTLR 0x0000
#define GICD_IGROUPR 0x0080
#define GICD_ISENABLER 0x0100
#define GICD_IPRIORITYR 0x0400
#define GICD_ITARGETSR 0x0800
#define GICD_IROUTER 0x6000
#define GICD_PIDR2 0xffe8
#define GICD_V2_PIDR2 0x0fe8
#define GICR_TYPER 0x0008
#define GICR_WAKER 0x0014
#define GICR_SGI 0x10000
#define GICR_IGROUPR0 (GICR_SGI + 0x0080)
#define GICR_ISENABLER0 (GICR_SGI + 0x0100)
#define GICR_IPRIORITYR (GICR_SGI + 0x0400)
#define GICC_CTLR 0x00
#define GICC_PMR 0x04
#define GICC_BPR 0x08
#define GICC_IAR 0x0c
#define GICC_EOIR 0x10

static volatile uint8_t *gicd, *rd, *gicc;
static unsigned gic_kind; /* 0 none, 2 GICv2 (MMIO CPU interface), 3 GICv3 */

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
    if (gic_kind == 2) { /* GICv2: SGIs/PPIs are banked in the distributor */
        set_prio(gicd, GICD_IPRIORITYR, intid, prio);
        w32(gicd, GICD_ISENABLER, 1u << intid);
        return;
    }
    w32(rd, GICR_IGROUPR0, r32(rd, GICR_IGROUPR0) | (1u << intid));
    set_prio(rd, GICR_IPRIORITYR, intid, prio);
    w32(rd, GICR_ISENABLER0, 1u << intid);
}

static int gicv2_init(const struct ck_madt_gic *m, struct ck_gic_report *out)
{
    gicd = ck_mmio_map(m->gicd, 0x1000);
    gicc = ck_mmio_map(m->gicc_base, 0x2000);
    gic_kind = 2;
    w32(gicd, GICD_CTLR, 1);
    w32(gicc, GICC_PMR, 0xf0);
    w32(gicc, GICC_BPR, 0);
    w32(gicc, GICC_CTLR, 1);
    ppi_enable(30, 0x80); /* EL1 physical timer */
    out->gicd = m->gicd;
    out->gicr = 0;
    out->gicc = m->gicc_base;
    out->kind = 2;
    out->arch_rev = (r32(gicd, GICD_V2_PIDR2) >> 4) & 0xf;
    out->icc_sre = 0;
    out->rd_frame = 0;
    return 0;
}

int ck_gic_init(const struct ck_madt_gic *m, struct ck_gic_report *out)
{
    int kind = ck_madt_gic_kind(m);
    if (!m->gicd || !kind)
        return -1;
    if (kind == 2)
        return gicv2_init(m, out);
    uint64_t region = m->gicr ? m->gicr : m->gicc_gicr;
    uint64_t len = m->gicr ? m->gicr_len : 0x20000;
    if (!region || !len)
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
    gic_kind = 3;
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
    out->gicc = 0;
    out->kind = 3;
    out->arch_rev = (r32(gicd, GICD_PIDR2) >> 4) & 0xf;
    out->icc_sre = ck_rd_s(ICC_SRE_EL1) & 1;
    out->rd_frame = (uint64_t)(uintptr_t)rd;
    return 0;
}

/* Acknowledge the highest-priority pending interrupt; 1020-1023 = none. */
uint32_t ck_gic_ack(void)
{
    if (gic_kind == 2)
        return r32(gicc, GICC_IAR) & 0x3ff; /* GICC_IAR_INT_ID_MASK; CPUID bits only for SGIs */
    return (uint32_t)ck_rd_s(ICC_IAR1_EL1) & 0xffffff;
}

void ck_gic_eoi(uint32_t intid)
{
    if (gic_kind == 2)
        w32(gicc, GICC_EOIR, intid);
    else
        ck_wr_s(ICC_EOIR1_EL1, intid);
}

int ck_irq_enable(uint32_t intid)
{
    if (!gicd || !gic_kind || intid >= 1020)
        return -1;
    if (intid < 32) {
        ppi_enable(intid, 0xa0);
        return 0;
    }
    uint32_t word = intid / 32, bit = 1u << (intid % 32);
    if (gic_kind == 2) {
        /* ITARGETSR0-7 read back this CPU's own target bit (GICv2 4.3.12). */
        uint8_t self = (uint8_t)(r32(gicd, GICD_ITARGETSR) & 0xff);
        set_prio(gicd, GICD_IPRIORITYR, intid, 0xa0);
        set_prio(gicd, GICD_ITARGETSR, intid, self);
        w32(gicd, GICD_ISENABLER + word * 4, bit);
        return 0;
    }
    w32(gicd, GICD_IGROUPR + word * 4, r32(gicd, GICD_IGROUPR + word * 4) | bit);
    set_prio(gicd, GICD_IPRIORITYR, intid, 0xa0);
    uint64_t m = ck_rd(mpidr_el1);
    w64(gicd, GICD_IROUTER + intid * 8, (m & 0xffffff) | (m & 0xff00000000ull));
    w32(gicd, GICD_ISENABLER + word * 4, bit);
    return 0;
}
