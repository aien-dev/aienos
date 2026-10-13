/* pi5_net.h -- Raspberry Pi 5 network lane, cut 2: (A) hardware confinement of the
 * BCM2712 PCIe2 inbound DMA window to the ADR 0020 bounce region, (B) RP1 Ethernet
 * bring-up as far as the PHY: RP1 clocks the GEM needs, PHY reset on RP1 GPIO32,
 * MDIO read of the PHY ID. NO frames, NO DMA descriptors, NO GEM transmit/receive.
 *
 * The decision and register-sequence logic here is hosted-testable over fake
 * registers (tests/test_pi5_net.c, with mutants). The MMIO glue at the bottom of
 * pi5_net.c is the CK_PI5_NET image only. A host test proves the decisions, NOT the
 * hardware. Every number below cites its source; anything not read is UNVERIFIED.
 *
 * SOURCES (all read in this cut):
 *  [E1] edk2-platforms 8e1779b (aien-dev/rpi5-uefi v0.3 c1ca184 pins it),
 *       Silicon/Broadcom/Bcm27xx/Library/Bcm2712PciHostBridgeLib/Bcm2712PciHostBridge.c
 *       PcieEncodeInboundSize + PcieSetupInboundWindow (size code, LO/HI, REMAP_LO/HI),
 *       PcieSetupOutboundWindow (MEM_WIN_LO/HI, BASE_LIMIT, BASE_HI, LIMIT_HI).
 *  [E2] Silicon/Broadcom/Bcm27xx/Include/IndustryStandard/Bcm2712Pcie.h register offsets
 *       and Include/IndustryStandard/Bcm2712.h BCM2712_BRCMSTB_PCIE2_CPU_MEM_BASE 0x1f00000000;
 *       RpiPlatformDxe/ConfigTable.h PCI_RESERVED_MEM32_BASE 0xC0000000 (bus) size 1 GiB.
 *  [E3] Silicon/RaspberryPi/RpiSiliconPkg/Include/Rp1.h block offsets inside RP1 BAR1.
 *  [L1] raspberrypi/linux rpi-6.12.y drivers/pci/controller/pcie-brcmstb.c
 *       set_inbound_win_registers (LO write with size code, HI, remap with ACCESS_EN bit 0).
 *  [L2] drivers/clk/clk-rp1.c (register offsets, CLK_CTRL_ENABLE bit 11, AUXSRC bits 9:5,
 *       PLL fields, PLL_SEC divider table, RP1_CLK_ETH / RP1_CLK_ETH_TSU / RP1_CLK_SYS).
 *  [L3] arch/arm/boot/dts/broadcom (rp1.dtsi, bcm2712-rpi-5-b.dts): rp1_eth clocks pclk/hclk
 *       = RP1_CLK_SYS, tsu_clk = RP1_CLK_ETH_TSU 50 MHz, tx_clk = RP1_CLK_ETH 125 MHz,
 *       phy-reset-gpios = rp1_gpio 32 GPIO_ACTIVE_LOW, phy-reset-duration 5 ms, phy reg 1.
 *  [L4] drivers/pinctrl/pinctrl-rp1.c (GPIO CTRL/PAD/RIO layout, bank table, FSEL gpio = 5).
 *  [L5] drivers/net/ethernet/cadence/macb_main.c + macb.h (MAN frame, NSR.IDLE, NCR.MPE,
 *       GEM MDC divider table, MID register).
 *  [L6] drivers/net/phy/broadcom.c + include/linux/brcmphy.h PHY_ID_BCM54213PE 0x600d84a2,
 *       phy_id_mask 0xffffffff.
 *  [D1] RP1 peripherals datasheet RP-008370-DS-1: section 2.2 (PCIe outbound direct mapped
 *       space), chapter 7 (GEM_GXL, RGMII, ETH_CFG registers). */
#ifndef AIENOS_CK_PI5_NET_H
#define AIENOS_CK_PI5_NET_H
#include <stddef.h>
#include <stdint.h>
#include "pi5_pcie.h"

enum {
    CK_PI5NET_OK = 0,
    CK_PI5NET_E_ARG = -1,
    CK_PI5NET_E_RANGE = -2,    /* window cannot be expressed by the hardware */
    CK_PI5NET_E_QUIESCE = -3,  /* RP1 bus mastering did not read back as off */
    CK_PI5NET_E_READBACK = -4, /* a register did not read back what was written */
    CK_PI5NET_E_TIMEOUT = -5,
    CK_PI5NET_E_NOMAP = -6     /* BAR/window address could not be derived */
};

/* ============ A. inbound window confinement ============ */

/* Registers (offset from the RC base) [E2] Bcm2712Pcie.h:90-185. Window 0 is BAR2. */
#define CK_PI5NET_IB0_LO 0x4034u
#define CK_PI5NET_IB0_HI 0x4038u
#define CK_PI5NET_IB0_REMAP_LO 0x40b4u
#define CK_PI5NET_IB0_REMAP_HI 0x40b8u
#define CK_PI5NET_REMAP_ENABLE 0x1u
#define CK_PI5NET_REMAP_LO_MASK 0xfffff000u
#define CK_PI5NET_REMAP_HI_MASK 0xffu /* CPU address is 40 bits */
#define CK_PI5NET_PCI_COMMAND 0x04u   /* config dword 1: status[31:16] | command[15:0] */
#define CK_PI5NET_CMD_BME 0x0004u     /* bus master enable */

/* The smallest hardware-expressible window that contains [b_cpu, b_cpu+b_size).
 * Bus address == CPU address (identity), as the firmware's own window 0 is
 * (bus 0 -> cpu 0) and as ck_dma_alloc documents for the bounce region. */
struct ck_pi5net_ibprog {
    uint64_t bus_base, cpu_base, size; /* window; bus_base == cpu_base */
    uint32_t size_code;                /* the 5-bit code [E1] PcieEncodeInboundSize */
    uint32_t lo, hi, remap_lo, remap_hi; /* register values to write */
    uint64_t extra_bytes;              /* size - b_size: reach beyond the bounce region */
};
/* Pure. E_ARG for size 0 / overflow; E_RANGE if the window would exceed 64 GiB,
 * the CPU address passes 40 bits, or the size has no code. */
int ck_pi5net_ib_plan(uint64_t b_cpu, uint64_t b_size, struct ck_pi5net_ibprog *p);
/* bytes -> 5-bit size code ([E1]: 4K..32K = 0x1c.., 64K..64G = log2-15); 0 = not expressible */
uint32_t ck_pi5net_ib_size_code(uint64_t size);

/* Write a config dword of 01:00.0 through the RC window (INDEX then DATA+reg). */
int ck_pi5net_cfg_write32(const struct ck_pi5pcie_io *io, uint8_t bus, uint8_t dev, uint8_t fn, uint32_t reg,
                          uint32_t v);
/* Clear RP1's PCI bus-master-enable so no new upstream DMA can start, and verify it
 * read back off. *saved = the command register as found. Status bits (RW1C) are never
 * written back. E_QUIESCE if the readback still shows BME. */
int ck_pi5net_rp1_quiesce(const struct ck_pi5pcie_io *io, uint16_t *saved);

/* Saved raw registers of window 0, to put the firmware's window back on failure. */
struct ck_pi5net_ibsaved {
    uint32_t lo, hi, remap_lo, remap_hi;
    uint32_t other_lo[CK_PI5PCIE_IB_WINDOWS]; /* index 1.. used */
};
/* Reprogram window 0 to `p` and disable every other enabled inbound window. Order:
 * window off (size code 0), HI, REMAP, LO (size code, enables last). Everything is read
 * back; on any mismatch the saved values are written back and E_READBACK returned.
 * `*n_disabled` = how many other windows were switched off. */
int ck_pi5net_ib_apply(const struct ck_pi5pcie_io *io, const struct ck_pi5net_ibprog *p,
                       struct ck_pi5net_ibsaved *saved, uint32_t *n_disabled);

/* Plain label for the boot line, from the verdict computed over what the registers read back as. CONFINED =
 * reach is exactly the bounce region. PARTIAL = reach is the smallest window the hardware can express (it
 * equals `plan`, so the extra bytes are unavoidable) and nothing else. NOT_CONFINED = anything wider.
 * BROKEN = the window misses or does not fully cover the bounce region (or no window at all). */
enum { CK_PI5NET_CONF_CONFINED = 0, CK_PI5NET_CONF_PARTIAL = 1, CK_PI5NET_CONF_NOT_CONFINED = 2, CK_PI5NET_CONF_BROKEN = 3,
       CK_PI5NET_CONF_UNKNOWN = 4 };
int ck_pi5net_confine_label(const struct ck_pi5pcie_dmav *dv, const struct ck_pi5net_ibprog *plan);
const char *ck_pi5net_confine_name(int label);

/* ============ B0. where RP1 BAR1 is, as the CPU sees it ============ */

/* Outbound CPU->PCIe window 0 as programmed by firmware [E1] PcieSetupOutboundWindow. */
#define CK_PI5NET_OB0_BUS_LO 0x400cu
#define CK_PI5NET_OB0_BUS_HI 0x4010u
#define CK_PI5NET_OB0_BASE_LIMIT 0x4070u
#define CK_PI5NET_OB0_BASE_HI 0x4080u
#define CK_PI5NET_OB0_LIMIT_HI 0x4084u
struct ck_pi5net_obwin {
    uint64_t bus_base, cpu_base, size; /* size = limit - base + 1MB granule */
    uint8_t valid;
};
int ck_pi5net_ob_read(const struct ck_pi5pcie_io *io, struct ck_pi5net_obwin *w);
/* CPU address of a PCI bus address inside the outbound window; 0 when outside. */
uint64_t ck_pi5net_bus_to_cpu(const struct ck_pi5net_obwin *w, uint64_t bus, uint64_t len);

/* ============ B1. RP1 blocks and the clocks the GEM needs ============ */

/* Offsets inside RP1 BAR1 [E3] Rp1.h. */
#define CK_RP1_SYSINFO 0x00000u
#define CK_RP1_CLOCKS 0x18000u
#define CK_RP1_PLL_SYS 0x20000u
#define CK_RP1_IO_BANK1 0xd4000u
#define CK_RP1_RIO1 0xe4000u
#define CK_RP1_PADS_BANK1 0xf4000u
#define CK_RP1_ETH 0x100000u
#define CK_RP1_ETH_CFG 0x104000u
#define CK_RP1_BAR1_MAP_BYTES 0x108000u /* through ETH_CFG + 0x4000 */

/* Clock registers: offset from CK_RP1_CLOCKS (clk-rp1.c:32-67,119-121) and from CK_RP1_PLL_SYS
 * for the PLL (clk-rp1.c:28-33; PLL_SYS_CS is 0x08000 from the clocks base = 0x20000 from BAR1). */
#define CK_RP1_CLK_SYS_CTRL 0x014u
#define CK_RP1_CLK_SYS_DIV 0x018u
#define CK_RP1_CLK_SYS_SEL 0x020u
#define CK_RP1_CLK_ETH_CTRL 0x064u
#define CK_RP1_CLK_ETH_DIV 0x068u
#define CK_RP1_CLK_ETH_SEL 0x070u
#define CK_RP1_CLK_TSU_CTRL 0x134u
#define CK_RP1_CLK_TSU_DIV 0x138u
#define CK_RP1_CLK_TSU_SEL 0x140u
#define CK_RP1_PLL_CS 0x00u
#define CK_RP1_PLL_FBDIV_INT 0x08u
#define CK_RP1_PLL_FBDIV_FRAC 0x0cu
#define CK_RP1_PLL_PRIM 0x10u
#define CK_RP1_PLL_SEC 0x14u
#define CK_RP1_XOSC_HZ 50000000u /* clk-rp1 DT: XOSC 50 MHz ("Must match the XOSC frequency") */
#define CK_RP1_CLK_ENABLE (1u << 11)
#define CK_RP1_CLK_AUXSRC_MASK 0x3e0u
#define CK_RP1_CLK_AUXSRC_SHIFT 5
#define CK_RP1_ETH_HZ 125000000u /* assigned-clock-rates RP1_CLK_ETH */
#define CK_RP1_TSU_HZ 50000000u  /* assigned-clock-rates RP1_CLK_ETH_TSU */

/* Raw register snapshot the plan works from. */
struct ck_rp1_clk_regs {
    uint32_t pll_cs, pll_fbdiv_int, pll_fbdiv_frac, pll_prim, pll_sec;
    uint32_t sys_ctrl, sys_div, sys_sel;
    uint32_t eth_ctrl, eth_div, eth_sel;
    uint32_t tsu_ctrl, tsu_div, tsu_sel;
};
/* Rates in Hz from the snapshot; 0 = off / unlocked / not computable. */
uint32_t ck_rp1_pll_core_hz(const struct ck_rp1_clk_regs *r);
uint32_t ck_rp1_pll_sec_hz(const struct ck_rp1_clk_regs *r);
uint32_t ck_rp1_pll_pri_hz(const struct ck_rp1_clk_regs *r);
uint32_t ck_rp1_clk_sys_hz(const struct ck_rp1_clk_regs *r);
uint32_t ck_rp1_clk_eth_hz(const struct ck_rp1_clk_regs *r); /* 0 if disabled */
uint32_t ck_rp1_clk_tsu_hz(const struct ck_rp1_clk_regs *r);

enum { CK_RP1_CLK_ALREADY_ON = 0, CK_RP1_CLK_TO_ENABLE = 1, CK_RP1_CLK_BLOCKED = 2 };
struct ck_rp1_clk_plan {
    int eth, tsu;                  /* the three states above */
    uint32_t eth_div, tsu_div;     /* DIV_INT to write when TO_ENABLE */
    uint32_t eth_ctrl, tsu_ctrl;   /* CTRL value to write (ENABLE set) when TO_ENABLE */
    const char *eth_why, *tsu_why; /* why BLOCKED / how decided */
};
/* A clock that is already enabled is left exactly as found (its rate is reported, never
 * changed). A disabled clock is programmed to the DT assigned rate only if its source is
 * running and gives an exact integer divide; the PLLs are never touched. */
void ck_rp1_clk_decide(const struct ck_rp1_clk_regs *r, struct ck_rp1_clk_plan *p);

/* Register access to RP1 BAR1 (offset from BAR1 base). */
struct ck_rp1_io {
    uint32_t (*rd)(void *ctx, uint32_t off);
    void (*wr)(void *ctx, uint32_t off, uint32_t v);
    void (*delay_us)(void *ctx, uint32_t us);
    void *ctx;
};
void ck_rp1_clk_read(const struct ck_rp1_io *io, struct ck_rp1_clk_regs *r);
/* Program the clocks the plan marks TO_ENABLE (DIV_INT, then CTRL with AUXSRC, then ENABLE) and
 * read back. 0 = ok; E_READBACK if ENABLE does not stick. */
int ck_rp1_clk_apply(const struct ck_rp1_io *io, const struct ck_rp1_clk_plan *p);

/* ============ B2. PHY reset on RP1 GPIO32 ============ */

#define CK_RP1_PHY_RESET_GPIO 32u
#define CK_RP1_PHY_RESET_MS 5u       /* [L3] phy-reset-duration */
#define CK_RP1_PHY_SETTLE_MS 30u     /* our own margin after release (PHY datasheet NOT read: UNVERIFIED) */
/* GPIO32 = bank 1 pin 4 (clk: pinctrl-rp1.c:292-296 bank table { 28, 6, ...}). */
#define CK_RP1_GPIO32_CTRL (CK_RP1_IO_BANK1 + 4u * 8u + 4u)  /* gpio base + j*8 + RP1_GPIO_CTRL */
#define CK_RP1_GPIO32_PAD (CK_RP1_PADS_BANK1 + 4u + 4u * 4u) /* pads bank offset 0x4004 + j*4 (from 0xf0000) */
#define CK_RP1_RIO1_OUT (CK_RP1_RIO1 + 0x0u)
#define CK_RP1_RIO1_OE (CK_RP1_RIO1 + 0x4u)
#define CK_RP1_RIO1_IN (CK_RP1_RIO1 + 0x8u)
#define CK_RP1_ATOMIC_SET 0x2000u
#define CK_RP1_ATOMIC_CLR 0x3000u
#define CK_RP1_GPIO_PIN_BIT (1u << 4) /* bit j inside the bank's RIO word */
#define CK_RP1_FSEL_GPIO 0x05u
#define CK_RP1_PAD_IN_ENABLE 0x40u
#define CK_RP1_PAD_OUT_DISABLE 0x80u

struct ck_rp1_phyreset {
    uint32_t ctrl_before, pad_before, oe_before, out_before, in_before;
    uint32_t ctrl_after, pad_after, in_low, in_high; /* in_low: pin read while we drive low */
};
/* Drive GPIO32: line high first (no glitch low), pad+function, output enable, then low for
 * CK_RP1_PHY_RESET_MS, then high and settle. Reads every register back. 0 = ok;
 * E_READBACK if the pin does not read low while driven low or high after release. */
int ck_rp1_phy_reset(const struct ck_rp1_io *io, struct ck_rp1_phyreset *out);

/* ============ B3. MDIO read of the PHY ID ============ */

#define CK_GEM_NCR 0x000u
#define CK_GEM_NCFGR 0x004u
#define CK_GEM_NSR 0x008u
#define CK_GEM_MAN 0x034u
#define CK_GEM_MID 0x0fcu
#define CK_GEM_NCR_MPE (1u << 4)
#define CK_GEM_NSR_IDLE (1u << 2)
#define CK_GEM_NCFGR_CLK_SHIFT 18
#define CK_GEM_NCFGR_CLK_MASK (7u << 18)
#define CK_GEM_MDIO_POLLS 2000u
#define CK_GEM_MDIO_POLL_US 10u

/* GEM MDC divider code from the pclk rate (macb_main.c:2826-2849); 0 pclk -> the slowest. */
uint32_t ck_gem_mdc_div_code(uint32_t pclk_hz);
/* The C22 read frame the MAN register wants (macb.h MACB_MAN_C22_*). phy, reg < 32. */
uint32_t ck_gem_mdio_frame_read(uint32_t phy, uint32_t reg);
/* Set NCR.MPE and the MDC divider (read-modify-write, other bits kept). */
int ck_gem_mdio_enable(const struct ck_rp1_io *io, uint32_t pclk_hz);
/* One clause 22 read. Waits for idle before and after (bounded). 0 = ok, E_TIMEOUT, E_ARG. */
int ck_gem_mdio_read(const struct ck_rp1_io *io, uint32_t phy, uint32_t reg, uint16_t *val);

enum { CK_PHY_ABSENT = 0, CK_PHY_BCM54213PE = 1, CK_PHY_BROADCOM_OTHER = 2, CK_PHY_OTHER = 3 };
#define CK_PHY_ID_BCM54213PE 0x600d84a2u
struct ck_phy_id {
    uint32_t id;       /* reg2 << 16 | reg3 */
    uint32_t oui;      /* 24-bit OUI in IEEE octet order (e.g. 0x18c086), bits 1,2 taken as 0 */
    uint8_t model, rev;
    int cls;           /* CK_PHY_* */
};
void ck_phy_id_decode(uint16_t r2, uint16_t r3, struct ck_phy_id *out);
const char *ck_phy_class_name(int cls);
/* Find the PHY: poll address `addr` (dts: 1) up to `tries` times with `gap_ms` between; the
 * first non-0xffff/0x0000 pair wins. If it never answers, scan 0..31 once for diagnostics
 * (`*scan_hit` = lowest answering address, -1 if none). *attempts = polls used at `addr`.
 * 0 = answered at addr, E_TIMEOUT otherwise. */
int ck_phy_find(const struct ck_rp1_io *io, uint32_t addr, uint32_t tries, uint32_t gap_ms, struct ck_phy_id *id,
                uint32_t *attempts, int *scan_hit);

#ifdef CK_PI5_NET
/* Boot stage (CK_PI5_NET image only): see pi5_net.c. */
void ck_pi5net_run(void);
#endif

#endif
