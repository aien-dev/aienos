/* pi5_pcie.h -- Raspberry Pi 5: how the kernel reaches the BCM2712 PCIe root
 * complex that hosts the RP1 south bridge, plus a read-only enumerator.
 * AIENOS-PI5 network lane, GEM-first plan step 1. NO GEM register code here.
 *
 * Everything below is READ-ONLY toward the hardware except one write: the
 * root complex's config window index (CK_PI5PCIE_EXT_CFG_INDEX), which only
 * selects which function the 4 KiB config window shows. No BAR sizing, no
 * COMMAND change, no inbound window change.
 *
 * WHY THE ROOT COMPLEX'S OWN CONFIG WINDOW, NOT ECAM (decision, cited):
 *  - RP1 sits behind PCIe controller 2 (segment 2, RC registers at
 *    0x1000120000). Frozen firmware = aien-dev/rpi5-uefi tag v0.3 (c1ca184), which
 *    pins worproject/edk2-platforms 8e1779b. In that tree:
 *      Platform/RaspberryPi/RPi5/AcpiTables/Mcfg.aslc:26-48  the MCFG entry for
 *        each segment has base = RC base + PCIE_EXT_CFG_DATA (0x8000) and bus
 *        range 0..0: a 4 KiB window, not an ECAM that can address bus 1.
 *      Platform/RaspberryPi/RPi5/Drivers/RpiPlatformDxe/ConfigTable.c:350-354
 *        in the default (DEN0115) mode the MCFG signature is zeroed ("MCFG
 *        must be hidden"); ConfigTable.h:23 makes NXPMX6_DEN0115 the default
 *        and ConfigTable.c:301-308 clears the NXPMX6 half for non-Windows OSes.
 *      Silicon/Broadcom/Bcm27xx/Library/Bcm2712PciSegmentLib/PciSegmentLib.c:
 *        89-115 is the firmware's own access rule: bus 0 = the root port at the
 *        RC base; bus > 0 = write bus/dev/fn to RC+0x9000 (INDEX), read the
 *        function at RC+0x8000+reg (DATA). 96-104: only dev 0 fn 0 exists on
 *        bus 0 and only dev 0 on bus 1.
 *      Platform/RaspberryPi/RPi5/AcpiTables/PcieCommon.asi:30-38 (_INI) points
 *        INDEX at 01:00.0 for OSes that cannot do more. The kernel does not
 *        run AML (core/pi5.c:15-21), so it writes INDEX itself.
 *  - So ECAM via MCFG is unusable here and the RC window is used always. The
 *    decision function reports WHY, from the actual MCFG if the firmware
 *    exposes one. Which MCFG the running firmware shows is UNVERIFIED until
 *    the hardware run (the stored UEFI variable AcpiPcieEcamCompatMode can
 *    change it).
 *  - Linux reference reading only: drivers/pci/controller/pcie-brcmstb.c uses
 *    the same INDEX/DATA pair; drivers/misc/rp1 is the RP1 platform driver.
 *    Not re-read in this cut (UNVERIFIED against the Linux tree).
 *
 * Inbound window registers: edk2-platforms
 * Silicon/Broadcom/Bcm27xx/Include/IndustryStandard/Bcm2712Pcie.h:97-104,
 * 133-170, 196-201; encode rules in Bcm2712PciHostBridge.c:113-170 (size code
 * and remap). The firmware programs one window per enabled RC: bus 0 -> CPU 0,
 * 64 GiB (Bcm2712PciHostBridgeLib.c:157-159). That is the whole of RAM, so the
 * hardware backstop of ADR 0020 rule 6 is NOT in place unless a later cut
 * reprograms it. This file only reports; it never programs. */
#ifndef AIENOS_CK_PI5_PCIE_H
#define AIENOS_CK_PI5_PCIE_H
#include <stddef.h>
#include <stdint.h>

#define CK_PI5PCIE_RC2_PHYS 0x1000120000ull /* BCM2712_BRCMSTB_PCIE2_BASE */
#define CK_PI5PCIE_RC_BYTES 0xa000u         /* through INDEX (0x9000) + 0x1000 */
#define CK_PI5PCIE_SEGMENT 2u
#define CK_PI5PCIE_EXT_CFG_DATA 0x8000u
#define CK_PI5PCIE_EXT_CFG_INDEX 0x9000u

#define CK_PI5PCIE_RP1_VENDOR 0x1de4u /* Rp1.h:12 */
#define CK_PI5PCIE_RP1_DEVICE 0x0001u /* Rp1.h:13 */

enum {
    CK_PI5PCIE_OK = 0,
    CK_PI5PCIE_E_ADDR = -1, /* bus/dev/fn/reg the root complex cannot address */
    CK_PI5PCIE_E_ARG = -2
};

/* Register access to the root complex block (offset from the RC base). A
 * host test stands a fake register file behind it. */
struct ck_pi5pcie_io {
    uint32_t (*rd)(void *ctx, uint32_t off);
    void (*wr)(void *ctx, uint32_t off, uint32_t v);
    void *ctx;
};

/* One 32-bit config read. Addressable: bus 0 dev 0 fn 0 (the root port, at the
 * RC base) and bus 1 dev 0 fn 0..7 (through INDEX/DATA). reg is dword aligned
 * and < 4096. Anything else is E_ADDR and touches no register. */
int ck_pi5pcie_cfg_read32(const struct ck_pi5pcie_io *io, uint8_t bus, uint8_t dev, uint8_t fn, uint32_t reg,
                          uint32_t *out);

struct ck_pi5pcie_func {
    uint8_t bus, dev, fn;
    uint16_t vendor, device;
    uint32_t class_code; /* class << 16 | subclass << 8 | progif */
    uint8_t revision, header_type, nbars;
    uint16_t command;
    uint32_t bar_raw[6];            /* as read, never sized */
    uint8_t primary, secondary, subordinate; /* header type 1 only */
};

/* 0 = present, 1 = absent (vendor 0xffff or 0), < 0 = E_ADDR. */
int ck_pi5pcie_read_func(const struct ck_pi5pcie_io *io, uint8_t bus, uint8_t dev, uint8_t fn,
                         struct ck_pi5pcie_func *f);

enum { CK_PI5PCIE_RP1_OK = 0, CK_PI5PCIE_RP1_ABSENT = 1, CK_PI5PCIE_RP1_MISMATCH = 2 };
/* rc = return of ck_pi5pcie_read_func for 01:00.0. */
int ck_pi5pcie_rp1_check(int read_rc, const struct ck_pi5pcie_func *f);

enum { CK_PI5PCIE_BAR_EMPTY = 0, CK_PI5PCIE_BAR_MEM32 = 1, CK_PI5PCIE_BAR_MEM64 = 2, CK_PI5PCIE_BAR_IO = 3,
       CK_PI5PCIE_BAR_BAD = 4 };
struct ck_pi5pcie_bar {
    uint8_t kind, prefetch;
    uint64_t addr; /* as firmware left it; size unknown (not sized) */
};
/* Decode BAR register `idx` of `nbars`. Returns how many registers it used
 * (1, or 2 for a 64-bit memory BAR). EMPTY = raw 0: unimplemented or
 * unassigned, which unsized reading cannot tell apart. */
uint32_t ck_pi5pcie_bar_decode(const uint32_t *raw, uint32_t idx, uint32_t nbars, struct ck_pi5pcie_bar *b);

/* ---- inbound windows (PCIe -> memory) ---- */
#define CK_PI5PCIE_IB_WINDOWS 8u /* PCIE_NUM_INBOUND_WINDOWS */
#define CK_PI5PCIE_MISC_CTRL 0x4008u
#define CK_PI5PCIE_RC_BAR1_LO 0x402cu /* GISB window: firmware disables it */
#define CK_PI5PCIE_RC_BAR3_LO 0x403cu /* SCB window: firmware disables it */
#define CK_PI5PCIE_BAR_SIZE_MASK 0x1fu

struct ck_pi5pcie_ibwin {
    uint32_t idx;
    uint8_t enabled;    /* size code != 0 */
    uint8_t size_valid; /* code decodes, base aligned to size */
    uint8_t remap_en;   /* UBUS remap enable (bit 0) */
    uint64_t bus_base, size, cpu_base;
};
/* Size code -> bytes. 1 = valid (*size set), 0 = disabled (code 0), -1 = a
 * code the firmware never writes. 1..21 = 64 KiB..64 GiB, 0x1c..0x1f =
 * 4 KiB..32 KiB (Bcm2712PciHostBridge.c:119-127). */
int ck_pi5pcie_ib_size_decode(uint32_t code, uint64_t *size);
int ck_pi5pcie_ib_read(const struct ck_pi5pcie_io *io, uint32_t idx, struct ck_pi5pcie_ibwin *w);

enum {
    CK_PI5PCIE_DMA_UNKNOWN = 0,   /* cannot tell (bad window, no remap, extra BAR windows) */
    CK_PI5PCIE_DMA_NO_WINDOW = 1, /* no inbound window enabled: DMA cannot reach memory at all */
    CK_PI5PCIE_DMA_MISS = 2,      /* windows exist but none reaches the bounce region */
    CK_PI5PCIE_DMA_PARTIAL = 3,   /* only part of the bounce region is reachable */
    CK_PI5PCIE_DMA_WIDER = 4,     /* bounce region reachable AND memory outside it: NOT confined */
    CK_PI5PCIE_DMA_CONFINED = 5   /* reach == bounce region exactly */
};
struct ck_pi5pcie_dmav {
    int verdict;
    uint32_t windows;       /* enabled windows */
    uint64_t reach_bytes;   /* union of CPU ranges the windows reach */
    uint64_t inside_bytes;  /* of which inside the bounce region */
    uint64_t outside_bytes; /* of which outside it */
};
/* ADR 0020 rule 6: does the hardware window confine inbound DMA to the bounce
 * region [b_cpu, b_cpu+b_size)? Works in CPU address space (bus -> CPU through
 * each window's remap). `unmodelled` = enabled windows this model does not
 * cover (RC_BAR1/BAR3); they can only turn CONFINED into UNKNOWN. */
int ck_pi5pcie_ib_verdict(const struct ck_pi5pcie_ibwin *w, uint32_t n, uint32_t unmodelled, uint64_t b_cpu,
                          uint64_t b_size, struct ck_pi5pcie_dmav *out);
const char *ck_pi5pcie_verdict_name(int v);

/* ---- which door: ECAM via MCFG, or the RC's own window ---- */
enum {
    CK_PI5PCIE_WHY_NO_MCFG = 0,       /* firmware exposes no MCFG (hidden or absent) */
    CK_PI5PCIE_WHY_MALFORMED = 1,
    CK_PI5PCIE_WHY_NO_SEGMENT = 2,    /* MCFG has no entry for segment 2 */
    CK_PI5PCIE_WHY_DATA_WINDOW = 3,   /* entry base is RC+0x8000: the 4 KiB window, not an ECAM */
    CK_PI5PCIE_WHY_NARROW = 4,        /* entry bus range stops before bus 1 */
    CK_PI5PCIE_WHY_ECAM_CANDIDATE = 5 /* looks like a real ECAM: still NOT used here (UNVERIFIED) */
};
struct ck_pi5pcie_door {
    int why;
    uint64_t base;
    uint8_t bus_min, bus_max;
};
/* The kernel always uses the RC window (the only door implemented and
 * proven by the firmware source); this explains why ECAM is not used. `mcfg`
 * may be NULL; `len` is the table length field. */
void ck_pi5pcie_door_decide(const uint8_t *mcfg, size_t len, uint16_t segment, uint64_t rc_phys,
                            struct ck_pi5pcie_door *out);
const char *ck_pi5pcie_why_name(int why);

/* Boot report (CK_PI5_PCIE image only): maps RC2, prints one line per fact,
 * allocates and zeroes the ADR 0020 bounce window and judges the hardware
 * inbound window against it. Read-only apart from the INDEX select. */
#ifdef CK_PI5_PCIE
void ck_pi5pcie_report(void);
#endif

#endif
