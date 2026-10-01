/* pci.h -- AIENOS C kernel stage: PCIe ECAM discovery from ACPI MCFG.
 *
 * Freestanding. The only outside services are ck.h ones (ck_printf,
 * ck_mmio_map, ck_acpi_find). The pure parts (MCFG parse, BAR sizing math)
 * take plain memory and are tested on the host against crafted tables.
 *
 * Scope: segment 0 from the first MCFG allocation, bus start_bus, plus any
 * bridge whose secondary bus firmware already programmed (bridges are never
 * reprogrammed here). Memory BARs firmware left unassigned are assigned only
 * inside a window the caller names (pci_window); with no window the device
 * is reported and left disabled. QEMU is not hardware.
 */
#ifndef AIENOS_CK_PCI_H
#define AIENOS_CK_PCI_H
#include <stddef.h>
#include <stdint.h>

#define PCI_MAX_FUNCS 64u
#define PCI_MAX_BARS 6u

enum {
    PCI_OK = 0,
    PCI_E_NO_MCFG = -401,  /* ACPI has no MCFG table */
    PCI_E_MCFG = -402,     /* MCFG malformed (length, no allocation, bus range) */
    PCI_E_FULL = -403,     /* more than PCI_MAX_FUNCS functions */
    PCI_E_BAR = -404,      /* BAR sizing / assignment failed */
    PCI_E_ARG = -405,
};

/* One MCFG allocation (ACPI PCI Firmware spec, 16 bytes). */
typedef struct {
    uint64_t base;     /* ECAM base of bus 0 of this segment */
    uint16_t segment;
    uint8_t start_bus, end_bus;
} pci_ecam;

/* Parse an MCFG table (header included, `len` = table length field).
 * Picks the first allocation for segment 0. Validates: length >= 44 + 16,
 * (length - 44) a multiple of 16, start_bus <= end_bus, base != 0, base
 * 1 MiB aligned. */
int pci_mcfg_parse(const uint8_t *table, size_t len, pci_ecam *out);

/* Config space access. `cfg` returns the 4 KiB config page of bus/dev/fn
 * or NULL when out of the ECAM bus range. */
typedef struct {
    volatile uint8_t *ecam; /* mapped ECAM for bus start_bus */
    uint8_t start_bus, end_bus;
} pci_bus_access;
volatile uint8_t *pci_cfg(const pci_bus_access *a, uint8_t bus, uint8_t dev, uint8_t fn);
uint32_t pci_r32(volatile uint8_t *cfg, uint32_t off);
void pci_w32(volatile uint8_t *cfg, uint32_t off, uint32_t v);
uint16_t pci_r16(volatile uint8_t *cfg, uint32_t off);
void pci_w16(volatile uint8_t *cfg, uint32_t off, uint16_t v);

/* Window for BARs firmware did not assign. [base, limit) and next. */
typedef struct {
    uint64_t base, limit, next;
} pci_window;

typedef struct {
    uint64_t addr;   /* assigned bus address (identity: CPU address) */
    uint64_t size;   /* 0: BAR not implemented */
    uint8_t is64, prefetch, io, assigned_here;
} pci_bar;

typedef struct {
    uint8_t bus, dev, fn;
    uint16_t vendor, device;
    uint32_t class_code; /* class << 16 | subclass << 8 | progif */
    uint8_t header_type;
    uint16_t subsys_vendor, subsys_id;
    volatile uint8_t *cfg;
    pci_bar bar[PCI_MAX_BARS];
    int bars_ok; /* every memory BAR assigned (by firmware or here) */
} pci_func;

typedef struct {
    pci_ecam ecam;
    pci_bus_access acc;
    pci_func f[PCI_MAX_FUNCS];
    uint32_t n;
    uint32_t bridges_followed;
} pci_system;

/* Size of a memory BAR from the value read back after writing all ones
 * (lo/hi halves; hi used only when is64). 0 when not implemented. */
uint64_t pci_bar_size(uint32_t lo_readback, uint32_t hi_readback, int is64);

/* Allocate size (power of two) aligned to size from the window. 0 on
 * exhaustion or overflow. */
uint64_t pci_window_alloc(pci_window *w, uint64_t size);

/* Enumerate: bus start_bus, then programmed bridges. Sizes every BAR; a
 * memory BAR reading 0 is assigned from `win` when win != NULL. Leaves
 * COMMAND as firmware set it except while sizing (decode is turned off
 * around the sizing writes and restored). */
int pci_enumerate(pci_system *s, pci_window *win);

/* Turn on memory decode (+ bus master when bm != 0). */
void pci_enable(const pci_func *f, int bm);
/* Clear Bus Master Enable and read it back: 0 when it reads clear. */
int pci_bus_master_off(const pci_func *f);


/* Post-exit bus-master sweep (port of crates/aienos-kernel/src/dma_gate.rs
 * sweep_bus_master): walk every bus in the ECAM window, every device and
 * (when marked multi-function) every function, and clear Bus Master Enable
 * on every endpoint (header type 0) that has it set, reading it back.
 * Bridges (header type 1) are counted, never changed: a bridge's BME only
 * forwards DMA from the endpoints below it, which are cleared one by one.
 * Runs before any device is given DMA, so every device starts with DMA off. */
#define PCI_SWEEP_FINDINGS 8u
typedef struct {
    uint8_t bus, dev, fn;
    uint16_t command_before, command_after; /* after: read back after the clear */
} pci_bme_finding;
typedef struct {
    uint16_t functions;       /* functions that answered a config read */
    uint16_t bridges;         /* header type 1 among them (left untouched) */
    uint16_t bridges_bme;     /* bridges with BME set */
    uint16_t endpoints_bme;   /* endpoints found with BME set (and cleared) */
    uint16_t still_enabled;   /* endpoints whose BME still reads set after the clear */
    pci_bme_finding f[PCI_SWEEP_FINDINGS]; /* first PCI_SWEEP_FINDINGS endpoints */
} pci_sweep;
void pci_sweep_bus_master(const pci_bus_access *a, pci_sweep *out);
/* Print the sweep in the Rust kernel's format: one "dma_sweep: seg ..." line
 * plus one "dma_sweep: bme cleared|STUCK ..." line per recorded finding. */
void pci_sweep_report(const pci_ecam *e, const pci_sweep *s);

/* First function with this class (class/subclass/progif masked by mask). */
const pci_func *pci_find_class(const pci_system *s, uint32_t class_code, uint32_t mask);
const pci_func *pci_find_id(const pci_system *s, uint16_t vendor, uint16_t device);

const char *pci_class_name(uint32_t class_code);

/* Stage glue (ck.h): find MCFG, map ECAM, enumerate, print one line per
 * function. Uses the QEMU virt 32-bit window only when the ECAM base is a
 * known QEMU virt base (0x4010000000 or 0x3f000000). */
int pci_stage_probe(pci_system *s);

#endif
