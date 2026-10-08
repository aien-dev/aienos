/* mmio_window.h -- AIENOS C kernel: capability-bound, READ-ONLY MMIO window
 * for one discovered PCI function (aienos#286, cut B3).
 *
 * Freestanding. Reuses the existing capability code (core/ipc.h: rights,
 * attenuating derive, generation-checked handles, cascading revoke); there is
 * no second authority system here. A window is a kernel resource: one memory
 * BAR of one pci_found, as firmware left it (pci_discover never sizes BARs and
 * never writes). The capability is the only way to reach it:
 *
 *   - rights are READ, DERIVE, REVOKE only; WRITE, MAP and GRANT are refused
 *     at creation, and derive cannot add a right the parent lacks;
 *   - there is NO write accessor for this object;
 *   - ck_mmio_read validates the handle (live, current generation, READ right,
 *     this window's resource) and then offset/width, all BEFORE the device is
 *     touched. After revoke every read through the old handle or any derived
 *     child is refused with CK_CAP_INVALID.
 *
 * Resource numbers: the registry never frees or reuses a window, so a number
 * is never given to a second resource (aienos#285 / ADR 0019 trigger not hit).
 *
 * Limits (named): BAR size is not discoverable here, so the caller supplies
 * it from firmware or a fixture; page tables are NOT unmapped on revoke (the
 * kernel mapping from ck_mmio_try_map stays Device RW; read-only and revoke
 * are enforced in the accessor, not by the MMU); no interrupts, no DMA, no
 * polling helper, no config-space or COMMAND changes. */
#ifndef AIENOS_CK_MMIO_WINDOW_H
#define AIENOS_CK_MMIO_WINDOW_H
#include <stdint.h>
#include "../core/ipc.h"
#include "pci.h"

#define CK_MMIO_RESOURCE_BASE 0x4d4d0000u /* "MM" */
#define CK_MMIO_WINDOWS 4u
/* The only rights a window capability may hold. */
#define CK_MMIO_RIGHTS (CK_R_READ | CK_R_DERIVE | CK_R_REVOKE)

enum {
    CK_MMIO_OK = 0,
    CK_MMIO_E_ARG = -501,      /* null argument, zero size, bad BAR index */
    CK_MMIO_E_RIGHTS = -502,   /* creation asked for a right outside CK_MMIO_RIGHTS, or no READ */
    CK_MMIO_E_BAR = -503,      /* I/O BAR, reserved type, 64-bit pair out of range, or address 0 */
    CK_MMIO_E_RANGE = -504,    /* window wraps u64, or access outside the window */
    CK_MMIO_E_ALIGN = -505,    /* width not 1/2/4/8, or offset not width-aligned */
    CK_MMIO_E_FULL = -506,     /* registry full (windows are never reused) */
    CK_MMIO_E_RESOURCE = -507, /* handle is live but names no MMIO window */
};

struct ck_mmio_window {
    uint8_t used;
    uint32_t resource;
    uint64_t bus_addr, size;
    const volatile uint8_t *base; /* caller's mapping of [bus_addr, +size) */
};
struct ck_mmio_registry {
    struct ck_mmio_window w[CK_MMIO_WINDOWS];
    uint32_t next; /* next unused index; never decreases */
};

void ck_mmio_registry_init(struct ck_mmio_registry *r);

/* Address of memory BAR `bar` of `f` from bar_raw (type bits masked; a 64-bit
 * BAR joins bar_raw[bar + 1]). CK_MMIO_E_BAR for I/O, reserved types, a
 * 64-bit pair past the last register, or an address of 0. */
int ck_mmio_bar_addr(const pci_found *f, unsigned bar, uint64_t *addr);

/* Create the window and put its capability into `t`. `base` is the caller's
 * mapping of the BAR (ck_mmio_try_map in the kernel, a fake on the host). */
int ck_mmio_window_create(struct ck_mmio_registry *r, struct ck_cap_table *t, const pci_found *f, unsigned bar,
                          uint64_t size, const volatile void *base, unsigned rights, struct ck_handle *out);

/* Checked read of `width` (1, 2, 4 or 8) bytes at `offset`. Capability
 * failures return the ck_cap code (CK_CAP_INVALID: revoked, stale or unknown
 * handle; CK_CAP_MISSING_RIGHTS). *value is written only on CK_MMIO_OK. */
int ck_mmio_read(const struct ck_mmio_registry *r, const struct ck_cap_table *t, struct ck_handle h,
                 uint64_t offset, unsigned width, uint64_t *value);

/* Stage glue: report-only. Binds a window to the first discovered NVMe
 * function's BAR0 (size from the NVMe register file minimum, 0x1000), reads
 * VS through the capability, revokes, proves the next read is refused. */
int ck_mmio_stage_report(void);

#endif
