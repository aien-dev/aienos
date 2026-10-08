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
 * Pages (cut B3b): a window made with ck_mmio_window_open OWNS its pages. It
 * maps them with ck_mmio_map_exclusive, which refuses (fail closed) when any
 * page is already mapped, so a mapping some other driver holds (nvme_bind maps
 * the same NVMe BAR0) can never be unmapped by a window. ck_mmio_revoke, once
 * no live capability for the window is left, unmaps the pages and invalidates
 * the TLB, so a raw access to the old pointer faults at the MMU; the accessor
 * refusal stays as a second layer. Refuse-not-refcount was chosen on purpose:
 * a shared page would make revoke depend on a stranger. Windows made with
 * ck_mmio_window_create (borrowed mapping) still revoke the capability only.
 * Exclusivity holds in both directions: while a window is live, the kernel's
 * ck_mm_mmio_try_map refuses (NULL) and ck_mmio_map panics for any range that
 * overlaps its pages, so a driver cannot share them later either.
 *
 * RULE: window capabilities must be revoked through ck_mmio_revoke. A bare
 * ck_cap_revoke removes the capability and the accessor refuses, but the
 * window is never told, so its pages stay mapped (tested in stage_test.c).
 * That is the remaining exposure; there is no lazy cleanup, because a revoked
 * handle no longer reaches the window.
 *
 * Limits (named): BAR size is not discoverable here, so the caller supplies
 * it from firmware or a fixture; the mapping is Device RW even though the
 * accessor is read-only (no read-only Device mapping is made); revoke must go
 * through ck_mmio_revoke (see RULE above); the exclusive-range table holds 8
 * ranges and a ninth window is refused with CK_MMIO_E_MAP; no interrupts, no DMA, no polling helper, no
 * config-space or COMMAND changes. */
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
    CK_MMIO_E_MAP = -508,      /* exclusive map refused: a page is already mapped, overlaps RAM, or cannot be mapped */
    CK_MMIO_E_UNMAP = -509,    /* capability revoked but the page unmap failed */
};

struct ck_mmio_window {
    uint8_t used;
    uint32_t resource;
    uint64_t bus_addr, size;
    uint8_t owned;                /* 1: window mapped these pages itself and unmaps them on revoke */
    uint8_t mapped;               /* owned pages still mapped */
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

/* Like ck_mmio_window_create, but the window OWNS its pages: it maps the BAR
 * itself with ck_mmio_map_exclusive (CK_MMIO_E_MAP, nothing created, if any
 * page is already mapped by someone else) and ck_mmio_revoke takes the pages
 * away again. */
int ck_mmio_window_open(struct ck_mmio_registry *r, struct ck_cap_table *t, const pci_found *f, unsigned bar,
                        uint64_t size, unsigned rights, struct ck_handle *out);

/* The revoke path for window capabilities: ck_cap_revoke(table_id, h, tables,
 * ntables), and when that leaves no live capability for the window's resource
 * in `tables` the owned pages are unmapped (MMU level; a raw access then
 * faults) and the TLB is invalidated. Revoking a derived child while its
 * parent is still live leaves the pages mapped. Returns the ck_cap code;
 * CK_MMIO_E_UNMAP if the capability is gone but the unmap failed (the pages
 * stay mapped and the accessor still refuses). `tables` must list every table
 * that can hold a capability for the window. Borrowed windows (created with
 * ck_mmio_window_create) revoke the capability only. Calling it again on a
 * revoked handle is harmless (CK_CAP_INVALID, nothing touched). */
int ck_mmio_revoke(struct ck_mmio_registry *r, uint32_t table_id, struct ck_handle h,
                   struct ck_cap_table *const *tables, unsigned ntables);

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
