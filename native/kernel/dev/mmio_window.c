/* mmio_window.c -- see mmio_window.h. Freestanding. */
#include "mmio_window.h"
#include "ck.h"

void ck_mmio_registry_init(struct ck_mmio_registry *r)
{
    for (unsigned i = 0; i < CK_MMIO_WINDOWS; i++)
        r->w[i] = (struct ck_mmio_window){ 0 };
    r->next = 0;
}

int ck_mmio_bar_addr(const pci_found *f, unsigned bar, uint64_t *addr)
{
    if (!f || !addr || bar >= PCI_MAX_BARS)
        return CK_MMIO_E_ARG;
    uint32_t raw = f->bar_raw[bar];
    if (raw & 1u) /* I/O BAR */
        return CK_MMIO_E_BAR;
    uint64_t a = raw & ~0xfu;
    switch ((raw >> 1) & 3u) {
    case 0: /* 32-bit */
        break;
    case 2: /* 64-bit: the next register holds the upper half */
        if (bar + 1 >= PCI_MAX_BARS)
            return CK_MMIO_E_BAR;
        a |= (uint64_t)f->bar_raw[bar + 1] << 32;
        break;
    default: /* reserved (type 1 is the legacy below-1-MiB type) */
        return CK_MMIO_E_BAR;
    }
    if (a == 0)
        return CK_MMIO_E_BAR;
    *addr = a;
    return CK_MMIO_OK;
}

int ck_mmio_window_create(struct ck_mmio_registry *r, struct ck_cap_table *t, const pci_found *f, unsigned bar,
                          uint64_t size, const volatile void *base, unsigned rights, struct ck_handle *out)
{
    if (!r || !t || !f || !out || !base || size == 0)
        return CK_MMIO_E_ARG;
    /* No write path exists, so a write (or map/grant) right is refused here
     * instead of being granted and ignored. */
    if ((rights & ~CK_MMIO_RIGHTS) || !(rights & CK_R_READ))
        return CK_MMIO_E_RIGHTS;
    uint64_t addr;
    int rc = ck_mmio_bar_addr(f, bar, &addr);
    if (rc)
        return rc;
    if (addr + size < addr)
        return CK_MMIO_E_RANGE;
    if (r->next >= CK_MMIO_WINDOWS)
        return CK_MMIO_E_FULL;
    uint32_t resource = CK_MMIO_RESOURCE_BASE + r->next;
    rc = ck_cap_insert(t, resource, rights, out);
    if (rc)
        return rc;
    r->w[r->next] = (struct ck_mmio_window){ .used = 1, .resource = resource, .bus_addr = addr, .size = size,
                                             .base = (const volatile uint8_t *)base };
    r->next++; /* never decremented: a resource number is not reused */
    return CK_MMIO_OK;
}

int ck_mmio_read(const struct ck_mmio_registry *r, const struct ck_cap_table *t, struct ck_handle h,
                 uint64_t offset, unsigned width, uint64_t *value)
{
    if (!r || !t || !value)
        return CK_MMIO_E_ARG;
    uint32_t resource;
    int rc = ck_cap_lookup(t, h, CK_R_READ, &resource);
    if (rc)
        return rc; /* revoked, stale, unknown or no READ: refused before the window is looked at */
    uint32_t idx = resource - CK_MMIO_RESOURCE_BASE;
    if (resource < CK_MMIO_RESOURCE_BASE || idx >= CK_MMIO_WINDOWS || !r->w[idx].used ||
        r->w[idx].resource != resource)
        return CK_MMIO_E_RESOURCE;
    const struct ck_mmio_window *w = &r->w[idx];
    if (width != 1 && width != 2 && width != 4 && width != 8)
        return CK_MMIO_E_ALIGN;
    if (offset & (width - 1u))
        return CK_MMIO_E_ALIGN;
    if (offset >= w->size || width > w->size - offset)
        return CK_MMIO_E_RANGE;
    const volatile uint8_t *p = w->base + offset;
    switch (width) {
    case 1: *value = *p; break;
    case 2: *value = *(const volatile uint16_t *)p; break;
    case 4: *value = *(const volatile uint32_t *)p; break;
    default: *value = *(const volatile uint64_t *)p; break;
    }
    return CK_MMIO_OK;
}

int ck_mmio_stage_report(void)
{
    uint32_t n = 0;
    const pci_found *found = pci_stage_disc_found(&n);
    const pci_found *nv = 0;
    for (uint32_t i = 0; i < n; i++)
        if ((found[i].class_code >> 8) == 0x0108 && ck_mmio_bar_addr(&found[i], 0, &(uint64_t){ 0 }) == CK_MMIO_OK) {
            nv = &found[i];
            break;
        }
    if (!nv) {
        ck_printf("mmio_win: no discovered NVMe function with a firmware-assigned BAR0 (report-only)\n");
        return CK_MMIO_E_BAR;
    }
    uint64_t addr = 0;
    (void)ck_mmio_bar_addr(nv, 0, &addr);
    /* 0x1000 covers the NVMe register file head (CAP, VS); the real BAR size is unknown here. */
    const volatile void *m = ck_mmio_try_map(addr, 0x1000);
    if (!m) {
        ck_printf("mmio_win: %04x:%02x:%02x.%u BAR0 map refused (report-only)\n", nv->segment, nv->bus, nv->dev, nv->fn);
        return CK_MMIO_E_BAR;
    }
    struct ck_mmio_registry reg;
    struct ck_cap_table tab;
    struct ck_cap_table *const tabs[1] = { &tab };
    struct ck_handle h;
    ck_mmio_registry_init(&reg);
    ck_cap_init(&tab, 1, CK_CAP_SLOTS);
    int crc = ck_mmio_window_create(&reg, &tab, nv, 0, 0x1000, m, CK_MMIO_RIGHTS, &h);
    uint64_t vs = 0, again = 0;
    int rrc = crc ? crc : ck_mmio_read(&reg, &tab, h, 0x08, 4, &vs); /* NVMe VS register */
    int wrc = crc ? crc : ck_mmio_read(&reg, &tab, h, 0x1000, 4, &again); /* one past the window */
    int vrc = crc ? crc : ck_cap_revoke(tab.id, h, tabs, 1);
    int arc = crc ? crc : ck_mmio_read(&reg, &tab, h, 0x08, 4, &again);
    ck_printf("mmio_win: %04x:%02x:%02x.%u bar0 addr=0x%llx size=0x1000 create=%d read(VS)=%d value=0x%llx "
              "past-end=%d revoke=%d after-revoke=%d (read-only, report-only)\n",
              nv->segment, nv->bus, nv->dev, nv->fn, (unsigned long long)addr, crc, rrc, (unsigned long long)vs, wrc, vrc, arc);
    return CK_MMIO_OK;
}
