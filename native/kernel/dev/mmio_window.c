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

int ck_mmio_window_open(struct ck_mmio_registry *r, struct ck_cap_table *t, const pci_found *f, unsigned bar,
                        uint64_t size, unsigned rights, struct ck_handle *out)
{
    if (!r || !t || !f || !out || size == 0)
        return CK_MMIO_E_ARG;
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
    /* Exclusive: a page some other driver already mapped is refused, so the
     * unmap on revoke can never pull a mapping out from under it. */
    const volatile void *m = ck_mmio_map_exclusive(addr, (size_t)size);
    if (!m)
        return CK_MMIO_E_MAP;
    uint32_t idx = r->next;
    rc = ck_mmio_window_create(r, t, f, bar, size, m, rights, out);
    if (rc) {
        (void)ck_mmio_unmap_exclusive(addr, (size_t)size);
        return rc;
    }
    r->w[idx].owned = r->w[idx].mapped = 1;
    return CK_MMIO_OK;
}

int ck_mmio_revoke(struct ck_mmio_registry *r, uint32_t table_id, struct ck_handle h,
                   struct ck_cap_table *const *tables, unsigned ntables)
{
    if (!r || !tables)
        return CK_MMIO_E_ARG;
    uint32_t resource = 0;
    int named = 0;
    for (unsigned i = 0; i < ntables; i++)
        if (tables[i]->id == table_id)
            named = ck_cap_lookup(tables[i], h, 0, &resource) == CK_CAP_OK;
    int rc = ck_cap_revoke(table_id, h, tables, ntables);
    if (rc || !named)
        return rc; /* refused or already revoked: nothing is unmapped here */
    uint32_t idx = resource - CK_MMIO_RESOURCE_BASE;
    if (resource < CK_MMIO_RESOURCE_BASE || idx >= CK_MMIO_WINDOWS || !r->w[idx].used ||
        r->w[idx].resource != resource || !r->w[idx].owned || !r->w[idx].mapped)
        return CK_CAP_OK;
    for (unsigned i = 0; i < ntables; i++)
        for (unsigned s = 0; s < tables[i]->n; s++)
            if (tables[i]->slots[s].live && !tables[i]->slots[s].tombstone && tables[i]->slots[s].resource == resource)
                return CK_CAP_OK; /* a parent or sibling still holds the window */
    struct ck_mmio_window *w = &r->w[idx];
    w->base = 0; /* the accessor has no pointer left to use, whatever the unmap does */
    if (ck_mmio_unmap_exclusive(w->bus_addr, (size_t)w->size))
        return CK_MMIO_E_UNMAP;
    w->mapped = 0;
    return CK_CAP_OK;
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
    if (!w->base)
        return CK_CAP_INVALID; /* owned pages were given back */
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
    if (!(nv->command & 0x2u)) { /* reading a BAR with memory decode off can abort on real hardware */
        ck_printf("mmio_win: %04x:%02x:%02x.%u memory decode off, not read (report-only)\n", nv->segment, nv->bus, nv->dev,
                  nv->fn);
        return CK_MMIO_E_BAR;
    }
    uint64_t addr = 0;
    (void)ck_mmio_bar_addr(nv, 0, &addr);
    struct ck_mmio_registry reg;
    struct ck_cap_table tab;
    struct ck_cap_table *const tabs[1] = { &tab };
    struct ck_handle h;
    ck_mmio_registry_init(&reg);
    ck_cap_init(&tab, 1, CK_CAP_SLOTS);
    /* 0x1000 covers the NVMe register file head (CAP, VS); the real BAR size is unknown here. The window maps
     * the page exclusively: if the page is already mapped it is refused and nothing is touched. */
    int crc = ck_mmio_window_open(&reg, &tab, nv, 0, 0x1000, CK_MMIO_RIGHTS, &h);
    if (crc == CK_MMIO_E_MAP) {
        ck_printf("mmio_win: %04x:%02x:%02x.%u BAR0 map refused (report-only)\n", nv->segment, nv->bus, nv->dev, nv->fn);
        return CK_MMIO_E_BAR;
    }
    uint64_t vs = 0, again = 0;
    int rrc = crc ? crc : ck_mmio_read(&reg, &tab, h, 0x08, 4, &vs); /* NVMe VS register */
    int wrc = crc ? crc : ck_mmio_read(&reg, &tab, h, 0x1000, 4, &again); /* one past the window */
    int shrc = crc ? crc : ck_mmio_try_map(addr, 0x1000) == 0; /* 1: a second (shared) map of the live window is refused */
    int vrc = crc ? crc : ck_mmio_revoke(&reg, tab.id, h, tabs, 1);
    int arc = crc ? crc : ck_mmio_read(&reg, &tab, h, 0x08, 4, &again);
    ck_printf("mmio_win: %04x:%02x:%02x.%u bar0 addr=0x%llx size=0x1000 create=%d read(VS)=%d value=0x%llx "
              "past-end=%d shared-map-refused=%d revoke=%d after-revoke=%d unmapped=%d (read-only, report-only)\n",
              nv->segment, nv->bus, nv->dev, nv->fn, (unsigned long long)addr, crc, rrc, (unsigned long long)vs, wrc, shrc, vrc, arc, crc ? -1 : !ck_mmio_is_mapped(addr, 0x1000));
    return CK_MMIO_OK;
}
