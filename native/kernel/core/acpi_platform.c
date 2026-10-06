/* acpi_platform.c -- ck_acpi_platform_devices (ck.h): the DSDT named by the
 * FADT plus every SSDT the XSDT lists, each scanned by core/acpi_dev.c.
 * Kernel only; the scan itself is host tested (tests/test_acpi_dev.c) and
 * run over real firmware tables by tools/ck_acpi_scan.c. */
#include "ck_internal.h"
#include "acpi.h"
#include "acpi_dev.h"

#define SCAN_MAX 8u

struct scan_ctx {
    const char *const *ids;
    unsigned nids, max;
    struct ck_platform_dev *out;
    struct ck_acpi_scan_info info;
    int n;
};

static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

static void copy(char *dst, size_t cap, const char *src)
{
    size_t i = 0;
    for (; i + 1 < cap && src[i]; i++) dst[i] = src[i];
    dst[i] = 0;
}

static void scan_block(struct scan_ctx *c, uint64_t pa)
{
    if (!pa || !ck_mm_mapped(pa, 36)) {
        c->info.refused++;
        if (!c->info.first_refusal) c->info.first_refusal = CK_AML_E_LEN;
        return;
    }
    const uint8_t *t = (const uint8_t *)(uintptr_t)pa;
    uint32_t len = rd32(t + 4);
    c->info.tables++;
    /* avail is what is mapped: a length that runs past the mapping is a
     * truncated table and is refused by the length check. */
    size_t avail = len >= 36 && ck_mm_mapped(pa, len) ? len : 36;
    struct ck_acpi_device d[SCAN_MAX];
    unsigned seen = 0;
    int rc = ck_aml_scan(t, avail, c->ids, c->nids, d, SCAN_MAX, &seen);
    if (rc < 0) {
        c->info.refused++;
        if (!c->info.first_refusal) c->info.first_refusal = rc;
        return;
    }
    c->info.devices += seen;
    for (int i = 0; i < rc; i++) {
        if (i < (int)SCAN_MAX && c->n < (int)c->max && c->out) {
            struct ck_platform_dev *o = &c->out[c->n];
            copy(o->name, sizeof o->name, d[i].path);
            copy(o->hid, sizeof o->hid, d[i].hid);
            copy(o->cid, sizeof o->cid, d[i].cid);
            o->mmio_base = d[i].mmio_base;
            o->mmio_len = d[i].mmio_len;
            o->table[0] = (char)t[0], o->table[1] = (char)t[1], o->table[2] = (char)t[2], o->table[3] = (char)t[3];
            o->table[4] = 0;
        }
        c->n++;
    }
}

static void each_table(uint64_t table, uint32_t len, void *ctx)
{
    (void)len;
    if (!table || !ck_mm_mapped(table, 4)) return;
    const uint8_t *t = (const uint8_t *)(uintptr_t)table;
    if (t[0] == 'S' && t[1] == 'S' && t[2] == 'D' && t[3] == 'T') scan_block(ctx, table);
}

int ck_acpi_platform_devices(const char *const *ids, unsigned nids, struct ck_platform_dev *out, unsigned max,
                             struct ck_acpi_scan_info *info)
{
    struct scan_ctx c = { ids, nids, max, out, { 0, 0, 0, 0 }, 0 };
    const struct ck_handoff *h = ck_handoff_get();
    const uint8_t *fadt = ck_acpi_find("FACP");
    uint64_t dsdt = 0;
    if (fadt) {
        uint32_t flen = rd32(fadt + 4);
        if (flen >= 148) dsdt = (uint64_t)rd32(fadt + 140) | (uint64_t)rd32(fadt + 144) << 32; /* X_DSDT */
        if (!dsdt && flen >= 44) dsdt = rd32(fadt + 40);                                    /* DSDT */
    }
    if (!dsdt || !h || !h->rsdp) {
        if (info) *info = c.info;
        return -1;
    }
    scan_block(&c, dsdt);
    (void)ck_acpi_each(h->rsdp, each_table, &c);
    if (info) *info = c.info;
    return c.n;
}
