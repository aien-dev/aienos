/* acpi.c -- see acpi.h. Unaligned little-endian reads only (ACPI tables are
 * byte packed and the kernel builds with -mstrict-align). */
#include "acpi.h"

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t rd64(const uint8_t *p)
{
    return (uint64_t)rd32(p) | (uint64_t)rd32(p + 4) << 32;
}

static const uint8_t *ptr(uint64_t a)
{
    return (const uint8_t *)(uintptr_t)a;
}

int ck_acpi_sum_ok(const void *p, size_t len)
{
    const uint8_t *b = p;
    uint8_t s = 0;
    for (size_t i = 0; i < len; i++)
        s = (uint8_t)(s + b[i]);
    return s == 0;
}

static int sig_eq(const uint8_t *p, const char *sig, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (p[i] != (uint8_t)sig[i])
            return 0;
    return 1;
}

uint64_t ck_acpi_root(uint64_t rsdp, int *is_xsdt)
{
    const uint8_t *r = ptr(rsdp);
    if (!r || !sig_eq(r, "RSD PTR ", 8) || !ck_acpi_sum_ok(r, 20))
        return 0;
    if (r[15] >= 2) {
        uint32_t len = rd32(r + 20);
        if (len < 36 || len > 4096 || !ck_acpi_sum_ok(r, len))
            return 0;
        uint64_t x = rd64(r + 24);
        if (x) {
            if (is_xsdt)
                *is_xsdt = 1;
            return x;
        }
    }
    if (is_xsdt)
        *is_xsdt = 0;
    return rd32(r + 16);
}

static int root_entries(uint64_t rsdp, const uint8_t **ents, uint32_t *count, uint32_t *width)
{
    int x = 0;
    const uint8_t *root = ptr(ck_acpi_root(rsdp, &x));
    if (!root || !sig_eq(root, x ? "XSDT" : "RSDT", 4))
        return -1;
    uint32_t len = rd32(root + 4);
    if (len < CK_ACPI_SDT_HEADER || len > (1u << 20) || !ck_acpi_sum_ok(root, len))
        return -1;
    *width = x ? 8 : 4;
    *count = (len - CK_ACPI_SDT_HEADER) / *width;
    *ents = root + CK_ACPI_SDT_HEADER;
    return 0;
}

const void *ck_acpi_lookup(uint64_t rsdp, const char sig[4])
{
    const uint8_t *ents;
    uint32_t count, width;
    if (root_entries(rsdp, &ents, &count, &width))
        return 0;
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *t = ptr(width == 8 ? rd64(ents + i * 8) : rd32(ents + i * 4));
        if (!t || !sig_eq(t, sig, 4))
            continue;
        uint32_t len = rd32(t + 4);
        if (len < CK_ACPI_SDT_HEADER || len > (1u << 24) || !ck_acpi_sum_ok(t, len))
            continue;
        return t;
    }
    return 0;
}

int ck_acpi_each(uint64_t rsdp, void (*fn)(uint64_t, uint32_t, void *), void *ctx)
{
    const uint8_t *ents;
    uint32_t count, width;
    if (root_entries(rsdp, &ents, &count, &width))
        return -1;
    for (uint32_t i = 0; i < count; i++) {
        uint64_t a = width == 8 ? rd64(ents + i * 8) : rd32(ents + i * 4);
        if (a)
            fn(a, rd32(ptr(a) + 4), ctx);
    }
    return (int)count;
}

int ck_madt_parse(const void *madt, struct ck_madt_gic *out)
{
    const uint8_t *m = madt;
    struct ck_madt_gic g = { 0 };
    uint32_t len = rd32(m + 4);
    if (!sig_eq(m, "APIC", 4) || len < 44)
        return -1;
    for (uint32_t at = 44; at < len;) {
        if (at + 2 > len)
            return -1;
        uint8_t type = m[at], elen = m[at + 1];
        if (elen < 2 || at + elen > len)
            return -1;
        const uint8_t *e = m + at;
        if (type == 0x0b) { /* GICC */
            if (elen < 76)
                return -1;
            uint32_t flags = rd32(e + 12);
            if (flags & (1u | 8u)) {
                if (!g.gicc_count)
                    g.gicc_gicr = rd64(e + 60);
                g.gicc_count++;
            }
        } else if (type == 0x0c) { /* GICD */
            if (elen < 24)
                return -1;
            if (!g.gicd) {
                g.gicd = rd64(e + 8);
                g.gic_version = e[20];
            }
        } else if (type == 0x0e) { /* GICR discovery range */
            if (elen < 16)
                return -1;
            if (!g.gicr) {
                g.gicr = rd64(e + 4);
                g.gicr_len = rd32(e + 12);
            }
        }
        at += elen;
    }
    *out = g;
    return 0;
}

int ck_spcr_parse(const void *spcr, struct ck_spcr *out)
{
    const uint8_t *s = spcr;
    if (!sig_eq(s, "SPCR", 4) || rd32(s + 4) < 52)
        return -1;
    out->interface_type = s[36];
    out->space = s[40];
    out->bit_width = s[41];
    out->access_size = s[43];
    out->base = rd64(s + 44);
    return 0;
}

int ck_fadt_arm_boot_arch(const void *fadt, uint16_t *flags)
{
    const uint8_t *f = fadt;
    if (!sig_eq(f, "FACP", 4) || rd32(f + 4) < 131)
        return -1;
    *flags = (uint16_t)(f[129] | f[130] << 8);
    return 0;
}
