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


static void topo_add(struct ck_cpu_topology *t, uint8_t cls)
{
    for (unsigned i = 0; i < t->distinct_classes; i++)
        if (t->class_id[i] == cls) {
            t->class_count[i]++;
            return;
        }
    if (t->distinct_classes >= CK_MAX_CLASSES) {
        t->unknown_class++;
        return;
    }
    /* Insert keeping the classes sorted. */
    unsigned at = t->distinct_classes;
    while (at > 0 && t->class_id[at - 1] > cls) {
        t->class_id[at] = t->class_id[at - 1];
        t->class_count[at] = t->class_count[at - 1];
        at--;
    }
    t->class_id[at] = cls;
    t->class_count[at] = 1;
    t->distinct_classes++;
}

int ck_madt_cpu_topology(const void *madt, struct ck_cpu_topology *out)
{
    const uint8_t *m = madt;
    struct ck_cpu_topology t = { 0 };
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
            if (elen < 16)
                return -1;
            if (rd32(e + 12) & (1u | 8u)) {
                t.cores++;
                if (!t.has_first_mpidr && elen >= 76) {
                    t.has_first_mpidr = 1;
                    t.first_mpidr = rd64(e + 68);
                }
                if (elen >= 77)
                    topo_add(&t, e[76]);
                else
                    t.unknown_class++;
            }
        }
        at += elen;
    }
    *out = t;
    return 0;
}

int ck_place_task(const struct ck_cpu_topology *t, uint32_t task_index, uint8_t *class_id,
                  uint32_t *core)
{
    uint32_t capacity = 0;
    for (unsigned i = 0; i < t->distinct_classes; i++)
        capacity += t->class_count[i];
    if (capacity == 0)
        return -1;
    uint32_t idx = task_index % capacity;
    for (unsigned i = 0; i < t->distinct_classes; i++) {
        if (idx < t->class_count[i]) {
            *class_id = t->class_id[i];
            *core = idx;
            return 0;
        }
        idx -= t->class_count[i];
    }
    return -1;
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

static uint64_t span_end(uint64_t a, uint64_t len)
{
    /* Saturate below the last 4 KiB page so page rounding cannot wrap. */
    const uint64_t top = ~(uint64_t)0xfff;
    return (a >= top || len > top - a) ? top : a + len;
}

int ck_acpi_spans(uint64_t rsdp, void (*fn)(uint64_t lo, uint64_t hi, void *ctx), void *ctx)
{
    int x = 0;
    uint64_t root = ck_acpi_root(rsdp, &x);
    if (!root)
        return -1;
    const uint8_t *r = ptr(rsdp);
    /* ck_acpi_root has checked the RSDP length (36..4096) for revision 2+. */
    uint32_t rlen = r[15] >= 2 ? rd32(r + 20) : 20;
    fn(rsdp, span_end(rsdp, rlen), ctx);
    int n = 1;
    uint32_t len = rd32(ptr(root) + 4);
    fn(root, span_end(root, len < CK_ACPI_SDT_HEADER ? CK_ACPI_SDT_HEADER : len), ctx);
    n++;
    const uint8_t *ents;
    uint32_t count, width;
    if (root_entries(rsdp, &ents, &count, &width))
        return n;
    for (uint32_t i = 0; i < count; i++) {
        uint64_t a = width == 8 ? rd64(ents + i * 8) : rd32(ents + i * 4);
        if (!a)
            continue;
        uint32_t tl = rd32(ptr(a) + 4);
        fn(a, span_end(a, tl < CK_ACPI_SDT_HEADER ? CK_ACPI_SDT_HEADER : tl), ctx);
        n++;
    }
    return n;
}

/* IORT walk: calls back for every node after checking its header, length
 * and ID-mapping array bounds. -1 on any malformed node. */
#define IORT_NODE_HDR 16u
#define IORT_NODE_ROOT_COMPLEX 2u
#define IORT_NODE_SMMUV3 4u
#define IORT_MAP_BYTES 20u
#define IORT_TABLE_HDR 48u /* SDT header + node count, node array offset, reserved */

static int iort_nodes(const uint8_t *t, uint32_t len, uint32_t *count, uint32_t *first)
{
    if (!sig_eq(t, "IORT", 4) || len < IORT_TABLE_HDR)
        return -1;
    *count = rd32(t + 36);
    *first = rd32(t + 40);
    return 0;
}

int ck_iort_parse(const void *iort, struct ck_iort_smmu *out)
{
    const uint8_t *t = iort;
    struct ck_iort_smmu s = { 0 };
    uint32_t len = rd32(t + 4), count, at;
    if (iort_nodes(t, len, &count, &at))
        return -1;
    int found = 0;
    for (int pass = 0; pass < 2; pass++) {
        uint32_t off = at;
        for (uint32_t i = 0; i < count; i++) {
            if (off < IORT_TABLE_HDR || off > len || len - off < IORT_NODE_HDR)
                return -1;
            const uint8_t *n = t + off;
            uint8_t type = n[0];
            uint32_t nlen = (uint32_t)n[1] | (uint32_t)n[2] << 8;
            if (nlen < IORT_NODE_HDR || nlen > len - off)
                return -1;
            uint32_t mcount = rd32(n + 8), moff = rd32(n + 12);
            if (mcount) {
                if (mcount > nlen / IORT_MAP_BYTES || moff < IORT_NODE_HDR || moff > nlen ||
                    (uint64_t)mcount * IORT_MAP_BYTES > (uint64_t)(nlen - moff))
                    return -1;
            }
            if (pass == 0 && type == IORT_NODE_SMMUV3 && !found) {
                if (nlen < 24)
                    return -1;
                s.base = rd64(n + 16);
                if (!s.base)
                    return -1;
                s.node_off = off;
                found = 1;
            }
            if (pass == 1 && type == IORT_NODE_ROOT_COMPLEX) {
                for (uint32_t m = 0; m < mcount; m++) {
                    const uint8_t *e = n + moff + m * IORT_MAP_BYTES;
                    if (rd32(e + 12) != s.node_off)
                        continue;
                    if (s.nmaps >= CK_IORT_MAX_MAPS)
                        return -1;
                    s.map[s.nmaps].input_base = rd32(e);
                    s.map[s.nmaps].id_count = rd32(e + 4);
                    s.map[s.nmaps].output_base = rd32(e + 8);
                    s.nmaps++;
                }
            }
            off += nlen;
        }
        if (pass == 0 && !found)
            return 0;
    }
    *out = s;
    return 1;
}

int ck_iort_stream_id(const struct ck_iort_smmu *s, uint32_t rid, uint32_t *sid)
{
    for (uint32_t i = 0; i < s->nmaps; i++) {
        const struct ck_iort_map *m = &s->map[i];
        if (rid < m->input_base)
            continue;
        uint32_t rel = rid - m->input_base;
        if (rel > m->id_count || m->output_base + rel < m->output_base)
            continue;
        *sid = m->output_base + rel;
        return 0;
    }
    return -1;
}
