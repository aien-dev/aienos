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


int ck_madt_mpidrs(const void *madt, uint64_t *out, unsigned max, unsigned *n)
{
    const uint8_t *m = madt;
    uint32_t len = rd32(m + 4);
    unsigned count = 0;
    *n = 0;
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
            if (rd32(e + 12) & (1u | 8u)) {
                if (count < max)
                    out[count] = rd64(e + 68) & CK_MPIDR_AFF_MASK;
                count++;
            }
        }
        at += elen;
    }
    *n = count;
    return count > max ? -2 : 0;
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

/* TEST-only IORT mutants (make iort-mutants): each must make test_smmu
 * FAIL. Host builds only; never part of an image. */
#if defined(CK_IORT_MUTANT_TRUNCATE) || defined(CK_IORT_MUTANT_SEGMENT_BLIND) || defined(CK_IORT_MUTANT_OVERLAP_OK) || \
    defined(CK_IORT_MUTANT_OTHER_BLIND) || defined(CK_IORT_MUTANT_RMR_BLIND) || \
    defined(CK_IORT_MUTANT_RMR_EXCLUSIVE) || defined(CK_IORT_MUTANT_ROUTE_FIRST)
#if !__STDC_HOSTED__
#error "CK_IORT_MUTANT_* are host test mutants only"
#endif
#ifdef CK_HARDWARE_STAGING
#error "CK_IORT_MUTANT_* cannot be combined with CK_HARDWARE_STAGING"
#endif
#endif

/* IORT walk: calls back for every node after checking its header, length
 * and ID-mapping array bounds. -1 on any malformed node. */
#define IORT_NODE_HDR 16u
#define IORT_NODE_ROOT_COMPLEX 2u
#define IORT_NODE_SMMUV3 4u
#define IORT_NODE_RMR 6u
#define IORT_RMR_HDR 28u        /* node header + flags, rmr_count, rmr_offset */
#define IORT_RMR_DESC_BYTES 20u /* base u64, length u64, reserved u32 */
#define IORT_MAP_BYTES 20u
#define IORT_TABLE_HDR 48u /* SDT header + node count, node array offset, reserved */
#define IORT_RC_SEGMENT 28u /* root complex node: pci_segment_number */

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
    /* Every SMMUv3 node seen in pass 0 goes to s.smmus (table order); the
     * first one is `base`/`node_off`, the ones root complexes map to
     * besides it are named by ck_iort_other_stream, and ck_iort_route
     * resolves a requester to any of them (cut B7a). */
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
            if (pass == 0 && type == IORT_NODE_SMMUV3) {
                if (nlen < 24)
                    return -1;
                uint64_t base = rd64(n + 16);
                if (!base)
                    return -1;
                if (s.nsmmus >= CK_IORT_MAX_SMMUS)
                    return -1;
                s.smmus[s.nsmmus].off = off;
                s.smmus[s.nsmmus].base = base;
                s.nsmmus++;
                if (!found) {
                    s.base = base;
                    s.node_off = off;
                    found = 1;
                }
            }
            if (pass == 1 && type == IORT_NODE_RMR) {
#ifndef CK_IORT_MUTANT_RMR_BLIND
                /* RMR node (ACPICA actbl2.h acpi_iort_rmr): flags @16,
                 * rmr_count @20, rmr_offset @24 (from the node start);
                 * acpi_iort_rmr_desc 20 bytes: base_address u64, length
                 * u64, reserved u32. One entry per ID mapping that targets
                 * an SMMUv3 node; its output range is the StreamID range
                 * (Linux iort.c iort_rmr_alloc_sids reads output_base and
                 * id_count the same way). Ranges must be page aligned and
                 * non-empty: the kernel maps them identity. */
                if (nlen < IORT_RMR_HDR)
                    return -1;
                uint32_t flags = rd32(n + 16), rcount = rd32(n + 20), roff = rd32(n + 24);
                if (!rcount || rcount > CK_IORT_MAX_RMR_RANGES || roff < IORT_RMR_HDR || roff > nlen ||
                    (uint64_t)rcount * IORT_RMR_DESC_BYTES > (uint64_t)(nlen - roff))
                    return -1;
                struct ck_iort_rmr r = { 0 };
                r.node_off = off;
                r.flags = flags;
                r.nranges = rcount;
                for (uint32_t d = 0; d < rcount; d++) {
                    const uint8_t *e = n + roff + d * IORT_RMR_DESC_BYTES;
                    uint64_t b = rd64(e), l = rd64(e + 8);
                    if (!l || (b & 0xfffu) || (l & 0xfffu) || b + l < b)
                        return -1;
                    r.range[d].base = b;
                    r.range[d].len = l;
                }
                for (uint32_t m = 0; m < mcount; m++) {
                    const uint8_t *e = n + moff + m * IORT_MAP_BYTES;
                    uint32_t ref = rd32(e + 12), k;
                    for (k = 0; k < s.nsmmus; k++)
                        if (s.smmus[k].off == ref)
                            break;
                    if (k == s.nsmmus)
                        continue; /* a mapping to a non-SMMU node is not a stream range */
                    if (s.nrmr >= CK_IORT_MAX_RMR)
                        return -1;
                    uint32_t ob = rd32(e + 8), cnt = rd32(e + 4);
                    if (ob + cnt < ob)
                        return -1;
                    r.smmu_index = k;
                    r.sid_lo = ob;
#ifndef CK_IORT_MUTANT_RMR_EXCLUSIVE
                    r.sid_hi = ob + cnt; /* id_count = number of IDs - 1: inclusive */
#else
                    r.sid_hi = cnt ? ob + cnt - 1u : ob; /* TEST mutant: id_count read as a count */
#endif
                    s.rmr[s.nrmr++] = r;
                }
#endif
            }
            if (pass == 1 && type == IORT_NODE_ROOT_COMPLEX) {
                /* Root complex node: PCI segment number at +28 (ACPICA
                 * actbl2.h acpi_iort_root_complex: memory_properties u64
                 * @16, ats_attribute u32 @24, pci_segment_number u32 @28). */
                if (nlen < IORT_RC_SEGMENT + 4)
                    return -1;
                uint32_t seg = rd32(n + IORT_RC_SEGMENT);
                for (uint32_t m = 0; m < mcount; m++) {
                    const uint8_t *e = n + moff + m * IORT_MAP_BYTES;
                    uint32_t ref = rd32(e + 12);
                    if (ref != s.node_off) {
#ifndef CK_IORT_MUTANT_OTHER_BLIND
                        /* A mapping to another SMMUv3 node: remembered so
                         * the requester is reported as behind that SMMU.
                         * A mapping to anything else (an ITS group) is not
                         * a stream at all. */
                        for (uint32_t k = 0; k < s.nsmmus; k++) {
                            if (s.smmus[k].off != ref)
                                continue;
                            if (s.nother >= CK_IORT_MAX_OTHER)
                                return -1;
                            struct ck_iort_other *o = &s.other[s.nother++];
                            o->map.segment = seg;
                            o->map.input_base = rd32(e);
                            o->map.id_count = rd32(e + 4);
                            o->map.output_base = rd32(e + 8);
                            o->smmu_base = s.smmus[k].base;
                            o->smmu_off = s.smmus[k].off;
                            break;
                        }
#else
                        (void)0; /* TEST mutant: other SMMUs forgotten */
#endif
                        continue;
                    }
                    if (s.nmaps >= CK_IORT_MAX_MAPS) {
#ifdef CK_IORT_MUTANT_TRUNCATE
                        continue; /* TEST mutant: drop the extra mappings silently */
#else
                        return -1;
#endif
                    }
                    struct ck_iort_map nm = { seg, rd32(e), rd32(e + 4), rd32(e + 8) };
#ifndef CK_IORT_MUTANT_OVERLAP_OK
                    for (uint32_t k = 0; k < s.nmaps; k++) {
                        const struct ck_iort_map *o = &s.map[k];
                        if (o->segment == seg &&
                            (uint64_t)nm.input_base <= (uint64_t)o->input_base + o->id_count &&
                            (uint64_t)o->input_base <= (uint64_t)nm.input_base + nm.id_count)
                            return -1;
                    }
#endif
                    s.map[s.nmaps++] = nm;
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

int ck_iort_stream_id(const struct ck_iort_smmu *s, uint32_t segment, uint32_t rid, uint32_t *sid)
{
    for (uint32_t i = 0; i < s->nmaps; i++) {
        const struct ck_iort_map *m = &s->map[i];
#ifndef CK_IORT_MUTANT_SEGMENT_BLIND
        if (m->segment != segment)
            continue;
#else
        (void)segment; /* TEST mutant: the pre-fix segment-blind lookup */
#endif
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

int ck_iort_other_stream(const struct ck_iort_smmu *s, uint32_t segment, uint32_t rid, uint32_t *sid,
                         uint64_t *smmu_base)
{
    for (uint32_t i = 0; i < s->nother; i++) {
        const struct ck_iort_map *m = &s->other[i].map;
        if (m->segment != segment || rid < m->input_base)
            continue;
        uint32_t rel = rid - m->input_base;
        if (rel > m->id_count || m->output_base + rel < m->output_base)
            continue;
        *sid = m->output_base + rel;
        *smmu_base = s->other[i].smmu_base;
        return 0;
    }
    return -1;
}

uint32_t ck_iort_rmr_for(const struct ck_iort_smmu *s, uint32_t smmu_off, uint32_t sid, struct ck_iort_route *out)
{
    out->nrmr = 0;
    for (uint32_t i = 0; i < s->nrmr; i++) {
        const struct ck_iort_rmr *r = &s->rmr[i];
        if (r->smmu_index >= s->nsmmus || s->smmus[r->smmu_index].off != smmu_off)
            continue;
        if (sid < r->sid_lo || sid > r->sid_hi)
            continue;
        if (out->nrmr < CK_IORT_MAX_RMR)
            out->rmr[out->nrmr++] = r;
    }
    return out->nrmr;
}

int ck_iort_route(const struct ck_iort_smmu *s, uint32_t segment, uint32_t rid, struct ck_iort_route *out)
{
    struct ck_iort_route r = { 0 };
    if (ck_iort_stream_id(s, segment, rid, &r.sid) == 0) {
        r.smmu_index = 0;
        r.smmu_base = s->base;
        r.smmu_off = s->node_off;
    } else {
        const struct ck_iort_other *hit = 0;
        for (uint32_t i = 0; i < s->nother && !hit; i++) {
            const struct ck_iort_map *m = &s->other[i].map;
            if (m->segment != segment || rid < m->input_base)
                continue;
            uint32_t rel = rid - m->input_base;
            if (rel > m->id_count || m->output_base + rel < m->output_base)
                continue;
            hit = &s->other[i];
            r.sid = m->output_base + rel;
        }
        if (!hit)
            return -1;
        uint32_t k;
        for (k = 0; k < s->nsmmus; k++)
            if (s->smmus[k].off == hit->smmu_off)
                break;
        if (k == s->nsmmus)
            return -1; /* not reachable after a successful parse */
#ifndef CK_IORT_MUTANT_ROUTE_FIRST
        r.smmu_index = k;
#else
        r.smmu_index = 0; /* TEST mutant: every requester routed to the first SMMU */
#endif
        r.smmu_base = s->smmus[r.smmu_index].base;
        r.smmu_off = s->smmus[r.smmu_index].off;
    }
    (void)ck_iort_rmr_for(s, r.smmu_off, r.sid, &r);
    *out = r;
    return 0;
}

/* ---- IORT named components (platform devices such as the DGX Spark USB
 * controllers, ACPI ids NVDA8000/NVDA8001) ---- */
#define IORT_NODE_NAMED 1u
#define IORT_NAMED_NAME_OFF 29u /* flags u32 @16, memory properties u64 @20, address size u8 @28, name @29 */
#define IORT_MAP_SINGLE 0x1u

/* Final segment of an ASCII object path, padded to 4 with '_'; -1 if a
 * segment is longer than 4 or the path is empty. */
static int last_seg4(const char *p, const char *end, char seg[4])
{
    const char *s = p;
    for (const char *q = p; q < end && *q; q++)
        if (*q == '.' || *q == '\\' || *q == '^') s = q + 1;
    int i = 0;
    for (; s < end && *s && i < 4; i++, s++) seg[i] = *s;
    if (i == 0 || (s < end && *s)) return -1;
    for (; i < 4; i++) seg[i] = '_';
    return 0;
}

int ck_iort_named(const void *iort, const char *name, struct ck_iort_named *out)
{
    const uint8_t *t = iort;
    uint32_t len = rd32(t + 4), count, at;
    if (!name || iort_nodes(t, len, &count, &at))
        return -1;
    char want[4];
    if (last_seg4(name, name + 64, want))
        return -1;
    int found = 0;
    struct ck_iort_named r = { 0 };
    uint32_t off = at;
    for (uint32_t i = 0; i < count; i++) {
        if (off < IORT_TABLE_HDR || off > len || len - off < IORT_NODE_HDR)
            return -1;
        const uint8_t *n = t + off;
        uint32_t nlen = (uint32_t)n[1] | (uint32_t)n[2] << 8;
        if (nlen < IORT_NODE_HDR || nlen > len - off)
            return -1;
        uint32_t mcount = rd32(n + 8), moff = rd32(n + 12);
        if (mcount && (mcount > nlen / IORT_MAP_BYTES || moff < IORT_NODE_HDR || moff > nlen ||
                       (uint64_t)mcount * IORT_MAP_BYTES > (uint64_t)(nlen - moff)))
            return -1;
        if (n[0] == IORT_NODE_NAMED) {
            if (nlen <= IORT_NAMED_NAME_OFF)
                return -1;
            const char *nm = (const char *)(n + IORT_NAMED_NAME_OFF);
            const char *nend = (const char *)(n + (mcount ? moff : nlen));
            if (nend <= nm)
                return -1;
            char seg[4];
            if (last_seg4(nm, nend, seg) == 0 && seg[0] == want[0] && seg[1] == want[1] && seg[2] == want[2] &&
                seg[3] == want[3]) {
                if (found)
                    return -2; /* two named components carry this name: refuse */
                found = 1;
                r.node_off = off;
                uint32_t k = 0;
                for (; k < sizeof r.name - 1 && nm + k < nend && nm[k]; k++)
                    r.name[k] = nm[k];
                r.name[k] = 0;
                r.nmaps = mcount;
                /* The stream: a single mapping, else a mapping of exactly one id. */
                r.target_off = 0;
                for (uint32_t m = 0; m < mcount; m++) {
                    const uint8_t *e = n + moff + m * IORT_MAP_BYTES;
                    uint32_t ref = rd32(e + 12);
                    if (ref < IORT_TABLE_HDR || ref > len || len - ref < IORT_NODE_HDR)
                        return -1;
                    if (t[ref] != IORT_NODE_SMMUV3)
                        continue;
                    if ((rd32(e + 16) & IORT_MAP_SINGLE) || rd32(e + 4) == 0) {
                        r.stream_id = rd32(e + 8);
                        r.target_off = ref;
                        uint32_t tlen = (uint32_t)t[ref + 1] | (uint32_t)t[ref + 2] << 8;
                        r.target_base = tlen >= 24 && tlen <= len - ref ? rd64(t + ref + 16) : 0;
                        break;
                    }
                }
            }
        }
        off += nlen;
    }
    if (!found)
        return 0;
    *out = r;
    return 1;
}
