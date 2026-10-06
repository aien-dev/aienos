/* ck_acpi_scan.c -- host tool (never part of an image): runs the kernel's
 * platform xHCI discovery over firmware tables dumped under Linux and
 * prints the console lines the kernel will print on that machine.
 *
 *   ck_acpi_scan [--iort IORT-FILE] DSDT-FILE [SSDT-FILE ...]
 *
 * Tables are given in the order the kernel visits them: the DSDT named by
 * the FADT first, then every SSDT in XSDT order. The scan is the kernel's
 * own code (core/acpi_dev.c, core/acpi.c) and the lines come from the same
 * format strings (dev/xhci_acpi_fmt.h).
 *
 * Output, one line each:
 *   plain lines   the kernel prints them byte for byte (they depend only on
 *                 the tables);
 *   "? " lines    the kernel prints a line here whose values come from the
 *                 hardware (controller registers, the SMMU, DMA addresses);
 *                 shown with the part that is not known from tables;
 *   "# " lines    tool notes: IORT nodes and stream mappings, assumptions.
 * The per-controller lines assume no PCI xHCI (measured on the DGX Spark:
 * no PCI class 0x0c03 device) and that every controller is tried, i.e. no
 * keyboard is found on an earlier one (the kernel stops at the first
 * controller whose keyboard phase succeeds). Exit 0, or 2 on a usage or
 * read error. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "acpi.h"
#include "acpi_dev.h"
#include "xhci_acpi_fmt.h"

#define FILE_MAX (4u << 20)
#define TABLES_MAX 32
#define STE_N 4096u /* core/smmu_svc.c linear stream table */

struct table {
    const char *path;
    uint8_t *data;
    size_t len;
};

/* Same fields as struct ck_acpi_scan_info in include/ck.h (kernel only). */
struct ck_acpi_scan_info {
    unsigned tables, refused, devices;
    int first_refusal;
};

struct plat {
    struct ck_acpi_device d;
    char table[5];
};

static uint8_t *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "ck_acpi_scan: cannot open %s\n", path);
        return 0;
    }
    uint8_t *b = malloc(FILE_MAX);
    size_t n = b ? fread(b, 1, FILE_MAX, f) : 0;
    int more = b && fgetc(f) != EOF;
    fclose(f);
    if (!b || more) {
        fprintf(stderr, "ck_acpi_scan: %s missing or larger than %u bytes\n", path, FILE_MAX);
        free(b);
        return 0;
    }
    *len = n;
    return b;
}

static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) | (uint64_t)rd32(p + 4) << 32; }

/* Mirrors core/acpi_platform.c scan_block over every table. */
static int scan_all(struct table *t, int nt, const char *const *ids, unsigned nids, struct plat *out, unsigned max,
                    struct ck_acpi_scan_info *info)
{
    int n = 0;
    memset(info, 0, sizeof *info);
    for (int i = 0; i < nt; i++) {
        if (t[i].len < 36) {
            info->refused++;
            if (!info->first_refusal) info->first_refusal = CK_AML_E_LEN;
            continue;
        }
        info->tables++;
        uint32_t len = rd32(t[i].data + 4);
        size_t avail = len >= 36 && len <= t[i].len ? len : 36;
        struct ck_acpi_device d[CK_XHCI_PLAT_MAX];
        unsigned seen = 0;
        int rc = ck_aml_scan(t[i].data, avail, ids, nids, d, CK_XHCI_PLAT_MAX, &seen);
        if (rc < 0) {
            info->refused++;
            if (!info->first_refusal) info->first_refusal = rc;
            continue;
        }
        info->devices += seen;
        for (int k = 0; k < rc; k++) {
            if (k < (int)CK_XHCI_PLAT_MAX && n < (int)max && out) {
                out[n].d = d[k];
                memcpy(out[n].table, t[i].data, 4);
                out[n].table[4] = 0;
            }
            n++;
        }
    }
    return n;
}

static void iort_notes(const uint8_t *t)
{
    uint32_t len = rd32(t + 4), count = rd32(t + 36), off = rd32(t + 40);
    printf("# iort: length=%u nodes=%u\n", len, count);
    for (uint32_t i = 0; i < count && off >= 48 && off < len && len - off >= 16; i++) {
        const uint8_t *n = t + off;
        uint32_t nlen = (uint32_t)n[1] | (uint32_t)n[2] << 8;
        if (nlen < 16 || nlen > len - off) break;
        uint32_t mcount = rd32(n + 8), moff = rd32(n + 12);
        if (n[0] == 4 && nlen >= 24)
            printf("# iort: node@0x%x smmuv3 base=0x%llx\n", off, (unsigned long long)rd64(n + 16));
        else if (n[0] == 1 && nlen > 29) {
            char name[64];
            uint32_t end = mcount ? moff : nlen, k = 0;
            for (; k + 1 < sizeof name && 29 + k < end && n[29 + k]; k++) name[k] = (char)n[29 + k];
            name[k] = 0;
            printf("# iort: node@0x%x named %s maps=%u\n", off, name, mcount);
        } else
            printf("# iort: node@0x%x type=%u maps=%u\n", off, n[0], mcount);
        for (uint32_t m = 0; m < mcount && moff + (m + 1) * 20 <= nlen; m++) {
            const uint8_t *e = n + moff + m * 20;
            uint32_t ref = rd32(e + 12);
            unsigned long long tb = ref + 24 <= len && t[ref] == 4 ? (unsigned long long)rd64(t + ref + 16) : 0;
            printf("#   map in=0x%x count=%u out=0x%x ref=0x%x flags=0x%x smmu=0x%llx\n", rd32(e), rd32(e + 4),
                   rd32(e + 8), ref, rd32(e + 16), tb);
        }
        off += nlen;
    }
}

/* Why ck_iort_parse refuses: root-complex (type 2) mappings that target the
 * first SMMUv3 node, against CK_IORT_MAX_MAPS, and the largest output id
 * against the linear stream table (STE_N). */
static void parse_notes(const uint8_t *t)
{
    uint32_t len = rd32(t + 4), count = rd32(t + 36), off = rd32(t + 40), first = 0, rc_maps = 0, max_out = 0;
    for (int pass = 0; pass < 2; pass++) {
        uint32_t o = off;
        for (uint32_t i = 0; i < count && o >= 48 && o < len && len - o >= 16; i++) {
            const uint8_t *n = t + o;
            uint32_t nlen = (uint32_t)n[1] | (uint32_t)n[2] << 8;
            if (nlen < 16 || nlen > len - o) break;
            if (pass == 0 && n[0] == 4 && !first) first = o;
            uint32_t mcount = rd32(n + 8), moff = rd32(n + 12);
            if (pass == 1 && n[0] == 2)
                for (uint32_t m = 0; m < mcount && moff + (m + 1) * 20 <= nlen; m++) {
                    const uint8_t *e = n + moff + m * 20;
                    if (rd32(e + 12) != first) continue;
                    rc_maps++;
                    uint32_t top = rd32(e + 8) + rd32(e + 4);
                    if (top > max_out) max_out = top;
                }
            o += nlen;
        }
    }
    printf("# smmu: %u PCI root-complex mapping(s) to the first SMMUv3 (limit CK_IORT_MAX_MAPS=%u), highest stream id 0x%x (linear table holds 0x0-0x%x)\n",
           rc_maps, (unsigned)CK_IORT_MAX_MAPS, max_out, STE_N - 1u);
}

static int last_seg_same(const char *a, const char *b) { return ck_aml_last_seg_eq(a, b); }

int main(int argc, char **argv)
{
    const char *iort_path = 0;
    struct table t[TABLES_MAX];
    int nt = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--iort") && i + 1 < argc) {
            iort_path = argv[++i];
            continue;
        }
        if (argv[i][0] == '-' || nt == TABLES_MAX) {
            fprintf(stderr, "usage: ck_acpi_scan [--iort IORT-FILE] DSDT-FILE [SSDT-FILE ...]\n");
            return 2;
        }
        t[nt].path = argv[i];
        if (!(t[nt].data = read_file(argv[i], &t[nt].len))) return 2;
        nt++;
    }
    if (!nt) {
        fprintf(stderr, "usage: ck_acpi_scan [--iort IORT-FILE] DSDT-FILE [SSDT-FILE ...]\n");
        return 2;
    }
    uint8_t *iort = 0;
    size_t iort_len = 0;
    if (iort_path && !(iort = read_file(iort_path, &iort_len))) return 2;
    if (iort && (iort_len < 48 || rd32(iort + 4) > iort_len)) {
        fprintf(stderr, "ck_acpi_scan: %s is shorter than its header length\n", iort_path);
        return 2;
    }

    /* ---- discovery (dev/xhci_fence.c acpi_discover) ---- */
    static const char *const ids[] = CK_XHCI_ACPI_IDS;
    static const char *const ctl[] = { CK_ACPI_CONTROL_ID };
    struct ck_acpi_scan_info info;
    struct plat c, p[CK_XHCI_PLAT_MAX];
    int nc = scan_all(t, nt, ctl, 1, &c, 1, &info);
    printf(CK_ACPI_SCAN_FMT, info.tables, info.refused, info.first_refusal, info.devices);
    if (nc > 0)
        printf(CK_ACPI_CONTROL_FMT, c.d.hid, c.d.path, (unsigned long long)c.d.mmio_base, (unsigned long long)c.d.mmio_len);
    else
        printf(CK_ACPI_CONTROL_NONE);
    int n = scan_all(t, nt, ids, CK_XHCI_ACPI_NIDS, p, CK_XHCI_PLAT_MAX, &info);
    if (n > (int)CK_XHCI_PLAT_MAX) n = (int)CK_XHCI_PLAT_MAX;
    for (int i = 0; i < n; i++)
        printf(CK_XHCI_ACPI_FMT, p[i].d.path, p[i].d.hid[0] ? p[i].d.hid : "-", p[i].d.cid[0] ? p[i].d.cid : "-",
               p[i].table, (unsigned long long)p[i].d.mmio_base, (unsigned long long)p[i].d.mmio_len);
    printf(CK_XHCI_ACPI_COUNT_FMT, n);

    /* ---- IORT (core/acpi.c, core/smmu_svc.c) ---- */
    struct ck_iort_smmu first;
    int prc = 0;
    if (iort) {
        iort_notes(iort);
        prc = ck_iort_parse(iort, &first);
        if (prc == 1)
            printf("# smmu: the kernel drives the first SMMUv3 node: node@0x%x base=0x%llx (pci maps=%u)\n",
                   first.node_off, (unsigned long long)first.base, first.nmaps);
        else
            printf("# smmu: ck_iort_parse=%d (%s)\n", prc, prc == 0 ? "no SMMUv3 node" : "malformed");
        parse_notes(iort);
    } else
        printf("# smmu: no IORT given; dma_gate lines below assume none (NoSmmu)\n");

    /* ---- fence (dev/xhci_fence.c ck_xhci_fence, plat_fence_one) ---- */
    printf("keyboard: no PCI xHCI controller; trying %d ACPI platform controller(s)\n", n);
    if (n == 0) printf("keyboard: unavailable (no xHCI controller)\n");
    int fenced = 0, smmu_said = 0;
    for (int i = 0; i < n; i++) {
        const char *nm = p[i].d.path;
        printf(CK_XHCI_PLAT_TRY_FMT, nm, (unsigned long long)p[i].d.mmio_base, (unsigned long long)p[i].d.mmio_len);
        int amb = 0;
        for (int j = 0; j < n; j++)
            if (j != i && last_seg_same(p[j].d.path, nm)) amb = 1;
        if (amb) {
            printf(CK_XHCI_PLAT_SKIP_FMT, nm, "name not unique in DSDT/SSDT");
            continue;
        }
        if (!p[i].d.mmio_base || p[i].d.mmio_len < 0x1000u || (p[i].d.mmio_base & 0xfffu)) {
            printf(CK_XHCI_PLAT_SKIP_FMT, nm, "no usable _CRS memory range");
            continue;
        }
        printf("? xhci: %s caplength=<hardware> hciversion=<hardware> (platform)\n", nm);
        printf("? xhci: halted before gate usbcmd=<hardware> usbsts=<hardware> halted=<yes, or NO (TIMEOUT) and the controller is left>\n");
        const char *deny = 0;
        if (!iort || prc == 0)
            deny = "NoSmmu";
        else if (prc < 0) {
            if (!smmu_said++) /* bring_up caches its state: once per boot, by the first DMA grant request (may be an earlier device) */
                printf("? smmu: IORT malformed, SMMU unusable (fail closed) [once per boot, at the first DMA grant request]\n");
            deny = "SmmuNotReady";
        }
        if (deny) {
            printf(CK_XHCI_PLAT_DENY_FMT, nm, deny);
            if (iort) {
                struct ck_iort_named w;
                int wrc = ck_iort_named(iort, nm, &w);
                if (wrc == 1 && w.target_off)
                    printf("# %s: IORT named component %s stream 0x%x on the SMMUv3 at 0x%llx%s\n", nm, w.name,
                           w.stream_id, (unsigned long long)w.target_base,
                           prc != 1 ? " (the first SMMUv3 node; granted only once the kernel can bring it up)" : "");
                else
                    printf("# %s: no IORT stream (ck_iort_named=%d)\n", nm, wrc);
            }
            continue;
        }
        printf("# assumes the SMMUv3 at 0x%llx comes up (else a smmu: bring-up line and SmmuNotReady)\n",
               (unsigned long long)first.base);
        struct ck_iort_named nc2;
        int nrc = ck_iort_named(iort, nm, &nc2);
        if (nrc != 1 || !nc2.target_off) {
            printf(CK_XHCI_PLAT_DENY_FMT, nm, nrc == -2 ? "Ambiguous" : "NoStream");
            continue;
        }
        if (nc2.target_off != first.node_off) {
            printf(CK_XHCI_PLAT_OTHER_FMT, nm, (unsigned long long)nc2.target_base, nc2.stream_id);
            continue;
        }
        if (nc2.stream_id >= STE_N) {
            printf(CK_XHCI_PLAT_DENY_FMT, nm, "NoStream");
            continue;
        }
        printf(CK_XHCI_PLAT_GRANT_FMT, nm, (unsigned long long)first.base, nc2.stream_id);
        printf("? smmu_dma_window: xhci %s only, translation active iova=<allocation> len=<allocation>\n", nm);
        printf("? keyboard phase on %s, then release: halt, reset, stream 0x%x back to abort\n", nm, nc2.stream_id);
        fenced++;
    }
    if (n > 0) printf("keyboard: unavailable (no keyboard on any platform xHCI)\n");
    printf("# %d controller(s) would reach the keyboard phase\n", fenced);
    return 0;
}
