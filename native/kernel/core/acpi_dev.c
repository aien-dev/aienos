/* acpi_dev.c -- bounded static scan of DSDT/SSDT Device objects (see
 * acpi_dev.h). Freestanding; host tested in tests/test_acpi_dev.c. */
#include "acpi_dev.h"

/* TEST-ONLY code mutants (host test tests/test_acpi_dev.c must FAIL against
 * each; Makefile target acpi-dev-mutant): 1 = signature check removed,
 * 2 = checksum check removed, 3 = length-versus-buffer check removed. Never
 * in a kernel image or a hardware staging build. */
#ifdef CK_AML_MUTANT
#if !__STDC_HOSTED__
#error "CK_AML_MUTANT is a host test mutant only"
#endif
#ifdef CK_HARDWARE_STAGING
#error "CK_AML_MUTANT cannot be combined with CK_HARDWARE_STAGING"
#endif
#else
#define CK_AML_MUTANT 0
#endif

#define AML_HDR 36u
#define OP_NAME 0x08u
#define OP_ZERO 0x00u
#define OP_ONE 0x01u
#define OP_BYTE 0x0au
#define OP_WORD 0x0bu
#define OP_DWORD 0x0cu
#define OP_STRING 0x0du
#define OP_QWORD 0x0eu
#define OP_BUFFER 0x11u
#define OP_METHOD 0x14u
#define OP_EXT 0x5bu
#define OP_EXT_DEVICE 0x82u
#define PFX_ROOT 0x5cu   /* '\\' */
#define PFX_PARENT 0x5eu /* '^' */
#define PFX_DUAL 0x2eu
#define PFX_MULTI 0x2fu

static uint32_t rd16(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8; }
static uint32_t rd32(const uint8_t *p) { return rd16(p) | rd16(p + 2) << 16; }
static uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) | (uint64_t)rd32(p + 4) << 32; }

static int str_eq(const char *a, const char *b)
{
    while (*a && *a == *b) a++, b++;
    return *a == *b;
}

int ck_aml_table_ok(const void *table, size_t avail)
{
    const uint8_t *t = table;
    if (!t || avail < AML_HDR) return CK_AML_E_LEN;
    int dsdt = t[0] == 'D' && t[1] == 'S' && t[2] == 'D' && t[3] == 'T';
    int ssdt = t[0] == 'S' && t[1] == 'S' && t[2] == 'D' && t[3] == 'T';
    if (!dsdt && !ssdt && CK_AML_MUTANT != 1) return CK_AML_E_SIG;
    uint32_t len = rd32(t + 4);
    if (len < AML_HDR) return CK_AML_E_LEN;
    if (len > avail && CK_AML_MUTANT != 3) return CK_AML_E_LEN;
    if (CK_AML_MUTANT == 3 && len > avail) len = (uint32_t)avail; /* mutant: trusts a truncated table */
    uint8_t sum = 0;
    for (uint32_t i = 0; i < len; i++) sum = (uint8_t)(sum + t[i]);
    return sum && CK_AML_MUTANT != 2 ? CK_AML_E_SUM : CK_AML_OK;
}

/* PkgLength at p (ACPI 6.5 20.2.4): *value is the package length (it counts
 * its own encoding bytes), *nbytes the encoding size. -1 if past end. */
static int pkg_length(const uint8_t *p, const uint8_t *end, uint32_t *value, uint32_t *nbytes)
{
    if (p >= end) return -1;
    uint32_t follow = p[0] >> 6;
    if ((uint32_t)(end - p) < follow + 1u) return -1;
    if (follow == 0) {
        *value = p[0] & 0x3fu;
    } else {
        if (p[0] & 0x30u) return -1; /* bits 5:4 must be zero in the multi-byte form */
        uint32_t v = p[0] & 0x0fu;
        for (uint32_t i = 0; i < follow; i++) v |= (uint32_t)p[1 + i] << (4u + 8u * i);
        *value = v;
    }
    *nbytes = follow + 1u;
    return 0;
}

static int seg_char(uint8_t c, int first)
{
    if (c == '_' || (c >= 'A' && c <= 'Z')) return 1;
    return !first && c >= '0' && c <= '9';
}
static int name_seg_ok(const uint8_t *s)
{
    return seg_char(s[0], 1) && seg_char(s[1], 0) && seg_char(s[2], 0) && seg_char(s[3], 0);
}

/* NameString at p into out ("\\", "^" prefixes kept, segments joined by
 * '.'). Returns the encoded size, or 0 if malformed / past end / too long. */
static uint32_t name_string(const uint8_t *p, const uint8_t *end, char *out, uint32_t cap)
{
    const uint8_t *q = p;
    uint32_t o = 0;
    if (q < end && *q == PFX_ROOT) {
        if (o + 1 >= cap) return 0;
        out[o++] = '\\';
        q++;
    } else {
        while (q < end && *q == PFX_PARENT) {
            if (o + 1 >= cap) return 0;
            out[o++] = '^';
            q++;
        }
    }
    if (q >= end) return 0;
    uint32_t segs;
    if (*q == PFX_DUAL) {
        segs = 2;
        q++;
    } else if (*q == PFX_MULTI) {
        if (end - q < 2) return 0;
        segs = q[1];
        q += 2;
        if (segs == 0) return 0;
    } else if (*q == 0x00) {
        segs = 0; /* NullName */
        q++;
    } else {
        segs = 1;
    }
    for (uint32_t s = 0; s < segs; s++) {
        if (end - q < 4 || !name_seg_ok(q)) return 0;
        if (o + (s ? 5u : 4u) >= cap) return 0;
        if (s) out[o++] = '.';
        for (int i = 0; i < 4; i++) out[o++] = (char)q[i];
        q += 4;
    }
    out[o] = 0;
    return (uint32_t)(q - p);
}

void ck_aml_eisaid(uint32_t v, char out[8])
{
    /* Stored little-endian; the id is the big-endian reading of the DWORD. */
    uint32_t b = ((v & 0xffu) << 24) | ((v & 0xff00u) << 8) | ((v >> 8) & 0xff00u) | (v >> 24);
    static const char hex[] = "0123456789ABCDEF";
    out[0] = (char)('@' + ((b >> 26) & 0x1fu));
    out[1] = (char)('@' + ((b >> 21) & 0x1fu));
    out[2] = (char)('@' + ((b >> 16) & 0x1fu));
    out[3] = hex[(b >> 12) & 0xfu];
    out[4] = hex[(b >> 8) & 0xfu];
    out[5] = hex[(b >> 4) & 0xfu];
    out[6] = hex[b & 0xfu];
    out[7] = 0;
}

/* The value of Name(XXXX, ...) for _HID / _CID: a String or an EisaId
 * DWORD. 0 ok, -1 other forms (packages, integers other than DWORD). */
static int id_value(const uint8_t *p, const uint8_t *end, char out[CK_AML_ID_MAX])
{
    if (p >= end) return -1;
    if (p[0] == OP_STRING) {
        uint32_t i = 0;
        for (const uint8_t *s = p + 1; s < end; s++, i++) {
            if (*s == 0) {
                out[i] = 0;
                return i ? 0 : -1;
            }
            if (i + 1 >= CK_AML_ID_MAX || *s < 0x20 || *s > 0x7e) return -1;
            out[i] = (char)*s;
        }
        return -1;
    }
    if (p[0] == OP_DWORD && end - p >= 5) {
        ck_aml_eisaid(rd32(p + 1), out);
        return 0;
    }
    return -1;
}

/* First memory range of a resource template [p, end) (ACPI 6.5 6.4):
 * Memory32Fixed, Memory32, DWord / QWord address space of type memory.
 * 0 found, -1 none or malformed before one was found. */
static int first_memory(const uint8_t *p, const uint8_t *end, uint64_t *base, uint64_t *len)
{
    while (p < end) {
        uint8_t tag = p[0];
        if (!(tag & 0x80u)) { /* small item */
            uint32_t n = tag & 0x7u;
            if ((tag >> 3) == 0x0fu) return -1; /* End Tag: no memory range */
            if ((uint32_t)(end - p) < 1u + n) return -1;
            p += 1u + n;
            continue;
        }
        if (end - p < 3) return -1;
        uint32_t n = rd16(p + 1);
        if ((uint32_t)(end - p) < 3u + n) return -1;
        const uint8_t *d = p + 3;
        switch (tag) {
        case 0x86: /* Memory32Fixed: info, base, length */
            if (n >= 9) {
                *base = rd32(d + 1);
                *len = rd32(d + 5);
                if (*len) return 0;
            }
            break;
        case 0x85: /* Memory32: info, min, max, align, length */
            if (n >= 17 && rd32(d + 1) == rd32(d + 5)) {
                *base = rd32(d + 1);
                *len = rd32(d + 13);
                if (*len) return 0;
            }
            break;
        case 0x87: /* DWord address space: type, gflags, tflags, gran, min, max, tra, len */
            if (n >= 23 && d[0] == 0) {
                *base = rd32(d + 7);
                *len = rd32(d + 19);
                if (*len) return 0;
            }
            break;
        case 0x8a: /* QWord address space */
            if (n >= 43 && d[0] == 0) {
                *base = rd64(d + 11);
                *len = rd64(d + 35);
                if (*len) return 0;
            }
            break;
        default:
            break;
        }
        p += 3u + n;
    }
    return -1;
}

/* Buffer object at p: [data, data_end). 0 ok, -1 malformed. */
static int buffer_at(const uint8_t *p, const uint8_t *end, const uint8_t **data, const uint8_t **data_end)
{
    if (p >= end || p[0] != OP_BUFFER) return -1;
    uint32_t plen, pn;
    if (pkg_length(p + 1, end, &plen, &pn)) return -1;
    const uint8_t *pend = p + 1 + plen;
    if (plen < pn || pend > end) return -1;
    const uint8_t *q = p + 1 + pn;
    uint64_t size;
    if (q >= pend) return -1;
    switch (q[0]) {
    case OP_ZERO: size = 0; q += 1; break;
    case OP_ONE: size = 1; q += 1; break;
    case OP_BYTE: if (pend - q < 2) return -1; size = q[1]; q += 2; break;
    case OP_WORD: if (pend - q < 3) return -1; size = rd16(q + 1); q += 3; break;
    case OP_DWORD: if (pend - q < 5) return -1; size = rd32(q + 1); q += 5; break;
    default: return -1;
    }
    if (size > (uint64_t)(pend - q)) size = (uint64_t)(pend - q); /* initializer shorter than the size: rest is zero */
    *data = q;
    *data_end = q + size;
    return 0;
}

/* Valid DeviceOp at p: *body / *dend span the device's term list, name in
 * path. 0 ok, -1 not a device. */
static int device_at(const uint8_t *p, const uint8_t *end, const uint8_t **body, const uint8_t **dend, char *path)
{
    if (end - p < 3 || p[0] != OP_EXT || p[1] != OP_EXT_DEVICE) return -1;
    uint32_t plen, pn;
    if (pkg_length(p + 2, end, &plen, &pn)) return -1;
    const uint8_t *pend = p + 2 + plen;
    if (plen < pn || pend > end) return -1;
    uint32_t nn = name_string(p + 2 + pn, pend, path, CK_AML_PATH_MAX);
    if (!nn) return -1;
    *body = p + 2 + pn + nn;
    *dend = pend;
    return 0;
}

static int seg_is(const uint8_t *p, const uint8_t *end, const char *s)
{
    return end - p >= 4 && p[0] == (uint8_t)s[0] && p[1] == (uint8_t)s[1] && p[2] == (uint8_t)s[2] && p[3] == (uint8_t)s[3];
}

/* Reads _HID, _CID and _CRS of the device body [b, e), stopping at the first
 * nested device (its objects belong to that device). */
static void device_fields(const uint8_t *b, const uint8_t *e, struct ck_acpi_device *d)
{
    for (const uint8_t *p = b; p < e; p++) {
        const uint8_t *nb, *ne;
        char tmp[CK_AML_PATH_MAX];
        if (p[0] == OP_EXT && device_at(p, e, &nb, &ne, tmp) == 0) break;
        if (p[0] == OP_NAME && seg_is(p + 1, e, "_HID") && !d->hid[0]) {
            if (id_value(p + 5, e, d->hid)) d->hid[0] = 0;
        } else if (p[0] == OP_NAME && seg_is(p + 1, e, "_CID") && !d->cid[0]) {
            if (id_value(p + 5, e, d->cid)) d->cid[0] = 0;
        } else if (p[0] == OP_NAME && seg_is(p + 1, e, "_CRS") && !d->mmio_len) {
            const uint8_t *db, *de;
            if (buffer_at(p + 5, e, &db, &de) == 0 && first_memory(db, de, &d->mmio_base, &d->mmio_len))
                d->mmio_base = d->mmio_len = 0;
        } else if (p[0] == OP_METHOD && !d->mmio_len) {
            uint32_t plen, pn;
            if (pkg_length(p + 1, e, &plen, &pn) || plen < pn) continue;
            const uint8_t *mend = p + 1 + plen;
            const uint8_t *mname = p + 1 + pn;
            if (mend > e || !seg_is(mname, mend, "_CRS")) continue;
            /* first Buffer inside the method body (after name and flags) */
            for (const uint8_t *q = mname + 5; q < mend; q++) {
                const uint8_t *db, *de;
                if (q[0] != OP_BUFFER || buffer_at(q, mend, &db, &de)) continue;
                if (first_memory(db, de, &d->mmio_base, &d->mmio_len)) d->mmio_base = d->mmio_len = 0;
                break;
            }
        }
    }
}

static int id_match(const struct ck_acpi_device *d, const char *const *ids, unsigned nids)
{
    if (!nids) return 1;
    for (unsigned i = 0; i < nids; i++)
        if ((d->hid[0] && str_eq(d->hid, ids[i])) || (d->cid[0] && str_eq(d->cid, ids[i]))) return 1;
    return 0;
}

int ck_aml_scan(const void *table, size_t avail, const char *const *ids, unsigned nids,
                struct ck_acpi_device *out, unsigned max, unsigned *seen)
{
    int rc = ck_aml_table_ok(table, avail);
    if (seen) *seen = 0;
    if (rc) return rc;
    const uint8_t *t = table;
    const uint8_t *end = t + rd32(t + 4);
    unsigned n = 0, parsed = 0;
    for (const uint8_t *p = t + AML_HDR; p + 3 <= end; p++) {
        const uint8_t *b, *e;
        struct ck_acpi_device d;
        for (unsigned i = 0; i < sizeof d; i++) ((uint8_t *)&d)[i] = 0;
        if (p[0] != OP_EXT || device_at(p, end, &b, &e, d.path)) continue;
        parsed++;
        d.offset = (uint32_t)(p - t);
        device_fields(b, e, &d);
        if (!id_match(&d, ids, nids)) continue;
        if (n < max && out) out[n] = d;
        n++;
    }
    if (seen) *seen = parsed;
    return (int)n;
}

/* Copies one segment (up to 4 chars, padded with '_'); NULL if longer. */
static const char *seg4(const char *p, char seg[4])
{
    int i = 0;
    for (; *p && *p != '.' && i < 4; i++, p++) seg[i] = *p;
    if (*p && *p != '.') return 0;
    for (; i < 4; i++) seg[i] = '_';
    return p;
}

int ck_aml_path_eq(const char *a, const char *b)
{
    for (;;) {
        while (*a == '\\' || *a == '.') a++;
        while (*b == '\\' || *b == '.') b++;
        if (!*a || !*b) return !*a && !*b;
        char sa[4], sb[4];
        a = seg4(a, sa);
        b = seg4(b, sb);
        if (!a || !b) return 0;
        for (int i = 0; i < 4; i++)
            if (sa[i] != sb[i]) return 0;
    }
}

int ck_aml_last_seg_eq(const char *a, const char *b)
{
    const char *la = a, *lb = b;
    for (const char *p = a; *p; p++)
        if (*p == '.' || *p == '\\' || *p == '^') la = p + 1;
    for (const char *p = b; *p; p++)
        if (*p == '.' || *p == '\\' || *p == '^') lb = p + 1;
    return *la && *lb && ck_aml_path_eq(la, lb);
}
