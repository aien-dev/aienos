/* test_acpi_dev.c -- core/acpi_dev.c (static DSDT/SSDT device scan) and the
 * IORT named-component lookup in core/acpi.c, on synthetic tables built
 * here in the encodings the real firmware uses:
 *   - DGX Spark form (measured from the Spark DSDT under Ubuntu, 2026-10-05):
 *     Scope(\_SB) { Device(USB0) { Name(_HID, "NVDA8000") Name(_CID,
 *     "PNP0D15") ... Method(_CRS) { Name(RBUF, Buffer() {Memory32Fixed ...})
 *     Return(RBUF) } } }
 *   - QEMU virt form: Device(COM0) { Name(_HID, "ARMH0011") Name(_CRS,
 *     ResourceTemplate() { Memory32Fixed(..., 0x09000000, 0x1000) ... }) }
 *   - EisaId _HID/_CID, QWord memory, nested devices.
 * Negative: bad signature, bad checksum, truncated table, short header,
 * device package past the end, descriptor past the buffer, bad names. The
 * Makefile target acpi-dev-mutant builds this test against code mutants
 * (signature / checksum / length check removed) and requires it to FAIL. */
#include <stdint.h>
#include <string.h>

#include "acpi.h"
#include "acpi_dev.h"
#include "ck_test.h"

static uint8_t buf[8192];
static uint32_t at;

static void b1(uint8_t v) { buf[at++] = v; }
static void b4(uint32_t v) { for (int i = 0; i < 4; i++) b1((uint8_t)(v >> (8 * i))); }
static void b8(uint64_t v) { for (int i = 0; i < 8; i++) b1((uint8_t)(v >> (8 * i))); }
static void bs(const char *s) { while (*s) b1((uint8_t)*s++); }

/* Package length covering `content` bytes after the encoding. Writes the
 * encoding at buf[pos] (space reserved by pk_open). */
static uint32_t pk_open(void) { uint32_t p = at; at += 2; return p; } /* always 2-byte form */
static void pk_close(uint32_t p)
{
    uint32_t total = at - p; /* includes the 2 encoding bytes */
    buf[p] = (uint8_t)(0x40u | (total & 0x0fu));
    buf[p + 1] = (uint8_t)(total >> 4);
}

static uint32_t hdr(const char *sig)
{
    uint32_t start = at;
    bs(sig);
    b4(0); /* length, fixed by finish */
    b1(2); b1(0); bs("AIENOS"); bs("CKTEST01"); b4(1); bs("CKT "); b4(1);
    return start;
}
static uint32_t finish(uint32_t start)
{
    uint32_t len = at - start;
    buf[start + 4] = (uint8_t)len;
    buf[start + 5] = (uint8_t)(len >> 8);
    buf[start + 6] = (uint8_t)(len >> 16);
    buf[start + 7] = (uint8_t)(len >> 24);
    buf[start + 9] = 0;
    uint8_t s = 0;
    for (uint32_t i = 0; i < len; i++) s = (uint8_t)(s + buf[start + i]);
    buf[start + 9] = (uint8_t)(0u - s);
    return len;
}

static void name_str(const char *seg, const char *val) { b1(0x08); bs(seg); b1(0x0d); bs(val); b1(0); }
static void name_dword(const char *seg, uint32_t v) { b1(0x08); bs(seg); b1(0x0c); b4(v); }
static void mem32fixed(uint32_t base, uint32_t len) { b1(0x86); b1(9); b1(0); b1(1); b4(base); b4(len); }
static void irq(uint32_t intid) { b1(0x89); b1(6); b1(0); b1(0x01); b1(1); b4(intid); }
static void end_tag(void) { b1(0x79); b1(0); }

/* Buffer(size) { bytes } where the bytes are emitted by fn. */
static void buffer_of(void (*fn)(void))
{
    b1(0x11);
    uint32_t p = pk_open();
    b1(0x0b); /* WordPrefix size, fixed below */
    uint32_t szpos = at;
    at += 2;
    uint32_t d0 = at;
    fn();
    uint32_t n = at - d0;
    buf[szpos] = (uint8_t)n;
    buf[szpos + 1] = (uint8_t)(n >> 8);
    pk_close(p);
}

static void spark_rbuf(void)
{
    mem32fixed(0x1db60000u, 0x7800u);
    mem32fixed(0x1db68000u, 0x100u);
    mem32fixed(0x1db70000u, 0x4000u);
    irq(0xaf);
    end_tag();
}
static void qemu_uart(void)
{
    mem32fixed(0x09000000u, 0x1000u);
    irq(0x21);
    end_tag();
}
static void qword_mem(void)
{
    b1(0x8a); b1(43); b1(0);
    b1(0); b1(0x0c); b1(0x01); /* memory, flags */
    b8(0); b8(0x4000000000ull); b8(0x400000ffffull); b8(0); b8(0x10000);
    end_tag();
}
static void desc_past_end(void)
{
    b1(0x86); b1(40); b1(0); b1(1); b4(0x12340000u); /* claims 40 bytes, has 5 */
}

/* Device(NAME) { fn() } */
static void device(const char *seg, void (*fn)(void))
{
    b1(0x5b); b1(0x82);
    uint32_t p = pk_open();
    bs(seg);
    fn();
    pk_close(p);
}

static void usb0_body(void)
{
    name_str("_HID", "NVDA8000");
    name_str("_CID", "PNP0D15");
    b1(0x08); bs("_UID"); b1(0x00);
    /* Method(_STA) { If (UP0E == 0) { Return (0) } Return (0x0F) } (shape only) */
    b1(0x14); { uint32_t p = pk_open(); bs("_STA"); b1(0x00); b1(0xa4); b1(0x0a); b1(0x0f); pk_close(p); }
    /* Method(_CRS, 0, Serialized) { Name(RBUF, Buffer(){...}) Return(RBUF) } */
    b1(0x14);
    uint32_t p = pk_open();
    bs("_CRS");
    b1(0x08);
    b1(0x08); bs("RBUF");
    buffer_of(spark_rbuf);
    b1(0xa4); bs("RBUF");
    pk_close(p);
}
static void usb4_body(void)
{
    name_str("_HID", "NVDA8001");
    name_str("_CID", "PNP0D15");
    b1(0x14);
    uint32_t p = pk_open();
    bs("_CRS");
    b1(0x08);
    b1(0x08); bs("RBUF");
    buffer_of(spark_rbuf);
    b1(0xa4); bs("RBUF");
    pk_close(p);
}
static void com0_body(void)
{
    name_str("_HID", "ARMH0011");
    b1(0x08); bs("_UID"); b1(0x00);
    b1(0x08); bs("_CRS");
    buffer_of(qemu_uart);
}
static void xhc_eisa_body(void)
{
    name_dword("_HID", 0x100dd041u); /* EisaId("PNP0D10") */
    b1(0x08); bs("_CRS");
    buffer_of(qword_mem);
}
static void pci0_body(void)
{
    name_dword("_HID", 0x080ad041u); /* EisaId("PNP0A08") */
    name_dword("_CID", 0x030ad041u); /* EisaId("PNP0A03") */
}
static void child_body(void) { name_str("_HID", "NVDA8001"); }
static void parent_body(void)
{
    device("CHL0", child_body);
    name_str("_HID", "PNP0C02"); /* after the nested device: not read for PAR0 */
}
static void bad_crs_body(void)
{
    name_str("_HID", "PNP0D15");
    b1(0x08); bs("_CRS");
    buffer_of(desc_past_end);
}
static void sb_scope(void)
{
    device("USB0", usb0_body);
    device("USB4", usb4_body);
    device("COM0", com0_body);
    device("XHC1", xhc_eisa_body);
    device("PCI0", pci0_body);
    device("PAR0", parent_body);
    device("BADC", bad_crs_body);
}

static uint32_t build_dsdt(const char *sig)
{
    at = 0;
    uint32_t s = hdr(sig);
    b1(0x10); /* Scope(\_SB_) */
    uint32_t p = pk_open();
    b1(0x5c); bs("_SB_");
    sb_scope();
    pk_close(p);
    return finish(s);
}

static const struct ck_acpi_device *by_name(const struct ck_acpi_device *d, int n, const char *name)
{
    for (int i = 0; i < n; i++)
        if (!strcmp(d[i].path, name)) return &d[i];
    return 0;
}

static void test_scan(void)
{
    uint32_t len = build_dsdt("DSDT");
    CHECK(ck_aml_table_ok(buf, len) == CK_AML_OK);
    struct ck_acpi_device d[16];
    unsigned seen = 0;
    int n = ck_aml_scan(buf, len, 0, 0, d, 16, &seen);
    CHECK(n == 8 && seen == 8); /* USB0 USB4 COM0 XHC1 PCI0 PAR0 CHL0 BADC */

    const struct ck_acpi_device *u = by_name(d, n, "USB0");
    CHECK(u && !strcmp(u->hid, "NVDA8000") && !strcmp(u->cid, "PNP0D15"));
    CHECK(u && u->mmio_base == 0x1db60000u && u->mmio_len == 0x7800u); /* first range only */
    const struct ck_acpi_device *c = by_name(d, n, "COM0");
    CHECK(c && !strcmp(c->hid, "ARMH0011") && c->cid[0] == 0 && c->mmio_base == 0x09000000u && c->mmio_len == 0x1000u);
    const struct ck_acpi_device *x = by_name(d, n, "XHC1");
    CHECK(x && !strcmp(x->hid, "PNP0D10") && x->mmio_base == 0x4000000000ull && x->mmio_len == 0x10000u);
    const struct ck_acpi_device *p = by_name(d, n, "PCI0");
    CHECK(p && !strcmp(p->hid, "PNP0A08") && !strcmp(p->cid, "PNP0A03") && p->mmio_len == 0);
    const struct ck_acpi_device *par = by_name(d, n, "PAR0");
    const struct ck_acpi_device *chl = by_name(d, n, "CHL0");
    CHECK(par && par->hid[0] == 0); /* the child's _HID is not the parent's */
    CHECK(chl && !strcmp(chl->hid, "NVDA8001"));
    const struct ck_acpi_device *bc = by_name(d, n, "BADC");
    CHECK(bc && bc->mmio_base == 0 && bc->mmio_len == 0); /* descriptor past its buffer: no range */

    /* The xHCI id filter (the fence's list). */
    static const char *const ids[] = { "NVDA8000", "NVDA8001", "PNP0D10", "PNP0D15" };
    n = ck_aml_scan(buf, len, ids, 4, d, 16, &seen);
    CHECK(n == 5); /* USB0 USB4 XHC1 CHL0 BADC */
    CHECK(by_name(d, n, "USB0") && by_name(d, n, "USB4") && by_name(d, n, "XHC1") && by_name(d, n, "CHL0") &&
          by_name(d, n, "BADC") && !by_name(d, n, "COM0"));
    /* max smaller than the matches: count returned, only max stored. */
    memset(d, 0x5a, sizeof d);
    CHECK(ck_aml_scan(buf, len, ids, 4, d, 2, 0) == 5);
    CHECK(d[2].path[0] == 0x5a);
    static const char *const ctl[] = { "ARMH0011" };
    n = ck_aml_scan(buf, len, ctl, 1, d, 16, 0);
    CHECK(n == 1 && !strcmp(d[0].path, "COM0"));
    static const char *const none[] = { "QEMU0002" };
    CHECK(ck_aml_scan(buf, len, none, 1, d, 16, 0) == 0);

    /* SSDT is accepted too. */
    len = build_dsdt("SSDT");
    CHECK(ck_aml_table_ok(buf, len) == CK_AML_OK && ck_aml_scan(buf, len, ids, 4, d, 16, 0) == 5);
}

static void test_refusals(void)
{
    struct ck_acpi_device d[16];
    unsigned seen = 7;
    /* bad signature */
    uint32_t len = build_dsdt("XSDT");
    CHECK(ck_aml_table_ok(buf, len) == CK_AML_E_SIG);
    CHECK(ck_aml_scan(buf, len, 0, 0, d, 16, &seen) == CK_AML_E_SIG && seen == 0);
    /* bad checksum (one byte flipped after the checksum was fixed) */
    len = build_dsdt("DSDT");
    buf[len - 1] ^= 0x01;
    CHECK(ck_aml_table_ok(buf, len) == CK_AML_E_SUM);
    CHECK(ck_aml_scan(buf, len, 0, 0, d, 16, 0) == CK_AML_E_SUM);
    /* truncated: the header claims more bytes than are available */
    len = build_dsdt("DSDT");
    CHECK(ck_aml_table_ok(buf, len - 1) == CK_AML_E_LEN);
    CHECK(ck_aml_scan(buf, len - 40, 0, 0, d, 16, 0) == CK_AML_E_LEN);
    CHECK(ck_aml_table_ok(buf, 35) == CK_AML_E_LEN);
    /* header length below 36 */
    len = build_dsdt("DSDT");
    buf[4] = 20, buf[5] = buf[6] = buf[7] = 0;
    CHECK(ck_aml_table_ok(buf, len) == CK_AML_E_LEN);
    CHECK(ck_aml_table_ok(0, 100) == CK_AML_E_LEN);

    /* A device whose package runs past the table end is skipped, not followed. */
    at = 0;
    uint32_t s = hdr("SSDT");
    device("GOOD", child_body);
    b1(0x5b); b1(0x82); b1(0x4f); b1(0x40); bs("LONG"); /* 2-byte PkgLength 0x40f, far past the end */
    name_str("_HID", "NVDA8000");
    len = finish(s);
    CHECK(ck_aml_table_ok(buf, len) == CK_AML_OK);
    int n = ck_aml_scan(buf, len, 0, 0, d, 16, &seen);
    CHECK(n == 1 && seen == 1 && !strcmp(d[0].path, "GOOD"));
    /* A bad name segment (lower case) is not a device. */
    at = 0;
    s = hdr("SSDT");
    b1(0x5b); b1(0x82); b1(0x0d); bs("usb0"); name_str("_HID", "NVDA");
    len = finish(s);
    CHECK(ck_aml_scan(buf, len, 0, 0, d, 16, &seen) == 0 && seen == 0);
}

static void test_helpers(void)
{
    char id[8];
    ck_aml_eisaid(0x150dd041u, id);
    CHECK(!strcmp(id, "PNP0D15"));
    ck_aml_eisaid(0x080ad041u, id);
    CHECK(!strcmp(id, "PNP0A08"));
    CHECK(ck_aml_path_eq("\\_SB.USB0", "_SB_.USB0"));
    CHECK(ck_aml_path_eq("\\_SB_.USB0", "\\_SB_.USB0"));
    CHECK(!ck_aml_path_eq("\\_SB_.USB0", "\\_SB_.USB1"));
    CHECK(!ck_aml_path_eq("\\_SB_.USB0", "\\_SB_"));
    CHECK(!ck_aml_path_eq("\\_SB_.USB00", "\\_SB_.USB0"));
    CHECK(ck_aml_last_seg_eq("USB0", "\\_SB_.USB0"));
    CHECK(ck_aml_last_seg_eq("\\_SB_.PCI0.XHC", "XHC_"));
    CHECK(!ck_aml_last_seg_eq("USB0", "\\_SB_.USB1"));
    CHECK(!ck_aml_last_seg_eq("", "USB0"));
}

/* ---- IORT named components ---- */
static uint32_t iort_smmu(uint64_t base)
{
    uint32_t off = at;
    b1(4); b1(68); b1(0); b1(4); b4(0); b4(0); b4(0); /* type, len, rev, id, no mappings */
    b8(base);
    while (at < off + 68) b1(0);
    return off;
}
static void iort_named(const char *name, uint32_t sid, uint32_t target, int single, int with_map)
{
    uint32_t off = at;
    uint32_t nlen = 29 + 32; /* fixed fields + name area */
    uint32_t total = nlen + (with_map ? 20u : 0u);
    b1(1); b1((uint8_t)total); b1((uint8_t)(total >> 8)); b1(4); b4(0);
    b4(with_map ? 1u : 0u); b4(with_map ? nlen : 0u);
    b4(0); b8(0x0000000000000001ull); b1(48);
    uint32_t nm = at;
    bs(name);
    while (at < nm + 32) b1(0);
    if (with_map) {
        b4(0); b4(0); b4(sid); b4(target); b4(single ? 1u : 0u);
    }
    (void)off;
}
static uint32_t build_iort(int dup)
{
    at = 0;
    uint32_t s = at;
    bs("IORT"); b4(0); b1(3); b1(0); bs("AIENOS"); bs("CKTEST01"); b4(1); bs("CKT "); b4(1);
    uint32_t count_pos = at;
    b4(0); b4(48); b4(0);
    uint32_t a = iort_smmu(0x13800000ull); /* the first SMMUv3: the one the kernel drives */
    uint32_t b = iort_smmu(0x14900000ull);
    iort_named("\\_SB_.USB0", 0x30, a, 1, 1);
    iort_named("\\_SB_.USB1", 0x31, b, 1, 1);
    iort_named("\\_SB_.USB2", 0, 0, 0, 0);
    iort_named("\\_SB_.USB3", 0x33, a, 0, 1); /* not flagged single, but one id (count 0) */
    uint32_t nodes = 6;
    if (dup) {
        iort_named("\\_SB_.PCI1.USB0", 0x40, a, 1, 1);
        nodes++;
    }
    buf[count_pos] = (uint8_t)nodes;
    return finish(s);
}

static void test_iort_named(void)
{
    build_iort(0);
    struct ck_iort_named r;
    struct ck_iort_smmu first;
    CHECK(ck_iort_parse(buf, &first) == 1 && first.base == 0x13800000ull);
    CHECK(ck_iort_named(buf, "USB0", &r) == 1);
    CHECK(r.stream_id == 0x30 && r.target_off == first.node_off && r.target_base == 0x13800000ull);
    CHECK(!strcmp(r.name, "\\_SB_.USB0"));
    CHECK(ck_iort_named(buf, "\\_SB.USB1", &r) == 1);
    CHECK(r.stream_id == 0x31 && r.target_off != first.node_off && r.target_base == 0x14900000ull);
    CHECK(ck_iort_named(buf, "USB2", &r) == 1 && r.target_off == 0); /* no mapping: no stream */
    CHECK(ck_iort_named(buf, "USB3", &r) == 1 && r.stream_id == 0x33 && r.target_off == first.node_off);
    CHECK(ck_iort_named(buf, "USB9", &r) == 0);
    CHECK(ck_iort_named(buf, "TOOLONG5", &r) == -1);
    build_iort(1);
    CHECK(ck_iort_named(buf, "USB0", &r) == -2); /* two named components end in USB0 */
    /* malformed: a mapping that references outside the table */
    uint32_t len = build_iort(0);
    for (uint32_t i = 48; i + 20 <= len; i++) /* find USB0's mapping (sid 0x30) */
        if (buf[i] == 0x30 && buf[i + 1] == 0 && buf[i + 4] != 0 && buf[i - 4] == 0) {
            buf[i + 4] = 0xff, buf[i + 5] = 0xff, buf[i + 6] = 0, buf[i + 7] = 0;
            break;
        }
    CHECK(ck_iort_named(buf, "USB0", &r) == -1);
    memcpy(buf, "XXXX", 4);
    CHECK(ck_iort_named(buf, "USB0", &r) == -1);
}

int main(void)
{
    test_scan();
    test_refusals();
    test_helpers();
    test_iort_named();
    return ck_t_verdict("test_acpi_dev");
}
