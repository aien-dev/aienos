/* test_acpi.c -- RSDP/XSDT walk, checksum and length checks, MADT, SPCR and
 * FADT parsing on crafted tables shaped like QEMU virt's. */
#include <stdint.h>
#include <string.h>
#include "ck_test.h"
#include "acpi.h"

static void w32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static void w64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }

static void sum_fix(uint8_t *t, size_t len, size_t at)
{
    t[at] = 0;
    uint8_t s = 0;
    for (size_t i = 0; i < len; i++)
        s = (uint8_t)(s + t[i]);
    t[at] = (uint8_t)-s;
}

static void sdt(uint8_t *t, const char *sig, uint32_t len)
{
    memcpy(t, sig, 4);
    w32(t + 4, len);
    t[8] = 2;
    memcpy(t + 10, "AIENOS", 6);
}

static uint8_t rsdp[36], xsdt[36 + 8 * 5], madt[256], spcr[80], fadt[276], badspcr[80], other[40];

static int seen;
static void each_cb(uint64_t t, uint32_t len, void *ctx)
{
    (void)t;
    (void)len;
    (*(int *)ctx)++;
    seen++;
}

int main(void)
{
    /* MADT: header + 8-byte MADT fields, 2 GICC (one disabled), GICD v3,
     * GICR range. */
    uint32_t at = 44;
    for (int i = 0; i < 2; i++) {
        uint8_t *e = madt + at;
        e[0] = 0x0b;
        e[1] = 80;
        w32(e + 12, i == 0 ? 1 : 0);
        w64(e + 60, 0x080a0000 + i * 0x20000);
        w64(e + 68, (uint64_t)i);
        at += 80;
    }
    madt[at] = 0x0c; madt[at + 1] = 24; w64(madt + at + 8, 0x08000000); madt[at + 20] = 3; at += 24;
    madt[at] = 0x0e; madt[at + 1] = 16; w64(madt + at + 4, 0x080a0000); w32(madt + at + 12, 0xf60000); at += 16;
    sdt(madt, "APIC", at);
    sum_fix(madt, at, 9);

    sdt(spcr, "SPCR", 80);
    spcr[36] = 0x03; spcr[40] = 0; spcr[41] = 32; spcr[43] = 3; w64(spcr + 44, 0x09000000);
    sum_fix(spcr, 80, 9);
    memcpy(badspcr, spcr, 80);
    badspcr[50] ^= 0x55; /* checksum now wrong */

    sdt(fadt, "FACP", 276);
    fadt[129] = 3; /* PSCI compliant, use HVC */
    sum_fix(fadt, 276, 9);
    sdt(other, "OEM1", 40);
    sum_fix(other, 40, 9);

    uint8_t *tabs[5] = { badspcr, madt, spcr, fadt, other };
    sdt(xsdt, "XSDT", sizeof xsdt);
    for (int i = 0; i < 5; i++)
        w64(xsdt + 36 + 8 * i, (uint64_t)(uintptr_t)tabs[i]);
    sum_fix(xsdt, sizeof xsdt, 9);

    memcpy(rsdp, "RSD PTR ", 8);
    memcpy(rsdp + 9, "AIENOS", 6);
    rsdp[15] = 2;
    w32(rsdp + 16, 0x1234);
    w32(rsdp + 20, 36);
    w64(rsdp + 24, (uint64_t)(uintptr_t)xsdt);
    sum_fix(rsdp, 20, 8);
    sum_fix(rsdp, 36, 32);
    uint64_t r = (uint64_t)(uintptr_t)rsdp;

    CHECK(ck_acpi_sum_ok(rsdp, 20) && ck_acpi_sum_ok(rsdp, 36));
    int x = -1;
    CHECK(ck_acpi_root(r, &x) == (uint64_t)(uintptr_t)xsdt && x == 1);
    CHECK(ck_acpi_lookup(r, "APIC") == madt);
    CHECK(ck_acpi_lookup(r, "SPCR") == spcr); /* bad-checksum copy skipped */
    CHECK(ck_acpi_lookup(r, "FACP") == fadt);
    CHECK(ck_acpi_lookup(r, "MCFG") == NULL);
    int n = 0;
    CHECK(ck_acpi_each(r, each_cb, &n) == 5 && n == 5 && seen == 5);

    struct ck_madt_gic g;
    CHECK(ck_madt_parse(madt, &g) == 0);
    CHECK(g.gicd == 0x08000000 && g.gic_version == 3 && g.gicr == 0x080a0000 && g.gicr_len == 0xf60000);
    CHECK(g.gicc_count == 1 && g.gicc_gicr == 0x080a0000);

    struct ck_spcr s;
    CHECK(ck_spcr_parse(spcr, &s) == 0 && s.interface_type == 3 && s.space == 0 &&
          s.bit_width == 32 && s.access_size == 3 && s.base == 0x09000000);
    uint16_t fl = 0;
    CHECK(ck_fadt_arm_boot_arch(fadt, &fl) == 0 && fl == 3);

    /* Malformed inputs. */
    CHECK(ck_spcr_parse(madt, &s) == -1);
    CHECK(ck_fadt_arm_boot_arch(spcr, &fl) == -1);
    uint8_t m2[256];
    memcpy(m2, madt, sizeof m2);
    m2[44 + 1] = 0; /* zero-length entry would loop forever */
    CHECK(ck_madt_parse(m2, &g) == -1);
    memcpy(m2, madt, sizeof m2);
    w32(m2 + 4, 44 + 80 + 10); /* table ends inside an entry */
    CHECK(ck_madt_parse(m2, &g) == -1);
    rsdp[8] ^= 1; /* RSDP checksum broken */
    CHECK(ck_acpi_root(r, &x) == 0 && ck_acpi_lookup(r, "APIC") == NULL && ck_acpi_each(r, each_cb, &n) == -1);
    rsdp[8] ^= 1;
    xsdt[40] ^= 1; /* XSDT checksum broken */
    CHECK(ck_acpi_lookup(r, "APIC") == NULL);
    xsdt[40] ^= 1;
    /* Revision 0 RSDP: RSDT address. */
    rsdp[15] = 0;
    sum_fix(rsdp, 20, 8);
    CHECK(ck_acpi_root(r, &x) == 0x1234 && x == 0);
    CHECK(ck_acpi_root(0, &x) == 0);
    return ck_t_verdict("CK_ACPI");
}
