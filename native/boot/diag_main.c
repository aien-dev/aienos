/* diag_main.c -- AIENOS-PI5-BOOT-0 / PI5-ACPI-0: a minimal AArch64 UEFI diagnostic.
 *
 * Prints what the firmware tells an application (vendor, revisions, EL, memory
 * map summary, every ConfigurationTable GUID) to ConOut and to a buffer, copies
 * every ACPI table the XSDT (and the FADT DSDT pointer) names, byte for byte, to
 * \EFI\AIENOS\ACPI\<SIG>[n].BIN, writes the buffer to \EFI\AIENOS\PI5BOOT0.TXT
 * on the volume the image was loaded from, waits ~5 s so a person can read the
 * screen, and cold-resets the machine through ResetSystem (on the Pi this ends a
 * one-shot tryboot run: the next boot is the normal OS). A 180 s firmware watchdog
 * covers a hang before that. It links no kernel and never calls ExitBootServices.
 * Built as PI5DIAG.EFI (make -C native/kernel pi5-diag); on the card it is
 * EFI/BOOT/BOOTAA64.EFI. Test: scripts/qemu_ck_pi5_diag_test.sh. */
#include <stdarg.h>
#include <string.h>
#include "efi.h"
#include "../kernel/core/fmt.h"

#define REPORT_BYTES 16384
#define MAP_BYTES (64u << 10)
#define LINE_BYTES 256

static EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *conout;
static char report[REPORT_BYTES];
static size_t report_len;
static uint64_t map_buf[MAP_BYTES / 8];

struct line {
    char b[LINE_BYTES];
    size_t n;
};

static void line_emit(void *ctx, char c)
{
    struct line *l = ctx;
    if (l->n < sizeof l->b - 1)
        l->b[l->n++] = c;
}

/* Format one line, print it on ConOut (CRLF) and append it (LF) to the report. */
static void say(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void say(const char *fmt, ...)
{
    struct line l;
    CHAR16 w[2 * LINE_BYTES + 1];
    size_t k = 0;
    va_list ap;
    l.n = 0;
    va_start(ap, fmt);
    ck_vformat(line_emit, &l, fmt, ap);
    va_end(ap);
    for (size_t i = 0; i < l.n; i++) {
        if (l.b[i] == '\n')
            w[k++] = '\r';
        w[k++] = (uint8_t)l.b[i];
        if (report_len < sizeof report)
            report[report_len++] = l.b[i];
    }
    w[k] = 0;
    if (conout)
        conout->OutputString(conout, w);
}


/* Format into out (always NUL-terminated, truncated to cap - 1 bytes). */
static void fmt_buf(char *out, size_t cap, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void fmt_buf(char *out, size_t cap, const char *fmt, ...)
{
    struct line l;
    va_list ap;
    l.n = 0;
    va_start(ap, fmt);
    ck_vformat(line_emit, &l, fmt, ap);
    va_end(ap);
    size_t n = l.n < cap - 1 ? l.n : cap - 1;
    memcpy(out, l.b, n);
    out[n] = 0;
}
struct named_guid {
    EFI_GUID g;
    const char *name;
};

/* Values from edk2 MdePkg/Include/Guid/{Acpi.h,SmBios.h,Fdt.h}. */
static const struct named_guid known[] = {
    {{0xeb9d2d30, 0x2d88, 0x11d3, {0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d}}, "ACPI 1.0"},
    {{0x8868e871, 0xe4f1, 0x11d3, {0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81}}, "ACPI 2.0"},
    {{0xeb9d2d31, 0x2d88, 0x11d3, {0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d}}, "SMBIOS"},
    {{0xf2fd1544, 0x9794, 0x4a2c, {0x99, 0x2e, 0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94}}, "SMBIOS3"},
    {{0xb1b621d5, 0xf19c, 0x41a5, {0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0}}, "Device Tree"},
};

static const char *guid_name(const EFI_GUID *g)
{
    for (size_t i = 0; i < sizeof known / sizeof known[0]; i++)
        if (memcmp(g, &known[i].g, sizeof *g) == 0)
            return known[i].name;
    return "unknown";
}

static void narrow(char *out, size_t cap, const CHAR16 *v)
{
    size_t i = 0;
    for (; v && v[i] && i < cap - 1; i++)
        out[i] = v[i] < 0x80 ? (char)v[i] : '?';
    out[i] = 0;
}

static CHAR16 *wide(CHAR16 *out, const char *s)
{
    size_t i = 0;
    for (; s[i]; i++)
        out[i] = (uint8_t)s[i];
    out[i] = 0;
    return out;
}

static void memory_summary(EFI_BOOT_SERVICES *bs)
{
    uint64_t size = sizeof map_buf, key = 0, dsize = 0, conv = 0;
    uint32_t dver = 0;
    EFI_STATUS s = bs->GetMemoryMap(&size, (EFI_MEMORY_DESCRIPTOR *)map_buf, &key, &dsize, &dver);
    if (s != EFI_SUCCESS || dsize < sizeof(EFI_MEMORY_DESCRIPTOR)) {
        say("memory_map: GetMemoryMap failed status=0x%llx\n", (unsigned long long)s);
        return;
    }
    uint64_t n = size / dsize;
    for (uint64_t i = 0; i < n; i++) {
        const EFI_MEMORY_DESCRIPTOR *d = (const void *)((const uint8_t *)map_buf + i * dsize);
        if (d->Type == EfiConventionalMemory)
            conv += d->NumberOfPages;
    }
    say("memory_map: entries=%llu conventional_mib=%llu map_key=0x%llx\n", (unsigned long long)n,
        (unsigned long long)(conv >> 8), (unsigned long long)key); /* 256 pages of 4 KiB per MiB */
}

/* Open (creating) a directory under the root of the volume the image came from. */
static EFI_STATUS open_dir(EFI_HANDLE image, EFI_SYSTEM_TABLE *st, const char *path, EFI_FILE_PROTOCOL **dir)
{
    static const EFI_GUID li_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID_INIT;
    static const EFI_GUID fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID_INIT;
    EFI_BOOT_SERVICES *bs = st->BootServices;
    EFI_LOADED_IMAGE_PROTOCOL *li = 0;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = 0;
    EFI_FILE_PROTOCOL *root = 0;
    CHAR16 w[48];
    EFI_STATUS s = bs->HandleProtocol(image, &li_guid, (void **)&li);
    if (s != EFI_SUCCESS)
        return s;
    s = bs->HandleProtocol(li->DeviceHandle, &fs_guid, (void **)&fs);
    if (s != EFI_SUCCESS)
        return s;
    s = fs->OpenVolume(fs, &root);
    if (s != EFI_SUCCESS)
        return s;
    /* Opening an existing directory with CREATE returns it. */
    s = root->Open(root, dir, wide(w, path), EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                   EFI_FILE_DIRECTORY);
    root->Close(root);
    return s;
}

/* Replace dir\name with exactly len bytes of buf (a stale file is deleted first). */
static EFI_STATUS write_file(EFI_FILE_PROTOCOL *dir, const char *name, const void *buf, uint64_t len)
{
    const uint64_t rw = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE;
    EFI_FILE_PROTOCOL *f = 0;
    CHAR16 w[32];
    if (dir->Open(dir, &f, wide(w, name), rw, 0) == EFI_SUCCESS)
        f->Delete(f);
    f = 0;
    EFI_STATUS s = dir->Open(dir, &f, wide(w, name), rw | EFI_FILE_MODE_CREATE, 0);
    if (s != EFI_SUCCESS)
        return s;
    uint64_t n = len;
    s = f->Write(f, &n, (void *)buf);
    if (s == EFI_SUCCESS && n != len)
        s = EFI_DEVICE_ERROR;
    if (s == EFI_SUCCESS)
        s = f->Flush(f);
    f->Close(f);
    return s;
}

static EFI_STATUS write_report(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    EFI_FILE_PROTOCOL *dir = 0;
    EFI_STATUS s = open_dir(image, st, "\\EFI\\AIENOS", &dir);
    if (s != EFI_SUCCESS)
        return s;
    s = write_file(dir, "PI5BOOT0.TXT", report, report_len);
    dir->Close(dir);
    return s;
}

/* ---- ACPI table copy (ACPI 6.5: 5.2.5.3 RSDP, 5.2.6 header, 5.2.8 XSDT, 5.2.9 FADT) ---- */
#define ACPI_MAX_TABLES 64
#define ACPI_MAX_LEN (1u << 20)

static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) | (uint64_t)rd32(p + 4) << 32; }

static int acpi_sum_ok(const uint8_t *p, uint32_t len)
{
    uint8_t s = 0;
    for (uint32_t i = 0; i < len; i++)
        s += p[i];
    return s == 0;
}

struct acpi_dump {
    EFI_FILE_PROTOCOL *dir;
    char seen[ACPI_MAX_TABLES][4];
    unsigned nseen, copied, failed;
};

/* Copy one table to <SIG>.BIN, or <SIG><k>.BIN for the k-th repeat of a signature. */
static void acpi_copy(struct acpi_dump *d, uint64_t addr, const char *via)
{
    const uint8_t *t = (const uint8_t *)(uintptr_t)addr;
    char sig[5], name[16];
    unsigned rep = 0;
    if (!addr) {
        say("acpi_table: NULL pointer via %s\n", via);
        d->failed++;
        return;
    }
    uint32_t len = rd32(t + 4);
    for (int i = 0; i < 4; i++) {
        char c = (char)t[i];
        sig[i] = ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) ? c : '_';
    }
    sig[4] = 0;
    if (len < 36 || len > ACPI_MAX_LEN) {
        say("acpi_table: %s at 0x%llx bad length %u via %s\n", sig, (unsigned long long)addr, len, via);
        d->failed++;
        return;
    }
    for (unsigned i = 0; i < d->nseen; i++)
        if (memcmp(d->seen[i], sig, 4) == 0)
            rep++;
    if (d->nseen < ACPI_MAX_TABLES)
        memcpy(d->seen[d->nseen++], sig, 4);
    if (rep)
        fmt_buf(name, sizeof name, "%s%u.BIN", sig, rep);
    else
        fmt_buf(name, sizeof name, "%s.BIN", sig);
    EFI_STATUS s = d->dir ? write_file(d->dir, name, t, len) : EFI_NOT_FOUND;
    say("acpi_table: %s rev=%u len=%u at 0x%llx checksum=%s via %s file=%s %s\n", sig, t[8], len,
        (unsigned long long)addr, acpi_sum_ok(t, len) ? "ok" : "BAD", via, name,
        s == EFI_SUCCESS ? "written" : "WRITE_FAILED");
    if (s == EFI_SUCCESS)
        d->copied++;
    else
        d->failed++;
}

static void acpi_dump_all(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    static const EFI_GUID acpi20 = EFI_ACPI_20_TABLE_GUID_INIT;
    static struct acpi_dump d;
    const uint8_t *rsdp = 0;
    for (uint64_t i = 0; i < st->NumberOfTableEntries; i++)
        if (memcmp(&st->ConfigurationTable[i].VendorGuid, &acpi20, sizeof acpi20) == 0)
            rsdp = st->ConfigurationTable[i].VendorTable;
    if (!rsdp || memcmp(rsdp, "RSD PTR ", 8) != 0 || rsdp[15] < 2) {
        say("acpi: no ACPI 2.0 RSDP\n");
        return;
    }
    uint64_t xsdt_addr = rd64(rsdp + 24);
    say("acpi_rsdp: rev=%u oem=%c%c%c%c%c%c xsdt=0x%llx\n", rsdp[15], rsdp[9], rsdp[10], rsdp[11], rsdp[12],
        rsdp[13], rsdp[14], (unsigned long long)xsdt_addr);
    /* FAT creates one level per Open: make \EFI\AIENOS before \EFI\AIENOS\ACPI. */
    EFI_FILE_PROTOCOL *parent = 0;
    EFI_STATUS s = open_dir(image, st, "\\EFI\\AIENOS", &parent);
    if (s == EFI_SUCCESS) {
        parent->Close(parent);
        s = open_dir(image, st, "\\EFI\\AIENOS\\ACPI", &d.dir);
    }
    if (s != EFI_SUCCESS) {
        say("acpi: open \\EFI\\AIENOS\\ACPI FAILED status=0x%llx\n", (unsigned long long)s);
        d.dir = 0;
    }
    acpi_copy(&d, xsdt_addr, "RSDP");
    const uint8_t *x = (const uint8_t *)(uintptr_t)xsdt_addr;
    uint32_t xlen = x ? rd32(x + 4) : 0;
    if (!x || memcmp(x, "XSDT", 4) != 0 || xlen < 36 || xlen > ACPI_MAX_LEN) {
        say("acpi: XSDT missing or malformed\n");
    } else {
        uint32_t n = (xlen - 36) / 8;
        for (uint32_t i = 0; i < n && i < ACPI_MAX_TABLES; i++) {
            uint64_t a = rd64(x + 36 + 8 * i);
            acpi_copy(&d, a, "XSDT");
            const uint8_t *t = (const uint8_t *)(uintptr_t)a;
            if (a && memcmp(t, "FACP", 4) == 0) {
                uint32_t flen = rd32(t + 4);
                uint64_t dsdt = flen >= 148 ? rd64(t + 140) : 0; /* X_DSDT */
                if (!dsdt && flen >= 44)
                    dsdt = rd32(t + 40); /* DSDT */
                acpi_copy(&d, dsdt, "FADT");
            }
        }
    }
    say("acpi_dump: copied=%u failed=%u\n", d.copied, d.failed);
    if (d.dir)
        d.dir->Close(d.dir);
}

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    EFI_BOOT_SERVICES *bs = st->BootServices;
    char vendor[80];
    uint64_t el;
    conout = st->ConOut;
    /* 180 s: the firmware resets the machine if this app hangs (UEFI 2.x 7.5). */
    if (bs->SetWatchdogTimer)
        bs->SetWatchdogTimer(180, 0x10000, 0, 0);
    __asm__ volatile("mrs %0, CurrentEL" : "=r"(el));

    say("AIENOS-PI5-BOOT-0\n");
    say("milestone: AIENOS-PI5-ACPI-0\n");
    narrow(vendor, sizeof vendor, st->FirmwareVendor);
    say("firmware_vendor: %s\n", vendor);
    say("firmware_revision: 0x%x\n", st->FirmwareRevision);
    say("uefi_spec_revision: %u.%u\n", st->Hdr.Revision >> 16, st->Hdr.Revision & 0xffff);
    say("current_el: EL%u\n", (unsigned)((el >> 2) & 3));
    memory_summary(bs);
    say("config_tables: %llu\n", (unsigned long long)st->NumberOfTableEntries);
    for (uint64_t i = 0; i < st->NumberOfTableEntries; i++) {
        const EFI_GUID *g = &st->ConfigurationTable[i].VendorGuid;
        say("table %llu: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x %s at 0x%llx\n",
            (unsigned long long)i, g->d1, g->d2, g->d3, g->d4[0], g->d4[1], g->d4[2], g->d4[3],
            g->d4[4], g->d4[5], g->d4[6], g->d4[7], guid_name(g),
            (unsigned long long)(uintptr_t)st->ConfigurationTable[i].VendorTable);
    }
    acpi_dump_all(image, st);

    say("AIENOS-PI5-BOOT-0 DONE\n"); /* last line of the file; the write result below is console only */
    EFI_STATUS s = write_report(image, st);
    if (s == EFI_SUCCESS)
        say("report_file: written \\EFI\\AIENOS\\PI5BOOT0.TXT (%llu bytes)\n", (unsigned long long)report_len);
    else
        say("report_file: write FAILED status=0x%llx\n", (unsigned long long)s);
    bs->Stall(5ull * 1000 * 1000);
    EFI_RUNTIME_SERVICES *rt = st->RuntimeServices;
    say("reset: cold\n");
    if (rt && rt->ResetSystem)
        rt->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, 0);
    say("reset: ResetSystem returned\n");
    return EFI_SUCCESS;
}
