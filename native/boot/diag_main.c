/* diag_main.c -- AIENOS-PI5-BOOT-0: a minimal AArch64 UEFI diagnostic.
 *
 * Prints what the firmware tells an application (vendor, revisions, EL, memory
 * map summary, every ConfigurationTable GUID) to ConOut and to a buffer, writes
 * the buffer to \EFI\AIENOS\PI5BOOT0.TXT on the volume the image was loaded
 * from, waits ~10 s so a person can read the screen, and returns EFI_SUCCESS.
 * It links no kernel and never calls ExitBootServices. Built as PI5DIAG.EFI
 * (make -C native/kernel pi5-diag); on the card it is EFI/BOOT/BOOTAA64.EFI.
 * Test: scripts/qemu_ck_pi5_diag_test.sh. */
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

static EFI_STATUS write_report(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    static const EFI_GUID li_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID_INIT;
    static const EFI_GUID fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID_INIT;
    EFI_BOOT_SERVICES *bs = st->BootServices;
    EFI_LOADED_IMAGE_PROTOCOL *li = 0;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = 0;
    EFI_FILE_PROTOCOL *root = 0, *dir = 0, *f = 0;
    CHAR16 w[32];
    EFI_STATUS s = bs->HandleProtocol(image, &li_guid, (void **)&li);
    if (s != EFI_SUCCESS)
        return s;
    s = bs->HandleProtocol(li->DeviceHandle, &fs_guid, (void **)&fs);
    if (s != EFI_SUCCESS)
        return s;
    s = fs->OpenVolume(fs, &root);
    if (s != EFI_SUCCESS)
        return s;
    const uint64_t rw = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE;
    /* Opening an existing directory with CREATE returns it. */
    s = root->Open(root, &dir, wide(w, "\\EFI\\AIENOS"), rw | EFI_FILE_MODE_CREATE, EFI_FILE_DIRECTORY);
    root->Close(root);
    if (s != EFI_SUCCESS)
        return s;
    /* A stale report is deleted first so the file holds exactly this run. */
    if (dir->Open(dir, &f, wide(w, "PI5BOOT0.TXT"), rw, 0) == EFI_SUCCESS)
        f->Delete(f);
    f = 0;
    s = dir->Open(dir, &f, wide(w, "PI5BOOT0.TXT"), rw | EFI_FILE_MODE_CREATE, 0);
    if (s == EFI_SUCCESS) {
        uint64_t n = report_len;
        s = f->Write(f, &n, report);
        if (s == EFI_SUCCESS && n != report_len)
            s = EFI_DEVICE_ERROR;
        if (s == EFI_SUCCESS)
            s = f->Flush(f);
        f->Close(f);
    }
    dir->Close(dir);
    return s;
}

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    EFI_BOOT_SERVICES *bs = st->BootServices;
    char vendor[80];
    uint64_t el;
    conout = st->ConOut;
    if (bs->SetWatchdogTimer)
        bs->SetWatchdogTimer(0, 0, 0, 0);
    __asm__ volatile("mrs %0, CurrentEL" : "=r"(el));

    say("AIENOS-PI5-BOOT-0\n");
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

    say("AIENOS-PI5-BOOT-0 DONE\n"); /* last line of the file; the write result below is console only */
    EFI_STATUS s = write_report(image, st);
    if (s == EFI_SUCCESS)
        say("report_file: written \\EFI\\AIENOS\\PI5BOOT0.TXT (%llu bytes)\n", (unsigned long long)report_len);
    else
        say("report_file: write FAILED status=0x%llx\n", (unsigned long long)s);
    bs->Stall(10ull * 1000 * 1000);
    return EFI_SUCCESS;
}
