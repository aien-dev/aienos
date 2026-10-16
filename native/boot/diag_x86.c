/* diag_x86.c -- AIENOS-IMAC-BOOT-0: the x86_64 part of the UEFI diagnostic
 * (diag_main.c). Read-only inventory of what a port needs to know:
 *
 *   cpu_*      CPUID vendor, brand, family/model/stepping, topology, features,
 *              and the mode the firmware left the CPU in (CPL, paging, EFER.LMA)
 *   smbios_*   SMBIOS type 0/1/2 identity (BIOS version, Mac model, board id).
 *              Serial numbers (type 1/2 offset 7) are never read.
 *   pci:       every PCI function, read through configuration mechanism #1
 *              (ports 0xCF8/0xCFC, PCI Local Bus 3.0 section 3.2.2.3.2); reads only
 *   gop:       every Graphics Output Protocol mode the firmware set
 *   block:     every whole-disk Block I/O device (no partitions)
 *
 * Built with -mabi=ms (all functions use the UEFI x86_64 calling convention),
 * so the firmware function pointers in efi.h need no annotations. */
#include <stdarg.h>
#include <string.h>
#include "efi.h"
#include "diag.h"

#define say diag_say

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)rd16(p) | (uint32_t)rd16(p + 2) << 16; }
static uint64_t rd64(const uint8_t *p) { return (uint64_t)rd32(p) | (uint64_t)rd32(p + 4) << 32; }

/* ---- console: Apple firmware starts in graphics mode, where ConOut text is
 * invisible until EFI_CONSOLE_CONTROL_PROTOCOL (Intel EFI 1.x, kept by Apple)
 * selects text mode. Absent on edk2/OVMF: nothing happens. ---- */
#define CONSOLE_CONTROL_GUID_INIT \
    { 0xf42f7782, 0x012e, 0x4c12, { 0x99, 0x56, 0x49, 0xf9, 0x43, 0x04, 0xf7, 0x21 } }
typedef struct CONSOLE_CONTROL {
    void *GetMode;
    EFI_STATUS (*SetMode)(struct CONSOLE_CONTROL *This, uint32_t Mode); /* 0: text */
    void *LockStdIn;
} CONSOLE_CONTROL;

void diag_x86_console(EFI_SYSTEM_TABLE *st)
{
    static const EFI_GUID guid = CONSOLE_CONTROL_GUID_INIT;
    EFI_BOOT_SERVICES *bs = st->BootServices;
    EFI_HANDLE *h = 0;
    uint64_t n = 0;
    if (bs->LocateHandleBuffer(ByProtocol, &guid, 0, &n, &h) != EFI_SUCCESS)
        return;
    for (uint64_t i = 0; i < n; i++) {
        CONSOLE_CONTROL *cc = 0;
        if (bs->HandleProtocol(h[i], &guid, (void **)&cc) == EFI_SUCCESS && cc && cc->SetMode)
            cc->SetMode(cc, 0);
    }
    bs->FreePool(h);
}

/* ---- CPU (Intel SDM vol. 2A, CPUID) ---- */
static void cpuid(uint32_t leaf, uint32_t sub, uint32_t r[4])
{
    __asm__ volatile("cpuid" : "=a"(r[0]), "=b"(r[1]), "=c"(r[2]), "=d"(r[3]) : "a"(leaf), "c"(sub));
}

struct feat {
    uint8_t reg, bit; /* reg: 0 leaf1.ecx 1 leaf1.edx 2 leaf7.ebx 3 leaf7.ecx 4 ext1.edx 5 ext7.edx */
    const char *name;
};
static const struct feat feats[] = {
    {0, 0, "sse3"}, {0, 9, "ssse3"}, {0, 12, "fma"}, {0, 19, "sse4.1"}, {0, 20, "sse4.2"},
    {0, 21, "x2apic"}, {0, 23, "popcnt"}, {0, 25, "aes"}, {0, 26, "xsave"}, {0, 28, "avx"},
    {0, 29, "f16c"}, {0, 30, "rdrand"}, {0, 31, "hypervisor"}, {1, 4, "tsc"}, {1, 9, "apic"},
    {1, 26, "sse2"}, {2, 3, "bmi1"}, {2, 5, "avx2"}, {2, 8, "bmi2"}, {2, 9, "erms"},
    {2, 10, "invpcid"}, {2, 16, "avx512f"}, {2, 18, "rdseed"}, {2, 19, "adx"}, {2, 20, "smap"},
    {2, 7, "smep"}, {2, 29, "sha"}, {3, 2, "umip"}, {3, 11, "avx512vnni"}, {4, 20, "nx"},
    {4, 26, "pdpe1gb"}, {4, 27, "rdtscp"}, {4, 29, "lm"}, {5, 8, "invariant_tsc"},
};

void diag_x86_cpu(void)
{
    uint32_t r[4], max, ext, reg[6] = {0};
    char vendor[13], brand[49];
    cpuid(0, 0, r);
    max = r[0];
    memcpy(vendor, &r[1], 4);
    memcpy(vendor + 4, &r[3], 4);
    memcpy(vendor + 8, &r[2], 4);
    vendor[12] = 0;
    cpuid(0x80000000u, 0, r);
    ext = r[0];
    brand[0] = 0;
    if (ext >= 0x80000004u) {
        for (uint32_t i = 0; i < 3; i++) {
            cpuid(0x80000002u + i, 0, r);
            memcpy(brand + 16 * i, r, 16);
        }
        brand[48] = 0;
    }
    const char *b = brand;
    while (*b == ' ')
        b++;
    say("cpu_vendor: %s\n", vendor);
    say("cpu_brand: %s\n", *b ? b : "(none)");

    cpuid(1, 0, r);
    uint32_t fam = (r[0] >> 8) & 0xf, model = (r[0] >> 4) & 0xf;
    if (fam == 0xf)
        fam += (r[0] >> 20) & 0xff;
    if (fam == 6 || fam >= 0xf)
        model |= ((r[0] >> 16) & 0xf) << 4;
    say("cpu_signature: family=0x%x model=0x%x stepping=%u cpuid_max=0x%x ext_max=0x%x\n", fam, model,
        r[0] & 0xf, max, ext);
    reg[0] = r[2];
    reg[1] = r[3];
    if (max >= 7) {
        cpuid(7, 0, r);
        reg[2] = r[1];
        reg[3] = r[2];
    }
    if (ext >= 0x80000001u) {
        cpuid(0x80000001u, 0, r);
        reg[4] = r[3];
    }
    if (ext >= 0x80000007u) {
        cpuid(0x80000007u, 0, r);
        reg[5] = r[3];
    }
    if (max >= 0xb) {
        uint32_t smt = 0, pkg = 0;
        for (uint32_t lvl = 0; lvl < 4; lvl++) {
            cpuid(0xb, lvl, r);
            uint32_t type = (r[2] >> 8) & 0xff;
            if (!type)
                break;
            if (type == 1)
                smt = r[1] & 0xffff;
            if (type == 2)
                pkg = r[1] & 0xffff;
        }
        say("cpu_topology: threads_per_core=%u threads_per_package=%u\n", smt, pkg);
    }
    if (ext >= 0x80000008u) {
        cpuid(0x80000008u, 0, r);
        say("cpu_address_bits: physical=%u linear=%u\n", r[0] & 0xff, (r[0] >> 8) & 0xff);
    }
    char line[512];
    size_t k = 0;
    for (size_t i = 0; i < sizeof feats / sizeof feats[0]; i++) {
        if (!(reg[feats[i].reg] >> feats[i].bit & 1))
            continue;
        for (const char *p = feats[i].name; *p && k < sizeof line - 2; p++)
            line[k++] = *p;
        line[k++] = ' ';
    }
    if (k)
        k--;
    line[k] = 0;
    say("cpu_features: %s\n", line);

    uint64_t cs, cr0, cr4;
    uint32_t lo, hi;
    __asm__ volatile("mov %%cs, %0" : "=r"(cs));
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(0xc0000080u)); /* IA32_EFER */
    say("cpu_mode: cpl=%u paging=%u long_mode=%u cr0=0x%llx cr4=0x%llx efer=0x%llx\n", (unsigned)(cs & 3),
        (unsigned)(cr0 >> 31 & 1), (unsigned)(lo >> 10 & 1), (unsigned long long)cr0, (unsigned long long)cr4,
        (unsigned long long)((uint64_t)hi << 32 | lo));
}

/* ---- SMBIOS (DMTF DSP0134 3.x: 5.2 entry points, 6.1 structures) ---- */
static const char *sm_str(const uint8_t *s, const uint8_t *end, uint8_t idx, char *out, size_t cap)
{
    const uint8_t *p = s + s[1];
    size_t k = 0;
    out[0] = 0;
    if (!idx)
        return "(none)";
    for (uint8_t i = 1; p < end && *p; i++) {
        if (i == idx) {
            for (; p < end && *p && k < cap - 1; p++)
                out[k++] = (*p >= 0x20 && *p < 0x7f) ? (char)*p : '?';
            out[k] = 0;
            return out;
        }
        while (p < end && *p)
            p++;
        p++;
    }
    return "(missing)";
}

static void smbios(EFI_SYSTEM_TABLE *st)
{
    static const EFI_GUID g2 = {0xeb9d2d31, 0x2d88, 0x11d3, {0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d}};
    static const EFI_GUID g3 = {0xf2fd1544, 0x9794, 0x4a2c, {0x99, 0x2e, 0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94}};
    const uint8_t *e2 = 0, *e3 = 0, *t = 0;
    uint64_t len = 0;
    for (uint64_t i = 0; i < st->NumberOfTableEntries; i++) {
        if (memcmp(&st->ConfigurationTable[i].VendorGuid, &g3, sizeof g3) == 0)
            e3 = st->ConfigurationTable[i].VendorTable;
        if (memcmp(&st->ConfigurationTable[i].VendorGuid, &g2, sizeof g2) == 0)
            e2 = st->ConfigurationTable[i].VendorTable;
    }
    if (e3 && memcmp(e3, "_SM3_", 5) == 0) {
        t = (const uint8_t *)(uintptr_t)rd64(e3 + 0x10);
        len = rd32(e3 + 0x0c);
        say("smbios: entry=3 version=%u.%u table=0x%llx max_len=%llu\n", e3[7], e3[8],
            (unsigned long long)(uintptr_t)t, (unsigned long long)len);
    } else if (e2 && memcmp(e2, "_SM_", 4) == 0) {
        t = (const uint8_t *)(uintptr_t)rd32(e2 + 0x18);
        len = rd16(e2 + 0x16);
        say("smbios: entry=2 version=%u.%u table=0x%llx len=%llu structures=%u\n", e2[6], e2[7],
            (unsigned long long)(uintptr_t)t, (unsigned long long)len, rd16(e2 + 0x1c));
    } else {
        say("smbios: none\n");
        return;
    }
    if (!t || !len || len > (1u << 20)) {
        say("smbios: table pointer or length invalid\n");
        return;
    }
    const uint8_t *p = t, *end = t + len;
    char a[65], b[65], c[65];
    while (p + 4 <= end && p[1] >= 4) {
        const uint8_t *q = p + p[1];
        while (q + 1 < end && !(q[0] == 0 && q[1] == 0))
            q++;
        uint8_t type = p[0], n = p[1];
        if (type == 0 && n >= 9)
            say("smbios_bios: vendor=%s version=%s date=%s\n", sm_str(p, end, p[4], a, sizeof a),
                sm_str(p, end, p[5], b, sizeof b), sm_str(p, end, p[8], c, sizeof c));
        if (type == 1 && n >= 7)
            say("smbios_system: manufacturer=%s product=%s version=%s\n", sm_str(p, end, p[4], a, sizeof a),
                sm_str(p, end, p[5], b, sizeof b), sm_str(p, end, p[6], c, sizeof c));
        if (type == 2 && n >= 7)
            say("smbios_board: manufacturer=%s product=%s version=%s\n", sm_str(p, end, p[4], a, sizeof a),
                sm_str(p, end, p[5], b, sizeof b), sm_str(p, end, p[6], c, sizeof c));
        if (type == 127)
            break;
        p = q + 2;
    }
}

/* ---- PCI: configuration mechanism #1, reads only ---- */
static uint32_t pci_rd(uint32_t bus, uint32_t dev, uint32_t fn, uint32_t off)
{
    uint32_t v, a = 0x80000000u | bus << 16 | dev << 11 | fn << 8 | (off & 0xfc);
    __asm__ volatile("outl %0, %w1" ::"a"(a), "Nd"((uint16_t)0xcf8));
    __asm__ volatile("inl %w1, %0" : "=a"(v) : "Nd"((uint16_t)0xcfc));
    return v;
}

static const char *pci_kind(uint32_t cls)
{
    switch (cls >> 8) {
    case 0x0101: return "storage-ide";
    case 0x0104: return "storage-raid";
    case 0x0106: return "storage-sata";
    case 0x0108: return "storage-nvme";
    case 0x0200: return "net-ethernet";
    case 0x0280: return "net-other";
    case 0x0300: return "display-vga";
    case 0x0380: return "display-other";
    case 0x0403: return "audio";
    case 0x0600: return "host-bridge";
    case 0x0601: return "isa-bridge";
    case 0x0604: return "pci-bridge";
    case 0x0880: return "system-other";
    case 0x0c03: return (cls & 0xff) == 0x30 ? "usb-xhci" : "usb";
    case 0x0c05: return "smbus";
    case 0x0c80: return "serial-bus-other";
    case 0x0d11: return "bluetooth";
    case 0x1180: return "signal-processing";
    }
    return "other";
}

static void pci_scan(void)
{
    unsigned found = 0;
    for (uint32_t bus = 0; bus < 256; bus++)
        for (uint32_t dev = 0; dev < 32; dev++) {
            if ((pci_rd(bus, dev, 0, 0) & 0xffff) == 0xffff)
                continue;
            uint32_t nfn = (pci_rd(bus, dev, 0, 0x0c) >> 16 & 0x80) ? 8 : 1;
            for (uint32_t fn = 0; fn < nfn; fn++) {
                uint32_t id = pci_rd(bus, dev, fn, 0);
                if ((id & 0xffff) == 0xffff)
                    continue;
                uint32_t cr = pci_rd(bus, dev, fn, 0x08), hdr = pci_rd(bus, dev, fn, 0x0c) >> 16 & 0x7f;
                uint32_t cls = cr >> 8, sub = hdr == 0 ? pci_rd(bus, dev, fn, 0x2c) : 0;
                found++;
                if (hdr == 1) {
                    uint32_t bn = pci_rd(bus, dev, fn, 0x18);
                    say("pci: %02x:%02x.%u %04x:%04x rev=%02x class=%06x hdr=1 secondary=%02x subordinate=%02x %s\n",
                        bus, dev, fn, id & 0xffff, id >> 16, cr & 0xff, cls, bn >> 8 & 0xff, bn >> 16 & 0xff,
                        pci_kind(cls));
                } else {
                    say("pci: %02x:%02x.%u %04x:%04x rev=%02x class=%06x hdr=%u sub=%04x:%04x %s\n", bus, dev, fn,
                        id & 0xffff, id >> 16, cr & 0xff, cls, hdr, sub & 0xffff, sub >> 16, pci_kind(cls));
                }
            }
        }
    say("pci_functions: %u\n", found);
}

/* ---- GOP modes and whole-disk Block I/O devices ---- */
static void gop_list(EFI_BOOT_SERVICES *bs)
{
    static const EFI_GUID guid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID_INIT;
    EFI_HANDLE *h = 0;
    uint64_t n = 0;
    if (bs->LocateHandleBuffer(ByProtocol, &guid, 0, &n, &h) != EFI_SUCCESS) {
        say("gop: none\n");
        return;
    }
    for (uint64_t i = 0; i < n; i++) {
        EFI_GRAPHICS_OUTPUT_PROTOCOL *g = 0;
        if (bs->HandleProtocol(h[i], &guid, (void **)&g) != EFI_SUCCESS || !g || !g->Mode || !g->Mode->Info)
            continue;
        const EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE *m = g->Mode;
        say("gop %llu: mode=%u/%u %ux%u format=%u stride=%u fb=0x%llx fb_bytes=%llu\n", (unsigned long long)i,
            m->Mode, m->MaxMode, m->Info->HorizontalResolution, m->Info->VerticalResolution, m->Info->PixelFormat,
            m->Info->PixelsPerScanLine, (unsigned long long)m->FrameBufferBase,
            (unsigned long long)m->FrameBufferSize);
    }
    bs->FreePool(h);
}

static void block_list(EFI_BOOT_SERVICES *bs)
{
    static const EFI_GUID guid = EFI_BLOCK_IO_PROTOCOL_GUID_INIT;
    EFI_HANDLE *h = 0;
    uint64_t n = 0, disks = 0, parts = 0;
    if (bs->LocateHandleBuffer(ByProtocol, &guid, 0, &n, &h) != EFI_SUCCESS) {
        say("block: none\n");
        return;
    }
    for (uint64_t i = 0; i < n; i++) {
        EFI_BLOCK_IO_PROTOCOL *b = 0;
        if (bs->HandleProtocol(h[i], &guid, (void **)&b) != EFI_SUCCESS || !b || !b->Media)
            continue;
        const EFI_BLOCK_IO_MEDIA *m = b->Media;
        if (m->LogicalPartition) {
            parts++;
            continue;
        }
        uint64_t blocks = m->MediaPresent ? m->LastBlock + 1 : 0;
        say("block %llu: disk removable=%u present=%u read_only=%u block_bytes=%u blocks=%llu mib=%llu\n",
            (unsigned long long)disks++, m->RemovableMedia, m->MediaPresent, m->ReadOnly, m->BlockSize,
            (unsigned long long)blocks, (unsigned long long)(blocks * m->BlockSize >> 20));
    }
    say("block_devices: disks=%llu partitions=%llu\n", (unsigned long long)disks, (unsigned long long)parts);
    bs->FreePool(h);
}

void diag_x86_devices(EFI_SYSTEM_TABLE *st)
{
    smbios(st);
    pci_scan();
    gop_list(st->BootServices);
    block_list(st->BootServices);
}
