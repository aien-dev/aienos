/* efi_x86.c -- UEFI stub of AIENOS-IMAC-KERNEL-0 (x86_64): the same job as
 * native/boot/efi_main.c does for the AArch64 kernel, on the same CHANDOF3
 * record (handoff.h), so core/handoff_check.c checks it unchanged.
 *
 * It finds the ACPI 2.0 RSDP and the GOP framebuffer (boot/efi_gop.c), takes
 * the final memory map, leaves boot services (retrying when the map key goes
 * stale) and jumps to ck_x86_kernel_entry. It never calls a runtime service.
 * x86 meaning of the AArch64-named fields: firmware_el = CPL (0),
 * firmware_ttbr0 = CR3, firmware_sctlr = CR0, uefi_entry_ticks = TSC,
 * counter_freq_hz = 0 (the kernel measures the TSC itself). */
#include "../../boot/efi.h"
#include "../core/ck_internal.h"
#include "x86.h"

#define MAP_BYTES (64u << 10)
#define EXIT_TRIES 8

extern char __image_base[], __image_end[];
__attribute__((noreturn)) void ck_x86_kernel_entry(struct ck_handoff *h);
void ck_boot_gop_find(EFI_SYSTEM_TABLE *st, struct ck_handoff *h);

static uint64_t map_buf[MAP_BYTES / 8];
static struct ck_handoff handoff;

static int guid_eq(const EFI_GUID *a, const EFI_GUID *b)
{
    return memcmp(a, b, sizeof *a) == 0;
}

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    struct ck_handoff *h = &handoff;
    uint16_t cs;
    __asm__ volatile("mov %%cs, %0" : "=r"(cs));
    h->magic = CK_HANDOFF_MAGIC;
    h->firmware_el = cs & 3u;
    h->uefi_entry_ticks = ck_rdtsc();
    h->firmware_ttbr0 = ck_rd_cr3();
    h->firmware_sctlr = ck_rd_cr0();
    h->image_base = (uint64_t)(uintptr_t)__image_base;
    h->image_end = (uint64_t)(uintptr_t)__image_end;
    h->commit = ck_commit();
    h->memory_map = (uint64_t)(uintptr_t)map_buf;

    ck_x86_com1_probe();
    if (st->BootServices->SetWatchdogTimer)
        st->BootServices->SetWatchdogTimer(0, 0, 0, 0);
    static const EFI_GUID acpi20 = EFI_ACPI_20_TABLE_GUID_INIT;
    for (uint64_t i = 0; i < st->NumberOfTableEntries; i++)
        if (guid_eq(&st->ConfigurationTable[i].VendorGuid, &acpi20))
            h->rsdp = (uint64_t)(uintptr_t)st->ConfigurationTable[i].VendorTable;

    ck_puts("AIENOS-IMAC-KERNEL-0\n");
    ck_printf("report_kind: pre_exit\naienos_commit: %s\n", ck_commit());
    ck_puts("kernel_impl: c (native/kernel/x86, x86_64)\n");
    char v[80];
    size_t n = 0;
    for (; st->FirmwareVendor && st->FirmwareVendor[n] && n < sizeof v - 1; n++)
        v[n] = st->FirmwareVendor[n] < 0x80 ? (char)st->FirmwareVendor[n] : '?';
    v[n] = 0;
    ck_printf("firmware_vendor: %s\nfirmware_revision: 0x%x\n", v, st->FirmwareRevision);
    ck_printf("firmware_cpl: %u\n", h->firmware_el);
    ck_boot_gop_find(st, h);
    ck_printf("acpi_rsdp: 0x%llx\n", (unsigned long long)h->rsdp);
    ck_printf("image: 0x%llx-0x%llx\n", (unsigned long long)h->image_base, (unsigned long long)h->image_end);
    ck_puts("exiting firmware boot services\n");

    EFI_BOOT_SERVICES *bs = st->BootServices;
    EFI_STATUS s = EFI_INVALID_PARAMETER;
    for (unsigned tries = 1; tries <= EXIT_TRIES; tries++) {
        uint64_t size = sizeof map_buf, key = 0, dsize = 0;
        uint32_t dver = 0;
        s = bs->GetMemoryMap(&size, (EFI_MEMORY_DESCRIPTOR *)map_buf, &key, &dsize, &dver);
        if (s != EFI_SUCCESS) {
            ck_printf("exit_boot_services: GetMemoryMap status=0x%llx size=%llu\n", (unsigned long long)s,
                      (unsigned long long)size);
            return s;
        }
        h->map_size = size;
        h->desc_size = dsize;
        h->desc_version = dver;
        h->exit_attempts = tries;
        s = bs->ExitBootServices(image, key);
        if (s == EFI_SUCCESS)
            break;
    }
    if (s != EFI_SUCCESS) {
        ck_printf("exit_boot_services: failed status=0x%llx after %u tries\n", (unsigned long long)s,
                  EXIT_TRIES);
        return s;
    }
    ck_x86_kernel_entry(h);
}
