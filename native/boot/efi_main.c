/* efi_main.c -- minimal AIENOS UEFI entry stub for the C kernel core.
 *
 * Loads nothing and checks nothing: the image already contains the kernel.
 * It prints the pre-exit report on ConOut, captures the firmware facts the
 * kernel needs (EL, TTBR0/SCTLR of the firmware regime, RSDP, counter), takes
 * the final memory map, leaves boot services (retrying when the map key goes
 * stale) and jumps to ck_kernel_entry with a handoff in the image's BSS.
 * The full loader (signature checks, A/B slots, BootNext, rollback) lives in
 * the Rust aienos-boot crate and is parked for the C path; see README.md. */
#include "efi.h"
#include "../kernel/arch/arch.h"
#include "../kernel/core/ck_internal.h"

/* TEST-ONLY (AIENOS_CK_SCREEN negative control, native/kernel/Makefile
 * CK_TEST_STALE_HANDOFF=2): hand the kernel a CHANDOF2 magic. Never in a
 * hardware staging image. */
#if defined(CK_TEST_STALE_HANDOFF) && defined(CK_HARDWARE_STAGING)
#error "CK_TEST_STALE_HANDOFF is TEST-only and cannot be combined with CK_HARDWARE_STAGING"
#endif

#define MAP_BYTES (64u << 10)
#define EXIT_TRIES 8

extern char __image_base[], __image_end[];

static uint64_t map_buf[MAP_BYTES / 8];
static struct ck_handoff handoff;
static EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *conout;

int ck_boot_model_load(EFI_HANDLE image, EFI_SYSTEM_TABLE *st, struct ck_handoff *h);
void ck_boot_gop_find(EFI_SYSTEM_TABLE *st, struct ck_handoff *h);

static void efi_write(const char *s, size_t n)
{
    CHAR16 buf[130];
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '\n')
            buf[k++] = '\r';
        buf[k++] = (uint8_t)s[i];
        if (k >= 128) {
            buf[k] = 0;
            conout->OutputString(conout, buf);
            k = 0;
        }
    }
    if (k) {
        buf[k] = 0;
        conout->OutputString(conout, buf);
    }
}

static int guid_eq(const EFI_GUID *a, const EFI_GUID *b)
{
    return memcmp(a, b, sizeof *a) == 0;
}

static void vendor_print(const CHAR16 *v)
{
    char b[80];
    size_t i = 0;
    for (; v && v[i] && i < sizeof b - 1; i++)
        b[i] = v[i] < 0x80 ? (char)v[i] : '?';
    b[i] = 0;
    ck_printf("firmware_vendor: %s\n", b);
}

EFI_STATUS efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    struct ck_handoff *h = &handoff;
    unsigned el = ck_current_el();
    h->magic = CK_HANDOFF_MAGIC;
    h->firmware_el = el;
    h->uefi_entry_ticks = ck_rd(cntpct_el0);
    h->counter_freq_hz = ck_rd(cntfrq_el0);
    if (el == 2) {
        h->firmware_ttbr0 = ck_rd(ttbr0_el2);
        h->firmware_sctlr = ck_rd(sctlr_el2);
    } else {
        h->firmware_ttbr0 = ck_rd(ttbr0_el1);
        h->firmware_sctlr = ck_rd(sctlr_el1);
    }
    h->image_base = (uint64_t)(uintptr_t)__image_base;
    h->image_end = (uint64_t)(uintptr_t)__image_end;
    h->commit = ck_commit();
    h->memory_map = (uint64_t)(uintptr_t)map_buf;

    conout = st->ConOut;
    if (conout)
        ck_console_set_efi(efi_write);
    ck_set_stage("firmware_entry");
    if (st->BootServices->SetWatchdogTimer)
        st->BootServices->SetWatchdogTimer(0, 0, 0, 0);

    static const EFI_GUID acpi20 = EFI_ACPI_20_TABLE_GUID_INIT;
    for (uint64_t i = 0; i < st->NumberOfTableEntries; i++)
        if (guid_eq(&st->ConfigurationTable[i].VendorGuid, &acpi20))
            h->rsdp = (uint64_t)(uintptr_t)st->ConfigurationTable[i].VendorTable;

    /* SPCR now, so a panic right after ExitBootServices can still print. */
    struct ck_spcr spcr = {0};
    int uart_ok = -1;
    const void *t = h->rsdp ? ck_acpi_lookup(h->rsdp, "SPCR") : 0;
    if (t && ck_spcr_parse(t, &spcr) == 0)
        uart_ok = ck_console_set_uart(&spcr);

    ck_puts("\n");
    ck_report_header("pre_exit");
    /* The GOP framebuffer for the kernel's screen console (efi_gop.c, CHANDOF3). */
    ck_boot_gop_find(st, h);
#ifdef CK_TEST_STALE_HANDOFF
    ck_puts("handoff: TEST-ONLY stale handoff image: the kernel gets a CHANDOF2 record; never counts toward a PASS\n");
#endif
    /* The yardstick model from the boot disk, while the firmware drivers are
     * still up (efi_model.c). Absent map: boot continues without a model. */
    ck_boot_model_load(image, st, h);
    ck_puts("kernel_impl: c (native/kernel, Lane 18)\n");
    vendor_print(st->FirmwareVendor);
    ck_printf("firmware_revision: 0x%x\n", st->FirmwareRevision);
    ck_printf("firmware_el: EL%u\n", el);
    ck_printf("counter_frequency_hz: %llu\n", (unsigned long long)h->counter_freq_hz);
    ck_printf("acpi_rsdp: 0x%llx\n", (unsigned long long)h->rsdp);
    if (uart_ok == 0)
        ck_printf("uart: %s spcr type=0x%x base=0x%llx\n", ck_console_uart_name(),
                  spcr.interface_type, (unsigned long long)spcr.base);
    else
        ck_puts("uart: unavailable (no usable SPCR)\n");
    ck_printf("image: 0x%llx-0x%llx\n", (unsigned long long)h->image_base,
              (unsigned long long)h->image_end);
    ck_puts("exiting firmware boot services\n");
    ck_set_stage("exit_boot_services");

    EFI_BOOT_SERVICES *bs = st->BootServices;
    EFI_STATUS s = EFI_INVALID_PARAMETER;
    for (unsigned tries = 1; tries <= EXIT_TRIES; tries++) {
        uint64_t size = sizeof map_buf, key = 0, dsize = 0;
        uint32_t dver = 0;
        s = bs->GetMemoryMap(&size, (EFI_MEMORY_DESCRIPTOR *)map_buf, &key, &dsize, &dver);
        if (s != EFI_SUCCESS) {
            ck_printf("exit_boot_services: GetMemoryMap status=0x%llx size=%llu\n",
                      (unsigned long long)s, (unsigned long long)size);
            return s;
        }
        h->map_size = size;
        h->desc_size = dsize;
        h->desc_version = dver;
        h->exit_attempts = tries;
        /* No ConOut between here and ExitBootServices: printing may allocate
         * and change the map key. */
        s = bs->ExitBootServices(image, key);
        if (s == EFI_SUCCESS)
            break;
    }
    if (s != EFI_SUCCESS) {
        ck_printf("exit_boot_services: failed status=0x%llx after %u tries\n",
                  (unsigned long long)s, EXIT_TRIES);
        return s;
    }
    /* Boot services are gone: ConOut too. */
    ck_console_set_efi(0);
    ck_set_stage("kernel_entry");
#ifdef CK_TEST_STALE_HANDOFF
    h->magic = CK_HANDOFF_MAGIC_V2;
#endif
    ck_kernel_entry(h);
}
