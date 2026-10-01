/* report.c -- report headers, panic, fault report, PSCI reset.
 * Report keys follow the Rust handoff (report_version, aienos_commit,
 * report_kind, last_stage) so the same scripts read both kernels. */
#include "arch.h"
#include "ck_internal.h"

#ifndef AIENOS_COMMIT
#define AIENOS_COMMIT "unknown"
#endif

static const char *stage = "uefi_entry";
static int psci_hvc;
static int in_fatal;

const char *ck_commit(void) { return AIENOS_COMMIT; }
uint32_t ck_boot_count_hint(void) { return 0; }
void ck_set_stage(const char *name) { stage = name; }
const char *ck_stage_name(void) { return stage; }

void ck_report_header(const char *kind)
{
    ck_printf("report_version: 1\naienos_commit: %s\nreport_kind: %s\nlast_stage: %s\n",
              ck_commit(), kind, stage);
}

void ck_psci_configure(const void *fadt)
{
    uint16_t flags = 0;
    if (fadt && ck_fadt_arm_boot_arch(fadt, &flags) == 0)
        psci_hvc = (flags & 2) != 0;
}

static void psci_call(uint64_t fn)
{
    register uint64_t x0 __asm__("x0") = fn;
    /* HVC would land in our own EL2 vectors while still at EL2. */
    if (psci_hvc && ck_current_el() == 1)
        __asm__ volatile("hvc #0" : "+r"(x0)::"x1", "x2", "x3", "memory");
    else
        __asm__ volatile("smc #0" : "+r"(x0)::"x1", "x2", "x3", "memory");
}

void ck_reset(void)
{
    __asm__ volatile("msr daifset, #0xf" ::: "memory");
    ck_mb();
    psci_call(0x84000009u); /* PSCI SYSTEM_RESET */
    psci_call(0x84000008u); /* SYSTEM_OFF if reset was refused */
    for (;;)
        __asm__ volatile("wfi");
}

void ck_mb(void)
{
    __asm__ volatile("dsb sy" ::: "memory");
}

void ck_panic(const char *fmt, ...)
{
    __asm__ volatile("msr daifset, #0xf" ::: "memory");
    if (in_fatal++)
        ck_reset();
    ck_puts("\n");
    ck_report_header("panic");
    ck_puts("panic: ");
    va_list ap;
    va_start(ap, fmt);
    ck_vprintf(fmt, ap);
    va_end(ap);
    ck_puts("\n");
    ck_reset();
}

void ck_fault_report(const char *what, uint64_t esr, uint64_t far, uint64_t elr, unsigned el)
{
    if (in_fatal++)
        ck_reset();
    ck_puts("\n");
    ck_report_header("fault");
    ck_printf("fault: vector=%s el=%u esr=0x%llx ec=0x%llx far=0x%llx elr=0x%llx\n", what, el,
              (unsigned long long)esr, (unsigned long long)((esr >> 26) & 0x3f),
              (unsigned long long)far, (unsigned long long)elr);
    ck_reset();
}
