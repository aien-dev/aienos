/* smp.c -- secondary core bring-up through PSCI CPU_ON (CK gate SMP).
 *
 * The boot core reads the MPIDR of every enabled or online-capable core from
 * the ACPI MADT GICC entries (the firmware's own CPU list; QEMU virt with
 * AAVMF gives ACPI, not a device tree, to this kernel), then for each
 * secondary core: takes a 16 KiB stack from the frame allocator, fills a
 * per-core context (our page-table root, MAIR, TCR, SCTLR, stack top), cleans
 * it to the point of coherency (the core reads it with its MMU off) and calls
 * PSCI CPU_ON (SMC64 function 0xC4000003) on the conduit the FADT names
 * (report.c ck_psci_call). The core starts in arch/smp_entry.S at the
 * firmware's EL (QEMU 8.2.2 target/arm/tcg/psci.c:144 starts it at EL2 when
 * EL2 exists, else EL1), goes through the same EL2 -> EL1h path as the boot
 * core (ck_enter_el1, ADR 0009) or the EL1 table switch (ck_switch_el1), and
 * lands in ck_smp_secondary_main at EL1 with the MMU on our tables. There it
 * records what it sees (MPIDR, EL, SCTLR, TTBR0, SP), publishes "checked in"
 * with a release store and parks in WFE with all interrupts masked.
 *
 * The boot core waits at most CK_SMP_TIMEOUT_US for every started core and
 * prints one line per core and a summary. It never panics: a core that never
 * checks in, a PSCI error code, a duplicate or missing MPIDR, or a core that
 * reports the wrong EL/MMU/tables/stack is printed and the summary says
 * result=FAIL. scripts/qemu_ck_smp_test.sh judges the lines itself.
 *
 * TEST-ONLY mutation: a build with -DCK_TEST_SMP_SKIP_CPU=1 (make
 * CK_TEST_SMP_SKIP_CPU=1, own OUT, refused with CK_HARDWARE_STAGING) never
 * calls CPU_ON for the last secondary core in the MADT but still waits for
 * it, so the gate must FAIL on that image. QEMU qualifies nothing physical. */
#include "arch.h"
#include "ck_internal.h"

#if defined(CK_TEST_SMP_SKIP_CPU) && defined(CK_HARDWARE_STAGING)
#error "CK_TEST_SMP_SKIP_CPU (TEST-only SMP mutation) cannot be combined with CK_HARDWARE_STAGING"
#endif

#define CK_SMP_MAX 16u
#define CK_SMP_STACK_PAGES 4u
#define CK_SMP_TIMEOUT_US 5000000ull
#define PSCI_VERSION 0x84000000u
#define PSCI_CPU_ON_64 0xC4000003u
#define TTBR_BADDR_MASK 0x0000fffffffffffeull

enum { SMP_IDLE = 0, SMP_ON_CALLED = 1, SMP_CHECKED_IN = 2 };

/* Field offsets 0..40 are read by arch/smp_entry.S with the MMU off. */
struct ck_smp_cpu {
    uint64_t root, mair, tcr, sctlr, sp; /* 0, 8, 16, 24, 32 */
    uint64_t target;                     /* 40: MPIDR from the MADT */
    uint64_t state;                      /* 48: SMP_* (atomic) */
    uint64_t seen_mpidr, seen_el, seen_sctlr, seen_ttbr0, seen_sp;
    uint64_t stack_lo, stack_hi;
} __attribute__((aligned(64)));
_Static_assert(__builtin_offsetof(struct ck_smp_cpu, sp) == 32, "smp_entry.S offsets");
_Static_assert(__builtin_offsetof(struct ck_smp_cpu, state) == 48, "smp_entry.S offsets");

static struct ck_smp_cpu cpus[CK_SMP_MAX];

/* arch/smp_entry.S: PSCI CPU_ON entry point, x0 = &cpus[i]. */
extern char ck_smp_entry[];
void ck_smp_secondary_main(void *arg);

/* Runs on the secondary core at EL1, MMU on, its own stack, DAIF masked. */
__attribute__((noreturn)) void ck_smp_secondary_main(void *arg)
{
    struct ck_smp_cpu *c = arg;
    uint64_t sp;
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    c->seen_mpidr = ck_rd(mpidr_el1) & CK_MPIDR_AFF_MASK;
    c->seen_el = ck_current_el();
    c->seen_sctlr = ck_rd(sctlr_el1);
    c->seen_ttbr0 = ck_rd(ttbr0_el1) & TTBR_BADDR_MASK;
    c->seen_sp = sp;
    __atomic_store_n(&c->state, (uint64_t)SMP_CHECKED_IN, __ATOMIC_RELEASE);
    __asm__ volatile("dsb ish\n\tsev" ::: "memory");
    for (;;)
        __asm__ volatile("wfe" ::: "memory");
}

static void clean_to_poc(const void *p, size_t len)
{
    uint64_t line = 4ull << ((ck_rd(ctr_el0) >> 16) & 0xf);
    uint64_t a = (uint64_t)(uintptr_t)p & ~(line - 1), end = (uint64_t)(uintptr_t)p + len;
    for (; a < end; a += line)
        __asm__ volatile("dc cvac, %0" ::"r"(a) : "memory");
    __asm__ volatile("dsb sy" ::: "memory");
}

static const char *psci_err(int64_t rc)
{
    switch (rc) {
    case 0: return "SUCCESS";
    case -1: return "NOT_SUPPORTED";
    case -2: return "INVALID_PARAMETERS";
    case -3: return "DENIED";
    case -4: return "ALREADY_ON";
    case -5: return "ON_PENDING";
    case -6: return "INTERNAL_FAILURE";
    case -9: return "INVALID_ADDRESS";
    default: return "UNKNOWN";
    }
}

void ck_smp_run(void)
{
    ck_set_stage("smp");
    uint64_t self = ck_rd(mpidr_el1) & CK_MPIDR_AFF_MASK;
    const struct ck_mm_report *mm = ck_mm_report();
    int fail = 0;
#ifdef CK_TEST_SMP_SKIP_CPU
    ck_puts("smp: TEST-ONLY SMP mutation build: CPU_ON is skipped for one core; this image never counts toward a PASS\n");
#endif

    const void *madt = ck_acpi_find("APIC");
    uint64_t mp[CK_SMP_MAX];
    unsigned n = 0;
    int prc = madt ? ck_madt_mpidrs(madt, mp, CK_SMP_MAX, &n) : -1;
    int64_t ver = ck_psci_call(PSCI_VERSION, 0, 0, 0);
    unsigned vmaj = ver < 0 ? 0 : (unsigned)((uint64_t)ver >> 16) & 0x7fff;
    unsigned vmin = ver < 0 ? 0 : (unsigned)((uint64_t)ver & 0xffff);
    ck_printf("smp: boot_mpidr=0x%llx madt_cpus=%u conduit=%s psci_version=%u.%u\n",
              (unsigned long long)self, n, ck_psci_conduit(), vmaj, vmin);
    if (prc != 0) {
        ck_printf("smp: FAIL madt %s (rc=%d, %u cores, max %u)\n",
                  !madt ? "absent" : prc == -2 ? "lists more cores than supported" : "malformed", prc,
                  n, CK_SMP_MAX);
        ck_printf("smp: cpus=%u checked_in=0 psci_errors=0 distinct_mpidrs=0 wait_us=0 result=FAIL\n", n);
        return;
    }
    if (ver < 0 || (vmaj == 0 && vmin < 2)) {
        ck_printf("smp: FAIL psci version %lld has no 64-bit CPU_ON\n", (long long)ver);
        fail = 1;
    }

    /* Distinct MPIDRs, and the boot core among them. */
    unsigned distinct = 0, boot_listed = 0;
    for (unsigned i = 0; i < n; i++) {
        unsigned dup = 0;
        for (unsigned j = 0; j < i; j++)
            if (mp[j] == mp[i])
                dup = 1;
        if (dup) {
            ck_printf("smp: FAIL duplicate mpidr=0x%llx in the MADT\n", (unsigned long long)mp[i]);
            fail = 1;
        } else {
            distinct++;
        }
        if (mp[i] == self)
            boot_listed = 1;
    }
    if (!boot_listed) {
        ck_printf("smp: FAIL boot core mpidr=0x%llx missing from the MADT\n", (unsigned long long)self);
        fail = 1;
    }

    /* Start every secondary core. */
    unsigned started = 0, psci_errors = 0, last = n;
    for (unsigned i = 0; i < n; i++)
        if (mp[i] != self)
            last = i;
    for (unsigned i = 0; i < n && !fail; i++) {
        struct ck_smp_cpu *c = &cpus[i];
        if (mp[i] == self)
            continue;
        uint64_t pa = 0;
        if (ck_mm_frames_alloc(CK_SMP_STACK_PAGES, &pa) || !ck_mm_mapped(pa, CK_SMP_STACK_PAGES * 4096ull)) {
            ck_printf("smp_cpu_on: target=0x%llx stack=unavailable\n", (unsigned long long)mp[i]);
            fail = 1;
            continue;
        }
        memset(c, 0, sizeof *c);
        c->root = mm->root;
        c->mair = ck_mm_mair();
        c->tcr = ck_mm_tcr();
        c->sctlr = ck_mm_sctlr();
        c->stack_lo = pa;
        c->stack_hi = pa + CK_SMP_STACK_PAGES * 4096ull;
        c->sp = c->stack_hi;
        c->target = mp[i];
        c->state = SMP_ON_CALLED;
        clean_to_poc(c, sizeof *c);
#ifdef CK_TEST_SMP_SKIP_CPU
        if (i == last) {
            ck_printf("smp_cpu_on: target=0x%llx psci_rc=SKIPPED (TEST-ONLY SMP mutation)\n",
                      (unsigned long long)mp[i]);
            started++;
            continue;
        }
#endif
        int64_t rc = ck_psci_call(PSCI_CPU_ON_64, mp[i], (uint64_t)(uintptr_t)ck_smp_entry,
                                  (uint64_t)(uintptr_t)c);
        ck_printf("smp_cpu_on: target=0x%llx psci_rc=%d (%s)\n", (unsigned long long)mp[i], (int)rc,
                  psci_err(rc));
        if (rc != 0) {
            psci_errors++;
            c->state = SMP_IDLE;
            continue;
        }
        started++;
    }
    (void)last;

    /* Bounded wait for every started core. */
    uint64_t t0 = ck_time_us(), waited = 0;
    for (;;) {
        unsigned pending = 0;
        for (unsigned i = 0; i < n; i++)
            if (mp[i] != self && __atomic_load_n(&cpus[i].state, __ATOMIC_ACQUIRE) == SMP_ON_CALLED)
                pending++;
        waited = ck_time_us() - t0;
        if (!pending || waited >= CK_SMP_TIMEOUT_US)
            break;
        ck_udelay(100);
    }

    /* One line per secondary core, then the summary. */
    unsigned checked = 1; /* the boot core */
    for (unsigned i = 0; i < n; i++) {
        struct ck_smp_cpu *c = &cpus[i];
        if (mp[i] == self)
            continue;
        if (__atomic_load_n(&c->state, __ATOMIC_ACQUIRE) != SMP_CHECKED_IN) {
            ck_printf("smp_cpu: target=0x%llx checked_in=no\n", (unsigned long long)mp[i]);
            fail = 1;
            continue;
        }
        int el_ok = c->seen_el == 1, mmu_ok = (c->seen_sctlr & 1) != 0;
        int tt_ok = c->seen_ttbr0 == mm->root;
        int sp_ok = c->seen_sp > c->stack_lo && c->seen_sp <= c->stack_hi;
        int id_ok = c->seen_mpidr == mp[i];
        ck_printf("smp_cpu: target=0x%llx checked_in=yes seen_mpidr=0x%llx el=%u mmu=%s ttbr0_match=%s "
                  "stack_ok=%s parked=wfe\n",
                  (unsigned long long)mp[i], (unsigned long long)c->seen_mpidr, (unsigned)c->seen_el,
                  mmu_ok ? "on" : "off", tt_ok ? "yes" : "no", sp_ok ? "yes" : "no");
        if (!(el_ok && mmu_ok && tt_ok && sp_ok && id_ok))
            fail = 1;
        checked++;
    }
    if (checked != n || psci_errors)
        fail = 1;
    ck_printf("smp: cpus=%u started=%u checked_in=%u psci_errors=%u distinct_mpidrs=%u wait_us=%llu result=%s\n", n,
              started + 1, checked, psci_errors, distinct, (unsigned long long)waited, fail ? "FAIL" : "ok");
}
