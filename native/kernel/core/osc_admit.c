/* osc_admit.c -- kernel policy and reporting for OSC unit admission.
 *
 * Policy (OSC_UNIT_ARTIFACT.md section 8.1), all local to this build:
 *   - ordinary build: release mode, no TEST anchor, no OWNER anchor. A TEST
 *     unit is refused TEST_SIGNER_IN_RELEASE, an OWNER unit UNTRUSTED_SIGNER
 *     (OWNER anchors are not provisioned until TRUST-1).
 *   - qualification build (CK_SEED0B_TEST_ANCHOR=1): qualification mode with
 *     the throwaway TEST key of the conformance vectors as the only TEST
 *     anchor, announced TEST ONLY. OWNER anchors stay empty.
 *   - capability domain 1 only (kernel IPC table, 32-bit generations); the
 *     kernel holds no resource state at admission, so any pinned generation is
 *     STALE (the lookup finds nothing). No reservation: launch is a later cut.
 * QEMU qualifies nothing physical. */
#include "ck_internal.h"
#include "osc_admit.h"
#include "osc_unit.h"
#ifdef CK_SEED0B_TEST_ANCHOR
#include "osc_unit_test_anchor.h"
#endif

static unsigned seen, accepted, refused, oversize, announced;
static struct osc_accept acc; /* ~5 KB: static, not on the kernel stack */

static int no_resource(void *ctx, unsigned domain, unsigned kind, uint32_t id, uint64_t *cur)
{
    (void)ctx; (void)domain; (void)kind; (void)id; (void)cur;
    return 1;
}

/* The Store and the native staging area hold at most 160 pages per artifact (= CK_ART_MAX_BYTES in
 * svc/artifact_store.h, 655,360 bytes; spec 8.2 step 16). */
#define OSC_STAGING_MAX (160u * 4096u)

static void hex(char *out, const uint8_t *b, size_t n)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[2 * n] = 0;
}

static void policy(struct osc_policy *p)
{
    memset(p, 0, sizeof *p);
    p->unit_formats = OSC_PROFILE_UNIT_FORMATS;
    p->abi_versions = OSC_PROFILE_ABI;
    p->cap_domains = 1u << 1;
    p->staging_max = OSC_STAGING_MAX;
    p->gen_lookup = no_resource;
#ifdef CK_SEED0B_TEST_ANCHOR
    static const uint8_t (*const ta)[32] = &osc_unit_test1_pk;
    p->release = 0;
    p->test_anchors = ta;
    p->n_test = 1;
#else
    p->release = 1;
#endif
}


#ifdef CK_OSC_LAUNCH_TEST
/* ======================================================================================================
 * C3-3a launch self-test (TEST ONLY, qualification build with CK_OSC_LAUNCH_TEST=1).
 * Runs a fixed script of launches over the admitted units the Store handed over and prints one
 * "osc_launch:" line each. QEMU (aarch64 virt), TEST signer, not physical.
 * ==================================================================================================== */
#include "osc_task.h"
#define LT_UNITS 4
#define LT_BYTES 8192
static struct {
    char name[48];
    uint8_t bytes[LT_BYTES];
    size_t len;
    struct osc_accept acc;
} lt_unit[LT_UNITS];
static unsigned lt_n;

static int lt_streq(const char *a, const char *b)
{
    size_t n = strlen(a);
    return n == strlen(b) && memcmp(a, b, n) == 0;
}

static void lt_save(const char *name, const uint8_t *b, size_t len)
{
    if (lt_n >= LT_UNITS || len > LT_BYTES)
        return;
    unsigned i = 0;
    while (name[i] && i < sizeof lt_unit[0].name - 1) {
        lt_unit[lt_n].name[i] = name[i];
        i++;
    }
    lt_unit[lt_n].name[i] = 0;
    memcpy(lt_unit[lt_n].bytes, b, len);
    lt_unit[lt_n].len = len;
    lt_unit[lt_n].acc = acc;
    lt_n++;
}

#define IN_PTR (1ull << 62) /* placeholders for the task's input and workspace windows */
#define WS_PTR (1ull << 63)
#define KERN_PTR (1ull << 61) /* an address in the kernel image (mapped EL1-only in the task address space) */
struct lt_step {
    const char *unit, *fn;
    unsigned nargs;
    uint64_t a[3];
    const char *in;
    int ws; /* 0 none, 1..2 which caller workspace */
    uint64_t cap;
};

extern void ck_osc_state_range(uint64_t *addr, uint64_t *len);
static uint8_t lt_ws_mem1[4 * 4096], lt_ws_mem2[4 * 4096], lt_ws_mem3[23 * 4096], lt_ws_mem4[33 * 4096]
    __attribute__((aligned(4096)));
static struct ck_osc_ws lt_ws[8] = { { lt_ws_mem1, 4 }, { lt_ws_mem2, 4 }, { lt_ws_mem3, 23 }, { lt_ws_mem4, 33 },
                                      { 0, 1 }, { lt_ws_mem1 + 8, 1 }, { 0, 1 }, { lt_ws_mem2, 4 } };
static unsigned lt_counts[5];

static void lt_run(const struct lt_step *s)
{
    for (unsigned u = 0; u < lt_n; u++) {
        if (!lt_streq(lt_unit[u].name, s->unit))
            continue;
        struct ck_osc_launch_req rq;
        memset(&rq, 0, sizeof rq);
        rq.name = s->fn;
        rq.name_len = strlen(s->fn);
        rq.nargs = s->nargs;
        rq.max_ticks = s->cap;
        for (unsigned i = 0; i < s->nargs; i++) {
            rq.args[i] = s->a[i];
            if (s->a[i] & IN_PTR)
                rq.args[i] = ck_osc_va_in() + (s->a[i] & 0xffffff);
            else if (s->a[i] & WS_PTR)
                rq.args[i] = ck_osc_va_ws() + (s->a[i] & 0xffffff);
            else if (s->a[i] & KERN_PTR)
                rq.args[i] = (uint64_t)(uintptr_t)&lt_counts;
        }
        if (s->in) {
            rq.in = (const uint8_t *)s->in;
            rq.in_len = strlen(s->in);
        }
        if (s->ws)
            rq.ws = &lt_ws[s->ws - 1];
        struct osc_result r;
        struct ck_osc_launch_info info;
        ck_osc_launch(lt_unit[u].bytes, lt_unit[u].len, &lt_unit[u].acc, &rq, &r, &info);
        char rs[96], as[80];
        ck_osc_result_str(&r, rs, sizeof rs);
        unsigned n = 0;
        as[0] = 0;
        for (unsigned i = 0; i < s->nargs && n < sizeof as - 24; i++) {
            uint64_t v = s->a[i];
            if (v & IN_PTR)
                n += (unsigned)ck_snprintf(as + n, sizeof as - n, "%sin+%u", i ? "," : "", (unsigned)(v & 0xffffff));
            else if (v & WS_PTR)
                n += (unsigned)ck_snprintf(as + n, sizeof as - n, "%sws+%u", i ? "," : "", (unsigned)(v & 0xffffff));
            else if (v & KERN_PTR)
                n += (unsigned)ck_snprintf(as + n, sizeof as - n, "%skernel", i ? "," : "");
            else
                n += (unsigned)ck_snprintf(as + n, sizeof as - n, "%s%llu", i ? "," : "", (unsigned long long)v);
        }
        ck_printf("osc_launch: %s %s(%s) -> %s ticks=%llu budget=%llu pages_mapped=%u page_tables_zeroed=%u slot_free=%u; "
                  "QEMU (aarch64 virt), TEST signer, not physical\n",
                  s->unit, s->fn, as, rs, (unsigned long long)r.ticks, (unsigned long long)info.budget,
                  info.pages_mapped, (unsigned)info.tables_zeroed, (unsigned)info.slot_free_after);
        lt_counts[r.cls]++;
        return;
    }
    ck_printf("osc_launch: %s %s -> NOT_RUN (unit was not admitted)\n", s->unit, s->fn);
}

static void lt_all(void)
{
    uint64_t sa, sl;
    ck_osc_state_range(&sa, &sl);
    lt_ws[6].mem = (uint8_t *)(uintptr_t)sa; /* a workspace aimed at the launcher's own state */
    lt_ws[6].pages = 1;
    memcpy(lt_ws_mem2 + 64, "Zeta", 5);       /* an input buffer that lies inside workspace 8 (index 7) */
    *(uint32_t *)(lt_ws_mem1 + 512) = 0xd65f03c0u; /* a valid `ret` in workspace 1, cell 64, for jump_ws */
    static const struct lt_step steps[] = {
        { "a01_valid_min.unit", "add", 2, { 1000000007, 998244353 }, 0, 0, 0 },
        { "a01_valid_min.unit", "add", 1, { 5 }, 0, 0, 0 },
        { "a01_valid_min.unit", "nosuch", 0, { 0 }, 0, 0, 0 },
        { "a01_valid_min.unit", "ADD", 2, { 1, 2 }, 0, 0, 0 },
        { "a01_valid_min.unit", "first_byte", 2, { IN_PTR, 4 }, "Zeta", 0, 0 },
        { "a01_valid_min.unit", "first_byte", 2, { 0x1000, 16 }, "Zeta", 0, 0 },
        { "l01_launch_fns.unit", "trap", 1, { 3 }, 0, 0, 0 },
        { "l01_launch_fns.unit", "trap", 1, { 14 }, 0, 0, 0 },
        { "l01_launch_fns.unit", "trap", 1, { 15 }, 0, 0, 0 },
        { "l01_launch_fns.unit", "bare_brk", 0, { 0 }, 0, 0, 0 },
        { "l01_launch_fns.unit", "spin", 0, { 0 }, 0, 0, 5 },
        { "a01_valid_min.unit", "add", 2, { 40, 2 }, 0, 0, 0 },
        { "l01_launch_fns.unit", "peek0", 0, { 0 }, 0, 0, 0 },
        { "a01_valid_min.unit", "add", 2, { 20, 22 }, 0, 0, 0 },
        { "l01_launch_fns.unit", "poke_rt", 0, { 0 }, 0, 0, 0 },
        { "l01_launch_fns.unit", "exec_stack", 0, { 0 }, 0, 0, 0 },
        { "l01_launch_fns.unit", "overflow", 0, { 0 }, 0, 0, 0 },
        { "a01_valid_min.unit", "add", 2, { 6, 36 }, 0, 0, 0 },
        { "l01_launch_fns.unit", "counter", 2, { WS_PTR, 1 }, 0, 1, 0 },
        { "l01_launch_fns.unit", "counter", 2, { WS_PTR, 1 }, 0, 1, 0 },
        { "l01_launch_fns.unit", "counter", 2, { WS_PTR, 1 }, 0, 1, 0 },
        { "l01_launch_fns.unit", "counter", 2, { WS_PTR, 1 }, 0, 2, 0 },
        { "l01_launch_fns.unit", "counter", 2, { WS_PTR | 4, 1 }, 0, 1, 0 },
        { "l01_launch_fns.unit", "counter", 2, { WS_PTR | 94200, 1 }, 0, 3, 0 },
        { "l01_launch_fns.unit", "counter", 2, { WS_PTR | 94200, 1 }, 0, 3, 0 },
        { "l01_launch_fns.unit", "counter", 2, { WS_PTR, 1 }, 0, 4, 0 },
        { "a06_valid_limits_at_max.unit", "add", 2, { 1, 2 }, 0, 0, 0 },
        { "l02_stack_over.unit", "peek0", 0, { 0 }, 0, 0, 0 },
        { "a01_valid_min.unit", "add", 2, { 3, 4 }, 0, 0, 0 },
        { "l01_launch_fns.unit", "peek_kernel", 1, { KERN_PTR }, 0, 0, 0 },
        { "a01_valid_min.unit", "add", 2, { 5, 6 }, 0, 0, 0 },
        { "l01_launch_fns.unit", "jump_ws", 2, { WS_PTR | 512, 1 }, 0, 1, 0 },
        { "a01_valid_min.unit", "add", 2, { 7, 8 }, 0, 0, 0 },
        { "l01_launch_fns.unit", "jump_in", 2, { IN_PTR, 4 }, "\xc0\x03\x5f\xd6", 0, 0 },
        { "a01_valid_min.unit", "add", 2, { 9, 10 }, 0, 0, 0 },
        { "l01_launch_fns.unit", "dirty", 0, { 0 }, 0, 0, 0 },
        { "l01_launch_fns.unit", "regs_or", 0, { 0 }, 0, 0, 0 },
        { "l01_launch_fns.unit", "touch_past", 2, { WS_PTR | 16376, 1 }, 0, 1, 0 },
        { "a01_valid_min.unit", "add", 2, { 11, 12 }, 0, 0, 0 },
        { "l01_launch_fns.unit", "counter", 2, { WS_PTR | 8, 1 }, 0, 5, 0 },
        { "l01_launch_fns.unit", "counter", 2, { WS_PTR | 16, 1 }, 0, 6, 0 },
        { "l01_launch_fns.unit", "counter", 2, { WS_PTR | 24, 1 }, 0, 7, 0 },
        { "l01_launch_fns.unit", "counter", 2, { WS_PTR | 32, 1 }, (const char *)(lt_ws_mem2 + 64), 8, 0 },
        { "a01_valid_min.unit", "add", 2, { 13, 14 }, 0, 0, 0 },
    };
    ck_printf("osc_launch_policy: units=%u code_max=%u stack_max=%u in_max=%u ws_max=%u pages; 1 tick = 10 ms; "
              "QEMU (aarch64 virt), TEST signer, not physical\n",
              lt_n, (unsigned)CK_OSC_CODE_MAX_BYTES, (unsigned)CK_OSC_STACK_MAX_BYTES, (unsigned)CK_OSC_IN_MAX_BYTES,
              (unsigned)OSC_WS_MAX_PAGES);
    for (unsigned i = 0; i < sizeof steps / sizeof steps[0]; i++)
        lt_run(&steps[i]);
    ck_printf("osc_launches: returned=%u trapped=%u refused=%u unknown=%u; QEMU (aarch64 virt), TEST signer, not "
              "physical\n",
              lt_counts[OSC_RES_RETURNED], lt_counts[OSC_RES_TRAPPED], lt_counts[OSC_RES_REFUSED],
              lt_counts[OSC_RES_UNKNOWN]);
}
#endif

int ck_osc_is_unit(const uint8_t *b, size_t len)
{
    return b && len >= 8 && memcmp(b, "OSCUNIT\0", 8) == 0;
}

unsigned ck_osc_candidate(const char *name, const uint8_t *b, size_t len)
{
    struct osc_policy p;
    policy(&p);
    if (!announced) {
        announced = 1;
#ifdef CK_SEED0B_TEST_ANCHOR
        ck_printf("osc_policy: mode=qualification test_anchors=1 (throwaway TEST key, TEST ONLY) owner_anchors=0 "
                  "domains=1 gen_width=32; QEMU, not physical\n");
#else
        ck_printf("osc_policy: mode=release test_anchors=0 owner_anchors=0 (none provisioned) "
                  "domains=1 gen_width=32; QEMU, not physical\n");
#endif
    }
    unsigned rc = osc_unit_admit(b, len, &p, &acc);
    seen++;
    if (rc == OSC_OK) {
        char d[65], i[65];
        hex(d, acc.unit_digest, 32);
        hex(i, acc.ir_sha256, 32);
        accepted++;
#ifdef CK_OSC_LAUNCH_TEST
        lt_save(name, b, len);
#endif
        ck_printf("osc_unit: %s ACCEPT unit_digest=%s program_id=%s funcs=%u caps=%u signer=%s\n", name, d, i,
                  (unsigned)acc.function_count, (unsigned)acc.cap_count,
                  acc.signer_class == OSC_SIGNER_TEST ? "TEST" : "OWNER");
    } else {
        refused++;
        ck_printf("osc_unit: %s REFUSED code=%u name=%s\n", name, rc, osc_code_name(rc));
    }
    return rc;
}

void ck_osc_oversize(const char *name, uint64_t len)
{
    oversize++;
    ck_printf("osc_unit: %s REFUSED code=%u name=%s reason=staging_too_large bytes=%llu limit=%u "
              "(content not read, format unknown; refusal by the Store size limit)\n",
              name, (unsigned)OSC_RESOURCE_UNAVAILABLE, osc_code_name(OSC_RESOURCE_UNAVAILABLE),
              (unsigned long long)len, (unsigned)OSC_STAGING_MAX);
}

void ck_osc_summary(void)
{
    if (seen || oversize)
#ifdef CK_OSC_LAUNCH_TEST
    {
        ck_printf("osc_units: seen=%u accepted=%u refused=%u oversize=%u (admission; launches follow)\n", seen, accepted,
                  refused, oversize);
        lt_all();
    }
#else
        ck_printf("osc_units: seen=%u accepted=%u refused=%u oversize=%u (admission only, nothing launched)\n", seen, accepted,
                  refused, oversize);
#endif
}
