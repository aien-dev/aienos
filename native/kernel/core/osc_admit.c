void ck_osc_summary(void)
{
    if (rcpt_seen)
        ck_printf("osc_receipts: seen=%u stored=%u dropped=%u (each is verified when a launch presents it)\n", rcpt_seen,
                  rcpt_n, rcpt_dropped);
    if (seen || oversize)/* osc_admit.c -- kernel policy and reporting for OSC unit admission.
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
#include "osc_receipt.h"
#include "osc_receipt_anchor.h"
#include "sha256.h"
#ifdef CK_OSH_TEST
void ck_osh_save(const char *name, const uint8_t *b, size_t len, const struct osc_accept *acc);
void ck_osh_all(void);
#endif
#ifdef CK_SEED0B_TEST_ANCHOR
#include "osc_unit_test_anchor.h"
#include "osc_receipt_test_anchor.h"
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

/* Realization receipt policy (artifact/osc_receipt.h, aienos#383), local to this build:
 *   - both builds: the accepted checker2 identities of osc_receipt_anchor.h, target aienos-ck-aarch64-el0, no
 *     firmware, no dependencies, producer NOT CHECKED (the unit names no producer), epoch floor and current epoch
 *     fixed below (the kernel has no epoch authority yet, so they are compile-time constants), no OWNER receipt
 *     anchor (the owner root is listed, not trusted, until docs/OWNER_KEY_CEREMONY.md says so).
 *   - release build: release mode, so every TEST receipt is TEST_SIGNER_IN_PRODUCTION; no receipt anchor at all,
 *     so no receipt is valid and nothing can be launched.
 *   - qualification build (CK_SEED0B_TEST_ANCHOR=1): checker2's TEST key as the only receipt anchor and the
 *     fixture n_revoked_id.rcpt on the revoked-id list (osc_receipt_test_anchor.h). TEST ONLY. */
#define CK_OSC_RCPT_EPOCH_FLOOR 10u
#define CK_OSC_RCPT_EPOCH_NOW 20u
static uint8_t rcpt_target[32];
#ifdef CK_OSC_LAUNCH_TEST
int ck_osc_rcpt_variant; /* TEST ONLY: 1 release mode, 2 the TEST key fingerprint revoked (receipt self-test) */
static uint8_t rcpt_test_fp[1][32];
#endif

void ck_osc_policy(struct osc_policy *p)
{
    memset(p, 0, sizeof *p);
    p->unit_formats = OSC_PROFILE_UNIT_FORMATS;
    p->abi_versions = OSC_PROFILE_ABI;
    p->cap_domains = 1u << 1;
    p->staging_max = OSC_STAGING_MAX;
    p->gen_lookup = no_resource;
    osc_receipt_target_hash(OSC_RCPT_TARGET_NAME, sizeof OSC_RCPT_TARGET_NAME - 1, rcpt_target);
    p->rcpt_checkers = osc_rcpt_checker_ids;
    p->n_rcpt_checkers = OSC_RCPT_N_CHECKERS;
    p->rcpt_epoch_floor = CK_OSC_RCPT_EPOCH_FLOOR;
    p->rcpt_epoch_now = CK_OSC_RCPT_EPOCH_NOW;
    p->rcpt_target = rcpt_target;
#ifdef CK_SEED0B_TEST_ANCHOR
    static const uint8_t (*const ta)[32] = &osc_unit_test1_pk;
    static const uint8_t (*const rta)[32] = &osc_rcpt_test_pk;
    static const uint8_t (*const rid)[32] = &osc_rcpt_qual_revoked_id;
    p->release = 0;
    p->test_anchors = ta;
    p->n_test = 1;
    p->rcpt_test_anchors = rta;
    p->n_rcpt_test = 1;
    p->rcpt_revoked_ids = rid;
    p->n_rcpt_revoked_ids = 1;
#else
    p->release = 1;
#endif
#ifdef CK_OSC_LAUNCH_TEST
    if (ck_osc_rcpt_variant == 1)
        p->release = 1;
    if (ck_osc_rcpt_variant == 2) {
        sha256_hash(osc_rcpt_test_pk, 32, rcpt_test_fp[0]);
        p->rcpt_revoked_keys = (const uint8_t (*)[32])rcpt_test_fp;
        p->n_rcpt_revoked_keys = 1;
    }
#endif
}

/* ---- receipts that arrived through the Store, kept by name until a launch asks for one ---- */
#define RCPT_SLOTS 24u
#define RCPT_KEEP 512u /* more than 416 so a wrong-length receipt reaches the verifier and is refused SIZE */
static struct {
    char name[33];
    uint8_t bytes[RCPT_KEEP];
    size_t len;
} rcpt[RCPT_SLOTS];
static unsigned rcpt_n, rcpt_seen, rcpt_dropped;

static int name_eq(const char *a, const char *b)
{
    size_t n = strlen(a);
    return n == strlen(b) && memcmp(a, b, n) == 0;
}

int ck_osc_is_receipt(const uint8_t *b, size_t len)
{
    return b && len >= 8 && memcmp(b, "OMRCPT1\0", 8) == 0;
}

void ck_osc_receipt_candidate(const char *name, const uint8_t *b, size_t len)
{
    rcpt_seen++;
    size_t nl = strlen(name);
    if (rcpt_n >= RCPT_SLOTS || nl >= sizeof rcpt[0].name) {
        rcpt_dropped++;
        ck_printf("osc_receipt: %s DROPPED (receipt table full or name too long; a launch that needs it is refused "
                  "RECEIPT_MISSING)\n", name);
        return;
    }
    memcpy(rcpt[rcpt_n].name, name, nl + 1);
    /* a receipt longer than RCPT_KEEP is kept as its first RCPT_KEEP bytes: still not 416, so refused SIZE */
    rcpt[rcpt_n].len = len <= RCPT_KEEP ? len : RCPT_KEEP;
    memcpy(rcpt[rcpt_n].bytes, b, rcpt[rcpt_n].len);
    char idh[65] = "-";
    if (len == OSC_RCPT_BYTES) {
        uint8_t id[32];
        sha256_hash(b, len, id);
        hex(idh, id, 32);
    }
    ck_printf("osc_receipt: %s STORED bytes=%llu id=%s (verified at launch against the unit launched)\n", name,
              (unsigned long long)len, idh);
    rcpt_n++;
}

const uint8_t *ck_osc_receipt_find(const char *name, size_t *len)
{
    *len = 0;
    for (unsigned i = 0; name && i < rcpt_n; i++)
        if (name_eq(rcpt[i].name, name)) {
            *len = rcpt[i].len;
            return rcpt[i].bytes;
        }
    return 0;
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
    const char *rcpt; /* receipt Store entry; NULL: the unit's own (lt_rcpt_for), "-": none */
    int variant;      /* receipt policy variant for this launch (ck_osc_rcpt_variant): 0 qual, 1 release, 2 revoked key */
};

/* The receipt of each launched unit: a receipt binds the IR and the code, so l02 (l01 with a bigger stack) shares
 * l01's and a06 (a01's IR and code, other limits) shares a01's. */
static const char *lt_rcpt_for(const char *unit)
{
    if (lt_streq(unit, "a01_valid_min.unit") || lt_streq(unit, "a06_valid_limits_at_max.unit"))
        return "a01.rcpt";
    if (lt_streq(unit, "l01_launch_fns.unit") || lt_streq(unit, "l02_stack_over.unit"))
        return "l01.rcpt";
    return "-";
}

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
        const char *rn = s->rcpt ? s->rcpt : lt_rcpt_for(s->unit);
        size_t rlen = 0;
        const uint8_t *rb = lt_streq(rn, "-") ? 0 : ck_osc_receipt_find(rn, &rlen);
        ck_osc_rcpt_variant = s->variant;
        ck_osc_launch(lt_unit[u].bytes, lt_unit[u].len, &lt_unit[u].acc, rb, rlen, &rq, &r, &info);
        ck_osc_rcpt_variant = 0;
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
#ifdef CK_OSC_RECEIPT_TEST
        static const char *const vname[3] = { "qualification", "release", "revoked_test_key" };
        char idh[17] = "-";
        if (info.rcpt.have_id)
            hex(idh, info.rcpt.id, 8);
        ck_printf("osc_rcpt_launch: %s %s(%s) receipt=%s policy=%s -> %s receipt_id=%s revoked=%s ticks=%llu "
                  "pages_mapped=%u page_tables_zeroed=%u slot_free=%u; QEMU (aarch64 virt), TEST signer, not physical\n",
                  s->unit, s->fn, as, rb ? rn : "none", vname[s->variant], rs, idh,
                  info.rcpt.revoked == OSC_RCPT_REVOKED_ID ? "receipt_id"
                  : info.rcpt.revoked == OSC_RCPT_REVOKED_KEY ? "signer_key" : "-",
                  (unsigned long long)r.ticks, info.pages_mapped, (unsigned)info.tables_zeroed,
                  (unsigned)info.slot_free_after);
#else
        ck_printf("osc_launch: %s %s(%s) -> %s ticks=%llu budget=%llu pages_mapped=%u page_tables_zeroed=%u slot_free=%u; "
                  "QEMU (aarch64 virt), TEST signer, not physical\n",
                  s->unit, s->fn, as, rs, (unsigned long long)r.ticks, (unsigned long long)info.budget,
                  info.pages_mapped, (unsigned)info.tables_zeroed, (unsigned)info.slot_free_after);
#endif
        lt_counts[r.cls]++;
        return;
    }
    ck_printf("osc_launch: %s %s -> NOT_RUN (unit was not admitted)\n", s->unit, s->fn);
}

#ifdef CK_OSC_RECEIPT_TEST
/* aienos#383 receipt self-test: every launch of a01_valid_min.unit add(a, b), each with one receipt from the Store
 * (tests/fixtures/osc_receipt, minted by omega checker2 with its TEST key) or none. Only the valid receipt may run
 * the unit; every refusal names its reason and maps nothing. Variant 1 and 2 change the policy for that one launch
 * (release mode; the TEST key fingerprint revoked), to show the release rule and key revocation in one boot. */
static void rt_all(void)
{
    static const struct lt_step steps[] = {
        { "a01_valid_min.unit", "add", 2, { 1, 2 }, 0, 0, 0, "a01.rcpt", 0 },
        { "a01_valid_min.unit", "add", 2, { 2, 3 }, 0, 0, 0, "-", 0 },
        { "a01_valid_min.unit", "add", 2, { 3, 4 }, 0, 0, 0, "n_altered.rcpt", 0 },
        { "a01_valid_min.unit", "add", 2, { 4, 5 }, 0, 0, 0, "n_stale.rcpt", 0 },
        { "a01_valid_min.unit", "add", 2, { 5, 6 }, 0, 0, 0, "n_revoked_id.rcpt", 0 },
        { "a01_valid_min.unit", "add", 2, { 6, 7 }, 0, 0, 0, "a01.rcpt", 2 },
        { "a01_valid_min.unit", "add", 2, { 7, 8 }, 0, 0, 0, "n_expired.rcpt", 0 },
        { "a01_valid_min.unit", "add", 2, { 8, 9 }, 0, 0, 0, "n_future.rcpt", 0 },
        { "a01_valid_min.unit", "add", 2, { 9, 10 }, 0, 0, 0, "n_target.rcpt", 0 },
        { "a01_valid_min.unit", "add", 2, { 10, 11 }, 0, 0, 0, "l01.rcpt", 0 },
        { "a01_valid_min.unit", "add", 2, { 11, 12 }, 0, 0, 0, "n_program.rcpt", 0 },
        { "a01_valid_min.unit", "add", 2, { 12, 13 }, 0, 0, 0, "n_length.rcpt", 0 },
        { "a01_valid_min.unit", "add", 2, { 13, 14 }, 0, 0, 0, "a01.rcpt", 1 },
        { "a01_valid_min.unit", "add", 2, { 14, 15 }, 0, 0, 0, "n_firmware.rcpt", 0 },
        { "a01_valid_min.unit", "add", 2, { 15, 16 }, 0, 0, 0, "n_deps.rcpt", 0 },
        { "a01_valid_min.unit", "add", 2, { 16, 17 }, 0, 0, 0, "n_checker.rcpt", 0 },
        { "a01_valid_min.unit", "add", 2, { 20, 22 }, 0, 0, 0, "a01.rcpt", 0 },
    };
    ck_printf("osc_rcpt_selftest: launches=%u unit=a01_valid_min.unit; QEMU (aarch64 virt), TEST signer, not physical\n",
              (unsigned)(sizeof steps / sizeof steps[0]));
    for (unsigned i = 0; i < sizeof steps / sizeof steps[0]; i++)
        lt_run(&steps[i]);
    ck_printf("osc_rcpt_launches: returned=%u trapped=%u refused=%u unknown=%u; QEMU (aarch64 virt), TEST signer, not "
              "physical\n",
              lt_counts[OSC_RES_RETURNED], lt_counts[OSC_RES_TRAPPED], lt_counts[OSC_RES_REFUSED],
              lt_counts[OSC_RES_UNKNOWN]);
}
#endif

static void lt_all(void)
{
#ifdef CK_OSC_RECEIPT_TEST
    rt_all();
    return;
#endif
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
    ck_osc_policy(&p);
    if (!announced) {
        announced = 1;
#ifdef CK_SEED0B_TEST_ANCHOR
        ck_printf("osc_policy: mode=qualification test_anchors=1 (throwaway TEST key, TEST ONLY) owner_anchors=0 "
                  "domains=1 gen_width=32; QEMU, not physical\n");
#else
        ck_printf("osc_policy: mode=release test_anchors=0 owner_anchors=0 (none provisioned) "
                  "domains=1 gen_width=32; QEMU, not physical\n");
#endif
        ck_printf("osc_receipt_policy: mode=%s receipt_test_anchors=%u receipt_owner_anchors=0 (owner root listed, not "
                  "trusted) checkers=%u target=%s epoch_floor=%u epoch_now=%u revoked_ids=%u revoked_keys=0 "
                  "firmware=none dependencies=none producer=NOT_CHECKED; launch requires a valid receipt; QEMU, not "
                  "physical\n",
                  p.release ? "release" : "qualification", p.n_rcpt_test, p.n_rcpt_checkers, OSC_RCPT_TARGET_NAME,
                  (unsigned)CK_OSC_RCPT_EPOCH_FLOOR, (unsigned)CK_OSC_RCPT_EPOCH_NOW, p.n_rcpt_revoked_ids);
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
#ifdef CK_OSH_TEST
        ck_osh_save(name, b, len, &acc);
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
#if defined(CK_OSC_LAUNCH_TEST) || defined(CK_OSH_TEST)
    {
        ck_printf("osc_units: seen=%u accepted=%u refused=%u oversize=%u (admission; launches follow)\n", seen, accepted,
                  refused, oversize);
#ifdef CK_OSC_LAUNCH_TEST
        lt_all();
#else
        ck_osh_all();
#endif
    }
#else
        ck_printf("osc_units: seen=%u accepted=%u refused=%u oversize=%u (admission only, nothing launched)\n", seen, accepted,
                  refused, oversize);
#endif
}
