/* store_crash.c -- see store_crash.h. TEST-ONLY; empty unless
 * CK_TEST_STORE_CRASH=1 (make full CK_TEST_STORE_CRASH=1). */
#include "store_crash.h"

#ifdef CK_TEST_STORE_CRASH
#ifdef CK_HARDWARE_STAGING
#error "CK_TEST_STORE_CRASH (TEST-ONLY Store crash hook) cannot be combined with CK_HARDWARE_STAGING"
#endif
#ifdef CK_QEMU_UNSAFE_DMA
#error "CK_TEST_STORE_CRASH cannot be combined with CK_QEMU_UNSAFE_DMA"
#endif
#include <stddef.h>
#include "ck.h"
#include "disk_layout.h"
#include "store_engine.h"
#include "store_sealed.h"

#define CR_MAX_WRITES 64u
#define CR_MAX_BYTES (256u * 1024u)
#define CR_PLAN_MAGIC "AIENCRSH v1 cp="

typedef struct {
    uint64_t lba;
    uint32_t count;
    uint32_t off;
} cr_write;

static struct {
    const disk_dev *real;
    disk_dev dev;
    cr_write w[CR_MAX_WRITES];
    uint32_t n, used;
    uint8_t *buf;
    int armed, cp, policy;
    uint64_t gen_open;
} cr;

static const char *cp_name(int cp)
{
    if (cp == SS_CP_BEFORE_ANCHOR) return "before_anchor";
    if (cp == SS_CP_AFTER_ANCHOR) return "after_anchor";
    return st_checkpoint_name(cp);
}
static const char *const policy_names[] = {"drop", "all", "newest", "torn"};

static int str_eq_n(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}
static size_t str_len(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    return n;
}
static void cp_bytes(uint8_t *d, const uint8_t *s, size_t n)
{
    while (n--) *d++ = *s++;
}

/* Parses "AIENCRSH v1 cp=<name> policy=<name>\n". 0 ok, -1 malformed. */
static int parse_plan(const char *p, size_t len, int *cp, int *policy)
{
    size_t m = sizeof CR_PLAN_MAGIC - 1, i = m, s;
    static const int cps[] = {ST_CP_BEFORE_FIRST_WRITE, ST_CP_AFTER_PAYLOAD_OBJECTS, ST_CP_AFTER_CATALOG,
                              ST_CP_AFTER_COMMIT_RECORD, ST_CP_AFTER_FIRST_FLUSH, ST_CP_AFTER_INACTIVE_SUPERBLOCK,
                              ST_CP_AFTER_FINAL_FLUSH, SS_CP_BEFORE_ANCHOR, SS_CP_AFTER_ANCHOR};
    *cp = -1;
    *policy = -1;
    for (s = i; i < len && p[i] != ' '; i++)
        ;
    if (i >= len) return -1;
    for (size_t k = 0; k < sizeof cps / sizeof cps[0]; k++) {
        const char *nm = cp_name(cps[k]);
        if (str_len(nm) == i - s && str_eq_n(p + s, nm, i - s)) *cp = cps[k];
    }
    if (*cp < 0 || len - i < 8 || !str_eq_n(p + i, " policy=", 8)) return -1;
    for (s = i = i + 8; i < len && p[i] != '\n'; i++)
        ;
    if (i >= len) return -1;
    for (int k = 0; k < 4; k++)
        if (str_len(policy_names[k]) == i - s && str_eq_n(p + s, policy_names[k], i - s)) *policy = k;
    if (*policy < 0) return -1;
    for (i = i + 1; i < len; i++) /* nothing after the line */
        if (p[i]) return -1;
    return 0;
}

static uint32_t pending_blocks(void)
{
    uint32_t b = 0;
    for (uint32_t i = 0; i < cr.n; i++) b += cr.w[i].count;
    return b;
}

/* Writes cached write i (its first `count` blocks) to the real disk. */
static int land(uint32_t i, uint32_t count)
{
    if (!count) return 0;
    return disk_write(cr.real, cr.w[i].lba, count, cr.buf + cr.w[i].off);
}

static int cr_read(void *ctx, uint64_t lba, uint32_t count, uint8_t *out)
{
    (void)ctx;
    int rc = disk_read(cr.real, lba, count, out);
    if (rc) return rc;
    uint32_t bs = cr.real->block_size;
    for (uint32_t i = 0; i < cr.n; i++) { /* later writes win */
        const cr_write *w = &cr.w[i];
        uint64_t a = lba > w->lba ? lba : w->lba;
        uint64_t e1 = lba + count, e2 = w->lba + w->count, b = e1 < e2 ? e1 : e2;
        if (a >= b) continue;
        cp_bytes(out + (a - lba) * bs, cr.buf + w->off + (a - w->lba) * bs, (size_t)(b - a) * bs);
    }
    return 0;
}

static int cr_write_fn(void *ctx, uint64_t lba, uint32_t count, const uint8_t *in)
{
    (void)ctx;
    uint32_t bytes = count * cr.real->block_size;
    if (cr.n >= CR_MAX_WRITES || cr.used + bytes > CR_MAX_BYTES) {
        ck_printf("store_crash: volatile cache full (writes=%u bytes=%u); write refused, fail closed\n", cr.n, cr.used);
        return DISK_EIO;
    }
    cr.w[cr.n] = (cr_write){lba, count, cr.used};
    cp_bytes(cr.buf + cr.used, in, bytes);
    cr.n++;
    cr.used += bytes;
    return 0;
}

static int cr_flush(void *ctx)
{
    (void)ctx;
    for (uint32_t i = 0; i < cr.n; i++) {
        int rc = land(i, cr.w[i].count);
        if (rc) return rc;
    }
    cr.n = 0;
    cr.used = 0;
    return disk_flush(cr.real);
}

const disk_dev *ck_store_crash_setup(const disk_dev *d)
{
    ck_puts("store_crash: TEST-ONLY Store crash hook image (CK_TEST_STORE_CRASH=1); "
            "never counts toward a PASS of M4_STORE\n");
#ifdef CK_TEST_STORE_MUTANT_SKIP_ROOT_FLUSH
    ck_puts("store_crash: TEST-ONLY MUTANT skip_root_flush: the Store does not flush before the root write\n");
#endif
#ifdef CK_TEST_STORE_MUTANT_ACCEPT_BAD_ROOT_CRC
    ck_puts("store_crash: TEST-ONLY MUTANT accept_bad_root_crc: the Store ignores the superblock CRC\n");
#endif
    if (!d || (d->block_size != 512 && d->block_size != 4096)) return d;
    uint32_t bpu = CK_LAYOUT_UNIT / d->block_size;
    uint64_t units = d->block_count / bpu;
    uint8_t *plan = ck_alloc(CK_LAYOUT_UNIT);
    if (!units || !plan) {
        ck_puts("store_crash: plan REFUSED (no plan buffer or no unit); Store runs on the disk directly\n");
        return d;
    }
    int rc = disk_read(d, (units - 1u) * bpu, bpu, plan);
    if (rc) {
        ck_printf("store_crash: plan REFUSED (read rc=%d); Store runs on the disk directly\n", rc);
        return d;
    }
    size_t m = sizeof CR_PLAN_MAGIC - 1;
    if (!str_eq_n((const char *)plan, CR_PLAN_MAGIC, m)) {
        ck_puts("store_crash: no plan; Store runs on the disk directly\n");
        return d;
    }
    if (parse_plan((const char *)plan, CK_LAYOUT_UNIT, &cr.cp, &cr.policy)) {
        ck_puts("store_crash: plan REFUSED (malformed); Store runs on the disk directly\n");
        return d;
    }
    cr.buf = ck_alloc(CR_MAX_BYTES);
    if (!cr.buf) {
        ck_puts("store_crash: plan REFUSED (no cache buffer); Store runs on the disk directly\n");
        return d;
    }
    cr.real = d;
    cr.dev = *d;
    cr.dev.ctx = &cr;
    cr.dev.read = cr_read;
    cr.dev.write = cr_write_fn;
    cr.dev.flush = cr_flush;
    cr.n = cr.used = 0;
    cr.armed = 1;
    ck_printf("store_crash: plan halt_at=%s policy=%s; Store runs on a volatile write cache\n", cp_name(cr.cp),
              policy_names[cr.policy]);
    return &cr.dev;
}

void ck_store_crash_opened(uint64_t generation)
{
    cr.gen_open = generation;
}

static __attribute__((noreturn)) void power_cut(int checkpoint)
{
    uint32_t pend = pending_blocks(), landed = 0, nw = cr.n;
    int rc = 0;
    switch (cr.policy) {
    case CK_STORE_CRASH_POLICY_ALL:
        for (uint32_t i = 0; i < cr.n && !rc; i++) {
            rc = land(i, cr.w[i].count);
            landed += cr.w[i].count;
        }
        break;
    case CK_STORE_CRASH_POLICY_NEWEST:
        if (cr.n) {
            rc = land(cr.n - 1u, cr.w[cr.n - 1u].count);
            landed = cr.w[cr.n - 1u].count;
        }
        break;
    case CK_STORE_CRASH_POLICY_TORN:
        if (cr.n) {
            landed = cr.w[cr.n - 1u].count / 2u;
            rc = land(cr.n - 1u, landed);
        }
        break;
    default:
        break;
    }
    if (!rc) rc = disk_flush(cr.real);
    cr.n = 0;
    cr.used = 0;
    ck_printf("store_crash: HALT at %s policy=%s generation_open=%llu target=%llu pending_writes=%u "
              "pending_blocks=%u landed_blocks=%u rc=%d (power cut: the host kills QEMU now)\n",
              cp_name(checkpoint), policy_names[cr.policy], (unsigned long long)cr.gen_open,
              (unsigned long long)(cr.gen_open + 1u), nw, pend, landed, rc);
    for (;;) __asm__ volatile("wfi");
}

void ck_store_crash_hook(void *arg, int checkpoint)
{
    (void)arg;
    ck_printf("store_crash: checkpoint %s generation_open=%llu pending_writes=%u\n", cp_name(checkpoint),
              (unsigned long long)cr.gen_open, cr.armed ? cr.n : 0u);
    if (cr.armed && checkpoint == cr.cp) power_cut(checkpoint);
}
#else
typedef int ck_store_crash_not_built; /* ISO C: no empty translation unit */
#endif
