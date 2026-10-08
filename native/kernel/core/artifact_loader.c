/* artifact_loader.c -- P2 sealed-artifact loader of the C kernel core.
 *
 * Port of crates/aienos-kernel/src/artifact_loader.rs (load_bound,
 * process_candidate, shadow code alias, W^X audit, receipts) and
 * task_runtime.rs (EL0 run, syscall table, budgets) onto the C core. The
 * format, signature and admission logic is native/kernel/artifact/ (ported
 * from aienos-artifact and admission.rs, cross-checked byte for byte against
 * the Rust tool).
 *
 * Candidates come from QEMU's fw_cfg file "opt/aienos/artifacts" (a bundle,
 * see tools/ck_artifact_tool.c), not from ESP files read by the Rust UEFI
 * loader: the C boot stub (native/boot) does not read files. The fw_cfg base
 * is taken from the ACPI DSDT (device QEMU0002); nothing is assumed.
 *
 * Trust: the qualification build (CK_SEED0B_TEST_ANCHOR=1) trusts the
 * RFC 8032 TEST 1 public key ONLY (SEED-0B, TEST ONLY). The ordinary build
 * has no anchors and refuses every candidate. No real key material here.
 *
 * Differences from the Rust kernel, all recorded in GATES.md:
 *   - one address space at a time on ASID 0 with a full TLB flush on every
 *     TTBR0 switch (Rust: TASK_ASID 2);
 *   - EL0 FP/SIMD traps (CPACR FPEN = 01) instead of zeroed FP state;
 *   - content+table frames and shadow frames are each one contiguous batch;
 *   - the loader scheduler is a single occupancy flag (one task at a time,
 *     LOADED_TASK_SLOTS = 4 for the availability snapshot, as in Rust). */

#include "arch.h"
#include "ck_internal.h"
#include "pt.h"
#include "ck_artifact.h"
#include "osc_admit.h"
#include "sha256.h"

#ifndef AIENOS_COMMIT
#define AIENOS_COMMIT "unknown"
#endif

#define PAGE 4096ull
#define ENTRIES 512u
#define TABLE_FRAMES 4u
#define MAX_BATCH 160u
#define MAX_CODE_PAGES 64u
#define MAX_DATA_PAGES 64u
#define MAX_STACK_PAGES 16u
#define TASK_CAPS 16u
#define LOADED_TASK_SLOTS 4u
#define MAX_CANDIDATES 48u
#define MAX_NAME 32u

#define ADDR_MASK 0x0000fffffffff000ull
#define ATTR_MASK 0xffff000000000ffcull
#define BLOCK_1G 0x0000ffffc0000000ull
#define BLOCK_2M 0x0000ffffffe00000ull
#define DESC_TYPE 3ull
#define DESC_TABLE 3ull
#define DESC_BLOCK 1ull
#define AP_RO (1ull << 7)
#define PXN (1ull << 53)
#define UXN (1ull << 54)
#define LEAF_COMMON                                                                         \
    (CK_PTE_ATTRIDX(CK_MAIR_IDX_NORMAL) | CK_PTE_SH_INNER | CK_PTE_AF | (1ull << 11) | PXN | \
     DESC_TABLE)
#define USER_CODE(pa) (((pa) & ADDR_MASK) | LEAF_COMMON | (3ull << 6))
#define USER_DATA(pa) (((pa) & ADDR_MASK) | LEAF_COMMON | (1ull << 6) | UXN)

#define SYS_EXIT 2u
#define SYS_OBJECT_READ 6u
#define SYS_OBJECT_WRITE 7u
#define DENIED (~0ull)
#define SEED_OBJECT_ID 1u
#define SEED_OBJECT_BYTES 32u
#define SPSR_EL1H_MASKED 0x3c5ull
#define RIGHT_READ 0x1u
#define RIGHT_WRITE 0x2u

struct ck_artifact_summary {
    unsigned candidates, admitted, rejected;
};
static struct ck_artifact_summary ck_artifact_summary;

extern struct ck_frame *(*ck_tick_switch)(struct ck_frame *f);
extern int (*ck_lower_sync)(struct ck_frame *f, uint64_t esr);
void ck_el0_enter(uint64_t entry, uint64_t user_sp, const uint64_t regs[31]);
void ck_el0_resume(void);

#ifdef CK_SEED0B_TEST_ANCHOR
static const uint8_t (*const anchors)[32] = &cka_test1_pk;
#define NANCHORS 1u
#define FEATURE_TEST_ANCHOR 1u
#else
static const uint8_t (*const anchors)[32] = 0;
#define NANCHORS 0u
#define FEATURE_TEST_ANCHOR 0u
#endif

/* ============================ platform ============================== */

static inline uint64_t *tbl(uint64_t pa) { return (uint64_t *)(uintptr_t)pa; }
static inline uint8_t *mem(uint64_t pa) { return (uint8_t *)(uintptr_t)pa; }
static inline unsigned tidx(uint64_t va, unsigned level)
{
    return (unsigned)((va >> (39 - 9 * level)) & 511);
}
static inline uint64_t free_frames(void) { return ck_mm_free_frames(); }

static void clean_range(uint64_t pa, uint64_t len, int icache)
{
    uint64_t ctr = ck_rd(ctr_el0);
    uint64_t dline = 4ull << ((ctr >> 16) & 0xf), iline = 4ull << (ctr & 0xf);
    uint64_t end = pa + len;
    for (uint64_t x = pa & ~(dline - 1); x < end; x += dline)
        __asm__ volatile("dc civac, %0" ::"r"(x) : "memory");
    ck_dsb_ish();
    if (icache) {
        for (uint64_t x = pa & ~(iline - 1); x < end; x += iline)
            __asm__ volatile("ic ivau, %0" ::"r"(x) : "memory");
        ck_dsb_ish();
    }
    ck_isb();
}

static void swap_ttbr0(uint64_t ttbr0)
{
    ck_dsb_ish();
    ck_wr(ttbr0_el1, ttbr0);
    ck_isb();
    __asm__ volatile("tlbi vmalle1" ::: "memory");
    ck_dsb_ish();
    ck_isb();
}

/* ============================ task layout =========================== */

struct layout {
    unsigned window;
    uint64_t base;
    unsigned cp, dp, sp; /* code, data, stack pages */
    uint64_t code_len, data_len, data_mlen, entry;
};

static unsigned code_first(void) { return 1; }
static unsigned data_first(const struct layout *l) { return code_first() + l->cp + 1; }
static unsigned stack_first(const struct layout *l) { return data_first(l) + l->dp + 1; }
static unsigned window_pages(const struct layout *l) { return stack_first(l) + l->sp + 1; }
static unsigned content_frames(const struct layout *l) { return l->cp + l->dp + l->sp; }
static uint64_t code_base(const struct layout *l) { return l->base + code_first() * PAGE; }
static uint64_t code_end(const struct layout *l) { return code_base(l) + l->cp * PAGE; }
static uint64_t data_base(const struct layout *l) { return l->base + data_first(l) * PAGE; }
static uint64_t data_end(const struct layout *l) { return data_base(l) + l->dp * PAGE; }
static uint64_t stack_base(const struct layout *l) { return l->base + stack_first(l) * PAGE; }
static uint64_t stack_top(const struct layout *l) { return stack_base(l) + l->sp * PAGE; }

/* TaskLayout::new: 0 or CKA_RESOURCE_LIMIT. */
static int layout_new(struct layout *l, unsigned window, const struct cka_env *env,
                      uint64_t code_len, uint64_t data_len, uint64_t data_mlen, uint64_t entry)
{
    l->window = window;
    l->base = (uint64_t)window << 39;
    l->cp = env->code_pages;
    l->dp = env->data_pages;
    l->sp = env->stack_pages;
    l->code_len = code_len;
    l->data_len = data_len;
    l->data_mlen = data_mlen;
    l->entry = entry;
    if (window < 1 || window >= 256 || env->code_pages == 0 || env->code_pages > MAX_CODE_PAGES ||
        env->data_pages == 0 || env->data_pages > MAX_DATA_PAGES || env->stack_pages == 0 ||
        env->stack_pages > MAX_STACK_PAGES || code_len == 0 || code_len > l->cp * PAGE ||
        data_len > data_mlen || data_mlen > l->dp * PAGE || (entry & 3) || entry + 4 > code_len ||
        window_pages(l) > ENTRIES)
        return CKA_RESOURCE_LIMIT;
    return 0;
}

static uint64_t expected_leaf(const struct layout *l, unsigned index, const uint64_t *frames)
{
    unsigned d = data_first(l), s = stack_first(l);
    if (index >= 1 && index < 1 + l->cp)
        return USER_CODE(frames[index - 1]);
    if (index >= d && index < d + l->dp)
        return USER_DATA(frames[l->cp + index - d]);
    if (index >= s && index < s + l->sp)
        return USER_DATA(frames[l->cp + l->dp + index - s]);
    return 0;
}

/* ============================ reports =============================== */

struct bindings {
    uint8_t id[32], payload[32], signer[32], policy[32], requested[32], granted[32],
        resources[32];
    int mapped_bytes_matched, wx_sealed;
};

enum { ST_NOT_RUN, ST_EXITED, ST_TIMEOUT, ST_FAULT, ST_BAD_SYSCALL, ST_OVERRUN };
struct outcome {
    unsigned status;
    uint64_t value; /* exit code / syscall number */
    uint64_t esr, far, elr;
    uint32_t syscalls, reads_ok, denials, write_denials, invalid_handle;
};

struct report {
    int admitted;
    unsigned stage, error; /* failed stage and reason code (0 = none) */
    int have_id;
    uint8_t id[32];
    int tier_test;
    uint64_t frames_reserved, free_before, free_after;
    unsigned caps_installed, caps_live_after;
    struct cka_cap granted[TASK_CAPS];
    uint64_t code_base, code_end, data_base, data_end, stack_base, stack_end;
    int wx_enforced, byte_chain;
    struct outcome out;
    struct bindings b;
};

static int reclaimed(const struct report *r)
{
    return r->free_after == r->free_before && r->caps_live_after == 0;
}

/* ============================ loader caps =========================== */

struct cap_slot {
    int live;
    uint32_t gen, resource, rights;
};
static struct cap_slot caps[TASK_CAPS];
static uint32_t cap_gens[TASK_CAPS];

static void caps_reset(void)
{
    memset(caps, 0, sizeof caps);
    memset(cap_gens, 0, sizeof cap_gens);
}

static int caps_insert(uint32_t resource, uint32_t rights, uint64_t *raw)
{
    for (unsigned i = 0; i < TASK_CAPS; i++) {
        if (caps[i].live || cap_gens[i] == 0xffffffffu)
            continue;
        uint32_t g = ++cap_gens[i];
        caps[i] = (struct cap_slot){1, g, resource, rights};
        *raw = (uint64_t)g << 32 | i;
        return 0;
    }
    return -1;
}

enum { LK_OK = 0, LK_INVALID = 1, LK_MISSING_RIGHTS = 2 };
static int caps_lookup(uint64_t raw, uint32_t right, uint32_t *resource)
{
    uint32_t index = (uint32_t)raw, gen = (uint32_t)(raw >> 32);
    if (gen == 0 || index >= TASK_CAPS || !caps[index].live || caps[index].gen != gen)
        return LK_INVALID;
    if ((caps[index].rights & right) != right)
        return LK_MISSING_RIGHTS;
    *resource = caps[index].resource;
    return LK_OK;
}

static void caps_remove(uint64_t raw)
{
    uint32_t index = (uint32_t)raw, gen = (uint32_t)(raw >> 32);
    if (gen && index < TASK_CAPS && caps[index].live && caps[index].gen == gen)
        caps[index].live = 0;
}

static unsigned caps_live(void)
{
    unsigned n = 0;
    for (unsigned i = 0; i < TASK_CAPS; i++)
        n += caps[i].live ? 1u : 0u;
    return n;
}

/* ============================ loaded task =========================== */

struct task {
    struct layout l;
    uint64_t batch, nframes;        /* content + table frames, contiguous */
    uint64_t shadow, nshadow, used; /* shadow batch, frames used by the alias */
    uint64_t frames[MAX_BATCH];
    uint64_t root;
    uint64_t entry_pc, sp, args[4];
    unsigned ngrants;
    struct cka_cap grants[TASK_CAPS];
    uint64_t handles[TASK_CAPS];
    uint64_t budget_cpu, budget_elapsed;
    uint32_t budget_syscalls;
    uint8_t code_digest[32];
};
static struct task task;
static int slot_busy; /* loader scheduler: one admitted task at a time */

static int release(struct task *t)
{
    int ok = 1;
    if (t->nframes) {
        memset(mem(t->batch), 0, t->nframes * PAGE);
        if (ck_mm_frames_free(t->batch, t->nframes))
            ok = 0;
        t->nframes = 0;
    }
    if (t->nshadow) {
        memset(mem(t->shadow), 0, t->nshadow * PAGE);
        if (ck_mm_frames_free(t->shadow, t->nshadow))
            ok = 0;
        t->nshadow = 0;
    }
    slot_busy = 0;
    return ok;
}

/* kernel_translation: the descriptor mapping va (level-3 page or L1/L2
 * block) and its level, or -1. */
static int translate(uint64_t root, uint64_t va, uint64_t *desc)
{
    uint64_t table = root;
    for (unsigned level = 0; level < 4; level++) {
        uint64_t e = tbl(table)[tidx(va, level)];
        if (level == 3 && (e & DESC_TYPE) == DESC_TABLE) {
            *desc = e;
            return 3;
        }
        if ((level == 1 || level == 2) && (e & DESC_TYPE) == DESC_BLOCK) {
            *desc = e;
            return (int)level;
        }
        if (level <= 2 && (e & DESC_TYPE) == DESC_TABLE) {
            table = e & ADDR_MASK;
            continue;
        }
        return -1;
    }
    return -1;
}

static int shadow_needed(uint64_t kroot, const uint64_t *frames, unsigned n, uint64_t *count)
{
    uint64_t keys[MAX_CODE_PAGES][3];
    uint64_t c = 0, d;
    for (unsigned i = 0; i < n; i++) {
        uint64_t pa = frames[i];
        if (translate(kroot, pa, &d) < 0)
            return CKL_MAPPING;
        uint64_t k[3] = {pa >> 39, pa >> 30, pa >> 21};
        for (unsigned level = 0; level < 3; level++) {
            int seen = 0;
            for (unsigned j = 0; j < i && !seen; j++)
                seen = keys[j][level] == k[level];
            if (!seen)
                c++;
        }
        keys[i][0] = k[0];
        keys[i][1] = k[1];
        keys[i][2] = k[2];
    }
    *count = c;
    return 0;
}

static int shadow_alias(struct task *t)
{
    uint64_t used = 0;
    for (unsigned f = 0; f < t->l.cp; f++) {
        uint64_t pa = t->frames[f], table = t->root;
        for (unsigned level = 0; level < 3; level++) {
            unsigned index = tidx(pa, level);
            uint64_t entry = tbl(table)[index], child = entry & ADDR_MASK;
            int priv = 0;
            for (uint64_t j = 0; j < used && !priv; j++)
                priv = t->shadow + j * PAGE == child;
            if ((entry & DESC_TYPE) == DESC_TABLE && priv) {
                table = child;
                continue;
            }
            if (used >= t->nshadow)
                return CKL_MAPPING;
            uint64_t fresh = t->shadow + used * PAGE;
            used++;
            if ((entry & DESC_TYPE) == DESC_TABLE) {
                memcpy(mem(fresh), mem(child), PAGE);
            } else if (level == 1 && (entry & DESC_TYPE) == DESC_BLOCK) {
                uint64_t attrs = entry & ATTR_MASK, base = entry & BLOCK_1G;
                for (uint64_t k = 0; k < ENTRIES; k++)
                    tbl(fresh)[k] = (base + (k << 21)) | attrs | DESC_BLOCK;
            } else if (level == 2 && (entry & DESC_TYPE) == DESC_BLOCK) {
                uint64_t attrs = entry & ATTR_MASK, base = entry & BLOCK_2M;
                for (uint64_t k = 0; k < ENTRIES; k++)
                    tbl(fresh)[k] = (base + (k << 12)) | attrs | DESC_TABLE;
            } else {
                return CKL_MAPPING;
            }
            tbl(table)[index] = (entry & ~ADDR_MASK & ~DESC_TYPE) | fresh | DESC_TABLE;
            table = fresh;
        }
        unsigned index = tidx(pa, 3);
        uint64_t leaf = tbl(table)[index];
        if ((leaf & DESC_TYPE) != DESC_TABLE || (leaf & ADDR_MASK) != pa)
            return CKL_MAPPING;
        tbl(table)[index] = leaf | AP_RO | PXN | UXN;
    }
    t->used = used;
    return 0;
}

static int audit_wx(const struct task *t)
{
    const struct layout *l = &t->l;
    unsigned content = content_frames(l);
    uint64_t l0e = tbl(t->root)[l->window], l1 = l0e & ADDR_MASK;
    if (l0e != ((t->frames[content + 1] & ADDR_MASK) | DESC_TABLE))
        return 0;
    for (unsigned i = 1; i < ENTRIES; i++)
        if (tbl(l1)[i])
            return 0;
    uint64_t l2 = tbl(l1)[0] & ADDR_MASK;
    if (l2 != t->frames[content + 2])
        return 0;
    for (unsigned i = 1; i < ENTRIES; i++)
        if (tbl(l2)[i])
            return 0;
    uint64_t l3 = tbl(l2)[0] & ADDR_MASK;
    if (l3 != t->frames[content + 3])
        return 0;
    for (unsigned i = 0; i < ENTRIES; i++) {
        uint64_t leaf = tbl(l3)[i];
        if (leaf != expected_leaf(l, i, t->frames))
            return 0;
        int writable = !(leaf & AP_RO), executable = !(leaf & UXN) || !(leaf & PXN);
        if (leaf && writable && executable)
            return 0;
    }
    for (unsigned f = 0; f < l->cp; f++) {
        uint64_t pa = t->frames[f], leaf;
        if (translate(t->root, pa, &leaf) != 3)
            return 0;
        if ((leaf & ADDR_MASK) != pa || !(leaf & AP_RO) || !(leaf & PXN) || !(leaf & UXN))
            return 0;
    }
    return 1;
}

static void copy_section(const struct task *t, unsigned first, const uint8_t *src, uint64_t len)
{
    for (uint64_t off = 0; off < len; off += PAGE) {
        uint64_t n = len - off < PAGE ? len - off : PAGE;
        memcpy(mem(t->frames[first + off / PAGE]), src + off, n);
    }
}

static void hash_loaded(const struct task *t, uint8_t payload[32], uint8_t code[32])
{
    sha256_ctx p, c;
    sha256_init(&p);
    sha256_init(&c);
    for (unsigned i = 0; i < t->l.cp && i * PAGE < t->l.code_len; i++) {
        uint64_t n = t->l.code_len - i * PAGE;
        n = n < PAGE ? n : PAGE;
        sha256_update(&p, mem(t->frames[i]), n);
        sha256_update(&c, mem(t->frames[i]), n);
    }
    for (unsigned i = 0; i < t->l.dp && i * PAGE < t->l.data_len; i++) {
        uint64_t n = t->l.data_len - i * PAGE;
        n = n < PAGE ? n : PAGE;
        sha256_update(&p, mem(t->frames[t->l.cp + i]), n);
    }
    sha256_final(&p, payload);
    sha256_final(&c, code);
}

static void code_digest(const struct task *t, uint8_t out[32])
{
    sha256_ctx c;
    sha256_init(&c);
    for (unsigned i = 0; i < t->l.cp && i * PAGE < t->l.code_len; i++) {
        uint64_t n = t->l.code_len - i * PAGE;
        sha256_update(&c, mem(t->frames[i]), n < PAGE ? n : PAGE);
    }
    sha256_final(&c, out);
}

/* ============================ load_bound ============================ */

static struct cka_policy policy;
static struct cka_parsed parsed;
static struct cka_ident ident;
static struct cka_decision decision;

/* Returns 0 (task loaded) or the failure stage in *stage and reason. */
static unsigned load_bound(uint64_t staged, uint64_t len, struct bindings *b, unsigned *stage,
                           int *tier_test)
{
    struct task *t = &task;
    const uint8_t *bytes = mem(staged);
    cka_policy_digest(&policy, b->policy);
    unsigned free_slots = LOADED_TASK_SLOTS - (slot_busy ? 1u : 0u);
    if (cka_identify(bytes, len, &parsed, &ident) == 0) {
        memcpy(b->id, ident.id, 32);
        memcpy(b->payload, ident.payload, 32);
        memcpy(b->requested, ident.requested, 32);
        memcpy(b->resources, ident.resources, 32);
    }
    uint8_t fp[32];
    int rc = cka_verify(bytes, len, anchors, NANCHORS, &parsed, &ident, fp);
    if (rc) {
        *stage = CKS_VERIFIED;
        return (unsigned)rc;
    }
    memcpy(b->signer, fp, 32);
    *tier_test = FEATURE_TEST_ANCHOR;
    uint64_t ff = free_frames();
    uint32_t frames = 0;
    if (free_slots)
        frames = ff > TABLE_FRAMES ? (ff - TABLE_FRAMES > 0xffffffffull ? 0xffffffffu
                                                                         : (uint32_t)(ff - TABLE_FRAMES))
                                   : 0;
    struct cka_limits avail = {
        .code_pages = frames, .data_pages = frames, .stack_pages = frames, .max_caps = TASK_CAPS,
        .ipc_msgs = 0, .ipc_bytes = 0, .cpu = policy.limits.cpu, .elapsed = policy.limits.elapsed,
        .syscalls = policy.limits.syscalls,
    };
    rc = cka_evaluate(&policy, &parsed, fp, &avail, &decision);
    if (rc) {
        *stage = CKS_AUTHORIZED;
        return (unsigned)rc;
    }
    memcpy(b->granted, decision.granted_digest, 32);
    /* The admission binds the identity it was computed over (cka_evaluate
     * works on the same parsed artifact, so this holds by construction). */
    if (decision.ngrants > TASK_CAPS) {
        *stage = CKS_AUTHORIZED;
        return CKA_RESOURCE_LIMIT;
    }
    uint64_t kroot = ck_mm_report()->root;
    unsigned window = 0;
    for (unsigned i = 1; i < 256 && !window; i++)
        if (!tbl(kroot)[i])
            window = i;
    if (!window) {
        *stage = CKS_RESERVED;
        return CKL_MAPPING;
    }
    memset(t, 0, sizeof *t);
    const struct cka_section *cs = &parsed.code, *ds = &parsed.data;
    rc = layout_new(&t->l, window, &parsed.env, cs->flen, ds->flen, ds->mlen, parsed.entry);
    if (rc) {
        *stage = CKS_AUTHORIZED;
        return (unsigned)rc;
    }
    const uint8_t *code_src = bytes + parsed.payload_off; /* code_bytes(): payload[..flen] */
    const uint8_t *data_src = bytes + parsed.payload_off + ds->rel;

    /* ---- Reserved: scheduler slot, content+table frames, shadow frames. */
    *stage = CKS_RESERVED;
    slot_busy = 1;
    unsigned content = content_frames(&t->l), total = content + TABLE_FRAMES;
    unsigned why;
    if (total > MAX_BATCH || ck_mm_frames_alloc(total, &t->batch)) {
        why = CKL_NO_FRAMES;
        goto fail;
    }
    t->nframes = total;
    for (unsigned i = 0; i < total; i++)
        t->frames[i] = t->batch + i * PAGE;
    uint64_t need;
    if ((why = (unsigned)shadow_needed(kroot, t->frames, t->l.cp, &need)))
        goto fail;
    if (need > MAX_BATCH || ck_mm_frames_alloc(need, &t->shadow)) {
        why = CKL_NO_FRAMES;
        goto fail;
    }
    t->nshadow = need;

    /* ---- Mapped */
    *stage = CKS_MAPPED;
    uint64_t l0 = t->frames[content], l1 = l0 + PAGE, l2 = l1 + PAGE, l3 = l2 + PAGE;
    memset(mem(t->batch), 0, total * PAGE);
    memset(mem(t->shadow), 0, need * PAGE);
    memcpy(mem(l0), mem(kroot), PAGE);
    t->root = l0;
    tbl(l0)[window] = l1 | DESC_TABLE;
    tbl(l1)[0] = l2 | DESC_TABLE;
    tbl(l2)[0] = l3 | DESC_TABLE;
    for (unsigned i = data_first(&t->l); i < window_pages(&t->l); i++) {
        uint64_t leaf = expected_leaf(&t->l, i, t->frames);
        if (leaf)
            tbl(l3)[i] = leaf;
    }
    copy_section(t, 0, code_src, t->l.code_len);
    copy_section(t, t->l.cp, data_src, t->l.data_len);

    /* ---- Hashed */
    *stage = CKS_HASHED;
    uint8_t payload[32];
    hash_loaded(t, payload, t->code_digest);
    if (memcmp(payload, ident.payload, 32)) {
        why = CKL_MAPPED_DIGEST;
        goto fail;
    }
    b->mapped_bytes_matched = 1;

    /* ---- Sealed */
    *stage = CKS_SEALED;
    clean_range(t->batch, t->l.cp * PAGE, 1);
    if ((why = (unsigned)shadow_alias(t)))
        goto fail;
    for (unsigned i = 0; i < t->l.cp; i++)
        tbl(l3)[1 + i] = USER_CODE(t->frames[i]);
    clean_range(t->batch, total * PAGE, 0);
    if (t->used)
        clean_range(t->shadow, t->used * PAGE, 0);
    if (!audit_wx(t)) {
        why = CKL_WX_AUDIT;
        goto fail;
    }
    b->wx_sealed = 1;

    /* ---- Caps */
    *stage = CKS_CAPS;
    caps_reset();
    t->ngrants = decision.ngrants;
    memcpy(t->grants, decision.grants, sizeof t->grants);
    for (unsigned i = 0; i < t->ngrants; i++) {
        if (caps_insert(i, decision.grants[i].rights, &t->handles[i])) {
            why = CKL_CAP_INSTALL;
            goto fail;
        }
    }
    uint64_t top = stack_top(&t->l), handles_va = top - 8ull * t->ngrants;
    uint64_t top_frame = t->frames[content - 1];
    for (unsigned i = 0; i < t->ngrants; i++)
        cka_wr64(mem(top_frame) + (handles_va + 8ull * i - (top - PAGE)), t->handles[i]);
    clean_range(top_frame, PAGE, 0);
    t->entry_pc = code_base(&t->l) + t->l.entry;
    t->sp = handles_va & ~15ull;
    t->args[0] = handles_va;
    t->args[1] = t->ngrants;
    t->args[2] = data_base(&t->l);
    t->args[3] = t->l.data_mlen;
    t->budget_cpu = parsed.env.cpu;
    t->budget_elapsed = parsed.env.elapsed;
    t->budget_syscalls = parsed.env.syscalls;
    return 0;
fail:
    caps_reset();
    release(t);
    return why;
}

/* ============================ EL0 runtime =========================== */

static struct {
    int active, done;
    uint64_t start, limit;
    uint32_t budget_syscalls;
    struct outcome out;
    struct { uint64_t ops, bytes; } usage[TASK_CAPS];
    uint64_t object[4];
} rt;

static void terminate(struct ck_frame *f, unsigned status, uint64_t value)
{
    if (!rt.done) {
        rt.done = 1;
        rt.out.status = status;
        rt.out.value = value;
    }
    f->elr = (uint64_t)(uintptr_t)ck_el0_resume;
    f->spsr = SPSR_EL1H_MASKED;
}

static int expired(uint64_t now) { return now - rt.start >= rt.limit; }

enum { D_AUTHORITY = 1, D_INVALID, D_BOUNDS, D_BUDGET };
static int object_access(uint64_t raw, uint32_t right, uint64_t off, unsigned *word)
{
    uint32_t index;
    int lk = caps_lookup(raw, right, &index);
    if (lk == LK_MISSING_RIGHTS)
        return D_AUTHORITY;
    if (lk != LK_OK)
        return D_INVALID;
    if (index >= task.ngrants)
        return D_AUTHORITY;
    const struct cka_cap *g = &task.grants[index];
    if (g->kind != CKA_KIND_OBJECT || g->id != SEED_OBJECT_ID || (g->rights & right) != right)
        return D_AUTHORITY;
    uint64_t end = off + 8, gend = g->off + g->len;
    if (end < off || gend < g->off)
        return D_BOUNDS;
    if ((off & 7) || off < g->off || end > gend || end > SEED_OBJECT_BYTES)
        return D_BOUNDS;
    uint64_t bytes = rt.usage[index].bytes + 8;
    if (bytes < rt.usage[index].bytes || rt.usage[index].ops >= g->max_ops || bytes > g->max_bytes)
        return D_BUDGET;
    rt.usage[index].ops++;
    rt.usage[index].bytes = bytes;
    *word = (unsigned)(off / 8);
    return 0;
}

static uint64_t deny(int why, int write)
{
    if (rt.out.denials != 0xffffffffu)
        rt.out.denials++;
    if (write && rt.out.write_denials != 0xffffffffu)
        rt.out.write_denials++;
    if (why == D_INVALID && rt.out.invalid_handle != 0xffffffffu)
        rt.out.invalid_handle++;
    return DENIED;
}

static int loader_sync(struct ck_frame *f, uint64_t esr)
{
    if (!rt.active || (f->spsr & 0xf) != 0)
        return -1;
    uint64_t ec = (esr >> 26) & 0x3f;
    if (ec != 0x15) {
        uint64_t far;
        __asm__ volatile("mrs %0, far_el1" : "=r"(far));
        if (!rt.done) {
            rt.out.esr = esr;
            rt.out.far = far;
            rt.out.elr = f->elr;
        }
        terminate(f, ST_FAULT, 0);
        return 0;
    }
    if (rt.out.syscalls != 0xffffffffu)
        rt.out.syscalls++;
    if (rt.out.syscalls > rt.budget_syscalls) {
        terminate(f, ST_OVERRUN, 0);
        return 0;
    }
    if (expired(ck_rd(cntpct_el0))) {
        terminate(f, ST_TIMEOUT, 0);
        return 0;
    }
    uint64_t number = f->x[8];
    if ((esr & 0xffff) != 0) {
        terminate(f, ST_BAD_SYSCALL, number);
        return 0;
    }
    unsigned word;
    int why;
    switch (number) {
    case SYS_EXIT:
        terminate(f, ST_EXITED, f->x[0]);
        return 0;
    case SYS_OBJECT_READ:
        if ((why = object_access(f->x[0], RIGHT_READ, f->x[1], &word)) == 0) {
            if (rt.out.reads_ok != 0xffffffffu)
                rt.out.reads_ok++;
            f->x[0] = rt.object[word];
        } else {
            f->x[0] = deny(why, 0);
        }
        return 0;
    case SYS_OBJECT_WRITE:
        if ((why = object_access(f->x[0], RIGHT_WRITE, f->x[1], &word)) == 0) {
            rt.object[word] = f->x[2];
            f->x[0] = 0;
        } else {
            f->x[0] = deny(why, 1);
        }
        return 0;
    default:
        terminate(f, ST_BAD_SYSCALL, number);
        return 0;
    }
}

static struct ck_frame *loader_tick(struct ck_frame *f)
{
    if ((f->spsr & 0xf) == 0 && rt.active && expired(ck_rd(cntpct_el0)))
        terminate(f, ST_TIMEOUT, 0);
    return f;
}

static void run_task(struct task *t, struct outcome *o)
{
    memset(&rt, 0, sizeof rt);
    rt.object[0] = 0xa1e05eed00000001ull;
    rt.object[1] = 0xa1e05eed00000002ull;
    rt.object[2] = 0xa1e05eed00000003ull;
    rt.object[3] = 0xa1e05eed00000004ull;
    rt.limit = t->budget_cpu < t->budget_elapsed ? t->budget_cpu : t->budget_elapsed;
    rt.budget_syscalls = t->budget_syscalls;
    uint64_t regs[31] = {0};
    for (unsigned i = 0; i < 4; i++)
        regs[i] = t->args[i];
    uint64_t hz = ck_rd(cntfrq_el0);
    uint64_t interval = hz >= 100 ? hz / 100 : 625000;
    uint64_t kttbr = ck_rd(ttbr0_el1), cpacr = ck_rd(cpacr_el1), cntkctl = ck_rd(cntkctl_el1);
    ck_lower_sync = loader_sync;
    ck_tick_switch = loader_tick;
    rt.start = ck_rd(cntpct_el0);
    rt.active = 1;
    ck_wr(cpacr_el1, (cpacr & ~(3ull << 20)) | (1ull << 20)); /* FP/SIMD traps at EL0 */
    /* EL0 must not touch the physical/virtual timers (EL0PTEN, EL0VTEN): the
     * budget timer is the kernel's, whatever firmware left in CNTKCTL_EL1. */
    ck_wr(cntkctl_el1, cntkctl & ~((1ull << 9) | (1ull << 8)));
    swap_ttbr0(t->root);
    ck_wr(cntp_cval_el0, rt.start + interval);
    ck_wr(cntp_ctl_el0, 1);
    ck_isb();
    ck_el0_enter(t->entry_pc, t->sp, regs);
    __asm__ volatile("msr daifset, #2" ::: "memory");
    ck_wr(cntp_ctl_el0, 0);
    ck_isb();
    swap_ttbr0(kttbr);
    ck_wr(cpacr_el1, cpacr);
    ck_wr(cntkctl_el1, cntkctl);
    ck_isb();
    rt.active = 0;
    ck_lower_sync = 0;
    ck_tick_switch = 0;
    *o = rt.out;
}

/* ============================ candidates ============================ */

static uint64_t receipt_seq = 1;
static uint8_t verifier_id[32];

static void report_empty(struct report *r, uint64_t free_before)
{
    memset(r, 0, sizeof *r);
    r->free_before = r->free_after = free_before;
}

static void firmware_rejection(struct report *r, unsigned error)
{
    report_empty(r, free_frames());
    r->stage = CKS_RECEIVED;
    r->error = error;
    cka_policy_digest(&policy, r->b.policy);
}

/* process_candidate: bytes at in_pa (len bytes, len >= 0). */
static void process_candidate(const uint8_t *bytes, uint64_t len, struct report *r)
{
    report_empty(r, free_frames());
    uint64_t pages = (len + PAGE - 1) / PAGE;
    if (len == 0 || pages > MAX_BATCH) {
        r->stage = CKS_RECEIVED;
        r->error = CKL_STAGING_TOO_LARGE;
        r->free_after = free_frames();
        return;
    }
    uint64_t staged;
    if (ck_mm_frames_alloc(pages, &staged)) {
        r->stage = CKS_STAGED;
        r->error = CKL_NO_FRAMES;
        r->free_after = free_frames();
        return;
    }
    memset(mem(staged), 0, pages * PAGE);
    memcpy(mem(staged), bytes, len);
    unsigned stage = 0;
    int tier_test = 0;
    unsigned why = load_bound(staged, len, &r->b, &stage, &tier_test);
    memset(mem(staged), 0, pages * PAGE);
    int staging_released = ck_mm_frames_free(staged, pages) == 0;
    if (why) {
        r->stage = stage;
        r->error = staging_released ? why : CKL_RECLAIM;
        r->free_after = free_frames();
        return;
    }
    struct task *t = &task;
    r->have_id = 1;
    memcpy(r->id, ident.id, 32);
    r->tier_test = tier_test;
    r->frames_reserved = t->nframes + t->nshadow;
    r->caps_installed = t->ngrants;
    memcpy(r->granted, t->grants, sizeof r->granted);
    r->code_base = code_base(&t->l);
    r->code_end = code_end(&t->l);
    r->data_base = data_base(&t->l);
    r->data_end = data_end(&t->l);
    r->stack_base = stack_base(&t->l);
    r->stack_end = stack_top(&t->l);
    r->wx_enforced = r->b.wx_sealed;
    run_task(t, &r->out);
    /* destroy */
    uint8_t now[32];
    code_digest(t, now);
    int executed = memcmp(now, t->code_digest, 32) == 0;
    for (unsigned i = 0; i < t->ngrants; i++)
        caps_remove(t->handles[i]);
    r->caps_live_after = caps_live();
    int released = release(t);
    r->admitted = 1;
    r->byte_chain = r->b.mapped_bytes_matched && executed;
    r->free_after = free_frames();
    if (!executed)
        r->error = CKL_EXECUTED_DIGEST;
    else if (!released || !staging_released)
        r->error = CKL_RECLAIM;
}

static void hex(char *out, const uint8_t *b, size_t n)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[2 * n] = 0;
}

static const char *classify_fault(const struct report *r)
{
    uint64_t esr = r->out.esr, far = r->out.far, ec = (esr >> 26) & 0x3f;
    uint64_t status = (esr >> 2) & 0xf;
#define WITHIN(b, e) (far >= (b) && far < (e))
    int in_ds = WITHIN(r->data_base, r->data_end) || WITHIN(r->stack_base, r->stack_end);
    if (ec == 0x24 && (esr & (1u << 6)) && status == 3 && WITHIN(r->code_base, r->code_end))
        return "code-write";
    if (ec == 0x20 && status == 3 && in_ds)
        return "exec-nx";
    if (ec == 0x20 && status == 1)
        return "exec-unmapped";
#undef WITHIN
    return "other";
}

static void print_candidate(const char *name, const struct report *r)
{
    const char *yn[2] = {"no", "yes"};
    if (!r->admitted) {
        ck_printf("artifact: %s rejected stage=%s reason=%s reclaimed=%s\n", name,
                  r->stage ? cka_stage_name(r->stage) : "unknown",
                  r->error ? cka_error_name(r->error) : "unknown", yn[reclaimed(r)]);
        return;
    }
    char id[17];
    hex(id, r->id, 8);
    ck_printf("artifact: %s admitted id=%s tier=%s exec=", name, r->have_id ? id : "",
              r->tier_test ? "seed0b-test" : "production");
    switch (r->out.status) {
    case ST_EXITED:
        ck_printf("exited:0x%llx", (unsigned long long)r->out.value);
        break;
    case ST_TIMEOUT:
        ck_puts("timeout");
        break;
    case ST_FAULT:
        ck_printf("fault:%s", classify_fault(r));
        break;
    case ST_BAD_SYSCALL:
        ck_printf("bad-syscall:%llu", (unsigned long long)r->out.value);
        break;
    case ST_OVERRUN:
        ck_puts("resource-overrun");
        break;
    default:
        ck_puts("not-run");
        break;
    }
    ck_printf(" bytes=%s wx=%s caps=%u revoked=%s reclaimed=%s frames=%llu syscalls=%u reads=%u "
              "denials=%u\n",
              r->byte_chain ? "identified=verified=admitted=mapped=executed" : "mismatch",
              r->wx_enforced ? "enforced" : "violated", r->caps_installed,
              yn[r->caps_live_after == 0], yn[reclaimed(r)],
              (unsigned long long)r->frames_reserved, r->out.syscalls, r->out.reads_ok,
              r->out.denials);
}

static void print_grants(const char *name, const struct report *r)
{
    if (!r->admitted)
        return;
    for (unsigned i = 0; i < r->caps_installed; i++) {
        const struct cka_cap *g = &r->granted[i];
        const char *kind = g->kind == CKA_KIND_OBJECT    ? "object"
                           : g->kind == CKA_KIND_CHANNEL ? "channel"
                                                         : "other";
        ck_printf("grant: %s[%u] kind=%s id=%u rights=0x%x bounds=%llu+%llu max_ops=%u "
                  "max_bytes=%llu\n",
                  name, i, kind, g->id, g->rights, (unsigned long long)g->off,
                  (unsigned long long)g->len, g->max_ops, (unsigned long long)g->max_bytes);
    }
}

static void print_receipt(const char *name, const struct report *r)
{
    uint64_t seq = receipt_seq++;
    struct cka_receipt rc;
    memset(&rc, 0, sizeof rc);
    int adm = r->admitted;
    rc.decision = adm ? CKR_ADMITTED : CKR_REJECTED;
    rc.tier = CKR_TIER_SEED0B_QEMU;
    rc.seq = seq;
    memcpy(rc.verifier, verifier_id, 32);
    cka_receipt_nonce(verifier_id, seq, rc.nonce);
    rc.status = CKR_NOT_RUN;
    if (adm) {
        static const uint32_t map[] = {CKR_NOT_RUN, CKR_EXITED, CKR_TIMEOUT, CKR_FAULT,
                                       CKR_BAD_SYSCALL, CKR_RESOURCE_OVERRUN};
        rc.status = map[r->out.status];
        if (r->out.status == ST_EXITED)
            rc.exit = (int32_t)(uint32_t)r->out.value;
    }
    uint32_t fl = 0;
    if (reclaimed(r))
        fl |= CKR_F_RECLAIMED;
    if (adm) {
        if (r->out.reads_ok)
            fl |= CKR_F_READ_OK;
        if (r->out.write_denials)
            fl |= CKR_F_WRITE_DENIED;
        if (r->out.invalid_handle)
            fl |= CKR_F_FORGED_DENIED;
        if (rc.status == CKR_EXITED && rc.exit == 0)
            fl |= CKR_F_CANARY;
        if (r->b.mapped_bytes_matched)
            fl |= CKR_F_MAPPED;
        if (r->byte_chain)
            fl |= CKR_F_EXECUTED;
        if (r->b.wx_sealed)
            fl |= CKR_F_WX;
    }
    rc.result_flags = fl;
    rc.stage = adm ? 0 : (uint16_t)r->stage;
    rc.reason = adm ? 0 : (uint16_t)r->error;
    rc.syscalls = adm ? r->out.syscalls : 0;
    rc.reads = adm ? r->out.reads_ok : 0;
    rc.denials = adm ? r->out.denials : 0;
    rc.frames = r->frames_reserved > 0xffffffffull ? 0xffffffffu : (uint32_t)r->frames_reserved;
    memcpy(rc.id, r->b.id, 32);
    memcpy(rc.payload, r->b.payload, 32);
    memcpy(rc.signer, r->b.signer, 32);
    memcpy(rc.policy, r->b.policy, 32);
    memcpy(rc.requested, r->b.requested, 32);
    memcpy(rc.granted, r->b.granted, 32);
    memcpy(rc.resources, r->b.resources, 32);
    if (cka_receipt_validate(&rc)) {
        ck_printf("receipt: %s seq=%llu invalid\n", name, (unsigned long long)seq);
        return;
    }
    static uint8_t rec[CKA_RECEIPT_SIZE];
    static char line[2 * CKA_RECEIPT_SIZE + 1];
    uint8_t dg[32];
    char dh[65];
    cka_receipt_encode(&rc, rec);
    cka_receipt_digest(rec, dg);
    hex(dh, dg, 32);
    hex(line, rec, CKA_RECEIPT_SIZE);
    ck_printf("receipt: %s seq=%llu digest=%s record=", name, (unsigned long long)seq, dh);
    ck_puts(line);
    ck_puts("\n");
}

/* ============================ candidate sources ===================== */

/* Default source: the boot disk. The Store stage (svc/artifact_store.c) read
 * the candidates from the sealed Store on NVMe before revoking the disk's DMA;
 * here they are untrusted bytes and take the same verification path as any
 * candidate. A test-only QEMU fw_cfg side channel exists only in images built
 * with CK_TEST_FWCFG_ARTIFACTS=1 and is compiled out of every default image. */

static struct report rep;
static unsigned run_admitted, run_rejected, run_seen;

static void source_preamble(uint32_t count)
{
    char vh[65], ph[65];
    uint8_t pd[32];
    cka_policy_digest(&policy, pd);
    hex(vh, verifier_id, 32);
    hex(ph, pd, 32);
    ck_printf("artifact_candidates: %u\n", count);
    ck_printf("artifact_receipt_tier: SEED-0B-QEMU\nartifact_verifier_identity: %s\n"
              "artifact_policy_digest: %s\n",
              vh, ph);
    ck_printf("artifact_frames_free_before: %llu\n", (unsigned long long)free_frames());
}

/* Candidate names come from untrusted input: 1..MAX_NAME printable bytes. */
static int candidate_name_ok(const char *name, unsigned *nlen)
{
    unsigned n = 0;
    if (!name)
        return 0;
    while (n <= MAX_NAME && name[n]) {
        if (name[n] <= ' ' || name[n] > '~')
            return 0;
        n++;
    }
    *nlen = n;
    return n >= 1 && n <= MAX_NAME;
}

static void finish_candidate(const char *name)
{
    run_seen++;
    if (rep.admitted)
        run_admitted++;
    else
        run_rejected++;
    print_candidate(name, &rep);
    print_grants(name, &rep);
    print_receipt(name, &rep);
}

#ifndef CK_TEST_FWCFG_ARTIFACTS
static uint32_t disk_source(void)
{
    struct ck_disk_artifacts da;
    const char *why = 0;
    memset(&da, 0, sizeof da);
    if (!ck_stage_disk_artifacts)
        why = "no Store stage in this image";
    else if (ck_stage_disk_artifacts(&da))
        why = "Store stage did not run";
    else if (!da.available)
        why = da.why ? da.why : "no artifacts";
    uint32_t count = why ? 0 : da.count;
    if (count > MAX_CANDIDATES)
        count = MAX_CANDIDATES;
    if (why)
        ck_printf("artifact_source: none (%s)\n", why);
    else
        ck_printf("artifact_source: nvme_store generation=%llu candidates=%u "
                  "(read by the store stage; bytes untrusted until verified)\n",
                  (unsigned long long)da.generation, count);
    source_preamble(count);
    for (uint32_t c = 0; c < count; c++) {
        const struct ck_disk_artifact *a = &da.a[c];
        char name[MAX_NAME + 1];
        unsigned nlen = 0;
        if (!candidate_name_ok(a->name, &nlen))
            break;
        memcpy(name, a->name, nlen);
        name[nlen] = 0;
        if (a->state == CK_DISK_ART_OK && a->bytes && ck_osc_is_unit(a->bytes, a->len)) {
            /* OSCUNIT container (OSC_UNIT_ARTIFACT v1): admission verdict only, not a Binary Artifact. */
            ck_osc_candidate(name, a->bytes, a->len);
            run_seen++;
            continue;
        }
        if (a->state == CK_DISK_ART_OK && a->bytes && a->len >= 1 && a->len <= MAX_BATCH * PAGE)
            process_candidate(a->bytes, a->len, &rep);
        else if (a->state == CK_DISK_ART_TOO_LARGE || a->len > MAX_BATCH * PAGE) {
            /* The Store never reads a too-large entry, so an OSCUNIT among them cannot be recognised:
             * say so on the osc_unit: channel (RESOURCE_UNAVAILABLE) and keep the old refusal. */
            if (a->state == CK_DISK_ART_TOO_LARGE)
                ck_osc_oversize(name, a->len);
            firmware_rejection(&rep, CKL_STAGING_TOO_LARGE);
        } else
            firmware_rejection(&rep, CKL_FIRMWARE_READ); /* missing on disk */
        finish_candidate(name);
    }
    ck_osc_summary();
    return count;
}
#else
/* ======== TEST-ONLY fw_cfg source (CK_TEST_FWCFG_ARTIFACTS=1) ======== */
#define FWCFG_TEST_BANNER                                                            \
    "artifact_source_mode: TEST-ONLY QEMU fw_cfg side channel "                       \
    "(CK_TEST_FWCFG_ARTIFACTS=1); not the boot disk; never counts toward a PASS\n"

static volatile uint8_t *fwcfg;

static void fw_select(uint16_t sel)
{
    *(volatile uint16_t *)(fwcfg + 8) = (uint16_t)((sel >> 8) | (sel << 8)); /* big endian */
    __asm__ volatile("dsb sy" ::: "memory");
}
static void fw_read(uint8_t *out, uint64_t n)
{
    for (uint64_t i = 0; i < n; i++)
        out[i] = fwcfg[0];
}
static void fw_skip(uint64_t n)
{
    for (uint64_t i = 0; i < n; i++)
        (void)fwcfg[0];
}
static uint32_t be32(const uint8_t *b)
{
    return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3];
}

/* The fw_cfg MMIO window from the DSDT: device _HID "QEMU0002", then its
 * _CRS Memory32Fixed descriptor (0x86, length 9). 0 if absent. */
static uint64_t fwcfg_from_dsdt(const char **why)
{
    const uint8_t *fadt = ck_acpi_find("FACP");
    if (!fadt) {
        *why = "no FADT";
        return 0;
    }
    uint32_t flen = cka_rd32(fadt + 4);
    uint64_t dsdt = 0;
    if (flen >= 148)
        dsdt = cka_rd64(fadt + 140);
    if (!dsdt && flen >= 44)
        dsdt = cka_rd32(fadt + 40);
    if (!dsdt || !ck_mm_mapped(dsdt, 36)) {
        *why = "DSDT not mapped";
        return 0;
    }
    const uint8_t *d = (const uint8_t *)(uintptr_t)dsdt;
    uint32_t len = cka_rd32(d + 4);
    if (len < 36 || memcmp(d, "DSDT", 4) || !ck_mm_mapped(dsdt, len)) {
        *why = "DSDT not mapped";
        return 0;
    }
    static const char hid[] = "QEMU0002";
    for (uint32_t i = 36; i + 9 <= len; i++) {
        if (memcmp(d + i, hid, 8))
            continue;
        for (uint32_t j = i + 8; j + 12 <= len && j < i + 8 + 96; j++)
            if (d[j] == 0x86 && d[j + 1] == 0x09 && d[j + 2] == 0x00) {
                uint64_t base = cka_rd32(d + j + 4), size = cka_rd32(d + j + 8);
                if (base && size >= 0x10)
                    return base;
            }
    }
    *why = "no QEMU0002 device";
    return 0;
}

/* Finds "opt/aienos/artifacts": selector and size, -1 if absent. */
static int fw_find(uint16_t *sel, uint32_t *size)
{
    uint8_t b[64];
    fw_select(0x19);
    fw_read(b, 4);
    uint32_t n = be32(b);
    for (uint32_t i = 0; i < n && i < 4096; i++) {
        fw_read(b, 64);
        b[63] = 0;
        if (!memcmp(b + 8, "opt/aienos/artifacts", 21)) {
            *sel = (uint16_t)(b[4] << 8 | b[5]);
            *size = be32(b);
            return 0;
        }
    }
    return -1;
}

static uint32_t fwcfg_source(void)
{
    const char *why = 0;
    uint64_t base = fwcfg_from_dsdt(&why);
    uint16_t sel = 0;
    uint32_t size = 0;
    if (base && !ck_mm_mmio_try_map(base, 0x18))
        why = "fw_cfg window not mappable", base = 0;
    if (base) {
        fwcfg = (volatile uint8_t *)(uintptr_t)base;
        uint8_t sig[4];
        fw_select(0);
        fw_read(sig, 4);
        if (memcmp(sig, "QEMU", 4))
            why = "fw_cfg signature", base = 0;
        else if (fw_find(&sel, &size))
            why = "no opt/aienos/artifacts", base = 0;
    }
    uint8_t hdr[12];
    uint32_t count = 0;
    if (base) {
        fw_select(sel);
        if (size < 12)
            why = "bundle too short", base = 0;
        else {
            fw_read(hdr, 12);
            if (memcmp(hdr, "AIENBND", 8))
                why = "bundle magic", base = 0;
            else
                count = cka_rd32(hdr + 8);
        }
    }
    if (!base)
        ck_printf("artifact_source: none (%s)\n", why);
    else
        ck_printf("artifact_source: fw_cfg TEST-ONLY base=0x%llx file=opt/aienos/artifacts bytes=%u\n",
                  (unsigned long long)base, size);
    if (count > MAX_CANDIDATES)
        count = MAX_CANDIDATES;
    source_preamble(count);

    uint64_t left = size >= 12 ? size - 12 : 0;
    for (uint32_t c = 0; c < count; c++) {
        uint8_t nb[2], lb[4];
        char name[MAX_NAME + 1];
        unsigned ok_len = 0;
        if (left < 2)
            break;
        fw_read(nb, 2);
        left -= 2;
        unsigned nlen = cka_rd16(nb);
        if (nlen == 0 || nlen > MAX_NAME || left < nlen + 4ull)
            break;
        fw_read((uint8_t *)name, nlen);
        name[nlen] = 0;
        fw_read(lb, 4);
        left -= nlen + 4ull;
        uint64_t len = cka_rd32(lb);
        if (len > left)
            break;
        left -= len;
        if (!candidate_name_ok(name, &ok_len) || ok_len != nlen)
            break;
        uint64_t pages = (len + PAGE - 1) / PAGE, in = 0;
        if (len > MAX_BATCH * PAGE) {
            fw_skip(len);
            firmware_rejection(&rep, CKL_STAGING_TOO_LARGE);
        } else if (len && ck_mm_frames_alloc(pages, &in)) {
            fw_skip(len);
            firmware_rejection(&rep, CKL_FIRMWARE_READ);
        } else {
            if (len)
                fw_read(mem(in), len);
            process_candidate(len ? mem(in) : (const uint8_t *)"", len, &rep);
            if (len) {
                memset(mem(in), 0, pages * PAGE);
                ck_mm_frames_free(in, pages);
            }
        }
        finish_candidate(name);
    }
    return count;
}
#endif

void ck_artifact_run(void)
{
    static int ran;
    if (ran)
        return;
    ran = 1;
    ck_set_stage("artifacts");
#ifdef CK_SEED0B_TEST_ANCHOR
    ck_puts("artifact_trust: seed0b-test qualification build \xe2\x80\x94 TEST ONLY\n");
#endif
#ifdef CK_TEST_FWCFG_ARTIFACTS
    ck_puts(FWCFG_TEST_BANNER);
#endif
    if (NANCHORS)
        cka_boot_policy(&policy, anchors, NANCHORS);
    else
        cka_boot_policy(&policy, 0, 0);
    cka_verifier_identity(AIENOS_COMMIT, FEATURE_TEST_ANCHOR, verifier_id);

#ifdef CK_TEST_FWCFG_ARTIFACTS
    uint32_t count = fwcfg_source();
#else
    uint32_t count = disk_source();
#endif
    if (run_seen != count)
        ck_printf("artifact_bundle: malformed after %u of %u candidates\n", run_seen, count);
    ck_printf("artifact_frames_free_after: %llu\n", (unsigned long long)free_frames());
    ck_artifact_summary.candidates = count;
    ck_artifact_summary.admitted = run_admitted;
    ck_artifact_summary.rejected = run_rejected;
#ifndef CK_TEST_FWCFG_ARTIFACTS
    if (ck_stage_disk_artifacts_free)
        ck_stage_disk_artifacts_free();
#endif
}


void ck_artifact_final(void)
{
#ifdef CK_SEED0B_TEST_ANCHOR
    ck_puts("artifact_trust: seed0b-test qualification build \xe2\x80\x94 TEST ONLY\n");
#endif
#ifdef CK_TEST_FWCFG_ARTIFACTS
    ck_puts(FWCFG_TEST_BANNER);
#endif
    ck_printf("artifacts: candidates=%u admitted=%u rejected=%u\n", ck_artifact_summary.candidates,
              ck_artifact_summary.admitted, ck_artifact_summary.rejected);
}
