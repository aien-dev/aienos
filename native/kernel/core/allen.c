/* allen.c -- the ALLEN exam stage of the pi5-allen image (PI5-8 cut K): ALLEN REFLEX (crates/allen-reflex, linked as
 * the Rust staticlib crates/allen-reflex-kernel, Makefile CK_ALLEN_LIB) decides every case of the card exam file
 * (core/allen.h) and every decision goes through the ALLEN gate (core/allen_gate.h), which only judges.
 * Only compiled in with CK_ALLEN=1; every other image gets the empty stub at the end.
 *
 * Per mode (reflex, nearest, perceptron, the order of the host harness crates/allen-reflex-kernel/examples/host_exam.rs):
 * train a fresh core on the compiled-in training pool (learning off afterwards: amendment 6), then two passes over the
 * cases. Pass 1 prints one decision line per case, exactly the host harness's line
 *     ALLEN_D <mode> <id> <decision json>
 * and one gate line
 *     ALLEN_G <mode> <id> <verdict> <verb> ns=<decision ns>
 * Pass 2 decides every case again and compares each line with pass 1 (repeated decisions, amendment 11). Then one
 *     ALLEN_STAT mode=... init_us=... decide_ns_median=... p90=... p99=... max=... heap_peak=... ...
 * line. The timed span of a decision is the Rust decision itself (turn split + core + JSON); card parsing, training,
 * the gate, line copies and console/klog printing are timed or excluded separately (amendment 11).
 *
 * Gate state: every case is judged against a fresh READY lifecycle (rehearsal: there is no Store in this image and
 * nothing is applied); the stage checks that the judgement left that state byte-for-byte unchanged and that no
 * approve/deny/cancel ever came out PROPOSED.
 *
 * Memory: one region of CK_ALLEN_HEAP_KIB KiB (default 32 MiB, = ALLEN_HEAP_BYTES in
 * crates/allen-reflex-kernel/tests/heap_budget.rs) from the frame allocator, handed to the Rust bump heap and returned
 * at the end. Exhaustion, or any Rust panic, ends in aienos_allen_panic: it prints ALLEN_ABORT and halts through
 * ck_panic, so the decision in progress is never printed, never judged, and nothing is written (no Store stage).
 *
 * FP/SIMD: the Rust unit uses them; it runs with CPACR_EL1.FPEN = 0b11 and every exception masked (DAIF) for the
 * whole stage, because the kernel saves no FP state (as core/fpu.c and core/infer.c). */
#include <stdint.h>
#include <stddef.h>

#include "arch.h"
#include "ck_internal.h"

#ifdef CK_ALLEN
#include "allen.h"
#include "allen_gate.h"
#include "sha256.h"

#ifndef CK_ALLEN_HEAP_KIB
#define CK_ALLEN_HEAP_KIB 32768
#endif
#define ALLEN_HEAP_BYTES ((uint64_t)(CK_ALLEN_HEAP_KIB) << 10)
#define PAGE 4096ull
#define CASES_MAX 512u /* = card::CASES_MAX */
#define LINE_CAP 8192u /* = the Rust line String capacity */

/* #[repr(C)] mirrors of crates/allen-reflex-kernel/src/{heap.rs Stats, kernel.rs TrainInfo, DecideInfo} */
struct allen_heap_stats {
    uint64_t cap, used, peak, live, live_peak, allocs, fails;
};
struct allen_train_info {
    uint64_t ticks, examples, exemplars, memory_bytes;
};
struct allen_decide_info {
    uint64_t len, json_off, ticks, heap_reset;
};

extern uint64_t aienos_allen_tick_hz(void);
extern void aienos_allen_heap_init(uintptr_t base, size_t len);
extern void aienos_allen_heap_stats(struct allen_heap_stats *out);
extern int32_t aienos_allen_card_open(const uint8_t *buf, size_t len, const char **why);
extern int32_t aienos_allen_train(uint32_t mode, struct allen_train_info *out);
extern int32_t aienos_allen_decide(uint32_t i, char *line, size_t cap, struct allen_decide_info *out);
extern void aienos_allen_close(void);

static const char *const mode_name[3] = {"reflex", "nearest", "perceptron"};

static char line[LINE_CAP];
static uint64_t dticks[CASES_MAX], gticks[CASES_MAX], sorted[CASES_MAX];
static uint64_t first_hash[CASES_MAX], first_len[CASES_MAX];
static char panic_msg[200];

/* Rust panic or heap exhaustion: say why, then halt through the kernel's panic path. Never returns. */
__attribute__((noreturn)) void aienos_allen_panic(const uint8_t *msg, size_t len)
{
    size_t n = len < sizeof panic_msg - 1 ? len : sizeof panic_msg - 1;
    for (size_t i = 0; i < n; i++) panic_msg[i] = (msg[i] >= 0x20 && msg[i] <= 0x7e) ? (char)msg[i] : '?';
    panic_msg[n] = 0;
    ck_printf("ALLEN_ABORT reason=%s\n", panic_msg);
    ck_printf("AIENOS_CK_ALLEN: ABORT (decision stopped, nothing judged, nothing written)\n");
    ck_panic("allen: Rust unit stopped: %s", panic_msg);
}

static void pet(void)
{
    if (ck_pi5_stage) ck_pi5_stage("allen");
}

static uint64_t ticks(void)
{
    ck_isb();
    return ck_rd(cntvct_el0);
}

static uint64_t fnv(const char *s, size_t n)
{
    uint64_t h = 0xcbf29ce484222325ull;
    for (size_t i = 0; i < n; i++) h = (h ^ (uint8_t)s[i]) * 0x100000001b3ull;
    return h;
}

/* ticks -> ns at hz (hz <= 1 GHz, ticks well under 2^34 for any one decision) */
static uint64_t ns(uint64_t t, uint64_t hz) { return hz ? t * 1000000000ull / hz : 0; }

/* sorted copy of v[0..n) into sorted[] (insertion sort, n <= 512, outside every timed span) */
static void sort_into(const uint64_t *v, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        uint64_t x = v[i];
        uint32_t j = i;
        while (j > 0 && sorted[j - 1] > x) {
            sorted[j] = sorted[j - 1];
            j--;
        }
        sorted[j] = x;
    }
}

/* nearest-rank percentile of sorted[0..n) */
static uint64_t pct(uint32_t n, uint32_t p)
{
    if (!n) return 0;
    uint32_t r = (uint32_t)(((uint64_t)p * n + 99) / 100);
    if (r < 1) r = 1;
    return sorted[r - 1];
}

/* "ALLEN_D <mode> <id> <json>": the id is the third field */
static void id_of(const char *l, const char **id, size_t *idl)
{
    size_t i = 0, sp = 0;
    while (l[i] && sp < 2) {
        if (l[i] == ' ') sp++;
        i++;
    }
    size_t s = i;
    while (l[i] && l[i] != ' ') i++;
    *id = l + s;
    *idl = i - s;
}

static void fpu_on(void)
{
    uint64_t v = ck_rd(cpacr_el1);
    v |= 3ull << 20; /* CPACR_EL1.FPEN = 0b11: no FP/SIMD trap at EL1 */
    ck_wr(cpacr_el1, v);
    ck_isb();
}

/* one mode: train, pass 1 (print + judge), pass 2 (compare), stats. 1 = all checks held. */
static int run_mode(uint32_t mode, uint32_t ncases, uint64_t hz)
{
    struct allen_train_info ti = {0, 0, 0, 0};
    pet();
    int32_t trc = aienos_allen_train(mode, &ti);
    pet();
    if (trc != 0) {
        ck_printf("ALLEN_STAT mode=%s train_rc=%d\n", mode_name[mode], (int)trc);
        return 0;
    }
    uint32_t resets = 0, rc_bad = 0, identical = 0, authority_leak = 0, lc_changed = 0;
    uint32_t verdicts[5] = {0, 0, 0, 0, 0};
    uint64_t print_t = 0;
    for (uint32_t pass = 0; pass < 2; pass++) {
        for (uint32_t i = 0; i < ncases; i++) {
            struct allen_decide_info di = {0, 0, 0, 0};
            int32_t rc = aienos_allen_decide(i, line, sizeof line, &di);
            if (rc != 0 || di.len >= sizeof line || di.json_off > di.len) {
                rc_bad++;
                ck_printf("ALLEN_ERR mode=%s case=%u rc=%d\n", mode_name[mode], (unsigned)i, (int)rc);
                continue;
            }
            resets += di.heap_reset ? 1u : 0u;
            uint64_t h = fnv(line, (size_t)di.len);
            if (pass == 1) {
                identical += (h == first_hash[i] && di.len == first_len[i]) ? 1u : 0u;
                continue;
            }
            first_hash[i] = h;
            first_len[i] = di.len;
            dticks[i] = di.ticks;

            /* the gate, against a fresh READY lifecycle that must come out unchanged */
            ck_lc lc, before;
            ck_lc_init(&lc);
            ck_lc_start(&lc, 1);
            before = lc;
            struct ck_allen_gate g;
            uint64_t g0 = ticks();
            ck_allen_gate_judge(line + di.json_off, (size_t)(di.len - di.json_off), &lc, &g);
            gticks[i] = ticks() - g0;
            {
                const uint8_t *a = (const uint8_t *)&lc, *b = (const uint8_t *)&before;
                for (size_t k = 0; k < sizeof lc; k++)
                    if (a[k] != b[k]) {
                        lc_changed++;
                        break;
                    }
            }
            if (g.verdict == CK_ALLEN_PROPOSED &&
                (g.verb == CK_LC_V_APPROVE || g.verb == CK_LC_V_DENY || g.verb == CK_LC_V_CANCEL))
                authority_leak++;
            verdicts[g.verdict <= CK_ALLEN_REJECTED ? g.verdict : CK_ALLEN_REJECTED]++;

            const char *id;
            size_t idl;
            id_of(line, &id, &idl);
            char idz[20];
            size_t k;
            for (k = 0; k < idl && k < sizeof idz - 1; k++) idz[k] = id[k];
            idz[k] = 0;
            uint64_t p0 = ticks();
            ck_printf("%s\n", line);
            ck_printf("ALLEN_G %s %s %s %s ns=%llu\n", mode_name[mode], idz, ck_allen_verdict_name(g.verdict),
                      g.verb == CK_LC_V_UNKNOWN ? "-" : ck_lc_verb_name(g.verb), (unsigned long long)ns(di.ticks, hz));
            print_t += ticks() - p0;
            if ((i & 15u) == 15u) pet();
        }
        pet();
    }
    struct allen_heap_stats hs;
    aienos_allen_heap_stats(&hs);
    uint64_t sum = 0;
    for (uint32_t i = 0; i < ncases; i++) sum += dticks[i];
    sort_into(dticks, ncases);
    uint64_t med = pct(ncases, 50), p90 = pct(ncases, 90), p99 = pct(ncases, 99), mx = sorted[ncases - 1];
    uint64_t mn = sorted[0];
    sort_into(gticks, ncases);
    uint64_t gmed = pct(ncases, 50), gmx = sorted[ncases - 1];
    ck_printf("ALLEN_STAT mode=%s cases=%u init_us=%llu examples=%llu exemplars=%llu memory_bytes=%llu "
              "decide_ns_min=%llu decide_ns_median=%llu decide_ns_p90=%llu decide_ns_p99=%llu decide_ns_max=%llu "
              "decide_ns_mean=%llu gate_ns_median=%llu gate_ns_max=%llu print_us=%llu\n",
              mode_name[mode], (unsigned)ncases, (unsigned long long)(ns(ti.ticks, hz) / 1000),
              (unsigned long long)ti.examples, (unsigned long long)ti.exemplars, (unsigned long long)ti.memory_bytes,
              (unsigned long long)ns(mn, hz), (unsigned long long)ns(med, hz), (unsigned long long)ns(p90, hz),
              (unsigned long long)ns(p99, hz), (unsigned long long)ns(mx, hz),
              (unsigned long long)ns(sum / ncases, hz), (unsigned long long)ns(gmed, hz),
              (unsigned long long)ns(gmx, hz), (unsigned long long)(ns(print_t, hz) / 1000));
    ck_printf("ALLEN_HEAP mode=%s cap=%llu peak=%llu live_peak=%llu used_now=%llu allocs=%llu fails=%llu "
              "resets=%u/%u repeat_identical=%u/%u\n",
              mode_name[mode], (unsigned long long)hs.cap, (unsigned long long)hs.peak,
              (unsigned long long)hs.live_peak, (unsigned long long)hs.used, (unsigned long long)hs.allocs,
              (unsigned long long)hs.fails, (unsigned)resets, (unsigned)(2 * ncases), (unsigned)identical,
              (unsigned)ncases);
    ck_printf("ALLEN_GATE mode=%s no_command=%u proposed=%u needs_operator=%u refused=%u rejected=%u "
              "authority_leaks=%u lifecycle_changed=%u\n",
              mode_name[mode], (unsigned)verdicts[CK_ALLEN_NO_COMMAND], (unsigned)verdicts[CK_ALLEN_PROPOSED],
              (unsigned)verdicts[CK_ALLEN_NEEDS_OPERATOR], (unsigned)verdicts[CK_ALLEN_REFUSED],
              (unsigned)verdicts[CK_ALLEN_REJECTED], (unsigned)authority_leak, (unsigned)lc_changed);
    return rc_bad == 0 && resets == 2 * ncases && identical == ncases && hs.fails == 0 && authority_leak == 0 &&
           lc_changed == 0;
}

void ck_allen_run(void)
{
    ck_set_stage("allen");
    ck_printf("allen: ALLEN REFLEX exam stage (PI5-8 cut K, QUALIFICATION ONLY: train/dev rehearsal, no Store, "
              "decisions judged by the ALLEN gate and never applied)\n");
    if (ck_allen_boot.state != CK_ALLEN_EXM_FOUND) {
        ck_printf("allen: no exam file (%s)\nAIENOS_CK_ALLEN: NOT_RUN\n",
                  ck_allen_boot.state == CK_ALLEN_EXM_REFUSED ? "refused by the stub" : "absent");
        return;
    }
    uint8_t dg[SHA256_DIGEST_SIZE];
    sha256_hash(ck_allen_boot.buf, ck_allen_boot.len, dg);
    char hex[2 * SHA256_DIGEST_SIZE + 1];
    for (unsigned i = 0; i < SHA256_DIGEST_SIZE; i++) {
        hex[2 * i] = "0123456789abcdef"[dg[i] >> 4];
        hex[2 * i + 1] = "0123456789abcdef"[dg[i] & 15];
    }
    hex[2 * SHA256_DIGEST_SIZE] = 0;

    uint64_t frames_before = ck_mm_free_frames(), hpa = 0;
    if (ck_mm_frames_alloc(ALLEN_HEAP_BYTES / PAGE, &hpa)) {
        ck_printf("allen: no frames for the %llu-byte heap\nAIENOS_CK_ALLEN: FAIL\n", (unsigned long long)ALLEN_HEAP_BYTES);
        return;
    }
    fpu_on();
    uint64_t daif = ck_rd(daif);
    __asm__ volatile("msr daifset, #0xf" ::: "memory");
    uint64_t hz = aienos_allen_tick_hz();
    aienos_allen_heap_init((uintptr_t)hpa, (size_t)ALLEN_HEAP_BYTES);

    const char *why = 0;
    uint64_t c0 = ticks();
    int32_t n = aienos_allen_card_open(ck_allen_boot.buf, ck_allen_boot.len, &why);
    uint64_t c1 = ticks();
    ck_printf("ALLEN_CARD cases=%d bytes=%u sha256=%s parse_us=%llu heap_bytes=%llu tick_hz=%llu\n", (int)n,
              (unsigned)ck_allen_boot.len, hex, (unsigned long long)(ns(c1 - c0, hz) / 1000),
              (unsigned long long)ALLEN_HEAP_BYTES, (unsigned long long)hz);
    int ok = n > 0 && (uint32_t)n <= CASES_MAX;
    if (!ok) ck_printf("allen: exam file refused (%s)\n", why ? why : "case count");
    for (uint32_t m = 0; ok && m < 3; m++) ok = run_mode(m, (uint32_t)n, hz) && ok;

    aienos_allen_close();
    struct allen_heap_stats hs;
    aienos_allen_heap_stats(&hs);
    aienos_allen_heap_init(0, 0);
    ck_wr(daif, daif);
    int f = ck_mm_frames_free(hpa, ALLEN_HEAP_BYTES / PAGE);
    uint64_t frames_after = ck_mm_free_frames();
    ok = ok && f == 0 && frames_after == frames_before && hs.live == 0;
    ck_printf("allen: closed heap_live=%llu heap_fails=%llu frames_free_before=%llu frames_free_after=%llu rc=%d\n",
              (unsigned long long)hs.live, (unsigned long long)hs.fails, (unsigned long long)frames_before,
              (unsigned long long)frames_after, f);
    ck_printf("AIENOS_CK_ALLEN: %s\n", ok ? "PASS" : "FAIL");
}
#else
void ck_allen_run(void) {}
#endif
