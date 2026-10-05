/* continuity_boot.c -- see continuity_boot.h. TEST-ONLY; empty unless
 * CK_TEST_CONTINUITY=1 (make full CK_TEST_CONTINUITY=1).
 *
 * Marker text is produced by cr_marker_* / rc_marker_* (contract section 3);
 * this file only chooses what to run and prints. Oracle: the Rust
 * continuity_phase and recovery_phase in crates/aienos-boot/src/nvme_read.rs
 * :1100-1400. */
#include "continuity_boot.h"

#ifdef CK_TEST_CONTINUITY
#ifdef CK_HARDWARE_STAGING
#error "CK_TEST_CONTINUITY (TEST-ONLY continuity mode selection) cannot be combined with CK_HARDWARE_STAGING"
#endif
#ifdef CK_QEMU_UNSAFE_DMA
#error "CK_TEST_CONTINUITY cannot be combined with CK_QEMU_UNSAFE_DMA"
#endif
#ifdef CK_TEST_STORE_CRASH
#error "CK_TEST_CONTINUITY cannot be combined with CK_TEST_STORE_CRASH"
#endif
#include <stddef.h>
#include <string.h>

#include "ck.h"
#include "continuity_recovery.h"
#include "continuity_subject_provision.h"
#include "disk_layout.h"
#include "entropy.h"
#include "fmt.h"
#include "m5.h"
#include "sha256.h"
#include "store_boot.h"

#define PLAN_MAGIC "AIENCONT v1 "

/* TEST operator key of the Rust qualification (store_qual.rs:59-63). */
static const uint8_t k_test_operator_key[32] = {
    0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
    0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f};

struct plan {
    int mode;
    int cp; /* -1 none */
    int have_response;
    uint8_t response[32];
    int have_lineage; /* mode 5: provision WITH the ALLEN subject (OS-0018) */
    uint8_t lineage[32];
    int have_intent; /* mode 5 with lineage: one standing intent after genesis */
    uint64_t intent[2];
    uint8_t request[32]; /* SHA-256 of the plan line: the provisioning request */
};

static const int k_cps[] = {ST_CP_BEFORE_FIRST_WRITE, ST_CP_AFTER_PAYLOAD_OBJECTS, ST_CP_AFTER_CATALOG,
                            ST_CP_AFTER_COMMIT_RECORD, ST_CP_AFTER_FIRST_FLUSH, ST_CP_AFTER_INACTIVE_SUPERBLOCK,
                            ST_CP_AFTER_FINAL_FLUSH, SS_CP_BEFORE_ANCHOR, SS_CP_AFTER_ANCHOR};

static const char *cp_name(int cp)
{
    if (cp == SS_CP_BEFORE_ANCHOR) return "before_anchor";
    if (cp == SS_CP_AFTER_ANCHOR) return "after_anchor";
    return st_checkpoint_name(cp);
}

static size_t str_len(const char *s)
{
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static int hexv(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* Parses "AIENCONT v1 mode=N[ cp=NAME][ response=64hex]\n" (nothing but zeros
 * after the newline). 0 ok, -1 malformed. */
static int parse_plan(const char *p, size_t len, struct plan *out)
{
    size_t i = sizeof PLAN_MAGIC - 1;
    memset(out, 0, sizeof *out);
    out->cp = -1;
    int have_mode = 0;
    while (i < len && p[i] != '\n') {
        size_t s = i;
        while (i < len && p[i] != ' ' && p[i] != '\n') i++;
        size_t n = i - s;
        const char *w = p + s;
        if (n > 5 && !memcmp(w, "mode=", 5)) {
            int v = 0;
            for (size_t k = 5; k < n; k++) {
                if (w[k] < '0' || w[k] > '9' || v > 100) return -1;
                v = v * 10 + (w[k] - '0');
            }
            out->mode = v;
            have_mode = 1;
        } else if (n > 3 && !memcmp(w, "cp=", 3)) {
            for (size_t k = 0; k < sizeof k_cps / sizeof k_cps[0]; k++) {
                const char *nm = cp_name(k_cps[k]);
                if (str_len(nm) == n - 3 && !memcmp(w + 3, nm, n - 3)) out->cp = k_cps[k];
            }
            if (out->cp < 0) return -1;
        } else if (n == 9 + 64 && !memcmp(w, "response=", 9)) {
            for (size_t k = 0; k < 32; k++) {
                int hi = hexv(w[9 + 2 * k]), lo = hexv(w[10 + 2 * k]);
                if (hi < 0 || lo < 0) return -1;
                out->response[k] = (uint8_t)(hi << 4 | lo);
            }
            out->have_response = 1;
        } else if (n == 8 + 64 && !memcmp(w, "lineage=", 8)) {
            for (size_t k = 0; k < 32; k++) {
                int hi = hexv(w[8 + 2 * k]), lo = hexv(w[9 + 2 * k]);
                if (hi < 0 || lo < 0) return -1;
                out->lineage[k] = (uint8_t)(hi << 4 | lo);
            }
            out->have_lineage = 1;
        } else if (n > 7 && !memcmp(w, "intent=", 7)) {
            /* intent=<regime>,<target ns>: one CS_INTENT_GOAL_LATENCY intent. */
            size_t k = 7;
            for (int f = 0; f < 2; f++) {
                uint64_t v = 0;
                size_t d = 0;
                while (k < n && w[k] >= '0' && w[k] <= '9' && d < 19) {
                    v = v * 10 + (uint64_t)(w[k] - '0');
                    k++;
                    d++;
                }
                if (!d) return -1;
                out->intent[f] = v;
                if (f == 0) {
                    if (k >= n || w[k] != ',') return -1;
                    k++;
                }
            }
            if (k != n) return -1;
            out->have_intent = 1;
        } else {
            return -1;
        }
        if (i < len && p[i] == ' ') i++;
    }
    if (!have_mode || i >= len) return -1;
    {
        sha256_ctx h; /* the provisioning request: the plan line up to its newline */
        sha256_init(&h);
        sha256_update(&h, (const uint8_t *)p, i);
        sha256_final(&h, out->request);
    }
    for (i = i + 1; i < len; i++)
        if (p[i]) return -1;
    return 0;
}

/* ---- the entropy source: the kernel's RNDR or a refusal, no fallback ---- */
static int ent_present(void *ctx)
{
    (void)ctx;
    return ck_entropy_status() == CK_RNG_OK;
}
static int ent_read(void *ctx, uint64_t *out)
{
    (void)ctx;
    uint64_t w = 0;
    if (ck_entropy_fill(&w, sizeof w) != 0) return 0;
    *out = w;
    return 1;
}
static const struct ck_rng_ops k_ent_ops = {ent_present, ent_read, 0};

/* ---- workspace (heap, once) ---- */
static struct {
    ss_workspace *ws;
    ss_store *s;
    struct cr_work *w;
    struct cr_txwork *tw;
    struct cr_view *v, *v2;
    struct cc_state *st;
    struct cs_subject *subj, *subj2; /* ALLEN (OS-0018) */
    st_disk sd;
    st_dev sdev;
    ts_device tdev;
    ss_keys keys;
    uint64_t store_base_lba, store_units;
    uint32_t bpu;
} g;

static int alloc_all(void)
{
    g.ws = ck_alloc(sizeof *g.ws);
    g.s = ck_alloc(sizeof *g.s);
    g.w = ck_alloc(sizeof *g.w);
    g.tw = ck_alloc(sizeof *g.tw);
    g.v = ck_alloc(sizeof *g.v);
    g.v2 = ck_alloc(sizeof *g.v2);
    g.st = ck_alloc(sizeof *g.st);
    g.subj = ck_alloc(sizeof *g.subj);
    g.subj2 = ck_alloc(sizeof *g.subj2);
    return g.ws && g.s && g.w && g.tw && g.v && g.v2 && g.st && g.subj && g.subj2 ? 0 : -1;
}

static void line(const char *s)
{
    ck_puts(s);
    ck_puts("\n");
}

static void print_view(const char *word, const struct cr_view *v)
{
    char b[256];
    if (cr_marker_view(b, sizeof b, word, v)) line(b);
}
static void print_outcome(int outcome, const char *why, int store_rc)
{
    char b[256];
    if (cr_marker_outcome(b, sizeof b, outcome, why, store_rc)) line(b);
}

static void hex_into(char *o, const uint8_t *b, size_t n)
{
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        o[2 * i] = hx[b[i] >> 4];
        o[2 * i + 1] = hx[b[i] & 15];
    }
    o[2 * n] = 0;
}

/* Observation hook for mode 8: print every checkpoint; halt at the planned one
 * (the host kills QEMU on seeing the marker; the halt only keeps the guest from
 * going on). Nothing is flushed or written here. */
static void cont_hook(void *arg, int cp)
{
    const struct plan *p = arg;
    ck_printf("CHECKPOINT: %s\n", cp_name(cp));
    if (p->cp == cp) {
        ck_printf("continuity: HALT at %s (the host kills QEMU now)\n", cp_name(cp));
        for (;;) __asm__ volatile("wfi");
    }
}

static int is_blank(const disk_dev *d, uint8_t *buf)
{
    for (uint64_t u = 0; u < CK_LAYOUT_ANCHOR_UNITS + 2u; u++) {
        if (disk_read(d, u * g.bpu, g.bpu, buf)) return 0;
        for (uint32_t i = 0; i < CK_LAYOUT_UNIT; i++)
            if (buf[i]) return 0;
    }
    return 1;
}

static void fact(struct cc_record *r, const char *s)
{
    memset(r, 0, sizeof *r);
    r->status = CC_EPI_DIRECT_OBSERVATION;
    r->len = (uint16_t)str_len(s);
    r->statement = (const uint8_t *)s;
}

static void recovery_record_line(const struct rc_record *r)
{
    char b[400];
    size_t n = 0;
    n += ck_snprintf(b + n, sizeof b - n, "RECOVERY_RECORD:");
    for (int i = 0; i < 2; i++) {
        switch (r->slot[i]) {
        case RC_SLOT_ZERO: n += ck_snprintf(b + n, sizeof b - n, " slot%d=zero", i); break;
        case RC_SLOT_SUPERBLOCK:
            n += ck_snprintf(b + n, sizeof b - n, " slot%d=gen%llu", i, (unsigned long long)r->slot_generation[i]);
            break;
        case RC_SLOT_UNDECODABLE: n += ck_snprintf(b + n, sizeof b - n, " slot%d=undecodable", i); break;
        default: n += ck_snprintf(b + n, sizeof b - n, " slot%d=read-error", i); break;
        }
    }
    if (r->have_mount)
        n += ck_snprintf(b + n, sizeof b - n, " mount=%s peer=%s generation=%llu",
                         r->mount_state == ST_VALID ? "Valid" : "DegradedRecovery", rc_peer_name(r->peer),
                         (unsigned long long)r->generation);
    if (r->have_catalog)
        n += ck_snprintf(b + n, sizeof b - n, " roots=%u manifests=%u other=%u", r->n_roots, r->n_manifests, r->n_other);
    n += ck_snprintf(b + n, sizeof b - n, " agent=");
    if (r->have_identity)
        hex_into(b + n, r->agent_id, 32);
    else
        ck_snprintf(b + n, sizeof b - n, "none");
    line(b);
}

static void recovery_phase(const disk_dev *d, const struct plan *p)
{
    (void)d;
    line("RECOVERY_OPERATOR_KEY: TEST-ONLY");
    struct rc_env e;
    memset(&e, 0, sizeof e);
    e.dev = &g.sdev;
    e.anchor = &g.tdev;
    e.anchor_lba = 0;
    e.keys = &g.keys;
    e.ws = g.ws;
    e.store = g.s;
    e.w = g.w;
    e.tw = g.tw;
    e.view = g.v2;
    static struct rc_record rec, after;
    if (rc_inspect(&e, &rec) != 0) {
        line("RECOVERY_REFUSED (Io)");
        return;
    }
    recovery_record_line(&rec);
    char b[256];
    if (rc_marker_entry(b, sizeof b, &rec)) line(b);
    int action = rc_applicable(&rec);
    if (action && rc_marker_challenge(b, sizeof b, &rec, (uint8_t)action)) line(b);
    if (p->mode == 9) return;

    int rc, cro = 0, srr = 0;
    const char *why = 0;
    uint8_t agent[32];
    int have_agent = 0;
    if (p->mode == 10) {
        rc = rc_repair_degraded_peer(&e, k_test_operator_key, p->response, &after);
    } else {
        struct ck_rng rng;
        memset(&rng, 0, sizeof rng);
        if (ck_rng_probe(&rng, &k_ent_ops) != CK_RNG_OK) {
            line("RECOVERY_REFUSED (NoEntropy)");
            return;
        }
        rc = rc_provision_identity(&e, k_test_operator_key, p->response, &rng, g.v, &cro, &why, &srr);
        if (rc == RC_OK) {
            memcpy(agent, g.v->root.agent_id, 32);
            have_agent = 1;
        }
    }
    if (rc == RC_OK) {
        uint8_t a = p->mode == 10 ? CR_ACTION_REPAIR_DEGRADED_PEER : CR_ACTION_PROVISION_IDENTITY;
        if (rc_marker_done(b, sizeof b, a, have_agent ? agent : 0)) line(b);
    } else if (rc_marker_refused(b, sizeof b, rc, cro)) {
        line(b);
    }
}

/* ---- ALLEN (ARCH-0035 / OS-0018, PROPOSED) ----
 * Provision (mode 5 with lineage=): identity and the genesis subject in ONE
 * Store transaction (cs_provision), then, if intent= is given, one standing
 * intent as subject sequence 2 through cs_commit (its own transaction).
 * Restore (modes 6..8): the subject is resolved read-only BEFORE anything is
 * written. RESOLVED is reported; ABSENT is reported and never minted;
 * anything else (corrupt, forked, foreign, unreadable) stops the boot with
 * nothing written. Markers:
 *   ALLEN: GENESIS|INTENDED|RESTORED subject=<64> sequence=<n> agent=<64> lineage=<64> intents=<n> active=<n>
 *   ALLEN: INTENT id=<64> kind=<k> regime=<r> target_ns=<t> since=<s>    (each ACTIVE intent)
 *   ALLEN: ABSENT (...)   ALLEN: CORRUPT (<why>)   ALLEN: STOP (<outcome>) */
static void allen_lines(const char *word, const struct cs_subject *s, const uint8_t id[32])
{
    char b[400], sub[65], ag[65], ln[65];
    uint32_t active = 0;
    for (uint32_t i = 0; i < s->n_intents; i++) active += s->in[i].state == CS_ACTIVE;
    hex_into(sub, id, 32);
    hex_into(ag, s->agent, 32);
    hex_into(ln, s->cortex, 32);
    ck_snprintf(b, sizeof b, "ALLEN: %s subject=%s sequence=%llu agent=%s lineage=%s intents=%u active=%u", word, sub,
                (unsigned long long)s->sequence, ag, ln, (unsigned)s->n_intents, (unsigned)active);
    line(b);
    for (uint32_t i = 0; i < s->n_intents; i++) {
        const struct cs_intent *a = &s->in[i];
        if (a->state != CS_ACTIVE) continue;
        hex_into(sub, a->id, 32);
        ck_snprintf(b, sizeof b, "ALLEN: INTENT id=%s kind=%u regime=%llu target_ns=%llu since=%llu", sub,
                    (unsigned)a->kind, (unsigned long long)a->payload[0], (unsigned long long)a->payload[1],
                    (unsigned long long)a->since);
        line(b);
    }
}

static void allen_stop(int o, const char *why)
{
    char b[256];
    if (o == CR_CORRUPT) ck_snprintf(b, sizeof b, "ALLEN: CORRUPT (%s)", why ? why : "-");
    else ck_snprintf(b, sizeof b, "ALLEN: STOP (%s%s%s)", cr_outcome_name(o), why ? ": " : "", why ? why : "");
    line(b);
}

static void allen_provision(const struct cr_source *src, const struct cr_sink *snk, struct cr_sealed_sink *sk,
                            const struct plan *p, struct ck_rng *rng)
{
    static struct cs_genesis gen;
    uint8_t sid[32], sid2[32], iid[32];
    const char *why = 0;
    int store_rc = 0;
    memcpy(gen.provenance, p->request, 32);
    gen.origin = CS_ORIGIN_OPERATOR;
    memcpy(gen.cortex, p->lineage, 32);
    if (p->cp >= 0) {
        sk->hook = cont_hook;
        sk->hook_arg = (void *)p;
    }
    int o = cs_provision(src, snk, g.w, g.tw, rng, ck_store_test_uuid, CC_SOURCE_QUALIFICATION, &gen, g.v, g.subj,
                         sid, &why, &store_rc);
    sk->hook = 0;
    if (o != CR_RESOLVED) {
        print_outcome(o, why, store_rc);
        allen_stop(o, why);
        return;
    }
    print_view("PROVISIONED", g.v);
    allen_lines("GENESIS", g.subj, sid);
    if (!p->have_intent) return;
    memcpy(g.subj2, g.subj, sizeof *g.subj2);
    cs_subject_advance(g.subj2, sid, p->request, CS_ORIGIN_OPERATOR);
    if (cs_subject_intend(g.subj2, CS_INTENT_GOAL_LATENCY, p->intent, iid, &why) != CC_OK) {
        allen_stop(CR_E_ARG, why);
        return;
    }
    o = cs_commit(src, snk, g.w, g.v, g.subj2, sid2, &why, &store_rc);
    if (o != CS_RESOLVED) {
        allen_stop(o, why);
        return;
    }
    allen_lines("INTENDED", g.subj2, sid2);
}

/* 1 = go on with the resume, 0 = stop (nothing written). */
static int allen_restore(const struct cr_source *src, const struct cr_sink *snk, const struct plan *p)
{
    uint8_t sid[32];
    const char *why = 0;
    int store_rc = 0;
    (void)snk;
    (void)p;
    if (cr_resolve(src, g.w, g.v2, &why, &store_rc) != CR_RESOLVED) return 1; /* cr_resume reports it */
    int s = cs_resolve(src, g.w, g.v2, g.subj, sid, &why, &store_rc);
#ifdef CS_MUTANT_RESTORE_MINTS
    if (s == CS_ABSENT) { /* MUTANT: restore mints a fresh subject */
        cs_subject_genesis(g.subj, g.v2, p->request, CS_ORIGIN_OPERATOR);
        if (cs_commit(src, snk, g.w, g.v2, g.subj, sid, &why, &store_rc) == CS_RESOLVED)
            s = cs_resolve(src, g.w, g.v2, g.subj, sid, &why, &store_rc);
    }
#endif
    if (s == CS_RESOLVED) {
        allen_lines("RESTORED", g.subj, sid);
        return 1;
    }
    if (s == CS_ABSENT) {
        line("ALLEN: ABSENT (provisioned without a subject; restore never mints one)");
        return 1;
    }
    allen_stop(s, why);
    return 0;
}

static void continuity_phase(const disk_dev *d, const struct plan *p)
{
    struct cr_source src;
    struct cr_sink snk;
    struct cr_sealed_sink sk = {g.s, 0, 0};
    cr_bind_sealed(&src, g.s);
    cr_bind_sealed_sink(&snk, &sk);
    (void)d;
    const char *why = 0;
    int store_rc = 0;
    struct ck_rng rng;

    if (p->mode == 5) {
        memset(&rng, 0, sizeof rng);
        if (ck_rng_probe(&rng, &k_ent_ops) != CK_RNG_OK) {
            line("CONTINUITY: NO_ENTROPY");
            return;
        }
        if (p->have_lineage) {
            allen_provision(&src, &snk, &sk, p, &rng);
            return;
        }
        int o = cr_provision(&src, &snk, g.w, g.tw, &rng, ck_store_test_uuid, CC_SOURCE_QUALIFICATION, g.v, &why,
                             &store_rc);
        if (o == CR_RESOLVED) print_view("PROVISIONED", g.v);
        else print_outcome(o, why, store_rc);
        return;
    }

    if (!allen_restore(&src, &snk, p)) return;
    int committed = 0;
    int o = cr_resume(&src, &snk, g.w, g.tw, g.v, &committed, &why, &store_rc);
    if (o != CR_RESOLVED) {
        print_outcome(o, why, store_rc);
        return;
    }
    if (!committed) {
        print_view("RESUMED_READONLY", g.v);
        return;
    }
    print_view("RESUMED", g.v);

    struct cc_record rec;
    if (p->mode == 7) {
        memcpy(g.st, &g.v->state, sizeof *g.st);
        uint8_t child[32];
        if (cc_state_fork(g.st, g.v->root.root_branch, child, 0) != CC_OK) {
            line("CONTINUITY: STOP (fork)");
            return;
        }
        fact(&rec, "qemu: the operator asked AIEN to remember this");
        struct cr_update up = {g.st, &rec, 1};
        o = cr_commit(&src, &snk, g.w, g.tw, g.v, &up, 0, g.v2, &why, &store_rc);
        if (o == CR_RESOLVED) print_view("REMEMBERED", g.v2);
        else print_outcome(o, why, store_rc);
    } else if (p->mode == 8) {
        sk.hook = cont_hook;
        sk.hook_arg = (void *)p;
        fact(&rec, "qemu: committed across a crash");
        struct cr_update up = {0, &rec, 1};
        o = cr_commit(&src, &snk, g.w, g.tw, g.v, &up, 0, g.v2, &why, &store_rc);
        if (o == CR_RESOLVED) print_view("COMMITTED", g.v2);
        else print_outcome(o, why, store_rc);
    }
}

int ck_cont_boot_stage(const disk_dev *d, int *rc)
{
    *rc = 0;
    ck_puts("continuity: TEST-ONLY continuity mode selection image (CK_TEST_CONTINUITY=1); "
            "never counts toward a default boot\n");
#ifdef CM_MUTANT_RESUME_NO_COMMIT
    ck_puts("continuity: TEST-ONLY MUTANT resume_no_commit: resume skips the incarnation commit\n");
#endif
#ifdef CM_MUTANT_RESUME_PROVISIONS
    ck_puts("continuity: TEST-ONLY MUTANT resume_provisions: resume mints an identity on an unprovisioned store\n");
#endif
#ifdef RC_MUTANT_DEGRADED_IS_UNPROVISIONED
    ck_puts("continuity: TEST-ONLY MUTANT degraded_is_unprovisioned: a degraded mount reads as unprovisioned\n");
#endif
#ifdef CR_MUTANT_BARE_SHA256
    ck_puts("continuity: TEST-ONLY MUTANT bare_sha256: operator response is a bare SHA-256\n");
#endif
#ifdef CS_MUTANT_RESTORE_MINTS
    ck_puts("continuity: TEST-ONLY MUTANT subject_restore_mints: restore mints an ALLEN subject when it finds none\n");
#endif
#ifdef CS_MUTANT_ACCEPT_FOREIGN
    ck_puts("continuity: TEST-ONLY MUTANT subject_accept_foreign: restore accepts a subject of another agent\n");
#endif
    if (!d || (d->block_size != 512 && d->block_size != 4096)) return 0;
    uint32_t bpu = CK_LAYOUT_UNIT / d->block_size;
    uint64_t units = d->block_count / bpu;
    uint8_t *buf = ck_alloc(CK_LAYOUT_UNIT);
    if (!units || !buf) {
        ck_puts("continuity: plan REFUSED (no plan buffer or no unit); Store stage runs as default\n");
        return 0;
    }
    if (disk_read(d, (units - 1u) * bpu, bpu, buf)) {
        ck_puts("continuity: plan REFUSED (read error); Store stage runs as default\n");
        return 0;
    }
    if (memcmp(buf, PLAN_MAGIC, sizeof PLAN_MAGIC - 1)) {
        ck_puts("continuity: no plan; Store stage runs as default\n");
        return 0;
    }
    static struct plan p;
    if (parse_plan((const char *)buf, CK_LAYOUT_UNIT, &p) || !(p.mode == 1 || (p.mode >= 5 && p.mode <= 11)) ||
        (p.mode >= 10 && !p.have_response)) {
        ck_puts("continuity: plan REFUSED (malformed); Store stage runs as default\n");
        return 0;
    }
    if (p.mode == 1) {
        ck_puts("continuity: plan mode=1 (ordinary Store boot)\n");
        return 0;
    }
    ck_printf("continuity: plan mode=%d\n", p.mode);

    g.bpu = bpu;
    g.store_base_lba = (uint64_t)CK_LAYOUT_ANCHOR_UNITS * bpu;
    g.store_units = units - CK_LAYOUT_ANCHOR_UNITS - CK_LAYOUT_PROBE_UNITS;
    if (alloc_all()) {
        ck_puts("continuity: REFUSED (no workspace)\n");
        *rc = -1;
        return 1;
    }
    int r = st_disk_bind(&g.sd, d, g.store_base_lba, g.store_units, &g.sdev);
    if (r) {
        ck_printf("continuity: REFUSED (st_disk_bind rc=%d)\n", r);
        *rc = r;
        return 1;
    }
    ss_ts_device(d, &g.tdev);
    ck_store_test_keys(&g.keys);

    int blank = is_blank(d, g.ws->rd);
    if (p.mode == 5 && blank) {
        r = ss_format(&g.sdev, &g.tdev, 0, ck_store_test_uuid, &g.keys, g.ws);
        if (r) {
            line("CONTINUITY: STOP (genesis write)");
            return 1;
        }
        blank = 0;
    }
    if (blank && p.mode >= 5 && p.mode <= 8) {
        line("CONTINUITY: STOP (store Unformatted)");
        return 1;
    }
    if (p.mode <= 8) {
        memset(g.s, 0, sizeof *g.s);
        r = ss_open(g.s, &g.sdev, &g.tdev, 0, &g.keys, g.ws);
        if (r) {
            ck_printf("CONTINUITY: STOP (store Refused(%d))\n", r);
            return 1;
        }
        continuity_phase(d, &p);
    } else {
        recovery_phase(d, &p);
    }
    memset(&g.keys, 0, sizeof g.keys);
    return 1;
}
#else
typedef int ck_continuity_boot_not_built; /* ISO C: no empty translation unit */
#endif
