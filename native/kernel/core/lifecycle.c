/* lifecycle.c -- resident production lifecycle (native v1 plan P03).
 *
 * Linked only into a CK_SERVICE=1 image (Makefile: full-service /
 * full-service-testkeys). kmain calls ck_lifecycle_run after every boot
 * stage instead of resetting: the product boundary where the diagnostic
 * image ends in ck_reset(). The diagnostic images are untouched (they do not
 * link this file; the weak ck_lifecycle_run is absent there).
 *
 * Operator input: the POLLED serial receive of the console UART the boot
 * stub chose from the ACPI SPCR (core/console.c, core/uart_rx.h: PL011/SBSA
 * on QEMU virt, 16550 on the DGX Spark), no interrupts. One bounded line
 * assembler (core/line_rx.c: CK_LC_LINE_MAX bytes, overlong or damaged lines
 * refused whole) serves the prompt and the cancel poll between generation
 * steps. Neither UART kind: `console input unsupported on this platform` and
 * the stop order. The USB keyboard binding stays with the xHCI session code
 * and is a later cut. Verbs and transitions: core/lifecycle_fsm.c.
 *
 * Store: the sealed Store opened by the store stage stays open and the NVMe
 * stays bound for the service lifetime (svc/store_boot.c, CK_SERVICE). An
 * approved task is committed as one Store object (kind CK_LC_OBJ_KIND).
 * Stop order on "shutdown": (1) close the Store (keys erased; every commit
 * is already durable: ss_transact returns after its final flush), (2) NVMe
 * normal shutdown, bus master off, SMMU stream to abort (ck_dev_nvme_release),
 * (3) return to kmain: final report, ck_reset (quiesce hook, PSCI). Never
 * the other way round.
 *
 * LOCKED at boot is the production truth: ck_store_production_keys refuses
 * (no TPM Slot 0 unwrap); the operator opens the Store with the recovery
 * secret (`unlock <64-hex>`, P04 cut 1). The TEST-ONLY full-service-testkeys
 * image (refused with CK_HARDWARE_STAGING) opens it with TEST keys at boot so
 * the READY and SERVE paths run in QEMU.
 *
 * Continuity (P05 cut 1): every Store open runs svc/continuity_service.c:
 * identity + ALLEN subject provisioned once, restored and resumed on every
 * boot; a refusal keeps the lifecycle LOCKED. `status` reports it.
 *
 * Remembered facts (P06 cut 4, the N3 "memory-only fact"): `remember <text>`
 * appends one CX_CLAIM record to the canonical Omega Cortex store whose
 * journal is the sealed Store (svc/cortex_journal.c, chunks of kind 'CJ');
 * `facts` reads the journal back (every record digest and the chain
 * re-verified by Omega's cx_open replay) and lists the newest facts. The
 * journal opens lazily on the first of either verb (a fresh journal is
 * created only by `remember`), stays open for the service lifetime and is
 * closed first in the stop order. Its heap is CK_CX_HEAP_PAGES kernel frames
 * handed to the Cortex bump allocator and returned at the stop order.
 * Nothing in memory is authoritative: a cold boot answers `facts` from the
 * disk, the fact never has to be restated. */
#include <stddef.h>
#include <stdint.h>
#include "ck.h"
#include "ck_internal.h"
#include "lifecycle_fsm.h"
#include "line_rx.h"
#include "store_boot.h"
#include "store_sealed.h"
#include "continuity_service.h"
#include "cortex_journal.h"
#include "slot_service.h"
#include "reply_obj.h"

#if !defined(CK_SERVICE)
#error "lifecycle.c is only part of a CK_SERVICE=1 image"
#endif
#if defined(CK_CONSOLE_SESSION) || defined(CK_TEST_STORE_CRASH) || defined(CK_TEST_CONTINUITY) || \
    defined(CK_QEMU_UNSAFE_DMA) || defined(CK_TEST_FWCFG_ARTIFACTS)
#error "CK_SERVICE cannot be combined with a TEST-only image flag"
#endif
#if defined(CK_SERVICE_TEST_KEYS) && defined(CK_HARDWARE_STAGING)
#error "CK_SERVICE_TEST_KEYS (TEST keys) cannot be combined with CK_HARDWARE_STAGING"
#endif

#define CK_LC_OBJ_KIND 0x4e31u   /* 'N1': v1 approved note, version 1 */
#define CK_LC_REPLY_KIND CK_REPLY_OBJ_KIND /* 0x5231 'R1': v1 approved reply (prompt + generated text), version 1 */

void ck_dev_nvme_release(void);
int ck_store_service_ready(void);
int ck_store_service_close(void);
int ck_store_service_unlock(const char *arg, size_t arg_len);
int ck_store_service_rotate(const char *arg, size_t arg_len);

static ck_lc g_lc;

/* P11 cut 2b health milestone for slot promotion (svc/slot_service.h): Store open,
 * continuity committed this boot, lifecycle READY. */
static int slot_healthy(void)
{
    return ck_store_service_ready() && ck_cont_service_writable() && g_lc.state == CK_LC_READY;
}
static uint8_t g_last_id[32];
static uint64_t g_last_gen;
static unsigned g_overlong;

/* The Cortex store over the sealed Store (P06 cuts 3 and 4). */
#define CK_CX_FACTS_SHOWN 16u    /* `facts` lists at most the newest 16 */
#define CK_CX_HEAP_BYTES (CK_CX_HEAP_PAGES * 4096u)
static ck_cj g_cj;
static CxStore g_cx;
static int g_cx_open;            /* 1 while the journal is open */
static uint64_t g_cx_heap_pa;    /* 0: no frames held */
static uint32_t g_cx_refused;    /* remember/facts refused by the Store or Cortex */

static void help(void)
{
    ck_puts("lifecycle: verbs: status unlock [<64-hex recovery secret>] rotate <current 64-hex> <new 64-hex> task <text> prompt <text> approve deny cancel recall remember <text> facts update evidence help shutdown\n");
}

static void status(void)
{
    char cs[96];
    ck_cont_service_status(cs, sizeof cs);
    ck_printf("lifecycle: state=%s store=%s pending=%s requests=%u %s\n", ck_lc_state_name(g_lc.state),
              ck_store_service_ready() ? "open" : "locked", g_lc.task_len ? g_lc.task : "-", g_lc.requests, cs);
}

static void evidence(void)
{
    ck_printf("lifecycle: evidence requests=%u refused=%u invalid=%u tasks=%u approved=%u denied=%u cancelled=%u "
              "overlong=%u last_commit_gen=%llu last_id=%02x%02x%02x%02x prompts=%u replies=%u gen_cancelled=%u "
              "gen_failed=%u recalls=%u inference=%s remembers=%u facts=%u cortex=%s records=%llu\n",
              g_lc.requests, g_lc.refused, g_lc.invalid, g_lc.tasks, g_lc.approved, g_lc.denied, g_lc.cancelled,
              g_overlong, (unsigned long long)g_last_gen, g_last_id[0], g_last_id[1], g_last_id[2], g_last_id[3],
              g_lc.prompts, g_lc.replies, g_lc.gen_cancelled, g_lc.gen_failed, g_lc.recalls,
              ck_infer_resident() ? "resident" : "none", g_lc.remembers, g_lc.facts, g_cx_open ? "open" : "none",
              (unsigned long long)(g_cx_open ? g_cx.n : 0));
}

/* Commit the pending task as one sealed Store object. Bytes: a fixed header
 * then the operator's text, bounded by CK_LC_TASK_MAX. */
/* Printable copy of a byte span for a serial line: ASCII 0x20..0x7e kept,
 * everything else (including the newline a reply may end with) becomes '?'. */
static void printable(char *out, size_t cap, const uint8_t *b, size_t n)
{
    size_t i;
    if (n > cap - 1) n = cap - 1;
    for (i = 0; i < n; i++) out[i] = (b[i] >= 0x20 && b[i] <= 0x7e) ? (char)b[i] : '?';
    out[n] = 0;
}

static void put(uint8_t *buf, size_t *n, const char *s, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) buf[(*n)++] = (uint8_t)s[i];
}

/* A note: "aienos.note.v1\n" + text (kind 'N1'). A reply: "aienos.reply.v1\nprompt: "
 * + prompt + "\nreply: " + generated bytes + "\n" (kind 'R1'). Both bounded. */
#define CK_LC_REPLY_OBJ_MAX (16 + 8 + CK_LC_TASK_MAX + 8 + CK_LC_REPLY_MAX + 1)
static int commit_task(void)
{
    static const char note_hdr[] = "aienos.note.v1\n";
    uint8_t buf[CK_LC_REPLY_OBJ_MAX];
    size_t n = 0, i;
    uint16_t kind = CK_LC_OBJ_KIND;
    ss_store *s = store_boot_store();
    if (!s || !ck_store_service_ready()) return -1;
    if (!ck_cont_service_writable()) return CK_SB_E_CONTINUITY; /* degraded mount: read-only */
    if (g_lc.pending == CK_LC_PENDING_REPLY) {
        kind = CK_LC_REPLY_KIND;
        n = ck_reply_obj_build(buf, g_lc.task, g_lc.task_len, (const uint8_t *)g_lc.reply, g_lc.reply_len, 0, 0, 0);
    } else {
        put(buf, &n, note_hdr, sizeof note_hdr - 1);
        put(buf, &n, g_lc.task, g_lc.task_len);
    }
    ss_object o = { kind, 1, buf, n };
    uint8_t ids[1][32];
    int rc = ss_transact(s, &o, 1, 0, 0, ids);
    if (rc == 0) {
        for (i = 0; i < 32; i++) g_last_id[i] = ids[0][i];
        g_last_gen = ss_generation(s);
    }
    return rc;
}

/* Between generation steps the console is polled (no interrupts): a complete
 * line "cancel" abandons the request; any other complete line, and an
 * overlong or damaged one, is refused and never run (only cancel is
 * accepted while generating). Same line rules as the prompt (core/line_rx.c). */
static struct ck_line_rx g_gen_rx;
static void gen_refuse(enum ck_lc_verb v, const char *reason)
{
    g_lc.refused++;
    ck_printf("lifecycle: REFUSED verb=%s reason=\"%s\"\n", ck_lc_verb_name(v), reason);
}
static int cancel_poll(void)
{
    return ck_line_rx_cancel_poll(&g_gen_rx, ck_console_rx_poll, gen_refuse);
}

/* prompt accepted: the resident model generates a bounded reply, which
 * becomes the pending proposal (approve | deny | cancel) exactly like a
 * note. Without a resident unit the verb is refused. */
static void generate(void)
{
    static struct ck_infer_reply r; /* ~0.4 KiB; static keeps it off the EL1 stack */
    static char shown[CK_LC_REPLY_MAX + 1];
    unsigned i;
    if (!ck_infer_resident()) {
        ck_lc_generate_done(&g_lc, CK_LC_GEN_FAILED, 0, 0);
        g_lc.refused++;
        ck_printf("lifecycle: REFUSED verb=prompt state=%s reason=\"no inference unit in this image\"\n",
                  ck_lc_state_name(g_lc.state));
        return;
    }
    ck_printf("lifecycle: generating prompt=\"%s\" (cancel stops it between steps)\n", g_lc.task);
    ck_line_rx_init(&g_gen_rx);
    int rc = ck_infer_prompt(g_lc.task, g_lc.task_len, cancel_poll, &r);
    if (rc < 0) {
        ck_lc_generate_done(&g_lc, CK_LC_GEN_FAILED, 0, 0);
        ck_printf("lifecycle: REFUSED verb=prompt rc=%d state=%s reason=\"inference refused the prompt\"\n", rc,
                  ck_lc_state_name(g_lc.state));
        return;
    }
    if (r.cancelled) {
        ck_lc_generate_done(&g_lc, CK_LC_GEN_CANCELLED, 0, 0);
        ck_printf("lifecycle: generation cancelled steps=%u prompt_ids=%u produced=%u us=%llu state=%s\n", r.steps,
                  r.prompt_ids, r.produced, (unsigned long long)r.us, ck_lc_state_name(g_lc.state));
        return;
    }
    ck_printf("lifecycle: reply ids=");
    for (i = 0; i < r.produced && i < CK_INFER_REPLY_IDS; i++) ck_printf("%s%u", i ? " " : "", r.ids[i]);
    ck_printf(" tokens=%u prompt_ids=%u steps=%u us=%llu\n", r.produced, r.prompt_ids, r.steps, (unsigned long long)r.us);
    if (r.text_len == 0) {
        ck_lc_generate_done(&g_lc, CK_LC_GEN_FAILED, 0, 0);
        ck_printf("lifecycle: REFUSED verb=prompt state=%s reason=\"empty reply\"\n", ck_lc_state_name(g_lc.state));
        return;
    }
    ck_lc_generate_done(&g_lc, CK_LC_GEN_REPLY, (const char *)r.text, r.text_len);
    printable(shown, sizeof shown, (const uint8_t *)g_lc.reply, g_lc.reply_len);
    ck_printf("lifecycle: reply pending state=%s proposed=\"reply: %s\" (approve | deny | cancel)\n",
              ck_lc_state_name(g_lc.state), shown);
}

/* recall: the newest approved object (note or reply) by Store generation,
 * read back through the sealed Store. Nothing in memory is trusted: a cold
 * boot answers from the disk. */
static void recall(void)
{
    static uint8_t body[SS_MAX_PLAINTEXT];
    static char shown[CK_LC_REPLY_OBJ_MAX + 1];
    ss_store *s = store_boot_store();
    if (!s || !ck_store_service_ready()) {
        ck_puts("lifecycle: recall REFUSED reason=\"no production Store\"\n");
        return;
    }
    int best = -1;
    uint32_t k;
    for (k = 0; k < s->nclaims; k++) {
        const ss_claim *c = &s->ws->claims[k];
        if (c->c.obj.object_kind != CK_LC_OBJ_KIND && c->c.obj.object_kind != CK_LC_REPLY_KIND) continue;
        if (best < 0 || c->c.store_generation > s->ws->claims[best].c.store_generation ||
            (c->c.store_generation == s->ws->claims[best].c.store_generation &&
             c->c.object_sequence > s->ws->claims[best].c.object_sequence))
            best = (int)k;
    }
    if (best < 0) {
        ck_printf("lifecycle: recall none objects=%u\n", (unsigned)s->nclaims);
        return;
    }
    uint8_t sid[32];
    size_t len = 0, i;
    uint16_t kind = 0;
    for (i = 0; i < 32; i++) sid[i] = s->ws->claims[best].sid[i];
    uint64_t gen = s->ws->claims[best].c.store_generation;
    int rc = ss_read(s, sid, body, sizeof body, &len, &kind);
    if (rc) {
        ck_printf("lifecycle: recall FAIL gen=%llu rc=%d\n", (unsigned long long)gen, rc);
        return;
    }
    printable(shown, sizeof shown, body, len);
    ck_printf("lifecycle: recall gen=%llu kind=%s id=%02x%02x%02x%02x bytes=%u text=\"%s\"\n", (unsigned long long)gen,
              kind == CK_LC_REPLY_KIND ? "reply" : "note", sid[0], sid[1], sid[2], sid[3], (unsigned)len, shown);
}

/* Number of journal chunks ('CJ' objects) the open Store holds: 0 means no
 * Cortex journal exists on this disk yet. */
static uint32_t cortex_chunks(const ss_store *s)
{
    uint32_t k, n = 0;
    for (k = 0; k < s->nclaims; k++)
        if (s->ws->claims[k].c.obj.object_kind == CK_CJ_KIND) n++;
    return n;
}

/* Open the Cortex journal once per service lifetime. create: a missing
 * journal is created (one sealed header transaction); else a missing journal
 * answers 1 and opens nothing. 0: open. <0: refused (printed). */
static int cortex_open(int create)
{
    ss_store *s = store_boot_store();
    if (g_cx_open) return 0;
    if (!s || !ck_store_service_ready()) return -1;
    if (!create && cortex_chunks(s) == 0) return 1;
    if (create && !ck_cont_service_writable()) return CK_SB_E_CONTINUITY;
    if (!g_cx_heap_pa) {
        uint64_t pa = 0;
        int rc = ck_mm_frames_alloc(CK_CX_HEAP_PAGES, &pa);
        if (rc) {
            ck_printf("lifecycle: cortex REFUSED heap frames=%u rc=%d\n", (unsigned)CK_CX_HEAP_PAGES, rc);
            return -2;
        }
        g_cx_heap_pa = pa;
    }
    ck_cx_heap_init((void *)(uintptr_t)g_cx_heap_pa, CK_CX_HEAP_BYTES);
    ck_cj_init(&g_cj, s);
    int rc = cx_open_with(&g_cx, &ck_cx_journal_store, &g_cj, "cortex", CK_CX_SUBJECTS, 0);
    if (rc != CX_OK) {
        ck_printf("lifecycle: cortex REFUSED open rc=%d chunks=%u\n", rc, cortex_chunks(s));
        return rc;
    }
    g_cx_open = 1;
    {
        size_t used = 0, peak = 0, size = 0;
        ck_cx_heap_stats(&used, &peak, &size);
        ck_printf("lifecycle: cortex open records=%llu chunks=%u journal_bytes=%u store_gen=%llu heap_used_kib=%u chain=%s\n",
                  (unsigned long long)g_cx.n, g_cj.nchunks, (unsigned)g_cj.len, (unsigned long long)ss_generation(s),
                  (unsigned)(used / 1024), cx_verify_chain(&g_cx) == CX_OK ? "ok" : "FAIL");
    }
    return 0;
}

/* remember: one CX_CLAIM record about the owner subject, payload = the text
 * packed into little-endian 64-bit words, tag = its byte length, t = the
 * record count + 1 (monotonic across boots: the count is replayed at open),
 * generation = the Store generation its transaction commits. One record is one
 * sealed Store transaction: durable before `remembered` is printed. */
static void remember(void)
{
    uint64_t pay[(CK_LC_TASK_MAX + 7) / 8];
    uint32_t nw = (uint32_t)((g_lc.fact_len + 7) / 8), i;
    int rc = cortex_open(1);
    if (rc == CK_SB_E_CONTINUITY || (rc == 0 && !ck_cont_service_writable())) {
        g_lc.refused++; g_cx_refused++;
        ck_printf("lifecycle: REFUSED verb=remember rc=%d state=%s reason=\"continuity read-only (degraded mount)\"\n",
                  CK_SB_E_CONTINUITY, ck_lc_state_name(g_lc.state));
        return;
    }
    if (rc) {
        g_lc.refused++; g_cx_refused++;
        ck_printf("lifecycle: REFUSED verb=remember rc=%d state=%s reason=\"cortex journal not open\"\n", rc,
                  ck_lc_state_name(g_lc.state));
        return;
    }
    for (i = 0; i < nw; i++) pay[i] = 0;
    for (i = 0; i < g_lc.fact_len; i++) pay[i / 8] |= (uint64_t)(uint8_t)g_lc.fact[i] << (8 * (i % 8));
    CxHeader h;
    uint64_t id = 0;
    for (i = 0; i < sizeof h; i++) ((uint8_t *)&h)[i] = 0;
    h.cls = CX_CLAIM;
    h.kind = CX_K_CLAIM;
    h.subject = CK_CX_FACT_SUBJECT;
    h.t = g_cx.n + 1;
    h.generation = ss_generation(store_boot_store()) + 1; /* the generation this append commits */
    h.tag = g_lc.fact_len;
    rc = cx_append(&g_cx, &h, pay, nw, &id);
    if (rc != CX_OK) {
        g_lc.refused++; g_cx_refused++;
        ck_printf("lifecycle: REFUSED verb=remember rc=%d state=%s reason=\"cortex append failed, nothing written\"\n", rc,
                  ck_lc_state_name(g_lc.state));
        return;
    }
    ck_printf("lifecycle: remembered id=%llu t=%llu store_gen=%llu bytes=%u text=\"%s\"\n", (unsigned long long)id,
              (unsigned long long)h.t, (unsigned long long)ss_generation(store_boot_store()), (unsigned)g_lc.fact_len,
              g_lc.fact);
}

/* facts: the newest CK_CX_FACTS_SHOWN owner records, oldest first, each read
 * back through cx_recall_id (digest re-checked) from the journal replayed at
 * open; then the whole chain is verified again. */
static void facts(void)
{
    static CxRecord r;
    static char shown[CK_LC_TASK_MAX + 1];
    uint64_t id, first;
    unsigned n = 0;
    int rc = cortex_open(0);
    if (rc == 1) {
        ck_puts("lifecycle: facts none cortex=none records=0\n");
        return;
    }
    if (rc) {
        g_lc.refused++; g_cx_refused++;
        ck_printf("lifecycle: REFUSED verb=facts rc=%d state=%s reason=\"cortex journal not open\"\n", rc,
                  ck_lc_state_name(g_lc.state));
        return;
    }
    first = g_cx.n > CK_CX_FACTS_SHOWN ? g_cx.n - CK_CX_FACTS_SHOWN + 1 : 1;
    for (id = first; id <= g_cx.n; id++) {
        uint8_t text[CK_LC_TASK_MAX];
        size_t len, i;
        if (cx_recall_id(&g_cx, id, &r) != CX_OK || !r.verified) {
            ck_printf("lifecycle: fact id=%llu DIGEST_FAIL\n", (unsigned long long)id);
            continue;
        }
        if (r.hdr.cls != CX_CLAIM || r.hdr.kind != CX_K_CLAIM || r.hdr.subject != CK_CX_FACT_SUBJECT) continue;
        len = (size_t)r.hdr.tag;
        if (len > sizeof text || len > (size_t)r.hdr.n * 8) len = 0; /* malformed tag: shown empty, still counted */
        for (i = 0; i < len; i++) text[i] = (uint8_t)(r.payload[i / 8] >> (8 * (i % 8)));
        printable(shown, sizeof shown, text, len);
        ck_printf("lifecycle: fact id=%llu t=%llu store_gen=%llu text=\"%s\"\n", (unsigned long long)id,
                  (unsigned long long)r.hdr.t, (unsigned long long)r.hdr.generation, shown);
        n++;
    }
    ck_printf("lifecycle: facts records=%llu shown=%u journal_bytes=%u chain=%s\n", (unsigned long long)g_cx.n, n,
              (unsigned)g_cj.len, cx_verify_chain(&g_cx) == CX_OK ? "ok" : "FAIL");
}

/* Stop order step 0: close the journal (nothing to flush: every append was
 * already durable) and return its heap frames. */
static void cortex_close(void)
{
    if (g_cx_open) {
        size_t used = 0, peak = 0, size = 0;
        ck_cx_heap_stats(&used, &peak, &size);
        ck_printf("lifecycle: cortex closed records=%llu appends=%u reads=%u refused=%u heap_peak_kib=%u\n",
                  (unsigned long long)g_cx.n, g_cj.appends, g_cj.reads, g_cx_refused, (unsigned)(peak / 1024));
        cx_close(&g_cx);
        g_cx_open = 0;
    }
    if (g_cx_heap_pa) {
        ck_mm_frames_free(g_cx_heap_pa, CK_CX_HEAP_PAGES);
        g_cx_heap_pa = 0;
    }
}

static void handle_line(const char *line, size_t len)
{
    const char *arg;
    size_t arg_len;
    enum ck_lc_verb v = ck_lc_decode(line, len, &arg, &arg_len);
    enum ck_lc_result r = ck_lc_apply(&g_lc, v, arg, arg_len);
    switch (r) {
    case CK_LC_R_INVALID:
        ck_printf("lifecycle: REFUSED verb=%s reason=\"%s\"\n", ck_lc_verb_name(v), g_lc.reason);
        return;
    case CK_LC_R_REFUSED:
        ck_printf("lifecycle: REFUSED verb=%s state=%s reason=\"%s\"\n", ck_lc_verb_name(v),
                  ck_lc_state_name(g_lc.state), g_lc.reason);
        return;
    case CK_LC_R_UNLOCK: {
        int opened = ck_store_service_unlock(arg, arg_len);
        ck_lc_unlock_done(&g_lc, opened);
        if (opened) ck_printf("lifecycle: unlock ok state=%s\n", ck_lc_state_name(g_lc.state));
        if (opened) ck_slot_service_health(slot_healthy());
        else ck_printf("lifecycle: REFUSED verb=unlock state=%s reason=\"%s\"\n", ck_lc_state_name(g_lc.state), g_lc.reason);
        return;
    }
    case CK_LC_R_ROTATE: {
        int ok = ck_store_service_rotate(arg, arg_len);
        ck_lc_rotate_done(&g_lc, ok);
        if (ok) ck_printf("lifecycle: rotate ok state=%s\n", ck_lc_state_name(g_lc.state));
        else ck_printf("lifecycle: REFUSED verb=rotate state=%s reason=\"%s\"\n", ck_lc_state_name(g_lc.state), g_lc.reason);
        return;
    }
    case CK_LC_R_COMMIT: {
        int rc = commit_task();
        ck_lc_commit_done(&g_lc, rc);
        if (rc == 0)
            ck_printf("lifecycle: approve committed gen=%llu id=%02x%02x%02x%02x state=%s\n",
                      (unsigned long long)g_last_gen, g_last_id[0], g_last_id[1], g_last_id[2], g_last_id[3],
                      ck_lc_state_name(g_lc.state));
        else if (rc == CK_SB_E_CONTINUITY)
            ck_printf("lifecycle: REFUSED verb=approve rc=%d state=%s reason=\"continuity read-only (degraded mount)\"\n", rc,
                      ck_lc_state_name(g_lc.state));
        else
            ck_printf("lifecycle: REFUSED verb=approve rc=%d state=%s reason=\"%s\"\n", rc,
                      ck_lc_state_name(g_lc.state), g_lc.reason);
        return;
    }
    case CK_LC_R_STOP:
        ck_printf("lifecycle: shutdown accepted state=%s\n", ck_lc_state_name(g_lc.state));
        return;
    case CK_LC_R_GENERATE: generate(); return;
    case CK_LC_R_RECALL: recall(); return;
    case CK_LC_R_REMEMBER: remember(); return;
    case CK_LC_R_FACTS: facts(); return;
    case CK_LC_R_UPDATE: ck_slot_service_update(arg, arg_len); return; /* P11 cut 3, svc/slot_service.c */
    case CK_LC_R_OK: break;
    }
    switch (v) {
    case CK_LC_V_HELP: help(); break;
    case CK_LC_V_STATUS: status(); break;
    case CK_LC_V_EVIDENCE: evidence(); break;
    case CK_LC_V_TASK:
        ck_printf("lifecycle: task pending state=%s proposed=\"note: %s\" (approve | deny | cancel)\n",
                  ck_lc_state_name(g_lc.state), g_lc.task);
        break;
    case CK_LC_V_DENY: ck_printf("lifecycle: denied state=%s\n", ck_lc_state_name(g_lc.state)); break;
    case CK_LC_V_CANCEL: ck_printf("lifecycle: cancelled state=%s\n", ck_lc_state_name(g_lc.state)); break;
    default: break;
    }
}

/* 1 when the line so far is "unlock" or "rotate" followed by its argument:
 * those bytes are recovery secrets and are echoed as '*' so the serial log
 * never carries them. */
static int after_verb(const char *buf, size_t len, const char *verb)
{
    size_t i = 0, j;
    while (i < len && buf[i] == ' ') i++;
    for (j = 0; verb[j]; j++)
        if (i + j >= len || buf[i + j] != verb[j]) return 0;
    return i + j < len && buf[i + j] == ' ';
}
static int in_secret(const char *buf, size_t len)
{
    return after_verb(buf, len, "unlock") || after_verb(buf, len, "rotate");
}

/* Bounded serial line editor over the POLLED console receive (no
 * interrupts): the rules are core/line_rx.c (printable bytes collected,
 * Backspace edits, CR or LF ends the line, a line past CK_LC_LINE_MAX or one
 * with a lost or damaged byte is refused whole at its Enter). This function
 * only echoes. At most CK_LINE_RX_BURST bytes per call. Returns 1 when
 * g_rx.buf[0..g_rx.len) is a complete line. */
static struct ck_line_rx g_rx;
static int rx_line(void)
{
    for (unsigned n = 0; n < CK_LINE_RX_BURST; n++) {
        int b = ck_console_rx_poll();
        if (b == CK_LINE_RX_EMPTY) return 0;
        switch (ck_line_rx_feed(&g_rx, b)) {
        case CK_LINE_ECHO: {
            char e[2] = { in_secret(g_rx.buf, g_rx.len - 1) ? '*' : g_rx.buf[g_rx.len - 1], 0 };
            ck_puts(e);
            break;
        }
        case CK_LINE_ERASE: ck_puts("\b \b"); break;
        case CK_LINE_DONE: ck_puts("\n"); return 1;
        case CK_LINE_OVERLONG:
            g_overlong++;
            ck_puts("\n");
            ck_printf("lifecycle: REFUSED verb=invalid reason=\"line longer than %u bytes\"\n", (unsigned)CK_LC_LINE_MAX);
            return 0;
        case CK_LINE_DAMAGED:
            ck_puts("\n");
            ck_puts("lifecycle: REFUSED verb=invalid reason=\"receive error in the line (overrun, parity, framing or break): type it again\"\n");
            return 0;
        default: break;
        }
    }
    return 0;
}

/* Returns 0 after an orderly stop (kmain then prints the final report and
 * resets). Never returns while serving. */
int ck_lifecycle_run(void)
{
    uint32_t cr = 0;
    ck_lc_init(&g_lc);
    ck_line_rx_init(&g_rx);
    ck_line_rx_init(&g_gen_rx);
#ifdef CK_SERVICE_TEST_KEYS
    ck_puts("lifecycle: TEST-ONLY service image (CK_SERVICE_TEST_KEYS=1: TEST Store keys; QEMU only, never a production boot)\n");
#endif
    ck_lc_start(&g_lc, ck_store_service_ready());
    ck_slot_service_start(slot_healthy());
    /* Operator input is the console UART the boot stub chose from the ACPI
     * SPCR (PL011/SBSA or 16550), POLLED: no interrupt is ever enabled. */
    const char *uname = ck_console_uart_name();
    if (uname[0] == 'n') { /* "none": no console UART of a kind this kernel drives */
        ck_puts("lifecycle: REFUSED console input unsupported on this platform (no PL011/SBSA or 16550 console UART in the ACPI SPCR): stop order\n");
        ck_lc_apply(&g_lc, CK_LC_V_SHUTDOWN, "", 0);
    } else if (!ck_console_rx_ready(&cr)) {
        ck_printf("lifecycle: REFUSED console input not ready (uart=%s base=0x%llx regs=0x%x): stop order\n", uname,
                  (unsigned long long)ck_console_uart_base(), cr);
        ck_lc_apply(&g_lc, CK_LC_V_SHUTDOWN, "", 0);
    } else {
        ck_printf("lifecycle: ready state=%s store=%s (operator input: serial %s at 0x%llx, polled)\n",
                  ck_lc_state_name(g_lc.state), ck_store_service_ready() ? "open" : "locked", uname,
                  (unsigned long long)ck_console_uart_base());
        ck_puts("> ");
        while (g_lc.state != CK_LC_QUIESCE) {
            if (rx_line()) {
                handle_line(g_rx.buf, g_rx.len);
                if (g_lc.state != CK_LC_QUIESCE) ck_puts("> ");
            } else {
                __asm__ volatile("yield");
            }
        }
    }
    /* Stop order: Cortex journal closed (frames returned), inference session
     * closed (frames returned), Store closed, then NVMe released, then the
     * caller resets. */
    ck_slot_service_stop();
    cortex_close();
    ck_infer_resident_close();
    int closed = ck_store_service_close();
    ck_dev_nvme_release();
    ck_lc_stopped(&g_lc);
    ck_printf("lifecycle: stop order store=%s nvme=released state=%s requests=%u\n", closed ? "closed" : "was-locked",
              ck_lc_state_name(g_lc.state), g_lc.requests);
    ck_printf("lifecycle: input uart=%s rx_errors=%u overruns=%u damaged_lines=%u overlong=%u dropped=%u\n", uname,
              ck_console_rx_errors(), ck_console_rx_overruns(), g_rx.damaged_lines + g_gen_rx.damaged_lines,
              g_rx.overlong + g_gen_rx.overlong, g_rx.dropped + g_gen_rx.dropped);
    return 0;
}
