/* lifecycle.c -- resident production lifecycle (native v1 plan P03).
 *
 * Linked only into a CK_SERVICE=1 image (Makefile: full-service /
 * full-service-testkeys). kmain calls ck_lifecycle_run after every boot
 * stage instead of resetting: the product boundary where the diagnostic
 * image ends in ck_reset(). The diagnostic images are untouched (they do not
 * link this file; the weak ck_lifecycle_run is absent there).
 *
 * Operator input: the polled PL011 serial receive the console already owns
 * (core/console.c), one bounded line editor (CK_LC_LINE_MAX bytes, overlong
 * lines refused whole). The USB keyboard binding stays with the xHCI session
 * code and is a later cut. Verbs and transitions: core/lifecycle_fsm.c.
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
 * later boot; a refusal keeps the lifecycle LOCKED. `status` reports it. */
#include <stddef.h>
#include <stdint.h>
#include "ck.h"
#include "lifecycle_fsm.h"
#include "store_boot.h"
#include "store_sealed.h"
#include "continuity_service.h"

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

#define CK_LC_OBJ_KIND 0x4e31u /* 'N1': v1 approved note, version 1 */

void ck_dev_nvme_release(void);
int ck_store_service_ready(void);
int ck_store_service_close(void);
int ck_store_service_unlock(const char *arg, size_t arg_len);

static ck_lc g_lc;
static uint8_t g_last_id[32];
static uint64_t g_last_gen;
static unsigned g_overlong, g_dropped;

static void help(void)
{
    ck_puts("lifecycle: verbs: status unlock [<64-hex recovery secret>] task <text> approve deny cancel evidence help shutdown\n");
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
              "overlong=%u last_commit_gen=%llu last_id=%02x%02x%02x%02x\n",
              g_lc.requests, g_lc.refused, g_lc.invalid, g_lc.tasks, g_lc.approved, g_lc.denied, g_lc.cancelled,
              g_overlong, (unsigned long long)g_last_gen, g_last_id[0], g_last_id[1], g_last_id[2], g_last_id[3]);
}

/* Commit the pending task as one sealed Store object. Bytes: a fixed header
 * then the operator's text, bounded by CK_LC_TASK_MAX. */
static int commit_task(void)
{
    static const char hdr[] = "aienos.note.v1\n";
    uint8_t buf[sizeof hdr - 1 + CK_LC_TASK_MAX];
    size_t n = 0, i;
    ss_store *s = store_boot_store();
    if (!s || !ck_store_service_ready()) return -1;
    if (!ck_cont_service_writable()) return CK_SB_E_CONTINUITY; /* degraded mount: read-only */
    for (i = 0; i < sizeof hdr - 1; i++) buf[n++] = (uint8_t)hdr[i];
    for (i = 0; i < g_lc.task_len; i++) buf[n++] = (uint8_t)g_lc.task[i];
    ss_object o = { CK_LC_OBJ_KIND, 1, buf, n };
    uint8_t ids[1][32];
    int rc = ss_transact(s, &o, 1, 0, 0, ids);
    if (rc == 0) {
        for (i = 0; i < 32; i++) g_last_id[i] = ids[0][i];
        g_last_gen = ss_generation(s);
    }
    return rc;
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
        else ck_printf("lifecycle: REFUSED verb=unlock state=%s reason=\"%s\"\n", ck_lc_state_name(g_lc.state), g_lc.reason);
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

/* 1 when the line so far is "unlock" followed by its argument: those bytes
 * are the recovery secret and are echoed as '*' so the serial log never
 * carries them. */
static int in_secret(const char *buf, size_t len)
{
    static const char verb[] = "unlock";
    size_t i = 0, j;
    while (i < len && buf[i] == ' ') i++;
    for (j = 0; j < sizeof verb - 1; j++)
        if (i + j >= len || buf[i + j] != verb[j]) return 0;
    return i + j < len && buf[i + j] == ' ';
}

/* Bounded serial line editor: printable bytes collected, Backspace edits,
 * CR or LF ends the line; a line past CK_LC_LINE_MAX is refused whole (the
 * rest of it is dropped until the next Enter). Returns 1 when the line is complete. */
static int rx_line(char *buf, size_t *len, int *overflow)
{
    for (;;) {
        int b = ck_console_rx_poll();
        if (b == -1) return 0;
        if (b == -2) continue; /* error byte: counted by the console, dropped here */
        char c = (char)b;
        if (c == '\r' || c == '\n') {
            if (*overflow) {
                g_overlong++;
                ck_puts("\n");
                ck_printf("lifecycle: REFUSED verb=invalid reason=\"line longer than %u bytes\"\n", (unsigned)CK_LC_LINE_MAX);
                *overflow = 0;
                *len = 0;
                return 0;
            }
            ck_puts("\n");
            return 1;
        }
        if (c == 0x7f || c == 0x08) {
            if (*len && !*overflow) { (*len)--; ck_puts("\b \b"); }
            continue;
        }
        if (c < 0x20 || c > 0x7e) { g_dropped++; continue; }
        if (*overflow) continue;
        if (*len >= CK_LC_LINE_MAX) { *overflow = 1; continue; }
        { char e[2] = { in_secret(buf, *len) ? '*' : c, 0 }; buf[(*len)++] = c; ck_puts(e); }
    }
}

/* Returns 0 after an orderly stop (kmain then prints the final report and
 * resets). Never returns while serving. */
int ck_lifecycle_run(void)
{
    char line[CK_LC_LINE_MAX + 1];
    size_t len = 0;
    int overflow = 0;
    uint32_t cr;
    ck_lc_init(&g_lc);
#ifdef CK_SERVICE_TEST_KEYS
    ck_puts("lifecycle: TEST-ONLY service image (CK_SERVICE_TEST_KEYS=1: TEST Store keys; QEMU only, never a production boot)\n");
#endif
    ck_lc_start(&g_lc, ck_store_service_ready());
    if (!ck_console_rx_ready(&cr)) {
        ck_puts("lifecycle: REFUSED no operator input (console UART has no PL011 receiver): stop order\n");
        ck_lc_apply(&g_lc, CK_LC_V_SHUTDOWN, "", 0);
    } else {
        ck_printf("lifecycle: ready state=%s store=%s (operator input: serial)\n", ck_lc_state_name(g_lc.state),
                  ck_store_service_ready() ? "open" : "locked");
        ck_puts("> ");
        while (g_lc.state != CK_LC_QUIESCE) {
            if (rx_line(line, &len, &overflow)) {
                handle_line(line, len);
                len = 0;
                if (g_lc.state != CK_LC_QUIESCE) ck_puts("> ");
            } else {
                __asm__ volatile("yield");
            }
        }
    }
    /* Stop order: Store closed, then NVMe released, then the caller resets. */
    int closed = ck_store_service_close();
    ck_dev_nvme_release();
    ck_lc_stopped(&g_lc);
    ck_printf("lifecycle: stop order store=%s nvme=released state=%s requests=%u\n", closed ? "closed" : "was-locked",
              ck_lc_state_name(g_lc.state), g_lc.requests);
    return 0;
}
