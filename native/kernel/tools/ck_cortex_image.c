/* ck_cortex_image -- host tool for the N3 memory gate (aienos#329,
 * scripts/qemu_ck_memory_test.sh): writes one owner memory record into the
 * canonical Omega Cortex journal (svc/cortex_journal.c) of the sealed Store
 * on a boot-disk image that a TEST-keys service kernel has already
 * provisioned. It reuses the kernel's own code paths (store_boot.c opens the
 * Store as a boot would, cortex_journal.c + rx_cortex append the record,
 * core/context.c encodes it), so there is no second disk or record format.
 * TEST keys only; hosted C test tooling, never part of an image.
 *
 *   ck_cortex_image foreign IMG BS AGENT_HEX64 TEXT
 *        append a v1 preference (permitted for context) bound to AGENT (a
 *        foreign identity: not the agent the disk was provisioned with)
 *   ck_cortex_image corrupt IMG BS TEXT
 *        append a legacy fact whose journal bytes have one byte flipped AFTER
 *        Cortex computed the record digest: replay must refuse the journal
 *        (the tool re-opens it and prints the refusal it gets)
 * Both refuse an image whose Store is blank (the kernel must have booted it
 * first, so the disk has a provisioned identity). No Python, no outside
 * libraries. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "context.h"
#include "cortex_journal.h"
#include "disk.h"
#include "disk_file.h"
#include "disk_part.h"
#include "store_boot.h"

#define SUBJECTS 2u /* = CK_CX_SUBJECTS of core/lifecycle.c */
#define HEAP_BYTES (4u << 20)

static int usage(void)
{
    fprintf(stderr, "usage: ck_cortex_image foreign IMG BS AGENT_HEX64 TEXT | corrupt IMG BS TEXT\n");
    return 2;
}

static int g_flip; /* 1: the next journal append flips one byte */
static int flip_append(void *ctx, void *h, const uint8_t *b, size_t n, int sync)
{
    static uint8_t c[CK_CJ_MAX_RECORD];
    if (!g_flip || n == 0 || n > sizeof c) return ck_cx_journal_store.append(ctx, h, b, n, sync);
    memcpy(c, b, n);
    c[n - 9] ^= 0x01; /* inside the record, before its trailing word: the digest no longer matches */
    g_flip = 0;
    return ck_cx_journal_store.append(ctx, h, c, n, sync);
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

int main(int argc, char **argv)
{
    int foreign;
    uint8_t agent[32];
    const char *text;
    if (argc == 6 && !strcmp(argv[1], "foreign")) {
        foreign = 1;
        if (strlen(argv[4]) != 64) return usage();
        for (int i = 0; i < 32; i++) {
            int a = hexval(argv[4][2 * i]), b = hexval(argv[4][2 * i + 1]);
            if (a < 0 || b < 0) return usage();
            agent[i] = (uint8_t)(a << 4 | b);
        }
        text = argv[5];
    } else if (argc == 5 && !strcmp(argv[1], "corrupt")) {
        foreign = 0;
        text = argv[4];
    } else {
        return usage();
    }
    size_t tn = strlen(text);
    if (tn == 0 || tn > CK_CTX_TEXT_MAX) {
        fprintf(stderr, "text must be 1..%u bytes\n", CK_CTX_TEXT_MAX);
        return 2;
    }
    uint32_t bs = (uint32_t)strtoul(argv[3], NULL, 10);
    disk_file f;
    disk_dev raw;
    ck_part part;
    ck_gpt_info gi;
    if (bs != 512 && bs != 4096) return usage();
    if (disk_file_open(&f, &raw, argv[2], bs, 0, 0)) {
        fprintf(stderr, "cannot open %s\n", argv[2]);
        return 1;
    }
    int rc = ck_gpt_find_aienos(&raw, &part, &gi);
    if (rc) {
        fprintf(stderr, "%s: no AIENOS partition (gpt: %s)\n", argv[2], ck_gpt_strerror(rc));
        return 1;
    }
    /* Refuse a blank Store BEFORE store_boot_run, which would format it: the
     * anchor unit of a provisioned disk is never all zero. */
    {
        static uint8_t blk[4096];
        int blank = 1;
        if (disk_read(&part.dev, 0, 1, blk)) {
            fprintf(stderr, "%s: cannot read the anchor\n", argv[2]);
            return 1;
        }
        for (uint32_t i = 0; i < bs; i++) blank &= blk[i] == 0;
        if (blank) {
            fprintf(stderr, "%s: Store is blank: boot the kernel on it first (nothing written)\n", argv[2]);
            disk_file_close(&f);
            return 1;
        }
    }
    ss_keys keys;
    ck_store_report r;
    ck_store_test_keys(&keys);
    rc = store_boot_run(&part.dev, &keys, ck_store_test_uuid, "ck_cortex_image", &r);
    memset(&keys, 0, sizeof keys);
    if (rc || r.formatted) {
        fprintf(stderr, "%s: %s\n", argv[2], rc ? "Store refused" : "Store was blank (formatted by this run; use a fresh image)");
        disk_file_close(&f);
        return 1;
    }
    ss_store *s = store_boot_store();
    static ck_cj cj;
    static CxStore cx;
    CxJournalOps ops = ck_cx_journal_store;
    void *heap = malloc(HEAP_BYTES);
    if (!heap) return 1;
    ops.append = flip_append;
    ck_cx_heap_init(heap, HEAP_BYTES);
    ck_cj_init(&cj, s);
    rc = cx_open_with(&cx, &ops, &cj, "cortex", SUBJECTS, 0);
    if (rc != CX_OK) {
        fprintf(stderr, "cortex open refused rc=%d\n", rc);
        return 1;
    }
    uint64_t pay[CK_MEM_MAX_WORDS], id = 0;
    uint32_t nw;
    memset(pay, 0, sizeof pay);
    if (foreign) {
        nw = ck_mem_encode(pay, CK_MEM_TYPE_PREF, CK_MEM_PERM_CONTEXT, agent, text, tn);
        if (!nw) return usage();
    } else {
        nw = (uint32_t)((tn + 7) / 8);
        for (size_t i = 0; i < tn; i++) pay[i / 8] |= (uint64_t)(uint8_t)text[i] << (8 * (i % 8));
        g_flip = 1;
    }
    CxHeader h;
    memset(&h, 0, sizeof h);
    h.cls = CX_CLAIM;
    h.kind = CX_K_CLAIM;
    h.subject = CK_CTX_OWNER_SUBJECT;
    h.t = cx.n + 1;
    h.generation = ss_generation(s) + 1;
    h.tag = tn;
    rc = cx_append(&cx, &h, pay, nw, &id);
    uint64_t gen = ss_generation(s);
    cx_close(&cx);
    if (rc != CX_OK || g_flip) {
        fprintf(stderr, "append refused rc=%d\n", rc);
        return 1;
    }
    /* read back exactly as the kernel will, from a fresh replay */
    ck_cx_heap_init(heap, HEAP_BYTES);
    ck_cj_init(&cj, s);
    int reopen = cx_open_with(&cx, &ck_cx_journal_store, &cj, "cortex", SUBJECTS, CX_OPEN_READONLY);
    uint64_t n = reopen == CX_OK ? cx.n : 0;
    if (reopen == CX_OK) cx_close(&cx);
    rc = disk_flush(&part.dev);
    disk_file_close(&f);
    free(heap);
    if (rc) return 1;
    if (foreign) {
        printf("ck_cortex_image: foreign preference id=%llu store_generation=%llu reopen=%d records=%llu agent=%.16s "
               "(TEST keys)\n", (unsigned long long)id, (unsigned long long)gen, reopen, (unsigned long long)n, argv[4]);
        return reopen == CX_OK ? 0 : 1;
    }
    printf("ck_cortex_image: corrupt record id=%llu store_generation=%llu reopen=%d (journal refused at replay) "
           "(TEST keys)\n", (unsigned long long)id, (unsigned long long)gen, reopen);
    return reopen != CX_OK ? 0 : 1;
}
