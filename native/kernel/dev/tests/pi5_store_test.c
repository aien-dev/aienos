/* pi5_store_test.c -- AIENOS-PI5 step 3b host test: the sealed Store stage
 * (svc/store_boot.c, the same one the QEMU full image runs) over the Pi 5
 * card layout (protective MBR, ESP, AIENOS partition, two-copy GPT), in the
 * TEST-key qualification tier (SEED-0B-PI5). A file stands in for the card;
 * the SD controller itself is proved on the hub Pi (pi5-run.sh).
 *
 * Checks: blank card formats and commits boot 1; after a "reboot" (file
 * closed, GPT parsed again, nothing kept in memory) the Store reopens and
 * commits boot 2 and 3 with the generation advancing; every byte outside the
 * AIENOS partition (MBR, GPT copies, ESP) is unchanged; the production key
 * source still refuses and hands out no key bytes; a hardware-staging policy
 * refuses the TEST keys before touching the card. Hosted test code only. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ck.h"
#include "ck_host.h"
#include "disk_file.h"
#include "disk_layout.h"
#include "disk_part.h"
#include "gpt_write.h"
#include "store_boot.h"

static int checks, failures;
#define CHECK(c)                                                    \
    do {                                                            \
        checks++;                                                   \
        if (!(c)) {                                                 \
            failures++;                                             \
            printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);   \
        }                                                           \
    } while (0)

#define BLOCKS 262144ull /* 128 MiB stand-in for the card */
static char g_path[256];

static uint8_t *slurp(size_t *n)
{
    FILE *fp = fopen(g_path, "rb");
    CHECK(fp != 0);
    if (!fp) { *n = 0; return 0; }
    fseek(fp, 0, SEEK_END);
    *n = (size_t)ftell(fp);
    rewind(fp);
    uint8_t *m = malloc(*n);
    CHECK(m && fread(m, 1, *n, fp) == *n);
    fclose(fp);
    return m;
}

/* One "boot": open the card file, parse the GPT, run the Store stage body. */
static int boot(int hardware_staging, const ss_keys *k, ck_store_report *r)
{
    disk_file f;
    disk_dev d;
    ck_part p;
    ck_gpt_info gi;
    if (disk_file_open(&f, &d, g_path, 512, 0, 0)) return -9999;
    int rc = ck_gpt_find_aienos(&d, &p, &gi);
    if (rc) { disk_file_close(&f); return -9998; }
    ck_host_quiet = 1;
    rc = store_boot_run_policy(&p.dev, k, ck_store_test_uuid, "pi5-store-test", hardware_staging, r);
    ck_host_quiet = 0;
    disk_file_close(&f);
    return rc;
}

int main(void)
{
    snprintf(g_path, sizeof g_path, "/tmp/aienos-pi5-store-test-%d.img", (int)getpid());
    gw_part gp[2] = {{gw_esp_type, 2048, 4095, "AIENOSPI5-ESP", 0x5a}, {ck_aienos_part_type, 8192, 8192 + 8192 - 1, "AIENOS", 0}};
    CHECK(gw_write(g_path, 512, BLOCKS, gp, 2, 0) == 0);
    size_t n0 = 0, n1 = 0;
    uint8_t *before = slurp(&n0);

    ss_keys k;
    ck_store_report r;
    ck_store_test_keys(&k);
    CHECK(k.identity_class == M5_ID_TEST); /* the tier is TEST: labelled, public, protects nothing */

    int rc = boot(0, &k, &r);
    CHECK(rc == 0 && r.verdict == CK_SB_COMMITTED && r.formatted == 1 && r.boot_count_new == 1);
    uint64_t g1 = r.gen_commit;
    rc = boot(0, &k, &r);
    CHECK(rc == 0 && r.formatted == 0 && r.boot_count_prev == 1 && r.boot_count_new == 2 && r.gen_commit > g1);
    uint64_t g2 = r.gen_commit;
    rc = boot(0, &k, &r);
    CHECK(rc == 0 && r.formatted == 0 && r.boot_count_new == 3 && r.gen_commit > g2);
    CHECK(strcmp(r.prev_commit, "pi5-store-test") == 0);
    /* AIENOS partition is 8192 sectors = 1024 units: anchor 4, probe 1. */
    CHECK(r.store_units == 8192u / 8u - CK_LAYOUT_ANCHOR_UNITS - CK_LAYOUT_PROBE_UNITS);

    uint8_t *after = slurp(&n1);
    CHECK(before && after && n0 == n1);
    if (before && after && n0 == n1) {
        CHECK(memcmp(before, after, 8192u * 512u) == 0);                                  /* MBR, GPT, ESP */
        CHECK(memcmp(before + 16384u * 512u, after + 16384u * 512u, n0 - 16384u * 512u) == 0); /* after the partition, backup GPT */
        CHECK(memcmp(before + 8192u * 512u, after + 8192u * 512u, 8192u * 512u) != 0);      /* the Store wrote inside */
    }
    free(before);
    free(after);

    /* Production key source: still BLOCKED_OPERATOR, no key bytes handed out, no fallback. */
    ss_keys pk;
    memset(&pk, 0xAA, sizeof pk);
    CHECK(ck_store_production_keys(&pk) == CK_SB_E_BLOCKED_OPERATOR);
    int nz = 0;
    for (size_t i = 0; i < sizeof pk; i++) nz |= ((uint8_t *)&pk)[i];
    CHECK(nz == 0);

    /* A hardware-staging policy refuses the TEST keys before any disk access. */
    uint8_t *b2 = slurp(&n0);
    rc = boot(1, &k, &r);
    CHECK(rc == CK_SB_E_TEST_KEYS);
    uint8_t *a2 = slurp(&n1);
    CHECK(b2 && a2 && n0 == n1 && memcmp(b2, a2, n0) == 0);
    free(b2);
    free(a2);

    memset(&k, 0, sizeof k);
    unlink(g_path);
    printf("pi5_store_test: %d checks, %d failures\n", checks, failures);
    printf("CK_PI5_STORE_HOST: %s\n", failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
