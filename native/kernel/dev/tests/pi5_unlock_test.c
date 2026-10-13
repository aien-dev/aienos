/* pi5_unlock_test.c -- AIENOS PI5-4 cut 1 host test: the Pi unlock image's Store policy
 * (svc/store_boot.c ck_store_pi5_unlock_run, compiled with -DCK_PI5_UNLOCK exactly as
 * "make pi5-unlock" builds it) over the Pi card layout. A file stands in for the card.
 *
 * Proves: no secret -> refused before the disk is read, nothing written; TEST-identity keys are
 * refused by the image's own policy (store_boot_run) before any disk access, on a blank card and on
 * a PRODUCTION Store; a TEST-tier Store (formatted with TEST keys and the TEST uuid by a different
 * image) is refused by the unlock path with no keyslot manifest, nothing written; a wrong secret
 * is refused, nothing written; the right secret on a blank card formats a PRODUCTION-class Store
 * under a drawn uuid that is not the TEST uuid; the same secret reopens it and the generation
 * advances. The TEST keys are built here from the public label, because the image itself does not
 * contain them (scripts/ck_pi5_build_check.sh checks that on the real ELF). Hosted test code only. */
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
#include "../../core/pi5_marker.h"
#include "m5.h"
#include "sha256.h"
#include "store_boot.h"

#ifndef CK_PI5_UNLOCK
#error "pi5_unlock_test.c must be built with -DCK_PI5_UNLOCK (the image's policy)"
#endif
#ifdef CK_STORE_TEST_KEYS
#error "the unlock image must not compile the TEST keys"
#endif

static int checks, failures;
#define CHECK(c)                                                    \
    do {                                                            \
        checks++;                                                   \
        if (!(c)) {                                                 \
            failures++;                                             \
            printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);   \
        }                                                           \
    } while (0)

extern int ck_host_entropy_refuse;

/* The secret source symbol the stage references; the real one lives in core/pi5.c. */
int ck_pi5_unlock_secret(uint8_t out[CK_SB_SECRET_LEN], const char **source)
{
    (void)out;
    (void)source;
    return -1;
}

#define BLOCKS 262144ull
#define PART_FIRST 8192u
#define PART_SECS 8192u
static char g_path[256];

/* The public TEST keys and uuid of the SEED-0B-PI5 image, rebuilt here (public label, not secret). */
static const uint8_t test_uuid[16] = {'A', 'I', 'E', 'N', '-', 'T', 'E', 'S', 'T', '-', 'B', 'O', 'O', 'T', '0', '1'};
static void test_keys(ss_keys *k)
{
    uint8_t kvol[32];
    m5_subkeys sk;
    static const char label[] = "AIENOS-LANE18-TEST-KVOL-NOT-SECRET";
    sha256_hash((const uint8_t *)label, sizeof label - 1, kvol);
    memset(k, 0, sizeof *k);
    m5_derive_subkeys(kvol, M5_ID_TEST, 0, &sk);
    k->identity_class = M5_ID_TEST;
    k->key_generation = 1;
    memcpy(k->k_root_auth, sk.k_root_auth, 32);
    memcpy(k->k_domain, sk.k_artifact, 32);
    m5_subkeys_wipe(&sk);
}

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

enum { BOOT_TESTKEYS_POLICY, BOOT_TESTKEYS_IMAGE, BOOT_UNLOCK };
/* One boot on the Store view of the card file. */
static int boot(int mode, const uint8_t *secret, ck_store_report *r)
{
    disk_file f;
    disk_dev d;
    ck_part p, sp;
    ck_gpt_info gi;
    ss_keys k;
    if (disk_file_open(&f, &d, g_path, 512, 0, 0)) return -9999;
    if (ck_gpt_find_aienos(&d, &p, &gi) || ck_pi5_store_view(&p, &sp)) { disk_file_close(&f); return -9998; }
    ck_host_quiet = 1;
    int rc;
    test_keys(&k);
    if (mode == BOOT_TESTKEYS_POLICY) rc = store_boot_run_policy(&sp.dev, &k, test_uuid, "pi5-unlock-test", 0, r);
    else if (mode == BOOT_TESTKEYS_IMAGE) rc = store_boot_run(&sp.dev, &k, test_uuid, "pi5-unlock-test", r);
    else rc = ck_store_pi5_unlock_run(&sp.dev, secret, "pi5-unlock-test", r);
    ck_host_quiet = 0;
    memset(&k, 0, sizeof k);
    disk_file_close(&f);
    return rc;
}

static int same_bytes(const uint8_t *a, size_t na, const uint8_t *b, size_t nb)
{
    return a && b && na == nb && memcmp(a, b, na) == 0;
}

int main(void)
{
    snprintf(g_path, sizeof g_path, "/tmp/aienos-pi5-unlock-test-%d.img", (int)getpid());
    gw_part gp[2] = {{gw_esp_type, 2048, 4095, "AIENOSPI5-ESP", 0x5a}, {ck_aienos_part_type, PART_FIRST, PART_FIRST + PART_SECS - 1, "AIENOS", 0}};
    CHECK(gw_write(g_path, 512, BLOCKS, gp, 2, 0) == 0);
    uint8_t S[CK_SB_SECRET_LEN], W[CK_SB_SECRET_LEN];
    for (int i = 0; i < 32; i++) S[i] = (uint8_t)(i * 11 + 3);
    memcpy(W, S, 32);
    W[31] ^= 0x80;
    ck_store_report r;
    size_t n0, n1;
    uint8_t *b, *a;

    /* 1. No secret source: refused before the disk is read; a blank card stays blank. */
    b = slurp(&n0);
    int rc = boot(BOOT_UNLOCK, 0, &r);
    a = slurp(&n1);
    CHECK(rc == CK_SB_E_BLOCKED_OPERATOR && r.verdict == CK_SB_REFUSED && r.formatted == 0);
    CHECK(r.proof && strcmp(r.proof, "keyed") == 0);
    CHECK(same_bytes(b, n0, a, n1));
    free(b);
    free(a);

    /* 2. TEST keys against the image's own policy (hardware policy): refused before any disk access. */
    b = slurp(&n0);
    rc = boot(BOOT_TESTKEYS_IMAGE, 0, &r);
    a = slurp(&n1);
    CHECK(rc == CK_SB_E_TEST_KEYS && r.verdict == CK_SB_REFUSED && r.formatted == 0);
    CHECK(same_bytes(b, n0, a, n1));
    free(b);
    free(a);

    /* 3. A TEST-tier Store (made by the SEED-0B-PI5 image's policy, TEST keys + TEST uuid) is not a
     * production Store: the unlock path finds no keyslot manifest and refuses, nothing written. */
    rc = boot(BOOT_TESTKEYS_POLICY, 0, &r);
    CHECK(rc == 0 && r.verdict == CK_SB_COMMITTED && r.formatted == 1 && r.identity_class == M5_ID_TEST);
    b = slurp(&n0);
    rc = boot(BOOT_UNLOCK, S, &r);
    a = slurp(&n1);
    CHECK(rc == CK_SB_E_NO_KEYSLOT && r.verdict == CK_SB_REFUSED && r.formatted == 0);
    CHECK(same_bytes(b, n0, a, n1));
    free(b);
    free(a);
    rc = boot(BOOT_TESTKEYS_IMAGE, 0, &r); /* and the image policy still refuses TEST keys on a Store that has TEST content */
    CHECK(rc == CK_SB_E_TEST_KEYS);

    /* Fresh blank card for the production path. */
    CHECK(gw_write(g_path, 512, BLOCKS, gp, 2, 0) == 0);

    /* 4. Blank card, entropy refused: no genesis, nothing written. */
    b = slurp(&n0);
    ck_host_entropy_refuse = 1;
    rc = boot(BOOT_UNLOCK, S, &r);
    ck_host_entropy_refuse = 0;
    a = slurp(&n1);
    CHECK(rc == CK_SB_E_ENTROPY && r.formatted == 0 && same_bytes(b, n0, a, n1));
    free(b);
    free(a);

    /* 5. Blank card, secret S: formatted PRODUCTION-class Store under a drawn uuid (not the TEST uuid). */
    rc = boot(BOOT_UNLOCK, S, &r);
    CHECK(rc == 0 && r.verdict == CK_SB_COMMITTED && r.formatted == 1 && r.unlocked_genesis == 1);
    CHECK(r.identity_class == M5_ID_PRODUCTION && r.boot_count_new == 1);
    CHECK(r.key_source && strcmp(r.key_source, "recovery-keyslot") == 0);
    CHECK(store_boot_store()->has_keyslot == 1 && store_boot_store()->keys.identity_class == M5_ID_PRODUCTION);
    CHECK(memcmp(store_boot_store()->uuid, test_uuid, 16) != 0);
    uint64_t g1 = r.gen_commit;

    /* 6. Wrong secret: refused, nothing written. */
    b = slurp(&n0);
    rc = boot(BOOT_UNLOCK, W, &r);
    a = slurp(&n1);
    CHECK(rc == CK_SB_E_SECRET_REJECTED && r.verdict == CK_SB_REFUSED && r.formatted == 0);
    CHECK(same_bytes(b, n0, a, n1));
    free(b);
    free(a);

    /* 7. TEST keys on the production Store: refused by policy, nothing written. */
    b = slurp(&n0);
    rc = boot(BOOT_TESTKEYS_IMAGE, 0, &r);
    a = slurp(&n1);
    CHECK(rc == CK_SB_E_TEST_KEYS && same_bytes(b, n0, a, n1));
    free(b);
    free(a);

    /* 8. Reboot, secret S: reopens, no reformat, generation advances, boot count 2. */
    rc = boot(BOOT_UNLOCK, S, &r);
    CHECK(rc == 0 && r.verdict == CK_SB_COMMITTED && r.formatted == 0 && r.unlocked_genesis == 0);
    CHECK(r.boot_count_prev == 1 && r.boot_count_new == 2 && r.gen_open == g1 && r.gen_commit > g1);
    CHECK(strcmp(r.prev_commit, "pi5-unlock-test") == 0 && r.identity_class == M5_ID_PRODUCTION);
    CHECK(memcmp(store_boot_store()->uuid, test_uuid, 16) != 0);

    memset(S, 0, sizeof S);
    memset(W, 0, sizeof W);
    unlink(g_path);
    printf("pi5_unlock_test: %d checks, %d failures\n", checks, failures);
    printf("CK_PI5_UNLOCK_HOST: %s\n", failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
