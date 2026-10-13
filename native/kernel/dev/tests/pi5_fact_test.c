/* pi5_fact_test.c -- AIENOS PI5-5 host test: the Pi Cortex fact stage (svc/pi5_fact.c, hooked by
 * svc/store_boot.c ck_store_pi5_fact_stage, compiled with -DCK_PI5_UNLOCK -DCK_PI5_UNLOCK_CARD -DCK_PI5_FACT
 * exactly as "make pi5-fact" builds it) over the Pi card layout. A file stands in for the card; every "boot"
 * reopens the file and starts from a cold C state (no Store or Cortex object survives between boots).
 *
 * Proves: boot 1 (card fact request) stores a fact into the sealed Store through the Cortex journal and
 * prints it with the Store generation that committed it; boot 2 (no request) recalls the same text and the
 * same generation from the disk, writes no new fact and verifies the chain; a third boot with a second fact
 * keeps both in order; a boot with the wrong recovery secret recalls nothing, prints no fact text and writes
 * nothing; the right secret afterwards still recalls; a card with no journal says "none" and creates none;
 * the request file checker refuses every malformed layout. Built with -DCK_FACT_MUTANT_NO_APPEND (the commit
 * skipped) or -DCK_FACT_MUTANT_RECALL_BLIND (recall never reads the journal) this test must FAIL.
 * Hosted test code only. */
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
#include "store_boot.h"
#include "../../core/unlock_req.h"
#include "../../core/fact_req.h"
#include "../../svc/pi5_fact.h"

#if !defined(CK_PI5_UNLOCK) || !defined(CK_PI5_FACT)
#error "pi5_fact_test.c must be built with -DCK_PI5_UNLOCK -DCK_PI5_FACT (the image's policy)"
#endif

static int checks, failures;
#define CHECK(c)                                                  \
    do {                                                          \
        checks++;                                                 \
        if (!(c)) {                                               \
            failures++;                                           \
            printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
        }                                                         \
    } while (0)

extern int ck_host_entropy_refuse;
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

/* One boot: open the card file, run the Store stage exactly as ck_stage_store does (unlock policy, then the
 * fact hook), close the card. text NULL: no request file this boot (the stub says ABSENT). Output captured. */
static int boot(const uint8_t *secret, const char *text, ck_store_report *r, char **cap)
{
    disk_file f;
    disk_dev d;
    ck_part p, sp;
    ck_gpt_info gi;
    if (disk_file_open(&f, &d, g_path, 512, 0, 0)) return -9999;
    if (ck_gpt_find_aienos(&d, &p, &gi) || ck_pi5_store_view(&p, &sp)) { disk_file_close(&f); return -9998; }
    memset(&ck_fact_req_boot, 0, sizeof ck_fact_req_boot);
    if (text) {
        struct ck_fact_req q;
        const char *why = 0;
        memset(&q, 0, sizeof q);
        memcpy(q.magic, CK_FACT_REQ_MAGIC, 8);
        q.version = CK_FACT_REQ_VERSION;
        memcpy(q.tag, CK_FACT_REQ_TAG, 16);
        q.len = (uint32_t)strlen(text);
        memcpy(q.text, text, q.len);
        CHECK(ck_fact_req_check(&q, &why) == 0);
        ck_fact_req_store(&q);
    } else {
        ck_fact_req_boot.state = CK_FACT_REQ_ABSENT;
    }
    ck_host_quiet = 1;
    ck_host_capture_start();
    int rc = ck_store_pi5_unlock_run(&sp.dev, secret, "pi5-fact-test", r);
    int frc = ck_store_pi5_fact_stage(r);
    CHECK(frc == 0);
    *cap = strdup(ck_host_capture_text());
    ck_host_capture_stop();
    ck_host_quiet = 0;
    CHECK(ck_fact_req_boot.state != CK_FACT_REQ_FOUND); /* the request is single use per boot */
    disk_file_close(&f);
    return rc;
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

/* "key=NNN" after the first occurrence of `after` in s; 0 when absent. */
static unsigned long long num_after(const char *s, const char *after, const char *key)
{
    const char *p = strstr(s, after);
    if (!p) return 0;
    p = strstr(p, key);
    if (!p) return 0;
    return strtoull(p + strlen(key), 0, 10);
}

static void req_with(struct ck_fact_req *q)
{
    memset(q, 0, sizeof *q);
    memcpy(q->magic, CK_FACT_REQ_MAGIC, 8);
    q->version = CK_FACT_REQ_VERSION;
    memcpy(q->tag, CK_FACT_REQ_TAG, 16);
    q->len = 5;
    memcpy(q->text, "hello", 5);
}

int main(void)
{
    snprintf(g_path, sizeof g_path, "/tmp/aienos-pi5-fact-test-%d.img", (int)getpid());
    gw_part gp[2] = {{gw_esp_type, 2048, 4095, "AIENOSPI5-ESP", 0x5a}, {ck_aienos_part_type, PART_FIRST, PART_FIRST + PART_SECS - 1, "AIENOS", 0}};
    CHECK(gw_write(g_path, 512, BLOCKS, gp, 2, 0) == 0);
    uint8_t S[CK_SB_SECRET_LEN], W[CK_SB_SECRET_LEN];
    for (int i = 0; i < 32; i++) S[i] = (uint8_t)(i * 7 + 5);
    memcpy(W, S, 32);
    W[31] ^= 0x80;
    ck_store_report r;
    char *c1, *c2, *c3, *c4, *c5;
    size_t n0, n1;
    uint8_t *b, *a;
    const char *FACT = "prefer short notes";

    /* 0. The request file checker. */
    {
        struct ck_fact_req q;
        const char *why = 0;
        req_with(&q);
        CHECK(ck_fact_req_check(&q, &why) == 0 && why == 0);
        req_with(&q); q.magic[0] = 'X'; CHECK(ck_fact_req_check(&q, &why) != 0);
        req_with(&q); q.version = 2; CHECK(ck_fact_req_check(&q, &why) != 0);
        req_with(&q); q.flags = 1; CHECK(ck_fact_req_check(&q, &why) != 0);
        req_with(&q); q.tag[0] = 'q'; CHECK(ck_fact_req_check(&q, &why) != 0);
        req_with(&q); q.len = 0; CHECK(ck_fact_req_check(&q, &why) != 0);
        req_with(&q); q.len = 49; CHECK(ck_fact_req_check(&q, &why) != 0);
        req_with(&q); q.reserved = 1; CHECK(ck_fact_req_check(&q, &why) != 0);
        req_with(&q); q.text[1] = 0x07; CHECK(ck_fact_req_check(&q, &why) != 0);
        req_with(&q); q.text[7] = 'z'; CHECK(ck_fact_req_check(&q, &why) != 0);
        req_with(&q); q.pad[0] = 1; CHECK(ck_fact_req_check(&q, &why) != 0);
        req_with(&q); q.len = 48; memset(q.text, 'a', 48); CHECK(ck_fact_req_check(&q, &why) == 0);
        CHECK(ck_fact_req_check(0, &why) != 0);
    }

    /* 1. Blank card, no request: the Store is created, recall says none, no journal is created. */
    CHECK(boot(S, 0, &r, &c1) == 0 && r.verdict == CK_SB_COMMITTED && r.formatted == 1);
    CHECK(strstr(c1, "fact_stage: recall none cortex=none records=0"));
    CHECK(!strstr(c1, "cortex open"));
    free(c1);

    /* 2. Boot 1 (F1): the card request stores a fact through the Cortex journal. */
    CHECK(boot(S, FACT, &r, &c1) == 0 && r.verdict == CK_SB_COMMITTED && r.formatted == 0);
    CHECK(strstr(c1, "fact_stage: cortex open records=0 chunks=1"));
    CHECK(strstr(c1, "fact_stage: remembered id=1 t=1 "));
    CHECK(strstr(c1, "bytes=18 text=\"prefer short notes\""));
    CHECK(strstr(c1, "fact_stage: readback id=1 t=1 "));
    CHECK(strstr(c1, "fact_stage: remember records=1 shown=1 newest_id=1"));
    CHECK(strstr(c1, "chain=ok"));
    unsigned long long gen1 = num_after(c1, "fact_stage: remembered", "store_gen=");
    CHECK(gen1 > 0);
    CHECK(num_after(c1, "fact_stage: readback", "store_gen=") == gen1);

    /* 3. Boot 2 (F2): cold start, no request file: the same fact and generation come back from the disk. */
    b = slurp(&n0);
    CHECK(boot(S, 0, &r, &c2) == 0 && r.verdict == CK_SB_COMMITTED && r.formatted == 0);
    CHECK(strstr(c2, "fact_stage: cortex open records=1 chunks=2"));
    CHECK(strstr(c2, "fact_stage: recalled id=1 t=1 "));
    CHECK(strstr(c2, "text=\"prefer short notes\""));
    CHECK(num_after(c2, "fact_stage: recalled", "store_gen=") == gen1);
    CHECK(strstr(c2, "fact_stage: recall records=1 shown=1 newest_id=1"));
    CHECK(strstr(c2, "chain=ok"));
    CHECK(!strstr(c2, "remembered") && !strstr(c2, "readback"));
    a = slurp(&n1);
    CHECK(n0 == n1); /* a recall adds no fact; only the boot record advanced */
    free(a);
    free(b);

    /* 4. Negative control (F3): the wrong recovery secret opens nothing, recalls nothing, writes nothing. */
    b = slurp(&n0);
    CHECK(boot(W, 0, &r, &c3) == CK_SB_E_SECRET_REJECTED && r.verdict == CK_SB_REFUSED);
    a = slurp(&n1);
    CHECK(n0 == n1 && memcmp(b, a, n0) == 0);
    CHECK(strstr(c3, "fact_stage: NOTHING RECALLED"));
    CHECK(!strstr(c3, "prefer short notes") && !strstr(c3, "recalled id=") && !strstr(c3, "cortex open"));
    free(a);
    free(b);
    /* a wrong secret together with a request file also writes nothing (the request is dropped) */
    b = slurp(&n0);
    CHECK(boot(W, "must not be stored", &r, &c4) == CK_SB_E_SECRET_REJECTED);
    a = slurp(&n1);
    CHECK(memcmp(b, a, n0) == 0 && strstr(c4, "NOTHING RECALLED") && !strstr(c4, "must not be stored"));
    free(a);
    free(b);

    /* 5. The right secret still recalls after the refusals; a second fact keeps both, in order. */
    CHECK(boot(S, "second fact", &r, &c5) == 0);
    CHECK(strstr(c5, "fact_stage: remembered id=2 t=2 "));
    CHECK(strstr(c5, "fact_stage: readback id=1 ") && strstr(c5, "fact_stage: readback id=2 "));
    free(c5);
    CHECK(boot(S, 0, &r, &c5) == 0);
    {
        const char *p1 = strstr(c5, "recalled id=1 ");
        const char *p2 = strstr(c5, "recalled id=2 ");
        CHECK(p1 && p2 && p1 < p2);
        CHECK(strstr(c5, "text=\"prefer short notes\"") && strstr(c5, "text=\"second fact\""));
        CHECK(strstr(c5, "fact_stage: recall records=2 shown=2"));
    }
    free(c5);

    free(c1);
    free(c2);
    free(c3);
    free(c4);
    memset(S, 0, sizeof S);
    memset(W, 0, sizeof W);
    unlink(g_path);
    printf("pi5_fact_test: %d checks, %d failures\n", checks, failures);
    printf("CK_PI5_FACT_HOST: %s\n", failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
