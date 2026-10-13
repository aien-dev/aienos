/* pi5_agent_test.c -- AIENOS PI5-6 final cut host test: the Pi agent stage (svc/pi5_agent.c, hooked by svc/store_boot.c
 * ck_store_pi5_agent_stage, compiled with -DCK_PI5_UNLOCK -DCK_PI5_UNLOCK_CARD -DCK_PI5_AGENT exactly as "make pi5-agent"
 * builds it) over the Pi card layout. A file stands in for the card; every "boot" reopens the file and starts from a cold C
 * state. The inference unit is a STUB defined here (a real 770 MiB model cannot run on the host); the stage's own policy
 * (order, golden checks, what gets committed, what is recovered) is the real code under test.
 *
 * Proves: boot 1 (right secret, model present) generates, closes the session, commits ONE sealed reply object and reads it
 * back; boot 2 (same secret, no model) recovers the same reply with the same Store generation and the same object digest
 * without touching the model; boot 2 with a model present still does not generate; the wrong secret recovers nothing,
 * never reaches the model (zero calls) and leaves the card byte-identical; a reply that is not the golden one (wrong ids,
 * wrong chat-template head, wrong text, wrong model digest, refused or cancelled prompt) commits nothing; a stored reply that
 * is not golden is reported FAIL on recovery; no reply and no model is NOMODEL; a lifecycle reply (no trailer) and another
 * prompt are ignored; the reply object format is the lifecycle's, byte for byte, plus the trailer.
 * Mutants (Makefile-less, see stage.mk pi5-agent-mutants) must make this test FAIL. Hosted test code only. */
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
#include "../../core/reply_obj.h"
#include "m5.h"
#include "store_boot.h"
#include "../../core/unlock_req.h"
#include "../../svc/pi5_agent.h"

#if !defined(CK_PI5_UNLOCK) || !defined(CK_PI5_AGENT)
#error "pi5_agent_test.c must be built with -DCK_PI5_UNLOCK -DCK_PI5_AGENT (the image's policy)"
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

/* ---- the inference unit stub (core/infer.c in the image) ---- */
static struct {
    int model;              /* MODEL.MAP present and the digest matched: ck_infer_run leaves a resident session */
    int resident;
    int prompt_rc;          /* ck_infer_prompt result */
    int cancelled;
    uint32_t ids[CK_INFER_REPLY_IDS];
    unsigned nids;
    char text[64];
    uint32_t head[4];
    uint8_t sha[32];
    int n_run, n_prompt, n_close;
    char last_prompt[96];
} G;

static const uint32_t gold_ids[8] = {791, 6864, 315, 9822, 374, 12366, 13, 128009};
static const uint32_t gold_head[4] = {128000, 128006, 882, 128007};

static void stub_good(int model)
{
    memset(&G, 0, sizeof G);
    G.model = model;
    memcpy(G.ids, gold_ids, sizeof gold_ids);
    G.nids = 8;
    strcpy(G.text, CK_AGENT_GOLDEN_TEXT);
    memcpy(G.head, gold_head, sizeof gold_head);
    for (int i = 0; i < 32; i++) {
        unsigned v;
        sscanf(CK_AGENT_GOLDEN_MODEL_SHA256 + 2 * i, "%2x", &v);
        G.sha[i] = (uint8_t)v;
    }
}

void ck_infer_run(void)
{
    G.n_run++;
    G.resident = G.model;
}
int ck_infer_resident(void) { return G.resident; }
const uint8_t *ck_infer_model_sha256(void) { return G.resident ? G.sha : 0; }
int ck_infer_prompt(const char *text, size_t len, int (*cancel_poll)(void), struct ck_infer_reply *r)
{
    (void)cancel_poll;
    G.n_prompt++;
    snprintf(G.last_prompt, sizeof G.last_prompt, "%.*s", (int)len, text);
    memset(r, 0, sizeof *r);
    if (G.prompt_rc) return G.prompt_rc;
    memcpy(r->ids, G.ids, sizeof G.ids);
    r->produced = G.nids;
    r->prompt_ids = 17;
    r->steps = 17 + G.nids;
    r->cancelled = G.cancelled;
    r->us = 1234;
    r->text_len = (uint32_t)strlen(G.text);
    memcpy(r->text, G.text, r->text_len);
    memcpy(r->prompt_head, G.head, sizeof G.head);
    return 0;
}
void ck_infer_resident_close(void)
{
    G.n_close++;
    G.resident = 0;
}

#define BLOCKS 262144ull
#define PART_FIRST 8192u
#define PART_SECS 8192u
static char g_path[256];

/* Optional forged object committed through the open Store before the agent stage (a tampered or foreign R1 object). */
static const uint8_t *g_forge;
static size_t g_forge_len;

/* One boot: open the card file, run the Store stage exactly as ck_stage_store does (unlock policy, then the agent hook),
 * close the card. Output captured. */
static int boot(const uint8_t *secret, ck_store_report *r, int *agent_rc, char **cap)
{
    disk_file f;
    disk_dev d;
    ck_part p, sp;
    ck_gpt_info gi;
    if (disk_file_open(&f, &d, g_path, 512, 0, 0)) return -9999;
    if (ck_gpt_find_aienos(&d, &p, &gi) || ck_pi5_store_view(&p, &sp)) { disk_file_close(&f); return -9998; }
    ck_host_quiet = 1;
    ck_host_capture_start();
    int rc = ck_store_pi5_unlock_run(&sp.dev, secret, "pi5-agent-test", r);
    if (g_forge && r->verdict == CK_SB_COMMITTED) {
        ss_object o = {CK_REPLY_OBJ_KIND, 1, g_forge, g_forge_len};
        CHECK(ss_transact(store_boot_store(), &o, 1, 0, 0, 0) == 0);
    }
    *agent_rc = ck_store_pi5_agent_stage(r);
    *cap = strdup(ck_host_capture_text());
    ck_host_capture_stop();
    ck_host_quiet = 0;
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

/* The whole "agent: reply ..." line of a capture ("" when absent). */
static void reply_line(const char *cap, char *out, size_t cap_out)
{
    const char *p = strstr(cap, "agent: reply ");
    size_t n = 0;
    out[0] = 0;
    if (!p) return;
    while (p[n] && p[n] != '\n' && n + 1 < cap_out) { out[n] = p[n]; n++; }
    out[n] = 0;
}

static unsigned long long num_after(const char *s, const char *after, const char *key)
{
    const char *p = strstr(s, after);
    if (!p) return 0;
    p = strstr(p, key);
    return p ? strtoull(p + strlen(key), 0, 10) : 0;
}

static void blank_card(void)
{
    gw_part gp[2] = {{gw_esp_type, 2048, 4095, "AIENOSPI5-ESP", 0x5a}, {ck_aienos_part_type, PART_FIRST, PART_FIRST + PART_SECS - 1, "AIENOS", 0}};
    CHECK(gw_write(g_path, 512, BLOCKS, gp, 2, 0) == 0);
}

int main(void)
{
    snprintf(g_path, sizeof g_path, "/tmp/aienos-pi5-agent-test-%d.img", (int)getpid());
    uint8_t S[CK_SB_SECRET_LEN], W[CK_SB_SECRET_LEN];
    for (int i = 0; i < 32; i++) S[i] = (uint8_t)(i * 7 + 5);
    memcpy(W, S, 32);
    W[31] ^= 0x80;
    ck_store_report r;
    char *c1, *c2, *c3, *c4;
    char l1[1024], l2[1024];
    size_t n0, n1;
    uint8_t *b, *a;
    int arc;

    /* 0. The shared reply object: the lifecycle format byte for byte, plus the trailer only when asked. */
    {
        uint8_t o[CK_REPLY_OBJ_TRAILER_MAX + 128];
        uint32_t ids[3] = {791, 0, 128009};
        size_t n = ck_reply_obj_build(o, "Q", 1, (const uint8_t *)"A\nB", 3, 0, 0, 0);
        static const char lit[] = "aienos.reply.v1\nprompt: Q\nreply: A\nB\n";
        CHECK(n == sizeof lit - 1 && memcmp(o, lit, n) == 0);
        n = ck_reply_obj_build(o, "Q", 1, (const uint8_t *)"A", 1, CK_AGENT_GOLDEN_MODEL_SHA256, ids, 3);
        static const char lit2[] = "aienos.reply.v1\nprompt: Q\nreply: A\nmodel: " CK_AGENT_GOLDEN_MODEL_SHA256 "\nids: 791 0 128009\n";
        CHECK(n == sizeof lit2 - 1 && memcmp(o, lit2, n) == 0);
        CHECK(CK_REPLY_OBJ_KIND == 0x5231u);
    }

    /* 1. Boot 1 (G1): blank card, model present: generate, close, commit, read back. */
    blank_card();
    stub_good(1);
    CHECK(boot(S, &r, &arc, &c1) == 0 && r.verdict == CK_SB_COMMITTED && r.formatted == 1 && arc == 0);
    CHECK(G.n_run == 1 && G.n_prompt == 1 && G.n_close == 1 && !G.resident);
    CHECK(strcmp(G.last_prompt, CK_AGENT_PROMPT) == 0);
    CHECK(strstr(c1, "agent: generated tokens=8 prompt_ids=17"));
    CHECK(strstr(c1, "prompt_head=128000,128006,882,128007"));
    CHECK(strstr(c1, "ids=791 6864 315 9822 374 12366 13 128009 text=\"The capital of France is Paris.\""));
    CHECK(strstr(c1, "model_sha256=" CK_AGENT_GOLDEN_MODEL_SHA256));
    CHECK(strstr(c1, "agent: committed store_gen="));
    CHECK(strstr(c1, "AIENOS_PI5_AGENT: GENERATED PASS"));
    CHECK(strstr(c1, "agent: reply store_gen="));
    unsigned long long gen1 = num_after(c1, "agent: reply", "store_gen=");
    CHECK(gen1 > 0);
    reply_line(c1, l1, sizeof l1);
    CHECK(strlen(l1) > 100);
    CHECK(strstr(l1, "object_sha256="));

    /* 2. Boot 2 (G2): same secret, NO model: the same reply, same generation, same digest, model never touched, nothing new. */
    stub_good(0);
    b = slurp(&n0);
    CHECK(boot(S, &r, &arc, &c2) == 0 && r.verdict == CK_SB_COMMITTED && r.formatted == 0 && arc == 0);
    CHECK(G.n_run == 0 && G.n_prompt == 0 && G.n_close == 0);
    CHECK(strstr(c2, "AIENOS_PI5_AGENT: RECOVERED PASS"));
    CHECK(!strstr(c2, "agent: generated") && !strstr(c2, "agent: committed"));
    reply_line(c2, l2, sizeof l2);
    CHECK(strcmp(l1, l2) == 0); /* boot 2 prints exactly boot 1's reply line, store generation and object digest included */
    a = slurp(&n1);
    CHECK(n0 == n1);
    free(a);
    free(b);
    /* 2b. Same, with the model present on the card: the Store already holds the reply, so nothing is generated. */
    stub_good(1);
    CHECK(boot(S, &r, &arc, &c3) == 0 && arc == 0);
    CHECK(G.n_run == 0 && G.n_prompt == 0);
    reply_line(c3, l2, sizeof l2);
    CHECK(strcmp(l1, l2) == 0 && strstr(c3, "RECOVERED PASS"));
    free(c3);

    /* 3. Negative control (G3): the wrong secret opens nothing, recovers nothing, never reaches the model, writes nothing. */
    stub_good(1);
    b = slurp(&n0);
    CHECK(boot(W, &r, &arc, &c3) == CK_SB_E_SECRET_REJECTED && r.verdict == CK_SB_REFUSED && arc == 0);
    a = slurp(&n1);
    CHECK(n0 == n1 && memcmp(b, a, n0) == 0);
    CHECK(G.n_run == 0 && G.n_prompt == 0 && G.n_close == 0);
    CHECK(strstr(c3, "agent: NOTHING RECOVERED") && strstr(c3, "AIENOS_PI5_AGENT: NOSTORE"));
    CHECK(!strstr(c3, "agent: reply") && !strstr(c3, "Paris") && !strstr(c3, "RECOVERED PASS"));
    free(a);
    free(b);
    free(c3);
    /* and the right secret afterwards recovers the same reply again */
    stub_good(0);
    CHECK(boot(S, &r, &arc, &c3) == 0 && arc == 0);
    reply_line(c3, l2, sizeof l2);
    CHECK(strcmp(l1, l2) == 0);
    free(c3);
    free(c1);
    free(c2);

    /* 4. Replies that are not golden commit nothing (each on a fresh card; then a no-model boot shows nothing is stored). */
    {
        enum { WRONG_ID, WRONG_HEAD, WRONG_TEXT, WRONG_MODEL, PROMPT_REFUSED, CANCELLED, MODEL_ABSENT_AFTER_RUN, TOO_MANY, N_CASES };
        for (int k = 0; k < N_CASES; k++) {
            blank_card();
            stub_good(1);
            switch (k) {
            case WRONG_ID: G.ids[3] ^= 1; break;
            case WRONG_HEAD: G.head[2] = 883; break;
            case WRONG_TEXT: strcpy(G.text, "The capital of France is Lyon."); break;
            case WRONG_MODEL: G.sha[0] ^= 1; break;
            case PROMPT_REFUSED: G.prompt_rc = -15; break;
            case CANCELLED: G.cancelled = 1; break;
            case MODEL_ABSENT_AFTER_RUN: G.model = 0; break;
            case TOO_MANY: G.nids = 9; G.ids[8] = 128009; break;
            }
            CHECK(boot(S, &r, &arc, &c4) == 0 && r.verdict == CK_SB_COMMITTED && arc != 0);
            CHECK(strstr(c4, "AIENOS_PI5_AGENT: GENERATED FAIL") || strstr(c4, "AIENOS_PI5_AGENT: NOMODEL"));
            CHECK(!strstr(c4, "agent: committed") && !strstr(c4, "agent: reply"));
            CHECK(G.n_close == (k == MODEL_ABSENT_AFTER_RUN ? 0 : 1) && !G.resident);
            free(c4);
            stub_good(0);
            CHECK(boot(S, &r, &arc, &c4) == 0 && arc != 0 && strstr(c4, "NOTHING GENERATED") && strstr(c4, "AIENOS_PI5_AGENT: NOMODEL"));
            CHECK(G.n_prompt == 0 && !strstr(c4, "agent: reply"));
            free(c4);
        }
    }

    /* 5. No reply and no model: NOMODEL, nothing written, the model path was tried but not the prompt. */
    blank_card();
    stub_good(0);
    CHECK(boot(S, &r, &arc, &c4) == 0 && arc != 0 && G.n_run == 1 && G.n_prompt == 0);
    CHECK(strstr(c4, "AIENOS_PI5_AGENT: NOMODEL"));
    free(c4);

    /* 6. Foreign R1 objects are ignored; a stored agent reply that is not golden is reported FAIL on recovery. */
    {
        uint8_t o[CK_REPLY_OBJ_TRAILER_MAX + 512];
        uint32_t bad[8];
        memcpy(bad, gold_ids, sizeof bad);
        blank_card();
        /* 6a. a lifecycle reply for the SAME prompt (no trailer) and an agent-format reply for ANOTHER prompt */
        g_forge_len = ck_reply_obj_build(o, CK_AGENT_PROMPT, strlen(CK_AGENT_PROMPT), (const uint8_t *)"Paris.", 6, 0, 0, 0);
        g_forge = o;
        stub_good(0);
        CHECK(boot(S, &r, &arc, &c4) == 0 && arc != 0 && strstr(c4, "NOMODEL")); /* ignored: no agent reply yet */
        free(c4);
        g_forge_len = ck_reply_obj_build(o, "Say hello.", 10, (const uint8_t *)"Hi", 2, CK_AGENT_GOLDEN_MODEL_SHA256, gold_ids, 8);
        CHECK(boot(S, &r, &arc, &c4) == 0 && arc != 0 && strstr(c4, "NOMODEL"));
        free(c4);
        g_forge = 0;
        stub_good(1);
        CHECK(boot(S, &r, &arc, &c4) == 0 && arc == 0 && strstr(c4, "GENERATED PASS")); /* still generates beside them */
        reply_line(c4, l1, sizeof l1);
        free(c4);
        stub_good(0);
        CHECK(boot(S, &r, &arc, &c4) == 0 && arc == 0 && strstr(c4, "RECOVERED PASS"));
        reply_line(c4, l2, sizeof l2);
        CHECK(strcmp(l1, l2) == 0);
        free(c4);
        /* 6b. a well-formed agent object whose token list is not golden (as if written by a broken generator) */
        blank_card();
        bad[2] = 316;
        g_forge_len = ck_reply_obj_build(o, CK_AGENT_PROMPT, strlen(CK_AGENT_PROMPT), (const uint8_t *)CK_AGENT_GOLDEN_TEXT,
                                         strlen(CK_AGENT_GOLDEN_TEXT), CK_AGENT_GOLDEN_MODEL_SHA256, bad, 8);
        g_forge = o;
        stub_good(1);
        CHECK(boot(S, &r, &arc, &c4) == 0 && arc != 0);
        CHECK(strstr(c4, "AIENOS_PI5_AGENT: RECOVERED FAIL") && strstr(c4, "not the golden reply"));
        CHECK(G.n_run == 0 && G.n_prompt == 0); /* a bad stored reply is reported, never silently regenerated over */
        free(c4);
        /* 6c. a stored reply carrying another model digest, and a text with newlines and trailer-looking lines inside */
        blank_card();
        g_forge_len = ck_reply_obj_build(o, CK_AGENT_PROMPT, strlen(CK_AGENT_PROMPT),
                                         (const uint8_t *)"The capital of France is Paris.\nids: 1 2\nmodel: x", 49, CK_AGENT_GOLDEN_MODEL_SHA256, gold_ids, 8);
        CHECK(boot(S, &r, &arc, &c4) == 0 && arc != 0 && strstr(c4, "RECOVERED FAIL"));
        CHECK(strstr(c4, "ids=791 6864 315 9822 374 12366 13 128009")); /* the trailer is read from the END */
        free(c4);
        blank_card();
        {
            char other[65];
            memcpy(other, CK_AGENT_GOLDEN_MODEL_SHA256, 65);
            other[10] = other[10] == '0' ? '1' : '0';
            g_forge_len = ck_reply_obj_build(o, CK_AGENT_PROMPT, strlen(CK_AGENT_PROMPT), (const uint8_t *)CK_AGENT_GOLDEN_TEXT,
                                             strlen(CK_AGENT_GOLDEN_TEXT), other, gold_ids, 8);
            CHECK(boot(S, &r, &arc, &c4) == 0 && arc != 0 && strstr(c4, "RECOVERED FAIL"));
            free(c4);
        }
        g_forge = 0;
    }

    memset(S, 0, sizeof S);
    memset(W, 0, sizeof W);
    unlink(g_path);
    printf("pi5_agent_test: %d checks, %d failures\n", checks, failures);
    printf("CK_PI5_AGENT_HOST: %s\n", failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
