/* ck_cont_tool -- host tool for the continuity / Recovery Core QEMU gates
 * (scripts/qemu_ck_continuity_test.sh, scripts/qemu_ck_recovery_test.sh). It
 * reuses the kernel's own Store and continuity code on a boot-disk image made by
 * tools/ck_gpt_image.c (AIENOS GPT partition, TEST keys). Hosted C; test
 * tooling, never in an image. No Python, no outside libraries.
 *
 *   ck_cont_tool respond KEY_HEX CHALLENGE_HEX
 *        operator response (HMAC-SHA256, contract 1.7 / recovery.rs OperatorAuth), hex on stdout
 *   ck_cont_tool inject-peer IMG BS
 *        fill the INACTIVE superblock slot (Store-region unit 1 - active) with seeded garbage
 *        (the Rust `store-tool inject ... inactive seeded_garbage`); needs a mountable Store
 *   ck_cont_tool corrupt-root IMG BS
 *        flip byte 20 of the first AgentRoot (kind 16) envelope (the Rust `corrupt-kind ... 16`
 *        stand-in; contract K-3/K-4: the sealed mount refuses it)
 *   ck_cont_tool subject-dump IMG BS [HEAD_OUT]
 *        read-only: the ALLEN subject (kind 24) on the image as the kernel resolves it; optional
 *        canonical bytes of the head object (ARCH-0035 / OS-0018, PROPOSED)
 *   ck_cont_tool subject-plant IMG BS fork | foreign SRC_IMG
 *        TEST fixture: a second genesis subject (fork), or every subject object of another image, verbatim
 *   ck_cont_tool corrupt-subject IMG BS
 *        flip byte 20 of the first subject envelope
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "continuity_resolve.h"
#include "continuity_resolve_sealed.h"
#include "continuity_subject.h"
#include "disk_file.h"
#include "disk_layout.h"
#include "disk_part.h"
#include "store_boot.h"

static int usage(void)
{
    fprintf(stderr, "usage: ck_cont_tool respond KEY CHALLENGE | inject-peer IMG BS | corrupt-root IMG BS |\n"
                    "       subject-dump IMG BS [HEAD_OUT] | subject-plant IMG BS fork | subject-plant IMG BS foreign SRC_IMG |\n"
                    "       corrupt-subject IMG BS\n");
    return 2;
}

static int unhex(const char *s, uint8_t out[32])
{
    if (strlen(s) != 64) return -1;
    for (int i = 0; i < 32; i++) {
        unsigned v;
        char t[3] = {s[2 * i], s[2 * i + 1], 0};
        char *end;
        v = (unsigned)strtoul(t, &end, 16);
        if (*end) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

typedef struct {
    disk_file f;
    disk_dev raw;
    ck_part part;
    const disk_dev *d;
    st_disk sd;
    st_dev sdev;
    ts_device tdev;
    uint64_t base_lba, units;
    uint32_t bpu;
} image;

static int img_open(image *im, const char *path, const char *bs_s)
{
    uint32_t bs = (uint32_t)strtoul(bs_s, NULL, 10);
    if (bs != 512 && bs != 4096) {
        fprintf(stderr, "block size must be 512 or 4096\n");
        return -1;
    }
    memset(im, 0, sizeof *im);
    if (disk_file_open(&im->f, &im->raw, path, bs, 0, 0)) {
        fprintf(stderr, "cannot open %s\n", path);
        return -1;
    }
    ck_gpt_info gi;
    int grc = ck_gpt_find_aienos(&im->raw, &im->part, &gi);
    if (grc) {
        fprintf(stderr, "%s: no AIENOS partition (gpt: %s, rc=%d)\n", path, ck_gpt_strerror(grc), grc);
        disk_file_close(&im->f);
        return -1;
    }
    im->d = &im->part.dev;
    im->bpu = CK_LAYOUT_UNIT / bs;
    uint64_t units = im->d->block_count / im->bpu;
    im->base_lba = (uint64_t)CK_LAYOUT_ANCHOR_UNITS * im->bpu;
    im->units = units - CK_LAYOUT_ANCHOR_UNITS - CK_LAYOUT_PROBE_UNITS;
    return 0;
}

static int img_mount(image *im, ss_store *s, ss_workspace *ws)
{
    ss_keys keys;
    ck_store_test_keys(&keys);
    int rc = st_disk_bind(&im->sd, im->d, im->base_lba, im->units, &im->sdev);
    if (!rc) {
        ss_ts_device(im->d, &im->tdev);
        memset(s, 0, sizeof *s);
        rc = ss_open(s, &im->sdev, &im->tdev, 0, &keys, ws);
    }
    memset(&keys, 0, sizeof keys);
    if (rc) fprintf(stderr, "Store refused: rc=%d\n", rc);
    return rc;
}

static int cmd_respond(int argc, char **argv)
{
    uint8_t key[32], ch[32], out[32];
    if (argc != 4 || unhex(argv[2], key) || unhex(argv[3], ch)) return usage();
    cr_operator_response(key, ch, out);
    for (int i = 0; i < 32; i++) printf("%02x", out[i]);
    printf("\n");
    return 0;
}

static int cmd_inject_peer(int argc, char **argv)
{
    if (argc != 4) return usage();
    image im;
    if (img_open(&im, argv[2], argv[3])) return 1;
    ss_workspace *ws = calloc(1, sizeof *ws);
    ss_store *s = calloc(1, sizeof *s);
    int rc = !ws || !s ? -1 : img_mount(&im, s, ws);
    if (!rc) {
        uint32_t active = st_active_slot(&s->st);
        uint8_t *junk = malloc(CK_LAYOUT_UNIT);
        for (uint32_t i = 0; i < CK_LAYOUT_UNIT; i++) junk[i] = (uint8_t)(i * 37u + 11u);
        uint64_t lba = im.base_lba + (uint64_t)(1u - active) * im.bpu;
        rc = disk_write(im.d, lba, im.bpu, junk);
        if (!rc) rc = disk_flush(im.d);
        free(junk);
        if (!rc) printf("inject-peer: slot %u of the Store region filled (active slot %u)\n", 1u - active, active);
    }
    free(s);
    free(ws);
    disk_file_close(&im.f);
    return rc ? 1 : 0;
}

static int cmd_corrupt_root(int argc, char **argv)
{
    if (argc != 4) return usage();
    image im;
    if (img_open(&im, argv[2], argv[3])) return 1;
    ss_workspace *ws = calloc(1, sizeof *ws);
    ss_store *s = calloc(1, sizeof *s);
    int rc = !ws || !s ? -1 : img_mount(&im, s, ws), done = 0;
    for (uint32_t k = 0; !rc && !done && k < s->nclaims; k++) {
        if (ws->claims[k].c.obj.object_kind != 16u) continue; /* AgentRoot */
        uint32_t n = 0;
        const sv1_entry *cat = st_catalog(&s->st, &n);
        for (uint32_t j = 0; j < n; j++) {
            if (memcmp(cat[j].object_id, ws->claims[k].sid, 32)) continue;
            uint8_t *u = malloc(CK_LAYOUT_UNIT);
            uint64_t lba = im.base_lba + cat[j].first_unit * im.bpu;
            rc = disk_read(im.d, lba, im.bpu, u);
            if (!rc) {
                u[20] ^= 0xff;
                rc = disk_write(im.d, lba, im.bpu, u);
            }
            if (!rc) rc = disk_flush(im.d);
            free(u);
            done = 1;
            if (!rc) printf("corrupt-root: byte 20 of the AgentRoot envelope (store unit %llu) flipped\n", (unsigned long long)cat[j].first_unit);
            break;
        }
    }
    if (!rc && !done) {
        fprintf(stderr, "no AgentRoot envelope found\n");
        rc = -1;
    }
    free(s);
    free(ws);
    disk_file_close(&im.f);
    return rc ? 1 : 0;
}

/* ---- ALLEN subject (kind 24; ARCH-0035 / OS-0018, PROPOSED) ----
 * subject-dump reads the Store of a boot-disk image the way the kernel does
 * (sealed mount, cr_resolve, cs_resolve) and prints what is ON THE DISK,
 * independent of the guest's serial output. It writes nothing; the gate runs
 * it on a copy. subject-plant and corrupt-subject make TEST fixtures. */
static void hexp(const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

struct subj_ctx {
    image im;
    ss_workspace *ws;
    ss_store *s;
    struct cr_source src;
    struct cr_work w;
    struct cr_view v;
    struct cs_subject subj;
    uint8_t id[32];
};

/* Mount, resolve identity, resolve subject. Returns the cr_resolve outcome
 * in *io and the cs_resolve outcome in *so (-1 if not reached); 0 or -1 when
 * the image could not be mounted. */
static int subj_open(struct subj_ctx *c, const char *path, const char *bs, int *io, int *so, const char **why)
{
    int src_rc = 0;
    *io = *so = -1;
    if (img_open(&c->im, path, bs)) return -1;
    c->ws = calloc(1, sizeof *c->ws);
    c->s = calloc(1, sizeof *c->s);
    if (!c->ws || !c->s || img_mount(&c->im, c->s, c->ws)) return -1;
    cr_bind_sealed(&c->src, c->s);
    *io = cr_resolve(&c->src, &c->w, &c->v, why, &src_rc);
    if (*io != CR_RESOLVED) return 0;
    *so = cs_resolve(&c->src, &c->w, &c->v, &c->subj, c->id, why, &src_rc);
    return 0;
}
static void subj_close(struct subj_ctx *c)
{
    free(c->s);
    free(c->ws);
    disk_file_close(&c->im.f);
}

static int cmd_subject_dump(int argc, char **argv)
{
    if (argc != 4 && argc != 5) return usage();
    static struct subj_ctx c;
    const char *why = NULL;
    int io, so;
    if (subj_open(&c, argv[2], argv[3], &io, &so, &why)) {
        printf("subject-dump: store=Refused\n");
        return 1;
    }
    uint32_t n = c.src.count(c.src.ctx), objs = 0, genesis = 0;
    for (uint32_t i = 0; i < n; i++) {
        uint16_t kind = 0, ver = 0;
        size_t len = 0;
        if (c.src.entry(c.src.ctx, i, &kind, &ver) || kind != CC_KIND_SUBJECT) continue;
        objs++;
        static struct cs_subject t;
        if (c.src.read(c.src.ctx, i, c.w.buf, sizeof c.w.buf, &len) == 0 &&
            cs_subject_decode(c.w.buf, len, &t, NULL) == CC_OK && t.sequence == 1)
            genesis++;
    }
    printf("subject-dump: generation=%llu identity=%s", (unsigned long long)ss_generation(c.s), cr_outcome_name(io));
    if (io == CR_RESOLVED) {
        printf(" agent=");
        hexp(c.v.root.agent_id, 32);
    }
    printf(" subject_objects=%u genesis_objects=%u", objs, genesis);
    if (so == CS_RESOLVED) {
        uint32_t active = 0;
        for (uint32_t i = 0; i < c.subj.n_intents; i++) active += c.subj.in[i].state == CS_ACTIVE;
        printf(" subject=");
        hexp(c.id, 32);
        printf(" sequence=%llu lineage=", (unsigned long long)c.subj.sequence);
        hexp(c.subj.cortex, 32);
        printf(" active=%u\n", active);
        for (uint32_t i = 0; i < c.subj.n_intents; i++) {
            const struct cs_intent *a = &c.subj.in[i];
            if (a->state != CS_ACTIVE) continue;
            printf("subject-dump: intent id=");
            hexp(a->id, 32);
            printf(" kind=%u regime=%llu target_ns=%llu since=%llu\n", (unsigned)a->kind,
                   (unsigned long long)a->payload[0], (unsigned long long)a->payload[1], (unsigned long long)a->since);
        }
        if (argc == 5) { /* the head object, canonical bytes, for omega's allen tool */
            static uint8_t b[CS_MAX_BYTES];
            size_t len = 0;
            uint8_t id2[32];
            FILE *f = NULL;
            if (cs_subject_encode(&c.subj, b, sizeof b, &len, &why) != CC_OK || cs_subject_id(b, len, id2) != CC_OK ||
                memcmp(id2, c.id, 32) || !(f = fopen(argv[4], "wb")) || fwrite(b, 1, len, f) != len) {
                if (f) fclose(f);
                fprintf(stderr, "subject-dump: cannot write the head object\n");
                subj_close(&c);
                return 1;
            }
            fclose(f);
        }
    } else if (so == CS_ABSENT) {
        printf(" subject=ABSENT\n");
    } else if (so >= 0) {
        printf(" subject=%s (%s)\n", cr_outcome_name(so), why ? why : "-");
    } else {
        printf("\n");
    }
    subj_close(&c);
    return 0;
}

static int plant(struct subj_ctx *c, const uint8_t *b, size_t len)
{
    struct cr_sealed_sink sk = {c->s, 0, 0};
    struct cr_sink snk;
    struct cr_wobj o = {CC_KIND_SUBJECT, CC_STORE_OBJECT_VERSION, b, len};
    cr_bind_sealed_sink(&snk, &sk);
    return snk.transact(snk.ctx, &o, 1);
}

/* subject-plant IMG BS fork          : a second sequence-1 subject for the same root and agent
  * subject-plant IMG BS foreign SRC   : every subject object of image SRC, verbatim */
static int cmd_subject_plant(int argc, char **argv)
{
    if (argc < 5) return usage();
    static struct subj_ctx c, f;
    static uint8_t b[CS_MAX_BYTES];
    size_t len = 0;
    const char *why = NULL;
    int io, so, rc = 1;
    if (subj_open(&c, argv[2], argv[3], &io, &so, &why) || io != CR_RESOLVED) {
        fprintf(stderr, "subject-plant: target identity does not resolve\n");
        return 1;
    }
    if (!strcmp(argv[4], "fork") && argc == 5) {
        if (so != CS_RESOLVED) {
            fprintf(stderr, "subject-plant: target has no subject to fork\n");
        } else {
            uint8_t prov[32];
            memset(prov, 0xf0, 32);
            static struct cs_subject g;
            cs_subject_genesis(&g, &c.v, prov, CS_ORIGIN_OPERATOR);
            cs_subject_bind_cortex(&g, c.subj.cortex);
            if (cs_subject_encode(&g, b, sizeof b, &len, &why) == CC_OK && plant(&c, b, len) == 0) {
                printf("subject-plant: second genesis subject planted (fork)\n");
                rc = 0;
            }
        }
    } else if (!strcmp(argv[4], "foreign") && argc == 6) {
        int fio, fso;
        if (subj_open(&f, argv[5], argv[3], &fio, &fso, &why) || fso != CS_RESOLVED) {
            fprintf(stderr, "subject-plant: source image has no subject\n");
        } else if (!memcmp(f.v.root.agent_id, c.v.root.agent_id, 32)) {
            fprintf(stderr, "subject-plant: source and target share an agent\n");
        } else {
            /* every subject object of the source image, verbatim */
            uint32_t n = f.src.count(f.src.ctx), k = 0;
            rc = 0;
            for (uint32_t i = 0; i < n && !rc; i++) {
                uint16_t kind = 0, ver = 0;
                if (f.src.entry(f.src.ctx, i, &kind, &ver) || kind != CC_KIND_SUBJECT) continue;
                if (f.src.read(f.src.ctx, i, b, sizeof b, &len) || plant(&c, b, len)) rc = 1;
                else k++;
            }
            if (!rc) {
                printf("subject-plant: %u foreign subject objects of agent ", k);
                hexp(f.subj.agent, 32);
                printf(" planted\n");
            }
        }
        if (f.s) subj_close(&f);
    } else {
        subj_close(&c);
        return usage();
    }
    subj_close(&c);
    return rc;
}

/* corrupt-subject IMG BS: flip byte 20 of the first subject (kind 24) envelope. */
static int cmd_corrupt_subject(int argc, char **argv)
{
    if (argc != 4) return usage();
    image im;
    if (img_open(&im, argv[2], argv[3])) return 1;
    ss_workspace *ws = calloc(1, sizeof *ws);
    ss_store *s = calloc(1, sizeof *s);
    int rc = !ws || !s ? -1 : img_mount(&im, s, ws), done = 0;
    for (uint32_t k = 0; !rc && !done && k < s->nclaims; k++) {
        if (ws->claims[k].c.obj.object_kind != CC_KIND_SUBJECT) continue;
        uint32_t n = 0;
        const sv1_entry *cat = st_catalog(&s->st, &n);
        for (uint32_t j = 0; j < n; j++) {
            if (memcmp(cat[j].object_id, ws->claims[k].sid, 32)) continue;
            uint8_t *u = malloc(CK_LAYOUT_UNIT);
            uint64_t lba = im.base_lba + cat[j].first_unit * im.bpu;
            rc = disk_read(im.d, lba, im.bpu, u);
            if (!rc) {
                u[20] ^= 0xff;
                rc = disk_write(im.d, lba, im.bpu, u);
            }
            if (!rc) rc = disk_flush(im.d);
            free(u);
            done = 1;
            if (!rc) printf("corrupt-subject: byte 20 of a subject envelope (store unit %llu) flipped\n",
                            (unsigned long long)cat[j].first_unit);
            break;
        }
    }
    if (!rc && !done) {
        fprintf(stderr, "no subject envelope found\n");
        rc = -1;
    }
    free(s);
    free(ws);
    disk_file_close(&im.f);
    return rc ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) return usage();
    if (!strcmp(argv[1], "respond")) return cmd_respond(argc, argv);
    if (!strcmp(argv[1], "inject-peer")) return cmd_inject_peer(argc, argv);
    if (!strcmp(argv[1], "corrupt-root")) return cmd_corrupt_root(argc, argv);
    if (!strcmp(argv[1], "subject-dump")) return cmd_subject_dump(argc, argv);
    if (!strcmp(argv[1], "subject-plant")) return cmd_subject_plant(argc, argv);
    if (!strcmp(argv[1], "corrupt-subject")) return cmd_corrupt_subject(argc, argv);
    return usage();
}
