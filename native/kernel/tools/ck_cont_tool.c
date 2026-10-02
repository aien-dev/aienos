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
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "continuity_resolve.h"
#include "disk_file.h"
#include "disk_layout.h"
#include "disk_part.h"
#include "store_boot.h"

static int usage(void)
{
    fprintf(stderr, "usage: ck_cont_tool respond KEY CHALLENGE | inject-peer IMG BS | corrupt-root IMG BS\n");
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

int main(int argc, char **argv)
{
    if (argc < 2) return usage();
    if (!strcmp(argv[1], "respond")) return cmd_respond(argc, argv);
    if (!strcmp(argv[1], "inject-peer")) return cmd_inject_peer(argc, argv);
    if (!strcmp(argv[1], "corrupt-root")) return cmd_corrupt_root(argc, argv);
    return usage();
}
