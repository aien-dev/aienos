/* ck_store_image -- host tool: put signed P2 artifacts into the sealed C Store
 * on a raw boot disk image, at image build time, so the C kernel's loader
 * reads them from NVMe (svc/artifact_store.h). It reuses the kernel's own
 * Store code (store_boot.c formats and commits the boot record exactly as a
 * first boot would; artifact_store.c writes and reads the artifact objects),
 * so there is no second disk format. TEST identity and TEST keys only.
 *
 *   ck_store_image build IMG BLOCK_SIZE ENTRY...   IMG must exist and be blank
 *        ENTRY = path to a file (Store name = its basename, 1..32 bytes)
 *              | missing:NAME:LEN (index entry, no chunks: hostile case)
 *   ck_store_image list IMG BLOCK_SIZE             read back with the kernel reader
 *   ck_store_image locate IMG BLOCK_SIZE NAME      "offset=B length=L" of the
 *        sealed envelope holding chunk 0 of NAME (for the corrupt-disk case)
 * list and locate only read the image. Hosted C; test tooling, never in an
 * image. No Python, no outside libraries. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "artifact_store.h"
#include "disk_file.h"
#include "disk_layout.h"
#include "store_boot.h"

static int usage(void)
{
    fprintf(stderr, "usage: ck_store_image build IMG BS ENTRY... | list IMG BS | locate IMG BS NAME\n");
    return 2;
}

static uint8_t *slurp(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = CK_ART_MAX_BYTES + 1, n = 0;
    uint8_t *b = malloc(cap);
    if (b) n = fread(b, 1, cap, f);
    fclose(f);
    if (!b || n == 0 || n > CK_ART_MAX_BYTES) {
        free(b);
        return NULL;
    }
    *len = n;
    return b;
}

typedef struct {
    disk_file f;
    disk_dev d;
    st_disk sd;
    st_dev sdev;
    ts_device tdev;
    uint64_t base_lba, units;
} image;

static int img_open(image *im, const char *path, const char *bs_s)
{
    uint32_t bs = (uint32_t)strtoul(bs_s, NULL, 10);
    if (bs != 512 && bs != 4096) {
        fprintf(stderr, "block size must be 512 or 4096\n");
        return -1;
    }
    memset(im, 0, sizeof *im);
    if (disk_file_open(&im->f, &im->d, path, bs, 0, 0)) {
        fprintf(stderr, "cannot open %s\n", path);
        return -1;
    }
    uint32_t bpu = CK_LAYOUT_UNIT / bs;
    uint64_t units = im->d.block_count / bpu;
    if (units < CK_LAYOUT_ANCHOR_UNITS + CK_LAYOUT_MIN_STORE_UNITS + CK_LAYOUT_PROBE_UNITS) {
        fprintf(stderr, "image too small\n");
        disk_file_close(&im->f);
        return -1;
    }
    im->base_lba = (uint64_t)CK_LAYOUT_ANCHOR_UNITS * bpu;
    im->units = units - CK_LAYOUT_ANCHOR_UNITS - CK_LAYOUT_PROBE_UNITS;
    return 0;
}

/* Read-only keyed mount, the same proofs as the kernel's store stage. */
static int img_mount(image *im, ss_store *s, ss_workspace *ws)
{
    ss_keys keys;
    ck_store_test_keys(&keys);
    int rc = st_disk_bind(&im->sd, &im->d, im->base_lba, im->units, &im->sdev);
    if (!rc) {
        ss_ts_device(&im->d, &im->tdev);
        memset(s, 0, sizeof *s);
        rc = ss_open(s, &im->sdev, &im->tdev, 0, &keys, ws);
    }
    memset(&keys, 0, sizeof keys);
    if (rc) fprintf(stderr, "Store refused: rc=%d\n", rc);
    return rc;
}

static void hex(const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

static int cmd_build(int argc, char **argv)
{
    if (argc < 5) return usage();
    size_t n = (size_t)argc - 4;
    if (n > CK_ART_MAX_ENTRIES) {
        fprintf(stderr, "at most %u artifacts\n", CK_ART_MAX_ENTRIES);
        return 1;
    }
    ck_art_input *in = calloc(n, sizeof *in);
    if (!in) return 1;
    for (size_t i = 0; i < n; i++) {
        const char *a = argv[4 + i];
        if (!strncmp(a, "missing:", 8)) {
            char *name = strdup(a + 8), *c = name ? strrchr(name, ':') : NULL;
            if (!c) return usage();
            *c = 0;
            in[i].name = name;
            in[i].len = strtoul(c + 1, NULL, 10);
            in[i].missing = 1;
        } else {
            const char *base = strrchr(a, '/');
            in[i].name = base ? base + 1 : a;
            in[i].bytes = slurp(a, &in[i].len);
            if (!in[i].bytes) {
                fprintf(stderr, "%s: unreadable, empty or over %u bytes\n", a, CK_ART_MAX_BYTES);
                return 1;
            }
        }
    }
    image im;
    if (img_open(&im, argv[2], argv[3])) return 1;
    ss_keys keys;
    ck_store_report r;
    ck_store_test_keys(&keys);
    int rc = store_boot_run(&im.d, &keys, ck_store_test_uuid, "ck_store_image", &r);
    memset(&keys, 0, sizeof keys);
    if (rc || !r.formatted) {
        fprintf(stderr, "%s: %s (the image must be blank: all zero)\n", argv[2],
                rc ? "Store format/commit failed" : "not blank");
        disk_file_close(&im.f);
        return 1;
    }
    rc = ck_art_write(store_boot_store(), in, n);
    if (!rc) rc = disk_flush(&im.d);
    uint64_t gen = ss_generation(store_boot_store());
    disk_file_close(&im.f);
    if (rc) {
        fprintf(stderr, "artifact write failed: rc=%d\n", rc);
        return 1;
    }
    printf("ck_store_image: %s artifacts=%zu store_generation=%llu (TEST identity, TEST keys)\n", argv[2], n,
           (unsigned long long)gen);
    return 0;
}

static int cmd_list(int argc, char **argv)
{
    if (argc != 4) return usage();
    image im;
    if (img_open(&im, argv[2], argv[3])) return 1;
    ss_workspace *ws = calloc(1, sizeof *ws);
    ss_store *s = calloc(1, sizeof *s);
    ck_art_set *set = calloc(1, sizeof *set);
    int rc = !ws || !s || !set ? -1 : img_mount(&im, s, ws);
    const char *why = "";
    if (!rc) rc = ck_art_collect(s, set, &why);
    if (!rc && !set->found) printf("no artifact index\n");
    if (!rc && set->found) {
        printf("index generation=%llu entries=%u sha256=", (unsigned long long)set->index_generation, set->count);
        hex(set->index_sha256, 32);
        printf("\n");
        for (uint32_t i = 0; i < set->count; i++) {
            const ck_art_entry *a = &set->e[i];
            printf("%s bytes=%u ", a->name, a->len);
            if (a->state == CK_ART_OK) {
                printf("sha256=");
                hex(a->sha256, 32);
                printf("\n");
            } else {
                printf("%s\n", a->state == CK_ART_TOO_LARGE ? "too-large" : a->state == CK_ART_MISMATCH ? "mismatch" : "missing");
            }
        }
    }
    if (rc) fprintf(stderr, "list failed: rc=%d %s\n", rc, why);
    if (set) ck_art_set_free(set);
    free(set);
    free(s);
    free(ws);
    disk_file_close(&im.f);
    return rc ? 1 : 0;
}

static int cmd_locate(int argc, char **argv)
{
    if (argc != 5) return usage();
    image im;
    if (img_open(&im, argv[2], argv[3])) return 1;
    ss_workspace *ws = calloc(1, sizeof *ws);
    ss_store *s = calloc(1, sizeof *s);
    uint8_t *buf = malloc(SS_MAX_PLAINTEXT);
    int rc = !ws || !s || !buf ? -1 : img_mount(&im, s, ws), found = 0;
    size_t nl = strlen(argv[4]);
    if (nl == 0 || nl > CK_ART_NAME_MAX) {
        fprintf(stderr, "name must be 1..%u bytes\n", CK_ART_NAME_MAX);
        free(buf);
        free(s);
        free(ws);
        disk_file_close(&im.f);
        return 1;
    }
    for (uint32_t k = 0; !rc && !found && k < s->nclaims; k++) {
        if (ws->claims[k].c.obj.object_kind != CK_ART_CHUNK_KIND) continue;
        uint8_t sid[32];
        size_t len = 0;
        uint16_t kind = 0;
        memcpy(sid, ws->claims[k].sid, 32);
        if (ss_read(s, sid, buf, SS_MAX_PLAINTEXT, &len, &kind) || len < CK_ART_CHUNK_HDR) continue;
        if (buf[16] || buf[17] || buf[20] != nl || memcmp(buf + 24, argv[4], nl)) continue; /* chunk 0 of NAME */
        const st_store *st = &s->st;
        for (uint32_t i = 0; i < st->root.n; i++) {
            const sv1_entry *e = &st->ws->cat[st->root.cat_index][i];
            if (memcmp(e->object_id, sid, 32)) continue;
            printf("offset=%llu length=%llu\n",
                   (unsigned long long)(im.base_lba * im.d.block_size + e->first_unit * CK_LAYOUT_UNIT),
                   (unsigned long long)e->byte_length);
            found = 1;
            break;
        }
    }
    if (!rc && !found) fprintf(stderr, "%s: no chunk 0 on disk\n", argv[4]);
    free(buf);
    free(s);
    free(ws);
    disk_file_close(&im.f);
    return !rc && found ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc < 2) return usage();
    if (!strcmp(argv[1], "build")) return cmd_build(argc, argv);
    if (!strcmp(argv[1], "list")) return cmd_list(argc, argv);
    if (!strcmp(argv[1], "locate")) return cmd_locate(argc, argv);
    return usage();
}
