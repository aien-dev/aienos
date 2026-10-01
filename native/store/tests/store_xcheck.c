/*
 * store_xcheck.c -- small hosted CLI used by tests/rust_crosscheck.sh to hand
 * C-written Store images to the Rust aienos-store-tool and to classify images
 * the Rust tool has changed. Image I/O goes through native/disk disk_file.
 *
 *   store_xcheck mkimage IMG BS BASE_BLOCKS UNITS
 *       format + generation 2 (kinds 3, 7) + generation 3 (kind 9, and kind 3
 *       again, deduplicated)
 *   store_xcheck mkpair OLD NEW BS BASE_BLOCKS UNITS
 *       same as mkimage up to generation 2, then generation 3 into NEW while
 *       copying the image to OLD at the after_first_flush checkpoint (all
 *       payload/catalog/commit units durable, root not yet written)
 *   store_xcheck advance IMG BS BASE_BLOCKS UNITS
 *       one more generation (kind 11)
 *   store_xcheck classify IMG BS BASE_BLOCKS UNITS
 *       prints "MOUNT state=<..> peer=<..> gen=<n> objects_ok=<n>" or
 *       "REFUSE <MountError>"
 */
#include "store_test_util.h"
#include "disk_file.h"

static st_workspace ws;
static const uint8_t UUID[16] = {0xc0, 0x5e, 0x11, 0x0b, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};

static int open_img(const char *path, uint32_t bs, uint64_t base, uint64_t units, int create,
                    disk_file *f, disk_dev *d, st_disk *a, st_dev *sd)
{
    uint64_t bpu = SV1_UNIT / bs;
    if (disk_file_open(f, d, path, bs, base + units * bpu, create)) {
        fprintf(stderr, "cannot open %s\n", path);
        return -1;
    }
    if (st_disk_bind(a, d, base, units, sd)) {
        fprintf(stderr, "bind failed\n");
        return -1;
    }
    return 0;
}

static const char *copy_to;
static const char *copy_from;
static void copy_hook(void *arg, int cp)
{
    (void)arg;
    if (cp != ST_CP_AFTER_FIRST_FLUSH || !copy_to)
        return;
    FILE *in = fopen(copy_from, "rb"), *out = fopen(copy_to, "wb");
    char buf[65536];
    size_t n;
    while (in && out && (n = fread(buf, 1, sizeof buf, in)) > 0)
        fwrite(buf, 1, n, out);
    if (in)
        fclose(in);
    if (out)
        fclose(out);
}

static uint8_t p3[100], p7[5000], p9[9000];
static void payloads(void)
{
    for (size_t i = 0; i < sizeof p3; i++)
        p3[i] = (uint8_t)(i * 3 + 1);
    for (size_t i = 0; i < sizeof p7; i++)
        p7[i] = (uint8_t)(i * 7 + 2);
    for (size_t i = 0; i < sizeof p9; i++)
        p9[i] = (uint8_t)(i * 9 + 3);
}

static int build(const char *img, const char *old, uint32_t bs, uint64_t base, uint64_t units)
{
    disk_file f;
    disk_dev d;
    st_disk a;
    st_dev sd;
    st_store s;
    int r;
    if (open_img(img, bs, base, units, 1, &f, &d, &a, &sd))
        return 1;
    payloads();
    if ((r = st_format(&sd, UUID)) || (r = st_open(&s, &sd, &ws)))
        goto fail;
    st_object g2[2] = {{3, 1, p3, sizeof p3}, {7, 1, p7, sizeof p7}};
    if ((r = st_transact(&s, g2, 2, NULL, NULL)))
        goto fail;
    st_object g3[2] = {{9, 1, p9, sizeof p9}, {3, 1, p3, sizeof p3}};
    copy_to = old;
    copy_from = img;
    if ((r = st_transact(&s, g3, 2, copy_hook, NULL)))
        goto fail;
    disk_file_close(&f);
    printf("C image %s: generation %llu, active slot %u\n", img,
           (unsigned long long)st_generation(&s), st_active_slot(&s));
    return 0;
fail:
    fprintf(stderr, "build failed: %s\n", st_strerror(r));
    disk_file_close(&f);
    return 1;
}

static int classify(const char *img, uint32_t bs, uint64_t base, uint64_t units)
{
    disk_file f;
    disk_dev d;
    st_disk a;
    st_dev sd;
    st_store s;
    if (open_img(img, bs, base, units, 0, &f, &d, &a, &sd))
        return 1;
    int r = st_open(&s, &sd, &ws);
    if (r) {
        printf("REFUSE %s\n", st_strerror(r));
        disk_file_close(&f);
        return 0;
    }
    static const char *states[] = {"Valid", "DegradedRecovery"};
    static const char *peers[] = {"Zero", "Valid", "Malformed", "GraphBadNewer", "GraphBadOlder"};
    uint32_t n;
    const sv1_entry *e = st_catalog(&s, &n);
    static uint8_t buf[SV1_MAX_OBJECT_BYTES / 64];
    unsigned ok = 0;
    for (uint32_t i = 0; i < n; i++) {
        size_t len;
        if (e[i].byte_length <= sizeof buf && st_read_object(&s, e[i].object_id, buf, sizeof buf, &len) == 0)
            ok++;
    }
    printf("MOUNT state=%s peer=%s gen=%llu objects_ok=%u/%u\n", states[s.state], peers[s.peer],
           (unsigned long long)st_generation(&s), ok, n);
    disk_file_close(&f);
    return 0;
}

static int advance(const char *img, uint32_t bs, uint64_t base, uint64_t units)
{
    disk_file f;
    disk_dev d;
    st_disk a;
    st_dev sd;
    st_store s;
    static uint8_t p[300];
    for (size_t i = 0; i < sizeof p; i++)
        p[i] = (uint8_t)(i ^ 0x5c);
    if (open_img(img, bs, base, units, 0, &f, &d, &a, &sd))
        return 1;
    st_object o = {11, 1, p, sizeof p};
    int r = st_open(&s, &sd, &ws);
    if (!r)
        r = st_transact(&s, &o, 1, NULL, NULL);
    disk_file_close(&f);
    if (r) {
        fprintf(stderr, "advance failed: %s\n", st_strerror(r));
        return 1;
    }
    printf("C image %s: generation %llu, active slot %u\n", img,
           (unsigned long long)st_generation(&s), st_active_slot(&s));
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 6 && !strcmp(argv[1], "advance"))
        return advance(argv[2], (uint32_t)strtoul(argv[3], 0, 10), strtoull(argv[4], 0, 10),
                       strtoull(argv[5], 0, 10));
    if (argc == 6 && !strcmp(argv[1], "mkimage"))
        return build(argv[2], NULL, (uint32_t)strtoul(argv[3], 0, 10), strtoull(argv[4], 0, 10),
                     strtoull(argv[5], 0, 10));
    if (argc == 7 && !strcmp(argv[1], "mkpair"))
        return build(argv[3], argv[2], (uint32_t)strtoul(argv[4], 0, 10), strtoull(argv[5], 0, 10),
                     strtoull(argv[6], 0, 10));
    if (argc == 6 && !strcmp(argv[1], "classify"))
        return classify(argv[2], (uint32_t)strtoul(argv[3], 0, 10), strtoull(argv[4], 0, 10),
                        strtoull(argv[5], 0, 10));
    fprintf(stderr, "usage: store_xcheck mkimage|mkpair|classify ...\n");
    return 2;
}
