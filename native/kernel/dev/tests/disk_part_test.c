/* disk_part_test.c -- host tests for the GPT parser and the LBA translation
 * layer (dev/disk_part.c), hostile inputs included, plus a whole sealed-Store
 * boot on the AIENOS partition view proving nothing outside the partition
 * changes. Hosted test code only.
 *
 * Built twice by stage.mk (make disk-part-test): normally (must PASS) and
 * with -DCK_TEST_DISK_XLATE_BYPASS (the translation-layer bypass mutation,
 * which must FAIL these checks). */
#include <fcntl.h>
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
#define CHECK(c)                                                                 \
    do {                                                                         \
        checks++;                                                                \
        if (!(c)) {                                                              \
            failures++;                                                          \
            printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c);                \
        }                                                                        \
    } while (0)

static char g_path[256];
#define MIB 64u

static void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static void put64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }

/* Standard layout of tools/ck_gpt_image.c "aienos-middle" (MiB units). */
static int make_image(uint32_t bs, const uint8_t *mid_type, const uint8_t *b_type, uint64_t mid_first_mib,
                      uint64_t mid_end_mib, int nparts, unsigned flags, uint64_t *first, uint64_t *last)
{
    uint64_t per = (1024u * 1024u) / bs;
    gw_part p[3] = {
        {gw_linux_type, 1 * per, 9 * per - 1u, "sentinel-a", 0xa5},
        {mid_type, mid_first_mib * per, mid_end_mib * per - 1u, "AIENOS", 0},
        {b_type, (MIB - 7u) * per, (MIB - 1u) * per - 1u, "sentinel-b", 0x5a},
    };
    if (first) *first = p[1].first;
    if (last) *last = p[1].last;
    return gw_write(g_path, bs, MIB * per, p, nparts, flags);
}
static int good_image(uint32_t bs, uint64_t *first, uint64_t *last)
{
    return make_image(bs, ck_aienos_part_type, gw_linux_type, 9, MIB - 7u, 3, 0, first, last);
}

static int find(uint32_t bs, ck_part *p, disk_file *f, disk_dev *d)
{
    ck_gpt_info gi;
    if (disk_file_open(f, d, g_path, bs, 0, 0)) return 9999;
    return ck_gpt_find_aienos(d, p, &gi);
}
static int find_rc(uint32_t bs)
{
    static ck_part p;
    disk_file f;
    disk_dev d;
    int rc = find(bs, &p, &f, &d);
    if (rc != 9999) disk_file_close(&f);
    return rc;
}

static uint8_t *slurp(size_t *len)
{
    FILE *fp = fopen(g_path, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t *b = malloc((size_t)n);
    if (b && fread(b, 1, (size_t)n, fp) != (size_t)n) {
        free(b);
        b = NULL;
    }
    fclose(fp);
    *len = (size_t)n;
    return b;
}

/* Rewrite one GPT header in place (field patch) and fix its CRC32. */
static void patch_header(uint32_t bs, uint64_t lba, size_t off, uint64_t v, int width)
{
    int fd = open(g_path, O_RDWR);
    uint8_t h[4096];
    if (fd < 0 || pread(fd, h, bs, (off_t)(lba * bs)) != (ssize_t)bs) {
        CHECK(!"patch_header read");
        if (fd >= 0) close(fd);
        return;
    }
    if (width == 4) put32(h + off, (uint32_t)v); else put64(h + off, v);
    uint32_t hs = h[12] | (uint32_t)h[13] << 8;
    if (hs > bs) hs = 92;
    put32(h + 16, 0);
    put32(h + 16, ck_crc32(0, h, hs));
    CHECK(pwrite(fd, h, bs, (off_t)(lba * bs)) == (ssize_t)bs);
    close(fd);
}

/* Crafted GPT with num entries of esize bytes; `used` consecutive 8-block
 * Linux partitions starting at first_usable; the last one is AIENOS. */
static void craft(uint32_t bs, uint64_t blocks, uint32_t num, uint32_t esize, uint32_t used)
{
    uint64_t eb = ((uint64_t)num * esize + bs - 1u) / bs, last = blocks - 1u;
    uint64_t fu = 2u + eb, lu = last - 1u - eb;
    uint8_t *ent = calloc(eb, bs), *h = calloc(1, bs), *m = calloc(1, bs);
    for (uint32_t i = 0; i < used && i < num; i++) {
        uint8_t *e = ent + (size_t)i * esize;
        memcpy(e, i + 1 == used ? ck_aienos_part_type : gw_linux_type, 16);
        e[16] = (uint8_t)(i + 1);
        put64(e + 32, fu + 8u * i);
        put64(e + 40, fu + 8u * i + 7u);
    }
    uint32_t ec = ck_crc32(0, ent, (size_t)num * esize);
    int fd = open(g_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    CHECK(fd >= 0 && ftruncate(fd, (off_t)(blocks * bs)) == 0);
    m[446 + 4] = 0xee;
    put32(m + 446 + 8, 1);
    m[510] = 0x55;
    m[511] = 0xaa;
    CHECK(pwrite(fd, m, bs, 0) == (ssize_t)bs);
    for (int k = 0; k < 2; k++) {
        uint64_t my = k ? last : 1, alt = k ? 1 : last, el = k ? last - eb : 2;
        memset(h, 0, bs);
        memcpy(h, "EFI PART", 8);
        put32(h + 8, 0x00010000u);
        put32(h + 12, 92);
        put64(h + 24, my);
        put64(h + 32, alt);
        put64(h + 40, fu);
        put64(h + 48, lu);
        memcpy(h + 56, "CRAFTED-DISKGUID", 16);
        put64(h + 72, el);
        put32(h + 80, num);
        put32(h + 84, esize);
        put32(h + 88, ec);
        put32(h + 16, ck_crc32(0, h, 92));
        CHECK(pwrite(fd, h, bs, (off_t)(my * bs)) == (ssize_t)bs);
        CHECK(pwrite(fd, ent, (size_t)(eb * bs), (off_t)(el * bs)) == (ssize_t)(eb * bs));
    }
    close(fd);
    free(ent);
    free(h);
    free(m);
}

static void test_crc32(void)
{
    CHECK(ck_crc32(0, (const uint8_t *)"123456789", 9) == 0xcbf43926u); /* standard check value */
    uint32_t c = ck_crc32(0, (const uint8_t *)"1234", 4);
    CHECK(ck_crc32(c, (const uint8_t *)"56789", 5) == 0xcbf43926u); /* chaining */
}

static void test_good_and_xlate(uint32_t bs)
{
    uint64_t f0 = 0, l0 = 0;
    CHECK(good_image(bs, &f0, &l0) == 0);
    static ck_part p;
    disk_file f;
    disk_dev d;
    CHECK(find(bs, &p, &f, &d) == CK_GPT_OK);
    CHECK(p.valid == 1 && p.first_lba == f0 && p.blocks == l0 - f0 + 1u);
    CHECK(p.dev.block_count == p.blocks && p.dev.block_size == bs && p.dev.ctx == &p);
    uint64_t a = 0;
    CHECK(ck_part_xlate(&p, 0, 1, &a) == DISK_OK && a == f0);
    CHECK(ck_part_xlate(&p, p.blocks - 1u, 1, &a) == DISK_OK && a == l0);
    CHECK(ck_part_xlate(&p, p.blocks, 1, &a) == DISK_ERANGE);
    CHECK(ck_part_xlate(&p, p.blocks - 1u, 2, &a) == DISK_ERANGE);
    CHECK(ck_part_xlate(&p, ~(uint64_t)0, 1, &a) == DISK_ERANGE);
    CHECK(ck_part_xlate(&p, ~(uint64_t)0 - p.first_lba + 1u, 1, &a) == DISK_ERANGE); /* offset wrap */
    CHECK(ck_part_xlate(&p, 0, 0, &a) == DISK_EARG);
    ck_part bad = p;
    bad.valid = 0;
    CHECK(ck_part_xlate(&bad, 0, 1, &a) == DISK_ESTATE);

    /* Real writes through the view: first and last partition block land at
     * the partition's absolute first/last LBA; past the end is refused both
     * by disk.c and by the translation layer itself (backend callback called
     * directly); nothing outside [f0, l0] changes. */
    size_t n0 = 0, n1 = 0;
    disk_file_close(&f);
    uint8_t *before = slurp(&n0);
    CHECK(find(bs, &p, &f, &d) == CK_GPT_OK);
    uint8_t *blk = malloc(bs);
    memset(blk, 0xc3, bs);
    CHECK(disk_write(&p.dev, 0, 1, blk) == DISK_OK);
    CHECK(disk_write(&p.dev, p.blocks - 1u, 1, blk) == DISK_OK);
    CHECK(disk_write(&p.dev, p.blocks, 1, blk) == DISK_ERANGE);
    CHECK(p.dev.write(p.dev.ctx, p.blocks, 1, blk) == DISK_ERANGE);
    CHECK(p.dev.write(p.dev.ctx, p.blocks - 1u, 2, blk) == DISK_ERANGE);
    CHECK(p.dev.read(p.dev.ctx, p.blocks, 1, blk) == DISK_ERANGE);
    CHECK(disk_flush(&p.dev) == DISK_OK);
    disk_file_close(&f);
    uint8_t *after = slurp(&n1);
    CHECK(before && after && n0 == n1);
    if (before && after && n0 == n1) {
        CHECK(memcmp(before, after, (size_t)(f0 * bs)) == 0);                     /* MBR, primary GPT, sentinel-a */
        CHECK(memcmp(before + (l0 + 1u) * bs, after + (l0 + 1u) * bs, n0 - (size_t)((l0 + 1u) * bs)) == 0); /* sentinel-b, backup */
        CHECK(after[f0 * bs] == 0xc3 && after[l0 * bs] == 0xc3);
    }
    free(before);
    free(after);
    free(blk);
    /* The image still parses after the writes (GPT untouched). */
    CHECK(find_rc(bs) == CK_GPT_OK);
}

/* A whole sealed-Store boot (format + two commits) on the AIENOS partition
 * view: the GPT, both sentinels and the backup stay byte-identical. */
static void test_store_on_partition(uint32_t bs)
{
    uint64_t f0 = 0, l0 = 0;
    CHECK(good_image(bs, &f0, &l0) == 0);
    size_t n0 = 0, n1 = 0;
    uint8_t *before = slurp(&n0);
    static ck_part p;
    disk_file f;
    disk_dev d;
    CHECK(find(bs, &p, &f, &d) == CK_GPT_OK);
    ss_keys k;
    ck_store_report r;
    ck_store_test_keys(&k);
    ck_host_quiet = 1;
    int rc1 = store_boot_run(&p.dev, &k, ck_store_test_uuid, "disk-part-test", &r);
    int fm = r.formatted;
    int rc2 = store_boot_run(&p.dev, &k, ck_store_test_uuid, "disk-part-test", &r);
    ck_host_quiet = 0;
    CHECK(rc1 == 0 && fm == 1);
    CHECK(rc2 == 0 && r.boot_count_new == 2 && r.anchor_lba == 0);
    CHECK(r.store_units == p.blocks / (CK_LAYOUT_UNIT / bs) - CK_LAYOUT_ANCHOR_UNITS - CK_LAYOUT_PROBE_UNITS);
    disk_file_close(&f);
    uint8_t *after = slurp(&n1);
    CHECK(before && after && n0 == n1);
    if (before && after && n0 == n1) {
        CHECK(memcmp(before, after, (size_t)(f0 * bs)) == 0);
        CHECK(memcmp(before + (l0 + 1u) * bs, after + (l0 + 1u) * bs, n0 - (size_t)((l0 + 1u) * bs)) == 0);
        CHECK(memcmp(before + f0 * bs, after + f0 * bs, (size_t)((l0 - f0 + 1u) * bs)) != 0); /* the Store wrote inside */
    }
    free(before);
    free(after);
    memset(&k, 0, sizeof k);
    CHECK(find_rc(bs) == CK_GPT_OK);
}

static void test_hostile(uint32_t bs)
{
    uint64_t per = (1024u * 1024u) / bs, blocks = MIB * per, last = blocks - 1u;
    /* No GPT at all (sentinel data only), and a GPT without a protective MBR. */
    CHECK(make_image(bs, ck_aienos_part_type, gw_linux_type, 9, MIB - 7u, 3, GW_NO_GPT, 0, 0) == 0);
    CHECK(find_rc(bs) == CK_GPT_ENOMBR);
    CHECK(make_image(bs, ck_aienos_part_type, gw_linux_type, 9, MIB - 7u, 3, GW_NO_PMBR, 0, 0) == 0);
    CHECK(find_rc(bs) == CK_GPT_ENOMBR);
    /* CRC32: primary header (valid backup present: still refused, no fallback). */
    CHECK(make_image(bs, ck_aienos_part_type, gw_linux_type, 9, MIB - 7u, 3, GW_BAD_PRIMARY_CRC, 0, 0) == 0);
    CHECK(find_rc(bs) == CK_GPT_EHDR_CRC);
    CHECK(make_image(bs, ck_aienos_part_type, gw_linux_type, 9, MIB - 7u, 3, GW_BAD_PRIMARY_CRC | GW_BAD_BACKUP_CRC, 0, 0) == 0);
    CHECK(find_rc(bs) == CK_GPT_EHDR_CRC);
    CHECK(make_image(bs, ck_aienos_part_type, gw_linux_type, 9, MIB - 7u, 3, GW_BAD_PRIMARY_ENT, 0, 0) == 0);
    CHECK(find_rc(bs) == CK_GPT_EENT_CRC);
    CHECK(make_image(bs, ck_aienos_part_type, gw_linux_type, 9, MIB - 7u, 3, GW_BAD_PRIMARY_ENT | GW_BAD_BACKUP_ENT, 0, 0) == 0);
    CHECK(find_rc(bs) == CK_GPT_EENT_CRC);
    CHECK(make_image(bs, ck_aienos_part_type, gw_linux_type, 9, MIB - 7u, 3, GW_BAD_BACKUP_CRC, 0, 0) == 0);
    CHECK(find_rc(bs) == CK_GPT_EBACKUP);
    CHECK(make_image(bs, ck_aienos_part_type, gw_linux_type, 9, MIB - 7u, 3, GW_BAD_BACKUP_ENT, 0, 0) == 0);
    CHECK(find_rc(bs) == CK_GPT_EBACKUP);
    /* Partition table semantics. */
    CHECK(make_image(bs, gw_linux_type, gw_linux_type, 9, MIB - 7u, 3, 0, 0, 0) == 0);
    CHECK(find_rc(bs) == CK_GPT_ENOPART);
    CHECK(make_image(bs, ck_aienos_part_type, ck_aienos_part_type, 9, MIB - 7u, 3, 0, 0, 0) == 0);
    CHECK(find_rc(bs) == CK_GPT_EMULTI);
    CHECK(make_image(bs, ck_aienos_part_type, gw_linux_type, 9, MIB + 1u, 2, 0, 0, 0) == 0); /* ends past the disk */
    CHECK(find_rc(bs) == CK_GPT_EOUTSIDE);
    CHECK(make_image(bs, ck_aienos_part_type, gw_linux_type, 0, MIB - 7u, 2, 0, 0, 0) == 0); /* starts on the GPT */
    CHECK(find_rc(bs) == CK_GPT_EOUTSIDE);
    CHECK(make_image(bs, ck_aienos_part_type, gw_linux_type, 5, MIB - 7u, 3, 0, 0, 0) == 0); /* overlaps sentinel-a */
    CHECK(find_rc(bs) == CK_GPT_EOVERLAP);

    /* Header field attacks on an otherwise good image (CRC re-computed). */
    struct { size_t off; uint64_t v; int w; int want; } hp[] = {
        {80, 0xffffffffu, 4, CK_GPT_EENT},           /* entry count overflow */
        {80, 0, 4, CK_GPT_EENT},                     /* no entries */
        {84, 0x80000000u, 4, CK_GPT_EENT},           /* entry size overflow */
        {84, 64, 4, CK_GPT_EENT},                    /* entry size below 128 */
        {84, 136, 4, CK_GPT_EENT},                   /* entry size not 128 x 2^n */
        {24, 2, 8, CK_GPT_EHDR},                     /* MyLBA not 1 */
        {32, 7, 8, CK_GPT_EHDR},                     /* AlternateLBA not the last LBA */
        {72, ~(uint64_t)0, 8, CK_GPT_EHDR},          /* entry LBA overflow */
        {72, 1, 8, CK_GPT_EHDR},                     /* entries on the header */
        {40, 3, 8, CK_GPT_EHDR},                     /* first usable inside the entry array */
        {48, ~(uint64_t)0, 8, CK_GPT_EHDR},          /* last usable past the disk */
        {12, 8192, 4, CK_GPT_ESIG},                  /* header size larger than a block */
        {12, 91, 4, CK_GPT_ESIG},                    /* header size below 92 */
        {8, 0x00020000u, 4, CK_GPT_ESIG},            /* unknown revision */
    };
    for (size_t i = 0; i < sizeof hp / sizeof hp[0]; i++) {
        CHECK(good_image(bs, 0, 0) == 0);
        patch_header(bs, 1, hp[i].off, hp[i].v, hp[i].w);
        int rc = find_rc(bs);
        if (rc != hp[i].want) printf("  header patch %zu: rc=%d want %d\n", i, rc, hp[i].want);
        CHECK(rc == hp[i].want);
    }
    /* Backup header disagreeing with the primary (both CRCs valid). */
    CHECK(good_image(bs, 0, 0) == 0);
    patch_header(bs, last, 48, 100u, 8);
    CHECK(find_rc(bs) == CK_GPT_EBACKUP);
    /* Disk grown after partitioning: the backup is no longer at the last LBA. */
    CHECK(good_image(bs, 0, 0) == 0);
    CHECK(truncate(g_path, (off_t)((blocks + per) * bs)) == 0);
    CHECK(find_rc(bs) == CK_GPT_EHDR);
    /* Disk too small for any GPT. */
    CHECK(truncate(g_path, (off_t)(4u * bs)) == 0);
    CHECK(find_rc(bs) == CK_GPT_EGEOM);

    /* Crafted tables (CRCs valid): 256 entries of 128 bytes with 129 used is
     * over the used-entry bound; 256 x 128 with 3 used and 128 x 256 with 2
     * used are accepted. */
    craft(bs, blocks, 256, 128, 129);
    CHECK(find_rc(bs) == CK_GPT_ETOOMANY);
    craft(bs, blocks, 256, 128, 3);
    CHECK(find_rc(bs) == CK_GPT_OK);
    craft(bs, blocks, 128, 256, 2);
    CHECK(find_rc(bs) == CK_GPT_OK);
    /* A 1024 x 512-byte entry array (512 KiB) overruns the first usable LBA. */
    CHECK(good_image(bs, 0, 0) == 0);
    patch_header(bs, 1, 80, 1024, 4);
    patch_header(bs, 1, 84, 512, 4);
    CHECK(find_rc(bs) == CK_GPT_EHDR);
}

int main(void)
{
    snprintf(g_path, sizeof g_path, "/tmp/aienos-disk-part-test-%d.img", (int)getpid());
#ifdef CK_TEST_DISK_XLATE_BYPASS
    printf("disk_part_test: TEST-ONLY translation bypass mutation build (these checks must FAIL)\n");
#endif
    test_crc32();
    for (uint32_t bs = 512; bs <= 4096; bs *= 8) {
        test_good_and_xlate(bs);
        test_store_on_partition(bs);
        test_hostile(bs);
    }
    unlink(g_path);
    printf("disk_part_test: %d checks, %d failures\n", checks, failures);
    printf("CK_DISK_PART_HOST: %s\n", failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
