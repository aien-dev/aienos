/* test_pi5_marker.c -- AIENOS-PI5 step 3: the Pi 5 card layout (ESP + AIENOS
 * partition under a protective MBR and a two-copy GPT) parsed by the kernel's
 * own dev/disk_part.c, and the scratch marker (core/pi5_marker.c) written
 * through the partition view with flush, "rebooted" (file closed and reopened,
 * nothing kept in memory) and verified. Hosted: a file stands in for the
 * card. This is NOT the SD controller, which QEMU cannot model; the controller
 * is proved on the hub Pi (pi5-run.sh) and its write path by native/disk/tests/sdhci_test.c. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ck_test.h"
#include "disk_file.h"
#include "disk_part.h"
#include "gpt_write.h"
#include "pi5_marker.h"

#define BLOCKS 262144ull /* 128 MiB stand-in for the 119 GiB card */

static const uint8_t esp_type_ok = 1;
static const char *img = "/tmp/ck_pi5_marker_test.img";
static uint8_t buf[CK_PI5_MARKER_BUF_BYTES] __attribute__((aligned(64)));

static void make_card(const uint8_t *aienos_type, unsigned flags)
{
    gw_part p[2] = {{gw_esp_type, 2048, 4095, "AIENOSPI5-ESP", 0}, {aienos_type, 8192, 16383, "AIENOS", 0}};
    (void)esp_type_ok;
    CHECK(gw_write(img, 512, BLOCKS, p, 2, flags) == 0);
}

static int open_view(disk_file *f, disk_dev *d, ck_part *part, ck_gpt_info *gi)
{
    if (disk_file_open(f, d, img, 512, BLOCKS, 0)) return -1;
    return ck_gpt_find_aienos(d, part, gi);
}

static int run(uint64_t *gen)
{
    disk_file f;
    disk_dev d;
    ck_part part;
    ck_gpt_info gi;
    int rc = open_view(&f, &d, &part, &gi);
    CHECK(rc == 0);
    if (rc) { disk_file_close(&f); return -999; }
    rc = ck_pi5_marker_run(&part.dev, buf, gen);
    disk_file_close(&f);
    return rc;
}

static uint8_t *slurp(size_t *n)
{
    FILE *fp = fopen(img, "rb");
    fseek(fp, 0, SEEK_END);
    *n = (size_t)ftell(fp);
    rewind(fp);
    uint8_t *m = malloc(*n);
    CHECK(fread(m, 1, *n, fp) == *n);
    fclose(fp);
    return m;
}

int main(void)
{
    const uint64_t first = 8192, last = 16383, region = last + 1 - CK_PI5_MARKER_SECS; /* absolute LBA of the marker */
    uint64_t gen = 0;
    size_t n1, n2;

    /* --- GPT as the Pi card has it --- */
    make_card(ck_aienos_part_type, 0);
    {
        disk_file f; disk_dev d; ck_part part; ck_gpt_info gi;
        CHECK(open_view(&f, &d, &part, &gi) == 0);
        CHECK(part.valid && part.first_lba == first && part.blocks == last - first + 1 && gi.used == 2);
        CHECK(part.dev.block_count == last - first + 1);
        uint64_t abs = 0;
        CHECK(ck_part_xlate(&part, 0, 1, &abs) == 0 && abs == first);
        CHECK(ck_part_xlate(&part, part.blocks - 1, 1, &abs) == 0 && abs == last);
        CHECK(ck_part_xlate(&part, part.blocks, 1, &abs) == DISK_ERANGE); /* one past the partition */
        CHECK(disk_write(&part.dev, part.blocks, 1, buf) == DISK_ERANGE);
        disk_file_close(&f);
    }
    /* hostile cards: nothing is presented and the marker refuses */
    {
        static const uint8_t other[16] = {1, 2, 3};
        const struct { const uint8_t *t; unsigned fl; } bad[] = {
            {other, 0}, {ck_aienos_part_type, GW_NO_PMBR}, {ck_aienos_part_type, GW_BAD_PRIMARY_CRC},
            {ck_aienos_part_type, GW_BAD_BACKUP_CRC}, {ck_aienos_part_type, GW_BAD_PRIMARY_ENT},
            {ck_aienos_part_type, GW_BAD_BACKUP_ENT}, {ck_aienos_part_type, GW_NO_GPT},
        };
        for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            make_card(bad[i].t, bad[i].fl);
            disk_file f; disk_dev d; ck_part part; ck_gpt_info gi;
            CHECK(open_view(&f, &d, &part, &gi) != 0);
            CHECK(!part.valid);
            CHECK(ck_pi5_marker_run(&part.dev, buf, &gen) == CK_PI5_MARKER_ESIZE);
            disk_file_close(&f);
        }
    }

    /* --- first boot: blank region is formatted --- */
    make_card(ck_aienos_part_type, 0);
    uint8_t *before = slurp(&n1);
    CHECK(run(&gen) == CK_PI5_MARKER_FORMATTED && gen == 1);
    uint8_t *after = slurp(&n2);
    CHECK(n1 == n2);
    size_t changed_outside = 0, changed_inside = 0;
    for (size_t i = 0; i < n1; i++)
        if (before[i] != after[i]) {
            if (i / 512 >= region && i / 512 <= last) changed_inside++; else changed_outside++;
        }
    CHECK(changed_inside > 0 && changed_outside == 0); /* every written byte is inside the marker region */
    /* --- reboot: reopen, same contents, generation moves --- */
    CHECK(run(&gen) == CK_PI5_MARKER_REOPENED && gen == 2);
    uint8_t *again = slurp(&n2);
    size_t diff_sectors = 0;
    for (size_t s = 0; s < n1 / 512; s++)
        if (memcmp(after + s * 512, again + s * 512, 512)) diff_sectors++;
    CHECK(diff_sectors == 1); /* only the header sector; the 63 payload sectors are identical */
    CHECK(run(&gen) == CK_PI5_MARKER_REOPENED && gen == 3);
    free(again);

    /* --- a flipped payload byte is caught and nothing is written --- */
    {
        FILE *fp = fopen(img, "r+b");
        fseek(fp, (long)((region + 7) * 512 + 100), SEEK_SET);
        int c = fgetc(fp);
        fseek(fp, -1, SEEK_CUR);
        fputc(c ^ 0x01, fp);
        fclose(fp);
        uint8_t *pre = slurp(&n1);
        CHECK(run(&gen) == CK_PI5_MARKER_ECORRUPT);
        uint8_t *post = slurp(&n2);
        CHECK(n1 == n2 && memcmp(pre, post, n1) == 0);
        free(pre); free(post);
    }

    /* --- foreign data in the region: refused, untouched --- */
    make_card(ck_aienos_part_type, 0);
    {
        FILE *fp = fopen(img, "r+b");
        fseek(fp, (long)((region + 3) * 512), SEEK_SET);
        fputs("someone else's data", fp);
        fclose(fp);
        uint8_t *pre = slurp(&n1);
        CHECK(run(&gen) == CK_PI5_MARKER_EREFUSED);
        uint8_t *post = slurp(&n2);
        CHECK(memcmp(pre, post, n1) == 0);
        free(pre); free(post);
    }

    /* --- power cut during the first format: header is written last, so a torn run is refused, never "reopened" --- */
    make_card(ck_aienos_part_type, 0);
    {
        disk_file f; disk_dev d; ck_part part; ck_gpt_info gi;
        CHECK(open_view(&f, &d, &part, &gi) == 0);
        disk_file_arm_cut(&f, 20); /* 20 of the 63 payload sectors reach the card */
        CHECK(ck_pi5_marker_run(&part.dev, buf, &gen) < 0);
        disk_file_close(&f);
        int rc = run(&gen);
        CHECK(rc == CK_PI5_MARKER_EREFUSED || rc == CK_PI5_MARKER_ECORRUPT);
    }
    free(before); free(after);
    unlink(img);
    return ck_t_verdict("test_pi5_marker");
}
