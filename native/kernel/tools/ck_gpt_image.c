/* ck_gpt_image -- host tool: GPT boot-disk images for the C kernel's QEMU
 * gates (scripts/qemu_ck_store_test.sh, qemu_ck_net_test.sh,
 * qemu_ck_artifact_test.sh, qemu_ck_disk_layout_test.sh). Hosted C, test
 * tooling only, never part of an image. No Python, no sgdisk.
 *
 *   ck_gpt_image create IMG BS MIB LAYOUT [CORRUPTION...]
 *       BS 512|4096, MIB >= 16. LAYOUT (MiB offsets, M = MIB):
 *         aienos-middle   sentinel-a [1,9) Linux type, filled with a pattern;
 *                         AIENOS [9,M-7) all zero; sentinel-b [M-7,M-1) filled
 *         no-aienos       same, middle partition has the Linux type
 *         two-aienos      same, sentinel-b also has the AIENOS type
 *         aienos-outside  sentinel-a, AIENOS [9, M+1): ends past the disk
 *         aienos-overlap  sentinel-a [1,9), AIENOS [5,M-7), sentinel-b
 *         no-gpt          sentinel fills only: no protective MBR, no GPT
 *         esp-model ESP_MIB MODEL_FILE   ESP + model in 3 out-of-order
 *                         extents (see esp_model below; model ingest gate)
 *       CORRUPTION: bad-primary-crc bad-backup-crc bad-primary-entries
 *         bad-backup-entries no-pmbr
 *       Prints one line: "gpt_image bs=B blocks=N aienos_first_lba=F
 *       aienos_last_lba=L" (the AIENOS range as WRITTEN, from this tool's own
 *       layout, not from the kernel parser; 0 0 when the layout has none).
 *   ck_gpt_image find IMG BS
 *       Runs the kernel's own parser (dev/disk_part.c) read-only; prints
 *       "aienos first_lba=F last_lba=L blocks=K" (exit 0) or
 *       "refused: <reason> rc=N" (exit 1). */
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "disk_file.h"
#include "disk_part.h"
#include "gpt_write.h"

static int usage(void)
{
    fprintf(stderr, "usage: ck_gpt_image create IMG BS MIB LAYOUT [CORRUPTION...] | find IMG BS\n");
    return 2;
}

/* esp-model (model ingest gate, scripts/qemu_ck_infer_test.sh --disk):
 *   ck_gpt_image create IMG BS MIB esp-model ESP_MIB MODEL_FILE
 * p0 = EFI System Partition [1, 1+ESP_MIB) MiB, left zero (the script formats
 * it with mkfs.vfat --offset and fills it with mtools); p1 = Linux type
 * [1+ESP_MIB, MIB-1) MiB holding MODEL_FILE in THREE extents written OUT OF
 * FILE ORDER with 1 MiB gaps (disk order C, A, B for file thirds A, B, C), so a
 * reader that ignores the map order or the gaps cannot produce the right
 * bytes. Prints: "gpt_image bs=B blocks=N esp_first_lba=F esp_last_lba=L
 * model_len=M model_extents=LBA:COUNT,LBA:COUNT,LBA:COUNT" (file order). */
static int esp_model(int argc, char **argv, uint32_t bs, uint64_t blocks, uint64_t per, unsigned flags)
{
    if (argc != 8) return usage();
    uint64_t esp_mib = strtoull(argv[6], NULL, 10);
    const char *mpath = argv[7];
    uint64_t mib = blocks / per;
    if (esp_mib < 16 || esp_mib + 4 >= mib) return usage();
    FILE *mf = fopen(mpath, "rb");
    if (!mf) { fprintf(stderr, "cannot open %s\n", mpath); return 1; }
    fseeko(mf, 0, SEEK_END);
    uint64_t mlen = (uint64_t)ftello(mf);
    fseeko(mf, 0, SEEK_SET);
    uint64_t sectors = (mlen + bs - 1) / bs, gap = (1u << 20) / bs;
    uint64_t a = sectors / 3, b = sectors / 3, c = sectors - a - b;
    uint64_t p1_first = (1 + esp_mib) * per, p1_last = (mib - 1u) * per - 1u;
    if (p1_first + 3 * gap + sectors > p1_last + 1) {
        fprintf(stderr, "image too small for the model: need %llu more MiB\n",
                (unsigned long long)((p1_first + 3 * gap + sectors - p1_last) / per + 1));
        fclose(mf);
        return 1;
    }
    /* disk order: C, A, B */
    uint64_t lba_c = p1_first + gap, lba_a = lba_c + c + gap, lba_b = lba_a + a + gap;
    gw_part p[2];
    p[0] = (gw_part){gw_esp_type, 1 * per, (1 + esp_mib) * per - 1u, "ESP", 0};
    p[1] = (gw_part){gw_linux_type, p1_first, p1_last, "model-home", 0};
    if (gw_write(argv[2], bs, blocks, p, 2, flags)) { fclose(mf); return 1; }
    int fd = open(argv[2], O_WRONLY);
    if (fd < 0) { fclose(mf); fprintf(stderr, "cannot reopen %s\n", argv[2]); return 1; }
    struct { uint64_t lba, count; } ext[3] = {{lba_a, a}, {lba_b, b}, {lba_c, c}};
    static uint8_t buf[1u << 20];
    int rc = 0;
    for (int i = 0; i < 3 && !rc; i++) {
        uint64_t left = ext[i].count * bs, off = ext[i].lba * bs;
        while (left && !rc) {
            size_t want = left < sizeof buf ? (size_t)left : sizeof buf;
            memset(buf, 0, want);
            size_t got = fread(buf, 1, want, mf); /* short only on the final partial sector */
            if (got == 0) { rc = 1; break; }
            if (pwrite(fd, buf, want, (off_t)off) != (ssize_t)want) rc = 1;
            left -= want;
            off += want;
        }
    }
    close(fd);
    fclose(mf);
    if (rc) { fprintf(stderr, "model write failed\n"); return 1; }
    printf("gpt_image bs=%u blocks=%llu esp_first_lba=%llu esp_last_lba=%llu model_len=%llu "
           "model_extents=%llu:%llu,%llu:%llu,%llu:%llu\n",
           bs, (unsigned long long)blocks, (unsigned long long)p[0].first, (unsigned long long)p[0].last,
           (unsigned long long)mlen, (unsigned long long)lba_a, (unsigned long long)a,
           (unsigned long long)lba_b, (unsigned long long)b, (unsigned long long)lba_c, (unsigned long long)c);
    return 0;
}

static int cmd_create(int argc, char **argv)
{
    if (argc < 6) return usage();
    uint32_t bs = (uint32_t)strtoul(argv[3], NULL, 10);
    uint64_t mib = strtoull(argv[4], NULL, 10);
    if ((bs != 512 && bs != 4096) || mib < 16 || mib > 1048576) return usage();
    uint64_t per = (1024u * 1024u) / bs, blocks = mib * per;
    const char *lay = argv[5];
    unsigned flags = 0;
    if (!strcmp(lay, "esp-model")) return esp_model(argc, argv, bs, blocks, per, flags);
    for (int i = 6; i < argc; i++) {
        if (!strcmp(argv[i], "bad-primary-crc")) flags |= GW_BAD_PRIMARY_CRC;
        else if (!strcmp(argv[i], "bad-backup-crc")) flags |= GW_BAD_BACKUP_CRC;
        else if (!strcmp(argv[i], "bad-primary-entries")) flags |= GW_BAD_PRIMARY_ENT;
        else if (!strcmp(argv[i], "bad-backup-entries")) flags |= GW_BAD_BACKUP_ENT;
        else if (!strcmp(argv[i], "no-pmbr")) flags |= GW_NO_PMBR;
        else return usage();
    }
    gw_part p[3];
    int n = 3;
    p[0] = (gw_part){gw_linux_type, 1 * per, 9 * per - 1u, "sentinel-a", 0xa5};
    p[1] = (gw_part){ck_aienos_part_type, 9 * per, (mib - 7u) * per - 1u, "AIENOS", 0};
    p[2] = (gw_part){gw_linux_type, (mib - 7u) * per, (mib - 1u) * per - 1u, "sentinel-b", 0x5a};
    if (!strcmp(lay, "aienos-middle")) {
    } else if (!strcmp(lay, "no-aienos")) {
        p[1].type = gw_linux_type;
    } else if (!strcmp(lay, "two-aienos")) {
        p[2].type = ck_aienos_part_type;
    } else if (!strcmp(lay, "aienos-outside")) {
        p[1].last = (mib + 1u) * per - 1u;
        n = 2;
    } else if (!strcmp(lay, "aienos-overlap")) {
        p[1].first = 5 * per;
    } else if (!strcmp(lay, "no-gpt")) {
        flags |= GW_NO_GPT;
    } else {
        return usage();
    }
    if (gw_write(argv[2], bs, blocks, p, n, flags)) return 1;
    int has = strcmp(lay, "no-aienos") != 0;
    printf("gpt_image bs=%u blocks=%llu aienos_first_lba=%llu aienos_last_lba=%llu\n", bs,
           (unsigned long long)blocks, has ? (unsigned long long)p[1].first : 0ull,
           has ? (unsigned long long)p[1].last : 0ull);
    return 0;
}

static int cmd_find(int argc, char **argv)
{
    if (argc != 4) return usage();
    uint32_t bs = (uint32_t)strtoul(argv[3], NULL, 10);
    if (bs != 512 && bs != 4096) return usage();
    disk_file f;
    disk_dev d;
    if (disk_file_open(&f, &d, argv[2], bs, 0, 0)) {
        fprintf(stderr, "cannot open %s\n", argv[2]);
        return 2;
    }
    static ck_part p;
    ck_gpt_info gi;
    int rc = ck_gpt_find_aienos(&d, &p, &gi);
    if (rc)
        printf("refused: %s rc=%d\n", ck_gpt_strerror(rc), rc);
    else
        printf("aienos first_lba=%llu last_lba=%llu blocks=%llu\n", (unsigned long long)p.first_lba,
               (unsigned long long)(p.first_lba + p.blocks - 1u), (unsigned long long)p.blocks);
    disk_file_close(&f);
    return rc ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) return usage();
    if (!strcmp(argv[1], "create")) return cmd_create(argc, argv);
    if (!strcmp(argv[1], "find")) return cmd_find(argc, argv);
    return usage();
}
