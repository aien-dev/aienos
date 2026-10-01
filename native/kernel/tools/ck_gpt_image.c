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
 *       CORRUPTION: bad-primary-crc bad-backup-crc bad-primary-entries
 *         bad-backup-entries no-pmbr
 *       Prints one line: "gpt_image bs=B blocks=N aienos_first_lba=F
 *       aienos_last_lba=L" (the AIENOS range as WRITTEN, from this tool's own
 *       layout, not from the kernel parser; 0 0 when the layout has none).
 *   ck_gpt_image find IMG BS
 *       Runs the kernel's own parser (dev/disk_part.c) read-only; prints
 *       "aienos first_lba=F last_lba=L blocks=K" (exit 0) or
 *       "refused: <reason> rc=N" (exit 1). */
#include <stdio.h>
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

static int cmd_create(int argc, char **argv)
{
    if (argc < 6) return usage();
    uint32_t bs = (uint32_t)strtoul(argv[3], NULL, 10);
    uint64_t mib = strtoull(argv[4], NULL, 10);
    if ((bs != 512 && bs != 4096) || mib < 16 || mib > 1048576) return usage();
    uint64_t per = (1024u * 1024u) / bs, blocks = mib * per;
    const char *lay = argv[5];
    unsigned flags = 0;
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
