/* gpt_write.c -- hosted GPT image writer (see gpt_write.h). libc only. */
#define _GNU_SOURCE
#include "gpt_write.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "disk_part.h" /* ck_crc32 only */

const uint8_t gw_linux_type[16] = {0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47,
                                   0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4};
const uint8_t gw_esp_type[16] = {0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11,
                                 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b};

static void put32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static void put64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

uint64_t gw_entry_blocks(uint32_t bs)
{
    return ((uint64_t)GW_ENTRIES * GW_ESIZE + bs - 1u) / bs;
}

static int pw(int fd, const void *b, size_t n, uint64_t off)
{
    const uint8_t *p = b;
    while (n) {
        ssize_t w = pwrite(fd, p, n, (off_t)off);
        if (w <= 0) return -1;
        p += w;
        n -= (size_t)w;
        off += (uint64_t)w;
    }
    return 0;
}

static void header(uint8_t *h, uint64_t my, uint64_t alt, uint64_t fu, uint64_t lu, uint64_t ent_lba,
                   uint32_t ent_crc)
{
    static const uint8_t disk_guid[16] = {0x41, 0x49, 0x45, 0x4e, 0x2d, 0x47, 0x50, 0x54,
                                          0x2d, 0x54, 0x45, 0x53, 0x54, 0x2d, 0x30, 0x31}; /* "AIEN-GPT-TEST-01" */
    memcpy(h, "EFI PART", 8);
    put32(h + 8, 0x00010000u);
    put32(h + 12, 92);
    put32(h + 16, 0);
    put64(h + 24, my);
    put64(h + 32, alt);
    put64(h + 40, fu);
    put64(h + 48, lu);
    memcpy(h + 56, disk_guid, 16);
    put64(h + 72, ent_lba);
    put32(h + 80, GW_ENTRIES);
    put32(h + 84, GW_ESIZE);
    put32(h + 88, ent_crc);
    put32(h + 16, ck_crc32(0, h, 92));
}

int gw_write(const char *path, uint32_t bs, uint64_t blocks, const gw_part *parts, int nparts, unsigned flags)
{
    if ((bs != 512 && bs != 4096) || blocks < 64 || nparts < 0 || nparts > GW_MAX_PARTS) {
        fprintf(stderr, "gw_write: bad geometry\n");
        return -1;
    }
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0 || ftruncate(fd, (off_t)(blocks * bs)) != 0) {
        fprintf(stderr, "gw_write: cannot create %s\n", path);
        if (fd >= 0) close(fd);
        return -1;
    }
    int rc = 0;
    /* Partition fills (sentinels): fill ^ low byte of the LBA, so every block differs. */
    enum { CHUNK = 256 };
    uint8_t *buf = malloc((size_t)CHUNK * bs);
    if (!buf) rc = -1;
    for (int i = 0; !rc && i < nparts; i++) {
        if (!parts[i].fill) continue;
        uint64_t f = parts[i].first, l = parts[i].last < blocks ? parts[i].last : blocks - 1u;
        for (uint64_t lba = f; !rc && lba <= l;) {
            uint64_t n = l - lba + 1u < CHUNK ? l - lba + 1u : CHUNK;
            for (uint64_t k = 0; k < n; k++) memset(buf + k * bs, parts[i].fill ^ (uint8_t)(lba + k), bs);
            rc = pw(fd, buf, (size_t)(n * bs), lba * bs);
            lba += n;
        }
    }
    free(buf);
    if (rc || (flags & GW_NO_GPT)) {
        close(fd);
        if (rc) fprintf(stderr, "gw_write: write failed\n");
        return rc;
    }

    uint64_t last = blocks - 1u, eb = gw_entry_blocks(bs);
    uint64_t fu = 2u + eb, lu = last - 1u - eb, bent = last - eb;
    size_t ebytes = (size_t)GW_ENTRIES * GW_ESIZE;
    uint8_t *ent = calloc(1, (size_t)eb * bs);
    uint8_t *h = calloc(1, bs), *mbr = calloc(1, bs);
    if (!ent || !h || !mbr) rc = -1;
    for (int i = 0; !rc && i < nparts; i++) {
        uint8_t *e = ent + (size_t)i * GW_ESIZE;
        memcpy(e, parts[i].type, 16);
        memcpy(e + 16, "AIEN-UNIQUE-PT", 14); /* unique GUID: fixed text + index */
        e[30] = (uint8_t)'0';
        e[31] = (uint8_t)('0' + i);
        put64(e + 32, parts[i].first);
        put64(e + 40, parts[i].last);
        for (size_t c = 0; parts[i].name && parts[i].name[c] && c < 36; c++) e[56 + 2 * c] = (uint8_t)parts[i].name[c];
    }
    uint32_t ecrc = ck_crc32(0, ent, ebytes);
    if (!rc && !(flags & GW_NO_PMBR)) {
        uint8_t *r = mbr + 446;
        r[1] = 0x00; r[2] = 0x02; r[3] = 0x00; /* CHS start 0/0/2 */
        r[4] = 0xee;
        r[5] = 0xff; r[6] = 0xff; r[7] = 0xff;
        put32(r + 8, 1);
        put32(r + 12, last > 0xffffffffu ? 0xffffffffu : (uint32_t)last);
        mbr[510] = 0x55;
        mbr[511] = 0xaa;
        rc = pw(fd, mbr, bs, 0);
    }
    /* Primary. */
    if (!rc) {
        header(h, 1, last, fu, lu, 2, ecrc);
        if (flags & GW_BAD_PRIMARY_CRC) h[16] ^= 0x01;
        rc = pw(fd, h, bs, 1u * bs);
    }
    if (!rc) {
        if (flags & GW_BAD_PRIMARY_ENT) ent[56] ^= 0x20; /* first entry's name, after the CRC */
        rc = pw(fd, ent, (size_t)eb * bs, 2u * bs);
        if (flags & GW_BAD_PRIMARY_ENT) ent[56] ^= 0x20;
    }
    /* Backup. */
    if (!rc) {
        if (flags & GW_BAD_BACKUP_ENT) ent[56] ^= 0x20;
        rc = pw(fd, ent, (size_t)eb * bs, bent * bs);
        if (flags & GW_BAD_BACKUP_ENT) ent[56] ^= 0x20;
    }
    if (!rc) {
        memset(h, 0, bs);
        header(h, last, 1, fu, lu, bent, ecrc);
        if (flags & GW_BAD_BACKUP_CRC) h[16] ^= 0x01;
        rc = pw(fd, h, bs, last * bs);
    }
    if (rc) fprintf(stderr, "gw_write: write failed\n");
    free(ent);
    free(h);
    free(mbr);
    if (fsync(fd) != 0) rc = -1;
    close(fd);
    return rc;
}
