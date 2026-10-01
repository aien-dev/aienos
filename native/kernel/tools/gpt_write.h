/* gpt_write.h -- hosted GPT image writer for the C kernel's QEMU gates and
 * host tests (tools/ck_gpt_image.c, dev/tests/disk_part_test.c). Test
 * tooling only (libc), never part of an image. It writes the layout
 * independently of the kernel parser (dev/disk_part.c); only the CRC32
 * routine (ck_crc32) is shared, and the host test checks it against the
 * standard check value.
 *
 * Layout written: protective MBR (one 0xEE record), primary header at LBA 1,
 * 128 entries of 128 bytes from LBA 2, backup entries just below the last
 * LBA, backup header at the last LBA (UEFI 2.10, section 5.3). */
#ifndef AIENOS_CK_GPT_WRITE_H
#define AIENOS_CK_GPT_WRITE_H
#include <stdint.h>

#define GW_ENTRIES 128u
#define GW_ESIZE 128u
#define GW_MAX_PARTS 8

/* Linux filesystem data type GUID 0FC63DAF-8483-4772-8E79-3D69D8477DE4
 * (on-disk byte order): used for the sentinel partitions. */
extern const uint8_t gw_linux_type[16];

typedef struct {
    const uint8_t *type;  /* 16 on-disk bytes */
    uint64_t first, last; /* inclusive LBAs as written into the entry */
    const char *name;     /* ASCII, up to 36 characters */
    uint8_t fill;         /* 0: leave zero; else fill the range with fill ^ (uint8_t)lba */
} gw_part;

enum {
    GW_NO_GPT = 1u << 0,           /* write partition fills only: no MBR, no GPT */
    GW_BAD_PRIMARY_CRC = 1u << 1,  /* primary header CRC32 field flipped */
    GW_BAD_BACKUP_CRC = 1u << 2,   /* backup header CRC32 field flipped */
    GW_BAD_PRIMARY_ENT = 1u << 3,  /* primary entry array changed after its CRC */
    GW_BAD_BACKUP_ENT = 1u << 4,   /* backup entry array changed after its CRC */
    GW_NO_PMBR = 1u << 5,          /* GPT written, protective MBR left zero */
};

/* Create (or truncate) path as a bs-byte-block image of `blocks` blocks and
 * write the layout. Fills that fall outside the image are clipped. Returns 0
 * or -1 (message on stderr). */
int gw_write(const char *path, uint32_t bs, uint64_t blocks, const gw_part *parts, int nparts, unsigned flags);

/* Entry array blocks for block size bs (128 x 128 bytes). */
uint64_t gw_entry_blocks(uint32_t bs);
#endif
