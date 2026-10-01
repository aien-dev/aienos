/* disk_part.h -- the AIENOS C kernel's partition-aware disk footprint.
 *
 * The kernel never writes a whole NVMe namespace. At bind time it parses the
 * disk's GUID Partition Table (UEFI 2.10, section 5.3) READ-ONLY and selects
 * exactly one AIENOS partition by its fixed partition type GUID:
 *
 *     AIENOS partition type GUID  38DAAC89-5EAD-4B40-8B1E-3687A7418061
 *     (generated once from /dev/urandom on 2026-10-01, version 4 / variant 1;
 *      on-disk bytes, mixed endian: 89 AC DA 38 AD 5E 40 4B 8B 1E 36 87 A7 41 80 61)
 *
 * Every kernel disk access after that (rw probe, torn_slot anchor, Store)
 * goes through ONE bounds-checked translation layer, ck_part_xlate, behind a
 * disk_dev "partition view" (ck_part.dev): partition-relative LBA in,
 * absolute LBA out, refused unless the whole transfer lies inside the
 * partition. Nothing else in the kernel holds a writable whole-disk handle.
 *
 * Validation is strict and fails closed (no fallback to the whole disk):
 * protective MBR (0x55AA, one 0xEE record), primary header (signature,
 * revision 1.0, size, CRC32, MyLBA 1, AlternateLBA = last LBA, usable range),
 * primary entry array CRC32, backup header (CRC32, MyLBA = last, AlternateLBA
 * 1, same disk GUID / entry geometry / entry CRC) and the backup entry array
 * CRC32; every used entry inside the usable range, no two used entries
 * overlapping, exactly one AIENOS entry. Any failure: the caller prints
 * "disk: no AIENOS partition, refusing writes" and never writes the disk.
 *
 * Freestanding: no libc, no heap; reads through disk_read only. Shared with
 * the host tools (tools/ck_gpt_image.c, tools/ck_store_image.c) and the host
 * test dev/tests/disk_part_test.c. */
#ifndef AIENOS_CK_DISK_PART_H
#define AIENOS_CK_DISK_PART_H
#include <stddef.h>
#include <stdint.h>
#include "disk.h"

/* TEST-ONLY mutation (scripts/qemu_ck_disk_layout_test.sh): the translation
 * layer adds no partition offset and checks only the parent disk's bounds.
 * It exists so the DISK_LAYOUT gate can prove it notices a bypass. Never
 * with a hardware staging build. */
#if defined(CK_TEST_DISK_XLATE_BYPASS) && defined(CK_HARDWARE_STAGING)
#error "CK_TEST_DISK_XLATE_BYPASS (TEST-ONLY translation bypass mutation) cannot be combined with CK_HARDWARE_STAGING"
#endif

extern const uint8_t ck_aienos_part_type[16]; /* on-disk byte order */

#define CK_GPT_MAX_ENTRIES 1024u   /* NumberOfPartitionEntries upper bound */
#define CK_GPT_MAX_USED 128u       /* used (non-zero type) entries upper bound */
#define CK_GPT_HDR_MIN 92u         /* HeaderSize lower bound (UEFI) */

enum {
    CK_GPT_OK = 0,
    CK_GPT_EIO = -401,        /* a read failed */
    CK_GPT_EGEOM = -402,      /* block size / disk too small for a GPT */
    CK_GPT_ENOMBR = -403,     /* no protective MBR (no 0x55AA or no 0xEE record) */
    CK_GPT_ESIG = -404,       /* primary header signature / revision / size */
    CK_GPT_EHDR_CRC = -405,   /* primary header CRC32 mismatch */
    CK_GPT_EHDR = -406,       /* primary header fields inconsistent */
    CK_GPT_EENT_CRC = -407,   /* primary entry array CRC32 mismatch */
    CK_GPT_EENT = -408,       /* entry geometry (count/size/overflow) refused */
    CK_GPT_EBACKUP = -409,    /* backup header or backup entry array invalid */
    CK_GPT_EOUTSIDE = -410,   /* a used entry lies outside the usable range */
    CK_GPT_EOVERLAP = -411,   /* two used entries overlap */
    CK_GPT_ENOPART = -412,    /* no AIENOS partition */
    CK_GPT_EMULTI = -413,     /* more than one AIENOS partition */
    CK_GPT_ETOOMANY = -414,   /* more than CK_GPT_MAX_USED used entries */
};

typedef struct {
    uint64_t last_lba;        /* disk's last LBA */
    uint64_t first_usable, last_usable;
    uint32_t entries, entry_size;
    uint32_t used;            /* used entries */
    uint32_t part_index;      /* index of the AIENOS entry */
} ck_gpt_info;

typedef struct {
    const disk_dev *parent;   /* whole namespace: read for the GPT, written only through ck_part_xlate */
    uint64_t first_lba;       /* absolute first LBA of the AIENOS partition */
    uint64_t blocks;          /* partition length in blocks */
    int valid;                /* 1 only after ck_gpt_find_aienos succeeded */
    disk_dev dev;             /* the partition view; dev.ctx == this */
} ck_part;

/* CRC32 (IEEE 802.3, reflected 0xEDB88320, init/xorout 0xFFFFFFFF), the
 * GPT checksum. Chain: crc = ck_crc32(crc, p, n) starting from 0. */
uint32_t ck_crc32(uint32_t crc, const uint8_t *p, size_t n);

/* Parse and validate the GPT on d (reads only). On success fills *p (a valid
 * partition view over d) and *info; on failure *p is invalid (every I/O
 * through p->dev refused) and the CK_GPT_* code is returned. */
int ck_gpt_find_aienos(const disk_dev *d, ck_part *p, ck_gpt_info *info);

/* The single translation layer: partition-relative lba/count -> absolute
 * LBA. DISK_ESTATE when p is not a valid partition, DISK_EARG for count 0,
 * DISK_ERANGE when any block of the transfer would fall outside the
 * partition (or the parent disk), including on overflow. */
int ck_part_xlate(const ck_part *p, uint64_t lba, uint32_t count, uint64_t *abs);

const char *ck_gpt_strerror(int rc);
#endif
