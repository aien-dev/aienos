/* klog_slot.h -- where the kernel may write its log on the boot card, and
 * the checks that keep it from writing anywhere else (Raspberry Pi 5 build).
 *
 * The host side (the run tool) creates a contiguous file on the card's FAT
 * volume, writes a slot header into its first sector with a fresh random
 * nonce, and writes \EFI\AIENOS\KLOG.MAP naming the file's first absolute
 * sector on the whole card, its length and the same nonce. The UEFI stub
 * reads the map before ExitBootServices (native/boot/efi_klog.c). The
 * kernel writes only after it has read the slot's first sector through its
 * own SD driver and found the header with this map's nonce, sector and
 * length (ck_klog_hdr_match): a stale map, a moved file, another card or a
 * wrong sector number all refuse, and nothing is written.
 *
 * Slot layout: sector 0 header, sectors 1..count-1 log text. The kernel
 * writes the text first and the header (state WRITTEN, lengths) last.
 * Both structures are 512 bytes, little endian. */
#ifndef AIENOS_CK_KLOG_SLOT_H
#define AIENOS_CK_KLOG_SLOT_H
#include <stddef.h>
#include <stdint.h>

#define CK_KLOG_MAP_MAGIC "AIENKLM1"
#define CK_KLOG_HDR_MAGIC "AIENKLG1"
#define CK_KLOG_SLOT_VERSION 1u
#define CK_KLOG_MAP_PATH "\\EFI\\AIENOS\\KLOG.MAP"
#define CK_KLOG_MIN_SECTORS 2u
#define CK_KLOG_MAX_SECTORS 8192u /* 4 MiB */

enum { CK_KLOG_STATE_EMPTY = 0, CK_KLOG_STATE_WRITTEN = 1 };

struct ck_klog_map {
    uint8_t magic[8];     /* "AIENKLM1" */
    uint32_t version;     /* 1 */
    uint32_t sector_size; /* 512 */
    uint64_t lba;         /* slot sector 0, absolute on the whole card */
    uint64_t count;       /* slot sectors, CK_KLOG_MIN_SECTORS..CK_KLOG_MAX_SECTORS */
    uint8_t nonce[16];
    uint8_t pad[512 - 48];
};

struct ck_klog_hdr {
    uint8_t magic[8];     /* "AIENKLG1" */
    uint32_t version;     /* 1 */
    uint32_t state;       /* CK_KLOG_STATE_* */
    uint8_t nonce[16];    /* equals the map's */
    uint64_t lba;         /* equals the map's: a copy of this sector elsewhere never matches */
    uint64_t count;       /* equals the map's */
    uint64_t log_len;     /* text bytes in sectors 1.. (state WRITTEN) */
    uint64_t log_total;   /* bytes the console produced, kept or not */
    uint64_t commit;      /* build commit (ck_commit) */
    char stage[32];       /* boot stage at the write, NUL terminated */
    uint8_t pad[512 - 104];
};

_Static_assert(sizeof(struct ck_klog_map) == 512, "ck_klog_map size");
_Static_assert(sizeof(struct ck_klog_hdr) == 512, "ck_klog_hdr size");

/* Structural map check. last_block 0 skips the disk-size comparison.
 * 0 or -1 with *why. */
int ck_klog_map_check(const struct ck_klog_map *m, uint64_t last_block, const char **why);
/* The slot's sector 0 as read from the card matches the map (magic, version,
 * nonce, lba, count). Any state. 0 or -1 with *why. */
int ck_klog_hdr_match(const struct ck_klog_hdr *h, const struct ck_klog_map *m, const char **why);
/* Builds the WRITTEN header for a log of log_len bytes. */
void ck_klog_hdr_written(struct ck_klog_hdr *h, const struct ck_klog_map *m, uint64_t log_len,
                         uint64_t log_total, uint64_t commit, const char *stage);
/* Text capacity of the slot in bytes. */
static inline uint64_t ck_klog_slot_bytes(const struct ck_klog_map *m) { return (m->count - 1u) * 512u; }
#endif
