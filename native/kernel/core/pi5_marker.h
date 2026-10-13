/* pi5_marker.h -- the layer below the sealed Store, proved on the Pi 5 card
 * (AIENOS-PI5 step 3). The Store itself needs production keys, which are
 * BLOCKED_OPERATOR (svc/store_boot.c), so the Pi image does not open it. What
 * the Store needs from the card is: GPT partition view in, multi-sector
 * writes with flush, bytes back identical after a reboot. This module
 * proves exactly that on a bounded scratch region at the END of the AIENOS
 * partition view, written only through that view (dev/disk_part.h).
 *
 * Region: CK_PI5_MARKER_SECS sectors. Sector 0 is the header, the rest a
 * payload that is a pure function of (seed, sector, offset), so a later boot
 * can verify it byte for byte without storing a copy:
 *   header: magic "AIENPI5M", version, generation, payload sectors, seed,
 *           CRC32 of the payload, CRC32 of the header's first 40 bytes.
 * First boot, region all zero: write payload, flush, write header, flush,
 * read back: CK_PI5_MARKER_FORMATTED. Later boot, valid header: payload
 * read (multi-sector) and compared with the regenerated pattern, then
 * generation + 1 is written and read back: CK_PI5_MARKER_REOPENED. Anything
 * else (neither zero nor a valid marker) is refused and nothing is written.
 *
 * Freestanding (no libc): the caller supplies the buffer. */
#ifndef AIENOS_CK_PI5_MARKER_H
#define AIENOS_CK_PI5_MARKER_H
#include <stdint.h>
#include "disk.h"
#include "../dev/disk_part.h"

#define CK_PI5_MARKER_SECS 64u /* 32 KiB: one header sector + 63 payload sectors */
#define CK_PI5_MARKER_BUF_BYTES (CK_PI5_MARKER_SECS * DISK_SECTOR_BYTES)
#define CK_PI5_MARKER_SEED 0x41494e5049354d31ull

enum {
    CK_PI5_MARKER_FORMATTED = 1, /* blank region: written, flushed, read back identical */
    CK_PI5_MARKER_REOPENED = 2,  /* valid marker: payload identical, generation bumped and read back */
    CK_PI5_MARKER_EIO = -501,    /* a read, write or flush failed */
    CK_PI5_MARKER_EREFUSED = -502, /* region is neither blank nor a valid marker: nothing written */
    CK_PI5_MARKER_ECORRUPT = -503, /* valid header, payload does not match: nothing written */
    CK_PI5_MARKER_EVERIFY = -504,  /* read back after a write differs */
    CK_PI5_MARKER_ESIZE = -505,    /* view smaller than the region, or not 512-byte blocks */
};

/* d is the AIENOS partition view. buf is CK_PI5_MARKER_BUF_BYTES, 64-aligned.
 * *generation is set on success. */
int ck_pi5_marker_run(const disk_dev *d, uint8_t *buf, uint64_t *generation);
const char *ck_pi5_marker_strerror(int rc);

/* The sealed Store's view of the AIENOS partition on the Pi card: the same
 * partition with the marker region reserved. *out ends before the last
 * CK_PI5_MARKER_SECS sectors, rounded down to whole CK_LAYOUT_UNIT units, so
 * the Store's units 4..U-2 and its probe unit U-1 (dev/disk_layout.h) never
 * touch a marker sector, and the marker never touches the Store. Every image
 * that writes either one uses this split. CK_PI5_MARKER_ESIZE when full is
 * invalid, not 512-byte blocks, or too small for one unit plus the marker. */
int ck_pi5_store_view(const ck_part *full, ck_part *out);
#endif
