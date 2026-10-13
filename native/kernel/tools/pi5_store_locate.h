/* pi5_store_locate.h -- host side only. Where the KeySlotManifest (Store object kind 21, ADR 0017 section
 * 2.4) sits inside a copy of the Pi card's AIENOS partition, found the way the kernel finds it:
 * the unkeyed st_open catalog (svc/store_boot.c ck_store_unlock_boot -> ss_keyslot_bootstrap) lists the
 * object's first_unit; the Store view starts CK_LAYOUT_ANCHOR_UNITS units into the partition and ends
 * before the 64-sector marker tail (core/pi5_marker.c ck_pi5_store_view). Used by the PI5-4 tamper run
 * (flip one byte of the wrapped K_vol) and by its host rehearsal in dev/tests/pi5_unlock_test.c. */
#ifndef AIENOS_CK_PI5_STORE_LOCATE_H
#define AIENOS_CK_PI5_STORE_LOCATE_H
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t keyslot_objects;     /* kind-21 catalog entries found (the locator needs exactly one) */
    uint64_t first_unit;          /* catalog first_unit, relative to the Store region */
    uint64_t byte_length;         /* manifest bytes (640, raw-secret profile) */
    uint64_t part_sector;         /* first sector of the object, counted from the partition start */
    uint64_t part_byte_offset;    /* part_sector * 512 */
    uint64_t wrapped_kvol_offset; /* partition byte of the first byte of the recovery slot's wrapped K_vol */
    uint64_t wrap_tag_offset;     /* partition byte of the first byte of that slot's wrap tag */
} ck_pi5_ksm_loc;

#define CK_PI5_KSM_RECOVERY_SLOT_OFF (128u + 128u * 1u) /* descriptor 1 of the manifest (m5_ksm_encode) */
#define CK_PI5_KSM_WRAPPED_KVOL_OFF 56u                 /* inside a descriptor (m5_keyslot_encode) */
#define CK_PI5_KSM_WRAP_TAG_OFF 88u

/* path: a file holding the partition from its first sector (sparse beyond what was copied is fine as
 * long as the file is the full partition length). 0 on success; else -1 and err says why. Read only. */
int ck_pi5_locate_keyslot(const char *path, ck_pi5_ksm_loc *out, char *err, size_t errn);
#endif
