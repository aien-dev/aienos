/* ck_pi5_store_locate.c -- host tool: print where the KeySlotManifest sits in a copy of the Pi card's
 * AIENOS partition (see pi5_store_locate.h). Read only, prints no secret and no key bytes.
 *   ck_pi5_store_locate <partition image> */
#include <stdio.h>
#include "pi5_store_locate.h"
#include "store_boot.h"

/* store_boot.c (compiled -DCK_PI5_UNLOCK, as in the image) references the board secret source; the locator
 * never unlocks anything, so it has none. */
int ck_pi5_unlock_secret(uint8_t out[CK_SB_SECRET_LEN], const char **source)
{
    (void)out;
    (void)source;
    return -1;
}

int main(int argc, char **argv)
{
    ck_pi5_ksm_loc l;
    char err[160];
    if (argc != 2) {
        fprintf(stderr, "usage: %s <partition image>\n", argv[0]);
        return 2;
    }
    if (ck_pi5_locate_keyslot(argv[1], &l, err, sizeof err)) {
        fprintf(stderr, "locate: FAIL: %s\n", err);
        return 1;
    }
    printf("keyslot_manifest first_unit=%llu bytes=%llu part_sector=%llu part_byte_offset=%llu\n",
           (unsigned long long)l.first_unit, (unsigned long long)l.byte_length, (unsigned long long)l.part_sector,
           (unsigned long long)l.part_byte_offset);
    printf("wrapped_k_vol_byte_offset=%llu wrap_tag_byte_offset=%llu\n", (unsigned long long)l.wrapped_kvol_offset,
           (unsigned long long)l.wrap_tag_offset);
    return 0;
}
