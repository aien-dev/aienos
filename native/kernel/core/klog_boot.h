/* klog_boot.h -- what the UEFI stub found about the log slot
 * (native/boot/efi_klog.c), read by the kernel after ExitBootServices
 * (core/klog_flush.c). Raspberry Pi 5 build only (CK_KLOG). */
#ifndef AIENOS_CK_KLOG_BOOT_H
#define AIENOS_CK_KLOG_BOOT_H
#include <stdint.h>
#include "klog_slot.h"

enum { CK_KLOG_BOOT_NONE = 0, CK_KLOG_BOOT_ABSENT = 1, CK_KLOG_BOOT_REFUSED = 2, CK_KLOG_BOOT_FOUND = 3 };

struct ck_klog_boot {
    int state;                /* CK_KLOG_BOOT_* */
    struct ck_klog_map map;   /* checked map (state FOUND) */
    uint64_t disk_last_block; /* firmware LastBlock of the disk that carries the slot */
};
extern struct ck_klog_boot ck_klog_boot;
#endif
