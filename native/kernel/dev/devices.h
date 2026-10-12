/* devices.h -- the devices boot stage (ck_stage_devices) and what it hands
 * to later stages. */
#ifndef AIENOS_CK_DEVICES_H
#define AIENOS_CK_DEVICES_H
#include "disk.h"
/* The AIENOS partition of the bound NVMe disk (a bounds-checked partition
 * view, dev/disk_part.h), or NULL when the devices stage bound no disk or the
 * disk has no valid AIENOS partition. */
const disk_dev *ck_dev_boot_disk(void);
/* The AIENOS image slots partition of the same bound NVMe disk (a second
 * bounds-checked partition view, P11 cut 2b), or NULL; *rc_out (optional) is
 * 0, the CK_GPT_* refusal, or CK_DEV_NO_BOOT_DISK. */
#define CK_DEV_NO_BOOT_DISK (-1)
const disk_dev *ck_dev_slots_disk(int *rc_out);
/* Revoke the NVMe function's bus mastering once the last disk user (the
 * Store stage) is done, or after a failed bind; prints the dma_gate line.
 * The boot disk is unavailable afterwards. */
void ck_dev_nvme_release(void);
#endif
