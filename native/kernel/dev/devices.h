/* devices.h -- the devices boot stage (ck_stage_devices) and what it hands
 * to later stages. */
#ifndef AIENOS_CK_DEVICES_H
#define AIENOS_CK_DEVICES_H
#include "disk.h"
/* The bound NVMe disk, or NULL when the devices stage did not bind one. */
const disk_dev *ck_dev_boot_disk(void);
#endif
