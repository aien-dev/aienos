/* disk_layout.h -- how the AIENOS C kernel stages share the boot NVMe disk.
 *
 *   unit 0..3            sealed-Store anti-rollback anchor (torn_slot, 4 units)
 *   unit 4..U-2          Store v1 region (store_sealed / ADR 0015)
 *   unit U-1             scratch unit for the NVMe write/flush/read-back probe
 * A unit is 4096 bytes (8 blocks of 512 or 1 block of 4096); U = whole units
 * on the namespace. The probe only ever writes the last unit. */
#ifndef AIENOS_CK_DISK_LAYOUT_H
#define AIENOS_CK_DISK_LAYOUT_H
#include <stdint.h>
#define CK_LAYOUT_UNIT 4096u
#define CK_LAYOUT_ANCHOR_UNITS 4u
#define CK_LAYOUT_PROBE_UNITS 1u
#define CK_LAYOUT_MIN_STORE_UNITS 64u
#endif
