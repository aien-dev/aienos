/* store_crash.h -- TEST-ONLY Store crash hook for the C kernel QEMU gate
 * M4_STORE_CRASH (scripts/qemu_ck_store_crash_test.sh).
 *
 * Compiled only into the TEST image "make full CK_TEST_STORE_CRASH=1"
 * ($(OUT)/full-test-store-crash/). The Makefile and store_crash.c refuse it
 * together with CK_HARDWARE_STAGING or CK_QEMU_UNSAFE_DMA, and every default
 * full image is checked to carry none of its code or strings. Such an image
 * announces itself on the console and never counts toward a PASS of M4_STORE.
 *
 * Crash plan. The host writes one ASCII line into the last 4096-byte unit of
 * the NVMe disk (the scratch unit of the devices-stage rw probe, which the
 * probe restores byte for byte, dev/nvme_bind.c ck_disk_rw_probe):
 *     AIENCRSH v1 cp=<checkpoint> policy=<drop|all|newest|torn>\n
 * checkpoint: a native/store st_checkpoint_name() name, or before_anchor /
 * after_anchor (store_sealed.h SS_CP_*).
 *
 * With a valid plan the Store stage runs on a volatile write cache wrapped
 * around the boot disk: writes stay in RAM until the Store flushes, reads see
 * them. At the planned checkpoint the hook models a power cut: per the policy
 * none (drop), all (all, = a QEMU process kill), only the newest write call
 * (newest, a device that reordered) or the first half of the blocks of the
 * newest write call (torn) of the unflushed writes reach the disk, the disk is
 * flushed, "store_crash: HALT at ..." is printed and the CPU stops forever. The
 * host then kills QEMU. Without a plan the Store runs on the disk directly. */
#ifndef AIENOS_CK_STORE_CRASH_H
#define AIENOS_CK_STORE_CRASH_H
#include <stdint.h>
#include "disk.h"

#ifdef CK_TEST_STORE_CRASH
#define CK_STORE_CRASH_POLICY_DROP 0
#define CK_STORE_CRASH_POLICY_ALL 1
#define CK_STORE_CRASH_POLICY_NEWEST 2
#define CK_STORE_CRASH_POLICY_TORN 3

/* Prints the TEST-ONLY banner, reads the plan from the last unit of d.
 * Returns the disk the Store must use: d without a plan, else the cache. */
const disk_dev *ck_store_crash_setup(const disk_dev *d);
/* Generation the Store opened at (printed on every checkpoint line). */
void ck_store_crash_opened(uint64_t generation);
/* st_hook: prints every checkpoint; halts at the planned one. */
void ck_store_crash_hook(void *arg, int checkpoint);
#endif
#endif
