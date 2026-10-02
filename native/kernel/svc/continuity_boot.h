/* continuity_boot.h -- K-7 TEST-ONLY mode selection and the kernel wiring of the
 * continuity (cut 3-4) and Recovery Core (cut 5) code into the Store stage.
 *
 * Compiled only into the TEST image "make full CK_TEST_CONTINUITY=1"
 * ($(OUT)/full-test-continuity[-mutant-<name>]/). The Makefile and
 * continuity_boot.c refuse it together with CK_HARDWARE_STAGING,
 * CK_QEMU_UNSAFE_DMA and CK_TEST_STORE_CRASH, and every default full image is
 * checked to carry none of its code or strings. The image announces itself on
 * the console and never counts toward anything but M4_CONTINUITY / M4_RECOVERY.
 *
 * Mode selection (contract K-7, DECIDED): the host writes one ASCII line into the
 * last 4096-byte unit of the AIENOS partition (the rw-probe scratch unit, which
 * the devices stage restores byte for byte, dev/nvme_bind.c ck_disk_rw_probe; the
 * same carrier as svc/store_crash.h):
 *     AIENCONT v1 mode=<N>[ cp=<checkpoint>][ response=<64 hex>]\n
 * mode uses the numbers of the Rust control block (store_qual.rs:27-48):
 *     1  ordinary Store boot (formats a blank disk, commits a boot record): used by
 *        the harness to make "a formatted Store with data, no identity"
 *     5  provision (formats a blank disk first, as the Rust mode 5)
 *     6  resume          7  resume + remember     8  resume + commit with a crash point
 *     9  Recovery Core inspect
 *     10 inspect + repair-degraded-peer with `response`
 *     11 inspect + provision-identity with `response`
 * cp (mode 8 only): the C checkpoint where the kernel halts after printing
 * "CHECKPOINT: <name>" (the host then kills QEMU): before_first_write,
 * after_payload_objects, after_catalog, after_commit_record, after_first_flush,
 * after_inactive_superblock, after_final_flush, before_anchor, after_anchor.
 * Without a valid plan (or mode 1) the Store stage runs exactly as the default
 * image does. A modes 5..11 boot runs INSTEAD of the boot-record commit: it
 * writes only what the mode's own continuity or recovery action writes.
 *
 * The TEST operator key (0x0f x 32) lives only in continuity_boot.c, behind
 * CK_TEST_CONTINUITY; every recovery boot prints "RECOVERY_OPERATOR_KEY: TEST-ONLY". */
#ifndef AIENOS_CK_CONTINUITY_BOOT_H
#define AIENOS_CK_CONTINUITY_BOOT_H
#include "disk.h"

#ifdef CK_TEST_CONTINUITY
/* Returns 1 when a modes 5..11 plan was found and run (the caller must not run
 * the ordinary Store boot), else 0. *rc is 0 unless the harness itself failed. */
int ck_cont_boot_stage(const disk_dev *d, int *rc);
/* Last Store opened by a continuity boot (NULL if none). */
#endif
#endif
