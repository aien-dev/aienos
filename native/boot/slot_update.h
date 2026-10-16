/* slot_update.h -- write a signed candidate image into the INACTIVE slot
 * (native v1 plan P11 cut 3, gate N7; docs/NATIVE_IMAGE_SLOTS.md section 9).
 *
 * One routine, shared by the service kernel (svc/slot_service.c, operator
 * verb `update`) and the host tool (ck_slot_tool, its self-test injects an
 * I/O error at every write). Source: the update inbox partition
 * (CK_SLOT_INBOX_TYPE, one slot's shape: manifest unit, then the image).
 *
 * Order, and what an interruption at each point leaves behind:
 *   1. refuse unless: control record present, no candidate staged, the
 *      booted slot is the active one; target = the other slot. Nothing read.
 *      The recovery image (booted_slot CK_SLOT_BOOT_RECOVERY, P11 cut 4) is
 *      exempt from the last two: staging replaces a stale (failed or exhausted)
 *      candidate and it writes the slot that is not active.
 *   2. read the inbox manifest and image, ck_slot_verify against the image's
 *      trusted keys (signature over the manifest, SHA-512 of the image), and
 *      dry-run ck_slot_stage_candidate (generation above the floor) on a copy
 *      of the control record. Any refusal: NOTHING written.
 *   3. overwrite the target's manifest unit with zeros, flush. From here the
 *      target slot is INVALID until step 5 completes; the control record is
 *      untouched, so the loader keeps booting the active slot.
 *   4. write the image units, flush.
 *   5. write the manifest unit, flush; read the whole slot back and verify it
 *      again (signature + digest from the disk bytes). A failed read-back
 *      zeroes the manifest unit again (best effort) and refuses.
 *   6. stage: one control record commit (ck_slot_control_commit), candidate =
 *      target, tries = CK_SLOT_MAX_TRIES. Only now does the loader try it.
 * Every write lies inside the target slot's unit range [M, M + CAP) (checked
 * before each write); the active slot and the control region (except the one
 * commit of step 6) are never written. Freestanding, no allocation: the
 * caller provides the image buffer. */
#ifndef AIENOS_CK_SLOT_UPDATE_H
#define AIENOS_CK_SLOT_UPDATE_H
#include "slot_control.h"
#include "../disk/disk.h"

struct ck_slot_update_io {
    const disk_dev *slots;          /* the slots partition (bounded view) */
    const disk_dev *inbox;          /* the update inbox partition (read only) */
    ts_region *control;             /* opened and recovered over the slots partition */
    const struct ck_slot_control *ctl; /* the recovered control record (NULL: refused) */
    unsigned booted_slot;           /* the slot this kernel was started from */
    const uint8_t (*keys)[32];      /* trusted manifest signers */
    unsigned nkeys;
    uint8_t *buf;                   /* image buffer, buf_cap bytes, 4096-aligned length */
    uint64_t buf_cap;
    /* Optional progress hook: step name, units done, units total. A nonzero
     * return stops the update there (the hosts's interruption point). */
    int (*progress)(void *ctx, const char *step, uint64_t done, uint64_t total);
    void *ctx;
};

struct ck_slot_update_result {
    unsigned target;                /* the slot written (0 or 1) */
    uint64_t generation;            /* of the staged image */
    uint64_t image_len;
    uint64_t units_written;         /* inside the target slot */
    uint64_t seq;                   /* control sequence after staging */
    int wrote;                      /* 1 once step 3 wrote anything */
};

/* 0 = staged (res filled). -1 = refused with *why (res->wrote says whether
 * the target slot was touched; the control record never was). */
int ck_slot_update(const struct ck_slot_update_io *io, struct ck_slot_update_result *res, const char **why);

#endif
