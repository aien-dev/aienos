/* allen.h -- the ALLEN exam stage of the pi5-allen image (PI5-8 cut K, build flag CK_ALLEN; core/allen.c).
 *
 * QUALIFICATION ONLY, train/dev rehearsal. The run tool places \EFI\AIENOS\ALLEN.EXM on the card's EFI partition: one
 * header line "AIENALX1 QUALIF-ALLEN-EXAM" and one "<id>|<turns>" line per case (format and bounds:
 * crates/allen-reflex-kernel/src/card.rs; built by scripts/allen_exam_card.sh, which carries no expected answers).
 * The UEFI stub (native/boot/efi_allen.c) reads it before ExitBootServices into ck_allen_boot; the kernel stage hands
 * it to the Rust unit, which checks it whole. The run tool deletes the file after the run. Nothing is written by the
 * stage: the image has no Store stage and the ALLEN gate (core/allen_gate.h) only judges. */
#ifndef AIENOS_CK_ALLEN_H
#define AIENOS_CK_ALLEN_H
#include <stdint.h>

#define CK_ALLEN_EXM_PATH "\\EFI\\AIENOS\\ALLEN.EXM"
#define CK_ALLEN_FILE_MAX 131072u /* = card::FILE_MAX */

enum { CK_ALLEN_EXM_NONE = 0, CK_ALLEN_EXM_ABSENT = 1, CK_ALLEN_EXM_REFUSED = 2, CK_ALLEN_EXM_FOUND = 3 };

/* What the UEFI stub found (the stub and the kernel are one image). */
struct ck_allen_boot {
    int state;    /* CK_ALLEN_EXM_* */
    uint32_t len; /* bytes in buf while FOUND */
    uint8_t buf[CK_ALLEN_FILE_MAX + 1u];
};
extern struct ck_allen_boot ck_allen_boot;

void ck_allen_run(void);
#endif
