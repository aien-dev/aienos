/* artifact_card.h -- the card artifact bundle of the Raspberry Pi 5 EL0 artifact qualification image
 * (PI5-7 cut 3, build flag CK_ARTIFACT_CARD, "make pi5-artifact"; the same code boots in QEMU for the
 * red-before-green run, see scripts/qemu_ck_artifact_card_test.sh).
 *
 * QUALIFICATION ONLY, TEST keys only. The Pi image has no Store stage and no NVMe, so the signed artifacts
 * reach the loader as ONE file on the card's EFI partition, \EFI\AIENOS\ARTIFACT.BND, placed by the run
 * tool before the run and deleted after it. The UEFI stub (native/boot/efi_artifact.c) reads it before
 * ExitBootServices into ck_acard_buf; core/artifact_card_stage.c hands the entries to the unchanged core
 * loader (core/artifact_loader.c) through the same hook the boot-disk Store uses (ck_stage_disk_artifacts).
 * The loader then runs every check it always runs (format, TEST-key signature, digest, admission, W^X,
 * EL0 containment, receipt): this file proves nothing about who wrote a byte, its bytes are untrusted.
 *
 * File layout: the existing bundle of tools/ck_artifact_tool.c (command "bundle OUT FILE...", the layout
 * the QEMU gates already use), unchanged, all integers little endian:
 *   "AIENBND\0"  u32 count (1..CK_ACARD_MAX_ENTRIES)
 *   count x { u16 name_len (1..32), name (printable ASCII 0x21..0x7e, unique in the file),
 *             u32 byte_len (1..CK_ACARD_ENTRY_MAX), byte_len bytes }
 * and nothing after the last entry. The whole file is at most CK_ACARD_FILE_MAX bytes. Any deviation
 * refuses the whole file: no entry of a refused file is offered to the loader. */
#ifndef AIENOS_CK_ARTIFACT_CARD_H
#define AIENOS_CK_ARTIFACT_CARD_H
#include <stddef.h>
#include <stdint.h>

#define CK_ACARD_PATH "\\EFI\\AIENOS\\ARTIFACT.BND"
#define CK_ACARD_FILE_MAX (128u * 1024u)
#define CK_ACARD_MAX_ENTRIES 16u
#define CK_ACARD_ENTRY_MAX (160u * 4096u) /* = the loader's MAX_BATCH pages */
#define CK_ACARD_NAME_MAX 32u

struct ck_acard_entry {
    char name[CK_ACARD_NAME_MAX + 1];
    uint32_t len;
    const uint8_t *bytes; /* inside the buffer given to ck_acard_parse */
};

struct ck_acard {
    uint32_t count;
    struct ck_acard_entry e[CK_ACARD_MAX_ENTRIES];
};

/* 0 = well formed and *out filled (entries point into buf); else -1, *out zeroed and *why names the first
 * failed check. */
int ck_acard_parse(const uint8_t *buf, size_t n, struct ck_acard *out, const char **why);

enum { CK_ACARD_NONE = 0, CK_ACARD_ABSENT = 1, CK_ACARD_REFUSED = 2, CK_ACARD_FOUND = 3 };

/* What the UEFI stub found (the stub and the kernel are one image). */
struct ck_acard_boot {
    int state;           /* CK_ACARD_* */
    const char *why;     /* ABSENT / REFUSED: what failed */
    uint32_t file_len;   /* bytes read, FOUND only */
    struct ck_acard set; /* FOUND only */
};
extern struct ck_acard_boot ck_acard_boot;
extern uint8_t ck_acard_buf[CK_ACARD_FILE_MAX + 1u];
#endif
