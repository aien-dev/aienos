/* handoff_check.h -- pure validator of the loader -> kernel handoff record
 * (docs/BOOT_HANDOFF_CONTRACT.md section 6, CHANDOF1 v1). No I/O, no
 * globals the caller can see; host tested by tests/test_handoff.c. */
#ifndef AIENOS_CK_HANDOFF_CHECK_H
#define AIENOS_CK_HANDOFF_CHECK_H

#include "handoff.h"

/* Largest memory map copy a loader may hand over (efi_main.c MAP_BYTES). */
#define CK_HANDOFF_MAP_MAX (64u << 10)
/* Smallest UEFI descriptor stride the kernel parses (struct ck_efi_desc,
 * mm/frames.h). */
#define CK_HANDOFF_DESC_MIN 40u
/* UEFI EFI_MEMORY_DESCRIPTOR_VERSION. */
#define CK_HANDOFF_DESC_VERSION 1u

/* Returns 0 when h is an acceptable CHANDOF1 record. Otherwise returns -1
 * and sets *why to the refusal reason without the "handoff: " prefix
 * (for example "bad magic"); the kernel panics with "handoff: <why>".
 * *why may point at a static buffer overwritten by the next call. */
int ck_handoff_check(const struct ck_handoff *h, const char **why);

#endif
