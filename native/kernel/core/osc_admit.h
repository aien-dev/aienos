/* osc_admit.h -- kernel-side use of artifact/osc_unit.c: admission verdict
 * for OSCUNIT containers that arrive through the artifact candidate path
 * (boot disk Store), and the realization receipts (artifact/osc_receipt.h,
 * aienos#383) that arrive the same way. Admission only: nothing is mapped or
 * launched here; a launch (core/osc_task.c) verifies its receipt. */
#ifndef AIENOS_CK_OSC_ADMIT_H
#define AIENOS_CK_OSC_ADMIT_H
#include <stddef.h>
#include <stdint.h>
#include "osc_unit.h"

/* Nonzero if the bytes begin with the container magic "OSCUNIT\0". */
int ck_osc_is_unit(const uint8_t *b, size_t len);
/* Admit one container and print its machine-readable "osc_unit:" line. Returns 0 accepted,
 * else the refusal code. */
unsigned ck_osc_candidate(const char *name, const uint8_t *b, size_t len);
/* A Store entry the Store refused as too large (RESOURCE_UNAVAILABLE) is never read, so its format is
 * unknown: print an "osc_unit:" refusal line for it and count it as oversize. The refusal itself stays
 * with the old firmware path. */
void ck_osc_oversize(const char *name, uint64_t len);
/* Print the "osc_units:" summary line if any OSC candidate or oversize entry was seen. */
void ck_osc_summary(void);

/* The kernel's local admission and receipt policy (release or qualification build). */
void ck_osc_policy(struct osc_policy *p);
/* Nonzero if the bytes begin with the receipt magic "OMRCPT1\0" (omega receipt v1). */
int ck_osc_is_receipt(const uint8_t *b, size_t len);
/* Keep a receipt by its Store name (it is verified later, against the unit a launch presents it with) and
 * print its "osc_receipt:" line. */
void ck_osc_receipt_candidate(const char *name, const uint8_t *b, size_t len);
/* The kept receipt of that name (*len its length), or NULL (*len 0) if none arrived. */
const uint8_t *ck_osc_receipt_find(const char *name, size_t *len);
#ifdef CK_OSC_LAUNCH_TEST
extern int ck_osc_rcpt_variant; /* TEST ONLY: receipt policy variant of the next launch (osc_admit.c) */
#endif
#endif
