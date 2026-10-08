/* osc_admit.h -- kernel-side use of artifact/osc_unit.c: admission verdict
 * for OSCUNIT containers that arrive through the artifact candidate path
 * (boot disk Store). Admission only: nothing is mapped or launched. */
#ifndef AIENOS_CK_OSC_ADMIT_H
#define AIENOS_CK_OSC_ADMIT_H
#include <stddef.h>
#include <stdint.h>

/* Nonzero if the bytes begin with the container magic "OSCUNIT\0". */
int ck_osc_is_unit(const uint8_t *b, size_t len);
/* Admit one container and print its machine-readable "osc_unit:" line. Returns 0 accepted,
 * else the refusal code. */
unsigned ck_osc_candidate(const char *name, const uint8_t *b, size_t len);
/* Print the "osc_units:" summary line if any OSC candidate was seen. */
void ck_osc_summary(void);
#endif
