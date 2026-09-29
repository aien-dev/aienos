/*
 * argus_detect.h -- internals of the ARGUS-0 hard-invariant detectors (lane E).
 *
 * The public entry points (argus_hard_detectors, argus_hard_detector_count,
 * argus_detect_run) are declared in argus_abi.h. This header only mirrors the
 * few authority constants the detectors compare against, so that
 * argus_detect.c stays freestanding and does not include or link the
 * authority. tests/test_argus_detect.c includes the real
 * ../capability/aienos_capability.h and asserts each mirror is equal.
 *
 * ARGUS never re-validates a capability. These values are only used to read
 * the result code the producer copied from the authority into ev->code, and
 * the rights mask the producer copied into a GRANTED event.
 */
#ifndef ARGUS_DETECT_H
#define ARGUS_DETECT_H
#include "argus_abi.h"

/* Mirrors of native/capability/aienos_capability.h (checked by the tests). */
#define ARGUS_AUTH_OK             0
#define ARGUS_AUTH_ERR_BOUNDS   (-1)
#define ARGUS_AUTH_ERR_STALE_GEN (-2)
#define ARGUS_AUTH_ERR_REVOKED  (-3)
#define ARGUS_AUTH_ERR_CHAIN    (-9)
#define ARGUS_AUTH_RIGHT_WRITE  0x2u
#define ARGUS_AUTH_RIGHT_EFFECT 0x4u

/* Number of detectors in argus_hard_detectors: ids 1..10, 14, 15, in id order.
 * Codes 11, 12, 13 and 16 are raised by the core, never by a detector. */
#define ARGUS_HARD_DETECTOR_COUNT 12u

/* Upper bound on findings argus_detect_run can emit for one event: one per
 * detector, except QUARANTINED_USE, which can emit two (provider + machine).
 * A caller that passes cap >= ARGUS_DETECT_MAX_FINDINGS never sees
 * ARGUS_ERR_OVERFLOW. */
#define ARGUS_DETECT_MAX_FINDINGS 13u

/* Machine trust rank (argus_abi.h machine lifecycle): lower is more trusted.
 * TRUSTED 0 < OBSERVED 1 < REATTESTATION_REQUIRED 2 < RESTRICTED 3 <
 * QUARANTINED 4 < UNTRUSTED 5. Returns -1 for values outside 1..6
 * (UNKNOWN or garbage), which callers treat as "no claim". */
static inline int argus_trust_rank(uint32_t trust)
{
    switch (trust) {
    case ARGUS_TRUST_TRUSTED:                return 0;
    case ARGUS_TRUST_OBSERVED:               return 1;
    case ARGUS_TRUST_REATTESTATION_REQUIRED: return 2;
    case ARGUS_TRUST_RESTRICTED:             return 3;
    case ARGUS_TRUST_QUARANTINED:            return 4;
    case ARGUS_TRUST_UNTRUSTED:              return 5;
    default:                                 return -1;
    }
}

#endif /* ARGUS_DETECT_H */
