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
#define ARGUS_AUTH_RIGHT_EFFECT 0x4u

/* Number of detectors in argus_hard_detectors (ids 1..10, in id order). */
#define ARGUS_HARD_DETECTOR_COUNT 10u

/* Upper bound on findings a single detector can emit for one event.
 * Only QUARANTINED_USE can emit two (provider + machine). A caller that
 * passes cap >= ARGUS_DETECT_MAX_FINDINGS never sees ARGUS_ERR_OVERFLOW. */
#define ARGUS_DETECT_MAX_FINDINGS 11u

#endif /* ARGUS_DETECT_H */
