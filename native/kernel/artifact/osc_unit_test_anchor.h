/* osc_unit_test_anchor.h -- the THROWAWAY TEST public key of the OSC unit
 * conformance vectors (aien-protocols PR #17, specs/osc-unit-artifact/keys/
 * test1.pub, derived from a fixed public label in tools/make-vectors.sh).
 * It protects nothing. It is compiled only into the host test and into the
 * TEST-anchor qualification image (CK_SEED0B_TEST_ANCHOR=1, banner "TEST
 * ONLY"); never into a release image's anchor set. test_osc_unit.c checks
 * these bytes against the fixture file. */
#ifndef AIENOS_CK_OSC_UNIT_TEST_ANCHOR_H
#define AIENOS_CK_OSC_UNIT_TEST_ANCHOR_H
#include <stdint.h>
static const uint8_t osc_unit_test1_pk[32] = {
    0x1d, 0xaa, 0xec, 0x3d, 0xcf, 0x62, 0x52, 0x6c, 0x52, 0xf7, 0x1c, 0xdf, 0x3e, 0x67, 0x1a, 0x8d,
    0xe5, 0xc4, 0x6b, 0x0f, 0x9c, 0xa7, 0x3e, 0xe2, 0x0c, 0x01, 0x44, 0x5b, 0x8b, 0x34, 0x18, 0xee};
#endif
