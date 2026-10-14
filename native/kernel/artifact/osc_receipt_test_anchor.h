/* osc_receipt_test_anchor.h -- THROWAWAY TEST material for realization receipts (aienos#383). It protects nothing.
 *
 * osc_rcpt_test_pk: omega checker2's TEST receipt key (omega spec/one-layer-receipts.md section 3, class TEST),
 * seed = SHA-256("OMEGA-CHECKER2-TEST-KEY-v1 NOT FOR PRODUCTION"), public on purpose. This is NOT the OSC unit
 * container TEST key (osc_unit_test_anchor.h, aien-protocols test1): the two keys sign different things and are
 * anchored separately. tests/test_osc_receipt.c checks these bytes against the checker2-minted fixtures
 * (tests/fixtures/osc_receipt, PROVENANCE.txt).
 *
 * osc_rcpt_qual_revoked_id: the id of tests/fixtures/osc_receipt/n_revoked_id.rcpt, on the qualification
 * policy's revoked-id list so the REVOKED path is exercised (test checks it is that file's SHA-256).
 *
 * Compiled only into the host tests and into the TEST-anchor qualification image (CK_SEED0B_TEST_ANCHOR=1,
 * banner "TEST ONLY"); never into a release image's anchor set. */
#ifndef AIENOS_CK_OSC_RECEIPT_TEST_ANCHOR_H
#define AIENOS_CK_OSC_RECEIPT_TEST_ANCHOR_H
#include <stdint.h>
static const uint8_t osc_rcpt_test_pk[32] = {
    0x60, 0x28, 0x10, 0xd4, 0x3c, 0x01, 0x15, 0xdf, 0x87, 0x7b, 0x0c, 0xf8, 0xc3, 0x27, 0x01, 0x0e,
    0x5a, 0x7e, 0x57, 0x04, 0x90, 0xc8, 0x5e, 0x31, 0x46, 0x6c, 0x0c, 0xff, 0x6c, 0xa3, 0x74, 0xc5};
static const uint8_t osc_rcpt_qual_revoked_id[32] = {
    0xe4, 0x52, 0x12, 0xd1, 0xea, 0x69, 0x56, 0xe4, 0xef, 0x65, 0xb9, 0xa8, 0x39, 0xda, 0x20, 0xaf,
    0x3f, 0xf9, 0xbd, 0x53, 0xc5, 0x66, 0xcd, 0x23, 0x3a, 0x6a, 0xe2, 0x6c, 0xad, 0x65, 0x8f, 0xf3};
#endif
