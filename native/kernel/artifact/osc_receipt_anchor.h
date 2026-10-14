/* osc_receipt_anchor.h -- receipt trust inputs that are not TEST material (aienos#383).
 *
 * osc_rcpt_owner_root_pk: Drake's owner root public key from the aienos#380 ceremony
 * (docs/OWNER_KEY_CEREMONY.md; the private key lives on a YubiKey, PIV slot 9c). It is LISTED here so that a
 * release-mode verifier can honour no other owner anchor (omega spec/one-layer-receipts.md section 6 step 2),
 * but it is NOT TRUSTED for receipts: no kernel policy puts it in rcpt_owner_anchors until
 * docs/OWNER_KEY_CEREMONY.md records that it may sign realization receipts. Nothing in this repository signs
 * with it. tests/test_osc_receipt.c checks that the release and qualification policies do not trust it.
 *
 * osc_rcpt_checker_ids: the accepted checker2 identities (spec section 5). One entry: checker2 of omega
 * 265ce82a (omega#448), `checker2 version` checker_id. A changed checker2 has a new identity and its receipts are
 * refused UNTRUSTED_CHECKER until it is added here. */
#ifndef AIENOS_CK_OSC_RECEIPT_ANCHOR_H
#define AIENOS_CK_OSC_RECEIPT_ANCHOR_H
#include <stdint.h>
static const uint8_t osc_rcpt_owner_root_pk[32] = {
    0x57, 0x8a, 0xda, 0x3c, 0xb0, 0xc2, 0xd1, 0x54, 0x62, 0x3a, 0xc0, 0x89, 0x19, 0x10, 0x23, 0xc8,
    0xad, 0x4b, 0xc5, 0xe6, 0x3b, 0x8c, 0xcd, 0x1a, 0x38, 0xdb, 0x2d, 0x67, 0x9b, 0x8c, 0x9e, 0x76};
#define OSC_RCPT_N_CHECKERS 1u
static const uint8_t osc_rcpt_checker_ids[OSC_RCPT_N_CHECKERS][32] = { {
    0xd7, 0xaa, 0xe6, 0x01, 0xe7, 0x32, 0xb4, 0xb1, 0x45, 0xc7, 0x3e, 0x8d, 0x4f, 0x92, 0x76, 0x9f,
    0x56, 0xda, 0xc2, 0xe6, 0xfb, 0xa5, 0xf7, 0x7a, 0xed, 0x49, 0x0a, 0xec, 0x42, 0x9c, 0xf3, 0xba} };
#endif
