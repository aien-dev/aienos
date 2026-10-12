/* store_boot.h -- the Store boot stage: mount the sealed C Store
 * (native/store store_sealed, M5 keyed, torn_slot anchor) on the boot disk,
 * read the boot record, bump boot_count, commit, flush.
 *
 * Proof separation (AGENTS.md section 1). A refusal names which proof
 * failed and never reformats a non-blank disk:
 *   structural  unkeyed Store::open (st_open) refused the region
 *   keyed       M5 identity/records/envelopes refused under the given keys
 *   rollback    the anti-rollback anchor refused the Store's generation
 *   io          the disk failed
 * Only an all-zero anchor + Store head counts as blank and is formatted.
 *
 * KEYS. Default (QEMU) build: ck_store_test_keys gives TEST identity
 * (M5_ID_TEST) keys derived from a public label. They protect nothing and
 * every line printed with them says TEST.
 * Hardware staging build (CK_HARDWARE_STAGING; built with CK_OWNER_PUBKEYS=
 * and CK_MACHINE_ID= files, see README "Owner provisioning"): the TEST keys
 * and TEST uuid are not compiled; the store uuid comes from the generated
 * owner provisioning header; keys come from ck_store_production_keys, the
 * BLOCKED_OPERATOR seam (K_vol is secret and needs the TRUST-1 key
 * ceremony), so the stage refuses before reading the disk. store_boot_run
 * refuses TEST-identity keys in that build before any disk access, so it
 * never formats a blank disk with them.
 *
 * RECOVERY KEYSLOT UNLOCK (P04 cut 1, ADR 0017 section 2.4 Slot 1).
 * ck_store_unlock_boot takes the operator's 32-byte raw recovery secret and
 * never any key material from the image: on a blank disk it draws K_vol,
 * salt and nonce from the kernel entropy service (RNDR; refused when RNDR
 * is), wraps K_vol into a Recovery_RawSecret descriptor (slot_id 1, HKDF
 * KEK) and commits the KeySlotManifest (kind 21, plaintext, bound by the
 * sealed transaction record) in the same first transaction as the boot
 * record. On a non-blank disk it reads the manifest before any key exists
 * (ss_keyslot_bootstrap), derives the KEK, unwraps K_vol and opens the Store
 * with PRODUCTION-class keys (owner hierarchy generation = active_key_epoch).
 * A wrong secret is refused by the AES-GCM-SIV tag before the Store is
 * touched. K_vol lives in a stack buffer for the unwrap only and is wiped.
 * Limits (cut 1): TPM Slot 0 stays BLOCKED_HARDWARE, no key rotation
 * (active_key_epoch 1), the manifest is not yet bound into the secman
 * keyslot_manifest_id field. */
#ifndef AIENOS_CK_STORE_BOOT_H
#define AIENOS_CK_STORE_BOOT_H
#include <stdint.h>
#include "disk.h"
#include "store_sealed.h"

#define CK_BOOT_KIND 0x0B00u   /* application kind of the boot record */
#define CK_BOOT_VERSION 1u
#define CK_BOOT_COMMIT_MAX 64u
#define CK_BOOT_RECORD_LEN 88u /* "AIENBOOT" u32 ver u32 0 u64 boot_count char commit[64] */

enum { CK_SB_COMMITTED = 0, CK_SB_REFUSED = 1 };

typedef struct {
    int verdict;              /* CK_SB_* */
    int formatted;            /* this run formatted a blank disk */
    int rc;                   /* first failing rc (ST_* / SS_* / disk), 0 if committed */
    const char *proof;        /* "structural" "keyed" "rollback" "io" "geometry" "record" "commit" */
    const char *step;         /* what was being done */
    int rb;                   /* SS_RB_* from the open */
    uint64_t gen_open, gen_commit;
    uint64_t boot_count_prev, boot_count_new;
    char prev_commit[CK_BOOT_COMMIT_MAX + 1];
    uint64_t store_base_lba, store_units, anchor_lba;
    uint8_t identity_class;   /* identity class of the keys given (M5_ID_*) */
    int unlocked_genesis;     /* ck_store_unlock_boot: this run created the keyslot manifest */
    const char *key_source;   /* ck_store_unlock_boot: "recovery-keyslot" */
} ck_store_report;

#define CK_SB_E_TEST_KEYS (-2001)        /* TEST identity keys refused (hardware staging) */
#define CK_SB_E_BLOCKED_OPERATOR (-2002) /* production key source needs the operator */
#define CK_SB_E_NO_KEYSLOT (-2003)       /* non-blank disk carries no KeySlotManifest (not a production Store) */
#define CK_SB_E_SECRET_REJECTED (-2004)  /* recovery secret did not unwrap K_vol (tag failed) */
#define CK_SB_E_ENTROPY (-2005)          /* genesis refused: kernel entropy service refused */
#define CK_SB_E_KEYSLOT_BAD (-2006)      /* manifest decoded but has no usable recovery descriptor / wrong uuid */
#define CK_SB_SECRET_LEN 32u

/* TEST keys and store uuid. Public, not secret, never production. Not
 * compiled in a CK_HARDWARE_STAGING build. */
void ck_store_test_keys(ss_keys *k);
extern const uint8_t ck_store_test_uuid[16];

/* Production Store keys. BLOCKED_OPERATOR: always zeroes k and returns
 * CK_SB_E_BLOCKED_OPERATOR until the TRUST-1 ceremony provides a K_vol source
 * (Gate 6 TPM Slot 0 unwrap or Slot 1 recovery KEK). Never falls back. */
int ck_store_production_keys(ss_keys *k);

/* 1 if keys of this identity class may open/format a Store in this build:
 * PRODUCTION always; TEST only when hardware_staging is 0. */
int ck_store_keys_admissible(const ss_keys *k, int hardware_staging);

/* One boot against disk d (the AIENOS partition view of dev/disk_part.h in the
 * kernel, a whole file in host tests; layout of dev/disk_layout.h, relative to d).
 * commit is the image commit string recorded in the new boot record.
 * Prints nothing; ck_stage_store prints. */
int store_boot_run(const disk_dev *d, const ss_keys *keys, const uint8_t uuid[16], const char *commit,
                   ck_store_report *r);
/* Same with the build policy explicit (store_boot_run passes 1 in a
 * CK_HARDWARE_STAGING build, else 0); the host test drives both. */
int store_boot_run_policy(const disk_dev *d, const ss_keys *keys, const uint8_t uuid[16], const char *commit,
                          int hardware_staging, ck_store_report *r);
/* Recovery keyslot unlock + boot (see the header comment). secret is the
 * operator's raw 32-byte recovery secret. expect_uuid (optional) must equal
 * the manifest's store_uuid and is the uuid of a formatted blank disk; when
 * NULL a blank disk gets a random uuid and any manifest uuid is accepted.
 * hardware_staging as store_boot_run_policy. Prints nothing. */
int ck_store_unlock_boot(const disk_dev *d, const uint8_t secret[CK_SB_SECRET_LEN], const uint8_t *expect_uuid,
                         const char *commit, int hardware_staging, ck_store_report *r);
/* Print the report lines (also used by the host test). */
void store_boot_print(const ck_store_report *r);
/* The open Store of the last store_boot_run (valid only after it returned 0;
 * host image tool and tests write further objects through it). */
ss_store *store_boot_store(void);
#endif
