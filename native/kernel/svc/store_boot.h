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
 * never formats a blank disk with them. */
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
} ck_store_report;

#define CK_SB_E_TEST_KEYS (-2001)        /* TEST identity keys refused (hardware staging) */
#define CK_SB_E_BLOCKED_OPERATOR (-2002) /* production key source needs the operator */

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
/* Print the report lines (also used by the host test). */
void store_boot_print(const ck_store_report *r);
/* The open Store of the last store_boot_run (valid only after it returned 0;
 * host image tool and tests write further objects through it). */
ss_store *store_boot_store(void);
#endif
