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
 * KEYS: the kernel has no production key path yet. ck_store_test_keys gives
 * TEST identity (M5_ID_TEST) keys derived from a public label. They protect
 * nothing and every line printed with them says TEST. */
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
} ck_store_report;

/* TEST keys and store uuid. Public, not secret, never production. */
void ck_store_test_keys(ss_keys *k);
extern const uint8_t ck_store_test_uuid[16];

/* One boot against disk d (whole namespace, layout of dev/disk_layout.h).
 * commit is the image commit string recorded in the new boot record.
 * Prints nothing; ck_stage_store prints. */
int store_boot_run(const disk_dev *d, const ss_keys *keys, const uint8_t uuid[16], const char *commit,
                   ck_store_report *r);
/* Print the report lines (also used by the host test). */
void store_boot_print(const ck_store_report *r);
/* The open Store of the last store_boot_run (valid only after it returned 0;
 * host image tool and tests write further objects through it). */
ss_store *store_boot_store(void);
#endif
