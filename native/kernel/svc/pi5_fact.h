/* pi5_fact.h -- the Pi 5 Cortex fact stage (PI5-5, CK_PI5_FACT, QUALIFICATION ONLY).
 *
 * After the Store stage opened the sealed Store through the Slot 1 recovery path, this stage does what
 * the service lifecycle's `remember` and `facts` verbs do (core/lifecycle.c, QEMU rows 179-181), with
 * the same Cortex records on the same journal ('CJ' chunks, one record = one sealed transaction):
 *   - a fact request from the card (core/fact_req.h): open or create the journal, append one CX_CLAIM
 *     about the owner subject, read it back, print it with the Store generation that committed it;
 *   - no request: replay the journal, re-check every digest and the chain, print each fact with the
 *     Store generation it was committed at. A disk with no journal prints "none" and writes nothing.
 * The Store not being open (wrong recovery secret) prints the refusal and recalls nothing. */
#ifndef AIENOS_CK_PI5_FACT_H
#define AIENOS_CK_PI5_FACT_H
#include "store_sealed.h"
#include "../core/fact_req.h"

enum { CK_FACT_MODE_REMEMBER = 1, CK_FACT_MODE_RECALL = 2, CK_FACT_MODE_NOSTORE = 3 };

struct ck_fact_result {
    int mode;           /* CK_FACT_MODE_* */
    uint64_t records;   /* Cortex records in the journal after the stage */
    uint64_t shown;     /* facts printed */
    uint64_t last_id;   /* newest fact id (0: none) */
    uint64_t last_gen;  /* Store generation that committed the newest fact */
    int chain_ok;
};

/* s: the open writable Store, or NULL when the Store is not open. req: the card request (state FOUND
 * remembers it; any other state recalls). Returns 0 when the stage did what the mode says; <0 on a
 * Cortex or Store failure (printed). NULL s returns 0 with mode NOSTORE (a refusal, not a failure of
 * this stage). */
int ck_pi5_fact_run(ss_store *s, const struct ck_fact_req_boot *req, struct ck_fact_result *out);
#endif
