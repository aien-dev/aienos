/* cortex_journal.h -- the Omega Cortex journal over the AIENOS sealed Store
 * (native v1 plan P06: "an AIENOS persistence adapter for canonical Omega
 * CxStore"; CURRENT_EXECUTION_PLAN addendum conflict 3: the native
 * continuity record of N2/N3 is the sealed C Store written and read through
 * this adapter).
 *
 * The Cortex store (third_party/omega/rx_cortex.c, built by svc/cortex_store.c)
 * reaches its journal only through CxJournalOps: a byte stream it appends
 * records to and reads back whole at open. Here the stream is the ordered
 * sequence of sealed Store objects of kind CK_CJ_KIND ('CJ'): one append is
 * ONE sealed transaction of 1..SS_MAX_OBJECTS chunks of <= SS_MAX_PLAINTEXT
 * bytes, so a record is on the disk entirely (generation G+1 durable, anchor
 * advanced) or not at all. That is the durability-before-success rule and
 * why a torn tail cannot exist: truncate accepts only the current length.
 * One semantic writer: the kernel's single ck_cj context; a second writable
 * open while one is held is CX_ERR_WRITER. Chain verification, digests and
 * replay are Omega's, unchanged: the backend stores bytes and never
 * interprets them. There is no second Cortex: the sealed Store on the disk
 * IS the Cortex of this subject.
 *
 * Declared limits (v1): a journal of at most CK_CJ_MAX_CHUNKS chunks
 * (CK_CJ_MAX_CHUNKS * 16 KiB), one record of at most SS_MAX_OBJECTS *
 * SS_MAX_PLAINTEXT bytes (larger: CX_ERR_IO, nothing written), replay reads
 * the whole journal into the Cortex heap, the heap is a bump allocator that
 * frees nothing until ck_cx_heap_init is called again (sized by the caller;
 * the kernel hands over CK_CX_HEAP_PAGES frames). Kernel use: the
 * lifecycle's `remember` and `facts` verbs (core/lifecycle.c, P06 cut 4). */
#ifndef AIENOS_CORTEX_JOURNAL_H
#define AIENOS_CORTEX_JOURNAL_H

#include <stddef.h>
#include <stdint.h>

#include "../third_party/omega/rx_cortex.h"
#include "store_sealed.h"

#define CK_CJ_KIND 0x434au       /* 'CJ': one journal chunk, sealed */
#define CK_CJ_MAX_CHUNKS 64u     /* 1 MiB of journal */
#define CK_CJ_MAX_RECORD (SS_MAX_OBJECTS * SS_MAX_PLAINTEXT) /* 128 KiB per append */
#define CK_CX_HEAP_PAGES 1024u   /* 4 MiB: the whole journal plus its replay */
#define CK_CX_SUBJECTS 2u        /* subject 0: the owner (facts); 1: reserved for ALLEN */
#define CK_CX_FACT_SUBJECT 0u    /* remembered facts: lifecycle `remember` and the Pi fact stage */

typedef struct {
    uint8_t sid[32];
    uint64_t gen, seq;
    uint32_t len;
} ck_cj_chunk;

typedef struct {
    ss_store *s;
    int writer;                  /* 1 while a writable handle is open */
    int ro_handles;
    size_t len;                  /* journal bytes = sum of chunk lengths */
    uint32_t nchunks;
    ck_cj_chunk chunks[CK_CJ_MAX_CHUNKS];
    uint8_t buf[SS_MAX_PLAINTEXT];
    uint32_t appends, reads, refused; /* evidence */
} ck_cj;

/* Bind the context to an open sealed Store (the index is rebuilt at every
 * journal open from the Store's verified claims). */
void ck_cj_init(ck_cj *j, ss_store *s);
extern const CxJournalOps ck_cx_journal_store;

/* The Cortex heap (CX_MALLOC of cortex_config.h): one region, bump
 * allocation, realloc copies, free is a no-op. Re-init forgets everything. */
void ck_cx_heap_init(void *base, size_t size);
void ck_cx_heap_stats(size_t *used, size_t *peak, size_t *size);

#endif /* AIENOS_CORTEX_JOURNAL_H */
