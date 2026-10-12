/* cortex_config.h -- CX_CONFIG_H for the vendored Omega Cortex store
 * (third_party/omega/rx_cortex.c) inside AIENOS. The kernel has no general
 * heap: the store's allocations come from one bounded region handed over
 * by ck_cx_heap_init (svc/cortex_journal.c). */
#ifndef AIENOS_CORTEX_CONFIG_H
#define AIENOS_CORTEX_CONFIG_H
#include <stddef.h>
void *ck_cx_alloc(size_t n);
void *ck_cx_realloc(void *p, size_t n);
void ck_cx_free(void *p);
#define CX_MALLOC(n) ck_cx_alloc(n)
#define CX_REALLOC(p, n) ck_cx_realloc((p), (n))
#define CX_FREE(p) ck_cx_free(p)
#endif
