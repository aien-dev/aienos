/* test_heap.c -- kernel heap: alignment, zeroing, reuse, coalescing,
 * exhaustion and rejection of bad frees. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "ck_test.h"
#include "heap.h"

int main(void)
{
    size_t size = 64 * 1024;
    uint8_t *mem = aligned_alloc(4096, size);
    struct ck_heap h;
    CHECK(ck_heap_init(&h, mem, size) == 0);
    size_t free0 = ck_heap_free_bytes(&h);
    uint8_t *a = ck_heap_alloc(&h, 1), *b = ck_heap_alloc(&h, 100), *c = ck_heap_alloc(&h, 4000);
    CHECK(a && b && c && ((uintptr_t)a & 15) == 0 && ((uintptr_t)b & 15) == 0 && ((uintptr_t)c & 15) == 0);
    CHECK(a + 1 <= b || b + 100 <= a);
    memset(b, 0xab, 100);
    CHECK(ck_heap_free(&h, b) == 0);
    CHECK(ck_heap_free(&h, b) == -1); /* double free */
    CHECK(ck_heap_free(&h, a + 8) == -1); /* interior pointer */
    CHECK(ck_heap_free(&h, mem + size + 64) == -1); /* foreign */
    uint8_t *d = ck_heap_alloc(&h, 100);
    int zero = 1;
    for (int i = 0; i < 100; i++)
        zero &= d[i] == 0;
    CHECK(d == b && zero);
    CHECK(ck_heap_check(&h) == 0);
    CHECK(ck_heap_free(&h, a) == 0 && ck_heap_free(&h, c) == 0 && ck_heap_free(&h, d) == 0);
    CHECK(ck_heap_free_bytes(&h) == free0); /* fully coalesced */
    CHECK(ck_heap_alloc(&h, size) == NULL);
    CHECK(ck_heap_alloc(&h, (size_t)-1) == NULL);
    void *big = ck_heap_alloc(&h, free0 - 64);
    CHECK(big != NULL);
    CHECK(ck_heap_check(&h) == 0);
    /* Corrupt a header: the walk notices. */
    ((uint64_t *)big)[-1] ^= 1;
    CHECK(ck_heap_check(&h) != 0);
    free(mem);
    return ck_t_verdict("CK_HEAP");
}
