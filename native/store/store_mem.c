/* store_mem.c -- memcpy/memmove/memset/memcmp for the freestanding build
 * (make freestanding) only. Hosted builds use libc. Compiled with
 * -fno-builtin -fno-tree-loop-distribute-patterns so the loops are not
 * turned back into calls to themselves. */
#include <stddef.h>

void *memcpy(void *restrict d, const void *restrict s, size_t n)
{
    unsigned char *a = d;
    const unsigned char *b = s;
    while (n--) *a++ = *b++;
    return d;
}

void *memmove(void *d, const void *s, size_t n)
{
    unsigned char *a = d;
    const unsigned char *b = s;
    if (a < b) {
        while (n--) *a++ = *b++;
    } else {
        while (n--) a[n] = b[n];
    }
    return d;
}

void *memset(void *d, int c, size_t n)
{
    unsigned char *a = d;
    while (n--) *a++ = (unsigned char)c;
    return d;
}

int memcmp(const void *x, const void *y, size_t n)
{
    const unsigned char *a = x, *b = y;
    for (; n; n--, a++, b++)
        if (*a != *b) return *a < *b ? -1 : 1;
    return 0;
}
