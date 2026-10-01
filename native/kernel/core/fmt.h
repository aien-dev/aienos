/* fmt.h -- freestanding printf-style formatting shared by the console and
 * the host tests. Pure: no I/O, no globals. */
#ifndef AIENOS_CK_FMT_H
#define AIENOS_CK_FMT_H

#include <stdarg.h>
#include <stddef.h>

typedef void (*ck_emit_fn)(void *ctx, char c);

/* Formats into emit(); returns the number of characters produced.
 * Supports %s %c %d %i %u %x %X %p %% with flags '-' '0', width (digits or
 * '*') and length hh h l ll z. %p prints 0x followed by lowercase hex. */
int ck_vformat(ck_emit_fn emit, void *ctx, const char *fmt, va_list ap);
int ck_vsnprintf(char *buf, size_t n, const char *fmt, va_list ap);
int ck_snprintf(char *buf, size_t n, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

#endif
