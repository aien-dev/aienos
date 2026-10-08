/* test_osc_admit.c -- host test for the kernel reporting in core/osc_admit.c.
 * Covers the one case the QEMU gate cannot build: a Store entry over the Store size limit is never read
 * (the Store writer refuses to make one), so the loader cannot tell whether it is an OSCUNIT. It must
 * still say, on the osc_unit: channel, that it was refused RESOURCE_UNAVAILABLE, and count it as oversize.
 * ck_printf is replaced by a buffer so the exact lines can be checked. */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "ck_test.h"
#include "osc_admit.h"

static char out[4096];
static size_t outn;

void ck_printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out + outn, sizeof out - outn, fmt, ap);
    va_end(ap);
    if (n > 0) outn += (size_t)n;
}

int main(void)
{
    ck_osc_oversize("big.unit", 667648);
    CHECK(strstr(out, "osc_unit: big.unit REFUSED code=30 name=RESOURCE_UNAVAILABLE reason=staging_too_large "
                      "bytes=667648 limit=655360 ") != NULL);
    outn = 0; out[0] = 0;
    ck_osc_summary();
    CHECK(strstr(out, "osc_units: seen=0 accepted=0 refused=0 oversize=1 (admission only, nothing launched)\n") != NULL);
    return ck_t_verdict("test_osc_admit");
}
