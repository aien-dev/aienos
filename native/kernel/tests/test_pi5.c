/* test_pi5.c -- Pi 5 build register values (dev/pi5_wdt.h) against the
 * Linux bcm2835_wdt.c sequence: PM_WDOG = password | (secs << 16 & 0xfffff),
 * PM_RSTC = password | (cur & ~0x30) | 0x20. */
#include "ck_test.h"
#include "../dev/pi5_wdt.h"

int main(void)
{
    CHECK(ck_pi5_wdog_value(15) == (0x5a000000u | 0x000f0000u));
    CHECK(ck_pi5_wdog_value(1) == 0x5a010000u);
    CHECK(ck_pi5_wdog_value(16) == 0x5a000000u); /* 16 s does not fit: shows why the default is 15 */
    CHECK(CK_PI5_WDT_S <= 15u && CK_PI5_WDT_S >= 1u);
    CHECK(ck_pi5_rstc_arm(0x00000000u) == 0x5a000020u);
    CHECK(ck_pi5_rstc_arm(0xffffffffu) == (0x5a000000u | 0xffffffcfu | 0x20u));
    CHECK(ck_pi5_rstc_arm(0x00000030u) == 0x5a000020u); /* old WRCFG bits cleared first */
    CHECK(CK_PI5_PM_PHYS == 0x107d200000ull);
    return ck_t_verdict("test_pi5");
}
