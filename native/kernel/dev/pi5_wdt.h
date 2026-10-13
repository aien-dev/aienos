/* pi5_wdt.h -- Raspberry Pi 5 (BCM2712) PM watchdog, Pi 5 build only
 * (CK_PI5). Armed at kernel start and petted at every boot stage
 * (ck_set_stage), so a kernel that stops making progress resets the board
 * within CK_PI5_WDT_S seconds; the Pi then starts its normal system (the
 * one-shot tryboot flag is already cleared). Never built for the Spark or
 * QEMU: the address below is BCM2712-only.
 * Registers and sequence: Linux drivers/watchdog/bcm2835_wdt.c
 * (bcm2835_wdt_start / _stop); address: bcm2712.dtsi watchdog@7d200000 in
 * the soc bus window 0x0 -> 0x10_0000_0000. */
#ifndef AIENOS_CK_PI5_WDT_H
#define AIENOS_CK_PI5_WDT_H
#include <stdint.h>

#define CK_PI5_PM_PHYS 0x107d200000ull
#define CK_PI5_PM_RSTC 0x1cu
#define CK_PI5_PM_WDOG 0x24u
#define CK_PI5_PM_PASSWORD 0x5a000000u
#define CK_PI5_PM_WDOG_TIME_SET 0x000fffffu
#define CK_PI5_PM_RSTC_WRCFG_CLR 0xffffffcfu
#define CK_PI5_PM_RSTC_WRCFG_FULL_RESET 0x00000020u
#define CK_PI5_PM_RSTC_RESET 0x00000102u
#ifndef CK_PI5_WDT_S
#define CK_PI5_WDT_S 15u /* the counter holds at most 0xfffff ticks of 1/65536 s: just under 16 s */
#endif

/* Register values (pure, host-tested). */
static inline uint32_t ck_pi5_wdog_value(uint32_t secs)
{
    return CK_PI5_PM_PASSWORD | ((secs << 16) & CK_PI5_PM_WDOG_TIME_SET);
}
static inline uint32_t ck_pi5_rstc_arm(uint32_t cur)
{
    return CK_PI5_PM_PASSWORD | (cur & CK_PI5_PM_RSTC_WRCFG_CLR) | CK_PI5_PM_RSTC_WRCFG_FULL_RESET;
}

/* Maps the PM block and arms the watchdog. 0, or -1 if the map failed. */
int ck_pi5_wdt_arm(void);
/* Restarts the countdown (no-op before arm). */
void ck_pi5_wdt_pet(void);
/* Stops the watchdog (before an orderly PSCI reset or a long operator hold). */
void ck_pi5_wdt_stop(void);
#endif
