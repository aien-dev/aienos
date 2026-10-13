/* pi5_wdt.c -- see pi5_wdt.h. Pi 5 build only. */
#ifndef CK_PI5
#error "pi5_wdt.c is Raspberry Pi 5 only (CK_PI5); never build it for another board"
#endif
#include "pi5_wdt.h"
#include "ck.h"

static volatile uint8_t *pm;

static uint32_t rd(uint32_t off) { return *(volatile uint32_t *)(pm + off); }
static void wr(uint32_t off, uint32_t v) { *(volatile uint32_t *)(pm + off) = v; }

int ck_pi5_wdt_arm(void)
{
    pm = ck_mmio_map(CK_PI5_PM_PHYS, 0x1000);
    if (!pm)
        return -1;
    ck_pi5_wdt_pet();
    wr(CK_PI5_PM_RSTC, ck_pi5_rstc_arm(rd(CK_PI5_PM_RSTC)));
    return 0;
}

void ck_pi5_wdt_pet(void)
{
    if (pm)
        wr(CK_PI5_PM_WDOG, ck_pi5_wdog_value(CK_PI5_WDT_S));
}

void ck_pi5_wdt_stop(void)
{
    if (pm)
        wr(CK_PI5_PM_RSTC, CK_PI5_PM_PASSWORD | CK_PI5_PM_RSTC_RESET);
}
