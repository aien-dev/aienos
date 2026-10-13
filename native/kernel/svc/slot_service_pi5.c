/* slot_service_pi5.c -- the slot service of the Pi resident-lifecycle qualification image (CK_PI5_LIFECYCLE).
 * The Pi card has no SLOTLDR.EFI image slots (P11 is the NVMe/GB10 layout), so there is nothing to promote,
 * abandon or update: the lifecycle's four slot hooks (svc/slot_service.h) are present and say so. The real
 * svc/slot_service.c needs the NVMe slot and inbox disks and is not linked. Freestanding. */
#include "ck.h"
#include "slot_service.h"

#ifndef CK_PI5_LIFECYCLE
#error "slot_service_pi5.c is only part of the CK_PI5_LIFECYCLE qualification image"
#endif

void ck_slot_service_start(int healthy)
{
    (void)healthy;
    ck_puts("slot: no image slots on the Pi qualification image (no SLOTLDR.EFI): slot service idle, nothing written\n");
}

void ck_slot_service_health(int healthy)
{
    (void)healthy;
}

void ck_slot_service_stop(void) {}

void ck_slot_service_update(const char *arg, size_t len)
{
    (void)arg;
    (void)len;
    ck_puts("lifecycle: update REFUSED reason=\"no image slots on the Pi qualification image\"\n");
}
