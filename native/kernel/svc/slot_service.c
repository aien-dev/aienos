/* slot_service.c -- kernel-side promotion and abandon of AIENOS image slots
 * (P11 cut 2b). Contract in slot_service.h. Freestanding. */
#include "ck.h"
#include "handoff.h"
#include "devices.h"
#include "disk.h"
#include "disk_part.h"
#include "store_sealed.h"
#include "slot_service.h"
#include "../../boot/slot_control.h"

#ifndef CK_SERVICE
#error "slot_service.c is only part of a CK_SERVICE=1 image"
#endif

/* Mirrors mm/frames.h struct ck_efi_desc (UEFI EFI_MEMORY_DESCRIPTOR). */
struct slot_efi_desc {
    uint32_t type;
    uint32_t pad;
    uint64_t phys;
    uint64_t virt;
    uint64_t pages;
    uint64_t attr;
};

static struct ck_slot_boot_record g_rec;
static int g_rec_state;            /* 0: none found, 1: valid, -1: refused */
static const char *g_rec_why;
static int g_wait;                 /* 1: candidate waits for health */
static int g_done;                 /* 1: decided for this boot (written or refused) */
static uint8_t g_unit[CK_SLOT_UNIT] __attribute__((aligned(4096)));
/* 4 KiB each: static, never on the kernel stack. */
static struct ck_slot_control ctl, out;
static struct ck_slot_manifest man;

/* Called from ck_kernel_entry after ck_handoff_check, while the firmware's
 * identity map is still live: the record page is not a RAM type the kernel
 * maps (mm/mmu.c ram_type), so it is read here or never. */
void ck_slot_boot_capture(const struct ck_handoff *h)
{
    unsigned found = 0;
    const struct slot_efi_desc *hit = 0;
    if (!h || !h->memory_map || h->desc_size < sizeof(struct slot_efi_desc)) return;
    for (uint64_t off = 0; off + h->desc_size <= h->map_size; off += h->desc_size) {
        const struct slot_efi_desc *d = (const struct slot_efi_desc *)(uintptr_t)(h->memory_map + off);
        if (d->type == CK_SLOT_BOOT_MEMTYPE) {
            found++;
            hit = d;
        }
    }
    if (found == 0) return;
    if (found != 1 || !hit->pages || !hit->phys || (hit->phys & 4095u)) {
        g_rec_state = -1;
        g_rec_why = found != 1 ? "more than one boot record page" : "boot record page geometry";
        return;
    }
    const uint8_t *src = (const uint8_t *)(uintptr_t)hit->phys;
    uint8_t *dst = (uint8_t *)&g_rec;
    for (unsigned i = 0; i < sizeof g_rec; i++) dst[i] = src[i];
    g_rec_state = ck_slot_boot_check(&g_rec, &g_rec_why) == 0 ? 1 : -1;
}

static void say_refuse(const char *why)
{
    ck_printf("slot: REFUSED %s: control record not written\n", why);
}

/* One evaluation: read the control record and the started slot's manifest
 * from the slots partition, decide, commit PROMOTE / ABANDON. */
static void evaluate(int healthy)
{
    int prc = 0;
    const disk_dev *d = ck_dev_slots_disk(&prc);
    if (!d) {
        g_done = 1;
        say_refuse(prc == CK_DEV_NO_BOOT_DISK ? "no bound boot disk" : ck_gpt_strerror(prc));
        return;
    }
    if (d->block_size != 512 && d->block_size != 4096) {
        g_done = 1;
        say_refuse("slots partition block size");
        return;
    }
    uint32_t bpu = CK_SLOT_UNIT / d->block_size;
    uint64_t units = d->block_count / bpu, cap = ck_slot_cap_units(units);
    if (cap < CK_SLOT_MIN_CAP_UNITS) {
        g_done = 1;
        say_refuse("slots partition too small");
        return;
    }
    ts_device tdev;
    ts_region r;
    ts_slot_state tss[2];
    uint64_t seq = 0;
    ss_ts_device(d, &tdev);
    int trc = ts_open(&r, &tdev, 0);
    if (trc == TS_OK) trc = ts_recover(&r, (uint8_t *)&ctl, &seq, tss);
    int have_ctl = trc == TS_OK;
    if (have_ctl && seq != g_rec.control_seq) {
        g_done = 1;
        ck_printf("slot: REFUSED control record moved since the loader read it (seq %llu on disk, %llu in the boot "
                  "record): control record not written\n",
                  (unsigned long long)seq, (unsigned long long)g_rec.control_seq);
        return;
    }
    uint64_t mlba = ck_slot_manifest_unit(g_rec.boot_slot, cap) * bpu;
    int have_man = disk_read(d, mlba, bpu, g_unit) == DISK_OK;
    if (have_man) {
        uint8_t *m = (uint8_t *)&man;
        for (unsigned i = 0; i < sizeof man; i++) m[i] = g_unit[i];
    }
    const char *why = 0;
    enum ck_slot_action a =
        ck_slot_kernel_action(&g_rec, have_ctl ? &ctl : 0, have_man ? &man : 0, healthy, &out, &why);
    g_wait = a == CK_SLOT_A_WAIT;
    if (a == CK_SLOT_A_WAIT) {
        ck_printf("slot: candidate %c waiting for health (tries left %u): not promoted yet\n",
                  'A' + g_rec.boot_slot, (unsigned)ctl.tries_remaining);
        return;
    }
    g_done = 1;
    if (a == CK_SLOT_A_REFUSE) {
        say_refuse(why ? why : "refused");
        return;
    }
    if (a == CK_SLOT_A_NONE) {
        ck_printf("slot: nothing to write (%s) active=%c\n", why ? why : "steady", 'A' + ctl.active_slot);
        return;
    }
    uint64_t nseq = 0;
    int crc = ck_slot_control_commit(&r, &out, &nseq);
    if (crc != TS_OK) {
        ck_printf("slot: %s FAILED control commit rc=%d (the previous record stays authoritative)\n",
                  ck_slot_action_text(a), crc);
        return;
    }
    if (a == CK_SLOT_A_PROMOTE)
        ck_printf("slot: promoted slot %c to active generation=%llu floor=%llu seq=%llu (health: store open, "
                  "continuity committed, lifecycle READY)\n",
                  'A' + out.active_slot, (unsigned long long)out.last_good_generation,
                  (unsigned long long)out.generation_floor, (unsigned long long)nseq);
    else
        ck_printf("slot: candidate abandoned (marked failed) active=%c stays seq=%llu\n", 'A' + out.active_slot,
                  (unsigned long long)nseq);
}

void ck_slot_service_start(int healthy)
{
    if (g_rec_state == 0) {
        g_done = 1;
        ck_puts("slot: no boot record (not started by SLOTLDR.EFI): slot service idle, nothing written\n");
        return;
    }
    if (g_rec_state < 0) {
        g_done = 1;
        say_refuse(g_rec_why ? g_rec_why : "boot record invalid");
        return;
    }
    ck_printf("slot: booted slot %c reason=%s generation=%llu tries=%u control_seq=%llu\n", 'A' + g_rec.boot_slot,
              ck_slot_reason_text((enum ck_slot_reason)g_rec.reason), (unsigned long long)g_rec.generation,
              (unsigned)g_rec.tries, (unsigned long long)g_rec.control_seq);
    evaluate(healthy);
}

void ck_slot_service_health(int healthy)
{
    if (g_done || !g_wait || !healthy) return;
    evaluate(healthy);
}

void ck_slot_service_stop(void)
{
    if (g_wait && !g_done)
        ck_printf("slot: candidate %c NOT promoted this boot (health milestone not reached); the loader counts "
                  "its tries down\n",
                  'A' + g_rec.boot_slot);
}
