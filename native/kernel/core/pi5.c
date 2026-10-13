/* pi5.c -- Raspberry Pi 5 board glue (CK_PI5 build only).
 *
 *   ck_pi5_start         arm the PM watchdog (dev/pi5_wdt.c), bring up the
 *                        microSD controller with native/disk/disk_sdhci.c
 *   ck_pi5_stage         pet the watchdog at every boot stage
 *   ck_pi5_before_reset  write the RAM console log (core/klog.c) into the
 *                        card's log slot (core/klog_slot.h), then reset
 *
 * The SD host address is fixed for this board: the firmware's ACPI DSDT
 * (\_SB.SDC0, dumped by AIENOS-PI5-ACPI-0, 2026-10-13) computes its _CRS in a
 * method the kernel's static scanner does not run, and gives the same range
 * as Linux bcm2712.dtsi sdio1 (mmc@fff000, 0x260 bytes, soc window
 * 0x0 -> 0x10_0000_0000). Its clock is clk_emmc2, a fixed 200 MHz
 * (bcm2712.dtsi); the CAPABILITIES base clock is printed beside it. The
 * driver is PIO only: no DMA, so the missing SMMU does not matter here. */
#ifndef CK_PI5
#error "pi5.c is Raspberry Pi 5 only (CK_PI5)"
#endif
#include "ck_internal.h"
#include "klog.h"
#include "klog_boot.h"
#include "klog_slot.h"
#include "../dev/pi5_wdt.h"
#include "disk.h"
#include "disk_sdhci.h"
#include "pi5_marker.h"
#include "../dev/disk_part.h"

#define PI5_SD_PHYS 0x1000fff000ull
#define PI5_SD_CLOCK_HZ 200000000u

static volatile uint8_t *sd_regs;
static sdhci_card sd;
static int sd_up;
static ck_part part; /* the AIENOS partition view, once found (the Store stage and the marker use it) */

static uint32_t sd_r32(void *c, uint32_t o) { (void)c; return *(volatile uint32_t *)(sd_regs + o); }
static void sd_w32(void *c, uint32_t o, uint32_t v) { (void)c; *(volatile uint32_t *)(sd_regs + o) = v; }
static void sd_delay(void *c, uint32_t us) { (void)c; ck_udelay(us); }
static const sdhci_ops sd_ops = {0, sd_r32, sd_w32, sd_delay};

void ck_pi5_start(void)
{
    if (ck_pi5_wdt_arm() == 0)
        ck_printf("pi5_watchdog: armed %u s (PM block 0x%llx), petted at every stage\n", (unsigned)CK_PI5_WDT_S,
                  (unsigned long long)CK_PI5_PM_PHYS);
    else
        ck_printf("pi5_watchdog: FAIL map 0x%llx; a hang now needs a power cycle\n",
                  (unsigned long long)CK_PI5_PM_PHYS);
    sd_regs = ck_mmio_map(PI5_SD_PHYS, 0x1000);
    if (!sd_regs) {
        ck_printf("pi5_sd: FAIL map 0x%llx\n", (unsigned long long)PI5_SD_PHYS);
        return;
    }
    uint32_t caps = sd_r32(0, 0x40), ver = sd_r32(0, 0xfc) >> 16;
    ck_printf("pi5_sd: host 0x%llx version=0x%x caps=0x%08x caps_base_mhz=%u using %u MHz (clk_emmc2)\n",
              (unsigned long long)PI5_SD_PHYS, ver, caps, (caps >> 8) & 0xff, PI5_SD_CLOCK_HZ / 1000000u);
    sdhci_cfg cfg = {PI5_SD_CLOCK_HZ, 0, 1, 0};
    int rc = sdhci_init(&sd, &sd_ops, &cfg);
    if (rc) {
        ck_printf("pi5_sd: init FAIL rc=%d last_cmd=%d last_int=0x%08x\n", rc, sd.last_cmd, sd.last_int);
        return;
    }
    sd_up = 1;
    ck_printf("pi5_sd: card ready spec=%u card_hz=%u high_capacity=%d blocks=%llu (%llu MiB) rca=0x%x bus=4bit\n",
              sd.spec, sd.card_hz, sd.high_capacity, (unsigned long long)sd.blocks,
              (unsigned long long)(sd.blocks / 2048u), sd.rca);
    /* Read-only check: sector 0 of the card is an MBR (0x55 0xaa). */
    static uint8_t s0[512] __attribute__((aligned(64)));
    rc = disk_read(&sd.dev, 0, 1, s0);
    ck_printf("pi5_sd: read sector 0 rc=%d signature=%02x%02x (%s)\n", rc, s0[510], s0[511],
              rc == 0 && s0[510] == 0x55 && s0[511] == 0xaa ? "MBR ok" : "no MBR signature");
    /* Step 3: the AIENOS partition through the same GPT partition view the NVMe path uses (dev/disk_part.c),
     * then the scratch marker at its end (core/pi5_marker.c): formatted on a blank card, reopened after a reboot. */
    ck_gpt_info gi;
    rc = ck_gpt_find_aienos(&sd.dev, &part, &gi);
    if (rc) {
        ck_printf("pi5_part: no AIENOS partition, refusing writes (%s, rc=%d)\n", ck_gpt_strerror(rc), rc);
        return;
    }
    ck_printf("pi5_part: AIENOS partition first_lba=%llu blocks=%llu (%llu MiB) entries_used=%u index=%u via GPT (CRC32 primary+backup ok)\n",
              (unsigned long long)part.first_lba, (unsigned long long)part.blocks,
              (unsigned long long)(part.blocks / 2048u), gi.used, gi.part_index);
#ifdef CK_PI5_STORE
    /* The sealed Store owns this partition (units 4..U-2 and the probe unit U-1): the scratch marker, which
     * lives in the same tail units, is not written. */
    ck_puts("pi5_store_layer: marker skipped (CK_PI5_STORE: the sealed Store stage owns the partition)\n");
#else
    static uint8_t mbuf[CK_PI5_MARKER_BUF_BYTES] __attribute__((aligned(64)));
    uint64_t gen = 0;
    rc = ck_pi5_marker_run(&part.dev, mbuf, &gen);
    if (rc > 0)
        ck_printf("pi5_store_layer: %s generation=%llu region=%u sectors at partition block %llu\n",
                  ck_pi5_marker_strerror(rc), (unsigned long long)gen, CK_PI5_MARKER_SECS,
                  (unsigned long long)(part.blocks - CK_PI5_MARKER_SECS));
    else
        ck_printf("pi5_store_layer: FAIL rc=%d (%s)\n", rc, ck_pi5_marker_strerror(rc));
#endif
}

void ck_pi5_stage(const char *name)
{
    (void)name;
    ck_pi5_wdt_pet();
}

static uint64_t commit_prefix(void)
{
    const char *c = ck_commit();
    uint64_t v = 0;
    for (int i = 0; i < 16 && c[i]; i++) {
        char x = c[i];
        unsigned d = x >= '0' && x <= '9' ? (unsigned)(x - '0') : x >= 'a' && x <= 'f' ? (unsigned)(x - 'a' + 10) : 16;
        if (d > 15)
            break;
        v = v << 4 | d;
    }
    return v;
}

static char text[CK_KLOG_MAX + 512] __attribute__((aligned(64)));
static struct ck_klog_hdr hdr __attribute__((aligned(64)));

/* 0 written and read back; 1 nothing to do (no slot / no card); -1 refused or failed. */
static int klog_write(void)
{
    const struct ck_klog_boot *kb = &ck_klog_boot;
    const struct ck_klog_map *m = &kb->map;
    const char *why = 0;
    if (kb->state != CK_KLOG_BOOT_FOUND) {
        ck_printf("klog_card: skipped (stub state %d: no checked KLOG.MAP)\n", kb->state);
        return 1;
    }
    if (!sd_up) {
        ck_puts("klog_card: skipped (SD card not ready)\n");
        return 1;
    }
    if (m->lba + m->count > sd.blocks || kb->disk_last_block + 1u != sd.blocks) {
        ck_printf("klog_card: refused (card has %llu sectors, firmware saw %llu, slot ends at %llu)\n",
                  (unsigned long long)sd.blocks, (unsigned long long)(kb->disk_last_block + 1u),
                  (unsigned long long)(m->lba + m->count));
        return -1;
    }
    if (disk_read(&sd.dev, m->lba, 1, (uint8_t *)&hdr) != DISK_OK || ck_klog_hdr_match(&hdr, m, &why)) {
        ck_printf("klog_card: refused (slot header check: %s)\n", why ? why : "read failed");
        return -1;
    }
    ck_printf("klog_card: slot verified by the kernel's own SD driver (lba=%llu sectors=%llu); writing\n",
              (unsigned long long)m->lba, (unsigned long long)m->count);
    uint64_t cap = ck_klog_slot_bytes(m);
    size_t n = ck_klog_read(text, cap < CK_KLOG_MAX ? (size_t)cap : CK_KLOG_MAX);
    uint32_t secs = (uint32_t)((n + 511u) / 512u);
    for (size_t i = n; i < (size_t)secs * 512u; i++)
        text[i] = 0;
    if (secs && disk_write(&sd.dev, m->lba + 1u, secs, (const uint8_t *)text) != DISK_OK)
        return -1;
    if (disk_flush(&sd.dev) != DISK_OK)
        return -1;
    ck_klog_hdr_written(&hdr, m, n, ck_klog_total(), commit_prefix(), ck_stage_name());
    if (disk_write(&sd.dev, m->lba, 1, (const uint8_t *)&hdr) != DISK_OK || disk_flush(&sd.dev) != DISK_OK)
        return -1;
    static struct ck_klog_hdr back __attribute__((aligned(64)));
    if (disk_read(&sd.dev, m->lba, 1, (uint8_t *)&back) != DISK_OK)
        return -1;
    const uint8_t *a = (const uint8_t *)&hdr, *b = (const uint8_t *)&back;
    for (unsigned i = 0; i < sizeof hdr; i++)
        if (a[i] != b[i])
            return -1;
    return 0;
}

void ck_pi5_before_reset(void)
{
    static int once;
    if (once++)
        return; /* a fault inside the write resets without a second try */
    ck_pi5_wdt_pet();
    int rc = klog_write();
    /* This line reaches the screen and UART only: the card copy ends above. */
    ck_printf("klog_card: %s\n", rc == 0 ? "written and read back" : rc > 0 ? "not written" : "FAILED");
    ck_pi5_wdt_pet();
}

#ifdef CK_PI5_STORE
/* Hand the card's AIENOS partition view to the sealed Store stage (svc/store_boot.c ck_stage_store), the
 * same stage the QEMU "full" image runs. Tier: SEED-0B-PI5, the Pi counterpart of SEED-0B-QEMU. The Store
 * keys are the labelled TEST keys (ck_store_test_keys); the production key source stays BLOCKED_OPERATOR
 * and is not touched here. CK_HARDWARE_STAGING and CK_PI5 cannot be combined (Makefile), so no hardware
 * staging image can ever carry this. */
const disk_dev *ck_dev_boot_disk(void)
{
    static int said;
    if (!said++)
        ck_puts("pi5_store_tier: SEED-0B-PI5 qualification only: Store keys are the public TEST keys, "
                "Store uuid is the TEST uuid, no production keys, not a production Store\n");
    return sd_up && part.valid ? &part.dev : 0;
}

/* The SD card has no bus master or SMMU stream to revoke: nothing to release. */
void ck_dev_nvme_release(void) {}
#endif
