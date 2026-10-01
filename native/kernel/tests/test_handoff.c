/* test_handoff.c -- host tests of core/handoff_check.c against the handoff
 * contract (docs/BOOT_HANDOFF_CONTRACT.md sections 6 and 9).
 *
 * Positive control: a record filled the way native/boot/efi_main.c fills it
 * (efi_main.c:60-76 and 126-129, static so reserved0 is zero) with a QEMU
 * AAVMF style map (48-byte descriptors, version 1; UNVERIFIED stand-in
 * values, the real boot is proven by scripts/qemu_ck_boot_test.sh).
 * One negative case per refusal reason, each checked for the exact
 * "handoff: <reason>" line the kernel panics with.
 *
 * Mutation: built with -DCK_HANDOFF_MUTANT_SKIP_RESERVED the validator
 * skips the reserved0 check; this test then FAILS (reserved0 = 1 is
 * accepted). "make test" builds that mutant and requires it to fail. */
#include <string.h>
#include "ck_test.h"
#include "handoff_check.h"

static uint64_t map_buf[(64u << 10) / 8];

static struct ck_handoff good(void)
{
    static const char commit[] = "test";
    struct ck_handoff h;
    memset(&h, 0, sizeof h); /* efi_main.c: static handoff, BSS zeroed */
    h.magic = CK_HANDOFF_MAGIC;
    h.firmware_el = 2;
    h.uefi_entry_ticks = 123456;
    h.counter_freq_hz = 62500000;
    h.firmware_ttbr0 = 0x13ffff000ull;
    h.firmware_sctlr = 0x30c5183dull;
    h.image_base = 0x13c000000ull;
    h.image_end = 0x13c080000ull;
    h.commit = commit;
    h.memory_map = (uint64_t)(uintptr_t)map_buf;
    h.rsdp = 0x13f5f0018ull;
    h.desc_size = 48;
    h.desc_version = 1;
    h.map_size = 48 * 120;
    h.exit_attempts = 1;
    return h;
}

/* Runs the validator and returns the panic line the kernel would print
 * ("" on acceptance). */
static const char *line(const struct ck_handoff *h)
{
    static char buf[96];
    const char *why = (const char *)1;
    if (ck_handoff_check(h, &why) == 0)
        return why == 0 ? "" : "accepted but why set";
    snprintf(buf, sizeof buf, "handoff: %s", why ? why : "(null why)");
    return buf;
}

static void expect(const struct ck_handoff *h, const char *want)
{
    const char *got = line(h);
    int ok = strcmp(got, want) == 0;
    CHECK(ok);
    if (!ok)
        printf("    want \"%s\" got \"%s\"\n", want, got);
}

int main(void)
{
    struct ck_handoff h;

    /* 13. positive control; the full 64 KiB map buffer is also accepted. */
    h = good();
    expect(&h, "");
    h.map_size = 48 * 1365; /* 65520, largest multiple of 48 <= 64 KiB */
    expect(&h, "");
    h = good();
    h.firmware_el = 1;
    expect(&h, "");

    /* 1. NULL record */
    expect(0, "handoff: null record");

    /* 2. bad magic: one bit off; CHANDOF2 (refused as bad magic in this cut) */
    h = good();
    h.magic ^= 1;
    expect(&h, "handoff: bad magic");
    h = good();
    h.magic = 0x32464f444e414843ull;
    expect(&h, "handoff: bad magic");
    h = good();
    h.magic = 0;
    expect(&h, "handoff: bad magic");

    /* 3. reserved0 nonzero (the mutant skips this; must FAIL then) */
    h = good();
    h.reserved0 = 1;
    expect(&h, "handoff: reserved field nonzero");
    h = good();
    h.reserved0 = 0x80000000u;
    expect(&h, "handoff: reserved field nonzero");

    /* 4. descriptor size 0, 39, 41 (not a multiple of 8), 44 */
    h = good();
    h.desc_size = 0;
    expect(&h, "handoff: bad descriptor size 0");
    h.desc_size = 39;
    expect(&h, "handoff: bad descriptor size 39");
    h.desc_size = 41;
    expect(&h, "handoff: bad descriptor size 41");
    h.desc_size = 44;
    expect(&h, "handoff: bad descriptor size 44");
    h.desc_size = 40; /* smallest accepted stride; 48*120 is a multiple of 40 */
    expect(&h, "");

    /* 5. descriptor version 0 and 2 */
    h = good();
    h.desc_version = 0;
    expect(&h, "handoff: bad descriptor version 0");
    h.desc_version = 2;
    expect(&h, "handoff: bad descriptor version 2");

    /* 6. map size 0, not a multiple of desc_size, 65544 (> 64 KiB) */
    h = good();
    h.map_size = 0;
    expect(&h, "handoff: bad map size 0");
    h.map_size = 48 * 120 + 8;
    expect(&h, "handoff: bad map size 5768");
    h.desc_size = 21848; /* 65544 = 3 * 21848: refused only for > 64 KiB */
    h.map_size = 65544;
    expect(&h, "handoff: bad map size 65544");
    h.desc_size = 64; /* boundary: exactly 64 KiB is accepted */
    h.map_size = 65536;
    expect(&h, "");
    h.desc_size = 65544; /* stride larger than 64 KiB: one descriptor cannot fit */
    h.map_size = 65544;
    expect(&h, "handoff: bad map size 65544");

    /* Check order: the first failing field is reported. */
    h = good();
    h.magic = 0;
    h.reserved0 = 1;
    h.map_size = 0;
    expect(&h, "handoff: bad magic");

    return ck_t_verdict("test_handoff");
}
