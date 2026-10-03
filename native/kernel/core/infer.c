/* infer.c -- ingest the Llama-3.2-1B GGUF into kernel RAM and call the Rust
 * inference crate from the general-regs-only C kernel (aienos#34 lane 4,
 * cut 1: header, model bind, prompt tokenization; aienos#34 lane 5 cut 2:
 * prefill + greedy decode of the fixed prompt, decoded text, per-token
 * timing, then a clean unload that returns every frame).
 * Only compiled into the probe build: Makefile CK_INFER_LIB=<.a> adds
 * -DCK_INFER_PROBE=1; the default image carries none of this.
 *
 * Ingest path (the smallest that works today): QEMU fw_cfg. The C kernel has
 * no virtio-blk driver (only NVMe store, virtio-net) and the C boot stub reads
 * no files, but fw_cfg is already used by the TEST-ONLY artifact source
 * (artifact_loader.c). The traditional byte-at-a-time data register would need
 * ~8e8 trapped MMIO reads under TCG, so this uses the fw_cfg DMA interface:
 * QEMU docs/specs/fw_cfg.rst, "Guest-side DMA Interface" (qemu 8.2.2,
 * /usr/share/doc/qemu-system-data/specs/fw_cfg.rst.gz): feature bit 1 of key
 * 0x0001 and the DMA address register (QEMU CFG signature) at Base + 16 (8
 * bytes, big endian); a FWCfgDmaAccess{control,length,address} in RAM, all
 * big endian, control bit 1 = read, bit 3 = select (index in the upper 16
 * bits), bit 0 = error; control reads back 0 when done. The model is passed as
 * -fw_cfg name=opt/aienos/model,file=<gguf>. QEMU only: a PASS says nothing
 * about hardware.
 *
 * The fw_cfg MMIO base comes from the ACPI DSDT (device QEMU0002), as in the
 * artifact loader; nothing is assumed.
 *
 * FP/SIMD: the Rust unit uses them (CPACR_EL1.FPEN = 0b11 here); it runs with
 * every exception masked (DAIF) because the kernel saves no FP state, exactly
 * as core/fpu.c does. */
#include <stdint.h>
#include <stddef.h>

#include "arch.h"
#include "ck_internal.h"

#ifdef CK_INFER_PROBE
#include "sha256.h"

extern void aienos_infer_heap_init(uintptr_t base, uintptr_t len);
/* Mirror of crates/aienos-infer-kernel/src/lib.rs `InferResult` (#[repr(C)]). */
#define INFER_MAX_NEW 16
#define INFER_TEXT_BYTES 256
struct infer_result {
    uint32_t words[9];
    uint32_t ntok;
    uint32_t tokens[INFER_MAX_NEW];
    uint64_t tok_us[INFER_MAX_NEW];
    uint64_t prefill_us;
    uint32_t text_len;
    uint8_t text[INFER_TEXT_BYTES];
};
extern int32_t aienos_infer_run(const uint8_t *model, uint64_t len, struct infer_result *out);

#define CPACR_FPEN_SHIFT 20
#define PAGE 4096ull
#define HEAP_BYTES (256ull << 20)    /* bump-allocator region for the Rust unit */
#define DMA_CHUNK (64ull << 20)      /* fw_cfg DMA length is 32 bit; read in chunks */
#define MODEL_FILE "opt/aienos/model"

/* The prompt's expected first four ids (crates/aienos-infer/tests/fixtures/ref_fr.txt). */
static const uint32_t expect_ids[4] = {128000, 128006, 882, 128007};
/* The greedy reply llama.cpp produced for the same prompt ("step" lines of the
 * same fixture): "The capital of France is Paris." then <|eot_id|>. */
static const uint32_t expect_gen[8] = {791, 6864, 315, 9822, 374, 12366, 13, 128009};
/* Decoded reply, escaped for one console line: printable ASCII other than
 * backslash as is, everything else as \\xNN. 4 bytes per input byte + NUL. */
static char esc[4 * INFER_TEXT_BYTES + 1];
static void escape(char *out, const uint8_t *b, uint32_t n)
{
    static const char d[] = "0123456789abcdef";
    for (uint32_t i = 0; i < n; i++) {
        if (b[i] >= 0x20 && b[i] < 0x7f && b[i] != 0x5c) {
            *out++ = (char)b[i];
        } else {
            *out++ = 0x5c;
            *out++ = 0x78;
            *out++ = d[b[i] >> 4];
            *out++ = d[b[i] & 15];
        }
    }
    *out = 0;
}

static volatile uint8_t *fwcfg;

static uint32_t be32(const uint8_t *b)
{
    return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3];
}
static uint32_t le32(const uint8_t *b)
{
    return (uint32_t)b[3] << 24 | (uint32_t)b[2] << 16 | (uint32_t)b[1] << 8 | b[0];
}
static uint64_t le64(const uint8_t *b) { return (uint64_t)le32(b + 4) << 32 | le32(b); }
static uint32_t bswap32(uint32_t v) { return __builtin_bswap32(v); }

static void fw_select(uint16_t sel)
{
    *(volatile uint16_t *)(fwcfg + 8) = (uint16_t)((sel >> 8) | (sel << 8)); /* big endian */
    __asm__ volatile("dsb sy" ::: "memory");
}
static void fw_read(uint8_t *out, uint64_t n)
{
    for (uint64_t i = 0; i < n; i++)
        out[i] = fwcfg[0];
}

/* The fw_cfg MMIO window from the DSDT (device _HID "QEMU0002", then its
 * _CRS Memory32Fixed descriptor 0x86 length 9). Same walk as the artifact
 * loader's TEST-ONLY source. 0 if absent. */
static uint64_t fwcfg_from_dsdt(const char **why)
{
    const uint8_t *fadt = ck_acpi_find("FACP");
    if (!fadt) {
        *why = "no FADT";
        return 0;
    }
    uint32_t flen = le32(fadt + 4);
    uint64_t dsdt = 0;
    if (flen >= 148)
        dsdt = le64(fadt + 140);
    if (!dsdt && flen >= 44)
        dsdt = le32(fadt + 40);
    if (!dsdt || !ck_mm_mapped(dsdt, 36)) {
        *why = "DSDT not mapped";
        return 0;
    }
    const uint8_t *d = (const uint8_t *)(uintptr_t)dsdt;
    uint32_t len = le32(d + 4);
    if (len < 36 || memcmp(d, "DSDT", 4) || !ck_mm_mapped(dsdt, len)) {
        *why = "DSDT not mapped";
        return 0;
    }
    for (uint32_t i = 36; i + 9 <= len; i++) {
        if (memcmp(d + i, "QEMU0002", 8))
            continue;
        for (uint32_t j = i + 8; j + 12 <= len && j < i + 8 + 96; j++)
            if (d[j] == 0x86 && d[j + 1] == 0x09 && d[j + 2] == 0x00) {
                uint64_t base = le32(d + j + 4), size = le32(d + j + 8);
                if (base && size >= 0x18)
                    return base;
            }
    }
    *why = "no QEMU0002 device";
    return 0;
}

/* File directory (key 0x0019): selector and size of MODEL_FILE, -1 if absent. */
static int fw_find(uint16_t *sel, uint32_t *size)
{
    uint8_t b[64];
    fw_select(0x19);
    fw_read(b, 4);
    uint32_t n = be32(b);
    for (uint32_t i = 0; i < n && i < 4096; i++) {
        fw_read(b, 64);
        b[63] = 0;
        if (!memcmp(b + 8, MODEL_FILE, sizeof MODEL_FILE)) {
            *sel = (uint16_t)(b[4] << 8 | b[5]);
            *size = be32(b);
            return 0;
        }
    }
    return -1;
}

struct fw_dma {
    uint32_t control, length;
    uint64_t address;
} __attribute__((aligned(16)));
static volatile struct fw_dma dma_desc;

/* One DMA read of len bytes into pa. sel >= 0 selects that item first (offset
 * 0); sel < 0 continues at the current offset. 0 on success. */
static int fw_dma_read(int sel, uint64_t pa, uint32_t len)
{
    uint32_t ctl = 2u /* read */ | (sel >= 0 ? (8u | ((uint32_t)sel << 16)) : 0u);
    dma_desc.control = bswap32(ctl);
    dma_desc.length = bswap32(len);
    dma_desc.address = __builtin_bswap64(pa);
    __asm__ volatile("dsb sy" ::: "memory");
    *(volatile uint64_t *)(fwcfg + 16) = __builtin_bswap64((uint64_t)(uintptr_t)&dma_desc);
    __asm__ volatile("dsb sy" ::: "memory");
    for (uint64_t spin = 0; spin < 1000000000ull; spin++) {
        uint32_t c = bswap32(dma_desc.control);
        if (c & 1u)
            return -1; /* error bit */
        if (c == 0)
            return 0;
    }
    return -2;
}

/* The Rust unit's panic handler lands here: report and stop, never return. */
__attribute__((noreturn)) void aienos_infer_panic(void) { ck_panic("infer: Rust unit panicked or ran out of heap"); }

static void hex(char *out, const uint8_t *b, unsigned n)
{
    static const char d[] = "0123456789abcdef";
    for (unsigned i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[2 * n] = 0;
}

void ck_infer_run(void)
{
    const char *why = 0;
    uint64_t base = fwcfg_from_dsdt(&why);
    uint16_t sel = 0;
    uint32_t size = 0;
    if (base && !ck_mm_mmio_try_map(base, 0x18)) {
        why = "fw_cfg window not mappable";
        base = 0;
    }
    if (base) {
        uint8_t sig[4], feat[4];
        fwcfg = (volatile uint8_t *)(uintptr_t)base;
        fw_select(0);
        fw_read(sig, 4);
        fw_select(1);
        fw_read(feat, 4);
        if (memcmp(sig, "QEMU", 4))
            why = "fw_cfg signature", base = 0;
        else if (!(le32(feat) & 2u))
            why = "fw_cfg DMA interface not offered", base = 0;
        else if (__builtin_bswap64(*(volatile uint64_t *)(fwcfg + 16)) != 0x51454d5520434647ull)
            why = "fw_cfg DMA register signature", base = 0;
        else if (fw_find(&sel, &size))
            why = "no " MODEL_FILE " fw_cfg file", base = 0;
    }
    if (!base) {
        ck_printf("infer: ingest FAIL (%s)\nAIENOS_CK_INFER: FAIL\n", why);
        return;
    }
    ck_puts("infer_source_mode: TEST-ONLY QEMU fw_cfg model ingest (CK_INFER_LIB=1); not the boot disk; never counts toward a PASS\n");
    ck_printf("infer: fw_cfg base=0x%llx dma=yes file=%s size=%u\n", (unsigned long long)base,
              MODEL_FILE, size);

    uint64_t frames_before = ck_mm_free_frames();
    uint64_t mpages = ((uint64_t)size + PAGE - 1) / PAGE, mpa = 0, hpa = 0;
    if (ck_mm_frames_alloc(mpages, &mpa) || ck_mm_frames_alloc(HEAP_BYTES / PAGE, &hpa)) {
        ck_printf("infer: ingest FAIL (no frames: need %llu + %llu pages, %llu free)\nAIENOS_CK_INFER: FAIL\n",
                  (unsigned long long)mpages, (unsigned long long)(HEAP_BYTES / PAGE),
                  (unsigned long long)ck_mm_free_frames());
        return;
    }

    uint64_t t0 = ck_time_us();
    int rc = 0;
    for (uint64_t off = 0; off < size && !rc; off += DMA_CHUNK) {
        uint64_t n = size - off < DMA_CHUNK ? size - off : DMA_CHUNK;
        rc = fw_dma_read(off == 0 ? (int)sel : -1, mpa + off, (uint32_t)n);
    }
    uint64_t t1 = ck_time_us();
    if (rc) {
        ck_printf("infer: ingest FAIL (fw_cfg DMA rc=%d)\nAIENOS_CK_INFER: FAIL\n", rc);
        return;
    }
    ck_printf("infer: ingest bytes=%u dma_us=%llu\n", size, (unsigned long long)(t1 - t0));

    sha256_ctx ctx;
    uint8_t dg[SHA256_DIGEST_SIZE];
    char dh[2 * SHA256_DIGEST_SIZE + 1];
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)(uintptr_t)mpa, size);
    sha256_final(&ctx, dg);
    hex(dh, dg, SHA256_DIGEST_SIZE);
    ck_printf("infer: sha256=%s sha_us=%llu\n", dh, (unsigned long long)(ck_time_us() - t1));

    /* FP/SIMD on, every exception masked for the Rust unit (see core/fpu.c).
     * The FP registers are left dirty afterwards (nothing else in the kernel
     * reads them; EL0 traps on FP). */
    static struct infer_result res; /* ~0.5 KiB; static keeps it off the EL1 stack */
    memset(&res, 0, sizeof res);
    uint64_t v = ck_rd(cpacr_el1);
    v |= 3ull << CPACR_FPEN_SHIFT;
    ck_wr(cpacr_el1, v);
    ck_isb();
    aienos_infer_heap_init((uintptr_t)hpa, HEAP_BYTES);
    uint64_t daif = ck_rd(daif);
    __asm__ volatile("msr daifset, #0xf" ::: "memory");
    uint64_t t2 = ck_time_us();
    int32_t prc = aienos_infer_run((const uint8_t *)(uintptr_t)mpa, size, &res);
    uint64_t t3 = ck_time_us();
    ck_wr(daif, daif);
    const uint32_t *out = res.words;

    ck_printf("infer: probe rc=%d tensors=%u vocab=%u ids=%u,%u,%u,%u prompt_len=%u layers=%u heap_peak_kib=%u probe_us=%llu\n",
              prc, out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7], out[8],
              (unsigned long long)(t3 - t2));
    int ok = prc == 0;
    for (unsigned i = 0; i < 4; i++)
        ok = ok && out[2 + i] == expect_ids[i];

    /* Generation lines: ids, per-token microseconds, decoded bytes. */
    uint32_t ntok = res.ntok <= INFER_MAX_NEW ? res.ntok : INFER_MAX_NEW;
    ck_printf("infer: prefill_us=%llu prompt_len=%u", (unsigned long long)res.prefill_us, out[6]);
    ck_printf("\ninfer: tokens=");
    for (uint32_t i = 0; i < ntok; i++)
        ck_printf("%s%u", i ? " " : "", res.tokens[i]);
    ck_printf("\ninfer: tok_us=");
    uint64_t sum = 0;
    for (uint32_t i = 1; i < ntok; i++) {
        ck_printf("%s%llu", i > 1 ? "," : "", (unsigned long long)res.tok_us[i]);
        sum += res.tok_us[i];
    }
    ck_printf("\ninfer: decode_tokens=%u mean_tok_us=%llu\n", ntok > 1 ? ntok - 1 : 0,
              (unsigned long long)(ntok > 1 ? sum / (ntok - 1) : 0));
    uint32_t tl = res.text_len <= INFER_TEXT_BYTES ? res.text_len : INFER_TEXT_BYTES;
    escape(esc, res.text, tl);
    ck_printf("infer: text=%s\n", esc);
    ok = ok && ntok == sizeof expect_gen / sizeof expect_gen[0];
    for (uint32_t i = 0; ok && i < ntok; i++)
        ok = ok && res.tokens[i] == expect_gen[i];

    /* Unload: the Rust unit kept nothing (its objects died at return); forget
     * its heap region, then return every frame of the model and the heap. The
     * free-frame count must come back to what it was before the ingest. */
    aienos_infer_heap_init(0, 0);
    int f1 = ck_mm_frames_free(mpa, mpages), f2 = ck_mm_frames_free(hpa, HEAP_BYTES / PAGE);
    uint64_t frames_after = ck_mm_free_frames();
    struct ck_mm_usage mu;
    ck_mm_usage(&mu);
    ck_printf("infer: unloaded heap_live_kib=%llu frames_free_before=%llu frames_free_after=%llu frames_returned=%llu rc=%d,%d\n",
              (unsigned long long)((mu.heap_bytes - mu.heap_free) / 1024), (unsigned long long)frames_before,
              (unsigned long long)frames_after, (unsigned long long)(mpages + HEAP_BYTES / PAGE), f1, f2);
    ok = ok && f1 == 0 && f2 == 0 && frames_after == frames_before;
    ck_printf("AIENOS_CK_INFER: %s\n", ok ? "PASS" : "FAIL");
}
#else
void ck_infer_run(void) {}
#endif
