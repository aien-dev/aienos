/* infer.c -- ingest the Llama-3.2-1B GGUF into kernel RAM and call the Rust
 * inference crate from the general-regs-only C kernel (aienos#34 lane 4,
 * cut 1: header, model bind, prompt tokenization; aienos#34 lane 5 cut 2:
 * prefill + greedy decode of the fixed prompt, decoded text, per-token
 * timing, then a clean unload that returns every frame).
 * Only compiled into the probe build: Makefile CK_INFER_LIB=<.a> adds
 * -DCK_INFER_PROBE=1; the default image carries none of this.
 *
 * Ingest paths: (1) the boot disk, read by the UEFI stub through the
 * firmware Block I/O driver before ExitBootServices and handed over in
 * CHANDOF2 (native/boot/efi_model.c; the hardware path, lane 6); (2) QEMU
 * fw_cfg, TEST-ONLY, when the stub found no MODEL.MAP. The C kernel has
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

/* Bounded resident session (crates/aienos-infer-kernel/src/session.rs,
 * native v1 P06): load once, accept a prompt, one step per call so the
 * kernel can cancel between steps, decode, unload. Mirrors of SessionLimits
 * and SessionInfo (#[repr(C)]). */
struct infer_limits {
    uint32_t kv_capacity, max_new, max_prompt_bytes, heap_reserve;
};
struct infer_info {
    uint32_t tensors, vocab, layers, heap_used_kib;
};
extern int32_t aienos_infer_session_open(const uint8_t *model, uint64_t len, const struct infer_limits *l,
                                         struct infer_info *info);
extern int32_t aienos_infer_session_prompt(const uint8_t *text, uint32_t len);
extern int32_t aienos_infer_session_step(uint32_t *token, uint64_t *us);
extern int32_t aienos_infer_session_cancel(void);
extern int32_t aienos_infer_session_tokens(uint32_t *out, uint32_t cap);
extern int32_t aienos_infer_session_text(const uint32_t *ids, uint32_t n, uint8_t *out, uint32_t cap);
extern int32_t aienos_infer_session_close(void);
extern void aienos_infer_heap_stats(uint64_t *used, uint64_t *peak);
#define SESS_E_STATE (-12)
#define SESS_E_PROMPT_BYTES (-16)
#define SESS_STEP_DONE 0
#define SESS_STEP_PREFILL 1
#define SESS_STEP_TOKEN 2
#define SESS_STEP_LAST 3

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

/* Session limits of the probe: a 64-position cache, 16 generated tokens, a
 * 256-byte prompt and 64 KiB of heap kept free (every prompt costs a few
 * KiB that the bump allocator never gives back). */
#define SESS_KV 64u
#define SESS_MAX_NEW 16u
#define SESS_PROMPT_BYTES 256u
#define SESS_RESERVE (64u << 10)

/* One request: prompt, then steps until done or until `cancel_after` steps,
 * then cancel. Prints one line per request. Returns 1 when the request
 * behaved (count of produced tokens as expected, no error), 0 otherwise.
 * `expect`/`nexpect`: the exact token list a complete reply must equal. */
static int session_request(unsigned which, const char *text, unsigned cancel_after, const uint32_t *expect,
                           unsigned nexpect)
{
    uint64_t t0 = ck_time_us(), used = 0, peak = 0, pre_us = 0, tok_us_sum = 0;
    unsigned steps = 0, prefill = 0, produced = 0, last = 0;
    int32_t ids = aienos_infer_session_prompt((const uint8_t *)text, (uint32_t)strlen(text));
    if (ids < 0) {
        ck_printf("infer: session prompt=%u REFUSED rc=%d\n", which, ids);
        return 0;
    }
    int32_t rc = 0;
    for (;;) {
        if (cancel_after && steps == cancel_after) break;
        uint32_t t = 0;
        uint64_t us = 0;
        rc = aienos_infer_session_step(&t, &us);
        if (rc < 0 || rc == SESS_STEP_DONE) break;
        steps++;
        if (rc == SESS_STEP_PREFILL) { prefill++; pre_us += us; continue; }
        produced++;
        tok_us_sum += us;
        if (rc == SESS_STEP_LAST) { last = 1; break; }
    }
    static uint32_t toks[SESS_MAX_NEW];
    static uint8_t text_out[INFER_TEXT_BYTES];
    int32_t n = aienos_infer_session_tokens(toks, SESS_MAX_NEW);
    int ok = rc >= 0 && n == (int32_t)produced;
    if (cancel_after) {
        int32_t c = aienos_infer_session_cancel();
        ok = ok && c == (int32_t)produced && steps == cancel_after;
        /* After a cancel the next step must do nothing. */
        ok = ok && aienos_infer_session_step(0, 0) == SESS_STEP_DONE;
        aienos_infer_heap_stats(&used, &peak);
        ck_printf("infer: session prompt=%u ids=%d cancel_after_steps=%u steps=%u prefill=%u produced=%u idle_step=%s heap_used_kib=%llu rc=%d\n",
                  which, ids, cancel_after, steps, prefill, produced, "done", (unsigned long long)(used / 1024), rc);
        return ok;
    }
    ok = ok && last && (unsigned)ids == prefill && produced == nexpect;
    for (unsigned i = 0; ok && i < nexpect; i++) ok = ok && toks[i] == expect[i];
    int32_t tl = aienos_infer_session_text(toks, (uint32_t)produced, text_out, INFER_TEXT_BYTES);
    ok = ok && tl >= 0;
    escape(esc, text_out, tl > 0 ? (uint32_t)tl : 0);
    aienos_infer_heap_stats(&used, &peak);
    ck_printf("infer: session prompt=%u ids=%d steps=%u prefill=%u produced=%u last=%s prefill_us=%llu mean_tok_us=%llu tokens=",
              which, ids, steps, prefill, produced, last ? "yes" : "no", (unsigned long long)pre_us,
              (unsigned long long)(produced > 1 ? tok_us_sum / (produced - 1) : 0));
    for (unsigned i = 0; i < produced; i++) ck_printf("%s%u", i ? " " : "", toks[i]);
    ck_printf(" text=%s heap_used_kib=%llu request_us=%llu rc=%d\n", esc, (unsigned long long)(used / 1024),
              (unsigned long long)(ck_time_us() - t0), rc);
    return ok;
}

/* The bounded session over the ingested model: open with explicit limits,
 * a request cancelled during its prefill, the golden prompt run to its end
 * through the step API (must equal the one-shot probe's reply), a second
 * cancelled request after a completed one, the cheap refusals, close, and
 * the heap region returned. Prints AIENOS_CK_INFER_SESSION: PASS|FAIL. */
static void session_run(uint64_t mpa, uint64_t msize)
{
    uint64_t hpa = 0, frames_before = ck_mm_free_frames();
    if (ck_mm_frames_alloc(HEAP_BYTES / PAGE, &hpa)) {
        ck_printf("infer: session FAIL (no frames for the heap)\nAIENOS_CK_INFER_SESSION: FAIL\n");
        return;
    }
    aienos_infer_heap_init((uintptr_t)hpa, HEAP_BYTES);
    uint64_t daif = ck_rd(daif);
    __asm__ volatile("msr daifset, #0xf" ::: "memory");

    struct infer_limits lim = { SESS_KV, SESS_MAX_NEW, SESS_PROMPT_BYTES, SESS_RESERVE };
    struct infer_info info = { 0, 0, 0, 0 };
    uint64_t t0 = ck_time_us();
    int32_t rc = aienos_infer_session_open((const uint8_t *)(uintptr_t)mpa, msize, &lim, &info);
    ck_printf("infer: session open rc=%d tensors=%u vocab=%u layers=%u kv_capacity=%u max_new=%u max_prompt_bytes=%u heap_reserve_kib=%u heap_used_kib=%u open_us=%llu\n",
              rc, info.tensors, info.vocab, info.layers, lim.kv_capacity, lim.max_new, lim.max_prompt_bytes,
              lim.heap_reserve >> 10, info.heap_used_kib, (unsigned long long)(ck_time_us() - t0));
    int ok = rc == 0;
    if (ok) {
        /* Cheap refusals: a second open, an over-long prompt, a step with no
         * request pending. None of them touches the model. */
        static char longp[SESS_PROMPT_BYTES + 2];
        memset(longp, 'a', sizeof longp - 1);
        longp[sizeof longp - 1] = 0;
        int32_t r_open = aienos_infer_session_open((const uint8_t *)(uintptr_t)mpa, msize, &lim, &info);
        int32_t r_bytes = aienos_infer_session_prompt((const uint8_t *)longp, (uint32_t)strlen(longp));
        int32_t r_idle = aienos_infer_session_step(0, 0);
        ck_printf("infer: session refusals open_twice=%d prompt_bytes=%d step_idle=%d\n", r_open, r_bytes, r_idle);
        ok = ok && r_open == SESS_E_STATE && r_bytes == SESS_E_PROMPT_BYTES && r_idle == SESS_STEP_DONE;

        ok = session_request(1, "Say hello.", 3, 0, 0) && ok;
        ok = session_request(2, "What is the capital of France?", 0, expect_gen,
                             sizeof expect_gen / sizeof expect_gen[0]) && ok;
        ok = session_request(3, "Say hello.", 1, 0, 0) && ok;
    }
    uint64_t used = 0, peak = 0;
    aienos_infer_heap_stats(&used, &peak);
    int32_t crc = aienos_infer_session_close();
    ok = ok && crc == 0 && aienos_infer_session_close() == SESS_E_STATE;
    ck_wr(daif, daif);
    aienos_infer_heap_init(0, 0);
    int f = ck_mm_frames_free(hpa, HEAP_BYTES / PAGE);
    uint64_t frames_after = ck_mm_free_frames();
    ok = ok && f == 0 && frames_after == frames_before;
    ck_printf("infer: session close rc=%d heap_used_kib=%llu heap_peak_kib=%llu frames_free_before=%llu frames_free_after=%llu rc=%d\n",
              crc, (unsigned long long)(used / 1024), (unsigned long long)(peak / 1024),
              (unsigned long long)frames_before, (unsigned long long)frames_after, f);
    ck_printf("AIENOS_CK_INFER_SESSION: %s\n", ok ? "PASS" : "FAIL");
}

#ifdef CK_INFER_RESIDENT
/* Resident mode (native v1 P06, CK_SERVICE images built with CK_INFER_LIB):
 * the ingested model and one bounded session stay open from boot to the
 * lifecycle stop order. */
static struct {
    int open;
    uint64_t mpa, msize, mpages, hpa, frames_before;
} g_res;

int ck_infer_resident(void) { return g_res.open; }

static void resident_open(uint64_t mpa, uint64_t msize, uint64_t mpages, uint64_t hpa, uint64_t frames_before)
{
    uint64_t v = ck_rd(cpacr_el1);
    v |= 3ull << CPACR_FPEN_SHIFT;
    ck_wr(cpacr_el1, v);
    ck_isb();
    aienos_infer_heap_init((uintptr_t)hpa, HEAP_BYTES);
    struct infer_limits lim = { SESS_KV, SESS_MAX_NEW, SESS_PROMPT_BYTES, SESS_RESERVE };
    struct infer_info info = { 0, 0, 0, 0 };
    uint64_t t0 = ck_time_us(), daif = ck_rd(daif);
    __asm__ volatile("msr daifset, #0xf" ::: "memory");
    int32_t rc = aienos_infer_session_open((const uint8_t *)(uintptr_t)mpa, msize, &lim, &info);
    ck_wr(daif, daif);
    ck_printf("infer: resident open rc=%d tensors=%u vocab=%u layers=%u kv_capacity=%u max_new=%u max_prompt_bytes=%u heap_reserve_kib=%u heap_used_kib=%u open_us=%llu\n",
              rc, info.tensors, info.vocab, info.layers, lim.kv_capacity, lim.max_new, lim.max_prompt_bytes,
              lim.heap_reserve >> 10, info.heap_used_kib, (unsigned long long)(ck_time_us() - t0));
    if (rc != 0) {
        aienos_infer_heap_init(0, 0);
        ck_mm_frames_free(hpa, HEAP_BYTES / PAGE);
        if (mpages) ck_mm_frames_free(mpa, mpages);
        ck_puts("infer: resident FAIL (session did not open; frames returned)\n");
        return;
    }
    g_res.open = 1;
    g_res.mpa = mpa;
    g_res.msize = msize;
    g_res.mpages = mpages;
    g_res.hpa = hpa;
    g_res.frames_before = frames_before;
}

int ck_infer_prompt(const char *text, size_t len, int (*cancel_poll)(void), struct ck_infer_reply *r)
{
    if (!g_res.open) return SESS_E_STATE;
    memset(r, 0, sizeof *r);
    uint64_t t0 = ck_time_us(), daif = ck_rd(daif);
    __asm__ volatile("msr daifset, #0xf" ::: "memory");
    int32_t ids = aienos_infer_session_prompt((const uint8_t *)text, (uint32_t)len);
    ck_wr(daif, daif);
    if (ids < 0) return ids;
    r->prompt_ids = (uint32_t)ids;
    int32_t rc = 0;
    for (;;) {
        uint32_t t = 0;
        uint64_t us = 0;
        __asm__ volatile("msr daifset, #0xf" ::: "memory");
        rc = aienos_infer_session_step(&t, &us);
        ck_wr(daif, daif);
        if (rc < 0 || rc == SESS_STEP_DONE) break;
        r->steps++;
        if (rc != SESS_STEP_PREFILL) r->produced++;
        if (rc == SESS_STEP_LAST) break;
        if (cancel_poll && cancel_poll()) {
            __asm__ volatile("msr daifset, #0xf" ::: "memory");
            aienos_infer_session_cancel();
            ck_wr(daif, daif);
            r->cancelled = 1;
            break;
        }
    }
    r->rc = rc;
    r->us = ck_time_us() - t0;
    if (rc < 0) return rc;
    if (!r->cancelled) {
        __asm__ volatile("msr daifset, #0xf" ::: "memory");
        int32_t n = aienos_infer_session_tokens(r->ids, CK_INFER_REPLY_IDS);
        int32_t tl = aienos_infer_session_text(r->ids, n > 0 && n <= CK_INFER_REPLY_IDS ? (uint32_t)n : 0, r->text,
                                              CK_INFER_REPLY_TEXT);
        ck_wr(daif, daif);
        if (n < 0) return n;
        if (tl < 0) return tl;
        r->produced = (uint32_t)n;
        r->text_len = (uint32_t)tl;
        /* A completed request is consumed: the session is idle for the next prompt. */
        __asm__ volatile("msr daifset, #0xf" ::: "memory");
        aienos_infer_session_cancel();
        ck_wr(daif, daif);
    }
    return 0;
}

void ck_infer_resident_close(void)
{
    if (!g_res.open) return;
    uint64_t daif = ck_rd(daif), used = 0, peak = 0;
    __asm__ volatile("msr daifset, #0xf" ::: "memory");
    aienos_infer_heap_stats(&used, &peak);
    int32_t crc = aienos_infer_session_close();
    ck_wr(daif, daif);
    aienos_infer_heap_init(0, 0);
    int f2 = ck_mm_frames_free(g_res.hpa, HEAP_BYTES / PAGE);
    int f1 = g_res.mpages ? ck_mm_frames_free(g_res.mpa, g_res.mpages) : 0;
    uint64_t frames_after = ck_mm_free_frames();
    struct ck_mm_usage mu;
    ck_mm_usage(&mu);
    g_res.open = 0;
    ck_printf("infer: resident close rc=%d heap_used_kib=%llu heap_peak_kib=%llu\n", crc, (unsigned long long)(used / 1024),
              (unsigned long long)(peak / 1024));
    ck_printf("infer: unloaded heap_live_kib=%llu frames_free_before=%llu frames_free_after=%llu frames_returned=%llu rc=%d,%d\n",
              (unsigned long long)((mu.heap_bytes - mu.heap_free) / 1024), (unsigned long long)g_res.frames_before,
              (unsigned long long)frames_after, (unsigned long long)(g_res.mpages + HEAP_BYTES / PAGE), f1, f2);
}
#endif /* CK_INFER_RESIDENT */

void ck_infer_run(void)
{
    const char *why = 0;
    /* Source 1, the boot disk: the UEFI stub read the model through the
     * firmware's Block I/O driver before ExitBootServices and recorded it in
     * CHANDOF2 (native/boot/efi_model.c, native/boot/model_map.h). The bytes
     * live in EfiLoaderData the frame allocator never hands out (mm/mmu.c
     * reserves the range). This is the path that exists on hardware.
     * Source 2, QEMU fw_cfg: TEST-ONLY, below, when the stub found no map. */
    const struct ck_handoff *h = ck_handoff_get();
    int from_disk = h && (h->model_flags & CK_HANDOFF_MODEL_PRESENT);
    uint64_t base = from_disk ? 0 : fwcfg_from_dsdt(&why);
    uint16_t sel = 0;
    uint32_t size = 0;
    if (!from_disk) {
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

    }
    uint64_t msize = from_disk ? h->model_len : (uint64_t)size;
    uint64_t mpa = from_disk ? h->model_base : 0, hpa = 0, mpages = 0;
    if (from_disk) {
        ck_puts("infer_source_mode: boot-disk model (MODEL.MAP read by the UEFI stub through the firmware's Block I/O before ExitBootServices); the path that exists on hardware\n");
        ck_printf("infer: disk base=0x%llx size=%llu extents=%u read_us=%llu block_size=%u\n",
                  (unsigned long long)mpa, (unsigned long long)msize, h->model_extents,
                  (unsigned long long)h->model_read_us, h->model_block_size);
        if (!ck_mm_mapped(mpa, msize)) {
            ck_puts("infer: ingest FAIL (disk model range not mapped)\nAIENOS_CK_INFER: FAIL\n");
            return;
        }
    }

    uint64_t frames_before = ck_mm_free_frames();
    if (!from_disk) {
        mpages = (msize + PAGE - 1) / PAGE;
        if (ck_mm_frames_alloc(mpages, &mpa)) {
            ck_printf("infer: ingest FAIL (no frames: need %llu + %llu pages, %llu free)\nAIENOS_CK_INFER: FAIL\n",
                      (unsigned long long)mpages, (unsigned long long)(HEAP_BYTES / PAGE),
                      (unsigned long long)ck_mm_free_frames());
            return;
        }
    }
    if (ck_mm_frames_alloc(HEAP_BYTES / PAGE, &hpa)) {
        if (mpages)
            ck_mm_frames_free(mpa, mpages);
        ck_printf("infer: ingest FAIL (no frames for the %llu-page heap, %llu free)\nAIENOS_CK_INFER: FAIL\n",
                  (unsigned long long)(HEAP_BYTES / PAGE), (unsigned long long)ck_mm_free_frames());
        return;
    }

    if (!from_disk) {
        uint64_t t0 = ck_time_us();
        int rc = 0;
        for (uint64_t off = 0; off < msize && !rc; off += DMA_CHUNK) {
            uint64_t n = msize - off < DMA_CHUNK ? msize - off : DMA_CHUNK;
            rc = fw_dma_read(off == 0 ? (int)sel : -1, mpa + off, (uint32_t)n);
        }
        if (rc) {
            ck_printf("infer: ingest FAIL (fw_cfg DMA rc=%d)\nAIENOS_CK_INFER: FAIL\n", rc);
            return;
        }
        ck_printf("infer: ingest bytes=%llu dma_us=%llu\n", (unsigned long long)msize,
                  (unsigned long long)(ck_time_us() - t0));
    }

    uint64_t t1 = ck_time_us();
    sha256_ctx ctx;
    uint8_t dg[SHA256_DIGEST_SIZE];
    char dh[2 * SHA256_DIGEST_SIZE + 1];
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t *)(uintptr_t)mpa, msize);
    sha256_final(&ctx, dg);
    hex(dh, dg, SHA256_DIGEST_SIZE);
    ck_printf("infer: sha256=%s sha_us=%llu\n", dh, (unsigned long long)(ck_time_us() - t1));
    if (from_disk && memcmp(dg, h->model_sha256, SHA256_DIGEST_SIZE) != 0) {
        /* The bytes the firmware read are not the declared model: a wrong
         * LBA, a short read or a stale file. Refuse to decode. */
        hex(dh, h->model_sha256, SHA256_DIGEST_SIZE);
        ck_printf("infer: sha256 mismatch declared=%s\nAIENOS_CK_INFER: FAIL\n", dh);
        ck_mm_frames_free(hpa, HEAP_BYTES / PAGE);
        return;
    }

#ifdef CK_INFER_RESIDENT
    /* Service image: the model stays resident for the lifecycle's prompt verb
     * (core/lifecycle.c); the one-shot probe and session_run below are the
     * QEMU probe image's regression, not the service's job. */
    resident_open(mpa, msize, mpages, hpa, frames_before);
    return;
#endif

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
    int32_t prc = aienos_infer_run((const uint8_t *)(uintptr_t)mpa, msize, &res);
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

    /* Unload the one-shot unit: it kept nothing (its objects died at return);
     * forget its heap region and return the heap frames. The model stays for
     * the session below. */
    aienos_infer_heap_init(0, 0);
    int f2 = ck_mm_frames_free(hpa, HEAP_BYTES / PAGE);
    ck_printf("AIENOS_CK_INFER: %s\n", ok ? "PASS" : "FAIL");

    /* Bounded session on the same model bytes, its own fresh heap region. */
    session_run(mpa, msize);

    /* Return the model's frames when it came over fw_cfg (the disk model stays
     * in LoaderData, never a frame). The free-frame count must come back to
     * what it was before the ingest. */
    int f1 = mpages ? ck_mm_frames_free(mpa, mpages) : 0;
    uint64_t frames_after = ck_mm_free_frames();
    struct ck_mm_usage mu;
    ck_mm_usage(&mu);
    ck_printf("infer: unloaded heap_live_kib=%llu frames_free_before=%llu frames_free_after=%llu frames_returned=%llu rc=%d,%d\n",
              (unsigned long long)((mu.heap_bytes - mu.heap_free) / 1024), (unsigned long long)frames_before,
              (unsigned long long)frames_after, (unsigned long long)(mpages + HEAP_BYTES / PAGE), f1, f2);
    if (!(f1 == 0 && f2 == 0 && frames_after == frames_before))
        ck_puts("infer: frames NOT returned\nAIENOS_CK_INFER: FAIL\n");
}
#else
void ck_infer_run(void) {}
#endif

#ifndef CK_INFER_RESIDENT
/* No resident session: the diagnostic image, the QEMU probe image and a
 * service image built without CK_INFER_LIB (every hardware image today). */
int ck_infer_resident(void) { return 0; }
int ck_infer_prompt(const char *text, size_t len, int (*cancel_poll)(void), struct ck_infer_reply *r)
{
    (void)text; (void)len; (void)cancel_poll; (void)r;
    return -12; /* no session in this image */
}
void ck_infer_resident_close(void) {}
#endif
