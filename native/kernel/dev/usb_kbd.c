/* usb_kbd.c -- polled xHCI boot-keyboard driver, operator line input,
 * console shell and recovery-access hook (see usb_kbd.h). Freestanding.
 * Register and structure layouts: xHCI 1.2 (sections 5.3-5.6 registers,
 * 6.2 contexts, 6.4 TRBs, 6.5 event ring segment table), USB 2.0 chapter 9
 * (standard requests), HID 1.11 (SET_PROTOCOL, SET_IDLE). */
#include "usb_kbd.h"
#include "usb_hid.h"
#include "ck.h"

#define PG 4096u
#define RING_N 256u /* TRBs per 4 KiB ring page */

/* DMA region layout, one 4 KiB page each. */
enum { P_DCBAA = 0, P_DEVCTX, P_INCTX, P_CMD, P_EVT, P_ERST, P_EP0, P_INTR, P_BUF, P_SPARRAY, P_SP0 };
#define BUF_REPORT 0u
#define BUF_DESC 512u
#define DESC_MAX 255u

/* Capability registers. */
#define CAP_LENGTH 0x00u
#define CAP_HCSPARAMS1 0x04u
#define CAP_HCSPARAMS2 0x08u
#define CAP_HCCPARAMS1 0x10u
#define CAP_DBOFF 0x14u
#define CAP_RTSOFF 0x18u
/* Operational registers. */
#define OP_USBCMD 0x00u
#define OP_USBSTS 0x04u
#define OP_PAGESIZE 0x08u
#define OP_CRCR 0x18u
#define OP_DCBAAP 0x30u
#define OP_CONFIG 0x38u
#define OP_PORTSC(p) (0x400u + 0x10u * ((p) - 1u))
#define CMD_RS 0x1u
#define CMD_HCRST 0x2u
#define STS_HCH 0x1u
#define STS_HSE 0x4u
#define STS_CNR 0x800u
/* Interrupter 0 (runtime base + 0x20). */
#define IR0_ERSTSZ 0x28u
#define IR0_ERSTBA 0x30u
#define IR0_ERDP 0x38u
/* PORTSC */
#define PS_CCS 0x1u
#define PS_PED 0x2u
#define PS_PR 0x10u
#define PS_PP 0x200u
#define PS_PRC 0x200000u
#define PS_CHANGES 0x00fe0000u
#define PS_KEEP (PS_PP | 0x0e000000u) /* PP and the wake enables: RW, not RW1C */
/* TRB types */
#define T_NORMAL 1u
#define T_SETUP 2u
#define T_DATA 3u
#define T_STATUS 4u
#define T_LINK 6u
#define T_ENABLE_SLOT 9u
#define T_DISABLE_SLOT 10u
#define T_ADDRESS 11u
#define T_CONFIGURE 12u
#define T_EVALUATE 13u
#define T_EV_TRANSFER 32u
#define T_EV_COMMAND 33u
#define TRB_TYPE(t) ((uint32_t)(t) << 10)
#define TRB_IOC 0x20u
#define TRB_ISP 0x4u
#define TRB_IDT 0x40u
#define TRB_TC 0x2u
#define CC_SUCCESS 1u
#define CC_SHORT 13u
/* Endpoint types (context) */
#define EP_CONTROL 4u
#define EP_INTR_IN 7u

typedef struct {
    volatile uint32_t *t;
    uint64_t phys;
    uint32_t i, c;
} ring;

typedef struct {
    volatile uint8_t *base;
    uint32_t op, rt, db;
    uint8_t *mem;
    uint64_t phys;
    unsigned ctx, max_ports;
    ring cmd, ep0, intr;
    uint32_t ev_i, ev_c;
    uint8_t slot, port, speed, dci;
    uint16_t mps0;
    ck_boot_kbd kbd;
    int ep_halted;
    const char *why;
    uint32_t last_code;
} kbd;

static kbd g_k;
static int g_offered;       /* the recovery choice was offered (keyboard ready) */
static int g_choice = -1;   /* CK_RECOVERY_* once decided */

static uint32_t rd(uint32_t off) { return *(volatile uint32_t *)(g_k.base + off); }
static void wr(uint32_t off, uint32_t v) { *(volatile uint32_t *)(g_k.base + off) = v; }
static void wr64(uint32_t off, uint64_t v)
{
    wr(off, (uint32_t)v);
    wr(off + 4u, (uint32_t)(v >> 32));
}
static uint8_t *page(unsigned p) { return g_k.mem + (size_t)p * PG; }
static uint64_t page_phys(unsigned p) { return g_k.phys + (uint64_t)p * PG; }
static void zero(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) ((volatile uint8_t *)p)[i] = 0;
}

static int fail(int rc, const char *why)
{
    g_k.why = why;
    return rc;
}

/* Bounded poll: returns 1 once cond() holds, 0 when ms ran out. */
#define WAIT_MS(ms, cond)                                                  \
    ({                                                                     \
        uint64_t t0_ = ck_time_us();                                       \
        int ok_ = 0;                                                       \
        for (;;) {                                                         \
            if (cond) { ok_ = 1; break; }                                  \
            if (ck_time_us() - t0_ > (uint64_t)(ms) * 1000u) break;        \
            ck_udelay(20);                                                 \
        }                                                                  \
        ok_;                                                               \
    })

static void ring_init(ring *r, unsigned p)
{
    zero(page(p), PG);
    r->t = (volatile uint32_t *)page(p);
    r->phys = page_phys(p);
    r->i = 0;
    r->c = 1;
}

/* Producer side: writes the control word (cycle bit) last; the last slot of
 * the page is a Link TRB back to the start with Toggle Cycle. */
static uint64_t ring_push(ring *r, uint32_t p0, uint32_t p1, uint32_t st, uint32_t ctl)
{
    volatile uint32_t *e = r->t + r->i * 4u;
    uint64_t at = r->phys + (uint64_t)r->i * 16u;
    e[0] = p0;
    e[1] = p1;
    e[2] = st;
    ck_mb();
    e[3] = (ctl & ~1u) | r->c;
    if (++r->i == RING_N - 1u) {
        volatile uint32_t *l = r->t + r->i * 4u;
        l[0] = (uint32_t)r->phys;
        l[1] = (uint32_t)(r->phys >> 32);
        l[2] = 0;
        ck_mb();
        l[3] = TRB_TYPE(T_LINK) | TRB_TC | r->c;
        r->i = 0;
        r->c ^= 1u;
    }
    return at;
}

static void doorbell(unsigned target, uint32_t value)
{
    ck_mb();
    wr(g_k.db + 4u * target, value);
}

/* Consumer side of the event ring; 1 and ev filled when an event was there. */
static int ev_next(uint32_t ev[4])
{
    volatile uint32_t *e = (volatile uint32_t *)page(P_EVT) + g_k.ev_i * 4u;
    if ((e[3] & 1u) != g_k.ev_c) return 0;
    for (int i = 0; i < 4; i++) ev[i] = e[i];
    if (++g_k.ev_i == RING_N) {
        g_k.ev_i = 0;
        g_k.ev_c ^= 1u;
    }
    wr64(g_k.rt + IR0_ERDP, (page_phys(P_EVT) + (uint64_t)g_k.ev_i * 16u) | 0x8u /* EHB */);
    return 1;
}
static uint64_t ev_ptr(const uint32_t ev[4]) { return (uint64_t)ev[0] | ((uint64_t)ev[1] << 32); }
static uint32_t ev_type(const uint32_t ev[4]) { return (ev[3] >> 10) & 0x3fu; }
static uint32_t ev_code(const uint32_t ev[4]) { return ev[2] >> 24; }

static int command(uint32_t p0, uint32_t p1, uint32_t ctl, uint32_t out[4], const char *step)
{
    uint64_t at = ring_push(&g_k.cmd, p0, p1, 0, ctl);
    doorbell(0, 0);
    uint32_t ev[4];
    uint64_t t0 = ck_time_us();
    while (ck_time_us() - t0 < 1000000u) {
        if (!ev_next(ev)) {
            ck_udelay(20);
            continue;
        }
        if (ev_type(ev) != T_EV_COMMAND || ev_ptr(ev) != at) continue; /* port status changes etc. */
        g_k.last_code = ev_code(ev);
        if (out)
            for (int i = 0; i < 4; i++) out[i] = ev[i];
        return ev_code(ev) == CC_SUCCESS ? 0 : fail(CK_KBD_E_FAILED, step);
    }
    return fail(CK_KBD_E_TIMEOUT, step);
}

/* Waits for the transfer event of the TRB at `at` on (slot, dci). An error
 * completion on an earlier TRB of the same TD ends the wait as a failure. */
static int transfer_wait(uint64_t at, uint8_t dci, uint32_t ms, const char *step)
{
    uint32_t ev[4];
    uint64_t t0 = ck_time_us();
    while (ck_time_us() - t0 < (uint64_t)ms * 1000u) {
        if (!ev_next(ev)) {
            ck_udelay(20);
            continue;
        }
        if (ev_type(ev) != T_EV_TRANSFER || (ev[3] >> 24) != g_k.slot || ((ev[3] >> 16) & 0x1fu) != dci) continue;
        uint32_t cc = ev_code(ev);
        g_k.last_code = cc;
        if (cc != CC_SUCCESS && cc != CC_SHORT) return fail(CK_KBD_E_FAILED, step);
        if (ev_ptr(ev) == at) return 0;
    }
    return fail(CK_KBD_E_TIMEOUT, step);
}

static int control(uint8_t rtype, uint8_t req, uint16_t val, uint16_t idx, uint16_t len, uint64_t buf, const char *step)
{
    int in = (rtype & 0x80u) != 0;
    uint32_t trt = len ? (in ? 3u : 2u) : 0u;
    ring_push(&g_k.ep0, (uint32_t)rtype | ((uint32_t)req << 8) | ((uint32_t)val << 16), (uint32_t)idx | ((uint32_t)len << 16),
              8u, TRB_TYPE(T_SETUP) | TRB_IDT | (trt << 16));
    if (len)
        ring_push(&g_k.ep0, (uint32_t)buf, (uint32_t)(buf >> 32), len, TRB_TYPE(T_DATA) | (in ? (1u << 16) : 0u));
    uint64_t st = ring_push(&g_k.ep0, 0, 0, 0, TRB_TYPE(T_STATUS) | TRB_IOC | ((len && in) ? 0u : (1u << 16)));
    doorbell(g_k.slot, 1);
    return transfer_wait(st, 1, 1000, step);
}

static volatile uint32_t *ictx(unsigned index) { return (volatile uint32_t *)(page(P_INCTX) + (size_t)index * g_k.ctx); }

static void ep0_context(uint32_t add, unsigned entries)
{
    zero(page(P_INCTX), PG);
    ictx(0)[1] = add;
    ictx(1)[0] = ((uint32_t)g_k.speed << 20) | ((uint32_t)entries << 27);
    ictx(1)[1] = (uint32_t)g_k.port << 16;
    volatile uint32_t *ep = ictx(2);
    ep[1] = (3u << 1) | (EP_CONTROL << 3) | ((uint32_t)g_k.mps0 << 16);
    uint64_t dq = g_k.ep0.phys + (uint64_t)g_k.ep0.i * 16u;
    ep[2] = (uint32_t)dq | g_k.ep0.c;
    ep[3] = (uint32_t)(dq >> 32);
    ep[4] = 8u;
}

static uint32_t intr_interval(uint8_t speed, uint8_t b)
{
    if (speed >= 3) { /* high / super speed: 2^(bInterval-1) microframes */
        uint32_t v = b ? (uint32_t)b - 1u : 0u;
        return v > 15u ? 15u : v;
    }
    /* full / low speed: bInterval frames of 1 ms = 8 microframes each */
    uint32_t f = b ? b : 1u, e = 0;
    while ((1u << (e + 1u)) <= f * 8u && e < 15u) e++;
    return e < 3u ? 3u : e > 10u ? 10u : e;
}

static int reset_port(uint8_t p)
{
    uint32_t off = g_k.op + OP_PORTSC(p);
    uint32_t s = rd(off);
    if (!(s & PS_PED)) {
        wr(off, (s & PS_KEEP) | PS_PR);
        if (!WAIT_MS(500, rd(off) & PS_PRC)) return fail(CK_KBD_E_TIMEOUT, "port reset");
        ck_udelay(10000); /* USB 2.0 7.1.7.5 reset recovery, 10 ms */
    }
    s = rd(off);
    wr(off, (s & PS_KEEP) | (s & PS_CHANGES));
    if (!(s & PS_PED)) return fail(CK_KBD_E_UNSUP, "port did not enable");
    g_k.speed = (uint8_t)((s >> 10) & 0xfu);
    return 0;
}

static int attach(uint8_t p)
{
    int rc = reset_port(p);
    if (rc) return rc;
    g_k.port = p;
    uint32_t ev[4];
    if ((rc = command(0, 0, TRB_TYPE(T_ENABLE_SLOT), ev, "Enable Slot"))) return rc;
    g_k.slot = (uint8_t)(ev[3] >> 24);
    if (g_k.slot == 0) return fail(CK_KBD_E_UNSUP, "slot id 0");
    zero(page(P_DEVCTX), PG);
    ((volatile uint64_t *)page(P_DCBAA))[g_k.slot] = page_phys(P_DEVCTX);
    ring_init(&g_k.ep0, P_EP0);
    g_k.mps0 = g_k.speed == 4 ? 512u : g_k.speed == 3 ? 64u : 8u;
    ep0_context(0x3u, 1);
    if ((rc = command((uint32_t)page_phys(P_INCTX), (uint32_t)(page_phys(P_INCTX) >> 32),
                      TRB_TYPE(T_ADDRESS) | ((uint32_t)g_k.slot << 24), 0, "Address Device")))
        return rc;
    uint8_t *desc = page(P_BUF) + BUF_DESC;
    uint64_t desc_phys = page_phys(P_BUF) + BUF_DESC;
    zero(desc, DESC_MAX + 1u);
    if ((rc = control(0x80, 6, 0x0100, 0, 8, desc_phys, "GET_DESCRIPTOR(device)"))) return rc;
    if (desc[0] >= 8 && desc[1] == 1 && desc[7]) {
        uint16_t m = g_k.speed == 4 ? (uint16_t)(1u << (desc[7] > 9 ? 9 : desc[7])) : desc[7];
        if (m != g_k.mps0) {
            g_k.mps0 = m;
            ep0_context(0x2u, 1);
            if ((rc = command((uint32_t)page_phys(P_INCTX), (uint32_t)(page_phys(P_INCTX) >> 32),
                              TRB_TYPE(T_EVALUATE) | ((uint32_t)g_k.slot << 24), 0, "Evaluate Context")))
                return rc;
        }
    }
    zero(desc, DESC_MAX + 1u);
    if ((rc = control(0x80, 6, 0x0200, 0, DESC_MAX, desc_phys, "GET_DESCRIPTOR(configuration)"))) return rc;
    if (ck_usb_find_boot_kbd(desc, DESC_MAX, &g_k.kbd)) return fail(CK_KBD_E_NOKBD, "no boot keyboard interface");
    uint8_t n = g_k.kbd.endpoint & 0x0fu;
    if (n == 0) return fail(CK_KBD_E_NOKBD, "endpoint 0");
    g_k.dci = (uint8_t)(2u * n + 1u);
    /* xHCI 4.3.5: Configure Endpoint, then SET_CONFIGURATION. */
    ring_init(&g_k.intr, P_INTR);
    zero(page(P_INCTX), PG);
    ictx(0)[1] = 1u | (1u << g_k.dci);
    ictx(1)[0] = ((uint32_t)g_k.speed << 20) | ((uint32_t)g_k.dci << 27);
    ictx(1)[1] = (uint32_t)g_k.port << 16;
    volatile uint32_t *ep = ictx(1u + g_k.dci);
    ep[0] = intr_interval(g_k.speed, g_k.kbd.interval) << 16;
    ep[1] = (3u << 1) | (EP_INTR_IN << 3) | ((uint32_t)g_k.kbd.max_packet << 16);
    ep[2] = (uint32_t)g_k.intr.phys | 1u;
    ep[3] = (uint32_t)(g_k.intr.phys >> 32);
    ep[4] = CK_HID_REPORT_LEN | ((uint32_t)g_k.kbd.max_packet << 16);
    if ((rc = command((uint32_t)page_phys(P_INCTX), (uint32_t)(page_phys(P_INCTX) >> 32),
                      TRB_TYPE(T_CONFIGURE) | ((uint32_t)g_k.slot << 24), 0, "Configure Endpoint")))
        return rc;
    if ((rc = control(0x00, 9, g_k.kbd.configuration, 0, 0, 0, "SET_CONFIGURATION"))) return rc;
    if ((rc = control(0x21, 0x0b, 0, g_k.kbd.interface, 0, 0, "SET_PROTOCOL(boot)"))) return rc;
    (void)control(0x21, 0x0a, 0, g_k.kbd.interface, 0, 0, "SET_IDLE"); /* optional: some keyboards stall it */
    return 0;
}

static uint64_t g_armed;
static void arm(void)
{
    g_armed = ring_push(&g_k.intr, (uint32_t)(page_phys(P_BUF) + BUF_REPORT), (uint32_t)((page_phys(P_BUF) + BUF_REPORT) >> 32),
                        CK_HID_REPORT_LEN, TRB_TYPE(T_NORMAL) | TRB_IOC | TRB_ISP);
    doorbell(g_k.slot, g_k.dci);
}

/* One completed report into rep (8 bytes), or 0 when none is waiting. */
static int poll_report(uint8_t rep[CK_HID_REPORT_LEN])
{
    uint32_t ev[4];
    while (ev_next(ev)) {
        if (ev_type(ev) != T_EV_TRANSFER || (ev[3] >> 24) != g_k.slot || ((ev[3] >> 16) & 0x1fu) != g_k.dci) continue;
        uint32_t cc = ev_code(ev);
        if (cc != CC_SUCCESS && cc != CC_SHORT) {
            g_k.last_code = cc;
            g_k.ep_halted = 1;
            return 0;
        }
        uint32_t got = CK_HID_REPORT_LEN - (ev[2] & 0xffffffu);
        const volatile uint8_t *b = page(P_BUF) + BUF_REPORT;
        for (unsigned i = 0; i < CK_HID_REPORT_LEN; i++) rep[i] = i < got ? b[i] : 0;
        arm();
        return got >= 3u;
    }
    return 0;
}

static int start(volatile uint8_t *bar0, uint8_t *mem, uint64_t phys, size_t bytes)
{
    /* Fresh state per controller (the fence may try several, cut 2). */
    for (size_t i = 0; i < sizeof g_k; i++) ((volatile uint8_t *)&g_k)[i] = 0;
    g_k.base = bar0;
    g_k.mem = mem;
    g_k.phys = phys;
    g_k.why = "";
    if (!bar0 || !mem || bytes < (size_t)CK_KBD_DMA_PAGES * PG || (phys & (PG - 1u)))
        return fail(CK_KBD_E_ARG, "DMA region too small or unaligned");
    uint32_t cap = rd(CAP_LENGTH), hcs1 = rd(CAP_HCSPARAMS1), hcs2 = rd(CAP_HCSPARAMS2), hcc1 = rd(CAP_HCCPARAMS1);
    if (cap == 0xffffffffu || (cap & 0xffu) < 0x20u) return fail(CK_KBD_E_ARG, "xHCI registers absent");
    g_k.op = cap & 0xffu;
    g_k.rt = rd(CAP_RTSOFF) & ~0x1fu;
    g_k.db = rd(CAP_DBOFF) & ~0x3u;
    g_k.max_ports = hcs1 >> 24;
    g_k.ctx = (hcc1 & 0x4u) ? 64u : 32u;
    uint32_t sp = ((hcs2 >> 27) & 0x1fu) | (((hcs2 >> 21) & 0x1fu) << 5);
    if (sp > CK_KBD_MAX_SCRATCHPADS) return fail(CK_KBD_E_UNSUP, "controller asks for more scratchpad pages than the window holds");
    if (!(hcc1 & 0x1u) && phys + bytes > 0x100000000ull) return fail(CK_KBD_E_UNSUP, "DMA above 4 GiB on a 32-bit controller");
    if (!(rd(g_k.op + OP_PAGESIZE) & 0x1u)) return fail(CK_KBD_E_UNSUP, "4 KiB pages not supported");
    /* USB legacy support capability (xHCI 7.1): take ownership from firmware. */
    uint32_t x = (hcc1 >> 16) << 2;
    for (unsigned guard = 0; x && guard < 64; guard++) {
        uint32_t v = rd(x);
        if ((v & 0xffu) == 1u) {
            if (v & (1u << 16)) {
                wr(x, v | (1u << 24));
                int ok = WAIT_MS(1000, !(rd(x) & (1u << 16)));
                ck_printf("xhci: legacy handoff bios_owned=%s\n", ok ? "released" : "STILL SET");
                if (!ok) return fail(CK_KBD_E_TIMEOUT, "firmware kept the controller (legacy handoff)");
            }
            wr(x + 4u, rd(x + 4u) & 0x1fff1feeu); /* SMI enables off; RW1C status bits 31:29 written 0 */
            break;
        }
        uint32_t next = (v >> 8) & 0xffu;
        x = next ? x + (next << 2) : 0;
    }
    /* The fence left it halted; reset (5.4.1: HCRST only while HCH = 1). */
    if (!(rd(g_k.op + OP_USBSTS) & STS_HCH)) return fail(CK_KBD_E_ARG, "controller not halted before reset");
    wr(g_k.op + OP_USBCMD, CMD_HCRST);
    if (!WAIT_MS(1000, !(rd(g_k.op + OP_USBCMD) & CMD_HCRST) && !(rd(g_k.op + OP_USBSTS) & STS_CNR)))
        return fail(CK_KBD_E_TIMEOUT, "controller reset");
    zero(mem, (size_t)CK_KBD_DMA_PAGES * PG);
    if (sp) {
        volatile uint64_t *arr = (volatile uint64_t *)page(P_SPARRAY);
        for (uint32_t i = 0; i < sp; i++) arr[i] = page_phys(P_SP0 + i);
        ((volatile uint64_t *)page(P_DCBAA))[0] = page_phys(P_SPARRAY);
    }
    ring_init(&g_k.cmd, P_CMD);
    g_k.ev_i = 0;
    g_k.ev_c = 1;
    volatile uint32_t *erst = (volatile uint32_t *)page(P_ERST);
    erst[0] = (uint32_t)page_phys(P_EVT);
    erst[1] = (uint32_t)(page_phys(P_EVT) >> 32);
    erst[2] = RING_N;
    erst[3] = 0;
    ck_mb();
    wr(g_k.op + OP_CONFIG, (rd(g_k.op + OP_CONFIG) & ~0xffu) | 1u);
    wr64(g_k.op + OP_DCBAAP, page_phys(P_DCBAA));
    wr64(g_k.op + OP_CRCR, page_phys(P_CMD) | 1u);
    wr(g_k.rt + IR0_ERSTSZ, 1);
    wr64(g_k.rt + IR0_ERDP, page_phys(P_EVT));
    wr64(g_k.rt + IR0_ERSTBA, page_phys(P_ERST));
    wr(g_k.op + OP_USBCMD, CMD_RS);
    if (!WAIT_MS(100, !(rd(g_k.op + OP_USBSTS) & STS_HCH))) return fail(CK_KBD_E_TIMEOUT, "controller run");
    if (rd(g_k.op + OP_USBSTS) & STS_HSE) return fail(CK_KBD_E_FAILED, "host system error");
    ck_printf("xhci: running ports=%u context_bytes=%u scratchpads=%u dma_pages=%u\n", g_k.max_ports, g_k.ctx, sp,
              (unsigned)CK_KBD_DMA_PAGES);
    /* Connections are re-reported after the reset: give them a bounded moment. */
    (void)WAIT_MS(500, ({
                      int any_ = 0;
                      for (unsigned p_ = 1; p_ <= g_k.max_ports; p_++) any_ |= rd(g_k.op + OP_PORTSC(p_)) & PS_CCS;
                      any_;
                  }));
    int rc = fail(CK_KBD_E_NOKBD, "no boot keyboard on any connected port");
    for (unsigned p = 1; p <= g_k.max_ports && p <= 255u; p++) {
        if (!(rd(g_k.op + OP_PORTSC(p)) & PS_CCS)) continue;
        g_k.slot = 0;
        rc = attach((uint8_t)p);
        if (rc == 0) break;
        ck_printf("keyboard: port %u not usable (%s, completion %u)\n", p, g_k.why, g_k.last_code);
        if (g_k.slot) (void)command(0, 0, TRB_TYPE(T_DISABLE_SLOT) | ((uint32_t)g_k.slot << 24), 0, "Disable Slot");
        g_k.slot = 0;
    }
    if (rc) return rc;
    arm();
    return 0;
}

static void echo(char c)
{
    if (c == '\b')
        ck_puts("\b \b");
    else
        ck_printf("%c", c);
}

static void shell_out(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    ck_vprintf(fmt, ap);
    va_end(ap);
}

/* Next key event, waiting at most ms; 1 and *ev filled, or 0. */
static int next_key(ck_hid_decoder *d, ck_key_event *pend, unsigned *npend, unsigned *ipend, uint32_t ms, ck_key_event *ev)
{
    uint64_t t0 = ck_time_us();
    for (;;) {
        if (*ipend < *npend) {
            *ev = pend[(*ipend)++];
            return 1;
        }
        uint8_t rep[CK_HID_REPORT_LEN];
        if (poll_report(rep)) {
            *npend = ck_hid_decode(d, rep, sizeof rep, pend);
            *ipend = 0;
            continue;
        }
        if (g_k.ep_halted || ck_time_us() - t0 >= (uint64_t)ms * 1000u) return 0;
        ck_udelay(100);
    }
}

int ck_kbd_phase(volatile uint8_t *bar0, uint8_t *mem, uint64_t phys, size_t bytes)
{
    int rc = start(bar0, mem, phys, bytes);
    if (rc) {
        ck_printf("keyboard: unavailable (%s, rc=%d, completion %u)\n", g_k.why, rc, g_k.last_code);
        return rc;
    }
    ck_printf("keyboard: ready (port %u, slot %u, endpoint 0x%02x)\n", g_k.port, g_k.slot, g_k.kbd.endpoint);

    ck_hid_decoder dec = {{0}};
    ck_key_event pend[CK_HID_MAX_KEYS], ev = {0, 0};
    unsigned np = 0, ip = 0;
    /* Recovery access: bounded wait for one operator key. */
    g_offered = 1;
    ck_printf("recovery_access: waiting %u ms for an operator key (r = recovery console; any other key or no key = "
              "normal boot)\n",
              (unsigned)CK_KBD_RECOVERY_WAIT_MS);
    int have = next_key(&dec, pend, &np, &ip, CK_KBD_RECOVERY_WAIT_MS, &ev);
    g_choice = ck_recovery_decide(have, ev);
    ck_printf("recovery_access: choice=%s\n", ck_recovery_name(g_choice));
    if (g_choice == CK_RECOVERY_CONSOLE) return CK_KBD_OK; /* the fence revokes; devices.c runs the stub */
    np = ip = 0;

    ck_printf("keyboard: shell ready (%u s, idle %u s)\n", (unsigned)(CK_KBD_SHELL_MS / 1000u),
              (unsigned)(CK_KBD_SHELL_IDLE_MS / 1000u));
    ck_line line;
    ck_line_reset(&line);
    uint64_t t0 = ck_time_us();
    const char *reason = "timeout";
    ck_puts("aienos> ");
    for (;;) {
        uint64_t used = (ck_time_us() - t0) / 1000u;
        if (used >= CK_KBD_SHELL_MS) break;
        uint32_t left = (uint32_t)(CK_KBD_SHELL_MS - used);
        if (!next_key(&dec, pend, &np, &ip, left < CK_KBD_SHELL_IDLE_MS ? left : CK_KBD_SHELL_IDLE_MS, &ev)) {
            reason = g_k.ep_halted ? "endpoint halted" : (ck_time_us() - t0) / 1000u >= CK_KBD_SHELL_MS ? "timeout" : "idle";
            break;
        }
        int r = ck_line_feed(&line, ev, echo);
        if (r == CK_LINE_OVERFLOW) {
            ck_printf("\nkeyboard_line: overflow (line refused: %u keys typed, limit %u)\n", line.typed, (unsigned)CK_LINE_CAP);
            ck_puts("keyboard: done (overflow)\n");
            ck_line_reset(&line);
            ck_puts("aienos> ");
            continue;
        }
        if (r != CK_LINE_DONE) continue;
        ck_printf("\nkeyboard_echo: %s\nkeyboard_line: %s\nkeyboard: done (enter)\n", line.buf, line.buf);
        ck_shell_ctx ctx = {ck_conventional_memory_kb(), ck_exception_level(), (ck_time_us() - t0) / 1000u, ck_commit()};
        int ex = ck_shell_run(line.buf, &ctx, shell_out);
        ck_line_reset(&line);
        if (ex) {
            reason = "exit";
            break;
        }
        ck_puts("aienos> ");
    }
    ck_printf("\nkeyboard: done (%s)\n", reason);
    return CK_KBD_OK;
}

void ck_kbd_recovery_report(const char *xhci_state)
{
    if (g_offered) return;
    g_choice = CK_RECOVERY_NORMAL_TIMEOUT;
    ck_printf("recovery_access: unavailable (no operator keyboard: xhci=%s); choice=normal reason=no-keyboard\n",
              xhci_state ? xhci_state : "absent");
}

int ck_kbd_recovery_requested(void) { return g_choice == CK_RECOVERY_CONSOLE; }

void ck_recovery_console_stub(void)
{
    uint8_t id[32];
    char hex[65];
    static const char hx[] = "0123456789abcdef";
    ck_recovery_identity(ck_commit(), id);
    for (int i = 0; i < 32; i++) {
        hex[2 * i] = hx[id[i] >> 4];
        hex[2 * i + 1] = hx[id[i] & 0xfu];
    }
    hex[64] = 0;
    ck_puts("recovery_console: STUB (NEXT-PHASE-3 cut 1: the console itself is not built; no commands)\n");
    ck_printf("recovery_console: identity build_sha256=%s commit=%s (image build identity; not an owner or machine "
              "identity)\n",
              hex, ck_commit());
    ck_puts("recovery_console: halted (no device DMA live; power-cycle to leave)\n");
    for (;;) {
#if defined(__aarch64__)
        __asm__ volatile("msr daifset, #0xf\n\twfi" ::: "memory");
#endif
    }
}

#if defined(CK_CONSOLE_SESSION) && CK_CONSOLE_SESSION
/* ---- console session (C3-1a, QEMU test image only) ----
 * Serial (PL011, polled) and the USB keyboard feed one bounded line editor
 * and the same shell. No time limit, no idle exit: it ends on "exit". The USB
 * half runs inside the xHCI fence (ck_kbd_session_phase); the serial half
 * can also run alone (ck_console_session_serial_only) when the keyboard is
 * unavailable or its endpoint halts. No new authority: the shell commands are
 * the existing ones. */
/* Most bytes the start-of-session drain reads before it gives up. */
#define CK_SESSION_DRAIN_MAX 4096u
static ck_line s_line;
static ck_src_gate s_gate;
static ck_hid_decoder s_dec;
static ck_key_event s_pend[CK_HID_MAX_KEYS];
static unsigned s_np, s_ip;
static uint8_t s_prev;
static int s_serial_ok, s_began, s_ended;
static uint64_t s_t0;

static const char *src_name(int s) { return s == CK_SRC_SERIAL ? "serial" : "usb"; }

static void sess_begin(const char *usb)
{
    if (s_began) return;
    s_began = 1;
    uint32_t cr = 0;
    s_serial_ok = ck_console_rx_ready(&cr);
    if (s_serial_ok) {
        /* Bytes typed before the session are not input. The drain is bounded: a
         * continuous flood must not stall the boot. Error bytes (-2) are drained
         * too; only an empty FIFO (-1) ends it early. */
        unsigned n = 0;
        while (n < CK_SESSION_DRAIN_MAX) {
            if (ck_console_rx_poll() == -1) break;
            n++;
        }
        if (n == CK_SESSION_DRAIN_MAX)
            ck_printf("console_session: serial drain cap hit (%u bytes read, flood?); going on\n", n);
        ck_printf("console_session: serial rx pl011 base=0x%llx uartcr=0x%04x ready\n",
                  (unsigned long long)ck_console_uart_base(), cr);
    } else
        ck_printf("console_session: serial rx unavailable (console uart is %s, uartcr=0x%04x)\n", ck_console_uart_name(), cr);
    ck_printf("console_session: ready (usb %s; no time limit, no idle exit; ends on exit)\n", usb);
    ck_line_reset(&s_line);
    ck_src_gate_reset(&s_gate);
    s_np = s_ip = 0;
    s_t0 = ck_time_us();
    ck_puts("console> ");
}

static void sess_drops(int owner, unsigned dropped)
{
    if (dropped)
        ck_printf("console_input: dropped %u key(s) from %s while %s owned the line\n", dropped,
                  src_name(owner == CK_SRC_SERIAL ? CK_SRC_USB : CK_SRC_SERIAL), src_name(owner));
}

/* One key from src. Returns 1 when the shell ran "exit". */
static int sess_key(int src, ck_key_event ev)
{
    if (!ck_src_gate_accept(&s_gate, src, ev)) return 0;
    int r = ck_line_feed(&s_line, ev, echo);
    if (r == CK_LINE_MORE && ev.kind != CK_KEY_ESCAPE) return 0;
    int owner = s_gate.owner ? s_gate.owner : src; /* an unowned Enter or Escape: the key's own source */
    if (r == CK_LINE_MORE && s_gate.owner == CK_SRC_NONE) return 0; /* Escape on an empty line: nothing to clear */
    if (r == CK_LINE_OVERFLOW)
        ck_printf("\nconsole_line: overflow (line refused: %u keys typed, limit %u) source=%s\n", s_line.typed,
                  (unsigned)CK_LINE_CAP, src_name(owner));
    else if (r == CK_LINE_DONE)
        ck_printf("\nconsole_echo: %s\nconsole_line: %s source=%s\n", s_line.buf, s_line.buf, src_name(owner));
    else
        ck_printf("\nconsole_line: cleared source=%s\n", src_name(owner));
    sess_drops(owner, ck_src_gate_release(&s_gate));
    int ex = 0;
    if (r == CK_LINE_DONE) {
        ck_shell_ctx ctx = {ck_conventional_memory_kb(), ck_exception_level(), (ck_time_us() - s_t0) / 1000u, ck_commit()};
        ex = ck_shell_run(s_line.buf, &ctx, shell_out);
        if (ex) ck_printf("console_session: exit (source=%s)\n", src_name(owner));
    }
    ck_line_reset(&s_line);
    if (!ex) ck_puts("console> ");
    return ex;
}

/* 0: the session ended (exit); 1: the USB endpoint halted, serial goes on. */
static int sess_loop(int usb_ok)
{
    for (;;) {
        int idle = 1;
        if (usb_ok) {
            if (s_ip < s_np) {
                ck_key_event ev = s_pend[s_ip++];
                idle = 0;
                if (sess_key(CK_SRC_USB, ev)) { s_ended = 1; return 0; }
            } else {
                uint8_t rep[CK_HID_REPORT_LEN];
                if (poll_report(rep)) {
                    s_np = ck_hid_decode(&s_dec, rep, sizeof rep, s_pend);
                    s_ip = 0;
                    idle = 0;
                }
                if (g_k.ep_halted) {
                    ck_printf("\nconsole_session: usb endpoint halted (completion %u); the keyboard is revoked, serial goes on\n",
                              g_k.last_code);
                    return 1;
                }
            }
        }
        if (s_serial_ok) {
            int b = ck_console_rx_poll();
            if (b == -2) idle = 0; /* errored byte: dropped by the console, look again at once */
            if (b >= 0) {
                idle = 0;
                ck_key_event ev = ck_serial_key((uint8_t)b, &s_prev);
                if (ev.kind != CK_KEY_NONE && sess_key(CK_SRC_SERIAL, ev)) { s_ended = 1; return 0; }
            }
        }
        if (idle && usb_ok && !(rd(g_k.op + OP_PORTSC(g_k.port)) & PS_CCS)) {
            ck_printf("\nconsole_session: usb keyboard disconnected (port %u); the keyboard is revoked, serial goes on\n", g_k.port);
            return 1;
        }
        if (idle) ck_udelay(100);
    }
}

int ck_kbd_session_phase(volatile uint8_t *bar0, uint8_t *mem, uint64_t phys, size_t bytes)
{
    int rc = start(bar0, mem, phys, bytes);
    if (rc) {
        ck_printf("console_session: usb keyboard unavailable (%s, rc=%d, completion %u)\n", g_k.why, rc, g_k.last_code);
        return rc;
    }
    ck_printf("console_session: usb keyboard attached (port %u, slot %u, endpoint 0x%02x), inside the xHCI fence\n",
              g_k.port, g_k.slot, g_k.kbd.endpoint);
    sess_begin("keyboard ready");
    (void)sess_loop(1);
    return CK_KBD_OK;
}

void ck_console_session_serial_only(void)
{
    if (s_ended) return;
    sess_begin("keyboard unavailable");
    (void)sess_loop(0);
}

int ck_console_session_ended(void) { return s_ended; }
#endif
