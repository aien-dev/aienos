/* dma_window.h -- software-only DMA confinement for the Raspberry Pi 5
 * (ADR 0020). One bounce window, an overflow-safe validator, and descriptor
 * ring helpers that only ever emit addresses inside the window.
 *
 * LABEL: software-only DMA confinement (Pi 5, weaker than the Spark).
 * This is an explicit Pi-only exception to ADR 0012 rule 5. The Spark's DMA
 * is fenced by SMMU stream windows (core/smmu.c); this file is not part of
 * that and is not linked into the Spark, QEMU or any default image.
 *
 * Pure C, freestanding (stdint only), no allocation, no I/O. The GEM
 * descriptor bit layout is NOT modelled here (UNVERIFIED, driver cut): a
 * descriptor is just (addr, len, flags) from the driver's own record. */
#ifndef AIENOS_CK_DMA_WINDOW_H
#define AIENOS_CK_DMA_WINDOW_H
#include <stdint.h>

#define CK_DMAW_MAX_BYTES (2u * 1024u * 1024u) /* ADR 0020 rule 1: <= 2 MiB */
#define CK_DMAW_MIN_BYTES 4096u
#define CK_DMAW_MAX_FRAME 1536u /* ADR 0020 rule 7: no jumbo frames */
#define CK_DMAW_BUF_ALIGN 8u    /* driver-chosen, not taken from the GEM manual */
#define CK_DMAW_RING_MAX 256u

enum {
    CK_DMAW_OK = 0,
    CK_DMAW_E_LATCHED = 1, /* the NIC is halted until reboot */
    CK_DMAW_E_RANGE = 2,   /* not fully inside the window */
    CK_DMAW_E_ZERO = 3,    /* zero length */
    CK_DMAW_E_ALIGN = 4,
    CK_DMAW_E_PARAM = 5,   /* bad init or call arguments */
    CK_DMAW_E_NOSPACE = 6, /* window or ring full (does not latch) */
    CK_DMAW_E_STALE = 7,   /* slot not in flight: reuse or double completion */
    CK_DMAW_E_BIG = 8,     /* frame larger than CK_DMAW_MAX_FRAME */
    CK_DMAW_E_INDEX = 9    /* device-supplied slot index out of range */
};

struct ck_dmaw {
    uint64_t base; /* bus address of the window */
    uint64_t size; /* power of two, 4 KiB..2 MiB, base aligned to size */
    uint64_t next; /* bump offset */
    int latched;
    int last_err;
};

/* Take a power-of-two, size-aligned block (bus address `bus_base`, CPU
 * mapping `mem`) and zero it. The block is used for nothing else. */
int ck_dmaw_init(struct ck_dmaw *w, void *mem, uint64_t bus_base, uint64_t size);

/* Is [addr, addr+len) fully inside the window? Never computes addr+len.
 * Any violation latches the window; a latched window refuses everything. */
int ck_dmaw_validate(struct ck_dmaw *w, uint64_t addr, uint64_t len);
int ck_dmaw_validate_aligned(struct ck_dmaw *w, uint64_t addr, uint64_t len, uint64_t align);

/* Carve `len` bytes at `align` (power of two) out of the window; returns the
 * bus address through *addr. Running out of space is E_NOSPACE (no latch). */
int ck_dmaw_alloc(struct ck_dmaw *w, uint64_t len, uint64_t align, uint64_t *addr);

/* Operator-visible halt: set when anything went wrong; cleared only by init. */
int ck_dmaw_halted(const struct ck_dmaw *w);

/* The descriptor handed to the device. Built only from the driver's record. */
struct ck_dmaw_desc {
    uint64_t addr;
    uint32_t len;
    uint32_t flags;
};

enum { CK_DMAW_SLOT_FREE = 0, CK_DMAW_SLOT_INFLIGHT = 1 };

struct ck_dmaw_slot { /* the driver's shadow of one descriptor */
    struct ck_dmaw_desc d;
    uint32_t state;
};

struct ck_dmaw_ring {
    struct ck_dmaw_slot *slots; /* caller storage, kernel memory, NOT in the window */
    uint32_t n;                 /* power of two, <= CK_DMAW_RING_MAX */
    uint32_t head;              /* next slot to post */
    uint32_t inflight;
};

int ck_dmaw_ring_init(struct ck_dmaw_ring *r, struct ck_dmaw_slot *slots, uint32_t n);

/* Post one buffer: validated (range, alignment, frame cap) against the window,
 * recorded in the shadow. *idx is the slot used. A full ring is E_NOSPACE. */
int ck_dmaw_ring_post(struct ck_dmaw_ring *r, struct ck_dmaw *w, uint64_t addr, uint32_t len,
                      uint32_t flags, uint32_t *idx);

/* Produce the descriptor for slot idx FROM THE SHADOW ONLY (never from ring
 * memory the device can write), re-validated. Slot not in flight: E_STALE. */
int ck_dmaw_ring_emit(const struct ck_dmaw_ring *r, struct ck_dmaw *w, uint32_t idx,
                      struct ck_dmaw_desc *out);

/* Device says slot idx finished with `got` bytes. Index out of range, slot not
 * in flight, or got > posted length: latch. Otherwise the slot is freed. */
int ck_dmaw_ring_complete(struct ck_dmaw_ring *r, struct ck_dmaw *w, uint32_t idx, uint32_t got);

#endif
