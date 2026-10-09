/* nvme_bind.h -- bind native/disk's freestanding NVMe driver to a PCI
 * function through ck.h services (MMIO map, barrier, delay, DMA memory). */
#ifndef AIENOS_CK_NVME_BIND_H
#define AIENOS_CK_NVME_BIND_H
#include "disk.h"
#include "disk_nvme.h"
#include "pci.h"
#include "disk_part.h"

/* DMA region handed to the driver: 6 fixed pages + 128 KiB bounce. */
#define CK_NVME_DMA_BYTES ((NVME_FIXED_PAGES * NVME_PAGE) + NVME_MAX_XFER)

typedef struct {
    nvme_ctrl ctrl;
    disk_dev disk;
    volatile uint8_t *bar0;
    const pci_func *pf;
    pci_func fn;       /* the bound function, built from the discovery result (pf points here) */
    int claimed;       /* ownership recorded once: a second bind is refused until the first is fully released */
    int bound;
    int bm_on; /* bus mastering was enabled for this function */
    int confined;      /* DMA confined by the SMMU (ck_dma_confine) */
    int shut;          /* normal shutdown already attempted (ck_nvme_shutdown_bound) */
    uint32_t stream_id; /* SMMU stream when confined */
    ck_part part;      /* the AIENOS partition view (dev/disk_part.h): the only writable disk */
} ck_nvme;

/* Bind the NVMe the multi-segment read-only discovery found (aienos#31): the
 * first class 01/08/02 function in `found` (lowest segment, bus, device,
 * function; any segment). Ownership is recorded once (n->claimed) before any
 * device access: a second call while owned, or while DMA is not fully released,
 * returns NVME_ESTATE and touches nothing. `probe` (may be NULL) is only used
 * to keep the "assigned by stage" log wording. Returns -1 when discovery holds
 * no NVMe. Bus mastering a function firmware left enabled is cleared before the
 * DMA gate (refused if it sticks). DMA gate and everything after it are
 * unchanged:
 *
 * gate DMA, map BAR0, init the
 * controller, fill n->disk, print identify/geometry/atomicity lines, run the
 * read-only checks (bounds refusal, read LBA 0), parse the GPT read-only and
 * select the AIENOS partition (n->part; none or an invalid GPT: print
 * "disk: no AIENOS partition, refusing writes" and return the CK_GPT_* code
 * with nothing written), check the translation layer refuses past the
 * partition end, then run the write+flush+read-back probe on the last 4 KiB
 * unit OF THE PARTITION. Returns 0, or a negative NVME_E* / DISK_E* /
 * CK_GPT_* / -1 when no NVMe function exists. */
int ck_nvme_bind(ck_nvme *n, const pci_found *found, uint32_t nfound, const pci_system *probe);

/* Normal NVMe shutdown (dev/nvme_shutdown.c) on the bound controller, run
 * while bus mastering is still on, before the bus-master revoke. Prints
 * "nvme: shutdown normal cc=0x..->0x.. csts=0x.. shst=<result> waited_us=N".
 * Runs at most once per bind; returns the CK_NVME_SHUT_* code. */
int ck_nvme_shutdown_bound(ck_nvme *n);

/* Run the write/flush/read-back probe on the last whole unit of `d` (the
 * kernel passes the AIENOS partition view, never the whole namespace;
 * shared with the host tests). `*lba_out` is relative to `d`. `seed` varies the pattern per boot.
 * The unit's original bytes are read first and written back (flushed and
 * verified) afterwards, so a boot leaves the disk bytes as it found them. */
int ck_disk_rw_probe(const disk_dev *d, uint32_t seed, uint64_t *lba_out);
#endif
