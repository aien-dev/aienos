/* nvme_bind.h -- bind native/disk's freestanding NVMe driver to a PCI
 * function through ck.h services (MMIO map, barrier, delay, DMA memory). */
#ifndef AIENOS_CK_NVME_BIND_H
#define AIENOS_CK_NVME_BIND_H
#include "disk.h"
#include "disk_nvme.h"
#include "pci.h"

/* DMA region handed to the driver: 6 fixed pages + 128 KiB bounce. */
#define CK_NVME_DMA_BYTES ((NVME_FIXED_PAGES * NVME_PAGE) + NVME_MAX_XFER)

typedef struct {
    nvme_ctrl ctrl;
    disk_dev disk;
    volatile uint8_t *bar0;
    const pci_func *pf;
    int bound;
    int bm_on; /* bus mastering was enabled for this function */
    int confined;      /* DMA confined by the SMMU (ck_dma_confine) */
    uint32_t stream_id; /* SMMU stream when confined */
} ck_nvme;

/* Find the first class 01/08/02 function, gate DMA, map BAR0, init the
 * controller, fill n->disk, print identify/geometry/atomicity lines, then
 * run the probe (bounds refusal, read LBA 0, write+flush+read-back of the
 * last 4 KiB unit). Returns 0, or a negative NVME_E* / DISK_E* / -1 when
 * no NVMe function exists. */
int ck_nvme_bind(ck_nvme *n, const pci_system *pci);

/* Run the write/flush/read-back probe on the last whole unit of `d`
 * (shared with the host tests). `seed` varies the pattern per boot.
 * The unit's original bytes are read first and written back (flushed and
 * verified) afterwards, so a boot leaves the disk bytes as it found them. */
int ck_disk_rw_probe(const disk_dev *d, uint32_t seed, uint64_t *lba_out);
#endif
