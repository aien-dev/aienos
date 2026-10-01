/* ck.h -- AIENOS C kernel core: the services the core gives to device,
 * Store and security code. Freestanding; no libc.
 *
 * Owner split (Lane 18):
 *   core  (native/boot, native/kernel/{arch,mm,core}) implements everything
 *         declared under "core services".
 *   stage (native/kernel/{dev,svc}) implements the "boot stages" at the end;
 *         core calls them from kmain in order, after MMU, heap, GIC and timer
 *         are up. A stage that is not linked is reported as "not linked".
 *
 * Memory model: the core runs with the MMU on and an identity map (VA == PA)
 * for RAM and for every MMIO region handed out by ck_mmio_map. QEMU is not
 * hardware: nothing built on these services is physically qualified.
 */
#ifndef AIENOS_CK_H
#define AIENOS_CK_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

/* ---- core services ------------------------------------------------------ */

/* Console (SPCR / PL011). Format: %s %c %d %u %x %ld %lu %lx %lld %llu %llx
 * %zu %zx %p %%, optional '0' pad and width (e.g. %016llx). */
void ck_puts(const char *s);
void ck_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void ck_vprintf(const char *fmt, va_list ap);

/* Prints "report_kind: panic" plus the message, then halts via PSCI reset
 * (or WFI loop if PSCI is missing). Never returns. */
__attribute__((noreturn, format(printf, 1, 2))) void ck_panic(const char *fmt, ...);

/* Kernel heap. Zeroed memory, 16-byte aligned. NULL on exhaustion. */
void *ck_alloc(size_t bytes);
void ck_free(void *p);

/* Physically contiguous, zeroed, `align`-aligned (power of two >= 4096)
 * memory that a device may DMA to. Mapped Normal Non-cacheable, so no cache
 * maintenance is needed by callers. *phys receives the bus address (identity
 * map: equals the pointer value). NULL on exhaustion. Never freed. */
void *ck_dma_alloc(size_t bytes, size_t align, uint64_t *phys);

/* Map [phys, phys+len) as Device-nGnRE (identity) and return the pointer.
 * Panics if the range overlaps RAM. */
volatile void *ck_mmio_map(uint64_t phys, size_t len);

/* Full system barrier (dsb sy). */
void ck_mb(void);

/* ACPI: the first table with this 4-byte signature ("MCFG", "MADT" is
 * "APIC", "SPCR", "IORT"), checksum already verified; NULL if absent. */
const void *ck_acpi_find(const char sig[4]);

/* Monotonic time from the generic timer. */
uint64_t ck_time_us(void);
void ck_udelay(uint32_t us);

/* Boot facts. */
const char *ck_commit(void);  /* git commit the image was built from */
uint32_t ck_boot_count_hint(void); /* 0; Store keeps the real count */

/* Interrupts (added by core, Lane 18). GICv3, group 1, routed to the boot
 * CPU. Handlers run in IRQ context with interrupts masked; the core
 * acknowledges and EOIs around the call. INTID 30 (timer) is reserved.
 * ck_irq_register: 0 ok, -1 bad/reserved intid, -2 already registered.
 * ck_irq_enable: 0 ok, -1 before the GIC is up or bad intid.
 * ck_irq_cpu_enable(1) unmasks IRQs on this CPU, (0) masks them. */
int ck_irq_register(uint32_t intid, void (*fn)(void *arg), void *arg);
int ck_irq_enable(uint32_t intid);
void ck_irq_cpu_enable(int on);

/* DMA isolation (IORT + SMMUv3, core/smmu_svc.c; added by Lane 25). The
 * first call brings the SMMU up with GBPA.ABORT set and every stream in
 * abort, then gives PCI requester `rid` (bus<<8 | dev<<3 | fn, segment 0)
 * a stage-1 table that maps only [phys, phys+len) at the same bus address
 * (identity IOVA, Normal Non-cacheable, read/write). Any DMA outside the
 * window faults and is aborted. phys and len must be 4 KiB aligned. At most
 * CK_DMA_MAX_STREAMS confinements, one per stream.
 * Returns 0 and fills *out, or:
 *   CK_SMMU_ABSENT    no SMMUv3 in the IORT (or no IORT): no confinement
 *   CK_SMMU_FAILED    SMMU present but bring-up or this stream failed;
 *                     the SMMU stays off behind ABORT or the stream aborts
 *   CK_SMMU_NOSTREAM  the IORT maps no stream for this requester
 *   CK_SMMU_EARG      bad window, stream already confined, or table full
 * Device DMA may be enabled only after a 0 return. */
#define CK_SMMU_ABSENT (-1)
#define CK_SMMU_FAILED (-2)
#define CK_SMMU_NOSTREAM (-3)
#define CK_SMMU_EARG (-4)
#define CK_DMA_MAX_STREAMS 8
struct ck_dma_confinement {
    uint64_t smmu_base;
    uint32_t stream_id;
    uint64_t iova, len;
};
int ck_dma_confine(uint32_t rid, uint64_t phys, uint64_t len, struct ck_dma_confinement *out);
/* Return a confined stream to abort (after the device's bus mastering is
 * off). 0 ok, CK_SMMU_EARG if not confined, CK_SMMU_FAILED on a command
 * timeout. */
int ck_dma_unconfine(uint32_t stream_id);
/* Drain the SMMU event queue. Returns how many records named `stream_id`
 * (others are dropped); *first gets the first of them. -1 if no SMMU. */
#define CK_DMA_FAULT_TRANSLATION 0x10u /* SMMUv3 F_TRANSLATION event */
struct ck_dma_fault {
    uint32_t type, stream_id;
    uint64_t addr;
    int overflow;
};
int ck_dma_faults(uint32_t stream_id, struct ck_dma_fault *first);

/* ---- boot stages (implemented by the stage worker, all optional) -------- */
/* Each returns 0 on success, negative on failure; core prints the result.
 * Declared weak so the core links and boots without them. */
__attribute__((weak)) int ck_stage_devices(void);  /* PCI, NVMe, virtio-net */
__attribute__((weak)) int ck_stage_security(void); /* capability + ARGUS */
__attribute__((weak)) int ck_stage_store(void);    /* sealed Store on NVMe */
/* Optional devices-stage hook: ck_reset calls it once, before PSCI reset or
 * off (final report, panic, fault), so no device keeps DMA across a reset. */
__attribute__((weak)) void ck_stage_quiesce(void);

#endif
