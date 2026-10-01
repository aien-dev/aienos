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

/* ---- boot stages (implemented by the stage worker, all optional) -------- */
/* Each returns 0 on success, negative on failure; core prints the result.
 * Declared weak so the core links and boots without them. */
__attribute__((weak)) int ck_stage_devices(void);  /* PCI, NVMe, virtio-net */
__attribute__((weak)) int ck_stage_security(void); /* capability + ARGUS */
__attribute__((weak)) int ck_stage_store(void);    /* sealed Store on NVMe */

#endif
