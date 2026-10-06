/* acpi_dev.h -- bounded static scan of ACPI definition blocks (DSDT, SSDT)
 * for Device objects: name path, _HID / _CID and the first memory range of
 * a constant _CRS resource template. Pure functions over memory (identity
 * mapped in the kernel, host buffers in the tests and the host tool).
 *
 * This is a scanner, not an AML interpreter: nothing is executed. It reads
 *   Device (NAME) { Name (_HID, "STRING" | EisaId) Name (_CID, ...)
 *                   Name (_CRS, Buffer) | Method (_CRS) { ... Buffer ... } }
 * where the _CRS buffer is a constant resource template (the first buffer
 * inside a _CRS method is taken; the DGX Spark USB controllers and the QEMU
 * virt UART use exactly these forms, see native/kernel/README.md). _STA is
 * never evaluated: a device the firmware would report absent is still
 * listed, and the caller must cope with a controller that does not answer.
 * Every read is bounds checked against the table length; the table itself
 * must pass signature, length and checksum checks first.
 * Spec: ACPI 6.5 sections 5.2.11 (DSDT/SSDT), 6.1.5 (_HID), 6.4 (resource
 * descriptors), 20.2 (AML grammar: DefDevice, PkgLength, NameString). */
#ifndef AIENOS_CK_ACPI_DEV_H
#define AIENOS_CK_ACPI_DEV_H
#include <stddef.h>
#include <stdint.h>

#define CK_AML_PATH_MAX 48u  /* "\\" + up to 9 segments "XXXX." + NUL */
#define CK_AML_ID_MAX 16u    /* _HID / _CID string, NUL terminated */

struct ck_acpi_device {
    char path[CK_AML_PATH_MAX]; /* name as written at the DeviceOp, usually relative ("USB0", "COM0") */
    char hid[CK_AML_ID_MAX];    /* "" when the device has no _HID */
    char cid[CK_AML_ID_MAX];    /* "" when no _CID */
    uint64_t mmio_base;         /* first memory range of _CRS, 0 when none */
    uint64_t mmio_len;
    uint32_t offset;            /* DeviceOp offset in the table */
};

enum {
    CK_AML_OK = 0,
    CK_AML_E_SIG = -1,      /* signature is not DSDT or SSDT */
    CK_AML_E_LEN = -2,      /* header length shorter than 36 or longer than the buffer */
    CK_AML_E_SUM = -3,      /* checksum does not sum to zero */
};

/* Checks a definition block: signature DSDT or SSDT, 36 <= length <= avail,
 * byte sum zero. CK_AML_OK or a CK_AML_E_*. */
int ck_aml_table_ok(const void *table, size_t avail);

/* Scans one checked definition block. For every Device object whose _HID or
 * _CID equals one of ids[0..nids) (nids == 0: every device), fills out[n]
 * while n < max. Returns the number of matching devices (it may exceed max;
 * only max are stored), or a CK_AML_E_* for a table that fails
 * ck_aml_table_ok. *seen (may be NULL) gets the number of Device objects
 * parsed, matching or not. A malformed device (package past the end, bad
 * name) is skipped, never followed past the table. */
int ck_aml_scan(const void *table, size_t avail, const char *const *ids, unsigned nids,
                struct ck_acpi_device *out, unsigned max, unsigned *seen);

/* Decodes a compressed EISA id (the DWORD form of EisaId("PNP0D15")) into 7
 * characters + NUL. */
void ck_aml_eisaid(uint32_t v, char out[8]);

/* Final name segments equal (each padded to 4 with '_'): "USB0" matches "\\_SB_.USB0".
 * The scan reports each device by the name written at its DeviceOp, which is
 * usually relative to an enclosing Scope; callers match IORT names this way
 * and must refuse a name that more than one device carries. */
int ck_aml_last_seg_eq(const char *a, const char *b);

/* Same name, ignoring a leading "\\" and padding each dot-separated segment
 * to 4 characters with '_' ("\\_SB.USB0" equals "_SB_.USB0"). */
int ck_aml_path_eq(const char *a, const char *b);
#endif
