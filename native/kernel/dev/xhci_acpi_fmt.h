/* xhci_acpi_fmt.h -- console lines of the platform xHCI discovery (ACPI
 * DSDT/SSDT + IORT), shared by dev/xhci_fence.c (the kernel) and
 * tools/ck_acpi_scan.c (the host tool that runs the same scan over firmware
 * tables dumped under Linux and prints the lines the kernel will print).
 * NEXT-PHASE-3 cut 2. */
#ifndef AIENOS_CK_XHCI_ACPI_FMT_H
#define AIENOS_CK_XHCI_ACPI_FMT_H

/* ACPI ids of a platform xHCI: the DGX Spark controllers (NVDA8000,
 * NVDA8001, measured under Ubuntu) and the generic xHCI ids Linux
 * xhci_plat_hcd binds (PNP0D10, PNP0D15). */
#define CK_XHCI_ACPI_IDS { "NVDA8000", "NVDA8001", "PNP0D10", "PNP0D15" }
#define CK_XHCI_ACPI_NIDS 4u
#define CK_XHCI_PLAT_MAX 8u
/* Positive control for the walker: the Arm PL011 UART id. QEMU virt
 * describes its UART as ARMH0011 at 0x09000000 (QEMU hw/arm/virt.c memory
 * map); the kernel prints the first one found. */
#define CK_ACPI_CONTROL_ID "ARMH0011"

#define CK_ACPI_SCAN_FMT "acpi_scan: tables=%u refused=%u first_refusal=%d devices=%u (static scan; _STA not evaluated)\n"
#define CK_ACPI_SCAN_NONE "acpi_scan: no DSDT reachable (FADT missing or table not mapped)\n"
#define CK_ACPI_CONTROL_FMT "acpi_scan: control %s %s mmio=0x%llx+0x%llx\n"
#define CK_ACPI_CONTROL_NONE "acpi_scan: control " CK_ACPI_CONTROL_ID " none\n"
#define CK_XHCI_ACPI_FMT "xhci_acpi: %s hid=%s cid=%s table=%s mmio=0x%llx+0x%llx\n"
#define CK_XHCI_ACPI_COUNT_FMT "xhci_acpi: %d platform controller(s)\n"
/* Platform fence (one line per controller tried, in table order). */
#define CK_XHCI_PLAT_TRY_FMT "xhci_plat: %s try mmio=0x%llx+0x%llx\n"
#define CK_XHCI_PLAT_SKIP_FMT "xhci_plat: %s skipped (%s)\n"
#define CK_XHCI_PLAT_DENY_FMT "dma_gate: xhci %s denied (%s), controller left halted\n"
#define CK_XHCI_PLAT_OTHER_FMT "dma_gate: xhci %s denied (OtherSmmu smmu=0x%llx stream=0x%x), controller left halted\n"
#define CK_XHCI_PLAT_GRANT_FMT "dma_gate: xhci %s granted (Confined) smmu=0x%llx stream=0x%x\n"
#endif
