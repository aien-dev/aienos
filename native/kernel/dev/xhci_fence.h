/* xhci_fence.h -- DMA fence for the xHCI (USB) controller: the DMA-safety
 * half of the SEED-0A keyboard gate (GATES.md "SEED-0A keyboard", rows 25-28,
 * 31, 32). Behaviour follows crates/aienos-boot/src/usb_keyboard.rs (run,
 * revoke_dma) and the Rust dma_gate; observables use the Rust line texts
 * where the Rust gate (scripts/qemu_keyboard_test.sh) greps them.
 *
 * What it does, after ExitBootServices, in the devices stage:
 *   1. find the first class 0x0c0330 (xHCI) function on the ECAM bus walk
 *      ("keyboard: xhci SSSS:BB:DD.F mmio 0x..");
 *   2. the post-exit bus-master sweep (pci_sweep_bus_master) already ran at
 *      the start of the devices stage; read the controller's PCI COMMAND
 *      register back ("xhci_pci: command=0x.... bus_master=off") and stop if
 *      bus mastering is still on;
 *   3. DMA gate, same rule as NVMe and virtio-net: no SMMU confinement means
 *      no DMA. The controller's DMA region is allocated first and becomes its
 *      stream's only SMMU window (ck_dma_confine); only then are memory
 *      decode and bus mastering enabled. Without an SMMU (or an SMMU that did
 *      not come up) the controller stays off: "dma_gate: xhci denied
 *      (NoSmmu), bus master stays off" + "keyboard: unavailable (SMMU DMA
 *      isolation not active)". There is no unconfined bypass for the xHCI,
 *      not even in the TEST-ONLY CK_QEMU_UNSAFE_DMA=1 build;
 *   4. with the grant: map BAR0 and make sure the controller is halted
 *      (USBCMD.R/S = 0, USBSTS.HCH = 1, bounded wait); then, only if it
 *      halted, the operator phase of usb_kbd.c runs on this DMA region: HID
 *      boot keyboard, recovery-access hook and console shell (rows 29-30);
 *   5. release, in the NVMe halt order: controller halted while it can
 *      still DMA, bus master off with read-back ("dma_gate: xhci bus master
 *      revoked"), the controller's COMMAND register read back again
 *      ("xhci_pci: after phase command=0x.... bus_master=off"), stream back
 *      to abort ("smmu: xhci stream 0x.. returned to abort (rc=0)").
 *
 * TEST-ONLY mutations (CK_TEST_XHCI_MUTATION, refused with
 * CK_HARDWARE_STAGING by the Makefile and by an #error here); each must
 * make scripts/qemu_ck_keyboard_test.sh --mutation see its rows FAIL:
 *   1 bm-left-on    the xHCI's bus mastering is switched back on after the
 *                   sweep and left on before the gate (row 27)
 *   2 no-revoke     the release skips the bus-master clear (row 31)
 *   3 grant-no-smmu with no SMMU the xHCI is granted DMA anyway (row 28)
 *   4 no-sweep      the post-exit bus-master sweep is skipped (row 26)
 * A mutation image announces itself on the console. QEMU only. */
#ifndef AIENOS_CK_XHCI_FENCE_H
#define AIENOS_CK_XHCI_FENCE_H
#include "pci.h"

/* DMA region the controller is confined to (its only SMMU window): the 16
 * pages of usb_kbd.c (DCBAA, device and input contexts, command and event
 * rings, ERST, EP0 and interrupt-IN rings, buffer, up to 6 scratchpads). */
#define CK_XHCI_DMA_BYTES (64u * 1024u)
#define CK_XHCI_CLASS 0x0c0330u
/* xHCI 1.2 section 5.4.1: the controller halts within 16 ms of R/S = 0. */
#define CK_XHCI_HALT_WAIT_US 16000u

enum {
    CK_XHCI_OK = 0,
    CK_XHCI_ABSENT = 1,       /* no xHCI function: nothing to fence */
    CK_XHCI_E_ARG = -601,     /* BAR0 unusable */
    CK_XHCI_E_BME = -602,     /* bus mastering still on before the gate */
    CK_XHCI_E_DENIED = -603,  /* no SMMU confinement: controller left off */
    CK_XHCI_E_DMA = -604,     /* DMA region allocation failed */
    CK_XHCI_E_HALT = -605,    /* controller would not halt (still released) */
};

/* TEST-ONLY mutation numbers (CK_TEST_XHCI_MUTATION). */
#define CK_XHCI_MUT_BM_LEFT_ON 1
#define CK_XHCI_MUT_NO_REVOKE 2
#define CK_XHCI_MUT_GRANT_NO_SMMU 3
#define CK_XHCI_MUT_NO_SWEEP 4

/* Steps 1-5 above. Always leaves the controller released (bus master off,
 * stream back to abort) before returning, except under the TEST-ONLY
 * no-revoke mutation. Returns CK_XHCI_OK, CK_XHCI_ABSENT or a CK_XHCI_E_*. */
int ck_xhci_fence(const pci_system *pci);
/* Halt, bus master off, stream back to abort if still live. Idempotent. */
void ck_xhci_release(void);
/* 1 while the controller may still DMA (bus master on or stream confined). */
int ck_xhci_live(void);
/* 1 when the post-exit bus-master sweep should run (0 only under the
 * TEST-ONLY no-sweep mutation); prints the mutation banner once. */
int ck_xhci_sweep_enabled(void);
/* Called by the devices stage right after the sweep (TEST-ONLY bm-left-on
 * mutation hook; does nothing in every other build). */
void ck_xhci_after_sweep(const pci_system *pci);
/* Short state for the devices summary line: absent, fenced, denied, ... */
const char *ck_xhci_state(void);
#endif
