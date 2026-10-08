/* usb_kbd.h -- operator keyboard for the AIENOS C kernel: a polled xHCI
 * driver for one USB HID boot keyboard, the operator line input, the console
 * shell of the Rust SEED-0A keyboard gate, and the recovery-access hook.
 * Port of crates/aienos-kernel/src/usb/xhci (controller.rs, ring.rs,
 * context.rs, trb.rs) and crates/aienos-boot/src/usb_keyboard.rs (run), with
 * the same console lines where the Rust gate greps them.
 *
 * Runs only inside the xHCI DMA fence (xhci_fence.c), between the
 * SMMU-confined grant and the revoke: every ring, context and buffer lives
 * in the fence's DMA region, which is the controller stream's only SMMU
 * window. No SMMU confinement means this code never runs (fail closed).
 * Polled only: no interrupt, no scheduler, no Store.
 *
 * Boot flow (devices stage, after NVMe and virtio-net):
 *   1. reset and start the controller, find the first connected port with a
 *      boot keyboard, address it, configure its interrupt IN endpoint
 *      ("keyboard: ready (port P, slot S, endpoint 0xEE)");
 *   2. recovery access: wait at most CK_KBD_RECOVERY_WAIT_MS for one key.
 *      'r' selects the recovery console, any other key or no key continues
 *      ("recovery_access: choice=...");
 *   3. normal boot: the console shell ("aienos> ", lines echoed, Enter ends a
 *      line: "keyboard_echo:", "keyboard_line:", "keyboard: done (enter)",
 *      then the command output) until "exit", CK_KBD_SHELL_IDLE_MS without a
 *      key, CK_KBD_SHELL_MS in all, or a halted endpoint;
 *   4. the fence then halts the controller and revokes its DMA. A recovery
 *      choice is acted on by devices.c after that revoke: every device DMA
 *      released, then ck_recovery_console_stub (identity digest, halt).
 * QEMU is not hardware: nothing here is physically qualified. */
#ifndef AIENOS_CK_USB_KBD_H
#define AIENOS_CK_USB_KBD_H
#include <stddef.h>
#include <stdint.h>

#ifndef CK_KBD_RECOVERY_WAIT_MS
#define CK_KBD_RECOVERY_WAIT_MS 5000u
#endif
#ifndef CK_KBD_SHELL_MS
#define CK_KBD_SHELL_MS 60000u
#endif
#ifndef CK_KBD_SHELL_IDLE_MS
#define CK_KBD_SHELL_IDLE_MS 15000u
#endif
/* Pages of the fence's DMA region the driver uses (4 KiB each). */
#define CK_KBD_DMA_PAGES 16u
#define CK_KBD_MAX_SCRATCHPADS 6u

enum {
    CK_KBD_OK = 0,
    CK_KBD_E_ARG = -651,     /* bad region or registers */
    CK_KBD_E_UNSUP = -652,   /* controller needs something this driver lacks */
    CK_KBD_E_TIMEOUT = -653, /* a bounded wait ran out */
    CK_KBD_E_FAILED = -654,  /* a command or transfer completed with an error */
    CK_KBD_E_NOKBD = -655,   /* no boot keyboard on any connected port */
};

/* Steps 1-3 on a controller the fence has granted (bus master on, stream
 * confined) and halted. mem/phys: the fence's DMA region (identity mapped,
 * Normal Non-cacheable, CK_KBD_DMA_PAGES pages). Never touches PCI config
 * or the SMMU; the caller revokes afterwards whatever this returns. */
int ck_kbd_phase(volatile uint8_t *bar0, uint8_t *mem, uint64_t phys, size_t bytes);
/* After the devices stage's xHCI step: prints the recovery-access line when
 * the phase never offered it (no keyboard: absent, denied, failed). */
void ck_kbd_recovery_report(const char *xhci_state);
/* 1 when the operator chose the recovery console. */
int ck_kbd_recovery_requested(void);
/* Recovery console, cut-1 stub: prints the image identity digest and halts
 * this CPU for good (interrupts masked, WFI). The caller must have released
 * every device's DMA first. Never returns. */
__attribute__((noreturn)) void ck_recovery_console_stub(void);

#if defined(CK_CONSOLE_SESSION) && CK_CONSOLE_SESSION
/* Console session (C3-1a, TEST-ONLY QEMU image): the operator console that
 * keeps taking serial and USB input until "exit". ck_kbd_session_phase runs
 * inside the xHCI fence in place of ck_kbd_phase; ck_console_session_serial_only
 * runs the serial half alone (no keyboard, or its endpoint halted);
 * ck_console_session_ended is 1 once the shell ran "exit". */
int ck_kbd_session_phase(volatile uint8_t *bar0, uint8_t *mem, uint64_t phys, size_t bytes);
void ck_console_session_serial_only(void);
int ck_console_session_ended(void);
#endif
#endif
