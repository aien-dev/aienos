/* usb_hid.h -- pure logic of the C kernel operator input (no MMIO, host
 * tested in svc/tests/stage_test.c): USB HID boot-keyboard report decode to a
 * small fixed keymap, the configuration-descriptor walk that finds a boot
 * keyboard, the operator line editor (bounded, fails closed on overflow), the
 * console shell commands of the Rust SEED-0A keyboard gate, and the
 * recovery-access key decision.
 *
 * Behaviour follows the Rust reference where the Rust gate
 * (scripts/qemu_keyboard_test.sh) observes it: crates/aienos-kernel/src/usb/
 * hid.rs (BootKeyboardDecoder: an event per newly pressed usage, rollover
 * reports ignored), usb/descriptor.rs (find_boot_keyboard) and shell.rs
 * (LINE_CAPACITY 64, TOKEN_CAPACITY 16, commands help mem el report uptime
 * exit). One deliberate difference: the Rust line silently drops keys past
 * its capacity; this editor refuses the whole line instead (fail closed).
 * Freestanding. QEMU is not hardware: nothing here is physically qualified. */
#ifndef AIENOS_CK_USB_HID_H
#define AIENOS_CK_USB_HID_H
#include <stddef.h>
#include <stdint.h>

/* ---- HID boot keyboard report (HID 1.11 appendix B.1) ---- */
#define CK_HID_REPORT_LEN 8u
#define CK_HID_MAX_KEYS 6u
enum ck_key_kind { CK_KEY_NONE = 0, CK_KEY_CHAR, CK_KEY_ENTER, CK_KEY_BACKSPACE, CK_KEY_ESCAPE };
typedef struct {
    uint8_t kind; /* enum ck_key_kind */
    char c;       /* CK_KEY_CHAR only */
} ck_key_event;
typedef struct {
    uint8_t previous[CK_HID_MAX_KEYS];
} ck_hid_decoder;

/* Fixed keymap (US layout, the only one): usages a-z (shift: A-Z), 1-0,
 * space, '-', '.', '/', Enter, Backspace, Escape. Every other usage, and
 * shifted digits or punctuation, yields nothing. */
ck_key_event ck_hid_usage(uint8_t usage, int shift);
/* Decode one 8-byte report: one event per usage that was not pressed in the
 * previous report (key repeat is not generated). A phantom/rollover report
 * (first usage 0x01) and a report of the wrong length change nothing.
 * Returns the number of events written to out (at most CK_HID_MAX_KEYS). */
unsigned ck_hid_decode(ck_hid_decoder *d, const uint8_t *report, size_t len, ck_key_event out[CK_HID_MAX_KEYS]);

/* ---- configuration descriptor: first boot keyboard ---- */
typedef struct {
    uint8_t configuration;   /* bConfigurationValue */
    uint8_t interface;       /* bInterfaceNumber of class 3 / subclass 1 / protocol 1 */
    uint8_t endpoint;        /* bEndpointAddress of its first interrupt IN endpoint */
    uint16_t max_packet;     /* wMaxPacketSize bits 10:0 */
    uint8_t interval;        /* bInterval */
} ck_boot_kbd;
/* 0 and *out filled, or -1 (no boot keyboard interface with an interrupt IN
 * endpoint, or a malformed descriptor: every length is bounds checked, the
 * walk never reads past min(len, wTotalLength)). */
int ck_usb_find_boot_kbd(const uint8_t *cfg, size_t len, ck_boot_kbd *out);

/* ---- operator line editor ---- */
#define CK_LINE_CAP 64u /* Rust shell LINE_CAPACITY */
enum { CK_LINE_MORE = 0, CK_LINE_DONE = 1, CK_LINE_OVERFLOW = 2 };
typedef struct {
    char buf[CK_LINE_CAP + 1];
    unsigned len;
    unsigned typed;   /* printable keys typed into this line, kept or not */
    int overflow;     /* a key arrived with the buffer full: line refused */
} ck_line;
void ck_line_reset(ck_line *l);
/* Feed one key. Printable keys are appended and echoed (echo(c) for the
 * character, echo('\b') for a rubbed-out one; echo may be NULL). Enter ends
 * the line: CK_LINE_DONE with buf NUL-terminated, or CK_LINE_OVERFLOW when
 * any key was lost to the bound (the line is then emptied and must not be
 * used). Escape clears the line. */
int ck_line_feed(ck_line *l, ck_key_event ev, void (*echo)(char c));

/* ---- console shell (Rust shell.rs commands) ---- */
enum { CK_SH_INVALID = -1, CK_SH_UNKNOWN = 0, CK_SH_HELP, CK_SH_MEM, CK_SH_EL, CK_SH_REPORT, CK_SH_UPTIME, CK_SH_EXIT,
       CK_SH_EMPTY };
/* Rust parse_line: at most CK_LINE_CAP bytes, first word at most 16 bytes, at
 * most one argument of at most 16 bytes; else CK_SH_INVALID. An all-blank
 * line is CK_SH_EMPTY (Rust: None, "invalid command line"). */
int ck_shell_parse(const char *line, size_t len);
typedef struct {
    uint64_t conventional_memory_kb;
    unsigned exception_level;
    uint64_t uptime_ms;
    const char *commit;
} ck_shell_ctx;
/* Run one line; output goes through out(). Returns 1 when the line was
 * "exit". Output texts are the Rust ones ("commands: help mem el report
 * uptime exit", "conventional_memory_kb: N", "EL1", "uptime_ms: N",
 * "unknown command: X", "invalid command line"). */
int ck_shell_run(const char *line, const ck_shell_ctx *ctx, void (*out)(const char *fmt, ...));

/* ---- recovery access ---- */
enum { CK_RECOVERY_NORMAL_TIMEOUT = 0, CK_RECOVERY_NORMAL_KEY = 1, CK_RECOVERY_CONSOLE = 2 };
/* The first key the operator presses in the recovery window decides: 'r' or
 * 'R' selects the recovery console, any other key continues the normal boot.
 * have_key == 0 (no key before the window closed) continues normally. */
int ck_recovery_decide(int have_key, ck_key_event ev);
const char *ck_recovery_name(int choice);
/* Identity digest the recovery console stub prints: SHA-256 over
 * "AIENOS-CK-RECOVERY-IDENTITY-V1" || 0x00 || commit (the image build
 * identity; not an owner or machine identity, which do not exist yet). */
void ck_recovery_identity(const char *commit, uint8_t out[32]);
#endif
