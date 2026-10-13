/* agent_cmd.h -- the card command script of the Pi resident-lifecycle qualification image
 * (PI5-7 cut 2, build flag CK_PI5_LIFECYCLE, only with CK_PI5_UNLOCK_CARD).
 *
 * QUALIFICATION ONLY. Nothing reads the Pi's serial port during a run, so the run tool may place
 * \EFI\AIENOS\AGENT.CMD on the card's EFI partition holding a short list of lifecycle verbs. The UEFI
 * stub (native/boot/efi_agentcmd.c) reads it before ExitBootServices; after the Store stage the resident
 * lifecycle (core/lifecycle.c) takes each line in order, exactly as if an operator had typed it on the
 * console, prints the reply on the console and the klog, then runs its stop order. The run tool deletes
 * the file after the run. The file is a labelled qualification input, never a user interface, and it can
 * never carry a secret: unlock, rotate, update and shutdown are refused by the parser (the Store secret
 * comes from the card UNLOCK.REQ request, core/unlock_req.h; shutdown is implicit at the end).
 *
 * File layout: plain text, at most CK_AGENT_CMD_FILE_MAX bytes, LF line ends.
 *   line 1        exactly "AIENAGC1 QUALIF-AGENT-CMD"
 *   lines 2..     1..CK_AGENT_CMD_LINES_MAX command lines, each:
 *                   <verb>                 status help evidence recall facts approve deny cancel
 *                   <verb> <text>          remember prefer prompt task (text 1..CK_AGENT_CMD_TEXT_MAX bytes)
 *   every byte is printable ASCII 0x20..0x7e or the LF that ends a line; the file ends with an LF;
 *   no empty line, no CR, no tab, no NUL; a line has no leading or trailing blank and a single blank
 *   between verb and text. */
#ifndef AIENOS_CK_AGENT_CMD_H
#define AIENOS_CK_AGENT_CMD_H
#include <stddef.h>
#include <stdint.h>

#define CK_AGENT_CMD_HEADER "AIENAGC1 QUALIF-AGENT-CMD"
#define CK_AGENT_CMD_PATH "\\EFI\\AIENOS\\AGENT.CMD"
#define CK_AGENT_CMD_FILE_MAX 2048u
#define CK_AGENT_CMD_LINES_MAX 16u
#define CK_AGENT_CMD_TEXT_MAX 48u  /* the lifecycle's own text bound (CK_LC_TASK_MAX) */
#define CK_AGENT_CMD_LINE_MAX 64u  /* "remember " + 48 text + NUL fits */

struct ck_agent_cmd {
    uint32_t nlines;
    uint32_t len[CK_AGENT_CMD_LINES_MAX];
    char line[CK_AGENT_CMD_LINES_MAX][CK_AGENT_CMD_LINE_MAX];
};

/* 0 = well formed and *out filled; else -1, *out zeroed and *why names the first failed check. */
int ck_agent_cmd_parse(const uint8_t *buf, size_t n, struct ck_agent_cmd *out, const char **why);

enum { CK_AGENT_CMD_NONE = 0, CK_AGENT_CMD_ABSENT = 1, CK_AGENT_CMD_REFUSED = 2, CK_AGENT_CMD_FOUND = 3 };

/* What the UEFI stub found (the stub and the kernel are one image). */
struct ck_agent_cmd_boot {
    int state; /* CK_AGENT_CMD_* */
    struct ck_agent_cmd cmd; /* only while FOUND */
};
extern struct ck_agent_cmd_boot ck_agent_cmd_boot;
#endif
