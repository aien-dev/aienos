/* test_agent_cmd.c -- core/agent_cmd.c: the card command script of the Pi resident-lifecycle qualification
 * image (CK_PI5_LIFECYCLE). A script is a labelled text file of a few lifecycle verbs; the parser is strict
 * (header, bytes, line count, verb whitelist, text bounds) and can never let a secret-carrying or
 * state-changing control verb (unlock, rotate, update, shutdown) through. */
#include <string.h>
#include "ck_test.h"
#include "agent_cmd.h"

#define H CK_AGENT_CMD_HEADER "\n"

static int parse(const char *s, struct ck_agent_cmd *o, const char **why)
{
    return ck_agent_cmd_parse((const uint8_t *)s, strlen(s), o, why);
}

static int refused(const char *s, const char *want)
{
    struct ck_agent_cmd o;
    const char *why = 0;
    int rc = parse(s, &o, &why);
    /* a refused script leaves nothing behind */
    int clean = o.nlines == 0 && o.line[0][0] == 0;
    return rc != 0 && why && strstr(why, want) != 0 && clean;
}

int main(void)
{
    struct ck_agent_cmd o;
    const char *why = (const char *)1;
    CHECK(strlen(CK_AGENT_CMD_HEADER) == 25);

    /* the L1 script of the qualification run */
    CHECK(parse(H "prefer short notes\nstatus\nrecall\nprompt What is the capital of France?\napprove\n", &o, &why) == 0 && why == 0);
    CHECK(o.nlines == 5 && o.len[0] == 18 && strcmp(o.line[0], "prefer short notes") == 0);
    CHECK(strcmp(o.line[3], "prompt What is the capital of France?") == 0 && strcmp(o.line[4], "approve") == 0);
    CHECK(parse(H "recall\nfacts\nevidence\nhelp\ndeny\ncancel\nremember a b c\ntask do it\n", &o, 0) == 0 && o.nlines == 8);
    CHECK(ck_agent_cmd_parse(0, 0, &o, &why) != 0 && ck_agent_cmd_parse((const uint8_t *)"x", 1, 0, &why) != 0);

    /* header */
    CHECK(refused("", "size"));
    CHECK(refused("status\n", "header"));
    CHECK(refused("AIENAGC1 QUALIF-AGENT-CMD", "line feed"));
    CHECK(refused("AIENAGC2 QUALIF-AGENT-CMD\nstatus\n", "header"));
    CHECK(refused("AIENAGC1 QUALIF-AGENT-CMD \nstatus\n", "header"));
    CHECK(refused(H, "no command line"));

    /* the control verbs can never ride in a card script */
    CHECK(refused(H "unlock\n", "not allowed"));
    CHECK(refused(H "unlock 0000000000000000000000000000000000000000000000000000000000000000\n", "not allowed"));
    CHECK(refused(H "rotate a b\n", "not allowed"));
    CHECK(refused(H "update\n", "not allowed"));
    CHECK(refused(H "shutdown\n", "not allowed"));
    CHECK(refused(H "status\nunlock\n", "not allowed"));
    CHECK(refused(H "Status\n", "not allowed"));
    CHECK(refused(H "statuses\n", "not allowed"));
    CHECK(refused(H "stat\n", "not allowed"));
    CHECK(refused(H "frob\n", "not allowed"));

    /* shape of a line */
    CHECK(refused(H "status now\n", "no text"));
    CHECK(refused(H "approve please\n", "no text"));
    CHECK(refused(H "prefer\n", "text must be"));
    CHECK(refused(H "prefer  two blanks\n", "text must be"));
    CHECK(refused(H " status\n", "blank"));
    CHECK(refused(H "status \n", "blank"));
    CHECK(refused(H "prefer short \n", "blank"));
    CHECK(refused(H "status\n\nrecall\n", "empty line"));
    CHECK(refused(H "prefer 0123456789012345678901234567890123456789012345678\n", "text must be")); /* 49 */
    CHECK(parse(H "prefer 012345678901234567890123456789012345678901234567\n", &o, &why) == 0 && o.len[0] == 7 + 48); /* 48 */

    /* bytes */
    CHECK(refused(H "status\r\n", "printable"));
    CHECK(refused(H "pre\tfer x\n", "printable"));
    CHECK(refused("AIENAGC1 QUALIF-AGENT-CMD\nprefer caf\xc3\xa9\n", "printable"));
    {
        char z[64];
        strcpy(z, H "status\n");
        z[strlen(H) + 2] = 0;
        CHECK(ck_agent_cmd_parse((const uint8_t *)z, strlen(H) + 7, &o, &why) != 0 && o.nlines == 0);
    }

    /* count and size bounds */
    {
        char big[CK_AGENT_CMD_FILE_MAX + 64];
        strcpy(big, H);
        for (int i = 0; i < 16; i++) strcat(big, "status\n");
        CHECK(parse(big, &o, &why) == 0 && o.nlines == 16);
        strcat(big, "status\n");
        CHECK(refused(big, "more than 16"));
        memset(big, 'a', sizeof big);
        CHECK(ck_agent_cmd_parse((const uint8_t *)big, CK_AGENT_CMD_FILE_MAX + 1, &o, &why) != 0 && strstr(why, "size"));
    }
    return ck_t_verdict("test_agent_cmd");
}
