/* efi_agentcmd.c -- read \EFI\AIENOS\AGENT.CMD from the boot volume before ExitBootServices
 * (Raspberry Pi 5 resident-lifecycle qualification image, CK_PI5_LIFECYCLE). Nothing is written. The file
 * holds a short list of lifecycle verbs placed by the run tool (native/kernel/core/agent_cmd.h). Result in
 * ck_agent_cmd_boot (stub and kernel are one image): ABSENT (no file: the lifecycle just stops), REFUSED
 * (printed why), FOUND. */
#include "efi.h"
#include "../kernel/core/agent_cmd.h"
#include "../kernel/arch/arch.h"
#include "../kernel/core/ck_internal.h"

static uint8_t buf[CK_AGENT_CMD_FILE_MAX + 1u] __attribute__((aligned(64)));

static void wipe_buf(void)
{
    volatile uint8_t *b = buf;
    for (unsigned i = 0; i < sizeof buf; i++)
        b[i] = 0;
}

void ck_boot_agent_cmd_find(EFI_HANDLE image, EFI_SYSTEM_TABLE *st)
{
    static const EFI_GUID li_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID_INIT;
    static const EFI_GUID fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID_INIT;
    static CHAR16 path[] = {'\\', 'E', 'F', 'I', '\\', 'A', 'I', 'E', 'N', 'O', 'S', '\\',
                            'A', 'G', 'E', 'N', 'T', '.', 'C', 'M', 'D', 0};
    EFI_BOOT_SERVICES *bs = st->BootServices;
    EFI_LOADED_IMAGE_PROTOCOL *li = 0;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs = 0;
    EFI_FILE_PROTOCOL *root = 0, *f = 0;
    ck_agent_cmd_boot.state = CK_AGENT_CMD_ABSENT;
    if (bs->HandleProtocol(image, &li_guid, (void **)&li) != EFI_SUCCESS || !li || !li->DeviceHandle ||
        bs->HandleProtocol(li->DeviceHandle, &fs_guid, (void **)&fs) != EFI_SUCCESS || !fs ||
        fs->OpenVolume(fs, &root) != EFI_SUCCESS || !root) {
        ck_puts("agent_cmd: absent (boot volume not readable); no command script this boot\n");
        return;
    }
    if (root->Open(root, &f, path, EFI_FILE_MODE_READ, 0) != EFI_SUCCESS || !f) {
        root->Close(root);
        ck_puts("agent_cmd: absent (no " CK_AGENT_CMD_PATH "); no command script this boot\n");
        return;
    }
    wipe_buf();
    uint64_t n = sizeof buf; /* one byte more than the format allows: a longer file is refused */
    EFI_STATUS s = f->Read(f, &n, buf);
    f->Close(f);
    root->Close(root);
    ck_agent_cmd_boot.state = CK_AGENT_CMD_REFUSED;
    if (s != EFI_SUCCESS || n < 1 || n > CK_AGENT_CMD_FILE_MAX) {
        ck_printf("agent_cmd: refused (read status=0x%llx bytes=%llu, want 1..%u)\n", (unsigned long long)s,
                  (unsigned long long)n, (unsigned)CK_AGENT_CMD_FILE_MAX);
        wipe_buf();
        return;
    }
    const char *why = 0;
    if (ck_agent_cmd_parse(buf, (size_t)n, &ck_agent_cmd_boot.cmd, &why)) {
        ck_printf("agent_cmd: refused (%s)\n", why ? why : "malformed");
        wipe_buf();
        return;
    }
    ck_agent_cmd_boot.state = CK_AGENT_CMD_FOUND;
    ck_printf("agent_cmd: found a well-formed command script (QUALIFICATION ONLY, %u lines)\n",
              (unsigned)ck_agent_cmd_boot.cmd.nlines);
    wipe_buf();
}
