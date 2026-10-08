/* ck_host.h -- knobs of the host ck.h shim (tests only). */
#ifndef AIENOS_CK_HOST_H
#define AIENOS_CK_HOST_H
#include <stdint.h>
extern const void *ck_host_mcfg; /* table returned for ck_acpi_find("MCFG") */
extern int ck_host_quiet;        /* 1: drop ck_printf output */
extern int ck_host_try_map_ok;            /* 1: ck_mmio_try_map is identity (default 0: always NULL) */
extern uint64_t ck_host_try_map_fail;     /* with try_map_ok: this exact phys still fails (0: none) */
void ck_host_capture_start(void);         /* record ck_printf/ck_puts text (even when quiet) */
const char *ck_host_capture_text(void);   /* NUL-terminated text captured since start */
void ck_host_capture_stop(void);
#endif
