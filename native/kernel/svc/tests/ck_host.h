/* ck_host.h -- knobs of the host ck.h shim (tests only). */
#ifndef AIENOS_CK_HOST_H
#define AIENOS_CK_HOST_H
extern const void *ck_host_mcfg; /* table returned for ck_acpi_find("MCFG") */
extern int ck_host_quiet;        /* 1: drop ck_printf output */
#endif
