/* x86.h -- x86_64 machine access for the AIENOS-IMAC-KERNEL-0 kernel
 * (native/kernel/x86): port and MSR I/O, CPUID, TSC, control registers,
 * the trap frame trap.S builds, and the entry points between the files.
 * Everything is compiled -mabi=ms (UEFI calling convention, like the stub),
 * so trap.S passes the first argument in rcx. */
#ifndef AIENOS_CK_X86_H
#define AIENOS_CK_X86_H
#include <stddef.h>
#include <stdint.h>

static inline void ck_outb(uint16_t p, uint8_t v) { __asm__ volatile("outb %0, %1" ::"a"(v), "Nd"(p)); }
static inline void ck_outw(uint16_t p, uint16_t v) { __asm__ volatile("outw %0, %1" ::"a"(v), "Nd"(p)); }
static inline uint8_t ck_inb(uint16_t p)
{
    uint8_t v;
    __asm__ volatile("inb %1, %0" : "=a"(v) : "Nd"(p));
    return v;
}
static inline uint16_t ck_inw(uint16_t p)
{
    uint16_t v;
    __asm__ volatile("inw %1, %0" : "=a"(v) : "Nd"(p));
    return v;
}
static inline uint64_t ck_rdmsr(uint32_t m)
{
    uint32_t lo, hi;
    __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(m));
    return (uint64_t)hi << 32 | lo;
}
static inline void ck_wrmsr(uint32_t m, uint64_t v)
{
    __asm__ volatile("wrmsr" ::"c"(m), "a"((uint32_t)v), "d"((uint32_t)(v >> 32)) : "memory");
}
static inline void ck_cpuid(uint32_t leaf, uint32_t sub, uint32_t r[4])
{
    __asm__ volatile("cpuid" : "=a"(r[0]), "=b"(r[1]), "=c"(r[2]), "=d"(r[3]) : "a"(leaf), "c"(sub));
}
static inline uint64_t ck_rdtsc(void)
{
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return (uint64_t)hi << 32 | lo;
}
#define CK_RD_CR(n)                                                                                \
    static inline uint64_t ck_rd_cr##n(void)                                                       \
    {                                                                                              \
        uint64_t v;                                                                                \
        __asm__ volatile("mov %%cr" #n ", %0" : "=r"(v));                                         \
        return v;                                                                                  \
    }
CK_RD_CR(0)
CK_RD_CR(2)
CK_RD_CR(3)
CK_RD_CR(4)
#undef CK_RD_CR
static inline void ck_wr_cr3(uint64_t v) { __asm__ volatile("mov %0, %%cr3" ::"r"(v) : "memory"); }
static inline void ck_cli(void) { __asm__ volatile("cli" ::: "memory"); }
static inline void ck_sti(void) { __asm__ volatile("sti" ::: "memory"); }
static inline void ck_pause(void) { __asm__ volatile("pause"); }

/* What trap.S pushes, lowest address first: the general registers, the
 * vector and error code (0 for vectors without one), then the CPU frame. */
struct ck_x86_frame {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8, rbp, rdi, rsi, rdx, rcx, rbx, rax;
    uint64_t vector, error;
    uint64_t rip, cs, rflags, rsp, ss;
};
_Static_assert(sizeof(struct ck_x86_frame) == 22 * 8, "ck_x86_frame size");

/* trap.S */
extern char ck_x86_isr_stubs[]; /* 256 stubs, 16 bytes apart */
#define CK_X86_ISR_STRIDE 16u
void ck_x86_load_gdt(const void *gdtr, uint16_t code_sel, uint16_t data_sel, uint16_t tss_sel);
__attribute__((noreturn)) void ck_x86_call_on_stack(void (*fn)(void *), void *arg, uint64_t sp);
void ck_x86_trap(struct ck_x86_frame *f); /* kmain.c, called by every stub */

/* console_x86.c: COM1 if a 16550 answers there, the GOP framebuffer once
 * the kernel turned it on, and a RAM copy of everything written so far that
 * is replayed onto the screen when it comes on. */
int ck_x86_com1_probe(void);
int ck_x86_console_fb_on(volatile void *base, uint32_t width, uint32_t height, uint32_t pitch,
                         uint32_t format, uint32_t *scale, uint32_t *cols, uint32_t *rows);

/* ahci_x86.c: PCI walk over the MCFG ECAM window and every SATA disk behind
 * an AHCI controller, read-only (IDENTIFY, READ DMA EXT and the GPT check). */
struct ck_frames;
void ck_x86_storage(uint64_t rsdp, struct ck_frames *fr, uint64_t tsc_hz, uint64_t map_top);

#endif
