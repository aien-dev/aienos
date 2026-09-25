// P2-6B first SEED-0B capability artifact: AArch64 EL0, position
// independent, no relocations. It requests exactly one capability: READ on
// SEED object 1, bytes [0, 32). Entry (task_runtime ABI): x0 = handle array,
// x1 = handle count, x2 = data base, x3 = data memory length.
//
// Exit 0 only if every allow/deny result is exactly as expected; otherwise
// each set bit names one failed expectation:
//   0x001 handle count != 1
//   0x002 authenticated data word missing
//   0x004 READ(handle, 0)  != SEED word 0       (authorized read)
//   0x008 READ(handle, 24) != SEED word 3       (authorized read)
//   0x010 WRITE(handle, 0) not denied           (WRITE never granted)
//   0x020 READ(handle, 0) changed after the denied write
//   0x040 forged-generation handle not denied
//   0x080 never-issued slot handle not denied
//   0x100 zero handle not denied                (no ambient authority)
//   0x200 READ(handle, 32) past the grant not denied
    .text
    .global _start
_start:
    mov     x19, x0                 // handle array
    mov     x20, x1                 // handle count
    mov     x21, x2                 // data base
    mov     x22, xzr                // failure bitmask

    // SEED word 0 = 0xa1e05eed00000001 in x24, word 3 in x25.
    movz    x24, #0x0001
    movk    x24, #0x5eed, lsl #32
    movk    x24, #0xa1e0, lsl #48
    movz    x25, #0x0004
    movk    x25, #0x5eed, lsl #32
    movk    x25, #0xa1e0, lsl #48

    cmp     x20, #1
    b.eq    1f
    orr     x22, x22, #0x001
    b       90f                     // no handle: nothing else is meaningful
1:
    // 0x002: data section is "SEED0B-1" = 0x312d423044454553
    ldr     x9, [x21]
    movz    x10, #0x4553
    movk    x10, #0x4445, lsl #16
    movk    x10, #0x4230, lsl #32
    movk    x10, #0x312d, lsl #48
    cmp     x9, x10
    b.eq    2f
    orr     x22, x22, #0x002
2:
    ldr     x23, [x19]              // the one granted handle

    // 0x004: authorized READ at offset 0
    mov     x0, x23
    mov     x1, #0
    mov     x8, #6
    svc     #0
    cmp     x0, x24
    b.eq    3f
    orr     x22, x22, #0x004
3:
    // 0x008: authorized READ at offset 24
    mov     x0, x23
    mov     x1, #24
    mov     x8, #6
    svc     #0
    cmp     x0, x25
    b.eq    4f
    orr     x22, x22, #0x008
4:
    // 0x010: WRITE through the READ-only handle must be denied
    mov     x0, x23
    mov     x1, #0
    mov     x2, #0x57
    mov     x8, #7
    svc     #0
    cmn     x0, #1
    b.eq    5f
    orr     x22, x22, #0x010
5:
    // 0x020: the denied write had no effect
    mov     x0, x23
    mov     x1, #0
    mov     x8, #6
    svc     #0
    cmp     x0, x24
    b.eq    6f
    orr     x22, x22, #0x020
6:
    // 0x040: forged generation (flip generation bit 0)
    mov     x9, #1
    lsl     x9, x9, #32
    eor     x0, x23, x9
    mov     x1, #0
    mov     x8, #6
    svc     #0
    cmn     x0, #1
    b.eq    7f
    orr     x22, x22, #0x040
7:
    // 0x080: slot 1 was never issued (index 1, generation 1)
    mov     x9, #1
    lsl     x9, x9, #32
    orr     x0, x9, #1
    mov     x1, #0
    mov     x8, #6
    svc     #0
    cmn     x0, #1
    b.eq    8f
    orr     x22, x22, #0x080
8:
    // 0x100: no ambient authority — the zero handle names nothing
    mov     x0, xzr
    mov     x1, #0
    mov     x8, #6
    svc     #0
    cmn     x0, #1
    b.eq    9f
    orr     x22, x22, #0x100
9:
    // 0x200: offset 32 is outside the granted byte range [0, 32)
    mov     x0, x23
    mov     x1, #32
    mov     x8, #6
    svc     #0
    cmn     x0, #1
    b.eq    90f
    orr     x22, x22, #0x200
90:
    mov     x0, x22
    mov     x8, #2
    svc     #0
91: b       91b
