// Binary Artifact v0 entry ABI: x0 is the first granted capability handle.
// This program has no ambient authority and makes no direct memory accesses
// outside its private stack/data pages and the admitted syscalls.
.section .text
.global _start
.type _start, %function
_start:
    mov     x19, x0              // admitted READ-only object handle

    mov     x8, #6               // SYS_OBJECT_READ
    mov     x0, x19
    mov     x1, #0               // first object word
    svc     #0

    // The qualification object starts with 0xc0ffee01. Exit 1 if the
    // legitimate read did not return that exact value.
    movz    x9, #0xee01
    movk    x9, #0xc0ff, lsl #16
    cmp     x0, x9
    b.ne    read_failed

    // This must be denied because the granted handle has READ and no WRITE.
    mov     x8, #7               // SYS_OBJECT_WRITE
    mov     x0, x19
    mov     x1, #0
    movz    x2, #0xbad0
    movk    x2, #0xbad0, lsl #16
    svc     #0
    cmn     x0, #1               // denied result is UINT64_MAX
    b.ne    write_was_allowed

    mov     x0, #0
    b       exit

read_failed:
    mov     x0, #1
    b       exit

write_was_allowed:
    mov     x0, #2

exit:
    mov     x8, #2               // SYS_EXIT
    svc     #0
1:  b       1b
.size _start, .-_start

.section .data
.global _seed0b_data_marker
_seed0b_data_marker:
    .quad 0x5345454430420001
