#![allow(static_mut_refs)]
//! Cooperative EL1 threads with caller-owned stacks.
#![allow(clippy::items_after_test_module)]
use crate::scheduler::{Scheduler, TaskPriority};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Context {
    pub x19_x30: [u64; 12],
    pub sp: u64,
    pub d8_d15: [u64; 8],
}

// Context switch and thread entry live in global assembly so no compiler
// prologue/epilogue sits between saving and restoring a context, and the
// argument registers are fixed (x0 = from, x1 = to).
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".global aienos_ctx_switch",
    "aienos_ctx_switch:",
    "stp x19, x20, [x0, #0]",
    "stp x21, x22, [x0, #16]",
    "stp x23, x24, [x0, #32]",
    "stp x25, x26, [x0, #48]",
    "stp x27, x28, [x0, #64]",
    "stp x29, x30, [x0, #80]",
    "mov x9, sp",
    "str x9, [x0, #96]",
    "stp d8, d9, [x0, #104]",
    "stp d10, d11, [x0, #120]",
    "stp d12, d13, [x0, #136]",
    "stp d14, d15, [x0, #152]",
    "ldp d8, d9, [x1, #104]",
    "ldp d10, d11, [x1, #120]",
    "ldp d12, d13, [x1, #136]",
    "ldp d14, d15, [x1, #152]",
    "ldr x9, [x1, #96]",
    "mov sp, x9",
    "ldp x19, x20, [x1, #0]",
    "ldp x21, x22, [x1, #16]",
    "ldp x23, x24, [x1, #32]",
    "ldp x25, x26, [x1, #48]",
    "ldp x27, x28, [x1, #64]",
    "ldp x29, x30, [x1, #80]",
    "ret",
    ".global aienos_thread_start",
    "aienos_thread_start:",
    "mov x0, x19",
    "blr x20",
    "bl aienos_thread_exit",
);

#[cfg(target_arch = "aarch64")]
extern "C" {
    fn aienos_ctx_switch(from: *mut Context, to: *const Context);
    fn aienos_thread_start();
}

/// Save the current callee-saved context into `from` and resume `to`.
///
/// # Safety
/// `to` must hold a valid stack and resume address; both contexts must stay
/// valid; execution must be serialized with interrupts masked.
#[cfg(target_arch = "aarch64")]
pub unsafe fn switch(from: *mut Context, to: *const Context) {
    aienos_ctx_switch(from, to);
}
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn switch(_from: *mut Context, _to: *const Context) {}

/// Prepare a new context at the aligned top of a caller-provided stack.
/// The thread starts in `aienos_thread_start`, which calls `entry(arg)` from
/// x19/x20 and parks the thread when it returns.
pub fn prepare(stack: &mut [u8], entry: extern "C" fn(usize), arg: usize) -> Option<Context> {
    let base = stack.as_mut_ptr() as usize;
    let end = base.checked_add(stack.len())? & !15usize;
    let sp = end.checked_sub(16)?;
    if sp < base {
        return None;
    }
    let mut ctx = Context {
        sp: sp as u64,
        ..Context::default()
    };
    ctx.x19_x30[0] = arg as u64;
    ctx.x19_x30[1] = entry as *const () as usize as u64;
    ctx.x19_x30[11] = thread_start_address();
    Some(ctx)
}

fn thread_start_address() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        aienos_thread_start as *const () as usize as u64
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        0
    }
}

#[no_mangle]
extern "C" fn aienos_thread_exit() -> ! {
    unsafe { park() }
}

const MAX: usize = 4;
static mut CONTEXTS: [Context; MAX] = [Context {
    x19_x30: [0; 12],
    sp: 0,
    d8_d15: [0; 8],
}; MAX];
static mut RUNNABLE: [bool; MAX] = [false; MAX];
/// Index of the running thread; MAX means the boot context.
static mut CURRENT: usize = MAX;
static mut SCHED: Scheduler<1, MAX> = Scheduler::new([0]);
static mut MAIN: Context = Context {
    x19_x30: [0; 12],
    sp: 0,
    d8_d15: [0; 8],
};
/// Register a thread on a caller-provided stack. Returns its scheduler ID.
///
/// # Safety
/// The stack must remain allocated and exclusively owned until the thread parks.
pub unsafe fn spawn(stack: &mut [u8], entry: extern "C" fn(usize), arg: usize) -> Option<u32> {
    let slot = (0..MAX).find(|&i| !RUNNABLE[i] && SCHED.task(i as u32).is_none())?;
    CONTEXTS[slot] = prepare(stack, entry, arg)?;
    SCHED.enqueue(slot as u32, TaskPriority::Normal).ok()?;
    RUNNABLE[slot] = true;
    Some(slot as u32)
}
/// Yield to the least-served runnable thread, returning to the boot context when idle.
///
/// # Safety
/// Call only after thread state is initialized, on the single scheduling core.
pub unsafe fn yield_now() {
    let from = CURRENT;
    let mut next = None;
    for _ in 0..MAX {
        if let Some(id) = SCHED.tick(0).ok().flatten() {
            if RUNNABLE[id as usize] && id as usize != from {
                next = Some(id as usize);
                break;
            }
        }
    }
    let target = next.unwrap_or(MAX);
    if target == from {
        return;
    }
    CURRENT = target;
    if target == MAX {
        switch(&raw mut CONTEXTS[from], &raw const MAIN);
    } else if from == MAX {
        switch(&raw mut MAIN, &raw const CONTEXTS[target]);
    } else {
        switch(&raw mut CONTEXTS[from], &raw const CONTEXTS[target]);
    }
}
/// Mark the current thread finished and transfer control to another runnable thread.
///
/// # Safety
/// Call only from a scheduled thread on the single scheduling core.
pub unsafe fn park() -> ! {
    RUNNABLE[CURRENT] = false;
    loop {
        yield_now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern "C" fn entry(_: usize) {}
    #[test]
    fn stack_setup_aligns_sp_and_records_trampoline_arguments() {
        let mut stack = [0u8; 257];
        let ctx = prepare(&mut stack, entry, 42).unwrap();
        assert_eq!(ctx.sp % 16, 0);
        assert_eq!(ctx.x19_x30[0], 42);
        assert_eq!(ctx.x19_x30[1], entry as *const () as usize as u64);
    }
    #[test]
    fn context_offsets_match_assembly_layout() {
        assert_eq!(core::mem::offset_of!(Context, sp), 96);
        assert_eq!(core::mem::offset_of!(Context, d8_d15), 104);
        assert_eq!(core::mem::size_of::<Context>(), 168);
    }
}

/// Run two bounded threads that each record a tag and yield five times.
/// Returns the observed interleaving (up to 10 bytes) and its length.
///
/// # Safety
/// Call once during single-core boot, at EL1 with interrupts masked, before
/// other threads are registered.
pub unsafe fn run_demo() -> ([u8; 10], usize) {
    static mut STACK_A: [u8; 8192] = [0; 8192];
    static mut STACK_B: [u8; 8192] = [0; 8192];
    static mut TRACE: [u8; 10] = [0; 10];
    static mut LEN: usize = 0;
    extern "C" fn worker(tag: usize) {
        for _ in 0..5 {
            unsafe {
                if LEN < TRACE.len() {
                    TRACE[LEN] = if tag == 0 { b'A' } else { b'B' };
                    LEN += 1;
                }
                yield_now();
            }
        }
    }
    if spawn(&mut STACK_A, worker, 0).is_none() || spawn(&mut STACK_B, worker, 1).is_none() {
        return ([0; 10], 0);
    }
    CURRENT = MAX;
    // Run until both workers have parked and control returns here.
    while RUNNABLE.iter().any(|r| *r) {
        yield_now();
    }
    (TRACE, LEN)
}
