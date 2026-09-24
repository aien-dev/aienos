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

/// Save the current callee-saved context and resume `to`.
/// Both contexts and their stacks must remain valid for the switch.
///
/// # Safety
/// The destination context must have a valid stack and resume address. `from` must
/// remain writable, and execution must be serialized with interrupts disabled.
#[cfg(target_arch = "aarch64")]
pub unsafe fn switch(from: &mut Context, to: &Context) {
    core::arch::asm!(
        "stp x19, x20, [{from}, #0]", "stp x21, x22, [{from}, #16]",
        "stp x23, x24, [{from}, #32]", "stp x25, x26, [{from}, #48]",
        "stp x27, x28, [{from}, #64]", "stp x29, x30, [{from}, #80]",
        "mov x9, sp", "str x9, [{from}, #96]",
        "stp d8, d9, [{from}, #104]", "stp d10, d11, [{from}, #120]",
        "stp d12, d13, [{from}, #136]", "stp d14, d15, [{from}, #152]",
        "ldp d8, d9, [{to}, #104]", "ldp d10, d11, [{to}, #120]",
        "ldp d12, d13, [{to}, #136]", "ldp d14, d15, [{to}, #152]",
        "ldr x9, [{to}, #96]", "mov sp, x9",
        "ldp x19, x20, [{to}, #0]", "ldp x21, x22, [{to}, #16]",
        "ldp x23, x24, [{to}, #32]", "ldp x25, x26, [{to}, #48]",
        "ldp x27, x28, [{to}, #64]", "ldp x29, x30, [{to}, #80]",
        "ret", from = in(reg) from, to = in(reg) to, lateout("x9") _, options(nostack)
    );
}
#[cfg(not(target_arch = "aarch64"))]
pub unsafe fn switch(_from: &mut Context, _to: &Context) {}

/// Prepare a new context at the aligned top of a caller-provided stack.
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
    ctx.x19_x30[11] = trampoline as *const () as usize as u64;
    Some(ctx)
}
extern "C" fn trampoline() -> ! {
    // x19 and x20 hold the argument and entry through the initial context.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let arg: usize;
        let fun: extern "C" fn(usize);
        core::arch::asm!("mov x0, x19", "mov x1, x20", out("x0") arg, out("x1") fun, options(nomem, nostack));
        fun(arg);
    }
    unsafe { park() }
}

const MAX: usize = 4;
static mut CONTEXTS: [Context; MAX] = [Context {
    x19_x30: [0; 12],
    sp: 0,
    d8_d15: [0; 8],
}; MAX];
static mut RUNNABLE: [bool; MAX] = [false; MAX];
static mut CURRENT: usize = 0;
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
        switch(&mut CONTEXTS[from], &MAIN);
    } else if from == MAX {
        switch(&mut MAIN, &CONTEXTS[target]);
    } else {
        switch(&mut CONTEXTS[from], &CONTEXTS[target]);
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

/// Run two bounded threads and return whether they produced five A/B pairs.
///
/// # Safety
/// Call once during single-core boot before other threads are registered.
pub unsafe fn run_demo() -> bool {
    static mut STACK_A: [u8; 4096] = [0; 4096];
    static mut STACK_B: [u8; 4096] = [0; 4096];
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
        return false;
    }
    CURRENT = MAX;
    yield_now();
    LEN == 10 && TRACE == *b"ABABABABAB"
}
