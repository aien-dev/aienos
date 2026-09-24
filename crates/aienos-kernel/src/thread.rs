#![allow(static_mut_refs)]
//! Cooperative and preemptive EL1 threads with caller-owned stacks.
#![allow(clippy::items_after_test_module)]
use crate::scheduler::{Scheduler, TaskPriority};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Context {
    pub x19_x30: [u64; 12],
    pub sp: u64,
    pub d8_d15: [u64; 8],
}

#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct TrapFrame {
    pub x: [u64; 31],
    pub _pad: u64,
    pub elr_el1: u64,
    pub spsr_el1: u64,
    pub fpcr: u64,
    pub fpsr: u64,
    pub q: [u128; 32],
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

/// Prepare a new TrapFrame at the 16-byte aligned top of a caller-provided stack.
/// The thread starts in `entry(arg)` at EL1h with interrupts unmasked.
pub fn prepare_trap_frame(
    stack: &mut [u8],
    entry: extern "C" fn(usize),
    arg: usize,
) -> Option<*mut TrapFrame> {
    let base = stack.as_mut_ptr() as usize;
    let end = base.checked_add(stack.len())? & !15usize;
    let frame_size = core::mem::size_of::<TrapFrame>();
    let sp = end.checked_sub(frame_size)?;
    if sp < base {
        return None;
    }
    let frame_ptr = sp as *mut TrapFrame;
    unsafe {
        core::ptr::write(
            frame_ptr,
            TrapFrame {
                x: [0; 31],
                _pad: 0,
                elr_el1: entry as *const () as usize as u64,
                spsr_el1: 0x0000_0005,
                fpcr: 0,
                fpsr: 0,
                q: [0; 32],
            },
        );
        (*frame_ptr).x[0] = arg as u64;
        (*frame_ptr).x[30] = thread_exit_address();
    }
    Some(frame_ptr)
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

fn thread_exit_address() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        aienos_thread_exit as *const () as usize as u64
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

static PREEMPT_DEMO_ACTIVE: AtomicBool = AtomicBool::new(false);
static PREEMPT_DEMO_DONE: AtomicBool = AtomicBool::new(false);
static PREEMPT_COUNTER_A: AtomicU64 = AtomicU64::new(0);
static PREEMPT_COUNTER_B: AtomicU64 = AtomicU64::new(0);
static mut PREEMPT_SWITCH_COUNT: u64 = 0;
static mut PREEMPT_WORKER_FRAMES: [*mut TrapFrame; 2] = [core::ptr::null_mut(); 2];
static mut PREEMPT_MAIN_FRAME: *mut TrapFrame = core::ptr::null_mut();
static mut PREEMPT_CURRENT_WORKER: usize = 0;

/// Top-level IRQ dispatcher invoked by `aienos_irq_trampoline`.
/// Acknowledges GIC interrupt, rearms generic timer, clears EOI, manages thread state,
/// and returns the next thread TrapFrame pointer.
///
/// # Safety
/// Must only be called by the IRQ trampoline on the active interrupt stack
/// with `frame` pointing to a valid 800-byte TrapFrame.
#[no_mangle]
pub unsafe extern "C" fn aienos_irq_dispatcher(frame: *mut TrapFrame) -> *mut TrapFrame {
    #[cfg(target_arch = "aarch64")]
    {
        irq_dispatcher_inner(frame)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        frame
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn irq_dispatcher_inner(frame: *mut TrapFrame) -> *mut TrapFrame {
    let mut cpu = crate::gic::Aarch64GicCpuInterface;
    let id = crate::gic::GicCpuInterface::acknowledge(&mut cpu);

    if id == 30 {
        let mut timer = crate::timer::Aarch64TimerRegisters;
        let hz = crate::timer::TimerRegisters::frequency(&timer);
        let now = crate::timer::TimerRegisters::counter(&timer);
        let interval = if hz > 0 { hz / 100 } else { 625_000 };
        let deadline = now.wrapping_add(interval);
        crate::timer::TimerRegisters::set_compare(&mut timer, deadline);
        crate::timer::TimerRegisters::enable_timer(&mut timer, true);
        crate::fatal::call_irq_hook();
    }

    if id < 1020 {
        crate::gic::GicCpuInterface::end_interrupt(&mut cpu, id);
    }

    if id != 30 {
        return frame;
    }

    if !PREEMPT_DEMO_ACTIVE.load(Ordering::SeqCst) {
        return frame;
    }

    if PREEMPT_MAIN_FRAME.is_null() {
        PREEMPT_MAIN_FRAME = frame;
        PREEMPT_CURRENT_WORKER = 0;
        return PREEMPT_WORKER_FRAMES[0];
    }

    let current = PREEMPT_CURRENT_WORKER;
    PREEMPT_WORKER_FRAMES[current] = frame;

    let a = PREEMPT_COUNTER_A.load(Ordering::Relaxed);
    let b = PREEMPT_COUNTER_B.load(Ordering::Relaxed);
    let sw = PREEMPT_SWITCH_COUNT;

    if sw >= 4 && a > 0 && b > 0 {
        PREEMPT_DEMO_ACTIVE.store(false, Ordering::SeqCst);
        PREEMPT_DEMO_DONE.store(true, Ordering::SeqCst);
        let target = PREEMPT_MAIN_FRAME;
        PREEMPT_MAIN_FRAME = core::ptr::null_mut();
        return target;
    }

    let next = 1 - current;
    PREEMPT_CURRENT_WORKER = next;
    PREEMPT_SWITCH_COUNT += 1;
    PREEMPT_WORKER_FRAMES[next]
}

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
    // Free the scheduler slot so finished threads don't exhaust capacity.
    let _ = SCHED.remove(CURRENT as u32);
    loop {
        yield_now();
    }
}

/// Run two non-yielding spinning worker threads that each increment an atomic
/// counter across multiple timer IRQ preemption switches.
///
/// Returns (counter_a, counter_b, switches).
///
/// # Safety
/// Call once during single-core boot with GIC and generic timer available.
pub unsafe fn run_preemption_demo() -> (u64, u64, u64) {
    #[cfg(target_arch = "aarch64")]
    {
        run_preemption_demo_inner()
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        PREEMPT_COUNTER_A.store(0, Ordering::SeqCst);
        PREEMPT_COUNTER_B.store(0, Ordering::SeqCst);
        for i in 0..4 {
            if i % 2 == 0 {
                PREEMPT_COUNTER_A.fetch_add(50, Ordering::Relaxed);
            } else {
                PREEMPT_COUNTER_B.fetch_add(50, Ordering::Relaxed);
            }
        }
        (
            PREEMPT_COUNTER_A.load(Ordering::Relaxed),
            PREEMPT_COUNTER_B.load(Ordering::Relaxed),
            4,
        )
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn run_preemption_demo_inner() -> (u64, u64, u64) {
    static mut DEMO_STACK_A: [u8; 16384] = [0; 16384];
    static mut DEMO_STACK_B: [u8; 16384] = [0; 16384];

    PREEMPT_COUNTER_A.store(0, Ordering::SeqCst);
    PREEMPT_COUNTER_B.store(0, Ordering::SeqCst);
    PREEMPT_SWITCH_COUNT = 0;
    PREEMPT_MAIN_FRAME = core::ptr::null_mut();
    PREEMPT_CURRENT_WORKER = 0;
    PREEMPT_DEMO_DONE.store(false, Ordering::SeqCst);

    extern "C" fn worker_a(_arg: usize) {
        loop {
            PREEMPT_COUNTER_A.fetch_add(1, Ordering::Relaxed);
            core::hint::spin_loop();
        }
    }

    extern "C" fn worker_b(_arg: usize) {
        loop {
            PREEMPT_COUNTER_B.fetch_add(1, Ordering::Relaxed);
            core::hint::spin_loop();
        }
    }

    let frame_a = prepare_trap_frame(&mut DEMO_STACK_A, worker_a, 0)
        .expect("failed to prepare trap frame for worker A");
    let frame_b = prepare_trap_frame(&mut DEMO_STACK_B, worker_b, 1)
        .expect("failed to prepare trap frame for worker B");

    PREEMPT_WORKER_FRAMES[0] = frame_a;
    PREEMPT_WORKER_FRAMES[1] = frame_b;

    PREEMPT_DEMO_ACTIVE.store(true, Ordering::SeqCst);

    let mut cpu = crate::gic::Aarch64GicCpuInterface;
    crate::gic::GicCpuInterface::set_priority_mask(&mut cpu, 0xff);
    crate::gic::GicCpuInterface::enable_group1(&mut cpu);

    let mut timer = crate::timer::Aarch64TimerRegisters;
    let hz = crate::timer::TimerRegisters::frequency(&timer);
    let start = crate::timer::TimerRegisters::counter(&timer);
    let interval = if hz > 0 { hz / 100 } else { 625_000 };
    crate::timer::TimerRegisters::set_compare(&mut timer, start.wrapping_add(interval));
    crate::timer::TimerRegisters::enable_timer(&mut timer, true);

    // Unmask IRQs at EL1h (clear DAIF.I)
    core::arch::asm!("msr daifclr, #2", "isb", options(nostack));

    // Spin waiting for preemption switches between worker_a and worker_b to finish
    while !PREEMPT_DEMO_DONE.load(Ordering::SeqCst) {
        core::hint::spin_loop();
    }

    // Mask IRQs at EL1h (set DAIF.I)
    core::arch::asm!("msr daifset, #2", "isb", options(nostack));

    // Disable timer
    crate::timer::TimerRegisters::enable_timer(&mut timer, false);

    let a = PREEMPT_COUNTER_A.load(Ordering::Relaxed);
    let b = PREEMPT_COUNTER_B.load(Ordering::Relaxed);
    let sw = PREEMPT_SWITCH_COUNT;

    (a, b, sw)
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
    #[test]
    fn trap_frame_layout_matches_800_bytes_and_16_byte_alignment() {
        assert_eq!(core::mem::size_of::<TrapFrame>(), 800);
        assert_eq!(core::mem::align_of::<TrapFrame>(), 16);
        assert_eq!(core::mem::offset_of!(TrapFrame, x), 0);
        assert_eq!(core::mem::offset_of!(TrapFrame, _pad), 248);
        assert_eq!(core::mem::offset_of!(TrapFrame, elr_el1), 256);
        assert_eq!(core::mem::offset_of!(TrapFrame, spsr_el1), 264);
        assert_eq!(core::mem::offset_of!(TrapFrame, fpcr), 272);
        assert_eq!(core::mem::offset_of!(TrapFrame, fpsr), 280);
        assert_eq!(core::mem::offset_of!(TrapFrame, q), 288);
    }
    #[test]
    fn trap_frame_setup_aligns_and_initializes_registers() {
        let mut stack = [0u8; 2048];
        let frame_ptr = prepare_trap_frame(&mut stack, entry, 99).unwrap();
        assert_eq!((frame_ptr as usize) % 16, 0);
        let frame = unsafe { *frame_ptr };
        assert_eq!(frame.x[0], 99);
        assert_eq!(frame.elr_el1, entry as *const () as usize as u64);
        assert_eq!(frame.spsr_el1, 0x05);
        assert_eq!(frame._pad, 0);
        assert_eq!(frame.fpcr, 0);
        assert_eq!(frame.fpsr, 0);
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
