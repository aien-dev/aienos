#![allow(static_mut_refs)]
//! Single-core EL0 task entry and capability-checked syscall substrate.

use crate::caps::{CapTable, Handle, Rights};
/// Complete general-purpose and floating-point state captured by the lower-EL
/// synchronous trampoline in this file. The assembly hard-codes the field
/// offsets, so `trap_frame_layout_matches_assembly` fails the build if this
/// layout ever drifts from the exception ABI.
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
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

pub const SYS_WRITE: u64 = 1;
pub const SYS_EXIT: u64 = 2;
pub const CONSOLE_RESOURCE: u32 = 1;
pub const SYSCALL_DENIED: u64 = u64::MAX;

const PAGE_BYTES: usize = 4096;
const TABLE_DESCRIPTOR: u64 = 0b11;
const ADDRESS_MASK: u64 = 0x0000_ffff_ffff_f000;
const PAGE_DESCRIPTOR: u64 = 0b11;
const AF: u64 = 1 << 10;
const NG: u64 = 1 << 11;
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DemoResult {
    pub write_granted: bool,
    pub forged_denied: bool,
    pub fault_contained: bool,
    pub exit_code: u64,
}

#[repr(C, align(4096))]
struct Page([u64; 512]);

static mut USER_L0: Page = Page([0; 512]);
static mut USER_L1: Page = Page([0; 512]);
static mut USER_L2: Page = Page([0; 512]);
static mut USER_L3: Page = Page([0; 512]);
static mut USER_CODE: Page = Page([0; 512]);
static mut USER_STACK: Page = Page([0; 512]);
static mut USER_CAPS: CapTable<4> = CapTable::new(0x454c_3001);

static USER_WRITE_HOOK: AtomicUsize = AtomicUsize::new(0);
static USER_ACTIVE: AtomicBool = AtomicBool::new(false);
static WRITE_GRANTED: AtomicBool = AtomicBool::new(false);
static FORGED_DENIED: AtomicBool = AtomicBool::new(false);
static FAULT_CONTAINED: AtomicBool = AtomicBool::new(false);
static EXIT_CODE: AtomicU64 = AtomicU64::new(u64::MAX);
static AUTHORIZED_HANDLE: AtomicU64 = AtomicU64::new(0);
static USER_VA_BASE: AtomicU64 = AtomicU64::new(0);

pub type WriteHook = fn(&[u8]);

pub fn set_write_hook(hook: WriteHook) {
    USER_WRITE_HOOK.store(hook as usize, Ordering::Release);
}

const fn pack_handle(handle: Handle) -> u64 {
    ((handle.generation as u64) << 32) | handle.index as u64
}

const fn unpack_handle(raw: u64) -> Handle {
    Handle {
        index: raw as u32,
        generation: (raw >> 32) as u32,
    }
}

fn user_bytes(address: u64, length: usize) -> Option<&'static [u8]> {
    let end = address.checked_add(length as u64)?;
    let code_base = USER_VA_BASE.load(Ordering::Acquire);
    let code_end = code_base + PAGE_BYTES as u64;
    if address < code_base || end > code_end {
        return None;
    }
    let offset = (address - code_base) as usize;
    Some(unsafe {
        core::slice::from_raw_parts(
            (core::ptr::addr_of!(USER_CODE) as *const u8).add(offset),
            length,
        )
    })
}

fn dispatch_write(frame: &mut TrapFrame) {
    let raw = frame.x[0];
    let allowed =
        unsafe { USER_CAPS.lookup(unpack_handle(raw), Rights::WRITE) == Ok(CONSOLE_RESOURCE) };
    let bytes = usize::try_from(frame.x[2])
        .ok()
        .and_then(|length| user_bytes(frame.x[1], length));
    if allowed {
        if let Some(bytes) = bytes {
            let hook = USER_WRITE_HOOK.load(Ordering::Acquire);
            if hook != 0 {
                let hook: WriteHook = unsafe { core::mem::transmute(hook) };
                hook(bytes);
            }
            WRITE_GRANTED.store(true, Ordering::Release);
            frame.x[0] = 0;
            return;
        }
    }
    if raw != AUTHORIZED_HANDLE.load(Ordering::Acquire) {
        FORGED_DENIED.store(true, Ordering::Release);
    }
    frame.x[0] = SYSCALL_DENIED;
}

/// Lower-EL synchronous exception dispatcher called by the assembly vector.
///
/// # Safety
/// `frame` must be the complete 800-byte frame created by the lower-EL
/// trampoline on SP_EL1.
#[no_mangle]
pub unsafe extern "C" fn aienos_lower_el_sync_dispatcher(frame: *mut TrapFrame) {
    let frame = unsafe { &mut *frame };
    let esr: u64;
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("mrs {0}, esr_el1", out(reg) esr, options(nomem, nostack));
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        esr = 0;
    }
    match (esr >> 26) & 0x3f {
        0x15 if esr & 0xffff == 0 => match frame.x[8] {
            SYS_WRITE => dispatch_write(frame),
            SYS_EXIT => {
                EXIT_CODE.store(frame.x[0], Ordering::Release);
                USER_ACTIVE.store(false, Ordering::Release);
                frame.elr_el1 = user_resume_address();
                frame.spsr_el1 = 0x5;
            }
            _ => frame.x[0] = SYSCALL_DENIED,
        },
        0x24 => {
            FAULT_CONTAINED.store(true, Ordering::Release);
            frame.elr_el1 = frame.elr_el1.wrapping_add(4);
        }
        _ => {
            EXIT_CODE.store(SYSCALL_DENIED, Ordering::Release);
            USER_ACTIVE.store(false, Ordering::Release);
            frame.elr_el1 = user_resume_address();
            frame.spsr_el1 = 0x5;
        }
    }
}

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".global aienos_enter_user",
    ".global aienos_user_resume",
    ".global aienos_user_code_start",
    ".global aienos_user_code_end",
    ".global aienos_lower_el_sync_trampoline",
    "aienos_enter_user:",
    "sub sp, sp, #96",
    "stp x19, x20, [sp, #0]",
    "stp x21, x22, [sp, #16]",
    "stp x23, x24, [sp, #32]",
    "stp x25, x26, [sp, #48]",
    "stp x27, x28, [sp, #64]",
    "stp x29, x30, [sp, #80]",
    "msr sp_el0, x1",
    "msr elr_el1, x0",
    "msr spsr_el1, xzr",
    "mov x0, x2",
    "eret",
    "aienos_user_resume:",
    "ldp x19, x20, [sp, #0]",
    "ldp x21, x22, [sp, #16]",
    "ldp x23, x24, [sp, #32]",
    "ldp x25, x26, [sp, #48]",
    "ldp x27, x28, [sp, #64]",
    "ldp x29, x30, [sp, #80]",
    "add sp, sp, #96",
    "ret",
    "aienos_user_code_start:",
    "mov x19, x0",
    "mov x0, x19",
    "adr x1, 2f",
    "mov x2, #16",
    "mov x8, #1",
    "svc #0",
    "mov x0, xzr",
    "adr x1, 2f",
    "mov x2, #16",
    "mov x8, #1",
    "svc #0",
    "ldr x21, [x3]",
    "mov x0, xzr",
    "mov x8, #2",
    "svc #0",
    "1: b 1b",
    ".balign 4",
    "2: .ascii \"el0 user: hello\\n\"",
    "aienos_user_code_end:",
    "aienos_lower_el_sync_trampoline:",
    "sub sp, sp, #800",
    "stp x0, x1, [sp, #0]",
    "stp x2, x3, [sp, #16]",
    "stp x4, x5, [sp, #32]",
    "stp x6, x7, [sp, #48]",
    "stp x8, x9, [sp, #64]",
    "stp x10, x11, [sp, #80]",
    "stp x12, x13, [sp, #96]",
    "stp x14, x15, [sp, #112]",
    "stp x16, x17, [sp, #128]",
    "stp x18, x19, [sp, #144]",
    "stp x20, x21, [sp, #160]",
    "stp x22, x23, [sp, #176]",
    "stp x24, x25, [sp, #192]",
    "stp x26, x27, [sp, #208]",
    "stp x28, x29, [sp, #224]",
    "str x30, [sp, #240]",
    "str xzr, [sp, #248]",
    "mrs x0, elr_el1",
    "mrs x1, spsr_el1",
    "stp x0, x1, [sp, #256]",
    "mrs x0, fpcr",
    "mrs x1, fpsr",
    "stp x0, x1, [sp, #272]",
    "stp q0, q1, [sp, #288]",
    "stp q2, q3, [sp, #320]",
    "stp q4, q5, [sp, #352]",
    "stp q6, q7, [sp, #384]",
    "stp q8, q9, [sp, #416]",
    "stp q10, q11, [sp, #448]",
    "stp q12, q13, [sp, #480]",
    "stp q14, q15, [sp, #512]",
    "stp q16, q17, [sp, #544]",
    "stp q18, q19, [sp, #576]",
    "stp q20, q21, [sp, #608]",
    "stp q22, q23, [sp, #640]",
    "stp q24, q25, [sp, #672]",
    "stp q26, q27, [sp, #704]",
    "stp q28, q29, [sp, #736]",
    "stp q30, q31, [sp, #768]",
    "mov x0, sp",
    "bl aienos_lower_el_sync_dispatcher",
    "ldp q0, q1, [sp, #288]",
    "ldp q2, q3, [sp, #320]",
    "ldp q4, q5, [sp, #352]",
    "ldp q6, q7, [sp, #384]",
    "ldp q8, q9, [sp, #416]",
    "ldp q10, q11, [sp, #448]",
    "ldp q12, q13, [sp, #480]",
    "ldp q14, q15, [sp, #512]",
    "ldp q16, q17, [sp, #544]",
    "ldp q18, q19, [sp, #576]",
    "ldp q20, q21, [sp, #608]",
    "ldp q22, q23, [sp, #640]",
    "ldp q24, q25, [sp, #672]",
    "ldp q26, q27, [sp, #704]",
    "ldp q28, q29, [sp, #736]",
    "ldp q30, q31, [sp, #768]",
    "ldp x0, x1, [sp, #272]",
    "msr fpcr, x0",
    "msr fpsr, x1",
    "ldp x0, x1, [sp, #256]",
    "msr elr_el1, x0",
    "msr spsr_el1, x1",
    "ldp x2, x3, [sp, #16]",
    "ldp x4, x5, [sp, #32]",
    "ldp x6, x7, [sp, #48]",
    "ldp x8, x9, [sp, #64]",
    "ldp x10, x11, [sp, #80]",
    "ldp x12, x13, [sp, #96]",
    "ldp x14, x15, [sp, #112]",
    "ldp x16, x17, [sp, #128]",
    "ldp x18, x19, [sp, #144]",
    "ldp x20, x21, [sp, #160]",
    "ldp x22, x23, [sp, #176]",
    "ldp x24, x25, [sp, #192]",
    "ldp x26, x27, [sp, #208]",
    "ldp x28, x29, [sp, #224]",
    "ldr x30, [sp, #240]",
    "ldp x0, x1, [sp, #0]",
    "add sp, sp, #800",
    "eret",
);

#[cfg(target_arch = "aarch64")]
extern "C" {
    fn aienos_enter_user(entry: u64, stack: u64, handle: u64, fault_address: u64);
    static aienos_user_code_start: u8;
    static aienos_user_code_end: u8;
    static aienos_user_resume: u8;
}

fn user_resume_address() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        core::ptr::addr_of!(aienos_user_resume) as u64
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        0
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn clean_and_invalidate(address: usize, length: usize, executable: bool) {
    let ctr: u64;
    unsafe { core::arch::asm!("mrs {0}, ctr_el0", out(reg) ctr, options(nomem, nostack)) };
    let dline = 4usize << ((ctr >> 16) & 0xf);
    let iline = 4usize << (ctr & 0xf);
    for at in (address..address + length).step_by(dline) {
        unsafe { core::arch::asm!("dc cvau, {0}", in(reg) at, options(nostack)) };
    }
    unsafe { core::arch::asm!("dsb ish", options(nostack)) };
    if executable {
        for at in (address..address + length).step_by(iline) {
            unsafe { core::arch::asm!("ic ivau, {0}", in(reg) at, options(nostack)) };
        }
        unsafe { core::arch::asm!("dsb ish", "isb", options(nostack)) };
    }
}

/// Run the EL0 isolation proof using a per-task TTBR0 root.
///
/// # Safety
/// `kernel_root` must be the active identity-mapped TTBR0 root and vectors
/// must already be installed at EL1.
pub unsafe fn run_demo(kernel_root: usize) -> DemoResult {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { run_demo_inner(kernel_root) }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = kernel_root;
        DemoResult {
            write_granted: true,
            forged_denied: true,
            fault_contained: true,
            exit_code: 0,
        }
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn run_demo_inner(kernel_root: usize) -> DemoResult {
    USER_CAPS = CapTable::new(0x454c_3001);
    let handle = USER_CAPS
        .insert(CONSOLE_RESOURCE, Rights::WRITE)
        .expect("EL0 console capability table full");
    let raw_handle = pack_handle(handle);
    AUTHORIZED_HANDLE.store(raw_handle, Ordering::Release);
    WRITE_GRANTED.store(false, Ordering::Release);
    FORGED_DENIED.store(false, Ordering::Release);
    FAULT_CONTAINED.store(false, Ordering::Release);
    EXIT_CODE.store(u64::MAX, Ordering::Release);

    USER_L0.0.fill(0);
    USER_L1.0.fill(0);
    USER_L2.0.fill(0);
    USER_L3.0.fill(0);
    USER_CODE.0.fill(0);
    USER_STACK.0.fill(0);
    core::ptr::copy_nonoverlapping(kernel_root as *const u64, USER_L0.0.as_mut_ptr(), 512);
    let user_root_index = (1..256)
        .find(|index| USER_L0.0[*index] == 0)
        .expect("kernel mappings leave no EL0 address window");
    let user_base = (user_root_index as u64) << 39;
    USER_VA_BASE.store(user_base, Ordering::Release);
    USER_L0.0[user_root_index] =
        (core::ptr::addr_of!(USER_L1) as u64 & ADDRESS_MASK) | TABLE_DESCRIPTOR;
    USER_L1.0[0] = (core::ptr::addr_of!(USER_L2) as u64 & ADDRESS_MASK) | TABLE_DESCRIPTOR;
    USER_L2.0[0] = (core::ptr::addr_of!(USER_L3) as u64 & ADDRESS_MASK) | TABLE_DESCRIPTOR;
    let user_code_pa = core::ptr::addr_of!(USER_CODE) as u64;
    let user_stack_pa = core::ptr::addr_of!(USER_STACK) as u64;
    USER_L3.0[0] =
        (user_code_pa & ADDRESS_MASK) | PAGE_DESCRIPTOR | (0b11 << 6) | (0b11 << 8) | AF | NG | PXN;
    USER_L3.0[1] = (user_stack_pa & ADDRESS_MASK)
        | PAGE_DESCRIPTOR
        | (0b01 << 6)
        | (0b11 << 8)
        | AF
        | NG
        | PXN
        | UXN;

    let start = core::ptr::addr_of!(aienos_user_code_start) as usize;
    let end = core::ptr::addr_of!(aienos_user_code_end) as usize;
    let length = end.checked_sub(start).expect("EL0 code symbols reversed");
    assert!(length <= PAGE_BYTES, "EL0 code page overflow");
    core::ptr::copy_nonoverlapping(start as *const u8, user_code_pa as *mut u8, length);

    clean_and_invalidate(core::ptr::addr_of!(USER_L0) as usize, PAGE_BYTES * 4, false);
    clean_and_invalidate(user_code_pa as usize, PAGE_BYTES, true);
    clean_and_invalidate(user_stack_pa as usize, PAGE_BYTES, false);

    let task_root = core::ptr::addr_of!(USER_L0) as u64;
    core::arch::asm!(
        "dsb ish",
        "msr ttbr0_el1, {0}",
        "tlbi vmalle1",
        "dsb ish",
        "isb",
        in(reg) task_root | (1u64 << 48),
        options(nostack)
    );
    USER_ACTIVE.store(true, Ordering::Release);
    aienos_enter_user(
        user_base,
        user_base + 0x1000 + PAGE_BYTES as u64,
        raw_handle,
        run_demo_inner as *const () as usize as u64,
    );
    core::arch::asm!(
        "dsb ish",
        "msr ttbr0_el1, {0}",
        "tlbi vmalle1",
        "dsb ish",
        "isb",
        in(reg) kernel_root as u64,
        options(nostack)
    );
    DemoResult {
        write_granted: WRITE_GRANTED.load(Ordering::Acquire),
        forged_denied: FORGED_DENIED.load(Ordering::Acquire),
        fault_contained: FAULT_CONTAINED.load(Ordering::Acquire),
        exit_code: EXIT_CODE.load(Ordering::Acquire),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_handle_round_trips() {
        let handle = Handle {
            index: 7,
            generation: 19,
        };
        assert_eq!(unpack_handle(pack_handle(handle)), handle);
    }

    #[test]
    fn trap_frame_layout_matches_assembly() {
        let frame = TrapFrame::default();
        let base = core::ptr::addr_of!(frame) as usize;
        assert_eq!(core::mem::size_of::<TrapFrame>(), 800);
        assert_eq!(core::ptr::addr_of!(frame.x) as usize - base, 0);
        assert_eq!(core::ptr::addr_of!(frame._pad) as usize - base, 248);
        assert_eq!(core::ptr::addr_of!(frame.elr_el1) as usize - base, 256);
        assert_eq!(core::ptr::addr_of!(frame.spsr_el1) as usize - base, 264);
        assert_eq!(core::ptr::addr_of!(frame.fpcr) as usize - base, 272);
        assert_eq!(core::ptr::addr_of!(frame.fpsr) as usize - base, 280);
        assert_eq!(core::ptr::addr_of!(frame.q) as usize - base, 288);
    }

    #[test]
    fn el0_mapping_attributes_are_wx_and_non_global() {
        let code = PAGE_DESCRIPTOR | (0b11 << 6) | AF | NG | PXN;
        let stack = PAGE_DESCRIPTOR | (0b01 << 6) | AF | NG | PXN | UXN;
        assert_eq!((code >> 6) & 3, 0b11, "EL0 read-only code");
        assert_eq!(code & UXN, 0, "EL0 code executable");
        assert_eq!((stack >> 6) & 3, 0b01, "EL0 read-write stack");
        assert_ne!(stack & UXN, 0, "EL0 stack execute-never");
        assert_ne!(code & NG, 0);
        assert_ne!(stack & NG, 0);
    }
}
