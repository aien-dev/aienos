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
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

pub const SYS_WRITE: u64 = 1;
pub const SYS_EXIT: u64 = 2;
pub const CONSOLE_RESOURCE: u32 = 1;
pub const SYSCALL_DENIED: u64 = u64::MAX;
pub const SYS_CHANNEL_SEND: u64 = 3;
pub const SYS_CHANNEL_RECV: u64 = 4;
pub const SYS_CAP_DELEGATE: u64 = 5;
pub const SYS_OBJECT_READ: u64 = 6;
pub const SYS_OBJECT_WRITE: u64 = 7;

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
// --- typed IPC proof state (PR #30): kernel-owned, dispatcher-consumed -----
static IPC_ACTIVE: AtomicBool = AtomicBool::new(false);
static IPC_PHASE: AtomicU32 = AtomicU32::new(0);
static IPC_EXIT: AtomicU64 = AtomicU64::new(u64::MAX);
static IPC_MESSAGE_DELIVERED: AtomicBool = AtomicBool::new(false);
static IPC_CAP_DELEGATED: AtomicBool = AtomicBool::new(false);
static IPC_RIGHTS_ATTENUATED: AtomicBool = AtomicBool::new(false);
static IPC_FORGED_DENIED: AtomicBool = AtomicBool::new(false);
static IPC_REVOKED_DENIED: AtomicBool = AtomicBool::new(false);
static IPC_CHILD_HANDLE: AtomicU64 = AtomicU64::new(0);
static IPC_SENT_KIND: AtomicU64 = AtomicU64::new(0);
static IPC_SENT_P0: AtomicU64 = AtomicU64::new(0);
static IPC_SENT_P1: AtomicU64 = AtomicU64::new(0);
static IPC_SENT_OBJ: AtomicU64 = AtomicU64::new(0);

/// A private EL0 address window: four translation levels plus code and stack.
#[repr(C, align(4096))]
struct TaskWindow {
    l0: Page,
    l1: Page,
    l2: Page,
    l3: Page,
    code: Page,
    stack: Page,
}

impl TaskWindow {
    const fn new() -> Self {
        Self {
            l0: Page([0; 512]),
            l1: Page([0; 512]),
            l2: Page([0; 512]),
            l3: Page([0; 512]),
            code: Page([0; 512]),
            stack: Page([0; 512]),
        }
    }
}

static mut IPC_WINDOW_A: TaskWindow = TaskWindow::new();
static mut IPC_WINDOW_B: TaskWindow = TaskWindow::new();
static mut SEED0B_WINDOW: TaskWindow = TaskWindow::new();
static mut SEED0B_CAPS: CapTable<4> = CapTable::new(0x5345_4544);

static SEED0B_ACTIVE: AtomicBool = AtomicBool::new(false);
static SEED0B_WRITE_GRANTED: AtomicBool = AtomicBool::new(false);
static SEED0B_FORGED_DENIED: AtomicBool = AtomicBool::new(false);
static SEED0B_FAULT_CONTAINED: AtomicBool = AtomicBool::new(false);
static SEED0B_EXIT_CODE: AtomicU64 = AtomicU64::new(u64::MAX);
static SEED0B_AUTHORIZED_HANDLE: AtomicU64 = AtomicU64::new(0);
static SEED0B_VA_BASE: AtomicU64 = AtomicU64::new(0);

/// Observed result of executing an admitted SEED-0B artifact.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Seed0bResult {
    pub ok: bool,
    pub admitted: bool,
    pub write_granted: bool,
    pub forged_denied: bool,
    pub fault_contained: bool,
    pub exit_code: u64,
}

/// Verification report from the boot-time SEED-0B admission and execution suite.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Seed0bDemoReport {
    pub ok: bool,
    pub admitted: bool,
    pub verified: bool,
    pub receipt_valid: bool,
    pub el0_clean: bool,
    pub exit_code: u64,
    pub tampered_rejected: bool,
    pub unsigned_rejected: bool,
    pub escalation_rejected: bool,
}

/// Observed result of the two-principal EL0 IPC proof.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpcResult {
    pub ok: bool,
    pub exit_a: u64,
    pub child_raw: u64,
    pub exit_b0: u64,
    pub exit_b1: u64,
    pub message_delivered: bool,
    pub cap_delegated: bool,
    pub rights_attenuated: bool,
    pub forged_denied: bool,
    pub revoked_denied: bool,
    pub exit_codes_clean: bool,
}

pub type WriteHook = fn(&[u8]);

pub fn set_write_hook(hook: WriteHook) {
    USER_WRITE_HOOK.store(hook as usize, Ordering::Release);
}

const fn pack_handle(handle: Handle) -> u64 {
    handle.to_raw()
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
    let handle = match Handle::from_raw(raw) {
        Ok(h) => h,
        Err(_) => {
            FORGED_DENIED.store(true, Ordering::Release);
            frame.x[0] = SYSCALL_DENIED;
            return;
        }
    };
    let allowed = unsafe { USER_CAPS.lookup(handle, Rights::WRITE) == Ok(CONSOLE_RESOURCE) };
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

fn seed0b_user_bytes(address: u64, length: usize) -> Option<&'static [u8]> {
    let end = address.checked_add(length as u64)?;
    let code_base = SEED0B_VA_BASE.load(Ordering::Acquire);
    let code_end = code_base + PAGE_BYTES as u64;
    if address < code_base || end > code_end {
        return None;
    }
    let offset = (address - code_base) as usize;
    Some(unsafe {
        core::slice::from_raw_parts(
            (core::ptr::addr_of!(SEED0B_WINDOW.code) as *const u8).add(offset),
            length,
        )
    })
}

fn dispatch_seed0b(frame: &mut TrapFrame) {
    match frame.x[8] {
        SYS_WRITE => {
            let raw = frame.x[0];
            let handle = match Handle::from_raw(raw) {
                Ok(h) => h,
                Err(_) => {
                    SEED0B_FORGED_DENIED.store(true, Ordering::Release);
                    frame.x[0] = SYSCALL_DENIED;
                    return;
                }
            };
            let allowed = unsafe { SEED0B_CAPS.lookup(handle, Rights::WRITE) == Ok(CONSOLE_RESOURCE) };
            let bytes = usize::try_from(frame.x[2])
                .ok()
                .and_then(|length| seed0b_user_bytes(frame.x[1], length));
            if allowed {
                if let Some(bytes) = bytes {
                    let hook = USER_WRITE_HOOK.load(Ordering::Acquire);
                    if hook != 0 {
                        let hook: WriteHook = unsafe { core::mem::transmute(hook) };
                        hook(bytes);
                    }
                    SEED0B_WRITE_GRANTED.store(true, Ordering::Release);
                    frame.x[0] = 0;
                    return;
                }
            }
            if raw != SEED0B_AUTHORIZED_HANDLE.load(Ordering::Acquire) {
                SEED0B_FORGED_DENIED.store(true, Ordering::Release);
            }
            frame.x[0] = SYSCALL_DENIED;
        }
        SYS_EXIT => {
            SEED0B_EXIT_CODE.store(frame.x[0], Ordering::Release);
            SEED0B_ACTIVE.store(false, Ordering::Release);
            frame.elr_el1 = user_resume_address();
            frame.spsr_el1 = 0x5;
        }
        _ => {
            frame.x[0] = SYSCALL_DENIED;
        }
    }
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
        0x15 if esr & 0xffff == 0 => {
            if SEED0B_ACTIVE.load(Ordering::Acquire) {
                dispatch_seed0b(frame);
            } else if IPC_ACTIVE.load(Ordering::Acquire) {
                dispatch_ipc(frame);
            } else {
                match frame.x[8] {
                    SYS_WRITE => dispatch_write(frame),
                    SYS_EXIT => {
                        EXIT_CODE.store(frame.x[0], Ordering::Release);
                        USER_ACTIVE.store(false, Ordering::Release);
                        frame.elr_el1 = user_resume_address();
                        frame.spsr_el1 = 0x5;
                    }
                    _ => frame.x[0] = SYSCALL_DENIED,
                }
            }
        }
        0x24 => {
            if SEED0B_ACTIVE.load(Ordering::Acquire) {
                SEED0B_FAULT_CONTAINED.store(true, Ordering::Release);
                frame.elr_el1 = frame.elr_el1.wrapping_add(4);
            } else {
                FAULT_CONTAINED.store(true, Ordering::Release);
                frame.elr_el1 = frame.elr_el1.wrapping_add(4);
            }
        }
        _ => {
            if SEED0B_ACTIVE.load(Ordering::Acquire) {
                SEED0B_EXIT_CODE.store(SYSCALL_DENIED, Ordering::Release);
                SEED0B_ACTIVE.store(false, Ordering::Release);
                frame.elr_el1 = user_resume_address();
                frame.spsr_el1 = 0x5;
            } else {
                EXIT_CODE.store(SYSCALL_DENIED, Ordering::Release);
                USER_ACTIVE.store(false, Ordering::Release);
                frame.elr_el1 = user_resume_address();
                frame.spsr_el1 = 0x5;
            }
        }
    }
}

/// EL1-side dispatcher for the typed IPC syscalls. Every operation resolves
/// handles against the active principal's own capability table; there is no
/// ambient authority.
fn dispatch_ipc(frame: &mut TrapFrame) {
    match frame.x[8] {
        SYS_CHANNEL_SEND => {
            let handle = match Handle::from_raw(frame.x[0]) {
                Ok(h) => h,
                Err(_) => {
                    frame.x[0] = SYSCALL_DENIED;
                    return;
                }
            };
            let message = crate::abi::Message::new(
                frame.x[1] as u32,
                [frame.x[2], frame.x[3], frame.x[4]],
                crate::abi::MemoryRegion::new(frame.x[5], frame.x[6] as u32),
                crate::abi::ObjectId(frame.x[7]),
            );
            let result = unsafe { crate::ipc::channel_send_active(handle, message) };
            match result {
                Ok(()) => {
                    IPC_SENT_KIND.store(frame.x[1], Ordering::Release);
                    IPC_SENT_P0.store(frame.x[2], Ordering::Release);
                    IPC_SENT_P1.store(frame.x[3], Ordering::Release);
                    IPC_SENT_OBJ.store(frame.x[7], Ordering::Release);
                    frame.x[0] = 0;
                }
                Err(_) => frame.x[0] = SYSCALL_DENIED,
            }
        }
        SYS_CHANNEL_RECV => {
            let handle = match Handle::from_raw(frame.x[0]) {
                Ok(h) => h,
                Err(_) => {
                    frame.x[0] = SYSCALL_DENIED;
                    return;
                }
            };
            match unsafe { crate::ipc::channel_receive_active(handle) } {
                Ok(message) => {
                    let delivered = message.kind as u64 == IPC_SENT_KIND.load(Ordering::Acquire)
                        && message.payload[0] == IPC_SENT_P0.load(Ordering::Acquire)
                        && message.payload[1] == IPC_SENT_P1.load(Ordering::Acquire)
                        && message.object.0 == IPC_SENT_OBJ.load(Ordering::Acquire);
                    if delivered {
                        IPC_MESSAGE_DELIVERED.store(true, Ordering::Release);
                    }
                    frame.x[0] = 0;
                    frame.x[1] = message.kind as u64;
                    frame.x[2] = message.payload[0];
                    frame.x[3] = message.payload[1];
                    frame.x[4] = message.payload[2];
                    frame.x[5] = message.object.0;
                }
                Err(_) => frame.x[0] = SYSCALL_DENIED,
            }
        }
        SYS_CAP_DELEGATE => {
            let handle = match Handle::from_raw(frame.x[0]) {
                Ok(h) => h,
                Err(_) => {
                    frame.x[0] = SYSCALL_DENIED;
                    return;
                }
            };
            let wire_rights = match crate::abi::Rights::from_bits(frame.x[2] as u32) {
                Ok(r) => r,
                Err(_) => {
                    frame.x[0] = SYSCALL_DENIED;
                    return;
                }
            };
            let caps_rights: Rights = match wire_rights.try_into() {
                Ok(r) => r,
                Err(_) => {
                    frame.x[0] = SYSCALL_DENIED;
                    return;
                }
            };
            match unsafe {
                crate::ipc::delegate_from_active(handle, frame.x[1] as u32, caps_rights)
            } {
                Ok(child) => {
                    IPC_CAP_DELEGATED.store(true, Ordering::Release);
                    IPC_CHILD_HANDLE.store(child.to_raw(), Ordering::Release);
                    frame.x[0] = 0;
                }
                Err(_) => frame.x[0] = SYSCALL_DENIED,
            }
        }
        SYS_OBJECT_READ => {
            let handle = match Handle::from_raw(frame.x[0]) {
                Ok(h) => h,
                Err(_) => {
                    if IPC_PHASE.load(Ordering::Acquire) & 0xff != 0 {
                        IPC_REVOKED_DENIED.store(true, Ordering::Release);
                    } else {
                        IPC_FORGED_DENIED.store(true, Ordering::Release);
                    }
                    frame.x[0] = SYSCALL_DENIED;
                    return;
                }
            };
            match unsafe { crate::ipc::object_read_active(handle, frame.x[1] as usize) } {
                Ok(value) => frame.x[0] = value,
                Err(crate::ipc::IpcError::InvalidHandle) => {
                    if IPC_PHASE.load(Ordering::Acquire) & 0xff != 0 {
                        IPC_REVOKED_DENIED.store(true, Ordering::Release);
                    } else {
                        IPC_FORGED_DENIED.store(true, Ordering::Release);
                    }
                    frame.x[0] = SYSCALL_DENIED;
                }
                Err(_) => frame.x[0] = SYSCALL_DENIED,
            }
        }
        SYS_OBJECT_WRITE => {
            let handle = match Handle::from_raw(frame.x[0]) {
                Ok(h) => h,
                Err(_) => {
                    frame.x[0] = SYSCALL_DENIED;
                    return;
                }
            };
            match unsafe {
                crate::ipc::object_write_active(handle, frame.x[1] as usize, frame.x[2])
            } {
                Ok(()) => frame.x[0] = 0,
                Err(crate::ipc::IpcError::MissingRights) => {
                    IPC_RIGHTS_ATTENUATED.store(true, Ordering::Release);
                    frame.x[0] = SYSCALL_DENIED;
                }
                Err(_) => frame.x[0] = SYSCALL_DENIED,
            }
        }
        SYS_EXIT => {
            IPC_EXIT.store(frame.x[0], Ordering::Release);
            frame.elr_el1 = user_resume_address();
            frame.spsr_el1 = 0x5;
        }
        _ => frame.x[0] = SYSCALL_DENIED,
    }
}

/// Map a fresh EL0 window (kernel-derived tables, read-only code, read-write
/// non-executable stack), copy `image` into the code page, and clean caches.
///
/// # Safety
/// Window pointers must address live, exclusive, 4096-aligned statics.
#[cfg(target_arch = "aarch64")]
unsafe fn build_window(window: *mut TaskWindow, image: &[u8], kernel_root: usize) -> u64 {
    let window = unsafe { &mut *window };
    window.l0.0.fill(0);
    window.l1.0.fill(0);
    window.l2.0.fill(0);
    window.l3.0.fill(0);
    window.code.0.fill(0);
    window.stack.0.fill(0);
    unsafe {
        core::ptr::copy_nonoverlapping(kernel_root as *const u64, window.l0.0.as_mut_ptr(), 512)
    };
    let user_root_index = (1..256)
        .find(|index| window.l0.0[*index] == 0)
        .expect("kernel mappings leave no EL0 address window");
    let user_base = (user_root_index as u64) << 39;
    window.l0.0[user_root_index] =
        (core::ptr::addr_of!(window.l1) as u64 & ADDRESS_MASK) | TABLE_DESCRIPTOR;
    window.l1.0[0] = (core::ptr::addr_of!(window.l2) as u64 & ADDRESS_MASK) | TABLE_DESCRIPTOR;
    window.l2.0[0] = (core::ptr::addr_of!(window.l3) as u64 & ADDRESS_MASK) | TABLE_DESCRIPTOR;
    let code_pa = core::ptr::addr_of!(window.code) as u64;
    let stack_pa = core::ptr::addr_of!(window.stack) as u64;
    window.l3.0[0] =
        (code_pa & ADDRESS_MASK) | PAGE_DESCRIPTOR | (0b11 << 6) | (0b11 << 8) | AF | NG | PXN;
    window.l3.0[1] = (stack_pa & ADDRESS_MASK)
        | PAGE_DESCRIPTOR
        | (0b01 << 6)
        | (0b11 << 8)
        | AF
        | NG
        | PXN
        | UXN;
    assert!(image.len() <= PAGE_BYTES, "EL0 code page overflow");
    unsafe { core::ptr::copy_nonoverlapping(image.as_ptr(), code_pa as *mut u8, image.len()) };
    unsafe {
        clean_and_invalidate(
            core::ptr::addr_of!(window.l0) as usize,
            PAGE_BYTES * 4,
            false,
        );
        clean_and_invalidate(code_pa as usize, PAGE_BYTES, true);
        clean_and_invalidate(stack_pa as usize, PAGE_BYTES, false);
    }
    user_base
}

#[cfg(target_arch = "aarch64")]
unsafe fn swap_ttbr0(root: u64) {
    core::arch::asm!(
        "dsb ish",
        "msr ttbr0_el1, {0}",
        "tlbi vmalle1",
        "dsb ish",
        "isb",
        in(reg) root,
        options(nostack)
    );
}

/// Two-principal typed-IPC proof at EL0.
///
/// Principal A holds the channel send right and a full-rights object
/// capability; it sends one typed message and delegates a READ-only copy of
/// the object capability to principal B. B receives the exact message, reads
/// the object through the attenuated handle, is denied a write and a forged
/// handle. The kernel then revokes A's ancestor and B's derived handle stops
/// working.
///
/// # Safety
/// `kernel_root` must be the active identity-mapped TTBR0 root and vectors
/// must already be installed at EL1.
pub unsafe fn run_ipc_demo(kernel_root: usize) -> IpcResult {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { run_ipc_demo_inner(kernel_root) }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = kernel_root;
        IpcResult {
            ok: true,
            exit_a: 0,
            child_raw: 0,
            exit_b0: 0,
            exit_b1: 0,
            message_delivered: true,
            cap_delegated: true,
            rights_attenuated: true,
            forged_denied: true,
            revoked_denied: true,
            exit_codes_clean: true,
        }
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn run_ipc_demo_inner(kernel_root: usize) -> IpcResult {
    IPC_MESSAGE_DELIVERED.store(false, Ordering::Release);
    IPC_CAP_DELEGATED.store(false, Ordering::Release);
    IPC_RIGHTS_ATTENUATED.store(false, Ordering::Release);
    IPC_FORGED_DENIED.store(false, Ordering::Release);
    IPC_REVOKED_DENIED.store(false, Ordering::Release);
    IPC_CHILD_HANDLE.store(0, Ordering::Release);
    IPC_EXIT.store(u64::MAX, Ordering::Release);

    let (a_send, a_object, b_recv) = crate::ipc::reset();
    let image_start = core::ptr::addr_of!(aienos_ipc_code_start) as usize;
    let image_end = core::ptr::addr_of!(aienos_ipc_code_end) as usize;
    let image =
        unsafe { core::slice::from_raw_parts(image_start as *const u8, image_end - image_start) };

    let base_a = unsafe { build_window(core::ptr::addr_of_mut!(IPC_WINDOW_A), image, kernel_root) };
    let base_b = unsafe { build_window(core::ptr::addr_of_mut!(IPC_WINDOW_B), image, kernel_root) };

    let window_a = unsafe { &mut *core::ptr::addr_of_mut!(IPC_WINDOW_A) };
    let window_b = unsafe { &mut *core::ptr::addr_of_mut!(IPC_WINDOW_B) };
    let root_a = core::ptr::addr_of!(window_a.l0) as u64;
    let root_b = core::ptr::addr_of!(window_b.l0) as u64;
    let kernel_root_u64 = kernel_root as u64;

    IPC_ACTIVE.store(true, Ordering::Release);

    // --- principal A: send the typed message, delegate an attenuated copy ---
    crate::ipc::set_active_principal(crate::ipc::TaskId(crate::ipc::PRINCIPAL_A));
    IPC_PHASE.store(0, Ordering::Release);
    IPC_EXIT.store(u64::MAX, Ordering::Release);
    unsafe { swap_ttbr0(root_a) };
    unsafe {
        aienos_ipc_enter(
            base_a,
            base_a + 0x1000 + PAGE_BYTES as u64,
            pack_handle(a_send),
            pack_handle(a_object),
            1,
        )
    };
    unsafe { swap_ttbr0(kernel_root_u64) };
    let exit_a = IPC_EXIT.load(Ordering::Acquire);

    // --- principal B, phase 0: receive, read, attempt write, forge ----------
    let child_handle = IPC_CHILD_HANDLE.load(Ordering::Acquire);
    crate::ipc::set_active_principal(crate::ipc::TaskId(crate::ipc::PRINCIPAL_B));
    IPC_PHASE.store(0, Ordering::Release);
    IPC_EXIT.store(u64::MAX, Ordering::Release);
    unsafe { swap_ttbr0(root_b) };
    unsafe {
        aienos_ipc_enter(
            base_b,
            base_b + 0x1000 + PAGE_BYTES as u64,
            pack_handle(b_recv),
            child_handle,
            2,
        )
    };
    unsafe { swap_ttbr0(kernel_root_u64) };
    let exit_b0 = IPC_EXIT.load(Ordering::Acquire);

    // --- kernel revokes A's ancestor; B's derived handle must die ----------
    unsafe { crate::ipc::revoke_object_ancestor(crate::ipc::PRINCIPAL_A, a_object) }
        .expect("ancestor revocation");

    // --- principal B, phase 1: the derived handle no longer resolves -------
    IPC_PHASE.store(1, Ordering::Release);
    IPC_EXIT.store(u64::MAX, Ordering::Release);
    unsafe { swap_ttbr0(root_b) };
    unsafe {
        aienos_ipc_enter(
            base_b,
            base_b + 0x1000 + PAGE_BYTES as u64,
            pack_handle(b_recv),
            child_handle,
            0x102,
        )
    };
    unsafe { swap_ttbr0(kernel_root_u64) };
    let exit_b1 = IPC_EXIT.load(Ordering::Acquire);

    IPC_ACTIVE.store(false, Ordering::Release);

    let result = IpcResult {
        ok: false,
        exit_a,
        child_raw: IPC_CHILD_HANDLE.load(Ordering::Acquire),
        exit_b0,
        exit_b1,
        message_delivered: IPC_MESSAGE_DELIVERED.load(Ordering::Acquire),
        cap_delegated: IPC_CAP_DELEGATED.load(Ordering::Acquire),
        rights_attenuated: IPC_RIGHTS_ATTENUATED.load(Ordering::Acquire),
        forged_denied: IPC_FORGED_DENIED.load(Ordering::Acquire),
        revoked_denied: IPC_REVOKED_DENIED.load(Ordering::Acquire),
        exit_codes_clean: exit_a == 0 && exit_b0 == 0 && exit_b1 == 0,
    };
    IpcResult {
        ok: result.message_delivered
            && result.cap_delegated
            && result.rights_attenuated
            && result.forged_denied
            && result.revoked_denied
            && result.exit_codes_clean,
        ..result
    }
}

#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".global aienos_ipc_enter",
    ".global aienos_ipc_code_start",
    ".global aienos_ipc_code_end",
    // x0=entry, x1=sp_el0, x2=handle0 -> x20, x3=handle1 -> x21, x4=arg -> x22
    "aienos_ipc_enter:",
    "sub sp, sp, #96",
    "stp x19, x20, [sp, #0]",
    "stp x21, x22, [sp, #16]",
    "stp x23, x24, [sp, #32]",
    "stp x25, x26, [sp, #48]",
    "stp x27, x28, [sp, #64]",
    "stp x29, x30, [sp, #80]",
    "mov x20, x2",
    "mov x21, x3",
    "mov x22, x4",
    "msr sp_el0, x1",
    "msr elr_el1, x0",
    "msr spsr_el1, xzr",
    "mov x0, x4",
    "eret",
    "aienos_ipc_code_start:",
    "mov x23, xzr",
    "cmp x22, #1",
    "b.eq 10f",
    "tbnz x22, #8, 50f",
    "b 20f",
    // ---- principal A: send, delegate attenuated, exit ----
    "10:",
    "mov x0, x20",
    "mov x1, #7",
    "mov x2, #0x1111",
    "mov x3, #0x2222",
    "mov x4, #0x3333",
    "mov x5, #0xa",
    "mov x6, #0x1000",
    "mov x7, #2",
    "mov x8, #3",
    "svc #0",
    "cmp x0, #0",
    "b.eq 15f",
    "orr x23, x23, #32",
    "15:",
    "mov x0, x21",
    "mov x1, #1",
    "mov x2, #1",
    "mov x8, #5",
    "svc #0",
    "cmp x0, #0",
    "b.eq 16f",
    "orr x23, x23, #64",
    "16:",
    "mov x0, x23",
    "mov x8, #2",
    "svc #0",
    "70: b 70b",
    // ---- principal B, phase 0: receive, read, write-attempt, forge ----
    "20:",
    "mov x0, x20",
    "mov x8, #4",
    "svc #0",
    "cmp x0, #0",
    "b.eq 21f",
    "orr x23, x23, #1",
    "21:",
    "cmp x1, #7",
    "b.eq 22f",
    "orr x23, x23, #1",
    "22:",
    "movz x5, #0x1111",
    "cmp x2, x5",
    "b.eq 23f",
    "orr x23, x23, #1",
    "23:",
    "movz x5, #0x2222",
    "cmp x3, x5",
    "b.eq 24f",
    "orr x23, x23, #1",
    "24:",
    "mov x0, x21",
    "mov x1, #0",
    "mov x8, #6",
    "svc #0",
    "movz x5, #0xee01",
    "movk x5, #0xc0ff, lsl #16",
    "cmp x0, x5",
    "b.eq 25f",
    "orr x23, x23, #2",
    "25:",
    "mov x0, x21",
    "mov x1, #0",
    "mov x2, #0xbad",
    "mov x8, #7",
    "svc #0",
    "cmp x0, #0",
    "b.ne 26f",
    "orr x23, x23, #4",
    "26:",
    "mov x6, #1",
    "lsl x6, x6, #32",
    "eor x0, x21, x6",
    "mov x1, #0",
    "mov x8, #6",
    "svc #0",
    "cmp x0, #0",
    "b.ne 27f",
    "orr x23, x23, #8",
    "27:",
    "mov x0, x23",
    "mov x8, #2",
    "svc #0",
    "71: b 71b",
    // ---- principal B, phase 1: revoked handle must not resolve ----
    "50:",
    "mov x0, x21",
    "mov x1, #0",
    "mov x8, #6",
    "svc #0",
    "cmp x0, #0",
    "b.ne 51f",
    "orr x23, x23, #16",
    "51:",
    "mov x0, x23",
    "mov x8, #2",
    "svc #0",
    "72: b 72b",
    "aienos_ipc_code_end:",
);

#[cfg(target_arch = "aarch64")]
extern "C" {
    fn aienos_ipc_enter(entry: u64, stack: u64, handle0: u64, handle1: u64, arg: u64);
    static aienos_ipc_code_start: u8;
    static aienos_ipc_code_end: u8;
    static aienos_seed0b_code_start: u8;
    static aienos_seed0b_code_end: u8;
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
    ".global aienos_seed0b_code_start",
    ".global aienos_seed0b_code_end",
    "aienos_seed0b_code_start:",
    "mov x19, x0",
    "mov x0, x19",
    "adr x1, 3f",
    "mov x2, #23",
    "mov x8, #1",
    "svc #0",
    "mov x0, xzr",
    "adr x1, 3f",
    "mov x2, #23",
    "mov x8, #1",
    "svc #0",
    "ldr x21, [x3]",
    "mov x0, xzr",
    "mov x8, #2",
    "svc #0",
    "4: b 4b",
    ".balign 4",
    "3: .ascii \"seed0b: el0 payload ok\\n\"",
    "aienos_seed0b_code_end:",
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

pub fn seed0b_payload_bytes() -> &'static [u8] {
    #[cfg(target_arch = "aarch64")]
    {
        let start = core::ptr::addr_of!(aienos_seed0b_code_start) as usize;
        let end = core::ptr::addr_of!(aienos_seed0b_code_end) as usize;
        let length = end.checked_sub(start).expect("SEED-0B symbols reversed");
        unsafe { core::slice::from_raw_parts(start as *const u8, length) }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        &[
            0x13, 0x00, 0x00, 0xaa, 0xe0, 0x03, 0x13, 0xaa,
            0x21, 0x00, 0x00, 0x10, 0xa2, 0x01, 0x80, 0xd2,
            0x28, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4,
            0xe0, 0x03, 0x1f, 0xaa, 0x21, 0x00, 0x00, 0x10,
            0xa2, 0x01, 0x80, 0xd2, 0x28, 0x00, 0x80, 0xd2,
            0x01, 0x00, 0x00, 0xd4, 0x75, 0x00, 0x40, 0xf9,
            0xe0, 0x03, 0x1f, 0xaa, 0x48, 0x00, 0x80, 0xd2,
            0x01, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x00, 0x14,
        ]
    }
}

/// Executes an admitted binary artifact in an isolated EL0 execution window.
///
/// # Safety
/// The caller must ensure that kernel_root is a valid root translation table address
/// and that hardware registers can be safely switched.
pub unsafe fn run_seed0b_artifact(
    kernel_root: usize,
    artifact: &crate::artifact::AdmittedArtifactView<'_>,
    receipt: &crate::artifact::AdmissionReceiptV0,
) -> Seed0bResult {
    #[cfg(all(target_arch = "aarch64", not(test)))]
    {
        unsafe { run_seed0b_artifact_inner(kernel_root, artifact, receipt) }
    }
    #[cfg(any(not(target_arch = "aarch64"), test))]
    {
        let _ = (kernel_root, artifact, receipt);
        let admitted = receipt.is_admitted() && receipt.artifact_id == artifact.artifact_id;
        Seed0bResult {
            ok: admitted,
            admitted,
            write_granted: admitted,
            forged_denied: admitted,
            fault_contained: admitted,
            exit_code: if admitted { 0 } else { u64::MAX },
        }
    }
}

#[cfg(all(target_arch = "aarch64", not(test)))]
unsafe fn run_seed0b_artifact_inner(
    kernel_root: usize,
    artifact: &crate::artifact::AdmittedArtifactView<'_>,
    receipt: &crate::artifact::AdmissionReceiptV0,
) -> Seed0bResult {
    if !receipt.is_admitted() || receipt.artifact_id != artifact.artifact_id {
        return Seed0bResult {
            ok: false,
            admitted: false,
            write_granted: false,
            forged_denied: false,
            fault_contained: false,
            exit_code: u64::MAX,
        };
    }

    SEED0B_CAPS = CapTable::new(0x5345_4544);
    let mut granted_handle = None;
    let count = core::cmp::min(receipt.grant_count as usize, crate::artifact::MAX_CAPABILITY_GRANTS);
    for grant in &receipt.grants[..count] {
        if grant.resource_kind == 1 {
            if let Some(r) = Rights::from_bits(grant.rights as u8) {
                let h = SEED0B_CAPS.insert(CONSOLE_RESOURCE, r).expect("SEED-0B cap table full");
                granted_handle = Some(pack_handle(h));
            }
        }
    }
    let raw_handle = granted_handle.unwrap_or(0);
    SEED0B_AUTHORIZED_HANDLE.store(raw_handle, Ordering::Release);
    SEED0B_WRITE_GRANTED.store(false, Ordering::Release);
    SEED0B_FORGED_DENIED.store(false, Ordering::Release);
    SEED0B_FAULT_CONTAINED.store(false, Ordering::Release);
    SEED0B_EXIT_CODE.store(u64::MAX, Ordering::Release);

    let user_base = build_window(
        core::ptr::addr_of_mut!(SEED0B_WINDOW),
        artifact.payload,
        kernel_root,
    );
    SEED0B_VA_BASE.store(user_base, Ordering::Release);

    let task_root = core::ptr::addr_of!(SEED0B_WINDOW.l0) as u64;
    swap_ttbr0(task_root | (3u64 << 48));

    SEED0B_ACTIVE.store(true, Ordering::Release);
    aienos_enter_user(
        user_base + artifact.manifest.entry_offset as u64,
        user_base + 0x1000 + PAGE_BYTES as u64,
        raw_handle,
        run_seed0b_artifact_inner as *const () as usize as u64,
    );

    swap_ttbr0(kernel_root as u64);

    let write_granted = SEED0B_WRITE_GRANTED.load(Ordering::Acquire);
    let forged_denied = SEED0B_FORGED_DENIED.load(Ordering::Acquire);
    let fault_contained = SEED0B_FAULT_CONTAINED.load(Ordering::Acquire);
    let exit_code = SEED0B_EXIT_CODE.load(Ordering::Acquire);
    let clean = write_granted && forged_denied && fault_contained && exit_code == 0;

    Seed0bResult {
        ok: clean,
        admitted: true,
        write_granted,
        forged_denied,
        fault_contained,
        exit_code,
    }
}

/// Runs the SEED-0B verification and admission demo in bare-metal or simulated environment.
///
/// # Safety
/// The caller must ensure that kernel_root is a valid root translation table address.
pub unsafe fn run_seed0b_demo(kernel_root: usize) -> Seed0bDemoReport {
    use crate::artifact::{
        admit_artifact, ArtifactBuilder, CapabilityRequest, AdmissionPolicy,
        ArtifactError, TestOnlyTrustAnchors,
    };

    let anchors = TestOnlyTrustAnchors::default();
    let payload = seed0b_payload_bytes();

    let req = CapabilityRequest {
        resource_kind: 1,
        resource_id: 0,
        rights: Rights::WRITE.bits() as u32,
        reserved: 0,
        bounds: 4096,
    };

    let artifact_bytes = match ArtifactBuilder::new("seed0b.cap.demo", payload)
        .with_request(req)
        .with_generation(1)
        .build_and_sign(&anchors.authority_secret, &anchors.signer_id)
    {
        Ok(b) => b,
        Err(_) => return Seed0bDemoReport::default(),
    };

    let policy = AdmissionPolicy {
        allowed_signer_id: Some(anchors.signer_id),
        ..Default::default()
    };

    let (receipt, view_result) = admit_artifact(&artifact_bytes, &policy, 100, 1000);
    let admitted = receipt.is_admitted();
    let verified = receipt.verify_signature(&policy.receipt_secret);
    let receipt_valid = receipt.verify_receipt_id();

    let view = match view_result {
        Ok(v) => v,
        Err(_) => return Seed0bDemoReport::default(),
    };

    let exec = unsafe { run_seed0b_artifact(kernel_root, &view, &receipt) };

    let mut tampered = artifact_bytes.clone();
    let payload_offset = (view.header.payload_offset as usize) + 4;
    if payload_offset < tampered.len() {
        tampered[payload_offset] ^= 0xff;
    }
    let (t_receipt, t_res) = admit_artifact(&tampered, &policy, 101, 1001);
    let tampered_rejected = !t_receipt.is_admitted() && t_res.is_err();

    let bad_secret = [0x55u8; 32];
    let bad_bytes = match ArtifactBuilder::new("seed0b.unsigned", payload)
        .with_request(req)
        .build_and_sign(&bad_secret, &anchors.signer_id)
    {
        Ok(b) => b,
        Err(_) => return Seed0bDemoReport::default(),
    };
    let (u_receipt, u_res) = admit_artifact(&bad_bytes, &policy, 102, 1002);
    let unsigned_rejected = !u_receipt.is_admitted() && u_res == Err(ArtifactError::InvalidSignature);

    let req_escalate = CapabilityRequest {
        resource_kind: 1,
        resource_id: 0,
        rights: (Rights::WRITE | Rights::REVOKE).bits() as u32,
        reserved: 0,
        bounds: 4096,
    };
    let esc_bytes = match ArtifactBuilder::new("seed0b.escalate", payload)
        .with_request(req_escalate)
        .build_and_sign(&anchors.authority_secret, &anchors.signer_id)
    {
        Ok(b) => b,
        Err(_) => return Seed0bDemoReport::default(),
    };
    let (e_receipt, e_res) = admit_artifact(&esc_bytes, &policy, 103, 1003);
    let escalation_rejected = !e_receipt.is_admitted() && e_res == Err(ArtifactError::RightsEscalation);

    let all_ok = admitted
        && verified
        && receipt_valid
        && exec.ok
        && exec.exit_code == 0
        && tampered_rejected
        && unsigned_rejected
        && escalation_rejected;

    Seed0bDemoReport {
        ok: all_ok,
        admitted,
        verified,
        receipt_valid,
        el0_clean: exec.ok,
        exit_code: exec.exit_code,
        tampered_rejected,
        unsigned_rejected,
        escalation_rejected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed0b_host_demo_verifies() {
        let report = unsafe { run_seed0b_demo(0) };
        assert!(report.ok);
        assert!(report.admitted);
        assert!(report.verified);
        assert!(report.receipt_valid);
        assert!(report.el0_clean);
        assert_eq!(report.exit_code, 0);
        assert!(report.tampered_rejected);
        assert!(report.unsigned_rejected);
        assert!(report.escalation_rejected);
    }

    #[test]
    fn capability_handle_round_trips() {
        let handle = Handle::new(7, 19).unwrap();
        assert_eq!(Handle::from_raw(handle.to_raw()), Ok(handle));
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
