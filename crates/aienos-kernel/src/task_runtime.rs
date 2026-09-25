//! EL0 execution of one admitted, loaded artifact task.
//!
//! The loader (`artifact_loader`) builds the private address space and the
//! capability table; this module only enters EL0 with that state, dispatches
//! the task's syscalls against its own table, enforces the admitted CPU,
//! elapsed-time and syscall budgets, and returns control to the kernel on
//! exit, fault, timeout, bad syscall, or budget overrun. It has no parser,
//! signature, or policy responsibilities.
//!
//! Entry ABI (v0 loader, ABI v1 register forms):
//! - `x0` = VA of the task's handle array (u64 register-form handles, in
//!   grant order) at the top of its stack; `x1` = handle count;
//!   `x2` = data section base VA; `x3` = admitted data memory length.
//! - Every other general-purpose and SIMD/FP register is zero.
//! - `sp_el0` is 16-byte aligned below the handle array.
//!
//! Syscalls (`svc #0`, number in `x8`):
//! - `SYS_EXIT` (2): `x0` = exit code. Ends the task.
//! - `SYS_OBJECT_READ` (6): `x0` = handle, `x1` = byte offset (8-aligned).
//!   Returns the u64 at that offset in `x0`, or `SYSCALL_DENIED`.
//! - `SYS_OBJECT_WRITE` (7): `x0` = handle, `x1` = offset, `x2` = value.
//!   Returns 0 or `SYSCALL_DENIED`.
//! - Any other number terminates the task with `ExecutionStatus::BadSyscall`.
//!
//! A capability-table resource value is the task's grant index; kind, object
//! id, byte range and operation/byte budgets come from that grant.

use crate::abi::{Handle, ResourceKind};
use crate::admission::GrantedCapability;
use crate::caps::{CapTable, Rights};
use core::sync::atomic::{AtomicBool, Ordering};

pub const SYS_EXIT: u64 = 2;
pub const SYS_OBJECT_READ: u64 = 6;
pub const SYS_OBJECT_WRITE: u64 = 7;
pub const SYSCALL_DENIED: u64 = u64::MAX;

/// Capability slots per loaded task (== artifact v0 maximum).
pub const TASK_CAPABILITIES: usize = 16;

/// Kernel-owned object reachable by SEED-0B qualification artifacts.
pub const SEED_OBJECT_ID: u32 = 1;
pub const SEED_OBJECT_WORDS: [u64; 4] = [
    0xa1e0_5eed_0000_0001,
    0xa1e0_5eed_0000_0002,
    0xa1e0_5eed_0000_0003,
    0xa1e0_5eed_0000_0004,
];
/// Size of the seed object in bytes.
pub const SEED_OBJECT_BYTES: u64 = (SEED_OBJECT_WORDS.len() * 8) as u64;

/// ASID used for loaded artifact tasks (M3 demos use 1).
pub const TASK_ASID: u16 = 2;

/// SPSR used when a termination returns control to EL1h with DAIF masked.
const SPSR_EL1H_MASKED: u64 = 0x3c5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionStatus {
    NotRun,
    Exited(u64),
    Timeout,
    Fault { esr: u64, far: u64, elr: u64 },
    BadSyscall(u64),
    ResourceOverrun,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskOutcome {
    pub status: ExecutionStatus,
    pub syscalls: u32,
    pub object_reads_ok: u32,
    pub denials: u32,
    pub elapsed_ticks: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskBudget {
    pub cpu_ticks: u64,
    pub elapsed_ticks: u64,
    pub syscalls: u32,
}

impl TaskBudget {
    /// With one task on one core, CPU time never exceeds elapsed time, so the
    /// tighter of the two budgets is the single wall-clock limit.
    pub const fn tick_limit(self) -> u64 {
        if self.cpu_ticks < self.elapsed_ticks {
            self.cpu_ticks
        } else {
            self.elapsed_ticks
        }
    }
}

/// Everything the runtime needs to run one task. Built by the loader.
pub struct TaskContext<'a> {
    /// Physical address of the task's private L0 table.
    pub root: u64,
    pub entry_pc: u64,
    pub stack_pointer: u64,
    pub args: [u64; 4],
    pub capabilities: &'a mut CapTable<TASK_CAPABILITIES>,
    pub grants: &'a [Option<GrantedCapability>],
    pub budget: TaskBudget,
}

/// Counter ticks elapsed since `start`, correct across one counter wrap.
pub const fn elapsed_since(start: u64, now: u64) -> u64 {
    now.wrapping_sub(start)
}

/// True once `limit` ticks have passed since `start`.
pub const fn deadline_expired(start: u64, now: u64, limit: u64) -> bool {
    elapsed_since(start, now) >= limit
}

/// Consumption of one grant's operation and byte budgets.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GrantUsage {
    pub operations: u32,
    pub bytes: u64,
}

/// What the dispatcher must do with the trapped task after a syscall.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallAction {
    /// Resume EL0 with this value in `x0`.
    Return(u64),
    /// End the task with this status.
    Terminate(ExecutionStatus),
}

/// Host-testable accounting and authority state of the running task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeState {
    pub budget: TaskBudget,
    pub start: u64,
    pub syscalls: u32,
    pub object_reads_ok: u32,
    pub denials: u32,
    pub usage: [GrantUsage; TASK_CAPABILITIES],
    pub object: [u64; 4],
}

impl RuntimeState {
    pub const fn new(budget: TaskBudget, start: u64) -> Self {
        Self {
            budget,
            start,
            syscalls: 0,
            object_reads_ok: 0,
            denials: 0,
            usage: [GrantUsage {
                operations: 0,
                bytes: 0,
            }; TASK_CAPABILITIES],
            object: SEED_OBJECT_WORDS,
        }
    }

    pub const fn expired(&self, now: u64) -> bool {
        deadline_expired(self.start, now, self.budget.tick_limit())
    }

    /// Decide one `svc` from EL0. `imm` is the SVC immediate (ESR ISS[15:0]),
    /// `number` is `x8`, `args` are `x0..x2`, `now` the counter value.
    pub fn syscall(
        &mut self,
        caps: &CapTable<TASK_CAPABILITIES>,
        grants: &[Option<GrantedCapability>],
        imm: u16,
        number: u64,
        args: [u64; 3],
        now: u64,
    ) -> SyscallAction {
        self.syscalls = self.syscalls.saturating_add(1);
        if self.syscalls > self.budget.syscalls {
            return SyscallAction::Terminate(ExecutionStatus::ResourceOverrun);
        }
        if self.expired(now) {
            return SyscallAction::Terminate(ExecutionStatus::Timeout);
        }
        if imm != 0 {
            return SyscallAction::Terminate(ExecutionStatus::BadSyscall(number));
        }
        match number {
            SYS_EXIT => SyscallAction::Terminate(ExecutionStatus::Exited(args[0])),
            SYS_OBJECT_READ => {
                match self.object_access(caps, grants, args[0], Rights::READ, args[1]) {
                    Some(word) => {
                        self.object_reads_ok = self.object_reads_ok.saturating_add(1);
                        SyscallAction::Return(self.object[word])
                    }
                    None => self.deny(),
                }
            }
            SYS_OBJECT_WRITE => {
                match self.object_access(caps, grants, args[0], Rights::WRITE, args[1]) {
                    Some(word) => {
                        self.object[word] = args[2];
                        SyscallAction::Return(0)
                    }
                    None => self.deny(),
                }
            }
            other => SyscallAction::Terminate(ExecutionStatus::BadSyscall(other)),
        }
    }

    fn deny(&mut self) -> SyscallAction {
        self.denials = self.denials.saturating_add(1);
        SyscallAction::Return(SYSCALL_DENIED)
    }

    /// Resolve and charge one 8-byte object access. Returns the object word
    /// index, or `None` for any authority, bounds, or budget failure (in
    /// which case nothing is charged).
    fn object_access(
        &mut self,
        caps: &CapTable<TASK_CAPABILITIES>,
        grants: &[Option<GrantedCapability>],
        raw_handle: u64,
        right: Rights,
        offset: u64,
    ) -> Option<usize> {
        let handle = Handle::from_raw(raw_handle).ok()?;
        let index = caps.lookup(handle, right).ok()? as usize;
        let grant = grants.get(index).copied().flatten()?;
        if grant.resource.kind() != ResourceKind::Object
            || grant.resource.id() != SEED_OBJECT_ID
            || !grant.rights.contains(right)
        {
            return None;
        }
        let end = offset.checked_add(8)?;
        let grant_end = grant
            .bounds
            .byte_offset
            .checked_add(grant.bounds.byte_length)?;
        if offset & 7 != 0
            || offset < grant.bounds.byte_offset
            || end > grant_end
            || end > SEED_OBJECT_BYTES
        {
            return None;
        }
        let usage = self.usage.get_mut(index)?;
        let bytes = usage.bytes.checked_add(8)?;
        if usage.operations >= grant.bounds.max_operations || bytes > grant.bounds.max_bytes {
            return None;
        }
        usage.operations += 1;
        usage.bytes = bytes;
        Some((offset / 8) as usize)
    }

    fn outcome(&self, status: ExecutionStatus, now: u64) -> TaskOutcome {
        TaskOutcome {
            status,
            syscalls: self.syscalls,
            object_reads_ok: self.object_reads_ok,
            denials: self.denials,
            elapsed_ticks: elapsed_since(self.start, now),
        }
    }
}

// ---- Active-task state (EL1, single core) ---------------------------------

struct Active {
    state: RuntimeState,
    caps: *const CapTable<TASK_CAPABILITIES>,
    grants: *const Option<GrantedCapability>,
    grant_count: usize,
    status: ExecutionStatus,
}

static TASK_ACTIVE: AtomicBool = AtomicBool::new(false);
static mut ACTIVE: Option<Active> = None;

/// True while a loaded task owns EL0. Exception dispatchers use this to route
/// EL0 exceptions here instead of the M3 demo paths.
pub fn is_active() -> bool {
    TASK_ACTIVE.load(Ordering::Acquire)
}

/// # Safety
/// EL1 only, single core; no other live reference to `ACTIVE`.
unsafe fn active() -> Option<&'static mut Active> {
    unsafe { (*core::ptr::addr_of_mut!(ACTIVE)).as_mut() }
}

fn terminate_frame(elr: &mut u64, spsr: &mut u64) {
    *elr = task_resume_address();
    *spsr = SPSR_EL1H_MASKED;
}

fn record_termination(active: &mut Active, status: ExecutionStatus) {
    if active.status == ExecutionStatus::NotRun {
        active.status = status;
    }
}

/// Lower-EL synchronous exception while a task is active. Called from
/// `user::aienos_lower_el_sync_dispatcher`.
///
/// # Safety
/// Called only from the lower-EL synchronous trampoline with a complete frame.
pub unsafe fn dispatch_sync(frame: &mut crate::user::TrapFrame, esr: u64, far: u64) {
    let Some(active) = (unsafe { active() }) else {
        terminate_frame(&mut frame.elr_el1, &mut frame.spsr_el1);
        return;
    };
    let now = counter();
    let ec = (esr >> 26) & 0x3f;
    let action = if ec == 0x15 {
        let caps = unsafe { &*active.caps };
        let grants = unsafe { core::slice::from_raw_parts(active.grants, active.grant_count) };
        active.state.syscall(
            caps,
            grants,
            (esr & 0xffff) as u16,
            frame.x[8],
            [frame.x[0], frame.x[1], frame.x[2]],
            now,
        )
    } else {
        SyscallAction::Terminate(ExecutionStatus::Fault {
            esr,
            far,
            elr: frame.elr_el1,
        })
    };
    match action {
        SyscallAction::Return(value) => frame.x[0] = value,
        SyscallAction::Terminate(status) => {
            record_termination(active, status);
            terminate_frame(&mut frame.elr_el1, &mut frame.spsr_el1);
        }
    }
}

/// Timer tick taken from EL0 while a task is active. Called from the IRQ
/// dispatcher after it acknowledged, re-armed and ended INTID 30.
///
/// # Safety
/// Called only from the IRQ dispatcher with a complete frame.
pub unsafe fn on_timer_tick(frame: &mut crate::thread::TrapFrame) {
    // Only an interrupted EL0 context (SPSR.M[3:0] == EL0t) is terminated.
    if frame.spsr_el1 & 0xf != 0 {
        return;
    }
    let Some(active) = (unsafe { active() }) else {
        return;
    };
    if active.state.expired(counter()) {
        record_termination(active, ExecutionStatus::Timeout);
        terminate_frame(&mut frame.elr_el1, &mut frame.spsr_el1);
    }
}

fn counter() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        crate::timer::TimerRegisters::counter(&crate::timer::Aarch64TimerRegisters)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        0
    }
}

/// Enter EL0 with `task` and return when it ends for any reason. Restores
/// `kernel_root` in TTBR0, disables the timer and masks IRQs before returning.
///
/// # Safety
/// EL1, single core, vectors installed, GIC/timer initialised; `task.root`
/// must be a complete private translation tree built by the loader.
pub unsafe fn run(task: TaskContext<'_>, kernel_root: usize) -> TaskOutcome {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe { run_inner(task, kernel_root) }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = (task, kernel_root);
        TaskOutcome {
            status: ExecutionStatus::NotRun,
            syscalls: 0,
            object_reads_ok: 0,
            denials: 0,
            elapsed_ticks: 0,
        }
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn run_inner(task: TaskContext<'_>, kernel_root: usize) -> TaskOutcome {
    use crate::timer::{Aarch64TimerRegisters, TimerRegisters};

    let grant_count = task.grants.len().min(TASK_CAPABILITIES);
    let mut timer = Aarch64TimerRegisters;
    let hz = timer.frequency();
    let interval = if hz >= 100 { hz / 100 } else { 625_000 };
    let start = timer.counter();
    unsafe {
        *core::ptr::addr_of_mut!(ACTIVE) = Some(Active {
            state: RuntimeState::new(task.budget, start),
            caps: task.capabilities as *const _,
            grants: task.grants.as_ptr(),
            grant_count,
            status: ExecutionStatus::NotRun,
        });
    }
    TASK_ACTIVE.store(true, Ordering::Release);

    unsafe { set_ttbr0(task.root | (u64::from(TASK_ASID) << 48)) };
    timer.set_compare(start.wrapping_add(interval));
    timer.enable_timer(true);
    let args = task.args;
    unsafe { aienos_task_enter(task.entry_pc, task.stack_pointer, args.as_ptr()) };
    // Back at EL1h with DAIF masked (SPSR 0x3c5 on every termination).
    unsafe { core::arch::asm!("msr daifset, #2", "isb", options(nostack)) };
    timer.enable_timer(false);
    unsafe { set_ttbr0(kernel_root as u64) };
    let now = timer.counter();

    TASK_ACTIVE.store(false, Ordering::Release);
    let active = unsafe { (*core::ptr::addr_of_mut!(ACTIVE)).take() };
    match active {
        Some(active) => active.state.outcome(active.status, now),
        None => TaskOutcome {
            status: ExecutionStatus::NotRun,
            syscalls: 0,
            object_reads_ok: 0,
            denials: 0,
            elapsed_ticks: 0,
        },
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn set_ttbr0(value: u64) {
    unsafe {
        core::arch::asm!(
            "dsb ish",
            "msr ttbr0_el1, {0}",
            "isb",
            "tlbi vmalle1",
            "dsb ish",
            "isb",
            in(reg) value,
            options(nostack)
        );
    }
}

fn task_resume_address() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        core::ptr::addr_of!(aienos_task_resume) as u64
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        0
    }
}

// Entry saves the callee-saved GPRs, d8-d15 and FPCR on SP_EL1, then enters
// EL0 with only x0-x3 carrying values: every other GPR, every SIMD/FP
// register, FPCR/FPSR and TPIDR_EL0 are zeroed so no kernel state leaks.
// Every termination returns to `aienos_task_resume` at EL1h with SP_EL1 back
// where entry left it, restoring the saved state.
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(
    ".global aienos_task_enter",
    ".global aienos_task_resume",
    // x0 = entry, x1 = sp_el0, x2 = pointer to [u64; 4] initial x0..x3
    "aienos_task_enter:",
    "sub sp, sp, #176",
    "stp x19, x20, [sp, #0]",
    "stp x21, x22, [sp, #16]",
    "stp x23, x24, [sp, #32]",
    "stp x25, x26, [sp, #48]",
    "stp x27, x28, [sp, #64]",
    "stp x29, x30, [sp, #80]",
    "stp d8, d9, [sp, #96]",
    "stp d10, d11, [sp, #112]",
    "stp d12, d13, [sp, #128]",
    "stp d14, d15, [sp, #144]",
    "mrs x9, fpcr",
    "str x9, [sp, #160]",
    "msr sp_el0, x1",
    "msr elr_el1, x0",
    "msr spsr_el1, xzr",
    "msr tpidr_el0, xzr",
    "msr fpcr, xzr",
    "msr fpsr, xzr",
    "mov x9, x2",
    "ldp x0, x1, [x9, #0]",
    "ldp x2, x3, [x9, #16]",
    "mov x4, xzr",
    "mov x5, xzr",
    "mov x6, xzr",
    "mov x7, xzr",
    "mov x8, xzr",
    "mov x9, xzr",
    "mov x10, xzr",
    "mov x11, xzr",
    "mov x12, xzr",
    "mov x13, xzr",
    "mov x14, xzr",
    "mov x15, xzr",
    "mov x16, xzr",
    "mov x17, xzr",
    "mov x18, xzr",
    "mov x19, xzr",
    "mov x20, xzr",
    "mov x21, xzr",
    "mov x22, xzr",
    "mov x23, xzr",
    "mov x24, xzr",
    "mov x25, xzr",
    "mov x26, xzr",
    "mov x27, xzr",
    "mov x28, xzr",
    "mov x29, xzr",
    "mov x30, xzr",
    ".irp reg, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31",
    "movi v\\reg\\().2d, #0",
    ".endr",
    "eret",
    "aienos_task_resume:",
    "ldr x9, [sp, #160]",
    "msr fpcr, x9",
    "msr fpsr, xzr",
    "ldp d8, d9, [sp, #96]",
    "ldp d10, d11, [sp, #112]",
    "ldp d12, d13, [sp, #128]",
    "ldp d14, d15, [sp, #144]",
    "ldp x19, x20, [sp, #0]",
    "ldp x21, x22, [sp, #16]",
    "ldp x23, x24, [sp, #32]",
    "ldp x25, x26, [sp, #48]",
    "ldp x27, x28, [sp, #64]",
    "ldp x29, x30, [sp, #80]",
    "add sp, sp, #176",
    "ret",
);

#[cfg(target_arch = "aarch64")]
extern "C" {
    fn aienos_task_enter(entry: u64, stack: u64, args: *const u64);
    static aienos_task_resume: u8;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::ResourceId;
    use aienos_artifact::capability::CapabilityRequest;

    const BUDGET: TaskBudget = TaskBudget {
        cpu_ticks: 1_000,
        elapsed_ticks: 2_000,
        syscalls: 8,
    };

    fn grant(rights: Rights, offset: u64, length: u64, ops: u32, bytes: u64) -> GrantedCapability {
        GrantedCapability {
            resource: ResourceId::new(ResourceKind::Object, SEED_OBJECT_ID),
            rights,
            bounds: CapabilityRequest {
                resource_kind: 3,
                resource_id: SEED_OBJECT_ID,
                rights: u32::from(rights.bits()),
                bounds_kind: 1,
                max_operations: ops,
                max_bytes: bytes,
                byte_offset: offset,
                byte_length: length,
            },
        }
    }

    /// One READ grant installed at grant index 0; returns its raw handle.
    fn setup(
        g: GrantedCapability,
    ) -> (
        CapTable<TASK_CAPABILITIES>,
        [Option<GrantedCapability>; 1],
        u64,
    ) {
        let mut caps = CapTable::new(0x5441_534b);
        let handle = caps.insert(0, g.rights).unwrap();
        (caps, [Some(g)], handle.to_raw())
    }

    fn read(
        state: &mut RuntimeState,
        caps: &CapTable<TASK_CAPABILITIES>,
        grants: &[Option<GrantedCapability>],
        handle: u64,
        offset: u64,
    ) -> SyscallAction {
        state.syscall(caps, grants, 0, SYS_OBJECT_READ, [handle, offset, 0], 10)
    }

    #[test]
    fn granted_read_returns_object_word_and_charges_budget() {
        let (caps, grants, h) = setup(grant(Rights::READ, 0, 32, 4, 32));
        let mut s = RuntimeState::new(BUDGET, 0);
        assert_eq!(
            read(&mut s, &caps, &grants, h, 8),
            SyscallAction::Return(SEED_OBJECT_WORDS[1])
        );
        assert_eq!(s.object_reads_ok, 1);
        assert_eq!(
            s.usage[0],
            GrantUsage {
                operations: 1,
                bytes: 8
            }
        );
        assert_eq!(s.denials, 0);
    }

    #[test]
    fn read_outside_grant_range_or_object_or_unaligned_is_denied() {
        let (caps, grants, h) = setup(grant(Rights::READ, 8, 8, 8, 64));
        let mut s = RuntimeState::new(BUDGET, 0);
        for offset in [0, 16, 12, 32, u64::MAX - 3] {
            assert_eq!(
                read(&mut s, &caps, &grants, h, offset),
                SyscallAction::Return(SYSCALL_DENIED),
                "offset {offset}"
            );
        }
        assert_eq!(s.denials, 5);
        assert_eq!(s.usage[0], GrantUsage::default());
        // Range past the 32-byte object is denied even if the grant covers it.
        let (caps, grants, h) = setup(grant(Rights::READ, 0, 64, 8, 64));
        let mut s = RuntimeState::new(BUDGET, 0);
        assert_eq!(
            read(&mut s, &caps, &grants, h, 32),
            SyscallAction::Return(SYSCALL_DENIED)
        );
    }

    #[test]
    fn read_past_operation_budget_is_denied() {
        let (caps, grants, h) = setup(grant(Rights::READ, 0, 32, 2, 32));
        let mut s = RuntimeState::new(BUDGET, 0);
        assert!(matches!(
            read(&mut s, &caps, &grants, h, 0),
            SyscallAction::Return(v) if v != SYSCALL_DENIED
        ));
        assert!(matches!(
            read(&mut s, &caps, &grants, h, 0),
            SyscallAction::Return(v) if v != SYSCALL_DENIED
        ));
        assert_eq!(
            read(&mut s, &caps, &grants, h, 0),
            SyscallAction::Return(SYSCALL_DENIED)
        );
        assert_eq!(s.object_reads_ok, 2);
    }

    #[test]
    fn read_past_byte_budget_is_denied() {
        let (caps, grants, h) = setup(grant(Rights::READ, 0, 32, 8, 12));
        let mut s = RuntimeState::new(BUDGET, 0);
        assert_eq!(
            read(&mut s, &caps, &grants, h, 0),
            SyscallAction::Return(SEED_OBJECT_WORDS[0])
        );
        assert_eq!(
            read(&mut s, &caps, &grants, h, 8),
            SyscallAction::Return(SYSCALL_DENIED)
        );
        assert_eq!(s.usage[0].bytes, 8);
    }

    #[test]
    fn write_without_write_right_is_denied_and_object_unchanged() {
        let (caps, grants, h) = setup(grant(Rights::READ, 0, 32, 8, 32));
        let mut s = RuntimeState::new(BUDGET, 0);
        assert_eq!(
            s.syscall(&caps, &grants, 0, SYS_OBJECT_WRITE, [h, 0, 0xbad], 10),
            SyscallAction::Return(SYSCALL_DENIED)
        );
        assert_eq!(s.denials, 1);
        assert_eq!(s.object, SEED_OBJECT_WORDS);
    }

    #[test]
    fn write_with_write_right_updates_kernel_copy() {
        let (caps, grants, h) = setup(grant(Rights::READ | Rights::WRITE, 0, 32, 8, 32));
        let mut s = RuntimeState::new(BUDGET, 0);
        assert_eq!(
            s.syscall(&caps, &grants, 0, SYS_OBJECT_WRITE, [h, 24, 0x77], 10),
            SyscallAction::Return(0)
        );
        assert_eq!(s.object[3], 0x77);
        assert_eq!(
            read(&mut s, &caps, &grants, h, 24),
            SyscallAction::Return(0x77)
        );
    }

    #[test]
    fn forged_stale_and_unbacked_handles_are_denied() {
        let (mut caps, grants, h) = setup(grant(Rights::READ, 0, 32, 8, 32));
        let mut s = RuntimeState::new(BUDGET, 0);
        // Generation 0 never parses; wrong generation and wrong index fail lookup.
        for forged in [0, h & 0xffff_ffff, h ^ (1 << 32), h + 1] {
            assert_eq!(
                read(&mut s, &caps, &grants, forged, 0),
                SyscallAction::Return(SYSCALL_DENIED),
                "forged {forged:#x}"
            );
        }
        // A handle whose resource names no grant is denied.
        let orphan = caps.insert(5, Rights::READ).unwrap().to_raw();
        assert_eq!(
            read(&mut s, &caps, &grants, orphan, 0),
            SyscallAction::Return(SYSCALL_DENIED)
        );
        // Revoked (removed) handle is stale.
        caps.remove(Handle::from_raw(h).unwrap()).unwrap();
        assert_eq!(
            read(&mut s, &caps, &grants, h, 0),
            SyscallAction::Return(SYSCALL_DENIED)
        );
        assert_eq!(s.denials, 6);
        assert_eq!(s.object_reads_ok, 0);
    }

    #[test]
    fn non_object_or_other_object_grant_is_denied() {
        let mut g = grant(Rights::READ, 0, 32, 8, 32);
        g.resource = ResourceId::new(ResourceKind::Channel, SEED_OBJECT_ID);
        let (caps, grants, h) = setup(g);
        let mut s = RuntimeState::new(BUDGET, 0);
        assert_eq!(
            read(&mut s, &caps, &grants, h, 0),
            SyscallAction::Return(SYSCALL_DENIED)
        );
        let mut g = grant(Rights::READ, 0, 32, 8, 32);
        g.resource = ResourceId::new(ResourceKind::Object, 99);
        let (caps, grants, h) = setup(g);
        assert_eq!(
            read(&mut s, &caps, &grants, h, 0),
            SyscallAction::Return(SYSCALL_DENIED)
        );
    }

    #[test]
    fn unknown_syscall_and_nonzero_immediate_terminate() {
        let (caps, grants, _) = setup(grant(Rights::READ, 0, 32, 8, 32));
        let mut s = RuntimeState::new(BUDGET, 0);
        assert_eq!(
            s.syscall(&caps, &grants, 0, 99, [0; 3], 10),
            SyscallAction::Terminate(ExecutionStatus::BadSyscall(99))
        );
        assert_eq!(
            s.syscall(&caps, &grants, 1, SYS_EXIT, [0; 3], 10),
            SyscallAction::Terminate(ExecutionStatus::BadSyscall(SYS_EXIT))
        );
        assert_eq!(
            s.syscall(&caps, &grants, 0, SYS_EXIT, [0x5a, 0, 0], 10),
            SyscallAction::Terminate(ExecutionStatus::Exited(0x5a))
        );
    }

    #[test]
    fn syscall_budget_overrun_terminates() {
        let (caps, grants, h) = setup(grant(Rights::READ, 0, 32, 100, 800));
        let budget = TaskBudget {
            syscalls: 3,
            ..BUDGET
        };
        let mut s = RuntimeState::new(budget, 0);
        for _ in 0..3 {
            assert!(matches!(
                read(&mut s, &caps, &grants, h, 0),
                SyscallAction::Return(_)
            ));
        }
        assert_eq!(
            read(&mut s, &caps, &grants, h, 0),
            SyscallAction::Terminate(ExecutionStatus::ResourceOverrun)
        );
    }

    #[test]
    fn syscall_after_deadline_times_out() {
        let (caps, grants, _) = setup(grant(Rights::READ, 0, 32, 8, 32));
        let mut s = RuntimeState::new(BUDGET, 500);
        assert_eq!(
            s.syscall(&caps, &grants, 0, SYS_EXIT, [0; 3], 500 + 1_000),
            SyscallAction::Terminate(ExecutionStatus::Timeout)
        );
    }

    #[test]
    fn deadline_uses_tighter_budget_and_survives_counter_wrap() {
        assert_eq!(BUDGET.tick_limit(), 1_000);
        let s = RuntimeState::new(BUDGET, u64::MAX - 100);
        assert!(!s.expired(u64::MAX - 100));
        assert!(!s.expired(u64::MAX));
        assert!(!s.expired(898)); // 999 ticks after start, across the wrap
        assert!(s.expired(899)); // exactly 1000 ticks
        assert_eq!(elapsed_since(u64::MAX - 1, 1), 3);
        assert!(deadline_expired(0, 5, 5));
        assert!(!deadline_expired(0, 4, 5));
    }
}
