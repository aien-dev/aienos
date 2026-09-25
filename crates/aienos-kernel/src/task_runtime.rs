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

use crate::admission::GrantedCapability;
use crate::caps::CapTable;

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

/// ASID used for loaded artifact tasks (M3 demos use 1).
pub const TASK_ASID: u16 = 2;

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

/// Enter EL0 with `task` and return when it ends for any reason. Restores
/// `kernel_root` in TTBR0, disables the timer and masks IRQs before returning.
///
/// # Safety
/// EL1, single core, vectors installed, GIC/timer initialised; `task.root`
/// must be a complete private translation tree built by the loader.
pub unsafe fn run(task: TaskContext<'_>, kernel_root: usize) -> TaskOutcome {
    let _ = (task, kernel_root);
    TaskOutcome {
        status: ExecutionStatus::NotRun,
        syscalls: 0,
        object_reads_ok: 0,
        denials: 0,
        elapsed_ticks: 0,
    }
}
