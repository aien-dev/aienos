//! Fatal-path capture for early boot: CPU exceptions and panics.
//!
//! After firmware exit the firmware's exception vectors are still installed,
//! and on a fault they typically print to a serial port and hang, leaving no
//! evidence. `install_exception_vectors` replaces them with AIENOS vectors
//! that switch to a dedicated stack, read the syndrome registers, and call a
//! registered hook (which reports the fault and resets). The decoding is pure
//! and host-tested; the vectors and register reads exist only on AArch64.

use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Registers captured when an exception is taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultInfo {
    /// Vector slot 0..=15 (origin * 4 + kind).
    pub vector: u64,
    pub exception_level: u8,
    pub esr: u64,
    pub elr: u64,
    pub far: u64,
    pub spsr: u64,
}

/// Purely decoded ESR_EL1/ESR_EL2 fields used by reports and host tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EsrInfo {
    pub exception_class: u8,
    pub iss: u32,
    pub abort: Option<AbortSyndrome>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbortSyndrome {
    pub instruction: bool,
    pub fault_status: u8,
    pub stage1_page_table_walk: bool,
    pub cache_maintenance: bool,
    pub external_abort: bool,
    pub not_valid: bool,
    pub write: bool,
    /// Load/store detail, present only for data aborts with ISV (ISS bit 24) set.
    pub access: Option<AccessSyndrome>,
}

/// SRT/SAS/SSE from a data-abort ISS; architecturally valid only when ISV = 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessSyndrome {
    pub register: u8,
    pub access_size: u8,
    pub sign_extend: bool,
}

/// Decode the common ESR layout without reading any system registers.
pub const fn decode_esr(esr: u64) -> EsrInfo {
    let ec = ((esr >> 26) & 0x3f) as u8;
    let iss = (esr & 0x1ff_ffff) as u32;
    let instruction = ec == 0x20 || ec == 0x21;
    let data = ec == 0x24 || ec == 0x25;
    let abort = if instruction || data {
        Some(AbortSyndrome {
            instruction,
            fault_status: (iss & 0x3f) as u8,
            stage1_page_table_walk: iss & (1 << 7) != 0,
            cache_maintenance: iss & (1 << 8) != 0,
            external_abort: iss & (1 << 9) != 0,
            not_valid: iss & (1 << 10) != 0,
            write: !instruction && iss & (1 << 6) != 0,
            access: if data && iss & (1 << 24) != 0 {
                Some(AccessSyndrome {
                    register: ((iss >> 16) & 0x1f) as u8,
                    access_size: ((iss >> 22) & 0x3) as u8,
                    sign_extend: iss & (1 << 21) != 0,
                })
            } else {
                None
            },
        })
    } else {
        None
    };
    EsrInfo {
        exception_class: ec,
        iss,
        abort,
    }
}

impl FaultInfo {
    pub fn kind(&self) -> &'static str {
        ["sync", "irq", "fiq", "serror"][(self.vector % 4) as usize]
    }

    pub fn origin(&self) -> &'static str {
        [
            "current_el_sp0",
            "current_el_spx",
            "lower_el_a64",
            "lower_el_a32",
        ][((self.vector / 4) % 4) as usize]
    }

    /// Exception class, ESR bits 31:26.
    pub fn exception_class(&self) -> u8 {
        ((self.esr >> 26) & 0x3f) as u8
    }
}

/// Human-readable name for an ESR exception class.
pub fn describe_exception_class(ec: u8) -> &'static str {
    match ec {
        0x00 => "unknown reason",
        0x01 => "trapped WFI/WFE",
        0x0e => "illegal execution state",
        0x15 => "SVC (AArch64)",
        0x16 => "HVC (AArch64)",
        0x17 => "SMC (AArch64)",
        0x18 => "trapped system register access",
        0x20 => "instruction abort from lower EL",
        0x21 => "instruction abort at current EL",
        0x22 => "PC alignment fault",
        0x24 => "data abort from lower EL",
        0x25 => "data abort at current EL",
        0x26 => "SP alignment fault",
        0x2f => "SError",
        0x3c => "BRK instruction",
        _ => "other",
    }
}

impl fmt::Display for FaultInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "fault_kind: {} from {}", self.kind(), self.origin())?;
        writeln!(f, "fault_el: EL{}", self.exception_level)?;
        writeln!(
            f,
            "fault_class: {:#04x} ({})",
            self.exception_class(),
            describe_exception_class(self.exception_class())
        )?;
        writeln!(f, "fault_esr: {:#x}", self.esr)?;
        let decoded = decode_esr(self.esr);
        writeln!(f, "fault_iss: {:#x}", decoded.iss)?;
        if let Some(abort) = decoded.abort {
            writeln!(
                f,
                "fault_type: {}",
                if abort.instruction {
                    "instruction_abort"
                } else {
                    "data_abort"
                }
            )?;
            writeln!(f, "fault_status: {:#x}", abort.fault_status)?;
            if !abort.instruction {
                writeln!(f, "fault_write: {}", if abort.write { "yes" } else { "no" })?;
            }
        }
        writeln!(f, "fault_elr: {:#x}", self.elr)?;
        writeln!(f, "fault_far: {:#x}", self.far)?;
        writeln!(f, "fault_spsr: {:#x}", self.spsr)
    }
}

/// Called for a fault once vectors are installed. Must not return.
pub type FaultHook = fn(&FaultInfo) -> !;

#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
static HOOK: AtomicUsize = AtomicUsize::new(0);
static IRQ_HOOK: AtomicUsize = AtomicUsize::new(0);

pub fn set_irq_hook(hook: extern "C" fn()) {
    IRQ_HOOK.store(hook as usize, Ordering::SeqCst);
}
#[cfg(target_arch = "aarch64")]
fn call_irq_hook() {
    let raw = IRQ_HOOK.load(Ordering::SeqCst);
    if raw != 0 {
        let hook: extern "C" fn() = unsafe { core::mem::transmute(raw) };
        hook();
    }
}

pub fn set_fault_hook(hook: FaultHook) {
    HOOK.store(hook as usize, Ordering::SeqCst);
}

#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
fn call_hook(info: &FaultInfo) -> ! {
    let raw = HOOK.load(Ordering::SeqCst);
    if raw != 0 {
        // SAFETY: only `set_fault_hook` stores into HOOK, always a FaultHook.
        let hook: FaultHook = unsafe { core::mem::transmute::<usize, FaultHook>(raw) };
        hook(info);
    }
    crate::arch::aarch64::halt()
}

#[cfg(target_arch = "aarch64")]
mod vectors {
    use super::{call_hook, call_irq_hook, FaultInfo};
    use crate::arch::aarch64::current_el;

    const STACK_BYTES: usize = 16 * 1024;

    #[repr(C, align(16))]
    struct ExceptionStack([u8; STACK_BYTES]);

    static mut EXCEPTION_STACK: ExceptionStack = ExceptionStack([0; STACK_BYTES]);

    macro_rules! read_sysreg {
        ($name:literal) => {{
            let v: u64;
            // SAFETY: reading a syndrome register of the current EL has no side effects.
            unsafe {
                core::arch::asm!(concat!("mrs {0}, ", $name), out(reg) v, options(nomem, nostack, preserves_flags));
            }
            v
        }};
    }

    /// Entered from the vector table on the exception stack.
    #[no_mangle]
    extern "C" fn aienos_exception_handler(vector: u64) -> ! {
        let el = current_el();
        let info = if el == 2 {
            FaultInfo {
                vector,
                exception_level: el,
                esr: read_sysreg!("esr_el2"),
                elr: read_sysreg!("elr_el2"),
                far: read_sysreg!("far_el2"),
                spsr: read_sysreg!("spsr_el2"),
            }
        } else {
            FaultInfo {
                vector,
                exception_level: el,
                esr: read_sysreg!("esr_el1"),
                elr: read_sysreg!("elr_el1"),
                far: read_sysreg!("far_el1"),
                spsr: read_sysreg!("spsr_el1"),
            }
        };
        call_hook(&info)
    }

    // Sixteen 128-byte entries on a 2 KiB boundary. Each loads its slot number
    // and jumps to a common trampoline that moves onto a dedicated stack, so a
    // fault caused by a bad stack still reaches the handler.
    core::arch::global_asm!(
        ".balign 2048",
        ".global aienos_exception_vectors",
        "aienos_exception_vectors:",
        ".irp slot, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15",
        ".balign 128",
        ".if \\slot == 5",
        "b aienos_irq_trampoline",
        ".else",
        "mov x0, #\\slot",
        "b aienos_exception_trampoline",
        ".endif",
        ".endr",
        "aienos_irq_trampoline:",
        "sub sp, sp, #256",
        "stp x0, x1, [sp, #0]",
        "stp x2, x3, [sp, #16]",
        "stp x4, x5, [sp, #32]",
        "stp x6, x7, [sp, #48]",
        "stp x8, x9, [sp, #64]",
        "stp x10, x11, [sp, #80]",
        "stp x12, x13, [sp, #96]",
        "stp x14, x15, [sp, #112]",
        "stp x16, x17, [sp, #128]",
        "stp x18, x30, [sp, #144]",
        "bl {irq_handler}",
        "ldp x0, x1, [sp, #0]",
        "ldp x2, x3, [sp, #16]",
        "ldp x4, x5, [sp, #32]",
        "ldp x6, x7, [sp, #48]",
        "ldp x8, x9, [sp, #64]",
        "ldp x10, x11, [sp, #80]",
        "ldp x12, x13, [sp, #96]",
        "ldp x14, x15, [sp, #112]",
        "ldp x16, x17, [sp, #128]",
        "ldp x18, x30, [sp, #144]",
        "add sp, sp, #256",
        "eret",
        "aienos_exception_trampoline:",
        "adrp x1, {stack}",
        "add x1, x1, :lo12:{stack}",
        "add x1, x1, #{stack_bytes_hi}, lsl #12",
        "mov sp, x1",
        "bl {handler}",
        "1: wfi",
        "b 1b",
        stack = sym EXCEPTION_STACK,
        stack_bytes_hi = const STACK_BYTES >> 12,
        handler = sym aienos_exception_handler,
        irq_handler = sym call_irq_hook,
    );

    extern "C" {
        static aienos_exception_vectors: u8;
    }

    pub fn install() {
        let base = core::ptr::addr_of!(aienos_exception_vectors) as u64;
        // SAFETY: VBAR of the current EL points at a valid, 2 KiB aligned table.
        unsafe {
            if current_el() == 2 {
                core::arch::asm!("msr vbar_el2, {0}", "isb", in(reg) base, options(nostack));
            } else {
                core::arch::asm!("msr vbar_el1, {0}", "isb", in(reg) base, options(nostack));
            }
        }
    }
}

/// Replace the firmware's exception vectors with AIENOS ones. Call only after
/// firmware boot services have exited; firmware may rely on its own vectors
/// until then.
pub fn install_exception_vectors() {
    #[cfg(target_arch = "aarch64")]
    vectors::install();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;

    #[test]
    fn decodes_vector_slot_and_exception_class() {
        let data_abort = FaultInfo {
            vector: 4,
            exception_level: 2,
            esr: 0x9600_0045, // EC 0x25, data abort at current EL
            elr: 0x8000_1000,
            far: 0xdead_0000,
            spsr: 0x3c9,
        };
        assert_eq!(data_abort.kind(), "sync");
        assert_eq!(data_abort.origin(), "current_el_spx");
        assert_eq!(data_abort.exception_class(), 0x25);
        let text = data_abort.to_string();
        assert!(
            text.contains("fault_class: 0x25 (data abort at current EL)"),
            "{text}"
        );
        assert!(text.contains("fault_far: 0xdead0000"), "{text}");

        let serror = FaultInfo {
            vector: 7,
            esr: 0xbe00_0000,
            ..data_abort
        };
        assert_eq!(serror.kind(), "serror");
        assert_eq!(describe_exception_class(serror.exception_class()), "SError");
    }

    #[test]
    fn decodes_abort_iss_fields_without_register_access() {
        let decoded = decode_esr(0x9600_0045);
        assert_eq!(decoded.exception_class, 0x25);
        assert_eq!(decoded.iss, 0x45);
        assert_eq!(decoded.abort.unwrap().fault_status, 5);
        assert!(decoded.abort.unwrap().write);

        let instruction = decode_esr((0x21u64 << 26) | 0x15);
        assert!(instruction.abort.unwrap().instruction);
        assert!(!instruction.abort.unwrap().write);
        assert_eq!(decode_esr(0).abort, None);
    }

    #[test]
    fn access_syndrome_only_when_isv_set() {
        // Data abort, same EL, ISV=0: SRT/SAS/SSE bits are not meaningful.
        let no_isv = decode_esr((0x25u64 << 26) | (7 << 16) | 0x04);
        assert_eq!(no_isv.abort.unwrap().access, None);
        // ISV=1, SAS=0b11 (64-bit), SSE=1, SRT=x7, WnR=0, DFSC=0x07.
        let isv =
            decode_esr((0x25u64 << 26) | (1 << 24) | (0b11 << 22) | (1 << 21) | (7 << 16) | 0x07);
        let access = isv.abort.unwrap().access.unwrap();
        assert_eq!(
            (access.register, access.access_size, access.sign_extend),
            (7, 3, true)
        );
        assert!(!isv.abort.unwrap().write);
        // Instruction aborts never carry an access syndrome, even with bit 24 set.
        let inst = decode_esr((0x21u64 << 26) | (1 << 24) | 0x0f);
        assert_eq!(inst.abort.unwrap().access, None);
        // Non-abort classes (e.g. SVC, EC 0x15) decode no abort detail.
        assert_eq!(decode_esr(0x15u64 << 26).abort, None);
    }
}
