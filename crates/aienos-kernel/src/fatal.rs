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
        writeln!(f, "fault_elr: {:#x}", self.elr)?;
        writeln!(f, "fault_far: {:#x}", self.far)?;
        writeln!(f, "fault_spsr: {:#x}", self.spsr)
    }
}

/// Called for a fault once vectors are installed. Must not return.
pub type FaultHook = fn(&FaultInfo) -> !;

static HOOK: AtomicUsize = AtomicUsize::new(0);

pub fn set_fault_hook(hook: FaultHook) {
    HOOK.store(hook as usize, Ordering::SeqCst);
}

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
    use super::{call_hook, FaultInfo};
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
        "mov x0, #\\slot",
        "b aienos_exception_trampoline",
        ".endr",
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
}
