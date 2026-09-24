//! Early serial console chosen from the firmware's ACPI SPCR table.
//!
//! The console never depends on accelerator discovery: the firmware says where
//! the serial port is, and AIENOS drives it if it knows the register model.
//! Every transmit is bounded, so an absent or unclocked UART cannot hang boot.

use crate::acpi::UartKind;
use crate::arch::aarch64::{EarlyUart, MmioReg, UART_TX_SPIN_LIMIT};
use core::cell::Cell;

/// ARM PL011 / SBSA generic UART register offsets.
pub mod pl011_regs {
    pub const DATA: usize = 0x00;
    pub const FLAGS: usize = 0x18;
    pub const TX_FULL: u32 = 1 << 5;
}

/// PL011 transmitter with the same bounded behaviour as `EarlyUart`.
pub struct Pl011Uart {
    base: usize,
    dead: Cell<bool>,
}

impl Pl011Uart {
    pub const fn new(base: usize) -> Self {
        Self {
            base,
            dead: Cell::new(false),
        }
    }

    pub fn is_dead(&self) -> bool {
        self.dead.get()
    }

    pub fn write_byte(&self, b: u8) {
        if self.dead.get() {
            return;
        }
        let flags = MmioReg::<u32>::new(self.base + pl011_regs::FLAGS);
        let mut polls = 0u32;
        while flags.read() & pl011_regs::TX_FULL != 0 {
            polls += 1;
            if polls >= UART_TX_SPIN_LIMIT {
                self.dead.set(true);
                return;
            }
            core::hint::spin_loop();
        }
        MmioReg::<u32>::new(self.base + pl011_regs::DATA).write(u32::from(b));
    }
}

/// The serial console found through SPCR.
pub enum EarlyConsole {
    Ns16550(EarlyUart),
    Pl011(Pl011Uart),
}

impl EarlyConsole {
    /// `None` when SPCR described no console this driver set can use.
    pub fn from_kind(kind: UartKind) -> Option<Self> {
        match kind {
            UartKind::Ns16550Mmio32(base) => Some(Self::Ns16550(EarlyUart::new(base as usize))),
            UartKind::Pl011(base) => Some(Self::Pl011(Pl011Uart::new(base as usize))),
            UartKind::Unsupported => None,
        }
    }

    pub fn write_str(&self, s: &str) {
        for b in s.bytes() {
            if b == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(b);
        }
    }

    fn write_byte(&self, b: u8) {
        match self {
            Self::Ns16550(u) => u.write_byte(b),
            Self::Pl011(u) => u.write_byte(b),
        }
    }

    pub fn is_dead(&self) -> bool {
        match self {
            Self::Ns16550(u) => u.is_dead(),
            Self::Pl011(u) => u.is_dead(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pl011_writes_when_ready_and_gives_up_when_always_full() {
        let mut regs = [0u32; 8]; // FLAGS (index 6) clear: ready
        let console = EarlyConsole::from_kind(UartKind::Pl011(regs.as_mut_ptr() as u64)).unwrap();
        console.write_str("A");
        assert_eq!(regs[0], u32::from(b'A'));
        assert!(!console.is_dead());

        let mut full = [0u32; 8];
        full[pl011_regs::FLAGS / 4] = pl011_regs::TX_FULL;
        let stuck = EarlyConsole::from_kind(UartKind::Pl011(full.as_mut_ptr() as u64)).unwrap();
        stuck.write_str("AIENOS\n");
        assert!(stuck.is_dead());
        assert_eq!(full[0], 0);
    }

    #[test]
    fn unsupported_spcr_gives_no_console() {
        assert!(EarlyConsole::from_kind(UartKind::Unsupported).is_none());
    }
}
