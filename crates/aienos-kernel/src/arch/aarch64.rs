//! AArch64 bare-metal architecture primitives, MMIO, and UART for AIENOS.

use core::marker::PhantomData;
use core::ptr::{read_volatile, write_volatile};

/// Memory-Mapped I/O Register abstraction for safe volatile access.
#[repr(transparent)]
pub struct MmioReg<T> {
    addr: usize,
    _marker: PhantomData<T>,
}

impl<T: Copy> MmioReg<T> {
    /// Create a new MMIO register accessor at the given physical/virtual address.
    pub const fn new(addr: usize) -> Self {
        Self {
            addr,
            _marker: PhantomData,
        }
    }

    /// Read volatile from MMIO register.
    pub fn read(&self) -> T {
        unsafe { read_volatile(self.addr as *const T) }
    }

    /// Write volatile to MMIO register.
    pub fn write(&self, value: T) {
        unsafe { write_volatile(self.addr as *mut T, value) }
    }
}

/// AArch64 Exception Level query.
/// Returns 0 for EL0, 1 for EL1, 2 for EL2, 3 for EL3.
#[inline(always)]
pub fn current_el() -> u8 {
    #[cfg(target_arch = "aarch64")]
    {
        let el: u64;
        unsafe {
            core::arch::asm!(
                "mrs {0}, CurrentEL",
                out(reg) el,
                options(nomem, nostack)
            );
        }
        ((el >> 2) & 0x03) as u8
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        1 // Default mock EL1 for non-aarch64 hosts
    }
}

/// Data Memory Barrier (DMB).
#[inline(always)]
pub fn dmb() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("dmb sy", options(nostack));
    }
}

/// Data Synchronization Barrier (DSB).
#[inline(always)]
pub fn dsb() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("dsb sy", options(nostack));
    }
}

/// Instruction Synchronization Barrier (ISB).
#[inline(always)]
pub fn isb() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("isb", options(nostack));
    }
}

/// Disable interrupts (set DAIF flags).
#[inline(always)]
pub fn disable_interrupts() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("msr daifset, #2", options(nomem, nostack));
    }
}

/// Enable interrupts (clear DAIF flags).
#[inline(always)]
pub fn enable_interrupts() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("msr daifclr, #2", options(nomem, nostack));
    }
}

/// Check if interrupts are enabled (I bit in DAIF).
#[inline(always)]
pub fn are_interrupts_enabled() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        let daif: u64;
        unsafe {
            core::arch::asm!("mrs {0}, daif", out(reg) daif, options(nomem, nostack));
        }
        (daif & (1 << 7)) == 0
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        true
    }
}

/// Wait For Interrupt (WFI) instruction - places core into low-power sleep until interrupt.
#[inline(always)]
pub fn wfi() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("wfi", options(nomem, nostack));
    }
    #[cfg(not(target_arch = "aarch64"))]
    core::hint::spin_loop();
}

/// Wait For Event (WFE) instruction.
#[inline(always)]
pub fn wfe() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("wfe", options(nomem, nostack));
    }
    #[cfg(not(target_arch = "aarch64"))]
    core::hint::spin_loop();
}

/// Send Event (SEV) instruction.
#[inline(always)]
pub fn sev() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("sev", options(nomem, nostack));
    }
}

/// Deterministic bare-metal halt loop: disables interrupts and sleeps in WFI.
pub fn halt() -> ! {
    disable_interrupts();
    loop {
        wfi();
    }
}

/// Serial MMIO base observed in the DGX Spark host kernel command line.
/// The host uses earlycon=uart,mmio32,0x16A00000, the 8250 register layout.
pub const SPARK_16550_UART_BASE: usize = 0x16A0_0000;

/// 8250 register indices with the observed 32-bit register stride.
pub mod uart16550_regs {
    pub const DATA: usize = 0;
    pub const LINE_STATUS: usize = 5 * 4;
    pub const DATA_READY: u32 = 1;
    pub const TX_HOLDING_EMPTY: u32 = 1 << 5;
}

/// Early 8250-compatible UART with 32-bit MMIO registers.
pub struct EarlyUart {
    base_addr: usize,
}

impl EarlyUart {
    /// Create a new EarlyUart driver instance at the specified MMIO base address.
    pub const fn new(base_addr: usize) -> Self {
        Self { base_addr }
    }

    /// Read raw register.
    fn reg(&self, offset: usize) -> MmioReg<u32> {
        MmioReg::new(self.base_addr + offset)
    }

    /// Send a single byte through UART transmit FIFO.
    pub fn write_byte(&self, b: u8) {
        let status = self.reg(uart16550_regs::LINE_STATUS);
        let data = self.reg(uart16550_regs::DATA);

        while (status.read() & uart16550_regs::TX_HOLDING_EMPTY) == 0 {
            core::hint::spin_loop();
        }
        data.write(b as u32);
    }

    /// Transmit a UTF-8 string through UART.
    pub fn write_str(&self, s: &str) {
        for b in s.bytes() {
            if b == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(b);
        }
    }

    /// Write an unsigned decimal number without heap allocation.
    pub fn write_u64(&self, mut value: u64) {
        let mut digits = [0u8; 20];
        let mut start = digits.len();
        loop {
            start -= 1;
            digits[start] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        for digit in &digits[start..] {
            self.write_byte(*digit);
        }
    }

    /// Attempt to read a single byte from UART receive FIFO without blocking.
    /// Returns None if receive FIFO is empty (RXFE == 1).
    pub fn try_read_byte(&self) -> Option<u8> {
        let status = self.reg(uart16550_regs::LINE_STATUS);
        if (status.read() & uart16550_regs::DATA_READY) == 0 {
            return None;
        }
        Some((self.reg(uart16550_regs::DATA).read() & 0xFF) as u8)
    }

    /// Read a single byte from UART, blocking until data arrives.
    pub fn read_byte(&self) -> u8 {
        loop {
            if let Some(b) = self.try_read_byte() {
                return b;
            }
            core::hint::spin_loop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spark_uart_uses_32_bit_16550_register_stride() {
        let mut registers = [0u32; 8];
        registers[5] = uart16550_regs::TX_HOLDING_EMPTY;
        let uart = EarlyUart::new(registers.as_mut_ptr() as usize);
        uart.write_byte(b'A');
        assert_eq!(registers[0], b'A' as u32);
        assert_eq!(uart.try_read_byte(), None);
        MmioReg::new(registers.as_mut_ptr() as usize + uart16550_regs::LINE_STATUS)
            .write(uart16550_regs::TX_HOLDING_EMPTY | uart16550_regs::DATA_READY);
        assert_eq!(uart.try_read_byte(), Some(b'A'));
    }
}
