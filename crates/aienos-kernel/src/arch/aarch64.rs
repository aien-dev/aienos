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

/// Reference MMIO base address for PL011 UART on NVIDIA DGX Spark (Cortex-X925).
pub const SPARK_PL011_UART_BASE: usize = 0x16A0_0000;

/// Reference MMIO base address for PL011 UART on QEMU AArch64 Virt machine.
pub const QEMU_VIRT_PL011_UART_BASE: usize = 0x0900_0000;

/// Standard PL011 UART register offsets.
pub mod pl011_regs {
    pub const UARTDR: usize = 0x00;
    pub const UARTFR: usize = 0x18;
    pub const UARTIBRD: usize = 0x24;
    pub const UARTFBRD: usize = 0x28;
    pub const UARTLCR_H: usize = 0x2C;
    pub const UARTCR: usize = 0x30;
    pub const UARTIMSC: usize = 0x38;

    pub const FR_BUSY: u32 = 1 << 3;
    pub const FR_TXFF: u32 = 1 << 5;
    pub const FR_RXFE: u32 = 1 << 4;
}

/// Early boot UART driver for AArch64 bare-metal console output.
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
        let fr = self.reg(pl011_regs::UARTFR);
        let dr = self.reg(pl011_regs::UARTDR);

        // Wait until transmit FIFO has space (TXFF == 0)
        while (fr.read() & pl011_regs::FR_TXFF) != 0 {
            core::hint::spin_loop();
        }

        dr.write(b as u32);
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

    /// Attempt to read a single byte from UART receive FIFO without blocking.
    /// Returns None if receive FIFO is empty (RXFE == 1).
    pub fn try_read_byte(&self) -> Option<u8> {
        let fr = self.reg(pl011_regs::UARTFR);
        if (fr.read() & pl011_regs::FR_RXFE) != 0 {
            None
        } else {
            let dr = self.reg(pl011_regs::UARTDR);
            Some((dr.read() & 0xFF) as u8)
        }
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
