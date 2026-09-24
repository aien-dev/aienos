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

/// Read the architectural virtual counter. Its frequency is reported by `counter_frequency_hz`.
#[inline(always)]
pub fn counter_ticks() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        let ticks: u64;
        unsafe {
            core::arch::asm!(
                "isb",
                "mrs {ticks}, cntvct_el0",
                ticks = out(reg) ticks,
                options(nomem, nostack, preserves_flags)
            );
        }
        ticks
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        0
    }
}

/// Main ID register of the executing core. Bits 15:4 are the part number
/// (0xd87 Cortex-A725, 0xd85 Cortex-X925 on the GB10).
#[inline(always)]
pub fn midr_el1() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        let midr: u64;
        unsafe {
            core::arch::asm!("mrs {0}, midr_el1", out(reg) midr, options(nomem, nostack, preserves_flags));
        }
        midr
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        0
    }
}

/// Multiprocessor affinity of the executing core (matches MADT GICC MPIDR).
#[inline(always)]
pub fn mpidr_el1() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        let mpidr: u64;
        unsafe {
            core::arch::asm!("mrs {0}, mpidr_el1", out(reg) mpidr, options(nomem, nostack, preserves_flags));
        }
        mpidr
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        0
    }
}

/// PSCI SYSTEM_RESET (function 0x8400_0009) through the secure monitor: the
/// architected Arm reset path, not a UEFI runtime service. Does not return if
/// the platform implements it; returns if the monitor refused the call.
pub fn psci_system_reset() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("smc #0", inout("x0") 0x8400_0009u64 => _, options(nostack));
    }
}

/// Part number field of a MIDR value.
pub const fn midr_part(midr: u64) -> u16 {
    ((midr >> 4) & 0xfff) as u16
}

/// Read the frequency of the architectural virtual counter.
#[inline(always)]
pub fn counter_frequency_hz() -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        let frequency: u64;
        unsafe {
            core::arch::asm!(
                "mrs {frequency}, cntfrq_el0",
                frequency = out(reg) frequency,
                options(nomem, nostack, preserves_flags)
            );
        }
        frequency
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        0
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

/// Smallest data cache line in bytes, from CTR_EL0.DminLine (log2 of the
/// line size in 4-byte words). Maintenance loops must step by this, never by
/// a guess: `dc` acts on the one line holding the address it is given.
pub fn dcache_line_bytes() -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        let ctr: u64;
        unsafe {
            core::arch::asm!("mrs {0}, ctr_el0", out(reg) ctr, options(nomem, nostack, preserves_flags));
        }
        4 << ((ctr >> 16) & 0xf)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        64
    }
}

/// Clean `[addr, addr + size)` to the point of coherency so a DMA master
/// sees what the CPU wrote. No-op on hosts.
pub fn clean_dcache_range(addr: usize, size: usize) {
    #[cfg(target_arch = "aarch64")]
    dcache_range(addr, size, |line| unsafe {
        core::arch::asm!("dc cvac, {0}", in(reg) line, options(nostack, preserves_flags));
    });
    #[cfg(not(target_arch = "aarch64"))]
    let _ = (addr, size);
}

/// Clean and invalidate `[addr, addr + size)` so the next CPU read sees what
/// a DMA master wrote. Cleaning first means no CPU write in a shared line is
/// lost. No-op on hosts.
pub fn clean_invalidate_dcache_range(addr: usize, size: usize) {
    #[cfg(target_arch = "aarch64")]
    dcache_range(addr, size, |line| unsafe {
        core::arch::asm!("dc civac, {0}", in(reg) line, options(nostack, preserves_flags));
    });
    #[cfg(not(target_arch = "aarch64"))]
    let _ = (addr, size);
}

#[cfg(target_arch = "aarch64")]
fn dcache_range(addr: usize, size: usize, op: impl Fn(usize)) {
    let line = dcache_line_bytes();
    let end = addr.saturating_add(size);
    let mut cursor = addr & !(line - 1);
    while cursor < end {
        op(cursor);
        cursor += line;
    }
    dsb();
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

/// Status polls allowed per byte before the UART is treated as absent. At
/// 921600 baud one byte takes about 11 us, far below this many MMIO reads.
pub const UART_TX_SPIN_LIMIT: u32 = 1_000_000;

/// Early 8250-compatible UART with 32-bit MMIO registers.
///
/// Transmission is bounded: if the transmitter never reports ready (no cable,
/// unclocked or absent device), the UART marks itself dead and drops further
/// output instead of hanging the boot before other outputs have run.
pub struct EarlyUart {
    base_addr: usize,
    dead: core::cell::Cell<bool>,
}

impl EarlyUart {
    /// Create a new EarlyUart driver instance at the specified MMIO base address.
    pub const fn new(base_addr: usize) -> Self {
        Self {
            base_addr,
            dead: core::cell::Cell::new(false),
        }
    }

    /// Read raw register.
    fn reg(&self, offset: usize) -> MmioReg<u32> {
        MmioReg::new(self.base_addr + offset)
    }

    /// True once a transmit timed out; later writes are skipped.
    pub fn is_dead(&self) -> bool {
        self.dead.get()
    }

    /// Send a single byte through UART transmit FIFO, giving up after
    /// `UART_TX_SPIN_LIMIT` status polls.
    pub fn write_byte(&self, b: u8) {
        if self.dead.get() {
            return;
        }
        let status = self.reg(uart16550_regs::LINE_STATUS);
        let data = self.reg(uart16550_regs::DATA);

        let mut polls = 0u32;
        while (status.read() & uart16550_regs::TX_HOLDING_EMPTY) == 0 {
            polls += 1;
            if polls >= UART_TX_SPIN_LIMIT {
                self.dead.set(true);
                return;
            }
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

impl core::fmt::Write for EarlyUart {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        EarlyUart::write_str(self, s);
        Ok(())
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

    #[test]
    fn a_uart_that_never_becomes_ready_is_abandoned_instead_of_hanging() {
        let mut registers = [0u32; 8]; // TX_HOLDING_EMPTY never set
        let uart = EarlyUart::new(registers.as_mut_ptr() as usize);
        uart.write_str("AIENOS\n");
        assert!(uart.is_dead());
        assert_eq!(registers[0], 0);
    }
}
