//! Driver for QEMU's `edu` educational PCI device (1234:11e8).
//!
//! The device exists to prove DMA confinement without risking a real
//! controller: it copies up to 4 KiB between its internal buffer and a bus
//! address we choose, so a test can aim a transfer at memory the SMMU must
//! refuse and then check that nothing moved.
//!
//! Register map (QEMU `docs/specs/edu.rst` and `hw/misc/edu.c`, checked
//! against QEMU 8.2.2): BAR0 is 1 MiB of MMIO. Offsets below 0x80 take only
//! 4-byte accesses; offsets from 0x80 take 4 or 8 bytes, and this driver uses
//! 8 for all of them.
//!
//! Things the device does that the driver must respect:
//! - A transfer whose device side falls outside the 4 KiB buffer at 0x40000
//!   makes QEMU abort (`hw_error`), so the driver checks lengths first.
//! - The RAM side address is silently masked with the device's `dma_mask`
//!   (28 bits unless `-device edu,dma_mask=...` says otherwise). An address
//!   above the mask would wrap to a different address, so the driver refuses
//!   it instead.
//! - A transfer runs from a timer 100 ms of guest time after the command is
//!   written, so completion polling needs a generous budget.
//! - Completion only means the command bit cleared. The device ignores DMA
//!   errors, so a transfer the SMMU blocked also "completes"; proof of a
//!   block is the memory contents and the SMMU event queue, not this status.
//!
//! Register access goes through [`Registers`], so the driver is host-tested
//! against a fake that simulates the DMA command state machine. [`EduMmio`]
//! is the real adapter over a mapped BAR0.

use crate::arch::aarch64::dsb;

/// PCI vendor id of the `edu` device.
pub const VENDOR_ID: u16 = 0x1234;
/// PCI device id of the `edu` device.
pub const DEVICE_ID: u16 = 0x11e8;
/// Size of BAR0, the MMIO register window.
pub const BAR0_SIZE: u64 = 1 << 20;

/// Identification, `0xRRrr00ed` for version RR.rr (read only).
pub const REG_ID: usize = 0x00;
/// Liveness check: reads back the bitwise inverse of the last value written.
pub const REG_LIVENESS: usize = 0x04;
/// Factorial computation input and result.
pub const REG_FACTORIAL: usize = 0x08;
/// Status: bit 0 computing factorial, bit 7 raise interrupt when done.
pub const REG_STATUS: usize = 0x20;
/// Interrupt status (read only): OR of values that raised an interrupt.
pub const REG_IRQ_STATUS: usize = 0x24;
/// Interrupt raise (write only): value is ORed into the interrupt status.
pub const REG_IRQ_RAISE: usize = 0x60;
/// Interrupt acknowledge (write only): value is cleared from the interrupt status.
pub const REG_IRQ_ACK: usize = 0x64;
/// DMA source address (u64).
pub const REG_DMA_SRC: usize = 0x80;
/// DMA destination address (u64).
pub const REG_DMA_DST: usize = 0x88;
/// DMA transfer length in bytes (u64).
pub const REG_DMA_COUNT: usize = 0x90;
/// DMA command (u64), see the `DMA_CMD_*` bits.
pub const REG_DMA_CMD: usize = 0x98;

/// DMA command bit: start the transfer. The device clears it when done.
pub const DMA_CMD_START: u64 = 1 << 0;
/// DMA command bit: direction. Clear copies RAM to the device buffer, set
/// copies the device buffer to RAM.
pub const DMA_CMD_TO_RAM: u64 = 1 << 1;
/// DMA command bit: raise interrupt [`DMA_IRQ`] when the transfer finishes.
pub const DMA_CMD_IRQ: u64 = 1 << 2;
/// Interrupt status value a finished DMA raises when [`DMA_CMD_IRQ`] was set.
pub const DMA_IRQ: u32 = 0x100;

/// Device address of the internal DMA buffer.
pub const DMA_BUFFER_ADDR: u64 = 0x40000;
/// Size of the internal DMA buffer in bytes.
pub const DMA_BUFFER_SIZE: u64 = 4096;
/// The device's default DMA address mask: 28 bits, so bus addresses below 256 MiB.
pub const DEFAULT_DMA_MASK: u64 = (1 << 28) - 1;
/// Low 16 bits of the identification register on every `edu` version.
const ID_SIGNATURE: u32 = 0x00ed;
/// Default number of command register reads before giving up on a transfer.
pub const DEFAULT_SPIN_LIMIT: u32 = 50_000_000;

/// MMIO access to the device's BAR0, by byte offset.
pub trait Registers {
    fn read32(&mut self, offset: usize) -> u32;
    fn write32(&mut self, offset: usize, value: u32);
    fn read64(&mut self, offset: usize) -> u64;
    fn write64(&mut self, offset: usize, value: u64);
}

/// Device version from the identification register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EduVersion {
    pub major: u8,
    pub minor: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EduError {
    /// The identification register does not carry the `edu` signature.
    NotEdu { id: u32 },
    /// The liveness register did not return the inverse of what was written.
    LivenessFailed { wrote: u32, read: u32 },
    /// A zero length transfer was requested.
    EmptyTransfer,
    /// The length exceeds the 4 KiB device buffer.
    TooLong { len: u64 },
    /// Part of the RAM side range lies above the device's DMA mask.
    IovaOutOfRange { iova: u64, len: u64, mask: u64 },
    /// A transfer is already in flight; the device would ignore a new command.
    Busy,
    /// The start bit did not clear within the spin budget. The transfer may
    /// still run later, so the RAM range stays owned by the device.
    Timeout,
}

/// Driver state: the register window, the DMA mask the device was created
/// with and the completion polling budget.
pub struct Edu<R: Registers> {
    regs: R,
    dma_mask: u64,
    spin_limit: u32,
}

impl<R: Registers> Edu<R> {
    /// Driver for a device with the default 28-bit DMA mask.
    pub fn new(regs: R) -> Self {
        Self {
            regs,
            dma_mask: DEFAULT_DMA_MASK,
            spin_limit: DEFAULT_SPIN_LIMIT,
        }
    }

    /// Use the mask the device was created with (`-device edu,dma_mask=`).
    pub fn with_dma_mask(mut self, mask: u64) -> Self {
        self.dma_mask = mask;
        self
    }

    /// Number of command register reads to wait for a transfer.
    pub fn with_spin_limit(mut self, spins: u32) -> Self {
        self.spin_limit = spins;
        self
    }

    pub fn dma_mask(&self) -> u64 {
        self.dma_mask
    }

    pub fn registers(&mut self) -> &mut R {
        &mut self.regs
    }

    pub fn into_registers(self) -> R {
        self.regs
    }

    /// Checks the identification signature and the liveness register.
    /// Touches no DMA state.
    pub fn probe(&mut self) -> Result<EduVersion, EduError> {
        let id = self.regs.read32(REG_ID);
        if id & 0xffff != ID_SIGNATURE {
            return Err(EduError::NotEdu { id });
        }
        for wrote in [0x5a5a_a5a5u32, 0x0123_4567] {
            self.regs.write32(REG_LIVENESS, wrote);
            let read = self.regs.read32(REG_LIVENESS);
            if read != !wrote {
                return Err(EduError::LivenessFailed { wrote, read });
            }
        }
        Ok(EduVersion {
            major: (id >> 24) as u8,
            minor: (id >> 16) as u8,
        })
    }

    /// Whether a transfer is in flight.
    pub fn dma_busy(&mut self) -> bool {
        self.regs.read64(REG_DMA_CMD) & DMA_CMD_START != 0
    }

    /// Copies `len` bytes from bus address `src_iova` into the start of the
    /// device buffer and waits for the command to finish.
    pub fn dma_to_device(&mut self, src_iova: u64, len: u64) -> Result<(), EduError> {
        self.transfer(src_iova, len, false)
    }

    /// Copies `len` bytes from the start of the device buffer to bus address
    /// `dst_iova` and waits for the command to finish.
    pub fn dma_from_device(&mut self, dst_iova: u64, len: u64) -> Result<(), EduError> {
        self.transfer(dst_iova, len, true)
    }

    /// Interrupt status bits currently raised.
    pub fn irq_status(&mut self) -> u32 {
        self.regs.read32(REG_IRQ_STATUS)
    }

    /// Clears `bits` from the interrupt status.
    pub fn ack_irq(&mut self, bits: u32) {
        self.regs.write32(REG_IRQ_ACK, bits);
    }

    /// Validates, programs and starts one transfer, then polls for completion.
    fn transfer(&mut self, iova: u64, len: u64, to_ram: bool) -> Result<(), EduError> {
        self.check(iova, len)?;
        if self.dma_busy() {
            return Err(EduError::Busy);
        }
        let (src, dst, command) = if to_ram {
            (DMA_BUFFER_ADDR, iova, DMA_CMD_START | DMA_CMD_TO_RAM)
        } else {
            (iova, DMA_BUFFER_ADDR, DMA_CMD_START)
        };
        self.regs.write64(REG_DMA_SRC, src);
        self.regs.write64(REG_DMA_DST, dst);
        self.regs.write64(REG_DMA_COUNT, len);
        self.regs.write64(REG_DMA_CMD, command);
        for _ in 0..self.spin_limit {
            if !self.dma_busy() {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(EduError::Timeout)
    }

    /// Length fits the device buffer and the whole RAM range sits under the mask.
    fn check(&self, iova: u64, len: u64) -> Result<(), EduError> {
        if len == 0 {
            return Err(EduError::EmptyTransfer);
        }
        if len > DMA_BUFFER_SIZE {
            return Err(EduError::TooLong { len });
        }
        let out_of_range = EduError::IovaOutOfRange {
            iova,
            len,
            mask: self.dma_mask,
        };
        let last = iova.checked_add(len - 1).ok_or(out_of_range)?;
        if iova & !self.dma_mask != 0 || last & !self.dma_mask != 0 {
            return Err(out_of_range);
        }
        Ok(())
    }
}

/// BAR0 of a real device through volatile MMIO. Every write is preceded by a
/// full data synchronization barrier and every read followed by one, so
/// buffer writes in RAM are visible to the device before a transfer starts
/// and device writes are visible to the CPU after completion is seen.
pub struct EduMmio {
    base: usize,
}

impl EduMmio {
    /// # Safety
    /// `base` must be the virtual address of the device's BAR0, mapped as
    /// device memory for [`BAR0_SIZE`] bytes for as long as this value is
    /// used, with memory decode enabled, and not driven by anything else.
    pub const unsafe fn new(base: usize) -> Self {
        Self { base }
    }
}

impl Registers for EduMmio {
    fn read32(&mut self, offset: usize) -> u32 {
        // SAFETY: inside the BAR that `new` requires to be mapped.
        let value = unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) };
        dsb();
        value
    }

    fn write32(&mut self, offset: usize, value: u32) {
        dsb();
        // SAFETY: as for `read32`.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) }
    }

    fn read64(&mut self, offset: usize) -> u64 {
        // SAFETY: as for `read32`.
        let value = unsafe { core::ptr::read_volatile((self.base + offset) as *const u64) };
        dsb();
        value
    }

    fn write64(&mut self, offset: usize, value: u64) {
        dsb();
        // SAFETY: as for `read32`.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u64, value) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simulated `edu` register file and bus. RAM is a small window of bus
    /// addresses from `ram_base`; addresses in `blocked` model an SMMU that
    /// refuses the access (the device still reports completion, as QEMU's
    /// does). Panics where real QEMU would abort or misbehave, so a test
    /// fails if the driver ever programs such a transfer.
    struct FakeEdu {
        id: u32,
        liveness: u32,
        irq_status: u32,
        src: u64,
        dst: u64,
        count: u64,
        cmd: u64,
        dma_mask: u64,
        buffer: [u8; DMA_BUFFER_SIZE as usize],
        ram_base: u64,
        ram: std::vec::Vec<u8>,
        blocked: core::ops::Range<u64>,
        /// Command reads before a started transfer runs; `None` never runs.
        delay: Option<u32>,
        polls_left: u32,
        transfers: u32,
        invert_liveness: bool,
    }

    impl FakeEdu {
        fn new() -> Self {
            Self {
                id: 0x0100_00ed,
                liveness: 0,
                irq_status: 0,
                src: 0,
                dst: 0,
                count: 0,
                cmd: 0,
                dma_mask: DEFAULT_DMA_MASK,
                buffer: [0; DMA_BUFFER_SIZE as usize],
                ram_base: 0x10_0000,
                ram: std::vec![0; 0x4000],
                blocked: 0..0,
                delay: Some(3),
                polls_left: 0,
                transfers: 0,
                invert_liveness: true,
            }
        }

        fn ram_index(&self, addr: u64) -> usize {
            usize::try_from(addr - self.ram_base).unwrap()
        }

        fn run_dma(&mut self) {
            let len = self.count;
            let to_ram = self.cmd & DMA_CMD_TO_RAM != 0;
            let (device, ram) = if to_ram {
                (self.src, self.dst)
            } else {
                (self.dst, self.src)
            };
            // QEMU aborts on a device side range outside the buffer.
            assert!(
                device >= DMA_BUFFER_ADDR && device + len <= DMA_BUFFER_ADDR + DMA_BUFFER_SIZE,
                "edu would abort: device range {device:#x}+{len:#x}"
            );
            // QEMU masks the RAM side; the driver must never rely on that.
            assert_eq!(ram & self.dma_mask, ram, "edu would clamp {ram:#x}");
            let off = (device - DMA_BUFFER_ADDR) as usize;
            let n = len as usize;
            if !self.blocked.contains(&ram) {
                let at = self.ram_index(ram);
                if to_ram {
                    self.ram[at..at + n].copy_from_slice(&self.buffer[off..off + n]);
                } else {
                    self.buffer[off..off + n].copy_from_slice(&self.ram[at..at + n]);
                }
            }
            self.transfers += 1;
            self.cmd &= !DMA_CMD_START;
            if self.cmd & DMA_CMD_IRQ != 0 {
                self.irq_status |= DMA_IRQ;
            }
        }
    }

    impl Registers for FakeEdu {
        fn read32(&mut self, offset: usize) -> u32 {
            match offset {
                REG_ID => self.id,
                REG_LIVENESS => self.liveness,
                REG_IRQ_STATUS => self.irq_status,
                _ => panic!("unexpected 32-bit read at {offset:#x}"),
            }
        }

        fn write32(&mut self, offset: usize, value: u32) {
            match offset {
                REG_LIVENESS if self.invert_liveness => self.liveness = !value,
                REG_LIVENESS => self.liveness = value,
                REG_IRQ_ACK => self.irq_status &= !value,
                _ => panic!("unexpected 32-bit write at {offset:#x}"),
            }
        }

        fn read64(&mut self, offset: usize) -> u64 {
            match offset {
                REG_DMA_CMD => {
                    if self.cmd & DMA_CMD_START != 0 {
                        if let Some(delay) = self.delay {
                            if self.polls_left >= delay {
                                self.run_dma();
                            } else {
                                self.polls_left += 1;
                            }
                        }
                    }
                    self.cmd
                }
                _ => panic!("unexpected 64-bit read at {offset:#x}"),
            }
        }

        fn write64(&mut self, offset: usize, value: u64) {
            match offset {
                REG_DMA_SRC => self.src = value,
                REG_DMA_DST => self.dst = value,
                REG_DMA_COUNT => self.count = value,
                // QEMU ignores a new command while a transfer runs.
                REG_DMA_CMD if self.cmd & DMA_CMD_START == 0 => {
                    self.cmd = value;
                    self.polls_left = 0;
                }
                REG_DMA_CMD => {}
                _ => panic!("unexpected 64-bit write at {offset:#x}"),
            }
        }
    }

    #[test]
    fn probe_reads_version_and_checks_liveness() {
        let mut edu = Edu::new(FakeEdu::new());
        assert_eq!(edu.probe(), Ok(EduVersion { major: 1, minor: 0 }));

        let mut fake = FakeEdu::new();
        fake.id = 0x1af4_1000;
        assert_eq!(
            Edu::new(fake).probe(),
            Err(EduError::NotEdu { id: 0x1af4_1000 })
        );

        let mut fake = FakeEdu::new();
        fake.invert_liveness = false;
        assert_eq!(
            Edu::new(fake).probe(),
            Err(EduError::LivenessFailed {
                wrote: 0x5a5a_a5a5,
                read: 0x5a5a_a5a5
            })
        );
    }

    #[test]
    fn round_trips_bytes_through_the_device_buffer() {
        let mut fake = FakeEdu::new();
        let src = fake.ram_base + 0x100;
        let dst = fake.ram_base + 0x2000;
        for (i, b) in fake.ram[0x100..0x100 + 200].iter_mut().enumerate() {
            *b = i as u8 ^ 0xa5;
        }
        let mut edu = Edu::new(fake);
        edu.dma_to_device(src, 200).unwrap();
        edu.dma_from_device(dst, 200).unwrap();
        let fake = edu.into_registers();
        assert_eq!(fake.ram[0x2000..0x2000 + 200], fake.ram[0x100..0x100 + 200]);
        assert_eq!(fake.transfers, 2);
        assert_eq!(fake.src, DMA_BUFFER_ADDR);
        assert_eq!(fake.dst, dst);
        assert_eq!(fake.cmd, DMA_CMD_TO_RAM);
        assert_eq!(fake.irq_status, 0, "no interrupt was requested");
    }

    #[test]
    fn full_buffer_transfer_is_allowed() {
        let fake = FakeEdu::new();
        let at = fake.ram_base;
        let mut edu = Edu::new(fake);
        edu.dma_to_device(at, DMA_BUFFER_SIZE).unwrap();
        edu.dma_from_device(at + DMA_BUFFER_SIZE, DMA_BUFFER_SIZE)
            .unwrap();
    }

    #[test]
    fn blocked_transfer_completes_but_leaves_ram_untouched() {
        let mut fake = FakeEdu::new();
        fake.buffer.fill(0x77);
        let forbidden = fake.ram_base + 0x3000;
        fake.blocked = forbidden..forbidden + 0x1000;
        let mut edu = Edu::new(fake);
        // The device reports success: completion is not proof of access.
        assert_eq!(edu.dma_from_device(forbidden, 64), Ok(()));
        let fake = edu.into_registers();
        assert!(fake.ram[0x3000..0x3040].iter().all(|b| *b == 0));
    }

    #[test]
    fn rejects_bad_lengths_and_addresses_before_touching_the_device() {
        let mut edu = Edu::new(FakeEdu::new());
        let top = DEFAULT_DMA_MASK + 1;
        assert_eq!(edu.dma_to_device(0x1000, 0), Err(EduError::EmptyTransfer));
        assert_eq!(
            edu.dma_to_device(0x1000, DMA_BUFFER_SIZE + 1),
            Err(EduError::TooLong {
                len: DMA_BUFFER_SIZE + 1
            })
        );
        let err = |iova, len| EduError::IovaOutOfRange {
            iova,
            len,
            mask: DEFAULT_DMA_MASK,
        };
        assert_eq!(edu.dma_from_device(top, 16), Err(err(top, 16)));
        // Starts below 256 MiB but runs past it.
        assert_eq!(edu.dma_from_device(top - 8, 16), Err(err(top - 8, 16)));
        assert_eq!(
            edu.dma_from_device(u64::MAX - 3, 16),
            Err(err(u64::MAX - 3, 16))
        );
        let fake = edu.into_registers();
        assert_eq!((fake.src, fake.dst, fake.count, fake.cmd), (0, 0, 0, 0));
    }

    #[test]
    fn last_byte_below_the_mask_is_accepted() {
        let mut fake = FakeEdu::new();
        fake.ram_base = DEFAULT_DMA_MASK + 1 - 0x2000;
        let at = DEFAULT_DMA_MASK + 1 - 16;
        let mut edu = Edu::new(fake);
        assert_eq!(edu.dma_from_device(at, 16), Ok(()));
    }

    #[test]
    fn wider_dma_mask_accepts_higher_addresses() {
        let mut fake = FakeEdu::new();
        fake.dma_mask = u64::MAX;
        fake.ram_base = 0x8000_0000;
        let mut edu = Edu::new(fake).with_dma_mask(u64::MAX);
        assert_eq!(edu.dma_mask(), u64::MAX);
        assert_eq!(edu.dma_from_device(0x8000_0000, 16), Ok(()));
    }

    #[test]
    fn times_out_when_the_transfer_never_finishes() {
        let mut fake = FakeEdu::new();
        fake.delay = None;
        let at = fake.ram_base;
        let mut edu = Edu::new(fake).with_spin_limit(100);
        assert_eq!(edu.dma_to_device(at, 16), Err(EduError::Timeout));
        assert!(edu.dma_busy());
        // The stuck transfer blocks the next one instead of being overwritten.
        assert_eq!(edu.dma_from_device(at, 16), Err(EduError::Busy));
        let fake = edu.into_registers();
        assert_eq!(fake.cmd, DMA_CMD_START, "first command still pending");
        assert_eq!(fake.transfers, 0);
    }

    #[test]
    fn spin_budget_covers_a_slow_transfer() {
        let mut fake = FakeEdu::new();
        fake.delay = Some(1000);
        let at = fake.ram_base;
        let mut edu = Edu::new(fake).with_spin_limit(1001);
        assert_eq!(edu.dma_to_device(at, 16), Ok(()));
        let mut fake = edu.into_registers();
        fake.delay = Some(1000);
        let mut edu = Edu::new(fake).with_spin_limit(1000);
        assert_eq!(edu.dma_to_device(at, 16), Err(EduError::Timeout));
    }

    #[test]
    fn interrupt_status_and_acknowledge() {
        let mut fake = FakeEdu::new();
        fake.irq_status = DMA_IRQ | 0x1;
        let mut edu = Edu::new(fake);
        assert_eq!(edu.irq_status(), DMA_IRQ | 0x1);
        edu.ack_irq(DMA_IRQ);
        assert_eq!(edu.irq_status(), 0x1);
    }
}
