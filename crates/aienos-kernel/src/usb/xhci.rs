//! Minimal polled xHCI (USB 3 host controller) driver.
//!
//! Just enough of the xHCI specification to attach one HID boot-protocol
//! keyboard: controller reset, one event ring and one command ring, Enable
//! Slot, Address Device, Configure Endpoint for the keyboard's interrupt-IN
//! endpoint, then a bounded transfer ring polled for reports. Every register
//! wait and command completion is bounded so a missing or wedged controller
//! degrades the keyboard instead of hanging boot.
//!
//! There is no allocator inside the driver: the caller hands over one
//! 64-byte-aligned 4 KiB block per ring or context structure (`Block`) plus
//! one 64-byte-aligned report buffer, all kept alive for the driver's
//! lifetime. The identity mapping inherited from the firmware makes each
//! block address usable as its DMA address.

use crate::arch::aarch64::{clean_cache_range, dmb, invalidate_cache_range, MmioReg};
use crate::usb::hid::BOOT_REPORT_LEN;
use core::fmt;

/// Every bounded wait gives up after this many polls. The register reads make
/// hardware timeouts land in the tens of milliseconds, far above what a
/// healthy controller needs, and a wedged controller cannot hang boot.
pub const SPIN_LIMIT: u32 = 200_000;

const COMMAND_RING_TRBS: usize = 16;
const EVENT_RING_TRBS: usize = 16;
const TRANSFER_RING_TRBS: usize = 16;

/// Offsets of the runtime registers from the base recorded in CAPLENGTH.
const RT_IMAN: usize = 0x20;
const RT_ERSTSZ: usize = 0x28;
const RT_ERSTBA: usize = 0x38;
const RT_ERDP: usize = 0x40;

const USBSTS_HALTED: u32 = 1 << 0;
const USBSTS_HOST_SYSTEM_ERROR: u32 = 1 << 2;
const USBSTS_CONTROLLER_NOT_READY: u32 = 1 << 11;

const USBCMD_RUN: u32 = 1 << 0;
const USBCMD_RESET: u32 = 1 << 1;

const TRB_SET_LINK: u32 = 1 << 1;
const TRB_INTERRUPT_ON_COMPLETION: u32 = 1 << 5;
const TRB_TYPE_SHIFT: u32 = 10;
const TRB_CYCLE: u32 = 1;

const TRT_NO_DATA: u32 = 3 << 16;

const CODE_SUCCESS: u8 = 1;
const CODE_SHORT_PACKET: u8 = 13;

const TYPE_NORMAL: u32 = 1;
const TYPE_SETUP_STAGE: u32 = 2;
const TYPE_STATUS_STAGE: u32 = 4;
const TYPE_LINK: u32 = 6;
const TYPE_ENABLE_SLOT: u32 = 9;
const TYPE_ADDRESS_DEVICE: u32 = 11;
const TYPE_CONFIGURE_ENDPOINT: u32 = 12;
const TYPE_TRANSFER_EVENT: u32 = 32;
const TYPE_COMMAND_COMPLETION: u32 = 33;

const SLOT_ID_SHIFT: u32 = 24;
const STATUS_IN: u32 = 1 << 16;

const REQUEST_SET_PROTOCOL: u8 = 0x0b;
const PROTOCOL_BOOT: u16 = 0;

const TARGET_CONTROL_ENDPOINT: u8 = 1;

/// A 4 KiB, 64-byte-aligned zeroed block handed to the controller.
#[repr(align(64))]
pub struct Block {
    /// Caller-owned storage for the DMA structure this block backs.
    pub data: [u8; 4096],
}

impl Block {
    pub const fn new() -> Self {
        Self { data: [0; 4096] }
    }

    /// Physical (DMA) address of the block. Valid while the caller keeps the
    /// block alive and the identity mapping holds.
    pub fn dma_addr(&self) -> u64 {
        self.data.as_ptr() as usize as u64
    }

    /// 64-byte alignment is the minimum every xHCI structure needs.
    pub fn is_aligned(&self) -> bool {
        (self.data.as_ptr() as usize).is_multiple_of(64)
    }

    /// Make the block's current bytes visible to the controller.
    pub fn flush(&self) {
        clean_cache_range(self.dma_addr() as usize, self.data.len());
    }

    /// Discard any cached copy so the next read sees the controller's bytes.
    pub fn invalidate(&self) {
        invalidate_cache_range(self.dma_addr() as usize, self.data.len());
    }

    fn trb(&mut self, index: usize) -> *mut u32 {
        // Caller guarantees index < 256 (one page of TRBs).
        unsafe { (self.data.as_mut_ptr() as *mut u32).add(index * 4) }
    }

    fn trb_const(&self, index: usize) -> *const u32 {
        unsafe { (self.data.as_ptr() as *const u32).add(index * 4) }
    }

    fn write_trb(&mut self, index: usize, fields: [u32; 4]) {
        let trb = self.trb(index);
        for (i, f) in fields.iter().enumerate() {
            // SAFETY: `trb` stays inside the caller-owned block; xHCI
            // structures are written dword-wise.
            unsafe { trb.add(i).write_volatile(*f) };
        }
    }

    fn read_trb(&self, index: usize) -> [u32; 4] {
        let trb = self.trb_const(index);
        let mut fields = [0u32; 4];
        for (i, f) in fields.iter_mut().enumerate() {
            // SAFETY: same in-bounds argument as `write_trb`.
            *f = unsafe { trb.add(i).read_volatile() };
        }
        fields
    }

    fn write_u32(&mut self, byte_offset: usize, value: u32) {
        // SAFETY: callers keep offsets inside the page.
        unsafe {
            core::ptr::copy_nonoverlapping(
                value.to_le_bytes().as_ptr(),
                self.data.as_mut_ptr().add(byte_offset),
                4,
            )
        };
    }
}

impl Default for Block {
    fn default() -> Self {
        Self::new()
    }
}

/// Why the keyboard could not be brought up. All failure paths are bounded
/// and reported; none of them can hang boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Capability registers read back as all-ones (device gone).
    DeadRegisters,
    ControllerNotReady,
    ResetTimedOut,
    EnableSlotFailed,
    AddressDeviceFailed,
    SetProtocolFailed,
    ConfigureEndpointFailed,
    EndpointNotInterruptIn,
    CommandTimedOut,
    HostError,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DeadRegisters => "capability registers read as all-ones",
            Self::ControllerNotReady => "controller never became ready",
            Self::ResetTimedOut => "controller reset timed out",
            Self::EnableSlotFailed => "Enable Slot failed",
            Self::AddressDeviceFailed => "Address Device failed",
            Self::SetProtocolFailed => "SET_PROTOCOL (boot) request failed",
            Self::ConfigureEndpointFailed => "Configure Endpoint failed",
            Self::EndpointNotInterruptIn => "endpoint is not an interrupt-IN endpoint",
            Self::CommandTimedOut => "command completion timed out",
            Self::HostError => "controller signalled a host system error",
        })
    }
}

/// Memory-mapped xHCI register groups, derived from the capability registers.
pub struct Regs {
    op: usize,
    rt: usize,
    db: usize,
}

impl Regs {
    fn read_op(&self, offset: usize) -> u32 {
        MmioReg::<u32>::new(self.op + offset).read()
    }

    fn write_op(&self, offset: usize, value: u32) {
        MmioReg::<u32>::new(self.op + offset).write(value);
    }

    fn write_rt(&self, offset: usize, value: u32) {
        MmioReg::<u32>::new(self.rt + offset).write(value);
    }

    fn write_rt64(&self, offset: usize, value: u64) {
        MmioReg::<u32>::new(self.rt + offset).write((value & 0xffff_ffff) as u32);
        MmioReg::<u32>::new(self.rt + offset + 4).write((value >> 32) as u32);
    }

    fn write_op64(&self, offset: usize, value: u64) {
        MmioReg::<u32>::new(self.op + offset).write((value & 0xffff_ffff) as u32);
        MmioReg::<u32>::new(self.op + offset + 4).write((value >> 32) as u32);
    }

    fn ring_command_doorbell(&self) {
        MmioReg::<u32>::new(self.db).write(0);
    }

    fn ring_slot_doorbell(&self, slot: u8, target: u8) {
        MmioReg::<u32>::new(self.db + usize::from(slot) * 4).write(u32::from(target));
    }
}

/// Register groups of a probed xHCI controller, or `None` when the registers
/// look absent (all-ones reads).
///
/// # Safety
/// `mmio_base` must be the physical base of a mapped xHCI register block.
pub unsafe fn claim(mmio_base: u64) -> Option<Regs> {
    let cap = mmio_base as usize;
    let cap_length = MmioReg::<u8>::new(cap).read();
    let hci_version = MmioReg::<u16>::new(cap + 2).read();
    if cap_length == 0xff || cap_length < 0x20 || hci_version == 0xffff {
        return None;
    }
    let db_off = MmioReg::<u32>::new(cap + 0x14).read() & !0x3;
    let rt_off = MmioReg::<u32>::new(cap + 0x18).read() & !0x1f;
    Some(Regs {
        op: cap + usize::from(cap_length),
        rt: cap + rt_off as usize,
        db: cap + db_off as usize,
    })
}

fn dword(addr: u64) -> [u32; 2] {
    [(addr & 0xffff_ffff) as u32, (addr >> 32) as u32]
}

fn completion_code(trb: [u32; 4]) -> u8 {
    ((trb[2] >> 24) & 0xff) as u8
}

fn event_slot(trb: [u32; 4]) -> u8 {
    (trb[3] >> SLOT_ID_SHIFT) as u8
}

/// Control request parameters (SETUP stage payload).
#[derive(Clone, Copy)]
pub struct SetupPacket {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

impl SetupPacket {
    fn low(&self) -> u32 {
        u32::from(self.request_type)
            | u32::from(self.request) << 8
            | u32::from(self.value) << 16
    }

    fn high(&self) -> u32 {
        u32::from(self.index) | u32::from(self.length) << 16
    }
}

/// Which keyboard endpoint to drive, learned from the port the caller saw the
/// keyboard on before firmware exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyboardEndpoint {
    /// 1-based root-hub port the keyboard is plugged into.
    pub port: u8,
    /// Port speed from PORTSC (1 = full, 2 = low, 3 = high, 4+ = super).
    pub speed: u8,
    /// Interrupt-IN endpoint address, usually 0x81.
    pub endpoint_address: u8,
    pub max_packet_size: u16,
}

impl KeyboardEndpoint {
    /// Device-context index for this endpoint address, if it is an IN
    /// endpoint with a non-zero endpoint number.
    fn dci(&self) -> Option<u8> {
        let number = self.endpoint_address & 0x0f;
        let direction_in = self.endpoint_address & 0x80 != 0;
        if number == 0 {
            return None;
        }
        direction_in.then_some(number * 2 + 1)
    }
}

/// DMA structures the caller must keep alive for the driver's lifetime.
pub struct Blocks {
    pub dcbaa: Block,
    pub device_context: Block,
    pub input_context: Block,
    pub command_ring: Block,
    pub event_ring: Block,
    pub event_ring_segment_table: Block,
    pub control_ring: Block,
    pub transfer_ring: Block,
}

/// Driver state for one keyboard behind one xHCI controller. The constructor
/// performs all controller programming; `poll_report` is then callable at any
/// cadence.
pub struct XhciKeyboard {
    regs: Regs,
    slot: u8,
    endpoint_dci: u8,
    blocks: Blocks,
    command_enqueue: usize,
    command_cycle: bool,
    event_dequeue: usize,
    event_cycle: bool,
    control_enqueue: usize,
    control_cycle: bool,
    transfer_enqueue: usize,
    transfer_cycle: bool,
    report_buffer: *mut u8,
    report_capacity: usize,
    armed: bool,
}

impl XhciKeyboard {
    /// Bring up the controller and the keyboard described by `endpoint`.
    ///
    /// # Safety
    /// Every block in `blocks` must be DMA-reachable (identity-mapped) memory
    /// owned by the caller, and `report_buffer` must be writable, 64-byte
    /// aligned and at least `BOOT_REPORT_LEN` bytes. All of them must outlive
    /// the driver.
    pub unsafe fn start(
        regs: Regs,
        endpoint: KeyboardEndpoint,
        mut blocks: Blocks,
        report_buffer: *mut u8,
        report_capacity: usize,
    ) -> Result<Self, Error> {
        let endpoint_dci = endpoint.dci().ok_or(Error::EndpointNotInterruptIn)?;
        if report_capacity < BOOT_REPORT_LEN || !(report_buffer as usize).is_multiple_of(64) {
            return Err(Error::HostError);
        }
        for block in [
            &blocks.dcbaa,
            &blocks.device_context,
            &blocks.input_context,
            &blocks.command_ring,
            &blocks.event_ring,
            &blocks.event_ring_segment_table,
            &blocks.control_ring,
            &blocks.transfer_ring,
        ] {
            if !block.is_aligned() {
                return Err(Error::HostError);
            }
        }
        blocks.dcbaa.data.fill(0);
        blocks.device_context.data.fill(0);
        blocks.input_context.data.fill(0);
        blocks.command_ring.data.fill(0);
        blocks.event_ring.data.fill(0);
        blocks.event_ring_segment_table.data.fill(0);
        blocks.control_ring.data.fill(0);
        blocks.transfer_ring.data.fill(0);
        write_link_trb(&mut blocks.command_ring, COMMAND_RING_TRBS);
        write_link_trb(&mut blocks.control_ring, TRANSFER_RING_TRBS);
        write_link_trb(&mut blocks.transfer_ring, TRANSFER_RING_TRBS);
        blocks.command_ring.flush();
        blocks.control_ring.flush();
        blocks.transfer_ring.flush();

        Self::reset_controller(&regs)?;

        // Device-context base address array points at the device context.
        let [dev_lo, dev_hi] = dword(blocks.device_context.dma_addr());
        blocks.dcbaa.write_u32(0, dev_lo);
        blocks.dcbaa.write_u32(4, dev_hi);
        blocks.dcbaa.flush();
        regs.write_op64(0x30, blocks.dcbaa.dma_addr()); // DCBAAP
        regs.write_op64(0x18, blocks.command_ring.dma_addr() | u64::from(TRB_CYCLE)); // CRCR

        // Event ring segment table: one segment covering the whole ring.
        let [er_lo, er_hi] = dword(blocks.event_ring.dma_addr());
        blocks.event_ring_segment_table.write_u32(0, er_lo);
        blocks.event_ring_segment_table.write_u32(4, er_hi);
        blocks
            .event_ring_segment_table
            .write_u32(8, EVENT_RING_TRBS as u32);
        blocks.event_ring_segment_table.flush();
        regs.write_rt(RT_ERSTSZ, 1);
        regs.write_rt64(RT_ERSTBA, blocks.event_ring_segment_table.dma_addr());
        regs.write_rt64(RT_ERDP, blocks.event_ring.dma_addr());
        // Interrupt-enable for interrupter 0; the driver polls regardless.
        let iman = MmioReg::<u32>::new(regs.rt + RT_IMAN).read();
        MmioReg::<u32>::new(regs.rt + RT_IMAN).write(iman | 1 << 1);

        regs.write_op(0x00, regs.read_op(0x00) | USBCMD_RUN);
        Self::wait_until(&regs, |sts| sts & USBSTS_HALTED == 0)
            .map_err(|_| Error::ControllerNotReady)?;

        let mut keyboard = Self {
            regs,
            slot: 0,
            endpoint_dci,
            blocks,
            command_enqueue: 0,
            command_cycle: true,
            event_dequeue: 0,
            event_cycle: true,
            control_enqueue: 0,
            control_cycle: true,
            transfer_enqueue: 0,
            transfer_cycle: true,
            report_buffer,
            report_capacity,
            armed: false,
        };
        keyboard.slot = keyboard.enable_slot()?;
        keyboard.address_device(&endpoint)?;
        keyboard.set_boot_protocol()?;
        keyboard.configure_endpoint(&endpoint)?;
        keyboard.arm_report();
        Ok(keyboard)
    }

    fn wait_until(regs: &Regs, ready: impl Fn(u32) -> bool) -> Result<(), Error> {
        for _ in 0..SPIN_LIMIT {
            let status = regs.read_op(0x04);
            if status & USBSTS_HOST_SYSTEM_ERROR != 0 {
                return Err(Error::HostError);
            }
            if ready(status) {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(Error::CommandTimedOut)
    }

    fn reset_controller(regs: &Regs) -> Result<(), Error> {
        let status = regs.read_op(0x04);
        if status == 0xffff_ffff {
            return Err(Error::DeadRegisters);
        }
        // Stop, wait for the halt, then reset and wait for the controller to
        // clear both the reset bit and the not-ready flag.
        regs.write_op(0x00, regs.read_op(0x00) & !USBCMD_RUN);
        Self::wait_until(regs, |sts| sts & USBSTS_HALTED != 0)
            .map_err(|_| Error::ControllerNotReady)?;
        regs.write_op(0x00, USBCMD_RESET);
        let mut polls = 0;
        while regs.read_op(0x00) & USBCMD_RESET != 0 {
            polls += 1;
            if polls >= SPIN_LIMIT {
                return Err(Error::ResetTimedOut);
            }
            core::hint::spin_loop();
        }
        Self::wait_until(regs, |sts| sts & USBSTS_CONTROLLER_NOT_READY == 0)
            .map_err(|_| Error::ControllerNotReady)
    }

    /// Push one TRB onto a ring, maintaining its producer state.
    fn push_trb(
        block: &mut Block,
        trbs: usize,
        enqueue: &mut usize,
        cycle: &mut bool,
        mut fields: [u32; 4],
    ) {
        fields[3] = fields[3] & !TRB_CYCLE | u32::from(*cycle);
        block.write_trb(*enqueue, fields);
        *enqueue += 1;
        if *enqueue == trbs - 1 {
            let mut link = block.read_trb(trbs - 1);
            link[3] = link[3] & !TRB_CYCLE | u32::from(*cycle);
            block.write_trb(trbs - 1, link);
            *enqueue = 0;
            *cycle = !*cycle;
        }
        block.flush();
    }

    /// Push one command TRB and ring the command doorbell.
    fn push_command(&mut self, fields: [u32; 4]) {
        // Disjoint field borrows: the ring block and its producer state.
        let block = &mut self.blocks.command_ring;
        let enqueue = &mut self.command_enqueue;
        let cycle = &mut self.command_cycle;
        Self::push_trb(block, COMMAND_RING_TRBS, enqueue, cycle, fields);
        dmb();
        self.regs.ring_command_doorbell();
    }

    /// Next unconsumed event TRB, if the controller has written one.
    fn pop_event(&mut self) -> Option<[u32; 4]> {
        self.blocks.event_ring.invalidate();
        let trb = self.blocks.event_ring.read_trb(self.event_dequeue);
        if (trb[3] & TRB_CYCLE != 0) != self.event_cycle {
            return None;
        }
        self.event_dequeue += 1;
        if self.event_dequeue == EVENT_RING_TRBS - 1 {
            self.event_dequeue = 0;
            self.event_cycle = !self.event_cycle;
        }
        Some(trb)
    }

    /// Advance the software dequeue pointer past consumed events and clear
    /// the event-handler busy bit.
    fn retire_events(&self) {
        let addr = self.blocks.event_ring.dma_addr() + (self.event_dequeue * 16) as u64;
        self.regs.write_rt64(RT_ERDP, addr | 1 << 3);
    }

    /// Wait, bounded, for the next command-completion event.
    fn await_command(&mut self) -> Result<[u32; 4], Error> {
        for _ in 0..SPIN_LIMIT {
            if let Some(event) = self.pop_event() {
                if (event[3] >> TRB_TYPE_SHIFT) & 0x3f == TYPE_COMMAND_COMPLETION {
                    self.retire_events();
                    return Ok(event);
                }
            }
            core::hint::spin_loop();
        }
        Err(Error::CommandTimedOut)
    }

    fn enable_slot(&mut self) -> Result<u8, Error> {
        self.push_command([
            0,
            0,
            0,
            TYPE_ENABLE_SLOT << TRB_TYPE_SHIFT | TRB_INTERRUPT_ON_COMPLETION,
        ]);
        let event = self.await_command()?;
        if completion_code(event) != CODE_SUCCESS {
            return Err(Error::EnableSlotFailed);
        }
        Ok(event_slot(event))
    }

    /// Fill the slot and endpoint-0 input contexts and run Address Device.
    fn address_device(&mut self, endpoint: &KeyboardEndpoint) -> Result<(), Error> {
        self.blocks.input_context.data.fill(0);
        self.blocks.input_context.write_u32(0x04, 0x3); // add A1 (ep0) | A0 (slot)
        let slot_ctx = 1 << 27 // Context Entries = 1
            | u32::from(endpoint.speed) << 20
            | u32::from(endpoint.port) << 16;
        self.blocks.input_context.write_u32(0x20, slot_ctx);
        // Endpoint 0 context: control, bidirectional (DCI 1 at offset 0x40).
        let max_packet = u32::from(endpoint.max_packet_size.clamp(8, 512));
        self.blocks.input_context.write_u32(0x40 + 1, 3 << 1); // CErr = 3
        self.blocks.input_context.write_u32(0x40 + 4, 4 << 3 | max_packet << 16);
        let [tr_lo, tr_hi] = dword(self.blocks.control_ring.dma_addr() | 1); // DCS=1
        self.blocks.input_context.write_u32(0x40 + 8, tr_lo);
        self.blocks.input_context.write_u32(0x40 + 12, tr_hi);
        self.blocks.input_context.write_u32(0x40 + 16, 8); // average TRB length
        self.blocks.input_context.flush();
        dmb();

        let [ic_lo, ic_hi] = dword(self.blocks.input_context.dma_addr());
        self.push_command([
            ic_lo,
            ic_hi,
            0,
            TYPE_ADDRESS_DEVICE << TRB_TYPE_SHIFT
                | TRB_INTERRUPT_ON_COMPLETION
                | u32::from(self.slot) << SLOT_ID_SHIFT,
        ]);
        let event = self.await_command()?;
        if completion_code(event) != CODE_SUCCESS {
            return Err(Error::AddressDeviceFailed);
        }
        Ok(())
    }

    /// SET_PROTOCOL(boot) so the keyboard emits 8-byte boot reports.
    fn set_boot_protocol(&mut self) -> Result<(), Error> {
        let setup = SetupPacket {
            request_type: 0x21, // host-to-device, class, interface
            request: REQUEST_SET_PROTOCOL,
            value: PROTOCOL_BOOT,
            index: 0,
            length: 0,
        };
        let block = &mut self.blocks.control_ring;
        let enqueue = &mut self.control_enqueue;
        let cycle = &mut self.control_cycle;
        Self::push_trb(
            block,
            TRANSFER_RING_TRBS,
            enqueue,
            cycle,
            [
                setup.low(),
                setup.high(),
                8,
                TYPE_SETUP_STAGE << TRB_TYPE_SHIFT | TRT_NO_DATA | TRB_INTERRUPT_ON_COMPLETION,
            ],
        );
        Self::push_trb(
            block,
            TRANSFER_RING_TRBS,
            enqueue,
            cycle,
            [0, 0, 0, TYPE_STATUS_STAGE << TRB_TYPE_SHIFT | STATUS_IN],
        );
        dmb();
        self.regs.ring_slot_doorbell(self.slot, TARGET_CONTROL_ENDPOINT);
        for _ in 0..SPIN_LIMIT {
            if let Some(event) = self.pop_event() {
                if (event[3] >> TRB_TYPE_SHIFT) & 0x3f == TYPE_TRANSFER_EVENT
                    && event_slot(event) == self.slot
                {
                    self.retire_events();
                    return match completion_code(event) {
                        CODE_SUCCESS | CODE_SHORT_PACKET => Ok(()),
                        _ => Err(Error::SetProtocolFailed),
                    };
                }
            }
            core::hint::spin_loop();
        }
        Err(Error::CommandTimedOut)
    }

    /// Enable the interrupt-IN endpoint with a Configure Endpoint command.
    fn configure_endpoint(&mut self, endpoint: &KeyboardEndpoint) -> Result<(), Error> {
        let dci = u32::from(self.endpoint_dci);
        self.blocks.input_context.data.fill(0);
        self.blocks.input_context.write_u32(0x04, 1 | 1 << dci); // A0 | A(dci)
        let slot_ctx = (dci + 1) << 27 // Context Entries
            | u32::from(endpoint.speed) << 20
            | u32::from(endpoint.port) << 16;
        self.blocks.input_context.write_u32(0x20, slot_ctx);
        // Interrupt-IN endpoint context.
        let base = 0x20 + dci as usize * 0x20;
        self.blocks.input_context.write_u32(base + 1, 3 << 1); // CErr = 3
        self.blocks.input_context.write_u32(
            base + 4,
            7 << 3 | u32::from(endpoint.max_packet_size.clamp(8, 1024)) << 16,
        );
        let [tr_lo, tr_hi] = dword(self.blocks.transfer_ring.dma_addr() | 1); // DCS=1
        self.blocks.input_context.write_u32(base + 8, tr_lo);
        self.blocks.input_context.write_u32(base + 12, tr_hi);
        self.blocks.input_context.write_u32(base + 16, 8);
        self.blocks.input_context.flush();
        dmb();

        let [ic_lo, ic_hi] = dword(self.blocks.input_context.dma_addr());
        self.push_command([
            ic_lo,
            ic_hi,
            0,
            TYPE_CONFIGURE_ENDPOINT << TRB_TYPE_SHIFT
                | TRB_INTERRUPT_ON_COMPLETION
                | u32::from(self.slot) << SLOT_ID_SHIFT,
        ]);
        let event = self.await_command()?;
        if completion_code(event) != CODE_SUCCESS {
            return Err(Error::ConfigureEndpointFailed);
        }
        Ok(())
    }

    /// Queue a report TRB so the keyboard's next interrupt has a buffer.
    fn arm_report(&mut self) {
        let [buf_lo, buf_hi] = dword(self.report_buffer as usize as u64);
        let block = &mut self.blocks.transfer_ring;
        let enqueue = &mut self.transfer_enqueue;
        let cycle = &mut self.transfer_cycle;
        Self::push_trb(
            block,
            TRANSFER_RING_TRBS,
            enqueue,
            cycle,
            [
                buf_lo,
                buf_hi,
                BOOT_REPORT_LEN as u32,
                TYPE_NORMAL << TRB_TYPE_SHIFT | TRB_INTERRUPT_ON_COMPLETION,
            ],
        );
        dmb();
        self.regs.ring_slot_doorbell(self.slot, self.endpoint_dci);
        self.armed = true;
    }

    /// Poll once for a completed keyboard report: `Some` with the 8 report
    /// bytes when the keyboard interrupted since the last poll, else `None`.
    /// The next report is armed immediately, so polling is free-running.
    pub fn poll_report(&mut self) -> Option<[u8; BOOT_REPORT_LEN]> {
        if !self.armed {
            self.arm_report();
        }
        let event = self.pop_event()?;
        if (event[3] >> TRB_TYPE_SHIFT) & 0x3f != TYPE_TRANSFER_EVENT
            || event_slot(event) != self.slot
        {
            return None;
        }
        self.retire_events();
        self.armed = false;
        if completion_code(event) != CODE_SUCCESS && completion_code(event) != CODE_SHORT_PACKET {
            return None;
        }
        invalidate_cache_range(self.report_buffer as usize, BOOT_REPORT_LEN);
        let mut report = [0u8; BOOT_REPORT_LEN];
        // SAFETY: the controller just completed a transfer into this buffer,
        // and the caller guaranteed it is valid for `report_capacity` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.report_buffer,
                report.as_mut_ptr(),
                BOOT_REPORT_LEN.min(self.report_capacity),
            )
        };
        self.arm_report();
        Some(report)
    }
}

/// Final TRB of a ring: link back to the ring start, toggling the cycle bit.
fn write_link_trb(block: &mut Block, trbs: usize) {
    let [lo, hi] = dword(block.dma_addr());
    block.write_trb(
        trbs - 1,
        [lo, hi, 0, TYPE_LINK << TRB_TYPE_SHIFT | TRB_SET_LINK],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trb_ring_cycles_and_links() {
        let mut block = Block::new();
        write_link_trb(&mut block, 4);
        let mut enqueue = 0;
        let mut cycle = true;
        XhciKeyboard::push_trb(&mut block, 4, &mut enqueue, &mut cycle, [1, 2, 3, 0]);
        XhciKeyboard::push_trb(&mut block, 4, &mut enqueue, &mut cycle, [4, 5, 6, 0]);
        XhciKeyboard::push_trb(&mut block, 4, &mut enqueue, &mut cycle, [7, 8, 9, 0]);
        assert_eq!((enqueue, cycle), (0, false));
        // Pushing past the link TRB wraps and flips the cycle bit.
        XhciKeyboard::push_trb(&mut block, 4, &mut enqueue, &mut cycle, [10, 11, 12, 0]);
        let link = block.read_trb(3);
        assert_eq!((link[3] >> TRB_TYPE_SHIFT) & 0x3f, TYPE_LINK);
        assert_eq!(link[3] & TRB_SET_LINK, TRB_SET_LINK);
        assert_eq!(link[3] & TRB_CYCLE, TRB_CYCLE);
        // First TRB of the second cycle has the flipped cycle bit (now 0).
        let first = block.read_trb(0);
        assert_eq!(first[..3], [10, 11, 12]);
        assert_eq!(first[3] & TRB_CYCLE, 0);
    }

    #[test]
    fn endpoint_dci_maps_interrupt_in_addresses() {
        let endpoint = |address| KeyboardEndpoint {
            port: 1,
            speed: 1,
            endpoint_address: address,
            max_packet_size: 8,
        };
        assert_eq!(endpoint(0x81).dci(), Some(3));
        assert_eq!(endpoint(0x82).dci(), Some(5));
        assert_eq!(endpoint(0x01).dci(), None);
        assert_eq!(endpoint(0x80).dci(), None);
    }

    #[test]
    fn setup_packet_endianness_matches_usb() {
        let setup = SetupPacket {
            request_type: 0x21,
            request: REQUEST_SET_PROTOCOL,
            value: PROTOCOL_BOOT,
            index: 0,
            length: 0,
        };
        assert_eq!(setup.low(), 0x0000_0b21);
        assert_eq!(setup.high(), 0);
    }
}
