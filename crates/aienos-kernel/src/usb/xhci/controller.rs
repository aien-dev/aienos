//! Polled xHCI bring-up of one HID boot keyboard.
//!
//! Sequence: halt and reset the controller, program one command ring, one
//! event ring (interrupter 0, interrupts left disabled) and the device
//! context array, run it, then for each connected root port: reset the port,
//! Enable Slot, Address Device, read the device and configuration
//! descriptors, and if a boot keyboard is found SET_CONFIGURATION,
//! SET_PROTOCOL(boot), SET_IDLE(0) and Configure Endpoint for its
//! interrupt-IN endpoint. Reports are then read by polling the event ring.
//!
//! No interrupts, no exception-vector changes and no allocator (ADR 0009).
//! Every wait is bounded by the architectural counter, so a missing or
//! wedged controller costs a bounded delay and an error, never a hang.
//! All DMA memory is one caller-owned [`DmaMemory`], used at its identity
//! address and kept coherent with explicit cache maintenance.

use super::context::{
    default_control_max_packet, endpoint_dci, interrupt_interval, EndpointConfig, InputContext,
    CONTROL_DCI, EP_TYPE_CONTROL, EP_TYPE_INTERRUPT_IN,
};
use super::ring::{EventRing, ProducerRing};
use super::trb::{completion, kind, request, SetupPacket, Trb};
use super::{op, portsc, rt, Capabilities};
use crate::arch::aarch64::{
    clean_dcache_range, clean_invalidate_dcache_range, counter_frequency_hz, counter_ticks, MmioReg,
};
use crate::usb::descriptor::{control_max_packet, find_boot_keyboard, BootKeyboard};
use crate::usb::hid::BOOT_REPORT_LEN;
use core::fmt;
use core::ptr::{addr_of_mut, read_volatile, write_bytes, write_volatile};

const PAGE_BYTES: usize = 4096;
const RING_TRBS: usize = PAGE_BYTES / 16;
const REPORT_OFFSET: usize = 0;
const DESCRIPTOR_OFFSET: usize = 512;
const DESCRIPTOR_MAX: u16 = 255;

/// One 4 KiB page of DMA memory. Page alignment keeps every structure
/// inside one 64 KiB boundary, as the specification requires.
#[repr(C, align(4096))]
pub struct DmaPage([u32; PAGE_BYTES / 4]);

/// Every structure the controller reads or writes, one page each.
#[repr(C)]
pub struct DmaMemory {
    dcbaa: DmaPage,
    device_context: DmaPage,
    input_context: DmaPage,
    command_ring: DmaPage,
    event_ring: DmaPage,
    segment_table: DmaPage,
    control_ring: DmaPage,
    report_ring: DmaPage,
    buffer: DmaPage,
}

impl DmaMemory {
    pub const fn new() -> Self {
        const ZERO: DmaPage = DmaPage([0; PAGE_BYTES / 4]);
        Self {
            dcbaa: ZERO,
            device_context: ZERO,
            input_context: ZERO,
            command_ring: ZERO,
            event_ring: ZERO,
            segment_table: ZERO,
            control_ring: ZERO,
            report_ring: ZERO,
            buffer: ZERO,
        }
    }
}

impl Default for DmaMemory {
    fn default() -> Self {
        Self::new()
    }
}

/// Why no keyboard is available. Every variant is reached by a bounded path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Absent,
    Unsupported(&'static str),
    Timeout(&'static str),
    HostSystemError,
    CommandTimeout {
        step: &'static str,
        command_addr: u64,
        command_words: [u32; 4],
        dcbaap: u64,
        erstba: u64,
        erstsz: u32,
        crcr: u64,
        erdp: u64,
        usbcmd: u32,
        usbsts: u32,
        config: u32,
        last_event: [u32; 4],
    },
    Failed {
        step: &'static str,
        code: u8,
    },
    NoKeyboard,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => f.write_str("xHCI registers absent"),
            Self::Unsupported(what) => write!(f, "unsupported: {what}"),
            Self::Timeout(step) => write!(f, "timed out: {step}"),
            Self::CommandTimeout { step, command_addr, command_words, crcr, erdp, usbcmd, usbsts, config, last_event, .. } => write!(
                f,
                "timed out: {step}; cmd@{command_addr:#x}={command_words:08x?}; CRCR={crcr:#x} ERDP={erdp:#x} USBCMD={usbcmd:#x} USBSTS={usbsts:#x} CONFIG={config:#x} last_event={last_event:08x?}"
            ),
            Self::HostSystemError => f.write_str("host system error"),
            Self::Failed { step, code } => write!(f, "{step} failed (completion {code})"),
            Self::NoKeyboard => f.write_str("no boot keyboard on any connected port"),
        }
    }
}

/// Bounded wait: a time limit on the architectural counter, or a poll count
/// when the counter frequency is unknown.
struct Deadline {
    start: u64,
    ticks: u64,
    polls: u32,
}

impl Deadline {
    fn after_ms(ms: u64) -> Self {
        Self {
            start: counter_ticks(),
            ticks: counter_frequency_hz().saturating_mul(ms) / 1000,
            polls: 0,
        }
    }

    fn expired(&mut self) -> bool {
        self.polls = self.polls.saturating_add(1);
        if self.ticks == 0 {
            return self.polls > 1_000_000;
        }
        counter_ticks().wrapping_sub(self.start) > self.ticks
    }
}

fn write64(addr: usize, value: u64) {
    MmioReg::<u32>::new(addr).write(value as u32);
    MmioReg::<u32>::new(addr + 4).write((value >> 32) as u32);
}

/// A running controller with one attached boot keyboard.
pub struct Keyboard {
    op: usize,
    rt: usize,
    db: usize,
    mem: *mut DmaMemory,
    context_bytes: usize,
    commands: ProducerRing,
    events: EventRing,
    control: ProducerRing,
    reports: ProducerRing,
    slot: u8,
    last_event: [u32; 4],
    dci: u8,
    port: u8,
    device: Option<BootKeyboard>,
    retire_pending: bool,
    halted: bool,
}

impl Keyboard {
    /// Reset the controller at `mmio_base` and attach the first boot
    /// keyboard found on a root port.
    ///
    /// # Safety
    /// `mmio_base` must be the mapped register block of an xHCI controller
    /// with memory decode and bus mastering enabled that nothing else drives,
    /// and `mem` must be identity-mapped memory that stays valid and unused
    /// by anything else for as long as the returned driver or the controller
    /// may run.
    pub unsafe fn start(mmio_base: u64, mem: *mut DmaMemory) -> Result<Self, Error> {
        let base = mmio_base as usize;
        let cap = |offset: usize| MmioReg::<u32>::new(base + offset).read();
        let caps = Capabilities::decode(cap(0), cap(4), cap(8), cap(0x10), cap(0x14), cap(0x18))
            .ok_or(Error::Absent)?;
        if caps.scratchpad_pages != 0 {
            return Err(Error::Unsupported("controller asks for scratchpad pages"));
        }
        let end = mem as u64 + core::mem::size_of::<DmaMemory>() as u64;
        if !caps.addresses_64 && end > u64::from(u32::MAX) {
            return Err(Error::Unsupported(
                "DMA memory above 4 GiB on a 32-bit controller",
            ));
        }
        let op = base + caps.operational_offset;
        reset(op)?;

        // SAFETY: the caller hands `mem` over exclusively.
        unsafe { write_bytes(mem, 0, 1) };
        let page = |p: *mut DmaPage| (p as *mut Trb, p as u64);
        // SAFETY: each ring gets its own page inside `mem`.
        let (commands, events, control, reports) = unsafe {
            let (c, c_dma) = page(addr_of_mut!((*mem).command_ring));
            let (e, e_dma) = page(addr_of_mut!((*mem).event_ring));
            let (t, t_dma) = page(addr_of_mut!((*mem).control_ring));
            let (r, r_dma) = page(addr_of_mut!((*mem).report_ring));
            (
                ProducerRing::new(c, RING_TRBS, c_dma),
                EventRing::new(e, RING_TRBS, e_dma),
                ProducerRing::new(t, RING_TRBS, t_dma),
                ProducerRing::new(r, RING_TRBS, r_dma),
            )
        };
        let (Some(commands), Some(events), Some(control), Some(reports)) =
            (commands, events, control, reports)
        else {
            return Err(Error::Unsupported("ring memory"));
        };
        let mut keyboard = Self {
            op,
            rt: base + caps.runtime_offset,
            db: base + caps.doorbell_offset,
            mem,
            context_bytes: caps.context_bytes,
            commands,
            events,
            control,
            reports,
            slot: 0,
            dci: 0,
            port: 0,
            device: None,
            retire_pending: false,
            halted: false,
            last_event: [0; 4],
        };
        keyboard.run()?;

        let mut outcome = Err(Error::NoKeyboard);
        for port in 1..=caps.max_ports {
            let status = keyboard.op_reg(op::portsc(port)).read();
            if status & portsc::CONNECTED == 0 {
                continue;
            }
            outcome = keyboard.attach(port);
            if outcome.is_ok() {
                break;
            }
            if keyboard.slot != 0 {
                let slot = keyboard.slot;
                let _ = keyboard.command(Trb::disable_slot(slot), "Disable Slot");
                keyboard.slot = 0;
            }
        }
        outcome.map(|()| keyboard)
    }

    /// Root hub port, slot and interrupt-IN endpoint address of the keyboard.
    pub fn location(&self) -> (u8, u8, u8) {
        let endpoint = self.device.map_or(0, |d| d.endpoint_address);
        (self.port, self.slot, endpoint)
    }

    /// True once the report endpoint failed; no further reports arrive.
    pub fn is_halted(&self) -> bool {
        self.halted
    }

    fn op_reg(&self, offset: usize) -> MmioReg<u32> {
        MmioReg::new(self.op + offset)
    }

    fn run(&mut self) -> Result<(), Error> {
        let mem = self.mem;
        // SAFETY: pages of the exclusively owned DMA memory.
        let (dcbaa, segment_table) = unsafe {
            (
                addr_of_mut!((*mem).dcbaa),
                addr_of_mut!((*mem).segment_table),
            )
        };
        let entry = self.events.segment_table_entry();
        // SAFETY: the segment table page is ours; 4 dwords fit.
        unsafe { write_volatile(segment_table as *mut [u32; 4], entry) };
        self.sync_to_device();

        let config = self.op_reg(op::CONFIG);
        // One device slot is enough for one keyboard.
        config.write(config.read() & !0xff | 1);
        write64(self.op + op::DCBAAP, dcbaa as u64);
        write64(self.op + op::CRCR, self.commands.dequeue_pointer());
        MmioReg::<u32>::new(self.rt + rt::ERSTSZ).write(1);
        write64(self.rt + rt::ERDP, self.events.dequeue_pointer());
        write64(self.rt + rt::ERSTBA, segment_table as u64);

        let usbcmd = self.op_reg(op::USBCMD);
        usbcmd.write(usbcmd.read() | op::USBCMD_RUN);
        wait(Deadline::after_ms(100), || {
            self.op_reg(op::USBSTS).read() & op::USBSTS_HALTED == 0
        })
        .map_err(|()| Error::Timeout("controller run"))
    }

    fn reset_port(&mut self, port: u8) -> Result<u8, Error> {
        let reg = self.op_reg(op::portsc(port));
        let status = reg.read();
        if status & portsc::ENABLED == 0 {
            // USB 2 ports need a reset to enable; USB 3 ports train on their own.
            reg.write(portsc::neutral(status) | portsc::RESET);
            wait(Deadline::after_ms(500), || {
                reg.read() & portsc::RESET_CHANGE != 0
            })
            .map_err(|()| Error::Timeout("port reset"))?;
        }
        let status = reg.read();
        reg.write(portsc::neutral(status) | status & portsc::CHANGES);
        if status & portsc::ENABLED == 0 {
            return Err(Error::Unsupported("port did not enable"));
        }
        Ok(portsc::speed(status))
    }

    fn attach(&mut self, port: u8) -> Result<(), Error> {
        let speed = self.reset_port(port)?;
        self.port = port;
        let event = self.command(Trb::enable_slot(), "Enable Slot")?;
        self.slot = event.slot_id();
        if self.slot == 0 {
            return Err(Error::Unsupported("slot id"));
        }
        let mem = self.mem;
        // SAFETY: pages of the exclusively owned DMA memory; a slot ID (at
        // most 255) indexes inside the 512-entry DCBAA page.
        unsafe {
            let device_context = addr_of_mut!((*mem).device_context);
            write_bytes(device_context, 0, 1);
            let dcbaa = addr_of_mut!((*mem).dcbaa) as *mut u64;
            write_volatile(dcbaa.add(usize::from(self.slot)), device_context as u64);
            let ring = addr_of_mut!((*mem).control_ring);
            self.control = ProducerRing::new(ring as *mut Trb, RING_TRBS, ring as u64)
                .ok_or(Error::Unsupported("ring memory"))?;
        }

        let mut max_packet = default_control_max_packet(speed);
        self.control_context(speed, max_packet, 0b11, 1);
        self.slot_command(Trb::address_device, "Address Device")?;

        let device = self.control_in(
            SetupPacket::get_descriptor(request::DESCRIPTOR_DEVICE, 0, 8),
            "GET_DESCRIPTOR(device)",
        )?;
        let reported = control_max_packet(&device[..8]).map_or(max_packet, |size| {
            if speed >= super::context::speed::SUPER {
                1 << size.min(9)
            } else {
                u16::from(size)
            }
        });
        if reported != max_packet {
            max_packet = reported;
            self.control_context(speed, max_packet, 0b10, 1);
            self.slot_command(Trb::evaluate_context, "Evaluate Context")?;
        }

        let config = self.control_in(
            SetupPacket::get_descriptor(request::DESCRIPTOR_CONFIGURATION, 0, DESCRIPTOR_MAX),
            "GET_DESCRIPTOR(configuration)",
        )?;
        let keyboard = find_boot_keyboard(&config).ok_or(Error::NoKeyboard)?;
        let dci = endpoint_dci(keyboard.endpoint_address).ok_or(Error::NoKeyboard)?;
        self.control_transfer(
            SetupPacket::set_configuration(keyboard.configuration),
            "SET_CONFIGURATION",
        )?;
        self.control_transfer(
            SetupPacket::set_boot_protocol(keyboard.interface),
            "SET_PROTOCOL",
        )?;
        // Keyboards may stall SET_IDLE; unchanged reports are then ignored
        // by the decoder anyway.
        let _ = self.control_transfer(
            SetupPacket::set_idle_forever(keyboard.interface),
            "SET_IDLE",
        );

        let (dequeue, bytes) = (self.reports.dequeue_pointer(), self.context_bytes);
        let mut input = InputContext::new(self.input_context(), bytes)
            .ok_or(Error::Unsupported("context size"))?;
        input.add(1 | 1 << dci);
        input.slot(speed, port, dci);
        input.endpoint(
            dci,
            &EndpointConfig {
                ep_type: EP_TYPE_INTERRUPT_IN,
                max_burst: 0,
                max_packet: keyboard.max_packet,
                interval: interrupt_interval(speed, keyboard.interval),
                dequeue,
                average_trb_length: BOOT_REPORT_LEN as u16,
                max_esit_payload: keyboard.max_packet,
            },
        );
        self.slot_command(Trb::configure_endpoint, "Configure Endpoint")?;
        self.dci = dci;
        self.device = Some(keyboard);
        self.arm();
        Ok(())
    }

    fn input_context(&mut self) -> &mut [u32] {
        // SAFETY: the input context page is only touched here, between
        // commands, while the controller is not reading it.
        unsafe { &mut (*addr_of_mut!((*self.mem).input_context)).0 }
    }

    fn control_context(&mut self, speed: u8, max_packet: u16, add: u32, entries: u8) {
        let dequeue = self.control.dequeue_pointer();
        let (port, bytes) = (self.port, self.context_bytes);
        if let Some(mut input) = InputContext::new(self.input_context(), bytes) {
            input.add(add);
            input.slot(speed, port, entries);
            input.endpoint(
                CONTROL_DCI,
                &EndpointConfig {
                    ep_type: EP_TYPE_CONTROL,
                    max_burst: 0,
                    max_packet,
                    interval: 0,
                    dequeue,
                    average_trb_length: 8,
                    max_esit_payload: 0,
                },
            );
        }
    }

    fn slot_command(&mut self, build: fn(u64, u8) -> Trb, step: &'static str) -> Result<(), Error> {
        // SAFETY: address of a page of the owned DMA memory.
        let input = unsafe { addr_of_mut!((*self.mem).input_context) } as u64;
        self.command(build(input, self.slot), step).map(|_| ())
    }

    fn doorbell(&self, target: u8, value: u8) {
        MmioReg::<u32>::new(self.db + usize::from(target) * 4).write(u32::from(value));
    }

    fn command(&mut self, trb: Trb, step: &'static str) -> Result<Trb, Error> {
        let addr = self.commands.push(trb);
        let command_words = unsafe { read_volatile(addr as *const Trb) }.0;
        self.sync_to_device();
        self.doorbell(0, 0);
        let event = self
            .wait_event(step, |e| {
                e.kind() == kind::COMMAND_COMPLETION && e.pointer() == addr
            })
            .map_err(|error| match error {
                Error::Timeout(_) => Error::CommandTimeout {
                    step,
                    command_addr: addr,
                    command_words,
                    dcbaap: unsafe { read_volatile((self.op + op::DCBAAP) as *const u64) },
                    erstba: unsafe { read_volatile((self.rt + rt::ERSTBA) as *const u64) },
                    erstsz: MmioReg::<u32>::new(self.rt + rt::ERSTSZ).read(),
                    crcr: unsafe { read_volatile((self.op + op::CRCR) as *const u64) },
                    erdp: unsafe { read_volatile((self.rt + rt::ERDP) as *const u64) },
                    usbcmd: self.op_reg(op::USBCMD).read(),
                    usbsts: self.op_reg(op::USBSTS).read(),
                    config: self.op_reg(op::CONFIG).read(),
                    last_event: self.last_event,
                },
                other => other,
            })?;
        match event.completion_code() {
            completion::SUCCESS => Ok(event),
            code => Err(Error::Failed { step, code }),
        }
    }

    fn control_in(
        &mut self,
        setup: SetupPacket,
        step: &'static str,
    ) -> Result<[u8; DESCRIPTOR_MAX as usize], Error> {
        let buffer = self.buffer_ptr(DESCRIPTOR_OFFSET);
        // SAFETY: the descriptor area lies inside the owned buffer page.
        unsafe { write_bytes(buffer, 0, usize::from(DESCRIPTOR_MAX)) };
        self.control_transfer(setup, step)?;
        let mut bytes = [0u8; DESCRIPTOR_MAX as usize];
        for (i, b) in bytes.iter_mut().enumerate() {
            // SAFETY: as above; the controller finished writing.
            *b = unsafe { read_volatile(buffer.add(i)) };
        }
        Ok(bytes)
    }

    fn control_transfer(&mut self, setup: SetupPacket, step: &'static str) -> Result<(), Error> {
        let buffer = self.buffer_ptr(DESCRIPTOR_OFFSET) as u64;
        self.control.push(Trb::setup_stage(&setup));
        if setup.length > 0 {
            self.control.push(Trb::data_stage(&setup, buffer));
        }
        let status = self.control.push(Trb::status_stage(&setup));
        self.sync_to_device();
        self.doorbell(self.slot, CONTROL_DCI);
        let slot = self.slot;
        let event = self.wait_event(step, |e| {
            e.kind() == kind::TRANSFER_EVENT
                && e.slot_id() == slot
                && e.endpoint_id() == CONTROL_DCI
                && (e.pointer() == status || !e.completed_ok())
        })?;
        if !event.completed_ok() {
            return Err(Error::Failed {
                step,
                code: event.completion_code(),
            });
        }
        Ok(())
    }

    fn buffer_ptr(&self, offset: usize) -> *mut u8 {
        // SAFETY: address arithmetic inside the owned buffer page.
        unsafe { (addr_of_mut!((*self.mem).buffer) as *mut u8).add(offset) }
    }

    /// Queue one report transfer on the interrupt-IN endpoint.
    fn arm(&mut self) {
        let buffer = self.buffer_ptr(REPORT_OFFSET) as u64;
        self.reports
            .push(Trb::normal(buffer, BOOT_REPORT_LEN as u32));
        self.sync_to_device();
        self.doorbell(self.slot, self.dci);
    }

    /// Consume pending events; return a completed keyboard report, if any.
    /// Other events (port changes, stray completions) are retired and dropped.
    pub fn poll(&mut self) -> Option<[u8; BOOT_REPORT_LEN]> {
        if self.halted {
            return None;
        }
        self.sync_from_device();
        let mut report = None;
        while let Some(event) = self.events.pop() {
            self.retire_pending = true;
            let ours = event.kind() == kind::TRANSFER_EVENT
                && event.slot_id() == self.slot
                && event.endpoint_id() == self.dci;
            if !ours {
                continue;
            }
            if !event.completed_ok() {
                // The endpoint halted; recovering it is not attempted.
                self.halted = true;
                break;
            }
            if event.residual() == 0 {
                let buffer = self.buffer_ptr(REPORT_OFFSET);
                let mut bytes = [0u8; BOOT_REPORT_LEN];
                for (i, b) in bytes.iter_mut().enumerate() {
                    // SAFETY: the report area lies inside the owned buffer page.
                    *b = unsafe { read_volatile(buffer.add(i)) };
                }
                report = Some(bytes);
            }
            self.arm();
            break;
        }
        self.retire();
        report
    }

    fn wait_event(
        &mut self,
        step: &'static str,
        wanted: impl Fn(&Trb) -> bool,
    ) -> Result<Trb, Error> {
        let mut deadline = Deadline::after_ms(1000);
        loop {
            self.sync_from_device();
            while let Some(event) = self.events.pop() {
                self.retire_pending = true;
                self.last_event = event.0;
                if wanted(&event) {
                    self.retire();
                    return Ok(event);
                }
            }
            self.retire();
            if self.op_reg(op::USBSTS).read() & op::USBSTS_HOST_ERROR != 0 {
                return Err(Error::HostSystemError);
            }
            if deadline.expired() {
                return Err(Error::Timeout(step));
            }
            core::hint::spin_loop();
        }
    }

    /// Tell the controller how far the event ring was consumed.
    fn retire(&mut self) {
        if self.retire_pending {
            write64(
                self.rt + rt::ERDP,
                self.events.dequeue_pointer() | rt::ERDP_BUSY,
            );
            self.retire_pending = false;
        }
    }

    /// Make CPU writes to the DMA memory visible to the controller.
    fn sync_to_device(&self) {
        clean_dcache_range(self.mem as usize, core::mem::size_of::<DmaMemory>());
    }

    /// Drop stale cached copies of what the controller writes.
    fn sync_from_device(&self) {
        // SAFETY: addresses of pages of the owned DMA memory.
        let (events, buffer) = unsafe {
            (
                addr_of_mut!((*self.mem).event_ring),
                addr_of_mut!((*self.mem).buffer),
            )
        };
        clean_invalidate_dcache_range(events as usize, PAGE_BYTES);
        clean_invalidate_dcache_range(buffer as usize, PAGE_BYTES);
    }
}

fn wait(mut deadline: Deadline, mut done: impl FnMut() -> bool) -> Result<(), ()> {
    while !done() {
        if deadline.expired() {
            return Err(());
        }
        core::hint::spin_loop();
    }
    Ok(())
}

/// Stop the controller, reset it and wait until it is ready for setup.
fn reset(op: usize) -> Result<(), Error> {
    let usbcmd = MmioReg::<u32>::new(op + op::USBCMD);
    let usbsts = MmioReg::<u32>::new(op + op::USBSTS);
    if usbsts.read() == u32::MAX {
        return Err(Error::Absent);
    }
    usbcmd.write(usbcmd.read() & !op::USBCMD_RUN);
    wait(Deadline::after_ms(100), || {
        usbsts.read() & op::USBSTS_HALTED != 0
    })
    .map_err(|()| Error::Timeout("controller halt"))?;
    usbcmd.write(op::USBCMD_RESET);
    wait(Deadline::after_ms(1000), || {
        usbcmd.read() & op::USBCMD_RESET == 0 && usbsts.read() & op::USBSTS_NOT_READY == 0
    })
    .map_err(|()| Error::Timeout("controller reset"))
}
