//! Transfer Request Blocks (xHCI 1.2 section 6.4): the 16-byte records that
//! commands, transfers and events are made of, and the USB SETUP packet a
//! control transfer carries.
//!
//! Only the TRB types the polled keyboard driver needs are built here. The
//! cycle bit is left clear; the ring that writes a TRB owns that bit.

/// TRB type numbers (xHCI 1.2 table 6-91).
pub mod kind {
    pub const NORMAL: u8 = 1;
    pub const SETUP_STAGE: u8 = 2;
    pub const DATA_STAGE: u8 = 3;
    pub const STATUS_STAGE: u8 = 4;
    pub const ISOCH: u8 = 5;
    pub const LINK: u8 = 6;
    pub const ENABLE_SLOT: u8 = 9;
    pub const DISABLE_SLOT: u8 = 10;
    pub const ADDRESS_DEVICE: u8 = 11;
    pub const CONFIGURE_ENDPOINT: u8 = 12;
    pub const EVALUATE_CONTEXT: u8 = 13;
    pub const TRANSFER_EVENT: u8 = 32;
    pub const COMMAND_COMPLETION: u8 = 33;
    pub const PORT_STATUS_CHANGE: u8 = 34;
}

/// Completion codes the driver treats as success (xHCI 1.2 table 6-90).
pub mod completion {
    pub const SUCCESS: u8 = 1;
    pub const SHORT_PACKET: u8 = 13;
}

/// Control dword (dword 3) flags.
pub const CYCLE: u32 = 1 << 0;
/// Link TRB: toggle the consumer cycle state when following this link.
pub const TOGGLE_CYCLE: u32 = 1 << 1;
/// Interrupt on short packet: report a short IN transfer on this TRB.
pub const ISP: u32 = 1 << 2;
/// Interrupt on completion: post an event when this TRB completes.
pub const IOC: u32 = 1 << 5;
/// Continue a transfer descriptor on the next TRB.
pub const CHAIN: u32 = 1 << 4;
/// Immediate data: the parameter dwords hold the data (Setup Stage only).
pub const IDT: u32 = 1 << 6;
/// Data and Status Stage direction bit: set for device-to-host.
pub const DIR_IN: u32 = 1 << 16;
const TYPE_SHIFT: u32 = 10;
const SLOT_SHIFT: u32 = 24;
/// Setup Stage transfer type (TRT) values, bits 17:16.
const TRT_OUT: u32 = 2 << 16;
const TRT_IN: u32 = 3 << 16;
/// Isoch TRB Schedule Immediately, used when Frame ID is not selected.
pub const SIA: u32 = 1 << 31;

/// One 16-byte TRB as four little-endian dwords.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Trb(pub [u32; 4]);

fn split(addr: u64) -> (u32, u32) {
    (addr as u32, (addr >> 32) as u32)
}

impl Trb {
    fn new(parameter: u64, status: u32, trb_type: u8, flags: u32) -> Self {
        let (lo, hi) = split(parameter);
        Self([lo, hi, status, u32::from(trb_type) << TYPE_SHIFT | flags])
    }

    fn for_slot(parameter: u64, trb_type: u8, slot: u8) -> Self {
        Self::new(parameter, 0, trb_type, u32::from(slot) << SLOT_SHIFT)
    }

    /// Link TRB back to `target` (the ring start), toggling the cycle state.
    pub fn link(target: u64) -> Self {
        Self::new(target, 0, kind::LINK, TOGGLE_CYCLE)
    }

    pub fn enable_slot() -> Self {
        Self::new(0, 0, kind::ENABLE_SLOT, 0)
    }

    pub fn disable_slot(slot: u8) -> Self {
        Self::for_slot(0, kind::DISABLE_SLOT, slot)
    }

    /// Address Device with the input context at `input_context`. Block Set
    /// Address Request is clear, so the device receives SET_ADDRESS.
    pub fn address_device(input_context: u64, slot: u8) -> Self {
        Self::for_slot(input_context, kind::ADDRESS_DEVICE, slot)
    }

    pub fn configure_endpoint(input_context: u64, slot: u8) -> Self {
        Self::for_slot(input_context, kind::CONFIGURE_ENDPOINT, slot)
    }

    pub fn evaluate_context(input_context: u64, slot: u8) -> Self {
        Self::for_slot(input_context, kind::EVALUATE_CONTEXT, slot)
    }

    /// Setup Stage: the 8-byte SETUP packet as immediate data.
    pub fn setup_stage(setup: &SetupPacket) -> Self {
        let trt = match (setup.length, setup.is_in()) {
            (0, _) => 0,
            (_, true) => TRT_IN,
            (_, false) => TRT_OUT,
        };
        let [lo, hi] = setup.dwords();
        Self([
            lo,
            hi,
            8,
            u32::from(kind::SETUP_STAGE) << TYPE_SHIFT | IDT | trt,
        ])
    }

    /// Data Stage of `setup.length` bytes at `buffer`.
    pub fn data_stage(setup: &SetupPacket, buffer: u64) -> Self {
        let dir = if setup.is_in() { DIR_IN } else { 0 };
        Self::new(buffer, u32::from(setup.length), kind::DATA_STAGE, dir)
    }

    /// Status Stage, which runs opposite to the data (IN when there is none),
    /// with an event on completion.
    pub fn status_stage(setup: &SetupPacket) -> Self {
        let dir = if setup.length > 0 && setup.is_in() {
            0
        } else {
            DIR_IN
        };
        Self::new(0, 0, kind::STATUS_STAGE, dir | IOC)
    }

    /// Normal TRB for an interrupt-IN report of up to `length` bytes, with an
    /// event on completion or on a short report.
    pub fn normal(buffer: u64, length: u32) -> Self {
        Self::new(buffer, length & 0x1_ffff, kind::NORMAL, IOC | ISP)
    }

    /// One isochronous OUT packet. SuperSpeed TBC/TLBPC are zero for an
    /// endpoint without a companion descriptor; `last` terminates the batch.
    pub fn isoch(buffer: u64, length: u32, frame_id: u16, sia: bool, last: bool) -> Self {
        let mut flags =
            (u32::from(frame_id & 0x7ff) << 20) | (u32::from(kind::ISOCH) << TYPE_SHIFT);
        if sia {
            flags |= SIA;
        }
        if last {
            flags |= IOC;
        } else {
            flags |= CHAIN;
        }
        Self::new(buffer, length & 0x1_ffff, kind::ISOCH, flags & !(0x7 << 7))
    }

    pub fn kind(&self) -> u8 {
        ((self.0[3] >> TYPE_SHIFT) & 0x3f) as u8
    }

    pub fn cycle(&self) -> bool {
        self.0[3] & CYCLE != 0
    }

    /// The same TRB with its cycle bit set to `cycle`.
    pub fn with_cycle(mut self, cycle: bool) -> Self {
        self.0[3] = self.0[3] & !CYCLE | u32::from(cycle);
        self
    }

    /// Event TRBs: completion code, bits 31:24 of dword 2.
    pub fn completion_code(&self) -> u8 {
        (self.0[2] >> 24) as u8
    }

    /// Event and slot-command TRBs: slot ID, bits 31:24 of dword 3.
    pub fn slot_id(&self) -> u8 {
        (self.0[3] >> SLOT_SHIFT) as u8
    }

    /// Transfer events: endpoint (device context index), bits 20:16.
    pub fn endpoint_id(&self) -> u8 {
        ((self.0[3] >> 16) & 0x1f) as u8
    }

    /// Events: the TRB (or port) the event refers to, from dwords 0 and 1.
    pub fn pointer(&self) -> u64 {
        u64::from(self.0[1]) << 32 | u64::from(self.0[0])
    }

    /// Transfer events: bytes not transferred, bits 23:0 of dword 2.
    pub fn residual(&self) -> u32 {
        self.0[2] & 0x00ff_ffff
    }

    /// True for a completion code the driver accepts as a good transfer.
    pub fn completed_ok(&self) -> bool {
        matches!(
            self.completion_code(),
            completion::SUCCESS | completion::SHORT_PACKET
        )
    }
}

/// Standard and HID class request numbers the keyboard bring-up sends.
pub mod request {
    pub const GET_DESCRIPTOR: u8 = 0x06;
    pub const SET_CONFIGURATION: u8 = 0x09;
    pub const HID_SET_IDLE: u8 = 0x0a;
    pub const HID_SET_PROTOCOL: u8 = 0x0b;
    pub const DESCRIPTOR_DEVICE: u8 = 1;
    pub const DESCRIPTOR_CONFIGURATION: u8 = 2;
}

/// The 8-byte USB SETUP packet (USB 2.0 section 9.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupPacket {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

impl SetupPacket {
    /// Standard GET_DESCRIPTOR from the device.
    pub fn get_descriptor(descriptor_type: u8, index: u8, length: u16) -> Self {
        Self {
            request_type: 0x80,
            request: request::GET_DESCRIPTOR,
            value: u16::from(descriptor_type) << 8 | u16::from(index),
            index: 0,
            length,
        }
    }

    pub fn set_configuration(value: u8) -> Self {
        Self {
            request_type: 0x00,
            request: request::SET_CONFIGURATION,
            value: u16::from(value),
            index: 0,
            length: 0,
        }
    }

    /// HID SET_PROTOCOL(boot) to `interface`, so reports use the 8-byte boot
    /// layout whatever the report descriptor says.
    pub fn set_boot_protocol(interface: u8) -> Self {
        Self {
            request_type: 0x21,
            request: request::HID_SET_PROTOCOL,
            value: 0,
            index: u16::from(interface),
            length: 0,
        }
    }

    /// HID SET_IDLE(0): report only on change, never repeat unchanged state.
    pub fn set_idle_forever(interface: u8) -> Self {
        Self {
            request_type: 0x21,
            request: request::HID_SET_IDLE,
            value: 0,
            index: u16::from(interface),
            length: 0,
        }
    }

    pub fn is_in(&self) -> bool {
        self.request_type & 0x80 != 0
    }

    /// The packet as the two little-endian dwords of a Setup Stage TRB.
    pub fn dwords(&self) -> [u32; 2] {
        [
            u32::from(self.request_type)
                | u32::from(self.request) << 8
                | u32::from(self.value) << 16,
            u32::from(self.index) | u32::from(self.length) << 16,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trb_is_sixteen_bytes_and_sixteen_aligned() {
        assert_eq!(core::mem::size_of::<Trb>(), 16);
        assert_eq!(core::mem::align_of::<Trb>(), 16);
    }

    #[test]
    fn setup_packet_bytes_match_the_usb_wire_order() {
        // GET_DESCRIPTOR(device, 18): 80 06 00 01 00 00 12 00.
        let get = SetupPacket::get_descriptor(request::DESCRIPTOR_DEVICE, 0, 18);
        assert_eq!(get.dwords(), [0x0100_0680, 0x0012_0000]);
        // SET_PROTOCOL(boot) on interface 1: 21 0b 00 00 01 00 00 00.
        assert_eq!(
            SetupPacket::set_boot_protocol(1).dwords(),
            [0x0000_0b21, 0x0000_0001]
        );
        assert_eq!(SetupPacket::set_configuration(1).dwords(), [0x0001_0900, 0]);
    }

    #[test]
    fn control_stages_carry_idt_transfer_type_and_directions() {
        let get = SetupPacket::get_descriptor(request::DESCRIPTOR_CONFIGURATION, 0, 64);
        let setup = Trb::setup_stage(&get);
        assert_eq!(setup.kind(), kind::SETUP_STAGE);
        assert_eq!(setup.0[2], 8, "setup TRB transfer length is always 8");
        assert_ne!(setup.0[3] & IDT, 0, "setup data is immediate");
        assert_eq!(setup.0[3] & (3 << 16), TRT_IN);
        let data = Trb::data_stage(&get, 0x1234_5678_9abc_def0);
        assert_eq!(data.kind(), kind::DATA_STAGE);
        assert_eq!(data.pointer(), 0x1234_5678_9abc_def0);
        assert_eq!(data.0[2], 64);
        assert_ne!(data.0[3] & DIR_IN, 0);
        let status = Trb::status_stage(&get);
        assert_eq!(status.kind(), kind::STATUS_STAGE);
        assert_eq!(status.0[3] & DIR_IN, 0, "status runs OUT after IN data");
        assert_ne!(status.0[3] & IOC, 0);

        let none = SetupPacket::set_configuration(1);
        assert_eq!(Trb::setup_stage(&none).0[3] & (3 << 16), 0, "no data stage");
        assert_ne!(Trb::status_stage(&none).0[3] & DIR_IN, 0, "status IN");
    }

    #[test]
    fn command_trbs_place_slot_and_input_context() {
        let address = Trb::address_device(0x8000_1000, 3);
        assert_eq!(address.kind(), kind::ADDRESS_DEVICE);
        assert_eq!(address.slot_id(), 3);
        assert_eq!(address.pointer(), 0x8000_1000);
        assert_eq!(Trb::enable_slot().0, [0, 0, 0, 9 << 10]);
        assert_eq!(
            Trb::configure_endpoint(0x40, 1).kind(),
            kind::CONFIGURE_ENDPOINT
        );
        assert_eq!(
            Trb::evaluate_context(0x40, 1).kind(),
            kind::EVALUATE_CONTEXT
        );
        assert_eq!(Trb::disable_slot(2).slot_id(), 2);
    }

    #[test]
    fn event_fields_decode_from_their_bit_positions() {
        // Transfer event: TRB pointer, residual 3, short packet, EP 3, slot 1.
        let event = Trb([0x1000, 0x2, 13 << 24 | 3, 1 << 24 | 3 << 16 | 32 << 10 | 1]);
        assert_eq!(event.kind(), kind::TRANSFER_EVENT);
        assert_eq!(event.pointer(), 0x2_0000_1000);
        assert_eq!(event.residual(), 3);
        assert_eq!(event.completion_code(), completion::SHORT_PACKET);
        assert!(event.completed_ok());
        assert_eq!(event.endpoint_id(), 3);
        assert_eq!(event.slot_id(), 1);
        assert!(event.cycle());
        assert!(!event.with_cycle(false).cycle());
        // Stall (code 6) is not a good completion.
        assert!(!Trb([0, 0, 6 << 24, 0]).completed_ok());
    }

    #[test]
    fn normal_trb_asks_for_an_event_on_short_reports() {
        let normal = Trb::normal(0x9000, 8);
        assert_eq!(normal.kind(), kind::NORMAL);
        assert_eq!(normal.0[2], 8);
        assert_eq!(normal.0[3] & (IOC | ISP), IOC | ISP);
        let link = Trb::link(0x4000);
        assert_eq!(link.kind(), kind::LINK);
        assert_ne!(link.0[3] & TOGGLE_CYCLE, 0);
    }

    #[test]
    fn isoch_trb_encodes_frame_id_and_batch_flags() {
        let first = Trb::isoch(0x1234_5678_9abc_def0, 176, 0x456, false, false);
        assert_eq!(first.kind(), kind::ISOCH);
        assert_eq!(first.pointer(), 0x1234_5678_9abc_def0);
        assert_eq!(first.0[2], 176);
        assert_eq!((first.0[3] >> 20) & 0x7ff, 0x456);
        assert_ne!(first.0[3] & CHAIN, 0);
        assert_eq!(first.0[3] & IOC, 0);
        assert_eq!(first.0[3] & (7 << 7), 0, "SuperSpeed companion fields zero");
        let last = Trb::isoch(0x2000, 180, 7, true, true);
        assert_ne!(last.0[3] & SIA, 0);
        assert_ne!(last.0[3] & IOC, 0);
        assert_eq!(last.0[3] & CHAIN, 0);
    }
}
