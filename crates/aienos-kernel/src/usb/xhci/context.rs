//! Input contexts for Address Device, Evaluate Context and Configure
//! Endpoint (xHCI 1.2 section 6.2), plus the speed and interval rules the
//! driver needs to fill them.
//!
//! An input context is an Input Control Context followed by a Slot Context
//! and one Endpoint Context per device context index (DCI 1 is the default
//! control endpoint). Each is 32 bytes, or 64 when HCCPARAMS1.CSZ is set.

/// Port speed IDs from PORTSC (default Protocol Speed ID mapping).
pub mod speed {
    pub const FULL: u8 = 1;
    pub const LOW: u8 = 2;
    pub const HIGH: u8 = 3;
    pub const SUPER: u8 = 4;
}

/// Endpoint Context EP Type values.
pub const EP_TYPE_CONTROL: u8 = 4;
pub const EP_TYPE_INTERRUPT_IN: u8 = 7;
pub const EP_TYPE_ISOCH_OUT: u8 = 1;
/// Error count: retry a failing transaction three times before halting.
const CERR: u32 = 3;
/// Device context index of the default control endpoint.
pub const CONTROL_DCI: u8 = 1;
/// Highest device context index.
const MAX_DCI: u8 = 31;

/// Default control endpoint packet size before the device descriptor is read.
pub fn default_control_max_packet(port_speed: u8) -> u16 {
    match port_speed {
        speed::HIGH => 64,
        s if s >= speed::SUPER => 512,
        _ => 8,
    }
}

/// Endpoint Context Interval (period 125 us * 2^n) for an interrupt
/// endpoint's bInterval. Full and low speed give bInterval in 1 ms frames;
/// high and super speed already give it as 2^(bInterval - 1) microframes.
pub fn interrupt_interval(port_speed: u8, b_interval: u8) -> u8 {
    match port_speed {
        speed::FULL | speed::LOW => {
            let microframes = u32::from(b_interval.max(1)) * 8;
            (31 - microframes.leading_zeros()).clamp(3, 10) as u8
        }
        _ => b_interval.clamp(1, 16) - 1,
    }
}

/// Configure an isochronous OUT endpoint. `max_esit_payload` is the maximum
/// bytes sent in one service interval (including high-bandwidth multipliers).
pub fn isoch_out_endpoint(
    port_speed: u8,
    b_interval: u8,
    max_packet: u16,
    max_esit_payload: u16,
    dequeue: u64,
) -> EndpointConfig {
    EndpointConfig {
        ep_type: EP_TYPE_ISOCH_OUT,
        max_packet,
        interval: interrupt_interval(port_speed, b_interval),
        dequeue,
        average_trb_length: max_esit_payload,
        max_esit_payload,
    }
}

/// Device context index for a non-control endpoint address such as 0x81.
pub fn endpoint_dci(endpoint_address: u8) -> Option<u8> {
    let number = endpoint_address & 0x0f;
    if number == 0 {
        return None;
    }
    Some(number * 2 + u8::from(endpoint_address & 0x80 != 0))
}

/// What one Endpoint Context says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointConfig {
    pub ep_type: u8,
    pub max_packet: u16,
    pub interval: u8,
    /// TR Dequeue Pointer with the Dequeue Cycle State in bit 0.
    pub dequeue: u64,
    pub average_trb_length: u16,
    pub max_esit_payload: u16,
}

/// An input context being filled in caller-owned, zeroed memory.
pub struct InputContext<'a> {
    words: &'a mut [u32],
    stride: usize,
}

impl<'a> InputContext<'a> {
    /// Zero `words` and lay out an input context with `context_bytes`-sized
    /// entries. `None` for a size other than 32 or 64 or too little memory.
    pub fn new(words: &'a mut [u32], context_bytes: usize) -> Option<Self> {
        let stride = match context_bytes {
            32 => 8,
            64 => 16,
            _ => return None,
        };
        // Input control context, slot context and 31 endpoint contexts.
        if words.len() < stride * (usize::from(MAX_DCI) + 2) {
            return None;
        }
        words.fill(0);
        Some(Self { words, stride })
    }

    fn entry(&mut self, index: usize) -> &mut [u32] {
        let start = index * self.stride;
        &mut self.words[start..start + 8]
    }

    /// Add Context flags: bit 0 the slot context, bit n the endpoint of DCI n.
    pub fn add(&mut self, flags: u32) {
        self.entry(0)[1] = flags;
    }

    /// Slot Context for a device on root hub port `root_port` (1-based, no
    /// hub route) whose highest valid endpoint is `context_entries`.
    pub fn slot(&mut self, port_speed: u8, root_port: u8, context_entries: u8) {
        let slot = self.entry(1);
        slot[0] = u32::from(context_entries & 0x1f) << 27 | u32::from(port_speed & 0xf) << 20;
        slot[1] = u32::from(root_port) << 16;
    }

    /// Endpoint Context for `dci` (1..=31); other indexes are ignored.
    pub fn endpoint(&mut self, dci: u8, config: &EndpointConfig) {
        if !(1..=MAX_DCI).contains(&dci) {
            return;
        }
        let ep = self.entry(usize::from(dci) + 1);
        ep[0] = u32::from(config.interval) << 16;
        ep[1] =
            CERR << 1 | u32::from(config.ep_type & 0x7) << 3 | u32::from(config.max_packet) << 16;
        ep[2] = config.dequeue as u32;
        ep[3] = (config.dequeue >> 32) as u32;
        ep[4] = u32::from(config.average_trb_length) | u32::from(config.max_esit_payload) << 16;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_converts_frames_and_exponents_to_125us_units() {
        // QEMU usb-kbd: full speed, bInterval 7 ms -> 56 microframes -> 2^5.
        assert_eq!(interrupt_interval(speed::FULL, 7), 5);
        assert_eq!(interrupt_interval(speed::FULL, 10), 6);
        assert_eq!(interrupt_interval(speed::LOW, 1), 3);
        assert_eq!(interrupt_interval(speed::FULL, 255), 10);
        assert_eq!(interrupt_interval(speed::FULL, 0), 3);
        assert_eq!(interrupt_interval(speed::HIGH, 4), 3);
        assert_eq!(interrupt_interval(speed::SUPER, 0), 0);
        assert_eq!(interrupt_interval(speed::HIGH, 200), 15);
    }

    #[test]
    fn endpoint_addresses_map_to_device_context_indexes() {
        assert_eq!(endpoint_dci(0x81), Some(3));
        assert_eq!(endpoint_dci(0x82), Some(5));
        assert_eq!(endpoint_dci(0x01), Some(2));
        assert_eq!(endpoint_dci(0x8f), Some(31));
        assert_eq!(endpoint_dci(0x80), None);
        assert_eq!(default_control_max_packet(speed::LOW), 8);
        assert_eq!(default_control_max_packet(speed::HIGH), 64);
        assert_eq!(default_control_max_packet(speed::SUPER), 512);
    }

    #[test]
    fn address_device_context_puts_port_and_endpoint_zero_in_place() {
        let mut words = [0xdead_beef_u32; 8 * 33];
        let mut input = InputContext::new(&mut words, 32).unwrap();
        input.add(0b11);
        input.slot(speed::FULL, 5, 1);
        input.endpoint(
            CONTROL_DCI,
            &EndpointConfig {
                ep_type: EP_TYPE_CONTROL,
                max_packet: 8,
                interval: 0,
                dequeue: 0x4000_1000 | 1,
                average_trb_length: 8,
                max_esit_payload: 0,
            },
        );
        assert_eq!(words[1], 0b11, "add flags in the input control context");
        assert_eq!(words[0], 0, "no drop flags");
        // Slot context at 0x20: entries 1, full speed; root port in dword 1.
        assert_eq!(words[8], 1 << 27 | 1 << 20);
        assert_eq!(words[9], 5 << 16);
        // Endpoint 0 context at 0x40: CErr 3, type control, max packet 8.
        assert_eq!(words[17], 3 << 1 | 4 << 3 | 8 << 16);
        assert_eq!([words[18], words[19]], [0x4000_1001, 0]);
        assert_eq!(words[20], 8);
        assert!(words[21..].iter().all(|w| *w == 0), "memory was zeroed");
    }

    #[test]
    fn large_contexts_double_the_stride_and_bad_sizes_are_refused() {
        let mut words = [0u32; 16 * 33];
        let mut input = InputContext::new(&mut words, 64).unwrap();
        input.slot(speed::HIGH, 2, 3);
        input.endpoint(
            3,
            &EndpointConfig {
                ep_type: EP_TYPE_INTERRUPT_IN,
                max_packet: 8,
                interval: 6,
                dequeue: 0x2_0000_0001,
                average_trb_length: 8,
                max_esit_payload: 8,
            },
        );
        input.endpoint(
            0,
            &EndpointConfig {
                ep_type: 0,
                max_packet: 0,
                interval: 0,
                dequeue: u64::MAX,
                average_trb_length: 0,
                max_esit_payload: 0,
            },
        );
        assert_eq!(words[16], 3 << 27 | 3 << 20);
        assert_eq!(words[17], 2 << 16);
        let ep = 16 * 4; // DCI 3 is entry 4
        assert_eq!(words[ep], 6 << 16);
        assert_eq!(words[ep + 1], 3 << 1 | 7 << 3 | 8 << 16);
        assert_eq!([words[ep + 2], words[ep + 3]], [1, 2]);
        assert_eq!(words[ep + 4], 8 | 8 << 16);
        assert_eq!(
            words[18..32],
            [0; 14],
            "DCI 0 did not overwrite the slot context"
        );
        assert!(InputContext::new(&mut words, 48).is_none());
        assert!(InputContext::new(&mut words[..100], 32).is_none());
    }

    #[test]
    fn isochronous_out_endpoint_fields_encode_in_context() {
        let mut words = [0u32; 8 * 33];
        let mut input = InputContext::new(&mut words, 32).unwrap();
        input.endpoint(
            2,
            &isoch_out_endpoint(speed::HIGH, 4, 192, 192, 0x1234_5001),
        );
        let ep = 8 * 3;
        assert_eq!(words[ep], 3 << 16);
        assert_eq!(
            words[ep + 1],
            CERR << 1 | (EP_TYPE_ISOCH_OUT as u32) << 3 | 192 << 16
        );
        assert_eq!([words[ep + 2], words[ep + 3]], [0x1234_5001, 0]);
        assert_eq!(words[ep + 4], 192 | 192 << 16);
    }
}
