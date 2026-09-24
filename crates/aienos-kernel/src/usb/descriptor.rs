//! USB descriptor parsing for keyboard bring-up (USB 2.0 section 9.6, HID
//! 1.11 appendix B): the device descriptor's control packet size and the
//! boot keyboard interface inside a configuration descriptor.

const DESCRIPTOR_DEVICE: u8 = 1;
const DESCRIPTOR_CONFIGURATION: u8 = 2;
const DESCRIPTOR_INTERFACE: u8 = 4;
const DESCRIPTOR_ENDPOINT: u8 = 5;
const CLASS_HID: u8 = 3;
const SUBCLASS_BOOT: u8 = 1;
const PROTOCOL_KEYBOARD: u8 = 1;
const TRANSFER_INTERRUPT: u8 = 3;

/// bMaxPacketSize0 from the first 8 bytes of a device descriptor.
pub fn control_max_packet(device_descriptor: &[u8]) -> Option<u8> {
    match device_descriptor {
        [len, DESCRIPTOR_DEVICE, _, _, _, _, _, size, ..] if *len >= 8 && *size > 0 => Some(*size),
        _ => None,
    }
}

/// Where a boot-protocol keyboard's reports come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootKeyboard {
    /// bConfigurationValue to pass to SET_CONFIGURATION.
    pub configuration: u8,
    pub interface: u8,
    /// Interrupt-IN endpoint address, for example 0x81.
    pub endpoint_address: u8,
    pub max_packet: u16,
    /// bInterval as the device states it.
    pub interval: u8,
}

/// First boot keyboard interface (class 3, subclass 1, protocol 1) with an
/// interrupt-IN endpoint in a configuration descriptor and what follows it.
/// Parsing stops at wTotalLength or the end of `bytes`, whichever is first,
/// and at any descriptor whose length is impossible.
pub fn find_boot_keyboard(bytes: &[u8]) -> Option<BootKeyboard> {
    if bytes.len() < 9 || bytes[0] < 9 || bytes[1] != DESCRIPTOR_CONFIGURATION {
        return None;
    }
    let total = usize::from(u16::from_le_bytes([bytes[2], bytes[3]])).min(bytes.len());
    let configuration = bytes[5];
    let mut interface = None;
    let mut at = 0;
    while at + 2 <= total {
        let len = usize::from(bytes[at]);
        if len < 2 || at + len > total {
            return None;
        }
        let d = &bytes[at..at + len];
        match d[1] {
            DESCRIPTOR_INTERFACE if len >= 9 => {
                let keyboard =
                    d[5] == CLASS_HID && d[6] == SUBCLASS_BOOT && d[7] == PROTOCOL_KEYBOARD;
                interface = keyboard.then_some(d[2]);
            }
            DESCRIPTOR_ENDPOINT if len >= 7 => {
                let is_in = d[2] & 0x80 != 0;
                if let (Some(interface), true, TRANSFER_INTERRUPT) = (interface, is_in, d[3] & 0x3)
                {
                    return Some(BootKeyboard {
                        configuration,
                        interface,
                        endpoint_address: d[2],
                        max_packet: u16::from_le_bytes([d[4], d[5]]) & 0x7ff,
                        interval: d[6],
                    });
                }
            }
            _ => {}
        }
        at += len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Configuration descriptor QEMU 8.2.2 usb-kbd returned to the driver in
    /// the QEMU keyboard test: config, interface, HID, endpoint 0x81.
    const KEYBOARD: [u8; 34] = [
        9, 2, 34, 0, 1, 1, 8, 0xa0, 50, //
        9, 4, 0, 0, 1, 3, 1, 1, 0, //
        9, 0x21, 0x11, 0x01, 0, 1, 0x22, 63, 0, //
        7, 5, 0x81, 3, 8, 0, 7,
    ];

    #[test]
    fn finds_the_keyboard_interrupt_in_endpoint() {
        assert_eq!(
            find_boot_keyboard(&KEYBOARD),
            Some(BootKeyboard {
                configuration: 1,
                interface: 0,
                endpoint_address: 0x81,
                max_packet: 8,
                interval: 7,
            })
        );
    }

    #[test]
    fn skips_a_mouse_interface_and_out_endpoints_in_a_composite_device() {
        let composite: [u8; 50] = [
            9, 2, 50, 0, 2, 2, 0, 0xa0, 50, //
            9, 4, 0, 0, 1, 3, 1, 2, 0, // boot mouse
            7, 5, 0x81, 3, 4, 0, 10, //
            9, 4, 1, 0, 2, 3, 1, 1, 0, // boot keyboard
            7, 5, 0x02, 3, 8, 0, 10, // interrupt OUT (LEDs): not this
            9, 0x21, 0x11, 0x01, 0, 1, 0x22, 63, 0,
        ];
        let mut with_endpoint = [0u8; 57];
        with_endpoint[..50].copy_from_slice(&composite);
        with_endpoint[50..].copy_from_slice(&[7, 5, 0x83, 3, 8, 0, 4]);
        with_endpoint[2] = 57;
        let found = find_boot_keyboard(&with_endpoint).unwrap();
        assert_eq!((found.configuration, found.interface), (2, 1));
        assert_eq!(found.endpoint_address, 0x83);
        assert_eq!(found.interval, 4);
        assert_eq!(
            find_boot_keyboard(&composite),
            None,
            "mouse only, no keyboard IN"
        );
    }

    #[test]
    fn stops_at_total_length_and_malformed_descriptors() {
        let mut short_total = KEYBOARD;
        short_total[2] = 27; // total length excludes the endpoint
        assert_eq!(find_boot_keyboard(&short_total), None);
        let mut zero_len = KEYBOARD;
        zero_len[9] = 0;
        assert_eq!(find_boot_keyboard(&zero_len), None, "no endless loop");
        let mut overrun = KEYBOARD;
        overrun[27] = 200;
        assert_eq!(find_boot_keyboard(&overrun), None);
        assert_eq!(find_boot_keyboard(&KEYBOARD[..20]), None, "truncated read");
        assert_eq!(
            find_boot_keyboard(&[9, 1, 0, 0]),
            None,
            "not a configuration"
        );
    }

    #[test]
    fn reads_the_control_packet_size_from_a_device_descriptor() {
        assert_eq!(
            control_max_packet(&[18, 1, 0x00, 0x02, 0, 0, 0, 64]),
            Some(64)
        );
        assert_eq!(
            control_max_packet(&[18, 1, 0x10, 0x01, 0, 0, 0, 8, 0x27, 0x06]),
            Some(8)
        );
        assert_eq!(control_max_packet(&[18, 2, 0, 0, 0, 0, 0, 8]), None);
        assert_eq!(control_max_packet(&[18, 1, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(control_max_packet(&[18, 1, 0]), None);
    }
}
