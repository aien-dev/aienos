//! SEED-0A candidate `input.keyboard.usb` (ADR 0012): after firmware exit,
//! drive the xHCI controller with the polled AIENOS driver and echo typed
//! keys on the SPCR console and the screen.
//!
//! Built only with the `usb-keyboard` feature, which the QEMU keyboard test
//! enables and hardware staging does not: the candidate is proven in QEMU
//! and never admitted to Machine 1 before M3 can confine it.

use aienos_kernel::acpi::{self, EcamWindow};
use aienos_kernel::arch::aarch64::{counter_frequency_hz, counter_ticks, MmioReg};
use aienos_kernel::console::EarlyConsole;
use aienos_kernel::display::Screen;
use aienos_kernel::usb::hid::{BootKeyboardDecoder, KeyEvent, TextSink};
use aienos_kernel::usb::xhci::controller::{DmaMemory, Keyboard};
use aienos_kernel::usb::xhci::{self, PCI_COMMAND_BUS_MASTER, PCI_COMMAND_MEMORY};
use core::fmt::Write;
use uefi::boot::{OpenProtocolAttributes, OpenProtocolParams};
use uefi::proto::pci::root_bridge::PciRootBridgeIo;
use uefi::proto::pci::PciIoAddress;

/// Seconds to wait for a line; `AIENOS_KEYBOARD_SECS` at build time.
fn listen_secs() -> u64 {
    option_env!("AIENOS_KEYBOARD_SECS")
        .and_then(|s| s.parse().ok())
        .unwrap_or(30)
}

/// DMA memory for the driver, used only after firmware exit.
static mut DMA: DmaMemory = DmaMemory::new();

/// Where the first xHCI controller sits, found before firmware exit.
#[derive(Clone, Copy)]
pub struct XhciLocation {
    segment: u16,
    bus: u8,
    device: u8,
    function: u8,
    mmio: u64,
}

/// Walk every root bridge for the first xHCI controller (pre-exit only).
pub fn find_xhci() -> Option<XhciLocation> {
    for handle in uefi::boot::find_handles::<PciRootBridgeIo>().ok()? {
        // Shared open, read-only use, as in GB10 discovery.
        let params = OpenProtocolParams {
            handle,
            agent: uefi::boot::image_handle(),
            controller: None,
        };
        let Ok(mut root) = (unsafe {
            uefi::boot::open_protocol::<PciRootBridgeIo>(
                params,
                OpenProtocolAttributes::GetProtocol,
            )
        }) else {
            continue;
        };
        let (bus_min, bus_max) = crate::bus_ranges(&mut root).unwrap_or((0, 0));
        for bus in bus_min..=bus_max {
            for device in 0..32u8 {
                for function in 0..8u8 {
                    let address = PciIoAddress::new(bus, device, function);
                    let mut read = |offset| {
                        root.pci()
                            .read_one::<u32>(address.with_register(offset))
                            .ok()
                    };
                    let Some(_) = read(0).filter(|id| id & 0xffff != 0xffff) else {
                        if function == 0 {
                            break;
                        }
                        continue;
                    };
                    let bar = (read(0x08), read(0x10), read(0x14));
                    if let (Some(class), Some(low), Some(high)) = bar {
                        if let Some(mmio) = xhci::xhci_mmio_base(class, low, high) {
                            let segment = root.segment_nr() as u16;
                            return Some(XhciLocation {
                                segment,
                                bus,
                                device,
                                function,
                                mmio,
                            });
                        }
                    }
                    let multi = read(0x0c).is_some_and(|v| v & 0x80_0000 != 0);
                    if function == 0 && !multi {
                        break;
                    }
                }
            }
        }
    }
    None
}

fn console() -> Option<EarlyConsole> {
    crate::CONSOLE
        .try_lock()
        .and_then(|k| *k)
        .and_then(EarlyConsole::from_kind)
}

/// Write `text` to the SPCR console and the screen.
fn say(screen: &mut Option<Screen>, text: &str) {
    if let Some(console) = console() {
        console.write_str(text);
    }
    if let Some(s) = screen.as_mut() {
        let _ = s.write_str(text);
    }
}

/// Enable memory decode and bus mastering through ECAM: firmware may have
/// turned them off when it stopped its own USB driver at exit.
fn enable_controller(ecam: &EcamWindow, at: &XhciLocation) -> bool {
    let Some(addr) = ecam.config_address(at.bus, at.device, at.function, 0x04) else {
        return false;
    };
    let command = MmioReg::<u16>::new(addr as usize);
    command.write(command.read() | PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER);
    true
}

/// Post-exit: bring up the keyboard and echo keys until Enter or timeout.
pub fn run(xhci: Option<XhciLocation>, mcfg: Option<&[u8]>, screen: &mut Option<Screen>) {
    let mut line = aienos_kernel::report::ReportBuf::<160>::new();
    let Some(at) = xhci else {
        say(screen, "\nkeyboard: unavailable (no xHCI controller)\n");
        return;
    };
    let _ = writeln!(
        line,
        "\nkeyboard: xhci {:04x}:{:02x}:{:02x}.{} mmio {:#x}",
        at.segment, at.bus, at.device, at.function, at.mmio
    );
    say(screen, line.as_str());
    let ecam = mcfg.and_then(|t| acpi::mcfg_window(t, at.segment, at.bus).ok().flatten());
    if !ecam.is_some_and(|w| enable_controller(&w, &at)) {
        say(
            screen,
            "keyboard: unavailable (no ECAM window for the controller)\n",
        );
        return;
    }
    // SAFETY: firmware has exited and released the controller; DMA is used
    // by nothing else, is identity-mapped, and lives for the whole boot.
    let started = unsafe { Keyboard::start(at.mmio, core::ptr::addr_of_mut!(DMA)) };
    let mut keyboard = match started {
        Ok(k) => k,
        Err(e) => {
            let mut msg = aienos_kernel::report::ReportBuf::<160>::new();
            let _ = writeln!(msg, "keyboard: unavailable ({e})");
            say(screen, msg.as_str());
            return;
        }
    };
    let (port, slot, endpoint) = keyboard.location();
    let mut msg = aienos_kernel::report::ReportBuf::<200>::new();
    let _ = writeln!(
        msg,
        "keyboard: ready (port {port}, slot {slot}, endpoint {endpoint:#04x})"
    );
    let _ = write!(
        msg,
        "keyboard: type a line, Enter ends it ({} s)\nkeyboard_echo: ",
        listen_secs()
    );
    say(screen, msg.as_str());

    let mut decoder = BootKeyboardDecoder::new();
    let mut text = TextSink::<64>::new();
    let mut entered = false;
    let deadline = listen_secs().saturating_mul(counter_frequency_hz());
    let start = counter_ticks();
    while !entered && counter_ticks().wrapping_sub(start) < deadline && !keyboard.is_halted() {
        let Some(report) = keyboard.poll() else {
            core::hint::spin_loop();
            continue;
        };
        decoder.handle_report(&report, |event| {
            if event == KeyEvent::Enter {
                entered = true;
            } else if let KeyEvent::Char(c) = event {
                let mut buf = [0u8; 4];
                say(screen, c.encode_utf8(&mut buf));
                text.record(event);
            }
        });
    }
    let mut end = aienos_kernel::report::ReportBuf::<200>::new();
    let reason = match (entered, keyboard.is_halted()) {
        (true, _) => "enter",
        (false, true) => "endpoint halted",
        (false, false) => "timeout",
    };
    let _ = writeln!(
        end,
        "\nkeyboard_line: {}\nkeyboard: done ({reason})",
        text.as_str()
    );
    say(screen, end.as_str());
}
