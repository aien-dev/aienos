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
use aienos_kernel::usb::hid::{BootKeyboardDecoder, KeyEvent};
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

const DEBUG_XHCI_WITHOUT_SMMU: bool = cfg!(feature = "debug-xhci-without-smmu");

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

impl XhciLocation {
    pub fn mmio_base(self) -> u64 {
        self.mmio
    }
    pub fn ecam_location(self) -> (u16, u8) {
        (self.segment, self.bus)
    }
    pub fn requester_id(self) -> u32 {
        (u32::from(self.bus) << 8) | (u32::from(self.device) << 3) | u32::from(self.function)
    }
    pub fn stream_id(self, iort: &acpi::IortSmmu) -> Option<u32> {
        iort.stream_id_for(self.requester_id())
    }
    pub fn dma_window(self) -> (u64, usize) {
        let base = core::ptr::addr_of!(DMA) as u64;
        (base & !0xfff, core::mem::size_of::<DmaMemory>())
    }
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
pub fn run(
    xhci: Option<XhciLocation>,
    mcfg: Option<&[u8]>,
    screen: &mut Option<Screen>,
    conventional_memory_kb: u64,
    exception_level: u8,
    boot_report: &str,
    smmu_ready: bool,
    smmu_base: Option<u64>,
    smmu_stream_id: Option<u32>,
    smmu_events: *const [[u64; 4]; 16],
) {
    let mut line = aienos_kernel::report::ReportBuf::<512>::new();
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
    if !smmu_ready && !DEBUG_XHCI_WITHOUT_SMMU {
        say(
            screen,
            "keyboard: unavailable (SMMU DMA isolation not active)\n",
        );
        return;
    }
    let dma_mode = if smmu_ready {
        "smmu-translated"
    } else {
        "debug-identity"
    };
    let mut mode = aienos_kernel::report::ReportBuf::<128>::new();
    let _ = writeln!(
        mode,
        "xhci_debug: dma_mode={dma_mode} dma_base={:#x} bytes={}",
        core::ptr::addr_of!(DMA) as usize,
        core::mem::size_of::<DmaMemory>()
    );
    say(screen, mode.as_str());
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
            let mut msg = aienos_kernel::report::ReportBuf::<512>::new();
            let _ = writeln!(msg, "keyboard: unavailable ({e:?})");
            say(screen, msg.as_str());
            if let Some(base) = smmu_base {
                let reg = |offset| MmioReg::<u32>::new(base as usize + offset).read();
                aienos_kernel::arch::aarch64::clean_invalidate_dcache_range(
                    smmu_events as usize,
                    core::mem::size_of::<[[u64; 4]; 16]>(),
                );
                let events = unsafe { core::ptr::read_volatile(smmu_events) };
                let mut fault = aienos_kernel::report::ReportBuf::<1024>::new();
                let _ = writeln!(fault, "smmu_fault: GERROR={:#x} GERRORN={:#x} EVENTQ_PROD={:#x} EVENTQ_CONS={:#x} events={events:016x?}", reg(0x60), reg(0x64), reg(0xa8), reg(0xac));
                say(screen, fault.as_str());
                if let Some(sid) = smmu_stream_id {
                    let table_base = (u64::from(reg(0x84)) << 32 | u64::from(reg(0x80))) & !0x3f;
                    let cfg = reg(0x88);
                    let ste_addr = table_base + u64::from(sid) * 64;
                    let ste0 = unsafe { core::ptr::read_volatile(ste_addr as *const u64) };
                    let ste1 = unsafe { core::ptr::read_volatile((ste_addr + 8) as *const u64) };
                    let mut entry = aienos_kernel::report::ReportBuf::<192>::new();
                    let _ = writeln!(entry, "smmu_ste: base={table_base:#x} cfg={cfg:#x} sid={sid:#x} addr={ste_addr:#x} words=[{ste0:#x},{ste1:#x}]");
                    say(screen, entry.as_str());
                }
            }
            return;
        }
    };
    let (port, slot, endpoint) = keyboard.location();
    let mut msg = aienos_kernel::report::ReportBuf::<200>::new();
    let _ = writeln!(
        msg,
        "keyboard: ready (port {port}, slot {slot}, endpoint {endpoint:#04x})"
    );
    let _ = writeln!(msg, "keyboard: shell ready ({} s)", listen_secs());
    say(screen, msg.as_str());

    let mut decoder = BootKeyboardDecoder::new();
    let mut line = [0u8; aienos_kernel::shell::LINE_CAPACITY];
    let mut length = 0usize;
    let mut exit = false;
    let deadline = listen_secs().saturating_mul(counter_frequency_hz());
    let start = counter_ticks();
    say(screen, "aienos> ");
    while !exit && counter_ticks().wrapping_sub(start) < deadline && !keyboard.is_halted() {
        let Some(report) = keyboard.poll() else {
            core::hint::spin_loop();
            continue;
        };
        decoder.handle_report(&report, |event| {
            if event == KeyEvent::Enter {
                say(screen, "\n");
                say(screen, "keyboard_echo: ");
                say(screen, core::str::from_utf8(&line[..length]).unwrap_or(""));
                say(screen, "\n");
                let mut entered = aienos_kernel::report::ReportBuf::<96>::new();
                let _ = writeln!(
                    entered,
                    "keyboard_line: {}",
                    core::str::from_utf8(&line[..length]).unwrap_or("")
                );
                say(screen, entered.as_str());
                say(screen, "keyboard: done (enter)\n");
                let elapsed = counter_ticks().wrapping_sub(start);
                let hz = counter_frequency_hz();
                let uptime_ms = if hz == 0 {
                    0
                } else {
                    elapsed.saturating_mul(1000) / hz
                };
                let input = core::str::from_utf8(&line[..length]).unwrap_or("");
                let parsed = aienos_kernel::shell::parse_line(input);
                let output = aienos_kernel::shell::dispatch(
                    input,
                    &aienos_kernel::shell::ShellContext {
                        conventional_memory_kb,
                        // Read live when the command runs, not cached at shell start.
                        exception_level: aienos_kernel::arch::aarch64::current_el(),
                        report: boot_report,
                        uptime_ms,
                    },
                );
                say(screen, output.as_str());
                exit = parsed.is_some_and(|p| p.command == aienos_kernel::shell::Command::Exit);
                length = 0;
                if !exit {
                    say(screen, "aienos> ");
                }
            } else if event == KeyEvent::Backspace {
                if length > 0 {
                    length -= 1;
                    say(screen, "\x08 \x08");
                }
            } else if let KeyEvent::Char(c) = event {
                if c.is_ascii() && length < line.len() {
                    line[length] = c as u8;
                    length += 1;
                    let mut buf = [0u8; 4];
                    say(screen, c.encode_utf8(&mut buf));
                }
            }
        });
    }
    let mut end = aienos_kernel::report::ReportBuf::<200>::new();
    let reason = match (exit, keyboard.is_halted()) {
        (true, _) => "exit",
        (false, true) => "endpoint halted",
        (false, false) => "timeout",
    };
    let _ = writeln!(end, "\nkeyboard: done ({reason})",);
    say(screen, end.as_str());
}
