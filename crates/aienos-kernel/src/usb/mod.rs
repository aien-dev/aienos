//! USB support for the early console.
//!
//! After `ExitBootServices` the firmware's USB keyboard support is gone, so
//! AIENOS must drive the keyboard itself. This module starts with the part
//! that needs no hardware: decoding HID boot-protocol keyboard reports into
//! key events and text. The polled xHCI controller driver that delivers those
//! reports follows separately (ADR 0012, SEED-0A experiment #1
//! `input.keyboard.usb`).

pub mod hid;
