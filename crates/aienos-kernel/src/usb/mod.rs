//! USB support for the early console.
//!
//! After `ExitBootServices` the firmware's USB keyboard support is gone, so
//! AIENOS must drive the keyboard itself. This module holds the parts that
//! need no hardware: decoding HID boot-protocol keyboard reports into key
//! events and text, and the xHCI data structures a polled controller driver
//! builds on (ADR 0012, SEED-0A experiment #1 `input.keyboard.usb`).

pub mod hid;
pub mod xhci;
