//! USB support for the early console.
//!
//! After `ExitBootServices` the firmware's USB keyboard support is gone, so
//! AIENOS must drive the keyboard itself. This module holds the parts that
//! need no hardware: decoding HID boot-protocol keyboard reports into key
//! events and text, parsing the descriptors that locate a boot keyboard, and
//! the xHCI data structures (TRBs, rings, contexts) a polled controller
//! driver builds on (ADR 0012, SEED-0A experiment #1 `input.keyboard.usb`).

pub mod audio;
pub mod descriptor;
pub mod hid;
pub mod xhci;
