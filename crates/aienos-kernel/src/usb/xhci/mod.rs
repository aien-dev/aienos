//! xHCI (USB 3 host controller) data structures for the polled keyboard
//! driver, host-tested against the xHCI 1.2 specification. Register access
//! and controller bring-up come later in the series and build on these.

pub mod context;
pub mod ring;
pub mod trb;
