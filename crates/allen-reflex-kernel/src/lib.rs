//! ALLEN REFLEX in the kernel (PI5-8 cut K): the glue that links the `allen-reflex` decision core
//! into the general-regs-only C kernel of the Raspberry Pi 5 image `make pi5-allen`.
//!
//! What it adds around the unchanged core:
//! - [`card`]: the exam card file `\EFI\AIENOS\ALLEN.EXM` (case id + turns only, never labels).
//! - [`pool`]: the training pool compiled into the image (exam train split + `cases-reflex-extra.psv`,
//!   read exactly as `crates/allen-reflex/examples/common` reads them). Dev and held-out are never in it.
//! - [`runner`]: one trained core per mode and one decision line per case,
//!   `ALLEN_D <mode> <id> <decision JSON>`, byte-identical on the host and on the Pi.
//! - [`heap`]: a bounded bump heap over one region the kernel hands over, with a mark/reset around
//!   each decision so repeated decisions do not grow it, and live/peak counters for the report.
//! - `kernel` (only for `target_os = "none"`): the global allocator, the panic handler (a panic or an
//!   exhausted heap stops the run through the kernel's panic path; nothing is written anywhere) and
//!   the C entry points used by `native/kernel/core/allen.c`.
//!
//! ALLEN only proposes: the decision line is text. The kernel's gate (`native/kernel/core/allen_gate.c`)
//! is what turns a proposal into a card-script command line and asks the lifecycle state machine;
//! nothing in this crate can approve, deny, cancel or write.
#![cfg_attr(target_os = "none", no_std)]

extern crate alloc;

pub mod card;
pub mod heap;
pub mod pool;
pub mod runner;

#[cfg(target_os = "none")]
mod kernel;
