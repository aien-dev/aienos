#![no_std]

//! Canonical, bounded parser and identity primitives for Binary Artifact v0.
//! Persistent data is decoded byte-by-byte; no input is reinterpreted as a
//! Rust struct and no parser path allocates.

#[cfg(test)]
extern crate std;

pub mod canonical;
pub mod capability;
pub mod error;
pub mod format;
pub mod id;
pub mod receipt;
pub mod resource;
pub mod signature;
pub mod verify;

pub use error::ArtifactError;
pub use format::{Artifact, Section};
pub use id::ArtifactId;

#[cfg(test)]
mod tests;
