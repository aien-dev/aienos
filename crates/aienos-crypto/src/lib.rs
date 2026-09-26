#![no_std]

//! Shared, allocation-free cryptographic primitives used by the kernel and
//! host/bare-metal parsers.

#[cfg(test)]
extern crate std;

pub mod aes;
pub mod aes_gcm_siv;
pub mod polyval;
pub mod sha256;
