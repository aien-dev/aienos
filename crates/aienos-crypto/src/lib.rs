#![no_std]

//! Shared, allocation-free cryptographic primitives used by the kernel and
//! host/bare-metal parsers.
//!
//! # Side-channel stance
//!
//! AES-256, POLYVAL and AES-256-GCM-SIV are written to be constant-time by
//! construction: no table lookup is indexed by secret data and no branch
//! depends on secret data. Secret key material and scratch buffers are wiped
//! with volatile writes when they go out of scope. This has been checked by
//! reading the source and spot-checking AArch64 disassembly; it has not been
//! measured on hardware and has not had an independent side-channel review.
//! See `docs/CRYPTO_CONSTANT_TIME.md`.

#[cfg(test)]
extern crate std;

pub mod aes;
pub mod aes_gcm_siv;
pub mod polyval;
pub mod sha256;

/// Overwrite `buf` with zeros using volatile writes the optimizer cannot drop.
#[inline(never)]
pub(crate) fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusive reference into `buf`.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Fixed-size secret byte buffer that is wiped on drop, on every exit path.
pub struct Secret<const N: usize>(pub(crate) [u8; N]);

impl<const N: usize> core::ops::Deref for Secret<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> core::ops::DerefMut for Secret<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> core::fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

impl<const N: usize> Secret<N> {
    #[inline(always)]
    pub(crate) fn zeroed() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}
