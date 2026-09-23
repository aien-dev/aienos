//! Sovereign synchronization primitives for bare-metal substrate.

pub mod spinlock;

pub use spinlock::{SpinLock, SpinLockGuard};
