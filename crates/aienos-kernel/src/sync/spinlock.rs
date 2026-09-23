//! Sovereign SpinLock for bare-metal `#![no_std]` concurrency.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

/// A simple, sovereign spinlock for bare-metal concurrency.
pub struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for SpinLock<T> {}
unsafe impl<T: Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// Create a new SpinLock protecting `data`.
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    /// Acquire the spinlock, spinning until available.
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        while self.locked.swap(true, Ordering::Acquire) {
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        SpinLockGuard { lock: self }
    }

    /// Try to acquire the spinlock without blocking.
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        if !self.locked.swap(true, Ordering::Acquire) {
            Some(SpinLockGuard { lock: self })
        } else {
            None
        }
    }
}

/// RAII guard for `SpinLock`.
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<'a, T> Deref for SpinLockGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> DerefMut for SpinLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for SpinLockGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spinlock_basic() {
        let lock = SpinLock::new(42);
        {
            let mut guard = lock.lock();
            assert_eq!(*guard, 42);
            *guard += 1;
        }
        {
            let guard = lock.lock();
            assert_eq!(*guard, 43);
        }
    }

    #[test]
    fn test_spinlock_try_lock() {
        let lock = SpinLock::new(100);
        let guard1 = lock.try_lock();
        assert!(guard1.is_some());
        let guard2 = lock.try_lock();
        assert!(guard2.is_none());
        drop(guard1);
        let guard3 = lock.try_lock();
        assert!(guard3.is_some());
    }
}
