//! Bounded bump heap over ONE region handed over by the kernel (`ck_mm_frames_alloc`).
//!
//! Allocation moves a cursor; `dealloc` only reclaims the newest block and `realloc` grows the
//! newest block in place (otherwise a new block is taken and the old one is not reused). Training
//! keeps everything it allocates, so the cursor after training is the trained core's footprint
//! plus training garbage. Around each decision the runner takes a [`Mark`] and, once every block
//! allocated after it is freed again (`live` back to the mark's value), resets the cursor to it:
//! repeated decisions then reuse the same bytes and the region does not grow.
//!
//! Exhaustion (or a region of length 0, the state before `init` and after close) returns 0;
//! the global allocator turns that into a null pointer, Rust's allocation-error path into a
//! panic, and the kernel's panic handler stops the run. The heap is NOT a general allocator and
//! has no locking: one core, interrupts masked by the caller.
//!
//! Counters: `peak` is the region high-water mark (what the region must hold for this run);
//! `live_peak` is the most bytes live at once (what a reusing allocator would need).

use core::cell::Cell;

/// The heap state. All fields are plain cells: single core, no locking.
pub struct Bump {
    base: Cell<usize>,
    end: Cell<usize>,
    next: Cell<usize>,
    last: Cell<usize>, // start of the newest block, 0 if none
    peak: Cell<usize>,
    live: Cell<usize>,
    live_peak: Cell<usize>,
    allocs: Cell<u64>,
    fails: Cell<u64>,
}

/// Cursor position to return to after a decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mark {
    next: usize,
    live: usize,
}

/// Snapshot for the report. `#[repr(C)]`: the kernel declares the same struct
/// (`native/kernel/core/allen.c`, `struct allen_heap_stats`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// region bytes
    pub cap: u64,
    /// cursor - base now
    pub used: u64,
    /// highest cursor - base seen
    pub peak: u64,
    /// bytes in blocks not yet freed
    pub live: u64,
    /// most bytes live at once
    pub live_peak: u64,
    /// successful allocations
    pub allocs: u64,
    /// refused allocations (exhausted or no region)
    pub fails: u64,
}

impl Bump {
    /// Empty heap: every allocation fails until [`Bump::init`].
    pub const fn new() -> Bump {
        Bump {
            base: Cell::new(0),
            end: Cell::new(0),
            next: Cell::new(0),
            last: Cell::new(0),
            peak: Cell::new(0),
            live: Cell::new(0),
            live_peak: Cell::new(0),
            allocs: Cell::new(0),
            fails: Cell::new(0),
        }
    }

    /// Use `[base, base + len)`. `len == 0` (or `base == 0`) closes the heap: every later
    /// allocation fails. Counters restart.
    pub fn init(&self, base: usize, len: usize) {
        let ok = base != 0 && len != 0 && base.checked_add(len).is_some();
        self.base.set(if ok { base } else { 0 });
        self.end.set(if ok { base + len } else { 0 });
        self.next.set(if ok { base } else { 0 });
        self.last.set(0);
        self.peak.set(0);
        self.live.set(0);
        self.live_peak.set(0);
        self.allocs.set(0);
        self.fails.set(0);
    }

    fn fail(&self) -> usize {
        self.fails.set(self.fails.get() + 1);
        0
    }

    fn grew(&self, e: usize, add_live: usize) {
        let used = e - self.base.get();
        if used > self.peak.get() {
            self.peak.set(used);
        }
        let live = self.live.get() + add_live;
        self.live.set(live);
        if live > self.live_peak.get() {
            self.live_peak.set(live);
        }
    }

    /// Address of a new block, or 0. `align` must be a power of two.
    pub fn alloc(&self, size: usize, align: usize) -> usize {
        if self.base.get() == 0 || align == 0 || !align.is_power_of_two() {
            return self.fail();
        }
        let start = match self.next.get().checked_add(align - 1) {
            Some(v) => v & !(align - 1),
            None => return self.fail(),
        };
        match start.checked_add(size) {
            Some(e) if e <= self.end.get() => {
                self.next.set(e);
                self.last.set(start);
                self.allocs.set(self.allocs.get() + 1);
                self.grew(e, size);
                start
            }
            _ => self.fail(),
        }
    }

    /// Free a block of `size` bytes at `p` (reclaimed only when it is the newest).
    pub fn dealloc(&self, p: usize, size: usize) {
        self.live.set(self.live.get().saturating_sub(size));
        if p == self.last.get() && p + size == self.next.get() {
            self.next.set(p);
            self.last.set(0);
        }
    }

    /// Grow or shrink the newest block in place; any other block: 0 (the caller copies).
    pub fn resize_in_place(&self, p: usize, size: usize, new_size: usize) -> usize {
        if p == 0 || p != self.last.get() || p + size != self.next.get() {
            return 0;
        }
        match p.checked_add(new_size) {
            Some(e) if e <= self.end.get() => {
                self.next.set(e);
                self.live.set(self.live.get().saturating_sub(size));
                self.grew(e, new_size);
                p
            }
            _ => 0,
        }
    }

    /// Current cursor and live bytes.
    pub fn mark(&self) -> Mark {
        Mark {
            next: self.next.get(),
            live: self.live.get(),
        }
    }

    /// Return to `m` if every block allocated since it was freed (live bytes equal the mark's);
    /// otherwise leave the cursor (memory is not reused, nothing is corrupted) and say so.
    pub fn reset_to(&self, m: Mark) -> bool {
        if self.base.get() == 0 || self.live.get() != m.live || m.next > self.next.get() {
            return false;
        }
        self.next.set(m.next);
        self.last.set(0);
        true
    }

    /// Start the peak counters again from the current state (one report per mode).
    pub fn reset_peaks(&self) {
        if self.base.get() != 0 {
            self.peak.set(self.next.get() - self.base.get());
        }
        self.live_peak.set(self.live.get());
    }

    /// Counters now.
    pub fn stats(&self) -> Stats {
        let b = self.base.get();
        Stats {
            cap: (self.end.get() - b) as u64,
            used: (self.next.get() - b) as u64,
            peak: self.peak.get() as u64,
            live: self.live.get() as u64,
            live_peak: self.live_peak.get() as u64,
            allocs: self.allocs.get(),
            fails: self.fails.get(),
        }
    }
}

impl Default for Bump {
    fn default() -> Bump {
        Bump::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(len: usize) -> (Vec<u64>, Bump) {
        let v = vec![0u64; len / 8];
        let h = Bump::new();
        h.init(v.as_ptr() as usize, len);
        (v, h)
    }

    #[test]
    fn closed_heap_refuses_everything() {
        let h = Bump::new();
        assert_eq!(h.alloc(8, 8), 0);
        assert_eq!(h.stats().fails, 1);
        let (_v, h) = region(64);
        h.init(0, 0);
        assert_eq!(h.alloc(1, 1), 0);
    }

    #[test]
    fn exhaustion_returns_zero_and_counts() {
        let (_v, h) = region(64);
        assert_ne!(h.alloc(48, 8), 0);
        assert_eq!(h.alloc(32, 8), 0);
        assert_eq!(h.stats().fails, 1);
        assert_eq!(h.stats().peak, 48);
    }

    #[test]
    fn alignment_and_bad_align() {
        let (_v, h) = region(256);
        let a = h.alloc(3, 1);
        let b = h.alloc(8, 64);
        assert_eq!(b % 64, 0);
        assert!(b >= a + 3);
        assert_eq!(h.alloc(8, 3), 0);
    }

    #[test]
    fn newest_block_is_reclaimed_and_grown_in_place() {
        let (_v, h) = region(256);
        let a = h.alloc(16, 8);
        assert_eq!(h.resize_in_place(a, 16, 64), a);
        assert_eq!(h.stats().live, 64);
        h.dealloc(a, 64);
        assert_eq!(h.stats().used, 0);
        assert_eq!(h.stats().live, 0);
        let b = h.alloc(16, 8);
        let _c = h.alloc(16, 8);
        assert_eq!(h.resize_in_place(b, 16, 32), 0, "not the newest block");
    }

    #[test]
    fn mark_reset_reuses_bytes_only_when_all_freed() {
        let (_v, h) = region(1024);
        let keep = h.alloc(100, 8);
        let m = h.mark();
        for _ in 0..50 {
            let x = h.alloc(200, 8);
            let y = h.alloc(300, 8);
            h.dealloc(x, 200);
            h.dealloc(y, 300);
            assert!(h.reset_to(m));
            assert_eq!(h.mark(), m);
        }
        assert!(h.stats().peak <= 104 + 200 + 8 + 300);
        let z = h.alloc(10, 8);
        assert!(
            !h.reset_to(m),
            "a live block after the mark blocks the reset"
        );
        h.dealloc(z, 10);
        assert!(h.reset_to(m));
        assert_ne!(keep, 0);
    }
}
