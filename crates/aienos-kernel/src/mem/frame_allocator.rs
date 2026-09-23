//! Deterministic physical memory and frame allocator primitives for AIENOS.

/// Physical Page Size on AArch64 (4 KiB standard).
pub const PAGE_SIZE: usize = 4096;

/// Physical address wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysAddr(pub usize);

impl PhysAddr {
    #[inline(always)]
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    #[inline(always)]
    pub const fn as_usize(self) -> usize {
        self.0
    }

    #[inline(always)]
    pub const fn is_page_aligned(self) -> bool {
        self.0.is_multiple_of(PAGE_SIZE)
    }

    #[inline(always)]
    pub const fn align_up(self) -> Self {
        Self((self.0 + PAGE_SIZE - 1) & !(PAGE_SIZE - 1))
    }

    #[inline(always)]
    pub const fn align_down(self) -> Self {
        Self(self.0 & !(PAGE_SIZE - 1))
    }

    #[inline(always)]
    pub const fn offset(self, bytes: usize) -> Self {
        Self(self.0 + bytes)
    }
}

/// Virtual address wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VirtAddr(pub usize);

impl VirtAddr {
    #[inline(always)]
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    #[inline(always)]
    pub const fn as_usize(self) -> usize {
        self.0
    }

    #[inline(always)]
    pub const fn is_page_aligned(self) -> bool {
        self.0.is_multiple_of(PAGE_SIZE)
    }
}

/// Represents a single physical page frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Frame {
    pub index: usize,
}

impl Frame {
    #[inline(always)]
    pub const fn from_index(index: usize) -> Self {
        Self { index }
    }

    #[inline(always)]
    pub const fn start_address(self, base: PhysAddr) -> PhysAddr {
        PhysAddr(base.0 + self.index * PAGE_SIZE)
    }
}

/// Fixed-size bitmap frame allocator for deterministic bare-metal memory tracking.
///
/// `FRAMES` is the total number of managed 4 KiB frames.
/// `WORDS` = `(FRAMES + 63) / 64`.
pub struct BitmapFrameAllocator<const WORDS: usize> {
    base_addr: PhysAddr,
    total_frames: usize,
    bitmap: [u64; WORDS],
    allocated_count: usize,
}

impl<const WORDS: usize> BitmapFrameAllocator<WORDS> {
    /// Initialize a new frame allocator for a physical memory region.
    pub const fn new(base_addr: PhysAddr, total_frames: usize) -> Self {
        Self {
            base_addr,
            total_frames,
            bitmap: [0u64; WORDS],
            allocated_count: 0,
        }
    }

    /// Total managed physical frames.
    pub const fn total_frames(&self) -> usize {
        self.total_frames
    }

    /// Number of allocated frames.
    pub const fn allocated_count(&self) -> usize {
        self.allocated_count
    }

    /// Number of free frames remaining.
    pub const fn free_count(&self) -> usize {
        self.total_frames.saturating_sub(self.allocated_count)
    }

    /// Allocate a single physical frame.
    pub fn allocate_frame(&mut self) -> Option<PhysAddr> {
        for (word_idx, word) in self.bitmap.iter_mut().enumerate() {
            if *word != !0u64 {
                let bit_idx = word.trailing_ones() as usize;
                let frame_idx = word_idx * 64 + bit_idx;
                if frame_idx < self.total_frames {
                    *word |= 1u64 << bit_idx;
                    self.allocated_count += 1;
                    return Some(PhysAddr(self.base_addr.0 + frame_idx * PAGE_SIZE));
                }
            }
        }
        None
    }

    /// Free a previously allocated physical frame.
    pub fn deallocate_frame(&mut self, addr: PhysAddr) -> bool {
        if addr.0 < self.base_addr.0 {
            return false;
        }
        let offset = addr.0 - self.base_addr.0;
        let frame_idx = offset / PAGE_SIZE;
        if frame_idx >= self.total_frames {
            return false;
        }

        let word_idx = frame_idx / 64;
        let bit_idx = frame_idx % 64;

        if (self.bitmap[word_idx] & (1u64 << bit_idx)) != 0 {
            self.bitmap[word_idx] &= !(1u64 << bit_idx);
            self.allocated_count = self.allocated_count.saturating_sub(1);
            true
        } else {
            false
        }
    }

    /// Allocate contiguous physical frames.
    pub fn allocate_contiguous(&mut self, count: usize) -> Option<PhysAddr> {
        if count == 0 || count > self.free_count() {
            return None;
        }

        let mut run_start = 0;
        let mut current_run = 0;

        for i in 0..self.total_frames {
            let word_idx = i / 64;
            let bit_idx = i % 64;
            let is_set = (self.bitmap[word_idx] & (1u64 << bit_idx)) != 0;

            if !is_set {
                if current_run == 0 {
                    run_start = i;
                }
                current_run += 1;
                if current_run == count {
                    // Mark run as allocated
                    for f in run_start..run_start + count {
                        let w = f / 64;
                        let b = f % 64;
                        self.bitmap[w] |= 1u64 << b;
                    }
                    self.allocated_count += count;
                    return Some(PhysAddr(self.base_addr.0 + run_start * PAGE_SIZE));
                }
            } else {
                current_run = 0;
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocator_basic() {
        let mut alloc = BitmapFrameAllocator::<4>::new(PhysAddr(0x1000_0000), 256);
        assert_eq!(alloc.total_frames(), 256);
        assert_eq!(alloc.free_count(), 256);

        let f0 = alloc.allocate_frame().expect("Alloc f0");
        assert_eq!(f0, PhysAddr(0x1000_0000));
        assert_eq!(alloc.allocated_count(), 1);

        let f1 = alloc.allocate_frame().expect("Alloc f1");
        assert_eq!(f1, PhysAddr(0x1000_1000));

        assert!(alloc.deallocate_frame(f0));
        assert_eq!(alloc.allocated_count(), 1);

        // Re-allocation should pick reused f0
        let f0_reused = alloc.allocate_frame().expect("Realloc f0");
        assert_eq!(f0_reused, PhysAddr(0x1000_0000));
    }

    #[test]
    fn test_alloc_contiguous() {
        let mut alloc = BitmapFrameAllocator::<2>::new(PhysAddr(0x2000_0000), 128);
        let block = alloc.allocate_contiguous(4).expect("Contiguous 4 frames");
        assert_eq!(block, PhysAddr(0x2000_0000));
        assert_eq!(alloc.allocated_count(), 4);
    }
}
