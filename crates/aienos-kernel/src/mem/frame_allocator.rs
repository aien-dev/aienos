//! Deterministic physical memory and frame allocator primitives for AIENOS.

/// Physical Page Size on AArch64 (4 KiB standard).
pub const PAGE_SIZE: usize = 4096;
pub const MAX_BATCH_FRAMES: usize = 160;

/// Fixed-capacity ownership record for a reservation made under one allocator
/// lock. The addresses are explicit physical frame starts; no Rust layout is
/// persisted or passed across the firmware handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameBatch {
    frames: [PhysAddr; MAX_BATCH_FRAMES],
    count: u16,
}

impl FrameBatch {
    pub const fn empty() -> Self {
        Self {
            frames: [PhysAddr(0); MAX_BATCH_FRAMES],
            count: 0,
        }
    }

    pub fn as_slice(&self) -> &[PhysAddr] {
        &self.frames[..usize::from(self.count)]
    }

    pub const fn len(&self) -> usize {
        self.count as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

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
        assert!(
            base_addr.is_page_aligned(),
            "frame region must be page aligned"
        );
        assert!(
            total_frames / 64 + (!total_frames.is_multiple_of(64)) as usize <= WORDS,
            "frame region exceeds bitmap capacity"
        );
        assert!(
            total_frames <= (usize::MAX - base_addr.0) / PAGE_SIZE,
            "frame region overflows physical address space"
        );
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
        if !addr.is_page_aligned() || addr.0 < self.base_addr.0 {
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

    /// Reserve a bounded set of frames atomically from this allocator. On
    /// exhaustion, every frame acquired by this call is returned before it
    /// reports failure.
    pub fn allocate_batch(&mut self, count: usize) -> Option<FrameBatch> {
        if count == 0 || count > MAX_BATCH_FRAMES || count > self.free_count() {
            return None;
        }
        let mut batch = FrameBatch::empty();
        for index in 0..count {
            match self.allocate_frame() {
                Some(frame) => {
                    batch.frames[index] = frame;
                    batch.count += 1;
                }
                None => {
                    self.release_batch(batch);
                    return None;
                }
            }
        }
        Some(batch)
    }

    /// Return every frame owned by a prior batch. Invalid/double-freed entries
    /// cause `false`; valid entries are still returned.
    pub fn release_batch(&mut self, batch: FrameBatch) -> bool {
        let mut complete = true;
        for frame in batch.as_slice() {
            complete &= self.deallocate_frame(*frame);
        }
        complete
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

    #[test]
    fn allocator_rejects_unaligned_deallocation() {
        let mut alloc = BitmapFrameAllocator::<1>::new(PhysAddr(0x2000_0000), 64);
        let frame = alloc.allocate_frame().unwrap();
        assert!(!alloc.deallocate_frame(PhysAddr(frame.0 + 1)));
        assert_eq!(alloc.allocated_count(), 1);
        assert!(alloc.deallocate_frame(frame));
    }

    #[test]
    fn batch_reservation_is_bounded_and_released_as_a_unit() {
        let mut alloc = BitmapFrameAllocator::<1>::new(PhysAddr(0x3000_0000), 8);
        let batch = alloc.allocate_batch(6).unwrap();
        assert_eq!(batch.len(), 6);
        assert_eq!(alloc.free_count(), 2);
        assert!(alloc.release_batch(batch));
        assert_eq!(alloc.free_count(), 8);
        assert!(alloc.allocate_batch(MAX_BATCH_FRAMES + 1).is_none());
    }

    #[test]
    fn insufficient_batch_reservation_leaves_no_partial_allocations() {
        let mut alloc = BitmapFrameAllocator::<1>::new(PhysAddr(0x4000_0000), 8);
        assert!(alloc.allocate_frame().is_some());
        assert!(alloc.allocate_batch(8).is_none());
        assert_eq!(alloc.allocated_count(), 1);
        assert_eq!(alloc.free_count(), 7);
    }

    #[test]
    #[should_panic(expected = "frame region exceeds bitmap capacity")]
    fn allocator_rejects_capacity_overflow() {
        let _ = BitmapFrameAllocator::<1>::new(PhysAddr(0x2000_0000), 65);
    }
}
