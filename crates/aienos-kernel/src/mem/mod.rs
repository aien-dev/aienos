//! Physical memory management primitives for AIENOS kernel.

pub mod frame_allocator;
pub mod map_plan;
pub mod pagetable;

pub use frame_allocator::{
    BitmapFrameAllocator, Frame, FrameBatch, PhysAddr, VirtAddr, MAX_BATCH_FRAMES, PAGE_SIZE,
};
