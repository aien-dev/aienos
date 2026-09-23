//! Physical memory management primitives for AIENOS kernel.

pub mod frame_allocator;

pub use frame_allocator::{BitmapFrameAllocator, Frame, PhysAddr, VirtAddr, PAGE_SIZE};
