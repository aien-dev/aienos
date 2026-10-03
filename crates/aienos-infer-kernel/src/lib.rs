//! Kernel-side entry for native inference (aienos#34 lane 4, cut 1).
//!
//! The C kernel (built -mgeneral-regs-only) hands this staticlib the Llama
//! GGUF bytes it ingested into RAM; the unit parses the header with
//! `aienos_infer::Gguf`, binds the `Model`, tokenizes the fixed chat prompt
//! and reports what it found. No token generation yet.
//!
//! Allocator: `aienos-infer` needs `alloc`. This crate installs a bump
//! allocator over ONE region the kernel provides (`aienos_infer_heap_init`,
//! a contiguous run of frames from `ck_mm_frames_alloc`). Allocation moves a
//! cursor; `dealloc` only reclaims when the block is the newest one and
//! `realloc` grows the newest block in place, otherwise memory is not
//! reused. That is enough for one load + one prompt; it is NOT a general
//! allocator. Single core, interrupts masked by the caller: no locking.
//! Exhaustion returns null, which Rust turns into a panic, which calls
//! `aienos_infer_panic` (the C kernel prints and stops; it never returns).
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::slice;

use aienos_infer::{Gguf, Model, Tokenizer};

/// The fixed chat prompt (user turn) of the lane's golden reference.
pub const PROMPT: &str = "What is the capital of France?";

/// Words written to `out` by `aienos_infer_probe`.
pub const OUT_WORDS: usize = 9;

extern "C" {
    /// Provided by native/kernel/core/infer.c: prints a message and halts the
    /// kernel with a panic report. Never returns.
    fn aienos_infer_panic() -> !;
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // SAFETY: plain C function with no arguments, defined by the kernel.
    unsafe { aienos_infer_panic() }
}

struct Bump {
    base: UnsafeCell<usize>,
    end: UnsafeCell<usize>,
    next: UnsafeCell<usize>,
    last: UnsafeCell<usize>, // start of the newest block, 0 if none
    peak: UnsafeCell<usize>,
}

// SAFETY: used from one core with interrupts masked (documented above).
unsafe impl Sync for Bump {}

#[global_allocator]
static HEAP: Bump = Bump {
    base: UnsafeCell::new(0),
    end: UnsafeCell::new(0),
    next: UnsafeCell::new(0),
    last: UnsafeCell::new(0),
    peak: UnsafeCell::new(0),
};

unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let next = *self.next.get();
        let start = match next.checked_add(l.align() - 1) {
            Some(v) => v & !(l.align() - 1),
            None => return core::ptr::null_mut(),
        };
        match start.checked_add(l.size()) {
            Some(e) if e <= *self.end.get() && *self.base.get() != 0 => {
                *self.next.get() = e;
                *self.last.get() = start;
                let used = e - *self.base.get();
                if used > *self.peak.get() {
                    *self.peak.get() = used;
                }
                start as *mut u8
            }
            _ => core::ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        if p as usize == *self.last.get() && p as usize + l.size() == *self.next.get() {
            *self.next.get() = p as usize;
            *self.last.get() = 0;
        }
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        if p as usize == *self.last.get() && p as usize + l.size() == *self.next.get() {
            if let Some(e) = (p as usize).checked_add(new_size) {
                if e <= *self.end.get() {
                    *self.next.get() = e;
                    let used = e - *self.base.get();
                    if used > *self.peak.get() {
                        *self.peak.get() = used;
                    }
                    return p;
                }
            }
            return core::ptr::null_mut();
        }
        let n = self.alloc(Layout::from_size_align_unchecked(new_size, l.align()));
        if !n.is_null() {
            core::ptr::copy_nonoverlapping(p, n, l.size().min(new_size));
        }
        n
    }
}

/// Gives the allocator its region `[base, base+len)`. Call once, before
/// `aienos_infer_probe`.
///
/// # Safety
/// The region must be writable RAM owned by the caller for the rest of the
/// run, 16-byte aligned, and not overlap the model bytes.
#[no_mangle]
pub unsafe extern "C" fn aienos_infer_heap_init(base: usize, len: usize) {
    *HEAP.base.get() = base;
    *HEAP.end.get() = base + len;
    *HEAP.next.get() = base;
    *HEAP.last.get() = 0;
    *HEAP.peak.get() = 0;
}

/// Error codes (negative): -1 null/short args, -2 GGUF parse, -3 model bind,
/// -4 tokenizer data, -5 tokenizer build, -6 encode, -7 fewer than 4 ids.
fn probe(bytes: &[u8], out: &mut [u32; OUT_WORDS]) -> i32 {
    let g = match Gguf::parse(bytes) {
        Ok(g) => g,
        Err(_) => return -2,
    };
    out[0] = g.tensors().len() as u32;
    let model = match Model::new(&g) {
        Ok(m) => m,
        Err(_) => return -3,
    };
    let td = match g.tokenizer() {
        Ok(t) => t,
        Err(_) => return -4,
    };
    let tok = match Tokenizer::new(&td) {
        Ok(t) => t,
        Err(_) => return -5,
    };
    out[1] = tok.vocab_size() as u32;
    let ids: Vec<u32> = match tok.encode_chat(PROMPT) {
        Ok(v) => v,
        Err(_) => return -6,
    };
    if ids.len() < 4 {
        return -7;
    }
    out[2..6].copy_from_slice(&ids[..4]);
    out[6] = ids.len() as u32;
    out[7] = model.params.block_count;
    0
}

/// Parses the GGUF at `model[..len]`, binds the `Model`, tokenizes
/// [`PROMPT`] with the chat template and writes nine u32 words to `out`:
///  [0] tensor count, [1] vocab size, [2..6] first four prompt token ids,
///  [6] prompt token count, [7] layer count, [8] allocator peak, in KiB.
/// Words are only meaningful up to the stage that failed. Returns 0 on
/// success, a negative code otherwise (see `probe`).
///
/// # Safety
/// `model` must point to `len` readable bytes and `out` to nine writable
/// u32. FP/SIMD must be enabled and interrupts masked (the kernel does not
/// save FP state). `aienos_infer_heap_init` must have been called.
#[no_mangle]
pub unsafe extern "C" fn aienos_infer_probe(model: *const u8, len: u64, out: *mut u32) -> i32 {
    if model.is_null() || out.is_null() || len == 0 || len > usize::MAX as u64 {
        return -1;
    }
    let bytes = slice::from_raw_parts(model, len as usize);
    let mut w = [0u32; OUT_WORDS];
    let rc = probe(bytes, &mut w);
    w[8] = (*HEAP.peak.get() / 1024) as u32;
    core::ptr::copy_nonoverlapping(w.as_ptr(), out, OUT_WORDS);
    rc
}
