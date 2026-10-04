//! Kernel-side entry for native inference (aienos#34 lane 4 cut 1 + lane 5
//! cut 2).
//!
//! The C kernel (built -mgeneral-regs-only) hands this staticlib the Llama
//! GGUF bytes it ingested into RAM; the unit parses the header with
//! `aienos_infer::Gguf`, binds the `Model`, tokenizes the fixed chat prompt,
//! runs prefill, greedy-decodes until `<|eot_id|>` (128009) or [`MAX_NEW`]
//! tokens and hands the ids, the decoded bytes and per-token timings back in
//! an [`InferResult`] for the kernel to print. The weights stay quantised in
//! the ingested bytes (Q4_K/Q6_K blocks are dequantised inside each dot
//! product by `aienos_infer`); only norms, the KV cache and activations live
//! on this unit's heap.
//!
//! Allocator: `aienos-infer` needs `alloc`. This crate installs a bump
//! allocator over ONE region the kernel provides (`aienos_infer_heap_init`,
//! a contiguous run of frames from `ck_mm_frames_alloc`). Allocation moves a
//! cursor; `dealloc` only reclaims when the block is the newest one and
//! `realloc` grows the newest block in place, otherwise memory is not
//! reused. The forward pass allocates nothing (`DecodeState` is sized up
//! front), so this is enough for one load + one generation; it is NOT a
//! general allocator. Single core, interrupts masked by the caller: no
//! locking. Exhaustion returns null, which Rust turns into a panic, which
//! calls `aienos_infer_panic` (the C kernel prints and stops; it never
//! returns). Unload: the kernel returns the region's frames and calls
//! `aienos_infer_heap_init(0, 0)`, after which every allocation fails closed.
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::slice;

use aienos_infer::{argmax, DecodeState, Gguf, Model, Tokenizer};

/// The fixed chat prompt (user turn) of the lane's golden reference.
pub const PROMPT: &str = "What is the capital of France?";

/// `<|eot_id|>`: end of the assistant turn (tokenizer.ggml.eos_token_id of
/// the frozen model; `crates/aienos-infer/tests/forward.rs` asserts 128009).
pub const EOT: u32 = 128009;

/// Generation stops after this many tokens if no EOT came first.
pub const MAX_NEW: usize = 16;

/// KV-cache positions: the 17-token prompt plus [`MAX_NEW`], rounded up.
pub const KV_CAPACITY: usize = 64;

/// Bytes of decoded text kept for the kernel to print.
pub const TEXT_BYTES: usize = 256;

/// Words in [`InferResult::words`] (the cut-1 probe words).
pub const OUT_WORDS: usize = 9;

/// What the kernel gets back. `#[repr(C)]`: the C side declares the same
/// struct (native/kernel/core/infer.c `struct infer_result`).
#[repr(C)]
pub struct InferResult {
    /// [0] tensor count, [1] vocab size, [2..6] first four prompt ids,
    /// [6] prompt token count, [7] layer count, [8] allocator peak in KiB.
    pub words: [u32; OUT_WORDS],
    /// Generated tokens (`tokens[..ntok]`), EOT included when it came.
    pub ntok: u32,
    pub tokens: [u32; MAX_NEW],
    /// Microseconds of the forward pass that produced `tokens[i]`'s logits
    /// for i >= 1 (`tok_us[0]` is 0: token 0 comes from the prefill).
    pub tok_us: [u64; MAX_NEW],
    /// Microseconds of the whole prefill (one forward per prompt token).
    pub prefill_us: u64,
    /// Decoded bytes of `tokens[..ntok]` (`text[..text_len]`, truncated to
    /// [`TEXT_BYTES`]; control tokens decode to nothing).
    pub text_len: u32,
    pub text: [u8; TEXT_BYTES],
}

extern "C" {
    /// Provided by native/kernel/core/infer.c: prints a message and halts the
    /// kernel with a panic report. Never returns.
    fn aienos_infer_panic() -> !;
    /// Kernel monotonic clock in microseconds (native/kernel/include/ck.h).
    /// General-registers-only C: safe to call with FP state live.
    fn ck_time_us() -> u64;
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
/// `aienos_infer_run`. Calling it again with `(0, 0)` after the kernel has
/// returned the frames forgets the region: every later allocation fails
/// closed (null -> panic) instead of touching freed memory.
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
/// -4 tokenizer data, -5 tokenizer build, -6 encode, -7 fewer than 4 ids,
/// -8 prompt longer than the KV cache, -9 prefill, -10 decode forward,
/// -11 token-to-text decode.
fn run(bytes: &[u8], r: &mut InferResult) -> i32 {
    let g = match Gguf::parse(bytes) {
        Ok(g) => g,
        Err(_) => return -2,
    };
    r.words[0] = g.tensors().len() as u32;
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
    r.words[1] = tok.vocab_size() as u32;
    let ids: Vec<u32> = match tok.encode_chat(PROMPT) {
        Ok(v) => v,
        Err(_) => return -6,
    };
    if ids.len() < 4 {
        return -7;
    }
    r.words[2..6].copy_from_slice(&ids[..4]);
    r.words[6] = ids.len() as u32;
    r.words[7] = model.params.block_count;
    if ids.len() + MAX_NEW > KV_CAPACITY {
        return -8;
    }

    // Same path as the host test (crates/aienos-infer/tests/forward.rs):
    // DecodeState + prefill + argmax + forward(t, true), f32 activations.
    let mut st = DecodeState::new(&model, KV_CAPACITY);
    // SAFETY: ck_time_us is a plain C function with no arguments.
    let t0 = unsafe { ck_time_us() };
    if st.prefill(&model, &ids).is_err() {
        return -9;
    }
    r.prefill_us = unsafe { ck_time_us() } - t0;
    let mut n = 0usize;
    loop {
        let t = argmax(&st.logits);
        r.tokens[n] = t;
        n += 1;
        if t == EOT || n == MAX_NEW {
            break;
        }
        let t1 = unsafe { ck_time_us() };
        if st.forward(&model, t, true).is_err() {
            r.ntok = n as u32;
            return -10;
        }
        r.tok_us[n] = unsafe { ck_time_us() } - t1;
    }
    r.ntok = n as u32;
    let text = match tok.decode(&r.tokens[..n]) {
        Ok(v) => v,
        Err(_) => return -11,
    };
    let keep = text.len().min(TEXT_BYTES);
    r.text[..keep].copy_from_slice(&text[..keep]);
    r.text_len = keep as u32;
    0
    // st, tok, model, g drop here: nothing of the model outlives this call.
}

/// Parses the GGUF at `model[..len]`, binds the `Model`, tokenizes [`PROMPT`]
/// with the chat template, runs prefill and greedy decode and fills `out`.
/// Fields are only meaningful up to the stage that failed. Returns 0 on
/// success, a negative code otherwise (see `run`).
///
/// # Safety
/// `model` must point to `len` readable bytes and `out` to one writable
/// `InferResult`. FP/SIMD must be enabled and interrupts masked (the kernel
/// does not save FP state). `aienos_infer_heap_init` must have been called.
#[no_mangle]
pub unsafe extern "C" fn aienos_infer_run(
    model: *const u8,
    len: u64,
    out: *mut InferResult,
) -> i32 {
    if model.is_null() || out.is_null() || len == 0 || len > usize::MAX as u64 {
        return -1;
    }
    let bytes = slice::from_raw_parts(model, len as usize);
    let r = &mut *out;
    *r = InferResult {
        words: [0; OUT_WORDS],
        ntok: 0,
        tokens: [0; MAX_NEW],
        tok_us: [0; MAX_NEW],
        prefill_us: 0,
        text_len: 0,
        text: [0; TEXT_BYTES],
    };
    let rc = run(bytes, r);
    r.words[8] = (*HEAP.peak.get() / 1024) as u32;
    rc
}
