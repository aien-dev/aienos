//! Bounded inference session for the resident kernel (native v1 P06).
//!
//! The one-shot probe (`aienos_infer_run`) parses, prefills, decodes and
//! drops everything inside one call with a fixed prompt. A resident product
//! needs the same work split into steps the kernel drives: load the model
//! once, accept an operator prompt, advance one token at a time so the
//! kernel can look at the console between steps (cancellation), decode the
//! result, unload. Every bound is a number the kernel configures
//! ([`SessionLimits`]); nothing here loops without the kernel asking.
//!
//! One session at a time (single core, interrupts masked by the caller).
//! Memory: the session's buffers come from the bump allocator the kernel
//! gave this unit; the decode state is sized once at open and reused by
//! every prompt (`DecodeState::reset`), so a prompt allocates only its id
//! list and its decoded text. The allocator never reclaims old blocks, so a
//! long run of prompts creeps upward; `heap_reserve` turns that creep into a
//! refusal (`E_HEAP`) before any allocation can fail, and the kernel can
//! read the creep (`aienos_infer_heap_stats`) and show it.

use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::slice;

use aienos_infer::{argmax, DecodeState, Gguf, Model, Tokenizer};

use crate::{ck_time_us, heap_remaining, EOT};

/// Limits the kernel sets at open. All are hard bounds, none is advisory.
#[repr(C)]
pub struct SessionLimits {
    /// KV-cache positions: prompt tokens + generated tokens never exceed it.
    pub kv_capacity: u32,
    /// Generated tokens per prompt (EOT counts).
    pub max_new: u32,
    /// Prompt text bytes the session accepts.
    pub max_prompt_bytes: u32,
    /// Heap bytes that must still be free before a prompt is accepted.
    pub heap_reserve: u32,
}

/// What open reports back.
#[repr(C)]
pub struct SessionInfo {
    pub tensors: u32,
    pub vocab: u32,
    pub layers: u32,
    pub heap_used_kib: u32,
}

/// Session error codes (negative). The one-shot probe's codes -1..-11 keep
/// their meaning; these continue the list.
pub const E_ARG: i32 = -1;
pub const E_GGUF: i32 = -2;
pub const E_MODEL: i32 = -3;
pub const E_TOK_DATA: i32 = -4;
pub const E_TOK_BUILD: i32 = -5;
pub const E_ENCODE: i32 = -6;
pub const E_TOO_LONG: i32 = -8;
pub const E_FORWARD: i32 = -10;
pub const E_DECODE: i32 = -11;
pub const E_STATE: i32 = -12; /* no session / session already open / no prompt */
pub const E_LIMITS: i32 = -13;
pub const E_UTF8: i32 = -14;
pub const E_HEAP: i32 = -15;
pub const E_PROMPT_BYTES: i32 = -16;

/// Step results (non-negative).
pub const STEP_DONE: i32 = 0; /* nothing left: EOT or max_new reached, or no prompt */
pub const STEP_PREFILL: i32 = 1; /* one prompt token fed, no token produced */
pub const STEP_TOKEN: i32 = 2; /* one token produced, more may follow */
pub const STEP_LAST: i32 = 3; /* one token produced and the reply is complete */

/// The largest KV capacity a session may ask for (a bound on the cache
/// allocation; 4096 positions of Llama-3.2-1B is about 256 MiB of f32 KV,
/// which is the whole probe heap, so real limits sit far below).
pub const KV_CAPACITY_MAX: u32 = 4096;

struct Session {
    model: Model<'static>,
    tok: Tokenizer<'static>,
    st: DecodeState,
    limits: SessionLimits,
    /// Prompt ids of the current request; `fed` of them are in the cache.
    prompt: Vec<u32>,
    fed: usize,
    /// Tokens produced for the current request.
    out: Vec<u32>,
    done: bool,
}

struct Slot(UnsafeCell<Option<Session>>);
// SAFETY: one core, interrupts masked by the caller (see the module doc).
unsafe impl Sync for Slot {}
static SLOT: Slot = Slot(UnsafeCell::new(None));

fn slot() -> &'static mut Option<Session> {
    // SAFETY: single-threaded by contract; no reference escapes a call.
    unsafe { &mut *SLOT.0.get() }
}

/// Load the model at `model[..len]` and size the decode state for
/// `limits`. Returns 0 and fills `info`, or a negative code. `E_STATE` when
/// a session is already open.
///
/// # Safety
/// `model` must point to `len` bytes that stay readable and unchanged until
/// `aienos_infer_session_close`; `limits` and `info` must be valid. FP/SIMD
/// enabled, interrupts masked, heap initialised (as for `aienos_infer_run`).
#[no_mangle]
pub unsafe extern "C" fn aienos_infer_session_open(
    model: *const u8,
    len: u64,
    limits: *const SessionLimits,
    info: *mut SessionInfo,
) -> i32 {
    if model.is_null() || limits.is_null() || info.is_null() || len == 0 || len > usize::MAX as u64
    {
        return E_ARG;
    }
    if slot().is_some() {
        return E_STATE;
    }
    let l = SessionLimits {
        kv_capacity: (*limits).kv_capacity,
        max_new: (*limits).max_new,
        max_prompt_bytes: (*limits).max_prompt_bytes,
        heap_reserve: (*limits).heap_reserve,
    };
    if l.kv_capacity == 0
        || l.kv_capacity > KV_CAPACITY_MAX
        || l.max_new == 0
        || l.max_new > l.kv_capacity
        || l.max_prompt_bytes == 0
    {
        return E_LIMITS;
    }
    let bytes: &'static [u8] = slice::from_raw_parts(model, len as usize);
    let g = match Gguf::parse(bytes) {
        Ok(g) => g,
        Err(_) => return E_GGUF,
    };
    let tensors = g.tensors().len() as u32;
    let model = match Model::new(&g) {
        Ok(m) => m,
        Err(_) => return E_MODEL,
    };
    let td = match g.tokenizer() {
        Ok(t) => t,
        Err(_) => return E_TOK_DATA,
    };
    let tok = match Tokenizer::new(&td) {
        Ok(t) => t,
        Err(_) => return E_TOK_BUILD,
    };
    let st = DecodeState::new(&model, l.kv_capacity as usize);
    (*info).tensors = tensors;
    (*info).vocab = tok.vocab_size() as u32;
    (*info).layers = model.params.block_count;
    (*info).heap_used_kib = (crate::heap_used() / 1024) as u32;
    *slot() = Some(Session {
        model,
        tok,
        st,
        limits: l,
        prompt: Vec::new(),
        fed: 0,
        out: Vec::new(),
        done: true,
    });
    0
}

/// Accept a new prompt (UTF-8 text of the user turn; the chat template is
/// applied as in the probe). Forgets the previous request. Returns the
/// prompt's token count, or a negative code: `E_PROMPT_BYTES` (over
/// `max_prompt_bytes`), `E_HEAP` (less than `heap_reserve` free), `E_UTF8`,
/// `E_ENCODE`, `E_TOO_LONG` (prompt + max_new would not fit the cache).
/// Nothing is fed to the model here; the first steps do that.
///
/// # Safety
/// `text` must point to `len` readable bytes. Same execution contract as open.
#[no_mangle]
pub unsafe extern "C" fn aienos_infer_session_prompt(text: *const u8, len: u32) -> i32 {
    let s = match slot() {
        Some(s) => s,
        None => return E_STATE,
    };
    if text.is_null() && len != 0 {
        return E_ARG;
    }
    if len > s.limits.max_prompt_bytes {
        return E_PROMPT_BYTES;
    }
    if heap_remaining() < s.limits.heap_reserve as usize {
        return E_HEAP;
    }
    let bytes = if len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(text, len as usize)
    };
    let user = match core::str::from_utf8(bytes) {
        Ok(u) => u,
        Err(_) => return E_UTF8,
    };
    let ids = match s.tok.encode_chat(user) {
        Ok(v) => v,
        Err(_) => return E_ENCODE,
    };
    if ids.len() + s.limits.max_new as usize > s.limits.kv_capacity as usize {
        return E_TOO_LONG;
    }
    s.st.reset();
    s.prompt = ids;
    s.fed = 0;
    s.out = Vec::new();
    s.done = false;
    s.prompt.len() as i32
}

/// Advance the current request by one unit of work:
/// `STEP_PREFILL` (one prompt token entered the cache), `STEP_TOKEN` (a
/// token was produced into `*token` and its forward pass ran),
/// `STEP_LAST` (a token was produced and the reply is complete: EOT or
/// `max_new`), `STEP_DONE` (nothing left). `*us` receives the microseconds
/// the step took. Negative: `E_STATE` (no session), `E_FORWARD`.
///
/// # Safety
/// `token` and `us` must be valid or null. Same execution contract as open.
#[no_mangle]
pub unsafe extern "C" fn aienos_infer_session_step(token: *mut u32, us: *mut u64) -> i32 {
    let s = match slot() {
        Some(s) => s,
        None => return E_STATE,
    };
    if s.done {
        return STEP_DONE;
    }
    let t0 = ck_time_us();
    let rc;
    if s.fed < s.prompt.len() {
        let id = s.prompt[s.fed];
        let last = s.fed + 1 == s.prompt.len();
        if s.st.forward(&s.model, id, last).is_err() {
            s.done = true;
            return E_FORWARD;
        }
        s.fed += 1;
        rc = STEP_PREFILL;
    } else {
        let t = argmax(&s.st.logits);
        s.out.push(t);
        if !token.is_null() {
            *token = t;
        }
        if t == EOT || s.out.len() >= s.limits.max_new as usize {
            s.done = true;
            rc = STEP_LAST;
        } else {
            if s.st.forward(&s.model, t, true).is_err() {
                s.done = true;
                return E_FORWARD;
            }
            rc = STEP_TOKEN;
        }
    }
    if !us.is_null() {
        *us = ck_time_us() - t0;
    }
    rc
}

/// Copy the token ids of the current request's prompt (chat template included) into `out[..cap]`.
/// Returns the number of prompt ids (which may exceed `cap`; only `cap` are copied), 0 when no prompt
/// is pending, or `E_STATE` without a session. The kernel uses the first four ids to check the chat
/// template the tokenizer built (PI5-6 agent: restores the one-shot probe's expect_ids check).
///
/// # Safety
/// `out` must point to `cap` writable u32s (or be null with `cap` 0). Same execution contract as open.
#[no_mangle]
pub unsafe extern "C" fn aienos_infer_session_prompt_ids(out: *mut u32, cap: u32) -> i32 {
    let s = match slot() {
        Some(s) => s,
        None => return E_STATE,
    };
    if out.is_null() && cap != 0 {
        return E_ARG;
    }
    let n = s.prompt.len().min(cap as usize);
    if n > 0 {
        core::ptr::copy_nonoverlapping(s.prompt.as_ptr(), out, n);
    }
    s.prompt.len() as i32
}

/// Abandon the current request: the cache is forgotten and no further step
/// does work. Returns the number of tokens produced before the cancel, or
/// `E_STATE` without a session. Idempotent.
///
/// # Safety
/// Same execution contract as open.
#[no_mangle]
pub unsafe extern "C" fn aienos_infer_session_cancel() -> i32 {
    let s = match slot() {
        Some(s) => s,
        None => return E_STATE,
    };
    let n = s.out.len() as i32;
    s.st.reset();
    s.prompt = Vec::new();
    s.fed = 0;
    s.out = Vec::new();
    s.done = true;
    n
}

/// Copy the tokens produced for the current request into `out[..cap]`.
/// Returns the count produced so far (which may exceed `cap`; only `cap`
/// are copied), or `E_STATE`.
///
/// # Safety
/// `out` must point to `cap` writable u32s. Same execution contract as open.
#[no_mangle]
pub unsafe extern "C" fn aienos_infer_session_tokens(out: *mut u32, cap: u32) -> i32 {
    let s = match slot() {
        Some(s) => s,
        None => return E_STATE,
    };
    let n = s.out.len().min(cap as usize);
    if n > 0 {
        core::ptr::copy_nonoverlapping(s.out.as_ptr(), out, n);
    }
    s.out.len() as i32
}

/// Decode `ids[..n]` to bytes into `out[..cap]` (truncated to `cap`).
/// Returns the number of bytes written, or `E_STATE` / `E_DECODE`.
///
/// # Safety
/// `ids` must point to `n` u32s and `out` to `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aienos_infer_session_text(
    ids: *const u32,
    n: u32,
    out: *mut u8,
    cap: u32,
) -> i32 {
    let s = match slot() {
        Some(s) => s,
        None => return E_STATE,
    };
    if (ids.is_null() && n != 0) || (out.is_null() && cap != 0) {
        return E_ARG;
    }
    let ids = if n == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(ids, n as usize)
    };
    let text = match s.tok.decode(ids) {
        Ok(v) => v,
        Err(_) => return E_DECODE,
    };
    let keep = text.len().min(cap as usize);
    if keep > 0 {
        core::ptr::copy_nonoverlapping(text.as_ptr(), out, keep);
    }
    keep as i32
}

/// Drop the session: model binding, tokenizer, cache, request. Returns 0,
/// or `E_STATE` when none is open. The kernel then forgets the heap region
/// and returns its frames, as after `aienos_infer_run`.
///
/// # Safety
/// Same execution contract as open.
#[no_mangle]
pub unsafe extern "C" fn aienos_infer_session_close() -> i32 {
    if slot().is_none() {
        return E_STATE;
    }
    *slot() = None;
    0
}
