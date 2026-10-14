//! Kernel side (`target_os = "none"` only): global allocator, panic handler and the C entry points
//! called by `native/kernel/core/allen.c`. Single core, interrupts and FP exceptions masked by the
//! caller for the whole time Rust code runs (as for the inference unit, `core/fpu.c`).
//!
//! Stop rule: any Rust panic, including an allocation the bounded heap cannot satisfy (Rust's
//! allocation-error path panics), calls `aienos_allen_panic`, which prints the reason and halts
//! through the kernel's panic path. It never returns, so the decision in progress is never
//! printed, never reaches the gate, and nothing is written (the pi5-allen image has no Store stage).

use alloc::string::String;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::arch::asm;
use core::cell::UnsafeCell;
use core::fmt::Write;

use crate::card::{self, CaseRef};
use crate::heap::{Bump, Mark, Stats};
use crate::runner::{self, Session};

extern "C" {
    /// `native/kernel/core/allen.c`: prints `msg[..len]` and halts through `ck_panic`. Never returns.
    fn aienos_allen_panic(msg: *const u8, len: usize) -> !;
}

struct KHeap(Bump);
// SAFETY: one core, interrupts masked while Rust runs (module doc).
unsafe impl Sync for KHeap {}

#[global_allocator]
static HEAP: KHeap = KHeap(Bump::new());

unsafe impl GlobalAlloc for KHeap {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        self.0.alloc(l.size(), l.align()) as *mut u8
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        self.0.dealloc(p as usize, l.size())
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        let q = self.0.resize_in_place(p as usize, l.size(), new_size);
        if q != 0 {
            return q as *mut u8;
        }
        let n = self.0.alloc(new_size, l.align());
        if n == 0 {
            return core::ptr::null_mut();
        }
        // SAFETY: both blocks are valid for the smaller size and do not overlap (n is new).
        core::ptr::copy_nonoverlapping(p, n as *mut u8, core::cmp::min(l.size(), new_size));
        self.0.dealloc(p as usize, l.size());
        n as *mut u8
    }
}

struct Msg {
    buf: [u8; 192],
    len: usize,
}

impl Write for Msg {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for &b in s.as_bytes() {
            if self.len < self.buf.len() {
                self.buf[self.len] = if (0x20..=0x7e).contains(&b) { b } else { b'?' };
                self.len += 1;
            }
        }
        Ok(())
    }
}

struct PanicBuf(UnsafeCell<Msg>);
// SAFETY: written once, on the single core, right before halting.
unsafe impl Sync for PanicBuf {}
static PANIC_MSG: PanicBuf = PanicBuf(UnsafeCell::new(Msg {
    buf: [0; 192],
    len: 0,
}));

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // SAFETY: single core; the kernel halts right after, so no one else touches the buffer.
    let m = unsafe { &mut *PANIC_MSG.0.get() };
    m.len = 0;
    let _ = write!(m, "{}", info.message());
    if let Some(loc) = info.location() {
        let _ = write!(m, " at {}:{}", loc.file(), loc.line());
    }
    // SAFETY: plain C function, defined by the kernel; the buffer outlives the call.
    unsafe { aienos_allen_panic(m.buf.as_ptr(), m.len) }
}

struct State {
    card: *const u8,
    card_len: usize,
    cases: Option<Vec<CaseRef>>,
    after_cases: Option<Mark>,
    session: Option<Session>,
    line: String,
}

struct Global(UnsafeCell<State>);
// SAFETY: one core, calls from the kernel never overlap (module doc).
unsafe impl Sync for Global {}
static G: Global = Global(UnsafeCell::new(State {
    card: core::ptr::null(),
    card_len: 0,
    cases: None,
    after_cases: None,
    session: None,
    line: String::new(),
}));

fn st() -> &'static mut State {
    // SAFETY: see `Global`.
    unsafe { &mut *G.0.get() }
}

fn ticks() -> u64 {
    let v: u64;
    // SAFETY: reads the virtual counter (always readable at EL1).
    unsafe { asm!("isb", "mrs {}, cntvct_el0", out(reg) v, options(nomem, nostack)) };
    v
}

/// Counter frequency in Hz (CNTFRQ_EL0): ticks of [`DecideInfo::ticks`] and [`TrainInfo::ticks`].
#[no_mangle]
pub extern "C" fn aienos_allen_tick_hz() -> u64 {
    let v: u64;
    // SAFETY: reads a read-only system register.
    unsafe { asm!("mrs {}, cntfrq_el0", out(reg) v, options(nomem, nostack)) };
    v
}

/// Hand the heap region over (`len == 0` closes it: every allocation fails from then on).
/// Drops nothing: call [`aienos_allen_close`] first.
///
/// # Safety
/// `[base, base + len)` must be writable memory owned by this unit until the next call.
#[no_mangle]
pub unsafe extern "C" fn aienos_allen_heap_init(base: usize, len: usize) {
    HEAP.0.init(base, len);
}

/// Heap counters now.
///
/// # Safety
/// `out` must point to a writable `Stats`.
#[no_mangle]
pub unsafe extern "C" fn aienos_allen_heap_stats(out: *mut Stats) {
    if !out.is_null() {
        *out = HEAP.0.stats();
    }
}

/// Check the card exam file and keep its case index. Returns the case count, or -1 with
/// `*why` set to a NUL-terminated reason. The buffer must stay unchanged until close.
///
/// # Safety
/// `buf[..len]` readable for the lifetime of the run; `why` null or writable.
#[no_mangle]
pub unsafe extern "C" fn aienos_allen_card_open(
    buf: *const u8,
    len: usize,
    why: *mut *const u8,
) -> i32 {
    let s = st();
    s.session = None;
    s.cases = None;
    let b = core::slice::from_raw_parts(buf, len);
    match card::parse(b) {
        Ok(c) => {
            let n = c.len() as i32;
            s.card = buf;
            s.card_len = len;
            s.cases = Some(c);
            s.line = String::with_capacity(8192);
            s.after_cases = Some(HEAP.0.mark());
            n
        }
        Err(e) => {
            if !why.is_null() {
                *why = reason_cstr(e);
            }
            -1
        }
    }
}

fn reason_cstr(e: &'static str) -> *const u8 {
    // Static, NUL-terminated copies of every reason card::parse can give.
    const R: [&[u8]; 11] = [
        b"file size must be 1..131072 bytes\0",
        b"only printable ASCII and LF line ends are allowed\0",
        b"file does not end with a line feed\0",
        b"bad header line\0",
        b"empty line\0",
        b"more than 512 cases\0",
        b"case line has no '|' after the id\0",
        b"id must be 1..16 bytes\0",
        b"id may hold only A-Z a-z 0-9 _ -\0",
        b"turns must be 1..4096 bytes\0",
        b"duplicate case id\0",
    ];
    for r in R {
        if &r[..r.len() - 1] == e.as_bytes() {
            return r.as_ptr();
        }
    }
    c"malformed".as_ptr().cast()
}

/// What training reports. `#[repr(C)]`, mirrored in `core/allen.c`.
#[repr(C)]
pub struct TrainInfo {
    /// counter ticks spent training (pool parse + train + finish), at [`aienos_allen_tick_hz`]
    pub ticks: u64,
    /// training examples
    pub examples: u64,
    /// exemplars kept
    pub exemplars: u64,
    /// learned-state bytes (capacity based, the core's own count)
    pub memory_bytes: u64,
}

/// Train a fresh core for `mode` (0 reflex, 1 nearest, 2 perceptron), dropping the previous one
/// and returning the heap to the state right after the case index. 0 ok; -1 bad mode or no card;
/// -2 training refused.
///
/// # Safety
/// `out` null or writable.
#[no_mangle]
pub unsafe extern "C" fn aienos_allen_train(mode: u32, out: *mut TrainInfo) -> i32 {
    let s = st();
    s.session = None;
    let (Some(m), Some(mark)) = (runner::mode_of(mode), s.after_cases) else {
        return -1;
    };
    HEAP.0.reset_to(mark);
    HEAP.0.reset_peaks();
    let t0 = ticks();
    let r = Session::train(m);
    let dt = ticks().wrapping_sub(t0);
    match r {
        Ok(sess) => {
            if !out.is_null() {
                *out = TrainInfo {
                    ticks: dt,
                    examples: sess.examples() as u64,
                    exemplars: sess.exemplars() as u64,
                    memory_bytes: sess.memory_bytes() as u64,
                };
            }
            s.session = Some(sess);
            0
        }
        Err(_) => -2,
    }
}

/// What one decision reports. `#[repr(C)]`, mirrored in `core/allen.c`.
#[repr(C)]
pub struct DecideInfo {
    /// bytes of the line written (no NUL)
    pub len: u64,
    /// offset of the decision JSON in the line
    pub json_off: u64,
    /// counter ticks of the decision itself (turn split + core.decide + JSON), not the line copy
    pub ticks: u64,
    /// 1 when the heap went back to its pre-decision mark
    pub heap_reset: u64,
}

/// Decide case `i` with the trained core and write `ALLEN_D <mode> <id> <json>` into `line`
/// (`cap` bytes, NUL-terminated). 0 ok; -1 no core/case; -2 line buffer too small.
///
/// # Safety
/// `line[..cap]` writable; `out` null or writable.
#[no_mangle]
pub unsafe extern "C" fn aienos_allen_decide(
    i: u32,
    line: *mut u8,
    cap: usize,
    out: *mut DecideInfo,
) -> i32 {
    let s = st();
    let (Some(sess), Some(cases)) = (s.session.as_ref(), s.cases.as_ref()) else {
        return -1;
    };
    let Some(c) = cases.get(i as usize).copied() else {
        return -1;
    };
    let card = core::slice::from_raw_parts(s.card, s.card_len);
    // card::parse admitted printable ASCII only: both ranges are valid UTF-8.
    let (Ok(id), Ok(turns)) = (
        core::str::from_utf8(&card[c.id.0..c.id.1]),
        core::str::from_utf8(&card[c.turns.0..c.turns.1]),
    ) else {
        return -1;
    };
    let mark = HEAP.0.mark();
    let (json_off, dt, len) = {
        let t0 = ticks();
        let json = sess.decide_json(turns);
        let dt = ticks().wrapping_sub(t0);
        let off = runner::line(&mut s.line, sess.mode(), id, &json);
        (off, dt, s.line.len())
    };
    if len + 1 > cap {
        return -2;
    }
    core::ptr::copy_nonoverlapping(s.line.as_ptr(), line, len);
    *line.add(len) = 0;
    let reset = HEAP.0.reset_to(mark);
    if !out.is_null() {
        *out = DecideInfo {
            len: len as u64,
            json_off: json_off as u64,
            ticks: dt,
            heap_reset: reset as u64,
        };
    }
    0
}

/// Drop the trained core and the case index; the heap is back at its start (if all was freed).
#[no_mangle]
pub extern "C" fn aienos_allen_close() {
    let s = st();
    s.session = None;
    s.cases = None;
    s.line = String::new();
    s.after_cases = None;
    s.card = core::ptr::null();
    s.card_len = 0;
}
