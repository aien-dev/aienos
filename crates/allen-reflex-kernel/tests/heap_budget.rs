//! The kernel's run, on the host, under the kernel's own heap: this test installs the same bump
//! heap as the global allocator over a region of the size the kernel hands over
//! (`ALLEN_HEAP_BYTES` in `native/kernel/core/allen.c`) and runs the kernel's sequence: card index,
//! then per mode train + every case twice with the per-decision mark/reset. It checks that the
//! run fits, that every decision returns the heap to its mark (repeated decisions do not grow it),
//! that the second pass gives the same lines, and prints the peaks used in the docs.
//! Single-threaded on purpose (`harness = false`): the bump heap has no locking. Allocations
//! made by the std runtime before `main` hands the region over go to the system allocator.
use allen_reflex_kernel::heap::Bump;
use allen_reflex_kernel::{card, runner};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::UnsafeCell;

/// Must equal ALLEN_HEAP_BYTES in native/kernel/core/allen.c.
const ALLEN_HEAP_BYTES: usize = 32 << 20;

struct Region(UnsafeCell<[u64; ALLEN_HEAP_BYTES / 8]>);
unsafe impl Sync for Region {}
static REGION: Region = Region(UnsafeCell::new([0; ALLEN_HEAP_BYTES / 8]));

struct H {
    main: Bump,
}
unsafe impl Sync for H {}

fn mine(p: *mut u8) -> bool {
    let b = REGION.0.get() as usize;
    (b..b + ALLEN_HEAP_BYTES).contains(&(p as usize))
}

unsafe impl GlobalAlloc for H {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if self.main.stats().cap == 0 {
            return System.alloc(l);
        }
        self.main.alloc(l.size(), l.align()) as *mut u8
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        if mine(p) {
            self.main.dealloc(p as usize, l.size())
        } else {
            System.dealloc(p, l)
        }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        if !mine(p) {
            return System.realloc(p, l, n);
        }
        let q = self.main.resize_in_place(p as usize, l.size(), n);
        if q != 0 {
            return q as *mut u8;
        }
        let m = self.main.alloc(n, l.align());
        if m == 0 {
            return std::ptr::null_mut();
        }
        std::ptr::copy_nonoverlapping(p, m as *mut u8, l.size().min(n));
        self.main.dealloc(p as usize, l.size());
        m as *mut u8
    }
}

#[global_allocator]
static A: H = H { main: Bump::new() };

fn main() {
    // The region is handed over before this unit allocates anything (as the kernel does).
    A.main.init(REGION.0.get() as usize, ALLEN_HEAP_BYTES);
    // std allocates the stdout buffer on the first print: do it now, outside the measured marks
    println!("heap_budget: region {ALLEN_HEAP_BYTES} bytes");
    let exam = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/native/pi5-8/orchestrator-exam/"
    );
    let mut buf = b"AIENALX1 QUALIF-ALLEN-EXAM\n".to_vec();
    for split in ["cases-train.psv", "cases-dev.psv"] {
        let s = std::fs::read_to_string(format!("{exam}{split}")).unwrap();
        for l in s.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let f: Vec<&str> = l.splitn(5, '|').collect();
            buf.extend_from_slice(format!("{}|{}\n", f[0], f[4]).as_bytes());
        }
    }
    // the longest allowed turns field, with more turns than the core reads
    let long: String = std::iter::repeat_n("approve the plan ~~ ok", 180)
        .collect::<Vec<_>>()
        .join(" ~~ ");
    let long = &long[..4096];
    buf.extend_from_slice(format!("MAXTURNS|{long}\n").as_bytes());
    let cases = card::parse(&buf).expect("card");
    let mut fails = 0;
    let mut line = String::with_capacity(8192);
    // pass-1 lines kept in buffers allocated before any mark, so no decision leaves a live block
    let mut first = String::with_capacity(64 << 10);
    let mut ends: Vec<usize> = Vec::with_capacity(cases.len());
    let after_cases = A.main.mark();
    for mode in 0..3 {
        assert!(A.main.reset_to(after_cases), "heap back to the case index");
        A.main.reset_peaks();
        let sess = runner::Session::train(runner::mode_of(mode).unwrap()).expect("train");
        let after_train = A.main.stats();
        first.clear();
        ends.clear();
        for pass in 0..2 {
            for (k, c) in cases.iter().enumerate() {
                let id = std::str::from_utf8(&buf[c.id.0..c.id.1]).unwrap();
                let turns = std::str::from_utf8(&buf[c.turns.0..c.turns.1]).unwrap();
                let m = A.main.mark();
                let json = sess.decide_json(turns);
                runner::line(&mut line, sess.mode(), id, &json);
                drop(json);
                if pass == 0 {
                    first.push_str(&line);
                    ends.push(first.len());
                } else {
                    let s = if k == 0 { 0 } else { ends[k - 1] };
                    if &first[s..ends[k]] != line.as_str() {
                        fails += 1;
                    }
                }
                if !A.main.reset_to(m) {
                    fails += 1;
                }
            }
        }
        let st = A.main.stats();
        assert_eq!(st.fails, 0, "no refused allocation");
        // stdout of a harness=false test is shown by cargo test --nocapture style runs and CI logs
        println!(
            "heap_budget mode={} cap={} used_after_train={} peak={} live_peak={} memory_bytes={} cases={}",
            sess.mode().name(),
            st.cap,
            after_train.used,
            st.peak,
            st.live_peak,
            sess.memory_bytes(),
            cases.len()
        );
        drop(sess);
    }
    assert_eq!(
        fails, 0,
        "pass 2 identical and every decision reset the heap"
    );
    println!("heap_budget: PASS");
}
