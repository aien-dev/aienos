//! FP/SIMD probe: one unit that uses f32 math and NEON, called from the C
//! kernel (which is built -mgeneral-regs-only and never touches FP itself).
//! Inputs go through black_box so LLVM cannot constant-fold the FP work away
//! (the gate must execute real FP/SIMD instructions). No alloc, no std, no panics reachable (panic=abort, handler spins).
#![no_std]

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::*;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// Words written to `out` by `aienos_fpu_probe`.
pub const OUT_WORDS: usize = 6;

/// exp(x) for |x| < 80: x*log2(e) = n + f, 2^f by a degree-6 polynomial
/// (Taylor of e^(f*ln2), f in [0,1)), 2^n by building the exponent bits.
fn exp_approx(x: f32) -> f32 {
    let t = x * core::f32::consts::LOG2_E;
    let mut n = t as i32; // truncates toward zero
    if (n as f32) > t {
        n -= 1; // floor
    }
    let f = (t - n as f32) * core::f32::consts::LN_2; // in [0, ln2)
    let p = 1.0
        + f * (1.0
            + f * (0.5
                + f * (1.0 / 6.0 + f * (1.0 / 24.0 + f * (1.0 / 120.0 + f * (1.0 / 720.0))))));
    let scale = f32::from_bits(((n + 127) as u32) << 23);
    p * scale
}

/// Writes six u32 words to `out`:
///  [0] bits of dot(a, b) with a[i]=i+1, b[i]=0.5 (i in 0..16): exactly 68.0
///  [1] bits of exp_approx(1.0)
///  [2..6] NEON vaddq_f32([1,2,3,4], [10,20,30,40]) lanes as bits: 11,22,33,44
/// Returns 0 when all three agree with their known answers (dot exact,
/// exp(1) within 1e-4, NEON exact), else a bit mask of the failing parts
/// (1 dot, 2 exp, 4 neon), or -1 for a null `out`.
///
/// # Safety
/// `out` must point to at least 6 writable u32. FP/SIMD must be enabled for
/// the calling exception level (CPACR_EL1.FPEN) and interrupts masked: the
/// kernel does not save FP state across exceptions.
#[no_mangle]
pub unsafe extern "C" fn aienos_fpu_probe(out: *mut u32) -> i32 {
    if out.is_null() {
        return -1;
    }
    let mut a = [0.0f32; 16];
    let mut b = [0.0f32; 16];
    let mut i = 0;
    while i < 16 {
        a[i] = core::hint::black_box((i + 1) as f32);
        b[i] = core::hint::black_box(0.5f32);
        i += 1;
    }
    let mut dot = 0.0f32;
    i = 0;
    while i < 16 {
        dot += a[i] * b[i];
        i += 1;
    }
    let e = exp_approx(core::hint::black_box(1.0f32));

    let mut lanes = [0.0f32; 4];
    #[cfg(target_arch = "aarch64")]
    {
        let x = core::hint::black_box([1.0f32, 2.0, 3.0, 4.0]);
        let y = core::hint::black_box([10.0f32, 20.0, 30.0, 40.0]);
        let s = vaddq_f32(vld1q_f32(x.as_ptr()), vld1q_f32(y.as_ptr()));
        vst1q_f32(lanes.as_mut_ptr(), s);
    }

    out.add(0).write_volatile(dot.to_bits());
    out.add(1).write_volatile(e.to_bits());
    i = 0;
    while i < 4 {
        out.add(2 + i).write_volatile(lanes[i].to_bits());
        i += 1;
    }

    let mut rc = 0;
    if dot != 68.0 {
        rc |= 1;
    }
    let d = e - core::f32::consts::E;
    if !(d < 1e-4 && d > -1e-4) {
        rc |= 2;
    }
    if lanes != [11.0, 22.0, 33.0, 44.0] {
        rc |= 4;
    }
    rc
}
