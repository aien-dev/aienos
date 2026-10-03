//! Scalar f32 math without libm (no_std).
//!
//! `exp_approx`, `sqrt_approx` and `sin_cos` are adapted from the retired
//! kernel crate's `crates/aienos-kernel/src/infer/{gemm,rope}.rs` (same
//! authors, Apache-2.0); `exp` got one more series term and `ln` is new.

use core::f32::consts::{FRAC_PI_2, LN_2, LOG2_E, PI, TAU};

/// Newton square root from a bit-trick seed (error ~1 ulp).
pub fn sqrt(x: f32) -> f32 {
    if x <= 0.0 {
        return 0.0;
    }
    let mut y = f32::from_bits((x.to_bits() >> 1) + 0x1fc0_0000);
    for _ in 0..5 {
        y = 0.5 * (y + x / y);
    }
    y
}

/// `e^x` by range reduction to `|r| <= ln2/2` and a degree-6 series
/// (relative error below 2e-7 on [-87, 88]).
pub fn exp(x: f32) -> f32 {
    let x = x.clamp(-87.0, 88.0);
    let scaled = x * LOG2_E;
    let n = if scaled >= 0.0 {
        (scaled + 0.5) as i32
    } else {
        (scaled - 0.5) as i32
    };
    let r = x - n as f32 * LN_2;
    let p = 1.0
        + r * (1.0
            + r * (0.5 + r * (1.0 / 6.0 + r * (1.0 / 24.0 + r * (1.0 / 120.0 + r / 720.0)))));
    p * f32::from_bits(((n + 127) as u32) << 23)
}

/// Natural log for positive normal `x` (frexp then atanh series on
/// the mantissa folded to [sqrt(1/2), sqrt(2)]; error below 1e-7).
pub fn ln(x: f32) -> f32 {
    let bits = x.to_bits();
    let mut e = ((bits >> 23) & 0xff) as i32 - 127;
    let mut m = f32::from_bits((bits & 0x7f_ffff) | (127 << 23));
    if m > core::f32::consts::SQRT_2 {
        m *= 0.5;
        e += 1;
    }
    let y = (m - 1.0) / (m + 1.0);
    let y2 = y * y;
    let s = y
        * (1.0
            + y2 * (1.0 / 3.0
                + y2 * (1.0 / 5.0 + y2 * (1.0 / 7.0 + y2 * (1.0 / 9.0 + y2 / 11.0)))));
    2.0 * s + e as f32 * LN_2
}

/// `base^e` for positive `base`.
pub fn powf(base: f32, e: f32) -> f32 {
    exp(e * ln(base))
}

/// `(sin, cos)`. Reduce to [-pi, pi], fold to [-pi/2, pi/2], Taylor series
/// (about 1e-6 absolute).
pub fn sin_cos(angle: f32) -> (f32, f32) {
    let mut r = (angle + PI) % TAU;
    if r < 0.0 {
        r += TAU;
    }
    let mut x = r - PI;
    let mut cos_sign = 1.0;
    if x > FRAC_PI_2 {
        x = PI - x;
        cos_sign = -1.0;
    } else if x < -FRAC_PI_2 {
        x = -PI - x;
        cos_sign = -1.0;
    }
    let x2 = x * x;
    let sin = x
        * (1.0
            + x2 * (-1.0 / 6.0
                + x2 * (1.0 / 120.0 + x2 * (-1.0 / 5040.0 + x2 * (1.0 / 362_880.0)))));
    let cos = 1.0
        + x2 * (-1.0 / 2.0
            + x2 * (1.0 / 24.0 + x2 * (-1.0 / 720.0 + x2 * (1.0 / 40_320.0 - x2 / 3_628_800.0))));
    (sin, cos_sign * cos)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(a: f32, b: f32) -> f32 {
        (a - b).abs() / b.abs().max(1e-30)
    }

    #[test]
    fn exp_matches_std() {
        let mut x = -80.0f32;
        while x < 80.0 {
            assert!(rel(exp(x), x.exp()) < 5e-7, "exp({x})");
            x += 0.173;
        }
    }

    #[test]
    fn ln_matches_std() {
        let mut x = 1e-6f32;
        while x < 1e6 {
            let (a, b) = (ln(x), x.ln());
            assert!((a - b).abs() < 2e-6 * b.abs().max(1.0), "ln({x}) {a} {b}");
            x *= 1.37;
        }
    }

    #[test]
    fn powf_rope_theta_scale() {
        // llama.cpp: theta_scale = powf(freq_base, -2/n_rot)
        let (a, b) = (powf(500000.0, -2.0 / 64.0), 500000f32.powf(-2.0 / 64.0));
        assert!(rel(a, b) < 1e-6, "{a} {b}");
    }

    #[test]
    fn sqrt_matches_std() {
        for &x in &[1e-8f32, 0.25, 1.0, 2.0, 1234.5, 1e9] {
            assert!(rel(sqrt(x), x.sqrt()) < 2e-7, "sqrt({x})");
        }
    }

    #[test]
    fn sin_cos_matches_std_and_unit_norm() {
        let mut a = -50.0f32;
        while a < 600.0 {
            let (s, c) = sin_cos(a);
            assert!((s - a.sin()).abs() < 3e-5, "sin({a})");
            assert!((c - a.cos()).abs() < 3e-5, "cos({a})");
            assert!((s * s + c * c - 1.0).abs() < 1e-5);
            a += 0.37;
        }
    }
}
