//! Row-dot microbenchmark, one thread: ns per Q4_K / Q6_K row dot of 8192
//! weights, scalar f32 path vs SDOT path (aienos#34 PI5-6). Random blocks
//! with a fixed seed; `AIENOS_DOT_ITERS` (default 20000) rows per timing.
//! Prints `key: value` lines. The SDOT numbers appear only when the CPU has
//! dotprod (runtime detection on the host).

use aienos_infer::dotprod::{dot_row_q8, Q8Act};
use aienos_infer::quant::{dot_row, Q4K_BYTES, Q6K_BYTES, QK_K};
use aienos_infer::{DotProd, GgmlType};
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let iters: usize = std::env::var("AIENOS_DOT_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20000);
    let nb = 32; // 8192 weights, the Llama-3.2-1B FFN width
    let mut s = 0x9e37_79b9_7f4a_7c15u64;
    let mut rnd = || {
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        (s.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32) as u32
    };
    let x: Vec<f32> = (0..nb * QK_K)
        .map(|_| (rnd() as f32 / u32::MAX as f32) * 2.0 - 1.0)
        .collect();
    let mut q8 = Q8Act::with_capacity(x.len());
    q8.quantize(&x).unwrap();
    #[cfg(target_arch = "aarch64")]
    let tok = DotProd::new(std::arch::is_aarch64_feature_detected!("dotprod"));
    #[cfg(not(target_arch = "aarch64"))]
    let tok: Option<DotProd> = None;
    println!("dotprod: {}", tok.is_some());
    println!("weights_per_row: {}", nb * QK_K);
    for (ty, bb, name) in [
        (GgmlType::Q4K, Q4K_BYTES, "q4k"),
        (GgmlType::Q6K, Q6K_BYTES, "q6k"),
    ] {
        let mut row: Vec<u8> = (0..nb * bb).map(|_| rnd() as u8).collect();
        for b in row.chunks_exact_mut(bb) {
            // sane f16 scales (0.0625) so values stay finite
            let at = if ty == GgmlType::Q4K { 0 } else { 208 };
            b[at..at + 2].copy_from_slice(&[0x00, 0x2c]);
            if ty == GgmlType::Q4K {
                b[2..4].copy_from_slice(&[0x00, 0x2c]);
            }
        }
        let t0 = Instant::now();
        let mut acc = 0f32;
        for _ in 0..iters {
            acc += dot_row(ty, black_box(&row), black_box(&x)).unwrap();
        }
        let scalar = t0.elapsed().as_nanos() as f64 / iters as f64;
        black_box(acc);
        println!("{name}_scalar_f32_ns_per_row: {scalar:.1}");
        if let Some(t) = tok {
            let t0 = Instant::now();
            let mut acc = 0f32;
            for _ in 0..iters {
                acc += dot_row_q8(t, ty, black_box(&row), black_box(&q8)).unwrap();
            }
            let sdot = t0.elapsed().as_nanos() as f64 / iters as f64;
            black_box(acc);
            println!("{name}_sdot_ns_per_row: {sdot:.1}");
            println!("{name}_speedup: {:.2}", scalar / sdot);
        }
    }
}
