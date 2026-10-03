//! Golden and hostile-input tests for the GGUF reader and dequantizers.
//!
//! Real-file tests read the frozen Llama-3.2-1B-Instruct-Q4_K_M model and are
//! skipped with a message when it is absent, so CI without the model stays
//! green. Fixtures in `tests/fixtures` were produced by ggml's own
//! `dequantize_row_q4_K` / `dequantize_row_q6_K` (LM Studio llama.cpp
//! backend 2.33.0 libggml-base.so) from blocks cut out of the real file.

#![allow(clippy::chunks_exact_to_as_chunks, clippy::manual_is_multiple_of)]

use aienos_infer::quant::{dequantize, dot_q4k_f32, dot_q6k_f32, dot_row, QK_K};
use aienos_infer::*;
use std::collections::BTreeMap;

const MODEL: &str = "/home/drakestapleton/models/aien-mail/Llama-3.2-1B-Instruct-Q4_K_M.gguf";
const META: &str = "/home/drakestapleton/models/aien-mail/.cache/huggingface/download/Llama-3.2-1B-Instruct-Q4_K_M.gguf.metadata";

fn model() -> Option<Vec<u8>> {
    match std::fs::read(MODEL) {
        Ok(b) => Some(b),
        Err(e) => {
            eprintln!("SKIP: model file {MODEL} not readable ({e})");
            None
        }
    }
}

fn fx(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn f32s(b: &[u8]) -> Vec<f32> {
    b.chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

// ---------------------------------------------------------------- real file

#[test]
fn real_header_matches_known_facts() {
    let Some(b) = model() else { return };
    let g = Gguf::parse(&b).unwrap();
    assert_eq!(g.version, 3);
    assert_eq!(g.alignment, 32);
    assert_eq!(g.data_start % 32, 0);
    assert_eq!(g.architecture().unwrap(), "llama");
    let p = g.llama_params().unwrap();
    // 16 layers, 2048 dim, 32 heads, 8 kv heads, 8192 ffn, 128256 vocab are
    // the published Llama-3.2-1B shape (config.json); the values here are
    // read from the file and asserted equal to those facts.
    assert_eq!(p.block_count, 16);
    assert_eq!(p.embedding_length, 2048);
    assert_eq!(p.head_count, 32);
    assert_eq!(p.head_count_kv, 8);
    assert_eq!(p.feed_forward_length, 8192);
    assert_eq!(p.vocab_size, 128256);
    assert_eq!(p.context_length, 131072);
    assert_eq!(p.rope_freq_base, 500000.0);
    assert_eq!(p.rms_norm_eps, 1e-5);
    let t = g.tokenizer().unwrap();
    assert_eq!(t.tokens.len(), 128256);
    assert_eq!(t.token_type.unwrap().len(), 128256);
    assert_eq!(t.merges.unwrap().len(), 280147);
    assert!(t.scores.is_none(), "this file has no tokenizer.ggml.scores");
    assert_eq!(t.bos_id, Some(128000));
    assert_eq!(t.eos_id, Some(128009));
    let toks: Vec<&str> = t.tokens.strings().collect();
    assert_eq!(toks.len(), 128256);
    assert_eq!(toks[128000], "<|begin_of_text|>");
    assert_eq!(toks[128009], "<|eot_id|>");
    assert_eq!(t.token_type.unwrap().i32s().count(), 128256);
    assert_eq!(t.merges.unwrap().strings().count(), 280147);
}

#[test]
fn real_file_matches_hf_metadata_hash() {
    let Ok(meta) = std::fs::read_to_string(META) else {
        eprintln!("SKIP: HF metadata file absent");
        return;
    };
    let Some(b) = model() else { return };
    // Line 2 of the HF cache metadata is the file's sha256 (etag).
    let want = meta.lines().nth(1).unwrap().trim().to_string();
    assert_eq!(want.len(), 64);
    let out = std::process::Command::new("sha256sum").arg(MODEL).output();
    let Ok(out) = out else {
        eprintln!("SKIP: no sha256sum");
        return;
    };
    let got = String::from_utf8_lossy(&out.stdout);
    assert_eq!(got.split_whitespace().next().unwrap(), want);
    assert_eq!(b.len(), 807_694_368);
}

#[test]
fn real_type_histogram_and_table_sanity() {
    let Some(b) = model() else { return };
    let g = Gguf::parse(&b).unwrap();
    let mut h: BTreeMap<GgmlType, usize> = BTreeMap::new();
    for t in g.tensors() {
        *h.entry(t.ty).or_default() += 1;
    }
    assert_eq!(h[&GgmlType::F32], 34);
    assert_eq!(h[&GgmlType::Q4K], 96);
    assert_eq!(h[&GgmlType::Q6K], 17);
    assert_eq!(h.len(), 3);
    assert_eq!(g.tensors().len(), 147);
    // Every range inside the file; sizes match block math; and tensors are
    // packed back to back at the alignment, which independently confirms the
    // per-type block sizes (a wrong size would shift every following offset).
    let mut v: Vec<&TensorInfo> = g.tensors().iter().collect();
    v.sort_by_key(|t| t.offset);
    let mut expect = 0u64;
    for t in &v {
        assert_eq!(t.offset, expect, "{}", t.name);
        let (bw, bb) = t.ty.block();
        assert_eq!(t.n_bytes, t.n_elements / bw as u64 * bb as u64);
        assert_eq!(
            t.row_bytes() * t.dims[1..].iter().product::<u64>(),
            t.n_bytes
        );
        assert!(g.data_start as u64 + t.offset + t.n_bytes <= b.len() as u64);
        assert_eq!(g.tensor_data(t).len() as u64, t.n_bytes);
        expect = (t.offset + t.n_bytes + 31) & !31;
    }
    assert_eq!(
        g.data_start as u64 + v.last().map(|t| t.offset + t.n_bytes).unwrap(),
        b.len() as u64
    );
    let e = g.tensor("token_embd.weight").unwrap();
    assert_eq!((e.ty, e.dims[0], e.dims[1]), (GgmlType::Q6K, 2048, 128256));
    assert!(
        g.tensor("output.weight").is_none(),
        "output is tied to token_embd"
    );
}

#[test]
fn real_layer0_dequantizes_to_sane_values() {
    let Some(b) = model() else { return };
    let g = Gguf::parse(&b).unwrap();
    for t in g.tensors().iter().filter(|t| t.name.starts_with("blk.0.")) {
        let mut out = vec![0f32; t.n_elements as usize];
        dequantize(t.ty, g.tensor_data(t), &mut out).unwrap();
        assert!(out.iter().all(|v| v.is_finite()), "{}", t.name);
        let max = out.iter().fold(0f32, |m, v| m.max(v.abs()));
        assert!(max > 0.0 && max < 100.0, "{} max {max}", t.name);
    }
}

// ---------------------------------------------------------------- ggml cross-check

#[test]
fn q4k_matches_ggml_bit_for_bit() {
    let bin = fx("q4k.bin");
    let want = f32s(&fx("q4k.f32"));
    let mut got = vec![0f32; want.len()];
    dequantize(GgmlType::Q4K, &bin, &mut got).unwrap();
    for (i, (a, b)) in got.iter().zip(&want).enumerate() {
        assert_eq!(a.to_bits(), b.to_bits(), "weight {i}: {a} vs ggml {b}");
    }
}

#[test]
fn q6k_matches_ggml_bit_for_bit() {
    let bin = fx("q6k.bin");
    let want = f32s(&fx("q6k.f32"));
    let mut got = vec![0f32; want.len()];
    dequantize(GgmlType::Q6K, &bin, &mut got).unwrap();
    for (i, (a, b)) in got.iter().zip(&want).enumerate() {
        assert_eq!(a.to_bits(), b.to_bits(), "weight {i}: {a} vs ggml {b}");
    }
}

#[test]
fn dot_helpers_match_dequant_then_dot() {
    let bin = fx("q4k.bin");
    let w = f32s(&fx("q4k.f32"));
    let x: Vec<f32> = (0..QK_K)
        .map(|i| ((i * 7 % 13) as f32 - 6.0) * 0.25)
        .collect();
    let xa: &[f32; QK_K] = x.as_slice().try_into().unwrap();
    let blk: &[u8; 144] = bin[..144].try_into().unwrap();
    let want: f32 = w[..QK_K].iter().zip(&x).map(|(a, b)| a * b).sum();
    assert_eq!(dot_q4k_f32(blk, xa), want);
    let bin6 = fx("q6k.bin");
    let w6 = f32s(&fx("q6k.f32"));
    let blk6: &[u8; 210] = bin6[..210].try_into().unwrap();
    let want6: f32 = w6[..QK_K].iter().zip(&x).map(|(a, b)| a * b).sum();
    assert_eq!(dot_q6k_f32(blk6, xa), want6);
    // Row of 4 blocks.
    let x4: Vec<f32> = (0..4 * QK_K).map(|i| (i % 5) as f32 - 2.0).collect();
    let w4: f32 = w[..4 * QK_K].iter().zip(&x4).map(|(a, b)| a * b).sum();
    let got = dot_row(GgmlType::Q4K, &bin[..4 * 144], &x4).unwrap();
    assert!(
        (got - w4).abs() <= 1e-3 * w4.abs().max(1.0),
        "{got} vs {w4}"
    );
}

// ---------------------------------------------------------------- round trip

fn f32_to_f16(v: f32) -> u16 {
    // Round to nearest, normal range only (test scales are well inside it).
    let b = v.to_bits();
    let sign = ((b >> 16) & 0x8000) as u16;
    let exp = ((b >> 23) & 0xff) as i32 - 127 + 15;
    let man = b & 0x7f_ffff;
    if v == 0.0 {
        return sign;
    }
    assert!((1..31).contains(&exp), "out of f16 normal range: {v}");
    let mut h = ((exp as u32) << 10) | (man >> 13);
    if man & 0x1000 != 0 {
        h += 1; // carries into the exponent correctly
    }
    sign | h as u16
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn unit(&mut self) -> f32 {
        (self.next() >> 40) as f32 / (1u64 << 24) as f32 * 2.0 - 1.0
    }
}

/// Simple reference Q4_K quantizer: 8 sub-blocks of 32, each w = d*sc*q - dmin*m.
fn quantize_q4k(x: &[f32; QK_K]) -> [u8; 144] {
    let mut ds = [0f32; 8];
    let mut ms = [0f32; 8];
    for j in 0..8 {
        let s = &x[32 * j..32 * j + 32];
        let mn = s.iter().cloned().fold(0f32, f32::min);
        let mx = s.iter().cloned().fold(0f32, f32::max);
        ms[j] = -mn;
        ds[j] = (mx - mn) / 15.0;
    }
    let dmax = ds.iter().cloned().fold(0f32, f32::max);
    let mmax = ms.iter().cloned().fold(0f32, f32::max);
    let d16 = f32_to_f16(dmax / 63.0);
    let m16 = f32_to_f16(mmax / 63.0);
    let d = aienos_infer::half::f16_to_f32(d16);
    let dmin = aienos_infer::half::f16_to_f32(m16);
    let mut sc = [0u8; 8];
    let mut mn6 = [0u8; 8];
    for j in 0..8 {
        sc[j] = if d > 0.0 {
            (ds[j] / d).round().clamp(0.0, 63.0) as u8
        } else {
            0
        };
        mn6[j] = if dmin > 0.0 {
            (ms[j] / dmin).round().clamp(0.0, 63.0) as u8
        } else {
            0
        };
    }
    let mut b = [0u8; 144];
    b[0..2].copy_from_slice(&d16.to_le_bytes());
    b[2..4].copy_from_slice(&m16.to_le_bytes());
    // Pack 6-bit scales/mins (inverse of get_scale_min_k4).
    for j in 0..4 {
        b[4 + j] = sc[j] | ((sc[j + 4] >> 4) << 6);
        b[8 + j] = mn6[j] | ((mn6[j + 4] >> 4) << 6);
        b[12 + j] = (sc[j + 4] & 0xf) | ((mn6[j + 4] & 0xf) << 4);
    }
    for j in 0..8 {
        let step = d * sc[j] as f32;
        let off = dmin * mn6[j] as f32;
        for l in 0..32 {
            let q = if step > 0.0 {
                ((x[32 * j + l] + off) / step).round().clamp(0.0, 15.0) as u8
            } else {
                0
            };
            // sub-blocks 2k (low nibble) and 2k+1 (high nibble) share 32 bytes.
            let byte = &mut b[16 + 32 * (j / 2) + l];
            if j % 2 == 0 {
                *byte |= q
            } else {
                *byte |= q << 4
            }
        }
    }
    b
}

/// Simple reference Q6_K quantizer: 16 sub-blocks of 16, w = d*sc*(q-32).
fn quantize_q6k(x: &[f32; QK_K]) -> [u8; 210] {
    let mut sub = [0f32; 16];
    for j in 0..16 {
        sub[j] = x[16 * j..16 * j + 16]
            .iter()
            .fold(0f32, |m, v| m.max(v.abs()))
            / 32.0;
    }
    let smax = sub.iter().cloned().fold(0f32, f32::max);
    let d16 = f32_to_f16(smax / 127.0);
    let d = aienos_infer::half::f16_to_f32(d16);
    let mut b = [0u8; 210];
    b[208..210].copy_from_slice(&d16.to_le_bytes());
    let mut sc = [0i8; 16];
    for j in 0..16 {
        sc[j] = if d > 0.0 {
            (sub[j] / d).round().clamp(0.0, 127.0) as i8
        } else {
            0
        };
        b[192 + j] = sc[j] as u8;
    }
    let q = |p: usize| -> u8 {
        let s = d * sc[p / 16] as f32;
        if s > 0.0 {
            ((x[p] / s).round() + 32.0).clamp(0.0, 63.0) as u8
        } else {
            32
        }
    };
    for h in 0..2 {
        for l in 0..32 {
            let base = 128 * h;
            let (q1, q2, q3, q4) = (
                q(base + l),
                q(base + l + 32),
                q(base + l + 64),
                q(base + l + 96),
            );
            b[64 * h + l] = (q1 & 0xf) | ((q3 & 0xf) << 4);
            b[64 * h + l + 32] = (q2 & 0xf) | ((q4 & 0xf) << 4);
            b[128 + 32 * h + l] =
                (q1 >> 4) | ((q2 >> 4) << 2) | ((q3 >> 4) << 4) | ((q4 >> 4) << 6);
        }
    }
    b
}

fn max_round_trip_err(ty: GgmlType, trials: usize) -> f32 {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut worst = 0f32;
    for _ in 0..trials {
        let mut x = [0f32; QK_K];
        for v in x.iter_mut() {
            *v = rng.unit();
        }
        let mut y = [0f32; QK_K];
        match ty {
            GgmlType::Q4K => dequantize(ty, &quantize_q4k(&x), &mut y).unwrap(),
            _ => dequantize(ty, &quantize_q6k(&x), &mut y).unwrap(),
        }
        for (a, b) in x.iter().zip(&y) {
            worst = worst.max((a - b).abs());
        }
    }
    worst
}

#[test]
fn q4k_round_trip_error_bound() {
    // x in [-1,1]: a 4-bit step over a sub-block range <= 2 is 2/15 = 0.133,
    // so half-step 0.067 plus 6-bit scale/min rounding stays under 0.1.
    let worst = max_round_trip_err(GgmlType::Q4K, 200);
    eprintln!("q4k round trip max abs error {worst}");
    assert!(worst < 0.1, "{worst}");
}

#[test]
fn q6k_round_trip_error_bound() {
    // 6-bit: step = maxabs/32 <= 1/32. The grid is -32..31, so +maxabs clamps
    // to 31 (one full step, 0.031) plus half-step rounding 0.016 -> under 0.05.
    let worst = max_round_trip_err(GgmlType::Q6K, 200);
    eprintln!("q6k round trip max abs error {worst}");
    assert!(worst < 0.05, "{worst}");
}

#[test]
fn round_trip_exact_when_grid_aligned() {
    // Values that lie exactly on the Q4_K grid must come back exactly:
    // d = dmin = 1/64 scales are exact in f16.
    let mut x = [0f32; QK_K];
    for (i, v) in x.iter_mut().enumerate() {
        *v = (i % 16) as f32; // each sub-block spans 0..15: sc=1*d, m=0
    }
    // d = 15/15 = 1 -> scale 63 needs d=1/63 which is inexact; use the
    // hand-built path instead: d=1, sc=1, min=0.
    let mut b = [0u8; 144];
    b[0..2].copy_from_slice(&0x3c00u16.to_le_bytes());
    for j in 0..4 {
        b[4 + j] = 1;
    }
    for j in 0..4 {
        b[12 + j] = 1;
    }
    for l in 0..128 {
        let lo = (l % 16) as u8;
        b[16 + l] = lo | (lo << 4);
    }
    let mut y = [0f32; QK_K];
    dequantize(GgmlType::Q4K, &b, &mut y).unwrap();
    assert_eq!(x.to_vec(), y.to_vec());
}

// ---------------------------------------------------------------- hostile input

/// Minimal valid GGUF builder for hostile-input tests.
struct B(Vec<u8>);
impl B {
    fn new(n_tensors: u64, n_kv: u64) -> Self {
        let mut v = b"GGUF".to_vec();
        v.extend(3u32.to_le_bytes());
        v.extend(n_tensors.to_le_bytes());
        v.extend(n_kv.to_le_bytes());
        B(v)
    }
    fn s(&mut self, s: &str) {
        self.0.extend((s.len() as u64).to_le_bytes());
        self.0.extend(s.as_bytes());
    }
    fn kv_u32(&mut self, k: &str, v: u32) {
        self.s(k);
        self.0.extend(4u32.to_le_bytes());
        self.0.extend(v.to_le_bytes());
    }
    fn tensor(&mut self, name: &str, dims: &[u64], ty: u32, off: u64) {
        self.s(name);
        self.0.extend((dims.len() as u32).to_le_bytes());
        for d in dims {
            self.0.extend(d.to_le_bytes());
        }
        self.0.extend(ty.to_le_bytes());
        self.0.extend(off.to_le_bytes());
    }
    fn pad_data(mut self, n: usize) -> Vec<u8> {
        while self.0.len() % 32 != 0 {
            self.0.push(0);
        }
        self.0.extend(std::iter::repeat_n(0u8, n));
        self.0
    }
}

fn good_small() -> Vec<u8> {
    let mut b = B::new(1, 2);
    b.kv_u32("a.b", 7);
    b.s("tokens");
    b.0.extend(9u32.to_le_bytes()); // array
    b.0.extend(8u32.to_le_bytes()); // of string
    b.0.extend(2u64.to_le_bytes());
    b.s("hi");
    b.s("yo");
    b.tensor("w", &[256], 12, 0);
    b.pad_data(144)
}

#[test]
fn small_good_file_parses() {
    let f = good_small();
    let g = Gguf::parse(&f).unwrap();
    assert_eq!(g.u32_key("a.b").unwrap(), 7);
    let toks: Vec<_> = g.array_key("tokens").unwrap().strings().collect();
    assert_eq!(toks, ["hi", "yo"]);
    assert_eq!(g.tensor("w").unwrap().n_bytes, 144);
    assert_eq!(g.u32_key("nope"), Err(GgufError::Missing("nope")));
    assert_eq!(g.str_key("a.b"), Err(GgufError::WrongType("a.b")));
}

#[test]
fn every_truncation_is_an_error_not_a_panic() {
    let f = good_small();
    for n in 0..f.len() {
        assert!(Gguf::parse(&f[..n]).is_err(), "len {n} should fail");
    }
    // Real file: all short lengths plus a strided sweep through the header.
    if let Some(b) = model() {
        let g = Gguf::parse(&b).unwrap();
        for n in 0..3000 {
            assert!(Gguf::parse(&b[..n]).is_err(), "len {n}");
        }
        let mut n = 3000;
        while n < g.data_start {
            assert!(Gguf::parse(&b[..n]).is_err(), "len {n}");
            n += 99_991;
        }
        // Cutting inside the tensor data must fail the range check.
        assert_eq!(
            Gguf::parse(&b[..b.len() - 1]).unwrap_err(),
            GgufError::TensorOutOfRange
        );
        assert!(Gguf::parse(&b[..g.data_start]).is_err());
    }
}

#[test]
fn absurd_counts_and_bad_fields() {
    let mut f = B::new(u64::MAX, 0).0;
    assert_eq!(Gguf::parse(&f).unwrap_err(), GgufError::TooMany);
    f = B::new(0, u64::MAX / 2).0;
    assert_eq!(Gguf::parse(&f).unwrap_err(), GgufError::TooMany);
    f = B::new(1_000_000, 0).pad_data(64);
    assert_eq!(Gguf::parse(&f).unwrap_err(), GgufError::TooMany);
    let mut bad_magic = good_small();
    bad_magic[0] = b'X';
    assert_eq!(Gguf::parse(&bad_magic).unwrap_err(), GgufError::BadMagic);
    let mut bad_ver = good_small();
    bad_ver[4] = 2;
    assert_eq!(
        Gguf::parse(&bad_ver).unwrap_err(),
        GgufError::UnsupportedVersion(2)
    );

    // Offset past end.
    let mut b = B::new(1, 0);
    b.tensor("w", &[256], 12, 1 << 40);
    assert_eq!(
        Gguf::parse(&b.pad_data(144)).unwrap_err(),
        GgufError::TensorOutOfRange
    );
    // Offset + size overflow u64.
    let mut b = B::new(1, 0);
    b.tensor("w", &[256], 12, u64::MAX - 8);
    assert_eq!(
        Gguf::parse(&b.pad_data(144)).unwrap_err(),
        GgufError::Overflow
    );
    // Misaligned offset.
    let mut b = B::new(1, 0);
    b.tensor("w", &[256], 12, 16);
    assert_eq!(
        Gguf::parse(&b.pad_data(400)).unwrap_err(),
        GgufError::TensorOutOfRange
    );
    // Dimension product overflow.
    let mut b = B::new(1, 0);
    b.tensor("w", &[1 << 40, 1 << 40], 0, 0);
    assert_eq!(
        Gguf::parse(&b.pad_data(8)).unwrap_err(),
        GgufError::Overflow
    );
    // Row not a whole number of blocks.
    let mut b = B::new(1, 0);
    b.tensor("w", &[255], 12, 0);
    assert_eq!(
        Gguf::parse(&b.pad_data(400)).unwrap_err(),
        GgufError::BadDims
    );
    // 0 and 5 dims.
    let mut b = B::new(1, 0);
    b.tensor("w", &[], 0, 0);
    assert_eq!(Gguf::parse(&b.pad_data(8)).unwrap_err(), GgufError::BadDims);
    let mut b = B::new(1, 0);
    b.tensor("w", &[1, 1, 1, 1, 1], 0, 0);
    assert_eq!(Gguf::parse(&b.pad_data(8)).unwrap_err(), GgufError::BadDims);
    // Unknown tensor type, unknown kv type.
    let mut b = B::new(1, 0);
    b.tensor("w", &[32], 99, 0);
    assert_eq!(
        Gguf::parse(&b.pad_data(8)).unwrap_err(),
        GgufError::UnsupportedType(99)
    );
    let mut b = B::new(0, 1);
    b.s("k");
    b.0.extend(77u32.to_le_bytes());
    assert_eq!(Gguf::parse(&b.0).unwrap_err(), GgufError::BadValueType(77));
    // Zero and non power of two alignment.
    for a in [0u32, 3] {
        let mut b = B::new(0, 1);
        b.kv_u32("general.alignment", a);
        assert_eq!(
            Gguf::parse(&b.pad_data(8)).unwrap_err(),
            GgufError::BadAlignment
        );
    }
    // Huge string length, huge array length, nested array.
    let mut b = B::new(0, 1);
    b.0.extend(u64::MAX.to_le_bytes());
    assert!(Gguf::parse(&b.0).is_err());
    let mut b = B::new(0, 1);
    b.s("k");
    b.0.extend(9u32.to_le_bytes());
    b.0.extend(4u32.to_le_bytes());
    b.0.extend(u64::MAX.to_le_bytes());
    assert_eq!(Gguf::parse(&b.0).unwrap_err(), GgufError::Overflow);
    let mut b = B::new(0, 1);
    b.s("k");
    b.0.extend(9u32.to_le_bytes());
    b.0.extend(8u32.to_le_bytes());
    b.0.extend((1u64 << 60).to_le_bytes());
    assert_eq!(Gguf::parse(&b.0).unwrap_err(), GgufError::TooMany);
    let mut b = B::new(0, 1);
    b.s("k");
    b.0.extend(9u32.to_le_bytes());
    b.0.extend(9u32.to_le_bytes());
    b.0.extend(1u64.to_le_bytes());
    assert!(Gguf::parse(&b.0).is_err());
    // Invalid UTF-8 key.
    let mut b = B::new(0, 1);
    b.0.extend(2u64.to_le_bytes());
    b.0.extend([0xff, 0xfe]);
    b.0.extend(4u32.to_le_bytes());
    b.0.extend(0u32.to_le_bytes());
    assert_eq!(Gguf::parse(&b.0).unwrap_err(), GgufError::BadUtf8);
}

#[test]
fn byte_flip_fuzz_never_panics() {
    let f = good_small();
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for _ in 0..20_000 {
        let mut g = f.clone();
        for _ in 0..1 + rng.next() % 3 {
            let i = (rng.next() % g.len() as u64) as usize;
            g[i] = rng.next() as u8;
        }
        if rng.next() % 4 == 0 {
            let n = (rng.next() % g.len() as u64) as usize;
            g.truncate(n);
        }
        if let Ok(p) = Gguf::parse(&g) {
            // Accessors on whatever parsed must also be panic free.
            for t in p.tensors() {
                let _ = p.tensor_data(t);
            }
            for (_, v) in p.kvs() {
                if let Value::Array(a) = v {
                    let _ = a.strings().count()
                        + a.u32s().count()
                        + a.i32s().count()
                        + a.f32s().count();
                }
            }
            let _ = p.llama_params();
            let _ = p.tokenizer();
        }
    }
}

#[test]
fn dequantize_rejects_bad_lengths_without_panic() {
    let mut out = vec![0f32; 256];
    for n in [0usize, 1, 143, 145, 288] {
        assert!(dequantize(GgmlType::Q4K, &vec![0u8; n], &mut out).is_err());
    }
    assert!(dequantize(GgmlType::Q6K, &[0u8; 209], &mut out).is_err());
    let mut odd = vec![0f32; 100];
    assert!(dequantize(GgmlType::Q4K, &[0u8; 144], &mut odd).is_err());
}
