//! PI5-8 host probe: can the engine's forward pass run an arbitrary llama-architecture GGUF,
//! and does it produce the same greedy tokens as llama.cpp?
//!
//! The prompt is given as token ids (the `ids` line printed by `tests/ref/llama_ref.c`), so the
//! engine's own tokenizer is NOT exercised: this judges only the weights loader, the quant paths
//! and the transformer forward pass. Greedy decode stops after the end-of-generation id (kept in
//! the output, like llama_ref) or after N tokens.
//!
//! usage: model_probe MODEL.gguf IDS_FILE N EOS_ID
//!   IDS_FILE: text file whose first line is `ids <id> <id> ...` (or bare ids)
//! Env: AIENOS_DOT=sdot (dotprod int8 path when the CPU has it; default f32 scalar).
//! Output: one `key: value` line per fact, `step <i> <id>` lines in llama_ref's style.

#![allow(clippy::chunks_exact_to_as_chunks)]

use aienos_infer::{argmax, DecodeState, DotProd, GgmlType, Gguf, Model};
use std::collections::BTreeMap;
use std::time::Instant;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 5 {
        eprintln!("usage: model_probe MODEL.gguf IDS_FILE N EOS_ID");
        std::process::exit(2);
    }
    let bytes = std::fs::read(&a[1]).expect("read model");
    let line = std::fs::read_to_string(&a[2]).expect("read ids");
    let ids: Vec<u32> = line
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .filter_map(|w| w.parse().ok())
        .collect();
    let n: usize = a[3].parse().expect("N");
    let eos: u32 = a[4].parse().expect("EOS_ID");
    let g = Gguf::parse(&bytes).expect("gguf");
    println!("arch: {}", g.architecture().unwrap_or("?"));
    let mut hist: BTreeMap<String, usize> = BTreeMap::new();
    for t in g.tensors() {
        let name = match t.ty {
            GgmlType::Q4K => "Q4_K".to_string(),
            GgmlType::Q6K => "Q6_K".to_string(),
            GgmlType::F32 => "F32".to_string(),
            GgmlType::F16 => "F16".to_string(),
            GgmlType::BF16 => "BF16".to_string(),
            other => format!("{other:?}"),
        };
        *hist.entry(name).or_default() += 1;
    }
    println!("tensor_types: {hist:?}");
    let m = match Model::new(&g) {
        Ok(m) => m,
        Err(e) => {
            println!("MODEL_REFUSED: {e:?}");
            std::process::exit(3);
        }
    };
    let p = &m.params;
    println!(
        "params: layers={} embd={} heads={} kv_heads={} ff={} vocab={} rope_base={} ctx={} tied_output={}",
        p.block_count, p.embedding_length, p.head_count, p.head_count_kv, p.feed_forward_length,
        p.vocab_size, p.rope_freq_base, p.context_length, g.tensor("output.weight").is_none()
    );
    println!(
        "gguf_eos_id: {:?} bos_id: {:?}",
        g.u32_key("tokenizer.ggml.eos_token_id").ok(),
        g.u32_key("tokenizer.ggml.bos_token_id").ok()
    );
    println!("prompt_ids: {}", ids.len());
    let mut st = DecodeState::new(&m, ids.len() + n + 8);
    st.dotprod = None;
    if std::env::var("AIENOS_DOT")
        .map(|v| v == "sdot")
        .unwrap_or(false)
    {
        #[cfg(target_arch = "aarch64")]
        {
            st.dotprod = DotProd::new(std::arch::is_aarch64_feature_detected!("dotprod"));
        }
    }
    let _: Option<DotProd> = st.dotprod;
    println!("dot: {}", if st.dotprod.is_some() { "sdot" } else { "f32" });
    let t0 = Instant::now();
    st.prefill(&m, &ids).expect("prefill");
    println!("prefill_us: {}", t0.elapsed().as_micros());
    // Optional: compare the first-position logits with llama.cpp's (f32 LE file written by llama_ref).
    if let Ok(path) = std::env::var("AIENOS_LOGITS") {
        let b = std::fs::read(&path).expect("read logits");
        let r: Vec<f32> = b
            .chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        let e = &st.logits;
        if r.len() == e.len() {
            let (mut mx, mut se, mut dot, mut na, mut nb) = (0f64, 0f64, 0f64, 0f64, 0f64);
            for (x, y) in r.iter().zip(e.iter()) {
                let d = (*x as f64 - *y as f64).abs();
                mx = mx.max(d);
                se += d * d;
                dot += *x as f64 * *y as f64;
                na += (*x as f64).powi(2);
                nb += (*y as f64).powi(2);
            }
            let top = |v: &[f32]| {
                v.iter()
                    .enumerate()
                    .fold(
                        (0usize, f32::MIN),
                        |a, (i, x)| if *x > a.1 { (i, *x) } else { a },
                    )
                    .0
            };
            println!("logits_vs_llama: n={} max_abs_diff={mx:.4} rms_diff={:.4} cosine={:.6} argmax_llama={} argmax_engine={}", r.len(), (se / r.len() as f64).sqrt(), dot / (na.sqrt() * nb.sqrt()), top(&r), top(e));
        } else {
            println!(
                "logits_vs_llama: SIZE MISMATCH llama={} engine={}",
                r.len(),
                e.len()
            );
        }
    }
    let mut tok_us = Vec::new();
    for i in 0..n {
        let t = argmax(&st.logits);
        println!("step {i} {t}");
        if t == eos {
            println!("eog");
            break;
        }
        if i + 1 == n {
            break;
        }
        let t1 = Instant::now();
        st.forward(&m, t, true).expect("forward");
        tok_us.push(t1.elapsed().as_micros() as f64);
    }
    let mean = tok_us.iter().sum::<f64>() / tok_us.len().max(1) as f64;
    println!("mean_tok_us: {mean:.1}");
    println!("tok_per_s: {:.3}", 1e6 / mean);
}
