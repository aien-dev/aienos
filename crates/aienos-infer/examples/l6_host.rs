//! L6-A host-side tokens-per-second harness (aienos#34 lane 6).
//!
//! Runs the same code path as the kernel (`aienos-infer-kernel`) and the host
//! tests: `encode_chat` + `DecodeState::prefill` + greedy `argmax`/`forward`,
//! f32 activations, single thread. Part A checks the first 8 ids against the
//! golden reply; Part B keeps decoding (ignoring end-of-turn) to N tokens and
//! times each `forward` call in microseconds.
//!
//! Env: AIENOS_MODEL (default $HOME/models/aien-mail/Llama-3.2-1B-Instruct-Q4_K_M.gguf),
//! AIENOS_N (default 64), AIENOS_COMMIT (printed as `commit`).
//! Output: one `key: value` line per fact. Exit 0 ok, 1 parity FAIL, 2 wrong model.

use aienos_infer::{argmax, DecodeState, Gguf, Model, Tokenizer};
use std::time::Instant;

const PROMPT: &str = "What is the capital of France?";
const MODEL_SHA256: &str = "3f5a22426976ab26cfe84dba63c1d08391717abb1af893e10f1b2968d862dcc1";
const GOLDEN: [u32; 8] = [791, 6864, 315, 9822, 374, 12366, 13, 128009];

fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut block = |b: &[u8]| {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [t1.wrapping_add(t2), v[0], v[1], v[2], v[3].wrapping_add(t1), v[4], v[5], v[6]];
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    };
    let mut chunks = data.chunks_exact(64);
    for c in &mut chunks {
        block(c);
    }
    let rem = chunks.remainder();
    let mut tail = rem.to_vec();
    tail.push(0x80);
    while tail.len() % 64 != 56 {
        tail.push(0);
    }
    tail.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for c in tail.chunks_exact(64) {
        block(c);
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

fn join(v: &[impl ToString]) -> String {
    v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(" ")
}

fn main() {
    let path = std::env::var("AIENOS_MODEL").unwrap_or_else(|_| {
        format!(
            "{}/models/aien-mail/Llama-3.2-1B-Instruct-Q4_K_M.gguf",
            std::env::var("HOME").unwrap_or_default()
        )
    });
    let n: usize = std::env::var("AIENOS_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        eprintln!("cannot read model {path}: {e}");
        std::process::exit(2);
    });
    let sha = sha256_hex(&bytes);
    println!("commit: {}", std::env::var("AIENOS_COMMIT").unwrap_or_else(|_| "unknown".into()));
    println!("model_path: {path}");
    println!("model_sha256: {sha}");
    println!("model_size_bytes: {}", bytes.len());
    if sha != MODEL_SHA256 {
        eprintln!("model sha256 mismatch, want {MODEL_SHA256}");
        std::process::exit(2);
    }
    let g = Gguf::parse(&bytes).expect("gguf");
    let m = Model::new(&g).expect("model");
    let tok = Tokenizer::new(&g.tokenizer().expect("tokenizer data")).expect("tokenizer");
    let ids = tok.encode_chat(PROMPT).expect("encode");
    println!("prompt: {PROMPT}");
    println!("prompt_ids: {}", join(&ids));
    println!("threads: 1");

    let mut st = DecodeState::new(&m, ids.len() + n + 8);
    let t0 = Instant::now();
    st.prefill(&m, &ids).expect("prefill");
    let prefill_us = t0.elapsed().as_micros() as u64;
    println!("prefill_us: {prefill_us}");

    // Same loop as the kernel, except the end-of-turn stop is ignored.
    let mut out: Vec<u32> = Vec::with_capacity(n);
    let mut tok_us: Vec<u64> = Vec::with_capacity(n);
    loop {
        let t = argmax(&st.logits);
        out.push(t);
        if out.len() == n {
            break;
        }
        let t1 = Instant::now();
        st.forward(&m, t, true).expect("forward");
        tok_us.push(t1.elapsed().as_micros() as u64);
    }
    println!("tokens: {}", join(&out));
    println!("tok_us: {}", join(&tok_us));
    let mean = tok_us.iter().sum::<u64>() as f64 / tok_us.len().max(1) as f64;
    println!("decode_tokens: {}", tok_us.len());
    println!("mean_tok_us: {mean:.1}");
    println!("tok_per_s: {:.3}", 1e6 / mean);
    println!("text: {}", String::from_utf8_lossy(&tok.decode(&out).expect("decode")).escape_debug());

    let pass = out.len() >= GOLDEN.len() && out[..GOLDEN.len()] == GOLDEN;
    println!("golden_ids: {}", join(&GOLDEN));
    println!("PARITY: {}", if pass { "PASS" } else { "FAIL" });
    if !pass {
        std::process::exit(1);
    }
}
