#![allow(clippy::chunks_exact_to_as_chunks)]
//! Golden tests for the Llama-3.2-1B forward pass, tokenizer and greedy decode
//! against llama.cpp (aienos#34 lanes 2+3).
//!
//! Reference fixtures `tests/fixtures/ref_*.txt` were produced by
//! `tests/ref/llama_ref.c` linked against the local llama.cpp build
//! (command in the header of that file and in the PR body). The tests need the frozen
//! model file (`AIENOS_MODEL`, default `~/models/aien-mail/
//! Llama-3.2-1B-Instruct-Q4_K_M.gguf`) and print SKIPPED when it is absent.

use aienos_infer::{argmax, DecodeState, Gguf, Model, Tokenizer};
use std::time::Instant;

fn model_bytes() -> Option<Vec<u8>> {
    let p = std::env::var("AIENOS_MODEL").unwrap_or_else(|_| {
        format!(
            "{}/models/aien-mail/Llama-3.2-1B-Instruct-Q4_K_M.gguf",
            std::env::var("HOME").unwrap_or_default()
        )
    });
    match std::fs::read(&p) {
        Ok(b) => Some(b),
        Err(_) => {
            eprintln!("SKIPPED: model file {p} not present");
            None
        }
    }
}

struct Reference {
    ids: Vec<u32>,
    /// (token, top1-top2 logit gap)
    steps: Vec<(u32, f32)>,
}

fn reference(name: &str) -> Reference {
    let path = format!(
        "{}/tests/fixtures/ref_{name}.txt",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(path).unwrap();
    let mut r = Reference {
        ids: vec![],
        steps: vec![],
    };
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        match f.first() {
            Some(&"ids") => r.ids = f[1..].iter().map(|s| s.parse().unwrap()).collect(),
            Some(&"step") => r.steps.push((f[2].parse().unwrap(), f[3].parse().unwrap())),
            _ => {}
        }
    }
    r
}

const PROMPTS: [(&str, &str); 3] = [
    ("cow", "Explain copy-on-write in one sentence."),
    ("fr", "What is the capital of France?"),
    (
        "uni",
        "Say hi in 3 languages: caf\u{e9}, \u{65e5}\u{672c}\u{8a9e}, \u{1F600} (it's 100% fine).\n\n  Thanks!",
    ),
];

#[test]
fn tokenization_matches_llama_cpp() {
    let Some(bytes) = model_bytes() else { return };
    let g = Gguf::parse(&bytes).unwrap();
    let tok = Tokenizer::new(&g.tokenizer().unwrap()).unwrap();
    assert_eq!(tok.vocab_size(), 128256);
    assert_eq!(tok.eot_id, Some(128009));
    for (name, prompt) in PROMPTS {
        let want = reference(name).ids;
        assert_eq!(tok.encode_chat(prompt).unwrap(), want, "prompt {name}");
    }
}

#[test]
fn decode_round_trips_text() {
    let Some(bytes) = model_bytes() else { return };
    let g = Gguf::parse(&bytes).unwrap();
    let tok = Tokenizer::new(&g.tokenizer().unwrap()).unwrap();
    for s in [
        "Hello, world!",
        "  caf\u{e9} \u{65e5}\u{672c}\u{8a9e} \u{1F600}\n\n",
        "a\tb\r\nc 12345",
    ] {
        let ids = tok.encode(s, false).unwrap();
        assert_eq!(tok.decode(&ids).unwrap(), s.as_bytes(), "{s:?}");
    }
}

fn check(q8k: bool, int8: bool, max_logit_diff: f32) {
    let Some(bytes) = model_bytes() else { return };
    let g = Gguf::parse(&bytes).unwrap();
    let m = Model::new(&g).unwrap();
    let tok = Tokenizer::new(&g.tokenizer().unwrap()).unwrap();
    let mut total_match = 0;
    let mut total = 0;
    for (name, prompt) in PROMPTS {
        let r = reference(name);
        let ids = tok.encode_chat(prompt).unwrap();
        // (c) free-running greedy
        let mut st = DecodeState::new(&m, 256);
        st.emulate_q8k = q8k;
        st.int8_dot = int8;
        let t0 = Instant::now();
        st.prefill(&m, &ids).unwrap();
        if name == "cow" {
            // (b)+(d) first-position logits vs llama.cpp
            let raw = std::fs::read(format!(
                "{}/tests/fixtures/ref_cow_logits0.f32",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap();
            let want: Vec<f32> = raw
                .chunks_exact(4)
                .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect();
            assert_eq!(want.len(), st.logits.len());
            let maxdiff = st
                .logits
                .iter()
                .zip(&want)
                .map(|(a, b)| (a - b).abs())
                .fold(0f32, f32::max);
            eprintln!("q8k={q8k} first-position logits: max abs diff vs llama.cpp = {maxdiff}");
            let n = want.len() as f32;
            let mean = st
                .logits
                .iter()
                .zip(&want)
                .map(|(a, b)| (a - b).abs())
                .sum::<f32>()
                / n;
            let top = argmax(&want) as usize;
            let rms_ref = (want.iter().map(|v| v * v).sum::<f32>() / n).sqrt();
            eprintln!(
                "mean abs diff {mean}, diff at top token {} (ref {}), ref logit rms {rms_ref}",
                st.logits[top] - want[top],
                want[top]
            );
            assert_eq!(argmax(&st.logits), argmax(&want));
            assert!(maxdiff < max_logit_diff, "max abs logit diff {maxdiff}");
        }
        let mut free = Vec::new();
        for i in 0..r.steps.len() {
            let t = argmax(&st.logits);
            free.push(t);
            if t == 128009 || i + 1 == r.steps.len() {
                break;
            }
            st.forward(&m, t, true).unwrap();
        }
        let secs = t0.elapsed().as_secs_f64();
        let want: Vec<u32> = r.steps.iter().map(|s| s.0).collect();
        let first_div = free.iter().zip(&want).position(|(a, b)| a != b);
        eprintln!(
            "{name}: {} tokens in {secs:.2}s (prefill {} + decode) {:.2} tok/s overall; free-run divergence at {:?}{}",
            free.len(),
            ids.len(),
            (free.len() + ids.len()) as f64 / secs,
            first_div,
            first_div
                .map(|p| format!(" (ref gap there {:.4}, ours {} vs ref {})", r.steps[p].1, free[p], want[p]))
                .unwrap_or_default()
        );
        match first_div {
            None => assert_eq!(free.len(), want.len()),
            // A divergence is only acceptable at a near-tie in llama.cpp's own logits.
            Some(p) => assert!(
                r.steps[p].1 < 0.05,
                "diverged at {p} with gap {}",
                r.steps[p].1
            ),
        }
        // teacher-forced top-1 match rate
        let mut st = DecodeState::new(&m, 256);
        st.emulate_q8k = q8k;
        st.int8_dot = int8;
        st.prefill(&m, &ids).unwrap();
        let mut hit = 0;
        for (i, &(t, gap)) in r.steps.iter().enumerate() {
            let mine = argmax(&st.logits);
            if mine == t {
                hit += 1;
            } else {
                eprintln!("{name}: teacher-forced mismatch at {i}: ours {mine} ref {t} (ref gap {gap:.4})");
                assert!(gap < 0.05, "mismatch at {i} with gap {gap}");
            }
            if t == 128009 {
                break;
            }
            st.forward(&m, t, true).unwrap();
        }
        total_match += hit;
        total += r.steps.len();
    }
    eprintln!("teacher-forced top-1 match {total_match}/{total}");
}

/// Plain f32 activations (more accurate than ggml's int8 activations, so a
/// small, bounded logit difference is expected).
#[test]
fn forward_matches_llama_cpp_f32_activations() {
    check(false, false, 1.0);
}

/// Activations rounded to ggml's Q8_K grid before every quantized dot.
#[test]
#[ignore = "slow; run with --ignored"]
fn forward_matches_llama_cpp_q8k_emulation() {
    check(true, false, 1.0);
}

/// Int8 activations with i32 dots (aienos#34 L6 speed path): the same
/// arithmetic ggml runs, so the same bound as the Q8_K emulation.
#[test]
fn forward_matches_llama_cpp_int8_dot() {
    check(false, true, 1.0);
}
