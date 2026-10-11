#![allow(clippy::chunks_exact_to_as_chunks)]
//! Golden tests for the Llama-3.2-1B forward pass, tokenizer and greedy decode
//! against llama.cpp (aienos#34 lanes 2+3).
//!
//! Reference fixtures `tests/fixtures/ref_*.txt` were produced by
//! `tests/ref/llama_ref.c` linked against the local llama.cpp build
//! (command in the header of that file and in the PR body). The tests need the frozen
//! model file (`AIENOS_MODEL`, default `~/models/aien-mail/
//! Llama-3.2-1B-Instruct-Q4_K_M.gguf`) and print SKIPPED when it is absent.

use aienos_infer::{
    argmax, DecodeState, Gguf, Model, Tokenizer, Q8_ALL, Q8_DOWN, Q8_GATE_UP, Q8_OUTPUT, Q8_QKV,
    Q8_WO,
};
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

/// Parity of the int8 path against the f32 path over the recorded 64-token
/// sequence (docs/l6b-int8-qualification.md, condition 2). PASS RULE: the
/// int8 tokens equal the f32 tokens. The per-position maximum absolute logit
/// difference is reported, not gated. Prints `PARITY_*` lines for
/// scripts/l6_host_receipt.sh. Run with:
/// `cargo test --release -p aienos-infer --test forward int8_parity -- --ignored --nocapture --test-threads=1`
#[test]
#[ignore = "model-backed, minutes on one core; run locally"]
fn int8_parity_64_tokens_vs_f32() {
    const N: usize = 64;
    let Some(bytes) = model_bytes() else {
        panic!("model file required");
    };
    let g = Gguf::parse(&bytes).unwrap();
    let m = Model::new(&g).unwrap();
    let tok = Tokenizer::new(&g.tokenizer().unwrap()).unwrap();
    let ids = tok.encode_chat("What is the capital of France?").unwrap();
    // Same loop as examples/l6_host.rs: greedy, end-of-turn ignored.
    let run = |int8: bool| -> (Vec<u32>, Vec<Vec<f32>>) {
        let mut st = DecodeState::new(&m, ids.len() + N + 8);
        st.int8_dot = int8;
        st.prefill(&m, &ids).unwrap();
        let (mut out, mut logits) = (Vec::new(), Vec::new());
        loop {
            let t = argmax(&st.logits);
            out.push(t);
            logits.push(st.logits.clone());
            if out.len() == N {
                break;
            }
            st.forward(&m, t, true).unwrap();
        }
        (out, logits)
    };
    let (ft, fl) = run(false);
    let (it, il) = run(true);
    let first_div = ft.iter().zip(&it).position(|(a, b)| a != b);
    // Positions after the first divergence have different histories.
    let upto = first_div.map_or(N, |p| p + 1);
    let per_pos: Vec<f32> = (0..upto)
        .map(|p| {
            fl[p]
                .iter()
                .zip(&il[p])
                .map(|(a, b)| (a - b).abs())
                .fold(0f32, f32::max)
        })
        .collect();
    let (maxpos, maxdiff) =
        per_pos.iter().enumerate().fold(
            (0, 0f32),
            |(bp, bv), (p, &v)| if v > bv { (p, v) } else { (bp, bv) },
        );
    let join = |v: &[String]| v.join(" ");
    println!(
        "PARITY_TOKENS_IDENTICAL: {}",
        if first_div.is_none() { "yes" } else { "no" }
    );
    println!(
        "PARITY_FIRST_DIVERGENCE: {}",
        first_div.map_or("none".to_string(), |p| p.to_string())
    );
    println!("PARITY_COMPARED_POSITIONS: {upto}");
    println!("PARITY_MAX_LOGIT_ABS_DIFF: {maxdiff}");
    println!("PARITY_MAX_LOGIT_ABS_DIFF_POSITION: {maxpos}");
    println!(
        "PARITY_PER_POSITION_MAX: {}",
        join(&per_pos.iter().map(|v| v.to_string()).collect::<Vec<_>>())
    );
    println!(
        "PARITY_F32_TOKENS: {}",
        join(&ft.iter().map(|v| v.to_string()).collect::<Vec<_>>())
    );
    println!(
        "PARITY_INT8_TOKENS: {}",
        join(&it.iter().map(|v| v.to_string()).collect::<Vec<_>>())
    );
    assert!(
        first_div.is_none(),
        "int8 tokens diverge from f32 at index {first_div:?}"
    );
}

/// aienos#34 int8 parity diagnosis (2026-10-11). Diagnosis only: it does not
/// change the parity rule, the default path or `INT8_PROMOTION_DEFAULT`.
///
/// The recorded parity run (`evidence/l6_host_3f5a22426976_l6b_parity.json`)
/// has f32 and int8 agree on indexes 0 to 11 and split at index 12 (f32 4897,
/// int8 53692). This test replays that common history teacher-forced (prompt
/// plus the 12 shared tokens) and compares the index-12 decision across paths:
/// plain f32, int8, f32 dots on Q8_K-rounded activations (`emulate_q8k`), int8
/// restricted to one matvec class or one layer, and int8 everywhere except one
/// class or layer. It also compares against llama.cpp's logits for the same
/// history (`tests/fixtures/ref_fr_idx12_logits.f32`, from
/// `tests/ref/llama_ref_hist.c`). Prints `DIAG_*` lines; asserts only that the
/// recorded split reproduces and that the f32 path is deterministic.
/// `cargo test --release -p aienos-infer --test forward int8_divergence -- --ignored --nocapture --test-threads=1`
#[test]
#[ignore = "model-backed, minutes on one core; run locally"]
fn int8_divergence_diagnosis_index_12() {
    const F32_TOK: u32 = 4897;
    const INT8_TOK: u32 = 53692;
    const COMMON: [u32; 12] = [
        791, 6864, 315, 9822, 374, 12366, 13, 128009, 128006, 78191, 128007, 271,
    ];
    let Some(bytes) = model_bytes() else {
        panic!("model file required");
    };
    let g = Gguf::parse(&bytes).unwrap();
    let m = Model::new(&g).unwrap();
    let tok = Tokenizer::new(&g.tokenizer().unwrap()).unwrap();
    let ids = tok.encode_chat("What is the capital of France?").unwrap();
    assert_eq!(ids, reference("fr").ids, "prompt ids differ from llama.cpp");
    let n_layer = m.layers.len();
    assert!(n_layer <= 64);

    // Logits after every position of the history (13 decisions, indexes 0..=12).
    let run = |int8: bool, round: bool, layers: u64, classes: u8| -> Vec<Vec<f32>> {
        let mut st = DecodeState::new(&m, ids.len() + COMMON.len() + 1);
        st.int8_dot = int8;
        st.emulate_q8k = round;
        st.q8_layers = layers;
        st.q8_classes = classes;
        st.prefill(&m, &ids).unwrap();
        let mut out = vec![st.logits.clone()];
        for &t in &COMMON {
            st.forward(&m, t, true).unwrap();
            out.push(st.logits.clone());
        }
        out
    };
    let top2 = |l: &[f32]| -> (u32, f32) {
        let (mut b1, mut b2, mut bi) = (f32::NEG_INFINITY, f32::NEG_INFINITY, 0u32);
        for (i, &v) in l.iter().enumerate() {
            if v > b1 {
                (b2, b1, bi) = (b1, v, i as u32);
            } else if v > b2 {
                b2 = v;
            }
        }
        (bi, b1 - b2)
    };
    let maxdiff = |a: &[f32], b: &[f32]| {
        a.iter()
            .zip(b)
            .map(|(x, y)| (x - y).abs())
            .fold(0f32, f32::max)
    };
    let raw = std::fs::read(format!(
        "{}/tests/fixtures/ref_fr_idx12_logits.f32",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let llama: Vec<f32> = raw
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();

    let f32l = run(false, false, u64::MAX, Q8_ALL);
    let base = &f32l[12];
    assert_eq!(llama.len(), base.len());
    let report = |name: &str, l: &[f32]| {
        let (am, gap) = top2(l);
        println!(
            "DIAG_MODE {name}: argmax {am} top1_top2_gap {gap:.6} logit_{F32_TOK} {:.6} logit_{INT8_TOK} {:.6} \
             f32tok_minus_int8tok {:.6} maxdiff_vs_f32 {:.6} maxdiff_vs_llama {:.6}",
            l[F32_TOK as usize],
            l[INT8_TOK as usize],
            l[F32_TOK as usize] - l[INT8_TOK as usize],
            maxdiff(l, base),
            maxdiff(l, &llama),
        );
        am
    };

    // Negative control: the f32 path is deterministic.
    let again = run(false, false, u64::MAX, Q8_ALL);
    let repeat_diff = maxdiff(&again[12], base);
    println!("DIAG_F32_REPEAT_MAXDIFF: {repeat_diff}");

    let i8l = run(true, false, u64::MAX, Q8_ALL);
    let eml = run(false, true, u64::MAX, Q8_ALL);
    for p in 0..=12 {
        let (fa, fg) = top2(&f32l[p]);
        let (ia, ig) = top2(&i8l[p]);
        println!(
            "DIAG_POS {p}: f32 argmax {fa} gap {fg:.6} | int8 argmax {ia} gap {ig:.6} | maxdiff {:.6} | emul_vs_int8 {:.6}",
            maxdiff(&f32l[p], &i8l[p]),
            maxdiff(&eml[p], &i8l[p]),
        );
    }
    let a_f32 = report("f32", base);
    let a_int8 = report("int8", &i8l[12]);
    report("emulate_q8k_f32_dots", &eml[12]);
    report("llama_cpp", &llama);

    let classes = [
        ("qkv", Q8_QKV),
        ("wo", Q8_WO),
        ("gate_up", Q8_GATE_UP),
        ("down", Q8_DOWN),
        ("output", Q8_OUTPUT),
    ];
    for (n, c) in classes {
        report(
            &format!("int8_only_{n}"),
            &run(true, false, u64::MAX, c)[12],
        );
        report(
            &format!("int8_except_{n}"),
            &run(true, false, u64::MAX, Q8_ALL & !c)[12],
        );
    }
    // Layer masks leave the output head on f32, so only layer effects show.
    let no_out = Q8_ALL & !Q8_OUTPUT;
    let all_layers = if n_layer == 64 {
        u64::MAX
    } else {
        (1u64 << n_layer) - 1
    };
    report(
        "int8_all_layers_f32_output",
        &run(true, false, u64::MAX, no_out)[12],
    );
    for l in 0..n_layer {
        report(
            &format!("int8_only_layer_{l:02}"),
            &run(true, false, 1 << l, no_out)[12],
        );
        report(
            &format!("int8_except_layer_{l:02}"),
            &run(true, false, all_layers & !(1 << l), no_out)[12],
        );
    }

    assert_eq!(repeat_diff, 0.0, "f32 path not deterministic");
    assert_eq!(
        a_f32, F32_TOK,
        "recorded f32 choice at index 12 not reproduced"
    );
    assert_eq!(
        a_int8, INT8_TOK,
        "recorded int8 choice at index 12 not reproduced"
    );
}

/// Part of the aienos#34 int8 parity diagnosis: on a real activation (layer 0
/// attention RMSNorm of the BOS embedding), the int8 matvec and the f32
/// matvec over the same Q8_K-rounded activations both equal an f64 reference
/// of `row . round(x)` to rounding error, for every K-quant weight that layer
/// 0 feeds from that activation. So the int8 arithmetic itself adds nothing
/// beyond the activation rounding.
#[test]
fn int8_matvec_equals_rounded_f32_on_real_activation() {
    use aienos_infer::decode::{q8k_round, rms_norm};
    use aienos_infer::quant::Q8Act;
    let Some(bytes) = model_bytes() else { return };
    let g = Gguf::parse(&bytes).unwrap();
    let m = Model::new(&g).unwrap();
    let l0 = &m.layers[0];
    let e = m.params.embedding_length as usize;
    let mut emb = vec![0f32; e];
    m.tok_embd.row_into(128000, &mut emb).unwrap();
    let mut h = vec![0f32; e];
    rms_norm(&emb, &l0.attn_norm, m.params.rms_norm_eps, &mut h);
    let mut xr = h.clone();
    q8k_round(&mut xr);
    let mut q8 = Q8Act::with_capacity(e);
    q8.quantize(&h).unwrap();
    let ws = [
        ("wq", &l0.wq),
        ("wk", &l0.wk),
        ("wv", &l0.wv),
        ("w_gate", &l0.w_gate),
        ("w_up", &l0.w_up),
    ];
    for (name, w) in ws {
        assert!(w.is_kquant());
        let mut a = vec![0f32; w.rows];
        let mut scr = vec![0f32; w.cols];
        w.matvec(&xr, &mut a, &mut scr).unwrap();
        let mut b = vec![0f32; w.rows];
        w.matvec_q8(&q8, &mut b).unwrap();
        let mut row = vec![0f32; w.cols];
        let (mut da, mut db, mut mc) = (0f64, 0f64, 0f64);
        for r in 0..w.rows {
            w.row_into(r, &mut row).unwrap();
            let c: f64 = row
                .iter()
                .zip(&xr)
                .map(|(p, q)| *p as f64 * *q as f64)
                .sum();
            da = da.max((a[r] as f64 - c).abs());
            db = db.max((b[r] as f64 - c).abs());
            mc = mc.max(c.abs());
        }
        println!("REAL_ACT {name}: max|f32-ref| {da:.3e} max|int8-ref| {db:.3e} max|ref| {mc:.3e}");
        assert!(
            da <= 1e-5 * mc.max(1.0),
            "{name}: f32 path off the f64 reference"
        );
        assert!(
            db <= 1e-5 * mc.max(1.0),
            "{name}: int8 path off the f64 reference"
        );
    }
}

/// Part of the aienos#34 int8 parity diagnosis: int8 against the f32 path on
/// the same Q8_K-rounded activations (`emulate_q8k`), per matvec class, over
/// the first `n` prompt tokens. Prints `DRIFT` lines. The two compute the same
/// values per matvec (test above) but in a different summation order; the
/// rounding to the Q8_K grid is a step function, so a last-bit difference
/// upstream can move an activation to the neighbouring grid point.
/// `cargo test --release -p aienos-infer --test forward int8_vs_q8k_emulation_drift -- --ignored --nocapture`
#[test]
#[ignore = "model-backed, about a minute; run locally"]
fn int8_vs_q8k_emulation_drift() {
    let Some(bytes) = model_bytes() else {
        panic!("model file required");
    };
    let g = Gguf::parse(&bytes).unwrap();
    let m = Model::new(&g).unwrap();
    let tok = Tokenizer::new(&g.tokenizer().unwrap()).unwrap();
    let ids = tok.encode_chat("What is the capital of France?").unwrap();
    let md = |a: &[f32], b: &[f32]| {
        a.iter()
            .zip(b)
            .map(|(x, y)| (x - y).abs())
            .fold(0f32, f32::max)
    };
    for n in [1usize, 2, 3, 8, ids.len()] {
        let run = |int8: bool, round: bool, c: u8| {
            let mut st = DecodeState::new(&m, ids.len() + 1);
            st.int8_dot = int8;
            st.emulate_q8k = round;
            st.q8_classes = c;
            st.prefill(&m, &ids[..n]).unwrap();
            st.logits.clone()
        };
        let f = run(false, false, Q8_ALL);
        for (name, c) in [
            ("qkv", Q8_QKV),
            ("wo", Q8_WO),
            ("gate_up", Q8_GATE_UP),
            ("down", Q8_DOWN),
            ("output", Q8_OUTPUT),
            ("all", Q8_ALL),
        ] {
            let i = run(true, false, c);
            let e = run(false, true, c);
            println!(
                "DRIFT tokens {n} class {name}: int8_vs_emul {:.3e} int8_vs_f32 {:.3e} emul_vs_f32 {:.3e}",
                md(&i, &e),
                md(&i, &f),
                md(&e, &f)
            );
        }
    }
}
