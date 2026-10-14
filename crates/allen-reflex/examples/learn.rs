//! Learning curves: predict first, score, then reveal the right answer (one-shot learning).
//! usage: cargo run --release -p allen-reflex --example learn
//! Never reads held-out. Memory is rebuilt from scratch for every run (no state carries over).
//!
//! A. cold start: memory holds only the 33 contract cases (written from the system prompt
//!    and agent_cmd.c). The 79 train cases and their 170 paraphrases then arrive one by one
//!    in a seeded random order. Each is decided with what is known so far and scored; then
//!    the operator's answer is revealed (learn_correct when wrong, learn_confirm when right).
//!    After the stream, dev is scored with learning off.
//! B. dev stream: memory = full pool (the exam configuration); the 23 dev cases arrive one by
//!    one with the same predict-then-reveal rule. Dev also chose the thresholds, so B shows
//!    the mechanism, not an unbiased number.
#[path = "common/mod.rs"]
mod common;
use allen_reflex::{exam_turns, Action, Config, Mode};
use common::*;

const RUNS: u64 = 5;
const WINDOW: usize = 25;

fn shuffle<T>(v: &mut [T], seed: u64) {
    let mut s = seed;
    for i in (1..v.len()).rev() {
        let r = allen_reflex::hv::splitmix(&mut s);
        v.swap(i, (r % (i as u64 + 1)) as usize);
    }
}

struct Step {
    exact: bool,
    asked: bool,
    corrections_before: usize,
}

/// Stream `stream` into a core built from `base`; returns per-step results and the core.
fn stream(mode: Mode, base: &[&Case], stream: &[&Case]) -> (Vec<Step>, allen_reflex::Reflex) {
    let mut core = build(Config::frozen(mode), base);
    core.set_learning(true);
    let mut out = Vec::new();
    let mut corr = 0;
    for c in stream {
        let t = exam_turns(&c.turns);
        let (d, _) = core.decide(&t);
        let (_, exact) = judge(c, &d);
        out.push(Step {
            exact,
            asked: d.action == Action::Clarify,
            corrections_before: corr,
        });
        let txt = if c.text.is_empty() {
            None
        } else {
            Some(c.text.as_str())
        };
        if exact {
            core.learn_confirm(&t, &d).expect("confirm");
        } else {
            core.learn_correct(&t, c.action, txt).expect("correct");
            corr += 1;
        }
    }
    (out, core)
}

fn main() {
    let pool = pool();
    let dev = load("dev");
    let contract: Vec<&Case> = pool.iter().filter(|c| c.source == "contract").collect();
    let rest: Vec<&Case> = pool.iter().filter(|c| c.source != "contract").collect();
    println!(
        "A. cold start: {} contract cases in memory, {} cases streamed, {RUNS} seeded orders",
        contract.len(),
        rest.len()
    );
    for mode in [Mode::Reflex, Mode::Nearest, Mode::Perceptron] {
        let nwin = rest.len().div_ceil(WINDOW);
        let mut acc = vec![0usize; nwin];
        let mut ask = vec![0usize; nwin];
        let mut cnt = vec![0usize; nwin];
        let mut corr_end = vec![0usize; nwin];
        let mut dev_after = 0;
        let mut dev_before = 0;
        for run in 0..RUNS {
            let mut order = rest.clone();
            shuffle(&mut order, 0xA11E_0000 + run);
            let (steps, mut core) = stream(mode, &contract, &order);
            for (i, s) in steps.iter().enumerate() {
                let w = i / WINDOW;
                acc[w] += s.exact as usize;
                ask[w] += s.asked as usize;
                cnt[w] += 1;
                if i % WINDOW == WINDOW - 1 || i == steps.len() - 1 {
                    corr_end[w] += s.corrections_before + !s.exact as usize;
                }
            }
            core.set_learning(false);
            for c in &dev {
                dev_after += judge(c, &core.decide(&exam_turns(&c.turns)).0).1 as usize;
            }
            let mut cold = build(Config::frozen(mode), &contract);
            cold.set_learning(false);
            for c in &dev {
                dev_before += judge(c, &cold.decide(&exam_turns(&c.turns)).0).1 as usize;
            }
        }
        println!(
            "{}: dev exact before stream {:.1}/23, after stream {:.1}/23 (mean of {RUNS})",
            mode.name(),
            dev_before as f32 / RUNS as f32,
            dev_after as f32 / RUNS as f32
        );
        println!("  cases     corrections_so_far  window_exact  window_ask_rate");
        for w in 0..nwin {
            let lo = w * WINDOW + 1;
            let hi = (w * WINDOW + WINDOW).min(rest.len());
            println!(
                "  {lo:>3}-{hi:<3}   {:>8.1}            {:>5.1}%        {:>5.1}%",
                corr_end[w] as f32 / RUNS as f32,
                100.0 * acc[w] as f32 / cnt[w] as f32,
                100.0 * ask[w] as f32 / cnt[w] as f32
            );
        }
    }
    println!("B. dev stream: full pool in memory, 23 dev cases streamed, {RUNS} seeded orders");
    for mode in [Mode::Reflex, Mode::Nearest, Mode::Perceptron] {
        let (mut first_half, mut second_half, mut corr, mut asked) = (0, 0, 0, 0);
        for run in 0..RUNS {
            let all: Vec<&Case> = pool.iter().collect();
            let mut order: Vec<&Case> = dev.iter().collect();
            shuffle(&mut order, 0xDE70_0000 + run);
            let (steps, _) = stream(mode, &all, &order);
            for (i, s) in steps.iter().enumerate() {
                if i < 12 {
                    first_half += s.exact as usize;
                } else {
                    second_half += s.exact as usize;
                }
                asked += s.asked as usize;
                corr += !s.exact as usize;
            }
        }
        println!(
            "{}: exact cases 1-12 {:.1}/12, cases 13-23 {:.1}/11, corrections {:.1}, asked {:.1} (means of {RUNS})",
            mode.name(),
            first_half as f32 / RUNS as f32,
            second_half as f32 / RUNS as f32,
            corr as f32 / RUNS as f32,
            asked as f32 / RUNS as f32
        );
    }
}
