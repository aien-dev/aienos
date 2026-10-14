//! Run the orchestration exam with ALLEN REFLEX and the two baselines.
//! usage: cargo run --release -p allen-reflex --example exam -- <split: train|dev|heldout> [modes...]
//! Writes docs/native/pi5-8/orchestrator-exam/results/allen-reflex.<split>.<mode>.jsonl in
//! run_exam.sh's record format (raw = the decision JSON only), plus a .why.tsv file with the
//! explanation of every decision (kept out of the scored JSON). Learning is off while scoring.
#[path = "common/mod.rs"]
mod common;
use allen_reflex::{exam_turns, Config, Mode};
use common::*;
use std::io::Write;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let split = args
        .first()
        .map(String::as_str)
        .unwrap_or("dev")
        .to_string();
    let modes: Vec<Mode> = if args.len() > 1 {
        args[1..]
            .iter()
            .map(|m| match m.as_str() {
                "reflex" => Mode::Reflex,
                "nearest" => Mode::Nearest,
                "perceptron" => Mode::Perceptron,
                _ => panic!("mode {m}"),
            })
            .collect()
    } else {
        vec![Mode::Reflex, Mode::Nearest, Mode::Perceptron]
    };
    let pool = pool();
    let cases = load(&split);
    for mode in modes {
        let refs: Vec<&Case> = pool.iter().collect();
        let mut core = build(Config::frozen(mode), &refs);
        core.set_learning(false);
        let dir = exam_dir().join("results");
        let f = dir.join(format!("allen-reflex.{split}.{}.jsonl", mode.name()));
        let w = dir.join(format!("allen-reflex.{split}.{}.why.tsv", mode.name()));
        let mut out = std::fs::File::create(&f).unwrap();
        let mut why = std::fs::File::create(&w).unwrap();
        writeln!(why, "id\tdecision\twhy\ttop\tsecond\tmargin\tbest_sim\tagree\tnearest_label\tnearest_message").unwrap();
        let (mut a_ok, mut e_ok) = (0, 0);
        for c in &cases {
            let t = exam_turns(&c.turns);
            let t0 = Instant::now();
            let (d, ex) = core.decide(&t);
            let us = t0.elapsed().as_micros();
            let raw = d.json();
            let (a, e) = judge(c, &d);
            a_ok += a as usize;
            e_ok += e as usize;
            writeln!(
                out,
                "{{\"id\":\"{}\",\"split\":\"{}\",\"cat\":\"{}\",\"exp_action\":\"{}\",\"exp_text\":\"{}\",\"ms\":{},\"finish\":\"stop\",\"raw\":\"{}\",\"ptok\":0,\"ctok\":0,\"us\":{}}}",
                esc(&c.id), esc(&split), esc(&c.cat), c.action.name(), esc(&c.text), us / 1000, esc(&raw), us
            )
            .unwrap();
            let (nl, nm) = ex
                .nearest
                .as_ref()
                .map(|(l, m)| (l.name(), m.as_str()))
                .unwrap_or(("-", "-"));
            writeln!(
                why,
                "{}\t{}\t{:?}\t{}\t{}\t{:.3}\t{:.3}\t{:.2}\t{}\t{}",
                c.id,
                raw,
                ex.why,
                ex.top.name(),
                ex.second.name(),
                ex.margin,
                ex.best_sim,
                ex.agree,
                nl,
                nm.replace('\t', " ")
            )
            .unwrap();
        }
        eprintln!(
            "allen-reflex {split} {}: action {a_ok}/{n} exact {e_ok}/{n}  (memory {} bytes, {} exemplars)",
            mode.name(),
            core.memory_bytes(),
            core.exemplars(),
            n = cases.len()
        );
    }
}
