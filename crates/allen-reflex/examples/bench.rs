//! Speed and size. usage: taskset -c 0 cargo run --release -p allen-reflex --example bench
//! Times the whole path a message takes (tokenize, segment, policy, features, encode, score,
//! span copy, JSON) on the train and dev messages, single thread. Never reads held-out.
#[path = "common/mod.rs"]
mod common;
use allen_reflex::{exam_turns, Config, Mode};
use common::*;
use std::time::Instant;

fn main() {
    let pool = pool();
    let mut msgs = load("train");
    msgs.extend(load("dev"));
    let reps = 50;
    println!("messages {} x {reps} repetitions, one thread", msgs.len());
    println!("mode        build_ms  memory_bytes  median_us  p99_us  max_us  decisions_per_s");
    for mode in [Mode::Reflex, Mode::Nearest, Mode::Perceptron] {
        let refs: Vec<&Case> = pool.iter().collect();
        let t0 = Instant::now();
        let mut core = build(Config::frozen(mode), &refs);
        let build_ms = t0.elapsed().as_secs_f64() * 1e3;
        core.set_learning(false);
        let turns: Vec<_> = msgs.iter().map(|c| exam_turns(&c.turns)).collect();
        // warm up
        for t in &turns {
            std::hint::black_box(core.decide(t));
        }
        let mut lat = Vec::with_capacity(turns.len() * reps);
        let all = Instant::now();
        for _ in 0..reps {
            for t in &turns {
                let s = Instant::now();
                let d = core.decide(t);
                let j = d.0.json();
                std::hint::black_box((d, j));
                lat.push(s.elapsed().as_nanos() as u64);
            }
        }
        let secs = all.elapsed().as_secs_f64();
        lat.sort_unstable();
        let p = |q: f64| lat[((lat.len() as f64 - 1.0) * q) as usize] as f64 / 1e3;
        println!(
            "{:<10}  {:>8.1}  {:>12}  {:>9.1}  {:>6.1}  {:>6.1}  {:>15.0}",
            mode.name(),
            build_ms,
            core.memory_bytes(),
            p(0.5),
            p(0.99),
            p(1.0),
            lat.len() as f64 / secs
        );
    }
}
