//! aienos-evidence CLI.
//!
//!   aienos-evidence capture --model PATH --repo NAME=PATH... [--endpoint URL]
//!                           [--samples N] [--warmup N] [--max-tokens N]
//!                           [--prompt TEXT] [--out PATH] [--allow-dirty]
//!   aienos-evidence verify [BUNDLE]
//!   aienos-evidence verify-efi IMAGE...
//!   aienos-evidence verify-rollback PRE.json POST.json
//!   aienos-evidence models [--endpoint URL]

use aienos_evidence::{capture, http, pe, rollback, verify};
use std::path::PathBuf;
use std::process::exit;

const DEFAULT_BUNDLE: &str = "evidence/config_a_reference_bundle.json";
const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:18094/v1";
const USAGE: &str = "usage:
  aienos-evidence capture --model PATH --repo NAME=PATH... [--endpoint URL] [--samples N]
                          [--warmup N] [--max-tokens N] [--prompt TEXT] [--out PATH] [--allow-dirty]
  aienos-evidence verify [BUNDLE]
  aienos-evidence verify-efi IMAGE...
  aienos-evidence verify-rollback PRE.json POST.json
  aienos-evidence models [--endpoint URL]";

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("{msg}");
    exit(1)
}

struct Args {
    flags: Vec<(String, String)>,
    switches: Vec<String>,
    positional: Vec<String>,
}

fn parse(args: &[String], switches: &[&str]) -> Args {
    let mut a = Args {
        flags: vec![],
        switches: vec![],
        positional: vec![],
    };
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if switches.contains(&arg.as_str()) {
            a.switches.push(arg.clone());
        } else if arg.starts_with("--") {
            let value = args
                .get(i + 1)
                .unwrap_or_else(|| fail(format!("{arg} needs a value\n{USAGE}")));
            a.flags.push((arg.clone(), value.clone()));
            i += 1;
        } else {
            a.positional.push(arg.clone());
        }
        i += 1;
    }
    a
}

impl Args {
    fn get(&self, name: &str) -> Option<&str> {
        self.flags
            .iter()
            .rev()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn all(&self, name: &str) -> Vec<&str> {
        self.flags
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    fn num<T: std::str::FromStr>(&self, name: &str, default: T) -> T {
        self.get(name)
            .map(|v| {
                v.parse()
                    .unwrap_or_else(|_| fail(format!("{name}: not a number: {v}")))
            })
            .unwrap_or(default)
    }
}

fn cmd_capture(args: &[String]) {
    let a = parse(args, &["--allow-dirty"]);
    let model = a
        .get("--model")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("AIENOS_BASELINE_MODEL").map(PathBuf::from))
        .unwrap_or_else(|| fail(format!("--model is required\n{USAGE}")));
    let repos: Vec<(String, PathBuf)> = a
        .all("--repo")
        .into_iter()
        .map(|r| {
            let (name, path) = r
                .split_once('=')
                .unwrap_or_else(|| fail(format!("--repo expects NAME=PATH, got {r}")));
            (name.to_string(), PathBuf::from(path))
        })
        .collect();
    if repos.is_empty() {
        fail(format!(
            "at least one --repo NAME=PATH is required\n{USAGE}"
        ));
    }
    let opts = capture::Options {
        model,
        endpoint: a.get("--endpoint").unwrap_or(DEFAULT_ENDPOINT).to_string(),
        prompt: a
            .get("--prompt")
            .unwrap_or(capture::DEFAULT_PROMPT)
            .to_string(),
        max_tokens: a.num("--max-tokens", 256),
        samples: a.num("--samples", 5),
        warmup: a.num("--warmup", 1),
        repos,
        allow_dirty: a.switches.iter().any(|s| s == "--allow-dirty"),
    };
    let bundle = capture::capture(&opts).unwrap_or_else(|e| fail(format!("capture failed: {e}")));
    let out = PathBuf::from(a.get("--out").unwrap_or(DEFAULT_BUNDLE));
    if let Some(dir) = out.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).unwrap_or_else(|e| fail(e));
    }
    let text = serde_json::to_string_pretty(&bundle).unwrap_or_else(|e| fail(e)) + "\n";
    std::fs::write(&out, text).unwrap_or_else(|e| fail(format!("{}: {e}", out.display())));
    let samples = bundle["reference_workload"]["samples"]
        .as_array()
        .map_or(0, Vec::len);
    println!(
        "Captured Config A: {} ({samples} measured samples)",
        out.display()
    );
}

fn cmd_verify(args: &[String]) {
    let path = args.first().map(String::as_str).unwrap_or(DEFAULT_BUNDLE);
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| fail(format!("Evidence unavailable: {e}")));
    let bundle: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| fail(format!("Evidence unreadable: {e}")));
    let report = verify::check(&bundle);
    if !report.errors.is_empty() {
        for e in &report.errors {
            println!("FAIL: {e}");
        }
        exit(1);
    }
    let samples = &bundle["reference_workload"]["samples"];
    let rates: Vec<f64> = samples
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s["decode_tokens_per_second"].as_f64())
        .collect();
    let mean = rates.iter().sum::<f64>() / rates.len().max(1) as f64;
    println!(
        "Config A capture verified for {}: {} samples, mean decode {mean:.1} tokens/s",
        bundle["config_identity"]["host"].as_str().unwrap_or("?"),
        rates.len()
    );
    if report.m0_open.is_empty() {
        println!("M0 closable: yes");
    } else {
        println!("M0 closable: no ({})", report.m0_open.join("; "));
    }
}

fn cmd_verify_efi(args: &[String]) {
    if args.is_empty() {
        fail(USAGE);
    }
    for path in args {
        let data = std::fs::read(path)
            .unwrap_or_else(|e| fail(format!("UEFI image verification failed: {path}: {e}")));
        match pe::verify_efi_application(&data) {
            Ok(()) => println!("AArch64 PE32+ EFI application verified: {path}"),
            Err(e) => fail(format!("UEFI image verification failed: {path}: {e}")),
        }
    }
}

/// Native-boot rollback verdict. Exits 0 PASS, 1 FAIL, 3 BLOCKED, 2 when a
/// capture cannot be read or parsed (stdout, as the former verifier printed).
fn cmd_verify_rollback(args: &[String]) {
    // Usage errors exit 2, never 1, so they cannot be mistaken for a FAIL verdict.
    let [pre, post] = args else {
        eprintln!("{USAGE}");
        exit(rollback::EXIT_UNPARSEABLE)
    };
    let load = |path: &str| {
        rollback::load(path).unwrap_or_else(|e| {
            println!("ERROR: Cannot parse {path}: {e}");
            exit(rollback::EXIT_UNPARSEABLE)
        })
    };
    let (pre, post) = (load(pre), load(post));
    let (report, verdict) = rollback::verify(&pre, &post);
    print!("{report}");
    exit(verdict.exit_code());
}

fn cmd_models(args: &[String]) {
    let a = parse(args, &[]);
    let url = a.get("--endpoint").unwrap_or(DEFAULT_ENDPOINT);
    let ep = http::Endpoint::parse(url).unwrap_or_else(|e| fail(e));
    for id in http::model_ids(&ep).unwrap_or_else(|e| fail(format!("{url}: {e}"))) {
        println!("{id}");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest = args.get(1..).unwrap_or(&[]);
    match args.first().map(String::as_str) {
        Some("capture") => cmd_capture(rest),
        Some("verify") => cmd_verify(rest),
        Some("verify-efi") => cmd_verify_efi(rest),
        Some("verify-rollback") => cmd_verify_rollback(rest),
        Some("models") => cmd_models(rest),
        _ => fail(USAGE),
    }
}
