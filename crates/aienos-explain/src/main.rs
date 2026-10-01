//! `aienos-explain`: host-side operator command for grounded explanations.
//!
//! aienos-explain explain (--graph FILE | --cortex-journal FILE) --artifact ID
//!     [--summary | --why | --technical | --analogy] [--depth 0-4] [--evidence]
//!     [--uncertain] [--alternatives] [--step N] [--source N]
//!     [--audience general|operator|developer|systems-engineer|researcher]
//!     [--max-depth N] [--max-nodes N] [--json]
//!
//! Exit codes: 0 ok, 2 usage error, 10 + contract error code on explanation errors.

use aienos_explain::adapters::{cortex_graph_for_record, store_from_journal};
use aienos_explain::contract::{EvidenceGraph, ExplainError};
use aienos_explain::{
    build_bundle, render, Audience, ExplanationRequest, ExplanationSession, Limits, Mode,
};
use std::process::ExitCode;

const USAGE: &str =
    "usage: aienos-explain explain (--graph FILE | --cortex-journal FILE) --artifact ID \
[--summary|--why|--technical|--analogy] [--depth 0-4] [--evidence] [--uncertain] [--alternatives] \
[--step N] [--source N] [--audience general|operator|developer|systems-engineer|researcher] \
[--max-depth N] [--max-nodes N] [--json]";

struct Args {
    graph: Option<String>,
    journal: Option<String>,
    artifact: Option<String>,
    mode: Mode,
    depth: Option<u8>,
    evidence: bool,
    uncertain: bool,
    alternatives: bool,
    step: Option<u32>,
    source: Option<u32>,
    audience: Audience,
    limits: Limits,
    json: bool,
}

fn parse(argv: &[String]) -> Result<Args, String> {
    if argv.first().map(String::as_str) != Some("explain") {
        return Err(USAGE.into());
    }
    let mut a = Args {
        graph: None,
        journal: None,
        artifact: None,
        mode: Mode::StepByStep,
        depth: None,
        evidence: false,
        uncertain: false,
        alternatives: false,
        step: None,
        source: None,
        audience: Audience::Operator,
        limits: Limits::default(),
        json: false,
    };
    let mut i = 1;
    let val = |i: &mut usize| -> Result<String, String> {
        *i += 1;
        argv.get(*i)
            .cloned()
            .ok_or_else(|| format!("missing value for {}", argv[*i - 1]))
    };
    let num = |s: String| -> Result<u32, String> {
        s.parse::<u32>().map_err(|_| format!("not a number: {s}"))
    };
    while i < argv.len() {
        match argv[i].as_str() {
            "--graph" => a.graph = Some(val(&mut i)?),
            "--cortex-journal" => a.journal = Some(val(&mut i)?),
            "--artifact" => a.artifact = Some(val(&mut i)?),
            "--summary" => a.mode = Mode::Summary,
            "--why" => a.mode = Mode::StepByStep,
            "--technical" => a.mode = Mode::Technical,
            "--analogy" => a.mode = Mode::Analogy,
            "--depth" => {
                let d = num(val(&mut i)?)?;
                if d > 4 {
                    return Err("--depth is 0 to 4".into());
                }
                a.depth = Some(d as u8);
            }
            "--evidence" => a.evidence = true,
            "--uncertain" => a.uncertain = true,
            "--alternatives" => a.alternatives = true,
            "--step" => a.step = Some(num(val(&mut i)?)?),
            "--source" => a.source = Some(num(val(&mut i)?)?),
            "--audience" => {
                let v = val(&mut i)?;
                a.audience = Audience::parse(&v).ok_or_else(|| format!("unknown audience {v}"))?;
            }
            "--max-depth" => a.limits.max_depth = num(val(&mut i)?)?,
            "--max-nodes" => a.limits.max_nodes = num(val(&mut i)?)?,
            "--json" => a.json = true,
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
        i += 1;
    }
    if a.graph.is_some() == a.journal.is_some() {
        return Err(format!(
            "give exactly one of --graph or --cortex-journal\n{USAGE}"
        ));
    }
    if a.artifact.is_none() {
        return Err(format!("--artifact is required\n{USAGE}"));
    }
    Ok(a)
}

fn parse_cortex_id(s: &str) -> Result<[u8; 16], ExplainError> {
    let h = s.strip_prefix("cortex:").unwrap_or(s);
    if h.len() != 32 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ExplainError::TargetNotFound(format!(
            "{s} is not a 32-hex-digit Cortex record id"
        )));
    }
    let mut id = [0u8; 16];
    for (k, b) in id.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[2 * k..2 * k + 2], 16).expect("hex checked");
    }
    Ok(id)
}

fn run(a: Args) -> Result<String, ExplainError> {
    let artifact = a.artifact.clone().expect("checked");
    let (graph, target) = if let Some(path) = &a.graph {
        let bytes =
            std::fs::read(path).map_err(|e| ExplainError::BadFormat(format!("{path}: {e}")))?;
        (EvidenceGraph::from_json(&bytes)?, artifact)
    } else {
        let path = a.journal.as_ref().expect("checked");
        let bytes =
            std::fs::read(path).map_err(|e| ExplainError::Journal(format!("{path}: {e}")))?;
        let store = store_from_journal(&bytes)?;
        let id = parse_cortex_id(&artifact)?;
        let g = cortex_graph_for_record(&store, &id, a.limits)?;
        (g, aienos_explain::adapters::cortex_node_id(&id))
    };
    let bundle = build_bundle(&graph, &target, a.limits)?;
    if a.json {
        return Ok(bundle.to_json() + "\n");
    }
    let session = ExplanationSession::new(bundle, a.audience);
    if let Some(n) = a.step {
        return session.step(n);
    }
    if let Some(n) = a.source {
        return session.source(n);
    }
    let mut out = render(
        session.bundle(),
        &ExplanationRequest {
            mode: a.mode,
            level: a.depth,
            audience: a.audience,
        },
    );
    if a.evidence {
        out.push_str("\nEvidence:\n");
        out.push_str(&session.evidence());
    }
    if a.uncertain {
        out.push_str("\nUncertain about:\n");
        out.push_str(&session.uncertainties());
    }
    if a.alternatives {
        out.push_str("\nAlternatives:\n");
        out.push_str(&session.alternatives());
    }
    Ok(out)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    match run(args) {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error {e}");
            ExitCode::from(10 + e.code() as u8)
        }
    }
}
