//! Cross-repo fixture from spark-rsi (the RSI KV-cache cycle) and the CLI.
//!
//! The fixture is produced by spark-rsi `tests/test_explain_evidence_graph.rs`; both
//! repos pin the same sha256 so a contract drift on either side fails a test.

use aienos_explain::bundle::{Role, UncertaintyKind};
use aienos_explain::contract::{
    EdgeDoc, EvidenceGraph, NodeDoc, NodeKind, Relation, SourceRef, Status,
};
use aienos_explain::{build_bundle, render, ExplanationRequest, Limits, Mode};
use std::process::Command;

const FIXTURE: &[u8] = include_bytes!("fixtures/rsi_kv_cycle.evidence.json");
const FIXTURE_SHA256: &str = "0c04376ca36d95d677942d7e97c0a3eef3728ef72dc3cdf070494174e6a6cc31";
const TARGET: &str = "rsi:conclusion:cycle-kv-0001";

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn fixture() -> EvidenceGraph {
    EvidenceGraph::from_json(FIXTURE).expect("fixture parses")
}

#[test]
fn rsi_fixture_is_pinned() {
    assert_eq!(
        hexs(&aienos_crypto::sha256::hash(FIXTURE)),
        FIXTURE_SHA256,
        "fixture changed; regenerate in spark-rsi and update both pins"
    );
}

#[test]
fn rsi_cycle_explains_in_causal_order() {
    let g = fixture();
    assert_eq!(g.producer, "spark-rsi/explain");
    let b = build_bundle(&g, TARGET, Limits::default()).expect("bundle");
    assert_eq!(b.conclusion().node_id, TARGET);
    // Role order along the path never goes backwards for this cycle.
    let roles: Vec<Role> = b.steps.iter().map(|s| s.role).collect();
    let first = |r: Role| roles.iter().position(|x| *x == r).expect("role present");
    assert!(first(Role::Observed) < first(Role::Analysis));
    assert!(first(Role::Analysis) < first(Role::Hypothesis));
    assert!(first(Role::Hypothesis) < first(Role::Prediction));
    assert!(first(Role::Prediction) < first(Role::Falsification));
    assert!(first(Role::Falsification) < first(Role::Evaluation));
    assert!(first(Role::Evaluation) < first(Role::Decision));
    assert_eq!(*roles.last().unwrap(), Role::Conclusion);

    let kinds: Vec<UncertaintyKind> = b.uncertainties.iter().map(|u| u.kind).collect();
    // Candidate -> hypothesis link is not recorded by RSI, so it stays visible.
    assert!(kinds.contains(&UncertaintyKind::MissingLink));
    // The receipt does not evaluate the hypothesis directly.
    assert!(kinds.contains(&UncertaintyKind::HypothesisNotFalsified));
    // Gate flags are outside the receipt digest: reported, status unknown.
    assert!(kinds.contains(&UncertaintyKind::Unknown));
    assert_eq!(b.alternatives.len(), 3);

    let receipt = b
        .steps
        .iter()
        .find(|s| s.kind == NodeKind::EvaluationReceipt && s.source.digest.is_some())
        .expect("receipt step");
    assert_eq!(receipt.status, Status::VerifiedFact);
    let summary = b
        .steps
        .iter()
        .find(|s| s.kind == NodeKind::EvaluationReceipt && s.source.digest.is_none())
        .expect("receipt summary step");
    assert_eq!(summary.status, Status::Unclassified);
    // The hypothesis is never presented as fact.
    let h = b
        .steps
        .iter()
        .find(|s| s.kind == NodeKind::Hypothesis)
        .expect("hypothesis");
    assert_eq!(h.status, Status::Hypothesis);

    let text = render(&b, &ExplanationRequest::new(Mode::StepByStep));
    for heading in [
        "Observed",
        "System analysis",
        "Hypothesis",
        "Prediction",
        "Falsification",
        "Evaluation",
        "Decision",
        "Conclusion",
    ] {
        assert!(text.contains(heading), "missing heading {heading}:\n{text}");
    }
    // Determinism across runs.
    let again = build_bundle(&fixture(), TARGET, Limits::default()).unwrap();
    assert_eq!(b.bundle_digest, again.bundle_digest);
}

fn node(id: &str, status: Status, parents: &[(&str, Relation)]) -> NodeDoc {
    NodeDoc {
        id: id.into(),
        kind: NodeKind::CortexRecord.code(),
        status: status.code(),
        statement: format!("statement of {id}"),
        source: SourceRef {
            system: "test".into(),
            artifact: "Node".into(),
            reference: id.into(),
            digest: None,
        },
        confidence_permille: None,
        confidence_basis: None,
        recorded_at_utc: None,
        parents: parents
            .iter()
            .map(|(to, r)| EdgeDoc {
                to: (*to).into(),
                relation: r.code(),
            })
            .collect(),
        measurements: Vec::new(),
        missing: Vec::new(),
        notes: Vec::new(),
    }
}

#[test]
fn contradiction_disclosed_in_both_directions() {
    let mut g = EvidenceGraph::new("test");
    g.nodes = vec![
        node("t:obs", Status::DirectObservation, &[]),
        // An ordinary record (not a Contradiction record) that contradicts the path.
        node(
            "t:rival",
            Status::DirectObservation,
            &[("t:obs", Relation::Contradicts)],
        ),
        // The target itself contradicts something off the path.
        node(
            "t:claim",
            Status::Inference,
            &[
                ("t:obs", Relation::SupportedBy),
                ("t:other", Relation::Contradicts),
            ],
        ),
        node("t:other", Status::DirectObservation, &[]),
    ];
    let b = build_bundle(&g, "t:claim", Limits::default()).unwrap();
    let ids: Vec<&str> = b
        .contradictions
        .iter()
        .map(|c| c.node_id.as_str())
        .collect();
    assert!(ids.contains(&"t:rival"), "{ids:?}");
    assert!(ids.contains(&"t:claim"), "{ids:?}");
    // Contradicting nodes are disclosed, never walked as support.
    assert!(b
        .steps
        .iter()
        .all(|s| s.node_id != "t:rival" && s.node_id != "t:other"));
}

#[test]
fn cli_explains_fixture() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/rsi_kv_cycle.evidence.json"
    );
    let bin = env!("CARGO_BIN_EXE_aienos-explain");
    let out = Command::new(bin)
        .args(["explain", "--graph", path, "--artifact", TARGET, "--why"])
        .output()
        .expect("run cli");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("Conclusion"));
    let json = Command::new(bin)
        .args(["explain", "--graph", path, "--artifact", TARGET, "--json"])
        .output()
        .unwrap();
    assert!(json.status.success());
    assert!(String::from_utf8_lossy(&json.stdout).contains("bundle_digest"));
    let bad = Command::new(bin)
        .args(["explain", "--graph", path, "--artifact", "no:such"])
        .output()
        .unwrap();
    assert_eq!(
        bad.status.code(),
        Some(15),
        "TargetNotFound is code 5, exit 10+5"
    );
    let usage = Command::new(bin).args(["explain"]).output().unwrap();
    assert_eq!(usage.status.code(), Some(2));
}
