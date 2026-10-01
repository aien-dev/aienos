//! Behavioural tests for the explanation bridge (brief section 20).

use aienos_agent_state::{AgentStateAbi, AgentStateManager, LogicalAgentId};
use aienos_cortex::{CortexStore, EpistemicRecord, EpistemicStatus};
use aienos_explain::adapters::{
    branch_graph, branch_graph_for_record, cortex_graph_for_record, cortex_graph_from,
    cortex_node_id, store_from_journal,
};
use aienos_explain::bundle::{Role, UncertaintyKind};
use aienos_explain::contract::{
    EdgeDoc, EvidenceGraph, NodeDoc, NodeKind, Relation, SourceRef, Status,
};
use aienos_explain::render::status_words;
use aienos_explain::{
    build_bundle, render, Audience, ExplanationBundle, ExplanationRequest, ExplanationSession,
    Limits, Mode,
};
use std::collections::HashMap;

fn n(id: &str, kind: NodeKind, status: Status, parents: &[(&str, Relation)]) -> NodeDoc {
    NodeDoc {
        id: id.into(),
        kind: kind.code(),
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
            .map(|(t, r)| EdgeDoc {
                to: (*t).into(),
                relation: r.code(),
            })
            .collect(),
        measurements: vec![],
        missing: vec![],
        notes: vec![],
    }
}

fn graph(nodes: Vec<NodeDoc>) -> EvidenceGraph {
    let mut g = EvidenceGraph::new("test");
    g.nodes = nodes;
    g
}

fn ids(b: &ExplanationBundle) -> Vec<&str> {
    b.steps.iter().map(|s| s.node_id.as_str()).collect()
}

fn has(b: &ExplanationBundle, k: UncertaintyKind) -> bool {
    b.uncertainties.iter().any(|u| u.kind == k)
}

const SUP: Relation = Relation::SupportedBy;
const REC: NodeKind = NodeKind::CortexRecord;

#[test]
fn linear_chain_is_ordered_parents_first() {
    let mut c = CortexStore::new();
    let obs = c.record_observation("allocator queue depth 900", "telemetry:kv", b"900", 10);
    let i1 = c
        .record_inference(
            "allocator is saturated",
            "rule:queue>512",
            vec![obs.id],
            0.9,
            20,
        )
        .unwrap();
    let i2 = c
        .record_inference(
            "p95 latency is allocator bound",
            "rule:join",
            vec![i1.id],
            0.8,
            30,
        )
        .unwrap();
    let g = cortex_graph_for_record(&c, &i2.id, Limits::default()).unwrap();
    let b = build_bundle(&g, &cortex_node_id(&i2.id), Limits::default()).unwrap();
    assert_eq!(
        ids(&b),
        vec![
            cortex_node_id(&obs.id),
            cortex_node_id(&i1.id),
            cortex_node_id(&i2.id)
        ]
    );
    assert_eq!(b.conclusion().node_id, cortex_node_id(&i2.id));
    assert_eq!(b.steps[1].supported_by[0].step, 1);
    assert_eq!(b.steps[2].supported_by[0].step, 2);
    assert!(b.steps[0].grounding);
    assert_eq!(b.steps[0].role, Role::Observed);
    assert!(!has(&b, UncertaintyKind::MissingParent));
}

#[test]
fn branching_support_is_deterministic_regardless_of_input_order() {
    let nodes = vec![
        n(
            "c",
            REC,
            Status::Inference,
            &[("z", SUP), ("a", SUP), ("m", SUP)],
        ),
        n("z", REC, Status::DirectObservation, &[]),
        n("a", REC, Status::VerifiedFact, &[]),
        n("m", REC, Status::OperatorDecision, &[]),
    ];
    let b1 = build_bundle(&graph(nodes.clone()), "c", Limits::default()).unwrap();
    let mut rev = nodes;
    rev.reverse();
    let b2 = build_bundle(&graph(rev), "c", Limits::default()).unwrap();
    assert_eq!(b1.steps, b2.steps);
    // Observed (a, z) before Decision (m), ids break ties, conclusion last.
    assert_eq!(ids(&b1), vec!["a", "z", "m", "c"]);
}

#[test]
fn shared_parent_appears_once() {
    let nodes = vec![
        n("concl", REC, Status::Inference, &[("i1", SUP), ("i2", SUP)]),
        n("i1", REC, Status::Inference, &[("obs", SUP)]),
        n("i2", REC, Status::Inference, &[("obs", SUP)]),
        n("obs", REC, Status::DirectObservation, &[]),
    ];
    let mut g = graph(nodes);
    g.nodes[3].source.digest = Some("ab".repeat(32));
    let b = build_bundle(&g, "concl", Limits::default()).unwrap();
    assert_eq!(b.steps.len(), 4);
    assert_eq!(ids(&b).iter().filter(|i| **i == "obs").count(), 1);
    assert_eq!(b.evidence.len(), 1);
    assert_eq!(b.steps[0].node_id, "obs");
}

#[test]
fn cycle_terminates_and_is_reported() {
    let nodes = vec![
        n("A", REC, Status::Inference, &[("B", SUP)]),
        n("B", REC, Status::Inference, &[("C", SUP)]),
        n("C", REC, Status::Inference, &[("A", SUP)]),
    ];
    let b = build_bundle(&graph(nodes), "A", Limits::default()).unwrap();
    assert_eq!(b.steps.len(), 3);
    assert_eq!(b.conclusion().node_id, "A");
    let cyc: Vec<_> = b
        .uncertainties
        .iter()
        .filter(|u| u.kind == UncertaintyKind::Cycle)
        .collect();
    assert_eq!(cyc.len(), 1);
    assert_eq!(cyc[0].node_id, "C");
    assert_eq!(cyc[0].related.as_deref(), Some("A"));
    let text = render(&b, &ExplanationRequest::new(Mode::StepByStep));
    assert!(text.contains("circular"));
}

#[test]
fn cycle_through_imported_cortex_journal_terminates() {
    // Cortex refuses cycles on write, but an imported journal is not re-verified.
    let mk = |tag: u8, parents: Vec<[u8; 16]>| {
        let mut r = EpistemicRecord::new(
            EpistemicStatus::Inference,
            format!("claim {tag}"),
            "test",
            &[tag],
            tag as u64,
            0.5,
            None,
            parents,
        );
        r.id = [tag; 16];
        r
    };
    let a = mk(1, vec![[2; 16]]);
    let bb = mk(2, vec![[3; 16]]);
    let c = mk(3, vec![[1; 16]]);
    let map: HashMap<[u8; 16], EpistemicRecord> =
        [a.clone(), bb, c].into_iter().map(|r| (r.id, r)).collect();
    let g = cortex_graph_from(&[a.id], |id| map.get(id), &[], Limits::default());
    let b = build_bundle(&g, &cortex_node_id(&a.id), Limits::default()).unwrap();
    assert_eq!(b.steps.len(), 3);
    assert!(has(&b, UncertaintyKind::Cycle));
}

#[test]
fn missing_parent_stays_missing() {
    let nodes = vec![
        n(
            "concl",
            REC,
            Status::Inference,
            &[("obs", SUP), ("ghost", SUP)],
        ),
        n("obs", REC, Status::DirectObservation, &[]),
    ];
    let b = build_bundle(&graph(nodes), "concl", Limits::default()).unwrap();
    assert_eq!(
        ids(&b),
        vec!["obs", "concl"],
        "no step is invented for the gap"
    );
    let u = b
        .uncertainties
        .iter()
        .find(|u| u.kind == UncertaintyKind::MissingParent)
        .expect("gap reported");
    assert_eq!(u.related.as_deref(), Some("ghost"));
    let text = render(&b, &ExplanationRequest::new(Mode::Summary));
    assert!(text.contains("no evidence for that link"), "{text}");
}

#[test]
fn unsupported_claim_is_flagged() {
    let nodes = vec![n("lonely", REC, Status::Inference, &[])];
    let b = build_bundle(&graph(nodes), "lonely", Limits::default()).unwrap();
    assert!(has(&b, UncertaintyKind::Unsupported));
}

#[test]
fn contradiction_remains_visible() {
    let mut c = CortexStore::new();
    let o1 = c.record_observation("sensor A says 70C", "sensor:a", b"70", 1);
    let o2 = c.record_observation("sensor B says 40C", "sensor:b", b"40", 2);
    let _x = c
        .flag_contradiction(o1.id, o2.id, "A and B disagree", 3)
        .unwrap();
    let inf = c
        .record_inference("die is hot", "rule:max", vec![o1.id], 0.7, 4)
        .unwrap();
    let g = cortex_graph_for_record(&c, &inf.id, Limits::default()).unwrap();
    let b = build_bundle(&g, &cortex_node_id(&inf.id), Limits::default()).unwrap();
    assert_eq!(b.contradictions.len(), 1);
    assert_eq!(b.contradictions[0].involves, vec![cortex_node_id(&o1.id)]);
    assert!(has(&b, UncertaintyKind::ConflictingEvidence));
    // The contradiction is disclosure, never a support step.
    assert_eq!(b.steps.len(), 2);
    let text = render(&b, &ExplanationRequest::new(Mode::StepByStep));
    assert!(text.contains("Conflicts:"));
    assert!(text.contains("A and B disagree"));
    let s = render(&b, &ExplanationRequest::new(Mode::Summary));
    assert!(s.contains("Main uncertainty"), "{s}");
    assert!(s.contains("contradiction"), "{s}");
}

#[test]
fn hypothesis_is_never_rendered_as_fact() {
    let mut c = CortexStore::new();
    let o = c.record_observation("cache misses up 40%", "perf:llc", b"40", 1);
    let h = c
        .record_hypothesis("prefetcher is mis-trained", "agent:rsi", vec![o.id], 2)
        .unwrap();
    let i = c
        .record_inference("retune prefetcher", "planner", vec![h.id], 0.6, 3)
        .unwrap();
    let g = cortex_graph_for_record(&c, &i.id, Limits::default()).unwrap();
    let b = build_bundle(&g, &cortex_node_id(&i.id), Limits::default()).unwrap();
    let hs = b
        .steps
        .iter()
        .find(|s| s.node_id == cortex_node_id(&h.id))
        .unwrap();
    assert_eq!(hs.status, Status::Hypothesis);
    assert!(!hs.grounding);
    assert!(has(&b, UncertaintyKind::HypothesisNotFalsified));
    for mode in [
        Mode::Summary,
        Mode::StepByStep,
        Mode::Technical,
        Mode::Analogy,
    ] {
        for aud in [Audience::General, Audience::Developer] {
            let t = render(
                &b,
                &ExplanationRequest {
                    mode,
                    level: Some(4),
                    audience: aud,
                },
            );
            for line in t
                .lines()
                .filter(|l| l.contains("prefetcher is mis-trained"))
            {
                assert!(!line.contains("checked fact"), "{line}");
                assert!(!line.contains("VerifiedFact"), "{line}");
                assert!(!line.contains("observed]"), "{line}");
            }
        }
    }
    assert!(status_words(Status::Hypothesis).contains("not yet established"));
}

fn branch_fixture() -> (
    CortexStore,
    AgentStateManager,
    aienos_agent_state::LogicalBranchId,
    [u8; 16],
    [u8; 16],
    [u8; 16],
) {
    let mut c = CortexStore::new();
    let used = c.record_observation("link 3 dropped 2% packets", "nic:3", b"2", 1);
    let derived = c
        .record_inference("link 3 is flaky", "rule:loss>1", vec![used.id], 0.7, 2)
        .unwrap();
    let unrelated = c
        .record_verified_fact(
            "firmware 1.2 is signed",
            "boot",
            "sha256",
            b"sig",
            vec![],
            3,
        )
        .unwrap();
    let m = AgentStateManager::new(1);
    let agent = LogicalAgentId::from_seed("explain-branch");
    let root = m.register_agent(agent, 1);
    let child = m.fork_branch(root).unwrap();
    m.add_epistemic_ref(child, derived.id).unwrap();
    (c, m, child, used.id, derived.id, unrelated.id)
}

#[test]
fn branch_explanation_uses_only_what_the_branch_depended_on() {
    let (c, m, child, used, derived, unrelated) = branch_fixture();
    let br = m.get_branch(&child).unwrap();
    let g = branch_graph(&c, &br, Limits::default());
    let b = build_bundle(&g, &g.nodes[0].id, Limits::default()).unwrap();
    let got = ids(&b);
    assert!(got.contains(&cortex_node_id(&used).as_str()));
    assert!(got.contains(&cortex_node_id(&derived).as_str()));
    assert!(
        !got.contains(&cortex_node_id(&unrelated).as_str()),
        "no opportunistic facts"
    );
    assert_eq!(b.conclusion().kind, NodeKind::AgentBranch);
    let d = b
        .steps
        .iter()
        .find(|s| s.node_id == cortex_node_id(&derived))
        .unwrap();
    assert!(d.branch_referenced);
    let u = b
        .steps
        .iter()
        .find(|s| s.node_id == cortex_node_id(&used))
        .unwrap();
    assert!(!u.branch_referenced, "ancestry, not a direct reference");
    let err = branch_graph_for_record(&c, &br, &unrelated, Limits::default()).unwrap_err();
    assert_eq!(err.code(), 8);
    assert!(branch_graph_for_record(&c, &br, &used, Limits::default()).is_ok());
}

#[test]
fn token_history_never_enters_the_explanation() {
    let (c, m, child, ..) = branch_fixture();
    let before = branch_graph(&c, &m.get_branch(&child).unwrap(), Limits::default());
    m.append_tokens(child, &[11, 22, 33, 44]).unwrap();
    let after = branch_graph(&c, &m.get_branch(&child).unwrap(), Limits::default());
    assert_eq!(
        before, after,
        "explanations are built from records, not token streams"
    );
}

#[test]
fn analogy_is_isolated_from_evidence() {
    let mut c = CortexStore::new();
    let o = c.record_observation("x", "s", b"x", 1);
    let h = c.record_hypothesis("y", "agent", vec![o.id], 2).unwrap();
    let journal_before = c.export_journal().unwrap();
    let g = cortex_graph_for_record(&c, &h.id, Limits::default()).unwrap();
    let b = build_bundle(&g, &cortex_node_id(&h.id), Limits::default()).unwrap();
    let digest = b.bundle_digest.clone();
    let json_before = b.to_json();
    let a = render(&b, &ExplanationRequest::new(Mode::Analogy));
    assert!(a.contains("illustration only, not evidence"));
    assert!(a.contains("The evidence itself:"));
    // Deleting the analogy leaves a complete explanation.
    let plain = render(&b, &ExplanationRequest::new(Mode::StepByStep));
    for s in &b.steps {
        assert!(plain.contains(&s.statement));
        assert!(a.contains(&s.statement));
    }
    // No mutation of the bundle or of Cortex; analogy text is not in the bundle.
    assert_eq!(b.bundle_digest, digest);
    assert_eq!(b.compute_digest(), digest);
    assert_eq!(b.to_json(), json_before);
    assert!(!json_before.contains("mechanic"));
    assert_eq!(c.export_journal().unwrap(), journal_before);
    assert_eq!(c.len(), 2);
}

#[test]
fn identical_input_gives_identical_bundle_and_text() {
    let mut c = CortexStore::new();
    let o = c.record_observation("o", "s", b"o", 1);
    let i = c.record_inference("i", "m", vec![o.id], 0.5, 2).unwrap();
    let journal = c.export_journal().unwrap();
    let c2 = store_from_journal(&journal).unwrap();
    let mk = |s: &CortexStore| {
        let g = cortex_graph_for_record(s, &i.id, Limits::default()).unwrap();
        build_bundle(&g, &cortex_node_id(&i.id), Limits::default()).unwrap()
    };
    let (b1, b2) = (mk(&c), mk(&c2));
    assert_eq!(b1.to_json(), b2.to_json());
    assert_eq!(b1.bundle_digest, b2.bundle_digest);
    for mode in [
        Mode::Summary,
        Mode::StepByStep,
        Mode::Technical,
        Mode::Analogy,
    ] {
        let r = ExplanationRequest::new(mode);
        assert_eq!(render(&b1, &r), render(&b2, &r));
    }
}

#[test]
fn depth_and_node_limits_bound_the_walk() {
    let mut nodes = vec![n("n0", REC, Status::DirectObservation, &[])];
    for k in 1..50 {
        let p = format!("n{}", k - 1);
        nodes.push(n(
            &format!("n{k}"),
            REC,
            Status::Inference,
            &[(p.as_str(), SUP)],
        ));
    }
    let g = graph(nodes);
    let lim = Limits {
        max_depth: 3,
        max_nodes: 256,
    };
    let b = build_bundle(&g, "n49", lim).unwrap();
    assert_eq!(b.steps.len(), 4);
    assert!(has(&b, UncertaintyKind::Truncated));
    // Wide fan-in: node limit holds.
    let mut wide = vec![];
    let parents: Vec<String> = (0..3000).map(|k| format!("p{k}")).collect();
    let refs: Vec<(&str, Relation)> = parents.iter().map(|p| (p.as_str(), SUP)).collect();
    // Parents are capped per node by the contract; split over 3 intermediate nodes.
    wide.push(n(
        "top",
        REC,
        Status::Inference,
        &[("m0", SUP), ("m1", SUP), ("m2", SUP)],
    ));
    for (j, chunk) in refs.chunks(1000).enumerate() {
        wide.push(n(&format!("m{j}"), REC, Status::Inference, chunk));
    }
    for p in &parents {
        wide.push(n(p, REC, Status::DirectObservation, &[]));
    }
    let lim = Limits {
        max_depth: 32,
        max_nodes: 100,
    };
    let b = build_bundle(&graph(wide), "top", lim).unwrap();
    assert!(b.steps.len() <= 100);
    assert!(has(&b, UncertaintyKind::Truncated));
    // Limits are validated.
    assert_eq!(
        build_bundle(
            &g,
            "n1",
            Limits {
                max_depth: 0,
                max_nodes: 1
            }
        )
        .unwrap_err()
        .code(),
        10
    );
    assert_eq!(
        build_bundle(
            &g,
            "n1",
            Limits {
                max_depth: 1,
                max_nodes: 1_000_000
            }
        )
        .unwrap_err()
        .code(),
        10
    );
}

#[test]
fn malformed_input_fails_safely() {
    assert_eq!(
        EvidenceGraph::from_json(b"{not json").unwrap_err().code(),
        1
    );
    let mut g = graph(vec![n("a", REC, Status::Inference, &[])]);
    g.version = 2;
    assert_eq!(g.validate().unwrap_err().code(), 2);
    let mut g = graph(vec![n("a", REC, Status::Inference, &[])]);
    g.nodes[0].status = 9;
    assert_eq!(
        build_bundle(&g, "a", Limits::default()).unwrap_err().code(),
        3
    );
    let g = graph(vec![
        n("a", REC, Status::Inference, &[]),
        n("a", REC, Status::Inference, &[]),
    ]);
    assert_eq!(
        build_bundle(&g, "a", Limits::default()).unwrap_err().code(),
        4
    );
    let g = graph(vec![n("a", REC, Status::Inference, &[])]);
    assert_eq!(
        build_bundle(&g, "zz", Limits::default())
            .unwrap_err()
            .code(),
        5
    );
    let mut j = CortexStore::new();
    j.record_observation("o", "s", b"o", 1);
    let mut bytes = j.export_journal().unwrap();
    let k = bytes.len() / 2;
    bytes[k] ^= 1;
    assert!(store_from_journal(&bytes).is_err());
}

#[test]
fn clarification_reads_the_same_bundle() {
    let nodes = vec![
        n("concl", REC, Status::Inference, &[("i1", SUP)]),
        n("i1", REC, Status::Inference, &[("obs", SUP)]),
        n("obs", REC, Status::DirectObservation, &[]),
    ];
    let b = build_bundle(&graph(nodes), "concl", Limits::default()).unwrap();
    let digest = b.bundle_digest.clone();
    let mut s = ExplanationSession::new(b, Audience::Operator);
    let l0 = s.explain();
    assert!(l0.contains("statement of concl"));
    assert!(!l0.contains("statement of obs"));
    let l1 = s.deeper();
    assert!(l1.contains("statement of i1"));
    assert!(!l1.contains("statement of obs"));
    let l2 = s.deeper();
    assert!(l2.contains("statement of obs"));
    assert_eq!(s.level(), 2);
    assert!(s.step(2).unwrap().contains("rests on step 1"));
    assert!(s.step(1).unwrap().contains("starting point"));
    assert!(s.source(1).unwrap().contains("test (Node)"));
    assert_eq!(s.step(9).unwrap_err().code(), 7);
    assert!(s.technical().contains("step 1 id=obs"));
    assert!(s.simple().contains("Conclusion:"));
    assert!(s.analogy().contains("The evidence itself:"));
    assert!(s.uncertainties().contains("inferred"));
    assert!(s.alternatives().contains("No alternative"));
    assert_eq!(s.bundle().bundle_digest, digest);
}
