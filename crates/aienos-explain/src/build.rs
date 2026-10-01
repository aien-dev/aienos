//! Bounded causal backtracking and linearization.
//!
//! Given an evidence graph and a target node, walk support edges backward
//! (breadth first, deterministic order), stop at grounding nodes and at the limits,
//! cut loops, keep every gap visible, then order the visited sub-graph so that
//! every step comes after the steps it rests on. Only explicit edges are followed;
//! time stamps are never used to order or connect steps.

use crate::bundle::{
    hex, Alternative, CausalStep, ContradictionRef, EvidenceRef, ExplanationBundle,
    ExplanationProvenance, Limits, Role, SupportLink, Uncertainty, UncertaintyKind,
};
use crate::contract::{EvidenceGraph, ExplainError, NodeDoc, NodeKind, Relation, Status};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Builder identity recorded in every bundle.
pub const BUILDER: &str = "aienos-explain/1";

struct Node<'a> {
    doc: &'a NodeDoc,
    kind: NodeKind,
    status: Status,
    /// Support parents, sorted by (relation code, id), duplicates removed.
    support: Vec<(Relation, &'a str)>,
}

fn index(graph: &EvidenceGraph) -> Result<BTreeMap<&str, Node<'_>>, ExplainError> {
    graph.validate()?;
    let mut map = BTreeMap::new();
    for doc in &graph.nodes {
        let kind = NodeKind::from_code(doc.kind)?;
        let status = Status::from_code(doc.status)?;
        let mut support: Vec<(Relation, &str)> = Vec::new();
        for e in &doc.parents {
            let rel = Relation::from_code(e.relation)?;
            if rel.is_support() {
                support.push((rel, e.to.as_str()));
            }
        }
        support.sort();
        support.dedup();
        map.insert(
            doc.id.as_str(),
            Node {
                doc,
                kind,
                status,
                support,
            },
        );
    }
    Ok(map)
}

fn check_limits(l: &Limits) -> Result<(), ExplainError> {
    if l.max_depth == 0 || l.max_nodes == 0 {
        return Err(ExplainError::InvalidLimits(
            "limits must be at least 1".into(),
        ));
    }
    if l.max_depth > Limits::HARD_MAX_DEPTH || l.max_nodes > Limits::HARD_MAX_NODES {
        return Err(ExplainError::InvalidLimits(format!(
            "max_depth <= {}, max_nodes <= {}",
            Limits::HARD_MAX_DEPTH,
            Limits::HARD_MAX_NODES
        )));
    }
    Ok(())
}

/// Build the grounded explanation of `target` from `graph`.
pub fn build_bundle(
    graph: &EvidenceGraph,
    target: &str,
    limits: Limits,
) -> Result<ExplanationBundle, ExplainError> {
    check_limits(&limits)?;
    let nodes = index(graph)?;
    if !nodes.contains_key(target) {
        return Err(ExplainError::TargetNotFound(target.to_string()));
    }
    let producer_truncated: BTreeSet<&str> =
        graph.truncated_at.iter().map(|s| s.as_str()).collect();
    let scope_refs: BTreeSet<&str> = graph
        .scope
        .as_ref()
        .map(|s| s.referenced.iter().map(|r| r.as_str()).collect())
        .unwrap_or_default();

    let mut unc: Vec<Uncertainty> = Vec::new();

    // 1. Bounded breadth-first discovery. depth = shortest edge count from target.
    let mut depth: BTreeMap<&str, u32> = BTreeMap::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    depth.insert(target, 0);
    queue.push_back(target);
    let mut truncated_nodes: BTreeSet<&str> = BTreeSet::new();
    while let Some(id) = queue.pop_front() {
        let n = &nodes[id];
        let d = depth[id];
        // Grounding nodes end the walk: their own parents are not needed to explain.
        if n.status.is_grounding() && id != target {
            continue;
        }
        for (_, pid) in &n.support {
            if depth.contains_key(pid) {
                continue;
            }
            if !nodes.contains_key(pid) {
                if !producer_truncated.contains(id) {
                    unc.push(Uncertainty {
                        kind: UncertaintyKind::MissingParent,
                        node_id: id.to_string(),
                        related: Some(pid.to_string()),
                        detail: format!(
                            "{id} lists {pid} as support, but no such artifact is available; \
                             the system has no evidence for that link"
                        ),
                    });
                }
                continue;
            }
            if d + 1 > limits.max_depth || depth.len() as u32 >= limits.max_nodes {
                truncated_nodes.insert(id);
                continue;
            }
            depth.insert(*pid, d + 1);
            queue.push_back(*pid);
        }
    }
    for id in &truncated_nodes {
        unc.push(Uncertainty {
            kind: UncertaintyKind::Truncated,
            node_id: id.to_string(),
            related: None,
            detail: format!(
                "support of {id} was not followed further (depth limit {}, node limit {})",
                limits.max_depth, limits.max_nodes
            ),
        });
    }

    // The producer also stopped somewhere (its own limits). Say so for every visited
    // node it marked, even when no parent is visibly missing.
    for id in &producer_truncated {
        if depth.contains_key(id) && !truncated_nodes.contains(id) {
            unc.push(Uncertainty {
                kind: UncertaintyKind::Truncated,
                node_id: id.to_string(),
                related: None,
                detail: format!(
                    "the producer of this graph stopped collecting evidence around {id} at \
                     its own limits; more support or contradictions may exist"
                ),
            });
        }
    }

    // 2. Visited support edges (child -> parent) restricted to the visited set.
    let visited: BTreeSet<&str> = depth.keys().copied().collect();
    let mut edges: BTreeMap<&str, Vec<(Relation, &str)>> = BTreeMap::new();
    for id in &visited {
        let n = &nodes[id];
        let keep: Vec<(Relation, &str)> = if n.status.is_grounding() && *id != target {
            Vec::new()
        } else {
            n.support
                .iter()
                .filter(|(_, p)| visited.contains(p))
                .copied()
                .collect()
        };
        edges.insert(*id, keep);
    }

    // 3. Cycle detection: iterative DFS with colors from the target; cut back edges.
    let mut color: BTreeMap<&str, u8> = visited.iter().map(|v| (*v, 0u8)).collect();
    let mut cut: BTreeSet<(&str, &str)> = BTreeSet::new();
    let mut stack: Vec<(&str, usize)> = vec![(target, 0)];
    color.insert(target, 1);
    while let Some((id, i)) = stack.pop() {
        let es = &edges[id];
        if i < es.len() {
            stack.push((id, i + 1));
            let p = es[i].1;
            match color[p] {
                0 => {
                    color.insert(p, 1);
                    stack.push((p, 0));
                }
                1 => {
                    cut.insert((id, p));
                }
                _ => {}
            }
        } else {
            color.insert(id, 2);
        }
    }
    for (from, to) in &cut {
        unc.push(Uncertainty {
            kind: UncertaintyKind::Cycle,
            node_id: from.to_string(),
            related: Some(to.to_string()),
            detail: format!(
                "{from} rests on {to}, which already rests on {from}; the loop was cut and \
                 this support is circular, not grounding"
            ),
        });
    }
    let dag: BTreeMap<&str, Vec<(Relation, &str)>> = edges
        .iter()
        .map(|(id, es)| {
            (
                *id,
                es.iter()
                    .filter(|(_, p)| !cut.contains(&(*id, *p)))
                    .copied()
                    .collect(),
            )
        })
        .collect();

    // 4. Linearize (Kahn): a node is ready once all its parents are placed.
    //    Ties are broken by narrative role, then by id. The target is always last.
    let mut remaining: BTreeMap<&str, usize> = dag.iter().map(|(id, es)| (*id, es.len())).collect();
    let mut children: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (id, es) in &dag {
        for (_, p) in es {
            children.entry(*p).or_default().push(*id);
        }
    }
    let key = |id: &str| -> (Role, String) {
        let n = &nodes[id];
        (Role::of(n.kind, n.status), id.to_string())
    };
    let mut ready: BTreeSet<(Role, String)> = remaining
        .iter()
        .filter(|(id, c)| **c == 0 && **id != target)
        .map(|(id, _)| key(id))
        .collect();
    let mut order: Vec<&str> = Vec::new();
    while let Some(k) = ready.iter().next().cloned() {
        ready.remove(&k);
        let id: &str = visited.get(k.1.as_str()).copied().expect("visited id");
        order.push(id);
        if let Some(cs) = children.get(id) {
            for c in cs {
                let r = remaining.get_mut(c).expect("child");
                *r -= 1;
                if *r == 0 && *c != target {
                    ready.insert(key(c));
                }
            }
        }
    }
    order.push(target);
    debug_assert_eq!(order.len(), visited.len());

    // 5. Steps.
    let pos: BTreeMap<&str, u32> = order
        .iter()
        .enumerate()
        .map(|(i, id)| (*id, i as u32 + 1))
        .collect();
    let mut steps: Vec<CausalStep> = Vec::with_capacity(order.len());
    for id in &order {
        let n = &nodes[id];
        let mut supported_by: Vec<SupportLink> = dag[id]
            .iter()
            .map(|(rel, p)| SupportLink {
                step: pos[p],
                relation: *rel,
            })
            .collect();
        supported_by.sort_by_key(|s| (s.step, s.relation));
        steps.push(CausalStep {
            index: pos[id],
            node_id: id.to_string(),
            kind: n.kind,
            status: n.status,
            role: Role::of(n.kind, n.status),
            statement: n.doc.statement.clone(),
            source: n.doc.source.clone(),
            confidence_permille: n.doc.confidence_permille,
            confidence_basis: n.doc.confidence_basis.clone(),
            recorded_at_utc: n.doc.recorded_at_utc,
            measurements: n.doc.measurements.clone(),
            notes: n.doc.notes.clone(),
            supported_by,
            depth: depth[id],
            grounding: n.status.is_grounding(),
            branch_referenced: scope_refs.contains(id),
        });
    }

    // 6. Per-step uncertainty that stays visible.
    for s in &steps {
        let n = &nodes[s.node_id.as_str()];
        for m in &n.doc.missing {
            unc.push(Uncertainty {
                kind: UncertaintyKind::MissingLink,
                node_id: s.node_id.clone(),
                related: Some(m.expected.clone()),
                detail: format!("no evidence for: {} ({})", m.expected, m.reason),
            });
        }
        for note in &n.doc.notes {
            unc.push(Uncertainty {
                kind: UncertaintyKind::ProducerNote,
                node_id: s.node_id.clone(),
                related: None,
                detail: note.clone(),
            });
        }
        if s.kind == NodeKind::AgentBranch {
            continue;
        }
        let has_support = !n.support.is_empty() || !n.doc.missing.is_empty();
        match s.status {
            Status::Unclassified => unc.push(Uncertainty {
                kind: UncertaintyKind::Unknown,
                node_id: s.node_id.clone(),
                related: None,
                detail: format!(
                    "the epistemic status of step {} is not known; it is neither observed \
                     nor verified",
                    s.index
                ),
            }),
            Status::Inference | Status::Hypothesis if !has_support => unc.push(Uncertainty {
                kind: UncertaintyKind::Unsupported,
                node_id: s.node_id.clone(),
                related: None,
                detail: format!(
                    "step {} is a {} with no recorded support",
                    s.index,
                    s.status.name()
                ),
            }),
            Status::Inference => unc.push(Uncertainty {
                kind: UncertaintyKind::Inferred,
                node_id: s.node_id.clone(),
                related: None,
                detail: format!(
                    "step {} is inferred from earlier steps, not observed directly",
                    s.index
                ),
            }),
            _ => {}
        }
        let is_hypothesis = s.kind == NodeKind::Hypothesis
            || (s.kind == NodeKind::CortexRecord && s.status == Status::Hypothesis);
        if is_hypothesis {
            let tested = steps.iter().any(|o| {
                let os = &nodes[o.node_id.as_str()].support;
                (o.kind == NodeKind::EvaluationReceipt
                    && os
                        .iter()
                        .any(|(rel, p)| *rel == Relation::Evaluates && *p == s.node_id))
                    || (o.kind == NodeKind::CortexRecord
                        && o.status == Status::VerifiedFact
                        && os.iter().any(|(_, p)| *p == s.node_id))
            });
            if !tested {
                unc.push(Uncertainty {
                    kind: UncertaintyKind::HypothesisNotFalsified,
                    node_id: s.node_id.clone(),
                    related: None,
                    detail: format!(
                        "hypothesis at step {} has no evaluation that tests it directly; it \
                         remains a hypothesis",
                        s.index
                    ),
                });
            }
        }
    }

    // 7. Contradictions and alternatives that touch the path. A Contradicts edge is
    //    disclosed when either end is on the path, in either direction, whatever the
    //    status of the node that carries it. Bounded by the input size cap; never
    //    followed further.
    let mut contradictions = Vec::new();
    let mut alternatives = Vec::new();
    for (id, n) in &nodes {
        let mut targets: Vec<String> = Vec::new();
        let mut alt_to: Option<String> = None;
        for e in &n.doc.parents {
            let rel = Relation::from_code(e.relation)?;
            match rel {
                Relation::Contradicts => targets.push(e.to.clone()),
                Relation::AlternativeTo if alt_to.is_none() && visited.contains(e.to.as_str()) => {
                    alt_to = Some(e.to.clone())
                }
                _ => {}
            }
        }
        let self_on_path = visited.contains(id);
        let mut involves: Vec<String> = targets
            .iter()
            .filter(|t| visited.contains(t.as_str()))
            .cloned()
            .collect();
        if !targets.is_empty() && self_on_path {
            involves.push(id.to_string());
        }
        involves.sort();
        involves.dedup();
        if !involves.is_empty() {
            targets.sort();
            targets.dedup();
            let statement = if n.status == Status::Contradiction {
                n.doc.statement.clone()
            } else {
                format!(
                    "{id} contradicts {}: {}",
                    targets.join(", "),
                    n.doc.statement
                )
            };
            for t in &involves {
                let other = if t.as_str() == *id {
                    targets.first().cloned().unwrap_or_default()
                } else {
                    id.to_string()
                };
                unc.push(Uncertainty {
                    kind: UncertaintyKind::ConflictingEvidence,
                    node_id: t.clone(),
                    related: Some(other),
                    detail: format!("{t} is involved in a recorded contradiction: {statement}"),
                });
            }
            contradictions.push(ContradictionRef {
                node_id: id.to_string(),
                statement,
                source: n.doc.source.clone(),
                involves,
            });
        }
        if let (NodeKind::Alternative, Some(to)) = (n.kind, alt_to) {
            alternatives.push(Alternative {
                node_id: id.to_string(),
                statement: n.doc.statement.clone(),
                source: n.doc.source.clone(),
                alternative_to: to,
                measurements: n.doc.measurements.clone(),
            });
        }
    }

    // 8. Evidence pointers: every step with a digest or measurements.
    let evidence: Vec<EvidenceRef> = steps
        .iter()
        .filter(|s| s.source.digest.is_some() || !s.measurements.is_empty())
        .map(|s| EvidenceRef {
            step: s.index,
            node_id: s.node_id.clone(),
            source: s.source.clone(),
            measurements: s.measurements.clone(),
        })
        .collect();

    unc.sort_by(|a, b| {
        (a.kind, &a.node_id, &a.related, &a.detail)
            .cmp(&(b.kind, &b.node_id, &b.related, &b.detail))
    });
    unc.dedup();

    let provenance = ExplanationProvenance {
        builder: BUILDER.to_string(),
        contract_format: graph.format.clone(),
        contract_version: graph.version,
        producer: graph.producer.clone(),
        input_digest: hex(&aienos_crypto::sha256::hash(&graph.to_json())),
        target: target.to_string(),
        limits,
        branch_scope: graph.scope.as_ref().map(|s| s.branch.clone()),
        visited_nodes: visited.len() as u32,
        graph_nodes: graph.nodes.len() as u32,
    };
    let mut bundle = ExplanationBundle {
        conclusion_step: order.len() as u32,
        steps,
        evidence,
        uncertainties: unc,
        contradictions,
        alternatives,
        provenance,
        bundle_digest: String::new(),
    };
    bundle.bundle_digest = bundle.compute_digest();
    Ok(bundle)
}
