//! Producers of the evidence-graph contract from aienos Cortex records and agent
//! branches. Read-only: nothing here writes to Cortex or to agent state.
//!
//! The walk over Cortex is bounded by the same [`Limits`] the builder uses, plus one
//! level of headroom, and records where it stopped (`truncated_at`) so the builder can
//! say "cut short" instead of "missing".

use crate::bundle::{hex, Limits};
use crate::contract::{
    EdgeDoc, EvidenceGraph, ExplainError, NodeDoc, NodeKind, Relation, ScopeDoc, SourceRef, Status,
};
use aienos_agent_state::LogicalBranch;
use aienos_cortex::{CortexStore, EpistemicRecord, EpistemicStatus};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Node id of a Cortex record in the contract.
pub fn cortex_node_id(id: &[u8; 16]) -> String {
    format!("cortex:{}", hex(id))
}

/// Node id of an agent branch in the contract.
pub fn branch_node_id(branch: &LogicalBranch) -> String {
    format!("branch:{}", hex(&branch.branch_id.0))
}

fn status_code(s: EpistemicStatus) -> u8 {
    s as u8
}

fn record_to_node(r: &EpistemicRecord) -> NodeDoc {
    let rel = if r.status == EpistemicStatus::Contradiction {
        Relation::Contradicts
    } else {
        Relation::SupportedBy
    };
    let mut notes = Vec::new();
    if let Some(v) = &r.verified_by {
        notes.push(format!("verified by {v}"));
    }
    let conf = r.confidence;
    let permille = if conf.is_finite() {
        Some((conf.clamp(0.0, 1.0) * 1000.0).round() as u16)
    } else {
        None
    };
    NodeDoc {
        id: cortex_node_id(&r.id),
        kind: NodeKind::CortexRecord.code(),
        status: status_code(r.status),
        statement: r.statement.clone(),
        source: SourceRef {
            system: "aienos-cortex".into(),
            artifact: "EpistemicRecord".into(),
            reference: r.provenance_source.clone(),
            digest: Some(hex(&r.evidence_hash)),
        },
        confidence_permille: permille,
        confidence_basis: permille.map(|_| "Cortex record confidence".to_string()),
        recorded_at_utc: Some(r.created_at_utc),
        parents: r
            .causal_parents
            .iter()
            .map(|p| EdgeDoc {
                to: cortex_node_id(p),
                relation: rel.code(),
            })
            .collect(),
        measurements: Vec::new(),
        missing: Vec::new(),
        notes,
    }
}

/// Bounded backward walk over Cortex from `roots`, emitting reachable records plus
/// contradiction records that involve them. `lookup` is any read-only view of the
/// store (the real `CortexStore`, an imported journal, a test map).
pub fn cortex_graph_from<'a, F>(
    roots: &[[u8; 16]],
    lookup: F,
    contradictions: &[&'a EpistemicRecord],
    limits: Limits,
) -> EvidenceGraph
where
    F: Fn(&[u8; 16]) -> Option<&'a EpistemicRecord>,
{
    let mut g = EvidenceGraph::new("aienos-explain/cortex-adapter");
    // Headroom: one extra level and node so the builder, not the adapter, decides
    // where the explanation is cut.
    let max_depth = limits.max_depth.saturating_add(1);
    let max_nodes = limits.max_nodes.saturating_add(1) as usize;
    let mut depth: BTreeMap<[u8; 16], u32> = BTreeMap::new();
    let mut order: Vec<[u8; 16]> = Vec::new();
    let mut queue: VecDeque<[u8; 16]> = VecDeque::new();
    let mut truncated: BTreeSet<[u8; 16]> = BTreeSet::new();
    let mut roots_sorted: Vec<[u8; 16]> = roots.to_vec();
    roots_sorted.sort();
    roots_sorted.dedup();
    for r in &roots_sorted {
        if depth.contains_key(r) || lookup(r).is_none() {
            continue;
        }
        if depth.len() >= max_nodes {
            // Roots beyond the cap are dropped; mark every admitted root as cut so the
            // builder says "cut short" rather than presenting a complete picture.
            truncated.extend(depth.keys().copied());
            break;
        }
        depth.insert(*r, 0);
        queue.push_back(*r);
    }
    while let Some(id) = queue.pop_front() {
        let Some(rec) = lookup(&id) else { continue };
        order.push(id);
        // Grounding records end the walk (except a root, which the builder may expand
        // as its target). Contradiction records' parents are what they contradict,
        // not support, so they are never walked.
        if (rec.status.is_ground_truth() && !roots.contains(&id))
            || rec.status == EpistemicStatus::Contradiction
        {
            continue;
        }
        let d = depth[&id];
        let mut parents: Vec<[u8; 16]> = rec.causal_parents.clone();
        parents.sort();
        parents.dedup();
        for p in &parents {
            if depth.contains_key(p) || lookup(p).is_none() {
                continue;
            }
            if d + 1 > max_depth || depth.len() >= max_nodes {
                truncated.insert(id);
                continue;
            }
            depth.insert(*p, d + 1);
            queue.push_back(*p);
        }
    }
    let in_set: BTreeSet<[u8; 16]> = order.iter().copied().collect();
    let mut emitted: BTreeSet<[u8; 16]> = BTreeSet::new();
    for id in &order {
        if let Some(r) = lookup(id) {
            if emitted.insert(*id) {
                g.nodes.push(record_to_node(r));
            }
        }
    }
    // Contradictions about records in the set (disclosure, never support).
    // Fixed order whatever order the store was built in.
    let mut contradictions: Vec<&EpistemicRecord> = contradictions.to_vec();
    contradictions.sort_by_key(|r| (r.created_at_utc, r.id));
    contradictions.dedup_by(|a, b| a.id == b.id);
    let mut extra = 0usize;
    for c in contradictions {
        if c.status != EpistemicStatus::Contradiction || emitted.contains(&c.id) {
            continue;
        }
        if c.causal_parents.iter().any(|p| in_set.contains(p)) {
            if extra >= max_nodes {
                // Disclosure cap reached: mark the records this contradiction involves
                // as cut so the builder reports that not everything was collected.
                truncated.extend(c.causal_parents.iter().filter(|p| in_set.contains(*p)));
                continue;
            }
            extra += 1;
            emitted.insert(c.id);
            g.nodes.push(record_to_node(c));
        }
    }
    g.truncated_at = truncated.iter().map(cortex_node_id).collect();
    g
}

/// Evidence graph explaining one Cortex record.
pub fn cortex_graph_for_record(
    store: &CortexStore,
    record: &[u8; 16],
    limits: Limits,
) -> Result<EvidenceGraph, ExplainError> {
    if store.get(record).is_none() {
        return Err(ExplainError::TargetNotFound(cortex_node_id(record)));
    }
    let contradictions = store.find_by_status(EpistemicStatus::Contradiction);
    Ok(cortex_graph_from(
        &[*record],
        |id| store.get(id),
        &contradictions,
        limits,
    ))
}

/// Read a sealed Cortex journal (as written by `CortexStore::export_journal`) into a
/// fresh store. The seal is checked; the live store is never touched.
pub fn store_from_journal(bytes: &[u8]) -> Result<CortexStore, ExplainError> {
    let mut s = CortexStore::new();
    s.import_journal(bytes)
        .map_err(|e| ExplainError::Journal(e.to_string()))?;
    Ok(s)
}

fn branch_node(branch: &LogicalBranch) -> NodeDoc {
    let parent = branch
        .parent_branch_id
        .map(|p| hex(&p.0)[..16].to_string())
        .unwrap_or_else(|| "none (root branch)".into());
    NodeDoc {
        id: branch_node_id(branch),
        kind: NodeKind::AgentBranch.code(),
        status: Status::Unclassified.code(),
        statement: format!(
            "Agent branch {} (lineage depth {}, parent {}) depends on {} referenced Cortex record(s)",
            &hex(&branch.branch_id.0)[..16],
            branch.lineage.depth,
            parent,
            branch.epistemic_refs.len()
        ),
        source: SourceRef {
            system: "aienos-agent-state".into(),
            artifact: "LogicalBranch".into(),
            reference: hex(&branch.branch_id.0),
            digest: None,
        },
        confidence_permille: None,
        confidence_basis: None,
        recorded_at_utc: Some(branch.created_at_utc),
        parents: branch
            .epistemic_refs
            .records()
            .iter()
            .map(|r| EdgeDoc {
                to: cortex_node_id(r),
                relation: Relation::References.code(),
            })
            .collect(),
        measurements: Vec::new(),
        missing: Vec::new(),
        notes: Vec::new(),
    }
}

/// "What evidence did this branch actually depend on?" The graph holds the branch,
/// the records it references, and their bounded causal ancestry. Records that exist
/// in Cortex but that the branch never referenced are not included.
pub fn branch_graph(store: &CortexStore, branch: &LogicalBranch, limits: Limits) -> EvidenceGraph {
    let refs: Vec<[u8; 16]> = branch.epistemic_refs.records().to_vec();
    let contradictions = store.find_by_status(EpistemicStatus::Contradiction);
    let mut g = cortex_graph_from(&refs, |id| store.get(id), &contradictions, limits);
    g.producer = "aienos-explain/branch-adapter".into();
    g.nodes.insert(0, branch_node(branch));
    g.scope = Some(ScopeDoc {
        branch: branch_node_id(branch),
        referenced: refs.iter().map(cortex_node_id).collect(),
    });
    g
}

/// Explain one record as seen from a branch. Fails with `NotInBranchScope` when the
/// record is neither referenced by the branch nor in the support ancestry of a
/// referenced record, so unrelated Cortex facts cannot be pulled in to strengthen a
/// branch. Contradiction records that are only disclosed (they point at the branch's
/// evidence) are not in scope as targets.
pub fn branch_graph_for_record(
    store: &CortexStore,
    branch: &LogicalBranch,
    record: &[u8; 16],
    limits: Limits,
) -> Result<EvidenceGraph, ExplainError> {
    let g = branch_graph(store, branch, limits);
    let want = cortex_node_id(record);
    let by_id: BTreeMap<&str, &NodeDoc> = g.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    if let Some(s) = &g.scope {
        for r in &s.referenced {
            if by_id.contains_key(r.as_str()) && seen.insert(r.as_str()) {
                queue.push_back(r.as_str());
            }
        }
    }
    while let Some(id) = queue.pop_front() {
        for e in &by_id[id].parents {
            let support = Relation::from_code(e.relation).map(|r| r.is_support());
            if support == Ok(true)
                && by_id.contains_key(e.to.as_str())
                && seen.insert(e.to.as_str())
            {
                queue.push_back(e.to.as_str());
            }
        }
    }
    if !seen.contains(want.as_str()) {
        return Err(ExplainError::NotInBranchScope(format!(
            "{want} is not evidence that branch {} depends on",
            branch_node_id(branch)
        )));
    }
    Ok(g)
}
