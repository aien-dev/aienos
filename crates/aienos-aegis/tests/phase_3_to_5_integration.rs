//! AIENOS Phases 3–5 Full Architecture Integration Verification Suite.
//!
//! Validates:
//! 1. AgentStateAbi reboot survival and state reconstruction (§9).
//! 2. Cortex epistemic grounding and hallucination loop rejection (§11).
//! 3. AEGIS deterministic effect brokering and operator authorization boundaries (§13, §5).
//! 4. C1 Copy-On-Write Prefix Tree with zero memory duplication across 10 branches (§10, §28).
//! 5. Native System Store and Recovery Core deterministic rollback and WAL truncation (ADR 0003, ADR 0006).

use aienos_aegis::{
    AegisError, AegisEvaluator, CapabilityGraph, CapabilityScope, EffectBroker, EffectIntent,
    JSpaceWorld, OperatorGrant,
};
use aienos_agent_state::{AgentStateAbi, AgentStateManager, ComputeState, LogicalAgentId};
use aienos_c1_tree::{C1PrefixTree, PAGE_CAPACITY_TOKENS};
use aienos_cortex::{CortexError, CortexStore};
use aienos_kernel::recovery::{BootSlot, SlotManager, WalRecovery};
use aienos_kernel::store::SystemStore;
use std::collections::BTreeMap;

#[test]
fn test_full_agent_epistemic_capability_and_c1_lifecycle() {
    // ------------------------------------------------------------------------
    // 1. PHASE 3: PERSISTENT AGENT STATE & CORTEX EPISTEMIC MEMORY
    // ------------------------------------------------------------------------
    let state_manager = AgentStateManager::new(1);
    let agent_id = LogicalAgentId::from_seed("sovereign-aien-genesis");
    let root_branch = state_manager.register_agent(agent_id, 1000);

    let mut cortex = CortexStore::new();

    // Ingest DirectObservation from hardware MMIO
    let obs = cortex.record_observation(
        "NVIDIA DGX Spark GB10 accelerator initialized at BAR0 0x10000000",
        "bare_metal_probe",
        b"hw_status:ready",
        1001,
    );

    // Ingest grounded Inference
    let inf = cortex
        .record_inference(
            "C1 engine can bind to physical page frames without host OS",
            "model_cortex_core",
            vec![obs.id],
            0.98,
            1002,
        )
        .expect("Inference must ground cleanly in observation");

    // Attempt ungrounded hallucination -> must be strictly rejected
    let hallucination = cortex.record_inference(
        "Cloud licensing server responded with OK",
        "hallucinating_agent",
        vec![], // No ground truth!
        0.5,
        1003,
    );
    assert!(
        matches!(hallucination, Err(CortexError::UngroundedAssertion(_))),
        "Ungrounded assertions must be rejected by Cortex"
    );

    // Attempt mixed-parent hallucination (one observation + one ungrounded claim) -> must fail!
    let bogus_claim = aienos_cortex::EpistemicRecord::new(
        aienos_cortex::EpistemicStatus::Inference,
        "Bogus premise",
        "bad_agent",
        &[],
        1003,
        0.5,
        None,
        vec![],
    );
    // Inject directly to simulate adversarial storage
    let bogus_id = bogus_claim.id;
    // cortex doesn't expose insert_record publicly outside crate, so test via ungrounded parent id
    let mixed_hallucination = cortex.record_inference(
        "Mixed inference",
        "bad_agent",
        vec![obs.id, bogus_id],
        0.5,
        1004,
    );
    assert!(
        matches!(
            mixed_hallucination,
            Err(CortexError::RecordNotFound(_)) | Err(CortexError::UngroundedAssertion(_))
        ),
        "Mixed parent with unverified parent must be rejected"
    );

    // Record verified fact
    let fact = cortex
        .record_verified_fact(
            "Kernel SHA-256 matches sovereign boot manifest",
            "crypto_audit",
            "sha256_verifier",
            b"manifest_sig",
            vec![obs.id, inf.id],
            1005,
        )
        .expect("Verified fact must succeed");

    // Attach epistemic refs to agent branch
    state_manager
        .add_epistemic_ref(root_branch, fact.id)
        .expect("Attach epistemic ref");

    // Append 500 prompt tokens into agent token history
    let prompt_tokens: Vec<u32> = (1..=500).collect();
    state_manager
        .append_tokens(root_branch, &prompt_tokens)
        .expect("Append tokens");

    // ------------------------------------------------------------------------
    // 2. PHASE 4: C1 COPY-ON-WRITE PREFIX TREE (§10, §28)
    // ------------------------------------------------------------------------
    let mut c1 = C1PrefixTree::new();
    c1.create_root_branch(root_branch, &prompt_tokens)
        .expect("Create C1 root branch");

    let root_pages = c1.pool().allocated_page_count();
    let expected_pages = 500_usize.div_ceil(PAGE_CAPACITY_TOKENS);
    assert_eq!(root_pages, expected_pages);

    // Fork into 10 exploratory branches
    let mut child_branches = Vec::new();
    for _ in 0..10 {
        let child_branch = state_manager
            .fork_branch(root_branch)
            .expect("Fork agent branch");
        c1.fork_branch(root_branch, child_branch)
            .expect("Fork C1 branch");
        child_branches.push(child_branch);
    }

    // VERIFY ZERO MEMORY DUPLICATION:
    // Physical pages allocated must remain EXACTLY identical
    assert_eq!(
        c1.pool().allocated_page_count(),
        root_pages,
        "C1 fork must allocate 0 additional physical pages"
    );

    // Deduplication / sharing metrics
    let metrics = c1.memory_metrics();
    assert!(metrics.sharing_ratio > 1.0);
    assert_eq!(metrics.total_virtual_tokens, 500 * 11);

    // Reserve step capacity and append divergent tokens on branch 0
    let reservation = c1
        .reserve_step_capacity(child_branches[0], 10, 1005, 100)
        .expect("Reserve step capacity");
    assert_eq!(reservation.tokens_reserved, 10);

    c1.append_tokens(child_branches[0], &[9001, 9002])
        .expect("Append divergent tokens");
    let b0_tokens = c1.get_tokens(child_branches[0]).expect("Get tokens");
    assert_eq!(b0_tokens.len(), 502);
    assert_eq!(b0_tokens[500], 9001);

    // ------------------------------------------------------------------------
    // 3. PHASE 4: AEGIS CAPABILITY GRAPH & EFFECT BROKER
    // ------------------------------------------------------------------------
    let master_secret = [0x55u8; 32];
    let operator_secret = [0x77u8; 32];
    let mut aegis_graph = CapabilityGraph::new(master_secret);
    let aegis_evaluator = AegisEvaluator::new(operator_secret);
    let mut broker = EffectBroker::new(aegis_evaluator);
    broker.register_handler("fs.write", |_| Ok("mock file write".to_string()));

    // Issue root filesystem capability to agent
    let cap_id = [0x33u8; 16];
    aegis_graph.issue_root_token(
        cap_id,
        agent_id,
        CapabilityScope::Filesystem {
            path_prefix: "/kernel/data".to_string(),
            read_only: false,
        },
        5,
        5000,
    );

    // Case A: the broker owns a World delta and routes the write into it.
    let world_id = [0x99u8; 16];
    let world = JSpaceWorld::new(world_id, None);
    broker.register_world(world).expect("Register World delta");

    let mut rev_params = BTreeMap::new();
    rev_params.insert("path".to_string(), "/kernel/data/scratch.log".to_string());
    rev_params.insert("content".to_string(), "temp_state".to_string());
    let reversible_intent = EffectIntent::new(
        agent_id,
        "fs.write",
        rev_params,
        cap_id,
        true, // is_reversible
        Some(world_id),
    );

    let rev_decision = broker.dispatch(&reversible_intent, &aegis_graph, None, 1006);
    assert!(rev_decision.is_ok());
    assert_eq!(
        broker
            .world(&world_id)
            .unwrap()
            .read_file("/kernel/data/scratch.log", |_| None),
        Some(b"temp_state".to_vec())
    );

    // Case B: Boundary-crossing irreversible effect without Operator Grant -> REJECTED
    let mut irrev_params = BTreeMap::new();
    irrev_params.insert(
        "path".to_string(),
        "/kernel/data/production.img".to_string(),
    );
    let irreversible_intent = EffectIntent::new(
        agent_id,
        "fs.write",
        irrev_params,
        cap_id,
        false, // irreversible!
        None,  // outside sandbox
    );

    let unapproved_res = broker.dispatch(&irreversible_intent, &aegis_graph, None, 1007);
    assert!(
        matches!(unapproved_res, Err(AegisError::MissingOperatorGrant)),
        "Irreversible intent must be blocked by AEGIS without operator grant"
    );

    // Case C: Provide authentic cryptographic Operator Grant -> APPROVED
    let grant = OperatorGrant::issue(
        irreversible_intent.id,
        "operator_drake",
        &operator_secret,
        1008,
    );

    let approved_res = broker.dispatch(&irreversible_intent, &aegis_graph, Some(&grant), 1008);
    assert!(
        approved_res.is_ok(),
        "Irreversible intent with valid operator grant must succeed"
    );

    // Case D: Cascading Revocation of root token immediately invalidates downstream intents
    let sub_agent = LogicalAgentId::from_seed("delegated_worker");
    let child_cap_id = [0x44u8; 16];
    let child_cap = aegis_graph
        .derive_child_token(
            cap_id,
            child_cap_id,
            sub_agent,
            CapabilityScope::Filesystem {
                path_prefix: "/kernel/data".to_string(),
                read_only: true,
            },
            1009,
        )
        .expect("Derive child capability");
    assert!(aegis_graph.validate_token(&child_cap, 1009).is_ok());

    aegis_graph.revoke(cap_id);
    assert!(
        matches!(
            aegis_graph.validate_token(&child_cap, 1010),
            Err(AegisError::TokenRevoked)
        ),
        "Cascading revocation must invalidate child token"
    );

    // ------------------------------------------------------------------------
    // 4. SOFT REBOOT & DETERMINISTIC RECONSTRUCTION (§9, ADR 0006)
    // ------------------------------------------------------------------------
    let checkpoint_bytes = state_manager
        .export_checkpoint(agent_id)
        .expect("Export checkpoint");

    // Simulate power cycle: new kernel boot incarnation 2
    let mut rebooted_manager = AgentStateManager::restore_from_checkpoint(&checkpoint_bytes, 2)
        .expect("Restore state across reboot");

    let restored_root = rebooted_manager
        .get_branch(&root_branch)
        .expect("Root branch exists");
    assert_eq!(restored_root.agent_id, agent_id);
    assert_eq!(restored_root.token_history.len(), 500);

    // Physical state is evicted post-reboot
    let inc = rebooted_manager
        .get_incarnation(&root_branch)
        .expect("Incarnation exists");
    assert_eq!(inc.incarnation_id, 2);
    assert_eq!(inc.physical_state.compute_state, ComputeState::Evicted);

    // Resume and reconstruct physical KV state
    let _seq = rebooted_manager
        .resume(root_branch)
        .expect("Resume execution slot");
    rebooted_manager
        .reconstruct_physical(root_branch)
        .expect("Reconstruct physical state");

    let inc_reconstructed = rebooted_manager
        .get_incarnation(&root_branch)
        .expect("Reconstructed incarnation");
    assert_eq!(
        inc_reconstructed.physical_state.compute_state,
        ComputeState::Decoding
    );
    assert_eq!(inc_reconstructed.physical_state.allocated_tokens_in_kv, 500);

    // Cleanly remove exploratory branches from C1 tree without leaks
    for child in child_branches {
        c1.remove_branch(child).expect("Remove child branch");
    }
    assert_eq!(c1.pool().allocated_page_count(), root_pages);

    // ------------------------------------------------------------------------
    // 5. NATIVE SYSTEM STORE & RECOVERY CORE (ADR 0003, ADR 0006)
    // ------------------------------------------------------------------------
    let mut sys_store = SystemStore::<32768>::new();
    let boot_bundle = b"AIENOS_BOOT_BUNDLE_v1:kernel=verified,model=llama-3.2-1b,hash=0x8899aabb";
    let extent_desc = sys_store
        .write_extent(boot_bundle)
        .expect("Write boot bundle extent to native store");
    let retrieved_bundle = sys_store
        .read_extent(&extent_desc)
        .expect("Read extent back");
    assert_eq!(retrieved_bundle, boot_bundle);

    // SliceStore verification on caller-provided buffer (no stack allocation)
    let mut slice_buf = [0u8; 1024];
    let mut slice_store = aienos_kernel::store::SliceStore::new(&mut slice_buf);
    let slice_desc = slice_store
        .write_extent(b"cortex_checkpoint_record_v1")
        .expect("Write slice extent");
    assert_eq!(
        slice_store.read_extent(&slice_desc),
        Some(&b"cortex_checkpoint_record_v1"[..])
    );

    // Deterministic A/B Slot Manager verification
    let mut slot_mgr = SlotManager::new();
    assert_eq!(slot_mgr.active_slot, BootSlot::SlotA);
    slot_mgr.record_boot_attempt();
    slot_mgr.record_boot_attempt();
    // 3rd failed attempt triggers automatic rollback to SlotB
    assert!(slot_mgr.record_boot_attempt());
    assert_eq!(slot_mgr.active_slot, BootSlot::SlotB);

    // WAL Truncation verification
    let mut wal_buffer = [0u8; 256];
    let mut wal_len = 0;
    wal_len += WalRecovery::encode_entry(b"op_1: mount store", &mut wal_buffer[wal_len..]);
    wal_len += WalRecovery::encode_entry(b"op_2: load cortex", &mut wal_buffer[wal_len..]);
    let valid_prefix_len = wal_len;
    // Append corrupted entry
    wal_len += WalRecovery::encode_entry(b"op_3: partial write", &mut wal_buffer[wal_len..]);
    wal_buffer[valid_prefix_len + 10] ^= 0xEE; // Corrupt record 3

    let (valid_entries, truncated_bytes) =
        WalRecovery::recover_and_truncate(&wal_buffer[..wal_len]);
    assert_eq!(valid_entries, 2);
    assert_eq!(truncated_bytes, valid_prefix_len);
}
