//! D-1 / D-2 golden vectors for the C continuity codec (contract
//! native/kernel/CONTINUITY_RECOVERY_CONTRACT.md 6.3, aienos#222, cut 2).
//!
//! TEST-ONLY emitter: nothing here is compiled outside `cfg(test)` and it
//! changes no kernel behaviour. It writes two plain-text fixtures under
//! `native/kernel/tests/fixtures/`:
//!
//! * `continuity_vectors.txt`: canonical bytes and logical ObjectIds (D-1).
//! * `continuity_verdicts.txt`: for every vector, the Rust decode verdict of
//!   the untouched bytes and of every single-bit flip (D-2).
//!
//! The C host test (`native/kernel/tests/test_continuity_codec.c`) reads both
//! files and must reproduce every byte, every ObjectId and every verdict.
//!
//! Regenerate (the only command):
//!   AIENOS_CONTINUITY_VECTORS_REGEN=1 cargo test -p aienos-kernel --lib continuity_vectors
//! Without the variable the test fails if a committed fixture differs from
//! freshly emitted bytes, so the fixtures cannot drift from the oracle.

use super::*;
use crate::recovery::OperatorAuth;
use crate::recovery_core::{Action, SlotView, SystemRecord};
use crate::store::engine::{MountState, PeerCondition};
use alloc::format;
use alloc::string::String;

const AGENT: [u8; 32] = [0x11; 32];
const UUID: [u8; 16] = [0x5a; 16];
/// The same TEST operator key recovery_core_tests.rs uses (OPERATOR).
const TEST_KEY: [u8; 32] = [0x0f; 32];

/// Every decode refusal text continuity.rs can return, as (code, class, why).
/// A reason missing from this table makes the emitter panic, so a new Rust
/// reason can never be silently dropped from the D-2 comparison.
const REASONS: &[(char, &str, &str)] = &[
    ('a', "Corrupt", "bad magic"),
    ('b', "Corrupt", "unsupported continuity format version"),
    ('c', "Corrupt", "nonzero header reserved"),
    ('d', "Corrupt", "body length mismatch"),
    ('e', "Corrupt", "truncated object"),
    ('f', "Corrupt", "nonzero reserved"),
    ('g', "Corrupt", "trailing bytes"),
    ('h', "Corrupt", "unknown provisioning source"),
    ('i', "Corrupt", "zero agent id"),
    ('j', "Corrupt", "root branch does not derive from agent"),
    ('k', "Corrupt", "too many cortex WAL segments"),
    ('l', "Corrupt", "manifest sequence/previous mismatch"),
    ('m', "Corrupt", "branch count out of range"),
    ('n', "Corrupt", "branches not strictly sorted"),
    ('o', "Corrupt", "unexpected root branch"),
    ('p', "Corrupt", "parent branch is absent"),
    ('q', "Corrupt", "branch lineage is inconsistent"),
    ('r', "Corrupt", "fork indexes are not contiguous"),
    ('s', "Corrupt", "WAL segment record count"),
    ('t', "Corrupt", "unknown epistemic status"),
    ('u', "Corrupt", "statement length"),
];

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn verdict(kind: u16, bytes: &[u8]) -> char {
    let r = match kind {
        KIND_AGENT_ROOT => AgentRoot::decode(bytes).map(|_| ()),
        KIND_MANIFEST => Manifest::decode(bytes).map(|_| ()),
        KIND_AGENT_STATE => AgentState::decode(bytes).map(|_| ()),
        KIND_CORTEX_WAL => WalSegment::decode(bytes).map(|_| ()),
        _ => panic!("unknown kind"),
    };
    match r {
        Ok(()) => '.',
        Err(ContinuityError::Corrupt(w)) => {
            REASONS
                .iter()
                .find(|(_, c, t)| *c == "Corrupt" && *t == w)
                .unwrap_or_else(|| panic!("reason not in REASONS: {w}"))
                .0
        }
        Err(ContinuityError::Limit(w)) => {
            REASONS
                .iter()
                .find(|(_, c, t)| *c == "Limit" && *t == w)
                .unwrap_or_else(|| panic!("reason not in REASONS: {w}"))
                .0
        }
        Err(e) => panic!("decode returned a non-codec error: {e:?}"),
    }
}

fn root(source: ProvisionSource) -> Vec<u8> {
    AgentRoot {
        agent_id: AGENT,
        store_uuid: UUID,
        root_branch: root_branch_id(&AGENT),
        provisioned_generation: 0x0102030405060708,
        source,
    }
    .encode()
}

fn manifest(n_wal: usize, sequence: u64) -> Vec<u8> {
    Manifest {
        root: ObjectId([0xa1; 32]),
        previous: (sequence > 1).then_some(ObjectId([0xd4; 32])),
        sequence,
        incarnation: 1,
        agent_state: Some(ObjectId([0xb2; 32])),
        cortex_wal: (0..n_wal).map(|i| ObjectId([i as u8 + 1; 32])).collect(),
    }
    .encode()
    .unwrap()
}

fn wal(status: Epistemic, len: usize) -> Vec<u8> {
    WalSegment {
        sequence: 3,
        records: alloc::vec![CortexRecord {
            status,
            evidence_hash: [0x40 + status as u8; 32],
            statement: (0..len).map(|i| b'A' + (i % 26) as u8).collect(),
        }],
    }
    .encode()
    .unwrap()
}

fn vectors() -> Vec<(String, u16, Vec<u8>)> {
    let mut v: Vec<(String, u16, Vec<u8>)> = Vec::new();
    v.push((
        "root_operator".into(),
        KIND_AGENT_ROOT,
        root(ProvisionSource::Operator),
    ));
    v.push((
        "root_qualification".into(),
        KIND_AGENT_ROOT,
        root(ProvisionSource::Qualification),
    ));
    for n in [0usize, 1, 64] {
        v.push((format!("manifest_wal{n}"), KIND_MANIFEST, manifest(n, 1)));
    }
    v.push((
        "manifest_seq2_previous".into(),
        KIND_MANIFEST,
        manifest(1, 2),
    ));

    let mut s = AgentState::genesis(AGENT, 1);
    v.push((
        "state_genesis".into(),
        KIND_AGENT_STATE,
        s.encode().unwrap(),
    ));
    let rb = root_branch_id(&AGENT);
    let c0 = s.fork(&rb).unwrap();
    v.push((
        "state_fork_depth1".into(),
        KIND_AGENT_STATE,
        s.encode().unwrap(),
    ));
    // The d1 bytes patched into a hostile table: root claims 2^64-1 forks and
    // the child 2, so a wrapping sum equals the child count (1). Both
    // implementations must refuse (Rust #232; contract 1.5, section 9).
    let mut hostile = s.encode().unwrap();
    // 64-byte header+fixed, 80 bytes per branch, forks at +72; sorted order.
    let (a, b) = if s.branches[0].id == rb {
        (0, 1)
    } else {
        (1, 0)
    };
    hostile[64 + 80 * a + 72..64 + 80 * a + 80].copy_from_slice(&u64::MAX.to_le_bytes());
    hostile[64 + 80 * b + 72..64 + 80 * b + 80].copy_from_slice(&2u64.to_le_bytes());
    s.fork(&rb).unwrap();
    s.fork(&c0).unwrap();
    v.push((
        "state_fork_depth2".into(),
        KIND_AGENT_STATE,
        s.encode().unwrap(),
    ));
    v.push(("state_forksum_overflow".into(), KIND_AGENT_STATE, hostile));

    for st in [
        Epistemic::DirectObservation,
        Epistemic::VerifiedFact,
        Epistemic::Inference,
        Epistemic::Hypothesis,
        Epistemic::Contradiction,
        Epistemic::OperatorDecision,
    ] {
        for len in [1usize, 1024] {
            v.push((
                format!("wal_status{}_len{len}", st as u8),
                KIND_CORTEX_WAL,
                wal(st, len),
            ));
        }
    }
    v
}

fn system_record() -> SystemRecord {
    SystemRecord {
        slots: [SlotView::Zero, SlotView::Zero],
        state_digest: [0x33; 32],
        store_uuid: Some(UUID),
        mount: Some((MountState::Valid, PeerCondition::Zero, 7)),
        reason: None,
        continuity: None,
        catalog: None,
    }
}

/// (vectors.txt, verdicts.txt) contents.
fn emit() -> (String, String) {
    let mut t = String::new();
    t.push_str("# continuity golden vectors (D-1), emitted by the Rust oracle.\n");
    t.push_str("# DO NOT EDIT. Regenerate with:\n");
    t.push_str("#   AIENOS_CONTINUITY_VECTORS_REGEN=1 cargo test -p aienos-kernel --lib continuity_vectors\n");
    t.push_str(
        "# bid <name> <hex32>                      branch id (root = SHA-256 of agent 0x11 x32)\n",
    );
    t.push_str(
        "# vec <name> <kind> <objectid> <bytes>    canonical bytes, logical ObjectId (store v1)\n",
    );
    t.push_str("# deferred <name> <hex32>                 recovery challenge / HMAC response: C does not\n");
    t.push_str("#                                         implement these yet (resolve cut), not checked\n");
    let rb = root_branch_id(&AGENT);
    t.push_str(&format!("bid root {}\n", hex(&rb)));
    for (name, ix) in [
        ("child_index_0", 0u64),
        ("child_index_1", 1),
        ("child_index_2p32", 1 << 32),
        ("child_index_2p64m1", u64::MAX),
    ] {
        t.push_str(&format!("bid {name} {}\n", hex(&child_branch_id(&rb, ix))));
    }
    let vs = vectors();
    for (name, kind, bytes) in &vs {
        let id = ObjectId::calculate(*kind, STORE_OBJECT_VERSION, bytes).unwrap();
        t.push_str(&format!(
            "vec {name} {kind} {} {}\n",
            hex(&id.0),
            hex(bytes)
        ));
    }
    let rec = system_record();
    for (name, a) in [
        ("repair_degraded_peer", Action::RepairDegradedPeer),
        ("provision_identity", Action::ProvisionIdentity),
    ] {
        let ch = rec.challenge(a).unwrap();
        t.push_str(&format!("deferred challenge_{name} {}\n", hex(&ch)));
        t.push_str(&format!(
            "deferred response_{name} {}\n",
            hex(&OperatorAuth::expected_response(&TEST_KEY, &ch))
        ));
    }

    let mut d = String::new();
    d.push_str("# continuity decode verdicts (D-2), emitted by the Rust oracle.\n");
    d.push_str("# DO NOT EDIT. Regenerate: see continuity_vectors.txt.\n");
    d.push_str(
        "# reason <c> <class> <why>; '.' = accept. verdict <name> <string>: char 0 is the\n",
    );
    d.push_str(
        "# untouched vector, char 1+i is the vector with bit (i%8) of byte (i/8) flipped.\n",
    );
    for (c, cls, why) in REASONS {
        d.push_str(&format!("reason {c} {cls} {why}\n"));
    }
    for (name, kind, bytes) in &vs {
        let mut s = String::new();
        s.push(verdict(*kind, bytes));
        let mut t = bytes.clone();
        for i in 0..bytes.len() * 8 {
            t[i / 8] ^= 1 << (i % 8);
            s.push(verdict(*kind, &t));
            t[i / 8] ^= 1 << (i % 8);
        }
        d.push_str(&format!("verdict {name} {s}\n"));
    }
    (t, d)
}

fn fixture_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../native/kernel/tests/fixtures")
}

#[test]
fn committed_fixtures_match_the_oracle() {
    let (vecs, verds) = emit();
    let dir = fixture_dir();
    let files = [
        ("continuity_vectors.txt", vecs),
        ("continuity_verdicts.txt", verds),
    ];
    if std::env::var_os("AIENOS_CONTINUITY_VECTORS_REGEN").is_some() {
        for (n, c) in &files {
            std::fs::write(dir.join(n), c).unwrap();
        }
        return;
    }
    for (n, c) in &files {
        let have = std::fs::read_to_string(dir.join(n)).unwrap_or_default();
        assert!(
            have == *c,
            "{n} differs from freshly emitted bytes; regenerate with \
             AIENOS_CONTINUITY_VECTORS_REGEN=1 cargo test -p aienos-kernel --lib continuity_vectors"
        );
    }
}

#[test]
fn emitted_vectors_are_canonical() {
    for (name, kind, bytes) in vectors() {
        let v = verdict(kind, &bytes);
        if name == "state_forksum_overflow" {
            assert_eq!(v, 'r', "{name}: the overflowing fork sum must be refused");
            continue;
        }
        assert_eq!(v, '.', "{name}: must decode");
        let again = match kind {
            KIND_AGENT_ROOT => AgentRoot::decode(&bytes).unwrap().encode(),
            KIND_MANIFEST => Manifest::decode(&bytes).unwrap().encode().unwrap(),
            KIND_AGENT_STATE => AgentState::decode(&bytes).unwrap().encode().unwrap(),
            _ => WalSegment::decode(&bytes).unwrap().encode().unwrap(),
        };
        assert_eq!(again, bytes, "{name}: decode then encode must be identical");
    }
}
