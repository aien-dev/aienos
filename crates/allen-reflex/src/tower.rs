//! ALLEN Tower: scheduling core for a Pi 5 bare-metal AIENOS test and verification orchestrator.
//!
//! Intended pairing: the persistent 8 GB Raspberry Pi 5 (bare-metal AIENOS + ALLEN REFLEX)
//! with the DGX Spark. Status: library only. Nothing links this module into the Pi kernel or
//! any test runner yet, and no Pi or Spark run has exercised it.
//!
//! Rules this core enforces:
//! - A PASS receipt is reused only for the exact `(gate, tier, input_digest)` it was recorded
//!   for, and only for gates marked cacheable. A receipt from one tier (for example the
//!   labelled Pi test tier) never stands in for another tier.
//! - `input_digest` is meant to come from [`combine_mneme_digest`]: SHA-256 over the declared
//!   inputs, the sibling pins and every observed Mneme (`libmneme.so`) file-read digest.
//! - Concurrent identical cacheable requests join the run already in flight (`JoinInflight`).
//!   Uncacheable gates always run on their own.
//! - Routing: `Portable` and `Pi5Host` gates run on the Pi 5 (`RunPi5Local`), `SparkHost` and
//!   `SparkQemu` gates go to the Spark host pool (`DispatchSparkHost`), and `SparkGb10` /
//!   `SparkNvrm` gates go to the Spark's one-at-a-time GPU queue (`QueueSparkGb10`).

use aienos_crypto::sha256::Sha256;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// Execution tier for a verification gate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GateTier {
    /// Pure tree/receipt check with no hardware or host tool assumptions.
    Portable,
    /// Lightweight C or Rust check runnable directly on the persistent 8 GB Pi 5.
    Pi5Host,
    /// Multi-core compilation or mutation sweep dispatched to Spark's 20 Grace cores.
    SparkHost,
    /// Full-system AArch64 QEMU emulation dispatched to Spark's host pool.
    SparkQemu,
    /// Exclusive Grace Blackwell GB10 silicon gate (serialized 1-at-a-time).
    SparkGb10,
    /// Exclusive NVRM kernel-driver lifecycle gate (serialized 1-at-a-time).
    SparkNvrm,
}

/// Gate scheduling request evaluated by ALLEN Tower.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GateSpec {
    pub gate: String,
    pub tier: GateTier,
    pub input_digest: [u8; 32],
    pub cacheable: bool,
}

/// Orchestrator action emitted by ALLEN Tower.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TowerAction {
    /// Exact `(gate, tier, input_digest)` already has a verified PASS receipt.
    ReuseReceipt { receipt_digest: [u8; 32] },
    /// Identical `(gate, tier, input_digest)` is running in slot `slot`; join its result.
    /// The slot number stays the same until that run is completed.
    JoinInflight { slot: usize },
    /// Execute locally on the persistent Pi 5 orchestrator node.
    RunPi5Local,
    /// Dispatch to DGX Spark's parallel host/QEMU worker pool.
    DispatchSparkHost,
    /// Enqueue on DGX Spark's serialized GB10/NVRM hardware lock queue.
    QueueSparkGb10,
}

impl TowerAction {
    /// Canonical wire name for the tower action.
    pub fn name(&self) -> &'static str {
        match self {
            TowerAction::ReuseReceipt { .. } => "reuse_receipt",
            TowerAction::JoinInflight { .. } => "join_inflight",
            TowerAction::RunPi5Local => "run_pi5_local",
            TowerAction::DispatchSparkHost => "dispatch_spark_host",
            TowerAction::QueueSparkGb10 => "queue_spark_gb10",
        }
    }
}

/// Machine-checkable reason for a [`TowerDecision`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TowerWhy {
    CachedPassReceipt,
    InflightDuplicate,
    TierLocalPi5,
    TierSparkHostPool,
    TierSparkGpuSerial,
    UncacheableGate,
}

impl TowerWhy {
    pub fn name(self) -> &'static str {
        match self {
            TowerWhy::CachedPassReceipt => "cached_pass_receipt",
            TowerWhy::InflightDuplicate => "inflight_duplicate",
            TowerWhy::TierLocalPi5 => "tier_local_pi5",
            TowerWhy::TierSparkHostPool => "tier_spark_host_pool",
            TowerWhy::TierSparkGpuSerial => "tier_spark_gpu_serial",
            TowerWhy::UncacheableGate => "uncacheable_gate",
        }
    }
}

/// Deterministic scheduling decision from ALLEN Tower.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TowerDecision {
    pub gate: String,
    pub action: TowerAction,
    pub why: TowerWhy,
}

impl TowerDecision {
    /// Format as a single-line JSON decision record. The gate name is JSON-escaped.
    pub fn to_json(&self) -> String {
        let mut out = String::from(r#"{"tower_action":""#);
        out.push_str(self.action.name());
        out.push_str(r#"","gate":""#);
        push_json_escaped(&mut out, &self.gate);
        out.push_str(r#"","why":""#);
        out.push_str(self.why.name());
        out.push_str(r#""}"#);
        out
    }
}

fn push_json_escaped(out: &mut String, s: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let b = c as u32 as u8;
                out.push_str("\\u00");
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0xf) as usize] as char);
            }
            c => out.push(c),
        }
    }
}

/// Domain tag that starts every cache-key encoding (NUL-terminated).
const INPUT_DOMAIN: &[u8] = b"ALLEN-TOWER-INPUT-V1\0";

/// Combine the declared input digest, the sibling pin digest and the Mneme observed
/// read-set digests into one 32-byte cache key.
///
/// Key = SHA-256(`"ALLEN-TOWER-INPUT-V1\0"` || declared || pins || read count as u64 LE ||
/// each read digest in order). Every field has a fixed size and the count is explicit, so two
/// different inputs never share an encoding; the order of the reads matters.
pub fn combine_mneme_digest(
    declared_inputs: &[u8; 32],
    sibling_pins: &[u8; 32],
    mneme_reads: &[[u8; 32]],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(INPUT_DOMAIN);
    h.update(declared_inputs);
    h.update(sibling_pins);
    h.update(&(mneme_reads.len() as u64).to_le_bytes());
    for r in mneme_reads {
        h.update(r);
    }
    h.finalize()
}

/// One recorded PASS receipt: `(gate, tier, input_digest, receipt_digest)`.
type ReceiptEntry = (String, GateTier, [u8; 32], [u8; 32]);
/// One occupied in-flight slot: `(gate, tier, input_digest)`.
type InflightEntry = (String, GateTier, [u8; 32]);

/// Bounded, `no_std` orchestrator state machine for the Pi 5 ALLEN Tower.
pub struct TowerOrchestrator {
    max_receipts: usize,
    receipts: Vec<ReceiptEntry>,
    /// Fixed table of `max_inflight` slots; a run keeps its slot index until completed.
    inflight: Vec<Option<InflightEntry>>,
}

impl TowerOrchestrator {
    pub fn new(max_receipts: usize, max_inflight: usize) -> Self {
        Self {
            max_receipts,
            receipts: Vec::new(),
            inflight: vec![None; max_inflight],
        }
    }

    /// Maximum number of PASS receipts kept (oldest evicted first).
    pub fn max_receipts(&self) -> usize {
        self.max_receipts
    }

    /// Number of in-flight slots.
    pub fn max_inflight(&self) -> usize {
        self.inflight.len()
    }

    /// Record a verified PASS receipt for `(gate, tier, input_digest)` and free its in-flight slot.
    pub fn record_pass_receipt(
        &mut self,
        gate: &str,
        tier: GateTier,
        input_digest: [u8; 32],
        receipt_digest: [u8; 32],
    ) {
        self.complete_inflight(gate, tier, &input_digest);
        for entry in &mut self.receipts {
            if entry.0 == gate && entry.1 == tier && entry.2 == input_digest {
                entry.3 = receipt_digest;
                return;
            }
        }
        if self.max_receipts == 0 {
            return;
        }
        if self.receipts.len() >= self.max_receipts {
            self.receipts.remove(0);
        }
        self.receipts
            .push((String::from(gate), tier, input_digest, receipt_digest));
    }

    /// Free the in-flight slot of a finished run. Returns false if no slot held it.
    pub fn complete_inflight(
        &mut self,
        gate: &str,
        tier: GateTier,
        input_digest: &[u8; 32],
    ) -> bool {
        for slot in &mut self.inflight {
            if matches!(slot, Some((g, t, d)) if g == gate && *t == tier && d == input_digest) {
                *slot = None;
                return true;
            }
        }
        false
    }

    /// Decide how to handle `spec` without dropping or weakening any gate check.
    ///
    /// A cacheable request that finds every in-flight slot taken is dispatched without being
    /// tracked, so a duplicate of it runs again instead of joining (never skipped).
    pub fn schedule_gate(&mut self, spec: &GateSpec) -> TowerDecision {
        let (action, tier_why) = match spec.tier {
            GateTier::Portable | GateTier::Pi5Host => {
                (TowerAction::RunPi5Local, TowerWhy::TierLocalPi5)
            }
            GateTier::SparkHost | GateTier::SparkQemu => {
                (TowerAction::DispatchSparkHost, TowerWhy::TierSparkHostPool)
            }
            GateTier::SparkGb10 | GateTier::SparkNvrm => {
                (TowerAction::QueueSparkGb10, TowerWhy::TierSparkGpuSerial)
            }
        };

        if !spec.cacheable {
            return TowerDecision {
                gate: spec.gate.clone(),
                action,
                why: TowerWhy::UncacheableGate,
            };
        }

        for (g, t, din, drcpt) in &self.receipts {
            if *g == spec.gate && *t == spec.tier && *din == spec.input_digest {
                return TowerDecision {
                    gate: spec.gate.clone(),
                    action: TowerAction::ReuseReceipt {
                        receipt_digest: *drcpt,
                    },
                    why: TowerWhy::CachedPassReceipt,
                };
            }
        }

        let same = |e: &Option<InflightEntry>| matches!(e, Some((g, t, d)) if *g == spec.gate && *t == spec.tier && *d == spec.input_digest);
        if let Some(slot) = self.inflight.iter().position(same) {
            return TowerDecision {
                gate: spec.gate.clone(),
                action: TowerAction::JoinInflight { slot },
                why: TowerWhy::InflightDuplicate,
            };
        }
        if let Some(free) = self.inflight.iter_mut().find(|e| e.is_none()) {
            *free = Some((spec.gate.clone(), spec.tier, spec.input_digest));
        }

        TowerDecision {
            gate: spec.gate.clone(),
            action,
            why: tier_why,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tower_reuses_receipt_and_deduplicates_inflight_and_routes_tiers() {
        let mut tower = TowerOrchestrator::new(64, 16);
        let d_decl = [0x11u8; 32];
        let d_pins = [0x22u8; 32];
        let d_read1 = [0x33u8; 32];
        let d_in = combine_mneme_digest(&d_decl, &d_pins, &[d_read1]);
        let d_rcpt = [0x99u8; 32];

        tower.record_pass_receipt("OMEGA-ALGEBRA", GateTier::SparkHost, d_in, d_rcpt);

        let spec = GateSpec {
            gate: String::from("OMEGA-ALGEBRA"),
            tier: GateTier::SparkHost,
            input_digest: d_in,
            cacheable: true,
        };
        let dec = tower.schedule_gate(&spec);
        assert_eq!(
            dec.action,
            TowerAction::ReuseReceipt {
                receipt_digest: d_rcpt
            }
        );
        assert_eq!(dec.why, TowerWhy::CachedPassReceipt);
        assert_eq!(
            dec.to_json(),
            r#"{"tower_action":"reuse_receipt","gate":"OMEGA-ALGEBRA","why":"cached_pass_receipt"}"#
        );

        // Changing a Mneme observed read-set file invalidates the receipt and dispatches to Spark.
        let d_in_changed = combine_mneme_digest(&d_decl, &d_pins, &[[0x34u8; 32]]);
        assert_ne!(d_in, d_in_changed);
        let spec_changed = GateSpec {
            gate: String::from("OMEGA-ALGEBRA"),
            tier: GateTier::SparkHost,
            input_digest: d_in_changed,
            cacheable: true,
        };
        let dec1 = tower.schedule_gate(&spec_changed);
        assert_eq!(dec1.action, TowerAction::DispatchSparkHost);
        assert_eq!(dec1.why, TowerWhy::TierSparkHostPool);

        // A second concurrent request for the same (gate, input_digest) joins the in-flight run.
        let dec2 = tower.schedule_gate(&spec_changed);
        assert_eq!(dec2.action, TowerAction::JoinInflight { slot: 0 });
        assert_eq!(dec2.why, TowerWhy::InflightDuplicate);

        // Portable/Pi5Host routes locally to Pi 5; SparkGb10 queues on Spark GPU lock.
        let pi_spec = GateSpec {
            gate: String::from("AIENOS-ZERO-DISK-SECRETS"),
            tier: GateTier::Portable,
            input_digest: [0x55u8; 32],
            cacheable: true,
        };
        assert_eq!(
            tower.schedule_gate(&pi_spec).action,
            TowerAction::RunPi5Local
        );

        let gpu_spec = GateSpec {
            gate: String::from("OMEGA-DIVSQRT-CHIP"),
            tier: GateTier::SparkGb10,
            input_digest: [0x66u8; 32],
            cacheable: false,
        };
        let gpu_dec = tower.schedule_gate(&gpu_spec);
        assert_eq!(gpu_dec.action, TowerAction::QueueSparkGb10);
        assert_eq!(gpu_dec.why, TowerWhy::UncacheableGate);
    }

    fn spec(gate: &str, tier: GateTier, d: u8, cacheable: bool) -> GateSpec {
        GateSpec {
            gate: String::from(gate),
            tier,
            input_digest: [d; 32],
            cacheable,
        }
    }

    #[test]
    fn join_slot_stays_stable_after_an_earlier_run_completes() {
        let mut tower = TowerOrchestrator::new(8, 4);
        let a = spec("GATE-A", GateTier::SparkHost, 1, true);
        let b = spec("GATE-B", GateTier::SparkHost, 2, true);
        assert_eq!(
            tower.schedule_gate(&a).action,
            TowerAction::DispatchSparkHost
        );
        assert_eq!(
            tower.schedule_gate(&b).action,
            TowerAction::DispatchSparkHost
        );
        assert_eq!(
            tower.schedule_gate(&b).action,
            TowerAction::JoinInflight { slot: 1 }
        );
        assert!(tower.complete_inflight("GATE-A", GateTier::SparkHost, &[1; 32]));
        // B is still the run in slot 1; a joiner must keep pointing at it.
        assert_eq!(
            tower.schedule_gate(&b).action,
            TowerAction::JoinInflight { slot: 1 }
        );
    }

    #[test]
    fn receipt_from_one_tier_is_not_reused_for_another_tier() {
        let mut tower = TowerOrchestrator::new(8, 4);
        tower.record_pass_receipt("AIENOS-STORE", GateTier::Pi5Host, [7; 32], [0xaa; 32]);
        // Same gate and inputs, but asked for on the Spark host tier: must run there.
        let spark = spec("AIENOS-STORE", GateTier::SparkHost, 7, true);
        let dec = tower.schedule_gate(&spark);
        assert_eq!(dec.action, TowerAction::DispatchSparkHost);
        assert_eq!(dec.why, TowerWhy::TierSparkHostPool);
        // The Pi tier still reuses its own receipt.
        let pi = spec("AIENOS-STORE", GateTier::Pi5Host, 7, true);
        assert_eq!(
            tower.schedule_gate(&pi).action,
            TowerAction::ReuseReceipt {
                receipt_digest: [0xaa; 32]
            }
        );
        // An in-flight run on one tier is not joined by a request for another tier.
        let qemu = spec("AIENOS-STORE", GateTier::SparkQemu, 7, true);
        assert_eq!(
            tower.schedule_gate(&qemu).action,
            TowerAction::DispatchSparkHost
        );
    }

    #[test]
    fn full_slot_table_dispatches_every_request_and_pass_frees_the_slot() {
        let mut tower = TowerOrchestrator::new(8, 1);
        let a = spec("GATE-A", GateTier::Pi5Host, 1, true);
        let b = spec("GATE-B", GateTier::Pi5Host, 2, true);
        assert_eq!(tower.schedule_gate(&a).action, TowerAction::RunPi5Local);
        // No free slot: B runs untracked, so a duplicate of B runs again (never skipped).
        assert_eq!(tower.schedule_gate(&b).action, TowerAction::RunPi5Local);
        assert_eq!(tower.schedule_gate(&b).action, TowerAction::RunPi5Local);
        // Recording A's PASS frees slot 0 for the next run.
        tower.record_pass_receipt("GATE-A", GateTier::Pi5Host, [1; 32], [0xbb; 32]);
        assert_eq!(tower.schedule_gate(&b).action, TowerAction::RunPi5Local);
        assert_eq!(
            tower.schedule_gate(&b).action,
            TowerAction::JoinInflight { slot: 0 }
        );
        assert_eq!(tower.max_inflight(), 1);
    }

    #[test]
    fn uncacheable_gate_is_never_joined_to_another_run() {
        let mut tower = TowerOrchestrator::new(8, 4);
        let g = spec("OMEGA-DIVSQRT-CHIP", GateTier::SparkGb10, 6, false);
        assert_eq!(tower.schedule_gate(&g).action, TowerAction::QueueSparkGb10);
        let again = tower.schedule_gate(&g);
        assert_eq!(again.action, TowerAction::QueueSparkGb10);
        assert_eq!(again.why, TowerWhy::UncacheableGate);
    }

    #[test]
    fn decision_json_escapes_the_gate_name() {
        let dec = TowerDecision {
            gate: String::from("a\"b\\c\nd\u{1}"),
            action: TowerAction::RunPi5Local,
            why: TowerWhy::TierLocalPi5,
        };
        assert_eq!(
            dec.to_json(),
            r#"{"tower_action":"run_pi5_local","gate":"a\"b\\c\nd\u0001","why":"tier_local_pi5"}"#
        );
    }

    #[test]
    fn cache_key_is_sha256_of_the_domain_separated_encoding() {
        // Expected value computed outside Rust with coreutils sha256sum over
        // "ALLEN-TOWER-INPUT-V1\0" || [0x11;32] || [0x22;32] || 2u64 LE || [0x33;32] || [0x34;32].
        let got = combine_mneme_digest(&[0x11; 32], &[0x22; 32], &[[0x33; 32], [0x34; 32]]);
        let want = [
            0x37, 0x6b, 0xdf, 0x72, 0xe9, 0xfb, 0xa8, 0xe7, 0xca, 0xf8, 0x23, 0x76, 0xb2, 0xc5,
            0x3d, 0xb5, 0x54, 0xca, 0xda, 0x99, 0xb8, 0xbb, 0x40, 0x1d, 0x54, 0x34, 0xf0, 0xc2,
            0xd9, 0x09, 0x83, 0x93,
        ];
        assert_eq!(got, want);
        // Order of the observed reads and their count both change the key.
        assert_ne!(
            got,
            combine_mneme_digest(&[0x11; 32], &[0x22; 32], &[[0x34; 32], [0x33; 32]])
        );
        assert_ne!(
            combine_mneme_digest(&[0x11; 32], &[0x22; 32], &[]),
            combine_mneme_digest(&[0x11; 32], &[0x22; 32], &[[0; 32]])
        );
    }
}
