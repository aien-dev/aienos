//! ALLEN Tower: Pi 5 bare-metal AIENOS test & verification orchestrator core.
//!
//! Pairs the persistent 8 GB Raspberry Pi 5 (booting bare-metal AIENOS + ALLEN REFLEX)
//! with DGX Spark ("Spark Forge"):
//! - Reuses content-addressed PASS receipts across commits when `(gate, input_digest)` matches.
//! - Folds observed Mneme (`libmneme.so`) file-read digests and sibling pins into `input_digest`.
//! - Deduplicates concurrent identical `(gate, input_digest)` requests in-flight (`JoinInflight`).
//! - Routes `Portable` and `Pi5Host` gates to local Pi 5 Cortex-A76 cores (`RunPi5Local`),
//!   `SparkHost` and `SparkQemu` gates to Spark's 20-core host pool (`DispatchSparkHost`),
//!   and `SparkGb10` / `SparkNvrm` gates to Spark's serialized GPU queue (`QueueSparkGb10`).

use alloc::string::String;
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
    /// Exact `(gate, input_digest)` already has a verified PASS receipt.
    ReuseReceipt { receipt_digest: [u8; 32] },
    /// Identical `(gate, input_digest)` is currently running in slot `slot`; join its result.
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
    /// Format as a single-line canonical JSON decision record.
    pub fn to_json(&self) -> String {
        let mut out = String::from(r#"{"tower_action":""#);
        out.push_str(self.action.name());
        out.push_str(r#"","gate":""#);
        out.push_str(&self.gate);
        out.push_str(r#"","why":""#);
        out.push_str(self.why.name());
        out.push_str(r#""}"#);
        out
    }
}

/// Combine declared input digest, sibling pin digest, and Mneme observed read-set digests
/// into a single 32-byte effective cache key (`no_std`, order-sensitive, domain-separated).
pub fn combine_mneme_digest(
    declared_inputs: &[u8; 32],
    sibling_pins: &[u8; 32],
    mneme_reads: &[[u8; 32]],
) -> [u8; 32] {
    let mut state = [0u64; 4];
    let seeds: [u64; 4] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
    ];
    state.copy_from_slice(&seeds);

    fn absorb(st: &mut [u64; 4], tag: u64, block: &[u8; 32]) {
        st[0] ^= tag;
        for i in 0..4 {
            let mut w = 0u64;
            for b in 0..8 {
                w = (w << 8) | (block[i * 8 + b] as u64);
            }
            st[i] = st[i].wrapping_add(w).wrapping_mul(0x9e3779b97f4a7c15);
            st[i] = st[i].rotate_left(27) ^ st[(i + 1) & 3];
        }
    }

    absorb(&mut state, 0x4445434c_u64, declared_inputs);
    absorb(&mut state, 0x50494e53_u64, sibling_pins);
    absorb(
        &mut state,
        (mneme_reads.len() as u64) ^ 0x4d4e454d_u64,
        &[0u8; 32],
    );
    for r in mneme_reads {
        absorb(&mut state, 0x52454144_u64, r);
    }

    let mut out = [0u8; 32];
    for i in 0..4 {
        let bytes = state[i].to_be_bytes();
        out[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }
    out
}

/// Bounded, `no_std` orchestrator state machine for the Pi 5 ALLEN Tower.
pub struct TowerOrchestrator {
    pub max_receipts: usize,
    pub max_inflight: usize,
    receipts: Vec<(String, [u8; 32], [u8; 32])>,
    inflight: Vec<(String, [u8; 32])>,
}

impl TowerOrchestrator {
    pub fn new(max_receipts: usize, max_inflight: usize) -> Self {
        Self {
            max_receipts,
            max_inflight,
            receipts: Vec::new(),
            inflight: Vec::new(),
        }
    }

    /// Record a verified PASS receipt in the bounded content-addressed index.
    pub fn record_pass_receipt(
        &mut self,
        gate: &str,
        input_digest: [u8; 32],
        receipt_digest: [u8; 32],
    ) {
        self.complete_inflight(gate, &input_digest);
        for entry in &mut self.receipts {
            if entry.0 == gate && entry.1 == input_digest {
                entry.2 = receipt_digest;
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
            .push((String::from(gate), input_digest, receipt_digest));
    }

    /// Remove an in-flight gate entry when execution finishes.
    pub fn complete_inflight(&mut self, gate: &str, input_digest: &[u8; 32]) -> bool {
        if let Some(pos) = self
            .inflight
            .iter()
            .position(|(g, d)| g == gate && d == input_digest)
        {
            self.inflight.remove(pos);
            true
        } else {
            false
        }
    }

    /// Decide how to handle `spec` without dropping or weakening any gate check.
    pub fn schedule_gate(&mut self, spec: &GateSpec) -> TowerDecision {
        if spec.cacheable {
            for (g, din, drcpt) in &self.receipts {
                if g == &spec.gate && *din == spec.input_digest {
                    return TowerDecision {
                        gate: spec.gate.clone(),
                        action: TowerAction::ReuseReceipt {
                            receipt_digest: *drcpt,
                        },
                        why: TowerWhy::CachedPassReceipt,
                    };
                }
            }
        }

        if let Some(slot) = self
            .inflight
            .iter()
            .position(|(g, d)| g == &spec.gate && *d == spec.input_digest)
        {
            return TowerDecision {
                gate: spec.gate.clone(),
                action: TowerAction::JoinInflight { slot },
                why: TowerWhy::InflightDuplicate,
            };
        }

        if self.inflight.len() < self.max_inflight {
            self.inflight.push((spec.gate.clone(), spec.input_digest));
        }

        let (action, default_why) = match spec.tier {
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

        let why = if spec.cacheable {
            default_why
        } else {
            TowerWhy::UncacheableGate
        };

        TowerDecision {
            gate: spec.gate.clone(),
            action,
            why,
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

        tower.record_pass_receipt("OMEGA-ALGEBRA", d_in, d_rcpt);

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
}
