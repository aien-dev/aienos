//! Binary Artifact v0 loader: the only path from authenticated artifact bytes
//! to a runnable EL0 task (ADR 0014 §5).
//!
//! INTERFACE SKELETON — the pipeline body lands in the P2-5 loader commit.

use aienos_artifact::error::ArtifactError;
use aienos_artifact::signature::TrustTier;
use aienos_artifact::ArtifactId;

use crate::task_runtime::{ExecutionStatus, TaskOutcome};

/// Candidate lifecycle (ADR 0014 §5). Only `Admitted` tasks ever run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateState {
    Received,
    Staged,
    Verified,
    Authorized,
    Reserved,
    Mapped,
    Hashed,
    Sealed,
    CapsInstalled,
    Admitted,
    Running,
    Rejected,
    Destroyed,
}

impl CandidateState {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Staged => "staged",
            Self::Verified => "verified",
            Self::Authorized => "authorized",
            Self::Reserved => "reserved",
            Self::Mapped => "mapped",
            Self::Hashed => "hashed",
            Self::Sealed => "sealed",
            Self::CapsInstalled => "caps",
            Self::Admitted => "admitted",
            Self::Running => "running",
            Self::Rejected => "rejected",
            Self::Destroyed => "destroyed",
        }
    }
}

/// Every reason a candidate can be refused or torn down.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadError {
    Artifact(ArtifactError),
    NoFrames,
    StagingTooLarge,
    Mapping,
    MappedDigestMismatch,
    WxAudit,
    CapabilityInstall,
    SchedulerFull,
    ExecutedDigestMismatch,
    Reclaim,
}

impl From<ArtifactError> for LoadError {
    fn from(error: ArtifactError) -> Self {
        Self::Artifact(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Admitted,
    Rejected,
}

/// What one boot candidate did, for the boot report and QEMU checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateReport {
    pub decision: Decision,
    pub failed_stage: Option<CandidateState>,
    pub error: Option<LoadError>,
    pub artifact_id: Option<ArtifactId>,
    pub trust_tier: Option<TrustTier>,
    pub frames_reserved: usize,
    pub frames_free_before: usize,
    pub frames_free_after: usize,
    pub caps_installed: usize,
    pub caps_live_after: usize,
    /// identified == verified == admitted == mapped == executed.
    pub byte_chain: bool,
    pub wx_enforced: bool,
    pub outcome: TaskOutcome,
    pub code_base: u64,
    pub code_end: u64,
}

impl CandidateReport {
    pub const fn reclaimed(&self) -> bool {
        self.frames_free_after == self.frames_free_before && self.caps_live_after == 0
    }
}

/// Stage, verify, admit, load, run and destroy one candidate.
///
/// # Safety
/// EL1, single core, after `boot::early_kernel_enter` initialised the frame
/// allocator and after exception vectors, GIC and timer are set up.
pub unsafe fn run_boot_candidate(bytes: &[u8], kernel_root: usize) -> CandidateReport {
    let _ = (bytes, kernel_root);
    unimplemented_report()
}

fn unimplemented_report() -> CandidateReport {
    CandidateReport {
        decision: Decision::Rejected,
        failed_stage: Some(CandidateState::Received),
        error: Some(LoadError::Mapping),
        artifact_id: None,
        trust_tier: None,
        frames_reserved: 0,
        frames_free_before: 0,
        frames_free_after: 0,
        caps_installed: 0,
        caps_live_after: 0,
        byte_chain: false,
        wx_enforced: false,
        outcome: TaskOutcome {
            status: ExecutionStatus::NotRun,
            syscalls: 0,
            object_reads_ok: 0,
            denials: 0,
            elapsed_ticks: 0,
        },
        code_base: 0,
        code_end: 0,
    }
}

/// One stable report line per candidate. Formats (QEMU checks grep these):
///
/// `artifact: NAME admitted id=HEX16 tier=seed0b-test exec=EXEC bytes=identified=verified=admitted=mapped=executed wx=enforced caps=N revoked=yes reclaimed=yes frames=N`
/// `artifact: NAME rejected stage=STAGE reason=REASON reclaimed=yes`
///
/// EXEC is `exited:0x..`, `timeout`, `fault:code-write`, `fault:other`,
/// `bad-syscall:N`, `resource-overrun`, or `not-run`.
pub fn write_candidate_line(out: &mut impl core::fmt::Write, name: &str, r: &CandidateReport) {
    let yes_no = |b: bool| if b { "yes" } else { "no" };
    match r.decision {
        Decision::Rejected => {
            let stage = r.failed_stage.map_or("unknown", CandidateState::name);
            let _ = write!(out, "artifact: {name} rejected stage={stage} reason=");
            match r.error {
                Some(LoadError::Artifact(e)) => {
                    let _ = write!(out, "{e:?}");
                }
                Some(e) => {
                    let _ = write!(out, "{e:?}");
                }
                None => {
                    let _ = write!(out, "unknown");
                }
            }
            let _ = writeln!(out, " reclaimed={}", yes_no(r.reclaimed()));
        }
        Decision::Admitted => {
            let _ = write!(out, "artifact: {name} admitted id=");
            if let Some(id) = r.artifact_id {
                for byte in &id.as_bytes()[..8] {
                    let _ = write!(out, "{byte:02x}");
                }
            }
            let tier = match r.trust_tier {
                Some(TrustTier::Seed0bQualification) => "seed0b-test",
                Some(TrustTier::Production) => "production",
                None => "none",
            };
            let _ = write!(out, " tier={tier} exec=");
            match r.outcome.status {
                ExecutionStatus::NotRun => {
                    let _ = write!(out, "not-run");
                }
                ExecutionStatus::Exited(code) => {
                    let _ = write!(out, "exited:{code:#x}");
                }
                ExecutionStatus::Timeout => {
                    let _ = write!(out, "timeout");
                }
                ExecutionStatus::Fault { esr, far, .. } => {
                    // EC 0x24 data abort from EL0, ISS.WnR (bit 6) set.
                    let write_abort = (esr >> 26) & 0x3f == 0x24 && esr & (1 << 6) != 0;
                    if write_abort && far >= r.code_base && far < r.code_end {
                        let _ = write!(out, "fault:code-write");
                    } else {
                        let _ = write!(out, "fault:other");
                    }
                }
                ExecutionStatus::BadSyscall(n) => {
                    let _ = write!(out, "bad-syscall:{n}");
                }
                ExecutionStatus::ResourceOverrun => {
                    let _ = write!(out, "resource-overrun");
                }
            }
            let _ = writeln!(
                out,
                " bytes={} wx={} caps={} revoked={} reclaimed={} frames={}",
                if r.byte_chain {
                    "identified=verified=admitted=mapped=executed"
                } else {
                    "mismatch"
                },
                if r.wx_enforced {
                    "enforced"
                } else {
                    "violated"
                },
                r.caps_installed,
                yes_no(r.caps_live_after == 0),
                yes_no(r.reclaimed()),
                r.frames_reserved,
            );
        }
    }
}
