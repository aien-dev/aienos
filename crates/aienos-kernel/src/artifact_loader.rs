//! Binary Artifact v0 loader: the only path from authenticated artifact bytes
//! to a runnable EL0 task (ADR 0014 §5).
//!
//! The pipeline is fixed and fail-closed:
//!
//! ```text
//! stage bytes (contiguous NX kernel frames, never mapped into the task)
//!   -> parse + ArtifactId + Ed25519 against local anchors   (Verified)
//!   -> deterministic admission policy                       (Authorized)
//!   -> scheduler slot + every frame, reserved up front      (Reserved)
//!   -> private tables; exact code/data copy via the NX alias (Mapped)
//!   -> SHA-256 of bytes read back from the private pages    (Hashed)
//!   -> I-cache sync, code EL0 RX, EL1 alias read-only, audit (Sealed)
//!   -> policy grants installed in the task's M3 CapTable    (CapsInstalled)
//!   -> LoadedTask                                           (Admitted)
//! ```
//!
//! Any failure scrubs and releases every frame and scheduler slot taken so
//! far; nothing partially admitted survives. After the task ends for any
//! reason its code pages are hashed again (executed bytes), its capabilities
//! are revoked, and every page is scrubbed and returned.
//!
//! No translation regime active while the task lives maps a code frame
//! writable: its user mapping is EL0 read-only/executable, and the task's
//! private copy of the kernel identity map marks the same frames read-only
//! (EL1 alias). The kernel's own root keeps the RW+NX alias, which is used
//! only before sealing and after the task has left the CPU.
//!
//! Hardware access goes through [`LoaderPlatform`] so the whole pipeline,
//! including every rollback, runs under host tests.

use aienos_artifact::capability::{CapabilityRequest, MAX_CAPABILITIES, RESOURCE_KIND_OBJECT};
use aienos_artifact::error::ArtifactError;
use aienos_artifact::resource::{
    ResourceEnvelope, MAX_CODE_PAGES, MAX_CPU_TICKS, MAX_DATA_PAGES, MAX_ELAPSED_TICKS,
    MAX_STACK_PAGES, MAX_SYSCALLS,
};
use aienos_artifact::signature::{ArtifactVerifier, TrustTier};
use aienos_artifact::ArtifactId;
use aienos_crypto::sha256::{Digest, Sha256};

use crate::abi::Handle;
use crate::admission::{AdmissionLimits, AdmissionPolicy, AvailableResources, GrantedCapability};
use crate::caps::{CapTable, Rights};
use crate::mem::pagetable::{page_descriptor, MapFlags, MemoryAttribute};
use crate::mem::{FrameBatch, PhysAddr, MAX_BATCH_FRAMES};
use crate::scheduler::{Scheduler, TaskPriority};
use crate::task_runtime::{
    ExecutionStatus, TaskBudget, TaskContext, TaskOutcome, SEED_OBJECT_ID, TASK_CAPABILITIES,
};

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

// ---------------------------------------------------------------------------
// Platform contract
// ---------------------------------------------------------------------------

pub const PAGE: usize = 4096;
const PAGE_U64: u64 = PAGE as u64;
const ENTRIES: usize = 512;
/// Private user-window tables: L0 (copy of the kernel root), L1, L2, L3.
pub const TABLE_FRAMES: usize = 4;
/// Largest staged artifact: the admitted maximum payload fits in 130 pages.
pub const MAX_STAGING_FRAMES: usize = MAX_BATCH_FRAMES;
/// Loaded artifact tasks that may hold a scheduler slot at once.
pub const LOADED_TASK_SLOTS: usize = 4;
pub type LoaderScheduler = Scheduler<1, LOADED_TASK_SLOTS>;

const ADDRESS_MASK: u64 = 0x0000_ffff_ffff_f000;
const ATTR_MASK: u64 = 0xffff_0000_0000_0ffc;
const BLOCK_1G_MASK: u64 = 0x0000_ffff_c000_0000;
const BLOCK_2M_MASK: u64 = 0x0000_ffff_ffe0_0000;
const DESC_TYPE: u64 = 0b11;
const DESC_TABLE: u64 = 0b11;
const DESC_BLOCK: u64 = 0b01;
/// AP[2]: read-only at every EL that can access the page.
pub const AP_READ_ONLY: u64 = 1 << 7;
/// AP[1]: EL0 accessible.
pub const AP_EL0: u64 = 1 << 6;
pub const PXN: u64 = 1 << 53;
pub const UXN: u64 = 1 << 54;

pub const USER_CODE: MapFlags = MapFlags {
    attribute: MemoryAttribute::NormalWriteBack,
    writable: false,
    user: true,
    executable: true,
    shareable: true,
    global: false,
};
pub const USER_DATA: MapFlags = MapFlags {
    writable: true,
    executable: false,
    ..USER_CODE
};

/// Physical memory and frame ownership as the loader needs them. On AArch64
/// the kernel identity map makes a physical address directly addressable;
/// host tests supply an arena.
pub trait LoaderPlatform {
    fn kernel_root(&self) -> u64;
    fn free_frames(&self) -> usize;
    /// All-or-nothing reservation of `count` frames.
    fn reserve_batch(&mut self, count: usize) -> Option<FrameBatch>;
    fn release_batch(&mut self, batch: FrameBatch) -> bool;
    fn reserve_contiguous(&mut self, count: usize) -> Option<u64>;
    fn release_contiguous(&mut self, start: u64, count: usize) -> bool;
    fn bytes(&self, pa: u64, len: usize) -> &[u8];
    /// Only ever called on frames the loader currently owns.
    fn bytes_mut(&mut self, pa: u64, len: usize) -> &mut [u8];
    fn copy(&mut self, src: u64, dst: u64, len: usize);
    /// Make table writes visible to the translation walker.
    fn clean_dcache(&mut self, pa: u64, len: usize);
    /// Clean D-cache to PoU and invalidate I-cache for freshly written code.
    fn sync_icache(&mut self, pa: u64, len: usize);
}

/// Runs a sealed task. The hardware implementation enters EL0.
pub trait TaskExecutor<P: LoaderPlatform> {
    fn execute(&mut self, task: TaskContext<'_>, platform: &mut P) -> TaskOutcome;
}

fn read_entry<P: LoaderPlatform>(p: &P, table: u64, index: usize) -> u64 {
    let b = p.bytes(table + (index as u64) * 8, 8);
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

fn write_entry<P: LoaderPlatform>(p: &mut P, table: u64, index: usize, value: u64) {
    p.bytes_mut(table + (index as u64) * 8, 8)
        .copy_from_slice(&value.to_le_bytes());
}

const fn table_index(va: u64, level: usize) -> usize {
    ((va >> (39 - 9 * level)) & 511) as usize
}

// ---------------------------------------------------------------------------
// Task layout
// ---------------------------------------------------------------------------

/// The private 2 MiB EL0 window, one L3 table, page by page:
/// guard | code | guard | data | guard | stack | guard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskLayout {
    pub window_index: usize,
    pub base: u64,
    pub code_pages: usize,
    pub data_pages: usize,
    pub stack_pages: usize,
    pub code_len: usize,
    pub data_len: usize,
    pub data_memory_len: usize,
    pub entry_offset: u64,
}

impl TaskLayout {
    pub fn new(
        window_index: usize,
        resources: &ResourceEnvelope,
        code_len: usize,
        data_len: usize,
        data_memory_len: usize,
        entry_offset: u32,
    ) -> Result<Self, LoadError> {
        let layout = Self {
            window_index,
            base: (window_index as u64) << 39,
            code_pages: resources.code_pages as usize,
            data_pages: resources.data_pages as usize,
            stack_pages: resources.stack_pages as usize,
            code_len,
            data_len,
            data_memory_len,
            entry_offset: u64::from(entry_offset),
        };
        let fits = |len: usize, pages: usize| len <= pages.saturating_mul(PAGE);
        if !(1..256).contains(&window_index)
            || layout.code_pages == 0
            || layout.code_pages > MAX_CODE_PAGES as usize
            || layout.data_pages == 0
            || layout.data_pages > MAX_DATA_PAGES as usize
            || layout.stack_pages == 0
            || layout.stack_pages > MAX_STACK_PAGES as usize
            || code_len == 0
            || !fits(code_len, layout.code_pages)
            || data_len > data_memory_len
            || !fits(data_memory_len, layout.data_pages)
            || !layout.entry_offset.is_multiple_of(4)
            || layout.entry_offset + 4 > code_len as u64
            || layout.window_pages() > ENTRIES
        {
            return Err(LoadError::Artifact(ArtifactError::ResourceLimit));
        }
        Ok(layout)
    }

    pub const fn content_frames(&self) -> usize {
        self.code_pages + self.data_pages + self.stack_pages
    }
    pub const fn total_frames(&self) -> usize {
        self.content_frames() + TABLE_FRAMES
    }
    const fn code_first(&self) -> usize {
        1
    }
    const fn data_first(&self) -> usize {
        self.code_first() + self.code_pages + 1
    }
    const fn stack_first(&self) -> usize {
        self.data_first() + self.data_pages + 1
    }
    const fn window_pages(&self) -> usize {
        self.stack_first() + self.stack_pages + 1
    }
    pub const fn code_base(&self) -> u64 {
        self.base + (self.code_first() * PAGE) as u64
    }
    pub const fn code_end(&self) -> u64 {
        self.code_base() + (self.code_pages * PAGE) as u64
    }
    pub const fn data_base(&self) -> u64 {
        self.base + (self.data_first() * PAGE) as u64
    }
    pub const fn stack_base(&self) -> u64 {
        self.base + (self.stack_first() * PAGE) as u64
    }
    pub const fn stack_top(&self) -> u64 {
        self.stack_base() + (self.stack_pages * PAGE) as u64
    }
    pub const fn entry_pc(&self) -> u64 {
        self.code_base() + self.entry_offset
    }

    /// Expected L3 descriptor at window page `index`, given the task frames.
    fn expected_leaf(&self, index: usize, frames: &[PhysAddr]) -> u64 {
        let (d, s) = (self.data_first(), self.stack_first());
        if (1..1 + self.code_pages).contains(&index) {
            page_descriptor(frames[index - 1], USER_CODE)
        } else if (d..d + self.data_pages).contains(&index) {
            page_descriptor(frames[self.code_pages + index - d], USER_DATA)
        } else if (s..s + self.stack_pages).contains(&index) {
            page_descriptor(
                frames[self.code_pages + self.data_pages + index - s],
                USER_DATA,
            )
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// Loaded task
// ---------------------------------------------------------------------------

/// Frames owned by one task: content frames then its four window tables, plus
/// the private shadow of the kernel identity map that makes code read-only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskAddressSpace {
    pub root: u64,
    pub layout: TaskLayout,
    frames: FrameBatch,
    shadow: FrameBatch,
    shadow_used: usize,
}

impl TaskAddressSpace {
    pub fn frames(&self) -> &[PhysAddr] {
        self.frames.as_slice()
    }
    pub fn code_frames(&self) -> &[PhysAddr] {
        &self.frames.as_slice()[..self.layout.code_pages]
    }
    pub fn shadow_frames(&self) -> &[PhysAddr] {
        &self.shadow.as_slice()[..self.shadow_used]
    }
    pub fn frames_reserved(&self) -> usize {
        self.frames.len() + self.shadow.len()
    }
}

/// A sealed, admitted task: the only thing the scheduler/runtime receives.
pub struct LoadedTask {
    pub artifact_id: ArtifactId,
    pub trust_tier: TrustTier,
    pub payload_digest: Digest,
    /// SHA-256 of the exact code bytes read back from the private pages.
    pub code_digest: Digest,
    pub address_space: TaskAddressSpace,
    pub entry_pc: u64,
    pub stack_pointer: u64,
    pub handle_array: u64,
    pub capabilities: CapTable<TASK_CAPABILITIES>,
    pub handles: [Option<Handle>; TASK_CAPABILITIES],
    pub grants: [Option<GrantedCapability>; MAX_CAPABILITIES],
    pub grant_count: usize,
    pub resource_budget: ResourceEnvelope,
    pub scheduler_id: u32,
    pub state: CandidateState,
}

impl LoadedTask {
    pub fn args(&self) -> [u64; 4] {
        [
            self.handle_array,
            self.grant_count as u64,
            self.address_space.layout.data_base(),
            self.address_space.layout.data_memory_len as u64,
        ]
    }

    pub fn budget(&self) -> TaskBudget {
        TaskBudget {
            cpu_ticks: self.resource_budget.cpu_ticks,
            elapsed_ticks: self.resource_budget.elapsed_ticks,
            syscalls: self.resource_budget.syscall_count,
        }
    }
}

/// What teardown observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Teardown {
    pub executed_bytes_match: bool,
    pub caps_live_after: usize,
    pub released: bool,
}

// ---------------------------------------------------------------------------
// Policy and resources
// ---------------------------------------------------------------------------

/// The local SEED-0B admission policy: READ on the SEED object only, no IPC,
/// signers limited to `signers` (empty in production builds).
pub fn boot_policy(signers: &[Digest]) -> Result<AdmissionPolicy, ArtifactError> {
    let mut policy = AdmissionPolicy::new(AdmissionLimits {
        code_pages: MAX_CODE_PAGES,
        data_pages: MAX_DATA_PAGES,
        stack_pages: MAX_STACK_PAGES,
        max_capabilities: MAX_CAPABILITIES as u32,
        ipc_messages: 0,
        ipc_bytes: 0,
        cpu_ticks: MAX_CPU_TICKS,
        elapsed_ticks: MAX_ELAPSED_TICKS,
        syscall_count: MAX_SYSCALLS,
    })?;
    policy.add_resource_rule(CapabilityRequest {
        resource_kind: RESOURCE_KIND_OBJECT,
        resource_id: SEED_OBJECT_ID,
        rights: u32::from(Rights::READ.bits()),
        bounds_kind: 1,
        max_operations: 16,
        max_bytes: 32,
        byte_offset: 0,
        byte_length: 32,
    })?;
    for signer in signers {
        policy.allow_signer(*signer)?;
    }
    Ok(policy)
}

/// Snapshot of what the kernel could reserve right now.
pub fn available_resources(free_frames: usize, free_task_slots: usize) -> AvailableResources {
    let frames = if free_task_slots == 0 {
        0
    } else {
        u32::try_from(free_frames.saturating_sub(TABLE_FRAMES)).unwrap_or(u32::MAX)
    };
    AvailableResources {
        code_pages: frames,
        data_pages: frames,
        stack_pages: frames,
        capability_slots: TASK_CAPABILITIES as u32,
        ipc_messages: 0,
        ipc_bytes: 0,
        cpu_ticks: MAX_CPU_TICKS,
        elapsed_ticks: MAX_ELAPSED_TICKS,
        syscall_count: MAX_SYSCALLS,
    }
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

type Failure = (CandidateState, LoadError);

/// Everything reserved so far, released as a unit on failure.
struct Reservation {
    scheduler_id: Option<u32>,
    frames: Option<FrameBatch>,
    shadow: Option<FrameBatch>,
}

impl Reservation {
    fn release<P: LoaderPlatform>(
        &mut self,
        platform: &mut P,
        scheduler: &mut LoaderScheduler,
    ) -> bool {
        let mut ok = true;
        for batch in [self.frames.take(), self.shadow.take()]
            .into_iter()
            .flatten()
        {
            for frame in batch.as_slice() {
                platform.bytes_mut(frame.0 as u64, PAGE).fill(0);
            }
            ok &= platform.release_batch(batch);
        }
        if let Some(id) = self.scheduler_id.take() {
            ok &= scheduler.remove(id).is_ok();
        }
        ok
    }
}

/// Verify, admit, reserve, map, hash, seal and install capabilities for the
/// artifact already staged at `staged_pa..staged_pa + staged_len`.
pub fn load<P, V>(
    platform: &mut P,
    staged_pa: u64,
    staged_len: usize,
    verifier: &V,
    policy: &AdmissionPolicy,
    scheduler: &mut LoaderScheduler,
    task_id: u32,
) -> Result<LoadedTask, Failure>
where
    P: LoaderPlatform,
    V: ArtifactVerifier,
{
    // ---- Verified + Authorized: pure decisions over the staged bytes.
    let free_slots = (0..LOADED_TASK_SLOTS as u32)
        .filter(|_| true)
        .count()
        .saturating_sub(occupied_slots(scheduler));
    let (admission, code_src, data_src, code_len, data_len, data_memory_len) = {
        let bytes = platform.bytes(staged_pa, staged_len);
        let verified = verifier
            .verify(bytes)
            .map_err(|e| (CandidateState::Verified, e.into()))?;
        let available = available_resources(platform.free_frames(), free_slots);
        let admission = policy
            .evaluate(&verified, available)
            .map_err(|e| (CandidateState::Authorized, e.into()))?;
        let identified = verified.identified();
        if admission.artifact_id != identified.artifact_id
            || admission.payload_digest != identified.payload_digest
        {
            return Err((CandidateState::Authorized, LoadError::MappedDigestMismatch));
        }
        let artifact = &identified.artifact;
        let offset_of = |slice: &[u8]| slice.as_ptr() as u64 - bytes.as_ptr() as u64;
        (
            admission,
            staged_pa + offset_of(artifact.code_bytes()),
            staged_pa + offset_of(artifact.data_bytes()),
            artifact.code_bytes().len(),
            artifact.data_bytes().len(),
            artifact.sections[1].memory_length as usize,
        )
    };
    if admission.capability_count() > TASK_CAPABILITIES {
        return Err((
            CandidateState::Authorized,
            LoadError::Artifact(ArtifactError::ResourceLimit),
        ));
    }
    let kernel_root = platform.kernel_root();
    let window_index = (1..256)
        .find(|&index| read_entry(platform, kernel_root, index) == 0)
        .ok_or((CandidateState::Reserved, LoadError::Mapping))?;
    let layout = TaskLayout::new(
        window_index,
        &admission.resources,
        code_len,
        data_len,
        data_memory_len,
        admission.entry_offset,
    )
    .map_err(|e| (CandidateState::Authorized, e))?;

    // ---- Reserved: scheduler slot, content+table frames, shadow frames.
    let mut reservation = Reservation {
        scheduler_id: None,
        frames: None,
        shadow: None,
    };
    macro_rules! fail {
        ($stage:expr, $error:expr) => {{
            reservation.release(platform, scheduler);
            return Err(($stage, $error));
        }};
    }
    if scheduler.enqueue(task_id, TaskPriority::Normal).is_err() {
        fail!(CandidateState::Reserved, LoadError::SchedulerFull);
    }
    reservation.scheduler_id = Some(task_id);
    if layout.total_frames() > MAX_BATCH_FRAMES {
        fail!(CandidateState::Reserved, LoadError::NoFrames);
    }
    let Some(frames) = platform.reserve_batch(layout.total_frames()) else {
        fail!(CandidateState::Reserved, LoadError::NoFrames);
    };
    reservation.frames = Some(frames);
    let all = frames.as_slice();
    let code_frames = &all[..layout.code_pages];
    let shadow_need = match shadow_frames_needed(platform, kernel_root, code_frames) {
        Ok(n) => n,
        Err(e) => fail!(CandidateState::Reserved, e),
    };
    if shadow_need > MAX_BATCH_FRAMES {
        fail!(CandidateState::Reserved, LoadError::NoFrames);
    }
    let Some(shadow) = platform.reserve_batch(shadow_need) else {
        fail!(CandidateState::Reserved, LoadError::NoFrames);
    };
    reservation.shadow = Some(shadow);

    // ---- Mapped: private tables, exact bytes copied through the NX alias.
    let content = layout.content_frames();
    let (l0, l1, l2, l3) = (
        all[content].0 as u64,
        all[content + 1].0 as u64,
        all[content + 2].0 as u64,
        all[content + 3].0 as u64,
    );
    for frame in all.iter().chain(shadow.as_slice()) {
        platform.bytes_mut(frame.0 as u64, PAGE).fill(0);
    }
    platform.copy(kernel_root, l0, PAGE);
    write_entry(platform, l0, window_index, (l1 & ADDRESS_MASK) | DESC_TABLE);
    write_entry(platform, l1, 0, (l2 & ADDRESS_MASK) | DESC_TABLE);
    write_entry(platform, l2, 0, (l3 & ADDRESS_MASK) | DESC_TABLE);
    for index in layout.data_first()..layout.window_pages() {
        let leaf = layout.expected_leaf(index, all);
        if leaf != 0 {
            write_entry(platform, l3, index, leaf);
        }
    }
    copy_section(platform, code_src, code_len, code_frames);
    copy_section(
        platform,
        data_src,
        data_len,
        &all[layout.code_pages..layout.code_pages + layout.data_pages],
    );

    // ---- Hashed: identified/verified/admitted == mapped.
    let (payload, code_digest) = hash_loaded(platform, &layout, all);
    if payload != admission.payload_digest {
        fail!(CandidateState::Hashed, LoadError::MappedDigestMismatch);
    }

    // ---- Sealed: code becomes EL0 RX; its EL1 alias read-only in this root.
    for frame in code_frames {
        platform.sync_icache(frame.0 as u64, PAGE);
    }
    let shadow_used = match shadow_code_alias(platform, l0, code_frames, shadow.as_slice()) {
        Ok(n) => n,
        Err(e) => fail!(CandidateState::Sealed, e),
    };
    for index in 1..1 + layout.code_pages {
        write_entry(platform, l3, index, layout.expected_leaf(index, all));
    }
    for table in all[content..]
        .iter()
        .chain(&shadow.as_slice()[..shadow_used])
    {
        platform.clean_dcache(table.0 as u64, PAGE);
    }
    let address_space = TaskAddressSpace {
        root: l0,
        layout,
        frames,
        shadow,
        shadow_used,
    };
    if !audit_wx(platform, &address_space) {
        fail!(CandidateState::Sealed, LoadError::WxAudit);
    }

    // ---- CapsInstalled: exactly the policy grants, in grant order.
    let mut capabilities = CapTable::new(0x5441_0000 | (task_id & 0xffff));
    let mut handles = [None; TASK_CAPABILITIES];
    let mut grants = [None; MAX_CAPABILITIES];
    let grant_count = admission.capability_count();
    for (index, grant) in admission.capabilities().iter().enumerate() {
        let Some(grant) = grant else {
            fail!(CandidateState::CapsInstalled, LoadError::CapabilityInstall);
        };
        match capabilities.insert(index as u32, grant.rights) {
            Ok(handle) => handles[index] = Some(handle),
            Err(_) => fail!(CandidateState::CapsInstalled, LoadError::CapabilityInstall),
        }
        grants[index] = Some(*grant);
    }
    let handle_array = layout.stack_top() - (grant_count as u64) * 8;
    let top_frame = all[content - 1].0 as u64;
    for (index, handle) in handles[..grant_count].iter().enumerate() {
        let va = handle_array + (index as u64) * 8;
        let offset = va - (layout.stack_top() - PAGE_U64);
        let raw = handle.map_or(0, Handle::to_raw);
        platform
            .bytes_mut(top_frame + offset, 8)
            .copy_from_slice(&raw.to_le_bytes());
    }
    platform.clean_dcache(top_frame, PAGE);

    Ok(LoadedTask {
        artifact_id: admission.artifact_id,
        trust_tier: admission.trust_tier,
        payload_digest: payload,
        code_digest,
        address_space,
        entry_pc: layout.entry_pc(),
        stack_pointer: handle_array & !15,
        handle_array,
        capabilities,
        handles,
        grants,
        grant_count,
        resource_budget: admission.resources,
        scheduler_id: task_id,
        state: CandidateState::Admitted,
    })
}

fn occupied_slots(scheduler: &LoaderScheduler) -> usize {
    scheduler.queue_len(0).unwrap_or(LOADED_TASK_SLOTS)
}

fn copy_section<P: LoaderPlatform>(p: &mut P, src: u64, len: usize, frames: &[PhysAddr]) {
    for (index, frame) in frames.iter().enumerate() {
        let start = index * PAGE;
        if start >= len {
            break;
        }
        let n = (len - start).min(PAGE);
        p.copy(src + start as u64, frame.0 as u64, n);
    }
}

/// SHA-256(code || data) and SHA-256(code), read back from private pages.
fn hash_loaded<P: LoaderPlatform>(
    p: &P,
    layout: &TaskLayout,
    frames: &[PhysAddr],
) -> (Digest, Digest) {
    let mut payload = Sha256::new();
    let mut code = Sha256::new();
    for (index, frame) in frames[..layout.code_pages].iter().enumerate() {
        let start = index * PAGE;
        if start >= layout.code_len {
            break;
        }
        let bytes = p.bytes(frame.0 as u64, (layout.code_len - start).min(PAGE));
        payload.update(bytes);
        code.update(bytes);
    }
    let data = &frames[layout.code_pages..layout.code_pages + layout.data_pages];
    for (index, frame) in data.iter().enumerate() {
        let start = index * PAGE;
        if start >= layout.data_len {
            break;
        }
        payload.update(p.bytes(frame.0 as u64, (layout.data_len - start).min(PAGE)));
    }
    (payload.finalize(), code.finalize())
}

/// SHA-256 of the code bytes currently in a task's code frames.
pub fn code_digest<P: LoaderPlatform>(p: &P, space: &TaskAddressSpace) -> Digest {
    let mut code = Sha256::new();
    for (index, frame) in space.code_frames().iter().enumerate() {
        let start = index * PAGE;
        if start >= space.layout.code_len {
            break;
        }
        code.update(p.bytes(frame.0 as u64, (space.layout.code_len - start).min(PAGE)));
    }
    code.finalize()
}

// ---------------------------------------------------------------------------
// Read-only shadow of the kernel identity map for code frames
// ---------------------------------------------------------------------------

/// Distinct (L0), (L0,L1), (L0,L1,L2) prefixes covering `frames`: one private
/// L1, L2 and L3 table per prefix. Fails if the identity map does not reach
/// a frame through L0 table → L1 table/1 GiB block → L2 table/2 MiB block → L3
/// page.
fn shadow_frames_needed<P: LoaderPlatform>(
    p: &P,
    kernel_root: u64,
    frames: &[PhysAddr],
) -> Result<usize, LoadError> {
    let mut prefixes: [[u64; 3]; MAX_CODE_PAGES as usize] =
        [[u64::MAX; 3]; MAX_CODE_PAGES as usize];
    let mut count = 0usize;
    for (n, frame) in frames.iter().enumerate() {
        let pa = frame.0 as u64;
        kernel_translation(p, kernel_root, pa).ok_or(LoadError::Mapping)?;
        let keys = [pa >> 39, pa >> 30, pa >> 21];
        for level in 0..3 {
            if !prefixes[..n].iter().any(|k| k[level] == keys[level]) {
                count += 1;
            }
        }
        prefixes[n] = keys;
    }
    Ok(count)
}

/// Walk `root` for `va`; returns (leaf descriptor, level) of a valid leaf.
fn kernel_translation<P: LoaderPlatform>(p: &P, root: u64, va: u64) -> Option<(u64, usize)> {
    let mut table = root;
    for level in 0..4 {
        let entry = read_entry(p, table, table_index(va, level));
        match (level, entry & DESC_TYPE) {
            (3, DESC_TABLE) => return Some((entry, 3)),
            (1 | 2, DESC_BLOCK) => return Some((entry, level)),
            (0..=2, DESC_TABLE) => table = entry & ADDRESS_MASK,
            _ => return None,
        }
    }
    None
}

/// Privatise the path to every code frame in the task root and mark its
/// identity-map leaf read-only. Returns shadow frames used.
fn shadow_code_alias<P: LoaderPlatform>(
    p: &mut P,
    task_root: u64,
    frames: &[PhysAddr],
    shadow: &[PhysAddr],
) -> Result<usize, LoadError> {
    let mut used = 0usize;
    for frame in frames {
        let pa = frame.0 as u64;
        let mut table = task_root;
        for level in 0..3 {
            let index = table_index(pa, level);
            let entry = read_entry(p, table, index);
            let child = entry & ADDRESS_MASK;
            let private = shadow[..used].iter().any(|f| f.0 as u64 == child);
            let next = if entry & DESC_TYPE == DESC_TABLE && private {
                child
            } else {
                let fresh = shadow.get(used).ok_or(LoadError::Mapping)?.0 as u64;
                used += 1;
                match (level, entry & DESC_TYPE) {
                    (_, DESC_TABLE) => p.copy(child, fresh, PAGE),
                    (1, DESC_BLOCK) => {
                        let attrs = entry & ATTR_MASK;
                        let base = entry & BLOCK_1G_MASK;
                        for k in 0..ENTRIES as u64 {
                            write_entry(
                                p,
                                fresh,
                                k as usize,
                                (base + (k << 21)) | attrs | DESC_BLOCK,
                            );
                        }
                    }
                    (2, DESC_BLOCK) => {
                        let attrs = entry & ATTR_MASK;
                        let base = entry & BLOCK_2M_MASK;
                        for k in 0..ENTRIES as u64 {
                            write_entry(
                                p,
                                fresh,
                                k as usize,
                                (base + (k << 12)) | attrs | DESC_TABLE,
                            );
                        }
                    }
                    _ => return Err(LoadError::Mapping),
                }
                write_entry(
                    p,
                    table,
                    index,
                    (entry & !ADDRESS_MASK & !DESC_TYPE) | fresh | DESC_TABLE,
                );
                fresh
            };
            table = next;
        }
        let index = table_index(pa, 3);
        let leaf = read_entry(p, table, index);
        if leaf & DESC_TYPE != DESC_TABLE || leaf & ADDRESS_MASK != pa {
            return Err(LoadError::Mapping);
        }
        write_entry(p, table, index, leaf | AP_READ_ONLY | PXN | UXN);
    }
    Ok(used)
}

/// Fail-closed W^X audit of the sealed task root:
/// - the user window holds exactly the expected leaves (code EL0 RO+X, data
///   and stack EL0 RW+NX, guards unmapped) and nothing else;
/// - every code frame's identity alias is read-only and never executable;
/// - no user-window leaf is both writable and executable.
pub fn audit_wx<P: LoaderPlatform>(p: &P, space: &TaskAddressSpace) -> bool {
    let layout = &space.layout;
    let root = space.root;
    let frames = space.frames();
    let l0e = read_entry(p, root, layout.window_index);
    let l1 = l0e & ADDRESS_MASK;
    let content = layout.content_frames();
    if l0e != (frames[content + 1].0 as u64 & ADDRESS_MASK) | DESC_TABLE {
        return false;
    }
    for index in 1..ENTRIES {
        if read_entry(p, l1, index) != 0 {
            return false;
        }
    }
    let l2 = read_entry(p, l1, 0) & ADDRESS_MASK;
    if l2 != frames[content + 2].0 as u64 {
        return false;
    }
    for index in 1..ENTRIES {
        if read_entry(p, l2, index) != 0 {
            return false;
        }
    }
    let l3 = read_entry(p, l2, 0) & ADDRESS_MASK;
    if l3 != frames[content + 3].0 as u64 {
        return false;
    }
    for index in 0..ENTRIES {
        let leaf = read_entry(p, l3, index);
        if leaf != layout.expected_leaf(index, frames) {
            return false;
        }
        let writable = leaf & AP_READ_ONLY == 0;
        let executable = leaf & UXN == 0 || leaf & PXN == 0;
        if leaf != 0 && writable && executable {
            return false;
        }
    }
    for frame in space.code_frames() {
        let pa = frame.0 as u64;
        match kernel_translation(p, root, pa) {
            Some((leaf, 3)) => {
                if leaf & ADDRESS_MASK != pa
                    || leaf & AP_READ_ONLY == 0
                    || leaf & PXN == 0
                    || leaf & UXN == 0
                {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Run and teardown
// ---------------------------------------------------------------------------

/// Hand the task to the scheduler and run it when the scheduler selects it.
pub fn run_task<P, E>(
    task: &mut LoadedTask,
    platform: &mut P,
    scheduler: &mut LoaderScheduler,
    executor: &mut E,
) -> TaskOutcome
where
    P: LoaderPlatform,
    E: TaskExecutor<P>,
{
    let not_run = TaskOutcome {
        status: ExecutionStatus::NotRun,
        syscalls: 0,
        object_reads_ok: 0,
        denials: 0,
        elapsed_ticks: 0,
    };
    if scheduler.tick(0) != Ok(Some(task.scheduler_id)) {
        return not_run;
    }
    task.state = CandidateState::Running;
    let args = task.args();
    let budget = task.budget();
    let context = TaskContext {
        root: task.address_space.root,
        entry_pc: task.entry_pc,
        stack_pointer: task.stack_pointer,
        args,
        capabilities: &mut task.capabilities,
        grants: &task.grants[..task.grant_count],
        budget,
    };
    executor.execute(context, platform)
}

/// Re-hash executed code, revoke every capability, scrub and release every
/// frame, and free the scheduler slot. Always completes.
pub fn destroy<P: LoaderPlatform>(
    mut task: LoadedTask,
    platform: &mut P,
    scheduler: &mut LoaderScheduler,
) -> Teardown {
    let executed_bytes_match = code_digest(platform, &task.address_space) == task.code_digest;
    for handle in task.handles.iter_mut() {
        if let Some(h) = handle.take() {
            let _ = task.capabilities.remove(h);
        }
    }
    let caps_live_after = task.capabilities.live_count();
    let mut reservation = Reservation {
        scheduler_id: Some(task.scheduler_id),
        frames: Some(task.address_space.frames),
        shadow: Some(task.address_space.shadow),
    };
    let released = reservation.release(platform, scheduler);
    Teardown {
        executed_bytes_match,
        caps_live_after,
        released,
    }
}

/// Stage, verify, admit, load, run and destroy one candidate on `platform`.
pub fn process_candidate<P, V, E>(
    bytes: &[u8],
    platform: &mut P,
    verifier: &V,
    policy: &AdmissionPolicy,
    scheduler: &mut LoaderScheduler,
    executor: &mut E,
    task_id: u32,
) -> CandidateReport
where
    P: LoaderPlatform,
    V: ArtifactVerifier,
    E: TaskExecutor<P>,
{
    let free_before = platform.free_frames();
    let mut report = empty_report(free_before);
    let reject = |mut report: CandidateReport, stage, error, free_after| {
        report.decision = Decision::Rejected;
        report.failed_stage = Some(stage);
        report.error = Some(error);
        report.frames_free_after = free_after;
        report
    };
    let pages = bytes.len().div_ceil(PAGE);
    if bytes.is_empty() || pages > MAX_STAGING_FRAMES {
        return reject(
            report,
            CandidateState::Received,
            LoadError::StagingTooLarge,
            platform.free_frames(),
        );
    }
    let Some(staged) = platform.reserve_contiguous(pages) else {
        return reject(
            report,
            CandidateState::Staged,
            LoadError::NoFrames,
            platform.free_frames(),
        );
    };
    platform.bytes_mut(staged, pages * PAGE).fill(0);
    platform
        .bytes_mut(staged, bytes.len())
        .copy_from_slice(bytes);
    let loaded = load(
        platform,
        staged,
        bytes.len(),
        verifier,
        policy,
        scheduler,
        task_id,
    );
    // The task owns its own copy; staging is scrubbed and returned now.
    platform.bytes_mut(staged, pages * PAGE).fill(0);
    let staging_released = platform.release_contiguous(staged, pages);
    let mut task = match loaded {
        Ok(task) => task,
        Err((stage, error)) => {
            let error = if staging_released {
                error
            } else {
                LoadError::Reclaim
            };
            return reject(report, stage, error, platform.free_frames());
        }
    };
    report.artifact_id = Some(task.artifact_id);
    report.trust_tier = Some(task.trust_tier);
    report.frames_reserved = task.address_space.frames_reserved();
    report.caps_installed = task.grant_count;
    report.code_base = task.address_space.layout.code_base();
    report.code_end = task.address_space.layout.code_end();
    report.wx_enforced = true;
    report.outcome = run_task(&mut task, platform, scheduler, executor);
    let teardown = destroy(task, platform, scheduler);
    report.decision = Decision::Admitted;
    report.byte_chain = teardown.executed_bytes_match;
    report.caps_live_after = teardown.caps_live_after;
    report.frames_free_after = platform.free_frames();
    if !teardown.executed_bytes_match {
        report.error = Some(LoadError::ExecutedDigestMismatch);
    } else if !teardown.released || !staging_released {
        report.error = Some(LoadError::Reclaim);
    }
    report
}

fn empty_report(free_before: usize) -> CandidateReport {
    CandidateReport {
        decision: Decision::Rejected,
        failed_stage: None,
        error: None,
        artifact_id: None,
        trust_tier: None,
        frames_reserved: 0,
        frames_free_before: free_before,
        frames_free_after: free_before,
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

// ---------------------------------------------------------------------------
// Boot platform (early allocator + identity map)
// ---------------------------------------------------------------------------

/// The early-boot platform: frames from `boot`'s allocator, memory through
/// the kernel identity map.
pub struct EarlyPlatform {
    kernel_root: u64,
}

impl LoaderPlatform for EarlyPlatform {
    fn kernel_root(&self) -> u64 {
        self.kernel_root
    }
    fn free_frames(&self) -> usize {
        crate::boot::early_free_frames()
    }
    fn reserve_batch(&mut self, count: usize) -> Option<FrameBatch> {
        crate::boot::reserve_early_frames(count)
    }
    fn release_batch(&mut self, batch: FrameBatch) -> bool {
        crate::boot::release_early_frames(batch)
    }
    fn reserve_contiguous(&mut self, count: usize) -> Option<u64> {
        crate::boot::reserve_early_contiguous(count).map(|pa| pa.0 as u64)
    }
    fn release_contiguous(&mut self, start: u64, count: usize) -> bool {
        crate::boot::release_early_contiguous(PhysAddr(start as usize), count)
    }
    fn bytes(&self, pa: u64, len: usize) -> &[u8] {
        // SAFETY: the kernel identity map covers RAM and page-table pools.
        unsafe { core::slice::from_raw_parts(pa as usize as *const u8, len) }
    }
    fn bytes_mut(&mut self, pa: u64, len: usize) -> &mut [u8] {
        // SAFETY: the loader only writes frames it reserved.
        unsafe { core::slice::from_raw_parts_mut(pa as usize as *mut u8, len) }
    }
    fn copy(&mut self, src: u64, dst: u64, len: usize) {
        // SAFETY: distinct frames owned by or staged for the loader.
        unsafe {
            core::ptr::copy_nonoverlapping(src as usize as *const u8, dst as usize as *mut u8, len)
        }
    }
    fn clean_dcache(&mut self, pa: u64, len: usize) {
        cache_maintenance(pa as usize, len, false);
    }
    fn sync_icache(&mut self, pa: u64, len: usize) {
        cache_maintenance(pa as usize, len, true);
    }
}

#[cfg(target_arch = "aarch64")]
fn cache_maintenance(address: usize, length: usize, instructions: bool) {
    let ctr: u64;
    // SAFETY: CTR_EL0 read and cache maintenance by VA on owned memory.
    unsafe {
        core::arch::asm!("mrs {0}, ctr_el0", out(reg) ctr, options(nomem, nostack));
        let dline = 4usize << ((ctr >> 16) & 0xf);
        let iline = 4usize << (ctr & 0xf);
        for at in (address & !(dline - 1)..address + length).step_by(dline) {
            core::arch::asm!("dc cvau, {0}", in(reg) at, options(nostack));
        }
        core::arch::asm!("dsb ish", options(nostack));
        if instructions {
            for at in (address & !(iline - 1)..address + length).step_by(iline) {
                core::arch::asm!("ic ivau, {0}", in(reg) at, options(nostack));
            }
            core::arch::asm!("dsb ish", "isb", options(nostack));
        }
    }
}

#[cfg(not(target_arch = "aarch64"))]
fn cache_maintenance(_address: usize, _length: usize, _instructions: bool) {}

/// Enters EL0 through [`crate::task_runtime::run`].
pub struct El0Executor {
    kernel_root: usize,
}

impl TaskExecutor<EarlyPlatform> for El0Executor {
    fn execute(&mut self, task: TaskContext<'_>, _platform: &mut EarlyPlatform) -> TaskOutcome {
        // SAFETY: caller of `run_boot_candidate` guarantees the EL1 context.
        unsafe { crate::task_runtime::run(task, self.kernel_root) }
    }
}

static BOOT_SCHEDULER: crate::sync::spinlock::SpinLock<LoaderScheduler> =
    crate::sync::spinlock::SpinLock::new(Scheduler::new([0]));
static NEXT_TASK_ID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);

/// Stage, verify, admit, load, run and destroy one candidate.
///
/// # Safety
/// EL1, single core, after `boot::early_kernel_enter` initialised the frame
/// allocator and after exception vectors, GIC and timer are set up.
pub unsafe fn run_boot_candidate(bytes: &[u8], kernel_root: usize) -> CandidateReport {
    #[cfg(feature = "seed0b-test-anchor")]
    let (anchors, signers) = {
        use aienos_artifact::signature::seed0b_test_anchor::{Seed0bTestAnchorSet, PUBLIC_KEY};
        (
            Seed0bTestAnchorSet,
            [aienos_artifact::signature::signer_fingerprint(&PUBLIC_KEY)],
        )
    };
    #[cfg(not(feature = "seed0b-test-anchor"))]
    let (anchors, signers): (aienos_artifact::ProductionTrustAnchorSet, [Digest; 0]) =
        (aienos_artifact::ProductionTrustAnchorSet::default(), []);
    let verifier = aienos_artifact::ConfiguredArtifactVerifier::new(
        &anchors,
        aienos_artifact::Ed25519Verifier,
    );
    let mut platform = EarlyPlatform {
        kernel_root: kernel_root as u64,
    };
    let Ok(policy) = boot_policy(&signers) else {
        let mut report = empty_report(platform.free_frames());
        report.failed_stage = Some(CandidateState::Authorized);
        report.error = Some(LoadError::Artifact(ArtifactError::ResourceLimit));
        return report;
    };
    let mut executor = El0Executor { kernel_root };
    let task_id = NEXT_TASK_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let mut scheduler = BOOT_SCHEDULER.lock();
    process_candidate(
        bytes,
        &mut platform,
        &verifier,
        &policy,
        &mut scheduler,
        &mut executor,
        task_id,
    )
}

/// One stable report line per candidate. Formats (QEMU checks grep these):
///
/// `artifact: NAME admitted id=HEX16 tier=seed0b-test exec=EXEC bytes=identified=verified=admitted=mapped=executed wx=enforced caps=N revoked=yes reclaimed=yes frames=N syscalls=N reads=N denials=N`
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
                " bytes={} wx={} caps={} revoked={} reclaimed={} frames={} syscalls={} reads={} denials={}",
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
                r.outcome.syscalls,
                r.outcome.object_reads_ok,
                r.outcome.denials,
            );
        }
    }
}

#[cfg(test)]
#[path = "artifact_loader_tests.rs"]
mod tests;
