//! Host tests for the Binary Artifact v0 loader over a mock physical memory.
//!
//! The mock kernel identity map covers the arena at `ARENA_BASE` in one of
//! three shapes (1 GiB block, 2 MiB blocks, 4 KiB pages) so the read-only
//! shadow of code frames is exercised at every level.

use super::*;

use std::collections::BTreeSet;
use std::string::String;
use std::vec;
use std::vec::Vec;

use aienos_artifact::capability::{RESOURCE_KIND_CHANNEL, RIGHT_READ, RIGHT_WRITE};
use aienos_artifact::signature::{
    artifact_signature_message, signer_fingerprint, ConfiguredArtifactVerifier, Ed25519Verifier,
    TrustAnchorSet, TrustedSigner,
};
use aienos_artifact::verify::parse_and_identify;
use ed25519_dalek::{Signer, SigningKey};

use crate::caps::CapError;
use crate::mem::BitmapFrameAllocator;

// ---------------------------------------------------------------------------
// Mock platform
// ---------------------------------------------------------------------------

const ARENA_BASE: u64 = 0x4000_0000;
const ARENA_FRAMES: usize = 1100;
/// Frames 0..KERNEL_RESERVED hold the mock kernel tables; the rest is managed.
const KERNEL_RESERVED: usize = 8;
const MANAGED: usize = ARENA_FRAMES - KERNEL_RESERVED;
const WORDS: usize = MANAGED.div_ceil(64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KernelMap {
    Block1G,
    Blocks2M,
    Pages4K,
}

struct MockPlatform {
    arena: Vec<u8>,
    allocator: BitmapFrameAllocator<WORDS>,
    kernel_frames: usize,
    handed_out: BTreeSet<u64>,
    batch_calls: usize,
    fail_batch_nth: Option<usize>,
    fail_contiguous: bool,
    copy_calls: usize,
    corrupt_after_copy: Option<usize>,
    release_calls: usize,
}

const KERNEL_ATTRS: u64 = {
    // Normal WB, EL1 RW, inner shareable, AF, global, PXN|UXN.
    (0b11 << 8) | (1 << 10) | PXN | UXN
};

impl MockPlatform {
    fn new(map: KernelMap) -> Self {
        let mut p = Self {
            arena: vec![0u8; ARENA_FRAMES * PAGE],
            allocator: BitmapFrameAllocator::new(
                PhysAddr((ARENA_BASE as usize) + KERNEL_RESERVED * PAGE),
                MANAGED,
            ),
            kernel_frames: 0,
            handed_out: BTreeSet::new(),
            batch_calls: 0,
            fail_batch_nth: None,
            fail_contiguous: false,
            copy_calls: 0,
            corrupt_after_copy: None,
            release_calls: 0,
        };
        let frame = |i: usize| ARENA_BASE + (i * PAGE) as u64;
        let (l0, l1, l2) = (frame(0), frame(1), frame(2));
        p.put(l0, 0, (l1 & ADDRESS_MASK) | DESC_TABLE);
        // An unrelated kernel mapping in L1[0] (below RAM) as a 1 GiB block.
        p.put(l1, 0, KERNEL_ATTRS | DESC_BLOCK);
        match map {
            KernelMap::Block1G => {
                p.put(l1, 1, ARENA_BASE | KERNEL_ATTRS | DESC_BLOCK);
                p.kernel_frames = 2;
            }
            KernelMap::Blocks2M => {
                p.put(l1, 1, l2 | DESC_TABLE);
                for k in 0..512u64 {
                    p.put(l2, k as usize, (ARENA_BASE + (k << 21)) | KERNEL_ATTRS | DESC_BLOCK);
                }
                p.kernel_frames = 3;
            }
            KernelMap::Pages4K => {
                p.put(l1, 1, l2 | DESC_TABLE);
                let l3_tables = (ARENA_FRAMES * PAGE).div_ceil(1 << 21);
                assert!(3 + l3_tables <= KERNEL_RESERVED);
                for k in 0..512u64 {
                    let region = ARENA_BASE + (k << 21);
                    if (k as usize) < l3_tables {
                        let l3 = frame(3 + k as usize);
                        p.put(l2, k as usize, l3 | DESC_TABLE);
                        for j in 0..512u64 {
                            p.put(l3, j as usize, (region + (j << 12)) | KERNEL_ATTRS | DESC_TABLE);
                        }
                    } else {
                        p.put(l2, k as usize, region | KERNEL_ATTRS | DESC_BLOCK);
                    }
                }
                p.kernel_frames = 3 + l3_tables;
            }
        }
        p
    }

    fn offset(&self, pa: u64, len: usize) -> usize {
        assert!(
            pa >= ARENA_BASE && pa + len as u64 <= ARENA_BASE + self.arena.len() as u64,
            "access outside arena: {pa:#x}+{len}"
        );
        (pa - ARENA_BASE) as usize
    }

    fn put(&mut self, table: u64, index: usize, value: u64) {
        let o = self.offset(table + index as u64 * 8, 8);
        self.arena[o..o + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn get(&self, table: u64, index: usize) -> u64 {
        read_entry(self, table, index)
    }

    fn kernel_snapshot(&self) -> Vec<u8> {
        self.arena[..self.kernel_frames * PAGE].to_vec()
    }

    fn all_handed_out_zero(&self) -> bool {
        self.handed_out.iter().all(|pa| {
            let o = self.offset(*pa, PAGE);
            self.arena[o..o + PAGE].iter().all(|b| *b == 0)
        })
    }
}

impl LoaderPlatform for MockPlatform {
    fn kernel_root(&self) -> u64 {
        ARENA_BASE
    }
    fn free_frames(&self) -> usize {
        self.allocator.free_count()
    }
    fn reserve_batch(&mut self, count: usize) -> Option<FrameBatch> {
        self.batch_calls += 1;
        if self.fail_batch_nth == Some(self.batch_calls) {
            return None;
        }
        let batch = self.allocator.allocate_batch(count)?;
        for f in batch.as_slice() {
            self.handed_out.insert(f.0 as u64);
        }
        Some(batch)
    }
    fn release_batch(&mut self, batch: FrameBatch) -> bool {
        self.release_calls += 1;
        self.allocator.release_batch(batch)
    }
    fn reserve_contiguous(&mut self, count: usize) -> Option<u64> {
        if self.fail_contiguous {
            return None;
        }
        let start = self.allocator.allocate_contiguous(count)?.0 as u64;
        for i in 0..count {
            self.handed_out.insert(start + (i * PAGE) as u64);
        }
        Some(start)
    }
    fn release_contiguous(&mut self, start: u64, count: usize) -> bool {
        self.release_calls += 1;
        let mut ok = true;
        for i in 0..count {
            ok &= self
                .allocator
                .deallocate_frame(PhysAddr(start as usize + i * PAGE));
        }
        ok
    }
    fn bytes(&self, pa: u64, len: usize) -> &[u8] {
        let o = self.offset(pa, len);
        &self.arena[o..o + len]
    }
    fn bytes_mut(&mut self, pa: u64, len: usize) -> &mut [u8] {
        let o = self.offset(pa, len);
        &mut self.arena[o..o + len]
    }
    fn copy(&mut self, src: u64, dst: u64, len: usize) {
        let (s, d) = (self.offset(src, len), self.offset(dst, len));
        self.arena.copy_within(s..s + len, d);
        self.copy_calls += 1;
        if self.corrupt_after_copy == Some(self.copy_calls) && len > 0 {
            self.arena[d] ^= 0x5a;
        }
    }
    fn clean_dcache(&mut self, _pa: u64, _len: usize) {}
    fn sync_icache(&mut self, _pa: u64, _len: usize) {}
}

// ---------------------------------------------------------------------------
// Artifact fixtures
// ---------------------------------------------------------------------------

/// RFC 8032 TEST 1 seed: the SEED-0B qualification signer. TEST ONLY.
const TEST_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const OTHER_SEED: [u8; 32] = [0x42; 32];

struct Res {
    code_pages: u32,
    data_pages: u32,
    stack_pages: u32,
    max_capabilities: u16,
    ipc_messages: u32,
    ipc_bytes: u32,
    cpu_ticks: u64,
    elapsed_ticks: u64,
    syscall_count: u32,
}

impl Default for Res {
    fn default() -> Self {
        Self {
            code_pages: 1,
            data_pages: 1,
            stack_pages: 1,
            max_capabilities: 1,
            ipc_messages: 0,
            ipc_bytes: 0,
            cpu_ticks: 1_000_000,
            elapsed_ticks: 1_000_000,
            syscall_count: 16,
        }
    }
}

struct Spec {
    entry: u32,
    caps: Vec<CapabilityRequest>,
    res: Res,
    code: Vec<u8>,
    data: Vec<u8>,
}

fn seed_read(rights: u32, id: u32) -> CapabilityRequest {
    CapabilityRequest {
        resource_kind: RESOURCE_KIND_OBJECT,
        resource_id: id,
        rights,
        bounds_kind: 1,
        max_operations: 4,
        max_bytes: 32,
        byte_offset: 0,
        byte_length: 32,
    }
}

fn code_words(n: usize) -> Vec<u8> {
    // Deterministic distinct instruction-sized words; content is never run.
    (0..n as u32)
        .flat_map(|i| (0xd503_201f_u32 ^ (i.wrapping_mul(0x9e37_79b9))).to_le_bytes())
        .collect()
}

fn spec() -> Spec {
    Spec {
        entry: 4,
        caps: vec![seed_read(RIGHT_READ, SEED_OBJECT_ID)],
        res: Res::default(),
        code: code_words(16),
        data: b"P2-5EXEC data section bytes".to_vec(),
    }
}

fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

/// Mirror of `aienos-artifact-tool pack`, then Ed25519-sign with `seed`.
fn pack_signed(s: &Spec, seed: &[u8; 32]) -> Vec<u8> {
    let cap_off = 192usize;
    let res_off = cap_off + s.caps.len() * 48;
    let payload_off = (res_off + 48 + 15) & !15;
    let payload_len = s.code.len() + s.data.len();
    let sig_off = payload_off + payload_len;
    let total = sig_off + 100;
    let mut b = vec![0u8; total];
    b[0..8].copy_from_slice(b"AIENART\0");
    put16(&mut b, 10, 128);
    put16(&mut b, 12, 1);
    put16(&mut b, 14, 1);
    put32(&mut b, 20, total as u32);
    put32(&mut b, 24, 128);
    put16(&mut b, 28, 2);
    put16(&mut b, 30, 32);
    put32(&mut b, 36, s.entry);
    put32(&mut b, 40, cap_off as u32);
    put16(&mut b, 44, s.caps.len() as u16);
    put16(&mut b, 46, 48);
    put32(&mut b, 48, res_off as u32);
    put16(&mut b, 52, 48);
    put32(&mut b, 56, payload_off as u32);
    put32(&mut b, 60, payload_len as u32);
    put32(&mut b, 64, sig_off as u32);
    put16(&mut b, 68, 100);
    put16(&mut b, 70, 1);
    let section = |b: &mut [u8], o: usize, kind: u16, perm: u16, rel: u32, len: u32, mem: u32| {
        put16(b, o, kind);
        put16(b, o + 2, perm);
        put32(b, o + 8, rel);
        put32(b, o + 12, len);
        put32(b, o + 16, mem);
        put32(b, o + 20, 4096);
    };
    let code_len = s.code.len() as u32;
    section(&mut b, 128, 1, 5, 0, code_len, code_len);
    section(
        &mut b,
        160,
        2,
        3,
        code_len,
        s.data.len() as u32,
        s.res.data_pages * 4096,
    );
    for (i, c) in s.caps.iter().enumerate() {
        b[cap_off + i * 48..cap_off + (i + 1) * 48].copy_from_slice(&c.to_bytes());
    }
    let r = &s.res;
    put32(&mut b, res_off, r.code_pages);
    put32(&mut b, res_off + 4, r.data_pages);
    put32(&mut b, res_off + 8, r.stack_pages);
    put16(&mut b, res_off + 12, r.max_capabilities);
    put32(&mut b, res_off + 16, r.ipc_messages);
    put32(&mut b, res_off + 20, r.ipc_bytes);
    put64(&mut b, res_off + 24, r.cpu_ticks);
    put64(&mut b, res_off + 32, r.elapsed_ticks);
    put32(&mut b, res_off + 40, r.syscall_count);
    b[payload_off..payload_off + s.code.len()].copy_from_slice(&s.code);
    b[payload_off + s.code.len()..sig_off].copy_from_slice(&s.data);
    put16(&mut b, sig_off, 1);
    let id = parse_and_identify(&b).expect("fixture parses").artifact_id;
    let key = SigningKey::from_bytes(seed);
    let signature = key.sign(&artifact_signature_message(&id));
    b[sig_off + 4..sig_off + 36]
        .copy_from_slice(&signer_fingerprint(&key.verifying_key().to_bytes()));
    b[sig_off + 36..sig_off + 100].copy_from_slice(&signature.to_bytes());
    b
}

fn payload_offset(bytes: &[u8]) -> usize {
    u32::from_le_bytes(bytes[56..60].try_into().unwrap()) as usize
}

struct TestAnchors {
    key: [u8; 32],
}

impl TrustAnchorSet for TestAnchors {
    fn find(&self, fingerprint: &Digest) -> Option<TrustedSigner> {
        (signer_fingerprint(&self.key) == *fingerprint).then_some(TrustedSigner {
            public_key: self.key,
            tier: TrustTier::Seed0bQualification,
        })
    }
}

fn public(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

fn anchors() -> TestAnchors {
    TestAnchors {
        key: public(&TEST_SEED),
    }
}

fn policy() -> AdmissionPolicy {
    boot_policy(&[signer_fingerprint(&public(&TEST_SEED))]).unwrap()
}

// ---------------------------------------------------------------------------
// Executors
// ---------------------------------------------------------------------------

struct FnExec<F>(F);

impl<F> TaskExecutor<MockPlatform> for FnExec<F>
where
    F: FnMut(TaskContext<'_>, &mut MockPlatform) -> TaskOutcome,
{
    fn execute(&mut self, task: TaskContext<'_>, platform: &mut MockPlatform) -> TaskOutcome {
        (self.0)(task, platform)
    }
}

fn exec<F>(f: F) -> FnExec<F>
where
    F: FnMut(TaskContext<'_>, &mut MockPlatform) -> TaskOutcome,
{
    FnExec(f)
}

fn outcome(status: ExecutionStatus) -> TaskOutcome {
    TaskOutcome {
        status,
        syscalls: 1,
        object_reads_ok: 0,
        denials: 0,
        elapsed_ticks: 10,
    }
}

fn exits_zero() -> FnExec<impl FnMut(TaskContext<'_>, &mut MockPlatform) -> TaskOutcome> {
    exec(|_, _| outcome(ExecutionStatus::Exited(0)))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Walk `root` for `va`; returns (output page PA, leaf attributes) of the 4 KiB
/// page containing `va`, whatever the leaf level.
fn effective(p: &MockPlatform, root: u64, va: u64) -> Option<(u64, u64)> {
    let (leaf, level) = kernel_translation(p, root, va)?;
    let page = va & !0xfff;
    let pa = match level {
        1 => (leaf & BLOCK_1G_MASK) + (page & ((1 << 30) - 1)),
        2 => (leaf & BLOCK_2M_MASK) + (page & ((1 << 21) - 1)),
        _ => leaf & ADDRESS_MASK,
    };
    Some((pa, leaf & ATTR_MASK))
}

struct Run {
    platform: MockPlatform,
    scheduler: LoaderScheduler,
    kernel_before: Vec<u8>,
    free_before: usize,
}

impl Run {
    fn new(map: KernelMap) -> Self {
        let platform = MockPlatform::new(map);
        Self {
            kernel_before: platform.kernel_snapshot(),
            free_before: platform.free_frames(),
            platform,
            scheduler: Scheduler::new([0]),
        }
    }

    fn candidate<E: TaskExecutor<MockPlatform>>(
        &mut self,
        bytes: &[u8],
        verifier: &impl ArtifactVerifier,
        policy: &AdmissionPolicy,
        executor: &mut E,
        task_id: u32,
    ) -> CandidateReport {
        process_candidate(
            bytes,
            &mut self.platform,
            verifier,
            policy,
            &mut self.scheduler,
            executor,
            task_id,
        )
    }

    /// Invariants every candidate, admitted or not, must leave behind.
    fn assert_clean(&self, report: &CandidateReport) {
        assert_eq!(self.platform.free_frames(), self.free_before, "frames leaked");
        assert_eq!(report.frames_free_before, self.free_before);
        assert_eq!(report.frames_free_after, self.free_before);
        assert!(report.reclaimed(), "{report:?}");
        assert_eq!(self.scheduler.queue_len(0), Some(0), "scheduler slot leaked");
        assert!(self.platform.all_handed_out_zero(), "unscrubbed frame");
        assert_eq!(
            self.platform.kernel_snapshot(),
            self.kernel_before,
            "kernel tables modified"
        );
    }
}

fn verifier(a: &TestAnchors) -> ConfiguredArtifactVerifier<'_, TestAnchors, Ed25519Verifier> {
    ConfiguredArtifactVerifier::new(a, Ed25519Verifier)
}

fn assert_rejected(report: &CandidateReport, stage: CandidateState, error: LoadError) {
    assert_eq!(report.decision, Decision::Rejected, "{report:?}");
    assert_eq!(report.failed_stage, Some(stage), "{report:?}");
    assert_eq!(report.error, Some(error), "{report:?}");
}

const MAPS: [KernelMap; 3] = [KernelMap::Block1G, KernelMap::Blocks2M, KernelMap::Pages4K];

// ---------------------------------------------------------------------------
// 1. Happy path
// ---------------------------------------------------------------------------

#[test]
fn admitted_task_sees_exact_entry_state_and_is_fully_reclaimed() {
    for map in MAPS {
        let s = spec();
        let bytes = pack_signed(&s, &TEST_SEED);
        let expected_id = parse_and_identify(&bytes).unwrap().artifact_id;
        let a = anchors();
        let v = verifier(&a);
        let pol = policy();
        let mut run = Run::new(map);
        let mut seen = false;
        let mut executor = exec(|ctx: TaskContext<'_>, p: &mut MockPlatform| {
            seen = true;
            let base = 1u64 << 39;
            let code_base = base + PAGE_U64;
            let data_base = base + 3 * PAGE_U64;
            let stack_top = base + 5 * PAGE_U64 + PAGE_U64;
            assert_eq!(ctx.entry_pc, code_base + 4);
            assert_eq!(ctx.args[0], stack_top - 8, "handle array VA");
            assert_eq!(ctx.args[1], 1);
            assert_eq!(ctx.args[2], data_base);
            assert_eq!(ctx.args[3], 4096);
            assert_eq!(ctx.stack_pointer % 16, 0);
            assert!(ctx.stack_pointer <= ctx.args[0]);
            assert!(ctx.args[0] - ctx.stack_pointer < 16);
            assert_eq!(ctx.budget.syscalls, 16);
            assert_eq!(ctx.grants.len(), 1);
            let handle = Handle::new(0, 1).unwrap();
            assert_eq!(ctx.capabilities.lookup(handle, Rights::READ), Ok(0));
            assert_eq!(
                ctx.capabilities.lookup(handle, Rights::WRITE),
                Err(CapError::MissingRights)
            );
            let (pa, _) = effective(p, ctx.root, ctx.args[0]).expect("handle array mapped");
            let raw = p.bytes(pa + (ctx.args[0] & 0xfff), 8);
            assert_eq!(
                u64::from_le_bytes(raw.try_into().unwrap()),
                handle.to_raw(),
                "handle array holds the installed handle"
            );
            outcome(ExecutionStatus::Exited(0))
        });
        let report = run.candidate(&bytes, &v, &pol, &mut executor, 7);
        assert!(seen, "executor never ran ({map:?})");
        assert_eq!(report.decision, Decision::Admitted, "{report:?}");
        assert_eq!(report.error, None);
        assert_eq!(report.artifact_id, Some(expected_id));
        assert_eq!(report.trust_tier, Some(TrustTier::Seed0bQualification));
        assert!(report.byte_chain);
        assert!(report.wx_enforced);
        assert_eq!(report.caps_installed, 1);
        assert_eq!(report.caps_live_after, 0);
        assert_eq!(report.outcome.status, ExecutionStatus::Exited(0));
        assert_eq!(report.code_base, (1u64 << 39) + PAGE_U64);
        assert_eq!(report.code_end, report.code_base + PAGE_U64);
        // 3 content + 4 window tables + 3 shadow tables.
        assert_eq!(report.frames_reserved, 10, "{map:?}");
        run.assert_clean(&report);
    }
}

// ---------------------------------------------------------------------------
// 2. Sealed address space, inspected while the task "runs"
// ---------------------------------------------------------------------------

#[test]
fn sealed_address_space_is_wx_with_read_only_code_alias() {
    for map in MAPS {
        let mut s = spec();
        s.res.code_pages = 2;
        s.res.data_pages = 2;
        s.res.stack_pages = 2;
        s.code = code_words(1100); // 4400 bytes: spans two code pages
        s.data = (0..5000u32).map(|i| (i * 7) as u8).collect();
        let bytes = pack_signed(&s, &TEST_SEED);
        let a = anchors();
        let v = verifier(&a);
        let pol = policy();
        let mut run = Run::new(map);
        let pages = bytes.len().div_ceil(PAGE);
        let staged = run.platform.reserve_contiguous(pages).unwrap();
        run.platform
            .bytes_mut(staged, bytes.len())
            .copy_from_slice(&bytes);
        let mut task = load(
            &mut run.platform,
            staged,
            bytes.len(),
            &v,
            &pol,
            &mut run.scheduler,
            9,
        )
        .expect("admitted");
        run.platform.bytes_mut(staged, pages * PAGE).fill(0);
        assert!(run.platform.release_contiguous(staged, pages));
        assert_eq!(task.state, CandidateState::Admitted);

        let p = &run.platform;
        let space = task.address_space;
        assert!(audit_wx(p, &space), "{map:?}");
        let layout = space.layout;
        let root = space.root;

        // User window: guard | code RX | guard | data RW NX | guard | stack RW NX | guard.
        let base = layout.base;
        let kinds: Vec<&str> = (0..10)
            .map(|i| match effective(p, root, base + i * PAGE_U64) {
                None => "guard",
                Some((_, attrs)) => {
                    let el0 = attrs & AP_EL0 != 0;
                    let ro = attrs & AP_READ_ONLY != 0;
                    let user_x = attrs & UXN == 0;
                    let kernel_x = attrs & PXN == 0;
                    assert!(el0, "user window page not EL0");
                    assert!(!kernel_x, "user page executable at EL1");
                    match (ro, user_x) {
                        (true, true) => "rx",
                        (false, false) => "rw",
                        _ => "bad",
                    }
                }
            })
            .collect();
        assert_eq!(
            kinds,
            ["guard", "rx", "rx", "guard", "rw", "rw", "guard", "rw", "rw", "guard"]
        );
        for i in 10..512 {
            assert!(effective(p, root, base + i * PAGE_U64).is_none());
        }

        // Code aliases: read-only, never executable; other pages untouched.
        let code_pas: Vec<u64> = space.code_frames().iter().map(|f| f.0 as u64).collect();
        for pa in &code_pas {
            let (out, attrs) = effective(p, root, *pa).unwrap();
            assert_eq!(out, *pa);
            assert_ne!(attrs & AP_READ_ONLY, 0, "code alias writable ({map:?})");
            assert_ne!(attrs & PXN, 0);
            assert_ne!(attrs & UXN, 0);
            assert_eq!(attrs & AP_EL0, 0, "code alias EL0-accessible");
            // Kernel root still has the original RW alias (used only after exit).
            let (_, kattrs) = effective(p, ARENA_BASE, *pa).unwrap();
            assert_eq!(kattrs & AP_READ_ONLY, 0);
        }
        let region = code_pas[0] & !((1 << 21) - 1);
        for page in (region..region + (1 << 21)).step_by(PAGE) {
            if code_pas.contains(&page) || page >= ARENA_BASE + (ARENA_FRAMES * PAGE) as u64 {
                continue;
            }
            assert_eq!(
                effective(p, root, page),
                effective(p, ARENA_BASE, page),
                "neighbour {page:#x} changed ({map:?})"
            );
        }
        for frame in &space.frames()[layout.code_pages..] {
            let pa = frame.0 as u64;
            assert_eq!(effective(p, root, pa), effective(p, ARENA_BASE, pa));
        }
        // Mappings outside RAM (kernel L1[0]) are shared, not copied.
        assert_eq!(effective(p, root, 0x1000), effective(p, ARENA_BASE, 0x1000));

        // Exact bytes, zero tails, zero stack (except the handle array).
        let read_va = |va: u64, len: usize| -> Vec<u8> {
            (0..len as u64)
                .map(|i| {
                    let (pa, _) = effective(p, root, va + i).unwrap();
                    p.bytes(pa + ((va + i) & 0xfff), 1)[0]
                })
                .collect()
        };
        assert_eq!(read_va(layout.code_base(), s.code.len()), s.code);
        assert!(read_va(
            layout.code_base() + s.code.len() as u64,
            2 * PAGE - s.code.len()
        )
        .iter()
        .all(|b| *b == 0));
        assert_eq!(read_va(layout.data_base(), s.data.len()), s.data);
        assert!(read_va(
            layout.data_base() + s.data.len() as u64,
            2 * PAGE - s.data.len()
        )
        .iter()
        .all(|b| *b == 0));
        let stack = read_va(layout.stack_base(), 2 * PAGE);
        assert!(stack[..2 * PAGE - 8].iter().all(|b| *b == 0));
        assert_eq!(
            u64::from_le_bytes(stack[2 * PAGE - 8..].try_into().unwrap()),
            task.handles[0].unwrap().to_raw()
        );
        assert_eq!(code_digest(p, &space), task.code_digest);

        let outcome = run_task(
            &mut task,
            &mut run.platform,
            &mut run.scheduler,
            &mut exits_zero(),
        );
        assert_eq!(outcome.status, ExecutionStatus::Exited(0));
        let teardown = destroy(task, &mut run.platform, &mut run.scheduler);
        assert_eq!(
            teardown,
            Teardown {
                executed_bytes_match: true,
                caps_live_after: 0,
                released: true,
            }
        );
        assert_eq!(run.platform.free_frames(), run.free_before);
        assert!(run.platform.all_handed_out_zero());
        assert_eq!(run.platform.kernel_snapshot(), run.kernel_before);
    }
}

#[test]
fn audit_rejects_writable_code_and_writable_alias() {
    let bytes = pack_signed(&spec(), &TEST_SEED);
    let a = anchors();
    let v = verifier(&a);
    let pol = policy();
    let mut run = Run::new(KernelMap::Blocks2M);
    let pages = bytes.len().div_ceil(PAGE);
    let staged = run.platform.reserve_contiguous(pages).unwrap();
    run.platform
        .bytes_mut(staged, bytes.len())
        .copy_from_slice(&bytes);
    let task = load(
        &mut run.platform,
        staged,
        bytes.len(),
        &v,
        &pol,
        &mut run.scheduler,
        3,
    )
    .unwrap();
    let space = task.address_space;
    assert!(audit_wx(&run.platform, &space));
    let l3 = space.frames()[space.layout.content_frames() + 3].0 as u64;

    // Code leaf made writable (RWX at EL0).
    let good = run.platform.get(l3, 1);
    run.platform.put(l3, 1, good & !AP_READ_ONLY);
    assert!(!audit_wx(&run.platform, &space));
    run.platform.put(l3, 1, good);
    // Data leaf made executable.
    let data = run.platform.get(l3, 3);
    run.platform.put(l3, 3, data & !UXN);
    assert!(!audit_wx(&run.platform, &space));
    run.platform.put(l3, 3, data);
    // A stray extra mapping in a guard slot.
    run.platform.put(l3, 2, data);
    assert!(!audit_wx(&run.platform, &space));
    run.platform.put(l3, 2, 0);
    assert!(audit_wx(&run.platform, &space));
    // Code frame alias made writable again in the task root.
    let pa = space.code_frames()[0].0 as u64;
    let shadow_l3 = space.shadow_frames()[2].0 as u64;
    let index = table_index(pa, 3);
    let alias = run.platform.get(shadow_l3, index);
    assert_ne!(alias & AP_READ_ONLY, 0);
    run.platform.put(shadow_l3, index, alias & !AP_READ_ONLY);
    assert!(!audit_wx(&run.platform, &space));
    run.platform.put(shadow_l3, index, alias);
    assert!(audit_wx(&run.platform, &space));

    let teardown = destroy(task, &mut run.platform, &mut run.scheduler);
    assert!(teardown.released);
    run.platform.bytes_mut(staged, pages * PAGE).fill(0);
    assert!(run.platform.release_contiguous(staged, pages));
    assert_eq!(run.platform.free_frames(), run.free_before);
}

// ---------------------------------------------------------------------------
// 3. Rejections
// ---------------------------------------------------------------------------

fn reject_case(
    map: KernelMap,
    bytes: &[u8],
    a: &TestAnchors,
    pol: &AdmissionPolicy,
    setup: impl FnOnce(&mut Run),
) -> (CandidateReport, Run) {
    let mut run = Run::new(map);
    setup(&mut run);
    let mut ran = false;
    let mut executor = exec(|_, _| {
        ran = true;
        outcome(ExecutionStatus::Exited(0))
    });
    let report = run.candidate(bytes, &verifier(a), pol, &mut executor, 11);
    assert!(!ran, "rejected candidate executed");
    (report, run)
}

#[test]
fn tampered_payload_is_rejected_before_any_task_frame() {
    let mut bytes = pack_signed(&spec(), &TEST_SEED);
    let at = payload_offset(&bytes);
    bytes[at] ^= 1;
    let (report, run) = reject_case(KernelMap::Block1G, &bytes, &anchors(), &policy(), |_| {});
    assert_rejected(
        &report,
        CandidateState::Verified,
        LoadError::Artifact(ArtifactError::BadSignature),
    );
    assert_eq!(run.platform.batch_calls, 0, "task frames reserved before verification");
    run.assert_clean(&report);
}

#[test]
fn unknown_signer_rejected_by_anchors_and_by_policy() {
    let bytes = pack_signed(&spec(), &OTHER_SEED);
    let (report, run) = reject_case(KernelMap::Block1G, &bytes, &anchors(), &policy(), |_| {});
    assert_rejected(
        &report,
        CandidateState::Verified,
        LoadError::Artifact(ArtifactError::UntrustedSigner),
    );
    run.assert_clean(&report);

    // Anchors know the key but local policy does not allow it.
    let bytes = pack_signed(&spec(), &TEST_SEED);
    let empty_policy = boot_policy(&[]).unwrap();
    let (report, run) =
        reject_case(KernelMap::Block1G, &bytes, &anchors(), &empty_policy, |_| {});
    assert_rejected(
        &report,
        CandidateState::Authorized,
        LoadError::Artifact(ArtifactError::UntrustedSigner),
    );
    run.assert_clean(&report);
}

#[test]
fn ipc_request_exceeds_policy_and_is_rejected() {
    let mut s = spec();
    s.res.ipc_messages = 1;
    let bytes = pack_signed(&s, &TEST_SEED);
    let (report, run) = reject_case(KernelMap::Block1G, &bytes, &anchors(), &policy(), |_| {});
    assert_rejected(
        &report,
        CandidateState::Authorized,
        LoadError::Artifact(ArtifactError::ResourceLimit),
    );
    assert_eq!(run.platform.batch_calls, 0);
    run.assert_clean(&report);
}

#[test]
fn empty_and_oversized_inputs_are_refused_before_staging() {
    for bytes in [Vec::new(), vec![0u8; (MAX_STAGING_FRAMES + 1) * PAGE]] {
        let (report, run) =
            reject_case(KernelMap::Block1G, &bytes, &anchors(), &policy(), |_| {});
        assert_rejected(&report, CandidateState::Received, LoadError::StagingTooLarge);
        assert!(run.platform.handed_out.is_empty());
        run.assert_clean(&report);
    }
    // Exactly MAX_STAGING_FRAMES pages is staged (then fails parsing).
    let bytes = vec![0u8; MAX_STAGING_FRAMES * PAGE];
    let (report, run) = reject_case(KernelMap::Block1G, &bytes, &anchors(), &policy(), |_| {});
    assert_rejected(
        &report,
        CandidateState::Verified,
        LoadError::Artifact(ArtifactError::BadMagic),
    );
    run.assert_clean(&report);
}

#[test]
fn staging_reservation_failure() {
    let bytes = pack_signed(&spec(), &TEST_SEED);
    let (report, run) = reject_case(KernelMap::Block1G, &bytes, &anchors(), &policy(), |r| {
        r.platform.fail_contiguous = true;
    });
    assert_rejected(&report, CandidateState::Staged, LoadError::NoFrames);
    run.assert_clean(&report);
}

#[test]
fn main_and_shadow_batch_failures_roll_back() {
    for nth in [1, 2] {
        for map in MAPS {
            let bytes = pack_signed(&spec(), &TEST_SEED);
            let (report, run) = reject_case(map, &bytes, &anchors(), &policy(), |r| {
                r.platform.fail_batch_nth = Some(nth);
            });
            assert_rejected(&report, CandidateState::Reserved, LoadError::NoFrames);
            assert_eq!(run.platform.batch_calls, nth);
            run.assert_clean(&report);
        }
    }
}

#[test]
fn full_scheduler_fails_closed_at_admission() {
    // With every loaded-task slot taken, the resource snapshot offers no
    // pages, so admission refuses before anything is reserved.
    let bytes = pack_signed(&spec(), &TEST_SEED);
    let (report, run) = reject_case(KernelMap::Block1G, &bytes, &anchors(), &policy(), |r| {
        for id in 0..LOADED_TASK_SLOTS as u32 {
            r.scheduler.enqueue(1000 + id, TaskPriority::Normal).unwrap();
        }
    });
    assert_rejected(
        &report,
        CandidateState::Authorized,
        LoadError::Artifact(ArtifactError::ResourceLimit),
    );
    assert_eq!(run.platform.free_frames(), run.free_before);
    assert_eq!(run.scheduler.queue_len(0), Some(LOADED_TASK_SLOTS));
    assert!(run.platform.all_handed_out_zero());
}

#[test]
fn scheduler_refusal_at_reservation_rolls_back() {
    // A duplicate task id passes admission but the scheduler refuses the slot.
    let bytes = pack_signed(&spec(), &TEST_SEED);
    let (report, run) = reject_case(KernelMap::Block1G, &bytes, &anchors(), &policy(), |r| {
        r.scheduler.enqueue(11, TaskPriority::Normal).unwrap();
    });
    assert_rejected(&report, CandidateState::Reserved, LoadError::SchedulerFull);
    assert_eq!(run.platform.batch_calls, 0);
    assert_eq!(run.platform.free_frames(), run.free_before);
    // The pre-existing entry is untouched; nothing of ours remains.
    assert_eq!(run.scheduler.queue_len(0), Some(1));
    assert!(run.platform.all_handed_out_zero());
}

#[test]
fn kernel_root_without_free_window_is_a_mapping_failure() {
    let bytes = pack_signed(&spec(), &TEST_SEED);
    let (report, run) = reject_case(KernelMap::Block1G, &bytes, &anchors(), &policy(), |r| {
        for index in 1..256 {
            r.platform.put(ARENA_BASE, index, 0x2);
        }
        r.kernel_before = r.platform.kernel_snapshot();
    });
    assert_rejected(&report, CandidateState::Reserved, LoadError::Mapping);
    run.assert_clean(&report);
}

#[test]
fn corrupted_mapped_bytes_fail_the_read_back_hash() {
    for map in MAPS {
        // Copy #1 is the kernel L0; #2 the first code page; #3 the data page.
        for k in [2, 3] {
            let bytes = pack_signed(&spec(), &TEST_SEED);
            let (report, run) = reject_case(map, &bytes, &anchors(), &policy(), |r| {
                r.platform.corrupt_after_copy = Some(k);
            });
            assert_rejected(&report, CandidateState::Hashed, LoadError::MappedDigestMismatch);
            run.assert_clean(&report);
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Executed-bytes check
// ---------------------------------------------------------------------------

#[test]
fn code_modified_during_execution_breaks_the_byte_chain() {
    let bytes = pack_signed(&spec(), &TEST_SEED);
    let a = anchors();
    let mut run = Run::new(KernelMap::Pages4K);
    let mut executor = exec(|ctx: TaskContext<'_>, p: &mut MockPlatform| {
        // Simulate a W^X hole: something writes the code frame.
        let (pa, _) = effective(p, ctx.root, ctx.entry_pc).unwrap();
        p.bytes_mut(pa + (ctx.entry_pc & 0xfff), 1)[0] ^= 0xff;
        outcome(ExecutionStatus::Exited(0))
    });
    let report = run.candidate(&bytes, &verifier(&a), &policy(), &mut executor, 5);
    assert_eq!(report.decision, Decision::Admitted);
    assert!(!report.byte_chain);
    assert_eq!(report.error, Some(LoadError::ExecutedDigestMismatch));
    let mut line = String::new();
    write_candidate_line(&mut line, "X.AIEN", &report);
    assert!(line.contains(" bytes=mismatch "), "{line}");
    run.assert_clean(&report);
}

// ---------------------------------------------------------------------------
// 5. Granted ⊆ requested
// ---------------------------------------------------------------------------

fn installed_rights(caps: Vec<CapabilityRequest>) -> (CandidateReport, Vec<(bool, bool)>) {
    let mut s = spec();
    s.res.max_capabilities = caps.len() as u16;
    s.caps = caps;
    let bytes = pack_signed(&s, &TEST_SEED);
    let a = anchors();
    let mut run = Run::new(KernelMap::Block1G);
    let mut rights = Vec::new();
    let mut executor = exec(|ctx: TaskContext<'_>, _p: &mut MockPlatform| {
        for index in 0..ctx.args[1] as u32 {
            let h = Handle::new(index, 1).unwrap();
            rights.push((
                ctx.capabilities.lookup(h, Rights::READ).is_ok(),
                ctx.capabilities.lookup(h, Rights::WRITE).is_ok(),
            ));
        }
        assert_eq!(ctx.grants.len() as u64, ctx.args[1]);
        outcome(ExecutionStatus::Exited(0))
    });
    let report = run.candidate(&bytes, &verifier(&a), &policy(), &mut executor, 21);
    run.assert_clean(&report);
    (report, rights)
}

#[test]
fn grants_never_exceed_requests_or_policy() {
    let (report, rights) = installed_rights(vec![seed_read(RIGHT_READ | RIGHT_WRITE, SEED_OBJECT_ID)]);
    assert_eq!(report.decision, Decision::Admitted);
    assert_eq!(report.caps_installed, 1);
    assert_eq!(rights, [(true, false)], "READ|WRITE request must reduce to READ");

    let (report, rights) = installed_rights(vec![seed_read(RIGHT_WRITE, SEED_OBJECT_ID)]);
    assert_eq!(report.decision, Decision::Admitted);
    assert_eq!(report.caps_installed, 0);
    assert!(rights.is_empty());

    let (report, rights) = installed_rights(vec![seed_read(RIGHT_READ, SEED_OBJECT_ID + 1)]);
    assert_eq!(report.decision, Decision::Admitted);
    assert_eq!(report.caps_installed, 0, "resource absent from policy");
    assert!(rights.is_empty());

    let channel = CapabilityRequest {
        resource_kind: RESOURCE_KIND_CHANNEL,
        resource_id: 1,
        rights: RIGHT_READ,
        bounds_kind: 2,
        max_operations: 1,
        max_bytes: 8,
        byte_offset: 0,
        byte_length: 0,
    };
    let (report, _) = installed_rights(vec![channel, seed_read(RIGHT_READ, SEED_OBJECT_ID)]);
    assert_eq!(report.caps_installed, 1, "only the policy-allowed object");
}

// ---------------------------------------------------------------------------
// 6. Envelope extremes and layout bounds
// ---------------------------------------------------------------------------

#[test]
fn largest_envelope_loads_in_one_l3_table() {
    for map in MAPS {
        let mut s = spec();
        s.res.code_pages = 64;
        s.res.data_pages = 64;
        s.res.stack_pages = 16;
        s.code = code_words(64 * 1024); // exactly 64 pages
        s.data = vec![0xa5; 64 * PAGE];
        let bytes = pack_signed(&s, &TEST_SEED);
        let a = anchors();
        let mut run = Run::new(map);
        let mut executor = exec(|ctx: TaskContext<'_>, p: &mut MockPlatform| {
            let base = 1u64 << 39;
            // 1 + 64 + 1 + 64 + 1 + 16 + 1 = 148 window pages.
            assert!(effective(p, ctx.root, base + 147 * PAGE_U64).is_none());
            assert!(effective(p, ctx.root, base + 146 * PAGE_U64).is_some());
            assert!(effective(p, ctx.root, base + 64 * PAGE_U64).is_some());
            assert!(effective(p, ctx.root, base + 65 * PAGE_U64).is_none());
            outcome(ExecutionStatus::Exited(0))
        });
        let report = run.candidate(&bytes, &verifier(&a), &policy(), &mut executor, 31);
        assert_eq!(report.decision, Decision::Admitted, "{report:?}");
        assert!(report.byte_chain);
        assert!(report.frames_reserved >= 148 + 3);
        run.assert_clean(&report);
    }
}

#[test]
fn task_layout_rejects_every_bound_violation() {
    let res = |c: u32, d: u32, st: u32| ResourceEnvelope {
        code_pages: c,
        data_pages: d,
        stack_pages: st,
        max_capabilities: 0,
        ipc_messages: 0,
        ipc_bytes: 0,
        cpu_ticks: 1,
        elapsed_ticks: 1,
        syscall_count: 1,
    };
    let ok = |w, r: &ResourceEnvelope, code, data, mem, entry| {
        TaskLayout::new(w, r, code, data, mem, entry)
    };
    let limit = Err(LoadError::Artifact(ArtifactError::ResourceLimit));
    let r = res(1, 1, 1);
    assert!(ok(1, &r, 8, 4, 4096, 4).is_ok());
    assert!(ok(255, &r, 8, 4, 4096, 0).is_ok());
    assert!(ok(1, &res(64, 64, 16), 64 * PAGE, 1, 64 * PAGE, 0).is_ok());
    assert_eq!(ok(0, &r, 8, 4, 4096, 0), limit);
    assert_eq!(ok(256, &r, 8, 4, 4096, 0), limit);
    for bad in [res(0, 1, 1), res(65, 1, 1), res(1, 0, 1), res(1, 65, 1), res(1, 1, 0), res(1, 1, 17)] {
        assert_eq!(ok(1, &bad, 8, 4, 4096, 0), limit, "{bad:?}");
    }
    assert_eq!(ok(1, &r, 0, 4, 4096, 0), limit, "empty code");
    assert_eq!(ok(1, &r, PAGE + 1, 4, 4096, 0), limit, "code overflows pages");
    assert_eq!(ok(1, &r, 8, 5, 4, 0), limit, "data longer than memory");
    assert_eq!(ok(1, &r, 8, 4, PAGE + 1, 0), limit, "data memory overflows pages");
    assert_eq!(ok(1, &r, 8, 4, 4096, 2), limit, "unaligned entry");
    assert_eq!(ok(1, &r, 8, 4, 4096, 8), limit, "entry at code end");
    assert_eq!(ok(1, &r, 8, 4, 4096, 12), limit, "entry past code");
}

// ---------------------------------------------------------------------------
// 7. Report lines
// ---------------------------------------------------------------------------

fn admitted_report(status: ExecutionStatus) -> CandidateReport {
    let mut r = empty_report(100);
    r.decision = Decision::Admitted;
    r.artifact_id = Some(ArtifactId([0xab; 32]));
    r.trust_tier = Some(TrustTier::Seed0bQualification);
    r.frames_reserved = 10;
    r.caps_installed = 1;
    r.byte_chain = true;
    r.wx_enforced = true;
    r.outcome = outcome(status);
    r.code_base = 0x80_0000_1000;
    r.code_end = 0x80_0000_2000;
    r
}

fn line(r: &CandidateReport) -> String {
    let mut s = String::new();
    write_candidate_line(&mut s, "P25EXEC.AIEN", r);
    s
}

#[test]
fn candidate_lines_are_stable() {
    let tail = "bytes=identified=verified=admitted=mapped=executed wx=enforced caps=1 revoked=yes reclaimed=yes frames=10\n";
    let head = "artifact: P25EXEC.AIEN admitted id=abababababababab tier=seed0b-test exec=";
    assert_eq!(
        line(&admitted_report(ExecutionStatus::Exited(0))),
        std::format!("{head}exited:0x0 {tail}")
    );
    assert_eq!(
        line(&admitted_report(ExecutionStatus::Timeout)),
        std::format!("{head}timeout {tail}")
    );
    // EC 0x24 (EL0 data abort), IL, WnR, permission fault level 3.
    let write_abort = 0x9200_004f;
    let code_write = ExecutionStatus::Fault {
        esr: write_abort,
        far: 0x80_0000_1008,
        elr: 0x80_0000_1004,
    };
    assert_eq!(
        line(&admitted_report(code_write)),
        std::format!("{head}fault:code-write {tail}")
    );
    let outside = ExecutionStatus::Fault {
        esr: write_abort,
        far: 0x80_0000_3008,
        elr: 0x80_0000_1004,
    };
    assert_eq!(
        line(&admitted_report(outside)),
        std::format!("{head}fault:other {tail}")
    );
    let read_abort = ExecutionStatus::Fault {
        esr: 0x9200_000f,
        far: 0x80_0000_1008,
        elr: 0x80_0000_1004,
    };
    assert_eq!(
        line(&admitted_report(read_abort)),
        std::format!("{head}fault:other {tail}")
    );
    assert_eq!(
        line(&admitted_report(ExecutionStatus::BadSyscall(9))),
        std::format!("{head}bad-syscall:9 {tail}")
    );
    assert_eq!(
        line(&admitted_report(ExecutionStatus::ResourceOverrun)),
        std::format!("{head}resource-overrun {tail}")
    );

    let mut rejected = empty_report(100);
    rejected.failed_stage = Some(CandidateState::Verified);
    rejected.error = Some(LoadError::Artifact(ArtifactError::BadSignature));
    assert_eq!(
        line(&rejected),
        "artifact: P25EXEC.AIEN rejected stage=verified reason=BadSignature reclaimed=yes\n"
    );
    rejected.failed_stage = Some(CandidateState::Reserved);
    rejected.error = Some(LoadError::NoFrames);
    rejected.frames_free_after = 99;
    assert_eq!(
        line(&rejected),
        "artifact: P25EXEC.AIEN rejected stage=reserved reason=NoFrames reclaimed=no\n"
    );
}

// ---------------------------------------------------------------------------
// 8. Sequential candidates
// ---------------------------------------------------------------------------

#[test]
fn sequential_candidates_reuse_resources_cleanly() {
    let a = anchors();
    let pol = policy();
    let mut run = Run::new(KernelMap::Blocks2M);
    let mut table_ids = Vec::new();
    for task_id in 1..=3u32 {
        let mut s = spec();
        s.data.push(task_id as u8); // distinct artifacts
        let bytes = pack_signed(&s, &TEST_SEED);
        let mut executor = exec(|ctx: TaskContext<'_>, _p: &mut MockPlatform| {
            table_ids.push(ctx.capabilities.id());
            outcome(ExecutionStatus::Exited(u64::from(task_id)))
        });
        let report = run.candidate(&bytes, &verifier(&a), &pol, &mut executor, task_id);
        assert_eq!(report.decision, Decision::Admitted);
        assert_eq!(
            report.outcome.status,
            ExecutionStatus::Exited(u64::from(task_id))
        );
        run.assert_clean(&report);
    }
    table_ids.sort_unstable();
    table_ids.dedup();
    assert_eq!(table_ids.len(), 3, "task principals must be distinct");
}
