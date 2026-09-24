//! Host-testable NVMe register, queue, command, and PRP primitives.
//! This module performs no MMIO and owns no DMA memory.

use core::convert::TryInto;

pub const REG_CAP: u32 = 0x00;
pub const REG_VS: u32 = 0x08;
pub const REG_INTMS: u32 = 0x0c;
pub const REG_CC: u32 = 0x14;
pub const REG_CSTS: u32 = 0x1c;
pub const REG_AQA: u32 = 0x24;
pub const REG_ASQ: u32 = 0x28;
pub const REG_ACQ: u32 = 0x30;
pub const REG_DOORBELL: u32 = 0x1000;
pub const CC_EN: u32 = 1;
pub const CSTS_RDY: u32 = 1;
pub const CSTS_CFS: u32 = 1 << 1;

/// Abstracts 32-bit controller register accesses for a host fake or a later MMIO adapter.
pub trait Registers {
    fn read32(&mut self, offset: u32) -> u32;
    fn write32(&mut self, offset: u32, value: u32);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cap(pub u64);

impl Cap {
    pub const fn dstrd(self) -> u8 {
        ((self.0 >> 32) & 0xf) as u8
    }
    pub const fn doorbell_stride(self) -> u32 {
        4 << self.dstrd()
    }
    pub const fn mqes(self) -> u16 {
        (self.0 as u16).wrapping_add(1)
    }
    pub const fn timeout_units(self) -> u8 {
        ((self.0 >> 24) & 0xff) as u8
    }
}

pub const fn doorbell_offset(qid: u16, completion: bool, stride: u32) -> u32 {
    REG_DOORBELL + (2 * qid as u32 + completion as u32) * stride
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerError {
    Failed,
    Timeout,
}

/// Bounded state transitions. `polls` is the maximum number of CSTS reads per transition.
pub fn set_enabled<R: Registers>(
    r: &mut R,
    enable: bool,
    polls: usize,
) -> Result<(), ControllerError> {
    let mut cc = r.read32(REG_CC);
    if enable {
        cc |= CC_EN;
    } else {
        cc &= !CC_EN;
    }
    r.write32(REG_CC, cc);
    for _ in 0..polls {
        let status = r.read32(REG_CSTS);
        if status & CSTS_CFS != 0 {
            return Err(ControllerError::Failed);
        }
        if (status & CSTS_RDY != 0) == enable {
            return Ok(());
        }
    }
    Err(ControllerError::Timeout)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Submission(pub [u8; 64]);

impl Submission {
    pub const fn zeroed() -> Self {
        Self([0; 64])
    }
    pub fn set_u32(&mut self, dword: usize, value: u32) {
        self.0[dword * 4..dword * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    pub fn set_u64(&mut self, dword: usize, value: u64) {
        self.0[dword * 4..dword * 4 + 8].copy_from_slice(&value.to_le_bytes());
    }
    pub fn u32_at(&self, dword: usize) -> u32 {
        u32::from_le_bytes(self.0[dword * 4..dword * 4 + 4].try_into().unwrap())
    }
    pub fn identify_controller(prp1: u64) -> Self {
        identify(prp1, 1)
    }
    pub fn identify_namespace(nsid: u32, prp1: u64) -> Self {
        let mut c = identify(prp1, 0);
        c.set_u32(1, nsid);
        c
    }
    pub fn create_io_cq(qid: u16, depth: u16, prp1: u64, vector: u16) -> Self {
        let mut c = Self::zeroed();
        c.set_u32(0, 0x05);
        c.set_u32(6, prp1 as u32);
        c.set_u32(7, (prp1 >> 32) as u32);
        c.set_u32(10, qid as u32 | ((depth as u32 - 1) << 16));
        c.set_u32(11, 1 | (1 << 1) | ((vector as u32) << 16));
        c
    }
    pub fn create_io_sq(qid: u16, depth: u16, prp1: u64, cqid: u16) -> Self {
        let mut c = Self::zeroed();
        c.set_u32(0, 0x01);
        c.set_u32(6, prp1 as u32);
        c.set_u32(7, (prp1 >> 32) as u32);
        c.set_u32(10, qid as u32 | ((depth as u32 - 1) << 16));
        c.set_u32(11, (cqid as u32) | (1 << 16));
        c
    }
    pub fn read(nsid: u32, lba: u64, blocks: u16, prp1: u64, prp2: u64) -> Self {
        io_command(0x02, nsid, lba, blocks, prp1, prp2)
    }
    pub fn write(nsid: u32, lba: u64, blocks: u16, prp1: u64, prp2: u64) -> Self {
        io_command(0x01, nsid, lba, blocks, prp1, prp2)
    }
}

fn identify(prp1: u64, cns: u32) -> Submission {
    let mut c = Submission::zeroed();
    c.set_u32(0, 0x06);
    c.set_u32(6, prp1 as u32);
    c.set_u32(7, (prp1 >> 32) as u32);
    c.set_u32(10, cns);
    c
}
fn io_command(op: u32, nsid: u32, lba: u64, blocks: u16, p1: u64, p2: u64) -> Submission {
    let mut c = Submission::zeroed();
    c.set_u32(0, op);
    c.set_u32(1, nsid);
    c.set_u32(6, p1 as u32);
    c.set_u32(7, (p1 >> 32) as u32);
    c.set_u32(8, p2 as u32);
    c.set_u32(9, (p2 >> 32) as u32);
    c.set_u32(10, lba as u32);
    c.set_u32(11, (lba >> 32) as u32);
    c.set_u32(12, (blocks as u32).wrapping_sub(1));
    c
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completion(pub [u8; 16]);
impl Completion {
    pub fn result(&self) -> u32 {
        u32::from_le_bytes(self.0[0..4].try_into().unwrap())
    }
    pub fn sq_head(&self) -> u16 {
        u16::from_le_bytes(self.0[8..10].try_into().unwrap())
    }
    pub fn sq_id(&self) -> u16 {
        u16::from_le_bytes(self.0[10..12].try_into().unwrap())
    }
    pub fn command_id(&self) -> u16 {
        u16::from_le_bytes(self.0[12..14].try_into().unwrap())
    }
    pub fn status(&self) -> u16 {
        u16::from_le_bytes(self.0[14..16].try_into().unwrap())
    }
    pub fn phase(&self) -> bool {
        self.status() & 1 != 0
    }
}

/// Single-producer submission ring. One slot stays unused to distinguish full from empty.
pub struct SubmissionQueue<'a> {
    entries: &'a mut [Submission],
    tail: usize,
    head: usize,
}
impl<'a> SubmissionQueue<'a> {
    pub fn new(entries: &'a mut [Submission]) -> Self {
        Self {
            entries,
            tail: 0,
            head: 0,
        }
    }
    pub fn push(&mut self, entry: Submission) -> Result<usize, Submission> {
        if self.entries.len() < 2 {
            return Err(entry);
        }
        let next = (self.tail + 1) % self.entries.len();
        if next == self.head {
            return Err(entry);
        }
        let slot = self.tail;
        self.entries[slot] = entry;
        self.tail = next;
        Ok(slot)
    }
    pub fn head(&self) -> usize {
        self.head
    }
    pub fn tail(&self) -> usize {
        self.tail
    }
    pub fn set_head(&mut self, head: usize) {
        self.head = head % self.entries.len();
    }
}

/// Completion ring consumer, initialized to the inverted phase as required by NVMe.
pub struct CompletionQueue<'a> {
    entries: &'a [Completion],
    head: usize,
    phase: bool,
}
impl<'a> CompletionQueue<'a> {
    pub fn new(entries: &'a [Completion]) -> Self {
        Self {
            entries,
            head: 0,
            phase: true,
        }
    }
    pub fn poll(&mut self) -> Option<Completion> {
        if self.entries.is_empty() {
            return None;
        }
        let c = self.entries[self.head];
        if c.phase() != self.phase {
            return None;
        }
        self.head += 1;
        if self.head == self.entries.len() {
            self.head = 0;
            self.phase = !self.phase;
        }
        Some(c)
    }
    pub fn head(&self) -> usize {
        self.head
    }
    pub fn phase(&self) -> bool {
        self.phase
    }
}

/// Build PRP1/PRP2 and optional page-list entries for a transfer buffer.
/// `list` is caller-owned and must itself be DMA-addressable when used by a real adapter.
pub fn build_prps(
    address: u64,
    length: usize,
    page_size: usize,
    list_address: u64,
    list: &mut [u64],
) -> Result<(u64, u64, usize), PrpError> {
    if length == 0 || page_size == 0 || !page_size.is_power_of_two() {
        return Err(PrpError::Invalid);
    }
    let offset = address as usize & (page_size - 1);
    let covered = offset.checked_add(length).ok_or(PrpError::Invalid)?;
    let pages = covered
        .checked_add(page_size - 1)
        .ok_or(PrpError::Invalid)?
        / page_size;
    if pages == 1 {
        return Ok((address, 0, 0));
    }
    let second = (address & !((page_size as u64) - 1)) + page_size as u64;
    if pages == 2 {
        return Ok((address, second, 0));
    }
    let count = pages - 1;
    if list.len() < count {
        return Err(PrpError::ListTooSmall);
    }
    if list_address == 0 || list_address & (page_size as u64 - 1) != 0 {
        return Err(PrpError::Invalid);
    }
    for (i, slot) in list[..count].iter_mut().enumerate() {
        *slot = second + (i as u64) * page_size as u64;
    }
    Ok((address, list_address, count))
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrpError {
    Invalid,
    ListTooSmall,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    #[derive(Default)]
    struct Fake {
        cc: u32,
        statuses: std::vec::Vec<u32>,
        writes: std::vec::Vec<(u32, u32)>,
    }
    impl Registers for Fake {
        fn read32(&mut self, off: u32) -> u32 {
            if off == REG_CC {
                self.cc
            } else {
                self.statuses.remove(0)
            }
        }
        fn write32(&mut self, off: u32, value: u32) {
            self.writes.push((off, value));
            if off == REG_CC {
                self.cc = value;
            }
        }
    }

    #[test]
    fn registers_and_doorbells() {
        let cap = Cap((3u64 << 32) | 0xff);
        assert_eq!(cap.dstrd(), 3);
        assert_eq!(cap.doorbell_stride(), 32);
        assert_eq!(cap.mqes(), 256);
        assert_eq!(doorbell_offset(2, true, cap.doorbell_stride()), 0x10a0);
    }
    #[test]
    fn command_layouts() {
        let c = Submission::identify_controller(0x1122_3344_5566_7788);
        assert_eq!(c.u32_at(0), 6);
        assert_eq!(c.u32_at(6), 0x5566_7788);
        assert_eq!(c.u32_at(7), 0x1122_3344);
        let r = Submission::read(7, 0x1234_5678_9abc_def0, 2, 0x1000, 0x2000);
        assert_eq!(r.u32_at(0), 2);
        assert_eq!(r.u32_at(1), 7);
        assert_eq!(r.u32_at(10), 0x9abc_def0);
        assert_eq!(r.u32_at(11), 0x1234_5678);
        assert_eq!(r.u32_at(12), 1);
        assert_eq!(Submission::write(1, 0, 1, 0, 0).u32_at(0), 1);
        assert_eq!(
            Submission::create_io_cq(3, 8, 0x4000, 2).u32_at(10),
            3 | (7 << 16)
        );
        assert_eq!(
            Submission::create_io_sq(4, 16, 0x5000, 3).u32_at(11),
            3 | (1 << 16)
        );
    }
    #[test]
    fn submission_full_and_wrap() {
        let mut mem = vec![Submission::zeroed(); 3];
        let mut q = SubmissionQueue::new(&mut mem);
        assert_eq!(q.push(Submission::zeroed()), Ok(0));
        assert_eq!(q.push(Submission::zeroed()), Ok(1));
        assert!(q.push(Submission::zeroed()).is_err());
        q.set_head(1);
        assert_eq!(q.push(Submission::zeroed()), Ok(2));
        assert_eq!(q.tail(), 0);
    }
    #[test]
    fn completion_phase_wrap_and_empty() {
        let mut mem = vec![Completion([0; 16]); 2];
        mem[0].0[14..16].copy_from_slice(&1u16.to_le_bytes());
        mem[1].0[14..16].copy_from_slice(&1u16.to_le_bytes());
        let mut q = CompletionQueue::new(&mem);
        assert!(q.poll().is_some());
        assert!(q.poll().is_some());
        assert!(!q.phase());
        assert!(q.poll().is_none());
    }
    #[test]
    fn prp_spans() {
        let mut list = [0; 4];
        assert_eq!(
            build_prps(0x1080, 100, 4096, 0x8000, &mut list).unwrap(),
            (0x1080, 0, 0)
        );
        assert_eq!(
            build_prps(0x1080, 4096, 4096, 0x8000, &mut list).unwrap(),
            (0x1080, 0x2000, 0)
        );
        let (p1, lp, n) = build_prps(0x1080, 9000, 4096, 0x8000, &mut list).unwrap();
        assert_eq!((p1, n), (0x1080, 2));
        assert_eq!(lp, 0x8000);
        assert_eq!(list[..2], [0x2000, 0x3000]);
        assert_eq!(
            build_prps(0x1000, 12000, 4096, 0x8000, &mut [0; 1]),
            Err(PrpError::ListTooSmall)
        );
    }
    #[test]
    fn controller_ready_failure_and_timeout() {
        let mut ok = Fake {
            statuses: vec![0, CSTS_RDY],
            ..Fake::default()
        };
        assert_eq!(set_enabled(&mut ok, true, 2), Ok(()));
        assert_eq!(ok.writes[0], (REG_CC, CC_EN));
        let mut fail = Fake {
            statuses: vec![CSTS_CFS],
            ..Fake::default()
        };
        assert_eq!(
            set_enabled(&mut fail, true, 3),
            Err(ControllerError::Failed)
        );
        let mut timeout = Fake {
            statuses: vec![0, 0],
            ..Fake::default()
        };
        assert_eq!(
            set_enabled(&mut timeout, true, 2),
            Err(ControllerError::Timeout)
        );
    }
}
