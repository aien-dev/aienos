//! Command, transfer and event rings (xHCI 1.2 section 4.9).
//!
//! A producer ring (command or transfer) is written by software and consumed
//! by the controller; its last slot holds a Link TRB back to the start with
//! Toggle Cycle set. An event ring is written by the controller and consumed
//! by software; it has no Link TRB, so the consumer wraps and flips its cycle
//! state at the end of the single segment.
//!
//! Ownership of each TRB is carried by its cycle bit. The producer writes
//! dwords 0 to 2 first and the dword holding the cycle bit last, with a
//! barrier between, so the controller never sees a half-written TRB as valid.
//! The consumer reads the cycle bit first and the rest only after a barrier.
//! Cache maintenance for non-coherent DMA is the caller's job.

use super::trb::{Trb, CYCLE};
use crate::arch::aarch64::dmb;
use core::ptr::{read_volatile, write_volatile};

const TRB_BYTES: u64 = 16;

/// Software-produced ring (command ring or one endpoint's transfer ring).
///
/// The driver waits for each command or transfer to complete before pushing
/// the next, so the ring can never lap the controller.
pub struct ProducerRing {
    base: *mut Trb,
    len: usize,
    dma: u64,
    enqueue: usize,
    cycle: bool,
}

impl ProducerRing {
    /// Take over `len` TRBs at `base`, zero them and install the Link TRB.
    /// `None` when the ring is too short to hold a TRB and its link.
    ///
    /// # Safety
    /// `base` must be valid for reads and writes of `len` TRBs for as long as
    /// the ring is used, not accessed through any other path meanwhile, and
    /// `dma` must be the controller-visible address of `base`.
    pub unsafe fn new(base: *mut Trb, len: usize, dma: u64) -> Option<Self> {
        if len < 2 {
            return None;
        }
        for i in 0..len {
            // SAFETY: in bounds by the caller's contract.
            unsafe { write_volatile(base.add(i), Trb::default()) };
        }
        // The link starts with cycle 0: the controller (cycle 1) must not
        // follow it until the producer reaches it and hands it over.
        // SAFETY: `len - 1` is in bounds.
        unsafe { write_volatile(base.add(len - 1), Trb::link(dma)) };
        Some(Self {
            base,
            len,
            dma,
            enqueue: 0,
            cycle: true,
        })
    }

    /// Controller-visible address of the ring start.
    pub fn dma(&self) -> u64 {
        self.dma
    }

    /// Enqueue pointer with the producer cycle state in bit 0, the format of
    /// CRCR and of an endpoint context's TR Dequeue Pointer.
    pub fn dequeue_pointer(&self) -> u64 {
        (self.dma + self.enqueue as u64 * TRB_BYTES) | u64::from(self.cycle)
    }

    /// Write `trb` at the enqueue slot, owned by the controller, and return
    /// its controller-visible address (events name completed TRBs by it).
    pub fn push(&mut self, trb: Trb) -> u64 {
        let addr = self.dma + self.enqueue as u64 * TRB_BYTES;
        self.write_owned(self.enqueue, trb);
        self.enqueue += 1;
        if self.enqueue == self.len - 1 {
            // SAFETY: the link slot is in bounds.
            let link = unsafe { read_volatile(self.base.add(self.len - 1)) };
            self.write_owned(self.len - 1, link);
            self.enqueue = 0;
            self.cycle = !self.cycle;
        }
        addr
    }

    fn write_owned(&mut self, index: usize, trb: Trb) {
        let trb = trb.with_cycle(self.cycle);
        // SAFETY: `index < len` at every call site.
        let slot = unsafe { self.base.add(index) } as *mut u32;
        for i in 0..3 {
            // SAFETY: dwords 0..3 of an in-bounds TRB.
            unsafe { write_volatile(slot.add(i), trb.0[i]) };
        }
        dmb();
        // SAFETY: dword 3 of the same TRB.
        unsafe { write_volatile(slot.add(3), trb.0[3]) };
    }
}

/// Controller-produced event ring of one segment.
pub struct EventRing {
    base: *const Trb,
    len: usize,
    dma: u64,
    dequeue: usize,
    cycle: bool,
}

impl EventRing {
    /// Take over `len` TRBs at `base` and zero them. `None` when empty.
    ///
    /// # Safety
    /// As for [`ProducerRing::new`]: `base` valid for `len` TRBs for the
    /// ring's lifetime, written only by the controller afterwards, and `dma`
    /// its controller-visible address.
    pub unsafe fn new(base: *mut Trb, len: usize, dma: u64) -> Option<Self> {
        if len == 0 || len > u16::MAX as usize {
            return None;
        }
        for i in 0..len {
            // SAFETY: in bounds by the caller's contract.
            unsafe { write_volatile(base.add(i), Trb::default()) };
        }
        Some(Self {
            base,
            len,
            dma,
            dequeue: 0,
            cycle: true,
        })
    }

    /// The single Event Ring Segment Table entry describing this ring.
    pub fn segment_table_entry(&self) -> [u32; 4] {
        [self.dma as u32, (self.dma >> 32) as u32, self.len as u32, 0]
    }

    /// Address of the next event to consume, the value for ERDP.
    pub fn dequeue_pointer(&self) -> u64 {
        self.dma + self.dequeue as u64 * TRB_BYTES
    }

    /// The next event, if the controller has written one.
    pub fn pop(&mut self) -> Option<Trb> {
        // SAFETY: `dequeue < len`, in bounds by the constructor's contract.
        let slot = unsafe { self.base.add(self.dequeue) } as *const u32;
        // SAFETY: dword 3 of an in-bounds TRB.
        let control = unsafe { read_volatile(slot.add(3)) };
        if (control & CYCLE != 0) != self.cycle {
            return None;
        }
        dmb();
        let mut trb = Trb([0, 0, 0, control]);
        for i in 0..3 {
            // SAFETY: dwords 0..3 of the same TRB.
            trb.0[i] = unsafe { read_volatile(slot.add(i)) };
        }
        self.dequeue += 1;
        if self.dequeue == self.len {
            self.dequeue = 0;
            self.cycle = !self.cycle;
        }
        Some(trb)
    }
}

#[cfg(test)]
mod tests {
    use super::super::trb::{kind, TOGGLE_CYCLE};
    use super::*;

    /// Minimal model of the controller consuming a producer ring: follow
    /// TRBs while their cycle bit matches, obey Link TRBs and Toggle Cycle.
    struct Consumer {
        index: usize,
        cycle: bool,
    }

    impl Consumer {
        fn take(&mut self, ring: &[Trb]) -> Option<Trb> {
            loop {
                let trb = ring[self.index];
                if trb.cycle() != self.cycle {
                    return None;
                }
                if trb.kind() == kind::LINK {
                    assert_eq!(trb.pointer(), ring.as_ptr() as u64, "link targets start");
                    if trb.0[3] & TOGGLE_CYCLE != 0 {
                        self.cycle = !self.cycle;
                    }
                    self.index = 0;
                    continue;
                }
                self.index += 1;
                return Some(trb);
            }
        }
    }

    #[test]
    fn controller_sees_every_push_in_order_across_many_wraps() {
        let mut memory = [Trb::default(); 4];
        let dma = memory.as_ptr() as u64;
        // SAFETY: `memory` outlives the ring and is only read below.
        let mut ring = unsafe { ProducerRing::new(memory.as_mut_ptr(), 4, dma) }.unwrap();
        let mut consumer = Consumer {
            index: 0,
            cycle: true,
        };
        assert!(consumer.take(&memory).is_none(), "fresh ring is empty");
        for n in 0..20u32 {
            let expected = dma + 16 * (n as u64 % 3);
            assert_eq!(
                ring.push(Trb([n, 0, 0, u32::from(kind::NORMAL) << 10])),
                expected
            );
            let seen = consumer.take(&memory).expect("pushed TRB is visible");
            assert_eq!(seen.0[0], n);
            assert!(consumer.take(&memory).is_none(), "nothing beyond the push");
        }
    }

    #[test]
    fn dequeue_pointer_carries_the_cycle_state_and_flips_after_the_link() {
        let mut memory = [Trb::default(); 3];
        let dma = memory.as_ptr() as u64;
        // SAFETY: as above.
        let mut ring = unsafe { ProducerRing::new(memory.as_mut_ptr(), 3, dma) }.unwrap();
        assert_eq!(ring.dequeue_pointer(), dma | 1);
        ring.push(Trb::default());
        assert_eq!(ring.dequeue_pointer(), (dma + 16) | 1);
        ring.push(Trb::default());
        assert_eq!(ring.dequeue_pointer(), dma, "wrapped with cycle 0");
        assert!(memory[2].cycle(), "link handed over with the old cycle");
        assert!(unsafe { ProducerRing::new(memory.as_mut_ptr(), 1, dma) }.is_none());
    }

    #[test]
    fn event_ring_consumes_matching_cycles_and_wraps_without_a_link() {
        let mut memory = [Trb::default(); 3];
        let dma = memory.as_ptr() as u64;
        // SAFETY: the test plays the controller through `base` only.
        let base = memory.as_mut_ptr();
        let mut ring = unsafe { EventRing::new(base, 3, dma) }.unwrap();
        assert_eq!(
            ring.segment_table_entry(),
            [dma as u32, (dma >> 32) as u32, 3, 0]
        );
        let post = |i: usize, id: u32, cycle: bool| unsafe {
            base.add(i)
                .write_volatile(Trb([id, 0, 1 << 24, 33 << 10]).with_cycle(cycle));
        };
        assert!(ring.pop().is_none());
        for (i, id) in [(0, 10), (1, 11), (2, 12)] {
            post(i, id, true);
        }
        assert_eq!(ring.pop().unwrap().0[0], 10);
        assert_eq!(ring.dequeue_pointer(), dma + 16);
        assert_eq!(ring.pop().unwrap().0[0], 11);
        assert_eq!(ring.pop().unwrap().0[0], 12);
        assert_eq!(ring.dequeue_pointer(), dma, "wrapped at the segment end");
        // Old events (cycle 1) are not consumed twice after the wrap.
        assert!(ring.pop().is_none());
        post(0, 13, false);
        assert_eq!(ring.pop().unwrap().0[0], 13);
        assert!(ring.pop().is_none());
    }
}
