//! Pure architectural timer arithmetic and injectable EL1 register access.

/// Convert nanoseconds to counter ticks, rounding up so a requested delay is not shortened.
pub const fn ns_to_ticks(ns: u64, frequency_hz: u64) -> Option<u64> {
    if frequency_hz == 0 {
        return None;
    }
    let product = (ns as u128) * (frequency_hz as u128);
    let ticks = product.saturating_add(999_999_999) / 1_000_000_000;
    if ticks > u64::MAX as u128 {
        None
    } else {
        Some(ticks as u64)
    }
}

/// Convert counter ticks to nanoseconds, truncating sub-nanosecond fractions.
pub const fn ticks_to_ns(ticks: u64, frequency_hz: u64) -> Option<u64> {
    if frequency_hz == 0 {
        return None;
    }
    let ns = (ticks as u128) * 1_000_000_000 / frequency_hz as u128;
    if ns > u64::MAX as u128 {
        None
    } else {
        Some(ns as u64)
    }
}

/// Return the absolute counter deadline after `delay_ns`, with checked overflow.
pub const fn deadline_after(now: u64, delay_ns: u64, frequency_hz: u64) -> Option<u64> {
    match ns_to_ticks(delay_ns, frequency_hz) {
        Some(delta) => now.checked_add(delta),
        None => None,
    }
}

/// Architectural EL1 physical counter and timer access.
pub trait TimerRegisters {
    fn frequency(&self) -> u64;
    fn counter(&self) -> u64;
    fn set_compare(&mut self, deadline: u64);
    fn enable_timer(&mut self, enabled: bool);
}

/// AArch64 EL1 physical timer access. EL2 bootstrap must grant EL1 timer access.
#[cfg(target_arch = "aarch64")]
pub struct Aarch64TimerRegisters;
#[cfg(target_arch = "aarch64")]
impl TimerRegisters for Aarch64TimerRegisters {
    fn frequency(&self) -> u64 {
        let value;
        unsafe {
            core::arch::asm!("mrs {0}, cntfrq_el0", out(reg) value, options(nomem, nostack));
        }
        value
    }
    fn counter(&self) -> u64 {
        let value;
        unsafe {
            core::arch::asm!("mrs {0}, cntpct_el0", out(reg) value, options(nomem, nostack));
        }
        value
    }
    fn set_compare(&mut self, deadline: u64) {
        unsafe {
            core::arch::asm!("msr cntp_cval_el0, {0}", "isb", in(reg) deadline, options(nostack));
        }
    }
    fn enable_timer(&mut self, enabled: bool) {
        let control = u64::from(enabled);
        unsafe {
            core::arch::asm!("msr cntp_ctl_el0, {0}", "isb", in(reg) control, options(nostack));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn conversion_rounding_and_frequency_validation() {
        assert_eq!(ns_to_ticks(1, 1_000_000), Some(1));
        assert_eq!(ns_to_ticks(1_000, 1_000_000), Some(1));
        assert_eq!(ticks_to_ns(1_000, 1_000_000), Some(1_000_000));
        assert_eq!(ns_to_ticks(1, 0), None);
    }
    #[test]
    fn deadline_detects_overflow() {
        assert_eq!(deadline_after(50, 10, 1_000_000_000), Some(60));
        assert_eq!(deadline_after(u64::MAX, 1, 1_000_000_000), None);
        assert_eq!(deadline_after(0, u64::MAX, u64::MAX), None);
    }
}
