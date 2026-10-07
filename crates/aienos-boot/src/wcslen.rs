//! `wcslen` for the UEFI target.
//!
//! Since rustc 1.99 (LLVM 23) the loop-idiom pass turns any "count 16-bit
//! units until zero" loop into a call to `wcslen`, and the UEFI targets ship
//! no C library to provide it (rust-lang/rust#160827, #163614). The `uefi`
//! crate has such loops (`proto::shell`, `proto::driver::component_name`),
//! so every image that links it fails with `undefined symbol: wcslen`.
//!
//! This defines the symbol for the UEFI target only. The counting loop uses
//! volatile reads so LLVM cannot turn the body of `wcslen` back into a call
//! to itself.

/// Number of `u16` units before the first zero unit.
///
/// # Safety
/// `s` must point to a readable, zero-terminated run of `u16`.
pub unsafe fn wide_len(s: *const u16) -> usize {
    let mut n = 0usize;
    // SAFETY: the caller guarantees the run is readable up to its terminator.
    while unsafe { core::ptr::read_volatile(s.add(n)) } != 0 {
        n += 1;
    }
    n
}

/// C `wcslen` for a 16-bit `wchar_t` (the UEFI ABI). Only for target_os = "uefi".
///
/// # Safety
/// `s` must point to a readable, zero-terminated run of `u16`.
#[cfg(target_os = "uefi")]
#[no_mangle]
pub unsafe extern "C" fn wcslen(s: *const u16) -> usize {
    // SAFETY: same contract as this function's.
    unsafe { wide_len(s) }
}

#[cfg(test)]
mod tests {
    use super::wide_len;

    fn len(v: &[u16]) -> usize {
        unsafe { wide_len(v.as_ptr()) }
    }

    #[test]
    fn empty_string_is_zero() {
        assert_eq!(len(&[0]), 0);
    }

    #[test]
    fn counts_units_before_first_zero() {
        assert_eq!(len(&[b'a' as u16, b'b' as u16, b'c' as u16, 0]), 3);
    }

    #[test]
    fn stops_at_first_zero_not_slice_end() {
        assert_eq!(len(&[1, 2, 0, 3, 4, 0]), 2);
    }

    #[test]
    fn high_unit_values_are_not_terminators() {
        assert_eq!(len(&[0xFFFF, 0x8000, 0x0100, 0xD800, 0]), 4);
    }
}
