//! D3 adversarial PRP tests for the AIENOS P3 native NVMe read substrate.
//!
//! External integration test crate. Baseline: aien-dev/aienos @ ff5de9c.
//! Exercises `aienos_kernel::nvme::build_prps` against the documented PRP
//! contract with exact expected values, including boundary, overflow, list
//! chaining, and 64 KiB page geometry.

use aienos_kernel::nvme::{build_prps, PrpError};

const P4K: usize = 4096;
const P64K: usize = 65536;

#[test]
fn invalid_zero_length_and_page_size() {
    assert_eq!(
        build_prps(0x1000, 0, P4K, 0x8000, &mut [0u64; 4]),
        Err(PrpError::Invalid)
    );
    assert_eq!(
        build_prps(0x1000, 100, 0, 0x8000, &mut [0u64; 4]),
        Err(PrpError::Invalid)
    );
    assert_eq!(
        build_prps(0, usize::MAX, 0, 0, &mut [0u64; 4]),
        Err(PrpError::Invalid)
    );
}

#[test]
fn invalid_non_power_of_two_page_size() {
    for ps in [3usize, 1000, 3000, 4097, 8191] {
        let mut list = [0u64; 4];
        assert_eq!(
            build_prps(0x1000, 100, ps, 0x8000, &mut list),
            Err(PrpError::Invalid),
            "page_size {ps} must be rejected"
        );
    }
}

#[test]
fn offset_plus_length_overflow_is_invalid() {
    let mut list = [0u64; 4];
    assert_eq!(
        build_prps(usize::MAX as u64, usize::MAX, P4K, 0x8000, &mut list),
        Err(PrpError::Invalid)
    );
    assert_eq!(
        build_prps(1, usize::MAX, P4K, 0x8000, &mut list),
        Err(PrpError::Invalid)
    );
    assert_eq!(
        build_prps(0, usize::MAX, P4K, 0x8000, &mut list),
        Err(PrpError::Invalid)
    );
}

#[test]
fn max_address_short_length_is_invalid_without_panic() {
    // Regression test for the end-address overflow fix: address = usize::MAX,
    // length = 2 computes pages == 2, and the second data page would overflow
    // u64. It must be rejected as Invalid with no panic and no wrap.
    let outcome = std::panic::catch_unwind(|| {
        let mut list = [0u64; 0];
        build_prps(usize::MAX as u64, 2, P4K, 0, &mut list)
    });
    match outcome {
        Ok(result) => assert_eq!(
            result,
            Err(PrpError::Invalid),
            "address=usize::MAX length=2 must be Invalid, got {result:?}"
        ),
        Err(_) => {
            panic!("address=usize::MAX length=2 panicked; expected Err(Invalid) with no panic")
        }
    }
}

#[test]
fn single_page_aligned_and_unaligned() {
    let mut list = [0u64; 0];
    assert_eq!(
        build_prps(0x1000, P4K, P4K, 0x8000, &mut list).unwrap(),
        (0x1000, 0, 0)
    );
    assert_eq!(
        build_prps(0x1080, 100, P4K, 0x8000, &mut list).unwrap(),
        (0x1080, 0, 0)
    );
    assert_eq!(
        build_prps(0x1FFF, 1, P4K, 0, &mut list).unwrap(),
        (0x1FFF, 0, 0)
    );
    assert_eq!(build_prps(0, P4K, P4K, 0, &mut list).unwrap(), (0, 0, 0));
}

#[test]
fn one_page_boundary_crossing() {
    let mut list = [0u64; 0];
    assert_eq!(
        build_prps(0x1000, P4K, P4K, 0x8000, &mut list).unwrap(),
        (0x1000, 0, 0)
    );
    assert_eq!(
        build_prps(0x1080, P4K, P4K, 0x8000, &mut list).unwrap(),
        (0x1080, 0x2000, 0)
    );
}

#[test]
fn two_pages_use_prp2_with_zero_used() {
    let mut list = [0u64; 0];
    assert_eq!(
        build_prps(0x1000, 2 * P4K, P4K, 0x8000, &mut list).unwrap(),
        (0x1000, 0x2000, 0)
    );
    assert_eq!(
        build_prps(0x1080, 7680, P4K, 0, &mut list).unwrap(),
        (0x1080, 0x2000, 0)
    );
    // PRP1 is the raw input, unmodified even when unaligned. One page of
    // length from an unaligned start spans exactly two pages.
    assert_eq!(
        build_prps(0x1ABC, P4K, P4K, 0, &mut list).unwrap(),
        (0x1ABC, 0x2000, 0)
    );
}

#[test]
fn multi_page_requires_aligned_nonzero_list() {
    let mut list = [0u64; 4];
    assert_eq!(
        build_prps(0x1000, 3 * P4K, P4K, 0, &mut list),
        Err(PrpError::Invalid)
    );
    assert_eq!(
        build_prps(0x1000, 3 * P4K, P4K, 0x8001, &mut list),
        Err(PrpError::Invalid)
    );
    assert_eq!(
        build_prps(0x1000, 3 * P4K, P4K, 0xFFF, &mut list),
        Err(PrpError::Invalid)
    );
    assert_eq!(
        build_prps(0x1000, 3 * P4K, P4K, 0x8000, &mut list).unwrap(),
        (0x1000, 0x8000, 2)
    );
    assert_eq!(list[..2], [0x2000, 0x3000]);

    let mut four = [0u64; 3];
    assert_eq!(
        build_prps(0x1000, 4 * P4K, P4K, 0x8000, &mut four).unwrap(),
        (0x1000, 0x8000, 3)
    );
    assert_eq!(four, [0x2000, 0x3000, 0x4000]);
}

#[test]
fn list_buffer_too_small_is_bounded() {
    let mut one = [0u64; 1];
    assert_eq!(
        build_prps(0x1000, 3 * P4K, P4K, 0x8000, &mut one),
        Err(PrpError::ListTooSmall)
    );

    let mut two = [0u64; 2];
    assert_eq!(
        build_prps(0x1000, 4 * P4K, P4K, 0x8000, &mut two),
        Err(PrpError::ListTooSmall)
    );
    assert_eq!(two, [0x2000, 0x3000]);

    let mut three = [0u64; 3];
    assert_eq!(
        build_prps(0x1000, 5 * P4K, P4K, 0x8000, &mut three),
        Err(PrpError::ListTooSmall)
    );
    assert_eq!(three, [0x2000, 0x3000, 0x4000]);
}

#[test]
fn list_page_chaining_4k_exact_used() {
    const PER: usize = P4K / 8;
    let list_at = 0x80_0000u64;

    let mut full = vec![0u64; 2 * PER];
    let (p1, p2, used) = build_prps(0x1000, (1 + PER) * P4K, P4K, list_at, &mut full).unwrap();
    assert_eq!((p1, p2, used), (0x1000, list_at, PER));
    assert_eq!(full[PER - 1], 0x2000 + ((PER - 1) * P4K) as u64);

    let mut chain = vec![0u64; 2 * PER];
    let (p1, p2, used) = build_prps(0x1000, (2 + PER) * P4K, P4K, list_at, &mut chain).unwrap();
    assert_eq!((p1, p2, used), (0x1000, list_at, PER + 2));
    assert_eq!(chain[PER - 1], list_at + P4K as u64);
    assert_eq!(chain[PER - 2], 0x2000 + ((PER - 2) * P4K) as u64);
    assert_eq!(chain[PER], 0x2000 + ((PER - 1) * P4K) as u64);
    assert_eq!(chain[PER + 1], 0x2000 + (PER * P4K) as u64);

    let mut short = vec![0u64; PER];
    assert_eq!(
        build_prps(0x1000, (2 + PER) * P4K, P4K, list_at, &mut short),
        Err(PrpError::ListTooSmall)
    );
}

#[test]
fn list_page_chaining_64k_exact_used() {
    const PER: usize = P64K / 8;
    let list_at = 0x200_0000u64;

    let mut fits = vec![0u64; PER];
    let (p1, p2, used) = build_prps(0x10000, (1 + PER) * P64K, P64K, list_at, &mut fits).unwrap();
    assert_eq!((p1, p2, used), (0x10000, list_at, PER));
    assert_eq!(fits[PER - 1], 0x20000 + ((PER - 1) * P64K) as u64);

    let mut chain = vec![0u64; PER + 2];
    let (p1, p2, used) = build_prps(0x10000, (2 + PER) * P64K, P64K, list_at, &mut chain).unwrap();
    assert_eq!((p1, p2, used), (0x10000, list_at, PER + 2));
    assert_eq!(chain[PER - 1], list_at + P64K as u64);
    assert_eq!(chain[PER - 2], 0x20000 + ((PER - 2) * P64K) as u64);
    assert_eq!(chain[PER], 0x20000 + ((PER - 1) * P64K) as u64);
    assert_eq!(chain[PER + 1], 0x20000 + (PER * P64K) as u64);

    let mut small = vec![0u64; 4];
    assert_eq!(
        build_prps(
            0x10000,
            (2 + PER) * P64K,
            P64K,
            list_at + 0x1000,
            &mut small
        ),
        Err(PrpError::Invalid)
    );
}

#[test]
fn page_boundaries_64k() {
    let mut list = [0u64; 0];
    assert_eq!(
        build_prps(0x10000, P64K, P64K, 0, &mut list).unwrap(),
        (0x10000, 0, 0)
    );
    assert_eq!(
        build_prps(0x10080, 100, P64K, 0, &mut list).unwrap(),
        (0x10080, 0, 0)
    );
    assert_eq!(
        build_prps(0x10080, P64K, P64K, 0, &mut list).unwrap(),
        (0x10080, 0x20000, 0)
    );
    assert_eq!(
        build_prps(0x10000, 2 * P64K, P64K, 0, &mut list).unwrap(),
        (0x10000, 0x20000, 0)
    );
}

#[test]
fn transfer_limit_arithmetic_is_bounded() {
    let mut list = [0u64; 8];
    let huge = (1usize << 40).checked_mul(4096).expect("64-bit host");
    assert_eq!(
        build_prps(0, huge, P4K, 0x8000, &mut list),
        Err(PrpError::ListTooSmall)
    );
    assert_eq!(
        build_prps(0, usize::MAX, P4K, 0x8000, &mut list),
        Err(PrpError::Invalid)
    );
    assert_eq!(
        build_prps(0, usize::MAX - 100, P4K, 0x8000, &mut list),
        Err(PrpError::Invalid)
    );
    assert_eq!(
        build_prps(usize::MAX as u64, usize::MAX, P4K, 0x8000, &mut list),
        Err(PrpError::Invalid)
    );
}

#[test]
fn prp_values_are_full_physical_addresses() {
    let high = 0x1_2345_6000u64;
    assert!(high > u32::MAX as u64);
    let mut list = [0u64; 4];

    assert_eq!(
        build_prps(high, P4K, P4K, 0, &mut list).unwrap(),
        (high, 0, 0)
    );
    assert_eq!(
        build_prps(high, 2 * P4K, P4K, 0, &mut list).unwrap(),
        (high, high + P4K as u64, 0)
    );

    let list_at = 0x2_0000_0000u64;
    assert!(list_at > u32::MAX as u64);
    let (p1, p2, used) = build_prps(high, 3 * P4K, P4K, list_at, &mut list).unwrap();
    assert_eq!((p1, p2, used), (high, list_at, 2));
    assert_eq!(list[..2], [high + P4K as u64, high + 2 * P4K as u64]);
    assert!(p1 > u32::MAX as u64);
    assert!(p2 > u32::MAX as u64);

    assert_eq!(
        build_prps(0x1080, P4K, P4K, 0, &mut list).unwrap().0,
        0x1080
    );
}
