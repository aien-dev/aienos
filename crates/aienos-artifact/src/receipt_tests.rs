//! Admission Receipt v0 tests: layout, golden bytes, strict decoding,
//! mutation and signature behaviour.

use std::vec::Vec;

use ed25519_dalek::{Signer, SigningKey};

use crate::error::ArtifactError;
use crate::receipt::*;
use crate::signature::{Ed25519Verifier, ReceiptSigner};
use aienos_crypto::sha256::{hash, Digest};

/// RFC 8032 TEST 2 seed: TEST-ONLY receipt key for SEED-0B qualification.
const TEST2_SEED: [u8; 32] = [
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
];
/// RFC 8032 TEST 3 seed: a key no receipt anchor trusts.
const TEST3_SEED: [u8; 32] = [
    0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc, 0xb7, 0xb1,
    0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44, 0x58, 0xf7,
];

struct KeySigner(SigningKey);

impl ReceiptSigner for KeySigner {
    fn signer_fingerprint(&self) -> Digest {
        hash(&self.0.verifying_key().to_bytes())
    }
    fn sign_receipt_digest(&self, digest: &Digest) -> Result<[u8; 64], ArtifactError> {
        Ok(self.0.sign(&signature_message(digest)).to_bytes())
    }
}

struct OneKey([u8; 32]);

impl ReceiptAnchorSet for OneKey {
    fn find(&self, fingerprint: &Digest) -> Option<[u8; 32]> {
        (hash(&self.0) == *fingerprint).then_some(self.0)
    }
}

fn pattern(seed: u8) -> Digest {
    let mut d = [0u8; 32];
    for (i, b) in d.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    d
}

fn admitted() -> Receipt {
    let verifier_identity = pattern(0x80);
    Receipt {
        flags: 0,
        decision: ReceiptDecision::Admitted,
        tier: QualificationTier::Seed0bQemu,
        sequence: 1,
        nonce: receipt_nonce(&verifier_identity, 1),
        observed_time_ns: 0,
        execution_status: ExecutionStatusCode::Exited,
        exit_status: 0,
        result_flags: RESULT_READ_OK
            | RESULT_WRITE_DENIED
            | RESULT_RECLAIMED
            | RESULT_CANARY_PASSED
            | RESULT_FORGED_DENIED
            | RESULT_MAPPED_BYTES_MATCH
            | RESULT_EXECUTED_BYTES_MATCH
            | RESULT_WX_SEALED,
        rejection_stage: 0,
        rejection_reason: 0,
        syscalls: 8,
        object_reads_ok: 2,
        denials: 5,
        frames_reserved: 10,
        artifact_id: pattern(0x10),
        payload_digest: pattern(0x20),
        artifact_signer_fingerprint: pattern(0x30),
        policy_digest: pattern(0x40),
        requested_capability_digest: pattern(0x50),
        granted_capability_digest: pattern(0x60),
        resource_envelope_digest: pattern(0x70),
        verifier_identity,
        machine_id_digest: [0; 32],
        generation: 0,
        context_id: 0,
    }
}

fn rejected() -> Receipt {
    let verifier_identity = pattern(0x80);
    Receipt {
        decision: ReceiptDecision::Rejected,
        sequence: 2,
        nonce: receipt_nonce(&verifier_identity, 2),
        execution_status: ExecutionStatusCode::NotRun,
        exit_status: 0,
        result_flags: RESULT_RECLAIMED,
        rejection_stage: 3,
        rejection_reason: ArtifactError::BadSignature as u16,
        syscalls: 0,
        object_reads_ok: 0,
        denials: 0,
        frames_reserved: 0,
        artifact_signer_fingerprint: [0; 32],
        granted_capability_digest: [0; 32],
        ..admitted()
    }
}

fn signed(r: &Receipt, seed: &[u8; 32]) -> [u8; RECEIPT_SIZE] {
    let mut bytes = encode(r);
    sign(&mut bytes, &KeySigner(SigningKey::from_bytes(seed))).unwrap();
    bytes
}

fn hex(bytes: &[u8]) -> std::string::String {
    use core::fmt::Write;
    let mut s = std::string::String::new();
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

#[test]
fn layout_matches_adr_table_offsets() {
    let r = admitted();
    let b = encode(&r);
    assert_eq!(&b[0..8], b"AIENRCP\0");
    assert_eq!(le16(&b, 8), 0);
    assert_eq!(le16(&b, 10), 96);
    assert_eq!(le32(&b, 12), 512);
    assert_eq!(le32(&b, 16), 0);
    assert_eq!(le16(&b, 20), 1);
    assert_eq!(le16(&b, 22), 1);
    assert_eq!(&b[24..32], &1u64.to_le_bytes());
    assert_eq!(&b[32..48], &r.nonce);
    assert!(b[48..64].iter().all(|x| *x == 0));
    assert_eq!(le32(&b, 64), 1);
    assert_eq!(le32(&b, 68), 0);
    assert_eq!(le32(&b, 72), 0xff);
    assert_eq!((le16(&b, 76), le16(&b, 78)), (0, 0));
    assert_eq!(
        (le32(&b, 80), le32(&b, 84), le32(&b, 88), le32(&b, 92)),
        (8, 2, 5, 10)
    );
    for (at, seed) in [
        (96, 0x10),
        (128, 0x20),
        (160, 0x30),
        (192, 0x40),
        (224, 0x50),
        (256, 0x60),
        (288, 0x70),
        (320, 0x80),
    ] {
        assert_eq!(&b[at..at + 32], &pattern(seed), "digest at {at}");
    }
    assert!(
        b[352..].iter().all(|x| *x == 0),
        "absent fields and signature block"
    );
    let exit = Receipt {
        execution_status: ExecutionStatusCode::Exited,
        exit_status: -2,
        result_flags: 0,
        ..r
    };
    assert_eq!(&encode(&exit)[68..72], &(-2i32).to_le_bytes());
}

#[test]
fn golden_bytes_are_stable() {
    let a = encode(&admitted());
    let r = encode(&rejected());
    assert_eq!(
        hex(&receipt_digest(&a)),
        GOLDEN_ADMITTED_DIGEST,
        "admitted record: {}",
        hex(&a)
    );
    assert_eq!(hex(&a), GOLDEN_ADMITTED_RECORD);
    assert_eq!(
        hex(&receipt_digest(&r)),
        GOLDEN_REJECTED_DIGEST,
        "rejected record: {}",
        hex(&r)
    );
}

#[test]
fn encoding_is_deterministic_and_round_trips() {
    for r in [admitted(), rejected()] {
        let first = encode(&r);
        assert_eq!(first, encode(&r));
        assert_eq!(decode(&first), Ok(r));
        let s = signed(&r, &TEST2_SEED);
        assert_eq!(decode(&s), Ok(r));
        assert_eq!(receipt_digest(&first), receipt_digest(&s));
    }
}

#[test]
fn nonce_and_verifier_identity_vectors() {
    let id = pattern(0x80);
    assert_ne!(receipt_nonce(&id, 1), receipt_nonce(&id, 2));
    assert_ne!(receipt_nonce(&id, 1), receipt_nonce(&pattern(0x81), 1));
    let commit = b"71cb1703484cbc9d56eabe43402a6f9bf62b1028";
    let bytes = verifier_identity_bytes(commit, 1, 1, 1).unwrap();
    assert_eq!(&bytes[..40], commit);
    assert_eq!(&bytes[40..], &[1, 0, 1, 0, 1]);
    assert!(
        verifier_identity_bytes(b"71CB1703484CBC9D56EABE43402A6F9BF62B1028", 1, 1, 1).is_none()
    );
    assert!(verifier_identity_bytes(&commit[..39], 1, 1, 1).is_none());
    assert!(
        verifier_identity_bytes(b"71cb1703484cbc9d56eabe43402a6f9bf62b102g", 1, 1, 1).is_none()
    );
}

#[test]
fn rejects_length_magic_version_and_sizes() {
    let b = encode(&admitted());
    assert_eq!(decode(&b[..511]), Err(ArtifactError::Truncated));
    assert_eq!(decode(&[]), Err(ArtifactError::Truncated));
    let mut long = b.to_vec();
    long.push(0);
    assert_eq!(decode(&long), Err(ArtifactError::WrongLength));
    let set = |at: usize, v: u8| {
        let mut m = b;
        m[at] = v;
        m
    };
    assert_eq!(decode(&set(0, b'X')), Err(ArtifactError::BadMagic));
    assert_eq!(decode(&set(8, 1)), Err(ArtifactError::UnsupportedVersion));
    assert_eq!(decode(&set(10, 95)), Err(ArtifactError::UnsupportedVersion));
    assert_eq!(decode(&set(13, 0)), Err(ArtifactError::UnsupportedVersion));
}

#[test]
fn rejects_unknown_flags_and_nonzero_reserved_bytes() {
    let b = encode(&admitted());
    for bit in 3..32 {
        let mut m = b;
        m[16..20].copy_from_slice(&(1u32 << bit).to_le_bytes());
        assert_eq!(
            decode(&m),
            Err(ArtifactError::UnsupportedFlags),
            "flag bit {bit}"
        );
    }
    for bit in 8..32 {
        let mut m = b;
        m[72..76].copy_from_slice(&(0xffu32 | (1 << bit)).to_le_bytes());
        assert_eq!(
            decode(&m),
            Err(ArtifactError::UnsupportedFlags),
            "result bit {bit}"
        );
    }
    for at in (56..64).chain(500..512) {
        let mut m = b;
        m[at] = 1;
        assert_eq!(
            decode(&m),
            Err(ArtifactError::ReservedNonZero),
            "reserved {at}"
        );
    }
    let mut s = signed(&admitted(), &TEST2_SEED);
    s[402] = 1;
    assert_eq!(decode(&s), Err(ArtifactError::ReservedNonZero));
    let mut s = signed(&admitted(), &TEST2_SEED);
    s[400] = 2;
    assert_eq!(decode(&s), Err(ArtifactError::BadSignatureFormat));
}

#[test]
fn rejects_unknown_enum_and_code_values() {
    let b = encode(&admitted());
    let m16 = |at: usize, v: u16| {
        let mut m = b;
        m[at..at + 2].copy_from_slice(&v.to_le_bytes());
        m
    };
    for v in [0u16, 5, 0xffff] {
        assert_eq!(
            decode(&m16(20, v)),
            Err(ArtifactError::MalformedReceipt),
            "decision {v}"
        );
    }
    for v in [0u16, 3, 0xffff] {
        assert_eq!(
            decode(&m16(22, v)),
            Err(ArtifactError::MalformedReceipt),
            "tier {v}"
        );
    }
    for v in [7u32, 0xffff_ffff] {
        let mut m = b;
        m[64..68].copy_from_slice(&v.to_le_bytes());
        assert_eq!(
            decode(&m),
            Err(ArtifactError::MalformedReceipt),
            "status {v}"
        );
    }
    let base = rejected();
    for stage in [0u16, 10, 0xffff] {
        let r = Receipt {
            rejection_stage: stage,
            ..base
        };
        assert_eq!(
            decode(&encode(&r)),
            Err(ArtifactError::MalformedReceipt),
            "stage {stage}"
        );
    }
    for reason in [0u16, 20, 0x100, 0x10b, 0xffff] {
        let r = Receipt {
            rejection_reason: reason,
            ..base
        };
        assert_eq!(
            decode(&encode(&r)),
            Err(ArtifactError::MalformedReceipt),
            "reason {reason}"
        );
    }
    for reason in (1u16..=19).chain(0x101..=0x10a) {
        let r = Receipt {
            rejection_reason: reason,
            ..base
        };
        assert_eq!(decode(&encode(&r)), Ok(r), "valid reason {reason}");
    }
}

#[test]
fn optional_fields_require_their_presence_flags() {
    let base = admitted();
    let cases = [
        Receipt {
            machine_id_digest: pattern(1),
            ..base
        },
        Receipt {
            generation: 1,
            ..base
        },
        Receipt {
            context_id: 1,
            ..base
        },
        Receipt {
            observed_time_ns: 1,
            ..base
        },
    ];
    for r in cases {
        assert_eq!(decode(&encode(&r)), Err(ArtifactError::MalformedReceipt));
    }
    let present = Receipt {
        flags: VALID_FLAGS,
        machine_id_digest: pattern(1),
        generation: 3,
        context_id: 4,
        observed_time_ns: 5,
        ..base
    };
    assert_eq!(decode(&encode(&present)), Ok(present));
}

#[test]
fn decision_consistency_rules_are_enforced() {
    let a = admitted();
    let r = rejected();
    let bad = [
        Receipt {
            rejection_stage: 3,
            rejection_reason: 18,
            ..a
        },
        Receipt {
            rejection_reason: 18,
            ..a
        },
        Receipt {
            execution_status: ExecutionStatusCode::Exited,
            ..r
        },
        Receipt {
            exit_status: 1,
            ..r
        },
        Receipt { syscalls: 1, ..r },
        Receipt {
            object_reads_ok: 1,
            ..r
        },
        Receipt { denials: 1, ..r },
        Receipt {
            result_flags: RESULT_RECLAIMED | RESULT_READ_OK,
            ..r
        },
        Receipt {
            exit_status: 3,
            ..a
        },
        Receipt {
            execution_status: ExecutionStatusCode::Fault,
            ..a
        },
        Receipt { sequence: 9, ..a },
        Receipt {
            nonce: [0; 16],
            ..a
        },
    ];
    for (i, case) in bad.iter().enumerate() {
        assert_eq!(
            decode(&encode(case)),
            Err(ArtifactError::MalformedReceipt),
            "case {i}"
        );
    }
    let faulted = Receipt {
        execution_status: ExecutionStatusCode::Fault,
        result_flags: RESULT_RECLAIMED | RESULT_WX_SEALED,
        ..a
    };
    assert_eq!(decode(&encode(&faulted)), Ok(faulted));
}

#[test]
fn every_single_bit_change_in_the_signed_range_changes_meaning_or_is_rejected() {
    let b = encode(&admitted());
    let digest = receipt_digest(&b);
    let original = decode(&b).unwrap();
    for at in 0..RECEIPT_SIGNATURE_OFFSET {
        for mask in [0x01u8, 0x80] {
            let mut m = b;
            m[at] ^= mask;
            assert_ne!(receipt_digest(&m), digest, "digest ignores byte {at}");
            if let Ok(r) = decode(&m) {
                assert_ne!(r, original, "byte {at} mask {mask:#x} decoded identically");
            }
        }
    }
}

#[test]
fn signature_block_is_outside_the_digest_and_fully_authenticated() {
    let anchors = OneKey(
        SigningKey::from_bytes(&TEST2_SEED)
            .verifying_key()
            .to_bytes(),
    );
    let s = signed(&admitted(), &TEST2_SEED);
    assert_eq!(verify(&s, &anchors, &Ed25519Verifier), Ok(admitted()));
    assert_eq!(receipt_digest(&s), receipt_digest(&encode(&admitted())));
    for at in RECEIPT_SIGNATURE_OFFSET..RECEIPT_SIZE {
        let mut m = s;
        m[at] ^= 0x01;
        assert!(verify(&m, &anchors, &Ed25519Verifier).is_err(), "byte {at}");
    }
    for at in 0..RECEIPT_SIGNATURE_OFFSET {
        let mut m = s;
        m[at] ^= 0x01;
        assert!(
            verify(&m, &anchors, &Ed25519Verifier).is_err(),
            "signed byte {at}"
        );
    }
}

#[test]
fn unsigned_untrusted_and_production_verification_fail_closed() {
    let anchors = OneKey(
        SigningKey::from_bytes(&TEST2_SEED)
            .verifying_key()
            .to_bytes(),
    );
    let unsigned = encode(&admitted());
    assert_eq!(
        verify(&unsigned, &anchors, &Ed25519Verifier),
        Err(ArtifactError::BadSignatureFormat)
    );
    let other = signed(&admitted(), &TEST3_SEED);
    assert_eq!(
        verify(&other, &anchors, &Ed25519Verifier),
        Err(ArtifactError::UntrustedSigner)
    );
    let good = signed(&admitted(), &TEST2_SEED);
    assert_eq!(
        verify(&good, &EmptyReceiptAnchorSet, &Ed25519Verifier),
        Err(ArtifactError::UntrustedSigner)
    );
    let mut forged = good;
    forged[436] ^= 0xff;
    assert_eq!(
        verify(&forged, &anchors, &Ed25519Verifier),
        Err(ArtifactError::BadSignature)
    );
    let mut resigned = good;
    assert_eq!(
        sign(
            &mut resigned,
            &KeySigner(SigningKey::from_bytes(&TEST2_SEED))
        ),
        Err(ArtifactError::BadSignatureFormat)
    );
    let mut invalid = encode(&Receipt {
        denials: 1,
        ..rejected()
    });
    assert_eq!(
        sign(
            &mut invalid,
            &KeySigner(SigningKey::from_bytes(&TEST2_SEED))
        ),
        Err(ArtifactError::MalformedReceipt)
    );
}

#[cfg(feature = "seed0b-test-anchor")]
#[test]
fn test_receipt_anchor_is_rfc8032_test2_and_distinct_from_artifact_key() {
    use crate::receipt::seed0b_test_receipt_anchor::{Seed0bTestReceiptAnchorSet, PUBLIC_KEY};
    use crate::signature::seed0b_test_anchor::PUBLIC_KEY as ARTIFACT_KEY;
    assert_eq!(
        SigningKey::from_bytes(&TEST2_SEED)
            .verifying_key()
            .to_bytes(),
        PUBLIC_KEY
    );
    assert_ne!(PUBLIC_KEY, ARTIFACT_KEY);
    let s = signed(&admitted(), &TEST2_SEED);
    assert_eq!(
        verify(&s, &Seed0bTestReceiptAnchorSet, &Ed25519Verifier),
        Ok(admitted())
    );
    let other = signed(&admitted(), &TEST3_SEED);
    assert_eq!(
        verify(&other, &Seed0bTestReceiptAnchorSet, &Ed25519Verifier),
        Err(ArtifactError::UntrustedSigner)
    );
}

#[test]
fn arbitrary_records_never_panic_the_decoder() {
    let base = encode(&admitted());
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut buffers: Vec<[u8; RECEIPT_SIZE]> = Vec::new();
    for _ in 0..512 {
        let mut m = base;
        for _ in 0..8 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            m[(state as usize) % RECEIPT_SIZE] = (state >> 32) as u8;
        }
        buffers.push(m);
    }
    for m in &buffers {
        let _ = decode(m);
    }
}

const GOLDEN_ADMITTED_DIGEST: &str =
    "16bcbe523a62d9f4c907729fb2fb09d630ce36f80d7169e202730173a59bdfdc";
const GOLDEN_ADMITTED_RECORD: &str = "4149454e52435000000060000002000000000000010001000100000000000000e28b2fcc80dd4e973fbc3d13dc62801b000000000000000000000000000000000100000000000000ff000000000000000800000002000000050000000a000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const GOLDEN_REJECTED_DIGEST: &str =
    "f12ebace5ec0f2a8f06c415d58d936389dcc2fed64dbed4bc91efd01a734a6a3";
