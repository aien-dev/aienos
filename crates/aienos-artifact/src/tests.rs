use std::vec;
use std::vec::Vec;

use crate::canonical::{
    granted_capability_digest, payload_digest, requested_capability_digest,
    resource_envelope_digest,
};
use crate::capability::{CapabilityRequest, RIGHT_READ, RIGHT_WRITE};
use crate::error::ArtifactError;
use crate::format::{Artifact, CAPABILITY_TABLE_OFFSET, MAX_ARTIFACT_SIZE};
use crate::id::compute_artifact_id;
use crate::signature::{Ed25519Verifier, SignatureVerifier};
use crate::verify::parse_and_identify;

#[cfg(feature = "seed0b-test-anchor")]
use crate::signature::{
    artifact_signature_message, signer_fingerprint, ArtifactVerifier, ConfiguredArtifactVerifier,
    EmptyTrustAnchorSet, TrustAnchorSet, TrustTier,
};

const RESOURCE_OFFSET: usize = 240;
const PAYLOAD_OFFSET: usize = 288;
const SIGNATURE_OFFSET: usize = 296;
const TOTAL_LENGTH: usize = 396;

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn fixture() -> Vec<u8> {
    let mut bytes = vec![0u8; TOTAL_LENGTH];
    bytes[0..8].copy_from_slice(b"AIENART\0");
    put_u16(&mut bytes, 8, 0);
    put_u16(&mut bytes, 10, 128);
    put_u16(&mut bytes, 12, 1);
    put_u16(&mut bytes, 14, 1);
    put_u32(&mut bytes, 20, TOTAL_LENGTH as u32);
    put_u32(&mut bytes, 24, 128);
    put_u16(&mut bytes, 28, 2);
    put_u16(&mut bytes, 30, 32);
    put_u16(&mut bytes, 32, 0);
    put_u32(&mut bytes, 36, 0);
    put_u32(&mut bytes, 40, CAPABILITY_TABLE_OFFSET as u32);
    put_u16(&mut bytes, 44, 1);
    put_u16(&mut bytes, 46, 48);
    put_u32(&mut bytes, 48, RESOURCE_OFFSET as u32);
    put_u16(&mut bytes, 52, 48);
    put_u32(&mut bytes, 56, PAYLOAD_OFFSET as u32);
    put_u32(&mut bytes, 60, 8);
    put_u32(&mut bytes, 64, SIGNATURE_OFFSET as u32);
    put_u16(&mut bytes, 68, 100);
    put_u16(&mut bytes, 70, 1);

    // Code section: one AArch64 RET instruction, RX.
    put_u16(&mut bytes, 128, 1);
    put_u16(&mut bytes, 130, 5);
    put_u32(&mut bytes, 136, 0);
    put_u32(&mut bytes, 140, 4);
    put_u32(&mut bytes, 144, 4);
    put_u32(&mut bytes, 148, 4096);

    // Data section: four initialized bytes, one page reserved, RW and NX.
    put_u16(&mut bytes, 160, 2);
    put_u16(&mut bytes, 162, 3);
    put_u32(&mut bytes, 168, 4);
    put_u32(&mut bytes, 172, 4);
    put_u32(&mut bytes, 176, 4096);
    put_u32(&mut bytes, 180, 4096);

    // Scoped READ request for object 7, restricted to bytes [0, 4).
    put_u16(&mut bytes, 192, 3);
    put_u32(&mut bytes, 196, 7);
    put_u32(&mut bytes, 200, RIGHT_READ);
    put_u32(&mut bytes, 204, 1);
    put_u32(&mut bytes, 208, 4);
    put_u64(&mut bytes, 216, 4);
    put_u64(&mut bytes, 224, 0);
    put_u64(&mut bytes, 232, 4);

    put_u32(&mut bytes, RESOURCE_OFFSET, 1); // code pages
    put_u32(&mut bytes, RESOURCE_OFFSET + 4, 1); // data pages
    put_u32(&mut bytes, RESOURCE_OFFSET + 8, 1); // stack pages
    put_u16(&mut bytes, RESOURCE_OFFSET + 12, 1); // capability slots
    put_u32(&mut bytes, RESOURCE_OFFSET + 16, 2); // IPC messages
    put_u32(&mut bytes, RESOURCE_OFFSET + 20, 16); // IPC bytes
    put_u64(&mut bytes, RESOURCE_OFFSET + 24, 1000); // CPU ticks
    put_u64(&mut bytes, RESOURCE_OFFSET + 32, 2000); // elapsed ticks
    put_u32(&mut bytes, RESOURCE_OFFSET + 40, 16); // syscalls

    bytes[PAYLOAD_OFFSET..PAYLOAD_OFFSET + 4].copy_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);
    bytes[PAYLOAD_OFFSET + 4..PAYLOAD_OFFSET + 8].copy_from_slice(b"DATA");
    put_u16(&mut bytes, SIGNATURE_OFFSET, 1);
    bytes[SIGNATURE_OFFSET + 4..SIGNATURE_OFFSET + 36].fill(0xa5);
    bytes[SIGNATURE_OFFSET + 36..SIGNATURE_OFFSET + 100].fill(0x5a);
    bytes
}

fn parse_error(bytes: &[u8]) -> ArtifactError {
    Artifact::parse(bytes).expect_err("mutation must fail closed")
}

#[test]
fn accepts_canonical_artifact_and_exposes_exact_slices() {
    let bytes = fixture();
    let parsed = parse_and_identify(&bytes).unwrap();
    assert_eq!(parsed.artifact.target_arch, 1);
    assert_eq!(parsed.artifact.abi_version, 1);
    assert_eq!(parsed.artifact.entry_offset, 0);
    assert_eq!(parsed.artifact.code_bytes(), &[0xc0, 0x03, 0x5f, 0xd6]);
    assert_eq!(parsed.artifact.data_bytes(), b"DATA");
    assert_eq!(parsed.artifact.capabilities.len(), 1);
    assert_eq!(parsed.artifact.capabilities.as_slice()[0].resource_id, 7);
    assert_eq!(
        parsed.artifact.capabilities.as_slice()[0].rights,
        RIGHT_READ
    );
    assert_eq!(parsed.artifact.resources.code_pages, 1);
    assert_eq!(parsed.artifact.unsigned_bytes.len(), SIGNATURE_OFFSET);
    assert_eq!(
        parsed.payload_digest,
        payload_digest(&parsed.artifact),
        "payload digest is the exact serialized code then data bytes"
    );
    assert_eq!(
        parsed.artifact_id,
        compute_artifact_id(&parsed.artifact),
        "host and kernel entry points share the same identity function"
    );
    let requested = requested_capability_digest(parsed.artifact.capability_request_bytes);
    let granted = granted_capability_digest(parsed.artifact.capability_request_bytes);
    let resources = resource_envelope_digest(parsed.artifact.resource_envelope_bytes);
    assert_ne!(requested, granted);
    assert_eq!(
        hex(&requested),
        "adf96aa3e792b1d4a48fe925532efe34ff2a82fe7c07ce013d6daa8bfecb28db"
    );
    assert_eq!(
        hex(&resources),
        "02f22c42bc7fff8143e11d282f2cfc7773fc483356a5ad9861c937cc6484a3e5"
    );
    assert_eq!(
        hex(&parsed.payload_digest),
        "f9f5b6ad6a7b931afdce57c59c806df4971c31d72ef560cd7a140d34aba19758"
    );
    assert_eq!(
        hex(parsed.artifact_id.as_bytes()),
        "71976b5c38ec15f2307565ed3eea51fde4a5375970cd49338d6e16166238cf4b"
    );
}

#[test]
fn every_truncation_of_a_valid_artifact_is_rejected() {
    let bytes = fixture();
    for end in 0..bytes.len() {
        assert!(
            Artifact::parse(&bytes[..end]).is_err(),
            "truncation at {end}"
        );
    }
}

#[test]
fn rejects_header_and_length_mutations() {
    let mut bytes = fixture();
    bytes[0] ^= 1;
    assert_eq!(parse_error(&bytes), ArtifactError::BadMagic);

    let mut bytes = fixture();
    put_u16(&mut bytes, 8, 1);
    assert_eq!(parse_error(&bytes), ArtifactError::UnsupportedVersion);

    let mut bytes = fixture();
    put_u16(&mut bytes, 12, 2);
    assert_eq!(parse_error(&bytes), ArtifactError::WrongTarget);

    let mut bytes = fixture();
    put_u16(&mut bytes, 14, 2);
    assert_eq!(parse_error(&bytes), ArtifactError::WrongAbi);

    let mut bytes = fixture();
    put_u32(&mut bytes, 20, (TOTAL_LENGTH - 1) as u32);
    assert_eq!(parse_error(&bytes), ArtifactError::WrongLength);

    let mut bytes = fixture();
    put_u32(&mut bytes, 64, u32::MAX - 15);
    assert!(
        parse_error(&bytes) == ArtifactError::SectionOverlap
            || parse_error(&bytes) == ArtifactError::LengthOverflow
    );

    let mut bytes = fixture();
    put_u32(&mut bytes, 16, 1);
    assert_eq!(parse_error(&bytes), ArtifactError::UnsupportedFlags);
}

#[test]
fn rejects_section_entry_capability_resource_and_reserved_mutations() {
    let mut bytes = fixture();
    put_u32(&mut bytes, 168, 0); // data overlaps code
    assert_eq!(parse_error(&bytes), ArtifactError::BadSection);

    let mut bytes = fixture();
    put_u32(&mut bytes, 36, 4); // entry outside code file bytes
    assert_eq!(parse_error(&bytes), ArtifactError::BadEntryPoint);

    let mut bytes = fixture();
    put_u32(&mut bytes, 200, RIGHT_READ | 0x40); // unknown rights bit
    assert_eq!(parse_error(&bytes), ArtifactError::MalformedCapability);

    let mut bytes = fixture();
    put_u64(&mut bytes, 224, u64::MAX); // range-end overflow
    assert_eq!(parse_error(&bytes), ArtifactError::LengthOverflow);

    let mut bytes = fixture();
    put_u32(&mut bytes, RESOURCE_OFFSET, 65); // code pages exceed format max
    assert_eq!(parse_error(&bytes), ArtifactError::ResourceLimit);

    let mut bytes = fixture();
    put_u64(&mut bytes, RESOURCE_OFFSET + 24, 1_000_000_001);
    assert_eq!(parse_error(&bytes), ArtifactError::ResourceLimit);

    let mut bytes = fixture();
    bytes[34] = 1;
    assert_eq!(parse_error(&bytes), ArtifactError::UnsupportedVersion);

    let mut bytes = fixture();
    bytes[192 + 2] = 1;
    assert_eq!(parse_error(&bytes), ArtifactError::ReservedNonZero);

    let mut bytes = fixture();
    bytes[RESOURCE_OFFSET + 14] = 1;
    assert_eq!(parse_error(&bytes), ArtifactError::ReservedNonZero);

    let mut bytes = fixture();
    put_u16(&mut bytes, 44, 17);
    assert_eq!(parse_error(&bytes), ArtifactError::ResourceLimit);
}

#[test]
fn payload_manifest_and_resource_changes_change_artifact_identity() {
    let original_bytes = fixture();
    let original = parse_and_identify(&original_bytes).unwrap();

    let mut payload_changed = fixture();
    payload_changed[PAYLOAD_OFFSET] ^= 1;
    let payload_changed = parse_and_identify(&payload_changed).unwrap();
    assert_ne!(original.artifact_id, payload_changed.artifact_id);
    assert_ne!(original.payload_digest, payload_changed.payload_digest);

    let mut request_changed = fixture();
    put_u32(&mut request_changed, 200, RIGHT_READ | RIGHT_WRITE);
    let request_changed = parse_and_identify(&request_changed).unwrap();
    assert_ne!(original.artifact_id, request_changed.artifact_id);

    let mut resources_changed = fixture();
    put_u64(&mut resources_changed, RESOURCE_OFFSET + 24, 999);
    let resources_changed = parse_and_identify(&resources_changed).unwrap();
    assert_ne!(original.artifact_id, resources_changed.artifact_id);
}

#[test]
fn signature_bytes_are_not_recursively_included_in_artifact_id() {
    let original_bytes = fixture();
    let original = parse_and_identify(&original_bytes).unwrap();
    let mut changed_signature = fixture();
    changed_signature[SIGNATURE_OFFSET + 36] ^= 1;
    let changed_signature = parse_and_identify(&changed_signature).unwrap();
    assert_eq!(original.artifact_id, changed_signature.artifact_id);

    let mut changed_signer = fixture();
    changed_signer[SIGNATURE_OFFSET + 4] ^= 1;
    let changed_signer = parse_and_identify(&changed_signer).unwrap();
    assert_eq!(original.artifact_id, changed_signer.artifact_id);
}

#[test]
fn arbitrary_bounded_bytes_never_panic_the_parser() {
    let mut state = 0x9e37_79b9_u32;
    for length in 0..=4096 {
        let mut bytes = vec![0u8; length];
        for byte in &mut bytes {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *byte = (state >> 24) as u8;
        }
        let _ = Artifact::parse(&bytes);
    }

    let over_limit = vec![0u8; MAX_ARTIFACT_SIZE + 1];
    assert_eq!(parse_error(&over_limit), ArtifactError::ResourceLimit);
}

#[test]
fn authority_attenuation_is_directly_checkable() {
    let read = CapabilityRequest {
        resource_kind: 3,
        resource_id: 7,
        rights: RIGHT_READ,
        bounds_kind: 1,
        max_operations: 4,
        max_bytes: 4,
        byte_offset: 0,
        byte_length: 4,
    };
    let read_write = CapabilityRequest {
        rights: RIGHT_READ | RIGHT_WRITE,
        ..read
    };
    assert!(read.is_attenuation_of(&read));
    assert!(!read_write.is_attenuation_of(&read));
    assert!(read.is_attenuation_of(&read_write));
}

#[test]
fn ed25519_verifier_accepts_rfc8032_pure_signature_vector() {
    const PUBLIC_KEY: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    const SIGNATURE: [u8; 64] = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c,
        0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
        0x8e, 0x7a, 0x10, 0x0b,
    ];
    assert!(Ed25519Verifier.verify(&PUBLIC_KEY, b"", &SIGNATURE));
    let mut changed = SIGNATURE;
    changed[0] ^= 1;
    assert!(!Ed25519Verifier.verify(&PUBLIC_KEY, b"", &changed));
}

#[cfg(feature = "seed0b-test-anchor")]
#[test]
fn qualification_anchor_authenticates_exact_artifact_identity() {
    use ed25519_dalek::{Signer, SigningKey};

    use crate::signature::seed0b_test_anchor::{Seed0bTestAnchorSet, PUBLIC_KEY};

    const TEST_ONLY_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    let signing_key = SigningKey::from_bytes(&TEST_ONLY_SEED);
    assert_eq!(signing_key.verifying_key().to_bytes(), PUBLIC_KEY);
    let mut bytes = fixture();
    let unsigned = Artifact::parse(&bytes).unwrap();
    let id = compute_artifact_id(&unsigned);
    let signature = signing_key.sign(&artifact_signature_message(&id));
    bytes[SIGNATURE_OFFSET + 4..SIGNATURE_OFFSET + 36]
        .copy_from_slice(&signer_fingerprint(&PUBLIC_KEY));
    bytes[SIGNATURE_OFFSET + 36..SIGNATURE_OFFSET + 100].copy_from_slice(&signature.to_bytes());

    let anchors = Seed0bTestAnchorSet;
    let verifier = ConfiguredArtifactVerifier::new(&anchors, Ed25519Verifier);
    let verified = verifier.verify(&bytes).unwrap();
    assert_eq!(verified.identified().artifact_id, id);
    assert_eq!(verified.trust_tier(), TrustTier::Seed0bQualification);

    let no_anchors = EmptyTrustAnchorSet;
    let production_verifier = ConfiguredArtifactVerifier::new(&no_anchors, Ed25519Verifier);
    assert_eq!(
        production_verifier.verify(&bytes).unwrap_err(),
        ArtifactError::UntrustedSigner
    );

    let mut bad_signature = bytes.clone();
    bad_signature[SIGNATURE_OFFSET + 36] ^= 1;
    assert_eq!(
        verifier.verify(&bad_signature).unwrap_err(),
        ArtifactError::BadSignature
    );

    let mut bad_fingerprint = bytes.clone();
    bad_fingerprint[SIGNATURE_OFFSET + 4] ^= 1;
    assert_eq!(
        verifier.verify(&bad_fingerprint).unwrap_err(),
        ArtifactError::UntrustedSigner
    );

    let mut changed_payload = bytes;
    changed_payload[PAYLOAD_OFFSET] ^= 1;
    assert_eq!(
        verifier.verify(&changed_payload).unwrap_err(),
        ArtifactError::BadSignature
    );

    let expected = signer_fingerprint(&PUBLIC_KEY);
    assert!(anchors.find(&expected).is_some());
    assert!(anchors.find(&[0; 32]).is_none());
}

fn hex(bytes: &[u8]) -> std::string::String {
    use std::fmt::Write;
    let mut output = std::string::String::new();
    for byte in bytes {
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}
