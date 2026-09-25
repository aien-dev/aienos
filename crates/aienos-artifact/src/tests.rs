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
use crate::verify::parse_and_identify;

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

fn hex(bytes: &[u8]) -> std::string::String {
    use std::fmt::Write;
    let mut output = std::string::String::new();
    for byte in bytes {
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}
