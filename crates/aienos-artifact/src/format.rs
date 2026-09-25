use core::convert::TryFrom;

use crate::capability::{
    CapabilityRequest, CapabilityTable, CAPABILITY_RECORD_SIZE, MAX_CAPABILITIES,
};
use crate::error::ArtifactError;
use crate::resource::{ResourceEnvelope, PAGE_SIZE, RESOURCE_ENVELOPE_SIZE};
use crate::signature::SignatureBlock;

pub const ARTIFACT_MAGIC: &[u8; 8] = b"AIENART\0";
pub const FORMAT_VERSION: u16 = 0;
pub const HEADER_SIZE: usize = 128;
pub const SECTION_TABLE_OFFSET: usize = HEADER_SIZE;
pub const SECTION_COUNT: usize = 2;
pub const SECTION_RECORD_SIZE: usize = 32;
pub const SECTION_TABLE_SIZE: usize = SECTION_COUNT * SECTION_RECORD_SIZE;
pub const CAPABILITY_TABLE_OFFSET: usize = HEADER_SIZE + SECTION_TABLE_SIZE;
pub const SIGNATURE_BLOCK_SIZE: usize = 100;
pub const SIGNATURE_ALGORITHM_ED25519: u16 = 1;
pub const MAX_ARTIFACT_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_PAYLOAD_SIZE: usize = 8 * 1024 * 1024;
pub const TARGET_AARCH64_LE: u16 = 1;
pub const ABI_V1: u16 = 1;

pub const SECTION_KIND_CODE: u16 = 1;
pub const SECTION_KIND_DATA: u16 = 2;
pub const PERMISSIONS_RX: u16 = 0b101;
pub const PERMISSIONS_RW: u16 = 0b011;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Section {
    pub kind: u16,
    pub permissions: u16,
    pub payload_relative_offset: u32,
    pub file_length: u32,
    pub memory_length: u32,
    pub alignment: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Artifact<'a> {
    pub target_arch: u16,
    pub abi_version: u16,
    pub entry_offset: u32,
    pub sections: [Section; SECTION_COUNT],
    pub capabilities: CapabilityTable,
    pub resources: ResourceEnvelope,
    pub capability_request_bytes: &'a [u8],
    pub resource_envelope_bytes: &'a [u8],
    pub payload: &'a [u8],
    pub unsigned_bytes: &'a [u8],
    pub signer_fingerprint: &'a [u8; 32],
    pub signature: &'a [u8; 64],
    pub signature_algorithm: u16,
}

impl<'a> Artifact<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ArtifactError> {
        if bytes.len() < HEADER_SIZE {
            return Err(ArtifactError::Truncated);
        }
        if bytes.len() > MAX_ARTIFACT_SIZE {
            return Err(ArtifactError::ResourceLimit);
        }
        if get(bytes, 0, 8)? != ARTIFACT_MAGIC {
            return Err(ArtifactError::BadMagic);
        }
        if read_u16(bytes, 8)? != FORMAT_VERSION || read_u16(bytes, 10)? as usize != HEADER_SIZE {
            return Err(ArtifactError::UnsupportedVersion);
        }

        let target_arch = read_u16(bytes, 12)?;
        if target_arch != TARGET_AARCH64_LE {
            return Err(ArtifactError::WrongTarget);
        }
        let abi_version = read_u16(bytes, 14)?;
        if abi_version != ABI_V1 {
            return Err(ArtifactError::WrongAbi);
        }
        if read_u32(bytes, 16)? != 0 {
            return Err(ArtifactError::UnsupportedFlags);
        }

        let total_length = usize_from_u32(read_u32(bytes, 20)?)?;
        if total_length != bytes.len() {
            return Err(ArtifactError::WrongLength);
        }
        if read_u32(bytes, 24)? as usize != SECTION_TABLE_OFFSET
            || read_u16(bytes, 28)? as usize != SECTION_COUNT
            || read_u16(bytes, 30)? as usize != SECTION_RECORD_SIZE
            || read_u16(bytes, 32)? != 0
            || read_u16(bytes, 34)? != 0
        {
            return Err(ArtifactError::UnsupportedVersion);
        }
        let entry_offset = read_u32(bytes, 36)?;
        if read_u32(bytes, 40)? as usize != CAPABILITY_TABLE_OFFSET
            || read_u16(bytes, 46)? as usize != CAPABILITY_RECORD_SIZE
            || read_u16(bytes, 52)? as usize != RESOURCE_ENVELOPE_SIZE
            || read_u16(bytes, 54)? != 0
        {
            return Err(ArtifactError::UnsupportedVersion);
        }
        if !all_zero(get(bytes, 72, 56)?) {
            return Err(ArtifactError::ReservedNonZero);
        }

        let capability_count = read_u16(bytes, 44)? as usize;
        if capability_count > MAX_CAPABILITIES {
            return Err(ArtifactError::ResourceLimit);
        }
        let capability_bytes_len = capability_count
            .checked_mul(CAPABILITY_RECORD_SIZE)
            .ok_or(ArtifactError::LengthOverflow)?;
        let capability_end = CAPABILITY_TABLE_OFFSET
            .checked_add(capability_bytes_len)
            .ok_or(ArtifactError::LengthOverflow)?;
        let resource_offset = usize_from_u32(read_u32(bytes, 48)?)?;
        if resource_offset != capability_end {
            return Err(ArtifactError::SectionOverlap);
        }
        let resource_end = resource_offset
            .checked_add(RESOURCE_ENVELOPE_SIZE)
            .ok_or(ArtifactError::LengthOverflow)?;
        let expected_payload_offset = align_up_16(resource_end)?;
        let payload_offset = usize_from_u32(read_u32(bytes, 56)?)?;
        if payload_offset != expected_payload_offset {
            return Err(ArtifactError::SectionOverlap);
        }
        if !all_zero(get(bytes, resource_end, payload_offset - resource_end)?) {
            return Err(ArtifactError::ReservedNonZero);
        }

        let payload_length = usize_from_u32(read_u32(bytes, 60)?)?;
        if payload_length > MAX_PAYLOAD_SIZE {
            return Err(ArtifactError::ResourceLimit);
        }
        let signature_offset = usize_from_u32(read_u32(bytes, 64)?)?;
        let signature_length = usize::from(read_u16(bytes, 68)?);
        let signature_algorithm = read_u16(bytes, 70)?;
        if signature_length != SIGNATURE_BLOCK_SIZE
            || signature_algorithm != SIGNATURE_ALGORITHM_ED25519
        {
            return Err(ArtifactError::BadSignatureFormat);
        }
        let expected_signature_offset = payload_offset
            .checked_add(payload_length)
            .ok_or(ArtifactError::LengthOverflow)?;
        if signature_offset != expected_signature_offset {
            return Err(ArtifactError::SectionOverlap);
        }
        let expected_total = signature_offset
            .checked_add(SIGNATURE_BLOCK_SIZE)
            .ok_or(ArtifactError::LengthOverflow)?;
        if expected_total != total_length {
            return Err(ArtifactError::WrongLength);
        }

        let mut sections = [Section::default(); SECTION_COUNT];
        let section_table_end = SECTION_TABLE_OFFSET
            .checked_add(SECTION_TABLE_SIZE)
            .ok_or(ArtifactError::LengthOverflow)?;
        if section_table_end != CAPABILITY_TABLE_OFFSET {
            return Err(ArtifactError::SectionOverlap);
        }
        for (index, section) in sections.iter_mut().enumerate() {
            let offset = SECTION_TABLE_OFFSET
                .checked_add(
                    index
                        .checked_mul(SECTION_RECORD_SIZE)
                        .ok_or(ArtifactError::LengthOverflow)?,
                )
                .ok_or(ArtifactError::LengthOverflow)?;
            *section = decode_section(get(bytes, offset, SECTION_RECORD_SIZE)?)?;
        }
        validate_sections(&sections, payload_length)?;

        let mut capabilities = CapabilityTable::default();
        let mut previous: Option<(u16, u32)> = None;
        for index in 0..capability_count {
            let offset = CAPABILITY_TABLE_OFFSET
                .checked_add(
                    index
                        .checked_mul(CAPABILITY_RECORD_SIZE)
                        .ok_or(ArtifactError::LengthOverflow)?,
                )
                .ok_or(ArtifactError::LengthOverflow)?;
            let request = CapabilityRequest::decode(get(bytes, offset, CAPABILITY_RECORD_SIZE)?)?;
            let key = (request.resource_kind, request.resource_id);
            if previous.is_some_and(|p| p >= key) {
                return Err(ArtifactError::MalformedCapability);
            }
            previous = Some(key);
            capabilities.push(request)?;
        }

        let resource_envelope_bytes = get(bytes, resource_offset, RESOURCE_ENVELOPE_SIZE)?;
        let resources = ResourceEnvelope::decode(resource_envelope_bytes, capability_count)?;
        if sections[0].memory_length > resources.code_capacity_bytes()?
            || sections[1].memory_length > resources.data_capacity_bytes()?
        {
            return Err(ArtifactError::ResourceLimit);
        }
        if entry_offset & 3 != 0 {
            return Err(ArtifactError::BadEntryPoint);
        }
        let entry_end = entry_offset
            .checked_add(4)
            .ok_or(ArtifactError::LengthOverflow)?;
        if entry_end > sections[0].file_length {
            return Err(ArtifactError::BadEntryPoint);
        }

        let payload_end = payload_offset
            .checked_add(payload_length)
            .ok_or(ArtifactError::LengthOverflow)?;
        let payload = get(bytes, payload_offset, payload_length)?;
        let signature_block =
            SignatureBlock::decode(get(bytes, signature_offset, SIGNATURE_BLOCK_SIZE)?)?;
        if signature_block.algorithm != signature_algorithm {
            return Err(ArtifactError::BadSignatureFormat);
        }
        if payload_end != signature_offset {
            return Err(ArtifactError::SectionOverlap);
        }

        Ok(Self {
            target_arch,
            abi_version,
            entry_offset,
            sections,
            capabilities,
            resources,
            capability_request_bytes: get(bytes, CAPABILITY_TABLE_OFFSET, capability_bytes_len)?,
            resource_envelope_bytes,
            payload,
            unsigned_bytes: get(bytes, 0, signature_offset)?,
            signer_fingerprint: signature_block.signer_fingerprint,
            signature: signature_block.signature,
            signature_algorithm,
        })
    }

    pub fn code_bytes(&self) -> &[u8] {
        &self.payload[..self.sections[0].file_length as usize]
    }

    pub fn data_bytes(&self) -> &[u8] {
        let start = self.sections[1].payload_relative_offset as usize;
        let end = start + self.sections[1].file_length as usize;
        &self.payload[start..end]
    }
}

fn decode_section(bytes: &[u8]) -> Result<Section, ArtifactError> {
    if bytes.len() != SECTION_RECORD_SIZE {
        return Err(ArtifactError::Truncated);
    }
    if read_u32(bytes, 4)? != 0 || !all_zero(get(bytes, 24, 8)?) {
        return Err(ArtifactError::ReservedNonZero);
    }
    Ok(Section {
        kind: read_u16(bytes, 0)?,
        permissions: read_u16(bytes, 2)?,
        payload_relative_offset: read_u32(bytes, 8)?,
        file_length: read_u32(bytes, 12)?,
        memory_length: read_u32(bytes, 16)?,
        alignment: read_u32(bytes, 20)?,
    })
}

fn validate_sections(
    sections: &[Section; SECTION_COUNT],
    payload_length: usize,
) -> Result<(), ArtifactError> {
    let code = sections[0];
    let data = sections[1];
    if code.kind != SECTION_KIND_CODE
        || code.permissions != PERMISSIONS_RX
        || code.payload_relative_offset != 0
        || code.file_length == 0
        || code.memory_length != code.file_length
        || code.alignment != PAGE_SIZE
    {
        return Err(ArtifactError::BadSection);
    }
    if data.kind != SECTION_KIND_DATA
        || data.permissions != PERMISSIONS_RW
        || data.payload_relative_offset != code.file_length
        || data.file_length == 0
        || data.memory_length < data.file_length
        || data.alignment != PAGE_SIZE
    {
        return Err(ArtifactError::BadSection);
    }
    let end = u64::from(code.file_length)
        .checked_add(u64::from(data.file_length))
        .ok_or(ArtifactError::LengthOverflow)?;
    if end != payload_length as u64 {
        return Err(ArtifactError::SectionOverlap);
    }
    Ok(())
}

fn align_up_16(value: usize) -> Result<usize, ArtifactError> {
    value
        .checked_add(15)
        .map(|v| v & !15)
        .ok_or(ArtifactError::LengthOverflow)
}

fn usize_from_u32(value: u32) -> Result<usize, ArtifactError> {
    usize::try_from(value).map_err(|_| ArtifactError::LengthOverflow)
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn get(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], ArtifactError> {
    let end = offset
        .checked_add(length)
        .ok_or(ArtifactError::LengthOverflow)?;
    bytes.get(offset..end).ok_or(ArtifactError::Truncated)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ArtifactError> {
    let value = get(bytes, offset, 2)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ArtifactError> {
    let value = get(bytes, offset, 4)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}
