use crate::error::ArtifactError;

pub const CAPABILITY_RECORD_SIZE: usize = 48;
pub const MAX_CAPABILITIES: usize = 16;

pub const RESOURCE_KIND_CHANNEL: u16 = 2;
pub const RESOURCE_KIND_OBJECT: u16 = 3;

pub const RIGHT_READ: u32 = 1 << 0;
pub const RIGHT_WRITE: u32 = 1 << 1;
pub const RIGHT_MAP: u32 = 1 << 2;
pub const RIGHT_GRANT: u32 = 1 << 3;
pub const RIGHT_DERIVE: u32 = 1 << 4;
pub const RIGHT_REVOKE: u32 = 1 << 5;
pub const VALID_RIGHTS: u32 =
    RIGHT_READ | RIGHT_WRITE | RIGHT_MAP | RIGHT_GRANT | RIGHT_DERIVE | RIGHT_REVOKE;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CapabilityRequest {
    pub resource_kind: u16,
    pub resource_id: u32,
    pub rights: u32,
    pub bounds_kind: u32,
    pub max_operations: u32,
    pub max_bytes: u64,
    pub byte_offset: u64,
    pub byte_length: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityTable {
    entries: [CapabilityRequest; MAX_CAPABILITIES],
    len: u8,
}

impl Default for CapabilityTable {
    fn default() -> Self {
        Self {
            entries: [CapabilityRequest::default(); MAX_CAPABILITIES],
            len: 0,
        }
    }
}

impl CapabilityTable {
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[CapabilityRequest] {
        &self.entries[..self.len()]
    }

    pub(crate) fn push(&mut self, request: CapabilityRequest) -> Result<(), ArtifactError> {
        let index = self.len();
        let slot = self
            .entries
            .get_mut(index)
            .ok_or(ArtifactError::ResourceLimit)?;
        *slot = request;
        self.len += 1;
        Ok(())
    }
}

impl CapabilityRequest {
    /// Canonical 48-byte little-endian encoding for policy and grant records.
    pub fn to_bytes(self) -> [u8; CAPABILITY_RECORD_SIZE] {
        let mut bytes = [0u8; CAPABILITY_RECORD_SIZE];
        bytes[0..2].copy_from_slice(&self.resource_kind.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.resource_id.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.rights.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.bounds_kind.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.max_operations.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.max_bytes.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.byte_offset.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.byte_length.to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ArtifactError> {
        if bytes.len() != CAPABILITY_RECORD_SIZE {
            return Err(if bytes.len() < CAPABILITY_RECORD_SIZE {
                ArtifactError::Truncated
            } else {
                ArtifactError::WrongLength
            });
        }
        if read_u16(bytes, 2)? != 0 || read_u32(bytes, 20)? != 0 {
            return Err(ArtifactError::ReservedNonZero);
        }

        let request = Self {
            resource_kind: read_u16(bytes, 0)?,
            resource_id: read_u32(bytes, 4)?,
            rights: read_u32(bytes, 8)?,
            bounds_kind: read_u32(bytes, 12)?,
            max_operations: read_u32(bytes, 16)?,
            max_bytes: read_u64(bytes, 24)?,
            byte_offset: read_u64(bytes, 32)?,
            byte_length: read_u64(bytes, 40)?,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), ArtifactError> {
        if !matches!(
            self.resource_kind,
            RESOURCE_KIND_OBJECT | RESOURCE_KIND_CHANNEL
        ) || self.resource_id == 0
            || self.rights == 0
            || self.rights & !VALID_RIGHTS != 0
            || self.max_operations == 0
            || self.max_bytes == 0
        {
            return Err(ArtifactError::MalformedCapability);
        }

        match (self.resource_kind, self.bounds_kind) {
            (RESOURCE_KIND_OBJECT, 1) => {
                if self.byte_offset.checked_add(self.byte_length).is_none() {
                    return Err(ArtifactError::LengthOverflow);
                }
                if self.byte_length == 0 || self.max_bytes > self.byte_length {
                    return Err(ArtifactError::MalformedCapability);
                }
            }
            (RESOURCE_KIND_CHANNEL, 2) => {
                if self.byte_offset != 0 || self.byte_length != 0 {
                    return Err(ArtifactError::MalformedCapability);
                }
            }
            _ => return Err(ArtifactError::MalformedCapability),
        }
        Ok(())
    }

    /// True only when `self` is no broader than the corresponding request.
    pub fn is_attenuation_of(&self, requested: &Self) -> bool {
        if self.validate().is_err()
            || requested.validate().is_err()
            || self.resource_kind != requested.resource_kind
            || self.resource_id != requested.resource_id
            || self.bounds_kind != requested.bounds_kind
            || self.rights & !requested.rights != 0
            || self.max_operations > requested.max_operations
            || self.max_bytes > requested.max_bytes
        {
            return false;
        }
        match self.bounds_kind {
            1 => {
                let Some(self_end) = self.byte_offset.checked_add(self.byte_length) else {
                    return false;
                };
                let Some(requested_end) = requested.byte_offset.checked_add(requested.byte_length)
                else {
                    return false;
                };
                self.byte_offset >= requested.byte_offset && self_end <= requested_end
            }
            2 => self.byte_offset == 0 && self.byte_length == 0,
            _ => false,
        }
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ArtifactError> {
    let end = offset.checked_add(2).ok_or(ArtifactError::LengthOverflow)?;
    let value = bytes.get(offset..end).ok_or(ArtifactError::Truncated)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ArtifactError> {
    let end = offset.checked_add(4).ok_or(ArtifactError::LengthOverflow)?;
    let value = bytes.get(offset..end).ok_or(ArtifactError::Truncated)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ArtifactError> {
    let end = offset.checked_add(8).ok_or(ArtifactError::LengthOverflow)?;
    let value = bytes.get(offset..end).ok_or(ArtifactError::Truncated)?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}
