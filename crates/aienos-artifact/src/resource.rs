use crate::error::ArtifactError;

pub const RESOURCE_ENVELOPE_SIZE: usize = 48;
pub const PAGE_SIZE: u32 = 4096;
pub const MAX_CODE_PAGES: u32 = 64;
pub const MAX_DATA_PAGES: u32 = 64;
pub const MAX_STACK_PAGES: u32 = 16;
pub const MAX_IPC_MESSAGES: u32 = 1024;
pub const MAX_IPC_BYTES: u32 = 1_048_576;
pub const MAX_CPU_TICKS: u64 = 1_000_000_000;
pub const MAX_ELAPSED_TICKS: u64 = 1_000_000_000;
pub const MAX_SYSCALLS: u32 = 65_536;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceEnvelope {
    pub code_pages: u32,
    pub data_pages: u32,
    pub stack_pages: u32,
    pub max_capabilities: u16,
    pub ipc_messages: u32,
    pub ipc_bytes: u32,
    pub cpu_ticks: u64,
    pub elapsed_ticks: u64,
    pub syscall_count: u32,
}

impl ResourceEnvelope {
    pub fn decode(bytes: &[u8], requested_capabilities: usize) -> Result<Self, ArtifactError> {
        if bytes.len() != RESOURCE_ENVELOPE_SIZE {
            return Err(if bytes.len() < RESOURCE_ENVELOPE_SIZE {
                ArtifactError::Truncated
            } else {
                ArtifactError::WrongLength
            });
        }
        if read_u16(bytes, 14)? != 0 || read_u32(bytes, 44)? != 0 {
            return Err(ArtifactError::ReservedNonZero);
        }
        let envelope = Self {
            code_pages: read_u32(bytes, 0)?,
            data_pages: read_u32(bytes, 4)?,
            stack_pages: read_u32(bytes, 8)?,
            max_capabilities: read_u16(bytes, 12)?,
            ipc_messages: read_u32(bytes, 16)?,
            ipc_bytes: read_u32(bytes, 20)?,
            cpu_ticks: read_u64(bytes, 24)?,
            elapsed_ticks: read_u64(bytes, 32)?,
            syscall_count: read_u32(bytes, 40)?,
        };
        envelope.validate(requested_capabilities)?;
        Ok(envelope)
    }

    pub fn validate(&self, requested_capabilities: usize) -> Result<(), ArtifactError> {
        if self.code_pages == 0
            || self.code_pages > MAX_CODE_PAGES
            || self.data_pages == 0
            || self.data_pages > MAX_DATA_PAGES
            || self.stack_pages == 0
            || self.stack_pages > MAX_STACK_PAGES
            || usize::from(self.max_capabilities) < requested_capabilities
            || usize::from(self.max_capabilities) > crate::capability::MAX_CAPABILITIES
            || self.ipc_messages > MAX_IPC_MESSAGES
            || self.ipc_bytes > MAX_IPC_BYTES
            || self.cpu_ticks == 0
            || self.cpu_ticks > MAX_CPU_TICKS
            || self.elapsed_ticks == 0
            || self.elapsed_ticks > MAX_ELAPSED_TICKS
            || self.syscall_count == 0
            || self.syscall_count > MAX_SYSCALLS
        {
            return Err(ArtifactError::ResourceLimit);
        }
        Ok(())
    }

    pub fn code_capacity_bytes(&self) -> Result<u32, ArtifactError> {
        self.code_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(ArtifactError::LengthOverflow)
    }

    pub fn data_capacity_bytes(&self) -> Result<u32, ArtifactError> {
        self.data_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(ArtifactError::LengthOverflow)
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
