//! Pure parsing of virtio PCI vendor capabilities.

/// A memory mapped virtio structure described by a PCI vendor capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtioPciRegion {
    pub bar: u8,
    pub offset: u32,
    pub length: u32,
}

/// The virtio PCI regions advertised by a device.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VirtioPciCapabilities {
    pub common_cfg: Option<VirtioPciRegion>,
    pub notify_cfg: Option<VirtioPciRegion>,
    pub notify_off_multiplier: Option<u32>,
    pub isr_cfg: Option<VirtioPciRegion>,
    pub device_cfg: Option<VirtioPciRegion>,
}

/// Errors found while walking a PCI capability list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtioPciParseError {
    InvalidConfigLength,
    CapabilitiesNotPresent,
    InvalidPointer,
    CapabilityLoop,
    ShortCapability,
    InvalidRegion,
    DuplicateCapability,
}

/// Parse virtio 1.x PCI vendor capabilities from a PCI configuration image.
///
/// `config` must contain either the 256-byte conventional config space or the
/// 4096-byte extended config space. This function performs no device access.
pub fn parse_virtio_pci_capabilities(
    config: &[u8],
) -> Result<VirtioPciCapabilities, VirtioPciParseError> {
    if config.len() != 256 && config.len() != 4096 {
        return Err(VirtioPciParseError::InvalidConfigLength);
    }
    if read_u16(config, 0x06) & (1 << 4) == 0 {
        return Err(VirtioPciParseError::CapabilitiesNotPresent);
    }

    let mut result = VirtioPciCapabilities::default();
    let mut pointer = config[0x34] & !0x03;
    let mut visited = [false; 256];
    let mut steps = 0;
    while pointer != 0 {
        let index = usize::from(pointer);
        if index < 0x40
            || index
                .checked_add(2)
                .filter(|end| *end <= config.len())
                .is_none()
        {
            return Err(VirtioPciParseError::InvalidPointer);
        }
        if visited[index] || steps >= 48 {
            return Err(VirtioPciParseError::CapabilityLoop);
        }
        visited[index] = true;
        steps += 1;

        let next = config[index + 1] & !0x03;
        if config[index] == 0x09 {
            if index
                .checked_add(16)
                .filter(|end| *end <= config.len())
                .is_none()
            {
                return Err(VirtioPciParseError::ShortCapability);
            }
            let cap_len = usize::from(config[index + 2]);
            let kind = config[index + 3];
            let minimum = if kind == 2 { 20 } else { 16 };
            if cap_len < minimum
                || index
                    .checked_add(cap_len)
                    .filter(|end| *end <= config.len())
                    .is_none()
            {
                return Err(VirtioPciParseError::ShortCapability);
            }
            let region = VirtioPciRegion {
                bar: config[index + 4],
                offset: read_u32(config, index + 8),
                length: read_u32(config, index + 12),
            };
            if region.bar > 5
                || region.length == 0
                || region.offset.checked_add(region.length).is_none()
            {
                return Err(VirtioPciParseError::InvalidRegion);
            }
            match kind {
                1 => set_region(&mut result.common_cfg, region)?,
                2 => {
                    set_region(&mut result.notify_cfg, region)?;
                    if result.notify_off_multiplier.is_some() {
                        return Err(VirtioPciParseError::DuplicateCapability);
                    }
                    result.notify_off_multiplier = Some(read_u32(config, index + 16));
                }
                3 => set_region(&mut result.isr_cfg, region)?,
                4 => set_region(&mut result.device_cfg, region)?,
                _ => {}
            }
        }
        pointer = next;
    }
    Ok(result)
}

fn set_region(
    slot: &mut Option<VirtioPciRegion>,
    region: VirtioPciRegion,
) -> Result<(), VirtioPciParseError> {
    if slot.replace(region).is_some() {
        return Err(VirtioPciParseError::DuplicateCapability);
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u32(config: &mut [u8], offset: usize, value: u32) {
        config[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_cap(config: &mut [u8], at: usize, next: u8, kind: u8, bar: u8, offset: u32, len: u32) {
        let cap_len = if kind == 2 { 20 } else { 16 };
        config[at..at + cap_len].fill(0);
        config[at] = 0x09;
        config[at + 1] = next;
        config[at + 2] = cap_len as u8;
        config[at + 3] = kind;
        config[at + 4] = bar;
        put_u32(config, at + 8, offset);
        put_u32(config, at + 12, len);
        if kind == 2 {
            put_u32(config, at + 16, 4);
        }
    }

    #[test]
    fn parses_modern_virtio_net_capabilities() {
        let mut config = [0u8; 256];
        config[0..2].copy_from_slice(&0x1af4u16.to_le_bytes());
        config[2..4].copy_from_slice(&0x1041u16.to_le_bytes());
        config[6] = 1 << 4;
        config[0x34] = 0x40;
        put_cap(&mut config, 0x40, 0x50, 1, 0, 0x1000, 0x100);
        put_cap(&mut config, 0x50, 0x64, 2, 2, 0x2000, 0x100);
        put_cap(&mut config, 0x64, 0x74, 3, 0, 0x3000, 1);
        put_cap(&mut config, 0x74, 0, 4, 0, 0x4000, 0x80);

        let parsed = parse_virtio_pci_capabilities(&config).unwrap();
        assert_eq!(
            parsed.common_cfg,
            Some(VirtioPciRegion {
                bar: 0,
                offset: 0x1000,
                length: 0x100
            })
        );
        assert_eq!(
            parsed.notify_cfg,
            Some(VirtioPciRegion {
                bar: 2,
                offset: 0x2000,
                length: 0x100
            })
        );
        assert_eq!(parsed.notify_off_multiplier, Some(4));
        assert_eq!(
            parsed.isr_cfg,
            Some(VirtioPciRegion {
                bar: 0,
                offset: 0x3000,
                length: 1
            })
        );
        assert_eq!(
            parsed.device_cfg,
            Some(VirtioPciRegion {
                bar: 0,
                offset: 0x4000,
                length: 0x80
            })
        );
    }

    #[test]
    fn rejects_loops_and_short_vendor_capabilities() {
        let mut config = [0u8; 256];
        config[6] = 1 << 4;
        config[0x34] = 0x40;
        put_cap(&mut config, 0x40, 0x40, 1, 0, 0x1000, 0x100);
        assert_eq!(
            parse_virtio_pci_capabilities(&config),
            Err(VirtioPciParseError::CapabilityLoop)
        );

        config[0x41] = 0;
        config[0x42] = 8;
        assert_eq!(
            parse_virtio_pci_capabilities(&config),
            Err(VirtioPciParseError::ShortCapability)
        );
    }
}
