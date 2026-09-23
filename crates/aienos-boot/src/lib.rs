#![no_std]

/// Diagnostic banner emitted while UEFI boot services are still available.
pub const FIRMWARE_BANNER: &str = "AIENOS firmware entry: aarch64";

/// The UEFI diagnostic never provisions or reconstructs an agent identity.
pub const CREATES_AGENT_IDENTITY: bool = false;
