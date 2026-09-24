#![no_std]

/// Diagnostic banner emitted while UEFI boot services are still available.
pub const FIRMWARE_BANNER: &str = "AIENOS firmware entry: aarch64";

/// The UEFI diagnostic never provisions or reconstructs an agent identity.
pub const CREATES_AGENT_IDENTITY: bool = false;

// The unsafe DMA bypass lets a device reach physical memory with no SMMU
// confinement. It is for QEMU debugging only and must never be part of an
// image staged on Machine 1.
#[cfg(all(
    feature = "unsafe-debug-dma-without-smmu",
    feature = "hardware-staging"
))]
compile_error!(
    "feature `unsafe-debug-dma-without-smmu` (unconfined DMA, QEMU debug only) \
     cannot be combined with `hardware-staging`: no SMMU confinement means no DMA"
);

/// Whether this build carries the unsafe, QEMU-only DMA bypass.
pub const UNSAFE_DMA_BYPASS: bool = cfg!(feature = "unsafe-debug-dma-without-smmu");
