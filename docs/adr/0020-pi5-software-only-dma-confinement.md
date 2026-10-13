# ADR 0020: Pi 5 software-only DMA confinement (an explicit, Pi-only exception to ADR 0012 rule 5)

Status: Accepted (operator, decision D3, 2026-10-13). Applies to the Raspberry Pi 5 only. It does NOT apply to the Spark.
Date: 2026-10-13
Amends: [ADR 0012](0012-self-construction-capability-growth-and-generations.md) rule 5 ("No native admission without enforcement"), for the Pi 5 network path only. Also names two doctrine passages in aien-architecture that this exception departs from: `doctrine/TRUST.md` section 5.1 item 2 (SMMUv3 DMA sandboxing) and `doctrine/ARCHITECTURE.md` "DMA & Bus Confinement" (SMMUv3 / PCIe IOMMU confinement). Those passages stay true for the Spark; a matching note is owed in aien-architecture (not done by this ADR).
Governing: ADR 0012 rule 5; `native/kernel/core/smmu.c` (the Spark's enforcement, SMMU stream windows).

Label used everywhere (boot banner, this ADR, gate names): **software-only DMA confinement (Pi 5, weaker than the Spark)**.

## Context

ADR 0012 rule 5 says native components run on the physical machine only after enforceable memory, DMA (SMMU) and capability isolation exist. On the Spark that is met by SMMU stream windows. The Pi 5 has no such unit in front of its network card.

Facts about the Pi 5 network path (read, not run; sources are the Linux tree `raspberrypi/linux` branch `rpi-6.12.y` and the RP1 datasheet, not this repository, and were read in the research that preceded this ADR, to be re-verified by whoever builds the driver):

1. The Ethernet MAC is a Cadence GEM_GXL block inside the RP1 south bridge, reached from the BCM2712 over PCIe (RP1 peripherals datasheet RP-008370-DS-1, chapter 7: packet buffer DMA, AXI4 bus master). Linux drives it with descriptor rings only (`drivers/net/ethernet/cadence/macb_main.c`, `raspberrypi_rp1_config` near line 5192; 44-bit DMA mask near line 5369). There is no programmed-I/O or FIFO mode to use instead. So once the NIC is on, a device on the bus reads and writes RAM at addresses that software puts in descriptors, and whatever the device itself decides.
2. A partial hardware backstop exists: the BCM2712 PCIe root complex has inbound windows (`drivers/pci/controller/pcie-brcmstb.c`: `brcm_pcie_get_inbound_wins` near line 1173, `set_inbound_win_registers` near line 1327, access enable near line 1359). A window is a power-of-two size from 4 KiB to 64 GiB, aligned to its size, up to 10 windows. Linux's `bcm2712.dtsi` pcie2 `dma-ranges` (near lines 556 to 562) maps 64 GiB, which is all of RAM, so Linux uses it as no confinement at all. The window belongs to the whole controller: the GEM, RP1's own DMA engines and USB share it, and there is no read/write split. Whether MSI writes from RP1 pass through the same window is UNVERIFIED.
3. This repository has no Pi 5 network driver yet. This ADR is written before the driver so the driver is built to the rule, not the rule fitted to the driver.

The decision to accept a software-only rule was taken by the operator as D3 on 2026-10-13, knowing that it is weaker than the Spark.

## Decision drivers

1. Be honest: a rule that software enforces cannot stop a device that ignores descriptors. State what is and is not covered.
2. Make the worst case small: if the NIC misbehaves, it should only be able to reach one small block that holds nothing of value.
3. Fail closed: any violation stops the NIC, it does not log and continue.
4. Keep the Spark untouched and its stronger rule intact.

## Options

### Option 1: No Pi networking (keep ADR 0012 rule 5 as written)

- Upside: no exception, no weaker path.
- Downside: the Pi stays offline; the house-server and Store-over-network work on the Pi cannot proceed.
- Picking it: nothing changes; the Pi 5 lane stops at local-only features. Reversible at any time.

### Option 2: Software-only confinement plus the root-complex window as a backstop (chosen)

- What it is: the rules in the Decision below.
- Upside: bounded, testable on a host, labelled; the hardware window removes the "any address in RAM" case when it works.
- Downside: a NIC that ignores descriptors is stopped only by the root-complex window, which is shared, coarse, and not yet proven to cover every path (MSI UNVERIFIED). Software checks cannot see what the device actually does.
- Picking it: Pi networking can be built. It is an exception to rule 5 that is written down, scoped to the Pi, and revisited (see Consequences).

### Option 3: Wait for a real IOMMU in front of the NIC

- Upside: would meet rule 5 fully.
- Downside: this ADR does not know of one on the Pi 5. UNVERIFIED whether any exists on RP1 or BCM2712 for this path; no date.
- Picking it: same as Option 1 in practice.

## Decision

Option 2. The following rules bind every Pi 5 network driver.

1. **One bounce window.** A single contiguous, power-of-two sized, size-aligned block of at most 2 MiB, allocated zeroed at boot, used for nothing else. It holds the descriptor rings and the packet buffers. No other memory is ever device-visible.
2. **One writer.** Only the kernel GEM driver writes descriptors. No agent, task or other kernel code gets a path to the rings.
3. **Every descriptor checked.** Each descriptor address and length must lie fully inside the window. The check is overflow-safe (it must not compute `addr + len` in a way that can wrap). A zero length is refused. A violation refuses the descriptor, halts the NIC and latches: the NIC stays off until reboot.
4. **Shadow, not trust.** The driver keeps its own record of each descriptor it issued. The device can write the ring (it writes status words back), so ring contents are never read back as addresses; a descriptor is re-issued only from the driver's record, and a reused (stale) slot is rewritten in full.
5. **Copy only.** Packets are copied into and out of the window. No kernel or agent pointer ever reaches the device.
6. **Hardware backstop where possible.** Program the BCM2712 PCIe root-complex inbound window to exactly the bounce block (one window, size and base equal to the block). Limits, stated plainly: it is controller-wide (RP1 DMA and USB share it), it has no read/write split, it only confines what the root complex sees, and the MSI path is UNVERIFIED. If it cannot be programmed, the boot banner says so and the driver does not claim a backstop.
7. **Refused outright:** scatter-gather (one descriptor per frame), jumbo frames (frame length capped at the standard Ethernet maximum), device-supplied addresses, and DMA from any other RP1 function (only the GEM is enabled for bus mastering).
8. **Label.** The boot banner prints `software-only DMA confinement (Pi 5, weaker than the Spark)`, and every gate that exercises this path carries `SWDMA` in its name.

### Scope of the exception

This is an explicit exception to ADR 0012 rule 5 for the Raspberry Pi 5 only. It does NOT apply to the Spark, whose DMA stays fenced by SMMU stream windows (`native/kernel/core/smmu.c`). No code from this ADR is built into the Spark or QEMU images. It does not allow native admission of generated components on the Pi; it covers the NIC's DMA only.

## Consequences

- A Pi 5 with networking is weaker than the Spark: a bug in this driver or a misbehaving RP1 can still reach the whole bounce block, and, if the root-complex window is not effective, possibly more. Nothing secret is ever placed in the window.
- The exception should be revisited if a hardware fence in front of the GEM is found.
- A later cut adds the real driver, the root-complex window programming and the boot banner; this ADR and the validator (`native/kernel/dev/dma_window.c`) come first.

## Tests (required before any Pi NIC path is enabled)

1. Host tests with mutants for the validator: address below the window, address plus length past the end, a length that makes `addr + len` wrap, zero length, a stale descriptor slot reused, misaligned buffers, a second violation after a latch.
2. Mutation proof: removing each check makes the host test fail.
3. Descriptor-ring helpers can only emit in-window addresses (property test over arbitrary inputs, including hostile ones).
4. Gate checks that the boot banner carries the label and that the default (Spark/QEMU) image contains none of the Pi DMA code.
5. On the Pi (later, by the operator's runner): NIC halts on an injected out-of-window descriptor; root-complex window readback equals the bounce block; MSI behaviour measured, not assumed.

## Evidence and limits

- Facts in Context were read from the Linux `rpi-6.12.y` tree, the RP1 datasheet and ADR 0012 / aien-architecture doctrine text; line numbers are approximate and no Pi hardware was touched by this ADR.
- Nothing here has been run on a Pi. The MSI path and the existence of any other fence are UNVERIFIED.
