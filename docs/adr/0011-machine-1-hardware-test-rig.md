# ADR 0011: Machine 1 Hardware Test Rig (Power, Capture, Input)

Status: proposed, 2026-09-24. Requires operator approval of the parts list
before maintainers wire anything. It does not change the boot architecture.
Governing: [MILESTONES.md gate M2C](../MILESTONES.md),
[HARDWARE_TEST_RIG.md](../HARDWARE_TEST_RIG.md),
[NATIVE_BOOT_ONE_TIME.md](../NATIVE_BOOT_ONE_TIME.md),
issue [#25](https://github.com/aien-dev/aienos/issues/25).

## Context

Every Spark boot needs a person at the machine: power and reset by hand,
screen evidence by photograph, and firmware interaction by keyboard. Gate M2C
requires power/reset control, HDMI capture and USB input emulation before
hardware testing can run unattended or at any cadence. A Raspberry Pi is
already cabled to the Spark and can host all three functions.

## Decision

Build the Machine 1 test rig as three **independent** functions on the
existing Raspberry Pi controller, with the parts list and wiring in
[HARDWARE_TEST_RIG.md](../HARDWARE_TEST_RIG.md):

1. **Power and reset control**: reed relays across the front-panel power and
   reset pins, a fail-on mains relay for hard power cut, and a `PWR_OK` sense
   line for power state.
2. **Display and console capture**: a UVC HDMI capture dongle with
   loop-through on the Spark's display output, and the Pi GPIO UART for the
   Spark console once SPCR-based UART discovery
   ([#22](https://github.com/aien-dev/aienos/issues/22)) exists.
3. **Deterministic input and boot selection**: the Pi USB OTG port as an HID
   boot-protocol keyboard gadget, driven by scripted, capture-verified
   keystroke sequences.

All three functions are serialized through
`aien-proof hold --resource machine-1`, whose implementation and ledger live
in the [aien-sovereign-core](https://github.com/aien-dev/aien-sovereign-core)
repository. This repository holds the design, the operating contract and the
versioned boot sequences.

## Invariants

1. **Independence.** Each function fails without breaking the other two. A
   failed capture never blocks power control; a dead keyboard gadget never
   traps the machine.
2. **Fail-on power.** The mains relay passes power at rest, so a dead or hung
   controller cannot hold the machine dark. The operator can always cut power
   by hand.
3. **Momentary-only buttons.** Button relays close only for bounded intervals,
   enforced in software and by the relay hardware.
4. **Read-only capture.** Capture observes; it never alters the machine.
5. **Serialized control.** Every rig function runs only inside an
   `aien-proof hold --resource machine-1`; the hold output is the ledger
   event. Deterministic sequences are versioned in this repository so a boot
   maps to one exact commit, same rule as the staged image.
6. **No trust change.** The rig drives boots; it does not change what boots.
   Secure Boot stays on and native AIENOS boots stay paused until the
   owner-controlled boot chain exists. The rig adds no credentials, network
   services or privileged host state to the trusted base.
7. **Off the critical path at rest.** With every relay at rest the Spark
   behaves exactly as it does unwired.

## Consequences

- Screen evidence for boots stops depending on an operator photograph; the
  post-exit drawing gap in the M2 evidence becomes a capture artifact named
  in the ledger payload.
- Recovery-media testing
  ([#17](https://github.com/aien-dev/aienos/issues/17)) and the TRUST-1
  100-boot campaign can run without a person at the machine.
- The HID gadget becomes the hardware test target for the native xHCI/HID
  keyboard driver ([#24](https://github.com/aien-dev/aienos/issues/24)).
- `aien-proof` gains rig commands under the existing `machine-1` resource
  lock; that work lands in aien-sovereign-core, not here.
- The rig is removed piece by piece only if a native path replaces it (for
  example native network control after M6); the capture and input functions
  are expected to stay through the M8 demonstration.
