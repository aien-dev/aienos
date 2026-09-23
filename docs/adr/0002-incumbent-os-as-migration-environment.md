# ADR 0002: Incumbent operating systems are bootstrap and migration environments

Status: accepted by the operator, 2026-09-23.

## Context

People adopting AIEN already run Windows, macOS, or Linux. AIEN can reach them by running inside those systems first. The risk is that "AIEN inside Windows" becomes the permanent product and the host's abstractions leak into the native architecture.

## Decision

**Incumbent operating systems are bootstrap and migration environments, not the target runtime.** AIEN may initially run inside Windows, macOS, or Linux to:

- inventory the machine and determine what hardware support native AIENOS needs;
- preserve the user's state;
- build and validate an AIENOS installation (for example on a separate partition);
- provide a reversible migration path ("Restart into AIEN"), leaving the old OS bootable until the user no longer needs it.

The long-term target is independent AIENOS boot on bare metal.

**AIENOS may learn from the host, but it must not require the host to survive.** Anything learned from the host (hardware inventory, user data, settings) is converted into AIENOS-native state. Once installed, AIENOS boots, runs, recovers, and updates with the host OS removed.

## Consequences

- Host-side AIEN is an installer and migration tool ("use Windows to escape Windows"), not a second product line.
- No native AIENOS component may call into, link against, or require artifacts that only the host OS can produce.
- The Linux reference baseline and GPU island ([ADR 0001](0001-native-boot-milestone-and-linux-island.md)) follow the same rule.
