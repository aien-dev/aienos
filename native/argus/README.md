# ARGUS (native, C)

ARGUS is the AIEN defensive plane: it observes, detects, and asks for containment.
It never authorizes; that is AEGIS (see `../capability`). ARGUS-0 is the
substrate only: event ABI, bounded ring, resident deterministic state,
hard-invariant detectors, findings.

`argus_abi.h` is the shared contract and is owned by the integrator. Lanes:
`argus_event.c` + `argus_ring.c` (ABI + transport), `argus_core.c` (state),
`argus_detect.c` (hard invariants). `tests/` hold each lane's tests and the
integration and determinism tests. Design: aien-architecture ADR 0017.

Rule enforced by test: the authority secret-word and its length macro never
appear under `native/argus/` (see lane B secret-negative test), and no event
field is secret-sized except digests.
