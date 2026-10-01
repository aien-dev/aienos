# native/net: AIENOS M6-A hosted network stack (C)

C port of the Rust reference `crates/aienos-kernel/src/net.rs` and
`virtio_net.rs` (read as the spec, not extended), plus a framed
control-transport stub. No Rust, no Python, no heap, no outside library.

| File | What it is |
|---|---|
| `aienos_net.{h,c}` | Ethernet II, ARP + fixed ARP cache, IPv4 (no reassembly), ICMP echo, UDP. Bounded parsers; error order matches the reference. |
| `aienos_virtio_pci.{h,c}` | virtio 1.x PCI vendor-capability walk over a config image (no device access). |
| `aienos_ctl.{h,c}` | Control-transport stub: authenticated frames, ordered exactly-once delivery, retransmit, link-down. **TEST identity only.** The frame format is specified in the header. |

## Tests (`make test`, `make sanitize`)

- `tests/net_test.c`: the reference's own vectors, malformed negatives
  (every truncation, bad lengths, bad checksums, ihl/version/ttl/flags,
  oversize builds, capability loops, short caps, bad regions, duplicates),
  build/parse round trips with single-bit corruption, seeded random hostile
  inputs with bounds checks on every returned view.
- `tests/ctl_test.c`: seeded simulated link with loss, duplication,
  corruption, reordering and blackouts; every scenario runs twice and must be
  bit-identical; refusal cases (truncation, trailing byte, header fields,
  tag coverage, wrong key, reflection, wrong session, non-TEST identity,
  forged ack, capacity, window, sequence exhaustion, sticky link-down).
- `tests/net_diff.c` + `make diff-check`: a 200,000-record structure-aware
  hostile corpus. Its canonical output was compared byte for byte with the
  unmodified Rust reference run by a scratch driver kept outside this repo
  (no Rust in AIENOS code); the agreed digest is pinned in the Makefile.
- `make receipt`: clean-tree-only, content-addressed receipt in `receipts/`.

## Deliberate differences from the reference

- Checksums accumulate in 64 bits (the Rust `u32` sum overflows above
  about 128 KiB of input).
- NULL pointer or argument misuse returns an error instead of being
  impossible by type.

## Not claimed (deferred, with the dependency)

- Native binding (virtio-net queues, real NIC, interrupts): needs a C kernel.
  No C kernel exists yet; the aienos port order is an open operator decision.
- Production identity and keys, secure transport: needs M5 (key hierarchy,
  TRUST-1). The stub refuses every identity kind except TEST, whose key is
  derived from a public label and so protects nothing against an attacker.
- Physical NIC qualification: the Machine 1 wave after TRUST-1 Gate 7.
- DHCP, NDP/IPv6, TCP, fragment reassembly: not in the reference; later M6 work.
- The ARP cache stores whatever reply the caller marks solicited; gating
  spoofed replies is the caller's job (same as the reference).
