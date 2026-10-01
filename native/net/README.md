# native/net: AIENOS M6-A hosted network stack (C)

C port of the Rust reference `crates/aienos-kernel/src/net.rs` and
`virtio_net.rs` (read as the spec, not extended), plus a framed
control-transport stub. No Rust, no Python, no heap, no outside library.

| File | What it is |
|---|---|
| `aienos_net.{h,c}` | Ethernet II, ARP + fixed ARP cache, IPv4 (no reassembly), ICMP echo, UDP. Bounded parsers; error order matches the reference. |
| `aienos_virtio_pci.{h,c}` | virtio 1.x PCI vendor-capability walk over a config image (no device access). Accepts the real QEMU virtio-net-pci layout (see Lane 26 below). |
| `aienos_virtio_net.{h,c}` | Lane 26: virtio-net driver core, split virtqueues, polled. New C written from the virtio 1.x spec (the Rust reference has no queue code). Device access only through a small ops struct. |
| `aienos_ctl.{h,c}` | Control-transport stub: authenticated frames, ordered exactly-once delivery, retransmit, link-down. **TEST identity only.** The frame format is specified in the header. |
| `x25519.{h,c}` | M6-B: X25519 (RFC 7748), constant-time ladder, small-order outputs refused. |
| `aienos_sec.{h,c}` | M6-B: mutually authenticated secure control transport over the M6-A UDP framing. **TEST identities only.** The wire format is specified in the header. |

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
- The ARP cache reuses an expired entry when learning (the reference only
  frees expired entries during a lookup, so a full cache refused new senders
  until some lookup ran). Found by the Codex review.

## Not claimed (deferred, with the dependency)

- Native binding (real NIC, interrupts, real DMA): the virtio-net queue code now
  exists as hosted code (Lane 26, below) but nothing in the C kernel calls it yet.
- Production identity and keys: needs M5 (key hierarchy, TRUST-1). The M6-B
  secure transport below exists as hosted code but runs on TEST keys only. The stub refuses every identity kind except TEST, whose key is
  derived from a public label and so protects nothing against an attacker.
- Physical NIC qualification: the Machine 1 wave after TRUST-1 Gate 7.
- DHCP, NDP/IPv6, TCP, fragment reassembly: not in the reference; later M6 work.
- The ARP cache stores whatever reply the caller marks solicited; gating
  spoofed replies is the caller's job (same as the reference).

## M6-B: secure control transport (hosted)

`aienos_sec` puts a mutually authenticated, encrypted session between two
AIENOS machines. Each datagram is one UDP payload of the M6-A stack. Make
targets: `make secure` runs everything below and prints
`AIENOS_NET_SECURE: PASS/FAIL`; `make mutants` runs the mutant pass alone.

**Scope.** The design follows the SIGMA pattern (sign, then MAC), in three
messages:

- **Identities.** Ed25519 keys (`native/sig`). Each side is configured with
  the single peer key it accepts.
- **Key exchange.** Fresh ephemeral X25519 keys (`x25519.c`) for every
  session.
- **Key derivation.** HKDF-SHA256 built on `native/crypto`'s HMAC.
- **Binding.** Each signature and each finished MAC covers a hash of every
  handshake byte so far, so messages from two sessions cannot be spliced
  together.
- **Records.** AES-256-GCM-SIV, one key per direction. The nonce is the
  direction plus a 64-bit counter, and the 24-byte record header is
  authenticated.
- **Replay.** A 64-record replay window.
- **Rekey.** A one-way key ratchet every `rekey_interval` records (at least
  128). The old key is wiped. The receiver keeps one previous epoch key so
  that reordering across a boundary still works.
- **Limits.** A hard `max_records` cap (`EXHAUSTED` once reached, so a new
  handshake is needed), and an authenticated CLOSE that wipes keys on both
  sides.
- **Handshake loss.** Resend timers, plus an answer to a repeated HS1 or HS3.
- **Data loss.** Recovered by carrying M6-A `aienos_ctl` frames inside the
  secure records (ordered, exactly once).
- **Parsers.** Every parser checks the total length first. A refused message
  changes no state.

**What is proven, hosted only** (`tests/x25519_test.c`, `tests/sec_test.c`,
two in-process machines over real M6-A Ethernet/IPv4/UDP frames):

- **X25519.**
  - The RFC 7748 vectors pass: section 5.2 (single vectors, plus 1 and 1000
    iterations) and section 6.1.
  - The 1,000,000-iteration vector passes with `X25519_LONG=1` (run once by
    hand; not part of `make test`).
  - Small-order inputs are refused.
- **HKDF.** RFC 5869 test case 1 passes.
- **Handshake.** It succeeds, and the two sides end up with matching keys
  and session id. Ephemeral and intermediate secrets are wiped.
- **Identity.**
  - A wrong identity is refused in both directions.
  - Impersonation is refused: claiming the expected key while signing with
    another key fails, even with a valid finished MAC.
- **Tampering.** A one-byte change at every position of HS1, HS2 and HS3 is
  refused, and no handshake completes. The following are also refused:
  - splicing HS2 or HS3 from a concurrent session
  - replaying an old HS2
  - a weak (small-order) key share, even when correctly signed
  - a different HS1 sent mid-handshake
- **Replay window.**
  - A replayed record is refused.
  - Records reordered inside the window, including fully shuffled, are
    accepted exactly once.
  - Records outside the window are refused, at the exact boundary (64 back
    accepted, 65 refused).
- **Record damage.** Every truncation, every extension of 1 to 64 bytes and
  every single-bit flip of a record is refused. The receiver is unchanged
  afterwards.
- **Misrouted records.** Reflected, wrong-session and wrong-state records
  are refused.
- **Rekey.**
  - It is correct over 10 epochs, with reordering across every epoch
    boundary.
  - The epoch-0 key is no longer anywhere in either endpoint's memory.
  - A record sealed with an old key is refused.
  - Jumping more than 4 epochs ahead is refused.
- **Limits and close.** The `max_records` limit holds on both the sender and
  the receiver. Close works.
- **Loss.** With every Nth datagram dropped in each direction (N = 2, 3, 4,
  5, 7, 11, 16), all 150 messages each way arrive in order exactly once,
  including with rekeys every 128 records, and reruns are bit-identical. A
  blackout or a permanently lost HS3 ends in `LINK_DOWN`.
- **Fuzzing.** 100,000 random and structured datagrams yield no data, the waiting
  responder stays in its start state, and the established endpoint keeps
  working.
- **Sanitizers.** All of the above also runs under ASan and UBSan.
- **Mutants.** Every one of the 24 guard mutants (5 in X25519, 19 in the
  transport) is killed.

**Not proven:**

- **No native binding.** Nothing runs on a NIC or in a kernel; the code is
  hosted C only.
- **No real keys.** Identities come from `sec_test_identity` (a public label,
  marked NOT-FOR-PRODUCTION), and the "entropy" is a seeded generator. Real
  identities wait for the M5 owner-key hierarchy (TRUST-1), and a real
  randomness source waits for the native binding.
- **No timing measurement.** The X25519 ladder, the masks and the MAC
  comparisons are written to be constant-time, but no timing, power or
  cache test was run. GCM-SIV and Ed25519 inherit whatever `native/crypto`
  and `native/sig` claim.
- **No formal protocol analysis.** There is no ProVerif or Tamarin model.
  The security argument is the SIGMA design plus the tests above.
- **Accepted design limits.**
  - Identity hiding is not a goal: the responder's key is sent in the clear.
  - There is no forward secrecy against a later compromise of an identity
    key alone. The ephemeral keys protect past sessions, but an identity key
    still allows future impersonation.
  - A responder keeps one handshake in flight. Denial-of-service hardening
    (cookies) is not done.
- **Lockstep finding.** On a strictly periodic loss pattern, the M6-A
  channel's fixed resend schedule can lock into step with the losses, so
  the same frame is dropped every round and the link goes down. This was
  seen with N = 2, 3 and 4 when both senders run in lockstep. **Fixed at the
  source (Lane 19):** `aienos_ctl` now waits exactly rto before the first
  retransmit and rto plus a deterministic jitter in [0, rto] before each later
  one (a pure function of session, role, seq and try count; no clock, no
  randomness, no key bits, no wire or header change). The loss tests no longer
  vary sender timing; `ctl_test` adds a drop-every-N run (N = 2 to 16) and a
  schedule test (bounds, determinism, variation), and `make mutants` covers the
  six jitter guard lines. The M6-B handshake resend (HS1/HS3) still uses a
  fixed rto; its loss tests pass for N = 2 to 16.

**Mapping onto omega's Fabric.** Omega's F5-0 Fabric (`src/fabric/fabric.h`)
takes a `FabTransport {ctx, send(ctx, from, to, msg, len), recv(ctx, self,
buf, cap, *len)}`, which it treats as untrusted, and a `FabAuth {sign,
verify}`, which carries a 32-byte tag. The two connect like this:

- **Session table.** An adapter keeps one `sec_endpoint` per peer machine,
  keyed by `AienMachineId`. Each endpoint's peer key comes from the
  roster/AEGIS boundary. The Fabric never adds peers.
- **`send`.** It hands the whole "AFAB" message (at most `FAB_MSG_MAX`,
  under `SEC_MAX_PAYLOAD` = 1100) to `sec_seal` for the `to` machine, or to
  `ct_send` and then `sec_seal` when ordered delivery is wanted. It then
  sends the result as one UDP datagram.
- **`recv`.** It drains UDP and calls `sec_receive`. Only `SEC_DATA`
  payloads reach the Fabric, so it sees only authenticated bytes from the
  configured peer.
- **Tag size.** An Ed25519 signature is 64 bytes, but `FAB_TAG_BYTES` is 32,
  so the identity key cannot sign Fabric messages directly. While
  `FabAuth` stays at 32 bytes, the adapter can set the tag to an HMAC under
  a per-session key exported from the secure session. A real per-machine
  signature means widening the Fabric tag to 64 bytes (an omega change).
- **Nothing is built yet.** No adapter exists in either repository. This
  section is the interface plan only.

## Lane 26: virtio-net PCI fix and virtqueue data path (hosted)

**The attach bug.** The capability walk refused any vendor capability whose
region had length 0, before looking at its type. Real QEMU virtio-net-pci
always carries a `VIRTIO_PCI_CAP_PCI_CFG` (cfg_type 5) capability with bar 0,
offset 0, length 0, which the virtio 1.x spec allows, so every real QEMU
virtio-net device was refused with `InvalidRegion`. Confirmed on real config
space dumped from QEMU 8.2.2 (no guest: the qtest protocol reads the ECAM
window while the CPU is paused; `tests/fixtures/dump_qemu_virtio_net_cfg.sh`
re-dumps it). Fix: the BAR / zero-length / overflow checks now apply to the
four structures the driver maps (cfg_type 1..4) only; other cfg types are
ignored, as the spec requires. The Rust reference has the same bug (left
unedited: no Rust work).

The pinned Rust differential still runs, against a reference-compat build
(`-DAIENOS_VIRTIO_PCI_REFERENCE_COMPAT`, test-only). The default build has its
own C-only pin, and `make diff-check` proves the two differ only on records
the reference refused as `InvalidRegion` (1,622 of 200,000).

**The data path** (`aienos_virtio_net`): reset, ACK, DRIVER; VERSION_1
required, MAC accepted if offered, every other feature declined; FEATURES_OK
read back; queue 0 RX and queue 1 TX, power-of-two size up to 256 (downsized to
what the device offers); notify offset checked against the notify window; all
RX buffers posted before DRIVER_OK; polled (no MSI-X vector, NO_INTERRUPT).
Rings and buffers live in one caller region; descriptors are rebuilt from the
id on every post and checked inside the region; nothing the device writes is
trusted. A used entry with an id out of range or not outstanding, a length
over the buffer, a short RX completion, or a used index running ahead marks the
device broken (sticky) until re-init.

**Tests** (`tests/vnet_test.c`, in `make test` and `make sanitize`):
- `VIRTIO_PCI_QEMU822_CAPS`: both real QEMU dumps (transitional 0x1000, modern
  0x1041) parse to the expected windows (BAR 4, common 0x0, ISR 0x1000, device
  0x2000, notify 0x3000, multiplier 4); 15 malformed variants of the real image
  stay refused (zero-length common/notify/ISR/device, bad BAR, offset overflow,
  short cap, cap past config space, loops, duplicate, bad pointer).
- Init against a simulated device in C: feature masking when the device offers
  all 64 bits; refusals for no VERSION_1, FEATURES_OK refused, stuck reset, one
  queue, queue size 0/1, pre-enabled queue, notify offset outside the window,
  unstable config generation, missing/short caps, small/misaligned/wrapping
  memory. No notify before DRIVER_OK.
- Data path: TX full/reclaim, max-size frames, 70,000 frames each way so the
  16-bit ring indices wrap; the device model checks every descriptor it reads.
- Hostile device: 9 directed cases plus a 2,000-round seeded fuzz of forged
  used entries and indices; each refusal is sticky; a device scribbling over
  the descriptor table cannot steer the driver.
- `VNET_M6A_UDP_ROUNDTRIP_SIM`: a UDP frame built by M6-A leaves through the TX
  queue byte-exact; the simulated device answers with a frame placed in the RX
  queue, and M6-A parses it (Ethernet, IPv4, UDP checksum, payload).

**Not proven (do not read more into the PASS lines):** no real device, no real
DMA or IOMMU/SMMU mapping, no interrupts, no QEMU slirp round trip, no
cache-coherence or MMIO ordering on real hardware, no physical NIC. The only
real-QEMU evidence is the static config space. A real QEMU end-to-end needs a
guest kernel that drives the device; this module is hosted and the kernel
binding belongs to the native kernel lane.

**Kernel hook (for the native kernel).** After `ck_virtio_net_probe` accepts
the caps: add `aienos_virtio_net.c` to the stage sources, enable memory space
and bus mastering, map the BARs named by the caps, supply `vnet_ops` (volatile
MMIO at BAR + cap offset + off; notify = 16-bit write at the notify window +
off), give a DMA-visible region of `vnet_mem_size(qsize)` bytes with its bus
address, and call `vnet_init`; then poll `vnet_rx` / `vnet_tx_reclaim`.
