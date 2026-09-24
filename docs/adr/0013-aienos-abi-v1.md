# ADR 0013: AIENOS ABI v1

Status: Proposed
Date: 2026-09-24
Governing: [ADR 0012](0012-self-construction-capability-growth-and-generations.md) (rule 5: no native admission without enforcement), [issue #30](https://github.com/aien-dev/aienos/issues/30) (IPC and capability handles), [PR #106](https://github.com/aien-dev/aienos/pull/106) (typed IPC).
Code: [`crates/aienos-kernel/src/abi.rs`](../../crates/aienos-kernel/src/abi.rs).

## Context

M3 puts a kernel-enforced boundary between tasks. Everything that crosses
that boundary (capability handles in registers, typed IPC messages, rights
masks, memory regions) is today defined only by Rust structs in `caps.rs`,
`user.rs` and the typed IPC work in PR #106. That makes the contract an
accident of the current code:

1. `caps::Handle { index: u32, generation: u32 }` is not `repr(C)`. Its
   register form `(generation << 32) | index` lives in private helpers in
   `user.rs` and is unpacked with no validity check.
2. `caps::Rights` is a `u8` whose reserved bits are rejected by the kernel,
   but no document says which bits are reserved or how wide the field is on
   the wire.
3. Resources are opaque `u32` values with no kind.
4. The IPC `Message` layout in PR #106 depends on `repr(C)` and the Rust
   compiler's layout rules on AArch64.

Generated components (ADR 0012) and future non-Rust or non-AArch64 peers
need a contract they can implement from a document, and persisted
capability records need a format that a later build can still read or
reject safely. This ADR freezes that contract as ABI v1.

## Decision

AIENOS ABI v1 is a byte-level contract. Every ABI type has an explicit
little-endian encoding defined here, independent of Rust in-memory layout,
architecture, and pointer width. The reference encoder and decoder is
`crates/aienos-kernel/src/abi.rs`; its golden-byte tests are the executable
form of this document.

### General rules

- Byte order: little-endian for every multi-byte integer.
- Only fixed-width unsigned integers (`u16`, `u32`, `u64`) and fixed arrays
  of them appear on the wire. No `usize`, `isize`, pointers, `Vec`, `String`,
  `&str`, floating point, booleans, or compiler-chosen enum layout.
- Every type has one fixed size. There is no implicit padding: every byte is
  a named field or a named reserved field.
- Reserved fields and reserved bits are written as zero and must be zero on
  decode.
- Enum discriminants are explicit integers. 0 is never a valid discriminant.
- Decoding requires the exact size. Shorter input is `Truncated`; longer
  input is `WrongLength`.

### Types

| Type | Size | Layout (byte offset: field) | Validity |
|---|---|---|---|
| `Handle` | 8 | 0: index u32; 4: generation u32 | generation != 0 |
| `TaskId` | 4 | 0: u32 | any value |
| `ObjectId` | 8 | 0: u64 | any value |
| `ChannelId` | 4 | 0: u32 | any value |
| `DeviceId` | 4 | 0: u32 | any value |
| `ResourceId` | 8 | 0: kind u16; 2: reserved u16; 4: id u32 | kind in 1..=5; reserved == 0 |
| `Rights` | 4 | 0: u32 bit mask | bits 6 to 31 == 0 |
| `Capability` | 16 | 0: resource `ResourceId`; 8: rights `Rights`; 12: reserved u32 | nested rules; reserved == 0 |
| `MemoryRegion` | 16 | 0: base u64; 8: pages u32; 12: reserved u32 | reserved == 0 |
| `Message` | 56 | 0: kind u32; 4: reserved u32; 8: payload 3 x u64; 32: region `MemoryRegion`; 48: object `ObjectId` | reserved == 0; nested rules |

`ResourceKind` discriminants: 1 Console, 2 Channel, 3 Object, 4 Device,
5 MemoryRegion. `ResourceId.id` is the kernel's resource number within that
kind (the existing opaque `u32` resource). It is not an `ObjectId`; an
`ObjectId` is a separate 64-bit identity carried in messages.

`Rights` bits: 0 READ, 1 WRITE, 2 MAP, 3 GRANT, 4 DERIVE, 5 REVOKE. The wire
field is 32 bits so new rights can be added without changing the size; the
kernel's in-memory `caps::Rights` stays `u8` and converts at the boundary.

`Message` keeps the field order of the typed IPC message in PR #106. Its
`_pad` word is the reserved field at offset 4. `Message.kind` is opaque to
this ABI; the IPC layer assigns meaning to it.

### Handles

A handle is 64 bits: a 32-bit slot index plus the 32-bit generation of that
slot when the handle was issued. The register form, used in `x0` by the
syscall path, is `(generation << 32) | index`.

Why 64-bit generational rather than a 32-bit handle:

- Stale-handle protection. When a slot is freed and reused, its generation
  goes up, so an old handle to the same index no longer matches and is
  refused. A task cannot reach a new resource through a handle it kept
  from an old one.
- Generations never wrap. They start at 1 on first use and a slot whose
  generation reaches `u32::MAX` is retired rather than reused, so the same
  (index, generation) pair is never issued twice for one table.
- Generation 0 is never issued, so it is a reserved "no handle" value and
  every decoder rejects it (`InvalidHandle`). Zeroed memory or a zeroed
  register is never a valid handle.
- 32 bits of index and 32 bits of generation both fit one AArch64 register
  and one 64-bit word on any other architecture.

### Versioned envelope

Any ABI value that is persisted or transported outside a single syscall
(capability records, messages written to storage or sent to another
machine) is wrapped in an 8-byte envelope header followed by the payload:

| Offset | Field | Rule |
|---|---|---|
| 0 | tag u16 | known `EnvelopeTag`, and equal to the expected type |
| 2 | version u16 | must equal `ABI_VERSION` (1) |
| 4 | length u32 | payload length in bytes, must equal the type's size |
| 8 | payload | exactly `length` bytes |

`EnvelopeTag` discriminants: 1 Handle, 2 TaskId, 3 ObjectId, 4 ChannelId,
5 DeviceId, 6 ResourceId, 7 Rights, 8 Capability, 9 MemoryRegion,
10 Message. The header layout itself is fixed for every future version, so
any reader can always find the version and length.

Decode checks run in this order and stop at the first failure: header
present, version, tag known, tag matches, length field, total buffer size,
payload.

### Errors

Decoding fails closed. Each failure has its own error:

| Error | Cause |
|---|---|
| `Truncated` | input shorter than required |
| `WrongLength` | input longer than the type, or envelope length field wrong |
| `UnknownVersion` | envelope version is not 1 |
| `UnknownTag` | envelope tag not defined |
| `TagMismatch` | envelope tag defined but for another type |
| `ReservedNonZero` | a reserved field is not zero |
| `ReservedBits` | a reserved rights bit is set |
| `UnknownDiscriminant` | a resource kind is not defined |
| `InvalidHandle` | handle generation is 0 |
| `BufferTooSmall` | output buffer too small when encoding |

### Compatibility and extension

- ABI v1 is frozen. The sizes, offsets, byte order, discriminants and
  validity rules above do not change for version 1.
- New fields are added only by giving meaning to a reserved field or reserved
  bit, or by defining a new version. A v1 decoder keeps rejecting nonzero
  reserved fields, so an old reader refuses a newer record instead of
  misreading it.
- Discriminants (`ResourceKind`, `EnvelopeTag`) are append only and never
  reused, even after a kind or tag is retired.
- A new version gets a new `ABI_VERSION` value. A decoder that does not know
  a version rejects it with `UnknownVersion`; it never guesses.
- Register calling conventions for individual syscalls are outside this ADR;
  they carry v1 values in the register form given here.

### Relation to AEGIS

This ABI is kernel enforcement: it defines what a well-formed handle,
capability, or message is, and the kernel refuses anything else before any
policy runs. AEGIS is runtime policy: it decides whether a well-formed,
correctly authorized request should be allowed for this owner and moment
(ADR 0004, ADR 0012 rule 4). AEGIS never widens what the kernel accepts, and
a malformed value never reaches AEGIS.

## Invariants

1. Every ABI v1 type has exactly one byte encoding, fixed in size, little
   endian, with no implicit padding.
2. Encode then decode returns the same value, and decode then encode returns
   the same bytes, for every valid value. Golden-byte tests pin this for every
   type.
3. Decoding never accepts: short or long input, nonzero reserved fields or
   bits, unknown discriminants, unknown versions, mismatched tags, or
   generation-0 handles.
4. Handle generations start at 1 and never wrap; a retired slot is never
   reissued.
5. No ABI type contains `usize`, `isize`, pointers, heap types, or
   compiler-chosen enum layout. `const` assertions pin the size, alignment and
   field offsets of every in-memory mirror.
6. Discriminants are never reused.
7. No em dashes or en dashes in this document or the ABI code comments.

## Consequences

- `abi.rs` is the reference contract. `caps.rs`, `user.rs` and `ipc.rs`
  adopt these types in a later change (after PR #106 lands); until then
  `abi.rs` provides lossless conversions to and from `caps::Handle` and
  `caps::Rights`.
- Non-Rust and non-AArch64 implementations (other languages, other
  machines through Fabric, generated components under ADR 0012) can
  implement the ABI from this document and check themselves against the
  golden bytes in the tests.
- Persisted capability records and Generation manifests (ADR 0012) can use
  the envelope and be rejected safely by a build that does not understand
  them.
- Any change to a v1 layout is a breaking change and needs a new version and
  a new ADR.
