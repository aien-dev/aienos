# ADR 0014: Binary Artifact v0 and Native Admission

Status: Proposed  
Date: 2026-09-25  
Phase 2 base: `04189416b0b14d8aa8961f2469caf52078fd2c09` (recovery closure, PR #117)  
Governing: [ADR 0012](0012-self-construction-capability-growth-and-generations.md), [ADR 0013](0013-aienos-abi-v1.md).  
Scope: SEED-0B qualification; no production owner root, M4 store, device authority, DMA, Secure Boot enrollment, TPM mutation, or self-promotion.

AIENOS will accept a native task only from a canonical, signed Binary Artifact v0 whose identity covers its execution metadata, requested authority, resource envelope, and exact payload bytes. The kernel parses and verifies the same bytes that the loader later copies into private W^X EL0 pages; admission reduces each scoped request under local policy and emits a separately signed Admission Receipt v0. Serialized bytes, rather than Rust layout or firmware file-loading decisions, are the contract.

## 1. Terms and trust boundary

- **Binary Artifact**: one bounded byte string containing a fixed header, two section records, bounded capability requests, one resource envelope, exact code/data payload bytes, and a detached-in-identity signature block appended at EOF.
- **ArtifactId**: the domain-separated SHA-256 identity of the canonical unsigned artifact bytes. It binds what may execute and what the artifact asks for.
- **Capability request**: a bounded request for rights over one named kernel object or channel. It conveys no authority by itself.
- **Granted admission**: the deterministic result of intersecting verified requests with local resource availability and local policy. A grant cannot contain rights or bounds broader than its corresponding request.
- **Admission Receipt**: a canonical, signed record of verification, policy, exact requested and granted capability sets, resources, and execution/canary outcome.
- **Qualification trust anchor**: an explicitly test-only Ed25519 identity. It may qualify SEED-0B but must never be confused with a production owner or machine identity.

Firmware is a byte provider only. It may read a specifically named `.aien` file and reserve the pages holding it before firmware exit, then pass a read-only physical-address/length descriptor. It does not authenticate, interpret, or authorize the artifact. The kernel copies those bytes to protected staging memory before parsing; the staging pages are never executable.

Host tooling provides `pack`, `inspect`, `id`, `sign`, and `verify`. `pack`
is deterministic for the same canonical manifest and payload. Host and kernel
verification use the same no-std parser and canonicalization implementation;
the host must not sign a separate interpretation of the file.

## 2. Binary Artifact v0 canonical encoding

All offsets below are from the first artifact byte. All integers are unsigned fixed-width little-endian unless explicitly signed. Arrays are raw bytes. No serialized field is a Rust enum, pointer, `usize`, `bool`, or compiler-layout-dependent struct. There is no implicit padding. The decoder rejects nonzero reserved bytes, unknown flags, unknown section kinds, unknown rights, noncanonical ordering, duplicate resource requests, and unconsumed/trailing bytes. Rust structs are in-memory views only.

### 2.1 Header: 128 bytes

| Offset | Size | Field | v0 rule |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `AIENART\0` |
| 8 | 2 | format_version | `0` |
| 10 | 2 | header_size | `128` |
| 12 | 2 | target_arch | `1` = AArch64 little-endian |
| 14 | 2 | abi_version | `1` = AIENOS ABI v1 |
| 16 | 4 | flags | `0` |
| 20 | 4 | total_length | exact complete file length, including signature |
| 24 | 4 | section_table_offset | `128` |
| 28 | 2 | section_count | exactly `2` |
| 30 | 2 | section_entry_size | `32` |
| 32 | 2 | entry_section_index | `0` (code) |
| 34 | 2 | reserved | zero |
| 36 | 4 | entry_offset | byte offset within code section; 4-byte aligned |
| 40 | 4 | capability_table_offset | `192` |
| 44 | 2 | capability_count | `0..=16` |
| 46 | 2 | capability_entry_size | `48` |
| 48 | 4 | resource_envelope_offset | `capability_table_offset + count * 48` |
| 52 | 2 | resource_envelope_size | `48` |
| 54 | 2 | reserved | zero |
| 56 | 4 | payload_offset | 16-byte alignment after the envelope; gap bytes are zero |
| 60 | 4 | payload_length | exact sum of code and data file lengths |
| 64 | 4 | signature_offset | exactly `payload_offset + payload_length` |
| 68 | 2 | signature_length | `100` |
| 70 | 2 | signature_algorithm | `1` = Ed25519 |
| 72 | 56 | reserved | all zero |

The section table follows the header immediately. Capability records follow
the section table immediately. The 48-byte resource envelope follows the
capability records immediately. Only the alignment gap between the envelope
and payload is permitted, and it must be all zero. Payload bytes are code
followed immediately by data. The 100-byte signature block follows the
payload immediately and is the final byte range. Thus the total length is
exactly `signature_offset + 100`.

### 2.2 Section records: 32 bytes each

| Offset | Size | Field | v0 rule |
|---:|---:|---|---|
| 0 | 2 | kind | `1` = code; `2` = data |
| 2 | 2 | permissions | code exactly `R|X` (`5`); data exactly `R|W` (`3`) |
| 4 | 4 | reserved | zero |
| 8 | 4 | payload_relative_offset | relative to `payload_offset`; code `0`, data exactly code file length |
| 12 | 4 | file_length | exact initialized bytes in the payload |
| 16 | 4 | memory_length | mapped bytes before page rounding; code equals file length, data is at least file length |
| 20 | 4 | alignment | `4096` |
| 24 | 8 | reserved | zero |

Records must occur in code-then-data order. Neither section may be empty.
`alignment` constrains each section's virtual load base; it does not add
padding between the serialized code and data payload bytes.
The memory length must fit its envelope page allocation. The entry offset
must identify a complete 4-byte AArch64 instruction inside code file bytes.
There are no relocations, dynamic linking, writable-executable sections, or
implicit imports in v0. Syscalls use ABI v1 and are checked against the
task's admitted capability table.

### 2.3 Capability requests: 48 bytes each

| Offset | Size | Field | v0 rule |
|---:|---:|---|---|
| 0 | 2 | resource_kind | `3` = Object or `2` = Channel, matching ABI v1 `ResourceKind` |
| 2 | 2 | flags | zero |
| 4 | 4 | resource_id | concrete local resource number; zero is invalid |
| 8 | 4 | rights | ABI v1 rights bits: READ=1, WRITE=2, MAP=4, GRANT=8, DERIVE=16, REVOKE=32 |
| 12 | 4 | bounds_kind | `1` = object byte range; `2` = channel message/byte budget |
| 16 | 4 | max_operations | positive hard upper bound |
| 20 | 4 | reserved | zero |
| 24 | 8 | max_bytes | positive byte limit for this resource |
| 32 | 8 | byte_offset | object offset for kind 1; zero for kind 2 |
| 40 | 8 | byte_length | nonzero object range for kind 1; zero for kind 2 |

Rights must be nonzero and contain only the six defined ABI v1 bits. Object
requests use bounds kind 1, with `max_bytes <= byte_length`; channel requests
use bounds kind 2 and require zero offset/length. Both kinds require positive
`max_operations` and `max_bytes`. A request must name exactly one resource
and use exactly one valid bounds form. Records are strictly sorted by
`(resource_kind, resource_id)` and duplicates are rejected. Policy may deny
a request or reduce its rights, operation count, byte limit, and object
range. The invariant is `granted capabilities ⊆ requested capabilities`;
admission cannot mint a resource, add a right, extend a bound, or combine
requests to create broader authority.

### 2.4 Resource envelope: 48 bytes

| Offset | Size | Field | v0 format maximum |
|---:|---:|---|---:|
| 0 | 4 | code_pages | 1..=64 |
| 4 | 4 | data_pages | 1..=64 |
| 8 | 4 | stack_pages | 1..=16 |
| 12 | 2 | max_capabilities | `capability_count..=16` |
| 14 | 2 | reserved | zero |
| 16 | 4 | ipc_messages | 0..=1024 |
| 20 | 4 | ipc_bytes | 0..=1,048,576 |
| 24 | 8 | cpu_ticks | 1..=1,000,000,000 |
| 32 | 8 | elapsed_ticks | 1..=1,000,000,000 |
| 40 | 4 | syscall_count | 1..=65,536 |
| 44 | 4 | reserved | zero |

All page and byte arithmetic uses checked operations. The kernel may impose
lower hard limits. It rejects an envelope before execution if a field
exceeds either limit, section memory lengths do not fit the declared pages,
the stack/IPC/capability resources cannot be reserved atomically, or any
reservation would overflow. Partial task creation is forbidden: all required
frames, page-table storage, stack, scheduler/task slot, and capability slots
are reserved before pages are installed. Failure releases every reservation.

### 2.5 Signature block: 100 bytes

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 2 | algorithm | `1` = Ed25519 |
| 2 | 2 | reserved | zero; header and block algorithm must match |
| 4 | 32 | signer_fingerprint | SHA-256 of the raw 32-byte Ed25519 public key |
| 36 | 64 | signature | Ed25519 signature over the domain-separated ArtifactId |

The public key is obtained only from the selected local trust-anchor set by
fingerprint. The artifact never supplies a key that can make itself trusted.

## 3. Canonical identity and signature

For a well-formed artifact, `canonical_unsigned_artifact` is the exact byte
range `[0, signature_offset)`: header, section records, capability records,
resource envelope, required zero alignment bytes, and exact code/data bytes.
The header's signature offset, length, and algorithm fields are included;
the signer fingerprint and signature bytes are not.

```text
ArtifactId = SHA256(
    "AIENOS-ARTIFACT-V1\\0"
    || canonical_unsigned_artifact
)

signature = Ed25519.Sign(
    private_key,
    "AIENOS-ARTIFACT-SIGNATURE-V1\\0" || ArtifactId
)
```

The file's payload digest is `SHA256(exact code bytes || exact data bytes)`.
The loader separately hashes the bytes in its private loaded code/data pages
after copy and deterministic zero-fill and before permissions become
executable; that result must match the digest of the admitted image. Any
change to code/data bytes, target, ABI, entry, requested rights/bounds, or
resource envelope changes ArtifactId. Signature-block changes leave
ArtifactId unchanged but must fail signer lookup or signature verification.

## 4. Size, extension, and rejection rules

- Maximum complete artifact length: 16 MiB. Maximum combined file payload:
  8 MiB. Maximum section count: 2. Maximum capability count: 16.
- Parsing uses checked integer arithmetic, validates every range against the
  supplied byte slice, and rejects truncation, overflow, overlaps, gaps other
  than the defined zero alignment bytes, payload spill, trailing bytes, and
  lengths inconsistent with the exact complete file length.
- Version 0 has no optional extension area. Unknown flags, reserved values,
  enum values, target/ABI values, section kinds, bounds kinds, rights bits,
  and signature algorithms are rejected. A later incompatible encoding
  requires a new format version and an explicit decoder; v0 readers never
  skip unknown data.
- Entry point outside code file bytes, unaligned entry point, empty sections,
  memory lengths exceeding page budgets, invalid rights/bounds, duplicate or
  unsorted resources, or any nonzero reserved byte are structural failures.
- Stable kernel rejection reasons include `BadMagic`, `UnsupportedVersion`,
  `WrongTarget`, `WrongAbi`, `LengthOverflow`, `Truncated`, `SectionOverlap`,
  `BadEntryPoint`, `DigestMismatch`, `UntrustedSigner`, `BadSignature`,
  `MalformedCapability`, `RightsEscalation`, and `ResourceLimit`.

## 5. Admission, loading, and lifecycle

Admission is deterministic and does not execute candidate code. Its input is
the parsed and structurally validated metadata, successful ArtifactId and
signature verification, local trust anchors, local policy, and a snapshot of
reservable kernel resources. It checks target, ABI, signer trust, request
resolution, rights/bounds intersection, entry point, the full resource
envelope, and policy digest. A request denied by policy receives no handle;
if the task's required contract cannot be met, admission rejects the whole
candidate.

For a deterministic `policy_digest`, the v0 canonical local policy is a
64-byte header followed by zero or more 48-byte policy records sorted by
`(resource_kind, resource_id)`. The header is: magic `AIENPOL\0` (8 bytes),
version u16=`0`, header size u16=`64`, record size u16=`48`, record count
u16=`0..=16`, maximum code/data/stack pages u32 each, maximum capability
count u32, maximum IPC messages u32, maximum IPC bytes u32, maximum CPU ticks
u64, maximum elapsed ticks u64, maximum syscalls u32, and reserved u32 zero.
Each record uses the same 48-byte field encoding as a capability request,
but `rights`, `max_operations`, `max_bytes`, and object range fields describe
the greatest grant policy allows for that resource. The digest is
`SHA256("AIENOS-ADMISSION-POLICY-V1\\0" || exact_policy_bytes)`. A kernel may
apply stricter compiled-in hard maxima; these are part of its verifier/build
identity and cannot be relaxed by artifact metadata.

The loader pipeline is fixed: receive bytes; parse; validate structure;
compute ArtifactId; verify signature; run admission policy; reserve every
resource atomically; allocate private code/data/stack pages; copy exact file
bytes and zero-fill the declared memory tails; hash the `file_length` bytes
read back from the private code pages followed by the `file_length` bytes
read back from the private data pages (excluding page padding and zero-fill
tails); compare with the admitted payload digest; clean D-cache, invalidate I-cache,
and issue required AArch64 barriers; remove code write permission; map code
EL0 RX, data EL0 RW+NX, and stack EL0 RW+NX (with guard pages where the page
map permits); install only the granted M3 capability handles; then make the
task runnable in EL0. No writable alias to executable physical pages is
allowed. The source/staging buffer remains NX and is not mapped into the task.

Every candidate follows `Received → Parsed → Verified → Authorized → Mapped
→ CanaryRunning → CanaryPassed → Admitted`. Every failure enters
`Rejected/Destroyed`, revokes candidate capabilities, releases pages and
slots, and records evidence. Timeout, fault, invalid syscall, resource
overrun, or failed canary terminates only the candidate. Scheduler code has
no artifact parser or signature responsibilities.

## 6. Trust-anchor and signing interfaces

The shared no-std artifact library exposes separable interfaces equivalent
to `TrustAnchorSet`, `SignatureVerifier`, `ArtifactVerifier`, and
`ReceiptSigner`. Ed25519 is the v0 signature algorithm; use a reviewed no-std
implementation with pinned, offline-available sources. Do not implement
elliptic-curve cryptography locally.

The ordinary production trust-anchor set is empty and fails closed. A build
feature named `seed0b-test-anchor` may add one known qualification public key;
the boot report must visibly identify a SEED-0B qualification build. Any
matching private test material is explicitly TEST ONLY, kept out of release
builds, and cannot enroll Secure Boot keys or alter TPM state. No owner root
or production receipt key is created in Phase 2; those ceremonies belong to
M5.

## 7. Admission Receipt v0

Receipt encoding is also independent of Rust layout. Every multi-byte value
is little-endian, reserved bytes are zero, and the record has exactly 512
bytes. Unknown versions, flags, decisions, tiers, algorithms, inconsistent
presence flags, and nonzero absent optional fields are rejected.

### 7.1 Fixed record layout

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 8 | magic | ASCII `AIENRCP\\0` |
| 8 | 2 | receipt_version | `0` |
| 10 | 2 | header_size | `96` |
| 12 | 4 | record_size | `512` |
| 16 | 4 | flags | bit 0 machine ID present; bit 1 context ID present; bit 2 timestamp present; all others zero |
| 20 | 2 | decision | `1` admitted; `2` rejected; `3` canary failed; `4` destroyed |
| 22 | 2 | qualification_tier | `1` = SEED-0B test qualification |
| 24 | 8 | sequence | monotonically increasing sequence within one verifier context |
| 32 | 16 | nonce | unique within that verifier context |
| 48 | 8 | observed_time_ns | UTC observation metadata, or zero when flag 2 is clear; never an admission input |
| 56 | 8 | reserved | zero |
| 64 | 4 | execution_status | `0` not run; `1` exited; `2` timeout; `3` fault; `4` bad syscall; `5` resource overrun; `6` canary failed |
| 68 | 4 | exit_status | signed 32-bit little-endian task exit code; zero if not executed |
| 72 | 4 | result_flags | bit 0 read succeeded; bit 1 write denied; bit 2 candidate reclaimed; bit 3 canary passed; all others zero |
| 76 | 4 | reserved | zero |
| 80 | 16 | reserved | zero |
| 96 | 32 | artifact_id | ArtifactId |
| 128 | 32 | payload_digest | SHA-256 of exact serialized code/data payload |
| 160 | 32 | artifact_signer_fingerprint | fingerprint from verified artifact signature block |
| 192 | 32 | policy_digest | digest of canonical local policy used for this decision |
| 224 | 32 | requested_capability_digest | digest of canonical request records |
| 256 | 32 | granted_capability_digest | digest of canonical grants; zero if rejected before grants |
| 288 | 32 | resource_envelope_digest | digest of the canonical 48-byte envelope |
| 320 | 32 | verifier_identity | stable verifier/build identity digest |
| 352 | 32 | machine_id | MachineId, or all zero when absent |
| 384 | 16 | generation_context_id | generation u64 then context ID u64; both zero when absent |
| 400 | 2 | receipt_signature_algorithm | `1` = Ed25519 |
| 402 | 2 | reserved | zero |
| 404 | 32 | receipt_signer_fingerprint | SHA-256 of raw Ed25519 receipt public key |
| 436 | 64 | receipt_signature | signature over domain-separated receipt digest |
| 500 | 12 | reserved | zero |

All digests are SHA-256 outputs in their ordinary 32-byte order. Compute:

```text
requested_capability_digest = SHA256(
    "AIENOS-ARTIFACT-CAP-REQUESTS-V1\\0" || exact_sorted_request_records
)
granted_capability_digest = SHA256(
    "AIENOS-ADMISSION-CAP-GRANTS-V1\\0" || exact_sorted_grant_records
)
resource_envelope_digest = SHA256(
    "AIENOS-ARTIFACT-RESOURCES-V1\\0" || exact_48_byte_resource_envelope
)
verifier_identity = SHA256(
    "AIENOS-VERIFIER-IDENTITY-V1\\0" || verifier_build_identity_bytes
)
```

These use canonical byte encodings, never Rust memory. The verifier build
identity bytes are the lowercase 40-byte Git commit ID, target and ABI as
u16 little-endian values, and a one-byte qualification feature ID (zero for
ordinary builds; one for `seed0b-test-anchor`).

### 7.2 Receipt digest and signature

The receipt signature block is excluded from its own digest. The digest
input is the exact canonical bytes `[0, 400)`; signature algorithm and
signer fingerprint are metadata in the signature block, outside that
range.

```text
ReceiptDigest = SHA256(
    "AIENOS-ADMISSION-RECEIPT-V1\\0" || receipt_bytes[0..400]
)

receipt_signature = Ed25519.Sign(
    receipt_private_key,
    "AIENOS-ADMISSION-RECEIPT-SIGNATURE-V1\\0" || ReceiptDigest
)
```

The test receipt key has a distinct qualification fingerprint. Production
receipt-key custody waits for M5. Wall-clock timestamps are observation
metadata only; authorization depends on deterministic policy, verified
bytes/signatures, and reserved resources. Sequence numbers increase within
the verifier context; nonce bytes are unique within that context. Qualification
receipts label the context scope so their sequence is not mistaken for a
machine-persistent counter before M4.

## 8. SEED-0B qualification boundary

The first artifact is a small AArch64 EL0 program requesting READ on one
existing object and no WRITE, device, DMA, network, filesystem, NVMe-write,
or firmware authority. It must read through the admitted handle, receive a
denial on write through that handle, and exit deterministically. QEMU
qualification must precede any Machine 1 boot, using identical artifact bytes
and ArtifactId. Physical qualification uses the one-time boot discipline and
must preserve Secure Boot, TPM state, BootOrder, and the existing Linux
recovery path. An artifact or AI agent cannot authorize or promote itself.

The acceptance invariant is:

```text
identified bytes = verified bytes = admitted bytes = mapped bytes = executed bytes
```

Phase 2 is complete only after the same qualified artifact is admitted,
executed with attenuated authority, denied an unauthorized write, reclaimed,
and covered by a valid receipt in QEMU and then on Machine 1.
