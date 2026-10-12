# Native image slots: install, update and recovery without Linux (P11 cut 1)

STATUS: PROPOSED (design note plus host tooling; no loader or kernel image
code changed in this cut; nothing here has run on hardware).
SECURITY_IMPACT: PERSISTENT_FORMAT + RECOVERY (a new on-disk format and a new
recovery rule are specified; neither is written to any machine by this cut).

Program: AIEN native v1 (aien-architecture CURRENT_EXECUTION_PLAN, addendum
2026-10-12), work package P11, gate N7: "Install, update and recovery work
with no Linux installation or recovery USB required for the supported
procedure. A BootNext return to Linux is insufficient." Today's rollback is
the one-time BootNext return to Linux (aienos#273), which N7 rejects.

## 1. The finding P11 was asked to make

The P01 addendum left one question to P11: is an A/B loader "the cheapest way
to hold two native images"? Answer, after reading what the image already does:

**Yes, two slots in their own partition, selected by the stub.** The reasons:

1. The stub already reads raw disk blocks through the firmware's own Block
   I/O driver before `ExitBootServices` (`native/boot/efi_model.c`: locate
   the whole disk by GPT disk GUID, `ReadBlocks` in page-aligned pieces).
   Reading a 4096-byte manifest and an image from a fixed partition offset
   is the same operation.
2. The image already carries freestanding SHA-512 and Ed25519 verification
   (`native/sig`) and SHA-256 (`native/argus/sha256.c`). Verifying a signed
   manifest costs no new primitive. `slot-free` in the kernel Makefile proves
   the selection code needs nothing else.
3. The kernel already writes a partition crash-safely with the torn-slot
   region (`native/store/torn_slot.c`): two bodies, two commit headers, the
   newest valid wins, a torn write can only lose the write in flight. The
   control record that says "which slot is active, which is the candidate,
   how many tries remain" fits in one such region.
4. UEFI gives the stub `LoadImage(SourceBuffer)` and `StartImage` (boot
   services table, `native/boot/efi.h`). A verified slot image can be
   started from memory with no filesystem, no second boot entry and no
   firmware variable write. The loader's own PE stays the single BootOrder
   entry; the images it chooses between live in the slots partition.

What this costs: one new partition, one new loader step (read control, read
and verify two manifests, pick, chain-load) and the updater on the kernel
side. What it does not cost: any Linux tool at install, update or recovery
time, any `BootNext` write, any change to the stub's frozen PE layout.

What it does **not** solve on its own (stated so nobody reads more into it):
if both slots are invalid, or both are below the security floor, the loader
can only report `recovery_required` and return to the firmware. Covering that
case without a Linux USB is the known-good AIENOS recovery image of P11
(a third, read-only copy of the loader plus a slot image on recovery media
built by our own tools), which is a later cut. Dual-invalid cannot happen by
update alone under the rules below (the active slot is never written while
it is active), only by media failure or a deliberate wipe.

## 2. Decision needed from the owner (Drake)

The loader is frozen: `docs/BOOT_HANDOFF_CONTRACT.md` section 7 says "There
are no slots and, per Q3, none will be added to this loader", and
`native/boot/README.md` parks "signature checks, BootNext staging, rollback".
Those statements stay true after this cut. Changing them is an owner decision
(ADR 0024 Q3; TRUST-1 Q14 "Loader changes rarely"). This note asks for that
decision with the design pinned, so the decision is about a concrete thing.

If the owner says yes, cut 2 adds one bounded step to the stub (section 6).
If the owner says no, the format and tool remain host-side specification and
N7 needs another path, which this note does not have.

## 3. Sources this design follows

- ADR 0006 (accepted 2026-09-23): "System updates employ transactional A/B
  slot switching with deterministic kernel health milestone verification";
  "atomic and safely reversible via hardware-backed A/B slots".
- TRUST-1 implementation plan, cross-cutting Q14 (loader minimality: "only
  what may boot, which slot, and what verified facts the kernel receives")
  and Q19 (slot/manifest: "A=known-good, B=candidate (roles, not names).
  Manifest minimum: format version, generation, kernel digest, image digest,
  loader ABI, kernel ABI, signer, commit, provenance, rollback compat, policy
  generation, timestamp, signature. Health gates before promotion receipt;
  explicit authenticated promotion"). Every Q19 field is in section 4.
- `docs/NATIVE_BOOT_ROLLBACK_CONTRACT.md` section 2: "A candidate may consume
  exactly one boot attempt. It may never promote itself into the persistent
  default boot path." Kept in a stronger form: a candidate gets a bounded
  number of attempts (3), each one consumed by the loader before the
  candidate runs, and promotion is a separate authenticated step by the
  kernel after health, never by the candidate's own boot.
- Owner public key format: `tools/ck_owner_gen.c` (`owner_root_ed25519
  <64 hex>`), the same file the trust path already uses. TEST keys (RFC 8032
  TEST 1/2/3) are refused for hardware exactly as there.

## 4. On-disk format (native/boot/slot_format.h is normative)

Partition: its own GPT partition, type GUID
`8B1096CD-7928-4E08-B5E4-C19B6B532760` (new; the existing AIENOS store
partition `38DAAC89-...` is not touched and keeps its one-partition rule).
Layout in 4096-byte units, U = partition size in units:

| Units | Content |
|---|---|
| 0..3 | control region: a torn-slot region holding the control record |
| 4 .. 4+CAP-1 | slot A: manifest in the first unit, image from the second |
| 4+CAP .. 4+2*CAP-1 | slot B: same |

CAP = (U - 4) / 2; an image may be at most (CAP - 1) * 4096 bytes. Current
images are 155648 (core) and 352256 (full) bytes; a 64 MiB partition holds
two images 500 times larger than today's.

Manifest, 4096 bytes, little-endian, the first 448 bytes signed:
magic `AIENSLT1`, version 1, payload kind 1 (one PE, `BOOTAA64`-style image:
kernel digest equals image digest), loader ABI 1, kernel ABI 3 (the current
handoff ABI), generation (strictly increasing per release), policy
generation (<= generation; promotion raises the floor to it), minimum
rollback generation (<= generation; documentation of compatibility),
image length, image SHA-512, kernel SHA-512, signer id (SHA-256 of the
signing public key), commit (40 lower-case hex), provenance (64 printable
ASCII, zero padded), timestamp, flags 0, reserved 0, Ed25519 signature,
zero pad to 4096.

Control record, 4096 bytes: magic `AIENSLC1`, version 1, active slot,
candidate slot (or none), tries remaining (<= 3), flags (bit 0: last
candidate failed), generation floor, last good generation, reserved 0.
It is committed through the torn-slot region (`ts_commit`) so a power cut
during the write leaves the previous record.

## 5. Rules (native/boot/slot_select.c is normative; its self-test is the oracle)

A slot is **usable** when its manifest is structurally valid, signed by a
trusted owner key, its image bytes match the digest, and its generation is
at or above the control record's floor.

Selection at every boot, with the control record C read from the region:

1. No valid C (blank media, corrupt): boot the usable slot with the highest
   generation (A on a tie); write nothing. Nothing usable: recovery required.
2. C names a candidate with tries remaining and the candidate is usable:
   commit C with tries - 1 **before** starting it, then boot the candidate.
   Three failed boots in a row (power cut, panic, hang and reset) therefore
   end with tries 0 and the next boot falls through to rule 3. No boot loop.
3. Candidate exhausted or unusable: boot the active slot if usable, write
   nothing. The kernel sees the exhausted candidate in C and abandons it.
   An exhausted candidate never boots on its own authority.
4. Active unusable and the other slot usable and not the candidate: boot the
   other slot (fallback to the last promoted image). Otherwise: recovery
   required, loader returns to the firmware.

Transitions (kernel side, after the owner-authorized update is written):

- **stage**: refuses the active slot, a generation below the floor, or not
  above the last good generation; sets tries 3, clears the failed flag.
- **promote**: only the staged candidate, only after the booted kernel passed
  its health milestone; flips active, clears candidate, sets last good, and
  raises the floor to the manifest's policy generation. The floor never goes
  down (monotonic security floor; TRUST-1 "reconcile rollback policy with
  monotonic security floors").
- **abandon**: clears the candidate and sets the failed flag; the active
  slot keeps booting.

Authorized rollback: promote the known-good image again with a higher
generation (a re-signed manifest). Unauthorized rollback (an old image below
the floor) is unusable by definition; the owner key is needed to lower
nothing and to re-release anything.

## 6. Cuts

1. **This cut (host only).** Format, rules, host tool `ck_slot_tool`
   (`make -C native/kernel slot-test`: 94 checks covering layout, key
   derivation, 26 manifest mutations each refused with its named reason,
   10 control mutations, 16 selection scenarios including the bounded tries
   and the floor, the transitions, and torn-slot commit/recover with a
   simulated torn write) and the freestanding proof (`slot-free`). The
   signing path is offline: `ck_slot_tool tbs` emits the 448 signed bytes,
   the owner signs them on the air-gapped machine with OpenSSL
   (`pkeyutl -sign -rawin`), `attach-sig` verifies and attaches. No private
   key ever touches the Spark. The TEST signer exists for tests only.
   **Cut 1b (merged with this note's follow-up): the package.**
   `scripts/native_package.sh` builds the image twice from a committed tree,
   refuses the package if the two builds differ, records `PACKAGE.txt`
   (commit, variant, image digests, toolchain, component pins, model and
   firmware digests) and `SHA256SUMS`, and sets the slot manifest's
   provenance to the SHA-256 of `SHA256SUMS`, so the owner's one signature
   over the manifest binds the whole package. `docs/NATIVE_PACKAGE.md`.
2. **Stub reads a slot (after the owner's yes).** The stub locates the
   slots partition on the boot disk, reads C, reads both manifests and
   images, calls `ck_slot_select`, commits the try if asked, and chain-loads
   the chosen image with `LoadImage(SourceBuffer)` + `StartImage`. A QEMU
   gate proves: fresh media boots A; a staged B boots and, after three forced
   failures, A boots again with B abandoned; a corrupt manifest is refused;
   a wrong key is refused; a torn control write keeps the old record.
3. **Kernel updater.** Writes the inactive slot over the kernel's own NVMe
   path, verifies by reading back, stages through the torn-slot region, and
   promotes after its health milestone. Qualifies interrupted updates,
   tampered images, failed candidates and authorized rollback (the P11 list).
4. **Known-good recovery image.** The same loader plus a slot image on
   recovery media built by our tools, for the dual-invalid case. Then N7 is
   run on the physical candidate inside an attended window.

Until cut 2 is approved and merged, the boot path is unchanged and the
statements in BOOT_HANDOFF_CONTRACT section 7 and native/boot/README.md hold.
