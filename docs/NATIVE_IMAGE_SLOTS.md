# Native image slots: install, update and recovery without Linux (P11 cuts 1, 2a, 2b, 3 and 4)

STATUS: cut 1 (format, rules, host tool), cut 2a (SLOTLDR.EFI, a separate
slot loader in front of the unchanged image, QEMU gate PASS) and cut 2b
(kernel-side promote / abandon, section 8) and cut 3 (the inactive-slot
updater and the loader in the package, section 9) and cut 4 (the
known-good native recovery image, section 10) done in QEMU; the owner
approved the loader on 2026-10-12 (section 2). Nothing here has run on
hardware (hardware NOT_RUN). The kernel image and its stub are unchanged.
SECURITY_IMPACT: PERSISTENT_FORMAT + RECOVERY (a new on-disk format and a new
recovery rule are specified; from cut 2a SLOTLDR.EFI writes the control
region of the slots partition, and nothing else, before a candidate try;
nothing has been written to a physical machine).

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

## 2. Owner decision (Drake): approved 2026-10-12, narrow scope

**Decision recorded 2026-10-12.** Drake: "Slot loader APPROVED, narrowly
scoped: the frozen boot stub may change only for signed A/B image selection,
boot-success tracking, and rollback. Emulator tests required before hardware:
successful update, invalid signature, interrupted update, unsuccessful boot."
Cut 2a meets that without changing the stub at all: the slot logic is a
separate UEFI application, `SLOTLDR.EFI`, in front of the unchanged stub +
kernel image (section 7). The four required emulator tests are rows 2
(a staged update boots, one counted try per boot; it is not yet made
permanent, that is the kernel promote of cut 2b; after three unsuccessful
boots the loader goes back to A), 3 and 4 (invalid signature, untrusted key)
and 6 (interrupted update) of its QEMU gate; rows 5, 7 and 8 add a tampered
image, both slots invalid and the generation floor. The text below is the request as it was asked.

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
   signing path is offline: `ck_slot_tool tbs M --pubkey HEX64 --out F`
   emits the 448 signed bytes (the owner public key is required because
   `signer_id`, its SHA-256, lies inside the signed bytes; aienos#324), the
   owner signs them on the air-gapped machine with OpenSSL
   (`pkeyutl -sign -rawin`), `attach-sig` verifies and attaches. No private
   key ever touches the Spark. The TEST signer exists for tests only.
   **Cut 1b (merged with this note's follow-up): the package.**
   `scripts/native_package.sh` builds the image twice from a committed tree,
   refuses the package if the two builds differ, records `PACKAGE.txt`
   (commit, variant, image digests, toolchain, component pins, model and
   firmware digests) and `SHA256SUMS`, and sets the slot manifest's
   provenance to the SHA-256 of `SHA256SUMS`, so the owner's one signature
   over the manifest binds the whole package. `docs/NATIVE_PACKAGE.md`.
2. **Cut 2a (done, QEMU): a slot loader in front of the stub.** Built as a
   separate loader, `SLOTLDR.EFI`, not inside the stub (section 7), so the
   qualified image stays byte-identical and its own stub never recurses into
   slot selection. As first planned: the stub locates the
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
   **Cut 3 (done, QEMU; section 9).**
4. **Known-good recovery image.** The same loader plus a slot image on
   recovery media built by our tools, for the dual-invalid case. Then N7 is
   run on the physical candidate inside an attended window.
   **Cut 4 (done, QEMU; section 10).** The recovery image lives on the
   loader's own ESP and runs only when neither slot may boot.

   **Cut 2b (done, QEMU; section 8): kernel-side promote.** After its health milestone the
   kernel writes the control record over its own NVMe path (promote the
   candidate, or mark it failed), so a good update becomes the active slot
   instead of only being tried three times.

The stub itself is unchanged: the statements in BOOT_HANDOFF_CONTRACT
section 7 and native/boot/README.md hold for it; slots live only in
SLOTLDR.EFI.

## 7. SLOTLDR.EFI and its gate (cut 2a)

`native/boot/slot_loader.c` builds `$(OUT)/SLOTLDR.EFI`
(`make -C native/kernel slot-loader`). Why a separate loader and not the
stub: if the stub chose a slot and chain-loaded an image, that image's own
stub would choose again; a front loader keeps the qualified image
byte-identical and keeps the stub frozen. The boot volume's
`EFI/BOOT/BOOTAA64.EFI` becomes SLOTLDR.EFI; the slot images are the
unchanged stub + kernel image.

What it does, in order:

1. Finds whole disks (Block I/O), checks each primary GPT (header and entry
   array CRC32, usable range) and takes the one partition with the slots type
   GUID (`slot_format.h`). None, or more than one across all disks:
   recovery required. The backup GPT is not read; a bad primary fails closed.
2. Reads the control region (units 0-3) and recovers the newest committed
   record with the torn-slot rules (`native/store/torn_slot.c`), read only.
3. Reads both manifests and images (bounded by the slot capacity, read in
   pieces of at most 8 MiB) and verifies each with `ck_slot_verify` against
   the keys baked in at build time.
4. Applies `ck_slot_select`. A candidate try commits the control record with
   tries reduced by one, then reads it back and compares; if that fails the
   candidate is treated as invalid and the selection runs again. This is the
   only write, and it lands only in the control region.
5. Prints `slot_loader: boot=<A|B> reason=<name> gen=<n> tries=<n> floor=<n>`
   and chain-loads the verified bytes with `LoadImage(SourceBuffer)` and its
   own device path (so the chained stub still sees the boot volume) and
   `StartImage`.
6. Both slots invalid: prints `slot_loader: recovery_required (A: <why>; B:
   <why>)` and returns `EFI_LOAD_ERROR` to the firmware.

Never: UEFI variables, runtime services, `ExitBootServices` (the chained
stub leaves boot services itself), `SetWatchdogTimer`, kernel objects (all
checked at build time).

Keys: `CK_SLOT_KEYS=<file>` bakes the owner's public keys in (same file
format as `ck_slot_tool --keys`, generated by `ck_slot_tool keys-c`).
`CK_TEST_SLOT_KEY=1` bakes the RFC 8032 TEST 1 key and the loader prints
`slot_loader: TEST-ONLY key`; it is refused with `CK_HARDWARE_STAGING=1`,
and the two options together are refused.

Boot-success tracking in cut 2a is the tries counter: a candidate that is
never promoted is tried three times and then left; the active slot boots.
Promotion after a kernel health milestone is cut 2b.

Gate: `scripts/qemu_ck_slot_loader_test.sh` (`AIENOS_CK_SLOT_LOADER`, child
`slots` of `scripts/ck_gates.sh`), rows 186-193 of `native/kernel/GATES.md`,
plus the build check row 194 (`make test` runs `slot-loader-check`). Run on
2026-10-12 at code commit bff20a1: PASS, 8 rows, 11 boots, 76 checks, 126 s
under QEMU TCG. Hardware NOT_RUN.

Host tool additions for the gate: `ck_slot_tool slots-image` (writes the
control record and both slots into a slots partition of a disk image),
`ck_slot_tool keys-c`, `ck_slot_tool sign-test --test2` (a second,
untrusted TEST key), and `ck_gpt_image` layout `slots`.

## 8. Kernel promotion and abandon (cut 2b)

Cut 2a left two things to the kernel: making a good candidate the active slot,
and marking a candidate that ran out of tries as failed. Both are now done by
the service kernel (`CK_SERVICE=1`), in `native/kernel/svc/slot_service.c`,
with the loader's own rules and commit routine. There is no second
implementation of the record format.

**How the kernel learns which slot it is.** The control record alone cannot
tell: "candidate on its last try" and "candidate out of tries, active booted"
both read `tries=0`. Before `StartImage`, SLOTLDR.EFI therefore allocates
one page of the OS-loader memory type `0x80000A1E` and writes a 256-byte boot
record into it (`struct ck_slot_boot_record`, `slot_format.h`): booted slot,
the loader's reason, tries, the control sequence it read or committed, the
started manifest's generation, policy generation and image SHA-512, the
loader commit, and a SHA-256 over the first 224 bytes. The page survives
`ExitBootServices` and is listed in the memory map the unchanged stub already
copies into the handoff, so neither the stub nor the handoff format changes.
The kernel copies it in `ck_kernel_entry` right after `ck_handoff_check`,
while the firmware identity map is still live (the kernel never maps that
memory type afterwards, and its frame allocator only hands out conventional
memory, so the page is never reused). The digest catches a torn or stray
page; it is not a signature, because the record comes from inside the same
firmware + loader trust boundary as the handoff itself.

**What the kernel does** (`ck_slot_kernel_action`, `slot_select.c`, pure and
self-tested):

| Boot record and disk | Action | Write |
|---|---|---|
| no record (image not started by SLOTLDR), record fails its checks, no slots partition, no control record, the started slot's manifest on disk differs from the record, or the control sequence moved since the loader read it | refuse, say why | none |
| reason `candidate_try`, control still names the slot, health reached | **promote**: active = this slot, candidate cleared, floor raised to the image's policy generation (never lowered) | one control commit |
| reason `candidate_try`, health not reached | wait; at the stop order the kernel says the candidate was not promoted | none (the loader keeps counting tries down) |
| reason `candidate_exhausted` or `candidate_invalid`, a candidate is set and the booted slot is the active one | **abandon**: candidate cleared, `CANDIDATE_FAILED` flag set, active slot unchanged | one control commit |
| anything else (steady boot of the active slot) | nothing | none |

Health is the service's own milestone, nothing new: the Store is open,
continuity committed this boot (PROVISIONED or RESUMED, the self-test
record the lifecycle already writes) and the lifecycle is READY. It is
checked when the lifecycle starts and again after a successful `unlock`.
Abandon is not gated on health: the loader already decided.

**The write.** One control record commit through the torn-slot protocol
(`ck_slot_control_commit`, `native/boot/slot_control.c`, shared with the
loader and `ck_slot_tool`): body, flush, commit header, flush, then read back
and compare. It goes over the kernel's own NVMe path, through a second
bounded partition view of the slots partition (`ck_dev_slots_disk`, found
with the same strict GPT validation as the AIENOS partition, primary and
backup), never a whole-disk handle. A failed commit leaves the previous record
authoritative and is reported.

**Gate.** Rows 9-11 of `scripts/qemu_ck_slot_loader_test.sh` (GATES.md
rows 195-197) boot SLOTLDR.EFI and the service image from one NVMe disk
(`ck_gpt_image` layout `aienos-slots`: the Store partition and the slots
partition):

- row 9: a healthy candidate B is promoted by the kernel (control
  `active=1 floor=2`), and the next boot is a steady boot of B with no write;
- row 10: a candidate that never becomes healthy (the plain service image,
  whose Store stays locked) spends its last try without promotion; the next
  boot falls back to A and the kernel abandons B (`flags=0x01`), A stays
  active and the host tool agrees the next decision is a steady boot of A;
- row 11 (negative control): the service image started directly, without
  SLOTLDR, finds no boot record and writes nothing although it is healthy.

Both slots invalid stays row 7: `recovery_required`, no image started, the
control record untouched. `make -C native/kernel slot-test` adds the boot
record mutations (each refused with its reason), the kernel-action scenarios
and the shared commit routine.

Not here: the updater that writes a new candidate into the inactive slot
(cut 3, section 9) and the recovery image for the dual-invalid case (cut 4).
Hardware NOT_RUN.

## 9. The inactive-slot updater (cut 3)

The running service kernel writes a new signed image into the slot it is
NOT running from, then stages it as the candidate; the loader tries it on
the next boot and the kernel promotes it after its health milestone
(section 8). One routine does the work, `ck_slot_update`
(`native/boot/slot_update.c`), shared by the kernel and the host tool's
self-test, over the same control-commit routine as the loader.

**Source: the update inbox partition.** GPT type
`58D9C90E-497A-4848-95DD-EB7E22B0CE96` (`CK_SLOT_INBOX_TYPE`), on the same
NVMe disk, with one slot's shape: the signed manifest in unit 0, the image
from unit 1. The desk tool fills it from a package
(`ck_slot_tool inbox-image --m slot/MANIFEST.signed.bin,image/BOOTAA64.EFI`);
the kernel only reads it. How the inbox is filled on the physical machine
(an owner-attended step) is not part of this cut.

**Operator verb `update`** (lifecycle READY only: a LOCKED Store, or a
pending task, refuses it; `core/lifecycle_fsm.c`). The kernel:

1. refuses unless it was started by SLOTLDR.EFI (boot record), a control
   record exists, no candidate is staged, and the booted slot is the active
   one; the target is the other slot;
2. reads the inbox manifest and image and runs the loader's own
   `ck_slot_verify` (Ed25519 signature by a trusted key, SHA-512 of the
   image, size within the slot) and a dry run of
   `ck_slot_stage_candidate` (generation above the floor). Any refusal:
   **nothing is written**;
3. zeroes the target's manifest unit and flushes: from here the target is
   invalid and the loader keeps booting the active slot;
4. writes the image units, flushes; then the manifest last, flushes;
5. reads the whole target back and verifies it again from the disk bytes
   (a mismatch zeroes the manifest unit again and refuses);
6. stages: one control record commit (candidate = target, three tries).

Every write is bounded to the target slot's unit range; the active slot and
the control region (except the one commit of step 6) are never written. An
interruption before step 6 leaves the control record untouched and the
target invalid (or, only between steps 5 and 6, valid but not staged, which
the loader ignores until a later `update` stages it).

**Trusted keys.** The service image is built with the same key table as
SLOTLDR.EFI (`ck_slot_tool keys-c`): RFC 8032 TEST 1 in the TEST-keys
service image (`CK_SERVICE_TEST_KEYS=1`, QEMU only), the Owner Root from
`CK_OWNER_PUBKEYS` under `CK_HARDWARE_STAGING`; the plain service image
has no table and refuses every update. TEST keys under hardware staging
stay refused by the Makefile (gate row 15) and by `keys-c`.

**Evidence.**
- `make -C native/kernel slot-test`: 155 checks. The 22 added for cut 3: a
  positive update (B written, verified from disk, staged, A unchanged, the
  loader's next decision is a candidate try; exhausted tries and an invalid
  candidate fall back to A), refusal while a candidate is staged, an
  injected I/O error at each of the 16 writes of an update (every one
  refused with A and the control record untouched and B invalid or
  unstaged), a stop at each step, and ten refusals before any write (bad
  signature, wrong key, wrong digest, truncated inbox, generation at the
  floor, booted slot not active, no trusted key, no control record, image
  larger than the slot, corrupt manifest). Three mutants of
  `slot_update.c` (writing the active slot, staging before the image,
  skipping signature verification) each fail these checks.
- `scripts/qemu_ck_slot_loader_test.sh` rows 12-15 (`docs/GATES.md`):
  row 12 update from slot A writes and stages B, a second `update` is
  refused, A's bytes are unchanged, the next boot tries B and the kernel
  promotes it; row 13 QEMU is killed in the middle of the image write
  (TEST-only `update halt-after=1`), the control record and A are
  untouched, the loader refuses the half-written B and boots A, and a new
  `update` then succeeds; row 14 an inbox signed by the wrong key and one
  with a flipped image byte are refused with the slots partition
  byte-identical; row 15 the update is refused while the Store is locked,
  and a TEST-key updater image is refused under hardware staging.
- The package carries SLOTLDR.EFI (`docs/NATIVE_PACKAGE.md`, "Slot loader
  in the package").

The known-good recovery image for the case where both slots are invalid
is cut 4 (section 10). Hardware NOT_RUN: nothing was written to a physical disk.

## 10. The known-good native recovery image (cut 4)

Cuts 2a to 3 cover one bad slot: the loader falls back to the other one. When
both slots are unusable the loader used to stop with `recovery_required` and
hand the machine back to the firmware. Cut 4 adds a small, signed AIENOS image
that SLOTLDR.EFI starts in that case, and that can rewrite a slot without
Linux.

**What it is.** A service image built with `CK_RECOVERY=1`
(`make -C native/kernel CK_SERVICE=1 CK_RECOVERY=1 full`; output directory
suffix `-recovery`). It is the service kernel without a model and without an
inference unit (make refuses `CK_RECOVERY` with `CK_INFER_LIB`), and it says so
on its first lifecycle line: `recovery: AIENOS native recovery image (P11 cut
4): no model, ...`. Its manifest has the slot format (section 4), is signed by
the same trusted key as a slot image (today the Owner Root, see
`docs/OWNER_KEY_CEREMONY.md`) and binds the image by SHA-512.

**Where it lives and how it is selected** (`native/boot/slot_loader.c`,
`slot_format.h`):

- On the loader's own boot volume (the ESP): `\EFI\AIENOS\RECOVERY.MAN`
  (exactly one 4096-byte manifest unit) and `\EFI\AIENOS\RECOVERY.EFI`
  (at most 64 MiB, `CK_SLOT_RECOVERY_MAX_BYTES`).
- Only after the loader has found the slots partition, read the control
  record and both slots, and `ck_slot_select` returned `recovery_required`
  (both slots invalid, below the floor, or the active one unusable while the
  candidate is out of tries). Whenever a slot may boot, the recovery image is
  never used, even if it is on the ESP.
- Not for the earlier refusals: no trusted key built in, no slots partition
  or two of them, a damaged primary GPT, a slots partition that is too small.
  Then the loader still returns `EFI_LOAD_ERROR` to the firmware; this cut
  does not repair the partition table.
- Verified like a slot: manifest structure, a trusted signer, the Ed25519
  signature over the manifest, and the image's SHA-512. A refused or missing
  recovery image prints `slot_loader: recovery image refused (<why>): not
  booted` and nothing starts. On success the loader prints `slot_loader:
  boot=R reason=recovery_required gen=<n> ...`, hands the kernel a boot record
  with slot 2 (`CK_SLOT_BOOT_RECOVERY`, shown as `R`), reason
  `recovery_required` and tries 0, and starts the image with `LoadImage` +
  `StartImage` from the verified bytes. The loader writes nothing on this
  path.
- The same image may also be staged into a slot like any other signed image.
  Booted from a slot it is an ordinary slot image: the normal rules apply
  (it is promoted after health, and its updater refuses unless it is the
  active slot).

**What it can do.**

- Unlock the Store (the service image's `unlock` verb; in QEMU the TEST keys
  open it at boot), show `status` and `evidence`, and `shutdown`.
- Rewrite a slot from a package: the operator verb `update` runs the cut 3
  updater (section 9) unchanged, with one difference: booted as the recovery
  image it does not require to be the active slot or that no candidate is
  staged. It writes the slot that is not active, after the same checks
  (signature and digest before any write, generation above the floor and
  above the last good generation, read back after the write), and stages it
  as the candidate with fresh tries, replacing a stale (failed or exhausted)
  candidate. The active slot and the loader are never written.
- After `shutdown` and a reboot, the loader tries the rewritten slot
  (`candidate_try`) and the kernel promotes it after its health milestone
  (section 8). From then on the machine boots normally.

**What it cannot do.**

- Promote or abandon anything: its boot record names no slot, and the kernel
  says `slot: booted the recovery image (both slots unusable) ...: nothing
  promoted or abandoned`.
- Write without a control record: a disk whose control region is empty or
  corrupt is refused (`no control record on disk`, nothing written). The
  control record is created at install time.
- Install an image below the generation floor or not newer than the last
  good generation (no rollback through recovery).
- Repair the GPT, the ESP, the loader or itself; rotate keys; use the network
  or a TPM; run a model.
- Production unlock still follows the Store's own key rules: an image built
  for hardware staging without its keys stays LOCKED and refuses `update`
  (gate row 15).

**Limits recorded here.** No generation floor applies to the recovery image
itself: an older, owner-signed recovery image on the ESP would still start.
It can only write a slot through the checks above, so it cannot install an
image below the floor. The package (`docs/NATIVE_PACKAGE.md`) does not yet
build or carry the recovery image, and putting it on the ESP is an attended
desk step. Hardware NOT_RUN: nothing here has run on the Spark.

**Linux is not recovery.** A development rescue through Linux (the BootNext
return to Linux of aienos#273, a Linux USB stick, or a Linux shell writing the
disk) does not satisfy the final N7 gate. N7 needs this path (both slots
invalid, the recovery image, a slot rewritten, a reboot into it) on the
physical candidate inside an attended window. That run is NOT_RUN.

**Tests.**

- `make -C native/kernel slot-test` (`ck_slot_tool selftest`, 172 checks): the
  recovery boot record (valid; tries, a slot reason, generation 0, a reserved
  byte and a sequence without a control record each refused), the kernel
  action for a recovery boot (nothing, also when healthy), and a recovery
  update over a disk with both slots damaged and an exhausted candidate
  (an ordinary update still refused, a wrong key refused with nothing
  written, B rewritten and staged with fresh tries, A's bytes untouched,
  the loader's next decision a candidate try of B).
- `scripts/qemu_ck_slot_loader_test.sh` row 7 (no recovery image on the ESP:
  nothing starts), row 16 (both slots invalid, the recovery image starts,
  `update` rewrites B, the next boot tries B and the kernel promotes it; the
  recovery image is not used while B may boot) and row 17 (a recovery image
  signed by the wrong key or with a flipped byte is refused, no kernel runs,
  the slots partition is byte-identical; make refuses a recovery image with a
  model). `native/kernel/GATES.md` rows 192, 215 and 216.
