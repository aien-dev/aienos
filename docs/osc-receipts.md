# OSC unit launch requires a realization receipt (aienos#383)

Label for everything below: **QEMU (aarch64 virt), TEST signer, not physical.** Nothing here has run on a
Spark or any real machine. Contract: omega `spec/one-layer-receipts.md` (receipt v1, normative; section
numbers below refer to it). Gate: `scripts/qemu_ck_osc_receipt_test.sh` (`OSC_RECEIPT` row in
`scripts/ck_gates.sh`, notes in `native/kernel/GATES.md`).

## What it does

A receipt is a 416-byte record, signed by a key of a stated class, saying that omega's independent checker
(checker2) judged one exact program (the OSC IR) and that one executable is bound to it by hash. The kernel
now refuses to launch an admitted OSC unit unless a receipt that is valid for that exact unit comes with the
launch.

- `artifact/osc_receipt.{h,c}`: `osc_receipt_verify(receipt, len, &accept, &policy, &info)`, a pure function
  written from the spec (no checker2 code copied). It reuses the in-tree SHA-256 and Ed25519 verify and
  compares keys, hashes and identities in constant time.
- `core/osc_task.c`: `ck_osc_launch` takes the receipt bytes and verifies them with the kernel's own policy
  (`ck_osc_policy`, `core/osc_admit.c`) before anything else; callers cannot pass a policy. A missing receipt
  is `RECEIPT_MISSING`. Nothing is mapped and nothing runs on any refusal. The code is still copied and
  re-hashed before mapping.
- `osc_unit_admit` and the container signature check are unchanged. A receipt grants no capability.
- Receipts reach the kernel as Store entries (magic `OMRCPT1`), kept by name (24 slots, 512 bytes each; a
  longer entry is kept truncated so it is refused `RECEIPT_SIZE`). The self-test drivers pair a unit with its
  receipt by name.

## Refusal codes

Kernel code = 64 + the spec's stable reason number; the name is `RECEIPT_<spec name>`. Order is spec
section 6; the first failure decides.

| code | name | when |
|---|---|---|
| 64 | RECEIPT_MISSING | no receipt (kernel only) |
| 65..71 | SIZE, MAGIC, VERSION, SIGNATURE_ALGORITHM, SIGNER_CLASS, EVIDENCE_CLASS, EPOCH_ORDER | structure |
| 73 | TEST_SIGNER_IN_PRODUCTION | release build and the receipt is not OWNER class |
| 74 | UNTRUSTED_SIGNER | fingerprint names no anchor of the receipt's class; a key in both classes; release mode and the owner key is not the owner root |
| 75 | BAD_SIGNATURE | |
| 76 | REVOKED | receipt id, then signer key fingerprint (`revoked=receipt_id` or `revoked=signer_key` on the launch line) |
| 77, 78, 79 | STALE_EPOCH, EXPIRED, NOT_YET_VALID | epoch window, inclusive at both ends |
| 86 | UNTRUSTED_CHECKER | checker identity not in the pinned list |
| 80..83 | WRONG_TARGET, WRONG_FIRMWARE, PROGRAM_MISMATCH, EXECUTABLE_MISMATCH | binding to the unit |
| 87 | WRONG_PRODUCER | only when a policy names a producer (the kernel's does not) |
| 88 | DEPENDENCIES_MISMATCH | any dependency claimed |
| 96 | LRAT_PROOFS_REQUIRED | evidence class 2 (kernel-assigned number, see below) |
| 84 | ARGUMENT | verifier called without a unit or a policy |

## Kernel policy (`ck_osc_policy`)

- Target: SHA-256(`"OMEGA-TARGET-V1\0"` ‖ `aienos-ck-aarch64-el0`). Program = the unit's IR hash (section 1).
  Executable = the unit's code hash. Firmware: none (all zero). Dependencies: the empty list.
- Checker identity: one pinned identity, checker2 at omega 265ce82a (`artifact/osc_receipt_anchor.h`).
- Epoch floor 10, current epoch 20 (compile-time constants: there is no epoch authority yet).
- Qualification build (`CK_SEED0B_TEST_ANCHOR=1`): checker2's TEST key is the only receipt anchor
  (`artifact/osc_receipt_test_anchor.h`, separate from the unit TEST key) and one fixture receipt id is revoked.
- Release build: release mode, no receipt anchor at all, so every receipt is refused. The owner root
  `578ada3c…` is listed in `osc_receipt_anchor.h` but is not trusted for receipts: it is in no anchor set
  until `docs/OWNER_KEY_CEREMONY.md` says it may sign receipts.

## Ambiguities in the spec, written down (no guess taken)

1. **Revoked id and revoked key share one code.** The brief asked for a reason of its own per case; the spec
   gives both `REVOKED` (12). The kernel returns the spec code and says which list matched in a separate
   field (`revoked=receipt_id|signer_key`).
2. **Evidence class 2.** Section 6 accepts class 2 as well formed; section 10 says a class 2 receipt is valid
   only when the same LRAT proofs are given and replayed, and names `LRAT-PROOFS-REQUIRED` without a number.
   The kernel is given no proofs and has no LRAT checker, so it refuses class 2 (fail closed) with the
   kernel-assigned code 96, after every section 6 step has passed (the spec does not place this check in the
   section 6 order).
3. **The "current epoch" and the floor** have no source in the spec beyond "the verifier's". The kernel uses
   compile-time constants.
4. **Producer.** The unit carries no producer identity, so there is nothing to compare with; the kernel
   policy names none and the producer field is NOT CHECKED (checker2's `verify` with no `--producer` would
   require all zero; n_producer.rcpt is the one case where the kernel and checker2 disagree, recorded in
   `expected.txt`).

## UNVERIFIED (not done, not claimed)

- **Physical Spark: NOT_RUN.** Only QEMU. No hardware, no GPU, no reboot.
- **OWNER receipts:** none exist; the owner root is not trusted for receipts; a positive OWNER acceptance is
  untested (refusals only).
- **Translation validation:** the executable is bound to the program by hash only (evidence class 1 says
  so). Nothing shows the code implements the IR.
- **LRAT proofs** are not replayed in the kernel; class 2 is refused instead.
- **Requirements and input digests:** NOT CHECKED. **Producer:** NOT CHECKED.
- **Dependency receipts:** not resolved; any claimed dependency is refused.
- **Container manifest** (entry table, capabilities, stack and tick budgets) is not bound by a receipt; it
  stays bound by the unit signature only.
- **Epoch and revocation** are compile-time; there is no live revocation feed or epoch authority.
- **Name pairing** of unit and receipt in the self-test drivers is a test convenience; no Store-driven or
  shell-driven launch exists yet.

## Tests

- Host: `tests/test_osc_receipt.c` (in `make test` and `make sanitize`, qualification and release builds):
  every case of `tests/fixtures/osc_receipt/expected.txt` (checker2's own verdict recorded beside the kernel's),
  trust inputs against the fixtures, each structure reason and the order of the checks, epoch window edges,
  all 3328 single-bit flips of a valid receipt refused, in-memory receipts re-signed with the published TEST
  seed (reproducing checker2's signature byte for byte), the Store receipt table.
- Mutants: `make osc-receipt-mutants` removes each of the 25 guards in `osc_receipt.c` one at a time; the
  test must fail for every one.
- QEMU: `scripts/qemu_ck_osc_receipt_test.sh`, 17 launches of one unit: the valid receipt runs it (first and
  last launch); every other launch is refused with its own named reason and maps nothing.
- Fixtures: `tests/fixtures/osc_receipt/make-receipts.sh` (provenance in `PROVENANCE.txt`).
