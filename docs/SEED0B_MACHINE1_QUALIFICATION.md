# SEED-0B on Machine 1 (P2-9): operator procedure

Status: **prepared, not run.** SEED-0B is qualified in QEMU only
([evidence/seed0b_qemu_2026-09-25.md](../evidence/seed0b_qemu_2026-09-25.md)).
This page is the attended procedure for the physical step. An agent must not
run it or claim Machine 1 qualification; the operator runs it and publishes
the evidence.

The claim to prove on hardware is the same as in QEMU, with identical
artifact bytes and ArtifactIds (ADR 0014 §8):

> An externally supplied, signed Binary Artifact v0 was authenticated,
> deterministically admitted with authority no broader than requested,
> executed from the exact verified bytes under W^X EL0 isolation, used an
> authorized READ capability, was denied unauthorized WRITE and forged
> authority, was fully reclaimed, and produced a canonical admission
> receipt. Hostile artifacts failed closed.

Everything here is **TEST ONLY**: the artifact signer and the receipt signer
are RFC 8032 test vectors. It is not a production identity ceremony, it
enrolls no key, and it changes no trust state.

## Blocking prerequisites (all required; stop if any is missing)

1. **TRUST-1 owner-signed boot chain** ([#40](https://github.com/aien-dev/aienos/issues/40)).
   Native Machine 1 boots are paused by operator decision (2026-09-24):
   turning Secure Boot off changes TPM PCR 7 and breaks the secrets sealed
   to it. **Secure Boot stays on.** The qualification image must therefore
   be signed by the owner-controlled chain TRUST-1 defines. Do not disable
   Secure Boot, enroll the test keys, or relax any other mechanism to run
   this step.
2. **Native-boot rollback qualification** (M0) and the one-time boot
   discipline in [NATIVE_BOOT_ONE_TIME.md](NATIVE_BOOT_ONE_TIME.md): a
   BootNext-only entry, BootOrder unchanged, automatic return to Linux.
3. **Recovery media and fallbacks** per
   [RECOVERY_MEDIA_MACHINE1.md](RECOVERY_MEDIA_MACHINE1.md): the
   `AIENOSRECOV` stick plugged in, the `ubuntu` entry, the firmware fallback
   loader and the installed kernels present.
4. **Console capture.** Per-candidate lines and receipts go to the console
   only (they exceed the bounded `AienosBootReportV1` record). Capture the
   Spark UART with the rig's Pi GPIO UART path
   ([HARDWARE_TEST_RIG.md](HARDWARE_TEST_RIG.md)); HDMI capture alone is
   not sufficient evidence for this step.
5. **The QEMU qualification is green on the exact commit being staged**:
   `AIENOS_STRICT=1 ./scripts/verify_all.sh` with `SEED_0B_QEMU: PASS`.

## 1. Prepare the inputs (Spark, Linux, no boot changes)

```bash
git switch --detach <qualified commit>
./scripts/seed0b_machine1_prepare.sh ~/seed0b-machine1
```

This builds, from a clean commit only:

- `BOOTAA64.EFI`: `aienos-handoff --features seed0b-qualification,hardware-staging`
  (receipts carry the `SEED-0B-MACHINE1` tier);
- `ARTIFACTS/`: the same signed `.AIEN` bytes the QEMU run used (P26SEED,
  the P2-5 probes and the H01–H29 matrix);
- `ids.txt`, `expected.txt`, and `MANIFEST.sha256` (with the commit).

It never touches the ESP, BootOrder/BootNext, Secure Boot, the TPM or any
firmware variable. Check that the P26SEED ArtifactId it prints equals the
one in the QEMU evidence.

## 2. Sign the image with the TRUST-1 chain

Sign `~/seed0b-machine1/BOOTAA64.EFI` with the owner-controlled AIENOS
signing key exactly as TRUST-1 specifies, and record the signed image's
SHA-256. The `.AIEN` files are not re-signed: their test signatures are what
the qualification checks.

## 3. Stage one boot (attended)

Use the established one-time procedure, which creates a BootNext-only entry
and leaves BootOrder unchanged, with two differences:

- the staged loader is the signed SEED-0B image from step 2;
- copy `~/seed0b-machine1/ARTIFACTS/*.AIEN` to `\EFI\AIENOS\ARTIFACTS\` on
  the same ESP. Nothing else on the ESP changes.

Record `efibootmgr` output, `mokutil --sb-state` and the TPM PCR 0–7 values
before the boot.

## 4. Boot, capture, return

Start the UART capture, then reboot once. The image runs every candidate,
prints one `artifact:` line and one `receipt:` line per candidate plus the
`artifact_*` header and footer, and resets. BootNext is consumed, so the
machine returns to Linux. If it does not, use the recovery media.

After return, confirm BootOrder, Secure Boot state and PCR 0–7 match the
pre-boot record, and that the Linux system is intact.

## 5. Verify the captured log (Spark, Linux)

```bash
AIENOS_SEED0B_SERIAL=<captured console log> \
AIENOS_SEED0B_INPUTS=~/seed0b-machine1 \
AIENOS_SEED0B_EVIDENCE=evidence/seed0b_machine1_<date>.md \
    ./scripts/qemu_artifact_test.sh
```

This mode boots nothing. It proves the staged inputs are byte-identical to a
fresh deterministic pack, applies every qualification-boot check to the
captured log (P26SEED allow/deny results, the matrix, frame accounting), and
checks, signs with the TEST ONLY receipt key, and verifies every receipt.
It requires the `SEED-0B-MACHINE1` tier, so a QEMU log cannot pass. The
step passes only on `SEED_0B_MACHINE1: PASS`.

## 6. Publish

Commit the generated evidence file with the captured log's SHA-256, the
signed image's SHA-256, the pre/post boot state records, and the operator's
name and date. SEED-0B PASS requires both `SEED_0B_QEMU: PASS` and
`SEED_0B_MACHINE1: PASS` on the same artifact bytes.
