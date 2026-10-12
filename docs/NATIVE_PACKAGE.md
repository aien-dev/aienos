# Reproducible native package with owner-signed verification (P11 cut 1b)

STATUS: IMPLEMENTED host-side (build, sign, verify, self-test). Nothing in
this document installs, boots or touches a machine. Gate N7 stays NOT_RUN.
SECURITY_IMPACT: RECOVERY (the package is what install, update and recovery
will carry; the format is covered by `docs/NATIVE_IMAGE_SLOTS.md`).

This is the "reproducible native package with exact component/model/firmware
manifests and owner-signed verification" item of work package P11 (AIEN
native v1 plan, aien-architecture CURRENT_EXECUTION_PLAN addendum 2026-10-12).

## What a package is

`scripts/native_package.sh build --out DIR --generation N [...]` makes:

| File | Content |
|---|---|
| `image/BOOTAA64.EFI` | the image (core, full, or hardware-staging variant), mode 444 |
| `PACKAGE.txt` | `key value` lines: format, repo, commit and commit time, variant, generation, policy generation, min rollback generation, image bytes/SHA-256/SHA-512, `reproducible two_clean_builds_identical`, gcc/ld/make versions, build host arch, `pin <repo> <sha>` lines from `--pins`, `model_bytes`/`model_sha256` from `--model`, `firmware <name> <bytes> <sha256>` per `--firmware`, and for the staging variant the SHA-256 of the owner public keys file and the machine id file |
| `SHA256SUMS` | `sha256sum` lines over the image and `PACKAGE.txt` |
| `slot/MANIFEST.bin` | the unsigned slot manifest (`native/boot/slot_format.h`): generation, digests, commit, timestamp = commit time, **provenance = the 64 hex characters of SHA-256(`SHA256SUMS`)** |
| `slot/MANIFEST.tbs` | the 448 bytes the owner signs |
| `slot/MANIFEST.signed.bin` | after `sign`: the manifest with signer id and signature, verified before it is written |

One signature covers everything: the manifest signs the image digest and the
provenance; the provenance is the digest of `SHA256SUMS`; `SHA256SUMS` covers
`PACKAGE.txt` and the image. Change any pin, digest or toolchain line and the
provenance no longer matches; the self-test proves each of these refusals.

## Rules the script enforces

- **Committed tree only.** A dirty working tree is refused (tests may pass
  `--allow-dirty`; the self-test does so only when the tree is dirty).
- **Reproducible or not signable** (TRUST-1 Q24). The image is built twice
  into two fresh directories; if the two differ, no package is written. On
  2026-10-12 the full image reproduced byte for byte across clean builds
  (sha256 540b7f75... at aienos 6e3c492).
- **Never overwritten, never re-signed in place.** `--out` must not exist;
  `sign` refuses when `MANIFEST.signed.bin` exists.
- **Private keys never on the Spark.** `build` emits the to-be-signed bytes;
  the owner signs them on the air-gapped machine
  (`openssl pkeyutl -sign -inkey owner_root.pem -rawin -in MANIFEST.tbs -out MANIFEST.sig`)
  and `sign --sig MANIFEST.sig --pubkey <64 hex>` attaches the signature
  after verifying it. `sign-test` uses the RFC 8032 TEST 1 key and is for
  tests only; `ck_owner_gen` and the slot tool refuse that key for hardware.
- **Verify fails closed.** `verify --package DIR --keys FILE` checks
  `SHA256SUMS`, the `PACKAGE.txt` image digest and the reproducibility line,
  the provenance binding, the commit match, the signed manifest's signature
  under the owner keys (`tools/ck_owner_gen.c` file format), and that the
  signed manifest equals the built one in every field but signer/signature.
  An unsigned package is refused unless `--allow-unsigned` (reported as not
  installable).

## Self-test

`make -C native/kernel package-test` runs `scripts/native_package_test.sh`:
32 checks (build with pins/model/firmware; every PACKAGE.txt line; refusals
for an existing output, a bad pin, owner files on the wrong variant, an
unsigned package, double signing, the wrong owner key, a tampered image, a
tampered PACKAGE.txt with and without re-made sums, a flipped signature byte,
a missing SHA256SUMS, another package's signed manifest, a non-reproducible
build via a test hook, the hardware-staging variant with the labelled
TEST-FIXTURE owner files). About 35 s, nothing booted.

## What is still missing for N7

The package is the input to the updater (slots cut 3) and to the known-good
recovery image (slots cut 4). Neither exists yet; both wait on the owner
decision in `docs/NATIVE_IMAGE_SLOTS.md` section 2. Install today is still
the one-time BootNext procedure of `docs/NATIVE_BOOT_ONE_TIME.md`, which N7
rejects as the supported path.
