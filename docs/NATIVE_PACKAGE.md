# Reproducible native package with owner-signed verification (P11 cut 1b)

STATUS: IMPLEMENTED host-side (build, tbs, sign, verify, self-test). Nothing in
this document installs, boots or touches a machine. Gate N7 stays NOT_RUN.
SECURITY_IMPACT: RECOVERY (the package is what install, update and recovery
will carry; the format is covered by `docs/NATIVE_IMAGE_SLOTS.md`).

This is the "reproducible native package with exact component/model/firmware
manifests and owner-signed verification" item of work package P11 (AIEN
native v1 plan, aien-architecture CURRENT_EXECUTION_PLAN addendum 2026-10-12).
Format 2 (2026-10-12) adds the provenance record the owner asked for: "matching
two builds demonstrates reproducibility under the recorded build conditions.
Connecting the signed package to reviewed source also requires recording the
source revision, toolchain, inputs, and resulting digest. Keep that evidence
with the release candidate."

## What a package is

### Integrated CPU service profile

For the resident production CPU service, select `--variant service-hardware-staging`
with `--owner-pubkeys`, `--machine-id` and `--model`. The recipe uses
`CK_SERVICE=1 CK_HARDWARE_STAGING=1` and the in-tree inference library. The
existing Makefile enforces owner provisioning, the resident lifecycle and
boot-disk-only model ingest; no QEMU fw_cfg model fallback or TEST Store keys
are selected. This profile builds a package only; it neither installs nor boots it.

The standalone inference library is built offline, locked, in release mode for
`aarch64-unknown-none` twice, using fresh Cargo homes and target directories.
Inherited Rust environment flags and caller, repository and user Cargo
configuration are excluded: Cargo runs from a fresh scratch directory with
an absolute manifest path. Configuration in the scratch directory's ancestors
is refused. The standalone crate has only local in-tree dependencies.
Untracked files, including ignored files, in either inference crate are refused
so Cargo cannot auto-discover an unrecorded `build.rs` or Rust module.
Both libraries, both service images and both owner-key slot loaders must match.
The package carries `inputs/libaienos_infer_kernel.a` in `SHA256SUMS`, binding
the exact linked archive through the existing signed package provenance.

Format 3 records the fixed inference recipe, Cargo/rustc versions, inference
manifest and lock digests, archive bytes/digest and reproducibility result.
`input_make_vars` binds the archive digest alongside the owner file digests.
Verification requires exactly one of each service field, checks the archive
and checksum coverage, and recomputes manifest/lock digests from the recorded
revision when available. `--same-host` also compares Rust toolchain versions.
Inference fields on other profiles are refused; existing profiles remain supported.

`--model` records the supplied model's size and digest; its bytes are not embedded
or decoded by packaging. Preparing and verifying `MODEL.MAP`, actual model
inference, owner receipt authority, attended boot and recovery still require
their own acceptance evidence. Public owner fixtures used by the self-test
qualify the build recipe only and cannot authorize deployment. A dirty-tree
package is test evidence, never a release candidate.

`scripts/native_package.sh build --out DIR --generation N [...]` makes:

| File | Content |
|---|---|
| `image/BOOTAA64.EFI` | the image (core, full, or hardware-staging variant), mode 444 |
| `PACKAGE.txt` | the provenance record, `key value` lines (next table) |
| `SHA256SUMS` | `sha256sum` lines over the image and `PACKAGE.txt` |
| `PROVENANCE.txt` | `package_sha256 <64 hex>` = SHA-256(`SHA256SUMS`): the resulting package digest. It is a separate file because `SHA256SUMS` covers `PACKAGE.txt`, so `PACKAGE.txt` cannot hold a digest of `SHA256SUMS` |
| `slot/MANIFEST.bin` | the unsigned slot manifest (`native/boot/slot_format.h`): generation, digests, commit, timestamp = commit time, **provenance = `package_sha256`** |
| `slot/MANIFEST.tbs` | the 448 bytes the owner signs, written by `tbs --package DIR --pubkey HEX64` (or `build --pubkey`). The manifest's `signer_id` (SHA-256 of the owner public key) lies inside the signed bytes, so the bytes to sign depend on which key will sign |
| `slot/MANIFEST.signed.bin` | after `sign`: the manifest with signer id and signature, verified before it is written |

`PACKAGE.txt` lines (format 3; the loader lines are in "Slot loader in the package"), grouped as the owner's correction names them:

| Group | Lines |
|---|---|
| Source revision | `format 3`, `repo aien-spark/aienos`, `commit <40 hex>`, `commit_time <unix seconds>`, `tree_clean yes` (`no` only for test builds with `--allow-dirty`) |
| What was asked for | `variant`, `generation`, `policy_generation`, `min_rollback_generation` |
| Toolchain | `toolchain_cross <prefix or none>` (the `CROSS` value the kernel Makefile resolves, asked from make itself), `toolchain_cc`, `toolchain_ld`, `toolchain_objcopy` (first line of `<CROSS>gcc/ld/objcopy --version`), `toolchain_make` (first line of `make --version`), `build_host_arch` (`uname -m`) |
| Inputs | `input_make_goal` (`all` for core, `full` otherwise), `input_make_vars` (`none`, or `CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS=sha256:<hex> CK_MACHINE_ID=sha256:<hex>`), `input_env_ck none` (any `CK_*` in the environment or in an outer make's `MAKEFLAGS` is refused, so nothing unrecorded selects the image), `input_makefile_sha256` (`native/kernel/Makefile`), `input_image_ld_sha256` (`native/boot/image.ld`), `pin <repo> <sha>` per `--pins` line, `model_bytes`/`model_sha256` from `--model`, `firmware <name> <bytes> <sha256>` per `--firmware`, and for the staging variant `owner_pubkeys_sha256` and `machine_id_sha256` |
| Resulting image | `image image/BOOTAA64.EFI`, `image_bytes`, `image_sha256`, `image_sha512`, `reproducible two_clean_builds_identical` |

The resulting package digest is `PROVENANCE.txt` `package_sha256`.

One signature covers everything: the manifest signs the image digest and the
provenance; the provenance is `package_sha256`; `SHA256SUMS` covers
`PACKAGE.txt` and the image. Change any record line and the provenance no
longer matches; the self-test proves each of these refusals.

The slot loader `SLOTLDR.EFI` is part of the package since P11 cut 3 (format
3): see "Slot loader in the package" at the end of this document.

## What the record proves and what it does not

- **Two identical builds prove reproducibility under the recorded conditions
  only.** The same commit, built twice in fresh directories with the recorded
  toolchain, gave the same bytes. It says nothing about other compilers,
  other hosts or other flags.
- **The record is what ties the package to reviewed source.** The commit
  (with `tree_clean yes`), the toolchain lines, the inputs and the resulting
  digests together say "these bytes came from that reviewed revision, built
  this way". Anyone with the repository can check the commit, its time and
  the Makefile and linker-script digests (`verify` does), and with the same
  toolchain can rebuild and compare the image digest.
- **It does not prove the toolchain itself is trustworthy.** A compromised
  compiler or linker produces the same wrong bytes every time, so a
  reproducible build inherits its flaws. The toolchain lines name what was
  trusted; they do not vouch for it.
- **Pins, model and firmware are recorded, not re-checked.** The package
  carries their digests, not the files; `verify` prints them as recorded.
- Keep the whole package directory (record, sums, provenance, manifests)
  with the release candidate: it is the evidence.

## Rules the script enforces

- **Committed tree only.** A dirty working tree (tracked files changed) is
  refused. Tests may pass `--allow-dirty`; the record then says
  `tree_clean no`, and `verify` and `sign` refuse that package unless given
  `--allow-dirty` too (`sign-test` accepts it; the TEST key never signs for
  hardware).
- **Reproducible or not signable** (TRUST-1 Q24). The image is built twice
  into two fresh directories; if the two differ, no package is written. On
  2026-10-12 the full image reproduced byte for byte across clean builds
  (sha256 540b7f75... at aienos 6e3c492).
- **No unrecorded inputs.** `CK_*` variables in the environment or passed
  down in `MAKEFLAGS` are refused; the variant's make goal and variables are
  the only ones used, and they are recorded.
- **Never overwritten, never re-signed in place.** `--out` must not exist;
  `sign` refuses when `MANIFEST.signed.bin` exists.
- **Private keys never on the Spark.** `tbs --pubkey` emits the to-be-signed
  bytes for that public key; the owner signs them on the offline machine
  (`openssl pkeyutl -sign -inkey owner_root.key.pem -rawin -in MANIFEST.tbs -out MANIFEST.sig`,
  `docs/OWNER_KEY_CEREMONY.md`) and `sign --sig MANIFEST.sig --pubkey <64 hex>`
  attaches the signature after verifying it. Before 2026-10-12 `ck_slot_tool
  tbs` emitted the bytes with an empty `signer_id`, while `attach-sig` checks
  the signature with `signer_id` filled in, so no real offline signature could
  attach; `tbs` now requires `--pubkey` and the self-test signs with a
  throwaway OpenSSL key end to end. `sign-test` uses the RFC 8032 TEST 1 key
  and is for tests only; `ck_owner_gen` and the slot tool refuse that key for
  hardware.
- **Verify fails closed.** `verify --package DIR --keys FILE` checks
  `SHA256SUMS`, `PROVENANCE.txt`, every record line it can recompute
  (exactly one of each required line; image bytes, SHA-256 and SHA-512;
  `tree_clean`; the make goal and variables against the variant; the commit
  time, Makefile and `image.ld` digests against the commit when the
  repository has it), the provenance binding, the commit match, the signed
  manifest's signature under the owner keys (`tools/ck_owner_gen.c` file
  format), and that the signed manifest equals the built one in every field
  but signer/signature. With `--same-host` it also compares the toolchain
  lines with the toolchain running here; without it they are printed as
  `recorded`. Every line is printed as `checked` or `recorded`. An unsigned
  package is refused unless `--allow-unsigned` (reported as not installable).

## Self-test

`make -C native/kernel package-test` runs `scripts/native_package_test.sh`:
85 checks. Build with pins/model/firmware; every PACKAGE.txt line including
each provenance line against an independent computation; the manifest
provenance equals `package_sha256`; refusals for an existing output, a bad
pin, owner files on the wrong variant, `CK_*` in the environment and in
`MAKEFLAGS`, a dirty tree (in a scratch worktree of HEAD, the real checkout is
never touched), an unsigned package, double signing, the wrong owner key, a
tampered image, a tampered PACKAGE.txt with and without re-made sums and
`PROVENANCE.txt`, a tampered or missing `PROVENANCE.txt`, a flipped signature
byte, a missing SHA256SUMS, another package's signed manifest, a
non-reproducible build via a test hook; twelve record tampers with re-made
sums (tree_clean, Makefile and image.ld digests, commit time, image SHA-512
and size, make goal and variables, `input_env_ck`, a missing and a duplicated
line, and a toolchain line under `--same-host`); the hardware-staging variant
with the labelled TEST-FIXTURE owner files; and the offline signing round
trip with a throwaway OpenSSL Ed25519 key (`tbs` without and with
`--pubkey`, the TEST key refused, a signature over signer-less bytes refused,
a dirty-tree package refused for a real signature, attach, verify under the
keys file, `signer_id` equal to OpenSSL's SHA-256 of the raw public key).
About 40 s, nothing booted.

## What is still missing for N7

The package is the input to the updater (slots cut 3, QEMU only:
`docs/NATIVE_IMAGE_SLOTS.md` section 9) and to the known-good recovery image
(slots cut 4). The owner approved the slot loader on 2026-10-12
(`docs/NATIVE_IMAGE_SLOTS.md` section 2); the package carries it since cut 3
(section below). Install today is still
the one-time BootNext procedure of `docs/NATIVE_BOOT_ONE_TIME.md`, which N7
rejects as the supported path.

## Slot loader in the package (P11 cut 3)

Format 3 adds the A/B slot loader (`native/boot/slot_loader.c`,
`docs/NATIVE_IMAGE_SLOTS.md`) to every package:

| File / line | Meaning |
| --- | --- |
| `loader/SLOTLDR.EFI` | `make slot-loader`, built twice from the same tree like the image; the two builds must be byte-identical or `build` refuses |
| `loader loader/SLOTLDR.EFI` | path inside the package |
| `loader_keys owner` or `test` | `owner` for `--variant hardware-staging`: the `--owner-pubkeys` file is the loader's `CK_SLOT_KEYS` (Owner Root keys; `ck_slot_tool keys-c` refuses an RFC 8032 TEST key in it). `test` for `core` and `full`: the labelled TEST 1 key loader (`CK_TEST_SLOT_KEY=1`), never for hardware |
| `loader_bytes`, `loader_sha256` | size and SHA-256 of the loader |
| `loader_reproducible two_clean_builds_identical` | the two builds matched |

`SHA256SUMS` covers `loader/SLOTLDR.EFI`, so the owner's one signature over
the slot manifest (whose provenance is `package_sha256`) binds the loader too.
The loader itself is not a slot payload: it is installed on the ESP once
(owner-attended, not part of this cut) and verifies slot manifests with the
keys it was built with. `verify` refuses a package whose loader bytes or
digest differ from the record, whose `loader_keys` does not match the
variant, a `test` loader without its "TEST-ONLY key" note, or an `owner`
loader carrying any TEST-ONLY note. Self-test rows (`make package-test`):
record lines, coverage by `SHA256SUMS`, a tampered loader byte, a missing
loader, tampered `loader_sha256` / `loader_keys` / missing `loader_bytes`
lines, and the hardware-staging package's owner-key loader without a
TEST-ONLY note. Format 2 packages (no loader) are refused by format 3
`verify`; rebuild them.
