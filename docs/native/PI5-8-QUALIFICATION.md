# PI5-8 groundwork: release qualification evidence (Pi 5)

QUALIFICATION ONLY, TEST keys only. This is the evidence package for qualifying the Pi, not a public release. No owner or
release key exists, was generated or was used.

## Q1 Reproducible builds

`scripts/ck_pi5_repro_check.sh [commit]` makes two clean detached worktrees of one commit at two different paths, builds all
eleven Pi images in each (pi5, pi5-store, pi5-unlock, pi5-unlock-card, pi5-fact, pi5-infer, pi5-agent, pi5-lifecycle,
pi5-artifact, pi5-pcie, pi5-net) with the same toolchain, and compares sha256 of each `BOOTAA64.EFI` and `aienos-ck.elf`.

Finding and fix: the first run matched for the eight C-only images and differed for the three that link the Rust inference
library (pi5-infer, pi5-agent, pi5-lifecycle). The Rust panic messages carry the absolute source path
(`<checkout>/crates/aienos-infer/src/*.rs`). Fix at the source: the three Makefile rules that build that library pass
`RUSTFLAGS=--remap-path-prefix=$(REPO)=/aienos`, so the checkout path no longer enters the image. What the image does is
unchanged (only path strings in panic messages). After the fix every `BOOTAA64.EFI` matches byte for byte.

Remaining, understood difference: in the same three images the raw `aienos-ck.elf` still differs in symbol NAMES only (Rust
crate-hash suffixes: cargo hashes the absolute path of the path dependency `aienos-infer`, which lies outside the infer-kernel
crate's own workspace). Symbols are not in `BOOTAA64.EFI`. The script accepts that case only when the ELF is byte-identical
after `strip -s`, and prints it as `match-stripped`.

Toolchain recorded by the script on every run. Used: GNU Make 4.3, gcc 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1), GNU ld and
objcopy 2.42, rustc 1.98.1 (48a229cea 2026-09-01), cargo 1.98.1 (797e8a9bc 2026-08-05).

The kernel embeds the commit id (`aienos_commit:`), so two builds are comparable only from the same commit. For the
QEMU/Spark images (default `all`, `full`, `full` with the TEST anchor, and the QEMU artifact-card twin) byte identity against
origin/main was checked by building both with the same pinned commit string: all identical.

## Q3 Receipt tier on the Pi

The artifact loader used to write receipt `tier` = SEED-0B-QEMU (record offset 22) even in the Pi image. Now
`CKA_IMAGE_TIER` (native/kernel/artifact/ck_artifact.h) is `CKR_TIER_SEED0B_PI5` (3) when the image is built with `CK_PI5`
and `CKR_TIER_SEED0B_QEMU` (1) otherwise; decode accepts the Pi tier only in the Pi image and in hosted tools (the
verifier), so the QEMU/Spark kernels keep their code unchanged. The Rust receipt codec (`aienos-artifact`) knows tier 3 too.
The host tool prints the tier it decoded. Host test: `test_artifact` (default build expects QEMU, `-DCK_PI5` build expects
PI5, round trip, signature covers the tier, tiers 2 and 4 refused). Mutant: `make artifact-tier-mutant` (Pi build that still
writes the QEMU tier) must fail the test, and does.

Pi run `pi5-artifact-a2` (same card bundle as a1, sha256 0757c5c5...6d70, no MODEL.MAP on the card):
`artifact_receipt_tier: SEED-0B-PI5`, `artifacts: candidates=6 admitted=5 rejected=1`, six receipts. On the host,
`ck_artifact_tool receipt check` (bound to the supplied artifacts), TEST-ONLY `sign-test` and `verify` all PASS for the six
receipts with `tier=SEED-0B-PI5` and the digests equal to the ones printed in the log.

## Q6 Receipts manifest (no signing key yet)

`scripts/pi5_receipts_manifest.sh <run-folder>... | --all <runs-root>` reads each run folder's `kernel.log` and `run.log` and
prints a deterministic manifest: per run tag (sorted), image EFI sha256, aienos_commit, kernel.log sha256 and the verdict
lines picked by the checked-in table `scripts/pi5_receipts_verdicts.tsv` (PI5-3 storage, PI5-4 unlock A-E, PI5-5 F1-F3,
PI5-6 infer and G1-G3, PI5-7 L1-L3, power cut P1, artifact a1 and a2, pi5-pcie-1, pi5-net-1, pi5-net-3-r1). It refuses to
print anything if a folder is missing, a field is absent or a table row matches no line. Plain ASCII, LF only, no timestamps or paths.

Signing design: the signature is a detached Ed25519 signature (RFC 8032, 64 raw bytes) over the exact manifest bytes.
`native/kernel/tools/ck_manifest_sig.c verify MANIFEST SIG PUBKEYHEX` checks it with the in-tree verifier; its only signing
command, `sign-test`, uses the public RFC 8032 TEST 1 key and says TEST ONLY. `scripts/ck_pi5_manifest_check.sh` proves the
round trip (and that a tampered manifest, a tampered signature and a different key all fail).

## Limits

- All Pi evidence is one Pi, one card, TEST keys. The manifest is unsigned for real: only a TEST signature was made.
- Run folders live on the Spark (`~/workspace/pi5-runs`), not in the repository; the manifest records their hashes.
- The Pi image tier change affects every Pi image that links the artifact loader (none of the other Pi images presents candidates).
