# PI5-7 cut 3: EL0 artifact loader on the Raspberry Pi 5 (QUALIFICATION ONLY)

Status: one Pi run, green first time (`pi5-artifact-a1`, 2026-10-14 00:0xZ). TEST keys only. Nothing here is a production claim.

## What was built

- `make pi5-artifact` (`CK_PI5_ARTIFACT=1`): the plain Pi core image (no Store, no NVMe, no unlock secret) whose signed artifact candidates
  come from ONE card file, `\EFI\AIENOS\ARTIFACT.BND`, read by the UEFI stub (`native/boot/efi_artifact.c`) before ExitBootServices and handed to the
  unchanged core loader (`core/artifact_loader.c`) through the hook the boot-disk Store uses. Layout of the file: the existing `AIENBND\0` bundle written
  by `ck_artifact_tool bundle` (`core/artifact_card.h`), parsed strictly (`core/artifact_card.c`, host test `test_artifact_card` plus a mutant).
- Trust is the public RFC 8032 TEST 1 key only (`CK_SEED0B_TEST_ANCHOR=1`, forced; the image prints `artifact_trust: seed0b-test qualification build — TEST ONLY`).
  No owner or release key was generated or touched. Store, signature and admission rules are unchanged.
- QEMU twin: `CK_ARTIFACT_CARD=1 CK_SEED0B_TEST_ANCHOR=1` (same code, no `CK_PI5`), gate `scripts/qemu_ck_artifact_card_test.sh`.
- New EL0 probes `fixtures/p2_7`: `P27KREAD` (load from a kernel address), `P27KWRITE` (store to a kernel address), `P27PRIV` (`mrs x0, sctlr_el1`). Kernel
  addresses in the committed Pi `code.bin`: read 0x210000 (translation-table root, `mmu_switch ... aienos_root=` of all 27 earlier Pi runs), write 0x2000000
  (inside the kernel heap 0x261000-0x4261000).
- Only the card image classifies these faults by name (`outside-read`, `outside-write`, `privileged-insn`) and prints an `artifact_fault:` line; every other image
  is byte-identical to main (checked: default, full, full with TEST anchor, pi5, pi5-store, pi5-unlock-card, pi5-pcie, pi5-net).
- Run tool (outside the repo, like its siblings): `~/workspace/pi5/pi5-run-artifact.sh`, copy in `scripts/pi5_run_artifact.sh`; `ARTIFACT_BND=<file>` places the bundle
  on the card and zeroes and deletes it after the run (verified: `artifact_bnd_deleted_verified`).

## Pi run pi5-artifact-a1

Image `target/native-kernel-pi5-artifact/BOOTAA64.EFI` sha256 `a074747fb866c9706e5e74bd50f19dabcc3a69a949f8de6c056d66ca14e8db5f`, built at commit `1192a687610da2290032eb7dbfd64861be83e77a`.
Bundle sha256 `0757c5c50efe5149504636e01d016d798fe55d7eeaae404b6642f8d99bb91d70` (6 entries: P25EXEC, P27KREAD, P27KWRITE, P27PRIV, P26SEED, P25TAMP).
`MODEL.MAP` is not on the card (`model_map: absent`). Command: `KLOG=1 ARTIFACT_BND=... pi5-run-artifact.sh <EFI> pi5-artifact-a1`. Evidence: `~/workspace/pi5-runs/pi5-artifact-a1/kernel.log`.

### Exact kernel.log lines

```
aienos_commit: 1192a687610da2290032eb7dbfd64861be83e77a
model_map: absent (no \EFI\AIENOS\MODEL.MAP on the boot volume)
artifact_card: found a well-formed bundle (QUALIFICATION ONLY, TEST keys, 6 entries, 3263 bytes)
mmu_switch: firmware=EL2 firmware_mmu=on firmware_ttbr0=0x3f3fa000 aienos_root=0x210000 ttbr0_el1=0x210000 switched=yes
memory: ram_ranges=105 free_bytes=7370326016 stack=0x220000-0x260000 heap=0x261000-0x4261000 dma=0x4400000-0x4c00000 exit_attempts=1
el0: ok write=granted forged=denied fault=contained exit=0
artifact_trust: seed0b-test qualification build — TEST ONLY
artifact_card: \EFI\AIENOS\ARTIFACT.BND bytes=3263 entries=6 sha256=0757c5c50efe5149504636e01d016d798fe55d7eeaae404b6642f8d99bb91d70 (QUALIFICATION ONLY, TEST keys; untrusted until verified)
artifact_card: P25EXEC.AIEN bytes=628 sha256=49c3621c190bf3fa8ea9ee4b7cd7f7b65472edc2a790d81aa4a29b43ffa56244
artifact_card: P27KREAD.AIEN bytes=380 sha256=5a441f1253d703647e6419c48b8e35de0e89ba9bcd7f7126e2a634f354005b2c
artifact_card: P27KWRITE.AIEN bytes=388 sha256=fa6d1989227b23fe1fbe72a241f3ae5509653da983f832fa5627366dfecf17ad
artifact_card: P27PRIV.AIEN bytes=368 sha256=90caa62fe2c4a870245222dfe9c1a733aa1d3863c93c2330516c4d36840d0e4e
artifact_card: P26SEED.AIEN bytes=748 sha256=0f560dff72cbd81c27677cb4de60a50eb6881be47aad0b8156efb1cbbba07224
artifact_card: P25TAMP.AIEN bytes=628 sha256=069e10eda35bef104a8ff877cdb956724f0ccf8b2ecada3926bf89a61ffb3852
artifact_source: card_file candidates=6 (read from the card by the UEFI stub; bytes untrusted until verified)
artifact_candidates: 6
artifact_receipt_tier: SEED-0B-PI5
artifact_frames_free_before: 1799379
artifact: P25EXEC.AIEN admitted id=19429f616c5b5315 tier=seed0b-test exec=exited:0x0 bytes=identified=verified=admitted=mapped=executed wx=enforced caps=1 revoked=yes reclaimed=yes frames=10 syscalls=3 reads=1 denials=1
grant: P25EXEC.AIEN[0] kind=object id=1 rights=0x1 bounds=0+32 max_ops=4 max_bytes=32
artifact: P27KREAD.AIEN admitted id=509e5262e1de8ce1 tier=seed0b-test exec=fault:outside-read bytes=identified=verified=admitted=mapped=executed wx=enforced caps=0 revoked=yes reclaimed=yes frames=10 syscalls=0 reads=0 denials=0
artifact_fault: P27KREAD.AIEN class=outside-read esr=0x9200000f ec=0x24 far=0x210000 elr=0x8000001004 contained=yes
artifact: P27KWRITE.AIEN admitted id=4392fbbf1c2a8b59 tier=seed0b-test exec=fault:outside-write bytes=identified=verified=admitted=mapped=executed wx=enforced caps=0 revoked=yes reclaimed=yes frames=10 syscalls=0 reads=0 denials=0
artifact_fault: P27KWRITE.AIEN class=outside-write esr=0x9200004e ec=0x24 far=0x2000000 elr=0x8000001008 contained=yes
artifact: P27PRIV.AIEN admitted id=abb2c16cdfed9d9d tier=seed0b-test exec=fault:privileged-insn bytes=identified=verified=admitted=mapped=executed wx=enforced caps=0 revoked=yes reclaimed=yes frames=10 syscalls=0 reads=0 denials=0
artifact_fault: P27PRIV.AIEN class=privileged-insn esr=0x2000000 ec=0x0 far=n/a elr=0x8000001000 contained=yes
artifact: P26SEED.AIEN admitted id=79e81fccae256533 tier=seed0b-test exec=exited:0x0 bytes=identified=verified=admitted=mapped=executed wx=enforced caps=1 revoked=yes reclaimed=yes frames=10 syscalls=9 reads=3 denials=5
grant: P26SEED.AIEN[0] kind=object id=1 rights=0x1 bounds=0+32 max_ops=4 max_bytes=32
artifact: P25TAMP.AIEN rejected stage=verified reason=BadSignature reclaimed=yes
artifact_frames_free_after: 1799379
artifact_card: released bundle bytes=3263 entries=6
artifacts: candidates=6 admitted=5 rejected=1
```

### Reading it

- (a) good artifacts: `P25EXEC` and `P26SEED` run at EL0 in their own address space, read their granted object through `SYS_OBJECT_READ`, are denied forged and
  out-of-grant handles, and return exit 0 through `SYS_EXIT` (the exit value is recorded in the receipt). `P26SEED` runs AFTER the three faults.
- (b) `P25TAMP` (one payload byte flipped after signing) is refused at stage `verified`, reason `BadSignature`, before any execution (`syscalls=0` in its receipt, `status=NotRun`).
- (c) `P27KREAD`, `P27KWRITE`: data abort from EL0 (EC 0x24, DFSC 0x0f permission fault level 3 for the read, 0x0e for the write: ESR 0x9200000f / 0x9200004e), FAR equal to
  the kernel address the probe used, WnR 0 / 1. `P27PRIV`: ESR 0x2000000 (EC 0x00, unknown reason = UNDEFINED instruction from EL0). Each was terminated and its frames
  reclaimed; none reached its violation exit (0x57); the kernel then ran `P26SEED`, rejected `P25TAMP`, printed the final report and the frame count came back
  (`1799379` free before and after).
- Receipts: all six decoded on the host from the log, bound to the supplied artifact, digest recomputed, TEST ONLY signature verified.

## Gates (host and QEMU)

`make test` (CK_CORE_HOST PASS, `test_artifact_card` 33 checks, mutant killed), `make stage-test` (839 checks), `scripts/ck_pi5_build_check.sh` (231 PASS), `scripts/qemu_ck_artifact_test.sh`
(208 PASS), `scripts/qemu_artifact_test.sh` (165 PASS), `scripts/qemu_ck_lifecycle_test.sh` PASS, `scripts/qemu_ck_artifact_card_test.sh` (new, 39 PASS).

## Limits

- Run a1 predates PI5-8 Q3: its receipt record `tier` field read `SEED-0B-QEMU` on the Pi. Since PI5-8 Q3 the Pi image writes `SEED-0B-PI5` into the receipt itself (run `pi5-artifact-a2`, see PI5-8-QUALIFICATION.md).
- Isolation was shown for the three attack classes above against the two kernel addresses used; it is not a proof for every kernel address, and the kernel does not itself
  re-read the targets after the stores (the faulting stores never retire, FAR names the address).
- `contained=yes` in `artifact_fault:` means the fault handler terminated the task and returned to the kernel; it is not an independent audit.
- One Pi run, one card, TEST keys. Not a production or release claim.
- The Pi run used the image built at commit 1192a687 on top of main 15c19d4. The branch was then rebased onto main 9404c9e (PI5-NET-3, which does not touch the artifact path; one Makefile test-list conflict resolved). Host and QEMU gates were re-run after the rebase; the Pi was not re-run.
