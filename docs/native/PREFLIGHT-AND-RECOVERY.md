# Native AIENOS: preflight and recovery for an attended Spark boot

Status: NOT A MASTER PLAN. A checklist and a procedure, nothing more. Nothing in
the change that adds this page runs on the physical Spark. Every PASS cited in
the repo for the C kernel is QEMU only, not physical (`native/kernel/GATES.md`).

Related, read first: `docs/NATIVE_BOOT_ONE_TIME.md` (the one-time BootNext
procedure and its invariants), `docs/NATIVE_BOOT_ROLLBACK_CONTRACT.md`
(rollback rules), `docs/RECOVERY_MEDIA_MACHINE1.md` (the recovery stick),
`docs/BOOT_HANDOFF_CONTRACT.md` section 7 (why there are no A/B slots).

## 0. Which "slot": there is none

The operator decision Q3 (ADR 0024) says the loader gets no A/B slots. The
"slot" is the firmware's one-time BootNext entry (the candidate) against the
unchanged BootOrder (Linux, Boot0001). A candidate gets one attempt. The next
boot is Linux again, whatever happened. Boot counters would need a loader that
reads and writes state, which Q3 freezes (see "Open decision" at the end).

## 1. Reproducible image build (host, no Spark involvement)

Run on any aarch64 or cross-capable Linux host, from a clean checkout:

    git status --porcelain            # must print nothing
    commit=$(git rev-parse HEAD)
    make -s -C native/kernel OUT=/tmp/ck-a AIENOS_COMMIT="$commit" full
    make -s -C native/kernel OUT=/tmp/ck-b AIENOS_COMMIT="$commit" full
    sha256sum /tmp/ck-a/BOOTAA64.EFI /tmp/ck-b/BOOTAA64.EFI

`scripts/ck_repro_build.sh [full|core] [--keep DIR]` does exactly this: it
refuses a dirty tree, builds twice into two fresh temp folders and prints
`CK_REPRO_BUILD: PASS <kind> commit=<commit> sha256=<digest>` only when the
digests are equal. Checked on the Spark host (gcc 13.3.0, GNU ld 2.42) at
commit ecd12c6: `full` both builds
`fa48c92029957e0c468b068b4196dde254f80036565b05facc240433b6fd77aa`, `core`
both builds `7bf5d58ce24ddf57de24cdf0c3240f37f0971eac2689fa63935f7c4732a69038`.
Negative control: the same tree built with a different `AIENOS_COMMIT` gives
a different digest, so the comparison can fail. Same-host only: a build on
another machine or toolchain is UNVERIFIED. The digest changes with every commit because the commit hash is built
into the image, so no single digest can be written down in advance. The
digest of the image that is actually staged is printed by the kernel itself on
the recovery console (`recovery_console: identity build_sha256=<64 hex>
commit=<commit>`) and recorded by the stage script. Compare the two.

The hardware staging image (the only one for the Spark) needs owner files and
refuses the TEST keys:

    make -C native/kernel full CK_HARDWARE_STAGING=1 \
        CK_OWNER_PUBKEYS=<owner public keys file> CK_MACHINE_ID=<machine id file>

Normally use `scripts/stage_one_time_boot_ck_full.sh --dry-run`, which prints
every command it would run and touches nothing.

## 2. Preflight checklist before any attended boot

All of these are read-only checks. Stop at the first one that fails.

`scripts/native_boot_preflight.sh [--image EFI --expect-sha256 HEX]` runs
items 2, 3, 4, 5 and 8 below. It only reads (`efibootmgr` with no arguments,
the SecureBoot variable file, `findmnt`, `git status`, the image file, the
quiet flag), needs no sudo and never stages or reboots; its `--self-test`
also fails if the script ever gains a writing command. Last line:
`NATIVE_PREFLIGHT: READY` or `NOT_READY (<n> STOP)`. Items 1, 6 and 7 are
printed as ASK lines: they are Drake's, a script cannot see them.

1. Drake is at the machine, with a display and keyboard attached. (Drake's
   physical presence and fresh go-ahead are required; see section 5.)
2. The recovery stick `AIENOSRECOV` is plugged in and listed as `Boot0004`
   (`efibootmgr` with no arguments). If it is absent, stop.
3. Secure Boot state: record it. As of 2026-10-01 it is OFF for development by
   owner decision, and it is recorded, not changed. A release candidate needs it
   ON. Never flip it as part of this procedure: flipping changes the TPM
   measurement and can lock the private storage volumes
   (`docs/NATIVE_BOOT_ONE_TIME.md`, historical warning).
4. `BootOrder` is the normal one (Linux first, `0001`) and `BootNext` is unset.
5. The working tree is clean and its commit equals the commit the image was
   built from; the image digest from section 1 is written down.
6. Which "slot": the candidate will be the one-time BootNext entry. Linux stays
   the permanent default.
7. The pre-boot capture runs first (`scripts/verify_native_rollback.sh
   --capture-pre`); the stage script does this itself.
8. No other session holds the machine quiet for its own hardware test.

## 3. Getting back to Linux

In plain words: the AIENOS test gets one try. Whatever it does (finishes,
crashes, freezes, or the computer refuses to start it), the next start of the
machine goes back to Linux by itself. If the screen stops changing for a full
minute, hold the power button until the machine turns off, wait ten seconds,
and press it again; Linux should come up. If Linux does not come up, use the
recovery stick (section 4). Each of these outcomes was rehearsed with the real
C image in QEMU (`scripts/qemu_ck_rollback_test.sh`, CK gate M0_ROLLBACK);
not yet on the Spark itself.

Normal return: do nothing. Firmware deletes BootNext before it starts the
candidate, so any reset or power-cycle (hold the chassis power button, wait,
press again) boots the next BootOrder entry, which is Linux. If the candidate
hangs, wait 60 seconds, then power-cycle.

## 4. Recovery procedure if Linux does not come back

1. At power-on, press the firmware boot-menu key (F11 or the firmware's own
   hotkey) and pick `AIENOSRECOV` (Boot0004). It runs entirely from RAM.
2. Mount the internal root and the EFI partition read-only and run the
   packaged collector exactly as in `docs/RECOVERY_MEDIA_MACHINE1.md`
   ("Inspect internal storage read-only", "Capture the recovery evidence").
3. Only with a separate fresh authorization from Drake: repair, or remove the
   staged files in `\EFI\AIENOS` on the EFI partition. Never edit BootOrder
   from the stick without that authorization.
4. After Linux is back: `sudo scripts/verify_native_rollback.sh --pre ...
   --post ... --verify` (the ten invariants in `docs/NATIVE_BOOT_ONE_TIME.md`).

## 5. What needs Drake's physical action and fresh authorization

Each of these needs Drake present and a new go-ahead for that boot. A past
approval does not carry over:

- plugging in or removing the recovery stick or any USB stick;
- any firmware (BIOS) setting, including Secure Boot;
- any reboot or power-cycle of the Spark;
- running `--apply` of any stage script (it writes to the EFI partition and
  sets BootNext);
- pressing keys at the recovery prompt, and any repair in section 4 step 3.

An agent may do the host-side parts: build the image, run the dry-run, run QEMU
gates. Nothing in this change was run on the physical Spark.

## Open decision (not made here)

A boot-count A/B scheme with automatic fallback after N failed boots is not
implemented and not specified here. The accepted spec forbids slots in this
loader (Q3, ADR 0024; `docs/BOOT_HANDOFF_CONTRACT.md` section 7: "the handoff
record carries no rollback state, and never will"). Doing it needs Drake to
reopen Q3 first. The existing one-time BootNext rollback is proven in QEMU
(M0_NATIVE_ROLLBACK_QEMU, Rust mock candidate), and with the C image as the
candidate in QEMU (CK gate M0_ROLLBACK, `scripts/qemu_ck_rollback_test.sh`,
rows 42-46 of `native/kernel/GATES.md`). Neither is a physical result.
