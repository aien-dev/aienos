# B7B-PHYSICAL-BOOT-PREP: the attended B7b hardware boot, on paper only

Status: PREPARATION DOCUMENT (2026-10-11). **None of this is executed without Drake's attended, explicitly approved
window.** Writing this page changed nothing on the machine: no reboot, no firmware staging, no boot-entry change, no
root command. Every PASS cited for the probe image is QEMU only, not physical.

Owner issue: aien-dev/aienos#286 (native GB10, cut B7b). Authority: Drake's ruling of 2026-10-10 (aien-architecture#190,
item 5) authorizes B7b *preparation*, not a boot; the boot needs "a first operator-confirmed, two-hour attended window
after the recovery media, rollback, trust and preflight checks pass" (`docs/GB10_IORT_DECODE.md` section 10).
Related, read first: `docs/native/PREFLIGHT-AND-RECOVERY.md`, `docs/NATIVE_BOOT_ONE_TIME.md`,
`docs/NATIVE_BOOT_ROLLBACK_CONTRACT.md`, `docs/RECOVERY_MEDIA_MACHINE1.md`.

## 1. What B7b is, and what is already built

Goal in plain words: boot a special test build of the AIENOS kernel once, let it switch on the second memory-protection
chip ("SMMUv3 B", at 0x13000000) for one made-up device slot, read two read-only identity registers of that chip, switch
the slot off again, print one summary line, and return to Linux. No device is allowed to move data; the GPU is not
touched.

Built and tested without hardware (PR #302, squash `863bef83`, issue #286 comment):

- Probe image: `make [full] CK_B7B_PROBE=1` (output directory `target/native-kernel-b7b-probe`, allowed with
  `CK_HARDWARE_STAGING`); code in `native/kernel/core/smmu_svc.c` (`ck_b7b_probe`). Default images are unchanged and
  the link refuses a default image that carries the probe.
- QEMU gate: `scripts/qemu_ck_b7b_probe_test.sh`. Default mode: the Spark-target image refuses fail-closed on QEMU
  (route none, `rc=-3 nostream`, nothing confined). `--positive`: TEST-ONLY segment-0 image confines one page, reads
  IDR0/IDR1, unconfines. `--self-test`: 19 canned logs and 4 Makefile refusals. Local runs recorded in the PR: all PASS.
- Expected Spark output: `docs/GB10_IORT_DECODE.md` section 10, labelled *expected, not observed*.

Not built, and therefore a blocker (section 4, G7): a probe variant of the one-time staging script
(`scripts/stage_one_time_boot_ck.sh` / `_full.sh`); it touches the boot-entry staging path and is left for this campaign.

## 2. People and things required (all physical, all Drake's)

| need | detail |
|---|---|
| Drake present for the whole window | at the machine, display and keyboard attached; a fresh go-ahead for this boot, given in this window (a past approval does not carry over) |
| Window | two hours, written down in advance with start time; nothing else uses the machine in it |
| Recovery stick | `AIENOSRECOV` plugged in, listed as `Boot0004`, verified (section 3) |
| Camera | one phone or camera on the screen for the whole boot; the screen is the only observation channel |
| Witness | a second person (or Drake plus a time-stamped recording) who reads the screen aloud and keeps the clock |
| Notes | paper or a laptop for times and the exact words on screen |

## 3. Recovery preflight: read-only checklist

Run on the Spark in Linux, as the normal user, before the window opens. **Every command below only reads or builds
into `target/`.** None needs sudo, none writes a boot variable, stages, mounts read-write or reboots. Stop at the first
failure.

| step | command | PASS looks like |
|---|---|---|
| P1 | `git -C <checkout> status --porcelain` | prints nothing (clean tree) |
| P2 | `git -C <checkout> rev-parse HEAD` | the commit the probe image is built from; write it down |
| P3 | `quietlock check` | clear (no other session holds the machine quiet) |
| P4 | `efibootmgr` (no arguments) | lists `Boot0004` with `AIENOSRECOV`; `BootOrder` starts `0001`; no `BootNext`; `BootCurrent: 0001` |
| P5 | `lsblk -f` | the recovery stick is visible; the internal drive layout matches `docs/RECOVERY_MEDIA_MACHINE1.md` (root ext4 `d27bfd26-ff30-400e-9eca-9cdf73de9406`, ESP vfat `9DA2-3597`) |
| P6 | `bash scripts/verify_recovery_tools.sh` | `PASS` (static check of the recovery initrd; `NOT_RUN` is not a pass) |
| P7 | `bash scripts/qemu_verify_recovery_media.sh` | the recovery environment boots in QEMU with zero hard disks |
| P8 | `bash scripts/qemu_ck_rollback_test.sh` and `bash scripts/qemu_native_rollback_test.sh` | the rollback gates pass for this commit |
| P9 | `bash scripts/qemu_ck_b7b_probe_test.sh --self-test`, then with no flag, then `--positive` | `AIENOS_CK_B7B_PROBE_SELF_TEST: PASS`, `AIENOS_CK_B7B_PROBE: PASS`, `AIENOS_CK_B7B_PROBE_POSITIVE: PASS` |
| P10 | `bash scripts/ck_repro_build.sh full` (builds twice, compares) and the probe build `make -C native/kernel full CK_B7B_PROBE=1 CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS=<file> CK_MACHINE_ID=<file>` | two equal digests; the probe image digest written down. UNVERIFIED that `ck_repro_build.sh` accepts the probe flag; read its help first |
| P11 | `bash scripts/native_boot_preflight.sh --image <probe image .efi> --expect-sha256 <digest from P10>` | last line `NATIVE_PREFLIGHT: READY`; the `ASK` lines are Drake's and are answered in person |
| P12 | `bash scripts/stage_one_time_boot_ck.sh --dry-run` (or the probe variant's dry run, once it exists) | prints every command, touches nothing; Drake reads it |
| P13 | the recovery stick, tested in person: booted once in an earlier attended window per `docs/RECOVERY_MEDIA_MACHINE1.md`, evidence kept | the evidence file from that boot is on hand. UNVERIFIED whether a current one exists; no script checks this |

Secure Boot is recorded, never changed. As of 2026-10-01 it is OFF for development by owner decision
(`docs/native/PREFLIGHT-AND-RECOVERY.md` item 3); `native_boot_preflight.sh` records the state and stops if it is ON.
Whether the physical-boot block described in `docs/NATIVE_BOOT_ONE_TIME.md` section 1 (trust chain) still applies is
UNVERIFIED here and is part of Drake's go/no-go.

## 4. Go / no-go

**GO requires all of these, decided by Drake at the start of the window:**

- G1 P1 to P12 passed within the last 24 hours on the commit being staged, outputs saved.
- G2 P13: a recovery-stick evidence record exists and Drake saw the stick boot.
- G3 Drake, camera and witness are present; the window is open; no other job needs the machine.
- G4 The image digest printed by the stage script equals the digest from P10 (and later the digest the kernel prints
  on screen).
- G5 `BootNext` unset, `BootOrder` unchanged (P4), Linux is the running system.
- G6 Everyone can state the abort rule (section 7) from memory.
- G7 A reviewed probe variant of the staging script exists and its dry run (P12) was read by Drake. **Today this is
  false; therefore today the answer is NO-GO.**
- G8 Drake says "go" out loud in the window, and the witness writes the time.

**NO-GO (any one):** any preflight STOP line; a dirty tree; the stick missing; an unexpected `BootNext`; a digest
mismatch; anyone unsure; less than the full window left; an open question about the SMMU B side effect (section 8)
that Drake wants answered first.

## 5. Boot steps (only after GO; Drake or the witness reads each step aloud)

1. Start the camera and the notes. Write the commit and digest at the top.
2. In Linux, capture the "before" state (needs sudo; Drake runs it):
   `sudo scripts/verify_native_rollback.sh --capture-pre evidence/pre_boot_capture.json`.
   The staging script does this itself; do not capture twice.
3. Stage once: the probe variant of the stage script with `--apply` (needs sudo; it writes only the staging directory
   `\EFI\AIENOS` on the ESP and sets `BootNext` once; it never reboots and never changes `BootOrder`). Read its
   output aloud; it must end with `BootNext` set and `Boot0004 AIENOSRECOV` still listed.
4. Reboot by Drake's hand (`sudo reboot`). Start the clock.
5. Watch the screen only. Firmware consumes `BootNext` and loads the probe image. Expected lines, in order, as in
   `docs/GB10_IORT_DECODE.md` section 10 (expected, not observed): `kernel: alive`;
   `b7b_probe: start segment=15 rid=0x100 ...`; `b7b_probe: route instance=1 base=0x13000000 stream=0x100 ...`;
   `smmu: instance 1 up base=0x13000000`; the reserved-range line; `b7b_probe: confined ...`;
   `b7b_probe: instance=1 idr0=0x........ idr1=0x........ st_level=. sidsize=..`; `b7b_probe: unconfine rc=0 (ok)`;
   `AIENOS_B7B_PROBE: CONFINED_AND_RELEASED`.
6. The image holds the console for its hold time (120 s on the infer image; UNVERIFIED for the probe image) and then
   resets. Do not touch anything. The next start is Linux because `BootNext` is already consumed.
7. Back in Linux: `sudo scripts/verify_native_rollback.sh --capture-post evidence/post_boot_capture.json`, then
   `--pre ... --post ... --verify` (ten invariants). Read the verdict aloud.

## 6. Observation points

| when | what to read | meaning |
|---|---|---|
| after the reboot, before any AIENOS text | firmware messages | `Secure Boot Violation` means the image was refused: a STOP condition, do not bypass; the machine falls back to Linux |
| `kernel: alive` | banner, memory map | the probe image started; the probe runs only after this line |
| `route ...` line | instance, base, stream | must read instance 1, base 0x13000000, stream 0x100. Anything else is a finding about the IORT decode (`GB10_IORT_DECODE.md` section 3), not a reason to retry |
| IDR0/IDR1 line | two register values | record verbatim; SIDSIZE must cover 0x100 |
| summary line | `CONFINED_AND_RELEASED`, `REFUSED` or `FAIL` | any other summary is a finding: `REFUSED` names a reason (`nostream`, `failed`), `FAIL` means unconfine failed or no live instance matched |
| after the summary | any extra line, panic, freeze, blank screen | write the time and the exact words |

## 7. Abort and rollback

- **Abort rule.** If the screen shows a panic, shows nothing new for 60 seconds, or anyone says "stop": touch nothing
  until the 60 seconds are over, then hold the chassis power button until the machine is off, wait ten seconds, press
  it again. `BootNext` was consumed before the image started, so the machine boots `BootOrder` (Linux, `0001`).
- **If Linux does not come up:** firmware boot-menu key (F11 or the firmware's own), pick `AIENOSRECOV` (`Boot0004`).
  Mount root and ESP **read-only** and run the collector exactly as in `docs/RECOVERY_MEDIA_MACHINE1.md` ("Inspect
  internal storage read-only", "Capture the recovery evidence").
- **Repair** (removing `\EFI\AIENOS`, touching `BootOrder`) needs a new, separate go-ahead from Drake at that moment.
- **Never**: change Secure Boot, change firmware settings, run `--apply` a second time, retry a failed probe in the
  same window without a fresh go, or "fix" anything on the machine during the window.
- Rehearsed so far only in QEMU (`scripts/qemu_ck_rollback_test.sh`, gate M0_ROLLBACK); not on the Spark.

## 8. Known unknowns (carried from #302)

- UNKNOWN whether the GB10 or the HDA0 audio device attempts DMA while no OS drives them, after SMMUv3 B is left
  enabled with every stream aborting until the next reset. An abort there is recorded as an event, not acted on.
- UNVERIFIED that the Spark's real IORT routes segment 15 rid 0x100 to instance 1; this is the expectation from
  decoded tables (`GB10_IORT_DECODE.md` sections 3 and 9), and the first thing the window tests.
- UNVERIFIED hold time and reset behavior of the probe image on the real console.

## 9. Evidence to collect

Camera recording of the whole boot; the witness's time-stamped notes; photographs of the summary screen; the stage
script output; `pre_boot_capture.json`, `post_boot_capture.json` and the verifier verdict; the preflight outputs P1 to
P12 saved with the commit and digests; `efibootmgr` output before and after; and a short result note that quotes the
summary line verbatim and lists every deviation from section 6. The result is posted on aienos#286 as observed facts
with limits; a physical PASS is claimed only for what was seen.

## 10. Statement of non-execution

This page prepares a boot. It is not an authorization. No command in sections 3 or 5 has been run for this campaign
beyond the host-side QEMU gates already recorded in PR #302, and nothing in it will run on the Spark until Drake has
opened an attended window and said "go" in it.
