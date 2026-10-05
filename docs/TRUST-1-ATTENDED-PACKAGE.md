# TRUST-1 attended package: what Drake does in person, in order

## In plain words first

This page is the one document to follow when you sit at the Spark for the security work. It
says what to prepare, what to do in each sitting, what you should see, what to do if it goes
wrong, and which security checks each sitting can help finish. It adds nothing new to the
plan. It gathers [TRUST-1-ATTENDED-SEQUENCE.md](TRUST-1-ATTENDED-SEQUENCE.md),
[TRUST-1-OPERATOR-STEPS.md](TRUST-1-OPERATOR-STEPS.md) and
[TRUST-1-M5-GATE-MATRIX.md](TRUST-1-M5-GATE-MATRIX.md) into one path, with the prerequisites
checked against the live machine on 2026-10-05 (19:17 UTC).

Words used here, one sentence each: **Secure Boot** is the firmware switch that lets the
computer start only signed software (it is OFF now). **TPM** is the security chip. A **PCR**
is one numbered logbook slot in the TPM that records what started up. **Relock script** is
our helper that re-locks the three stored passwords to the current Secure Boot state.
**Evidence checker** is a new helper (below) that reads the files a sitting leaves behind and
refuses them if they are incomplete, wrong or failing.

**Honest status (2026-10-05).** No attended boot, no recovery-stick boot under Secure Boot and
no key ceremony has happened since the baseline of 2026-10-03. Every row below that needs one of
those stays BLOCKED until it really happens and its evidence is recorded. Nothing on this page
marks a physical result as done.

## 1. Prerequisites, checked against the live repos and machine

Result column: OK means observed on 2026-10-05 19:17 UTC; the other tags are explained after the table.

| # | Prerequisite | How to check (read-only) | Result |
|---|---|---|---|
| 1 | Repository is at the pinned work | `gh api repos/aien-dev/aienos/commits/main -q .sha` | OK: main is `6bbd3c6` (docs only after `bbad5e4`; the scripts are unchanged between them, `git diff --stat` lists only docs and crumbs) |
| 2 | Gate 2 tool copy is the one the runbook names | `sha256sum ~/workspace/aienos-recovery-gate/scripts/tpm_measurement_campaign.sh` | OK: `aac10377...4529`, byte-identical to main's file |
| 3 | Secure Boot state | `mokutil --sb-state` | OK for the Gate 2 sittings: `SecureBoot disabled` (it must be enabled only after sitting 3) |
| 4 | Booted by UEFI, boot entries | `efibootmgr` | OK: BootCurrent 0001, BootOrder 0001,0003, no stale USB entry |
| 5 | Recovery stick not plugged in | `lsblk` | OK: only the internal NVMe drive is present |
| 6 | Firmware-update timer paused | `systemctl is-enabled fwupd-refresh.timer` | OK: `disabled` |
| 7 | You may use the TPM | `id -nG` lists `tss`; `ls -l /dev/tpmrm0` | OK |
| 8 | Tools present | `command -v tpm2_pcrread tpm2_eventlog efibootmgr mokutil age sbsign sbverify openssl jq swtpm` | OK: all present |
| 9 | Spare copies of the three passwords on the Spark | `ls -l ~/.config/atlas/offline-spares/` | OK: five `.age` files, `MANIFEST.txt`, the public recipient file |
| 10 | Same spares on the MacBook | `ssh macbook 'ls -l ~/aienos-offline-recovery'` and compare `MANIFEST.txt` | OK, with a correction: MANIFEST.txt has the same digest on both machines (`093624fd...`). The MacBook folder holds a sixth file, `atlas-forge-state-luks-recovery-key.txt.age`, that the manifest does not list (see stale item S2) |
| 11 | Relock script exists | `ls -l ~/handoffs/secure-boot-off/after-restart.sh` | OK, but it lives only in the home folder, not in any repo (S3). Its three expected digests match the manifest |
| 12 | Test file from Step 3 | `cat ~/trust1-evidence/step3-roundtrip-fingerprint.txt` | OK: `32b2dc31...98a1` |
| 13 | Recovery stick `AIENOSRECOV` built and holding no secrets | `~/trust1-evidence/step4-stick-rebuild.txt` | OK on paper (built 2026-10-03 on `130aa20`); the stick itself is not plugged in, so its contents are UNVERIFIED today |
| 14 | No chip run in progress | `test -e ~/workspace/.spark-quiet` | OK: file absent at 19:17 UTC. Check again just before any restart: a restart during a chip run ruins that run |
| 15 | Gate 7 pre-flight | `bash scripts/trust1_gate7_preflight.sh` | EXPECTED FAIL: 23 passed, 2 failed (the two Secure Boot checks), as the sequence page predicts |
| 16 | Gate 2 attended runs already done | `ls ~/trust1-evidence` | None: no `g2-exp*` folders. Only the four baseline boots exist |
| 17 | Spare USB sticks | physical | MISSING: none (`step5-decision.txt`, 2026-10-03). Needed: 1 for the key (decision below) and 2 for the Gate 3 backups |
| 18 | Where the recovery key lives | `step5-decision.txt` | OPEN: Option B (key on the stick) was chosen, then Steps 4 to 6 were deferred. Option B clashes with the stick builder's "no secrets on the stick" rule; that rule needs a decision first |
| 19 | Firmware screen key and Secure Boot menu names | none recorded | UNVERIFIED: sitting 3 of Gate 2 is where you write them down |

### Stale or imprecise items found in the existing docs and handoff

- **S1.** The handoff and the sequence page say the chip window holds the quiet flag until about 14:25 UTC. It is over: the flag is absent now. Still re-check before a restart.
- **S2.** The handoff says the MacBook list "matches" the Spark: five `.age` spares. The MacBook folder actually has six `.age` files; the extra forge-state recovery key is not in `MANIFEST.txt`, and the relock script does not touch it. Whether anything needs it after Secure Boot flips is UNVERIFIED.
- **S3.** The sequence page names the relock script without a path. Its only copy is `~/handoffs/secure-boot-off/after-restart.sh`, outside git. Back it up before the Secure Boot sitting (a lost script leaves only the manual route).
- **S4.** The sequence page says the exact arguments of `tpm_measurement_campaign.sh receipt` are UNVERIFIED. They are now verified from the script (`scripts/tpm_measurement_campaign.sh` lines 13 and 216 to 232): `receipt --variable NAME --before DIR --after DIR --post-rollback DIR --out FILE`, with optional `--prev FILE --baseline FILE --explain TEXT`.
- **S5.** Parts 3 and 4 of the sequence page recommend "a runner or a recorded-receipt check". That check now exists as a host-only checker (section 4 below). It does not make any blocked row pass.
- **S6.** The sequence page and runbook are written against `bbad5e4` and `9d41efc`; main is now `6bbd3c6`. No script they cite changed. The line numbers they cite inside `docs/TRUST-1-OPERATOR-STEPS.md` (Step 6 at 168 to 234, Step 8 at 244 to 296, Gate 2 run at 297 to 598) and in `scripts/trust1_m5_qualify.sh` (rows at 69 to 86) were re-checked on `6bbd3c6` and are right; the new gate row was added at the end of the table so those numbers do not move.

## 2. The sittings, in order

General rules (from the runbook): one step at a time; if anything differs from "expected", stop and give the output to the orchestrator; never improvise with security settings. Emergency stop for a stuck restart: plain power off, wait 30 seconds, one press of the power button, nothing else.

### Sitting A. Gate 2 restarts with Secure Boot staying OFF (about 2 hours)

- **What it is for.** Learn whether a warm restart's PCR1 value is stable, whether the firmware-update timer moves any measurement, and whether just visiting the firmware screen moves any. Sitting 3 also teaches us the real menu names Sitting C needs.
- **Where and how.** At the Spark, in a terminal, following `docs/TRUST-1-OPERATOR-STEPS.md` "Gate 2 attended run" (Before the first sitting, Sitting 1 with 4 boots, Sitting 2 with 3 boots, Sitting 3 with 3 boots). Per experiment, the receipt command is `bash scripts/tpm_measurement_campaign.sh receipt --variable NAME --before ~/trust1-evidence/<before> --after ~/trust1-evidence/<after> --post-rollback ~/trust1-evidence/<rollback> --baseline <baseline receipt> --out <receipt.json>`.
- **Does it change anything?** No firmware setting, key or TPM. It restarts the machine and, in Sitting 2, turns one timer on then off. In Sitting 3, look and photograph only; leave with "exit without saving"; open no Secure Boot, key or TPM menu.
- **Success looks like.** The `compare` lines in the runbook (cold against cold shows `changed=0`); each receipt prints `result=RECORDED`.
- **Expected evidence.** Folders `~/trust1-evidence/g2-exp1-*`, `g2-exp2-*`, `g2-exp4-*`, the `compare` text, one receipt per experiment, and a note of the setup key and menu names. The orchestrator copies them into `evidence/trust1_gate2_experiments_<date>/` in a pull request. Photos must have location data stripped before they go into a repository.
- **If a step fails.** PCR 7 moves, Ubuntu does not start, or storage or vault will not unlock: emergency stop above, then give the output to the orchestrator. A setting changed by mistake: restore it by hand and say so before the next boot. Timer: `sudo systemctl disable --now fwupd-refresh.timer`.
- **Can unlock.** Evidence toward `t1_gate2_reboot_campaign` (hardware) and `t1_gate0_firmware_refresh_pause` (operator). It does not finish either: the experiments are OFF-only and 3 and 5 have no written steps. Check a receipt with `gate2-receipt` (section 4).

### Sitting B. Decide the key location, get three sticks, make the second offline copy

- **Decision (the orchestrator will ask in the usual format).** Option A: key on a separate stick, so the recovery stick holds no secrets. Option B: key on the recovery stick (needs a rule change). Either way you need 3 spare sticks in total, one for the key and two for the Gate 3 backups kept in two different places.
- **Changes anything?** Only the new sticks, which are wiped first. Nothing on the Spark.
- **Success.** The identity's `sha256sum` at both places matches, written to `~/trust1-evidence/` as a note holding the fingerprint only, never the secret. Do not copy the identity until the orchestrator names the file.
- **If wrong.** Wipe the new stick. Nothing on the Spark changed.
- **Can unlock.** Evidence for `t1_gate0_second_offline_location` (operator). It stays BLOCKED until the note exists.

### Sitting C. Turn Secure Boot ON, relock, repeat the cold-boot baseline

- **Do not start unless all four are true:** Sitting A is done and the firmware setup key and the Secure Boot menu name are written down; the `AIENOSRECOV` stick is plugged in; the MacBook is on and its spares match `MANIFEST.txt`; and your written approval is recorded. Also back up the relock script (S3).
- **Why it is risky.** Turning Secure Boot on changes PCR 7, so the three stored passwords (private storage, forge storage, vault) can stop unlocking. On 2026-09-24 that happened when it was turned off. The fallback is the relock script, proven on 2026-10-01.
- **Steps.** Follow `docs/TRUST-1-ATTENDED-SEQUENCE.md` Action 3 steps 1 to 7: capture "before"; plug in the stick; `sudo systemctl reboot --firmware-setup`; set Secure Boot to enabled, save and exit, touching no key menus; log in; `mokutil --sb-state` must say `SecureBoot enabled`; if a credential refuses, retry once, then run `~/handoffs/secure-boot-off/after-restart.sh` (needs the MacBook online; it prints `MATCH` three times and `private storage: OPEN`); then three cold boots, each `sudo poweroff`, 30 seconds, power button, capture.
- **Changes anything?** Yes: the firmware Secure Boot setting and the TPM state of the three stored passwords.
- **Success.** `SecureBoot enabled`; PCR 7 differs from the OFF value and is identical across the three cold boots; all three credentials open.
- **If it fails.** `sudo systemctl reboot --firmware-setup` again and set Secure Boot back to disabled; boot Ubuntu; run the relock script (it re-locks to the OFF state and checks the digests). If Ubuntu will not start at all: power off, remove the stick, power on (Ubuntu is entry 0001); last resort is the recovery stick to read the disk.
- **Expected evidence.** `~/trust1-evidence/sb-on-before`, `sb-on-boot1`, `sb-on-boot2`, `sb-on-boot3`, the `compare` text, the relock output, the `mokutil` output. Check with `gate0-stability` (section 4).
- **Can unlock.** `t1_gate7_preflight` (the one software FAIL) is expected to turn PASS: re-run `bash scripts/trust1_gate7_preflight.sh`. Evidence for `t1_gate0_cold_boot_pcr_stability` (hardware).

### Sitting D. Gate 1 recovery-stick boot with Secure Boot ON

- **Needs:** Sitting C done and kept in the ON state; the stick and the key stick plugged in.
- **Steps.** `docs/TRUST-1-OPERATOR-STEPS.md` Step 6: read the stick's entry number from `efibootmgr`; `sudo efibootmgr --bootnext <number>`; `sudo reboot`; at the recovery prompt mount the internal drive read-only; run `/usr/local/sbin/collect_recovery_boot_evidence /mnt/root` with the unlock settings and `AIENOS_UNLOCK_EXPECT="trust1-roundtrip-test.txt 32b2dc3155e92e071800370f9578e0ebf404df8513ca4b6213f015bacab498a1"`; save the output to a file on the key stick (for example with `| tee /mnt/key/gate1-output.txt`), unmount, remove the sticks, `reboot -f`, then `mokutil --sb-state`.
- **Changes anything?** One one-shot boot instruction that the firmware erases itself. Everything else is read-only.
- **Success.** Banner `AIENOS Standalone Hardware Recovery Core`; `PASS  recovery_unlock_readonly`; `PASS  test_artifact_round_trip`; `RECOVERY_BOOT_GATE: PASS`; Ubuntu starts again and says `SecureBoot enabled`.
- **If it fails.** Pick the stick's own entry (`UEFI: USB ...`) from the firmware boot menu, never a hand-made `AIENOS` entry (that bypassed the signed starter on 2026-09-24). If stuck: power off, remove the stick, power on.
- **Expected evidence.** The saved collector output, `efibootmgr` before and after, the final `mokutil` output. Check with `gate1`.
- **Can unlock.** Evidence for `t1_gate1_attended_recovery_boot` (operator). It needs Gate 0 closed first.

### Sitting E. Gate 3 owner key ceremony (MacBook, network off)

- **Needs:** the two backup sticks, a long passphrase written on paper, and your choice of machine.
- **Steps.** `docs/TRUST-1-OPERATOR-STEPS.md` Step 8: `preflight`, `generate`, `backup` twice (A and B), `record`. Only the `public` folder returns to the Spark. Write down the `manifest_sha256` printed by the tool on screen, on paper, so the checker has a value that did not come from the file itself. Then replace the placeholder `operator_signature=` line in `ceremony_record.txt` by hand with your own signature text.
- **Changes anything?** Creates a folder on the ceremony machine and files on the two sticks. Nothing is installed into the firmware.
- **Success.** Four `PASS ... matches manifest`, four `PASS ... decrypts from the backup copy` per backup, a `generated:` line, and a record with no private material.
- **If it fails.** Nothing in the firmware changed. Destroy or quarantine the folder and rerun.
- **Expected evidence.** The `public` folder committed under `evidence/`. Check with `gate3`.
- **Can unlock.** Evidence for `t1_gate3_offline_key_ceremony` (operator); it is also the first requirement of `m5_migration_owner_signature` (operator), which still needs a real owner signature.

### Not yet possible (no written steps or no tool)

Gate 2 experiments 3 and 5 and the Secure Boot ON experiment list; Gate 6 (needs the real-TPM sealing code); Gate 7 (needs its own checklist, an enrollment tool for the firmware's trusted-signer list, and an owner-signed loader); Gates 8 and 9. These are listed in Part 3 of the sequence page. No sitting above starts them.

## 3. What each sitting can unlock

"Row" means a line of `scripts/trust1_m5_qualify.sh`. No row below goes PASS by itself: the qualify script marks a row PASS only when it has a runner, and these rows have none by design (the sequence page, Part 4). The evidence checker output is a pre-check that the files are sound. The owner records the physical result separately.

| Sitting | Row | State today | After the sitting |
|---|---|---|---|
| C | `t1_gate7_preflight` | FAIL (Secure Boot OFF) | Expected PASS once Secure Boot is ON; re-run the pre-flight |
| A | `t1_gate0_firmware_refresh_pause` | BLOCKED_OPERATOR | Still blocked: owes a written approval and a service baseline |
| A | `t1_gate2_reboot_campaign` | BLOCKED_HARDWARE | Still blocked: experiments 3 and 5 and the ON list are missing |
| B | `t1_gate0_second_offline_location` | BLOCKED_OPERATOR | Evidence once the matching hashes are recorded |
| C | `t1_gate0_cold_boot_pcr_stability` | BLOCKED_HARDWARE | Evidence (three ON cold boots). Only the OFF repeat exists today |
| D | `t1_gate1_attended_recovery_boot` | BLOCKED_OPERATOR | Evidence once the log is checked and recorded |
| E | `t1_gate3_offline_key_ceremony`, `m5_migration_owner_signature` | BLOCKED_OPERATOR | Evidence for the first; the second also needs a real signature |
| none | `t1_gate4_manifest_ab`, `t1_gate6`, `t1_gate7`, `t1_gate8`, `t1_gate9`, `m5_sealed_volume_keys_real_tpm`, `m5_store_kernel_binding`, `m5_owner_signed_chain_machine1`, `m5_production_store_512b` | blocked or missing | Cannot start from any sitting listed here |

## 4. The evidence checker (HOST VALIDATION ONLY)

`scripts/trust1_attended_evidence_check.sh` reads the files a sitting leaves behind and prints `TRUST1_ATTENDED_EVIDENCE <gate>: ACCEPT` or `REJECT` with the reasons. Every run starts with the line `HOST VALIDATION ONLY`. It checks files only, so a forged file could pass: ACCEPT means "well formed and matches the digests you named", never "the boot happened". It does not touch the TPM, firmware, sticks or keys, and it is not wired to change any row in the qualify script. Its own test is `bash scripts/test_trust1_attended_evidence_check.sh` and the qualify script runs it as the row `t1_attended_evidence_checker`.

It rejects, for every command: a missing record, a record with the wrong digest or candidate, a partial record, and a failing record.

| Sitting | Command |
|---|---|
| A | `bash scripts/trust1_attended_evidence_check.sh gate2-receipt RECEIPT.json --expect-baseline-sha <baseline receipt digest> --expect-variable NAME --before DIR --after DIR --post-rollback DIR` |
| C | `bash scripts/trust1_attended_evidence_check.sh gate0-stability ~/trust1-evidence/sb-on-boot1 .../sb-on-boot2 .../sb-on-boot3 --expect-secure-boot 1` (give cold boots only; add `--expect-pcr7 HEX` once you know the value to expect) |
| D | `bash scripts/trust1_attended_evidence_check.sh gate1 gate1-output.txt --expect-test-sha 32b2dc3155e92e071800370f9578e0ebf404df8513ca4b6213f015bacab498a1 [--expect-loader-sha SHA]` |
| E | `bash scripts/trust1_attended_evidence_check.sh gate3 public --expect-manifest-sha <value written on paper at the ceremony>` |

Limits stated plainly: it cannot tell a cold boot from a warm one; for Gate 1 the collector log carries no commit id, so candidate binding rests on the test-file digest and, if given, the loader digest; the second-location note for Sitting B has no checker because no record format exists for it yet.
