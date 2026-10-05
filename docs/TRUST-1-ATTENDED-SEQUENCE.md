# TRUST-1 attended sequence, missing implementations and gate unlock map

## In plain words first (for the operator, who is not a programmer)

This page is the order of the hands-on jobs that remain for the Spark's security plan, what each one
unlocks, and what has not been built yet. Terms, each in one everyday sentence:

- **Secure Boot**: a firmware switch that makes the computer start only software signed by a trusted key. It is OFF now.
- **TPM**: a small security chip on the board that keeps secrets and locks them to the machine's startup state.
- **PCR**: one numbered logbook slot inside the TPM that records what started up (PCR 7 records the Secure Boot state).
- **Unseal**: the TPM handing a locked secret back, which only works if the logbook matches what it was locked to.
- **Relock script**: our helper that re-locks the three stored passwords to the current Secure Boot state, using spare copies kept on the MacBook.
- **Shim**: the small signed starter program Ubuntu uses to boot under Secure Boot.
- **BootNext**: a one-time firmware instruction "start from this entry next time only".
- **MOK**: the extra list of trusted keys that Ubuntu's shim keeps beside the firmware's own list.
- **db and KEK**: the firmware's list of allowed signers (db) and the keys allowed to edit that list (KEK).
- **PolicyAuthorize**: a TPM rule that unlocks a secret for any software release the owner has signed, instead of one fixed fingerprint.

Status: documentation only. Machine-independent companion to
[TRUST-1-OPERATOR-STEPS.md](TRUST-1-OPERATOR-STEPS.md) and
[TRUST-1-M5-GATE-MATRIX.md](TRUST-1-M5-GATE-MATRIX.md). Written 2026-10-05 against aienos main
bbad5e4 (CAND-1 TRUST receipt: pass 20, fail 1, blocked 11, missing 5, NOT_QUALIFIED). It records no
live machine state; the live preflight results and the request to the operator live in the
operator's private handoff, not here. Nothing in this page was run on Machine 1. The single in-person document, with live-checked prerequisites and corrections to this page, is [TRUST-1-ATTENDED-PACKAGE.md](TRUST-1-ATTENDED-PACKAGE.md).

Secure Boot has been OFF since 2026-10-01. The one software FAIL, `t1_gate7_preflight`, reports that
state and is not a code regression.

Important reading rule: the 16 rows that are blocked or missing (11 blocked, 5 missing) have no runner in the gate table
(`scripts/trust1_m5_qualify.sh`, runner column `-`), so `trust1_m5_qualify.sh` cannot run them even
after the attended action. An attended action produces evidence; turning it into PASS needs a
runner or a recorded-receipt check added to the table (a recommendation, no design exists).

# Part 2. Attended actions in order

General rules: one step at a time; anything unexpected stops the run (plan, "Unexpected states"). "Relock script" means the operator's private re-seal helper that re-seals the three Ubuntu credentials to the current Secure Boot state from the MacBook spares. Not before the chip window ends.

## Action 1. Gate 2, Experiments 1, 2 and 4 (Secure Boot stays OFF; no sticks, no firmware change)

- Purpose: answer the one open question (is a warm restart's PCR1 value stable), show the firmware-update timer
  moves no startup measurement, show that merely visiting the firmware screen moves none. Experiment 4 also
  teaches the orchestrator the real firmware menu names, which Action 3 needs.
- Exact steps: follow the section "Gate 2 attended run (written 2026-10-05, aienos main 9d41efc)" in
  `docs/TRUST-1-OPERATOR-STEPS.md` (lines 297 to 598): "Before the first sitting", then Sitting 1 (4 boots),
  Sitting 2 (3 boots, one Ubuntu timer turned on then off), Sitting 3 (3 boots, firmware screen visit). In
  Sitting 3 the screen's setup key is UNVERIFIED for this machine ("typically Delete or F2"); alternative that is
  OBSERVED to be supported: `sudo systemctl reboot --firmware-setup`. Change NOTHING on that screen; choose exit
  without saving. Look and photograph only: no setting may be changed there, not even by accident, and no Secure Boot, key or TPM menu may be opened.
- Expected: `compare` lines per runbook (`changed=0` for cold vs cold; PCR1 and PCR10 may differ on warm).
- Evidence afterwards: folders `~/trust1-evidence/g2-exp1-*`, `g2-exp2-*`, `g2-exp4-*` and the `compare` text.
  The orchestrator copies them to `evidence/trust1_gate2_experiments_<date>/` in a PR. Receipt per experiment:
  `bash scripts/tpm_measurement_campaign.sh receipt ...` (exact arguments UNVERIFIED here; read `--help`).
- If it goes wrong: stop rules in the runbook (PCR 7 moves, Ubuntu does not start, storage or vault will not
  unlock: plain power off, wait 30 s, one press of the power button, nothing else). Firmware setting changed by
  mistake: restore it by hand and tell the orchestrator before the next boot. Timer: `sudo systemctl disable --now
  fwupd-refresh.timer`.
- Authorization: Drake's own go-ahead (runbook says the run changes no firmware, keys or TPM). Time estimate
  (ESTIMATE from the 2026-10-03 boot timestamps, about 10 minutes per restart cycle): 10 boots, 1.5 to 2 hours.
- Limit: results describe Secure Boot OFF only (runbook, "What would decide the TPM policy").

## Action 2. Decide the key location, get the sticks, make the second offline copy (Gate 0 item)

- Purpose: Gate 0 says the offline material has one copy and the identity has no passphrase
  (`evidence/trust1_gate0_addendum_v1.json`, matrix row Gate 0). Gates 1 and 3 need sticks.
- Needs: 1 stick for the identity (runbook Option A) or a rule change (Option B), and 2 further sticks for the
  Gate 3 backups, held in two different places. Total 3 spare sticks plus the existing AIENOSRECOV. (Plan,
  Gate 3: "Two encrypted offline backups in separate locations.")
- Steps: decision in chat (the orchestrator uses the decision template). Then copy per runbook Step 5 and write
  the second-location note. Exact copy commands for the identity are UNVERIFIED (the runbook says the
  orchestrator confirms the file first). Do not copy the identity until the orchestrator names the file.
- Expected: second copy exists, `sha256sum` of the identity matches the original, written to
  `~/trust1-evidence/` as a note (fingerprint only, never the secret).
- If wrong: wipe the new stick; nothing on the Spark changed.
- Authorization: Drake's decision, plus physical custody (plan Q27: offline recovery credentials and custody
  are operator-only).

## Action 3. Turn Secure Boot ON again, relock the credentials, repeat the cold-boot baseline

- Purpose: put the machine in the state Gates 0, 1, 2 and 7 all assume (plan, Gate 0 "Preconditions: Secure Boot
  enabled"). It is the single largest unlock (Part 4).
- HARD PRECONDITIONS (all four must be true or Action 3 does not start): (a) Action 1 Sitting 3 has been done and the firmware setup key and the exact Secure Boot menu names are written down, so nobody hunts through menus; (b) the AIENOSRECOV recovery stick is plugged in; (c) the MacBook is on and the relock path is confirmed by a dry check that the spares match their manifest; (d) Drake's written approval is recorded. Plainly: when Secure Boot flips, the private storage and the password vault stop unlocking, because their locks are tied to the Secure Boot state. The recovery step is the relock script, or turning Secure Boot back off and running it again.
- Why risky: turning Secure Boot off changed PCR 7 on 2026-09-24 and the three sealed credentials (private
  storage, forge storage, vault) stopped unsealing (aienos #40, memory). Turning it on changes PCR 7 again.
  Runbook: this "needs its own written approval, a tested fallback and the recovery stick first". The fallback
  is the relock script plus the MacBook spares, proven to work on 2026-10-01 (memory
  `aienos-native-boot-status.md`).
- Before sitting (agents): confirm MacBook is reachable (checked 2026-10-05), `*.sb-on` copies exist,
  Action 2 done (stick present and identity location settled), Drake's written approval recorded.
- Exact steps (the menu names are UNVERIFIED; no document records them. Action 1 Sitting 3 records them):
  1. Capture "before": `bash scripts/tpm_measurement_campaign.sh capture ~/trust1-evidence/sb-on-before sb-on-before`.
  2. Plug in the AIENOSRECOV stick (needed before the change, per the runbook).
  3. `sudo systemctl reboot --firmware-setup`. On the firmware screen find the Secure Boot setting, set it to
     enabled (Drake did the reverse on 2026-10-01 17:11 CDT), save and exit. Do NOT touch key menus (PK, KEK, db).
  4. Ubuntu starts with Secure Boot on. If the private storage or vault fails the first time, the known quirk is
     that the first unseal fails with TPM_RC_PCR_CHANGED and a retry works (memory `aienos-recovery-stick.md`).
  5. If credentials still refuse: run the relock script (needs the MacBook online,
     asks sudo). It prints `MATCH` three times and `private storage: OPEN`.
  6. `mokutil --sb-state` must print `SecureBoot enabled`.
  7. Three cold boots, each `sudo poweroff`, wait 30 s, power button, then
     `bash scripts/tpm_measurement_campaign.sh capture ~/trust1-evidence/sb-on-bootN sb-on-bootN`; compare the
     three with `compare` (runbook Step 7 pattern).
- Expected: `SecureBoot enabled`; PCR7 differs from the OFF value `127c18eba230...fa1` (OBSERVED in the CAND-1
  receipt) and is identical across the three cold boots; all three credentials unseal.
- Evidence: the four capture folders, `compare` text, the relock script's output, `mokutil --sb-state` output.
- If it goes wrong: return to firmware setup (`sudo systemctl reboot --firmware-setup`; if Ubuntu will not boot,
  the firmware setup key at power-on, UNVERIFIED which), set Secure Boot back to disabled, boot Ubuntu, run the
  relock script (re-seals to the OFF state; the OFF hashes are verified by the script). Last resort: the
  recovery stick (Action 4 procedure) to read the disk. Stick boot with Secure Boot ON was proven only
  partially on 2026-09-24 (aienos #59).
- Authorization: Drake in person (plan Q27: Secure Boot enable/disable is operator-only), plus the written
  approval noted above. No agent may do this.

## Action 4. Gate 1 attended recovery-stick boot with Secure Boot ON (round trip)

- Purpose: prove the stick boots under Secure Boot, opens the private storage read-only with the offline spare,
  and the harmless test file matches (plan Gate 1 acceptance 1 to 16).
- Exact steps: `docs/TRUST-1-OPERATOR-STEPS.md` Step 6 (lines 168 to 234). Summary: `efibootmgr` to read the
  stick's entry number (was 0004; may differ now), `sudo efibootmgr --bootnext NNNN`, `sudo reboot`; at the
  recovery prompt mount `/dev/nvme0n1p2` and `/dev/nvme0n1p1` read-only plus the key location; run
  `/usr/local/sbin/collect_recovery_boot_evidence /mnt/root` with the `AIENOS_UNLOCK_*` settings and
  `AIENOS_UNLOCK_EXPECT="trust1-roundtrip-test.txt 32b2dc3155e92e071800370f9578e0ebf404df8513ca4b6213f015bacab498a1"`;
  then `umount`, remove the sticks, `reboot -f`, and check `mokutil --sb-state`.
- Expected on screen: banner `AIENOS Standalone Hardware Recovery Core`; `PASS  recovery_unlock_readonly`,
  `PASS  test_artifact_round_trip`, `RECOVERY_BOOT_GATE: PASS`.
- Evidence: photograph or save the collector output (never photos with phone GPS into a repo, memory
  `aienos-recovery-stick.md`); `efibootmgr` before and after; `mokutil --sb-state` after return; `aien-proof`
  ledger line from the stick build (already on 2026-10-03).
- If it goes wrong: the BootNext entry is one-shot; the firmware erases it. Pick the stick entry "UEFI: USB ..."
  from the firmware boot menu, NOT a hand-made `AIENOS` entry (the 2026-09-24 failure was Boot0000 pointing at
  `vmlinuz` and bypassing shim). If stuck, power off, remove the stick, power on: Ubuntu is entry 0001.
- Authorization: Drake in person; the runbook says Step 4 (the rebuild) needed approval and is done; the boot
  itself is read-only.

## Action 5. Gate 3 offline owner key ceremony (MacBook, network off)

- Purpose: create Owner Root, Boot Signer, Release Signer, Operator Approval keys, two verified backups, ceremony
  record. Nothing is installed in firmware at this gate.
- Preconditions per plan: Gates 0 and 1 PASS, Gate 2 collected. Needs 2 backup sticks (Action 2).
- Exact steps: runbook Step 8 (lines 244 to 296): `brew install openssl@3` while online, copy
  `scripts/trust1_key_ceremony.sh`, Wi-Fi and cables off, `preflight`, `generate`, two `backup`, `record`. Only
  the `public` folder returns to the Spark.
- Expected: four `PASS ... matches manifest`, four `PASS ... decrypts from the backup copy` per backup, a
  `generated:` line, a ceremony record with no private material.
- Evidence: `public/` folder (authority manifest, certs, ceremony record) committed to `evidence/`; passphrase
  on paper with the backups (never in the repo).
- If wrong: nothing in firmware changed; destroy or quarantine the folder and rerun (plan, Gate 3 rollback).
- Authorization: Drake in person; the Owner Root never touches the Spark (plan Q6). Machine choice
  (MacBook vs dedicated machine) is Drake's decision (runbook Step 8).

## Actions 6 to 9 (cannot be scripted for Drake yet; each waits on missing work in Part 3)

- Action 6: Gate 2 remaining experiments with Secure Boot ON (Experiments 3 and 5 and the plan's Q15 list: db
  addition, owner certificate, loader rehash, signer rotation, tampered image). No written steps exist
  (`docs/TRUST-1-GATE2-EXPERIMENTS.md` says 3 and 5 wait for their own steps; the Q15 items that touch the db
  need Action 5 certificates and a db enrollment tool that does not exist).
- Action 7: Gate 6, add the owner-policy unlock next to the old one on the real TPM (needs M5 sealed-volume
  implementation, Part 3 item 1). Own written steps and approval (runbook "Later gates").
- Action 8: Gate 7, the single attended Secure Boot ON boot with an owner-signed loader, checkpoints A to E
  (plan, Gate 7). The runbook says it "gets its own written checklist and approval": that checklist does not
  exist (Part 3 item 8).
- Action 9: Gates 8 and 9, observation then retire the old policy, only with Drake's approval.

---

# Part 3. Missing implementations

The five `MISSING_IMPLEMENTATION` rows (all NOT_RUN, "the gate table lists no implementation to run",
`scripts/trust1_m5_qualify.sh` lines 79, 81, 82, 83 and 84; line 80 is a software row that passes):

| # | Row id | What is missing | Where it is specified or stubbed |
|---|---|---|---|
| 1 | `m5_sealed_volume_keys_real_tpm` | Product seal and unseal of the volume key on a real TPM. Today the kernel's production key source is a refusing stub returning `CK_SB_E_BLOCKED_OPERATOR` | `native/kernel/svc/store_boot.c:98-101` and `:335`; ADR 0017 section 2.8 (TPM `PolicyAuthorize`), `docs/adr/0017-m5-key-hierarchy-and-encrypted-store.md:226`; Gate 6 in the plan |
| 2 | `m5_store_kernel_binding` | Sealed C Store bound into the kernel boot path on a real device with real keys. QEMU with TEST keys passes (`ck_store_kernel_qemu`) and does not count | matrix row "Production Store wiring"; `store_boot.c:172` refuses TEST keys in the hardware staging build (that refusal is the correct guard) |
| 3 | `m5_owner_signed_chain_machine1` | Owner-signed trust chain on Machine 1: needs Gate 3 real keys, a db enrollment tool, signed loader on the real image, Gate 7 run. No script contains `efi-updatevar`, `KeyTool`, `sign-efi-sig-list` or `mokutil --import` (searched `scripts/` and `docs/`: none) | plan Gate 7 "add owner trust without deleting factory trust"; matrix row "Owner-signed trust chain on Machine 1" |
| 4 | `m5_production_store_512b` | Real-device run of the production Store on the Machine 1 NVMe (512-byte blocks). Host and QEMU pass, including `DISK_LAYOUT` in QEMU | matrix "Production Store on 512-byte geometry"; `native/kernel/dev/disk_layout.h`; operator-steps "Known hardware risk" (do not boot the C kernel on a disk holding data) |
| 5 | `t1_gate4_manifest_ab` | Signed boot manifest format and loader verification, A/B slot selection, failed-candidate fallback. No spec fixes a manifest format (matrix: searched `docs/` and aien-architecture). Conflict to decide: the Gate 9 text asks for "AIENOS A/B discipline" but ADR 0024 Q3 says no A/B in the Rust loader; the C path uses firmware BootNext instead | matrix "Signed boot manifests, A/B" table; `docs/BOOT_HANDOFF_CONTRACT.md` sections 1 and 7 |

Other gaps found (not rows in the table):

6. Anti-rollback anchor in a TPM NV index: the anchor is on disk; rolling back store and anchor regions together
   still mounts (matrix, "Anti-rollback anchors"; ADR 0017 lines 190 to 207 define the rule).
7. C rollback rows 42 to 46 (`M0_ROLLBACK`): spec in `docs/BOOT_HANDOFF_CONTRACT.md` section 7.1 (line 249), rows
   42, 45, 46 need script changes only, rows 43 and 44 need two TEST-only kernel flags. Physical rollback test
   `M0_NATIVE_ROLLBACK_MACHINE1` is BLOCKED.
8. Gate 7 written checklist and approval receipt template: absent (runbook "Later gates"; `grep` for "Gate 7" in
   `docs/` finds only the plan, the runbook line and the preflight script).
9. Firmware db enrollment and owner-signing procedure for the real boot image (see row 3): absent.
10. Gate 2 Experiment 3 (USB stick) and 5 (boot order) written steps, and the Secure Boot ON experiment list
    (`docs/TRUST-1-GATE2-EXPERIMENTS.md`).
11. Runners for the 11 blocked rows (Part 4 explains why this matters): none exists.
12. Soak after #243 is stale (matrix, Gate 4 row); a 5-boot rerun was queued, not part of the attended work.
13. Menu names of the firmware Secure Boot setting: not recorded anywhere (UNVERIFIED).

---

# Part 4. Gate unlock map

Reading rule. The qualify script marks a row PASS only if it has a runner. These 16 rows (the 11 blocked rows and the 5 missing rows) have none, so even
after the action below, `bash scripts/trust1_m5_qualify.sh` will still print them as NOT_RUN. What each action
really produces is evidence (capture folders, collector output, ceremony record). Turning that evidence into a
PASS needs a small agent change: add a runner or a recorded-receipt check to the gate table (UNVERIFIED that a
design exists; this is a recommendation). Exception: `t1_gate7_preflight` has a runner today.

| After this action | Row | What changes | Command to run afterwards |
|---|---|---|---|
| Action 3 (Secure Boot ON, steps 1 to 6) | `t1_gate7_preflight` (the FAIL) | Expected to pass after Action 3 (its two Secure Boot checks are inferred, not yet observed; the other checks passed in the 05:44Z run) | `bash scripts/trust1_gate7_preflight.sh` then, for the receipt, `bash scripts/trust1_m5_qualify.sh --out evidence/` (no `--with-qemu`) |
| Action 3 step 7 (3 SB-ON cold boots) | `t1_gate0_cold_boot_pcr_stability` (hardware) | Evidence to answer it; plan says Secure Boot ON precondition. Today only an OFF repeat exists (`evidence/trust1_gate2_baseline_2026-10-03/`) | `bash scripts/tpm_measurement_campaign.sh compare ~/trust1-evidence/sb-on-boot1 ~/trust1-evidence/sb-on-boot2` (and 2 vs 3). Needs a runner to count |
| Action 1 (Experiments 1, 2, 4) | `t1_gate2_reboot_campaign` (hardware) | Some experiments done, not all, and OFF only. Does NOT go PASS | `bash scripts/tpm_measurement_campaign.sh receipt ...` per experiment (arguments UNVERIFIED) |
| Action 1 (Experiment 2 end state: timer disabled) plus a written approval note | `t1_gate0_firmware_refresh_pause` (operator) | Pause is observed (`disabled` at 2026-10-05T03:25Z and 12:55Z). Owed: the written approval and a service baseline (matrix Gate 0 row) | `systemctl is-enabled fwupd-refresh.timer`; the approval is an agent note, no command |
| Action 2 (second offline copy) | `t1_gate0_second_offline_location` (operator) | Evidence once the copy and hash match are recorded | `sha256sum` of the identity at both places, compared by the orchestrator |
| Action 4 (Gate 1 stick boot) | `t1_gate1_attended_recovery_boot` (operator) | Evidence: `RECOVERY_BOOT_GATE: PASS` and the round trip. Needs Gate 0 first | collector command printed in Action 4; host-side pre-check `bash scripts/verify_recovery_tools.sh` (already PASS in the CAND-1 receipt) |
| Action 5 (Gate 3 ceremony) | `t1_gate3_offline_key_ceremony` (operator) | Evidence: ceremony record. Also unlocks `m5_migration_owner_signature` (operator), which needs a real owner signature, and the Gate 4 signing with the real Boot Signer | `bash scripts/trust1_key_ceremony.sh record <dir>` on the ceremony machine; host test remains `bash scripts/test_trust1_key_ceremony.sh` |
| Actions 6 and 7 plus Part 3 items 1, 6, 8 | `t1_gate6` (operator), `m5_sealed_volume_keys_real_tpm`, `m5_store_kernel_binding` | Cannot start | none exists |
| Action 8 plus Part 3 items 3, 5, 8, 9 | `t1_gate7` (hardware), `m5_owner_signed_chain_machine1`, `t1_gate4_manifest_ab` | Cannot start | none exists |
| After Gate 7 | `t1_gate8`, `t1_gate9`, `m5_production_store_512b` | wait | none exists |

Which of the 11 blocked rows become attended-runnable in order: Gate 0 pause (now), Gate 2 (partly now, fully
after Action 3 and Gate 3 certificates), Gate 0 stability, Gate 0 second location, Gate 1, Gate 3,
`m5_migration_owner_signature`. The other four blocked rows (`t1_gate6`, `t1_gate7`, `t1_gate8`, `t1_gate9`)
are not unlocked by anything on the list above.

---

