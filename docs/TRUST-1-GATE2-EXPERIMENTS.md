# TRUST-1 Gate 2: one-change-at-a-time experiments

Written for Drake, who runs these at the keyboard of the Spark (Machine 1).
Companion to `docs/TRUST-1-OPERATOR-STEPS.md` (Steps 1, 2, 7) and Gate 2 in
`docs/TRUST-1-IMPLEMENTATION-PLAN.md`. Baseline evidence is in
`evidence/trust1_gate2_baseline_2026-10-03/`.

## Where we are

Four boots are captured (see the README in that evidence folder). Cold boots
(powered fully off, then the power button) gave identical measurements. One warm
restart (`sudo reboot`) gave a different PCR1 and PCR10. A "PCR" is one of the
TPM chip's numbered logbook slots that record what started up. We now change
exactly ONE thing at a time and see which slots move. That tells us which slots
mean something about security and which just wobble.

## What Gate 2 requires (from the plan)

Acceptance as the plan defines it: "Baseline repeated cold boots produce stable
measurements or variation explained. Each experiment changes exactly one
variable ... with before, mutation, PCR/event result, after, rollback,
post-rollback measurements recorded. Final report explains why each candidate
PCR contributes to security; no PCR selected by convention."
Stop condition in the plan: any unexplained PCR change goes to the
UnexpectedState protocol (Gate 9) and no policy is chosen.

**Gate 2 PASS criterion: the plan gives the acceptance test above but no single
numeric line, so for the pass/fail count: DOCS SILENT.** Proposal (not yet
accepted): Gate 2 PASSES when (1) the baseline shows cold boots identical
(already met: boot2 vs boot3 changed=0), (2) every experiment below has a
before, after and post-rollback capture, with post-rollback equal to before on
every PCR (otherwise the receipt says `STOP_UNEXPECTED_STATE`), (3) every PCR
that moved in any experiment has a written reason, and (4) the final report
names which PCRs the policy may use and why.

## Rules for every experiment

- Run from the repo folder: `cd ~/workspace/aienos-recovery-gate`
- Do ONE experiment per sitting, in the order below. Never combine two.
- Always cold boot (`sudo poweroff`, wait 30 seconds, power button) unless the
  experiment says otherwise, because cold boots are the stable reference.
- Do not update firmware, change Secure Boot or touch the TPM during this
  campaign. If anything unexpected moves, stop and tell the orchestrator.
- Each experiment has a "before" snapshot, the one change, an "after"
  snapshot, an undo, and a "post-rollback" snapshot that must match "before".

The capture and compare commands are the same each time. Replace `EXPn` with the
experiment name (for example `exp1`):

```bash
# before the change
bash scripts/tpm_measurement_campaign.sh capture ~/trust1-evidence/EXPn-before EXPn-before
# ... make the one change, restart as the experiment says ...
bash scripts/tpm_measurement_campaign.sh capture ~/trust1-evidence/EXPn-after EXPn-after
bash scripts/tpm_measurement_campaign.sh compare ~/trust1-evidence/EXPn-before ~/trust1-evidence/EXPn-after
# ... undo, cold boot ...
bash scripts/tpm_measurement_campaign.sh capture ~/trust1-evidence/EXPn-rollback EXPn-rollback
bash scripts/tpm_measurement_campaign.sh compare ~/trust1-evidence/EXPn-before ~/trust1-evidence/EXPn-rollback
```

*What it does:* reads the startup measurements and saves them in a folder.
*Changes:* nothing on the machine. *Success:* each `compare` ends with
`compared=... changed=...`; for the rollback compare we want `changed=0` apart
from clearly named non-PCR items (event log bytes, timer state).
Optionally the orchestrator builds the signed receipt with the tool's `receipt`
subcommand (`--variable EXPn --before ... --after ... --post-rollback ...`, and
`--prev` pointing at the previous experiment's receipt); you do not need to.

Which PCR means what is UNVERIFIED in this document (I have not cited the TCG
specification here), so "expected effect" lines are guesses to be checked
against the results, not facts. Confidence is stated on each.

---

## Experiment 1. A second warm restart (is the warm value stable?)

Question: the warm restart changed PCR1; is the new value always the same?
This resolves the one [UNKNOWN] from the baseline.

- **The one change:** none to the machine. Use `sudo reboot` twice, one capture after each.
- **Before:** use `boot2-after` or `boot3-after` (cold) as the reference, no new capture needed.
- **Steps:** `sudo reboot`; capture into `~/trust1-evidence/exp1-warmA`; `sudo reboot` again; capture into `~/trust1-evidence/exp1-warmB`; compare `exp1-warmA` with `exp1-warmB`, and each with `boot1-after`.
- **Expected effect (UNVERIFIED, confidence medium):** warmA, warmB and `boot1-after` agree on PCR1; PCR10 may differ.
- **Success:** you have a line for each compare. Either result is evidence.
- **Undo:** nothing to undo. Finish with a cold boot (`sudo poweroff`, power button) and capture `exp1-cold`; compare to `boot3-after`, expect the cold values back.

## Experiment 2. Turn the firmware-update checker back on

Question: does Ubuntu's background firmware-update check change any measurement?

- **The one change:** `sudo systemctl enable --now fwupd-refresh.timer` (the undo of Step 2).
- **Changes:** one Ubuntu setting; no firmware is touched. You should see a line saying a link was created.
- **Steps:** before capture (system as it is now, timer off), run the command, cold boot, after capture, compare.
- **Expected effect (UNVERIFIED, confidence medium):** no PCR change; only the `fwupd_refresh_timer` item flips from disabled to enabled and the event log bytes may differ. This matches the boot0 vs boot3 result, where that timer was the only non-event-log difference and all PCRs were identical [OBSERVED].
- **Risk:** if a firmware update is actually applied during this window, STOP and report: the plan forbids it during the campaign.
- **Undo:** `sudo systemctl disable --now fwupd-refresh.timer`, cold boot, rollback capture.

## Experiment 3. Cold boot with a USB stick plugged in

Question: does merely having a USB storage device present change a measurement?
(No spare sticks existed on 2026-10-03, so this experiment waits until one is available. Use any stick with nothing needed on it, never the recovery stick.)

- **The one change:** plug in one blank or unimportant USB stick before powering on; do not select it to boot from.
- **Steps:** before capture; `sudo poweroff`; plug in the stick; wait 30 seconds; power button; let Ubuntu start normally; after capture; compare.
- **Expected effect (UNVERIFIED, confidence low):** probably none on PCR 0/2/3/4/7; it might change PCR1 or the event log if the firmware records device or boot-entry data.
- **Undo:** `sudo poweroff`, remove the stick, wait 30 seconds, power button, rollback capture.

## Experiment 4. Visit the firmware setup screen and leave without changing anything

Question: does just entering the setup menu (and saving nothing) change a measurement?

- **The one change:** enter the firmware setup screen during startup and exit with "discard changes" / "exit without saving".
- **Steps:** before capture; `sudo poweroff`; power button; press the setup key shown on the startup screen (typically Delete or F2: UNVERIFIED for this machine, read what the screen says); look, change NOTHING, choose exit without saving; Ubuntu starts; after capture; compare.
- **Safety:** do not change any setting, and do not touch Secure Boot or key menus. If you are unsure you changed something, tell the orchestrator before the next boot.
- **Expected effect (UNVERIFIED, confidence low):** no PCR change; some firmware measure the configuration (PCR1) on a setup visit, so PCR1 is the one to watch.
- **Undo:** nothing was changed; do a cold boot and a rollback capture to prove it.

## Experiment 5. Cold boot with the recovery stick first in the boot order

Question: does changing boot order, without actually booting from the stick, change measurements? (This also exercises Gate 1's stick.)

- **The one change:** put the recovery stick (AIENOSRECOV) first in the boot menu; the plan lists "boot order" and "recovery boot" as separate Q15 variables, so this is only boot order, with the stick's boot entry unable to succeed or being skipped if it fails (UNVERIFIED how this firmware behaves, confidence low).
- **Steps:** needs an approved stick and an approved way to change boot order. The orchestrator will give exact written steps for the current boot-order tool before you do this. Do not improvise here: boot-order changes touch firmware variables.
- **Expected effect (UNVERIFIED, confidence medium):** `BootOrder` item changes in capture; PCR1 may change (boot variables are measured; compare the `EV_EFI_VARIABLE_BOOT` digests).
- **Undo:** restore the original order (the boot-order line in `boot0-before/boot_entries.txt` is the reference), cold boot, rollback capture must match `exp5-before`.
- **Status:** blocked until a stick exists and the orchestrator posts the exact steps.

## Order and stop rule

Run 1, 2, 4 first (no hardware needed), then 3 and 5 when sticks exist. After
each, send the compare lines to the orchestrator. If any rollback compare shows
a PCR that does not return to its "before" value, STOP: that is the plan's
UnexpectedState case, no PCR is chosen, and the orchestrator writes it up.
The Q15 list in the plan has more variables (kernel, init image, loader
and so on); those are not in this first set because they change software we
build, and need their own written steps.
