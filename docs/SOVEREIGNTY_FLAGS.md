# Sovereignty flags: systemd and tpm2-tools

Status: flag only. Nothing here changes behaviour. Standing rules: no systemd anywhere in
AIENOS boot, init, services or tooling (see `.github/copilot-instructions.md:22`), and no
outside dependencies. Each in-script hit carries a `# FLAG(sovereignty):` comment.
Found with `git grep -n -iE 'systemd|systemctl|tpm2_|tpm2-tools|journalctl'` on origin/main.
No earlier equivalent document existed. All results are NOT_RUN (documentation only).

Line numbers are origin/main numbering (before the added FLAG comment lines), checked after merging a047289 and 7a16a9f.

"Runs on" key: IMAGE = executes inside the AIENOS recovery image; HOST = Linux host only
(TRUST-1 operator steps, CI, or the software-TPM test); DOC = text only.

## systemd

| Where | What it does | Runs on | Replacement owed |
|---|---|---|---|
| scripts/tpm_measurement_campaign.sh:141 | `systemctl is-enabled fwupd-refresh.timer`, recorded in capture.env | HOST | Remove the line (or read the fwupd state without systemctl) |
| scripts/trust1_credential_policy.sh:2 (and :5-:34, :103) | Decodes systemd-creds credential headers and checks the TPM policy | HOST (Gate 0) | Retire once credentials leave systemd-creds; in-house C decoder if still needed |
| docs/TRUST-1-OPERATOR-STEPS.md:74,80 | Operator disables/enables `fwupd-refresh.timer` with systemctl | DOC (HOST steps for Drake) | Replace the step with a non-systemd instruction or remove it |
| docs/HARDWARE_TEST_RIG.md:121 | Documents `systemctl reboot --firmware-setup` | DOC (HOST) | Replace with a firmware-setup key or `efibootmgr` step |
| docs/TRUST-1-IMPLEMENTATION-PLAN.md:27 | Describes decoding systemd credentials | DOC | Reword when the decoder is retired |
| evidence/gate0_evidence_receipt_v1.json:106,111 | Record that the old key was sealed with systemd-creds (historical) | DOC (evidence, do not edit) | None; historical record |
| evidence/trust1_gate0_addendum_v1.json:39,59 | Historical record of systemd-creds decode and decrypt | DOC (evidence, do not edit) | None |
| .github/workflows/ci.yml:26 | No systemd; installs tpm2-tools (see below) | HOST (CI) | See tpm2-tools |
| .github/copilot-instructions.md:22 | The rule itself | DOC | None |
| vendor/log/** | Third-party text mentioning systemd-journal-logger | DOC (vendored) | None; not used |

## tpm2-tools (tpm2_* commands)

| Where | What it does | Runs on | Replacement owed |
|---|---|---|---|
| scripts/build_standalone_recovery_initrd.sh:39 (+:101 comment) | Copies `/usr/bin/tpm2_pcrread` and its TCTI library into the recovery initrd | IMAGE | In-house C PCR reader |
| scripts/capture_gate1_receipt.sh:67 (origin/main numbering) | Names `tpm2_pcrread` in the Gate 1 receipt tool list | IMAGE (receipt) | Follows the C reader |
| scripts/collect_recovery_boot_evidence.sh:119 | Reads SHA-256 PCRs in the rescue shell | IMAGE | In-house C PCR reader |
| scripts/verify_recovery_tools.sh:87,123 | Checks tpm2_pcrread is present in the built image | HOST (checks IMAGE) | Check for the C reader instead |
| scripts/tpm_measurement_campaign.sh:18,67-68,72,77,91,143 | pcrread, eventlog parse, version | HOST (Gate 0 operator) | In-house C PCR reader and event-log parser |
| scripts/trust1_credential_policy.sh:78 | tpm2_pcrread for live policy check | HOST | In-house C PCR reader |
| scripts/trust1_gate7_preflight.sh:65,67,113 | Requires tpm2_pcrread, tpm2_eventlog on Ubuntu | HOST | In-house C tools |
| scripts/test_trust1_measurement_tools.sh:19,38-39,65,97,116 | Self-test of the measurement tools against swtpm | HOST | Test against the C tools |
| scripts/trust1_gate5_policy_sim.sh:66-72 and every tpm2_ call through :465 | Software-TPM simulation of the seal policy (createprimary, policy*, unseal, nv*) | HOST (swtpm) | In-house C TPM policy simulator (native/m5 already defines the slot types) |
| scripts/verify_all.sh:219,222 | Runs Step 10 only if tpm2_pcrread exists | HOST | Gate on the C tools |
| .github/workflows/ci.yml:26 | `apt-get install tpm2-tools swtpm-tools libtss2-tcti-swtpm0t64` | HOST (CI) | Drop once the C tools replace the tests (not edited here) |
| docs/RECOVERY_MEDIA_MACHINE1.md:40,45 | Says the recovery media carries tpm2_pcrread | DOC (IMAGE) | Reword with the C reader |
| docs/adr/0017-m5-key-hierarchy-and-encrypted-store.md:133,238-244 | TPM2 command names as spec text (TPM2_PolicyPCR etc.) | DOC | None; these are TPM spec names, not the tool |
| evidence/gate1_zero_disk_recovery_receipt.json:45 | Historical receipt listing tpm2_pcrread | DOC (do not edit) | None |
| evidence/trust1_gate0_addendum_v1.json:32; evidence/trust1_gate0_capture_2026-09-30/capture.env:23 | Historical tpm2_eventlog / tool version record | DOC (do not edit) | None |
| native/m5/m5.h:79 | Constant name TPM2_POLICY_AUTHORIZE, not the tool | none | None |

## Listed here only (not edited; owned by LT-AIENOS aienos#213)

| Where | What it does | Runs on | Replacement owed |
|---|---|---|---|
| scripts/trust1_m5_qualify.sh:317-320 | `tpm2_getcap properties-fixed` for TPM vendor and firmware | HOST (qualify) | In-house C TPM capability reader |
| scripts/trust1_m5_qualify.sh:326 | `tpm2_pcrread sha256:0..15` | HOST (qualify) | In-house C PCR reader |

`native/capability/**` had no hits.

## What the image actually carries today

Only `tpm2_pcrread` (plus its device transport library) reaches the recovery image. The
rest is Linux-host operator or test tooling. One in-house C PCR reader removes the image
dependency; the event-log parser and policy simulator remove the host dependency.
