# TRUST-1 Gate 2 baseline: four attended boots on Machine 1

- Captured by: Drake, at the keyboard of Machine 1 (the Spark), 2026-10-03.
- State: Secure Boot OFF (`secure_boot=0` in each `capture.env`), aienos main 130aa20, firmware 5.36_0ACUM018, kernel 7.0.0-1019-nvidia.
- Tool: `scripts/tpm_measurement_campaign.sh capture` (35 items each). Read-only on the machine.

## Folders

| Folder | What it is | boot_id (first 8) |
|---|---|---|
| `boot0-before` | running system before Step 1 (an earlier cold boot) | 2e8c2654 |
| `boot1-after` | after `sudo reboot` (warm restart) | a1e81fa0 |
| `boot2-after` | after `sudo poweroff` + power button (cold) | 79caf03e |
| `boot3-after` | after `sudo poweroff` + power button (cold) | 744edd02 |

Also here: `compare-*.txt` (output of the `compare` step) and `GATE2-BASELINE-SUMMARY.md` (the operator's summary). The `efivars/*.efivar` files are the public Secure Boot certificate lists (PK, KEK, db, dbx). No private keys or passphrases were found (searched for "PRIVATE KEY", "passphrase", "password"). The operator's Step 3 to 5 notes in the same source folder were left out because they are not Gate 2 baseline evidence.

## Findings (tags exactly as in the summary)

- [OBSERVED] boot2 vs boot3 (cold vs cold): changed=0 of 35, including PCR1, PCR10 and the event log.
- [OBSERVED] boot0 vs boot3 (cold vs cold): changed=2: event log bytes and `fwupd_refresh_timer` (enabled -> disabled; Drake paused it in Step 2). All PCR values identical.
- [OBSERVED] boot1 (warm reboot) vs any cold boot: PCR1, PCR10 and the event log differ. The PCR1 difference is the `EV_EFI_HANDOFF_TABLES2` digest only; `EV_EFI_VARIABLE_BOOT` digests and boot entries are identical in all four boots.
- [OBSERVED] PCR7 (Secure Boot state) and PCR0/2/3/4/5 are identical across all four boots.
- [UNKNOWN] Whether the warm-reboot PCR1 value is itself stable across warm reboots (one sample only).

Implication stated in the summary: a TPM policy baseline must be taken from, and only promise, cold-boot values; warm restarts need a separate baseline or PCR1 left out of the policy set.

Note: `compare-boot0-boot1.txt` carries a hand-written line saying PCR10 is "Linux IMA runtime, varies by design". That is UNVERIFIED (confidence medium): PCR10 was identical across the three cold boots, so what moves it on a warm reboot is not established here.

Nothing captured here touched firmware, Secure Boot or the TPM.
