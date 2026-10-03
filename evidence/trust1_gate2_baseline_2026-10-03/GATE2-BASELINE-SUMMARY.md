# TRUST-1 Gate 2 baseline: four attended boots on Machine 1 (2026-10-03, Secure Boot OFF, aienos main 130aa20)

Captures (scripts/tpm_measurement_campaign.sh, 35 items each):
- boot0-before  : running system before Step 1 (prior boot, cold)
- boot1-after   : after `sudo reboot` (warm restart)         boot_id a1e81fa0
- boot2-after   : after `sudo poweroff` + power button (cold) boot_id 79caf03e
- boot3-after   : after `sudo poweroff` + power button (cold) boot_id 744edd02

Results [OBSERVED]:
- boot2 vs boot3 (cold vs cold): changed=0 of 35. Fully identical, including PCR1, PCR10 and the event log.
- boot0 vs boot3 (cold vs cold): changed=2: event log bytes and fwupd_refresh_timer (enabled -> disabled, Drake paused it in Step 2). All PCR values identical.
- boot1 (warm reboot) vs any cold boot: PCR1, PCR10 and event log differ. PCR1 delta = EV_EFI_HANDOFF_TABLES2 digest only; EV_EFI_VARIABLE_BOOT digests and boot entries identical in all four boots.
- PCR7 (Secure Boot state) and PCR0/2/3/4/5 identical across all four boots.

Finding: cold boots reproduce every PCR exactly; a warm `reboot` yields a different PCR1 (firmware handoff tables) and PCR10. Any TPM policy baseline must be taken from, and only promise, cold-boot values; warm restarts need either a separate baseline or exclusion of PCR1 from the policy set. UNKNOWN: whether the warm-boot PCR1 value is itself stable across warm reboots (one sample only).

Pending for Gate 2 PASS: the one-change-at-a-time experiments (agents) and the Gate 2 report. Nothing above touched firmware, Secure Boot or the TPM.
