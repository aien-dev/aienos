# Machine 1 core operational baseline (2026-09-24)

Known-good "core Spark" state of the Linux reference system on Machine 1,
recorded after the 2026-09-24 restart storm was resolved. Return to this set
when the machine needs to be quiet for AIENOS work.

**What happened:** turning Secure Boot off for the first native AIENOS boot
changed TPM PCR 7; the TPM-sealed private-storage key and vault credential no
longer unsealed, the encrypted Forgejo storage stayed locked, and dependent
services restarted every few seconds. Four more services pointed at files that
no longer exist and had been looping independently, and three MAX/PAIR system
services were also looping. Secure Boot was restored (operator decision), the
missing-file services were disabled, and everything outside the core was
stopped.

**Core kept running:** encrypted storage (`atlas-private-storage`,
`atlas-forgejo-storage`), Forgejo and its runner, `cortex`, `spark-cockpit`
(agent task leases on port 18095), and the `aienos-waitlist` container.

**Stopped, not disabled:** these return at the next reboot unless the operator
chooses to disable them.

```text
captured_utc: 2026-09-24T02:27:33Z
host: spark-b87b
kernel: 7.0.0-1019-nvidia
booted: 2026-09-23 21:16:35
secure_boot: SecureBoot enabled
atlas-private-storage: active
atlas-forgejo-storage: active
forgejo_data_mounted: yes
restarts_after_cleanup: 0 across user and system units (checked 45 s after the last stop, 2026-09-24T02:29Z)
memory_used_mb: 6117
memory_available_mb: 118490
load: 0.17 0.72 0.61

running_user_services:
  atlas-forgejo-web.service
  cortex.service
  dbus.service
  filter-chain.service
  forgejo-runner.service
  pipewire-pulse.service
  pipewire.service
  snap.snapd-desktop-integration.snapd-desktop-integration.service
  spark-cockpit.service
  wireplumber.service
  xdg-document-portal.service
  xdg-permission-store.service
enabled_user_services:
  aien-astrosage.service
  aien-mail-model.service
  aien-mail.service
  atlas-authelia.service
  atlas-finetune.service
  atlas-forgejo-web.service
  atlas-olivetin.service
  atlas-repair.service
  atlas-vault-context7.service
  conduit.service
  cortex.service
  filter-chain.service
  forgejo-runner.service
  gcr-ssh-agent.service
  gnome-keyring-daemon.service
  nvpair.service
  obex.service
  openclaw-heartbeat.service
  org.freedesktop.IBus.session.GNOME.service
  pipewire-pulse.service
  pipewire.service
  radicle-node.service
  session-migration.service
  snap.snapd-desktop-integration.snapd-desktop-integration.service
  spark-cockpit.service
  spark-dream.service
  spark-mail.service
  spark-muse-bridge.service
  spark-neural-os.service
  user-session-migration.service
  wireplumber.service
  xdg-desktop-portal-rewrite-launchers.service
running_custom_system_services:
  atlas-forgejo-storage.service
  atlas-private-storage.service
  dgx-dashboard-admin.service
  dgx-dashboard.service
docker_running:
aienos-waitlist (aienos-waitlist:local)
stopped_this_session_user: aien-astrosage aien-mail-model aien-mail spark-mail atlas-authelia atlas-finetune atlas-olivetin conduit openclaw-heartbeat radicle-node spark-dream spark-muse-bridge spark-neural-os
stopped_this_session_system: apache2 atlas-max-flux atlas-trueforge-mcp atlas-max-coder atlas-max-qwen pair
stopped_this_session_docker: grafana prometheus node-exporter dcgm-exporter uptime-kuma
disabled_missing_files: atlas-cortex-max-encoder ddg-bridge atlas-htb-connector atlas-curiosity-daemon
failed_not_investigated: atlas-vault-context7 atlas-repair
```
