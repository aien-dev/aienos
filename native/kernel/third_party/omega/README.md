# Vendored Omega sources

`rx_cortex.c` and `rx_cortex.h` are the canonical Omega Cortex store
(`src/runtime/` of https://github.com/aien-dev/omega), copied byte for byte
from the commit named on line 1 of `omega.lock` at the repository root.
Both repositories are AGPL-3.0; the copyright stays with the Omega authors.

Rules:
- Never edit these files here. A change goes to Omega first; then the copy is
  refreshed and `omega.lock` updated (commit sha and sha256 lines).
- `scripts/omega_lock_check.sh` (CI, workflow ck-kernel.yml) fails when a
  file differs from its recorded sha256, and when it can reach the omega
  commit, when the recorded sha256 differs from that commit's file.
- AIENOS builds them through `svc/cortex_store.c` (`CX_NO_POSIX`,
  `CX_CONFIG_H` = `svc/cortex_config.h`) and backs the journal with
  `svc/cortex_journal.c` over the sealed Store. Native v1 plan P06.
