# M4 continuity over System Store v1: QEMU qualification (2026-09-25)

Code commit `3df62b23f3a0441c73bed8bd4b5a89f82d866ccc` (clean tree), branch
`feat/m4-continuity`, base `main` `2276906`.
Design: [ADR 0016](../docs/adr/0016-continuity-objects-over-store-v1.md)
(**Proposed**: continuity encodings are format version 0 on disposable media;
freezing them is an operator decision).
QEMU only, 4096-byte LBA, native NVMe driver, SMMUv3-confined DMA.
`CONTINUITY_NATIVE` is not claimed: Machine 1 waits on TRUST-1.

Reproduce: `./scripts/qemu_continuity_test.sh`

## What is proven

Every boot is a separate QEMU process (a cold restart); only the NVMe image
carries state between boots. The guest prints one line per boot from
`aienos_kernel::continuity`, including the full 256-bit `LogicalAgentId` and a
digest of every committed Cortex statement.

| Claim (ADR 0007 / Continuous-Existence Amendment) | Step |
|---|---|
| A normal boot never mints an identity: blank media stops `STOP (store Unformatted)`, a formatted store with data but no agent root stops `UNPROVISIONED`, and the image is byte-identical after both boots | 1 |
| Provisioning happens once, from an explicit request, with an identity drawn from `RNDR`; a second request is refused (`AlreadyProvisioned`) without writing; an independent provisioning draws a different identity | 2 |
| Committed memory and branch lineage survive cold restarts under the same `LogicalAgentId`; each start durably advances the incarnation before acting (commit-before-observation) | 3 |
| A crash (SIGKILL) at every Store checkpoint of a continuity commit leaves the old or the new committed memory, never a third state, and never another identity; the switch happens exactly at the superblock write | 4 |
| A `DegradedRecovery` mount (malformed peer superblock) resumes read-only with the same identity and memory and writes nothing | 5 |

Conflict (two agent roots), forked or gapped manifest chains, tampered
encodings, broken branch lineage and a power cut before every unit write of a
commit are covered by host tests (`cargo test -p aienos-kernel --lib
continuity`, 9 tests).

## Result

```text
=== 1. Refusals: no boot path mints an identity ===
PASS  resume on blank media stops (store Unformatted) and writes nothing
PASS  resume on a formatted but unprovisioned store stops UNPROVISIONED and writes nothing
=== 2. Provisioning happens once ===
PASS  provisioned agent 1e87cd17709ddce9... (incarnation 1, empty memory, root branch)
PASS  a second provisioning request is refused and writes nothing
PASS  independent provisioning draws a different identity from RNDR
=== 3. Memory and lineage survive cold restarts ===
PASS  resume + remember: incarnation 2, one Cortex fact and one forked branch committed
PASS  cold restart 1: same agent, same memory 93153a653f8f3b39, same lineage, incarnation 3
PASS  cold restart 2: same agent, same memory 93153a653f8f3b39, same lineage, incarnation 4
=== 4. SIGKILL at every Store checkpoint of a continuity commit ===
PASS  kill at before_first_write: same agent, old memory
PASS  kill at after_payloads: same agent, old memory
PASS  kill at after_catalog: same agent, old memory
PASS  kill at after_commit_record: same agent, old memory
PASS  kill at after_first_flush: same agent, old memory
PASS  kill at after_superblock_write: same agent, new memory
PASS  kill at after_final_flush: same agent, new memory
=== 5. Degraded mount resumes read-only ===
PASS  malformed peer superblock: same agent and memory, read-only, nothing written

=== Summary (commit 3df62b23f3a0441c73bed8bd4b5a89f82d866ccc) ===
CONTINUITY_QEMU: PASS
CONTINUITY_NATIVE: NOT CLAIMED (Machine 1 waits on TRUST-1)
```

## Not claimed

- Machine 1 behaviour, TRUST-1, encryption at rest (M5).
- Recovery Core operator flows (ADR 0006): the STOP states here are the entry
  conditions; the operator-authenticated recovery actions are the next step.
- Catalog compaction: every Class A commit adds a manifest to the append-only
  Store v1 catalog (bounded at 4096 entries).
- Whether Machine 1's cores implement FEAT_RNG (`RNDR`); provisioning fails
  closed (`NO_ENTROPY`) if not.
