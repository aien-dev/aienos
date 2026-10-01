# TRUST-1 and M5: live gate matrix

Snapshot of every TRUST-1 gate (docs/TRUST-1-IMPLEMENTATION-PLAN.md) and every
M5 requirement (aien-architecture CURRENT_EXECUTION_PLAN.md section D1, ADR
0017) against what is actually on `main`. Base commit for this snapshot:
`a3be1b0` (2026-10-01, after #180). Verdict vocabulary only: PASS, FAIL,
NOT_RUN, BLOCKED_HARDWARE, BLOCKED_OPERATOR, MISSING_IMPLEMENTATION. A gate is
PASS only when every acceptance assertion in the plan is true; a gate with
some items done and others open carries the verdict of its worst open item.
QEMU, swTPM and host tests never count as Machine 1 hardware qualification.

Overall: **TRUST-1 NOT QUALIFIED. M5 NOT QUALIFIED.**

## TRUST-1 gates

| Gate | Criterion (short) | Implementation on main | Evidence on main | Testable by agents now | Hardware needed | Operator needed | Verdict | Remaining blocker |
|---|---|---|---|---|---|---|---|---|
| 0 Freeze baseline | SB, PK/KEK/db/dbx, PCRs, event log, every unlock path, offline recovery proven, service baseline | `tpm_measurement_campaign.sh capture`, `trust1_credential_policy.sh --live` | `evidence/trust1_gate0_addendum_v1.json` (corrects the 2026-09-23 receipt to OPEN), capture dir 2026-09-30 | read-only capture only | Machine 1 | yes | BLOCKED_OPERATOR | 4 open items in the addendum: offline material in a second independent place; PCR stability across cold boots (restarts); firmware auto-update paused (approval); service baseline (Forgejo restart loop, backup script) |
| 1 Recovery media | 16 Q17 assertions with SB ON + test-file round trip | `build_standalone_recovery_initrd.sh`, `verify_recovery_tools.sh`, `collect_recovery_boot_evidence.sh`, `test_recovery_unlock_chroot.sh` | QEMU zero-disk boot receipt; stick boot-and-return on hardware (#53, #59, partial) | image build + host proofs | Machine 1 + USB stick | yes | BLOCKED_OPERATOR | Operator Steps 3, 4, 6: test file, rebuild stick (approval), attended SB-ON boot with unlock round trip |
| 2 TPM measurement campaign | one-variable boot experiments, every candidate PCR explained | `tpm_measurement_campaign.sh capture/compare/receipt`, `test_trust1_measurement_tools.sh` | tooling self-test (verify_all step 10); one baseline capture | tooling only | Machine 1 | yes (reboots) | BLOCKED_OPERATOR | Operator Steps 1, 2, 7 (baseline restarts), then the Q15 one-variable experiments, each needing a reboot |
| 3 Owner Root ceremony | offline hierarchy, generation-1 manifest, two verified backups, rotation demo | `trust1_key_ceremony.sh`, `test_trust1_key_ceremony.sh` | throwaway-key self-test (verify_all step 12) | tooling only | offline machine, two media | yes | BLOCKED_OPERATOR | Operator Step 8 (offline ceremony, two backups in separate places); precondition Gates 0-1 PASS |
| 4 Emulator security suite | Q9 list: signed/unsigned/tampered, manifest accept/alter, A/B select + fallback, swTPM policy, 100-boot soak, receipts | `qemu_secureboot_signing_test.sh` (snakeoil TEST key), `qemu_security_suite.sh`, `qemu_native_rollback_test.sh` | signed/unsigned/tampered PASS in QEMU; soak 3-5 boots in verify_all | yes (QEMU) | no | no | MISSING_IMPLEMENTATION | loader has no signed boot manifest and no A/B slot selection (crates/aienos-boot has none; loader is Rust and awaits the C/asm loader); signing with the real Boot Signer needs Gate 3; 100-boot soak NOT_RUN; build/emulator receipts not produced |
| 5 TPM policy simulation | release-set policy N / N+1 / retire, cases current, next, rollback, invalid, rotation, recovery, in swTPM | `trust1_gate5_policy_sim.sh selftest` (swTPM; PolicyAuthorize by a throwaway Owner Root over Release Signer delegations, signed release sets of PolicyPCR + PolicyNV, monotonic NV counters for release and signer floors, PolicyOR recovery branch via PolicySigned by a throwaway Operator Approval key over a fresh TPM nonce) | selftest on swTPM: 31 checks, `TRUST1_GATE5_POLICY_SIM: PASS`; every refusal comes from the TPM; includes mutated-policy negative controls. Simulation only, never Machine 1 | yes (swTPM) | no | yes (preconditions) | BLOCKED_OPERATOR | the simulation itself passes, but formal Gate 5 PASS needs preconditions Gates 2-4 PASS: the PCR selection (PCR 7 and 11 are placeholders) comes from the Gate 2 campaign, the real Owner Root / Release Signer / Operator Approval keys from the Gate 3 ceremony, and Gate 4 is MISSING_IMPLEMENTATION; no simulation receipt file is written yet |
| 6 Storage migration prep | add owner-policy unlock path beside old, three paths proven | none | none | no | Machine 1 | yes | BLOCKED_OPERATOR | preconditions Gates 0-5; needs its own written steps and approval |
| 7 Hardware validation | one attended owner-signed boot with SB ON, Linux stays default | `trust1_gate7_preflight.sh` (read-only) | preflight script only | preflight only | Machine 1 | yes | BLOCKED_OPERATOR | preconditions Gates 0-6 and operator approval receipt |
| 8 Observation | repeated Linux + AIENOS cycles, all paths retained | none | none | no | Machine 1 | yes | BLOCKED_OPERATOR | Gate 7 |
| 9 Retire legacy policy | retire old TPM enrollment only | none | none | no | Machine 1 | yes | BLOCKED_OPERATOR | Gate 8 + operator approval |

## M5 encryption and identity (D1 + ADR 0017)

Implementation language today: Rust (`crates/aienos-crypto`,
`crates/aienos-kernel/src/crypto/envelope.rs`, `crates/aienos-kernel/src/security.rs`).
Under the no-Rust rule these are the reference to port, not the target.
None of it is wired into the Store engine yet.

| Requirement | Implementation on main | Evidence on main | Hardware / operator | Verdict | Remaining blocker |
|---|---|---|---|---|---|
| Owner-controlled key hierarchy | subkey derivation (`derive_subkeys`), keyslot wrap/unwrap, root-auth MAC over SecurityManifest (Rust) | 4 unit tests in security.rs | Owner Root from Gate 3 | MISSING_IMPLEMENTATION | no binding of the store root-auth key to the Gate 3 Owner Root hierarchy; no C implementation |
| Sealed volume keys | keyslot descriptor types; no TPM sealing code | none | real TPM (Gate 6) | MISSING_IMPLEMENTATION | no TPM seal/unseal of K_vol; TPM path depends on Gate 5 policy and Gate 6 |
| AES-256-GCM-SIV object envelopes | aienos-crypto AES/POLYVAL/GCM-SIV + chunked envelope (Rust) | KATs in aienos-crypto; 9 envelope tests incl. late-chunk tamper (#153) and bounded header (#159) | none | MISSING_IMPLEMENTATION | C implementation and the corruption matrix (header, first/middle/last chunk, commit record, anchor, key generation, store generation) |
| Anti-rollback anchors | `RollbackAnchor`, `evaluate_anti_rollback` (Rust) | decision-matrix unit test | TPM NV for a hardware anchor | MISSING_IMPLEMENTATION | anchor not persisted anywhere (no Store or TPM NV wiring); no C implementation |
| Migration authorization | `MigrationManifest` encode/decode (Rust) | none beyond decode | Owner approval | MISSING_IMPLEMENTATION | no authorization check binding a migration to an owner signature |
| Production/test identity separation | none for M5 (only the SEED-0B artifact tool labels a TEST signing identity) | none | none | MISSING_IMPLEMENTATION | no identity-class field or refusal of test identities in production |
| Deterministic recovery | Store recovery in Rust (ADR 0015, QEMU-qualified) | STORE_V1_QEMU, STORE_512B_CRASH_RECOVERY_QEMU | none | MISSING_IMPLEMENTATION | encrypted-object recovery path does not exist |
| Owner-signed trust chain on Machine 1 | TRUST-1 tooling | see TRUST-1 table | Machine 1 | BLOCKED_OPERATOR | TRUST-1 Gates 0-7 |

## Store on real Spark SSD geometry (WP-B)

| Item | Finding | Verdict |
|---|---|---|
| Production Store language | Rust (`crates/aienos-kernel/src/store`, NVMe driver in `crates/aienos-kernel/src/nvme*`, plumbing in `crates/aienos-boot`) | n/a |
| Production geometry rule | the non-qualification path requires the 4096-byte atomic-root predicate and fails closed otherwise (`crates/aienos-boot/src/nvme_read.rs`, Store-over-NVMe section); the 512-byte path is a TEST-ONLY qualification mode | n/a |
| Machine 1 SSD | 512-byte logical block, one-block power-fail atomic unit: `NATIVE_GB10_STORE_ROOT_ATOMICITY: FAIL` for 4K (evidence/p3_nvme_atomicity_2026-09-25.md) | n/a |
| Protocol for 512-byte tearing | proven twice: Rust engine root-tear closure (#136 Tier 2a: every non-zero superblock byte in sector 0) and the C host reference `native/store/torn_slot.c` (#175, every block subset enumerated); neither is the production path | n/a |
| Production Store on 512-byte geometry | needs a C disk layer (C NVMe driver + C ADR 0015 engine) that carries the torn_slot protocol; it does not exist, and new Rust is not allowed | MISSING_IMPLEMENTATION |
