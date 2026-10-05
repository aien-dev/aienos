# TRUST-1 and M5: live gate matrix

Snapshot of every TRUST-1 gate (docs/TRUST-1-IMPLEMENTATION-PLAN.md) and every
M5 requirement (aien-architecture CURRENT_EXECUTION_PLAN.md section D1, ADR
0017) against what is actually on `main`. Base commit for this snapshot:
`a3be1b0` (2026-10-01, after #180); the 2026-10-05 refresh below re-checks it against 9d41efc. Verdict vocabulary only: PASS, FAIL,
NOT_RUN, BLOCKED_HARDWARE, BLOCKED_OPERATOR, MISSING_IMPLEMENTATION. A gate is
PASS only when every acceptance assertion in the plan is true; a gate with
some items done and others open carries the verdict of its worst open item.
QEMU, swTPM and host tests never count as Machine 1 hardware qualification.

Overall: **TRUST-1 NOT QUALIFIED. M5 NOT QUALIFIED.**

## Refresh 2026-10-05 against aienos main 9d41efc (read this section first)

Authority for this section: lane L4-TRUST of the overnight campaign, candidate CAND-0
(`9d41efc9d1bea31be0640ca70eeeec9d1d000fad`, ALLEN native #260). It re-reads every row of the
tables below against current main. The tables further down are history: their
"Base commit" and "newest receipt" sentences are superseded by this section.
Overall is unchanged: **TRUST-1 NOT QUALIFIED. M5 NOT QUALIFIED.** No row became PASS in
this refresh and nothing here was run on Machine 1 by an agent.

Tags: OBSERVED (read in a file or command output named here), INFERRED (follows from
observed facts, reasoning given), UNVERIFIED (not checked in this refresh).

### Receipts used and how fresh they are

| Receipt | Commit | Tier | Counts | Status for 9d41efc |
|---|---|---|---|---|
| `evidence/trust1_m5_qualification_3f9d07f50196b4ad741b03c353ed3c45c268a72f04c32f00a0ddfab5294a3eee.json` (in repo) | 44de11f, 2026-10-02 | host + QEMU | pass 19, fail 1, not_run 1, blocked 11, missing 5 | older, kept as history |
| `~/workspace/evidence-out/TRUST1-M5-20261003-130aa20/trust1_m5_qualification_c992277b5396191ba6fe74d6022b8c3bbbceb7588fe01def99c1d7a493317540.json` (NOT in repo; lane TR-02; started 2026-10-03T17:02:32Z) | 130aa20 | host + QEMU | pass 20, fail 1, not_run 0, blocked 11, missing 5 (37 rows) | newest TRUST-1/M5 receipt that exists; see staleness below |
| `evidence/ck_gates_1ecf5bcd303bf88422dd0542f14851c931f5d52276838fa182c812f3c73f3c1b.json` (in repo, from #260) | 640522a, 2026-10-05 | QEMU only | 20 gates: pass 15, fail 0, not_run 5 | binds 9d41efc, see "Binding" below |
| `evidence/allen_native_qemu_cfe9aecffb8b20e0c1ff51fad54c46c522ec7d6c56c6cba7661e4b8cda1ee25a.json` (in repo, from #260) | 640522a | QEMU only | 3 results PASS | binds 9d41efc, see ALLEN section |
| New receipt at 9d41efc | 9d41efc | host + QEMU | QUEUED, NOT_RUN at the time of writing | owed, see "Owed" |

The one FAIL in both newest TRUST-1/M5 receipts is `t1_gate7_preflight`. It reads live
operator state and Secure Boot is off on the Spark (`secure_boot=0` in every Gate 2
baseline `capture.env`; OBSERVED), so the pre-flight correctly refuses. It is a software
FAIL that reports operator state, not a code regression, and it stays FAIL until Secure Boot
is on again.

Binding of the 640522a receipts to 9d41efc (OBSERVED, `git diff` in this worktree):
`197206c` (the PR head that added the receipts) has git tree `5b9615818287e1369dd87ce82c428c188f3db699`, identical
to the tree of 9d41efc. Between `640522a` (the commit the receipts name) and 9d41efc the
only non-evidence, non-crumb files that differ are `docs/adr/0018-allen-subject-state-object.md`
and `native/kernel/GATES.md`. So every C kernel, boot, Store, M5 and script byte the QEMU
runs used is the code of 9d41efc.

Staleness test applied to the 130aa20 receipt (OBSERVED, `git diff --stat 130aa20 HEAD` with
crumb files excluded): no change at all in `native/crypto`, `native/m5`, `native/sig`,
`native/store`, `native/disk`, `native/net`, `crates/aienos-crypto`,
`crates/aienos-kernel/src/crypto`, `crates/aienos-kernel/src/store`, `crates/aienos-boot`,
`crates/aienos-store-tool`, nor in any `scripts/trust1_*`, `tpm_measurement_campaign.sh`,
`qemu_secureboot_signing_test.sh`, `qemu_security_suite.sh`, `qemu_store_512b_crash_test.sh`,
`build_standalone_recovery_initrd.sh` or `verify_recovery_tools.sh`. Changed since 130aa20:
`native/boot` (GOP console, model load), `native/kernel` (FPU, infer, screen, ALLEN) and
the `ck_gates.sh` gate list. So the host and Rust rows of the 130aa20 receipt are current
for 9d41efc; its three C-kernel QEMU rows (`ck_m1_boot_qemu`, `ck_store_kernel_qemu`,
`ck_argus1_revoke_qemu`) are STALE and are replaced by the same gates in the 640522a
`ck_gates` receipt (rows M1, M4_STORE, ARGUS1_REVOKE all PASS there).

GitHub CI on 9d41efc (OBSERVED, `gh run list -R aien-dev/aienos -b main`): Native suites,
Crypto boundary, Crumb compiler, Push on main and "C kernel (CK) gates" (run 37257444148)
all concluded success (CK gates checked again at 03:29Z on 2026-10-05; it was still in
progress at 03:23Z). The CK run is a QEMU-only check.

### TRUST-1 gates, classified

Classes: DONE (every acceptance item has evidence at the stated tier), MISSING_IMPLEMENTATION,
software FAIL, BLOCKED_OPERATOR, BLOCKED_HARDWARE, STALE. A gate carries the class of its
worst open item.

| Gate | Class now | Evidence and tier | Fresh for 9d41efc? | What is still owed |
|---|---|---|---|---|
| 0 Freeze baseline | BLOCKED_OPERATOR | Gate 0 addendum (2026-09-30, Secure Boot ON capture) keeps Gate 0 OPEN. New since: two cold boots compared identical, `boot2` vs `boot3` changed=0 of 35 (physical Machine 1, 130aa20, Secure Boot OFF; `evidence/trust1_gate2_baseline_2026-10-03/`); `fwupd-refresh.timer` observed paused (`boot0` vs `boot3`: enabled to disabled; `systemctl is-enabled` printed `disabled` at 2026-10-05T03:25Z) | Tools unchanged, evidence not stale. The addendum's operator facts are 5 days old (UNVERIFIED now) | Second independent place for the offline material (addendum: identity has one copy and no passphrase); cold-boot stability with Secure Boot ON (the plan's precondition is Secure Boot ON, the only repeat is OFF); a written approval for the firmware pause; service baseline (Forgejo loop, backup script) |
| 1 Recovery media | BLOCKED_OPERATOR | `t1_recovery_tools` PASS (host, 130aa20). The 2026-09-24 QEMU zero-disk receipt is amended to NOT_RUN by `gate1_zero_disk_recovery_receipt_addendum_v1.json`. Stick boot-and-return partial per #53/#59 (UNVERIFIED here) | Recovery scripts unchanged since 3156c33, not stale | Operator Steps 3 to 6: test file, stick rebuild (approval), attended Secure Boot ON boot with unlock round trip |
| 2 TPM measurement campaign | BLOCKED_OPERATOR (reboots are BLOCKED_HARDWARE) | Tooling self-test `t1_measurement_tools` PASS (host). Baseline of 4 physical boots 2026-10-03 (Secure Boot OFF). Experiments 1 to 5 not run, no Gate 2 per-experiment receipt exists | Not stale | The one-change experiments, the report, and the Secure Boot ON repeat. Attended steps: `docs/TRUST-1-OPERATOR-STEPS.md`, "Gate 2 attended run" |
| 3 Owner Root ceremony | BLOCKED_OPERATOR | `t1_key_ceremony` PASS (host, throwaway keys) | Not stale | Offline ceremony (Operator Step 8), two backups. Precondition Gates 0 and 1 |
| 4 Emulator security suite | MISSING_IMPLEMENTATION | Signed accepted, unsigned and tampered refused, QEMU: `qemu_secureboot_signing` PASS (130aa20, snakeoil TEST key). 100 of 100 boots plus tamper rejection, QEMU + swTPM, 2026-10-02 (log only, `~/workspace/test-queue-logs/C5-SOAK-005901.log`) | Signing test not stale. The soak is STALE against #243 (`qemu_security_suite.sh` changed after it ran: the tamper check now also needs the firmware banner). A 5-boot rerun is queued | Signed boot manifest, manifest accept and alter, A/B selection, failed-candidate fallback: no code (see next section). Build and emulator receipts for the gate are not produced. Firmware dbx revocation is not tested |
| 5 TPM policy simulation | BLOCKED_OPERATOR | `t1_gate5_policy_sim` PASS on swTPM (130aa20). Simulation only | Not stale | Preconditions Gates 2 to 4. PCR 7 and 11 in the simulation are placeholders. PCR 11 is all zero on the live Spark (OBSERVED in every baseline capture) |
| 6 Storage migration prep | BLOCKED_OPERATOR | none | n/a | Gates 0 to 5, own written steps |
| 7 Hardware validation | BLOCKED_OPERATOR and BLOCKED_HARDWARE; `t1_gate7_preflight` is a software FAIL (reads live state, Secure Boot off) | preflight script only | Not stale | Gates 0 to 6, approval receipt, Secure Boot ON |
| 8 Observation | BLOCKED_OPERATOR | none | n/a | Gate 7 |
| 9 Retire legacy policy | BLOCKED_OPERATOR | none | n/a | Gate 8 and approval |

### M5 rows, classified

| Requirement | Class now | Evidence and tier | Still owed |
|---|---|---|---|
| Owner-controlled key hierarchy | BLOCKED_OPERATOR | `m5_native_test` PASS (host; sources unchanged since 130aa20; CI Native suites success at 9d41efc) | Gate 3 ceremony and the real Owner Root |
| Sealed volume keys | MISSING_IMPLEMENTATION (the real TPM part is BLOCKED_HARDWARE) | swTPM policy model only. The kernel's production key source `ck_store_production_keys` is a refusing seam that returns `CK_SB_E_BLOCKED_OPERATOR` (`native/kernel/svc/store_boot.c`) | Product seal/unseal of K_vol; Gate 6 on real TPM |
| AES-256-GCM-SIV object envelopes | MISSING_IMPLEMENTATION for the production row; mechanism DONE on host and in QEMU with TEST keys | Host: `m5_store_encrypted_objects` PASS. QEMU: `M4_STORE` PASS (640522a `ck_gates`) | Real device, real keys |
| Anti-rollback anchors | MISSING_IMPLEMENTATION | Anchor in its own region, host and QEMU (`M4_STORE`); the kernel opens it at every boot | TPM NV anchor (Gate 6); rolling back Store and anchor regions together still mounts |
| Migration authorization | BLOCKED_OPERATOR | `m5_migration_sig_test_key` PASS (host, TEST keys) | Real owner signature from Gate 3 |
| Production/test identity separation | MISSING_IMPLEMENTATION for production | The hardware-staging build refuses TEST identity keys before any disk access (`store_boot.c`, CK_SB_E_TEST_KEYS); host tests for the mechanism; QEMU with TEST class only | A production boot path that enforces it |
| Deterministic recovery | MISSING_IMPLEMENTATION (Machine 1) | Newer than the older row text: the kernel-path Store crash campaign now exists and passed in QEMU, `M4_STORE_CRASH` PASS (640522a `ck_gates`, `scripts/qemu_ck_store_crash_test.sh`, 709 s). The older sentence "no crash campaign in the kernel path" is superseded. The C Recovery Core has a QEMU gate, `M4_RECOVERY` PASS with a TEST-only operator key (the prose in `native/kernel/GATES.md` rows 88 to 91p still says NOT_RUN: documentation lag, INFERRED from the receipt row and `qemu_ck_recovery_test.sh`) | A Machine 1 run |
| Owner-signed trust chain on Machine 1 | BLOCKED_OPERATOR | none | Gates 0 to 7 |
| Production Store on 512-byte geometry | MISSING_IMPLEMENTATION | C engine and driver host and QEMU; partition-aware layout `DISK_LAYOUT` PASS in QEMU (640522a `ck_gates`, 512 B and 4096 B) | Real-device run on the Machine 1 SSD; DISK_LAYOUT on hardware is NOT_RUN |

### Signed boot manifests, A/B, rollback, recovery, production Store wiring: exactly what exists

| Piece | Code that exists | What is missing | Gate that covers it |
|---|---|---|---|
| Signed boot manifest | None. The Rust loader has no manifest, the C stub "loads nothing and checks nothing" (`native/boot/efi_main.c`, `native/boot/README.md`, `docs/BOOT_HANDOFF_CONTRACT.md` section 1). Firmware Secure Boot signature checks on the single PE are tested | Manifest format, loader verification, owner signature chain. No spec fixes a manifest format (searched `docs/` and aien-architecture: only the plan's gate text names it) | `t1_gate4_manifest_ab` NOT_RUN (MISSING_IMPLEMENTATION); closest covered item: `qemu_secureboot_signing` (signature on the image, not a manifest) |
| A/B slot selection | None. Operator decision Q3 (ADR 0024) froze the Rust loader and says no slots will be added to it. The C path replaces slots with firmware one-time BootNext (`docs/BOOT_HANDOFF_CONTRACT.md` section 7) | Everything slot-related. Conflict to decide: Gate 9 acceptance text in `docs/TRUST-1-IMPLEMENTATION-PLAN.md` asks for "AIENOS A/B discipline", Q3 says no A/B in this loader | none (same row) |
| One-time boot and rollback to the default | Rust: BootNext one-time candidate with return to the default entry, QEMU script `scripts/qemu_native_rollback_test.sh` (ROADMAP records `M0_NATIVE_ROLLBACK_QEMU: PASS`; not rerun in this refresh, rerun queued). C: `CK_HARDWARE_STAGING` image plus `scripts/stage_one_time_boot_ck.sh --dry-run` (from #256) | C rollback rows 42 to 46 (`M0_ROLLBACK` in `ck_gates.sh`) report NOT_RUN: MISSING_IMPLEMENTATION. The spec exists, `docs/BOOT_HANDOFF_CONTRACT.md` section 7.1: rows 42, 45, 46 need script changes only, rows 43 and 44 also need two TEST-only kernel build flags (bad magic, hang) | `M0_ROLLBACK` NOT_RUN. Physical `M0_NATIVE_ROLLBACK_MACHINE1` BLOCKED |
| Recovery | Recovery media build and tools (`t1_recovery_tools` PASS host). Rust and C Recovery Core, TEST-only operator key, QEMU PASS for the C one (`M4_RECOVERY`) | Real operator key and attended stick boot with Secure Boot ON (Gate 1 steps) | `t1_recovery_tools`, `M4_RECOVERY`, Gate 1 attended |
| Production Store wiring | C kernel opens the sealed Store at boot, TEST keys, SMMU-confined NVMe DMA, partition-aware layout, crash campaign, ARGUS-1 revoke, ALLEN genesis and restore, all in QEMU (640522a `ck_gates`: M4_NVME, M4_STORE, M4_STORE_CRASH, M4_CONTINUITY, M4_ALLEN, DISK_LAYOUT, ARGUS1_REVOKE PASS) | Production K_vol source (BLOCKED_OPERATOR seam), real TPM seal, real device run, Gate 3 owner keys | `ck_store_kernel_qemu`, `ck_argus1_revoke_qemu`, `m5_store_kernel_binding` (MISSING_IMPLEMENTATION), `m5_production_store_512b` (MISSING_IMPLEMENTATION) |

Decision on a software prerequisite: none was implemented in this refresh. The only
candidate with an existing spec is the C port of rollback rows 42 to 46 (section 7.1 above).
It spans a script change plus two new kernel TEST build flags and a labelled second mode,
and the document that specifies it still marks every part PROPOSED. It is better done as its
own cut with its own review than folded into a matrix refresh. Cut list for whoever takes it:
(1) row 42, 45, 46 by pointing `candidate.efi` at the normal C image and grepping
`report_kind: final`; (2) row 43 with a TEST-only bad-magic flag refused by
`CK_HARDWARE_STAGING` (the existing `CK_TEST_STALE_HANDOFF=2` flag passes an old magic, so
check whether it is enough before adding a new flag); (3) row 44 with a TEST-only hang flag.

### ALLEN native continuity (not a TRUST-1 or M5 row; recorded because #260 touched the same kernel)

Every claim in #260 maps to a check in `scripts/qemu_ck_allen_test.sh`:

| #260 claim | Check | Evidence |
|---|---|---|
| Genesis is atomic inside the provisioning Store transaction | host `test_continuity_subject_provision`: power cut at 9 checkpoints and every block boundary gives unprovisioned or identity plus one genesis, 0 other, and the split-transaction mutant is caught; QEMU `FI.1` to `FI.9`: SIGKILL at all 9 Store checkpoints, then a cold boot finds old or new state, never identity without subject | Host rerun in this refresh (OBSERVED): `test_continuity_subject_provision: PASS (764 checks)`, mutant `CS_MUTANT_PROVISION_SPLIT_TXN caught (83 checks failed)`, logs in `~/workspace/overnight-1005/reports/L4-TRUST-evidence/host-allen-*-9d41efc.log`. QEMU: receipt `evidence/allen_native_m4_allen_f50447aa35e01c30deaf5508bc88e5fa3e011ae49d34fd2010f6eefe280a35bb.log` PASS lines FI.1 to FI.9 |
| Exactly-once provisioning | `G8`: provisioning a provisioned image is refused (`AlreadyProvisioned`), no genesis, image unchanged; `FI.1b` re-provision after an uncommitted attempt works | same log |
| Cold restore never mints | `G9` (two new QEMU processes, no `ALLEN: GENESIS` line, still 1 genesis and 2 subject objects, head object byte-identical); `G11c` identity without subject reports `ALLEN: ABSENT` on two boots and the host reader still finds 0 subject objects | same log |
| Cold restore is read-only | `G9` shows no new subject object and an identical head object. It does not compare a whole-image hash, because a restore legitimately advances the incarnation. The strict "image unchanged" check is applied to the refusal cases `G8`, `G11a`, `G11b`, `G12a`, `G12b`. So "read-only" holds for the subject, and is INFERRED, not asserted byte for byte, for the whole disk | same log |
| Foreign-state refusal | `G12a` another installation's chain beside ours and `G12b` on a subjectless identity: `ALLEN: CORRUPT (subject object belongs to another agent)`, nothing restored, nothing minted, image unchanged | same log |
| Corruption refusal | `G11a` forked chain (2 boots), `G11b` flipped envelope byte: refused, image unchanged | same log |
| No re-provisioning on restore | `G10` restore plan is only `AIENCONT v1 mode=6`; a second image restores its own subject, not the first image's | same log |
| QEMU mutants `subject_restore_mints` and `subject_accept_foreign` are KILLED | the script supports `--mutant`; `GATES.md` A16-A20 name which checks kill them | UNVERIFIED in recorded evidence: the receipt and the gate log contain no mutant run. Both runs are queued (below) |

Receipt binding: both ALLEN receipts name `640522a`, whose code equals 9d41efc (see Binding above). Limits stated by #260 and
kept: QEMU only, no physical cold reboot or NVMe, native genesis exists only in the TEST
continuity image (the default image does not provision an identity; operator decision, not
changed here), ADR 0018 stays PROPOSED.

### Owed after this refresh (queued through the shared heavy queue, NOT_RUN when this was written)

- `trust1_m5_qualify.sh --with-qemu` on a pristine 9d41efc worktree (lane `L4-TRUST-qualify`): the missing receipt at current main.
- `qemu_ck_allen_test.sh` plain (`L4-TRUST-allen`) and the two mutants (`L4-TRUST-allen-mut1`, `-mut2`): ALLEN rerun at 9d41efc and the mutant evidence.
- `GATE4_SOAK_RUNS=5 qemu_security_suite.sh` (`L4-TRUST-gate4`): Gate 4 under the stricter tamper check.
- `qemu_native_rollback_test.sh` (`L4-TRUST-rollback`): current Rust BootNext rollback result.

---

## TRUST-1 gates

| Gate | Criterion (short) | Implementation on main | Evidence on main | Testable by agents now | Hardware needed | Operator needed | Verdict | Remaining blocker |
|---|---|---|---|---|---|---|---|---|
| 0 Freeze baseline | SB, PK/KEK/db/dbx, PCRs, event log, every unlock path, offline recovery proven, service baseline | `tpm_measurement_campaign.sh capture`, `trust1_credential_policy.sh --live` | `evidence/trust1_gate0_addendum_v1.json` (corrects the 2026-09-23 receipt to OPEN), capture dir 2026-09-30 | read-only capture only | Machine 1 | yes | BLOCKED_OPERATOR | 4 open items in the addendum: offline material in a second independent place; PCR stability across cold boots (restarts); firmware auto-update paused (approval); service baseline (Forgejo restart loop, backup script) |
| 1 Recovery media | 16 Q17 assertions with SB ON + test-file round trip | `build_standalone_recovery_initrd.sh`, `verify_recovery_tools.sh`, `collect_recovery_boot_evidence.sh`, `test_recovery_unlock_chroot.sh` | QEMU zero-disk boot receipt; stick boot-and-return on hardware (#53, #59, partial) | image build + host proofs | Machine 1 + USB stick | yes | BLOCKED_OPERATOR | Operator Steps 3, 4, 6: test file, rebuild stick (approval), attended SB-ON boot with unlock round trip |
| 2 TPM measurement campaign | one-variable boot experiments, every candidate PCR explained | `tpm_measurement_campaign.sh capture/compare/receipt`, `test_trust1_measurement_tools.sh` | tooling self-test (verify_all step 10); one baseline capture | tooling only | Machine 1 | yes (reboots) | BLOCKED_OPERATOR | Operator Steps 1, 2, 7 (baseline restarts), then the Q15 one-variable experiments, each needing a reboot |
| 3 Owner Root ceremony | offline hierarchy, generation-1 manifest, two verified backups, rotation demo | `trust1_key_ceremony.sh`, `test_trust1_key_ceremony.sh` | throwaway-key self-test (verify_all step 12) | tooling only | offline machine, two media | yes | BLOCKED_OPERATOR | Operator Step 8 (offline ceremony, two backups in separate places); precondition Gates 0-1 PASS |
| 4 Emulator security suite | Q9 list: signed/unsigned/tampered, manifest accept/alter, A/B select + fallback, swTPM policy, 100-boot soak, receipts | `qemu_secureboot_signing_test.sh` (snakeoil TEST key), `qemu_security_suite.sh`, `qemu_native_rollback_test.sh` | signed/unsigned/tampered PASS in QEMU; soak 3-5 boots in verify_all | yes (QEMU) | no | no | MISSING_IMPLEMENTATION | (outside the Q9 list, recorded for revocation coverage) firmware-level revocation (adding a revoked Boot Signer or image hash to dbx) is not tested in QEMU: no in-house authenticated-variable writer and no efitools; loader has no signed boot manifest and no A/B slot selection (crates/aienos-boot has none; loader is Rust and awaits the C/asm loader); signing with the real Boot Signer needs Gate 3; 100-boot soak recorded 100/100 in QEMU on 2026-10-02 (see the update below; the repo holds no receipt file for it, only a queue log); build/emulator receipts not produced |
| 5 TPM policy simulation | release-set policy N / N+1 / retire, cases current, next, rollback, invalid, rotation, recovery, in swTPM | `trust1_gate5_policy_sim.sh selftest` (swTPM; PolicyAuthorize by a throwaway Owner Root over Release Signer delegations, signed release sets of PolicyPCR + PolicyNV, monotonic NV counters for release and signer floors, PolicyOR recovery branch via PolicySigned by a throwaway Operator Approval key over a fresh TPM nonce) | selftest on swTPM: 31 checks, `TRUST1_GATE5_POLICY_SIM: PASS`; every refusal comes from the TPM; includes mutated-policy negative controls. Simulation only, never Machine 1 | yes (swTPM) | no | yes (preconditions) | BLOCKED_OPERATOR | the simulation itself passes, but formal Gate 5 PASS needs preconditions Gates 2-4 PASS: the PCR selection (PCR 7 and 11 are placeholders) comes from the Gate 2 campaign, the real Owner Root / Release Signer / Operator Approval keys from the Gate 3 ceremony, and Gate 4 is MISSING_IMPLEMENTATION; no simulation receipt file is written yet |
| 6 Storage migration prep | add owner-policy unlock path beside old, three paths proven | none | none | no | Machine 1 | yes | BLOCKED_OPERATOR | preconditions Gates 0-5; needs its own written steps and approval |
| 7 Hardware validation | one attended owner-signed boot with SB ON, Linux stays default | `trust1_gate7_preflight.sh` (read-only) | preflight script only | preflight only | Machine 1 | yes | BLOCKED_OPERATOR | preconditions Gates 0-6 and operator approval receipt |
| 8 Observation | repeated Linux + AIENOS cycles, all paths retained | none | none | no | Machine 1 | yes | BLOCKED_OPERATOR | Gate 7 |
| 9 Retire legacy policy | retire old TPM enrollment only | none | none | no | Machine 1 | yes | BLOCKED_OPERATOR | Gate 8 + operator approval |

## M5 encryption and identity (D1 + ADR 0017)

Implementation language at the base snapshot: Rust (`crates/aienos-crypto`,
`crates/aienos-kernel/src/crypto/envelope.rs`, `crates/aienos-kernel/src/security.rs`).
Under the no-Rust rule these are the reference to port, not the target.
C ports landed 2026-10-01: `native/crypto` (#183) and `native/m5` (#186), host-tested only.
The C sealed Store (`native/store/store_sealed.c`, lane 11) wires `native/m5` into the C twin of the Store engine over `native/disk`, host file-backed only (receipt `evidence/trust1_m5_qualification_6fd36c3012ad792862e6098492ae78d7b091c5fada8af73c7c60e6a8f544a650.json`, gates `store_native_c`, `store_rust_crosscheck` and `m5_store_encrypted_objects`). The `m5_store_encrypted_objects` PASS is a host software gate only; it is not the production Store row, which stays MISSING_IMPLEMENTATION. The sealed C Store is QEMU-tested in the C kernel: `native/kernel/svc/store_boot.c` opens it (TEST keys, keyed M5 + anchor) in the C kernel boot path on QEMU virtual NVMe, 512 B and 4096 B namespaces, through the QEMU-only unsafe DMA bypass build (receipt `evidence/trust1_m5_qualification_3358bc2585f0982e1dfbcd0f5ed2fe077847332591782edff8974f0da9caeded.json`, gates `ck_m1_boot_qemu`, `ck_store_kernel_qemu`, `ck_argus1_revoke_qemu`; also `evidence/ck_gates_7a8b4dac2f2ff3ab37154fdd94e2f4894425090bdf95728f4e546aad14866548.json`). Physical: NOT_RUN. The SMMU-confined NVMe mode has since passed in QEMU only (`evidence/ck_gates_23482745517ec1967d2667b24d2a1cd9eafb27cdd91bdb91be7712a3a2968812.json`, gates `SMMU`, `M4_NVME`, `M4_STORE`); physical NOT_RUN. Gate `m5_store_kernel_binding` stays MISSING_IMPLEMENTATION: it asks for the binding on a real device, which QEMU cannot show. The Rust kernel Store has no M5 wiring. Summary: `TRUST1_M5_QUALIFICATION: NOT_QUALIFIED (pass=20 fail=0 not_run=1 blocked=11 missing=5)` with QEMU suites on (`store_rust_crosscheck` NOT_RUN: Rust store tool not built in that worktree).

| Requirement | Implementation on main | Evidence on main | Hardware / operator | Verdict | Remaining blocker |
|---|---|---|---|---|---|
| Owner-controlled key hierarchy | C: `native/m5` (HKDF subkeys, keyslot wrap/unwrap with suite/flag checks, root-auth MAC over the Rust-v1-layout SecurityManifest); Rust reference unchanged | `make -C native/m5 test` (t_subkeys_*, t_keyslot_*, t_secman_*) | Owner Root from Gate 3 | BLOCKED_OPERATOR | software done on the host; binding the store root-auth key to the real Gate 3 Owner Root needs Operator Step 8 (offline ceremony) |
| Sealed volume keys | swTPM policy model in `trust1_gate5_policy_sim.sh` (seal/unseal under PolicyAuthorize + PolicyNV); no product code seals K_vol | Gate 5 simulation selftest | real TPM (Gate 6) | MISSING_IMPLEMENTATION | product-side TPM seal/unseal of K_vol not written; real sealing also needs Gate 6 (attended) |
| AES-256-GCM-SIV object envelopes | C: `native/crypto` (AES-256, POLYVAL, GCM-SIV, RFC 8452) + `native/m5` envelope (Rust V1 header, Standard Envelope AAD, all-or-nothing open) | `native/crypto` 1820 checks incl. 26 RFC 8452 vectors; `native/m5` corruption matrix (header, first/middle/last chunk, commit record, anchor, key generation, store generation, truncate, extend, reorder, splice) (host only; ASan/UBSan and mutants run at PR time, not in the receipt) | none | MISSING_IMPLEMENTATION | envelope mechanism done and host-tested; wired into the C sealed Store on the host (envelope corruption refused at mount and read, `evidence/trust1_m5_qualification_6fd36c3012ad792862e6098492ae78d7b091c5fada8af73c7c60e6a8f544a650.json`); QEMU-tested in the C kernel: the sealed Store opens in the C kernel boot path on QEMU virtual NVMe (TEST keys, `evidence/trust1_m5_qualification_3358bc2585f0982e1dfbcd0f5ed2fe077847332591782edff8974f0da9caeded.json`, row `ck_store_kernel_qemu`); envelope corruption is tested on the host only; physical NOT_RUN, not on Machine 1 |
| Anti-rollback anchors | C: MAC'd anchor + evaluation in `native/m5`; persistence only through a caller buffer | t_rb_* (9 tests), t_corrupt_rollback_anchor | TPM NV for a hardware anchor | MISSING_IMPLEMENTATION | anchor persisted through torn_slot in its own region by the C sealed Store (host file-backed, power cut at every block, `evidence/trust1_m5_qualification_6fd36c3012ad792862e6098492ae78d7b091c5fada8af73c7c60e6a8f544a650.json`); QEMU-tested in the C kernel (anchor opened at every boot, `evidence/trust1_m5_qualification_3358bc2585f0982e1dfbcd0f5ed2fe077847332591782edff8974f0da9caeded.json`; the anchor shares the disk, rollback not tested there), physical NOT_RUN; rolling back the Store and anchor regions together still mounts, which needs a TPM NV anchor (Gate 6) |
| Migration authorization | C: MAC-bound migration manifest (source store, generation, destination, counter) in `native/m5`; owner-signed migration record `native/m5/m5_owner_sig.c` (pure Ed25519 from `native/sig`) binding identity class, owner key id, agent root, source and destination store, source store generation, store format version, envelope count + envelope-set digest, manifest digest, monotonic counter, owner hierarchy generation; `m5_migration_authorize_owner` needs both; signing CLI `native/m5/tools/m5_migsig` takes a key file path and never creates keys | `make -C native/m5 test`: `m5_migsig_test` 13 tests (`AIENOS_M5_MIGRATION_SIG: PASS`; wrong key, every byte flip, field mismatch, unsigned, replayed/older counter, every truncation refused) + `m5_migsig_tool_test.sh` (fresh random TEST keys, OpenSSL cross-check) + t_mig_* (5 tests); host only, TEST keys only (ASan/UBSan and 57/57 mutants at PR time, not in the receipt); receipt `evidence/trust1_m5_qualification_f21f2c038946093a01f3d6553b5bc1a82d8e6ac0bfbb6b36ed4e7a932a9df709.json` (row `m5_migration_sig_test_key` PASS) | Owner Root from Gate 3 | BLOCKED_OPERATOR | host-tested with TEST keys only; the real owner signature needs the Gate 3 offline key ceremony (Operator Step 8), which also yields the trusted owner public key to provision; not yet called by the Store or boot path (needs the C disk layer) |
| Production/test identity separation | C: identity class bound into key derivation and manifest MAC in `native/m5` | t_identity_production_refuses_test, t_identity_test_refuses_production, t_identity_relabel_breaks_mac (host only) | none | MISSING_IMPLEMENTATION | mechanism done and host-tested; enforced at mount by the C sealed Store on the host (`evidence/trust1_m5_qualification_6fd36c3012ad792862e6098492ae78d7b091c5fada8af73c7c60e6a8f544a650.json`); QEMU-tested in the C kernel with the TEST identity class only (`evidence/trust1_m5_qualification_3358bc2585f0982e1dfbcd0f5ed2fe077847332591782edff8974f0da9caeded.json`); not yet enforced by any production boot path, physical NOT_RUN |
| Deterministic recovery | C: commit record v2 (Store generation + ObjectId bound after sealing), object-level recovery in `native/m5`; Store recovery in Rust (ADR 0015) | t_recovery_* (5 tests); STORE_V1_QEMU, STORE_512B_CRASH_RECOVERY_QEMU | none | MISSING_IMPLEMENTATION | encrypted-object recovery runs in the C sealed Store over the C disk layer on the host (power cut at every block, prepared-advance recovery, `evidence/trust1_m5_qualification_6fd36c3012ad792862e6098492ae78d7b091c5fada8af73c7c60e6a8f544a650.json`); the C NVMe driver passes write/flush/reset/read-back on QEMU virtual NVMe only; QEMU-tested in the C kernel (reopen across 3 boots, corrupt superblock refused with the disk unchanged, `evidence/trust1_m5_qualification_3358bc2585f0982e1dfbcd0f5ed2fe077847332591782edff8974f0da9caeded.json`); no crash campaign in the kernel path, no Machine 1 run |
| Owner-signed trust chain on Machine 1 | TRUST-1 tooling | see TRUST-1 table | Machine 1 | BLOCKED_OPERATOR | TRUST-1 Gates 0-7 |

## Store on real Spark SSD geometry (WP-B)

| Item | Finding | Verdict |
|---|---|---|
| Production Store language | Rust (`crates/aienos-kernel/src/store`, NVMe driver in `crates/aienos-kernel/src/nvme*`, plumbing in `crates/aienos-boot`) | n/a |
| Production geometry rule | the non-qualification path requires the 4096-byte atomic-root predicate and fails closed otherwise (`crates/aienos-boot/src/nvme_read.rs`, Store-over-NVMe section); the 512-byte path is a TEST-ONLY qualification mode | n/a |
| Machine 1 SSD | 512-byte logical block, one-block power-fail atomic unit: `NATIVE_GB10_STORE_ROOT_ATOMICITY: FAIL` for 4K (evidence/p3_nvme_atomicity_2026-09-25.md) | n/a |
| Protocol for 512-byte tearing | proven twice: Rust engine root-tear closure (#136 Tier 2a: every non-zero superblock byte in sector 0) and the C host reference `native/store/torn_slot.c` (#175, every block subset enumerated); neither is the production path | n/a |
| Production Store on 512-byte geometry | C disk layer now exists: `native/disk` (block layer + freestanding C NVMe driver, #190, QEMU virtual NVMe only) and `native/store` (byte-identical C twin of the ADR 0015 engine, 89/89 golden-vector rows, plus the sealed Store with the torn_slot anchor); host receipt `evidence/trust1_m5_qualification_6fd36c3012ad792862e6098492ae78d7b091c5fada8af73c7c60e6a8f544a650.json`. QEMU kernel-path evidence: the sealed C Store runs in the C kernel boot path on a 512 B QEMU namespace (`evidence/trust1_m5_qualification_3358bc2585f0982e1dfbcd0f5ed2fe077847332591782edff8974f0da9caeded.json`, row `ck_store_kernel_qemu`; QEMU-only unsafe DMA bypass, no crash campaign). The same C kernel Store path now runs SMMU-confined in QEMU (`iommu=smmuv3`, NVMe stream mapped to its DMA window only, out-of-window DMA faulted; `evidence/ck_gates_23482745517ec1967d2667b24d2a1cd9eafb27cdd91bdb91be7712a3a2968812.json`, gates `SMMU`, `M4_NVME`, `M4_STORE`; QEMU only, physical NOT_RUN). Missing: the binding on a real device (`m5_store_kernel_binding`) and any run on the Machine 1 SSD | MISSING_IMPLEMENTATION |

## Superseded receipt (2026-10-01, lane 33): NOT_QUALIFIED and STALE (the newest is in the 2026-10-02 update below)

This was the newest TRUST-1/M5 receipt on 2026-10-01 (superseded by 3f9d07f5, see the 2026-10-02 update below), namely
`evidence/trust1_m5_qualification_3358bc2585f0982e1dfbcd0f5ed2fe077847332591782edff8974f0da9caeded.json`:
37 rows, pass 20, fail 0, not_run 1, blocked 11, missing 5, verdict
**NOT_QUALIFIED**. It is **stale**: it ran at 5a3a05c, before #197 (SMMU), #199
(Store record v2), #201, #203 and #204, and its `ck_store_kernel_qemu` row ran
with the QEMU-only unsafe DMA bypass. A rerun on current main is owed. Where
rows below cite receipt `6fd36c30...` (or `f21f2c03`, `cbdb2fe7`), those are
older receipts kept as history for that row's evidence, not the latest.
That receipt marks `t1_gate7` BLOCKED_HARDWARE, while the Gate 7 row in the
table above says BLOCKED_OPERATOR (Gate 7 needs both operator approval and
Machine 1); both are blocked and neither is a PASS.

## Update 2026-10-01 (lane 1)

Qualification entrypoint: `bash scripts/trust1_m5_qualify.sh` (#182) runs every
software gate above, marks operator / hardware / unimplemented gates without
running them, and writes a content-addressed receipt (`evidence/trust1_m5_qualification_<sha256>.json`).
New on main since the snapshot: Gate 5 swTPM simulation (#185), `native/crypto`
(#183), `native/m5` (#186). Overall is unchanged: **TRUST-1 NOT QUALIFIED. M5
NOT QUALIFIED.** The receipt committed with that update was the authoritative count at the time; the newest one is named in the section above.

## Update 2026-10-02 (LT-C5): fresh receipt and 100-boot soak

Newest receipt, run at 44de11f with QEMU suites on:
`evidence/trust1_m5_qualification_3f9d07f50196b4ad741b03c353ed3c45c268a72f04c32f00a0ddfab5294a3eee.json`,
`TRUST1_M5_QUALIFICATION: NOT_QUALIFIED (pass=19 fail=1 not_run=1 blocked=11 missing=5)`. It supersedes 3358bc25.
The one FAIL is `t1_gate7_preflight`, which reads live operator state: the Spark now has SecureBoot=0 (Drake's decision 2026-10-01), so the pre-flight correctly refuses. It is not a code regression. `store_rust_crosscheck` is NOT_RUN (Rust store tool not built).
Gate 4 soak: `GATE4_SOAK_RUNS=100 bash scripts/qemu_security_suite.sh` passed 100/100 boots plus the tampered-binary rejection (swTPM, QEMU, forge job C5-SOAK, log `~/workspace/test-queue-logs/C5-SOAK-005901.log`). The tampered-binary step in that run used the older check (the guest merely never printed `kernel: alive`); the suite now also requires the firmware banner, so a rerun of that step under the stricter check is NOT_RUN. Gate 4 stays MISSING_IMPLEMENTATION for the loader A/B and manifest items.
