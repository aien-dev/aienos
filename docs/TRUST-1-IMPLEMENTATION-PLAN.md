# AIENOS TRUST-1 Implementation Plan: Owner-Controlled Boot & Recovery Gate

Status: Proposed. Requires operator approval before any trust mutation.
Scope: Transition from M2 (proven native boot, Secure Boot restored, native boots paused) to owner-controlled Secure Boot, TPM re-seal, emulator-first development, and safe resumption of native boots.
Out of scope: Blackwell GPU execution, CUDA replacement, GSP submission, native inference, Fabric rollout, desktop/GUI, mail/Matrix/OpenClaw/AstroSage, productization. GPU characterization continues as non-blocking research only.

Governing sentence: **Approval authorizes only the mutations and gates written in this plan. It does not authorize agents to improvise around failed gates.**

Conventions per milestone: Objective / Preconditions / Permitted mutations / Acceptance tests / Evidence required / Rollback. Result is PASS only when every acceptance assertion is true. Any unexplained deviation is FAIL/STOP, not partial success. Avoid ambiguous words (works, secure, ready, probably, should, supports, tested).

Owners (Q27):
- Operator-only: firmware setup, PK/KEK/db changes, Secure Boot enable/disable, Owner Root ceremony and private material, offline recovery credentials, destructive keyslot removal, final TPM-policy retirement, physical recovery-media custody, authority-broadening decisions, TRUST-1 approval, root-of-trust promotion. Agents prepare exact instructions and evidence only.
- Agent implementation: loader, kernel, A/B machinery, manifest formats, subordinate-key signing tooling, TPM simulation, measurement tooling, recovery environment, receipt formats, emulator tests, fault injection, CI classifier, reproducibility, docs, non-destructive inspection, proposed firmware/TPM commands for review.
- Automation: clean-tree, reproducibility, hashing, signature verification, emulator boots, fault suites, boundary classification, review enforcement, aien-proof serialization, ledger, boot budgets, manifest validation, rollback logic, retention, dirty/unapproved detection.

`aien-proof` owns `machine-1` during every trust-transition action. Every firmware/key/policy mutation has an explicit rollback procedure.

---

## Gate 0: Freeze current good state (Owner: Operator + Agents)

Objective: Record the known-good Spark baseline that all later rollback refers to.

Preconditions: Secure Boot enabled; Linux boots normally; TPM-sealed storage unlocks; vault unlocks.

Permitted mutations: Read-only inspection only, plus writing the baseline receipt to `evidence/`. No trust, boot, TPM, or storage mutation.

Acceptance tests:
- Secure Boot state recorded; PK/KEK/db/dbx fingerprints recorded.
- PCR values stable across multiple identical cold boots or variation explained.
- TPM event-log digest recorded; parser correctness confirmed.
- BootOrder and boot entries recorded; firmware version recorded.
- Every encrypted volume identified; LUKS/container IDs and header metadata digests recorded; every unlock path/keyslot recorded; which TPM object unlocks which volume/credential recorded; exact current TPM policy/PCR selection per secret recorded from enrollment config, not inferred.
- Offline recovery credential located; age identity located; decryption actually exercised against intended volume; vault credential recovery path proven independently. Secret values never recorded: identifiers, fingerprints, policy metadata, and proof only.
- Service baseline after restart-storm cleanup recorded; clean git/source state for reconstruction repos recorded; M2 CPU/memory facts referenced; UART/debug uncertainties listed.
- ATLAS_RECOV catalogued without exposing secrets; explicitly marked not disposable, not an installer disk.

Evidence required: Baseline `EvidenceReceiptV1` with fields per Q21 (receipt type, schema, timestamp, machine ID, operator/agent identity, repo, commit SHA, dirty flag, build ID, input/output digests, toolchain, procedure ID, result, assertions, receipt dependencies, hardware state, signature). Includes Secure Boot variables export where platform permits.

Rollback: N/A (read-only). If any Q26 item unanswerable, Gate 0 FAILS: nothing else starts.

Stop condition: If Spark does not unlock tomorrow we must know what protects data, what changed, and which independent path restores access. Otherwise not frozen.

---

## Gate 1: Build and prove recovery media (Owner: Operator + Agents)

Objective: Dedicated recovery USB proven on the real Spark before any trust change.

Preconditions: Gate 0 PASS.

Permitted mutations: Create recovery image on build host; write to separate physical USB (not ATLAS_RECOV); boot it once via operator-attended boot with Secure Boot enabled. No internal trust, TPM, or slot mutation.

Acceptance tests (Q17, all must pass with Secure Boot ON):
1. Firmware accepts recovery image. 2. Environment starts without internal Linux. 3. No network required. 4. No model required. 5. No Cortex required. 6. Identifies NVMe and encrypted volumes. 7. Inspects Secure Boot state. 8. Inspects PCRs/event data. 9. Shows AIENOS A/B slots and manifests. 10. Verifies signatures/hashes. 11. Accesses independent recovery mechanism only when explicitly authorized. 12. Mounts recovered storage safely. 13. Can reinstall known-good loader/slot. 14. Can restore documented boot config. 15. Returns machine to known-good Linux boot. 16. No destructive overwrite unless operator explicitly chooses it.
- Harmless test artifact round-trip: create known file → shutdown → recovery boot → unlock via recovery path → verify → normal boot. No destructive test of real dataset.

Evidence required: Recovery receipt (image SHA-256 + BLAKE3, layout digest, tool manifest, signing cert fingerprint, boot result, test-artifact digest, unlock method, return-to-Linux proof) plus `aien-proof` ledger receipt.

Rollback: Remove USB; boot Linux default. If recovery not proven, STOP: no Gate 2+.

---

## Gate 2: TPM measurement campaign (Owner: Agents, Operator for reboots)

Objective: Determine which measurements represent enforceable security properties before choosing any PCR policy.

Preconditions: Gates 0-1 PASS. System stable. No firmware auto-update during campaign.

Permitted mutations: Controlled one-variable boot experiments + rollback after each. No permanent policy change.

Acceptance tests: Baseline repeated cold boots produce stable measurements or variation explained. Each experiment changes exactly one variable (Q15 list: kernel, init image, boot order, db addition, owner cert addition, loader version, semantically-identical loader rehash, signer rotation, manifest-only, kernel-only, slot A vs B, firmware setting, firmware update if occurs, recovery boot, tampered image) with before → mutation → PCR/event result → after → rollback → post-rollback measurements recorded. Final report explains why each candidate PCR contributes to security; no PCR selected by convention.

Evidence required: Per-experiment measurement receipts (baseline, one variable, resulting PCRs, event-log digest, rollback result) chained to baseline receipt.

Rollback: Restore pre-experiment boot state after each run. Firmware changes treated as new campaign input; never relax policy automatically.

Stop condition: Any unexplained PCR change → UnexpectedState protocol (Gate 9), no policy chosen.

---

## Gate 3: Owner Root key ceremony (Owner: Operator; Agents prepare)

Objective: Small owner-controlled hierarchy exists offline with verified backups, unenrolled in firmware yet.

Preconditions: Gates 0-1 PASS; Gate 2 measurements collected (analysis may finish in parallel, but no firmware enrollment until Gate 2 complete).

Permitted mutations: Offline ceremony on clean disconnected environment only. Generate Owner Root, Boot Signer, Release Signer, Operator Approval key. Owner Root signs generation-1 authority manifest (subordinate publics, creation time, generation, roles, rotation rules). Two encrypted offline backups in separate locations. Export publics/fingerprints only. Destroy plaintext temp copies and verify.

Roles (Q6): Root never on Spark, never routine; Boot Signer signs small stable loader (firmware trusts its cert); Release Signer signs kernel/manifests under loader (replaceable via root-signed manifest; compromise never requires firmware-root replacement); Operator Approval authorizes boundary changes, never boots. Firmware must not trust a general dev key. Preserve factory trust alongside; full PK/KEK replacement is a later milestone after recovery independently proven.

Acceptance tests: Ceremony record contains tool versions, procedure, public fingerprints, manifest digest, backup-media IDs, both-backup decrypt verification, operator signature. Record contains no private material. Rotation path demonstrated as add → verify → exercise recovery → revoke (never delete-first). Root replacement defined as special recovery ceremony.

Evidence required: Key ceremony receipt (fingerprints, manifest digest, roles, backup count, verification success).

Rollback: No firmware state changed; destroy or quarantine disputed material per operator direction and re-run ceremony if needed.

---

## Gate 4: Emulator security suite (Owner: Agents)

Objective: Signed loader + A/B flow proven entirely in QEMU before hardware eligibility.

Preconditions: Gates 2-3 complete (authority manifest exists). Clean checkout; dirty builds never signable.

Permitted mutations: Code, manifests, and test artifacts in repo/QEMU only. No hardware trust mutation.

Acceptance tests (Q9, all must pass):
Clean UEFI boot; ExitBootServices handoff; memory-map validation; MMU init; vectors; allocator invariants; timer/interrupt where emulatable; scheduler invariants; panic/fault reporting; deterministic shutdown/reset; signed loader accepted; unsigned rejected; tampered rejected; valid manifest accepted; altered manifest rejected; A/B selection; failed candidate fallback; software-TPM policy cases (current, next, rollback) pass; Recovery Core boots model-/network-free; reproducible build from clean checkout; commit/inputs/digest recorded. Soak: 100 consecutive boots, 100 expected outcomes. Fault injection: bad manifest, corrupt kernel, missing state, invalid memory map, interrupted update, boot panic, invalid policy, failed slot.

Evidence required: Build receipts (commit, lockfile digest, toolchain, command, binary digest, reproducibility) + emulator receipts (image digest, suite version, counts, fault results, swTPM state).

Rollback: N/A (no hardware state). Failure returns to implementation, never to hardware.

---

## Gate 5: TPM authorization policy simulation (Owner: Agents)

Objective: Owner-approved release-set policy defined and exercised in software TPM.

Preconditions: Gates 2-4 PASS (measurements + emulator suite).

Permitted mutations: Policy definition files and swTPM simulation only. No real TPM enrollment change.

Acceptance tests: Semantics owner-approves-N → accepts N; approves N+1 → accepts N and N+1 during transition; N+1 healthy → may retire N. Cases pass: current, next, rollback, invalid, rotation, recovery. Target statement enforced: "Secure Boot active, owner-approved chain executed, manifest in approved release set": never a frozen hex value. Anti-rollback generation semantics defined (Q29): approved vs emergency-only vs revoked; recovery override under operator control only.

Evidence required: Policy spec + simulation receipts.

Rollback: N/A. Do not proceed to storage migration until simulation passes.

---

## Gate 6: Storage migration preparation, no retirement (Owner: Operator + Agents)

Objective: New unlock envelope installed alongside old; independent recovery verified; nothing retired.

Preconditions: Gates 0-5 PASS. Volume healthy.

Permitted mutations: Add new TPM authorization envelope and verify new offline recovery credential while volume healthy. Add-only; never remove last working path.

Stages (Q16): 1. Prove existing recovery (decrypt, correspond to volume) or create/test new independent credential first. 2. Coexist: current TPM path + new owner-policy path + offline path. 3. Prove all three unlock. 4. Exercise approved/previous/rejected-unsigned/Linux-rollback/recovery-media cases. 5. Observation across update/rollback cycles.

Acceptance tests: Current Linux unlocks; recovery credential unlocks; owner-policy unlocks; rejected image rejected; rollback to Linux works; recovery-media unlock works. Old enrollment retained.

Evidence required: Storage-migration receipt (old verified, offline verified, new installed, new verified, old retained, header metadata digest).

Rollback: New path disabled; old + offline paths remain. If new path fails, STOP, preserve, report.

---

## Gate 7: TRUST-1 hardware validation, single exception (Owner: Operator; one aien-proof machine-1 hold)

Objective: With Secure Boot ON, owner-signed loader boots once, Linux remains default/fallback, storage/vault survive, no permanent trust lost.

Preconditions: Gates 0-6 PASS; recovery USB proven; owner keys backed up; Secure Boot variables archived; emulator suite passing; operator TRUST-1 approval receipt.

Permitted mutations (only these, in order): add owner trust without deleting factory trust; one-time BootNext AIENOS entry; add new TPM authorization path without removing current one. No BootOrder default change, no Linux entry replacement, no AIENOS default, no factory-trust removal, no old-TPM removal.

Checkpoints (Q18):
- Preflight bundle captured (variables, PCRs/event log, boot entries, unlock methods, volume metadata, kernel identity, candidate digest, key fingerprints, recovery digest, service state, approval).
- A: recovery media boots or STOP.
- B: add owner trust → reboot Linux → Secure Boot on, Linux boots, storage unlocks or restore trust and STOP.
- C: stage owner-signed AIENOS BootNext only → boot → loader accepted, chain valid, kernel entered, measurements recorded, timed return or recover and STOP.
- D: Linux returns → Secure Boot on, storage unlocks, vault unlocks, default unchanged, services stable.
- E: test new TPM path only after chain proven; never enroll trust + replace policy in one irreversible step.
- Every mutation: before evidence → one mutation → validation → rollback checkpoint. Unexpected state → STOP-PRESERVE-OBSERVE-REPORT, no improvisation; documented non-boundary rollback only.

Acceptance tests: Secure Boot stayed ON; owner loader accepted; unsigned/tampered rejected (proven in emulator + spot-check where safe); kernel alive; BootNext consumed; Linux default; storage unlocks; vault unlocks; previous unlock path still valid; recovery re-proven after.

Evidence required: TRUST-1 receipt chain (pre-state, each mutation/validation/checkpoint, final state, approvals) + aien-proof hold ledger + PCR/event snapshots + artifact digests.

Rollback: Level 1 candidate→known-good; Level 2 AIENOS→Linux default; Level 3 restore prior Secure Boot variables/keys; Level 4 previous TPM enrollment or offline credential; Level 5 dedicated recovery media (Q11).

---

## Gate 8: Observation period (Owner: Automation + Operator)

Objective: Prove reliability before retiring anything.

Preconditions: Gate 7 PASS.

Permitted mutations: Normal Linux boots + controlled AIENOS candidate cycles under new chain. No retirement.

Acceptance tests: Several successful Linux boots and AIENOS candidate cycles with old + new + offline paths retained and healthy.

Evidence required: Ongoing boot/storage receipts chained to TRUST-1.

Rollback: Any regression → retain all paths, return to Gate 7 analysis.

---

## Gate 9: Retire legacy TPM policy; resume native development (Owner: Operator approval required)

Objective: Owner-controlled policy becomes primary; ordinary native AIENOS development resumes under new chain.

Preconditions: Gate 8 evidence shows repeatable reliability.

Permitted mutations: Retire old TPM enrollment only. No other trust change in same step.

Acceptance tests: Owner policy unlocks repeatedly across boots/updates/rollbacks; offline recovery still valid; Linux default intact; AIENOS A/B discipline holds (write inactive → verify → boot once → health → promote → retain rollback; bounded attempts, no boot-loop, last-good never erased by candidate/agent; dual-invalid → recovery media; root-of-trust promotion still needs operator approval even if tests pass).

Evidence required: Retirement receipt + updated policy manifest.

Rollback: Re-enroll previous policy from archived state or unlock via offline credential.

---

## Cross-cutting requirements (apply to all gates)

Loader minimality (Q14): Loader answers only what may boot, which slot, and what verified facts the kernel receives. Out: networking, package management, inference, Cortex, AEGIS evaluation, general FS, shell, repair, apps, update download, complex drivers, excess unseal, business logic. Loader changes rarely.

Slot/manifest (Q19): A=known-good, B=candidate (roles, not names). Manifest minimum: format version, generation, kernel digest, image digest, loader ABI, kernel ABI, signer, commit, provenance, rollback compat, policy generation, timestamp, signature. Health gates before promotion receipt; explicit authenticated promotion.

M3 readiness (post-TRUST-1 only): Emulator must prove EL/vectors/IRQ/fault, allocator/page tables/isolation/permissions, timer/GIC, scheduler/SMP, IPC/capabilities, panic/watchdog/fallback, security invariants (no arbitrary phys map, no cross-task access, no forged caps, no writable kernel metadata), stress + 100 clean boots. First hardware M3 proves platform differences only.

Boundary enforcement (Q23): `security-boundary.toml` (root_of_trust, secure_boot, tpm_policy, storage_unlock, cryptography, kernel_privilege, aegis, capability_model, effect_broker, persistent_identity, recovery, persistent_format) mapping paths/APIs to approval class and tests. Every PR declares SECURITY_IMPACT (NONE/BOUNDARY/ROOT_OF_TRUST/AUTHORITY/RECOVERY/PERSISTENT_FORMAT). CI independently classifies; mismatch with NONE fails hard; any sensitive class requires operator approval receipt + security tests. Classifier/branch/CI/boundary-map/signing changes are ROOT_OF_TRUST/AUTHORITY, never autonomous.

Build identity (Q24): BuildIdentityV1 (repo, commit, dirty flag, dep digests, Cargo.lock, compiler, target, linker, flags, features, env whitelist, script versions, epoch, artifact digest). SHA-256 + BLAKE3. Loader/ kernel/ manifest/ recovery identities as specified. Reproducibility: two clean builds → same unsigned artifact or not signable. Sign after identity; manifest references unsigned digest + envelope digest.

Unexpected states (Q25): STOP → PRESERVE → OBSERVE → REPORT with UnexpectedStateReceipt (expected, actual, last checkpoint, last mutation, evidence, rollback options). Forbidden to fix-forward across unknown security state. Documented non-boundary rollback only; else wait for operator. Rule: unknown state means no new mutation.

Firmware policy (Q29): No auto firmware update during transition; record version before every TRUST-1-class op; firmware change = new measurement input; never auto-relax policy; recover via recovery path and deliberately authorize new state.

Disaster recovery (Q29, architectural now, required before AIENOS becomes sole environment): Off-machine encrypted backups for Owner Root, storage recovery, AIEN identity, Cortex, source/provenance, manifests/recovery artifacts. Invariant: loss of Machine 1 costs hardware and unreplicated execution state, never ownership, data, authority, or rebuild ability.

Documentation: This plan + receipts live in `docs/` and `evidence/` with hash-linked chain. Every important claim has an artifact, not a memory.
