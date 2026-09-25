# Recovery Core over Store v1 and continuity: QEMU qualification (2026-09-25)

Code commit `e5b44d8ff5692f74fe191ab07f48fd21511ff82f` (clean tree), branch
`feat/recovery-core` (main `39e246a` + the operator-auth HMAC fix).
Design: ADR 0006 (Recovery Core), ADR 0007 (provisioning once), ADR 0016
(continuity, Proposed). QEMU only, 4096-byte LBA, native NVMe driver.

Reproduce: `./scripts/qemu_recovery_test.sh`

**Operator credential: TEST-ONLY.** The operator key is a public constant in
this tree and every boot prints `RECOVERY_OPERATOR_KEY: TEST-ONLY`. How the
real operator key is derived (Argon2id passphrase, FIDO/hardware key, ...) is
not decided (ADR 0006 / M5, operator decision). The verification primitive is
real: `HMAC-SHA256(key, "AIENOS-RECOVERY-OPERATOR-AUTH-v1\0" || challenge)`
compared in constant time.

## What is proven

| Claim | Step |
|---|---|
| Entry and inspection are deterministic and read-only: the raw system record (both superblock slots, mount state, peer condition, catalog counts, agent) is printed and the image is byte-identical after the boot | 1, 2, 3 |
| A challenge binds Store UUID, generation, action and a digest of both raw superblock units; zero, wrong-key and wrong-challenge responses are refused with no write | 1, 2 |
| An authorised repair of a malformed peer restores a writable store; a cold boot resumes the same agent with the same memory; replaying the authorisation on the repaired store does nothing | 1 |
| Operator provisioning on a healthy, unprovisioned store creates exactly one identity, which a cold boot resumes | 2 |
| After identity loss (corrupted agent root) no action is offered, both actions are refused, and a normal boot neither resumes nor mints | 3 |

## Finding fixed during qualification

The first run (commit `fe2c2bd`) failed step 3: corrupting the agent root of a
store provisioned at generation 2 made the Store mount `DegradedRecovery` on
generation 1 (genesis, no identity), continuity reported `Unprovisioned`, and
the Recovery Core offered `provision-identity`. A valid operator response
would have minted a replacement identity after identity loss. Fixed in
`e5b44d8` (fail toward preservation): a degraded mount is never
unprovisioned; repair only a malformed peer while the valid root still
resolves the identity; never discard a CRC-valid newer root in-band;
continuity objects without an agent root are `Corrupt`. The host regression
test uses a response that is genuinely valid for the state and fails on the
previous code.

## Result

```text
=== 1. Degraded store: operator-authorised repair ===
PASS  inspection enters the Recovery Core (Degraded(Malformed)), shows the same agent, writes nothing
PASS  repair with zero response refused, nothing written
PASS  repair with wrong_key response refused, nothing written
PASS  repair with wrong_action response refused, nothing written
PASS  authorised repair done
PASS  after repair a cold boot resumes writable with the same agent and memory
PASS  replaying the repair authorisation on the healthy store does nothing
=== 2. Unprovisioned store: operator-authorised provisioning ===
PASS  unprovisioned store enters the Recovery Core and offers only provisioning
PASS  provisioning with a wrong key refused, nothing written
PASS  operator provisioning created one identity and a cold boot resumes it
=== 3. Identity loss: nothing may mint ===
PASS  corrupted agent root: Recovery Core entered, no action offered, nothing written (Degraded(GraphBadNewer))
PASS  mode 10 after identity loss refused, nothing written
PASS  mode 11 after identity loss refused, nothing written
PASS  a normal boot after identity loss does not resume or mint (2c0752ceed5e81cd... is not replaced)

=== Summary (commit e5b44d8ff5692f74fe191ab07f48fd21511ff82f) ===
RECOVERY_CORE_QEMU: PASS
RECOVERY_CORE_OPERATOR_CREDENTIAL: TEST-ONLY (real scheme undecided, ADR 0006 / M5)
```

Host tests: `cargo test -p aienos-kernel --lib recovery_core` (8) and
`recovery` (operator-auth HMAC, RFC 4231 primitive vector, known answer,
bit-flip and legacy-construction rejection).

## Not claimed

- A real operator credential, Machine 1 behaviour, TRUST-1, M5 encryption.
- Rolling back to an older root when the newer one is graph-broken: refused
  in-band on purpose; it discards committed state and is an out-of-band
  operator decision.
- A/B boot-slot rollback and crash records on hardware (ADR 0006 items
  outside the Store).
