# ALLEN interactive routing (aienos#399)

ALLEN REFLEX decides a 15-way label for one conversation. `crates/allen-reflex/src/route.rs` turns that label,
plus facts the caller holds (who speaks, recorded memory consent, whether the lifecycle has a pending item, which
capabilities the machine really has), into one typed `DecisionProposal`:

- `route`: `local_deterministic`, `memory`, `clarify`, `refuse`, `local_model`, `spark_inference`,
  `spark_omegese` or `approval_needed`; `then` names the owner decision an `approval_needed` waits for.
- `ready`: `yes`, or `no:<reason>` (`store_absent`, `owner_desk_absent`, `no_local_model`, `spark_link_down`,
  `no_memory_consent`) with `fallback: local_deterministic`. A missing capability is said, never hidden.
- `clarify` is the explicit unknown route: no user turn, non-ASCII or unknown words, a score under the frozen
  calibration, a missing subject, a model that is not installed, or approve/deny/cancel with nothing pending.
- `grants: none`, always. A proposal is data. Pending state and consent come from the caller's records, never
  from the conversation text, and the owner desk (lifecycle) is still the only place an approval happens.
- Spark routes carry the SHA-256 of a bounded PST1 request (aien-protocols Draft v0: 224-byte header, payload at
  most 800 bytes, objective id = SHA-256 of `AIEN_E2E_OBJECTIVE_V1\n` + text). Nothing is sent from this cut.

## Families and calibration

`route-dev.psv` (35), `route-val.psv` (24), `route-heldout.psv` (37), hashes in `FREEZE.sha256`, frozen before
any scoring. Scoring context: owner/guest and flags per row, all capabilities present, installed model
`tinyllama` (`crates/allen-reflex/examples/route_exam.rs`). Calibration was swept on dev only and frozen:
reflex `min_sim 0.20`, nearest `min_sim 0.35`, perceptron `min_margin 0.15`.

| split (scored once) | reflex | nearest | perceptron |
|---|---|---|---|
| dev (tuned here) | 34/35 | 33/35 | 33/35 |
| val | 23/24 | 23/24 | 22/24 |
| held-out | 36/37 | 36/37 | 33/37 |

Every miss is non-granting (a stored-text injection read as a memory read; perceptron refusing two unknown
requests instead of clarifying and sending one out-of-capability request to the owner desk). Limits: the
families were written by the same author as the router (Claude), so these scores are likely optimistic; they
test routing policy on top of the frozen core, and the 15-way exam held-out set was not re-scored.
Logs: `results/route-{dev-frozen,val,heldout-host}.log`.

## Red before green

`results/route-red.log`: the 14 route tests against a stub (9 failed). `results/route-green1.log`: 14/14.
`scripts/allen_route_mutants.sh` (`results/route-mutants.log`): an approval phrase that runs without the desk,
pending state read from the conversation, and a guest reading owner memory are each caught by the tests.

## On the image

`make pi5-allen` accepts a route card on `\EFI\AIENOS\ALLEN.EXM` (header `AIENALR1 QUALIF-ALLEN-ROUTE`, built by
`scripts/allen_route_card.sh`; no expected answers, no capabilities, held-out files refused). `core/allen.c`
prints one `ALLEN_P <mode> <id> <proposal>` line per request and mode with the image's own capabilities (none),
checks the authority rules again in C (`ALLEN_Q ... authority=held`), repeats every proposal, and prints
`ALLEN_RSTAT` with the per-request latency measured with the CPU counter around the Rust call (decode, core,
route policy, PST1 digest, JSON; printing excluded).

QEMU twin (`scripts/qemu_ck_allen_reflex_test.sh` section 5, `results/qemu-twin.log`): 177 proposal lines equal
the host harness byte for byte, authority held, a card claiming a capability flag is refused whole, and the same
stage linked with the grant mutant fails its own check. QEMU qualifies nothing physical.

## On the Raspberry Pi 5 (run `pi5-allen-route-399b`, 2026-10-16)

Image `make pi5-allen` at commit 2613e56 (BOOTAA64.EFI sha256 `6e6ababd...f381`), cold boot by one-shot tryboot,
route card = dev + val families + 10 requests written after the image was built (`results/pi-route-399b.fresh.req`),
69 requests, card sha256 `d9abc833...1726`. Capabilities passed by the image: none.

- `AIENOS_CK_ALLEN: PASS`; all 207 `ALLEN_P` lines (3 modes x 69) are byte-identical to the host harness
  (`results/pi-route-399b.host-lines.txt`); every proposal repeated identically; heap returned to its mark after every
  proposal, no refused allocation, heap live 0 and every frame returned at the end.
- Authority: 207/207 `authority=held`, `authority_violations=0` in every mode; 28 to 30 proposals per mode said
  not ready (with the `local_deterministic` fallback) because this image has no Store, desk, local model or link.
- Measured per-request latency on the Pi (CPU counter at 54 MHz around the Rust call, printing excluded; with 69
  requests the nearest-rank p99 is the maximum):

| mode | p50 | p95 | p99 = max | training at boot |
|---|---|---|---|---|
| reflex | 875 us | 1241 us | 1303 us | 254 ms |
| nearest | 57 us | 73 us | 85 us | 2.9 ms |
| perceptron | 23 us | 38 us | 41 us | 18.7 ms |

Kernel stack used 7808 of 262144 bytes (`mm_usage`). Evidence: `results/pi-route-399b.{kernel,run}.log`.

Two of the ten fresh requests got a route a person would not pick, both safe: "Is everything on the box healthy
this evening?" went to the owner desk as a `remember` (not ready), and "Compose a short poem about the moon over the
lake." asked to clarify (missing subject) instead of going to a model. They are recorded, not tuned away.

Not run on the Pi: input typed after boot (the native image has no live input path yet; aienos#396 has no live
request channel and the Pi network lane is not ready), presentation and owner consent through #396, any Spark send,
and energy (no sensor).
