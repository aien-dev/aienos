# ADR 0019: Per-resource capability generation (OSC unit `required_generation`, domain 1)

Status: Proposed (operator decision open; nothing is implemented against it)
Date: 2026-10-08
Amends, only if accepted: [ADR 0013](0013-aienos-abi-v1.md) (adds a resource generation beside the handle generation), [ADR 0014](0014-binary-artifact-v0-and-native-admission.md) (replaces amendment "the OSC unit is a second container type", point 5).
Governing: [ADR 0012](0012-self-construction-capability-growth-and-generations.md) (rule 5: no native admission without enforcement), [aien-protocols](https://github.com/aien-dev/aien-protocols) `specs/osc-unit-artifact/OSC_UNIT_ARTIFACT.md` (v1 FROZEN, read at `666100969cedb97eded6533906c42307320ea61c`), sections 6.3, 8.2 step 15 and 15.3 C1.

## Context

An OSC unit capability request (spec section 6.3, bytes 48 to 63) carries `domain` and `required_generation`. Zero means "no requirement". A nonzero value means "admit this request only if the resource is currently at exactly this generation". The spec says the loader supplies that counter per (`domain`, `resource_kind`, `resource_id`), and forbids filling it from a handle-slot generation or a system Generation "until an AIENOS ADR defines a per-resource generation" (section 6.3, last rule; section 15.3 C1).

No AIENOS ADR defines one. Today's position (ADR 0014 amendment point 5, aienos#277) is fail closed: AIENOS supports domain 1 only and refuses every nonzero pin, in the spec's fixed order: `CAP_DOMAIN_UNSUPPORTED` (27), then `CAP_GEN_NOT_REPRESENTABLE` (28) for a domain-1 value above `0xFFFFFFFF`, then `CAP_GENERATION_STALE` (29) for any remaining nonzero pin. The kernel does this with a lookup that always reports "no such resource" (`native/kernel/core/osc_admit.c`, `no_resource`, passed as `gen_lookup`; the check is `native/kernel/artifact/osc_unit.c`, spec step 15c). Host tests pin the check itself (`native/kernel/tests/test_osc_unit.c`): vector `r18` gives code 28 (`vectors/expected.txt`), and `vectors/state.txt` admits `a02` (domain 1, kind 3, id 1, pin 7) when the test lookup reports 7 and refuses it 29 when the lookup reports 8. The kernel's own always-refuse lookup is not exercised by any host test or QEMU gate today (`scripts/qemu_ck_osc_unit_test.sh` loads a01, a04, r14 and r37 only).

### What AIENOS already counts (none is a per-resource generation)

| Counter | Where | Width | What it counts |
|---|---|---|---|
| Handle generation | ADR 0013 "Handles"; `crates/aienos-kernel/src/caps.rs`, `native/kernel/core/ipc.c` | u32 | Reuse of one slot in one task's capability table. Starts at 1, never wraps, slot retired at `u32::MAX`. |
| Authority reference generation | `crates/aienos-capability/src/lib.rs` (`CapRef`, `Entry.generation`) | u32 | Reuse of one slot in the native authority table, same rules. |
| Authority epoch | same crate, `bump_epoch` | u64 | Whole-authority invalidation: an entry from an older epoch is refused. |
| Boot generation | same crate, `take_boot_gen` | u32 | Each authority instance starts higher than the last. |
| System Generation | ADR 0012; ADR 0014 receipt `generation_context_id` | u64 | Which system image is running. |

None of these belongs to a resource. A handle or reference generation belongs to a table slot, which does not exist when a unit is admitted (spec section 15.1 row 55). The epoch and the system Generation change for reasons unrelated to any one resource, and the 64-bit ones cannot be represented in domain 1 anyway.

### What the kernel's resources look like today

Domain-1 resources are kernel channels and objects (ADR 0013 `ResourceKind` 2 and 3). Two numberings exist today, and both are fixed by the kernel image. The C kernel names its IPC channel and object with the constants `CK_IPC_CHANNEL_RESOURCE` (`0x49504348`) and `CK_IPC_OBJECT_RESOURCE` (`0x49504f42`) in `native/kernel/core/ipc.h`. The Rust kernel's Binary Artifact v0 path names its seed object `SEED_OBJECT_ID` (1) in `crates/aienos-kernel/src/task_runtime.rs`. The C kernel's OSC unit admission knows no resource at all (`no_resource`); vector `a02` pins object 1, which matches neither C constant. No code path in either kernel destroys a channel or object and hands its number to a different one (handle removal and revocation free table slots, not resources; artifact teardown frees tasks, frames and handles). So the problem a per-resource generation solves (a signed request naming resource number N meant the old N, and N now names something else) cannot happen on today's kernel. It becomes possible the first time the kernel creates and destroys channels or objects at run time, or persists resources across reboot or rollback.

## Decision drivers

1. A pin must never admit more than today without an explicit operator decision. Today every nonzero pin is refused; any option that starts admitting some pins widens behavior and must say so.
2. No counter may be filled from a handle-slot generation, an authority epoch, a boot generation or the system Generation (spec 6.3).
3. No byte change in the frozen container (spec C1 was settled as "Option A without a byte change").
4. Rollback (ADR 0012) must never make a counter go backwards, or an old signed pin could match a new resource.

## Options

### Option 1: "Domain-1 resources have no generation", made permanent

What it is: AIENOS declares that kernel resources carry no generation, now and for ABI v1. `required_generation` must be 0 for domain 1; any nonzero value stays refused exactly as today (28 or 29). ADR 0014 point 5 stops being "until an ADR defines one" and becomes the rule.

- Upside: nothing to build, prove or persist. Matches the kernel exactly (fixed resource numbers, no reuse). Behavior is byte-for-byte today's.
- Downside: signers can never pin a resource version. When the kernel gains dynamic resources, number reuse protection has to come from somewhere else (for example never reusing numbers), or this ADR is reopened. The spec's domain-1 generation field becomes permanently dead weight, which argues for dropping it in a future container version (spec C1 Option B).
- What changes: one ADR paragraph. No code, no vectors.
- Undo: a later ADR can define a generation; that would widen admission and needs its own operator decision.

### Option 2: Define a resource incarnation counter and build it now

What it is: every domain-1 resource number gets an incarnation counter (u32) with the ADR 0013 handle rules: 0 is never issued, the first resource to hold a number is at 1, each time the number is given to a new resource the counter goes up by 1, it never wraps, and a number whose counter reaches `u32::MAX` is retired. The loader's `gen_lookup` returns the current counter; a pin equal to it is admitted, anything else is STALE. A persistent resource stores its counter with it, and rollback never lowers a stored counter. A resource whose counter cannot be shown to be monotonic across reboot and rollback answers "no such resource", so its pins stay refused.

- Upside: completes what the spec intends; real protection against number reuse; one meaning shared by both container paths.
- Downside: new kernel state and, for persistent resources, a Store format change (ADR 0015 is frozen for P3-1; ADR 0016 says its format freeze needs operator approval). Kernel code, host tests, new vectors and a QEMU gate, for a counter that reads 1 for every resource on today's kernel. It widens admission: a unit pinning 1 on a fixed resource, refused today, would be admitted.
- What changes: kernel lookup, capability bookkeeping, possibly the Store format, vectors and gates. Roughly one campaign cut plus its reviews and QEMU runs.
- Undo: reverting the code returns to refusal; the persisted counters would remain as unused data.

### Option 3: Define the counter now, build it when resources become reusable (recommended)

What it is: this ADR adopts the incarnation counter of Option 2 as the contract (same rules, same rollback and fail-closed clauses), but the kernel keeps `no_resource` and keeps refusing every nonzero pin. Building the counter is tied to a named trigger: the first kernel change that lets a resource number be destroyed and reused at run time, or that persists a domain-1 resource across reboot or rollback. That change must implement the counter in the same cut, and its PR must state openly that pins which were refused become admissible (driver 1).

- Upside: costs nothing now and changes no behavior (refusal stays exactly as today). Gives the signed field a fixed meaning, so spec C1 is closed and the frozen container never needs a byte change. The work lands exactly when it starts protecting something.
- Downside: a defined but unbuilt rule can drift from the code if the trigger is missed; the trigger cut carries extra work. Until then signers still cannot pin.
- What changes: this ADR, plus a one-line pointer in ADR 0014 point 5. No code, no vectors.
- Undo: Option 1 or Option 2 can still be chosen later; nothing is built that would need removing.

### Rejected without an option

- Fill the counter from the handle-slot generation, the authority epoch, the boot generation or the system Generation: forbidden by spec 6.3, and each counts something other than the resource (table above). The 64-bit counters also fail driver 3 for domain 1.
- Change the container to drop the field (spec C1 Option B): a byte change in a frozen spec, out of scope for an AIENOS ADR.

## Recommendation

Option 3. It keeps today's fail-closed behavior, writes down the one meaning that fits the spec's rules, and spends engineering effort only when the kernel can actually reuse a resource number. Option 1 is the right choice if the operator prefers to keep ABI v1 minimal and drop pinning in a later container version.

## Invariants (all options)

1. A nonzero `required_generation` is admitted only if `gen_lookup` returns a counter equal to it; any lookup failure is STALE.
2. No counter is ever derived from a handle-slot generation, authority reference generation, authority epoch, boot generation or system Generation.
3. A counter never decreases, including across reboot and rollback; 0 is never issued.
4. Domain 2 (hosted, 64-bit) stays unsupported by AIENOS (`CAP_DOMAIN_UNSUPPORTED`); this ADR does not define it.
5. Any change that admits a pin refused before must say so in its PR and record the operator's approval.

## Evidence and limits

- Facts above were read on 2026-10-08 from aienos `origin/main` at `827e20f4` and the spec at aien-protocols `666100969ced`. No code was run for this ADR.
- This ADR changes no code, vector or gate. Kernel behavior stays: every nonzero pin refused.
- Gap recorded, not fixed here: no test runs the kernel's own `no_resource` lookup. A unit that pins a generation (for example `a02`) is not among the units the QEMU admission gate loads, so "the kernel refuses every nonzero pin" rests on code reading, not on a run.
- QEMU is the only place the OSC unit path has run; nothing here is a physical-Spark result.
