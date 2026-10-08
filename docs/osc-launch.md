# OSC unit task launch (C3-3a)

Label for everything below: **QEMU (aarch64 virt), TEST signer, not physical.** Nothing here has run on a
Spark or any real machine. Contract: `OSC_UNIT_ARTIFACT.md` section 9 (aien-protocols PR #17). Gate:
`scripts/qemu_ck_osc_launch_test.sh` (`OSC_LAUNCH` row in `scripts/ck_gates.sh`, notes in
`native/kernel/GATES.md`).

## What runs

An admitted unit (`struct osc_accept` from `osc_unit_admit`) is run as one function call in an EL0 task with
its own address space, by `ck_osc_launch` (`core/osc_task.c`): look up the function by exact name, check the
arguments, copy and re-hash the code, map, enter EL0, wait, classify, tear down. One call at a time, one slot.

## The call signature (what an entry gets)

- **x0..x5:** the arguments in `reg_kind` order. A slice takes two registers: pointer, then length (`bytes`
  length in bytes, `cells` length in 8-byte cells). Scalars are checked for their kind first (bool 0/1,
  narrow ints in range, signed ints canonically sign-extended).
- **x7:** `OscRt *`, a unit-space address (base + 0x1000). It points at the 13-pointer vtable of
  `runtime_abi_version` 1 (offsets 0..96). The page is **read-only and never executable** to the unit; the
  pointers lead to read-execute stubs (base + 0x2000), each `svc #i`. Only the `trap` stub (offset 16) and the
  return stub are serviced.
- **x30:** the return stub. The entry function's `ret` reaches it and the kernel reads **x0** as the result.
  Every other register is zero. **sp** is the top of a stack of the declared `max_stack_bytes`.
- **Slices:** `bytes` pointers must lie in the input window (read-only to the unit, at most 4096 bytes copied
  from the caller, address from `ck_osc_va_in()`). `cells` pointers must be 8-byte aligned and lie in the
  caller's workspace (read-write, caller-sized 0 to 32 pages, `ck_osc_va_ws()`). A zero-length slice may carry a null pointer and
  is never touched. A pointer anywhere else is refused with 41 before the first instruction.
- **Return value:** one u64 in x0 (`RETURNED.value`); a void function (`ret_kind` 0) reports 0, as the spec says (not exercised by the gate: no
  void function in the test units). Narrow return kinds are not re-canonicalized.

## The ticks budget

The unit is **timer ticks**: one tick is one EL1 physical-timer interrupt, `CNTFRQ/100` counter counts =
**10 ms** (the C kernel's scheduler tick, `arch/timer.c`). The budget is the unit's declared `cpu_ticks`,
lowered (never raised) by `max_ticks` in the request. The timer is armed only for the duration of the task;
the Nth tick that arrives while EL0 is running ends the task. A task shorter than one tick is never charged
(`ticks=0`); the limit is accurate to one tick.

`OUTCOME_UNKNOWN` reaches the caller as `struct osc_result`: `cls == OSC_RES_UNKNOWN (4)` and
`unknown_reason`: 1 FAULT, 2 TICK_OVERRUN, 3 LAUNCH_LOST, 4 TRAP_CODE_UNKNOWN, 255 OTHER (the spec's values).
The other classes: `RETURNED (1)` with `value`, `TRAPPED (2)` with `trap_code` 1..14, `REFUSED (3)` with
`refused_code` (40, 41, 30 or 16). The reason is diagnostic and never changes the class.

## Re-entry: yes, with a caller-owned workspace

A unit can be called again and see state left in a **caller-owned `cells` workspace**: pass the same
`struct ck_osc_ws` (`{ mem, pages }`, page aligned, `pages` chosen by the caller, 0 to 32) in `ck_osc_launch_req.ws`. The kernel maps the caller's pages read-write (never executable)
and does not clear them at teardown; the unit's own stack and registers are not kept, nothing else persists.
The gate calls `counter(ws, 1)` three times on one workspace (1, 2, 3), once on a fresh one (1 again), and twice on a
23-page workspace (the OSH resumable size, 91,648 bytes) touching its very last cell: 1, then 2, state preserved.
Section 9 allows this: borrows last for one call and the runtime keeps no reference. An OSH step that returns
NEED_MORE_INPUT and is called again therefore works if all its state lives in that workspace. Not provided:
`alloc`, arenas and pools (the runtime services behind vtable offsets 0 and 24..96), so a step that allocates
through `OscRt` ends `OUTCOME_UNKNOWN(OTHER)`.

## What is enforced

- **W^X:** code and runtime stubs are read-execute and never writable; data, stack, input window, OscRt table
  and workspace are never executable (UXN) and PXN is set on every user page. Kernel mappings are EL1-only.
- **OscRt and kernel memory are not writable by the unit:** a write to the table, to code or to any kernel
  address is a contained fault. The stack has an unmapped page below it: overflow is a fault.
- **Code integrity:** the code is copied into private pages and hashed again against `code_sha256` before it
  is mapped (spec 8.2); a mismatch is refused 16.
- **No system calls from unit context (9.1.1 item 1):** an SVC anywhere but a runtime stub (with the stub's own
  immediate) ends the task as `OUTCOME_UNKNOWN(FAULT)`. Admission already refuses every SVC word (8.4).
- **Arguments before the first instruction:** 9.2 exactly (verified against the spec's C reference) plus
  ownership (9.1.1 item 4). Unknown name: 40. Bad shape or range: 41.
- **Results:** RETURNED only through the return stub; TRAPPED only through the trap stub with a code in
  1..14; a `brk` reached directly, any CPU fault, a trap code outside 1..14 and a budget overrun are
  `OUTCOME_UNKNOWN`, never RETURNED or TRAPPED.
- **Teardown:** tables, runtime pages, input, code and stack are zeroed and unmapped; `pages_after=0` and the
  slot is free for the next launch. Caches are cleaned and the TLB invalidated.

## Decisions (simplest honest option, with reasons)

1. **A bare `brk` is a fault, not TRAPPED.** The brief said "TRAPPED with the BRK immediate for BRK 1..14".
   Spec 8.4 says a unit that reaches a `brk` has faulted and the platform reports `OUTCOME_UNKNOWN(FAULT)`,
   "never TRAPPED"; 9.3 says a launcher never maps a fault to TRAPPED. The spec wins. TRAPPED comes from the
   real compiler sequence: the unit calls the runtime trap service with the code (`ldr x16,[rt,#16]; blr x16`,
   code in x1), served by the `trap` stub. The gate shows TRAPPED 3 and 14 that way, and `brk` reached
   directly as FAULT.
2. **The ticks budget uses the existing 10 ms timer interrupt**, armed only while a task runs, with no
   preemption between tasks. This keeps the C kernel's scheduler untouched. Cost: 10 ms granularity.
3. **A caller cap on the budget** (`max_ticks`), because the declared maximum of a signer is up to 1e9 ticks
   (a loop would run 115 days). The cap only lowers.
4. **Launcher hard maxima are stricter than the container's:** code 64 KiB, stack 64 KiB, input 4 KiB,
   declared workspace 16 KiB. A unit declaring more is refused 30 (`RESOURCE_UNAVAILABLE`) at launch, nothing runs
   (spec 8.2 step 16 lets a loader apply stricter limits). `a06_valid_limits_at_max` is such a unit.
4a. **The workspace is caller-sized, capped at 32 pages (128 KiB, `OSC_WS_MAX_PAGES`).** OSH needs 23 pages. 0 pages
   means no workspace. The cap bounds the user pages, page-table slots and kernel bss; it is the kernel's choice,
   never read from the container (container format and vectors unchanged). A request over the cap, with a null
   or non-page-aligned `mem`, is refused before the first instruction with 30 (`RESOURCE_UNAVAILABLE`), the
   code spec 8.3 gives to a failed reservation of pages. The mapping stays read-write and never executable,
   is not cleared at teardown, and `cells` pointer checks use the actual size.
5. **Ownership failures use code 41.** The spec gives no separate code for 9.1.1 item 4.
6. **Unprovided runtime services end the task as `OUTCOME_UNKNOWN(OTHER)`** instead of being faked.
7. **Hand-assembled test unit.** The extra gate units (trap, spin, faults, counter) are written in assembly
   (`tests/fixtures/osc_unit/launch/l01.S`) and signed with the spec's own generator helpers; `oscc` emits
   only digests, and OSC has no way to loop forever or fault. The IR section is `min.ir`, so the IR does not
   describe that code (attested, never checked: spec section 10).

## Not done (later cuts)

- **Capability authority:** the capability table delivered to the task is empty. CAPS requests are admitted but
  not granted or enforced; admission still treats every pinned generation as stale.
- **Generation** (`required_generation`, the 32/64-bit bridge, conflict C1).
- **IPC and console input**, and any runtime service behind `OscRt` other than trap: alloc, arenas, pools.
- **Concurrency:** one task slot, one call at a time, no preemption between tasks, no SMP use.
- **Return canonicalization:** x0 is reported as-is for every kind except void (reported as 0).
- Kernel entry for launches outside the gate: the self-test driver (`CK_OSC_LAUNCH_TEST`, qualification
  builds only) is the only caller. No Store-driven or shell-driven launch exists yet.
- **Nothing is physical.** No Spark, no hardware, no release signer; the only key is the spec's throwaway
  TEST key.
