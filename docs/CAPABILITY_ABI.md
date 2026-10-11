# Capability ABI: one production authority, one separate Rust implementation

Ruling of the ABI qualification (abi-qual, 2026-10-11). The two capability implementations in this
repository are intentionally independent. They are not two builds of one binary contract, and they
must never be linked in place of each other.

| | Native C authority (production ABI) | Rust crates (separate implementation) |
|---|---|---|
| Source | `native/capability/aienos_capability.{h,c}` | `crates/aienos-capability` (core, `no_std`), `crates/aienos-capability-ffi` (C binding) |
| Generation | 64 bits, `AIENOS_CAP_GENERATION_BITS` = 64 | 32 bits, `AIENOS_CAP32_GENERATION_BITS` = 32 |
| `AienosCapRef` | 16 bytes, align 8, generation at offset 8 | 8 bytes, align 4, generation at offset 4 |
| `AienosCapEntry` / `AienosCapMint` | 88 / 64 bytes | 64 / 48 bytes |
| Exported symbols | `aienos_cap_*` | `aienos_cap32_*`, plus `aienos_cap32_abi_layout` (ABI version 1) |
| Who links it | omega (`libaienos_capability.a` merged into `librx_compose.a`, header copy `src/runtime/aienos_cap.h`), `native/argus` | nothing in this repository |

## Why the separate prefix

Before this ruling the Rust FFI crate exported the same 17 function names as the C library with the
smaller layout. A program compiled against `aienos_capability.h` and linked against
`libaienos_capability_ffi.a` resolved every symbol and silently misread every `AienosCapRef` and
`AienosCapEntry`. With the `aienos_cap32_` prefix that program now fails to link.

The 32-bit generation is not widened: the Rust crates keep their own contract, and a slot whose
generation reaches `u32::MAX` fails closed (`ERR_EXHAUSTED`) instead of wrapping.

## What enforces it

- `native/capability/aienos_capability.c`: `_Static_assert`s pin the production layout.
- `crates/aienos-capability-ffi/src/lib.rs`: `const` layout asserts and `aienos_cap32_abi_layout`,
  which reports `AienosCapRef` size, generation offset, generation size and `AienosCapEntry` size.
- `scripts/cap_abi_isolation_test.sh`: builds both archives and fails unless they share no
  `aienos_cap*` symbol, a C caller of `aienos_cap_*` fails to link against the Rust archive, a cap32
  caller links against it, and a drifted C header (narrowed or reordered `AienosCapRef`) is rejected.
- CI: the `capability-abi` job in `.github/workflows/native-suites.yml` runs the C rule tests, the
  Rust crates' fmt, clippy and tests, and the isolation script.

```bash
make -C native/capability test
cargo test -p aienos-capability -p aienos-capability-ffi
bash scripts/cap_abi_isolation_test.sh   # ends with AIENOS_CAP_ABI_ISOLATION: PASS
```

## Restart fix brought to the Rust side

The Rust authority had the restart defect the C authority fixed in b1fa747: a restart started the new
table at the old boot generation + 1, which a reclaim had already used, so a reference minted after
one reclaim validated again after the restart. `aienos_cap32_restart` now starts the new table at or
above `AuthorityState::generation_floor()` of the table it replaces (`take_boot_gen_above`), and
refuses with `ERR_EXHAUSTED` when no such start exists.

## Known differences (not interchangeable, by design or still open)

- The C authority also seeds a restart from `CLOCK_BOOTTIME` so a new process starts above an old one
  on the same boot. The `no_std` Rust core has no clock: its starts are monotonic within one process
  only.
- The C `auth_use` requires privileged operations to present an entry on `AIENOS_CAP_RES_AUTHORITY`
  (issue #266, `docs/CAPABILITY_AUTHORITY_RESOURCE.md`). The Rust core does not have that check yet.
  Nothing links the Rust crates today; port the check before any consumer does.
