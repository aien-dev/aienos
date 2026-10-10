# L6-B int8 dot path: qualification receipts (aienos#34, draft PR #300)

Pre-registered before any test or code for this round (2026-10-10). Drake's ruling
(aien-architecture#190, last comment on PR #300): int8 promotion is approved for supported hardware,
gated, subject to native qualification. The PR stays a draft until the four conditions below have
receipts. The f32 path stays as the fallback. This round produces receipts only. It does not change
the kernel's default path, any kernel source outside `crates/aienos-infer`, or anything to do with
the accelerator.

## Terms

- f32 path: activations stay f32 (`DecodeState.int8_dot == false`). The default today.
- int8 path: activations on ggml's Q8_K grid, i32 dots (`int8_dot == true`).
- Features: `Features { dotprod, i8mm }`, supplied by the caller (the crate is `no_std` and
  `forbid(unsafe_code)`, so it never reads CPU registers itself).

## Condition 1: CPU-feature detection

Design (all in new module `crates/aienos-infer/src/dotpath.rs`):

- `pub struct Features { pub dotprod: bool, pub i8mm: bool }`, plus `Features::from_hwcap(hwcap, hwcap2)`
  that decodes the Linux auxiliary-vector words (`HWCAP_ASIMDDP` = bit 20 of `AT_HWCAP`;
  `HWCAP2_I8MM` = bit 13 of `AT_HWCAP2`, checked against `/usr/include/asm/hwcap.h`; the brief said
  both are in `AT_HWCAP`, but I8MM is in `AT_HWCAP2`, so that is what the code and receipt use).
- `pub enum DotPath { F32, Int8 }`.
- `DotPath::select(features, requested)` calls `select_with(features, requested, INT8_PROMOTION_DEFAULT)`.
  Rule: `Int8` iff `requested || (promotion && features.dotprod && features.i8mm)`, else `F32`.
  An explicit request is honoured even without the features: the int8 path is correct on every CPU
  (portable integer code), only slower than with `usdot`.
- Host harness (`examples/l6_host.rs`) fills `Features` from `/proc/self/auxv` (the same kernel
  vector that `getauxval` returns, read through std so the example needs no `unsafe`), on aarch64
  only; other architectures report no features.
- Kernel side: a documented hook point only (a comment in `dotpath.rs` naming `ID_AA64ISAR0_EL1.DP`
  and `ID_AA64ISAR1_EL1.I8MM`). Kernel register reads go through the manual-guard process and are
  not implemented here.

Tests (in `dotpath.rs`):

| Test | Before | After |
|---|---|---|
| `dotpath::tests::select_matrix_all_combinations` (4 feature sets x requested x promotion, 16 rows) | absent (does not compile) | PASS |
| `dotpath::tests::features_from_hwcap_bits` | absent | PASS |

## Condition 2: numerical parity

Pre-registered criterion, stated before measuring:

- Subject: the 64-token greedy sequence of the recorded f32 record (`evidence/l6_host_3f5a22426976_l6b.json`,
  prompt "What is the capital of France?", Llama-3.2-1B-Instruct Q4_K_M, sha256 3f5a2242..., end-of-turn
  ignored, same loop as `l6_host`).
- PASS RULE (gated): the int8 path produces the identical 64 token ids as the f32 path run in the same
  process. A second reported check: the in-run f32 tokens equal the recorded f32 tokens in the evidence JSON.
- REPORTED, NOT GATED this round: the per-position maximum absolute difference between the int8 and
  f32 logit vectors, and the overall maximum. Positions after a first token divergence are not
  comparable (different histories), so the logit comparison covers positions 0 through the first
  divergence index inclusive (all 64 if tokens are identical).
- If parity FAILS it is recorded as FAIL with the numbers. Nothing is tuned to make it pass.
- Expected result: unknown before the run. The existing llama.cpp-comparison tests show int8 stays
  within the Q8_K bound against llama.cpp; they do not prove token identity against our own f32 path.

Mechanism: ignored model-backed test `tests/forward.rs::int8_parity_64_tokens_vs_f32` prints
`PARITY_*` lines (`--nocapture`). `scripts/l6_host_receipt.sh` runs it (release build, pinned to one
core, 1 thread) and writes a `parity_int8_vs_f32` block: `{tokens_identical, first_divergence_index,
max_logit_abs_diff, max_logit_abs_diff_position, per_position_max_logit_abs_diff, compared_positions,
f32_matches_recorded, rule, verdict}`. The existing top-level string `parity` (first 8 ids against the golden
reply) is left unchanged. New flag `--parity-only` writes only
`evidence/l6_host_<sha12>_l6b_parity.json` without redoing the speed legs, so the committed speed
receipt is not overwritten.

## Condition 3: rollback path

- Default is f32. `pub const INT8_PROMOTION_DEFAULT: bool = false;` in `dotpath.rs` is the kernel's
  build-time switch: with it `false`, `DotPath::select` returns `F32` unless the caller explicitly
  requests int8, whatever the features say. Flipping it is the only change needed to promote,
  flipping it back is the rollback.
- Host: `AIENOS_DOT=f32` forces f32 regardless of features and regardless of the constant;
  `AIENOS_DOT=int8` forces int8; unset means `auto` (the selector with detected features).
  Parsing lives in `DotSetting::parse` so it is testable without std.
- Operator rollback step (also in the PR body): set `AIENOS_DOT=f32` for a host run, or, for a kernel
  build, make sure `INT8_PROMOTION_DEFAULT` is `false` (it is) and that the kernel does not request
  int8, then rebuild. The kernel crate is untouched by this round and still runs f32.

Tests:

| Test | Before | After |
|---|---|---|
| `dotpath::tests::rollback_setting_f32_forces_f32_with_all_features` (setting f32, features present, promotion true gives F32) | absent | PASS |
| `dotpath::tests::default_constant_off_and_auto_is_f32_with_features` | absent | PASS |
| `dotpath::tests::setting_parse` (unset=auto, f32, int8, auto, garbage rejected) | absent | PASS |

## Condition 4: native regression tests (CI, no model)

Kept as they are: `quant::tests::q4k_int8_dot_matches_f32_dot_of_rounded_activations`,
`q6k_int8_dot_matches_f32_dot_of_rounded_activations`, `int8_row_dot_matches_block_sum_and_checks_lengths`,
`q8k_quantize_matches_q8k_round`.

New:

| Test | Checks | Before | After |
|---|---|---|---|
| the selector matrix and rollback tests above | selection rule | absent | PASS |
| `quant::tests::q8k_properties_bounds_and_error` | |q| <= 127; largest-magnitude value maps to -127; per-value error <= d/2 (+1 ulp slack); group sums equal sums of values; negation symmetry; scaling by a power of two scales d only and keeps q | absent | PASS |
| `quant::tests::golden_q4k_q8k_i32_accumulations` | fixed block, hardcoded (sumi, mins) | absent | PASS |
| `quant::tests::golden_q6k_q8k_i32_accumulations` | fixed block, hardcoded isum | absent | PASS |

Golden blocks (derived independently with a throwaway awk script from the ggml block layout,
not from the crate's code, so an inner-loop change is caught):

- Q4_K: d = 1.0, dmin = 0.5, scale bytes `41 82 C3 14 25 76 37 08 9A 5B DC 2D` (exercises the
  high-bit extension for sub-blocks 4 to 7), `qs[i] = (37 i + 11) mod 256`, `y[i] = ((29 i + 7) mod 255) - 127`,
  `yd = 0.25`. Expected `sumi = -284188`, `mins = -7913`, dot = `-70057.875`.
- Q6_K: `ql[i] = (53 i + 5) mod 256`, `qh[i] = (91 i + 17) mod 256`, scales `((23 i + 3) mod 61) - 30` as i8,
  d = 0.25, `y[i] = ((31 i + 5) mod 255) - 127`, `yd = 0.5`. Expected `isum = -275808`, dot = `-34476.0`.

To expose the accumulations without duplicating the loops, the golden tests call two small
`pub(crate)` helpers that the existing block dots are refactored to use (`q4k_q8k_accum`,
`q6k_q8k_isum`); the f32 results of the block dots must be bit-identical to before (the existing
tests plus the model-backed Q8_K comparison cover this).

Model-backed parity test `int8_parity_64_tokens_vs_f32` stays `#[ignore]` in CI and is run locally once;
its output is pasted into the PR body.

## What must not change

- Default path stays f32. No kernel source outside `crates/aienos-infer`. Nothing about the accelerator.
- The f32 dot code and results stay bit-identical. No new dependencies. No Python.
- The speed receipt `evidence/l6_host_3f5a22426976_l6b.json` is not rewritten.
