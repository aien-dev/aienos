# INT8-ACTIVATION-QUAL-v1: prospective numerical qualification of the int8 activation path

Status: SPECIFICATION, written before any run (2026-10-11). Nothing in this document has been measured.
Owner issue: aien-dev/aienos#34 (L6-B). Draft implementation: PR #300 (branch `l6b-int8-dot`).
Authority: Drake's ruling of 2026-10-11 (aien-architecture#190, comment 6109731585; aienos#34, comment 6109732149).
Kernel default stays **f32** until a run of this specification records PASS and a separate, reviewed change flips it.

Every threshold below is marked PREREGISTERED: fixed here, before measuring, never edited after a run. Changing
one means writing `INT8-ACTIVATION-QUAL-v2` and applying it only to runs made after it is merged.

## 1. Purpose

Decide, with numbers fixed in advance, whether the int8 activation path (activations rounded to ggml's Q8_K grid,
integer block dots, `usdot` on cores that have it) is an acceptable replacement for f32 activations on the
supported GB10 hardware. The test must tell two things apart:

- **Expected quantization difference.** Rounding activations to 8 bits changes every logit a little. This is
  allowed, and it can flip a greedy choice only where the f32 model itself is almost undecided.
- **Implementation error.** A wrong scale, a wrong sub-block index, a missing term, an overflow, a wrong fallback.
  This is never allowed. Because the integer part of the int8 path is exact arithmetic, most implementation errors
  can be caught by exact comparison, not by a tolerance (section 5).

## 2. What the earlier FAIL established (aienos#300)

Sources: `docs/l6b-int8-qualification.md`, `docs/l6b-int8-divergence-diagnosis.md`,
`evidence/l6_host_3f5a22426976_l6b_parity.json`, `evidence/l6b_int8_divergence_3f5a22426976.json` (all on branch
`l6b-int8-dot` / PR #300, not on `main`).

- The registered rule was "identical 64 token ids". Observed: ids 0 to 11 identical, split at index 12 (f32 4897,
  int8 53692). That verdict is **FAIL and stays FAIL**. This specification does not change it retroactively.
- Index 12 is the first token of an unprompted second assistant turn. The golden reply ends at index 7 (end-of-turn,
  id 128009); the harness `l6_host` deliberately ignores end-of-turn for that run, and the kernel loop
  (`aienos-infer-kernel`, `EOT = 128009`) stops at it. So the split sits in a region the kernel never decodes
  (INFERRED from the sources, high confidence).
- At index 12 the f32 top1-top2 gap was 0.349 (4.97 to 14.40 at indexes 0 to 11), int8-vs-f32 logit noise was
  0.43 to 1.29 at every index, and llama.cpp 4a89937 on the same history picked the int8 token (gap 0.091).
  Diagnosis: Q8_K rounding noise against a near-tie, no int8 defect found (mechanism INFERRED, about 85 percent per
  the diagnosis). Limits: one model, one prompt, one history, one machine.
- Lesson built into this document: an "identical N tokens" rule conflates a near-tie with a defect. This
  specification keeps token agreement as a gate, but excuses a split only when the f32 margin proves it was a
  near-tie, and adds exact checks that cannot be excused.

## 3. Reference: how the independent quantized reference is produced

The int8 path under test is the crate's own code (`quantize_q8k`, `Q4_K`/`Q6_K` block dots shaped for `usdot`).
A check that reuses that code proves nothing, so three references are used and none shares source with it.

**R-A, scalar integer reference (exact tier).** A new stand-alone C program, `crates/aienos-infer/tests/ref/q8ref.c`
(to be written by the implementation round; it does not exist yet), built with plain `cc -O0` and no vector flags.
It is written from the published ggml block layouts (`block_q4_K` 144 bytes, `block_q6_K` 210 bytes, `block_q8_K`)
and the Q8_K rule, not from the crate: scale `iscale = -127 / max` where `max` is the signed value of largest
magnitude in the 256-value block, `q = min(127, nearest_int(iscale * x))` with ties-to-even, `d = 1 / iscale`,
plus the 16 group sums. The implementer must quote the governing lines of `ggml-quants.c` at commit 4a89937 in the
`docs-read` record before writing it (UNVERIFIED here: the rule above is from memory of ggml and from the crate's
own tests, not re-read for this document). It unpacks the 4-bit and 6-bit weights with its own shifts and masks and
accumulates every product in `int64_t`.
Why it is independent: different language and compiler path, no shared code, no lane structure and no dot-product
instruction, wider accumulators. It shares only the published format. Where it and the crate agree bit for bit on
integers, a shared mistake would have to be a mistake in the format itself, which R-B below also tests.

**R-B, llama.cpp 4a89937, CPU, 1 thread (cross-implementation tier).** Already used by #300 (`llama_ref.c`,
`llama_ref_hist.c`, fixtures `tests/fixtures/ref_*.txt`). It quantizes activations to Q8_K for these weight types too,
but with its own float order, so it is compared with tolerances, never bitwise. It is the tiebreaker for near-ties.

**R-C, the crate's own f32 path at the base commit (baseline tier).** Defines the f32 logits, the f32 margins and
the rollback target. Its logits are recorded (SHA-256 of the little-endian f32 bytes per step) before any int8 change
lands, in the same evidence file.

## 4. Prompts

All prompts use the chat template of the frozen model (Llama-3.2-1B-Instruct-Q4_K_M, sha256
`3f5a22426976ab26cfe84dba63c1d08391717abb1af893e10f1b2968d862dcc1`), greedy decoding, no system prompt beyond the
template's default. Host budget: at most 64 new tokens. Every run must end at id 128009 inside the budget (section 5,
T1). Texts are verbatim; `\n` is a newline.

| id | text | source |
|---|---|---|
| P1 | `What is the capital of France?` | existing (`fr`; golden reply ids 791 6864 315 9822 374 12366 13 128009) |
| P2 | `Explain copy-on-write in one sentence.` | existing (`cow`) |
| P3 | `Say hi in 3 languages: café, 日本語, 😀 (it's 100% fine).\n\n  Thanks!` | existing (`uni`) |
| P4 | `List the three primary colors, separated by commas.` | new |
| P5 | `What is 17 plus 25? Answer with just the number.` | new |
| P6 | `Write one short sentence about the ocean.` | new |

Reserves, used in this order only if an earlier prompt fails the admission rule: R1 `Name one planet in the solar system.`
then R2 `Spell the word "cat" backwards.`

Admission rule (PREREGISTERED): a prompt is admitted only if the **f32** path itself ends at 128009 within 64 new
tokens. Whether P4 to P6 satisfy it is UNVERIFIED (not run). A rejected prompt is replaced by the next reserve and
the swap is recorded; the f32 outcome is the only thing consulted, never the int8 outcome. Minimum for a valid run:
6 admitted prompts.

Native leg: the kernel image today carries one fixed prompt (P1, `MAX_NEW = 16`, `KV_CAPACITY = 64`). The native
leg therefore checks P1 only, until the kernel takes other prompts; that limit is stated in the verdict.

## 5. Metrics, bounds and failure signals

Two groups. Group X is exact: any miss is an implementation error. Group N is numerical: bounds on expected noise.

### Group X, exact (no tolerance)

| id | check | bound | why |
|---|---|---|---|
| X1 | Quantizer: for every activation vector fed to a matvec during the teacher-forced runs, the crate's Q8_K output (`qs`, `d`, group sums) equals R-A's | 0 differing values; `d` bit-identical | Rounding is deterministic IEEE arithmetic with ties-to-even; there is no legitimate difference. PREREGISTERED |
| X2 | Integer block dots: for every block of every matvec (every layer and class, every prompt, every step), the crate's i32 accumulators (`sumi`, `mins` for Q4_K; `isum` for Q6_K) equal R-A's int64 results | 0 mismatches | Both are integer sums over identical inputs; order cannot matter. This includes the `usdot` build and the portable build. PREREGISTERED |
| X3 | Scaled row result: crate's f32 row output vs R-A's f64 recomputation from the same integers | abs diff <= 1e-6 x max abs of that row's reference | #300 measured 6.6e-7 absolute on rows of size about 5.4 (about 1.2e-7 relative); 1e-6 relative leaves roughly 8x headroom and still catches a wrong scale. PREREGISTERED |
| X4 | Overflow guard: every i32 accumulator stays below 2^31 and no Q8_K value leaves [-127, 127] | 0 violations | The diagnosis derived the bounds on paper; the run asserts them. PREREGISTERED |
| X5 | Determinism: each path run twice gives bit-identical logits for every step | 0 differing bits | Negative control for the harness; also separates noise from nondeterminism. PREREGISTERED |
| X6 | No non-finite value (NaN or inf) in any hidden state or logit vector, any path | 0 | A non-finite value is never quantization noise. PREREGISTERED |

### Group N, numerical (teacher-forced along the f32 token history unless stated)

Teacher forcing: both paths are fed the same f32 history, so one flipped choice cannot contaminate later steps.

| id | metric | bound | why |
|---|---|---|---|
| N1 | Per-layer: for every layer and step, `max abs(h_int8 - h_f32) / max abs(h_f32)` of that layer's output hidden state | <= 0.05 | A priori only: Q8_K rounds each value by at most half a step, about 0.4 percent of the block maximum, and 16 layers compound it; 5 percent is a loose ceiling meant to catch gross errors, not to bound noise tightly. No measurement was used. PREREGISTERED (basis weak, confidence low; X1/X2 carry the weight) |
| N2 | Per-step max abs logit difference, int8 vs f32, over the whole vocabulary, every step of every prompt | <= 2.0 | #300 measured 0.43 to 1.29 over 13 steps (largest 1.288); 2.0 leaves about 55 percent headroom over the largest value seen. PREREGISTERED |
| N3 | Per-step max abs logit difference, int8 vs llama.cpp (R-B), same history | <= 2.0 | #300 measured 1.304 at index 12 and 0.567 at the first position; same reasoning as N2. PREREGISTERED |
| N4 | First decode position of P1, int8 vs llama.cpp max abs logit difference | <= 1.0 | The bound #300 already used (observed 0.567). PREREGISTERED |
| N5 | Logit margin: record f32 top1-top2 margin at every step (reported always, used by N6 and N7) | reported | The margin is what makes a flip excusable or not. |
| N6 | Divergence rule: a step where int8 top-1 differs from f32 top-1 is excused only if the f32 margin at that step is < T = **1.5** | T = 1.5 logits | T is above the largest single-logit error seen (1.288) and far above the one observed flip (margin 0.349). It is deliberately stricter than the theoretical maximum (two opposite errors could flip a margin up to 2 x N2); a false FAIL costs a re-specification, a false PASS ships a defect. PREREGISTERED |
| N7 | Top-1 agreement rate over all teacher-forced steps of all admitted prompts | >= 0.98, and 1.00 over steps whose f32 margin >= T | With about 100 or more steps, 2 percent allows a couple of true near-ties; the per-step rule N6 is the real gate, this is a floor against many small flips. PREREGISTERED |
| N8 | Free run (each path decoding its own tokens): token sequences of int8 and f32 are identical, or the first split is at a step excused by N6 | identical or excused | Free run shows what a user sees. After an excused split the runs may differ; they must still terminate (T1). PREREGISTERED |

### Termination, required

| id | check | bound |
|---|---|---|
| T1 | f32, int8 and llama.cpp free runs each emit 128009 (`<|eot_id|>`) within the budget, and decoding stops there | all admitted prompts; no token is decoded after 128009. PREREGISTERED |
| T2 | Comparisons stop at the first 128009. Positions after it (the unprompted second turn that #300 index 12 sat in) are excluded from every bound and rate | by construction |

### Failure signals (any one means the whole run is FAIL)

1. Any X1 to X6 miss.
2. Any step where int8 top-1 differs from f32 top-1 and the f32 margin is >= 1.5 (N6).
3. Any NaN or inf (X6).
4. Any run that does not reach 128009 inside the budget (T1), including an int8 run that loops or never stops.
5. Any N bound exceeded, or N7 below 0.98.
6. The usdot path and the portable integer path disagree with R-A at all (X2), since both are integer math.
7. A mutant that is not caught (section 8, negative controls).

A run with any leg skipped is **NOT_RUN**, never PASS.

## 6. CPU-feature checks and the fallback

What is needed: `usdot` is Armv8.6 FEAT_I8MM; the signed `sdot` form needs FEAT_DotProd. The #300 design selects int8
automatically only when both are present (`Features { dotprod, i8mm }`, `DotPath::select`).

- **Detection, host.** Read `AT_HWCAP` bit 20 (`HWCAP_ASIMDDP`) and `AT_HWCAP2` bit 13 (`HWCAP2_I8MM`) from
  `/proc/self/auxv`, as #300 does. Record the result and the CPU part number (`0xd85` X925, `0xd87` A725) in the
  evidence file.
- **Detection, kernel.** Read `ID_AA64ISAR0_EL1.DP` and `ID_AA64ISAR1_EL1.I8MM` at boot, once per core, and print
  one line with the result (`dotprod=.. i8mm=..`). The exact bit positions must be quoted from the Arm Architecture
  Reference Manual in the implementer's `docs-read` record; they are not restated here (UNVERIFIED by this document).
  The path is chosen from the weakest core, because inference may run on the A725 cores as well as the X925 cores.
- **Fallback.** No features: f32 path. Features present but int8 not requested or promotion off: f32 path. The
  selector matrix (all 4 feature sets x requested x promotion, 16 rows, #300 `select_matrix_all_combinations`) is
  re-run and must reproduce the same table.
- **No stray instructions.** Building the crate with `+dotprod,+i8mm` lets the compiler use those instructions
  anywhere, not just in the int8 functions. On a core lacking them that is an illegal-instruction fault, not a
  fallback. Requirement (PREREGISTERED): either the f32 image is a separate build without those features, or the
  int8 code sits behind runtime dispatch; and `objdump -d` of the f32 image shows **zero** `sdot`, `udot`, `usdot`,
  `smmla`, `ummla`, `usmmla` instructions, while the int8 image shows them only inside the designated int8 functions.
- **Both paths tested.** Legs: (L1) host X925, features present, int8 with `usdot`; (L2) host A725 core, same build;
  (L3) portable integer build with no dot features (`cargo` without `-C target-feature`) run on the same host, forced
  int8; (L4) QEMU `-cpu max` kernel image with features (the leg records the feature line it actually saw);
  (L5) QEMU with a CPU model that lacks the features (candidate `cortex-a72`, to be confirmed by the recorded feature
  line), which must select f32 and print the feature line showing why. L1 to L3 must satisfy every X and N check.
  L3 supports qualifying the portable path, but production auto-selection still requires both features.

## 7. Rollback

- **Default.** `INT8_PROMOTION_DEFAULT = false` (`dotpath.rs`). Until this specification records PASS and a separate
  reviewed change flips it, the shipped default is f32.
- **Switch.** Host: `AIENOS_DOT=f32` forces f32 regardless of features and constant; `AIENOS_DOT=int8` forces int8;
  unset is `auto`. Kernel: the build constant, plus a boot-time forcing flag that must exist before promotion
  (to be added by the implementing change; not designed here).
- **Proof, required (R1 to R3, all PREREGISTERED):**
  - R1: with all features present and promotion forced true, setting `f32` yields logits whose per-step SHA-256 equals
    the base-commit f32 record (section 3, R-C) for every admitted prompt. Bit-identical, not tolerance.
  - R2: flipping the constant back to `false` and rebuilding yields the same hashes (the rollback is a one-line change).
  - R3: native: the QEMU kernel image with f32 forced (feature-rich CPU model) prints the golden P1 ids
    `791 6864 315 9822 374 12366 13 128009` and the boot is otherwise unchanged.
- "Reliable" means R1 to R3 pass on every release candidate, not only once.

## 8. Procedure

Order matters: the harness goes red before it goes green.

1. Freeze: commit this document. The harness reads the bounds from the table below and refuses to run if a constant
   in code differs; the evidence file stores this document's SHA-256.
2. Base record: run the f32 path at the base commit; store per-step logit hashes, margins, token ids (R-C).
3. Negative controls (must FAIL, each one recorded): (a) truncate instead of round in the Q8_K quantizer;
   (b) off-by-one in a sub-block scale index; (c) drop the Q4_K mins term; (d) swap a Q6_K scale sign. If a mutant
   passes, the harness is blind and the run is invalid. Also run f32 twice (X5) and f32-vs-f32 through the N rules
   (must give zero difference).
4. Host legs L1 to L3 for all admitted prompts: teacher-forced pass (X, N1 to N7), free-run pass (N8, T1), llama.cpp
   comparison (N3, N4). Release build, pinned to one core, `quietlock check` clear first, one thread.
5. Native legs L4, L5, R3 on QEMU (no hardware). A physical-Spark native leg is a separate decision and needs its own
   attended window; it is not part of v1.
6. Write `evidence/int8_qual_v1_<sha12>.json`: commit, doc hash, model hash, feature lines, per-prompt tables, every
   metric against its bound, every mutant result, verdict. Verdict is PASS only if every row passes and no leg was
   skipped; FAIL on any failure signal; NOT_RUN otherwise. Nothing is re-tuned after a FAIL; the FAIL is recorded.
7. After PASS: a separate PR proposes flipping the default, cites the evidence, and waits for Drake's decision.

### BOUNDS-v1 (machine-readable, PREREGISTERED)

```text
X3_REL=1e-6 N1_REL=0.05 N2_ABS=2.0 N3_ABS=2.0 N4_ABS=1.0 TIE_T=1.5 N7_AGREE=0.98
MAX_NEW_HOST=64 MIN_PROMPTS=6 EOT=128009 ZERO_EXACT=X1,X2,X4,X5,X6
```

## 9. Non-goals

- No change to the #300 FAIL, to its rule, or to any recorded evidence.
- No kernel, Rust or Mojo change in this round; no default change; no new model.
- No performance claim (speed receipts are separate) and no claim about other models or other quantization types.
- No physical-hardware run, no GPU path, no multi-thread numerics.
- Does not decide whether int8 should ship; it defines what evidence would justify asking.

## 10. Limits and UNVERIFIED items

- All bounds are PREREGISTERED judgments anchored to one prior run (13 steps, one prompt); N1 has no data behind it.
- R-A does not exist yet; the Q8_K rule text is from memory of ggml and must be quoted from source at implementation.
- Whether P4 to P6 end at 128009 under f32 inside 64 tokens is untested.
- QEMU `-cpu max` exposing both features and `cortex-a72` lacking them are expectations, confirmed only by the
  feature line a leg prints.
- The #300 sources cited here live on a draft branch, not on `main`.
