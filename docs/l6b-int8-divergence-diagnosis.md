# L6-B int8 vs f32 divergence at token index 12: diagnosis (aienos#34, PR #300)

Diagnosis only (2026-10-11). Nothing here changes the parity rule in `docs/l6b-int8-qualification.md`, the
default path (f32), `INT8_PROMOTION_DEFAULT` (false) or the recorded FAIL. The int8 path stays unpromoted.

Evidence: `evidence/l6b_int8_divergence_3f5a22426976.json` (commit a362beb, Spark spark-b87b, core 19 =
Cortex-X925 0xd85, release build with `+dotprod,+i8mm`, `quietlock check` clear). Reproduce with
`scripts/l6b_divergence_receipt.sh`. Every number below is read from that file unless marked otherwise.

## Question

The recorded parity run (`evidence/l6_host_3f5a22426976_l6b_parity.json`) has f32 and int8 agree on token
indexes 0 to 11 and split at index 12 (f32 4897, int8 53692). Is that an int8 defect (accumulation order,
saturation, rounding, one badly quantized tensor), or activation-quantization noise meeting a close decision?

## Method

All runs replay the same history teacher-forced: the 17 prompt ids plus the 12 tokens both paths agree on.
The decision at index 12 is the argmax of the logits after the last of those. Paths compared:

- `f32`: the default path; run twice as a negative control (determinism).
- `int8`: the opt-in path (activations on ggml's Q8_K grid, i32 block dots).
- `emulate_q8k_f32_dots`: the existing `DecodeState::emulate_q8k`: the same Q8_K rounding of the same
  activations, but f32 dots, so it differs from int8 only in summation order.
- int8 restricted to one matvec class or one layer, and int8 everywhere except one class or one layer, through
  the new diagnostic selectors `DecodeState::q8_classes` / `q8_layers` (default: all; consulted only when
  `int8_dot` or `emulate_q8k` is on, so the f32 path is untouched). Layer masks keep the output head on f32.
- llama.cpp 4a89937 (`~/llama.cpp-build`, CPU, 1 thread) on the same history through the new C harness
  `crates/aienos-infer/tests/ref/llama_ref_hist.c` (prompt as one batch, later tokens one at a time, as
  `llama_ref.c` does). Its logits are committed as `tests/fixtures/ref_fr_idx12_logits.f32`; the receipt
  rebuilds the harness and checks the bytes match (`fixture_reproduced: true`; two runs bit-identical).

Tests: `int8_divergence_diagnosis_index_12` and `int8_vs_q8k_emulation_drift` (ignored, model-backed) and
`int8_matvec_equals_rounded_f32_on_real_activation` (model-backed, skips without the model).

## Findings

1. **Reproduced.** Teacher-forced, f32 picks 4897 (top1-top2 gap 0.349) and int8 picks 53692 (gap 0.393).
   The f32 repeat differs by exactly 0.
2. **Index 12 is the first close decision.** The f32 top1-top2 gap at indexes 0 to 11 is between 4.97 and
   14.40 logits; at index 12 it is 0.349. The int8-vs-f32 maximum logit difference is 0.43 to 1.29 at every
   index, so index 12 is the first place where the noise is larger than the margin. Index 12 is the first token
   of an unprompted second assistant turn (after end-of-turn, the assistant header and a blank line).
3. **llama.cpp makes the int8 choice.** On the same history llama.cpp picks 53692 with gap 0.091 (logit 4897:
   20.286, 53692: 20.377). llama.cpp also quantizes activations to Q8_K for these weight types. Max absolute
   logit difference at index 12: our f32 vs llama.cpp 1.059, our int8 vs llama.cpp 1.304.
4. **The int8 arithmetic is exact for what it computes.** On a real activation (layer 0 attention RMSNorm of
   BOS), the int8 matvec and the f32 matvec over the same Q8_K-rounded activation both equal an f64 reference
   to within 6.6e-7 absolute for wq, wk, wv, w_gate and w_up (largest reference value 5.37). The unit tests
   already pin the block dots and `q8k_properties_bounds_and_error` pins |q| <= 127 with the largest magnitude
   at -127, so there is no saturation by construction. The i32 accumulators cannot overflow: per Q4_K block
   |sumi| <= 8 x 32 x 15 x 128 x 63 < 2^28 (6-bit scales); per Q6_K block |isum| <= 16 x 16 x 32 x 128 x 128
   < 2^31 (arithmetic from the formats, not measured).
5. **No single layer or class carries the flip.** With int8 on only one class (5 runs) or only one layer (16
   runs) every run keeps the f32 choice 4897. With int8 everywhere except one class or layer, 19 of 21 runs keep
   the int8 choice 53692; only "except qkv" and "except layer 3" go back to 4897. The output head alone moves
   the logits by at most 0.077. The flip is the accumulated effect of activation rounding across most of the
   network, not one tensor.
6. **Two implementations of the same Q8_K arithmetic also disagree here.** `emulate_q8k_f32_dots` keeps 4897
   (gap 0.124) while int8 picks 53692; the two differ by up to 1.42 logits at index 12 although each matvec
   agrees to about 1e-6. The drift test shows how: after 1 prompt token int8 and emulation agree to within 6e-6
   for every class; from 2 to 3 tokens on, every class whose output is rounded again downstream drifts by 0.13 to
   0.67, while the output head (no rounding after it) stays within 4e-6 at every length.
   Mechanism, INFERRED (confidence about 85%, not instrumented per activation): Q8_K rounding is a step
   function, so a last-bit summation-order difference upstream can move a single activation to the neighbouring
   grid point (a jump of one quantization step, about amax/127), and those jumps compound through later layers
   and the cached keys and values.

## Conclusion

The index-12 divergence is activation-quantization noise (0.4 to 1.3 logits on this prompt) meeting a near-tie
(0.35 logits) in the f32 path. No defect was found in the int8 arithmetic: it computes exactly the Q8_K dot it
is defined to compute, llama.cpp makes the same choice at index 12, and our own f32-dot emulation of the same
rounding lands on the other side of the tie. Route (a) in the round-1 receipt ("an engineering cause found and
fixed in the int8 path") has no defect to fix on this evidence. Under the registered rule (64 identical token ids
against f32) any path that rounds activations to Q8_K, llama.cpp included, can fail wherever the f32 margin is
below that noise. Whether the rule should change is Drake's decision (route (b)); this document does not
propose or apply a new criterion.

## Limits

- One model, one prompt, one history, one machine. The llama.cpp comparison is the CPU backend at 4a89937, one
  thread; other backends or thread counts may sum in a different order.
- The flip mechanism in finding 6 is inferred from the drift pattern, not from counting grid moves.
- The selectors and tests are diagnostic; they do not change any shipped path. The kernel crate still runs f32.
