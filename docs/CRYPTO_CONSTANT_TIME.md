# Constant-time AES/POLYVAL and secret wiping

Scope: `crates/aienos-crypto` (AES-256, POLYVAL, AES-256-GCM-SIV) and the
kernel envelope decrypt scratchpad. All code is in-house; no outside crates.

## What changed

- **AES S-box is computed, not looked up.** Each byte is inverted in GF(2^8)
  as `x^254` (fixed chain of 11 multiplications) and passed through the
  FIPS 197 affine transform. Only shifts, masks and XORs; 16 bytes at a time
  packed in a `u128`. Used by both encryption (`SubBytes`) and key expansion
  (`SubWord`). `xtime` in MixColumns is branch-free.
- **POLYVAL multiply is branch-free.** The conditional add and the reduction
  step use all-ones/all-zeros masks instead of `if`.
- **Secrets are wiped on every path.** Derived GCM-SIV keys, the key-derivation
  scratch block, the CTR keystream and padded plaintext tails live in a
  self-wiping buffer (volatile writes on drop). AES round keys are built in
  place in the returned key object; encryption works in the caller's buffer
  with no extra state copy. The kernel envelope decrypt scratchpad is wiped
  after its plaintext is copied out.
- The public `derive_keys` returns self-wiping buffers with redacted debug
  output. Callers borrow the contained arrays; explicit copies remain the
  caller's responsibility.

## What is and is not claimed

- Constant-time by construction in the source, plus an AArch64 release
  disassembly spot-check of the S-box routine (no conditional branches, no
  data-indexed loads).
- **Not measured** on hardware. **No independent side-channel review.**
- Envelope storage is reserved once after the first chunk authenticates the
  complete bounded header. Later chunks cannot trigger growth that leaves
  plaintext in freed heap blocks. Allocation failures wipe the temporary chunk.
- Existing FIPS 197 and RFC 8452 known-answer vectors pass unchanged; a new
  test checks the computed S-box against the standard table for all 256 inputs.

## Future speedup (not implemented)

ARMv8 FEAT_AES instructions (`AESE`/`AESMC`) are constant-time in hardware and
much faster than this software S-box. They are a possible future speedup.
