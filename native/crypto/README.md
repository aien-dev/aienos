# native/crypto: in-house AES-256, POLYVAL, AES-256-GCM-SIV in C

A C (gnu11) port of `crates/aienos-crypto`: AES-256 encryption (FIPS 197),
POLYVAL and AEAD_AES_256_GCM_SIV (RFC 8452), plus HMAC-SHA-256 with a 32-byte
key. SHA-256 is the existing in-house copy in `native/argus/sha256.c`; there
is no second SHA-256 here. No outside library. The library objects use no
heap, no clock and no I/O (checked by `make lib-checks` with `nm -u`).

API: one header, `aienos_crypto.h`. Library: `out/libaienos_crypto.a`
(includes the SHA-256 object).

## Test

    make -C native/crypto test        # lib-checks + known-answer + negative tests
    make -C native/crypto sanitize    # same tests under ASan + UBSan
    make -C native/crypto mutants     # optional: each GUARD rule removed must fail the tests
    make -C native/crypto clean

`OUT=<dir relative to native/crypto>` moves build output. The test's last line
is `AIENOS_CRYPTO_NATIVE: PASS` (exit 0) or `AIENOS_CRYPTO_NATIVE: FAIL` (exit 1).

Vectors are hard-coded in `tests/crypto_test.c`: all 24 RFC 8452 Appendix C.2
AES-256-GCM-SIV vectors and both C.3 counter-wrap vectors (each checked for
record keys, POLYVAL result, tag and sealed output, then opened, opened in
place, and tampered), RFC 8452 Section 7 and Appendix A POLYVAL examples,
the FIPS 197 AES-256 block and full S-box, FIPS 180-2 SHA-256 examples,
RFC 4231 HMAC cases 1 and 2, and every vector in the Rust crate's unit tests.

## Behaviour worth knowing

- **Open on failure.** RFC 8452 computes the tag over the plaintext, so open
  decrypts into the caller's buffer, recomputes the tag, compares it in
  constant time, and on a mismatch zeroes the whole output buffer (volatile
  writes) before returning `AIENOS_CRYPTO_ERR_AUTH`. Callers must not read
  the output unless the return is `AIENOS_CRYPTO_OK`. Tests check the buffer
  is all zero after each failed open (tag, ciphertext, AAD, nonce, key flips).
- **Lengths.** Plaintext and AAD above 2^36 bytes, ciphertext above
  2^36 + 16, input shorter than a tag, a size mismatch or a NULL buffer with
  a nonzero length return `AIENOS_CRYPTO_ERR_LENGTH` before any byte is read
  or written.
- **In place.** `out == pt` (seal) and `out == in` (open) are supported; any
  other overlap is undefined.
- **Wiping.** Derived keys, key schedules, keystream, padded tails and
  POLYVAL/HMAC state are wiped before return.

## Limitations

- Host-tested port only: run on the build machine, not in the AIENOS kernel,
  not under QEMU, not on bare metal.
- Constant-time by construction (computed S-box, no tables; masks instead of
  branches behind compiler barriers). Checked by reading the source and
  spot-checking AArch64 `-O2` disassembly. Not measured with timing tools and
  not independently reviewed for side channels. Another compiler or flag set
  could still introduce branches.
- Slow: no hardware AES (ARMv8 AESE/AESMC) or PMULL POLYVAL yet.
- AES decryption is not implemented (GCM-SIV does not need it).
- Mutants that remove a length limit are killed by a crash (the test then
  reads past a small buffer), not by a clean assertion.
