# native/sig: in-house Ed25519 and SHA-512 in C

Scope: pure Ed25519 from RFC 8032 Section 5.1 (key derivation, sign, verify) and SHA-512 (FIPS 180-4). No Ed25519ph, no Ed25519ctx, no batch verification, no outside library. Library objects use no heap, clock or I/O (`make lib-checks`). API: `aienos_sig.h`; library: `out/libaienos_sig.a`. Built for the owner-key signed migration (M5) and signed commitment records (M23 G3); not yet wired into either.

    make -C native/sig test       # lib-checks + RFC 8032 7.1 vectors + negatives + 1000 round trips
    make -C native/sig sanitize   # same tests under ASan + UBSan
    make -C native/sig mutants    # 14 GUARD rules removed one at a time; each must fail the tests

The test's last line is `AIENOS_SIG_NATIVE: PASS` (exit 0) or `AIENOS_SIG_NATIVE: FAIL` (exit 1).

Verification policy (stricter than the RFC minimum): refuses S >= L, non-canonical y (y >= p) in A or R, off-curve points, x = 0 with the sign bit set, and A or R of small order (order dividing 8). It checks encode([S]B - [k]A) == R bytes (cofactorless). A public key with a small-order component mixed into a large-order point is accepted.

Constant-time claims: key derivation and signing have no branch and no memory index that depends on the secret key or nonce. The scalar ladder always doubles and adds and keeps the sum with a masked select; scalar reduction mod L is bit-serial with a masked subtract; inversion and square-root exponents are public constants. Checked by reading the source and spot-checking AArch64 `-O2` disassembly (only loop-counter and stack-guard branches in those paths). Verification and point decoding take only public input and are NOT constant time.

Not covered: no timing measurement on real hardware, no fault-injection or glitch resistance (no sign-then-verify countermeasure), no power or EM side-channel analysis, no independent cryptographic audit. Another compiler or flag set could reintroduce branches. Stack temporaries inside field operations are not wiped; the key hash, nonce and secret scalar buffers are. Host-tested only: not run in the AIENOS kernel, under QEMU, or on bare metal. Slow by design (generic ladder, no precomputed tables): about 1 ms per sign plus verify on the Spark.
