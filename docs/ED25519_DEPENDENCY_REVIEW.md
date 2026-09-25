# Binary Artifact Ed25519 dependency review

Binary Artifact v0 uses the RustCrypto `ed25519-dalek` implementation pinned
to **2.2.0**. The kernel-facing dependency disables default features and
enables only `fast`; this keeps the verifier `no_std` and excludes signing
helpers, serialization, and OS integration from the kernel build. Verification
uses `VerifyingKey::verify_strict` over the exact 29-byte signature domain
followed by the 32-byte ArtifactId. The format does not accept Ed25519ph or
Ed25519ctx.

The exact dependency graph is locked in `Cargo.lock` and all workspace registry
dependencies are checked into `vendor/`. `.cargo/config.toml` redirects
crates.io to this snapshot so builds do not need registry access. The vendored
manifest versions, upstream license declarations, and Cargo checksum metadata
are retained. The primary packages in the signature implementation are:

| Package | Locked version | Declared license |
|---|---:|---|
| `ed25519-dalek` | 2.2.0 | BSD-3-Clause |
| `curve25519-dalek` | 4.1.3 | BSD-3-Clause |
| `ed25519` | 2.2.3 | Apache-2.0 OR MIT |
| `sha2` | 0.10.9 | MIT OR Apache-2.0 |
| `subtle` | 2.6.1 | BSD-3-Clause |

The application-side checks are deliberately narrow: the public-key
fingerprint must match the selected local trust anchor; `verify_strict` must
accept the canonical domain-plus-ArtifactId message; empty production anchors
reject every signer; and qualification-only tests reject changed payloads,
signature bytes, and signer fingerprints. The deterministic private test seed
exists only in test/host qualification code and is never linked into the
kernel. The qualification public key is behind the explicit
`seed0b-test-anchor` feature, and the boot report labels that image as a test
qualification build.

This is a dependency selection and integration review, not a claim that this
repository performed an independent cryptographic implementation audit. Any
dependency update requires re-vendoring, lockfile review, the signature test
vectors, and offline `aarch64-unknown-none` verification before merge.

Upstream implementation and feature metadata:

- <https://github.com/dalek-cryptography/curve25519-dalek/tree/main/ed25519-dalek>
- <https://docs.rs/ed25519-dalek/2.2.0/ed25519_dalek/struct.VerifyingKey.html#method.verify_strict>
