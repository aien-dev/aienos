# Constant-time cipher and secret lifetime repair

AES-256 uses RustCrypto aes 0.8.4 with its zeroize feature and default features disabled. Its AArch64 default is the portable fixsliced software implementation; no OS runtime or allocator is required. Expanded round keys zeroize on drop. The existing FIPS AES and RFC 8452 vectors remain the compatibility oracle. aes, cipher and inout are vendored from their published crates with package checksums verified against the registry. Upstream MIT/Apache license files are retained.

Derived authentication/encryption keys and intermediate derivation blocks use Zeroizing guards. The kernel's authenticated chunk scratchpad uses a Zeroizing guard on success and error. POLYVAL arithmetic uses masks instead of secret-dependent branches. Store formats, tags and known-answer ciphertexts remain unchanged.

Targeted tests and bare-metal compilation verify compatibility. This change is not a claim of an independent audit of the complete encryption protocol, physical trust chain, or hardware side-channel qualification. Those qualification boundaries remain separate.

Upstream implementation: https://github.com/RustCrypto/block-ciphers/tree/aes-v0.8.4/aes
