# ADR 0015 canonical golden vectors

`0015-golden-vectors.json` contains the byte-exact inputs and outputs for
ObjectId, empty and one-entry catalogs, CommitRecord objects, Superblock A/B,
CRC32C, genesis, adjacent generations, and equivalent roots. Unit fixtures are
full 4096-byte hex strings; each includes a SHA-256 digest. CommitRecord
semantic bytes, ObjectIds, catalog semantic bytes, CRC fields, fixed resource
geometry, and expected root classifications are also recorded.

The fixtures use a deterministic UUID (`00 01 ... 0f`) so bytes are
reproducible. A real provisioner MUST still create a fresh random 128-bit Store
UUID.

Check the kernel against the vectors from the repository root:

```sh
cargo test -p aienos-kernel --test store_v1_golden_vectors
```

The test (`crates/aienos-kernel/tests/store_v1_golden_vectors.rs`) builds every
fixture with the kernel's own Store v1 encoders (`ObjectId`, `Catalog`,
`CatalogEntry`, `CommitRecord`, `Superblock`, `crc32c`) and requires each
hex field in the manifest to match byte for byte, including every padded
4096-byte unit, every `*_sha256` digest, and every CRC field. It also decodes
each encoding back to the value that produced it, rebuilds the ObjectId
preimages from the contract and ties them to the kernel ObjectIds, and checks
the genesis, adjacent-generation, and equivalent-root relations. Every field in
each manifest section must be asserted: a field added to the JSON without a
matching assertion fails the test. The exact fixtures are the
interoperability oracle; they are frozen and must not be regenerated to match a
changed encoder.
