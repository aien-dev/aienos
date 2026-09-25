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

Run the standard-library-only independent encoder/verifier from the repository
root:

```sh
python3 scripts/check_store_v1_vectors.py
```

The verifier rebuilds each encoding, checks all padded unit bytes and
SHA-256/CRC32C values against the checked-in manifest, and checks the genesis,
adjacent-generation, and equivalent-root relations. The exact fixtures are the
interoperability oracle; the Python code is a second implementation of the
format and is not production Store code.
