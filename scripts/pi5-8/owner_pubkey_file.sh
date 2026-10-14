#!/usr/bin/env bash
# owner_pubkey_file.sh -- PI5-8 Q2: turn an exported Ed25519 public key into the CK_OWNER_PUBKEYS file (PUBLIC material only).
#
#   scripts/pi5-8/owner_pubkey_file.sh PUBKEY.pem OUTFILE ["comment text"]
#
# PUBKEY.pem is what the YubiKey tool exports (`yubico-piv-tool -a read-public-key -s 9c`, or the output of `-a generate`):
# a PEM SubjectPublicKeyInfo, DER = 12 fixed bytes 30 2a 30 05 06 03 2b 65 70 03 21 00 followed by the 32 raw key bytes.
# The conversion takes the last 32 bytes after checking those 12 bytes exactly, and writes the file format that
# native/kernel/tools/ck_owner_gen.c reads (native/kernel/README.md "Owner provisioning"):
#     owner_root_ed25519 <64 lowercase hex>
# Prints the 64 hex digits on stdout and the sha256 of the file on stderr. Refuses anything that is not exactly an Ed25519
# public key and an all-equal-bytes key. Never reads or writes secret material. Real owner files are never committed.
set -euo pipefail
pem="${1:?usage: owner_pubkey_file.sh PUBKEY.pem OUTFILE [comment]}"; out="${2:?outfile}"; comment="${3:-}"
case "${comment}" in *$'\n'*|*$'\r'*) echo "REFUSED: comment must be one line" >&2; exit 2;; esac
der="$(openssl pkey -pubin -in "${pem}" -outform DER 2>/dev/null | od -An -v -tx1 | tr -d ' \n')" \
    || { echo "REFUSED: ${pem} is not a PEM public key" >&2; exit 1; }
prefix=302a300506032b6570032100
if [ "${#der}" != 88 ] || [ "${der:0:24}" != "${prefix}" ]; then
    echo "REFUSED: ${pem} is not exactly an Ed25519 public key (SPKI prefix/length mismatch)" >&2; exit 1
fi
hex="${der:24}"
if [ "$(fold -w2 <<<"${hex}" | sort -u | wc -l)" = 1 ]; then echo "REFUSED: all bytes equal (placeholder, not a key)" >&2; exit 1; fi
tmp="${out}.tmp.$$"
{
    echo "# AIENOS owner public key. PUBLIC material only (the private key never leaves the YubiKey)."
    [ -z "${comment}" ] || echo "# ${comment}"
    echo "owner_root_ed25519 ${hex}"
} > "${tmp}"
mv "${tmp}" "${out}"
echo "owner file sha256 $(sha256sum < "${out}" | cut -d' ' -f1)" >&2
echo "${hex}"
