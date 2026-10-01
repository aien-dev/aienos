#!/bin/sh
# receipt.sh: one content-addressed M6-A + M6-B host receipt for the current
# commit. Refuses a dirty tree. Runs make test + sanitize + mutants from clean, records the
# commit, toolchain, source hashes and verdict lines, and writes
# receipts/m6a_net_host_<sha256 of the receipt body>.txt. Never overwrites.
#
# Optional: RUSTDIFF=/path/to/driver runs an external driver built from the
# UNMODIFIED Rust reference (kept outside this repo: no Rust in AIENOS) on the
# same corpus and records a live comparison; otherwise that line is NOT_RUN and
# only the pinned digest is checked.
set -eu
cd "$(dirname "$0")"
top=$(git rev-parse --show-toplevel)
if [ -n "$(git -C "$top" status --porcelain --untracked-files=normal)" ]; then
    echo "receipt: refusing to run on a dirty tree:" >&2
    git -C "$top" status --short >&2
    exit 2
fi
commit=$(git rev-parse HEAD)
log=$(mktemp -d "${TMPDIR:-/tmp}/m6a-net-receipt.XXXXXX")
make clean >/dev/null
status=PASS
make test > "$log/test.txt" 2>&1 || status=FAIL
make sanitize > "$log/sanitize.txt" 2>&1 || status=FAIL
secure=PASS
make mutants > "$log/mutants.txt" 2>&1 || { status=FAIL; secure=FAIL; }
grep -q "^AIENOS_NET_SECURE_TESTS: PASS" "$log/test.txt" || secure=FAIL
grep -q "^AIENOS_NET_SECURE_TESTS: PASS" "$log/sanitize.txt" || secure=FAIL
grep -q "^X25519_RFC7748: PASS" "$log/test.txt" || secure=FAIL
live="NET_RUST_DIFFERENTIAL_LIVE: NOT_RUN (no RUSTDIFF driver given; pinned digest checked)"
if [ -n "${RUSTDIFF:-}" ]; then
    if "$RUSTDIFF" < out/diff_corpus.bin > "$log/rust.txt" && cmp -s "$log/rust.txt" out/diff_c.txt; then
        live="NET_RUST_DIFFERENTIAL_LIVE: PASS (driver sha256 $(sha256sum "$RUSTDIFF" | cut -d' ' -f1))"
    else
        live="NET_RUST_DIFFERENTIAL_LIVE: FAIL"; status=FAIL
    fi
fi
if [ -n "$(git -C "$top" status --porcelain --untracked-files=normal)" ]; then
    echo "receipt: the run changed tracked files" >&2; status=FAIL
fi
body="$log/body.txt"
{
    echo "AIENOS M6-A hosted C network stack + M6-B secure transport receipt"
    echo "commit: $commit"
    echo "host: $(uname -srm)"
    echo "cc: $(${CC:-cc} --version 2>/dev/null | head -1)"
    echo "scope: host tests only (no QEMU, no hardware, no native binding, TEST identity only)"
    echo "scope M6-B: hosted protocol code only; no real keys, no timing measurement, no formal protocol analysis"
    echo "sources:"
    for f in aienos_net.c aienos_net.h aienos_virtio_pci.c aienos_virtio_pci.h aienos_ctl.c aienos_ctl.h \
             x25519.c x25519.h aienos_sec.c aienos_sec.h ../argus/sha256.c \
             ../crypto/aes.c ../crypto/polyval.c ../crypto/gcm_siv.c ../crypto/hmac.c ../crypto/ct.c \
             ../sig/ed25519.c ../sig/sha512.c ../sig/ct.c \
             tests/net_test.c tests/ctl_test.c tests/net_diff.c tests/x25519_test.c tests/sec_test.c \
             Makefile receipt.sh; do
        echo "  $(sha256sum "$f" | cut -d' ' -f1)  native/net/$f"
    done
    echo "rust reference (spec, unmodified):"
    for f in "$top/crates/aienos-kernel/src/net.rs" "$top/crates/aienos-kernel/src/virtio_net.rs"; do
        echo "  $(sha256sum "$f" | cut -d' ' -f1)  ${f#$top/}"
    done
    echo "differential corpus: $(sha256sum out/diff_corpus.bin | cut -d' ' -f1)"
    echo "results:"
    grep -hE '^(net_test|ctl_test|lib-checks|NET_|CTL_|X25519_|AIENOS_NET_|  [a-z+0-9-]+ +(done|link_down))' "$log/test.txt" "$log/sanitize.txt" "$log/mutants.txt" | sed 's/^/  /'
    echo "  $live"
    echo "deferred (not claimed): native binding -> needs a C kernel (no-Rust rule; port order open);"
    echo "  production identity and keys -> needs M5 key hierarchy (TRUST-1); M6-B runs on TEST keys only;"
    echo "  physical NIC qualification -> needs Machine 1 wave after TRUST-1 Gate 7."
    echo "M6A_NET_HOST: $status"
    echo "AIENOS_NET_SECURE: $secure"
} > "$body"
digest=$(sha256sum "$body" | cut -d' ' -f1)
mkdir -p receipts
out="receipts/m6a_net_host_${digest}.txt"
[ -e "$out" ] || cp "$body" "$out"
cat "$out"
echo "receipt: native/net/$out (raw logs in $log)"
[ "$status" = PASS ]
