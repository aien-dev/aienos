#!/usr/bin/env bash
# pi5_unlock_req.sh -- write a THROWAWAY unlock request file for the PI5-4 qualification image
# (make pi5-unlock-card). QUALIFICATION ONLY. Layout: native/kernel/core/unlock_req.h
# (512 bytes: magic AIENUNQ1, version 1, flags 0, tag QUALIF-THROWAWAY, 32-byte secret, zero padding).
#
#   pi5_unlock_req.sh <out file> [<secret file, exactly 32 bytes>]
#
# With no secret file, 32 random bytes come from /dev/urandom. Refuses an output path inside a git
# checkout (a secret must never be committed) and an existing output file. The secret is never printed.
# Use a different secret file to make a "wrong secret" request, or the same one to reopen.
set -euo pipefail
out="${1:?output file}"
sec="${2:-}"
[[ ! -e "${out}" ]] || { echo "refusing: ${out} exists" >&2; exit 1; }
dir="$(cd "$(dirname "${out}")" && pwd)"
if git -C "${dir}" rev-parse --git-dir >/dev/null 2>&1; then echo "refusing: ${dir} is inside a git checkout" >&2; exit 1; fi
tmp="$(mktemp)"; trap 'rm -f "${tmp}"' EXIT
if [[ -n "${sec}" ]]; then
    [[ "$(stat -c %s "${sec}")" == 32 ]] || { echo "secret file must be exactly 32 bytes" >&2; exit 1; }
    cp "${sec}" "${tmp}"
else
    head -c 32 /dev/urandom > "${tmp}"
fi
# not all zero, not one repeated byte (the kernel refuses those too)
[[ "$(od -An -v -tx1 "${tmp}" | tr -s ' \n' '\n\n' | sort -u | grep -c .)" -gt 1 ]] || { echo "weak secret refused" >&2; exit 1; }
umask 077
{
    printf 'AIENUNQ1\x01\x00\x00\x00\x00\x00\x00\x00QUALIF-THROWAWAY'
    cat "${tmp}"
    head -c 448 /dev/zero
} > "${out}"
[[ "$(stat -c %s "${out}")" == 512 ]] || { rm -f "${out}"; echo "internal error: size" >&2; exit 1; }
echo "wrote ${out} (512 bytes, throwaway secret not shown)"
