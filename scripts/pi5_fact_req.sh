#!/usr/bin/env bash
# pi5_fact_req.sh -- write a fact request file for the PI5-5 Cortex qualification image (make pi5-fact).
# QUALIFICATION ONLY. Layout: native/kernel/core/fact_req.h (512 bytes: magic AIENFCT1, version 1, flags 0,
# tag QUALIF-FACT-DATA, length 1..48, reserved 0, printable ASCII text, zero padding).
#
#   pi5_fact_req.sh <out file> "<fact text, 1..48 printable ASCII characters>"
#
# Refuses an existing output file. A fact is not a secret; do not put one in it anyway.
set -euo pipefail
out="${1:?output file}"
txt="${2:?fact text}"
[[ ! -e "${out}" ]] || { echo "refusing: ${out} exists" >&2; exit 1; }
n=${#txt}
(( n >= 1 && n <= 48 )) || { echo "fact must be 1..48 characters (got ${n})" >&2; exit 1; }
LC_ALL=C
[[ "${txt}" =~ ^[\ -~]+$ ]] || { echo "fact must be printable ASCII" >&2; exit 1; }
{
    printf 'AIENFCT1\x01\x00\x00\x00\x00\x00\x00\x00QUALIF-FACT-DATA'
    printf "\\x$(printf '%02x' "${n}")\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
    printf '%s' "${txt}"
    head -c $((48 - n)) /dev/zero
    head -c 424 /dev/zero
} > "${out}"
[[ "$(stat -c %s "${out}")" == 512 ]] || { rm -f "${out}"; echo "internal error: size" >&2; exit 1; }
echo "wrote ${out} (512 bytes, fact of ${n} characters)"
