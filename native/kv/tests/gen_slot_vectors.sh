#!/usr/bin/env bash
# Generate tests/golden/kv_slot_v1.json: the native slot header unit and the
# envelope id / nonce prefix vectors of ADR 0003 section 2.5 (aienos#367, N1).
#
# This is the INDEPENDENT side of the slot vectors: it never calls the C
# codec. Everything is rebuilt byte by byte with printf, xxd, sha256sum and
# openssl (HMAC-SHA-256; HKDF-Expand for one 32-byte block is
# HMAC(prk, info || 0x01)). The C test then checks kv_record.c against the
# file. No Python.
#
# The record header inside each slot is taken from the sc golden file
# (kv_record_v1.json, vector native-f32-partial-tail), so the two files are
# tied together: a different sc vector set changes this output.
#
# Usage: gen_slot_vectors.sh tests/golden/kv_record_v1.json > tests/golden/kv_slot_v1.json
set -euo pipefail
sc_json=$1

hexs() { xxd -p | tr -d '\n'; }                       # stdin bytes -> hex
unhex() { xxd -r -p; }                                  # stdin hex -> bytes
le() { # le VALUE NBYTES -> little-endian hex
  local v=$1 n=$2 h out="" i
  h=$(printf '%0*x' $((n * 2)) "$v")
  for ((i = n - 1; i >= 0; i--)); do out+=${h:$((i * 2)):2}; done
  printf '%s' "$out"
}
ascii() { printf '%s' "$1" | hexs; }
sha() { printf '%s' "$1" | unhex | sha256sum | cut -d' ' -f1; }
hmac() { # hmac KEYHEX MSGHEX -> hex
  printf '%s' "$2" | unhex | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$1" -binary | hexs
}
hkdf1() { hmac "$1" "$(ascii "$2")00$(le 1 1)"; }      # info = label + one NUL; block counter 1
patt() { # patt START -> 32 bytes START, START+1, ... as hex
  local s=$1 i out=""
  for ((i = 0; i < 32; i++)); do out+=$(printf '%02x' $(((s + i) & 255))); done
  printf '%s' "$out"
}
zeros_hex() { head -c "$1" /dev/zero | hexs; }

# ---- pull the two native chunk records out of the sc file -----------------
# Keys are sorted in the file: chunk objects precede the vector "name" line.
native=$(awk '
  /"chunk_key":/    { gsub(/[",]/, ""); ck = $2 }
  /"header_hex":/   { gsub(/[",]/, ""); hh = $2 }
  /"payload_len":/  { gsub(/[",]/, ""); pl = $2 }
  /"payload_sha256":/ { gsub(/[",]/, ""); ps = $2; n++; row[n] = ck " " hh " " pl " " ps }
  /"namespace_id":/ { gsub(/[",]/, ""); ns = $2 }
  /^      "name":/   { gsub(/[",]/, ""); if ($2 == "native-f32-partial-tail") {
                         for (i = 1; i <= n; i++) print ns " " row[i]; found = 1 }
                       n = 0 }
  END { if (!found) exit 1 }
' "$sc_json")
chunk0=$(printf '%s\n' "$native" | sed -n 1p)
chunk1=$(printf '%s\n' "$native" | sed -n 2p)

slot_vector() { # slot_vector NAME "<ns ck hh pl ps>" SLOT_INDEX INCARNATION KEYGEN CLASS UUIDSTART DOMAINSTART
  local name=$1; read -r ns ck hh pl ps <<<"$2"
  local si=$3 inc=$4 kg=$5 cls=$6 uuid k_dom
  uuid=$(patt "$7" | cut -c1-32)
  k_dom=$(patt "$8")
  local k_kv k_envid msg full env_id nonce
  k_kv=$(hkdf1 "$k_dom" "AIENOS-PKV-SLOT-KEY-V1")
  k_envid=$(hkdf1 "$k_dom" "AIENOS-PKV-ENVID-KEY-V1")
  msg="$(ascii "AIENOS-PKV-ENVID-V1")00${uuid}${ns}${ck}$(le "$si" 4)$(le "$inc" 8)$(le "$kg" 8)$(le "$cls" 1)$(le "$pl" 8)${ps}"
  full=$(hmac "$k_envid" "$msg")
  env_id=${full:0:32}
  nonce=${full:32:16}
  local chunks=$(((pl + 4079) / 4080))
  local sealed_len=$((pl + 16 * chunks))
  local sealed_units=$(((sealed_len + 4095) / 4096))
  local env_len=$((64 + sealed_len))
  local prefix="${hh}$(ascii AIENENV1)$(le 1 2)$(le 1 2)$(le 0 4)$(le 4080 4)$(le "$pl" 8)${env_id}${nonce}$(le "$kg" 8)$(le 0 4)"
  prefix+="$(le "$inc" 8)$(le "$sealed_units" 4)$(le "$env_len" 4)$(le "$si" 4)"
  [ $((${#prefix} / 2)) -eq 340 ] || { echo "prefix length ${#prefix}" >&2; exit 1; }
  local body="${prefix}$(zeros_hex 3724)"
  local unit_sha
  unit_sha=$(printf '%s' "$body" | unhex | sha256sum | cut -d' ' -f1)
  local full_sha
  full_sha=$(printf '%s' "${body}${unit_sha}" | unhex | sha256sum | cut -d' ' -f1)
  cat <<EOF
    {
      "name": "$name",
      "input": {
        "namespace_id": "$ns",
        "chunk_key": "$ck",
        "record_header_hex": "$hh",
        "payload_len": $pl,
        "payload_sha256": "$ps",
        "slot_index": $si,
        "slot_incarnation": $inc,
        "key_generation": $kg,
        "identity_class": $cls,
        "store_uuid": "$uuid",
        "k_domain": "$k_dom"
      },
      "expected": {
        "k_kv": "$k_kv",
        "k_envid_kv": "$k_envid",
        "envelope_id": "$env_id",
        "nonce_prefix": "$nonce",
        "sealed_len": $sealed_len,
        "sealed_units": $sealed_units,
        "envelope_len": $env_len,
        "slot_units": $((1 + sealed_units)),
        "unit_prefix_hex": "$prefix",
        "unit_sha256_field": "$unit_sha",
        "unit_full_sha256": "$full_sha"
      }
    }
EOF
}

bound_row() { # bound_row PAYLOAD_LEN
  local pl=$1 chunks sealed_len sealed_units
  chunks=$(((pl + 4079) / 4080))
  sealed_len=$((pl + 16 * chunks))
  sealed_units=$(((sealed_len + 4095) / 4096))
  printf '    {"payload_len": %s, "sealed_len": %s, "sealed_units": %s, "envelope_len": %s, "slot_units": %s}' \
    "$pl" "$sealed_len" "$sealed_units" "$((64 + sealed_len))" "$((1 + sealed_units))"
}

cat <<EOF
{
  "about": "ADR 0003 section 2.5 (native slot header unit, 4096 bytes) and the authenticated mapping from the KV identity into M5 inputs. Produced by native/kv/tests/gen_slot_vectors.sh with printf, xxd, sha256sum and openssl only (independent of the C codec). unit bytes: 0..256 record header (record_header_hex), 256..320 M5 envelope header (AIENENV1, version 1, suite 1, flags 0, chunk_size 4080, total_plaintext_len = payload_len, envelope_id, nonce_prefix, key_epoch = key_generation, reserved 0), 320 slot_incarnation u64, 328 sealed_units u32, 332 envelope_len u32, 336 slot_index u32, 340..4064 zero, 4064..4096 unit_sha256 = SHA-256(bytes 0..4064). unit_prefix_hex is bytes 0..340. unit_full_sha256 is SHA-256 of the whole 4096-byte unit. k_kv = HKDF-Expand(k_domain, 'AIENOS-PKV-SLOT-KEY-V1' || 0x00, 32); k_envid_kv = HKDF-Expand(k_domain, 'AIENOS-PKV-ENVID-KEY-V1' || 0x00, 32); envelope_id || nonce_prefix = first 24 bytes of HMAC-SHA256(k_envid_kv, 'AIENOS-PKV-ENVID-V1' || 0x00 || store_uuid || namespace_id || chunk_key || slot_index u32le || slot_incarnation u64le || key_generation u64le || identity_class u8 || payload_len u64le || payload_sha256). The label NUL is one byte, as in the sc domain strings and the Store's sizeof(literal) convention. sealed_len = payload_len + 16 * ceil(payload_len / 4080); sealed_units = ceil(sealed_len / 4096); envelope_len = 64 + sealed_len; slot_units = 1 + sealed_units. Bounds: payload_len in 1 to 16711680 (4096 chunks of 4080).",
  "format_version": 1,
  "object_kind": 1312,
  "object_version": 1,
  "chunk_size": 4080,
  "max_payload_len": 16711680,
  "vectors": [
EOF
slot_vector "native-chunk0-slot3-test-class" "$chunk0" 3 7 2 2 0 160
echo "    ,"
slot_vector "native-chunk1-partial-slot0-production-class" "$chunk1" 0 1 1 1 16 32
echo "    ,"
slot_vector "native-chunk0-extreme-counters" "$chunk0" 4294967295 18446744073709551615 18446744073709551615 2 240 96
cat <<EOF
  ],
  "bounds": [
EOF
first=1
for pl in 1 4079 4080 4081 8160 8161 393216 4194304 16707600 16711679 16711680; do
  if [ $first -eq 0 ]; then echo ","; fi
  first=0
  bound_row "$pl"
done
echo
echo "  ]"
echo "}"
