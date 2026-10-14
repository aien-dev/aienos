# klog-lib.sh -- KLOG slot helpers for pi5-run.sh (sourced). Formats:
# aienos native/kernel/core/klog_slot.h (struct ck_klog_map, ck_klog_hdr).
le32() { local v=$1; printf '\\x%02x\\x%02x\\x%02x\\x%02x' $((v&255)) $(((v>>8)&255)) $(((v>>16)&255)) $(((v>>24)&255)); }
le64() { le32 $(( $1 & 0xffffffff )); le32 $(( ($1 >> 32) & 0xffffffff )); }
hexbytes() { local h=$1 out="" i; for ((i=0;i<${#h};i+=2)); do out+="\\x${h:i:2}"; done; printf '%s' "$out"; }
# klog_struct <magic8> <lba> <count> <nonce-hex32> <out> ; map or empty header
klog_map() { # magic version sector_size lba count nonce pad
    { printf "AIENKLM1$(le32 1)$(le32 512)$(le64 $1)$(le64 $2)$(hexbytes $3)"; head -c $((512-48)) /dev/zero; } > "$4"
}
klog_hdr_empty() { # magic version state nonce lba count, rest zero
    { printf "AIENKLG1$(le32 1)$(le32 0)$(hexbytes $3)$(le64 $1)$(le64 $2)"; head -c $((512-48)) /dev/zero; } > "$4"
}
# klog_extract <KLOG.BIN> <out.txt> : prints the header fields, writes the text
klog_extract() {
    local f=$1 out=$2
    [[ "$(head -c 8 "$f")" == AIENKLG1 ]] || { echo "klog: no header"; return 1; }
    local state len total
    state=$(od -An -tu4 -j12 -N4 "$f" | tr -d ' ')
    len=$(od -An -tu8 -j48 -N8 "$f" | tr -d ' ')
    total=$(od -An -tu8 -j56 -N8 "$f" | tr -d ' ')
    echo "klog: state=${state} log_len=${len} log_total=${total} stage=$(dd if="$f" bs=1 skip=72 count=32 status=none | tr -d '\0')"
    [[ ${state} == 1 ]] || return 2
    { tail -c +513 "$f" | head -c "${len}" > "$out"; } || true  # head stops tail early (SIGPIPE under pipefail)
    [[ $(stat -c %s "$out") == "${len}" ]] || { echo "klog: short extract"; return 3; }
}
