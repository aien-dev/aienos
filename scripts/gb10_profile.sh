#!/usr/bin/env bash
# Read-only GB10 hardware characterization collector for Linux (Machine 1).
#
# This script only reads. It opens no sysfs attribute for writing, changes no
# PCI command bit, resizes no BAR, resets no device, unbinds no driver, writes
# no MMIO, and touches no /dev/mem. Every source is a kernel-exposed read-only
# interface.
#
# Output is a deterministic structured profile (JSON) plus a human-readable
# report. Every field records:
#   - the value
#   - the source (which kernel interface)
#   - the collection method
#   - whether Linux interpreted the value (true for sysfs attributes, false for
#     raw configuration-space bytes that this script decodes itself)
#   - whether native AIENOS has independently verified it (always false here;
#     this collector runs under Linux)
#
# Privilege: by default the collector runs unprivileged and reads only the
# first 64 bytes of PCI configuration space, which excludes the capability
# list. Extended configuration space (256 bytes) and the ACPI table copies are
# readable only by root on this platform. Pass --allow-sudo (or set
# GB10_PROFILE_ALLOW_SUDO=1) to perform those specific, strictly read-only
# reads through `sudo -n`. Nothing else is escalated.

set -euo pipefail

SCHEMA="aienos.gb10.profile.v1"
GB10_VENDOR="0x10de"
GB10_DEVICE="0x2e12"

JSON_OUT="-"
REPORT_OUT="/dev/stderr"
ALLOW_SUDO="${GB10_PROFILE_ALLOW_SUDO:-0}"
EMIT_TIMESTAMP=0
GENERATED_AT="${GB10_PROFILE_GENERATED_AT:-}"

usage() {
    cat <<'EOF'
usage: bash scripts/gb10_profile.sh [options]

  --json PATH        write the structured profile to PATH ('-' for stdout; default -)
  --report PATH      write the human report to PATH (default stderr)
  --allow-sudo       allow the specific read-only privileged reads described above
  --generated-at S   set a fixed collection timestamp; default is omitted so
                     repeated runs on unchanged hardware are byte-identical
  -h, --help         show this help

This collector is read-only. It never writes configuration space, MMIO, driver
state, firmware variables, or storage.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --json) JSON_OUT="$2"; shift 2 ;;
        --report) REPORT_OUT="$2"; shift 2 ;;
        --allow-sudo) ALLOW_SUDO=1; shift ;;
        --generated-at) GENERATED_AT="$2"; EMIT_TIMESTAMP=1; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ "$ALLOW_SUDO" == "1" ]]; then
    if ! sudo -n true 2>/dev/null; then
        echo "warning: --allow-sudo requested but sudo -n is unavailable; continuing unprivileged" >&2
        ALLOW_SUDO=0
    fi
fi

TMP_CONFIG="$(mktemp "${TMPDIR:-/tmp}/gb10-config.XXXXXX")"
TMP_ACPI="$(mktemp "${TMPDIR:-/tmp}/gb10-acpi.XXXXXX")"
TMP_PROFILE="$(mktemp "${TMPDIR:-/tmp}/gb10-profile.XXXXXX")"
cleanup() { rm -f "$TMP_CONFIG" "$TMP_ACPI" "$TMP_PROFILE"; }
trap cleanup EXIT

# --- small helpers ---------------------------------------------------------

read_attr() { # dir name
    local path="$1/$2"
    [[ -r "$path" ]] && tr -d '\n' < "$path" || true
}

read_attr_or_null() { # dir name -> JSON null when absent
    local value
    value="$(read_attr "$1" "$2")"
    if [[ -z "$value" ]]; then printf 'null'; else printf '"%s"' "$value"; fi
}

read_resource_line() { # dir index -> "start end flags" (empty when absent)
    local file="$1/resource"
    [[ -r "$file" ]] || return 0
    awk -v n="$2" 'NR == n+1 { print $1, $2, $3 }' "$file"
}

attr_present() { [[ -e "$1/$2" ]]; }

config_byte() { # offset -> hex byte from TMP_CONFIG
    od -An -tx1 -j "$1" -N 1 "$TMP_CONFIG" 2>/dev/null | tr -d ' \n'
}

# --- capability decoding from raw configuration bytes ----------------------
# The capability list lives above offset 0x40 and needs a 256-byte read, which
# requires --allow-sudo. When only 64 bytes are available these decode to
# unknown rather than to zero.

CFG=()
load_config() { # dir bytes
    local dir="$1" count="$2"
    : > "$TMP_CONFIG"
    if [[ "$ALLOW_SUDO" == "1" ]]; then
        sudo -n dd if="$dir/config" bs=1 count="$count" status=none 2>/dev/null > "$TMP_CONFIG" || true
    else
        dd if="$dir/config" bs=1 count="$count" status=none 2>/dev/null > "$TMP_CONFIG" || true
    fi
    mapfile -t CFG < <(od -An -tx1 -v "$TMP_CONFIG" 2>/dev/null | tr -s ' ' '\n' | grep -E '^[0-9a-f]{2}$' || true)
}

cfg_len() { printf '%s' "${#CFG[@]}"; }

cfg_u8() { # offset
    printf '%s' "${CFG[$1]:-}"
}

cfg_u16() { # offset
    local lo hi
    lo="$(cfg_u8 "$1")"; hi="$(cfg_u8 "$(($1 + 1))")"
    [[ -n "$lo" && -n "$hi" ]] || { printf ''; return; }
    printf '%s' "$(( 16#$lo + 16#$hi * 256 ))"
}

cfg_u32() { # offset
    local b0 b1 b2 b3
    b0="$(cfg_u8 "$1")"; b1="$(cfg_u8 "$(($1 + 1))")"
    b2="$(cfg_u8 "$(($1 + 2))")"; b3="$(cfg_u8 "$(($1 + 3))")"
    [[ -n "$b0" && -n "$b1" && -n "$b2" && -n "$b3" ]] || { printf ''; return; }
    printf '%s' "$(( 16#$b0 + 16#$b1 * 256 + 16#$b2 * 65536 + 16#$b3 * 16777216 ))"
}

speed_name() { # pcie link speed encoding
    case "$1" in
        1) printf '2.5 GT/s' ;; 2) printf '5.0 GT/s' ;; 3) printf '8.0 GT/s' ;;
        4) printf '16.0 GT/s' ;; 5) printf '32.0 GT/s' ;; 6) printf '64.0 GT/s' ;;
        *) printf 'unknown' ;;
    esac
}

# Walk the standard capability list. Sets CAP_IDS, CAP_PCIE, CAP_MSI, CAP_MSIX
# (as "present offset", or empty) so the caller can build JSON.
decode_capabilities() {
    CAP_IDS=""; CAP_PCIE=""; CAP_MSI=""; CAP_MSIX=""
    if [[ "$(cfg_len)" -lt 256 ]]; then
        CAP_STATUS="requires-256-byte-config-read"
        return
    fi
    local status
    status="$(cfg_u16 0x06)"
    if [[ -z "$status" ]]; then CAP_STATUS="unreadable"; return; fi
    if (( (status & 0x10) == 0 )); then CAP_STATUS="capability-list-absent"; return; fi
    local pointer
    pointer="$(cfg_u8 0x34)"
    [[ -n "$pointer" ]] || { CAP_STATUS="unreadable"; return; }
    [[ "$pointer" == "00" ]] && { CAP_STATUS="capability-list-absent"; return; }
    CAP_STATUS="decoded"
    local offset=$((16#$pointer)) steps=0 seen=""
    while (( offset != 0 )); do
        if (( steps >= 48 )); then CAP_STATUS="too-many-capabilities"; return; fi
        if (( offset < 0x40 || offset % 4 != 0 || offset + 2 > 256 )); then
            CAP_STATUS="malformed-capability-pointer"; return
        fi
        case ",$seen," in *",$offset,"*) CAP_STATUS="capability-loop"; return ;; esac
        seen="$seen,$offset"
        local id next
        id="$(cfg_u8 "$offset")"
        next="$(cfg_u8 "$((offset + 1))")"
        [[ -n "$id" && -n "$next" ]] || { CAP_STATUS="unreadable"; return; }
        CAP_IDS="$CAP_IDS $id:$offset"
        case "$id" in
            05) CAP_MSI="$offset" ;;
            10) CAP_PCIE="$offset" ;;
            11) CAP_MSIX="$offset" ;;
        esac
        offset=$((16#$next))
        steps=$((steps + 1))
    done
}

# --- per-device extraction -------------------------------------------------

device_profile() { # sysfs device dir
    local dir="$1"
    local bdf; bdf="$(basename "$dir")"
    local domain_hex="${bdf%%:*}"
    local rest="${bdf#*:}"
    local bus_hex="${rest%%:*}"
    local devfn="${rest#*:}"
    local device_hex="${devfn%%.*}"
    local function_hex="${devfn#*.}"
    local domain=$((16#$domain_hex)) bus=$((16#$bus_hex))
    local device=$((16#$device_hex)) function=$((16#$function_hex))

    load_config "$dir" 256
    decode_capabilities

    local vendor device_id class revision sub_vendor sub_device
    vendor="$(read_attr "$dir" vendor)"
    device_id="$(read_attr "$dir" device)"
    class="$(read_attr "$dir" class)"
    revision="$(read_attr "$dir" revision)"
    sub_vendor="$(read_attr "$dir" subsystem_vendor)"
    sub_device="$(read_attr "$dir" subsystem_device)"

    # Convert the "0x...." sysfs hex strings to numbers for the structured
    # profile. An unreadable attribute stays null.
    hex_to_num() {
        local value="$1"
        if [[ "$value" == 0x* && ${#value} -le 6 ]]; then
            printf '%s' "$((16#${value#0x}))"
        else
            printf 'null'
        fi
    }
    local vendor_num device_num revision_num sub_vendor_num sub_device_num
    vendor_num="$(hex_to_num "$vendor")"
    device_num="$(hex_to_num "$device_id")"
    revision_num="$(hex_to_num "$revision")"
    sub_vendor_num="$(hex_to_num "$sub_vendor")"
    sub_device_num="$(hex_to_num "$sub_device")"

    local command="null" status="null"
    local raw_cmd; raw_cmd="$(od -An -tx4 -j 4 -N 4 "$TMP_CONFIG" 2>/dev/null | tr -d ' \n')"
    if [[ -n "$raw_cmd" ]]; then
        command="$((16#$raw_cmd & 0xffff))"
        status="$(( (16#$raw_cmd >> 16) & 0xffff ))"
    fi

    # BARs from the kernel resource file: base, size, and flags are already
    # decoded by Linux, so they are a Linux-observed fact.
    local bars="[]"
    local index line start end flags size kind prefetch is64
    for index in 0 1 2 3 4 5; do
        line="$(read_resource_line "$dir" "$index" || true)"
        [[ -n "$line" ]] || continue
        read -r start end flags <<< "$line"
        if [[ "$end" == "0x0000000000000000" ]]; then
            continue
        fi
        start=$((start)); end=$((end)); flags=$((flags))
        size=$((end - start + 1))
        kind="memory"; prefetch=false; is64=false
        if (( flags & 0x100 )); then kind="io"; fi
        if (( flags & 0x2000 )); then prefetch=true; fi
        if (( flags & 0x100000 )); then is64=true; fi
        bars="$(jq -c --argjson i "$index" --argjson base "$start" --arg base_hex "$(printf '0x%x' "$start")" \
            --argjson size "$size" --arg kind "$kind" --argjson prefetch "$prefetch" --argjson is64 "$is64" \
            '. + [{index:$i, base:$base, base_hex:$base_hex, size:$size, kind:$kind, prefetchable:$prefetch, is_64_bit:$is64}]' <<<"$bars")"
    done

    local pcie="null" msi="null" msix="null"
    if [[ -n "$CAP_PCIE" ]]; then
        local cap lc ls dev_caps max_speed max_width cur_speed cur_width dtype
        dev_caps="$(cfg_u32 "$((CAP_PCIE + 4))")"
        cap="$(cfg_u16 "$((CAP_PCIE + 2))")"
        dtype=$(( (cap >> 4) & 0x0f ))
        lc="$(cfg_u32 "$((CAP_PCIE + 0x0c))")"
        ls="$(cfg_u16 "$((CAP_PCIE + 0x12))")"
        max_speed=$((lc & 0x0f)); max_width=$(( (lc >> 4) & 0x3f ))
        cur_speed=$((ls & 0x0f)); cur_width=$(( (ls >> 4) & 0x3f ))
        pcie="$(jq -n --argjson ver "$((cap & 0x0f))" --argjson dtype "$dtype" \
            --argjson max_payload "$((128 << (dev_caps & 7)))" \
            --arg max_speed "$(speed_name "$max_speed")" --argjson max_width "$max_width" \
            --arg cur_speed "$(speed_name "$cur_speed")" --argjson cur_width "$cur_width" \
            '{present:true, version:$ver, device_type:$dtype, max_payload_bytes:$max_payload,
              max_speed:$max_speed, max_width:$max_width, current_speed:$cur_speed, current_width:$cur_width}')"
    fi
    if [[ -n "$CAP_MSI" ]]; then
        local mc
        mc="$(cfg_u16 "$((CAP_MSI + 2))")"
        msi="$(jq -n --argjson enabled "$(( (mc & 1) != 0 ))" --argjson is64 "$(( (mc & 0x80) != 0 ))" \
            --argjson maskable "$(( (mc & 0x100) != 0 ))" \
            --argjson capable "$(( 1 << ((mc >> 1) & 7) ))" \
            '{present:true, enabled:$enabled, is_64_bit:$is64, maskable:$maskable, capable_vectors:$capable}')"
    fi
    if [[ -n "$CAP_MSIX" ]]; then
        local mc table pba
        mc="$(cfg_u16 "$((CAP_MSIX + 2))")"
        table="$(cfg_u32 "$((CAP_MSIX + 4))")"
        pba="$(cfg_u32 "$((CAP_MSIX + 8))")"
        msix="$(jq -n --argjson enabled "$(( (mc & 0x8000) != 0 ))" \
            --argjson masked "$(( (mc & 0x4000) != 0 ))" --argjson vectors "$(( (mc & 0x7ff) + 1 ))" \
            --argjson bir "$((table & 7))" --argjson toff "$((table & ~7))" \
            --argjson pbir "$((pba & 7))" --argjson poff "$((pba & ~7))" \
            '{present:true, enabled:$enabled, function_masked:$masked, vectors:$vectors,
              table_bir:$bir, table_offset:$toff, pba_bir:$pbir, pba_offset:$poff}')"
    fi

    local iommu_group="" numa="" driver="" firmware="" irq="" msi_count=0
    [[ -e "$dir/iommu_group" ]] && iommu_group="$(basename "$(readlink -f "$dir/iommu_group")")"
    numa="$(read_attr "$dir" numa_node)"
    [[ -e "$dir/driver" ]] && driver="$(basename "$(readlink -f "$dir/driver")")"
    [[ -e "$dir/firmware_node" ]] && firmware="$(readlink -f "$dir/firmware_node")"
    irq="$(read_attr "$dir" irq)"
    if [[ -d "$dir/msi_irqs" ]]; then
        msi_count="$(find "$dir/msi_irqs" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l | tr -d ' ')"
    fi

    local cur_link_speed max_link_speed cur_link_width max_link_width
    cur_link_speed="$(read_attr "$dir" current_link_speed)"
    max_link_speed="$(read_attr "$dir" max_link_speed)"
    cur_link_width="$(read_attr "$dir" current_link_width)"
    max_link_width="$(read_attr "$dir" max_link_width)"

    local cap_ids_json="[]"
    if [[ -n "$CAP_IDS" ]]; then
        local pair id off
        for pair in $CAP_IDS; do
            id="${pair%%:*}"; off="${pair#*:}"
            cap_ids_json="$(jq -c --argjson id "$((16#$id))" --argjson off "$off" \
                '. + [{id:$id, offset:$off}]' <<<"$cap_ids_json")"
        done
    fi

    jq -n \
        --arg bdf "$bdf" --argjson domain "$domain" --argjson bus "$bus" \
        --argjson device "$device" --argjson function "$function" \
        --argjson vendor "$vendor_num" --argjson device_id "$device_num" \
        --arg vendor_hex "$vendor" --arg device_hex "$device_id" \
        --arg class "$class" --argjson revision "$revision_num" \
        --argjson sub_vendor "$sub_vendor_num" --argjson sub_device "$sub_device_num" \
        --argjson command "$command" --argjson status "$status" \
        --argjson bars "$bars" --arg cap_status "$CAP_STATUS" --argjson cap_ids "$cap_ids_json" \
        --argjson pcie "$pcie" --argjson msi "$msi" --argjson msix "$msix" \
        --argjson config_bytes "$(cfg_len)" \
        --argjson iommu_group "${iommu_group:-null}" --argjson numa "${numa:-null}" \
        --arg driver "$driver" --arg firmware "$firmware" --argjson irq "${irq:-null}" \
        --argjson msi_count "$msi_count" \
        --arg cur_link_speed "$cur_link_speed" --arg max_link_speed "$max_link_speed" \
        --arg cur_link_width "$cur_link_width" --arg max_link_width "$max_link_width" \
        'def obs(v; s; m; li): {value:v, source:s, method:m, linux_interpreted:li, native_verified:false};
         def unk(r): {value:null, source:null, method:null, linux_interpreted:false, native_verified:false, state:"unknown", reason:r};
         {
           bdf:$bdf,
           vendor_hex:$vendor_hex,
           device_hex:$device_hex,
           location:{domain:$domain, bus:$bus, device:$device, function:$function,
                     source:"linux-sysfs", method:"sysfs device path", linux_interpreted:true},
           vendor_id:obs($vendor; "linux-sysfs"; "read vendor"; true),
           device_id:obs($device_id; "linux-sysfs"; "read device"; true),
           class:obs($class; "linux-sysfs"; "read class"; true),
           revision:obs($revision; "linux-sysfs"; "read revision"; true),
           subsystem_vendor_id:obs($sub_vendor; "linux-sysfs"; "read subsystem_vendor"; true),
           subsystem_id:obs($sub_device; "linux-sysfs"; "read subsystem_device"; true),
           command:obs($command; "linux-sysfs"; "raw config dword at 0x04"; false),
           status:obs($status; "linux-sysfs"; "raw config dword at 0x04"; false),
           bars:($bars | map(. + {source:"linux-sysfs", method:"read resource (kernel-sized)", linux_interpreted:true, native_verified:false})),
           bar_size_note:"kernel resource size; native AIENOS has not independently decoded it",
           capability_status:$cap_status,
           capabilities:$cap_ids,
           pcie:(if $pcie == null then unk($cap_status) else ($pcie + {source:"linux-sysfs", method:"raw config capability decode", linux_interpreted:false, native_verified:false}) end),
           msi:(if $msi == null then unk($cap_status) else ($msi + {source:"linux-sysfs", method:"raw config capability decode", linux_interpreted:false, native_verified:false}) end),
           msix:(if $msix == null then unk($cap_status) else ($msix + {source:"linux-sysfs", method:"raw config capability decode", linux_interpreted:false, native_verified:false}) end),
           iommu_group:(if $iommu_group == null then unk("no iommu_group attribute") else {value:$iommu_group, source:"linux-sysfs", method:"readlink iommu_group", linux_interpreted:true, native_verified:false} end),
           numa_node:(if $numa == null then unk("no numa_node attribute") else {value:$numa, source:"linux-sysfs", method:"read numa_node", linux_interpreted:true, native_verified:false} end),
           driver:(if $driver == "" then unk("no driver bound") else {value:$driver, source:"linux-sysfs", method:"readlink driver", linux_interpreted:true, native_verified:false} end),
           firmware_node:(if $firmware == "" then unk("no ACPI firmware node") else {value:$firmware, source:"linux-sysfs", method:"readlink firmware_node", linux_interpreted:true, native_verified:false} end),
           irq:(if $irq == null then unk("no irq attribute") else {value:$irq, source:"linux-sysfs", method:"read irq", linux_interpreted:true, native_verified:false} end),
           msi_irq_count:(if $msi_count == 0 then unk("no msi_irqs") else {value:$msi_count, source:"linux-sysfs", method:"count msi_irqs", linux_interpreted:true, native_verified:false} end),
           current_link_speed:(if $cur_link_speed == "" then unk("not exposed") else {value:$cur_link_speed, source:"linux-sysfs", method:"read current_link_speed", linux_interpreted:true, native_verified:false} end),
           max_link_speed:(if $max_link_speed == "" then unk("not exposed") else {value:$max_link_speed, source:"linux-sysfs", method:"read max_link_speed", linux_interpreted:true, native_verified:false} end),
           current_link_width:(if $cur_link_width == "" then unk("not exposed") else {value:$cur_link_width, source:"linux-sysfs", method:"read current_link_width", linux_interpreted:true, native_verified:false} end),
           max_link_width:(if $max_link_width == "" then unk("not exposed") else {value:$max_link_width, source:"linux-sysfs", method:"read max_link_width", linux_interpreted:true, native_verified:false} end),
           config_bytes_read:$config_bytes
         }'
}

# --- firmware topology -----------------------------------------------------

acpi_presence() {
    local dir="/sys/firmware/acpi/tables"
    local table list="[]"
    [[ -d "$dir" ]] || { printf '[]'; return; }
    for table in MCFG IORT PPTT SPCR GTDT APIC DSDT TPM2 WSMT; do
        if [[ -e "$dir/$table" ]]; then
            local size digest
            size="$(stat -c %s "$dir/$table" 2>/dev/null || printf 'null')"
            digest=""
            if [[ "$ALLOW_SUDO" == "1" ]]; then
                digest="$(sudo -n sha256sum "$dir/$table" 2>/dev/null | awk '{print $1}' || true)"
            fi
            list="$(jq -c --arg name "$table" --argjson size "${size:-null}" --arg digest "$digest" \
                '. + [{name:$name, size_bytes:$size, sha256:(if $digest == "" then null else $digest end)}]' <<<"$list")"
        fi
    done
    printf '%s' "$list"
}

# Parse the MCFG base-address allocation entries: each maps a PCI segment to an
# ECAM base and a bus range. Requires a privileged read-only table copy.
mcfg_segments() {
    local table="/sys/firmware/acpi/tables/MCFG"
    if [[ "$ALLOW_SUDO" != "1" ]]; then
        printf 'null'; return
    fi
    if [[ ! -e "$table" ]]; then
        printf 'null'; return
    fi
    : > "$TMP_ACPI"
    sudo -n dd if="$table" bs=1 status=none 2>/dev/null > "$TMP_ACPI" || { printf 'null'; return; }
    local length
    length="$(od -An -tu4 -j 4 -N 4 "$TMP_ACPI" 2>/dev/null | tr -d ' \n')"
    [[ -n "$length" ]] || { printf 'null'; return; }
    local count=$(( (length - 44) / 16 ))
    local entries="[]" i off
    for (( i = 0; i < count; i++ )); do
        off=$((44 + i * 16))
        local base_lo base_hi base segment start end
        base_lo="$(od -An -tu4 -j "$off" -N 4 "$TMP_ACPI" 2>/dev/null | tr -d ' \n')"
        base_hi="$(od -An -tu4 -j "$((off + 4))" -N 4 "$TMP_ACPI" 2>/dev/null | tr -d ' \n')"
        segment="$(od -An -tu2 -j "$((off + 8))" -N 2 "$TMP_ACPI" 2>/dev/null | tr -d ' \n')"
        start="$(od -An -tu1 -j "$((off + 10))" -N 1 "$TMP_ACPI" 2>/dev/null | tr -d ' \n')"
        end="$(od -An -tu1 -j "$((off + 11))" -N 1 "$TMP_ACPI" 2>/dev/null | tr -d ' \n')"
        base=$(( base_lo + base_hi * 4294967296 ))
        entries="$(jq -c --argjson seg "$segment" --argjson base "$base" \
            --argjson start "$start" --argjson end "$end" \
            --arg base_hex "$(printf '0x%x' "$base")" \
            '. + [{segment:$seg, ecam_base:$base, ecam_base_hex:$base_hex, start_bus:$start, end_bus:$end}]' <<<"$entries")"
    done
    printf '%s' "$entries"
}

bridge_topology() {
    local list="[]" dir class
    for dir in /sys/bus/pci/devices/*; do
        [[ -r "$dir/class" ]] || continue
        class="$(read_attr "$dir" class)"
        case "$class" in
            0x0604*|0x0600*) ;;  # PCI bridge, host bridge
            *) continue ;;
        esac
        list="$(jq -c --arg bdf "$(basename "$dir")" --arg class "$class" \
            '. + [{bdf:$bdf, class:$class, source:"linux-sysfs", linux_interpreted:true}]' <<<"$list")"
    done
    jq -c 'sort_by(.bdf)' <<<"$list"
}

gb10_devices() {
    local list="[]" dir vendor device_id
    for dir in /sys/bus/pci/devices/*; do
        [[ -r "$dir/vendor" && -r "$dir/device" ]] || continue
        vendor="$(read_attr "$dir" vendor)"
        device_id="$(read_attr "$dir" device)"
        if [[ "$vendor" == "$GB10_VENDOR" && "$device_id" == "$GB10_DEVICE" ]]; then
            list="$(jq -c --argjson dev "$(device_profile "$dir")" '. + [$dev]' <<<"$list")"
        fi
    done
    jq -c 'sort_by(.bdf)' <<<"$list"
}

# --- assemble --------------------------------------------------------------

DEVICES="$(gb10_devices)"
DEVICE_COUNT="$(jq 'length' <<<"$DEVICES")"

if [[ "$EMIT_TIMESTAMP" == "1" ]]; then
    TIMESTAMP_FIELD="$GENERATED_AT"
else
    TIMESTAMP_FIELD=""
fi

GIT_COMMIT=""
if git -C "$(dirname "$0")/.." rev-parse HEAD >/dev/null 2>&1; then
    GIT_COMMIT="$(git -C "$(dirname "$0")/.." rev-parse HEAD)"
fi

PROFILE="$(jq -n \
    --arg schema "$SCHEMA" \
    --arg product "$(read_attr /sys/class/dmi/id product_name)" \
    --arg sys_vendor "$(read_attr /sys/class/dmi/id sys_vendor)" \
    --arg commit "$GIT_COMMIT" \
    --argjson sudo "$([[ "$ALLOW_SUDO" == "1" ]] && echo true || echo false)" \
    --arg timestamp "${TIMESTAMP_FIELD}" \
    --argjson cmdline_iommu "$(tr ' ' '\n' < /proc/cmdline 2>/dev/null | grep -i iommu | jq -Rsc 'split("\n") | map(select(length>0))' || printf '[]')" \
    --argjson devices "$DEVICES" \
    --argjson acpi "$(acpi_presence)" \
    --argjson mcfg "$(mcfg_segments)" \
    --argjson bridges "$(bridge_topology)" \
    '{
       schema:$schema,
       generated_at_utc:(if $timestamp == "" then null else $timestamp end),
       collector:{name:"scripts/gb10_profile.sh", git_commit:$commit, read_only:true, sudo_used:$sudo},
       platform:{product_name:$product, system_vendor:$sys_vendor, source:"linux-sysfs", linux_interpreted:true},
       machine_identity_note:"Linux-observed facts only; not a native AIENOS proof.",
       iommu_kernel_parameters:$cmdline_iommu,
       acpi_tables:$acpi,
       mcfg_segments:$mcfg,
       pci_bridge_topology:$bridges,
       gb10_device_count:$devices|length,
       gb10_devices:$devices
     }' | jq -S '.')"

printf '%s' "$PROFILE" > "$TMP_PROFILE"
if [[ "$JSON_OUT" == "-" ]]; then
    printf '%s\n' "$PROFILE"
else
    printf '%s\n' "$PROFILE" > "$JSON_OUT"
fi

{
    echo "# GB10 read-only hardware characterization (Linux-observed)"
    echo
    echo "schema: $SCHEMA"
    echo "collector commit: ${GIT_COMMIT:-unknown}"
    echo "sudo used for read-only config/ACPI: $([[ "$ALLOW_SUDO" == "1" ]] && echo yes || echo no)"
    echo "GB10 devices found: $DEVICE_COUNT"
    echo
    if [[ "$DEVICE_COUNT" == "0" ]]; then
        echo "No NVIDIA 10de:2e12 device is present in /sys/bus/pci/devices."
    else
        jq -r '.gb10_devices[] |
            "## \(.bdf)",
            "  vendor:device      \(.vendor_hex):\(.device_hex)  class \(.class.value)",
            "  location           domain=\(.location.domain) bus=\(.location.bus) device=\(.location.device) function=\(.location.function)",
            "  iommu_group        \(.iommu_group.value // "unknown")",
            "  driver             \(.driver.value // "none")",
            "  numa_node          \(.numa_node.value // "unknown")",
            "  firmware_node      \(.firmware_node.value // "unknown")",
            "  pcie link          current \(.current_link_speed.value // "?") x\(.current_link_width.value // "?")  max \(.max_link_speed.value // "?") x\(.max_link_width.value // "?")",
            "  capability status  \(.capability_status)",
            "  BARs:" ,
            ( .bars[] | "    [\(.index)] \(.kind) base=\(.base_hex) size=\(.size) 64bit=\(.is_64_bit) prefetch=\(.prefetchable)" ),
            ""' "$TMP_PROFILE"
    fi
    echo "The structured profile records source, method, whether Linux interpreted"
    echo "the value, and whether AIENOS independently verified it. No observation"
    echo "here is a native AIENOS proof, and none of it involved a GPU command."
} > "$REPORT_OUT"
rm -f "$TMP_PROFILE"
