#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 argus_event.o argus_ring.o aienos_capability.o" >&2
    exit 2
fi

bad=()
for object in "$@"; do
    [[ -f "$object" ]] || { echo "missing object: $object" >&2; exit 2; }
    while IFS= read -r symbol; do
        symbol="${symbol#_}"
        if [[ "$symbol" =~ ^(argus_detect_|argus_contain_|aienos_contain_|argus_aegis_bridge_) ]]; then
            bad+=("$object -> $symbol")
        fi
    done < <(nm -u "$object" | awk 'NF {print $NF}')
done

if ((${#bad[@]})); then
    printf 'GATE ARGUS1_AUTHORITY_DIRECTION FAIL %s\n' "${bad[@]}" >&2
    exit 1
fi

printf 'GATE ARGUS1_AUTHORITY_DIRECTION PASS event/ring/authority have no upward detection, containment, or bridge references\n'
