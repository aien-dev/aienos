#!/usr/bin/env bash
# allen_route_card.sh -- build a pi5-allen route card (\EFI\AIENOS\ALLEN.EXM with header "AIENALR1 QUALIF-ALLEN-ROUTE",
# crates/allen-reflex-kernel/src/card.rs parse_route) from route family files (aienos#399). Only the request id, the
# speaker, the consent/pending flags and the turns go into the card; the expected route stays on the host.
# Capabilities never go into the card: the image passes its own (core/allen.c CK_ALLEN_ROUTE_CAPS).
#
#   allen_route_card.sh <out file> <file>...
#
# A .psv file is a route family (id|family|speaker|flags|expected_route|expected_then|turns, docs/native/pi5-8/route/);
# a .req file holds requests with no expected answer (id|owner|guest|flags|turns), for example requests written after
# the image was built. Each request gets its own session id (its line number on the card).
# Refuses held-out and sealed files: the Pi card is a rehearsal; held-out families are scored once on the host only.
set -euo pipefail
out="${1:?out file}"; shift
[[ $# -ge 1 ]] || { echo "usage: $0 <out file> <file>..." >&2; exit 2; }
for f in "$@"; do
    case "$(readlink -f "$f")" in
        */sealed/*|*heldout*) echo "REFUSE: ${f} is a held-out or sealed file" >&2; exit 2 ;;
    esac
    [[ -r "$f" ]] || { echo "no file ${f}" >&2; exit 2; }
done
tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT
printf 'AIENALR1 QUALIF-ALLEN-ROUTE\n' > "${tmp}"
for f in "$@"; do
    if [[ "$f" == *.psv ]]; then nf=6; else nf=3; fi
    # keep id, speaker, flags; drop the family and expected columns; turns may hold '|' (all after the last field)
    awk -v nf="${nf}" '!/^#/ && NF {
        r = $0
        for (n = 0; n < nf; n++) { j = index(r, "|"); if (!j) { print "bad line: " $0 > "/dev/stderr"; exit 1 }
                                   f[n] = substr(r, 1, j - 1); r = substr(r, j + 1) }
        sp = (nf == 6) ? f[2] : f[1]; fl = (nf == 6) ? f[3] : f[2]
        print f[0] "|" sp "|" fl "|" r }' "$f" >> "${tmp}"
done
# speaker -> speaker:<session>, session = the request's line number on the card
awk 'NR == 1 { print; next } { i = index($0, "|"); id = substr($0, 1, i - 1); r = substr($0, i + 1);
     j = index(r, "|"); sp = substr(r, 1, j - 1); print id "|" sp ":" NR - 1 "|" substr(r, j + 1) }' "${tmp}" > "${tmp}.s"
mv "${tmp}.s" "${tmp}"
n=$(( $(wc -l < "${tmp}") - 1 ))
bytes=$(stat -c %s "${tmp}")
[[ ${bytes} -le 131072 ]] || { echo "card file ${bytes} bytes > 131072" >&2; exit 1; }
[[ ${n} -ge 1 && ${n} -le 512 ]] || { echo "card file has ${n} requests (1..512)" >&2; exit 1; }
dups=$(tail -n +2 "${tmp}" | cut -d'|' -f1 | sort | uniq -d | head -3 | tr '\n' ' ')
[[ -z "${dups}" ]] || { echo "duplicate request ids: ${dups}" >&2; exit 1; }
mv "${tmp}" "${out}"
trap - EXIT
echo "route card ${out}: ${n} requests, ${bytes} bytes, sha256 $(sha256sum "${out}" | cut -d' ' -f1)"
