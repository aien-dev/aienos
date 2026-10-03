#!/usr/bin/env bash
# Boot the AIENOS C kernel with the inference unit linked in (QEMU AArch64,
# UEFI/AAVMF, EL2 like Machine 1, -m 4096), let the kernel ingest the
# Llama-3.2-1B-Instruct Q4_K_M GGUF (807,694,368 bytes) into its own RAM over
# QEMU fw_cfg DMA, then check that the Rust crate crates/aienos-infer, called
# from the general-regs-only C kernel through crates/aienos-infer-kernel,
# parsed the header, bound the model and tokenized the fixed chat prompt
# "What is the capital of France?" (aienos#34 lane 4, cut 1: no generation).
# Last line: AIENOS_CK_INFER: PASS|FAIL|NOT_RUN (read by scripts/ck_gates.sh).
# NOT_RUN (never a silent pass) when the model file, cargo, the Rust target
# aarch64-unknown-none, qemu or AAVMF is missing, or the quiet flag is held.
# QEMU is not hardware: a PASS here qualifies nothing physical.
#
# FAIL when the script re-checks the serial lines itself and finds: the
# kernel did not ingest exactly the host file's size in bytes, the kernel's
# SHA-256 of the ingested bytes differs from the host's sha256sum (and, in the
# gate, the pinned model hash), no or several "infer: probe" lines, rc != 0,
# tensor count != 147, vocab != 128256, layers != 16, the first four prompt
# ids differ from the first four of the "ids" line of
# crates/aienos-infer/tests/fixtures/ref_fr.txt (128000 128006 882 128007),
# prompt length differs from that line's id count, a kernel PASS the script
# does not reproduce, a panic/fault report, no "kernel: alive", or a non-zero
# QEMU exit (PSCI reset = 0).
#
# Usage: bash scripts/qemu_ck_infer_test.sh                    the gate
#        bash scripts/qemu_ck_infer_test.sh --negative-control  corrupt the GGUF
#             magic; the gate checks must FAIL (rc=-2) -> prints
#             AIENOS_CK_INFER_NEGATIVE_CONTROL: PASS when they do
#        bash scripts/qemu_ck_infer_test.sh --self-test         canned logs, no QEMU/build
# Environment: AIENOS_MODEL (the GGUF), AIENOS_QEMU_TIMEOUT (900 s),
# AIENOS_QUIET_FLAG / AIENOS_QUIET_TAG, AIENOS_LOG_DIR, AIENOS_QEMU_VERBOSE.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
verdict_name=AIENOS_CK_INFER
model="${AIENOS_MODEL:-${HOME}/models/aien-mail/Llama-3.2-1B-Instruct-Q4_K_M.gguf}"
ref_file=crates/aienos-infer/tests/fixtures/ref_fr.txt
# Pinned model hash: evidence/config_a_reference_bundle.json and
# crates/aienos-infer/tests/fixtures/PROVENANCE.md.
pinned_sha=3f5a22426976ab26cfe84dba63c1d08391717abb1af893e10f1b2968d862dcc1
# Tensor count: crates/aienos-infer/tests/golden.rs:112; vocab/layers: golden.rs:61,56.
want_tensors=147 want_vocab=128256 want_layers=16

# infer_check_log FILE WANT_SIZE WANT_SHA WANT_IDS("a b c d ...") PIN(1|0):
# PASS/FAIL line per check; sets infer_failed=1 on failure.
infer_check_log() {
    local f="$1" want_size="$2" want_sha="$3" want_ids="$4" pin="$5"
    local line rc ids_got first4 plen
    ok()  { echo "PASS  $*"; }
    bad() { echo "FAIL  $*"; infer_failed=1; }
    local re_fw='^infer: fw_cfg base=0x[0-9a-f]+ dma=yes file=opt/aienos/model size=([0-9]+)$'
    local re_in='^infer: ingest bytes=([0-9]+) dma_us=([0-9]+)$'
    local re_sha='^infer: sha256=([0-9a-f]{64}) sha_us=[0-9]+$'
    local re_p='^infer: probe rc=(-?[0-9]+) tensors=([0-9]+) vocab=([0-9]+) ids=([0-9]+),([0-9]+),([0-9]+),([0-9]+) prompt_len=([0-9]+) layers=([0-9]+) heap_peak_kib=([0-9]+) probe_us=[0-9]+$'
    local n sz
    n="$(grep -cE "${re_fw}" "${f}" || true)"
    if [[ "${n}" == 1 ]]; then
        sz="$(sed -nE "s|${re_fw}|\\1|p" "${f}")"
        [[ "${sz}" == "${want_size}" ]] && ok "fw_cfg file size ${sz} = host file size" || bad "fw_cfg file size ${sz}, host file is ${want_size}"
    else bad "exactly one well-formed fw_cfg line (found ${n})"; fi
    n="$(grep -cE "${re_in}" "${f}" || true)"
    if [[ "${n}" == 1 ]]; then
        sz="$(sed -nE "s|${re_in}|\\1|p" "${f}")"
        [[ "${sz}" == "${want_size}" ]] && ok "kernel ingested ${sz} bytes = host file size" || bad "kernel ingested ${sz} bytes, host file is ${want_size}"
    else bad "exactly one well-formed ingest line (found ${n})"; fi
    n="$(grep -cE "${re_sha}" "${f}" || true)"
    if [[ "${n}" == 1 ]]; then
        sz="$(sed -nE "s|${re_sha}|\\1|p" "${f}")"
        [[ "${sz}" == "${want_sha}" ]] && ok "kernel SHA-256 of the ingested bytes = host sha256sum" || bad "kernel SHA-256 ${sz} differs from host ${want_sha}"
        if [[ "${pin}" == 1 ]]; then
            [[ "${sz}" == "${pinned_sha}" ]] && ok "SHA-256 = pinned model hash" || bad "SHA-256 is not the pinned model hash"
        fi
    else bad "exactly one well-formed sha256 line (found ${n})"; fi
    if [[ "$(grep -cE "${re_p}" "${f}" || true)" != 1 ]]; then
        bad "exactly one well-formed infer: probe line"
    else
        line="$(grep -E "${re_p}" "${f}")"
        local -a m; [[ "${line}" =~ ${re_p} ]]; m=("${BASH_REMATCH[@]}")
        g() { echo "${m[$1]}"; }
        rc="$(g 1)"
        [[ "${rc}" == 0 ]] && ok "probe returned 0" || bad "probe returned ${rc}"
        [[ "$(g 2)" == "${want_tensors}" ]] && ok "tensor count ${want_tensors}" || bad "tensor count $(g 2), expected ${want_tensors}"
        [[ "$(g 3)" == "${want_vocab}" ]] && ok "vocab size ${want_vocab}" || bad "vocab size $(g 3), expected ${want_vocab}"
        [[ "$(g 9)" == "${want_layers}" ]] && ok "layers ${want_layers}" || bad "layers $(g 9), expected ${want_layers}"
        ids_got="$(g 4) $(g 5) $(g 6) $(g 7)"
        first4="$(awk '{print $1,$2,$3,$4}' <<<"${want_ids}")"
        [[ "${ids_got}" == "${first4}" ]] && ok "first four prompt ids ${ids_got}" || bad "first four prompt ids '${ids_got}', expected '${first4}'"
        plen="$(wc -w <<<"${want_ids}")"
        [[ "$(g 8)" == "${plen}" ]] && ok "prompt length ${plen} tokens" || bad "prompt length $(g 8), expected ${plen}"
        local hp; hp="$(g 10)"
        (( hp > 0 && hp < 262144 )) && ok "allocator peak ${hp} KiB within the 256 MiB region" || bad "allocator peak ${hp} KiB outside (0, 262144)"
    fi
    grep -qx 'AIENOS_CK_INFER: PASS' "${f}" && ok "kernel reported AIENOS_CK_INFER: PASS" || bad "kernel did not report AIENOS_CK_INFER: PASS"
    grep -q "kernel: alive" "${f}" && ok "kernel alive" || bad "kernel never reached kernel: alive"
    if grep -qE 'report_kind: (panic|fault)' "${f}"; then bad "panic or fault report"; else ok "no panic or fault"; fi
    grep -q '^report_kind: final' "${f}" && ok "kernel reached its final report" || bad "no final report"
}

# The expected ids come from the golden reference, not from this script.
read_want_ids() { sed -n 's/^ids //p' "${ref_file}" | head -1; }

if [[ "${1:-}" == --self-test ]]; then
    tmp="$(mktemp -d)"; trap 'rm -rf "${tmp}"' EXIT
    [[ -r "${ref_file}" ]] || { echo "FAIL  ${ref_file} missing"; echo "AIENOS_CK_INFER_SELF_TEST: FAIL"; exit 1; }
    ids="$(read_want_ids)"
    [[ "$(wc -w <<<"${ids}")" == 17 && "$(awk '{print $1,$2,$3,$4}' <<<"${ids}")" == "128000 128006 882 128007" ]] \
        && echo "PASS  reference ids line parsed (17 ids, first four 128000 128006 882 128007)" || { echo "FAIL  reference ids line"; echo "AIENOS_CK_INFER_SELF_TEST: FAIL"; exit 1; }
    sz=807694368
    good() { printf 'kernel: alive\ninfer: fw_cfg base=0x9020000 dma=yes file=opt/aienos/model size=%s\ninfer: ingest bytes=%s dma_us=42340\ninfer: sha256=%s sha_us=8568801\ninfer: probe rc=0 tensors=147 vocab=128256 ids=128000,128006,882,128007 prompt_len=17 layers=16 heap_peak_kib=24695 probe_us=1116277\nAIENOS_CK_INFER: PASS\nreport_kind: final\n' "${sz}" "${sz}" "${pinned_sha}"; }
    st=0
    chk() { infer_failed=0; out="$(infer_check_log "$3" "${sz}" "${pinned_sha}" "${ids}" 1)"; grep -q '^FAIL' <<<"${out}" && infer_failed=1
        if [[ "$2" == pass && ${infer_failed} == 0 ]] || [[ "$2" == fail && ${infer_failed} == 1 && -n "$4" ]] && { [[ "$2" == pass ]] || grep -q "^FAIL.*$4" <<<"${out}"; }; then echo "PASS  self-test $1"; else echo "FAIL  self-test $1"; st=1; fi; }
    good >"${tmp}/g"; chk good pass "${tmp}/g"
    sed 's/rc=0 /rc=-2 /' "${tmp}/g" >"${tmp}/a"; chk bad-header-rc fail "${tmp}/a" "probe returned -2"
    sed 's/tensors=147/tensors=146/' "${tmp}/g" >"${tmp}/b"; chk wrong-tensors fail "${tmp}/b" "tensor count 146"
    sed 's/vocab=128256/vocab=128255/' "${tmp}/g" >"${tmp}/c"; chk wrong-vocab fail "${tmp}/c" "vocab size 128255"
    sed 's/ids=128000,/ids=128001,/' "${tmp}/g" >"${tmp}/d"; chk wrong-id0 fail "${tmp}/d" "first four prompt ids"
    sed 's/,128007 prompt_len/,128008 prompt_len/' "${tmp}/g" >"${tmp}/e"; chk wrong-id3 fail "${tmp}/e" "first four prompt ids"
    sed 's/prompt_len=17/prompt_len=16/' "${tmp}/g" >"${tmp}/f"; chk wrong-prompt-len fail "${tmp}/f" "prompt length 16"
    sed 's/layers=16/layers=15/' "${tmp}/g" >"${tmp}/h"; chk wrong-layers fail "${tmp}/h" "layers 15"
    sed 's/ingest bytes=807694368/ingest bytes=807694367/' "${tmp}/g" >"${tmp}/i"; chk short-ingest fail "${tmp}/i" "kernel ingested"
    sed 's/size=807694368/size=807694367/' "${tmp}/g" >"${tmp}/i2"; chk wrong-fwcfg-size fail "${tmp}/i2" "fw_cfg file size"
    sed "s/sha256=${pinned_sha}/sha256=0${pinned_sha:1}/" "${tmp}/g" >"${tmp}/j"; chk wrong-sha fail "${tmp}/j" "kernel SHA-256"
    sed 's/heap_peak_kib=24695/heap_peak_kib=0/' "${tmp}/g" >"${tmp}/k"; chk zero-heap fail "${tmp}/k" "allocator peak"
    # a log whose sha equals the host value but is not the pinned model hash
    sed "s|${pinned_sha}|0${pinned_sha:1}|" "${tmp}/g" >"${tmp}/g2"
    out="$(infer_check_log "${tmp}/g2" "${sz}" "0${pinned_sha:1}" "${ids}" 1)"
    grep -q '^FAIL  SHA-256 is not the pinned' <<<"${out}" && ! grep -q '^FAIL  kernel SHA-256' <<<"${out}" \
        && echo "PASS  self-test not-the-pinned-model" || { echo "FAIL  self-test not-the-pinned-model"; st=1; }
    grep -v '^AIENOS_CK_INFER' "${tmp}/g" >"${tmp}/l"; chk no-kernel-verdict fail "${tmp}/l" "kernel did not report"
    grep -v '^infer: probe' "${tmp}/g" >"${tmp}/m"; chk no-probe-line fail "${tmp}/m" "infer: probe line"
    grep -v '^kernel: alive' "${tmp}/g" >"${tmp}/n"; chk not-alive fail "${tmp}/n" "never reached kernel: alive"
    { cat "${tmp}/g"; echo "report_kind: fault"; } >"${tmp}/o"; chk fault fail "${tmp}/o" "panic or fault"
    grep -v '^report_kind: final' "${tmp}/g" >"${tmp}/p"; chk no-final fail "${tmp}/p" "no final report"
    { cat "${tmp}/g"; grep '^infer: probe' "${tmp}/g"; } >"${tmp}/q"; chk two-probe-lines fail "${tmp}/q" "infer: probe line"
    [[ ${st} == 0 ]] && { echo "AIENOS_CK_INFER_SELF_TEST: PASS"; exit 0; }
    echo "AIENOS_CK_INFER_SELF_TEST: FAIL"; exit 1
fi

negctl=0
[[ "${1:-}" == --negative-control ]] && negctl=1
if [[ ${negctl} == 1 ]]; then verdict_name=AIENOS_CK_INFER_NEGATIVE_CONTROL; fi

notrun() { echo "NOT_RUN  $*"; echo "${verdict_name}: NOT_RUN ($*)"; exit 2; }
[[ -r "${model}" ]] || notrun "model file ${model} not found"
[[ -r "${ref_file}" ]] || notrun "${ref_file} not found"
command -v qemu-system-aarch64 >/dev/null || notrun "qemu-system-aarch64 not installed"
code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || notrun "AAVMF firmware not found"
command -v cargo >/dev/null || notrun "cargo not installed"
if ! rustc --print target-list 2>/dev/null | grep -qx aarch64-unknown-none \
   || ! [[ -d "$(rustc --print sysroot)/lib/rustlib/aarch64-unknown-none/lib" ]]; then
    notrun "Rust target aarch64-unknown-none not installed (rustup target add aarch64-unknown-none)"
fi

cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
out="${repo_root}/target/native-kernel-infer"
lib="${repo_root}/target/infer-kernel/aarch64-unknown-none/release/libaienos_infer_kernel.a"
CARGO_TARGET_DIR="${repo_root}/target/infer-kernel" cargo build -q --release --target aarch64-unknown-none \
    --manifest-path crates/aienos-infer-kernel/Cargo.toml
make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" CK_INFER_LIB="${lib}" >/dev/null

quiet_flag="${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}"
quiet_tag="${AIENOS_QUIET_TAG:-qemu_ck_infer_test $$}"
if ! ( set -C; echo "${quiet_tag}" > "${quiet_flag}" ) 2>/dev/null; then
    echo "NOT_RUN  quiet flag ${quiet_flag} is held: $(head -c 200 "${quiet_flag}" 2>/dev/null || true)"
    echo "${verdict_name}: NOT_RUN"
    exit 3
fi
own_flag=1
release_flag() {
    if [[ "${own_flag}" == 1 ]]; then
        own_flag=0
        if [[ -f "${quiet_flag}" ]] && grep -qxF -- "${quiet_tag}" "${quiet_flag}"; then rm -f "${quiet_flag}"; fi
    fi
}
work="$(mktemp -d)"
cleanup() { rm -rf "${work}"; release_flag; }
trap cleanup EXIT

use_model="${model}"
if [[ ${negctl} == 1 ]]; then
    # Same bytes, first four (the GGUF magic "GGUF") overwritten: the header
    # parser must refuse it. Host-side copy; the original is never touched.
    use_model="${work}/corrupt.gguf"
    cp "${model}" "${use_model}"
    printf 'XXXX' | dd of="${use_model}" bs=1 count=4 conv=notrunc status=none
fi
want_size="$(stat -c %s "${use_model}")"
want_sha="$(sha256sum "${use_model}" | cut -d' ' -f1)"
want_ids="$(read_want_ids)"

mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
cp "${out}/BOOTAA64.EFI" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"
cp "${vars_fd}" "${work}/vars.fd"
log="${work}/serial.log"

started=$(date +%s)
set +e
timeout "${AIENOS_QEMU_TIMEOUT:-900}" qemu-system-aarch64 \
    -M virt,virtualization=on,gic-version=3 -accel tcg,thread=single -cpu max -smp 2 -m 4096 \
    -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
    -drive if=pflash,format=raw,file="${work}/vars.fd" \
    -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp" \
    -device virtio-blk-pci,drive=esp \
    -fw_cfg name=opt/aienos/model,file="${use_model}" \
    -device ramfb -display none -nic none \
    -serial file:"${log}" -no-reboot
qemu_status=$?
set -e
elapsed=$(( $(date +%s) - started ))
release_flag

tr -d '\r' <"${log}" >"${work}/serial.txt"
[[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/serial.txt" "${AIENOS_LOG_DIR}/qemu_ck_infer_serial.log"
echo "qemu exit ${qemu_status} after ${elapsed} s (commit ${commit:0:12})"

infer_failed=0
results="$(infer_check_log "${work}/serial.txt" "${want_size}" "${want_sha}" "${want_ids}" "$(( 1 - negctl ))")" || true
grep -q '^FAIL' <<<"${results}" && infer_failed=1
printf '%s\n' "${results}"
if [[ "${qemu_status}" == 0 ]]; then echo "PASS  QEMU exit 0 (PSCI reset)"; else echo "FAIL  QEMU exit ${qemu_status}"; infer_failed=1; fi
grep -E '^infer: ' "${work}/serial.txt" || true
if [[ ${negctl} == 1 ]]; then
    # The control passes only when the corrupted header is what made the gate fail.
    if [[ ${infer_failed} == 1 ]] && grep -q '^infer: probe rc=-2 ' "${work}/serial.txt" \
       && grep -q '^FAIL  probe returned -2' <<<"${results}" && grep -q "kernel: alive" "${work}/serial.txt"; then
        echo "AIENOS_CK_INFER_NEGATIVE_CONTROL: PASS (corrupt GGUF magic -> probe rc=-2 -> gate FAIL)"; exit 0
    fi
    echo "AIENOS_CK_INFER_NEGATIVE_CONTROL: FAIL (corrupt magic was not caught as probe rc=-2)"; exit 1
fi
if [[ "${infer_failed}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    echo "---- serial console ----"; cat "${work}/serial.txt"
fi
if [[ "${infer_failed}" == 0 ]]; then echo "AIENOS_CK_INFER: PASS"; exit 0; fi
echo "AIENOS_CK_INFER: FAIL"; exit 1
