#!/usr/bin/env bash
# Boot the AIENOS C kernel with the P2 sealed-artifact loader
# (native/kernel/core/artifact_loader.c) in QEMU AArch64 + UEFI (AAVMF) and
# check the serial console against the same expectations as the Rust gate
# scripts/qemu_artifact_test.sh (SEED-0B / P2-5). QEMU is not hardware: a
# PASS here qualifies nothing physical.
#
# The candidates come from the boot disk: at image build time the host tool
# native/kernel/tools/ck_store_image.c writes the signed artifacts into the
# sealed C Store (TEST identity, TEST keys) on a raw NVMe image; at boot the
# store stage reads them back over the SMMU-confined NVMe driver before the
# NVMe DMA revoke, and the loader verifies them as untrusted bytes.
#
# Three boots of the full image (devices, security, Store stages), each with
# QEMU iommu=smmuv3 and the NVMe image:
#   1. qualification build (make full CK_SEED0B_TEST_ANCHOR=1): trusts the RFC
#      8032 TEST 1 public key only (TEST ONLY); P26SEED, P25EXEC/WX/SPIN/TAMP,
#      the hostile set H01..H29 with their expected stage and reason, and
#      D01-DISK-MISSING (named in the disk index, no bytes on disk: refused
#      at "received", FirmwareRead);
#   2. ordinary build (make full): empty production trust, every candidate refused;
#   3. qualification build on a copy of the disk with one byte of a sealed
#      artifact envelope flipped: the Store is refused, no artifact byte is
#      used, nothing is admitted.
# Every candidate's receipt is decoded, bound to the supplied artifact,
# digest-recomputed, TEST-signed and verified by the in-tree C tool. Every
# artifact the kernel read is checked against the host's SHA-256 of the file.
# Static check: no default image (core or full, production or qualification)
# contains fw_cfg artifact code; a CK_TEST_FWCFG_ARTIFACTS=1 image is built only
# to prove that check sees it, and is never booted here.
#
# Differences from qemu_artifact_test.sh, all deliberate (native/kernel/GATES.md):
#  - builds with make (gcc), the artifacts with the in-tree C tool
#    (native/kernel/tools/ck_artifact_tool.c), not cargo / the Rust tool; the
#    probe programs are the committed fixtures, packed by the same pack.sh;
#  - candidates are read from the sealed Store on the NVMe boot disk instead of
#    ESP files read by a UEFI loader: the C boot stub reads no files;
#  - no Machine 1 captured-log mode (SEED-0B Machine 1 stays with the Rust gate);
#  - takes the machine quiet flag itself (noclobber) before building and prints
#    NOT_RUN while another run holds it; AIENOS_QUIET_FLAG / AIENOS_QUIET_TAG as
#    in qemu_ck_boot_test.sh;
#  - stricter: any QEMU exit status other than 0 fails.
# Last line: AIENOS_CK_P2_ARTIFACT: PASS|FAIL|NOT_RUN.
# Needs qemu-system-aarch64 and AAVMF (Ubuntu: qemu-system-arm qemu-efi-aarch64).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
verdict=AIENOS_CK_P2_ARTIFACT

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; echo "${verdict}: NOT_RUN"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; echo "${verdict}: NOT_RUN"; exit 2; }

# Machine quiet flag: one heavy run (builds included) at a time on the Spark.
quiet_flag="${AIENOS_QUIET_FLAG:-${HOME}/workspace/.spark-quiet}"
quiet_tag="${AIENOS_QUIET_TAG:-qemu_ck_artifact_test $$}"
if ! ( set -C; echo "${quiet_tag}" > "${quiet_flag}" ) 2>/dev/null; then
    echo "NOT_RUN  quiet flag ${quiet_flag} is held: $(head -c 200 "${quiet_flag}" 2>/dev/null || true)"
    echo "${verdict}: NOT_RUN"
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
cleanup() {
    rm -rf "${work}"
    release_flag
}
trap cleanup EXIT
failed=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; failed=1; }

cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
out_prod="${repo_root}/target/native-kernel"
out_qual="${repo_root}/target/native-kernel-seed0b-test"
out_fwcfg="${repo_root}/target/native-kernel-test-fwcfg"
mk() { make -s -C native/kernel CROSS="${cross}" AIENOS_COMMIT="${commit}" "$@" >/dev/null; }
mk OUT="${out_prod}"
mk OUT="${out_prod}" full
mk OUT="${out_qual}" CK_SEED0B_TEST_ANCHOR=1
mk OUT="${out_qual}" CK_SEED0B_TEST_ANCHOR=1 full
mk OUT="${out_fwcfg}" CK_TEST_FWCFG_ARTIFACTS=1
make -s -C native/kernel OUT="${out_prod}" tool store-image gpt-image >/dev/null
tool="${out_prod}/host/ck_artifact_tool"
simg="${out_prod}/host/ck_store_image"

# ---- static: the fw_cfg side channel is compiled out of every default image ----
fwcfg_pat='opt/aienos/artifacts|fw_cfg|QEMU0002'
fwcfg_syms=' (fw_select|fw_read|fw_skip|fw_find|fwcfg_from_dsdt|fwcfg_source|fwcfg)$'
for d in "${out_prod}" "${out_prod}/full" "${out_qual}" "${out_qual}/full"; do
    s=$(grep -aoE "${fwcfg_pat}" "${d}/BOOTAA64.EFI" | sort -u | tr '\n' ' ' || true)
    y=$("${cross}nm" "${d}/aienos-ck.elf" | grep -E "${fwcfg_syms}" | tr '\n' ' ' || true)
    if [[ -z "${s}${y}" ]]; then pass "default image ${d#"${repo_root}"/}: no fw_cfg artifact strings or symbols"
    else fail "default image ${d#"${repo_root}"/} carries fw_cfg artifact code: ${s}${y}"; fi
done
if grep -aqF "opt/aienos/artifacts" "${out_fwcfg}/BOOTAA64.EFI" \
    && grep -aqF "TEST-ONLY QEMU fw_cfg side channel" "${out_fwcfg}/BOOTAA64.EFI"; then
    pass "the check sees fw_cfg code in a CK_TEST_FWCFG_ARTIFACTS=1 image, which announces TEST-ONLY (not booted, never counted)"
else
    fail "CK_TEST_FWCFG_ARTIFACTS=1 image lacks the fw_cfg source or its TEST-ONLY announcement"
fi

# ---- inputs -----------------------------------------------------------------
fixtures="crates/aienos-artifact-tool/fixtures/p2_5"
seed_fixtures="crates/aienos-artifact-tool/fixtures/p2_6"
art="${work}/artifacts"
mkdir -p "${art}"
"${fixtures}/pack.sh" "${tool}" "${art}" >/dev/null
"${seed_fixtures}/pack.sh" "${tool}" "${art}" >/dev/null
mv "${art}/ids.txt" "${work}/ids.txt"
"${tool}" negative-corpus "${art}" >/dev/null
mv "${art}/expected.txt" "${work}/expected.txt"
for f in "${art}"/H*.AIEN; do
    n=$(basename "${f}")
    awk -v n="${n}" '$1 == n { found = 1 } END { exit !found }' "${work}/ids.txt" \
        || echo "${n} $("${tool}" id "${f}" 2>/dev/null || echo none)" >>"${work}/ids.txt"
done
mapfile -t files < <(find "${art}" -maxdepth 1 -name '*.AIEN' | LC_ALL=C sort)
missing=D01-DISK-MISSING.AIEN
missing_len=4096
candidate_count=$(( ${#files[@]} + 1 ))
id_prefix() { awk -v n="$1" '$1 == n { print substr($2, 1, 16) }' "${work}/ids.txt"; }

# ---- boot disk: signed artifacts into the sealed Store (image build time) ----
disk="${work}/nvme.img"
# GPT boot disk: the Store lives only inside its AIENOS partition (dev/disk_part.h).
"${out_prod}/host/ck_gpt_image" create "${disk}" 512 64 aienos-middle >/dev/null || fail "GPT boot disk image created"
if "${simg}" build "${disk}" 512 "${files[@]}" "missing:${missing}:${missing_len}" >"${work}/build.txt" 2>&1; then
    pass "boot disk built: $(head -1 "${work}/build.txt")"
else
    fail "boot disk build: $(head -3 "${work}/build.txt" | tr '\n' ' ')"
fi
# The empty file stands for the absent artifact in the host receipt checks.
: >"${art}/${missing}"
"${simg}" list "${disk}" 512 >"${work}/list.txt" 2>&1 || fail "host read-back of the boot disk Store"
rb_ok=1
for f in "${files[@]}"; do
    n=$(basename "${f}")
    grep -qxF "${n} bytes=$(stat -c %s "${f}") sha256=$(sha256sum "${f}" | cut -d' ' -f1)" "${work}/list.txt" || rb_ok=0
done
grep -qxF "${missing} bytes=${missing_len} missing" "${work}/list.txt" || rb_ok=0
if [[ "${rb_ok}" == 1 ]]; then pass "host read-back: all ${#files[@]} artifacts byte-identical in the Store, ${missing} absent"
else fail "host read-back of the boot disk Store differs from the files"; fi

boot() { # image, serial text output, disk image
    local esp="${work}/esp" log="${work}/serial.log" started status
    rm -rf "${esp}"
    mkdir -p "${esp}/EFI/BOOT" "${esp}/EFI/AIENOS"
    touch "${esp}/EFI/AIENOS/BOOTREPORT.TXT"
    cp "$1" "${esp}/EFI/BOOT/BOOTAA64.EFI"
    cp "${vars_fd}" "${work}/vars.fd"
    started=$(date +%s)
    set +e
    # Issue #61: single-threaded TCG; MTTCG hung in 1/40 soak boots.
    nice -n 10 timeout "${AIENOS_QEMU_TIMEOUT:-300}" qemu-system-aarch64 \
        -M virt,virtualization=on,gic-version=3,iommu=smmuv3 -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${esp}" \
        -device virtio-blk-pci,drive=esp \
        -drive if=none,id=nvme0,format=raw,file="$3" \
        -device nvme,drive=nvme0,serial=aienos-nvme-test \
        -device ramfb -display none -nic none \
        -serial file:"${log}" -no-reboot
    status=$?
    set -e
    tr -d '\r' <"${log}" >"$2"
    echo "qemu exit ${status} after $(( $(date +%s) - started )) s (commit ${commit:0:12})"
    [[ "${status}" == 0 ]] || fail "QEMU exit status ${status} (124 = timeout)"
}

has() { grep -qE -- "$2" "$1"; }
check() { if has "$1" "$3"; then pass "$2"; else fail "$2"; fi; }
check_absent() { if has "$1" "$3"; then fail "$2"; else pass "$2"; fi; }
common_checks() { # serial [candidate count]
    local want="${2:-${candidate_count}}"
    check "$1" "left firmware and entered the kernel" "kernel: alive"
    check "$1" "M3 cooperative threads unchanged" "threads: ok"
    check "$1" "M3 EL0 isolation proof unchanged" "el0: ok write=granted forged=denied fault=contained exit=0"
    check "$1" "M3 typed IPC proof unchanged" "ipc: ok message=delivered cap=delegated rights=attenuated forged=denied revoked=denied"
    check "$1" "kernel read all ${want} artifact candidates" "^artifact_candidates: ${want}$"
    if grep -q "^report-truncated:" "$1"; then fail "kernel report lines were truncated"; else pass "no kernel report line was truncated"; fi
    check "$1" "final report reached the console" "report_kind: final"
    if has "$1" "report_kind: (panic|fault)"; then fail "panic or fault reported"; fi
    if has "$1" "^receipt: [^ ]+ seq=[0-9]+ invalid$"; then fail "a candidate produced no valid receipt"; fi
    if has "$1" "^artifact_bundle: malformed"; then fail "kernel found the candidate list malformed"; fi
    check_absent "$1" "no TEST-ONLY fw_cfg source in a counted boot" "TEST-ONLY QEMU fw_cfg|^artifact_source: fw_cfg"
    local before after
    before=$(grep -oE "artifact_frames_free_before: [0-9]+" "$1" | awk '{print $2}' | tail -1)
    after=$(grep -oE "artifact_frames_free_after: [0-9]+" "$1" | awk '{print $2}' | tail -1)
    if [[ -n "${before}" && "${before}" == "${after}" ]]; then
        pass "every frame returned after all candidates (${before} free before and after)"
    else
        fail "frame accounting across candidates (before=${before:-?} after=${after:-?})"
    fi
}
disk_checks() { # serial: the candidates came from the boot disk, as read by the kernel
    check "$1" "SMMUv3 enabled; NVMe confined" "smmu: enabled"
    check "$1" "store stage committed this boot" "^store: committed generation=[0-9]+ boot_count=[0-9]+"
    check "$1" "artifact index read from the boot disk Store" \
        "^artifact_disk: index generation=[0-9]+ entries=${candidate_count} chunks_used=[0-9]+ chunks_ignored=0 sha256=[0-9a-f]{64}$"
    check "$1" "artifact_source=nvme_store with every candidate" \
        "^artifact_source: nvme_store generation=[0-9]+ candidates=${candidate_count} "
    local ok=1 f n
    for f in "${files[@]}"; do
        n=$(basename "${f}")
        has "$1" "^artifact_disk: ${n//./\\.} bytes=$(stat -c %s "${f}") sha256=$(sha256sum "${f}" | cut -d' ' -f1)$" || { ok=0; echo "  missing or different on the kernel side: ${n}"; }
    done
    if [[ "${ok}" == 1 ]]; then pass "kernel read all ${#files[@]} artifacts from NVMe, each SHA-256 equal to the host file"
    else fail "kernel-side SHA-256 of the disk artifacts"; fi
    check "$1" "${missing} named on disk without bytes: reported missing, not used" \
        "^artifact_disk: ${missing//./\\.} bytes=${missing_len} missing chunks=0/1; not used$"
    check "$1" "${missing} refused cleanly at received (FirmwareRead), reclaimed" \
        "^artifact: ${missing//./\\.} rejected stage=received reason=FirmwareRead reclaimed=yes$"
    local total=0
    for f in "${files[@]}"; do total=$(( total + $(stat -c %s "${f}") )); done
    check "$1" "kernel heap copies of the disk artifacts released after the loader" \
        "^artifact_disk: released heap copies artifacts=${#files[@]} bytes=${total}$"
    local ld lr ls
    ld=$(grep -n '^artifact_disk: ' "$1" | grep -v ':artifact_disk: released ' | tail -1 | cut -d: -f1)
    lr=$(grep -n 'dma_gate: nvme bus master revoked' "$1" | head -1 | cut -d: -f1)
    ls=$(grep -n '^artifact_source: ' "$1" | head -1 | cut -d: -f1)
    if [[ -n "${ld}" && -n "${lr}" && -n "${ls}" && "${ld}" -lt "${lr}" && "${lr}" -lt "${ls}" ]]; then
        pass "disk read finished before the NVMe DMA revoke; verification ran after it"
    else
        fail "order: disk read (${ld:-?}) < NVMe revoke (${lr:-?}) < loader (${ls:-?})"
    fi
}
rtag=""
receipt_check() { # serial name pattern
    local serial="$1" name="$2" want="$3" line record kdigest out
    line=$(grep -E "^receipt: ${name//./\\.} seq=[0-9]+ digest=[0-9a-f]{64} record=[0-9a-f]{1024}$" "${serial}" | tail -1 || true)
    if [[ -z "${line}" ]]; then fail "${name} receipt emitted"; return; fi
    record=${line##*record=}
    kdigest=$(sed -E 's/.* digest=([0-9a-f]{64}) .*/\1/' <<<"${line}")
    local file="${work}/${rtag}-${name}.receipt"
    if ! "${tool}" receipt from-hex "${record}" "${file}" >/dev/null 2>&1; then fail "${name} receipt record decodes on the host"; return; fi
    if ! out=$("${tool}" receipt check "${file}" "${art}/${name}" 2>&1); then
        fail "${name} receipt binds the supplied artifact (${out})"; return
    fi
    if [[ "${out}" != *"digest=${kdigest} "* ]]; then fail "${name} receipt digest recomputed by the host"; return; fi
    if ! grep -qE -- "${want}" <<<"${out}"; then fail "${name} receipt records the observed outcome (${out})"; return; fi
    if ! "${tool}" receipt sign-test "${file}" "${file}.signed" >/dev/null 2>&1; then fail "${name} receipt TEST ONLY signing"; return; fi
    if "${tool}" receipt verify "${file}.signed" | grep -q "RECEIPT_VERIFY: PASS digest=${kdigest} "; then
        pass "${name} receipt: bound, host digest match, observed outcome, TEST ONLY signature verifies"
    else
        fail "${name} signed receipt verifies"
    fi
}
stage_code() { case "$1" in received) echo 1;; staged) echo 2;; verified) echo 3;; authorized) echo 4;;
    reserved) echo 5;; mapped) echo 6;; hashed) echo 7;; sealed) echo 8;; caps) echo 9;; *) echo x;; esac; }
status_of() { case "$1" in exited:*) echo Exited;; timeout) echo Timeout;; fault:*) echo Fault;;
    bad-syscall:*) echo BadSyscall;; resource-overrun) echo ResourceOverrun;; *) echo NotRun;; esac; }
admitted_line() { # name, exec regex, caps
    echo "^artifact: ${1//./\\.} admitted id=$(id_prefix "$1") tier=seed0b-test exec=$2 bytes=identified=verified=admitted=mapped=executed wx=enforced caps=$3 revoked=yes reclaimed=yes frames=[0-9]+ "
}

# ---- boot 1: qualification build -------------------------------------------
qual="${work}/qualification.txt"
rtag=qual
cp "${disk}" "${work}/disk-qual.img"
boot "${out_qual}/full/BOOTAA64.EFI" "${qual}" "${work}/disk-qual.img"
common_checks "${qual}"
disk_checks "${qual}"
receipt_check "${qual}" "${missing}" "decision=Rejected .* stage=1 reason=0x10a status=NotRun exit=0 syscalls=0 reads_ok=0 denials=0 flags=0x04\$"
check "${qual}" "qualification build is labelled TEST ONLY" \
    "artifact_trust: seed0b-test qualification build — TEST ONLY"
check "${qual}" "receipts carry the SEED-0B-QEMU tier" "^artifact_receipt_tier: SEED-0B-QEMU$"
check "${qual}" "P26SEED read through its grant, WRITE and forged authority denied, exit 0, reclaimed" \
    "$(admitted_line P26SEED.AIEN exited:0x0 1)syscalls=9 reads=3 denials=5$"
check "${qual}" "P26SEED granted exactly its READ request" \
    "^grant: P26SEED\.AIEN\[0\] kind=object id=1 rights=0x1 bounds=0\+32 max_ops=4 max_bytes=32$"
if [[ $(grep -c "^grant: P26SEED\.AIEN\[" "${qual}") == 1 ]]; then pass "P26SEED holds exactly one capability"; else fail "P26SEED holds exactly one capability"; fi
receipt_check "${qual}" P26SEED.AIEN "decision=Admitted tier=SEED-0B-QEMU stage=0 reason=0x0 status=Exited exit=0 syscalls=9 reads_ok=3 denials=5 flags=0xff$"
check "${qual}" "P25EXEC executed its exact authenticated bytes, exit 0, caps revoked, reclaimed" \
    "$(admitted_line P25EXEC.AIEN exited:0x0 1)syscalls=3 reads=1 denials=1$"
check "${qual}" "P25WX killed by a W^X fault on its code page, reclaimed" \
    "$(admitted_line P25WX.AIEN fault:code-write 0)syscalls=0 reads=0 denials=0$"
check "${qual}" "P25SPIN killed at its time budget, reclaimed" \
    "$(admitted_line P25SPIN.AIEN timeout 0)syscalls=0 reads=0 denials=0$"
check "${qual}" "P25TAMP (payload byte flipped after signing) rejected BadSignature, reclaimed" \
    "^artifact: P25TAMP\.AIEN rejected stage=verified reason=BadSignature reclaimed=yes$"
receipt_check "${qual}" P25EXEC.AIEN "decision=Admitted .* status=Exited exit=0 syscalls=3 reads_ok=1 denials=1 flags=0xfd$"
receipt_check "${qual}" P25WX.AIEN "decision=Admitted .* status=Fault exit=0 syscalls=0 reads_ok=0 denials=0 flags=0xe4$"
receipt_check "${qual}" P25SPIN.AIEN "decision=Admitted .* status=Timeout exit=0 syscalls=0 reads_ok=0 denials=0 flags=0xe4$"
receipt_check "${qual}" P25TAMP.AIEN "decision=Rejected .* stage=3 reason=0x12 status=NotRun exit=0 syscalls=0 reads_ok=0 denials=0 flags=0x04$"

matrix_total=0 matrix_admitted=0
while read -r name decision a b c _; do
    [[ -n "${name}" ]] || continue
    matrix_total=$((matrix_total + 1))
    if [[ "${decision}" == rejected ]]; then
        check "${qual}" "${name} refused at ${a} (${b}), never ran, reclaimed" \
            "^artifact: ${name//./\\.} rejected stage=${a} reason=${b} reclaimed=yes$"
        receipt_check "${qual}" "${name}" "decision=Rejected .* stage=$(stage_code "${a}") reason=${c} status=NotRun exit=0 syscalls=0 reads_ok=0 denials=0 flags=0x04$"
    else
        matrix_admitted=$((matrix_admitted + 1))
        check "${qual}" "${name} admitted and contained (${a}), reclaimed" "$(admitted_line "${name}" "${a}" "${b}")"
        receipt_check "${qual}" "${name}" "decision=Admitted .* status=$(status_of "${a}") "
    fi
done < <(sed 's/ #.*//' "${work}/expected.txt")
[[ "${matrix_total}" -ge 29 ]] && pass "hostile matrix has ${matrix_total} cases" || fail "hostile matrix has only ${matrix_total} cases"
check "${qual}" "H29 requested READ|WRITE and was granted READ only" \
    "^grant: H29-READ-WRITE-REQUEST\.AIEN\[0\] kind=object id=1 rights=0x1 "
if has "${qual}" "^grant: H28-"; then fail "H28 (WRITE-only request) received a capability"; else pass "H28 requested only WRITE and received no capability"; fi
check "${qual}" "final report summarises every admission decision" \
    "^artifacts: candidates=${candidate_count} admitted=$((4 + matrix_admitted)) rejected=$((2 + matrix_total - matrix_admitted))$"

# ---- boot 2: ordinary build, empty production trust -------------------------
prod="${work}/production.txt"
rtag=prod
cp "${disk}" "${work}/disk-prod.img"
boot "${out_prod}/full/BOOTAA64.EFI" "${prod}" "${work}/disk-prod.img"
common_checks "${prod}"
disk_checks "${prod}"
if has "${prod}" "seed0b-test qualification build"; then fail "ordinary build must not carry the qualification label"; fi
if has "${prod}" "^artifact: [^ ]+ admitted"; then fail "ordinary build admitted an artifact"; else pass "ordinary build admitted nothing"; fi
prod_expect() { # name -> "stage reason code" in the ordinary build
    local line
    if [[ "$1" == "${missing}" ]]; then echo "received FirmwareRead 0x10a"; return; fi
    line=$(sed 's/ #.*//' "${work}/expected.txt" | awk -v n="$1" '$1 == n')
    if [[ -n "${line}" ]] && read -r _ d s r c <<<"${line}" && [[ "${d}" == rejected && "${s}" == verified \
        && "${r}" != BadSignature && "${r}" != UntrustedSigner ]]; then
        echo "${s} ${r} ${c}"
    else
        echo "verified UntrustedSigner 0x11"
    fi
}
for f in "${files[@]}" "${art}/${missing}"; do
    name=$(basename "${f}")
    read -r s r c <<<"$(prod_expect "${name}")"
    check "${prod}" "ordinary build refuses ${name} (${r}), reclaimed" \
        "^artifact: ${name//./\\.} rejected stage=${s} reason=${r} reclaimed=yes$"
    receipt_check "${prod}" "${name}" "decision=Rejected .* stage=$(stage_code "${s}") reason=${c} status=NotRun .* flags=0x04$"
done
check "${prod}" "final report summarises zero admitted" \
    "^artifacts: candidates=${candidate_count} admitted=0 rejected=${candidate_count}$"


# ---- boot 3: qualification build, one byte of the boot disk Store flipped ----
corrupt="${work}/corrupt.txt"
cp "${disk}" "${work}/disk-corrupt.img"
loc=$("${simg}" locate "${work}/disk-corrupt.img" 512 P26SEED.AIEN 2>/dev/null || true)
c_off=$(sed -nE 's/^offset=([0-9]+) length=([0-9]+)$/\1/p' <<<"${loc}")
c_len=$(sed -nE 's/^offset=([0-9]+) length=([0-9]+)$/\2/p' <<<"${loc}")
if [[ -n "${c_off}" && -n "${c_len}" ]]; then
    c_at=$(( c_off + c_len / 2 ))
    c_old=$(od -An -tu1 -j "${c_at}" -N1 "${work}/disk-corrupt.img" | tr -d ' ')
    printf "$(printf '\\%03o' $(( c_old ^ 0xa5 )))" \
        | dd of="${work}/disk-corrupt.img" bs=1 seek="${c_at}" count=1 conv=notrunc status=none
    pass "corrupted one byte of P26SEED's sealed envelope on the disk copy (offset ${c_at})"
else
    fail "locate P26SEED's envelope on the disk image (${loc})"
fi
if "${simg}" list "${work}/disk-corrupt.img" 512 >/dev/null 2>&1; then
    fail "host Store open accepted the corrupted disk"
else
    pass "host Store open refuses the corrupted disk"
fi
boot "${out_qual}/full/BOOTAA64.EFI" "${corrupt}" "${work}/disk-corrupt.img"
release_flag
common_checks "${corrupt}" 0
check "${corrupt}" "kernel refuses the corrupted boot disk Store" "^store: REFUSED "
check "${corrupt}" "no artifact byte read from a refused Store" "^artifact_disk: none \(Store refused: "
check "${corrupt}" "loader reports no source, clean refusal" "^artifact_source: none \("
check_absent "${corrupt}" "no artifact named or loaded from the corrupted disk" "^artifact(_disk)?: [A-Z][^ ]*\.AIEN "
check "${corrupt}" "final report: zero candidates, nothing admitted" "^artifacts: candidates=0 admitted=0 rejected=0$"
if [[ -n "${AIENOS_LOG_DIR:-}" ]]; then
    cp "${qual}" "${AIENOS_LOG_DIR}/qemu_ck_artifact_qualification_serial.log"
    cp "${prod}" "${AIENOS_LOG_DIR}/qemu_ck_artifact_production_serial.log"
    cp "${corrupt}" "${AIENOS_LOG_DIR}/qemu_ck_artifact_corrupt_disk_serial.log"
fi
if [[ "${failed}" != 0 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    echo "---- qualification serial (artifact lines) ----"
    grep -E "^(artifact|grant|kernel|report_kind|panic|fault|exception|esr|far)" "${qual}" | head -120 || true
fi
if [[ "${failed}" == 0 ]]; then echo "${verdict}: PASS"; else echo "${verdict}: FAIL"; exit 1; fi
