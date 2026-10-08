#!/usr/bin/env bash
# Network gate for the AIENOS C kernel: AIENOS_CK_NET (C-only gate; the Rust
# kernel has no virtio-net queue driver, so there is no Rust counterpart).
# Boots the full C image (make full) in QEMU AArch64 with UEFI (AAVMF), an
# NVMe disk (so the boot is the normal full boot) and a virtio-net-pci NIC on
# QEMU user networking (slirp). QEMU is not hardware: a PASS here qualifies
# nothing physical.
#
# The devices stage (native/kernel/dev/net_bind.c) binds native/net's polled
# virtio-net driver: SMMU window for its one DMA region first, then memory
# decode + bus master, vnet_init_flags with VIRTIO_F_ACCESS_PLATFORM required
# (the NIC is iommu_platform=on,disable-legacy=on, so QEMU sends every ring
# and buffer access of the device through the smmuv3 vIOMMU), then ARP for the slirp gateway 10.0.2.2 and
# one UDP datagram from 10.0.2.15:47030 to 10.0.2.2:47029, then device reset,
# bus master off, SMMU stream back to abort. Slirp forwards 10.0.2.2:47029 to
# the host's 127.0.0.1:47029, where the in-tree C helper
# native/kernel/tools/ck_udp_echo.c (make udp-echo; no Python, no nc/socat)
# answers "AIENOS-CK-NET pong token=<per-run random token> echo=<datagram>".
#
#  boot 1  iommu=smmuv3: must pass every M1 check (scripts/lib_ck_m1_checks.sh)
#          and show
#   (a) attach: caps parsed, SMMU window for virtio_net, "dma_gate: virtio_net
#       granted (Confined)", "virtio_net: attached ... mac=52:54:00:12:34:56"
#       (QEMU's default NIC MAC), ARP reply from the slirp gateway MAC
#       52:55:0a:00:02:02;
#   (b) TX: the guest's "net: udp tx ... completed=yes" line (the device
#       returned the TX descriptor) AND the helper's log shows that exact
#       datagram (same nonce) arriving from 127.0.0.1;
#   (c) RX: the guest's "net: udp rx ... udp_csum=verified parsed=m6a
#       echo_of_ours=yes" line carries this run's helper token and the
#       guest's own nonce, and the helper logged its reply;
#   (d) fence: after the round trip the kernel points every RX descriptor the
#       device holds at a 0x5a page outside the window and sends one probe
#       datagram (helper logs it and replies). The SMMU event queue must hold
#       an F_TRANSLATION (0x10) record whose stream id is the NIC's (from the
#       smmu_dma_window line) and whose address is in that page; this script
#       re-checks those printed event fields itself (page outside the window,
#       sid equal, addr in page), the page must read back intact (whether QEMU
#       completes the RX via its bounce buffer is reported, not judged), and
#       the positive round trip must have raised no fault;
#   (e) recovery: device reset + re-init (ACCESS_PLATFORM again) and a second
#       full ARP + UDP round trip inside the window with no new fault;
#   plus the release order (device reset, bus master revoked, stream back to
#   abort, after the fence and recovery) and "devices: ... virtio_net=selftest-ok".
#  boot 2  no SMMU, same image: virtio-net DMA must be denied (NoSmmu), no
#          grant, no datagram sent, and the helper must log nothing new.
#  boot 3  SMMU on, modern-only NIC WITHOUT iommu_platform (QEMU offers no
#          ACCESS_PLATFORM and would DMA around the vIOMMU): the driver must
#          refuse it before FEATURES_OK ("init FAIL (NoAccessPlatform)"), no
#          attach, no datagram, helper logs nothing new, device released.
# Not proven (stated, not hidden): QEMU's smmuv3 and virtio models are not
# hardware; measured on QEMU 8.2.2 the refused DMA does not set NEEDS_RESET (QEMU
# completes the RX through its bounce buffer, write dropped); the kernel
# discards the redirected descriptors and shows recovery by reset + re-init,
# not a device that keeps running through the fault.
# Netdev: -netdev user,ipv6=off,restrict=off (AIENOS_NET_RESTRICT overrides).
# Measured 2026-10-01 with QEMU on the Spark: AIENOS_NET_RESTRICT=on makes the
# gate FAIL (ARP still answers, but the datagram never reaches the helper on
# 127.0.0.1), so restricted slirp cannot carry this round trip; nothing else
# listens for the guest and the run lasts two short boots.
#
# Reads the machine quiet flag and takes the QEMU gate lock through
# scripts/lib_gate_hold.sh like the other qemu_ck_* scripts. Final line: AIENOS_CK_NET:
# PASS|FAIL|NOT_RUN. Exit 0 PASS, 1 FAIL, 2 missing tools, 3 NOT_RUN.
# Needs qemu-system-aarch64, AAVMF (Ubuntu: qemu-system-arm qemu-efi-aarch64)
# and a C compiler.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

code_fd="${AAVMF_CODE:-/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd}"
vars_fd="${AAVMF_VARS:-/usr/share/AAVMF/AAVMF_VARS.fd}"
command -v qemu-system-aarch64 >/dev/null || { echo "qemu-system-aarch64 not installed"; echo "AIENOS_CK_NET: NOT_RUN"; exit 2; }
[[ -r "${code_fd}" && -r "${vars_fd}" ]] || { echo "AAVMF firmware not found"; echo "AIENOS_CK_NET: NOT_RUN"; exit 2; }

cross=""
if [ "$(uname -m)" != "aarch64" ]; then cross="aarch64-linux-gnu-"; fi
commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
out="${repo_root}/target/native-kernel"
make -s -C native/kernel CROSS="${cross}" OUT="${out}" AIENOS_COMMIT="${commit}" full >/dev/null
make -s -C native/kernel OUT="${out}" udp-echo gpt-image >/dev/null
efi="${out}/full/BOOTAA64.EFI"
echo_bin="${out}/host/ck_udp_echo"
port="$(sed -nE 's/^#define CK_NET_ECHO_PORT ([0-9]+)u.*/\1/p' native/kernel/dev/net_udp.h)"
lport="$(sed -nE 's/^#define CK_NET_LOCAL_PORT ([0-9]+)u.*/\1/p' native/kernel/dev/net_udp.h)"
[[ -n "${port}" && -n "${lport}" ]] || { echo "FAIL  ports not found in native/kernel/dev/net_udp.h"; echo "AIENOS_CK_NET: FAIL"; exit 1; }

# Machine quiet flag (read only) and the QEMU gate lock (one gate at a time):
# scripts/lib_gate_hold.sh (aienos#278).
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib_gate_hold.sh"
if ! gh_quiet_check || ! gh_lock_take "qemu_ck_net_test" "${AIENOS_GATE_MINUTES:-60}"; then
    echo "NOT_RUN  ${gh_why}"
    echo "AIENOS_CK_NET: NOT_RUN"
    exit 3
fi
# Release only this run's own gate lock record, at most once.
release_flag() { gh_lock_release; }
top="$(mktemp -d)"
helper_pid=""
cleanup() {
    if [[ -n "${helper_pid}" ]]; then kill "${helper_pid}" 2>/dev/null || true; wait "${helper_pid}" 2>/dev/null || true; fi
    rm -rf "${top}"
    release_flag
}
trap cleanup EXIT

# Per-run token: the guest can only print it if the helper's reply reached it.
token="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
[[ "${token}" =~ ^[0-9a-f]{16}$ ]] || { echo "FAIL  could not read a random token"; echo "AIENOS_CK_NET: FAIL"; exit 1; }
hlog="${top}/helper.log"
"${echo_bin}" "${port}" "${token}" "${hlog}" "${AIENOS_NET_HELPER_SECONDS:-600}" &
helper_pid=$!
for _ in $(seq 1 50); do
    grep -q '^ready port=' "${hlog}" 2>/dev/null && break
    kill -0 "${helper_pid}" 2>/dev/null || break
    sleep 0.1
done
if ! grep -q "^ready port=${port}$" "${hlog}" 2>/dev/null; then
    echo "NOT_RUN  UDP echo helper could not listen on 127.0.0.1:${port}: $(head -c 200 "${hlog}" 2>/dev/null || true)"
    echo "AIENOS_CK_NET: NOT_RUN"
    exit 3
fi
echo "PASS  UDP echo helper listening on 127.0.0.1:${port} (token ${token})"

# shellcheck source=scripts/lib_ck_m1_checks.sh
source "${repo_root}/scripts/lib_ck_m1_checks.sh"
img_bytes=67108864
image="${top}/nvme.img"
# GPT boot disk with an AIENOS partition (native/kernel/tools/ck_gpt_image.c):
# the kernel binds NVMe only when it finds one (dev/disk_part.h).
"${out}/host/ck_gpt_image" create "${image}" 512 $(( img_bytes / 1048576 )) aienos-middle >/dev/null
net_fail=0; m1_fail=0

# boot <name> [smmu|nosmmu] [nic options]: one QEMU boot; serial text in
# ${work}/serial.txt. The NIC defaults to modern-only behind the vIOMMU.
nic_confined="disable-legacy=on,iommu_platform=on"
boot() {
    work="${top}/$1"
    mkdir -p "${work}/esp/EFI/BOOT" "${work}/esp/EFI/AIENOS"
    touch "${work}/esp/EFI/AIENOS/BOOTREPORT.TXT"
    cp "${efi}" "${work}/esp/EFI/BOOT/BOOTAA64.EFI"
    cp "${vars_fd}" "${work}/vars.fd"
    local machine="virt,virtualization=on,gic-version=3"
    [[ "${2:-}" != smmu ]] || machine+=",iommu=smmuv3"
    set +e
    # Issue #61: single-threaded TCG (see qemu_boot_test.sh).
    timeout "${AIENOS_QEMU_TIMEOUT:-180}" qemu-system-aarch64 \
        -M "${machine}" -accel tcg,thread=single -cpu max -smp 4 -m 2048 \
        -drive if=pflash,format=raw,readonly=on,file="${code_fd}" \
        -drive if=pflash,format=raw,file="${work}/vars.fd" \
        -drive if=none,id=esp,format=raw,file=fat:rw:"${work}/esp" \
        -device virtio-blk-pci,drive=esp \
        -drive if=none,id=nvme0,format=raw,file="${image}" \
        -device nvme,drive=nvme0,serial=aienos-net-test \
        -netdev user,id=n0,ipv6=off,restrict="${AIENOS_NET_RESTRICT:-off}" \
        -device "virtio-net-pci,netdev=n0,mac=52:54:00:12:34:56${3+,$3}" \
        -device ramfb -display none \
        -serial file:"${work}/serial.log" -no-reboot
    qemu_status=$?
    set -e
    tr -d '\r' <"${work}/serial.log" >"${work}/serial.txt"
    [[ -z "${AIENOS_LOG_DIR:-}" ]] || cp "${work}/serial.txt" "${AIENOS_LOG_DIR}/qemu_ck_net_$1.log"
    echo "== boot $1: qemu exit ${qemu_status}"
    failed=0
    ck_m1_checks
    [[ "${failed}" == 0 ]] || m1_fail=1
    failed=0
}
line_of() { grep -n -- "$1" "${work}/serial.txt" | head -1 | cut -d: -f1; }

# ---- boot 1: SMMU present, full round trip ----
boot net-smmu smmu "${nic_confined}"
echo "-- (a) attach"
check "virtio-net capabilities parsed" "^virtio_net: [0-9a-f:.]* caps ok common=bar"
check "SMMU window programmed for the virtio-net DMA region only" \
    "^smmu_dma_window: virtio_net only iova=0x[0-9a-f]* len=0x[0-9a-f]* rid=0x[0-9a-f]* stream_id=0x[0-9a-f]*$"
check "virtio-net DMA granted only after confinement" "^dma_gate: virtio_net granted (Confined), bus master on$"
check "driver attached, QEMU NIC MAC read from the device, ACCESS_PLATFORM negotiated (features = VERSION_1|ACCESS_PLATFORM|MAC)" \
    "^virtio_net: attached [0-9a-f:.]* rid=0x[0-9a-f]* qsize=rx[0-9]*/tx[0-9]* mac=52:54:00:12:34:56 features=0x300000020 access_platform=yes$"
check "ARP reply from the slirp gateway (52:55:0a:00:02:02)" \
    "^net: arp who-has 10.0.2.2 tell 10.0.2.15 -> 52:55:0a:00:02:02 tries=[0-9]*$"
echo "-- (b) TX"
tx_re="^net: udp tx 10\.0\.2\.15:${lport} -> 10\.0\.2\.2:${port} frame=[0-9]+ bytes payload=\"(AIENOS-CK-NET ping nonce=[0-9a-f]{8})\" try=[0-9]+ completed=yes$"
tx_line="$(grep -E "${tx_re}" "${work}/serial.txt" | head -1 || true)"
nonce=""
if [[ "${tx_line}" =~ ${tx_re} ]]; then
    nonce="${BASH_REMATCH[1]}"
    echo "PASS  guest sent one UDP frame and the device completed it (${nonce})"
else
    echo "FAIL  guest UDP TX line with completed=yes"; failed=1
fi
if [[ -n "${nonce}" ]] && grep -qE "^rx from 127\.0\.0\.1:[0-9]+ len=[0-9]+ payload=\"${nonce}\"$" "${hlog}"; then
    echo "PASS  host helper received the guest's datagram through slirp (same nonce)"
else
    echo "FAIL  host helper did not log the guest's datagram"; failed=1
fi
echo "-- (c) RX"
if grep -qE '^tx to 127\.0\.0\.1:[0-9]+ len=[0-9]+ reply=[0-9]+$' "${hlog}"; then
    echo "PASS  host helper sent its reply"
else
    echo "FAIL  host helper reply not logged"; failed=1
fi
rx_want="^net: udp rx 10\.0\.2\.2:${port} -> 10\.0\.2\.15:${lport} payload_len=[0-9]+ udp_csum=verified parsed=m6a echo_of_ours=yes payload=\"AIENOS-CK-NET pong token=${token} echo=${nonce:-NONE}\"$"
if [[ -n "${nonce}" ]] && grep -qE "${rx_want}" "${work}/serial.txt"; then
    echo "PASS  guest received and parsed (M6-A, checksum verified) the helper's reply with this run's token"
else
    echo "FAIL  guest UDP RX line with this run's token and its own nonce"; failed=1
fi
check "round trip reported" "^net: udp round trip ok tx_reclaimed=[1-9][0-9]* rx_frames=[1-9][0-9]*$"
echo "-- (d) fence: device DMA outside the window"
win_re='^smmu_dma_window: virtio_net only iova=0x([0-9a-f]+) len=0x([0-9a-f]+) rid=0x[0-9a-f]+ stream_id=0x([0-9a-f]+)$'
win_line="$(grep -E "${win_re}" "${work}/serial.txt" | head -1 || true)"
w_lo=""; w_len=""; w_sid=""
if [[ "${win_line}" =~ ${win_re} ]]; then w_lo=$((16#${BASH_REMATCH[1]})); w_len=$((16#${BASH_REMATCH[2]})); w_sid=$((16#${BASH_REMATCH[3]})); fi
probe_re='^net_smmu_negative: rx descriptors redirected=([1-9][0-9]*) to iova=0x([0-9a-f]+) \(outside window 0x[0-9a-f]+\+0x[0-9a-f]+\); probe datagram "(AIENOS-CK-NET ping smmu-probe nonce=[0-9a-f]{8})" tx=Ok$'
probe_line="$(grep -E "${probe_re}" "${work}/serial.txt" | head -1 || true)"
probe=""
if [[ "${probe_line}" =~ ${probe_re} ]]; then
    probe="${BASH_REMATCH[3]}"
    echo "PASS  ${BASH_REMATCH[1]} RX descriptors pointed outside the window, probe datagram sent"
else
    echo "FAIL  probe line (RX descriptors redirected, probe datagram tx=Ok)"; failed=1
fi
if [[ -n "${probe}" ]] && grep -qE "^rx from 127\.0\.0\.1:[0-9]+ len=[0-9]+ payload=\"${probe}\"$" "${hlog}" &&
    grep -A1 -F "payload=\"${probe}\"" "${hlog}" | tail -n +2 | grep -qE "^tx to 127\.0\.0\.1:[0-9]+ len=[0-9]+ reply=[0-9]+$"; then
    echo "PASS  host helper received the probe and replied (the device had a frame to write)"
else
    echo "FAIL  host helper did not log the probe datagram and a reply to it"; failed=1
fi
neg_re='^net_smmu_negative: refused rx dma outside window iova=0x([0-9a-f]+) faults=([1-9][0-9]*) type=0x10 sid=0x([0-9a-f]+) addr=0x([0-9a-f]+) page=intact rx_completed=([0-9]+) device_status=0x([0-9a-f]{2}) needs_reset=(yes|no) faults_during_roundtrip=0 overflow=([01])$'
neg_line="$(grep -E "${neg_re}" "${work}/serial.txt" | head -1 || true)"
if [[ -n "${w_lo}" && "${neg_line}" =~ ${neg_re} ]]; then
    c_iova=$((16#${BASH_REMATCH[1]})); e_sid=$((16#${BASH_REMATCH[3]})); e_addr=$((16#${BASH_REMATCH[4]}))
    e_rx="${BASH_REMATCH[5]}"; e_status="${BASH_REMATCH[6]}"; e_nr="${BASH_REMATCH[7]}"; e_ovf="${BASH_REMATCH[8]}"; e_n="${BASH_REMATCH[2]}"
    if (( (c_iova + 4096 <= w_lo || c_iova >= w_lo + w_len) && e_sid == w_sid && (e_addr & ~4095) == c_iova )); then
        echo "PASS  SMMU event F_TRANSLATION (0x10) x${e_n} for the NIC's stream 0x${BASH_REMATCH[3]} at 0x${BASH_REMATCH[4]}, in the target page 0x${BASH_REMATCH[1]} outside the window; page intact; positive round trip fault-free (device model reaction, reported not judged: rx_completed=${e_rx} device_status=0x${e_status} needs_reset=${e_nr} event_overflow=${e_ovf})"
    else
        echo "FAIL  event fields do not match the window/stream/page (iova=0x${BASH_REMATCH[1]} sid=0x${BASH_REMATCH[3]} addr=0x${BASH_REMATCH[4]} window=${w_lo}+${w_len} stream=${w_sid})"; failed=1
    fi
else
    echo "FAIL  SMMU refused-DMA line (F_TRANSLATION for this stream, page intact, fault-free round trip before it)"; failed=1
fi
echo "-- (e) recovery inside the window"
check "device reset + re-init with ACCESS_PLATFORM after the fault" \
    "^net_smmu_recovery: device reset + reinit ok (Ok) access_platform=yes late_probe_faults=[0-9][0-9]*$"
check "second round trip after the fault, no new SMMU fault" \
    "^net_smmu_recovery: round trip after the fault ok (rc=0 new_faults=0)$"
if [[ "$(grep -cE "^net: udp rx .* echo_of_ours=yes payload=\"AIENOS-CK-NET pong token=${token} echo=AIENOS-CK-NET ping nonce=[0-9a-f]{8}\"$" "${work}/serial.txt" || true)" -ge 2 ]]; then
    echo "PASS  two helper replies with this run's token parsed (before and after the fault)"
else
    echo "FAIL  fewer than two parsed helper replies with this run's token"; failed=1
fi
check "net selftest PASS (round trip, fence and recovery)" "^net: selftest PASS (rc=0)$"
echo "-- release"
check "device reset before the revoke" "^virtio_net: device reset status=0x00 (stopped)$"
check "virtio-net bus master revoked" "^dma_gate: virtio_net bus master revoked$"
check "virtio-net SMMU stream returned to abort" "^smmu: virtio_net stream 0x[0-9a-f]* returned to abort (rc=0)$"
lg="$(line_of '^dma_gate: virtio_net granted (Confined)')"; lt="$(line_of '^net: udp round trip ok')"; ld="$(line_of '^virtio_net: device reset status=0x00 (stopped)$')"
lr="$(line_of '^dma_gate: virtio_net bus master revoked$')"; la="$(line_of '^smmu: virtio_net stream .* returned to abort')"
ln="$(line_of '^net_smmu_negative: refused ')"; lv="$(line_of '^net_smmu_recovery: round trip after the fault ok')"
if [[ -n "${lg}" && -n "${lt}" && -n "${ln}" && -n "${lv}" && -n "${ld}" && -n "${lr}" && -n "${la}" && "${lg}" -lt "${lt}" && "${lt}" -lt "${ln}" && "${ln}" -lt "${lv}" && "${lv}" -lt "${ld}" && "${ld}" -lt "${lr}" && "${lr}" -lt "${la}" ]]; then
    echo "PASS  order: grant < round trip < fault refused < recovery round trip < device reset < bus master off < stream abort"
else
    echo "FAIL  order (lines ${lg:-none} ${lt:-none} ${ln:-none} ${lv:-none} ${ld:-none} ${lr:-none} ${la:-none})"; failed=1
fi
check "devices stage summary" "^devices: pci=ok nvme=bound virtio_net=selftest-ok$"
check_absent "no virtio-net failure lines" "^net: .*FAIL\|^net_smmu_[a-z]*: .*FAIL\|^virtio_net: .*FAIL\|^virtio_net: not bound"
[[ "${failed}" == 0 ]] || net_fail=1
failed=0
helper_rx_after_boot1="$(grep -c '^rx from ' "${hlog}" || true)"

# ---- boot 2: no SMMU, fail closed ----
boot net-nosmmu nosmmu "${nic_confined}"
check "virtio-net DMA denied without an SMMU" "^dma_gate: virtio_net denied (NoSmmu rc=-1), bus master stays off$"
check "virtio-net not bound without an SMMU" "^virtio_net: not bound (SMMU DMA isolation not active)$"
check_absent "no virtio-net grant without an SMMU" "dma_gate: virtio_net granted"
check_absent "no datagram sent without an SMMU" "^net: udp tx"
check "devices stage summary (no SMMU)" "virtio_net=selftest-failed$"
if [[ "$(grep -c '^rx from ' "${hlog}" || true)" == "${helper_rx_after_boot1}" ]]; then
    echo "PASS  host helper saw nothing from the no-SMMU boot"
else
    echo "FAIL  host helper received traffic during the no-SMMU boot"; failed=1
fi
[[ "${failed}" == 0 ]] || net_fail=1
failed=0
helper_rx_after_boot2="$(grep -c '^rx from ' "${hlog}" || true)"

# ---- boot 3: SMMU on, NIC without iommu_platform: refused (fail closed) ----
boot net-noap smmu "disable-legacy=on"
check "SMMU window programmed (the refusal is the driver's, not the SMMU's)" \
    "^smmu_dma_window: virtio_net only iova=0x[0-9a-f]* len=0x[0-9a-f]* rid=0x[0-9a-f]* stream_id=0x[0-9a-f]*$"
check "driver refuses a NIC that does not offer ACCESS_PLATFORM" "^virtio_net: init FAIL (NoAccessPlatform)$"
check_absent "no attach without ACCESS_PLATFORM" "^virtio_net: attached"
check_absent "no datagram sent without ACCESS_PLATFORM" "^net: udp tx"
check "device released (reset, bus master revoked, stream back to abort)" \
    "^smmu: virtio_net stream 0x[0-9a-f]* returned to abort (rc=0)$"
check "devices stage summary (no ACCESS_PLATFORM)" "virtio_net=selftest-failed$"
if [[ "$(grep -c '^rx from ' "${hlog}" || true)" == "${helper_rx_after_boot2}" ]]; then
    echo "PASS  host helper saw nothing from the no-ACCESS_PLATFORM boot"
else
    echo "FAIL  host helper received traffic during the no-ACCESS_PLATFORM boot"; failed=1
fi
[[ "${failed}" == 0 ]] || net_fail=1
release_flag

if [[ "${m1_fail}${net_fail}" != 00 || -n "${AIENOS_QEMU_VERBOSE:-}" ]]; then
    for s in "${top}"/*/serial.txt; do
        echo "---- serial console $(basename "$(dirname "${s}")") (net lines) ----"
        grep -E '^(virtio_net|net:|net_smmu|dma_gate: virtio|smmu|devices:|stage |report_kind:)' "${s}" | head -60 || true
    done
    echo "---- helper log ----"; head -20 "${hlog}" || true
fi
[[ "${m1_fail}" != 0 ]] && echo "M1 checks failed on at least one boot: the NET verdict cannot pass"
if [[ "${m1_fail}${net_fail}" == 00 ]]; then echo "AIENOS_CK_NET: PASS"; exit 0; fi
echo "AIENOS_CK_NET: FAIL"
exit 1
