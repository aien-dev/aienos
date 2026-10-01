#!/usr/bin/env bash
# trust1_gate5_policy_sim.sh: TRUST-1 Gate 5, TPM authorization policy
# simulation on a software TPM (swtpm).
#
#   bash scripts/trust1_gate5_policy_sim.sh selftest
#
# SIMULATION ONLY. swTPM is never Machine 1 qualification. Every key here is
# a throwaway test key made in a temp dir and deleted on exit; no owner key
# material is read or created, and no real TPM (/dev/tpm*) is touched.
#
# Policy spec (docs/TRUST-1-IMPLEMENTATION-PLAN.md, Gate 5)
# --------------------------------------------------------
# The sealed secret (stand-in for a storage unlock key) is bound to ONE
# fixed policy that never names a PCR value:
#
#   sealed = PolicyOR( ROOT_BRANCH , RECOVERY_BRANCH )
#   ROOT_BRANCH     = PolicyAuthorize(Owner Root key, ref "deleg")
#   RECOVERY_BRANCH = PolicySigned(Operator Approval key, fresh TPM nonce,
#                                  ref "recovery")
#
# Owner Root signs one delegation per Release Signer:
#   deleg(S) = PolicyAuthorize(S, ref "set") ; PolicyNV(SIGNER_FLOOR <= epoch(S))
# A Release Signer signs a release set {G1..Gk} (k <= 8):
#   set = PolicyOR( branch(G1) .. branch(Gk) )        (k = 1: branch(G1))
#   branch(G) = PolicyPCR(PCR 7, PCR 11 = expected values of release G)
#               ; PolicyNV(RELEASE_FLOOR <= G)
#
# PCR 7 carries "Secure Boot active + owner Boot Signer chain executed" and
# PCR 11 the release manifest digest. These two PCRs are placeholders: Gate 2
# decides the real selection. The statement enforced is "Secure Boot active,
# owner-approved chain executed, manifest in an approved release set"; the
# expected PCR values live only in signed, replaceable release sets, never as
# a frozen value inside the sealed object.
#
# RELEASE_FLOOR and SIGNER_FLOOR are TPM NV counters (monotonic: they can only
# go up). Raising them needs owner (operator) authorization.
#
# Anti-rollback generation semantics (Q29):
#   approved       generation G >= RELEASE_FLOOR and G in a set signed by a
#                  signer whose epoch >= SIGNER_FLOOR: unseals normally.
#   emergency-only generation G < RELEASE_FLOOR (retired): the normal path is
#                  refused by the TPM; only the recovery branch, which needs a
#                  fresh Operator Approval signature over the TPM nonce, can
#                  unseal.
#   revoked        signer epoch < SIGNER_FLOOR, or G in no signed set: normal
#                  path refused; recovery branch still operator-only.
# Release transition: approve {N} -> approve {N, N+1} (both boot) -> N+1
# healthy -> operator raises RELEASE_FLOOR to N+1 (N retired).
# Signer rotation: add (root signs deleg for the new signer) -> verify ->
# exercise recovery -> revoke (operator raises SIGNER_FLOOR). Never
# delete-first.
#
# Every refusal below comes from the TPM (a policy command or the unseal
# fails); the shell only compares outcomes.
#
# Exit: 0 PASS, 1 FAIL, 2 missing tools.

set -euo pipefail

usage() {
    echo "usage: $0 selftest" >&2
    exit 2
}
[[ $# -eq 1 && "$1" == "selftest" ]] || usage

# FLAG(sovereignty): whole script drives tpm2-tools (tpm2_* list below and every tpm2_ call to end of file, outside dep), host-only software-TPM sim; replace with in-house C TPM policy simulator.
for t in swtpm swtpm_ioctl tpm2_startup tpm2_pcrextend tpm2_createprimary \
    tpm2_create tpm2_load tpm2_unseal tpm2_startauthsession tpm2_policypcr \
    tpm2_policynv tpm2_policyor tpm2_policyauthorize tpm2_policysigned \
    tpm2_verifysignature tpm2_loadexternal tpm2_nvdefine tpm2_nvincrement \
    tpm2_nvread tpm2_nvwrite tpm2_flushcontext tpm2_changeauth tpm2_dictionarylockout openssl xxd cmp; do
    command -v "${t}" >/dev/null || {
        echo "Error: ${t} not installed (need swtpm, tpm2-tools, openssl, xxd)" >&2
        echo "TRUST1_GATE5_POLICY_SIM: FAIL"
        exit 2
    }
done

echo "NOTE: swTPM SIMULATION. This is never Machine 1 qualification."
echo "NOTE: throwaway test keys only; no real TPM is touched."

work="$(mktemp -d)"
SWTPM_PID=""
cleanup() {
    if [[ -n "${SWTPM_PID}" ]]; then
        kill "${SWTPM_PID}" 2>/dev/null || true
        wait "${SWTPM_PID}" 2>/dev/null || true
    fi
    rm -rf "${work}"
}
trap cleanup EXIT
trap 'exit 1' INT TERM HUP

fails=0
passes=0
pass() { echo "PASS  $*"; passes=$((passes + 1)); }
fail() { echo "FAIL  $*"; fails=$((fails + 1)); }
die() {
    echo "FAIL  setup: $*"
    [[ -f "${log:-}" ]] && tail -n 15 "${log}" >&2
    echo "TRUST1_GATE5_POLICY_SIM: FAIL"
    exit 1
}

# ---- swtpm (same pattern as scripts/test_trust1_measurement_tools.sh) ----
port=""
for _ in 1 2 3 4 5; do
    port=$((20000 + RANDOM % 20000))
    mkdir -p "${work}/tpm"
    swtpm socket --tpm2 --tpmstate dir="${work}/tpm" \
        --server type=tcp,port="${port}",bindaddr=127.0.0.1 \
        --ctrl type=tcp,port=$((port + 1)),bindaddr=127.0.0.1 \
        --flags not-need-init,startup-clear >"${work}/swtpm.log" 2>&1 &
    SWTPM_PID=$!
    export TPM2TOOLS_TCTI="swtpm:host=127.0.0.1,port=${port}"
    for _ in $(seq 1 50); do tpm2_pcrread sha256:0 >/dev/null 2>&1 && break; sleep 0.1; done
    tpm2_pcrread sha256:0 >/dev/null 2>&1 && break
    kill "${SWTPM_PID}" 2>/dev/null || true
    wait "${SWTPM_PID}" 2>/dev/null || true
    SWTPM_PID=""
done
[[ -n "${SWTPM_PID}" ]] || die "swtpm did not start"
ctrl="127.0.0.1:$((port + 1))"
log="${work}/tpm2.log"
q() { "$@" >>"${log}" 2>&1; }

OWNER_AUTH="throwaway-owner-$RANDOM$RANDOM"
RELEASE_FLOOR=0x01500010
SIGNER_FLOOR=0x01500011
PCRSEL="sha256:7,11"

k="${work}/keys"; d="${work}/pol"; mkdir -p "${k}" "${d}"
printf 'set' >"${d}/ref_set"
printf 'deleg' >"${d}/ref_deleg"
printf 'recovery' >"${d}/ref_recovery"

flush_all() {
    tpm2_flushcontext -t >/dev/null 2>&1 || true
    tpm2_flushcontext -s >/dev/null 2>&1 || true
    tpm2_flushcontext -l >/dev/null 2>&1 || true
}

# ---- throwaway keys ----
newkey() {
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
        -out "${k}/$1.key" 2>/dev/null || die "genpkey $1"
    openssl pkey -in "${k}/$1.key" -pubout -out "${k}/$1.pub.pem" 2>/dev/null
    tpm2_loadexternal -C o -G rsa -u "${k}/$1.pub.pem" -c "${k}/$1.ctx" \
        -n "${k}/$1.name" >>"${log}" 2>&1 || die "loadexternal $1"
    flush_all
}
for key in root relA relB operator attacker opattacker; do newkey "${key}"; done
# Throwaway Boot Signer stand-in: only its public fingerprint is measured.
boot_fp="$(openssl pkey -in "${k}/root.pub.pem" -pubin -outform DER 2>/dev/null |
    openssl dgst -sha256 -r | cut -c1-64)"
foreign_fp="$(printf 'foreign-boot-signer' | openssl dgst -sha256 -r | cut -c1-64)"

sig() { openssl dgst -sha256 -sign "${k}/$1.key" -out "$3" "$2"; }

# ---- NV counters (monotonic floors), owner-write, open read ----
# Dictionary-attack lockout would trip on the many deliberate refusals in
# this suite; raise the threshold for the simulation only.
q tpm2_dictionarylockout -s -n 1000 -t 1 -l 1 || die "DA parameters"
q tpm2_changeauth -c o "${OWNER_AUTH}" || die "set owner auth"
for idx in "${RELEASE_FLOOR}" "${SIGNER_FLOOR}"; do
    q tpm2_nvdefine "${idx}" -C o -P "${OWNER_AUTH}" -s 8 \
        -a "nt=counter|ownerwrite|authread|no_da" || die "nvdefine ${idx}"
    q tpm2_nvincrement -C o -P "${OWNER_AUTH}" "${idx}" || die "nvincrement ${idx}"
done
nvval() { tpm2_nvread -C "$1" "$1" 2>>"${log}" | xxd -p | tr -d '\n'; }
N=$((16#$(nvval "${RELEASE_FLOOR}")))
EA=$((16#$(nvval "${SIGNER_FLOOR}")))
EB=$((EA + 1))
N1=$((N + 1))
be64() { printf '%016x' "$1" | xxd -r -p; }
echo "INFO  release floor N=${N}, signer A epoch=${EA}, signer B epoch=${EB}"

# ---- expected PCR values from measurement lists ----
sha_hex() { openssl dgst -sha256 -r | cut -c1-64; }
pcr_chain() { # measurements (hex) -> final PCR hex
    local v
    v="$(printf '%064d' 0)"
    for m in "$@"; do v="$(printf '%s%s' "${v}" "${m}" | xxd -r -p | sha_hex)"; done
    echo "${v}"
}
sb_meas() { printf 'SecureBoot=%s' "$1" | sha_hex; }
manifest() { printf 'aienos-release-manifest-v1 generation=%s kernel=test-%s' "$1" "$1"; }
mf_meas() { manifest "$1" | sha_hex; }
# boot profile: sb(on|off) chain(owner|foreign) generation
expected_pcrs() { # -> file with PCR7||PCR11
    local fp="${boot_fp}"
    [[ "$2" == owner ]] || fp="${foreign_fp}"
    { pcr_chain "$(sb_meas "$1")" "${fp}"; pcr_chain "$(mf_meas "$3")"; } |
        tr -d '\n' | xxd -r -p >"$4"
}

# Power-cycle the swTPM (PCRs reset, NV kept) and replay one boot's
# measurements, like firmware + owner loader would.
boot() { # sb chain generation
    flush_all
    q swtpm_ioctl --tcp "${ctrl}" -i || die "swtpm power cycle"
    tpm2_startup -c >>"${log}" 2>&1 || true
    local fp="${boot_fp}"
    [[ "$2" == owner ]] || fp="${foreign_fp}"
    q tpm2_pcrextend "7:sha256=$(sb_meas "$1")" || die "extend"
    q tpm2_pcrextend "7:sha256=${fp}" || die "extend"
    q tpm2_pcrextend "11:sha256=$(mf_meas "$3")" || die "extend"
}

# ---- trial-session policy building ----
trial() { q tpm2_startauthsession -S "${d}/trial.ctx"; }
trial_end() {
    tpm2_flushcontext "${d}/trial.ctx" >/dev/null 2>&1 || true
}
branch_digest() { # gen out
    expected_pcrs on owner "$1" "${d}/pcrs_$1.bin"
    trial
    q tpm2_policypcr -S "${d}/trial.ctx" -l "${PCRSEL}" -f "${d}/pcrs_$1.bin" || die "trial pcr"
    be64 "$1" | q tpm2_policynv -S "${d}/trial.ctx" -i- "${RELEASE_FLOOR}" ule \
        -L "$2" || die "trial nv"
    trial_end
}
or_list() { # files... -> sha256:f1,f2
    local IFS=,
    echo "sha256:$*"
}
# make_set NAME SIGNER gen...: signed release set
make_set() {
    local name="$1" signer="$2"; shift 2
    local files=() g
    for g in "$@"; do
        branch_digest "${g}" "${d}/br_${name}_${g}.dig"
        files+=("${d}/br_${name}_${g}.dig")
    done
    if [[ $# -eq 1 ]]; then
        cp "${files[0]}" "${d}/set_${name}.dig"
    else
        trial
        q tpm2_policyor -S "${d}/trial.ctx" -l "$(or_list "${files[@]}")" \
            -L "${d}/set_${name}.dig" || die "trial or"
        trial_end
    fi
    printf '%s\n' "${files[@]}" >"${d}/set_${name}.branches"
    echo "${signer}" >"${d}/set_${name}.signer"
    cat "${d}/set_${name}.dig" "${d}/ref_set" >"${d}/set_${name}.msg"
    sig "${signer}" "${d}/set_${name}.msg" "${d}/set_${name}.sig"
}
# make_deleg NAME SIGNER EPOCH: Owner Root delegation to a Release Signer
make_deleg() {
    trial
    q tpm2_policyauthorize -S "${d}/trial.ctx" -n "${k}/$2.name" -q "${d}/ref_set" \
        -i /dev/null || die "trial authorize"
    be64 "$3" | q tpm2_policynv -S "${d}/trial.ctx" -i- "${SIGNER_FLOOR}" ule \
        -L "${d}/deleg_$1.dig" || die "trial deleg nv"
    trial_end
    echo "$2" >"${d}/deleg_$1.signer"
    echo "$3" >"${d}/deleg_$1.epoch"
    cat "${d}/deleg_$1.dig" "${d}/ref_deleg" >"${d}/deleg_$1.msg"
    sig root "${d}/deleg_$1.msg" "${d}/deleg_$1.sig"
}

flush_all
trial
q tpm2_policyauthorize -S "${d}/trial.ctx" -n "${k}/root.name" -q "${d}/ref_deleg" \
    -i /dev/null -L "${d}/root_branch.dig" || die "trial root branch"
trial_end
trial
q tpm2_loadexternal -C o -G rsa -u "${k}/operator.pub.pem" -c "${k}/operator.ctx" || die "load op"
q tpm2_policysigned -S "${d}/trial.ctx" -g sha256 -c "${k}/operator.ctx" -q "${d}/ref_recovery" \
    -L "${d}/recovery_branch.dig" || die "trial recovery branch"
trial_end
flush_all
trial
q tpm2_policyor -S "${d}/trial.ctx" \
    -l "$(or_list "${d}/root_branch.dig" "${d}/recovery_branch.dig")" \
    -L "${d}/sealed.dig" || die "trial sealed policy"
trial_end
flush_all

# ---- seal the throwaway secret ----
head -c 32 /dev/urandom >"${work}/secret.bin"
q tpm2_createprimary -C o -P "${OWNER_AUTH}" -c "${d}/prim.ctx" || die "createprimary"
seal_obj() { # policy-file out-prefix
    tpm2_flushcontext -t >/dev/null 2>&1 || true
    q tpm2_create -C "${d}/prim.ctx" -L "$1" -i "${work}/secret.bin" \
        -u "$2.pub" -r "$2.priv" -a "fixedtpm|fixedparent" || die "seal"
    tpm2_flushcontext -t >/dev/null 2>&1 || true
}
seal_obj "${d}/sealed.dig" "${d}/sealed"
# Negative-control object: same secret, sealed to a one-byte-mutated policy.
xxd -p "${d}/sealed.dig" | tr -d '\n' | sed 's/^\(..\)/ff/' | xxd -r -p >"${d}/mutated.dig"
cmp -s "${d}/sealed.dig" "${d}/mutated.dig" && die "mutation did not change policy"
seal_obj "${d}/mutated.dig" "${d}/mutated"
flush_all

# ---- runtime: one unseal attempt; returns 0 only if TPM releases secret ----
out="${work}/out.bin"
S="${work}/sess.ctx"
load_and_unseal() { # object-prefix
    q tpm2_createprimary -C o -P "${OWNER_AUTH}" -c "${work}/p.ctx" || return 1
    q tpm2_load -C "${work}/p.ctx" -u "$1.pub" -r "$1.priv" -c "${work}/o.ctx" || return 1
    tpm2_flushcontext -t >/dev/null 2>&1 || true
    rm -f "${out}"
    tpm2_unseal -c "${work}/o.ctx" -p "session:${S}" -o "${out}" >>"${log}" 2>&1 || return 1
    cmp -s "${out}" "${work}/secret.bin"
}
no_policy_unseal() { # plain password auth, no policy session
    flush_all
    q tpm2_createprimary -C o -P "${OWNER_AUTH}" -c "${work}/p.ctx" || return 1
    q tpm2_load -C "${work}/p.ctx" -u "${d}/sealed.pub" -r "${d}/sealed.priv" -c "${work}/o.ctx" || return 1
    tpm2_flushcontext -t >/dev/null 2>&1 || true
    rm -f "${out}"
    tpm2_unseal -c "${work}/o.ctx" -o "${out}" >>"${log}" 2>&1 || return 1
    cmp -s "${out}" "${work}/secret.bin"
}
# normal_path SET GEN DELEG [object]
normal_path() {
    local set="$1" gen="$2" deleg="$3" obj="${4:-${d}/sealed}"
    local signer dsigner depoch
    signer="$(cat "${d}/set_${set}.signer")"
    dsigner="$(cat "${d}/deleg_${deleg}.signer")"
    depoch="$(cat "${d}/deleg_${deleg}.epoch")"
    flush_all
    q tpm2_startauthsession --policy-session -S "${S}" || return 1
    q tpm2_policypcr -S "${S}" -l "${PCRSEL}" || return 1
    be64 "${gen}" | q tpm2_policynv -S "${S}" -i- "${RELEASE_FLOOR}" ule || return 1
    if [[ $(wc -l <"${d}/set_${set}.branches") -gt 1 ]]; then
        q tpm2_policyor -S "${S}" -l "$(or_list $(cat "${d}/set_${set}.branches"))" || return 1
    fi
    q tpm2_loadexternal -C o -G rsa -u "${k}/${signer}.pub.pem" -c "${work}/v.ctx" || return 1
    q tpm2_verifysignature -c "${work}/v.ctx" -g sha256 -m "${d}/set_${set}.msg" \
        -s "${d}/set_${set}.sig" -f rsassa -t "${work}/t1.tk" || return 1
    tpm2_flushcontext -t >/dev/null 2>&1 || true
    q tpm2_policyauthorize -S "${S}" -i "${d}/set_${set}.dig" -q "${d}/ref_set" \
        -n "${k}/${dsigner}.name" -t "${work}/t1.tk" || return 1
    be64 "${depoch}" | q tpm2_policynv -S "${S}" -i- "${SIGNER_FLOOR}" ule || return 1
    q tpm2_loadexternal -C o -G rsa -u "${k}/root.pub.pem" -c "${work}/v.ctx" || return 1
    q tpm2_verifysignature -c "${work}/v.ctx" -g sha256 -m "${d}/deleg_${deleg}.msg" \
        -s "${d}/deleg_${deleg}.sig" -f rsassa -t "${work}/t2.tk" || return 1
    tpm2_flushcontext -t >/dev/null 2>&1 || true
    q tpm2_policyauthorize -S "${S}" -i "${d}/deleg_${deleg}.dig" -q "${d}/ref_deleg" \
        -n "${k}/root.name" -t "${work}/t2.tk" || return 1
    q tpm2_policyor -S "${S}" -l "$(or_list "${d}/root_branch.dig" "${d}/recovery_branch.dig")" || return 1
    load_and_unseal "${obj}"
}
# recovery_path KEY [replay-from-file] [object]: fresh operator signature over nonceTPM
recovery_path() {
    local key="$1" replay="${2:-}" obj="${3:-${d}/sealed}"
    flush_all
    q tpm2_startauthsession --policy-session -S "${S}" || return 1
    q tpm2_loadexternal -C o -G rsa -u "${k}/${key}.pub.pem" -c "${work}/op.ctx" || return 1
    q tpm2_policysigned -S "${S}" -g sha256 -c "${work}/op.ctx" -q "${d}/ref_recovery" -x \
        --raw-data "${work}/tosign.bin" || return 1
    if [[ -n "${replay}" ]]; then
        cp "${replay}" "${work}/op.sig"
    else
        sig "${key}" "${work}/tosign.bin" "${work}/op.sig" || return 1
        cp "${work}/op.sig" "${work}/last_op.sig"
    fi
    q tpm2_policysigned -S "${S}" -g sha256 -c "${work}/op.ctx" -q "${d}/ref_recovery" -x \
        -s "${work}/op.sig" -f rsassa || return 1
    tpm2_flushcontext -t >/dev/null 2>&1 || true
    q tpm2_policyor -S "${S}" -l "$(or_list "${d}/root_branch.dig" "${d}/recovery_branch.dig")" || return 1
    load_and_unseal "${obj}"
}

allow() { # label cmd...
    local label="$1"; shift
    if "$@"; then pass "${label}: unsealed, secret byte-exact"; else
        fail "${label}: expected unseal, TPM refused"
        grep "ERROR" "${log}" | tail -n 2 >&2 || true
    fi
}
refuse() {
    local label="$1"; shift
    local mark where
    mark=$(wc -l <"${log}")
    if "$@"; then
        fail "${label}: expected TPM refusal, secret was released"
    else
        where="$(tail -n +"$((mark + 1))" "${log}" | grep -o 'Unable to run tpm2_[a-z]*' | tail -n 1 | sed 's/Unable to run //')"
        [[ -n "${where}" ]] && pass "${label}: refused by TPM at ${where}" ||
            pass "${label}: refused (secret mismatch)"
    fi
}

# ---- signed artefacts (all throwaway) ----
make_deleg A relA "${EA}"
make_set N relA "${N}"
make_set NN1 relA "${N}" "${N1}"
flush_all

echo "== current"
boot on owner "${N}"
allow "current: approved {N}, boot N" normal_path N "${N}" A

echo "== next (transition N -> N+1)"
boot on owner "${N1}"
refuse "next: boot N+1 under old set {N}" normal_path N "${N1}" A
allow "next: approved {N,N+1}, boot N+1" normal_path NN1 "${N1}" A
boot on owner "${N}"
allow "next: approved {N,N+1}, boot N still accepted" normal_path NN1 "${N}" A

echo "== invalid"
boot on owner "$((N1 + 5))"
refuse "invalid: unseal without any policy session" no_policy_unseal
refuse "invalid: manifest not in approved set" normal_path NN1 "$((N1 + 5))" A
boot off owner "${N}"
refuse "invalid: Secure Boot off" normal_path NN1 "${N}" A
boot on foreign "${N}"
refuse "invalid: non-owner boot chain" normal_path NN1 "${N}" A
boot on owner "${N}"
# Set signed by a key Owner Root never delegated to.
make_set ATK attacker "${N}" "${N1}"
# The attacker presents Owner Root's real delegation for signer A, but signs
# the release set with its own key (Owner Root never delegated to it).
echo attacker >"${d}/deleg_ATK.signer"; echo "${EA}" >"${d}/deleg_ATK.epoch"
cp "${d}/deleg_A.msg" "${d}/deleg_ATK.msg"; cp "${d}/deleg_A.sig" "${d}/deleg_ATK.sig"
cp "${d}/deleg_A.dig" "${d}/deleg_ATK.dig"
flush_all
refuse "invalid: release set signed by undelegated key" normal_path ATK "${N}" ATK
cp "${d}/set_NN1.sig" "${d}/sig.keep"
printf '\x01' | dd of="${d}/set_NN1.sig" bs=1 seek=17 conv=notrunc status=none
refuse "invalid: tampered release-set signature" normal_path NN1 "${N}" A
cp "${d}/sig.keep" "${d}/set_NN1.sig"
allow "invalid: control, restored signature accepted again" normal_path NN1 "${N}" A

echo "== retire N (N+1 healthy)"
if tpm2_nvincrement "${RELEASE_FLOOR}" -C "${RELEASE_FLOOR}" >>"${log}" 2>&1 ||
    tpm2_nvincrement -C o -P wrong-owner-auth "${RELEASE_FLOOR}" >>"${log}" 2>&1; then
    fail "retire: floor raised without operator authorization"
else
    pass "retire: raising the floor without operator authorization refused by TPM"
fi
q tpm2_nvincrement -C o -P "${OWNER_AUTH}" "${RELEASE_FLOOR}" || die "retire increment"
[[ $((16#$(nvval "${RELEASE_FLOOR}"))) -eq ${N1} ]] && pass "retire: release floor now N+1" ||
    fail "retire: release floor not N+1"
boot on owner "${N1}"
allow "retire: boot N+1 after retirement" normal_path NN1 "${N1}" A

echo "== rollback"
boot on owner "${N}"
refuse "rollback: boot retired N under {N,N+1}" normal_path NN1 "${N}" A
refuse "rollback: boot retired N under old signed {N}" normal_path N "${N}" A
if be64 "${N}" | tpm2_nvwrite -C o -P "${OWNER_AUTH}" -i- "${RELEASE_FLOOR}" >>"${log}" 2>&1; then
    fail "rollback: floor counter was overwritten"
else
    pass "rollback: floor counter cannot be written back (monotonic)"
fi

echo "== rotation (signer A -> B: add, verify, exercise recovery, revoke)"
make_deleg B relB "${EB}"
make_set NN1B relB "${N}" "${N1}"
flush_all
boot on owner "${N1}"
allow "rotation: add, new signer B accepted" normal_path NN1B "${N1}" B
allow "rotation: overlap, old signer A still accepted" normal_path NN1 "${N1}" A
refuse "rotation: B set with A delegation refused" normal_path NN1B "${N1}" A
allow "rotation: recovery exercised before revoke" recovery_path operator
if tpm2_nvincrement -C o -P wrong-owner-auth "${SIGNER_FLOOR}" >>"${log}" 2>&1 ||
    tpm2_nvincrement "${SIGNER_FLOOR}" -C "${SIGNER_FLOOR}" >>"${log}" 2>&1; then
    fail "rotation: signer floor raised without operator authorization"
else
    pass "rotation: raising the signer floor without operator authorization refused by TPM"
fi
q tpm2_nvincrement -C o -P "${OWNER_AUTH}" "${SIGNER_FLOOR}" || die "revoke increment"
refuse "rotation: revoked signer A refused" normal_path NN1 "${N1}" A
allow "rotation: signer B accepted after revoke" normal_path NN1B "${N1}" B

echo "== recovery (operator control only)"
boot off foreign "${N}"
allow "recovery: operator-approved unseal of emergency-only state" recovery_path operator
cp "${work}/last_op.sig" "${work}/replay.sig"
refuse "recovery: replayed operator signature (stale nonce)" recovery_path operator "${work}/replay.sig"
refuse "recovery: signature by non-operator key" recovery_path opattacker
refuse "recovery: normal path in emergency-only state" normal_path NN1B "${N}" B

echo "== negative controls (the harness can fail)"
boot on owner "${N1}"
if normal_path NN1B "${N1}" B "${d}/mutated"; then
    fail "control: object sealed to mutated policy released its secret"
else
    pass "control: object sealed to mutated policy refused by TPM"
fi
if recovery_path operator "" "${d}/mutated"; then
    fail "control: mutated object released secret via recovery"
else
    pass "control: mutated object refused on recovery path too"
fi
# A checker that should report failure does: allow() on a refused case.
saved_fails=${fails}
allow "control: (expected to report FAIL)" normal_path NN1 "${N1}" A >/dev/null 2>&1
if [[ ${fails} -eq $((saved_fails + 1)) ]]; then
    fails=${saved_fails}
    pass "control: allow() reports FAIL when the TPM refuses"
else
    fails=$((saved_fails + 1))
    echo "FAIL  control: allow() did not detect a refusal"
fi

echo "SUMMARY  pass=${passes} fail=${fails} (swTPM simulation, not Machine 1)"
flush_all
if [[ ${fails} -eq 0 && ${passes} -gt 0 ]]; then
    echo "TRUST1_GATE5_POLICY_SIM: PASS"
    exit 0
fi
echo "TRUST1_GATE5_POLICY_SIM: FAIL"
exit 1
