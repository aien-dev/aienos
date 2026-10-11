#!/usr/bin/env bash
# tests/gates/run.sh: the one entry point for the local verification gates of aienos.
# Every step runs the SAME command as the hosted job it mirrors (.github/workflows/ck-kernel.yml,
# native-suites.yml, crypto-boundary.yml, infer-crate.yml, crumb.yml; ci.yml is disabled on
# GitHub and its two surviving suites are declared here too). Manifests under tests/gates/ name
# this script plus one step word, so no manifest needs shell expansion (ADR 0028 P6).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
step="${1:?usage: tests/gates/run.sh <step>}"
obs() { printf 'AIEN-OBS %s %s\n' "$1" "$2"; }

# The hosted jobs keep the quiet flag and the QEMU gate lock in the runner's temp dir, never
# in ~/workspace (ck-kernel.yml, native-suites.yml). Same here.
TMP="$(mktemp -d /tmp/aienos-gate.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
export AIENOS_QUIET_FLAG="$TMP/spark-quiet"
export AIENOS_GATE_LOCK="$TMP/qemu-gate-lock"

# native-suites.yml: make must succeed AND every suite must print its own pass marker, and
# never NOT_RUN. $1 = suite dir, $2 = make targets, $3 = required marker regexes joined by |.
native_suite() {
  local suite="$1" targets="$2" req="$3" log="$TMP/suite.log" found=0
  set -o pipefail
  # native/crypto has no .gitignore for its out/ (the other suites do), so the build output
  # would stay in the tree; the hosted job throws its checkout away. Remove an out/ that this
  # step created, and only when git does not already ignore it. The gate itself is unchanged.
  if [ ! -e "native/$suite/out" ] && ! git check-ignore -q "native/$suite/out"; then
    CLEAN_OUT="$ROOT/native/$suite/out"
    trap 'rm -rf "$TMP" "$CLEAN_OUT"' EXIT
  fi
  # shellcheck disable=SC2086
  make -C "native/$suite" $targets 2>&1 | tee "$log"
  while IFS= read -r m; do
    grep -qE "$m" "$log" || { echo "missing marker: $m"; obs markers_missing 1; exit 1; }
    echo "found: $m"; found=$((found + 1))
  done < <(printf '%s\n' "$req" | tr '|' '\n')
  if grep -q 'NOT_RUN' "$log"; then echo 'NOT_RUN in log'; obs not_run_in_log true; exit 1; fi
  obs markers_found "$found"
  obs not_run_in_log false
}

case "$step" in
  crumb-verify)
    # Hosted crumb.yml builds the crumb tool from the aien-architecture commit in crumb.lock.
    # Same here, from the sibling checkout ../aien-architecture into a temp dir outside the
    # tree, so a newer crumb on PATH can never change the verdict.
    if [ ! -d ../aien-architecture ]; then
      echo "run.sh: ../aien-architecture is missing; the hosted job checks out aien-dev/aien-architecture at crumb.lock" >&2
      exit 3
    fi
    pin=$(tr -d '[:space:]' < crumb.lock)
    git -C ../aien-architecture archive "$pin" tools/crumb | tar -x -C "$TMP"
    make -s -C "$TMP/tools/crumb" crumb
    obs crumb_tool_commit "\"$pin\""
    "$TMP/tools/crumb/crumb" verify .
    ;;
  # ck-kernel.yml, host steps (ubuntu-24.04-arm there, AArch64 here)
  ck-host-tests)      make -C native/kernel test sanitize ;;
  ck-stage-tests)     make -C native/kernel stage-test stage-sanitize ;;
  ck-gate-selftest)   bash scripts/ck_gates.sh --self-test ;;
  ck-hold-selftest)   bash scripts/gate_hold_selftest.sh ;;
  ck-owner-keys)      bash scripts/ck_owner_keys_check.sh ;;
  # ck-kernel.yml, QEMU TCG gates: every gate with a C implementation except FPU and INFER
  ck-qemu-gates)
    mkdir -p "$TMP/ck-receipt"
    set +e
    bash scripts/ck_gates.sh --out "$TMP/ck-receipt" | tee "$TMP/ck-gates.txt"
    rc=${PIPESTATUS[0]}
    set -e
    echo "ck_gates.sh exit ${rc}"
    [ "${rc}" = 0 ] || exit 1
    required=$(sed -n "/^CK_GATE_TABLE='/,/^'/p" scripts/ck_gates.sh | awk -F'|' 'NF==3 && $2!="missing" && $1!="FPU" && $1!="INFER" {print $1}')
    [ -n "${required}" ] || { echo "could not read the gate table"; exit 1; }
    fail=0; n=0
    for g in ${required}; do
      if grep -q "^AIENOS_CK_${g}: PASS" "$TMP/ck-gates.txt"; then echo "required gate ${g}: PASS"; n=$((n + 1))
      else echo "required gate ${g}: not PASS"; fail=1; fi
    done
    obs required_gates_pass "$n"
    exit ${fail}
    ;;
  ck-b7b-probe)
    bash scripts/qemu_ck_b7b_probe_test.sh --self-test
    bash scripts/qemu_ck_b7b_probe_test.sh
    bash scripts/qemu_ck_b7b_probe_test.sh --positive
    ;;
  # native-suites.yml matrix
  native-net)        native_suite net "test sanitize mutants" 'AIENOS_NET_SECURE_TESTS: PASS|NET_SANITIZE: PASS|NET_SECURE_MUTANTS: [0-9]+/[0-9]+ killed' ;;
  native-sig)        native_suite sig "test sanitize mutants" 'AIENOS_SIG_NATIVE: PASS|AIENOS_SIG_MUTANTS: PASS' ;;
  native-crypto)     native_suite crypto "test sanitize mutants" 'AIENOS_CRYPTO_NATIVE: PASS|AIENOS_CRYPTO_MUTANTS: PASS' ;;
  native-m5)         native_suite m5 "test sanitize mutants" 'M5_NATIVE: PASS|M5_NATIVE_MUTANTS: PASS' ;;
  native-disk)       native_suite disk "test sanitize mutants" 'AIENOS_DISK_NATIVE: PASS|AIENOS_DISK_SANITIZE: PASS|AIENOS_DISK_MUTANTS: PASS' ;;
  native-argus)      native_suite argus "test sanitize" 'GATE CONTAIN_TEST PASS|GATE CONTAIN_DETERMINISM PASS' ;;
  native-capability) native_suite capability "mutants" 'AIENOS_CAP_MUTANTS: PASS' ;;
  disk-qemu)
    set -o pipefail
    bash scripts/qemu_native_nvme_test.sh 2>&1 | tee "$TMP/qemu.log"
    # The script exits 0 on NOT_RUN; only an explicit PASS counts.
    grep -qx 'AIENOS_STORE_NVME_QEMU: PASS' "$TMP/qemu.log"
    ;;
  # crypto-boundary.yml (one job, four commands)
  crypto-boundary)
    cargo test --locked --offline -p aienos-crypto
    cargo test --locked --offline -p aienos-kernel crypto::
    cargo clippy --locked --offline -p aienos-crypto --all-targets -- -D warnings
    cargo check --locked --offline -p aienos-kernel --target aarch64-unknown-none --no-default-features
    ;;
  # infer-crate.yml (one job: fmt, clippy, test, no_std build)
  infer-crate)
    export AIENOS_MODEL="${AIENOS_MODEL:-/nonexistent/no-model.gguf}"  # hosted runner has no model file; forward tests SKIP
    test -f crates/aienos-infer/Cargo.toml
    cargo fmt -p aienos-infer --check
    cargo clippy -p aienos-infer --all-targets -- -D warnings
    cargo test -p aienos-infer
    cargo build -p aienos-infer --target aarch64-unknown-none
    ;;
  # ci.yml (disabled on GitHub since the CK workflow took over): the suites it still names
  store-native)      make -C native/store test mutants ;;
  verify-all)        bash scripts/verify_all.sh ;;
  zero-disk-secrets)
    echo "Auditing repository for prohibited plaintext secret files..."
    if find . -maxdepth 4 -name ".env*" -not -path "*/.git/*" -not -path "*/target/*" -not -path "*/vendor/*" | grep -q .; then
      echo "::error::Prohibited plaintext .env file found. Use an approved AIEN SecretProvider."
      obs env_files_found true
      exit 1
    fi
    obs env_files_found false
    echo "Zero plaintext .env files verified."
    ;;
  *)
    echo "run.sh: unknown step '$step'" >&2
    exit 2
    ;;
esac
