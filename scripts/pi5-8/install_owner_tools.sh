#!/usr/bin/env bash
# install_owner_tools.sh -- PI5-8 Q2: install the YubiKey tools the owner-key ceremony needs. Host only; never touches a YubiKey.
#
#   scripts/pi5-8/install_owner_tools.sh
#
# Why not the Ubuntu packages: Ubuntu 24.04 ships yubico-piv-tool 2.2.0 and yubikey-manager 5.2.1. PIV Ed25519 keys need
# yubico-piv-tool >= 2.5.0 (its NEWS: "Add support for ED25519 and X25519 key types. Available in firmware 5.7.0 and newer")
# and a YubiKey with firmware >= 5.7. This script builds the newest released yubico-piv-tool from Yubico's official source tarball
# and installs yubikey-manager (ykman, read-only status and checks) into a private virtual environment.
#
# Checks before anything is built: the tarball sha256 is pinned below, and the detached OpenPGP signature must verify against
# Yubico's signing key (primary key 1D73 08B0 055F 5AEF 3694 4A8F 27A9 C24D 9588 EA0F, listed on
# https://developers.yubico.com/Software_Projects/Software_Signing.html), fetched from keys.openpgp.org into a throw-away keyring.
# Needs (apt): pcscd libpcsclite-dev libssl-dev cmake gcc pkg-config check zlib1g-dev gengetopt help2man swig python3-venv gnupg.
# The smart card daemon also needs a polkit rule when you run from a non-graphical login; see docs/native/PI5-8-OWNER-CEREMONY.md.
set -euo pipefail
ver=2.7.3
url="https://developers.yubico.com/yubico-piv-tool/Releases/yubico-piv-tool-${ver}.tar.gz"
sha=fcb25c42f54298ece8b20684fb3c581ed9195a162cbc55180a4161501be93181
primary=1D7308B0055F5AEF36944A8F27A9C24D9588EA0F
ykman_ver=5.9.2
ykman_whl_sha=19a1173106b104bea37722e61ce748fb2d39c87a02880c1964461837ddaa7fba
prefix="${AIENOS_OWNER_TOOLS:-$HOME/.local}"
work="$(mktemp -d)"; trap 'rm -rf "${work}"' EXIT
mkdir -p "${work}/dl" "${work}/src" "${work}/build" "${work}/gnupg"; chmod 700 "${work}/gnupg"
curl -fsSL -o "${work}/dl/t.tar.gz" "${url}"
curl -fsSL -o "${work}/dl/t.tar.gz.sig" "${url}.sig"
[ "$(sha256sum < "${work}/dl/t.tar.gz" | cut -d' ' -f1)" = "${sha}" ] || { echo "REFUSED: tarball sha256 differs from the pinned value" >&2; exit 1; }
export GNUPGHOME="${work}/gnupg"
gpg --batch --quiet --keyserver hkps://keys.openpgp.org --recv-keys "${primary}"
st="$(gpg --batch --status-fd 1 --verify "${work}/dl/t.tar.gz.sig" "${work}/dl/t.tar.gz" 2>/dev/null || true)"
grep -q '^\[GNUPG:\] GOODSIG' <<<"${st}" && grep -q "^\[GNUPG:\] VALIDSIG .* ${primary}\$" <<<"${st}" \
    || { echo "REFUSED: signature does not verify against Yubico's key ${primary}" >&2; exit 1; }
echo "tarball sha256 and Yubico OpenPGP signature verified (${ver})"
tar -xzf "${work}/dl/t.tar.gz" -C "${work}/src"
cmake -S "${work}/src/yubico-piv-tool-${ver}" -B "${work}/build" -DCMAKE_INSTALL_PREFIX="${prefix}/yubico-piv-tool" >/dev/null
make -C "${work}/build" -j"$(nproc)" >/dev/null
make -C "${work}/build" install >/dev/null
python3 -m venv "${prefix}/ykman-venv"
"${prefix}/ykman-venv/bin/pip" download -q --no-deps "yubikey-manager==${ykman_ver}" -d "${work}/dl"
[ "$(sha256sum < "${work}/dl/yubikey_manager-${ykman_ver}-py3-none-any.whl" | cut -d' ' -f1)" = "${ykman_whl_sha}" ] \
    || { echo "REFUSED: ykman wheel sha256 differs from the pinned value" >&2; exit 1; }
"${prefix}/ykman-venv/bin/pip" install -q "yubikey-manager==${ykman_ver}"
LD_LIBRARY_PATH="${prefix}/yubico-piv-tool/lib" "${prefix}/yubico-piv-tool/bin/yubico-piv-tool" --version
"${prefix}/ykman-venv/bin/ykman" --version
