# PI5-8 Q2: the owner-key ceremony (PERFORMED 2026-10-14)

Status: performed once, by Drake, on 2026-10-14 at 11:45Z. `CEREMONY_REAL: PASS`. The owner key is an Ed25519 key in PIV slot
9c of YubiKey serial 39017074. Public key `owner_root_ed25519 578ada3cb0c2d154623ac089191023c8ad4bc5e63b8ccd1a38db2d679b8c9e76`,
owner file sha256 `9d2aabd949c71aa5e3d618e9182af1ce58bb8a2b52e10006caf0af2ceb34d181`. Re-checked afterwards with a separate
tool: openssl verifies the ceremony signature over the ceremony statement; `ykman piv info` shows no factory PIN, PUK or
management key (management key AES256), PIN tries 3/3, PUK tries 3/3, slot 9C occupied.

Deviation from the plan below, by Drake's decision: the Spark was ONLINE. It has no screen output (it boots without a display,
and the graphics driver offers no display connectors), so the ceremony ran over an ssh login from Drake's MacBook on the home
network, with Drake beside the Spark to touch the key. The script was run as
`owner_ceremony.sh --real --online-by-owner-decision`. That flag skips only the offline check, prints the network state, and
writes it into `ceremony-report.txt` (`checks: network offline NOT CHECKED: ONLINE by owner decision ...`). Without the flag,
`--real` still refuses while the Spark is online. What stays true: the private key was generated inside the YubiKey and never
left it; the PIN, PUK and management key were typed by Drake and never seen, stored or logged by the script. What is weaker: the
PIN, PUK and management key crossed the home network inside the encrypted ssh session.

The text below is the plan as prepared before the ceremony.

## What this is

The OWNER key is an Ed25519 key made inside Drake's YubiKey (PIV application, slot 9c, YubiKey 5C NFC, firmware 5.7.4). The
private half never leaves the device. It does two jobs:

1. It signs the PI5-8 receipts manifest (`scripts/pi5_receipts_manifest.sh`), so anyone can check the Pi test evidence
   was approved by the owner.
2. Its public half is the owner public key built into images: `make -C native/kernel full CK_HARDWARE_STAGING=1
   CK_OWNER_PUBKEYS=<file> CK_MACHINE_ID=<file>` (see `native/kernel/README.md`, "Owner provisioning").

Added after the ceremony (aienos#387): it also signs Omega realization receipts, and the kernel's receipt policy
trusts it for them. The entry and its limits are in `docs/OWNER_KEY_CEREMONY.md` section 7.

It is NOT the public-release signing key. That key is generated only at the first public release and is not touched here.

## Tools (installed on the Spark, verified)

Ubuntu 24.04's packages are too old: yubico-piv-tool 2.2.0 and yubikey-manager 5.2.1. Yubico's own yubico-piv-tool NEWS lists
"Add support for ED25519 and X25519 key types. Available in firmware 5.7.0 and newer" in 2.5.0 (2024-01-31), so Ed25519 needs
yubico-piv-tool 2.5.0 or newer and a YubiKey with firmware 5.7 or newer. Drake's key is 5.7.4.

| Tool | Version | Source | sha256 |
| --- | --- | --- | --- |
| yubico-piv-tool | 2.7.3 (2026-01-20, newest release) | https://developers.yubico.com/yubico-piv-tool/Releases/yubico-piv-tool-2.7.3.tar.gz, built from source | fcb25c42f54298ece8b20684fb3c581ed9195a162cbc55180a4161501be93181 |
| tarball signature | good, key A8CE 1679 14EE E232 B923 7B54 10CA C496 2E03 C7CC, a subkey of 1D73 08B0 055F 5AEF 3694 4A8F 27A9 C24D 9588 EA0F, which is on https://developers.yubico.com/Software_Projects/Software_Signing.html | | |
| yubikey-manager (ykman) | 5.9.2 (2026-06-30) | PyPI, in a private virtual environment (used for read-only status and checks) | wheel 19a1173106b104bea37722e61ce748fb2d39c87a02880c1964461837ddaa7fba |
| pcscd | 2.0.3 (Ubuntu) | apt | |

`scripts/pi5-8/install_owner_tools.sh` repeats the whole install and refuses if the tarball sha256 or the OpenPGP signature
does not match. It installs under `~/.local`. The smart card service on this Spark also needed one small permission rule so a
non-graphical login may talk to the card reader: `/etc/polkit-1/rules.d/49-aienos-pcsc-drake.rules` (allows user drakestapleton
only the two pcsc actions).

## Signing design: what exact bytes the YubiKey signs

PIV Ed25519 is pure Ed25519 (RFC 8032): the YubiKey signs the message it is sent, with no hash wrapper, and returns the 64-byte
signature. `yubico-piv-tool --sign -A ED25519` sends the raw input file and refuses input of 3072 bytes or more
(`YKPIV_OBJ_MAX_SIZE`, "File too big"). A real manifest is longer than that, and the card's own limit is not documented in
what we could read. So the key signs a small FIXED STATEMENT that binds the manifest. Exactly four lines, each ending in LF:

```
AIENOS-OWNER-STATEMENT-V1
purpose pi5-8-receipts-manifest
manifest_bytes <decimal length of the manifest>
manifest_sha256 <64 lowercase hex, sha256 of the manifest bytes>
```

`native/kernel/tools/ck_manifest_sig.c` builds and checks these bytes:

- `statement MANIFEST OUT` writes the statement (this is the file the YubiKey signs).
- `verify MANIFEST SIG PUBKEYHEX` rebuilds the statement from the manifest it is given and checks a plain Ed25519
  signature over it with the in-tree verifier. Change one manifest byte and the statement changes, so the signature fails.
- `sign-test` signs the statement with the public RFC 8032 TEST 1 key (output says TEST ONLY).

A signature over the raw manifest bytes (the Q6 scheme) is no longer accepted. `scripts/ck_pi5_manifest_check.sh` proves:
statement bytes equal the spec and an independent `sha256sum`; TEST key round trip; tampered manifest, tampered signature,
wrong key and a raw-manifest signature all fail; an openssl Ed25519 software key (TEST, standing in for the YubiKey)
signs the statement and the in-tree verifier accepts it. That is two independent Ed25519 implementations agreeing.

UNVERIFIED until the real ceremony: that this YubiKey firmware returns exactly the pure Ed25519 signature over those bytes.
The ceremony checks it in step 6 and stops if the two verifiers do not agree.

## Owner public key file

The YubiKey exports the public key as PEM (SubjectPublicKeyInfo). For Ed25519 the DER form is 12 fixed bytes
`30 2a 30 05 06 03 2b 65 70 03 21 00` followed by the 32 key bytes. `scripts/pi5-8/owner_pubkey_file.sh PUBKEY.pem OUTFILE
["comment"]` checks those 12 bytes exactly (anything else, such as RSA, P-256, X25519 or an all-equal key, is refused), takes the
32 bytes and writes the file the image build reads:

```
# AIENOS owner public key. PUBLIC material only ...
owner_root_ed25519 <64 lowercase hex>
```

It prints the sha256 of the file. The ceremony then runs the same checker the image build uses (`ck_owner_gen`), which also
refuses the RFC 8032 TEST keys.

Pi images: the Makefile deliberately refuses `CK_HARDWARE_STAGING` together with any `CK_PI5*` flag, so there is no Pi image with
an owner key today (every Pi image is a TEST-key qualification tier). `scripts/ck_pi5_owner_check.sh` therefore proves the owner
file on the hardware staging image (`make full CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS=...`): the image carries the owner public
key; it has no `artifact_trust: seed0b-test qualification build ... TEST ONLY` banner, no TEST Store label, no TEST machine id;
the TEST-anchor image is the positive control (has the banner, not the key); and the Makefile refuses a TEST key as owner key and
refuses mixing the owner image with the Pi or TEST-anchor tiers.

## Drake's step list (real ceremony), about 25 minutes

Before (can be done days earlier, 10 minutes, network may be up):

1. On paper, write three things: the new PIN (6 to 8 characters, letters and digits allowed), the new PUK (6 to 8 characters) and
   a management key. For the management key open a terminal and type `openssl rand -hex 32`; it prints 64 letters and digits
   (0-9 and a-f). Copy it onto the paper by hand. Keep the paper in a safe place. (It prints a secret on screen once; that is
   the only time.)
2. Rehearse: in a terminal in the repository type `scripts/pi5-8/owner_ceremony.sh --dry-run`. It uses a software key, never
   touches the YubiKey, and ends with `CEREMONY_DRY_RUN: PASS`.

The ceremony (sit at the Spark keyboard and screen, not over a remote login):

3. Plug the YubiKey into the Spark. Unplug the network cable and turn Wi-Fi off. Wait ten seconds.
4. Type `scripts/pi5-8/owner_ceremony.sh --real` and press Enter. If you see `REFUSED: the Spark is still online`, the network is
   not fully down: nothing was touched, fix it and run it again.
5. The screen shows the YubiKey model, serial number and firmware. Compare the serial with the one on your key. Type `YES`.
6. It asks for the new PIN twice, the new PUK twice, and the new management key twice (type from your paper; nothing shows on
   screen while you type). It stops if any of them is still the factory value afterwards.
7. It asks for the management key once more and creates the key inside the YubiKey. You see `Successfully generated a new private key.`
8. It shows the public key, the owner file hash, and then says the key will sign a test text: type the PIN and TOUCH the metal
   contact of the key when it blinks.
9. You see `Signature verified two ways`, `A changed manifest is refused, as it must be.` and `CEREMONY_REAL: PASS`.
10. Reconnect the network. Copy `owner-pubkeys.txt` and `owner-pubkeys.txt.sha256` from the folder it names (under
    `~/aienos-owner-ceremony/`). They are public. Write the sha256 on the paper too.

Later, to sign the PI5-8 manifest with the YubiKey: `scripts/pi5_receipts_manifest.sh --all <runs-root> > manifest.txt`, then
`scripts/pi5-8/owner_ceremony.sh --sign-manifest manifest.txt manifest.sig owner-pubkeys.txt` (PIN, then touch). It first checks
that the key in the slot is the owner key in the file, and verifies the signature before finishing.

What the real mode writes to the YubiKey: new PIN, new PUK, new management key, and one key in slot 9c. It refuses if slot 9c
already holds a key and never overwrites one. It never receives, shows or stores a PIN, PUK or management key: the YubiKey tool
asks for them on the terminal. The only values it passes itself are the public factory defaults (PIN 123456, PUK 12345678), and
only while the YubiKey still reports the factory values.

State of Drake's YubiKey when this was prepared (read-only checks on 2026-10-13): PIV PIN tries 3 of 3, PUK tries 3 of 3, PIN, PUK and
management key all still the FACTORY defaults (management key algorithm AES192), no certificates, and every key slot empty.

## If something goes wrong

- Wrong PIN three times: the PIN is blocked. Unblock it with the PUK: `yubico-piv-tool -a unblock-pin` (asks for the PUK, then a
  new PIN). Do not guess further.
- Wrong PUK three times as well: the PIV application can only be reset (`ykman piv reset`), which ERASES the owner key. Do that
  only on Drake's say. A new ceremony then makes a NEW owner key, so images and signatures made with the old key stop being trusted.
- Lost or broken YubiKey: the owner key is gone; run a new ceremony with a new key and rebuild what carries the public key.
- Touch missed: the signing step fails; run it again. Nothing was damaged.
- The management key typed wrong once is harmless; there is no retry counter on it. If it is truly lost, the only remedy is the
  reset above, so keep the paper.
- The PAPER RECOVERY SECRET is a different thing. It is the Store backup (PD1: paper backup plus YubiKey unlock) and is not in the
  YubiKey and not made here. Losing the YubiKey does not lose it; losing the YubiKey does mean the owner key must be redone.

## What is NOT done

- No owner key exists yet. Nothing was written to Drake's YubiKey (only read-only commands were run: `ykman info`, `ykman piv info`,
  `yubico-piv-tool -a list-readers`, `-a version`, `-a status`).
- No release signing key: it is generated only at the first public release.
- No machine id or Store uuid file, no image built with a real owner key, no manifest signed for real.
- No Pi run. The real mode and the YubiKey signing bytes are UNVERIFIED on hardware; the dry run and the tests use software keys only.
