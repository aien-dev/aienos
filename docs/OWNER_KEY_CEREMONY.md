# Owner key ceremony: step by step (MacBook, Wi-Fi off)

STATUS: PREPARED, NOT RUN. Written 2026-10-12 for the owner's decision of
that day: "generate the owner signing key on the MacBook, offline (Wi-Fi
off), only while the owner is present; prepare the instructions and the
backup and recovery procedure now." Nothing on this page has been done with
a real key. Every command on it was run on 2026-10-12 with a throwaway key
and a throwaway passphrase on the Spark (Linux, OpenSSL 3.0.13) in a scratch
folder outside the repository; lines marked **check on the MacBook** are the
places where macOS may behave differently and nobody has tried them there.
SECURITY_IMPACT: KEYS (procedure only; no key material, no code that runs on
a machine).

**No private key, passphrase or backup copy ever goes into this repository,
onto the Spark, or into a chat.** Only the public key, its fingerprints and
signatures leave the MacBook (part 5).

This page is the plain-language companion of two existing pages and does
not replace them: `docs/TRUST-1-OPERATOR-STEPS.md` Step 8 (the TRUST-1 Gate 3
ceremony) and `docs/TRUST-1-ATTENDED-PACKAGE.md` Sitting E (what evidence the
sitting leaves). It uses the same tool they use,
`scripts/trust1_key_ceremony.sh`, so there is one ceremony and one owner
key, not two.

**Depends on:** the `ck_slot_tool tbs --pubkey` fix in aienos#324 (branch
`native-v1/p11-package-provenance`). Before that fix, a real OpenSSL signature
could never be attached to a slot manifest (the tool emitted the bytes to
sign with an empty signer field, then checked the signature with the signer
field filled in). Part 3, step 9 needs the fixed tool. Do not hold the
ceremony before that fix is merged.

---

## 1. What the key is and what it protects

Think of the owner key as the one signature stamp that the Spark will
believe. It comes in two halves:

- **The private half** (`owner_root.key.pem`) makes signatures. Whoever has it
  can make the Spark accept new software as yours. It is created on the
  MacBook, locked with your passphrase from the first moment (the tool never
  writes it unlocked to disk), and it never leaves the MacBook except on the
  two backup sticks.
- **The public half** (`owner_root.pub.pem`) only checks signatures. It is
  safe to copy anywhere. The Spark gets this half.

What it protects, in this project:

- **Which software the native machine will start.** Every AIENOS image slot
  carries a manifest (a small signed label saying "this exact image,
  generation N, built from commit C") signed by the Owner Root Ed25519 key
  (`native/boot/slot_format.h`, lines 32-33; `docs/NATIVE_IMAGE_SLOTS.md`
  section 6). The loader starts an image only if that signature checks out
  under a trusted owner public key (`native/boot/slot_select.c`,
  `ck_slot_select`).
- **Which release package is yours.** A package's manifest binds the whole
  package (image, `PACKAGE.txt`, `SHA256SUMS`) through one signature
  (`docs/NATIVE_PACKAGE.md`, "What a package is").
- **The TRUST-1 key hierarchy.** The same tool also creates the Boot Signer,
  Release Signer and Operator Approval keys and an authority manifest signed
  by the Owner Root (`scripts/trust1_key_ceremony.sh`, header;
  `docs/TRUST-1-OPERATOR-STEPS.md` Step 8). This page focuses on the Owner
  Root because that is the key the slot manifests use today.

Open point recorded, not decided here: the TRUST-1 hierarchy says the
Release Signer "signs kernels and manifests under the loader"
(`scripts/trust1_key_ceremony.sh`, `role.release_signer.duty`), while the
slot format today trusts the Owner Root directly for slot manifests
(`native/boot/slot_format.h` line 32). Which key signs routine releases is
a later design decision; this ceremony creates both, so either answer works
without a second ceremony.

**Two fingerprints, both correct, do not mix them up.** The ceremony record
prints `role.owner_root.pub_sha256`: the SHA-256 of the public key in its
44-byte standard file form. The slot manifests use `signer_id`: the SHA-256
of the bare 32-byte public key (`ck_slot_tool.c`, `sha256_hash(pk, 32,
m->signer_id)`). They are different numbers for the same key. On
2026-10-12's throwaway key they were `73459826...` and `b77a9844...`.

## 2. Preparation (do this the day before, while the MacBook is online)

What to have on the table:

- The MacBook, charged, with Homebrew installed.
- **Two new USB sticks** for the backups. Label them by hand "OWNER KEY A"
  and "OWNER KEY B". They hold the locked private key; they will be stored in
  two different places.
- **A third stick** labelled "TRANSFER". It carries public files only, between
  the MacBook and the Spark.
- **Paper and a pen**: one sheet for the passphrase (stored apart from the
  sticks), one printout of the checklist in part 6.
- About 45 minutes with no interruptions.

Steps (in the Terminal app on the MacBook; open it from Applications >
Utilities > Terminal):

1. **Install OpenSSL 3.** macOS ships a different program called LibreSSL
   under the name `openssl`; the ceremony tool refuses it
   (`scripts/trust1_key_ceremony.sh`, `check_tools`). Type:

   ```
   brew install openssl@3
   ```

   *What it does:* downloads and installs OpenSSL 3. *Changes:* adds a
   program to the MacBook; nothing else. *Success:* it ends without an
   "Error" line.

2. **Tell the Terminal where it is.** Type:

   ```
   export AIENOS_OPENSSL=/opt/homebrew/opt/openssl@3/bin/openssl
   ```

   *What it does:* sets a name for this Terminal window only; the ceremony
   tool and the commands below use it. *Changes:* nothing on disk.
   **Check on the MacBook:** `/opt/homebrew` is Homebrew's home on Apple
   chips; on an older Intel Mac it is `/usr/local/opt/openssl@3/bin/openssl`
   (Homebrew documentation, "Installation", default prefix). The same path is
   used in `docs/TRUST-1-OPERATOR-STEPS.md` Step 8. You must type this line
   again in every new Terminal window.

3. **Check the version.** Type:

   ```
   "$AIENOS_OPENSSL" version
   ```

   *Changes:* nothing. *Success:* a line starting `OpenSSL 3.` If it says
   `LibreSSL` or "No such file", step 1 or 2 did not work: stop.

4. **Copy the ceremony tool to the MacBook.** An agent puts
   `trust1_key_ceremony.sh` on the TRANSFER stick, together with its SHA-256
   fingerprint printed on paper. Copy it to your home folder:

   ```
   cp /Volumes/TRANSFER/trust1_key_ceremony.sh ~/
   "$AIENOS_OPENSSL" dgst -sha256 ~/trust1_key_ceremony.sh
   ```

   *Changes:* copies one file. *Success:* the long number printed matches the
   one on paper, character for character. If it does not match, stop.
   **Check on the MacBook:** the stick appears under `/Volumes/` with the
   name you gave it; use that name instead of `TRANSFER` if different.

5. **Plug in each backup stick once** to make sure the MacBook sees it, then
   eject it. Use Disk Utility to format any stick that is not empty (format:
   "APFS" or "Mac OS Extended"; **check on the MacBook** which one Disk
   Utility offers).

## 3. The ceremony (owner present, Wi-Fi off)

Type every command in the same Terminal window. Run step 2 of part 2 again
first if the window is new.

1. **Turn Wi-Fi off** (menu bar Wi-Fi icon, switch off) and unplug any network
   cable or adapter. Leave it off until part 3 is finished.

2. **Preflight.** Type:

   ```
   bash ~/trust1_key_ceremony.sh preflight
   ```

   *What it does:* checks the OpenSSL version and that no network route
   exists. *Changes:* nothing. *Success:* `openssl: OpenSSL 3...`,
   `host: Darwin ...` and `network: offline`. If it says a network route
   exists, Wi-Fi is still on: fix that and run it again.
   **Check on the MacBook:** on macOS the tool decides "offline" with
   `route -n get default` (`network_route` in the tool); nobody has run it on
   the MacBook yet.

3. **Generate the keys.** Type:

   ```
   bash ~/trust1_key_ceremony.sh generate ~/aienos-ceremony-gen1
   ```

   *What it does:* asks for your passphrase twice (nothing shows while you
   type; that is normal), then creates the Owner Root, Release Signer and
   Operator Approval keys (Ed25519) and the Boot Signer (RSA-2048
   certificate), each private key locked with the passphrase from the start
   (`openssl genpkey ... -aes-256-cbc`), and signs an authority manifest
   with the Owner Root. The passphrase must be at least 12 characters; use a
   long sentence. Write it on the passphrase sheet now.
   *Changes:* creates the folder `~/aienos-ceremony-gen1` only (it refuses if
   the folder exists). Rows of dots and plus signs while the RSA key is made
   are normal. *Success:* six `PASS` lines and a final
   `generated: ...` line. Write the `manifest_sha256=` value on the
   checklist.

4. **Make the owner public key file for the Spark.** Type these three lines:

   ```
   cd ~/aienos-ceremony-gen1/public
   PK=$("$AIENOS_OPENSSL" pkey -pubin -in owner_root.pub.pem -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n')
   printf 'owner_root_ed25519 %s\n' "$PK" > owner_pubkeys.txt; cat owner_pubkeys.txt
   ```

   *What it does:* takes the bare 32-byte public key out of the standard file
   (the standard file is a fixed 12-byte header plus those 32 bytes; on
   2026-10-12 the header read `302a300506032b6570032100` and the file was 44
   bytes), writes it as 64 hex characters in the format the Spark's tools
   read (`owner_root_ed25519 <64 hex>`, `ck_slot_tool.c` `load_keys`,
   `ck_owner_gen.c` header). *Changes:* creates `owner_pubkeys.txt` in the
   public folder. *Success:* one line, `owner_root_ed25519 ` followed by
   exactly 64 characters from 0-9 and a-f. **Check on the MacBook:** `od` on
   macOS is the BSD version, not the GNU one used for the test; nobody has
   run this exact line there yet. The result must still be 64 characters.

5. **Compute the signer id.** Type:

   ```
   "$AIENOS_OPENSSL" pkey -pubin -in owner_root.pub.pem -outform DER | tail -c 32 | "$AIENOS_OPENSSL" dgst -sha256 -r | cut -c1-64 | tee signer_id.txt
   ```

   *What it does:* the SHA-256 of the bare public key, exactly how
   `ck_slot_tool` makes `signer_id` (`sha256_hash(pk, 32, m->signer_id)`).
   On 2026-10-12 the value this printed for the throwaway key matched the
   `signer_id=` that `ck_slot_tool show` printed for a manifest signed with
   it. *Changes:* creates `signer_id.txt`. *Success:* 64 hex characters.
   Write the first 16 and last 16 on the checklist.

6. **Back up to stick A.** Plug in OWNER KEY A. Type (use the stick's real
   name after `/Volumes/`):

   ```
   bash ~/trust1_key_ceremony.sh backup ~/aienos-ceremony-gen1 "/Volumes/OWNER KEY A" backup-A
   ```

   *What it does:* asks for the passphrase, copies the locked private keys and
   the public files into a folder `aienos-owner-keys-gen1` on the stick, then
   opens every key **from the stick's copy** to prove the copy works.
   *Changes:* writes that folder on the stick; adds one line to
   `public/backups.txt`. *Success:* four `PASS  backup-A: ... decrypts from
   the backup copy` lines and `recorded backup backup-A`. Eject the stick.

7. **Back up to stick B.** Same command with stick B and the label
   `backup-B`. Same success lines with `backup-B`. Eject it.

8. **Write the ceremony record.** Type:

   ```
   bash ~/trust1_key_ceremony.sh record ~/aienos-ceremony-gen1
   ```

   *Changes:* writes `public/ceremony_record.txt` (public fingerprints,
   backup count, no private material; the tool refuses if it finds any).
   *Success:* `wrote .../ceremony_record.txt` and no `NOTE only ...
   backup(s)` line.

9. **Signature round trip (the proof that the Spark will accept your
   signatures).** This needs two trips of the TRANSFER stick; the MacBook
   stays offline the whole time.

   a. Copy the public folder to the TRANSFER stick:

      ```
      cp -R ~/aienos-ceremony-gen1/public /Volumes/TRANSFER/owner-public-gen1
      ```

      *Changes:* copies public files only. Eject and hand the stick over.

   b. **On the Spark (an agent types these, you watch):** make a test
      manifest over a short text file that is not a program, and the bytes
      to sign, bound to your public key:

      ```
      printf 'AIENOS OWNER KEY CEREMONY TEST. NOT AN IMAGE. NEVER BOOTS.\n' > ceremony-test.txt
      ck_slot_tool make-manifest --image ceremony-test.txt --generation 1 --provenance ceremony-test --out test.manifest
      ck_slot_tool tbs test.manifest --pubkey "$(cut -d' ' -f2 owner-public-gen1/owner_pubkeys.txt)" --out test.tbs
      ```

      (`ck_slot_tool` is built with `make -C native/kernel slot-tool`; it
      lands in `target/native-kernel/host/`.) *Changes:* three files in a
      scratch folder on the Spark. *Success:* `tbs: 448 bytes written`. The
      manifest can only ever vouch for that text file (it records the text
      file's SHA-512), so a signed copy cannot start anything. Copy
      `test.tbs` to the TRANSFER stick.

   c. **On the MacBook:** sign it.

      ```
      "$AIENOS_OPENSSL" pkeyutl -sign -rawin -inkey ~/aienos-ceremony-gen1/private/owner_root.key.pem -in /Volumes/TRANSFER/test.tbs -out /Volumes/TRANSFER/test.sig
      ```

      *What it does:* asks `Enter pass phrase for ...owner_root.key.pem:`,
      unlocks the key in memory only, and writes a 64-byte signature. This
      is the same command every future release signature uses
      (`docs/NATIVE_IMAGE_SLOTS.md` section 6, `docs/NATIVE_PACKAGE.md`).
      *Changes:* writes `test.sig` on the stick. *Success:* no output after
      the passphrase.

   d. **Quick check on the MacBook, public key only:**

      ```
      "$AIENOS_OPENSSL" pkeyutl -verify -rawin -pubin -inkey ~/aienos-ceremony-gen1/public/owner_root.pub.pem -in /Volumes/TRANSFER/test.tbs -sigfile /Volumes/TRANSFER/test.sig
      ```

      *Success:* `Signature Verified Successfully`.

   e. **On the Spark, the real check (public key only):**

      ```
      ck_slot_tool attach-sig test.manifest --sig test.sig --pubkey "$(cut -d' ' -f2 owner-public-gen1/owner_pubkeys.txt)" --out test.signed
      ck_slot_tool verify test.signed --image ceremony-test.txt --keys owner-public-gen1/owner_pubkeys.txt
      ck_slot_tool show test.signed
      ```

      *Success:* `signature attached and verified`, then `verify: OK
      generation=1`, and the `signer_id=` line equals the value on the
      checklist from step 5. A negative check the agent also runs: the same
      `verify` with a keys file holding some other key must print
      `refused: signer_id names no trusted key` (seen on 2026-10-12).

10. **Turn Wi-Fi back on** only after step 9c is done. Keep
    `~/aienos-ceremony-gen1/private` on the MacBook (it is locked with the
    passphrase), or delete it if you prefer to sign from a backup stick each
    time; either works because every backup is a complete copy.

## 4. Backup and recovery

**What a backup is.** Each of the two sticks holds the locked private keys
and the public files (`backup` in the tool). The keys on the sticks are
encrypted with your passphrase (AES-256, `openssl genpkey -aes-256-cbc`), so
a stick alone is not enough to sign: someone needs the stick **and** the
paper. That is why they are stored apart.

**Where to keep them.**

- Stick A: at home, somewhere fire-safe if possible.
- Stick B: in a different building (bank box, trusted relative).
- Passphrase paper: in a third place, never in the same bag or drawer as a
  stick.

**Check a backup without exposing the key** (once a year, and before any
rotation). Offline MacBook, the stick plugged in:

```
"$AIENOS_OPENSSL" pkey -in "/Volumes/OWNER KEY A/aienos-owner-keys-gen1/owner_root.key.pem" -pubout -outform DER | tail -c 32 | "$AIENOS_OPENSSL" dgst -sha256 -r | cut -c1-64
```

*What it does:* asks for the passphrase, unlocks the key in memory, and
prints only the signer id **derived from it**. Nothing secret is printed or
written. *Success:* the number equals the signer id on your checklist. A
wrong passphrase prints `Could not read key from ...` (seen on
2026-10-12): then either the passphrase or the stick is wrong. If the stick
fails, make a new backup from the other stick (restore below, then `backup`
to a fresh stick).

**Restore onto a machine** (new MacBook, wiped MacBook). Offline, the stick
plugged in:

```
mkdir -p ~/aienos-ceremony-gen1/private ~/aienos-ceremony-gen1/public
cp "/Volumes/OWNER KEY A/aienos-owner-keys-gen1/"*.key.pem ~/aienos-ceremony-gen1/private/
cp "/Volumes/OWNER KEY A/aienos-owner-keys-gen1/"*.pub.pem "/Volumes/OWNER KEY A/aienos-owner-keys-gen1/"authority_manifest* "/Volumes/OWNER KEY A/aienos-owner-keys-gen1/"boot_signer.crt.* ~/aienos-ceremony-gen1/public/
bash ~/trust1_key_ceremony.sh verify ~/aienos-ceremony-gen1/public
```

*Changes:* creates the folder on this machine. *Success:* six `PASS` lines for
the manifest signature, the four public keys and the generation. Then run
the backup check above against the restored file to confirm the signer id.

**If the key is lost** (both sticks gone, or the passphrase forgotten: these
are the same thing).

- *While a copy still works,* replace the key in an orderly way: make a new
  owner key in a new ceremony, then ship one package signed with the **old**
  key whose trusted-key set lists **both** keys, then later a package signed
  with the new key that lists only the new one. This is the same
  "add, verify, exercise recovery, then revoke; never delete first" rule the
  tool records for the other keys (`authority_manifest.txt`,
  `rotation_rule=`). The slot tool already accepts up to 8 trusted keys in
  one keys file (`ck_slot_tool.c`, `MAX_KEYS 8u`). **Not built yet:** how the
  loader carries and updates its trusted-key set is part of the slot loader
  (`docs/NATIVE_IMAGE_SLOTS.md` section 6, cut 2, in progress), and today's
  hardware-staging image takes exactly one owner key at build time
  (`ck_owner_gen.c`: "every name must appear exactly once"). This paragraph
  becomes concrete steps when that lands.
- *If no working copy is left,* nothing can sign a package the machine will
  accept. The only way back is the recovery path: the known-good recovery
  image on recovery media (`docs/NATIVE_IMAGE_SLOTS.md` section 6, cut 4,
  not built yet) or the existing Ubuntu recovery stick
  (`docs/RECOVERY_MEDIA_MACHINE1.md`), followed by a new ceremony and a fresh
  install with the new public key. This is slow and attended, which is why
  there are two backups.
- *If the key may have been copied by someone else* (stolen stick together
  with the paper, or the MacBook compromised): do the orderly replacement
  above at once, and treat any signature made after the suspected date as
  untrusted. (Recommendation, not yet written into a tool.)

## 5. What leaves the MacBook

Only these, and only on the TRANSFER stick:

| File | What it is | Secret? |
|---|---|---|
| `owner_root.pub.pem` and the other `*.pub.pem`, `boot_signer.crt.*` | public halves | no |
| `owner_pubkeys.txt` | the line `owner_root_ed25519 <64 hex>` for the Spark's tools | no |
| `signer_id.txt` | SHA-256 of the bare public key | no |
| `authority_manifest*`, `ceremony_record.txt`, `backups.txt` | the signed authority manifest and the record | no |
| later: `*.sig` | one 64-byte signature per release manifest | no |

Never: anything from `private/`, any `*.key.pem`, the passphrase, or a photo
of the passphrase sheet. The tool's `verify` refuses a public folder that
contains the words `PRIVATE KEY`; the agent runs it on the Spark side as
well before anything is committed. The public folder is committed under
`evidence/` (`docs/TRUST-1-ATTENDED-SEQUENCE.md`, Action 5) and checked with
`scripts/trust1_attended_evidence_check.sh gate3 PUBLIC_DIR
--expect-manifest-sha <the value you wrote on paper>`
(`docs/TRUST-1-ATTENDED-PACKAGE.md`, Sitting E).

## 6. Checklist (print, fill in by hand, sign)

```
AIENOS owner key ceremony, generation 1

Date: ____________   Start time: ______   End time: ______
Machine: MacBook  ____________________ (model)
OpenSSL version printed in part 2 step 3: ______________________

[ ] Wi-Fi off and cables out before preflight
[ ] preflight printed "network: offline"
[ ] generate printed six PASS lines and "generated:"
    manifest_sha256 = ________________________________________________
                      ________________ (all 64 characters)
[ ] owner_pubkeys.txt holds one line, 64 hex characters
[ ] signer_id   first 16: ________________   last 16: ________________
[ ] backup-A: four "decrypts from the backup copy" PASS lines
[ ] backup-B: four "decrypts from the backup copy" PASS lines
[ ] record written, no "NOTE only" line
[ ] MacBook check: "Signature Verified Successfully"
[ ] Spark check: "verify: OK generation=1", signer_id matches the line above
[ ] Spark check: other key refused ("signer_id names no trusted key")
[ ] Only public files left the MacBook (part 5)
[ ] Stick A stored at: _______________________
[ ] Stick B stored at: _______________________
[ ] Passphrase sheet stored at: _______________  (not with a stick)

Signed: ______________________   Date: ____________
```

Keep the signed checklist with the passphrase sheet's location noted on it,
not the passphrase itself. A photo of the checklist (no passphrase in view)
may be committed next to the public folder as the owner's signed record.

## 7. Realization receipts: the owner root may sign them (aienos#387)

Recorded 2026-10-14 for aienos#387. The owner key that exists is the one made on 2026-10-14 by the YubiKey
ceremony (`docs/native/PI5-8-OWNER-CEREMONY.md`, aienos#380), not by the MacBook procedure above: YubiKey serial
39017074, PIV slot 9c, `owner_root_ed25519
578ada3cb0c2d154623ac089191023c8ad4bc5e63b8ccd1a38db2d679b8c9e76`.

**Entry: this owner root may sign Omega realization receipts** (omega `spec/one-layer-receipts.md`, receipt v1,
signer class OWNER). This is the entry `native/kernel/artifact/osc_receipt_anchor.h` and
`native/kernel/core/osc_admit.c` wait for: from aienos#387 the kernel's receipt policy, in the release and the
qualification build, has this key as its one OWNER receipt anchor.

- **Basis.** The owner signed the first realization receipt with this key himself (PIN and touch, 2026-10-15
  00:02:50 UTC; omega#455, `tests/checker2/fixtures/owner-receipt/a01.owner.rcpt`). Omega's spec makes the owner
  root the only owner anchor honoured in production mode (section 6, step 2).
- **What such a signature says.** One checker2 identity accepted one exact program (the OSC IR), one executable is
  bound to it by hash, for one target and one epoch window. It grants no capability and admits no unit: a unit
  still needs its own container signature, and a release build has no OWNER unit anchor until TRUST-1, so a release
  build still launches nothing.
- **The exact bytes signed** (65): `"OMEGA-REALIZATION-RECEIPT-SIG-V1\0"` followed by
  SHA-256(`"OMEGA-REALIZATION-RECEIPT-V1\0"` and receipt bytes 0 to 351). The same key also signs owner
  statements (they begin `AIENOS-OWNER-STATEMENT-V1`) and slot manifests (448 bytes beginning `AIENSLT1`). The
  three messages differ in length and in their first bytes, and Ed25519 signs the exact bytes, so a signature made
  for one can never pass as another.
- **Signing.** `yubico-piv-tool -a verify-pin --sign -s 9c -A ED25519` over the 65-byte message, the same call as
  `scripts/pi5-8/owner_ceremony.sh`. The tool asks for the PIN itself; nothing stores it.
- **Withdrawing.** Revocation in the kernel is compile-time (`rcpt_revoked_ids`, `rcpt_revoked_keys` in
  `core/osc_admit.c`): withdrawing one receipt, or this permission, means building a new image with the receipt id
  or the key fingerprint revoked, or with the anchor removed. There is no live revocation feed yet
  (`docs/osc-receipts.md`, UNVERIFIED).
- **Checks.** `native/kernel/tests/test_osc_receipt.c` (`owner_receipt`): the committed owner receipt is VALID under
  the release policy; every single-bit flip, another unit, another target, the epoch window edges, an unlisted
  checker, a revoked receipt id and a revoked owner key are refused; TEST receipts stay refused. QEMU gate
  `scripts/qemu_ck_osc_receipt_test.sh`: the owner receipt runs a01 under the release receipt policy.
