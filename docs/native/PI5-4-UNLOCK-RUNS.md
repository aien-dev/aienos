# PI5-4 unlock runs on the Raspberry Pi 5 (qualification evidence)

Tier: PI5-UNLOCK-QUALIFICATION. Image: `make pi5-unlock-card` at commit 55f6cc0130d2932263ef0baece5a89c88a99c739
(BOOTAA64.EFI sha256 8936579f86eb367fb14fef725bc363e647d2ee46b914a7b57397fa3741f3e10a). The recovery secret is a
THROWAWAY (32 random bytes from /dev/urandom, never committed, never printed); the request file
\EFI\AIENOS\UNLOCK.REQ was placed on the card by `pi5-run.sh UNLOCK_REQ=...` and zeroed, deleted and checked
absent after each run (`unlock_req_deleted_verified`). Not a production Store: no TPM (Slot 0), the secret came
from the card. Logs: `~/workspace/pi5-runs/<tag>/kernel.log` on the Spark (not committed).

Before run A the AIENOS partition (/dev/mmcblk0p2 on the hub, 8388608 sectors, not mounted) held a TEST-tier Store.
Its first 48 sectors were zeroed and read back as zeros (`head_zeroed_readback_ok`), so the new Store is
production-class from its first byte and never reuses TEST content.

## Run A, pi5-unlock-a: first-time setup with secret S

```
unlock_req: found a well-formed request file (QUALIFICATION ONLY, throwaway secret); secret not printed
unlock_source: card request file (QUALIFICATION ONLY, throwaway secret)
store: identity class=1 (production); anchor lba=0 store lba=32 units=1048563
store: blank disk (all-zero anchor + Store head): formatted production store
store: key source=recovery-keyslot genesis=1 (K_vol source: the Slot 1 recovery descriptor; TPM Slot 0 BLOCKED_HARDWARE; no rotation)
store: opened generation=1 boot_count=0 prev_commit=none anchor=valid-resume
store: committed generation=2 boot_count=1
store: security manifest sequence=1 generation=2 keyslot=bound previous=genesis
store: limit: anchor shares this disk, so a whole-disk rollback is not detectable (needs TPM NV or another external counter)
stage store: ok
```

Result: blank Store formatted as a PRODUCTION-class Store, KeySlotManifest bound, generation 1 to 2, boot_count 1.

## Run B, pi5-unlock-b: reboot, same secret S

```
unlock_req: found a well-formed request file (QUALIFICATION ONLY, throwaway secret); secret not printed
unlock_source: card request file (QUALIFICATION ONLY, throwaway secret)
store: identity class=1 (production); anchor lba=0 store lba=32 units=1048563
store: key source=recovery-keyslot genesis=0 (K_vol source: the Slot 1 recovery descriptor; TPM Slot 0 BLOCKED_HARDWARE; no rotation)
store: opened generation=2 boot_count=1 prev_commit=55f6cc0130d2932263ef0baece5a89c88a99c739 anchor=valid-resume
store: committed generation=3 boot_count=2
store: security manifest sequence=2 generation=3 keyslot=bound previous=linked
store: limit: anchor shares this disk, so a whole-disk rollback is not detectable (needs TPM NV or another external counter)
stage store: ok
```

Result: the Store reopens through the Slot 1 recovery path, no reformat, generation 2 to 3, boot_count 2, the
SecurityManifest sequence advances to 2 and links the first.

## How "nothing written" was checked (cut 4)

After each refused run, the hub (Linux, partition not mounted) read the Store view of the AIENOS partition (sectors
0 to 8388543, so the 64-sector run marker at the end is excluded because it changes every run) and took its SHA-256.

- H0, taken after Run B and before Run C: 7954edfc924ac4c20d3599757149b81b9497a110757f6ea83ef30bc4b94a9943
- H1, taken after Run C: 7954edfc924ac4c20d3599757149b81b9497a110757f6ea83ef30bc4b94a9943 (equal to H0)

## Run C, pi5-unlock-c: wrong secret W (last byte differs from S)

```
unlock_req: found a well-formed request file (QUALIFICATION ONLY, throwaway secret); secret not printed
unlock_source: card request file (QUALIFICATION ONLY, throwaway secret)
store: identity class=1 (production); anchor lba=0 store lba=32 units=1048563
store: key source=recovery-keyslot genesis=0 (K_vol source: the Slot 1 recovery descriptor; TPM Slot 0 BLOCKED_HARDWARE; no rotation)
store: REFUSED proof=keyed step="recovery secret rejected (K_vol unwrap tag failed); disk not opened" rc=-2004 (RecoverySecretRejected); disk left as found, not reformatted
stage store: FAIL rc=-2004
```

Result: refused, and the Store view hash after the run equals the hash before (H0 = H1), so nothing was written.

## Run D, pi5-unlock-d: one byte of the KeySlotManifest flipped, correct secret S

The locator (`ck_pi5_store_locate`, run on a copy of the partition) put the KeySlotManifest at Store unit 6, partition
sector 80, byte offset 40960, 640 bytes. The wrapped K_vol of the recovery slot is at byte offset 41272. One byte there
was XOR-ed with 0xFF (0x8b to 0x74) on the card by a whole-sector read-modify-write, read back, and checked to differ
from the original in exactly one byte.

```
unlock_source: card request file (QUALIFICATION ONLY, throwaway secret)
store: identity class=1 (production); anchor lba=0 store lba=32 units=1048563
store: key source=recovery-keyslot genesis=0 (K_vol source: the Slot 1 recovery descriptor; TPM Slot 0 BLOCKED_HARDWARE; no rotation)
store: REFUSED proof=keyed step="no KeySlotManifest on a non-blank disk" rc=-105 (MountError::CorruptRecoveryRequired); disk left as found, not reformatted
stage store: FAIL rc=-105
```

Result: refused with CorruptRecoveryRequired, no reformat. After the run, a byte-for-byte comparison of the Store view
against the pre-flip copy showed exactly one differing byte, the flipped one (hash after Run D 37d47b09...a85791), so the
refusal wrote nothing. Limit: the refusal comes from the object integrity check on the manifest, which treats the damaged
manifest as absent on a non-blank disk; it is not a separate "slot tag mismatch" message. The SecurityManifest (sealed
envelopes) was not targeted because it cannot be located without the keys.

## Run E, pi5-unlock-e: byte restored, correct secret S

The original byte was written back (the saved sector was byte-identical on readback) and the Store view hash returned to
H0 (7954edfc...a9943) before the run.

```
unlock_source: card request file (QUALIFICATION ONLY, throwaway secret)
store: identity class=1 (production); anchor lba=0 store lba=32 units=1048563
store: key source=recovery-keyslot genesis=0 (K_vol source: the Slot 1 recovery descriptor; TPM Slot 0 BLOCKED_HARDWARE; no rotation)
store: opened generation=3 boot_count=2 prev_commit=55f6cc0130d2932263ef0baece5a89c88a99c739 anchor=valid-resume
store: committed generation=4 boot_count=3
store: security manifest sequence=3 generation=4 keyslot=bound previous=linked
stage store: ok
```

Result: the Store reopens after the damage is repaired, generation 3 to 4, boot_count 3, SecurityManifest sequence 3 linked
to the previous one. In every run the request file was deleted from the card and verified absent afterwards.
