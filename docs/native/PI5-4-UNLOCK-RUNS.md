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
