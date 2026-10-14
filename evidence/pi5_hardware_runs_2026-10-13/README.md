# Pi 5 hardware runs, 2026-10-13: pi5-k1, pi5-sd1a, pi5-sd1b

These are the raw records of the three runs of the AIENOS C kernel on the hub
Raspberry Pi 5 that merged PR #345 (pi5-k1) and PR #346 (pi5-sd1a, pi5-sd1b) cite.
Before this folder they existed only on the Spark, under `/home/drakestapleton/workspace/pi5-runs/<tag>/`.
Every file here is a byte-for-byte copy of the file of the same name in that run
folder (`cmp` equal when copied). Nothing was edited, including the home-directory paths inside `run.log`.

Check the copies: `cd evidence/pi5_hardware_runs_2026-10-13 && sha256sum -c SHA256SUMS`
(SHA256SUMS covers every file in this folder except itself).

The runner that produced the `run.log` files is `scripts/pi5/pi5-run.sh` (with `klog-lib.sh`).
It runs on the Spark and drives the hub over ssh. It is not run by CI.

## Manifest

The date is 2026-10-13 UTC for all three runs. `run.log` itself carries only
`HH:MM:SSZ`; the date is taken from the file times (`kernel.log` of pi5-k1 was written
2026-10-12 23:13:05 -0500, which is 04:13:05Z on the 13th). The time range is the first
and last timestamped line of `run.log`.

| Tag | UTC time | EFI sha256 (`run.log`) | `aienos_commit` line (`kernel.log`) | Cited by |
| --- | --- | --- | --- | --- |
| pi5-k1 | 2026-10-13 04:03:42Z to 04:13:05Z | `cb25f3d3294e6b72b7cc773a8cbae2ff0718ada55cfa12c57d767369f9a69266` | `aienos_commit: 8863d91d410ae70536954a0166b71a2a7a982181` | #345 |
| pi5-sd1a | 2026-10-13 07:28:33Z to 07:39:14Z | `b0ffdc61dc23a255af63723a2dc813952d4e069aa8e11e77383eedbbc01ec55a` | `aienos_commit: 502d1682153b03146c421e5eba4555a9b1ba1c4b` | #346 |
| pi5-sd1b | 2026-10-13 07:39:28Z to 07:50:44Z | `b0ffdc61dc23a255af63723a2dc813952d4e069aa8e11e77383eedbbc01ec55a` | `aienos_commit: 502d1682153b03146c421e5eba4555a9b1ba1c4b` | #346 |

pi5-sd1a and pi5-sd1b ran the same EFI file (same sha256). In each `kernel.log` the
`aienos_commit` line appears three times (one per report) and all three are identical.

The EFI files themselves are not in this folder. When this folder was made, the
Spark copies (`~/workspace/pi5-efi/PI5SD1.EFI` and
`~/.claude/jobs/9974574d/tmp/PI5K1-8863d91.EFI`) hashed to the values above.

### Key result lines, quoted exactly

Each block is the output of
`grep -E 'pi5_part|pi5_store_layer|klog|timer|cpu|PASS|FAIL' <tag>/kernel.log`.
No line in any of the three `kernel.log` files contains the words PASS or FAIL
(the kernel prints `ok`, `result=ok` and `SUCCESS` instead), so the "PASS on hardware" in the title of PR #345
is a reading of these lines, not a verdict the kernel printed.
pi5-k1 has no `pi5_part` or `pi5_store_layer` lines (that code came later).

pi5-k1:

```
klog_map: slot lba=86336 sectors=4096 on a disk of 250347520 sectors (firmware read back the header)
timer_irq: 19 ticks in 200 ms
gic_cpu_interface: mmio gicc=0x107fffa000
timer_stats: intid=30 freq_hz=54000000 period_us=10000 min_us=10000 avg_us=10000 max_us=10000
smp: boot_mpidr=0x0 madt_cpus=4 conduit=smc psci_version=1.1
smp_cpu_on: target=0x100 psci_rc=0 (SUCCESS)
smp_cpu_on: target=0x200 psci_rc=0 (SUCCESS)
smp_cpu_on: target=0x300 psci_rc=0 (SUCCESS)
smp_cpu: target=0x100 checked_in=yes seen_mpidr=0x100 el=1 mmu=on ttbr0_match=yes stack_ok=yes parked=wfe
smp_cpu: target=0x200 checked_in=yes seen_mpidr=0x200 el=1 mmu=on ttbr0_match=yes stack_ok=yes parked=wfe
smp_cpu: target=0x300 checked_in=yes seen_mpidr=0x300 el=1 mmu=on ttbr0_match=yes stack_ok=yes parked=wfe
smp: cpus=4 started=4 checked_in=4 psci_errors=0 distinct_mpidrs=4 wait_us=1 result=ok
klog_card: slot verified by the kernel's own SD driver (lba=86336 sectors=4096); writing
```

pi5-sd1a:

```
klog_map: slot lba=16392 sectors=4096 on a disk of 250347520 sectors (firmware read back the header)
pi5_part: AIENOS partition first_lba=1050624 blocks=8388608 (4096 MiB) entries_used=2 index=1 via GPT (CRC32 primary+backup ok)
pi5_store_layer: formatted (blank region written, flushed, read back identical) generation=1 region=64 sectors at partition block 8388544
timer_irq: 19 ticks in 200 ms
gic_cpu_interface: mmio gicc=0x107fffa000
timer_stats: intid=30 freq_hz=54000000 period_us=10000 min_us=10000 avg_us=10000 max_us=10000
smp: boot_mpidr=0x0 madt_cpus=4 conduit=smc psci_version=1.1
smp_cpu_on: target=0x100 psci_rc=0 (SUCCESS)
smp_cpu_on: target=0x200 psci_rc=0 (SUCCESS)
smp_cpu_on: target=0x300 psci_rc=0 (SUCCESS)
smp_cpu: target=0x100 checked_in=yes seen_mpidr=0x100 el=1 mmu=on ttbr0_match=yes stack_ok=yes parked=wfe
smp_cpu: target=0x200 checked_in=yes seen_mpidr=0x200 el=1 mmu=on ttbr0_match=yes stack_ok=yes parked=wfe
smp_cpu: target=0x300 checked_in=yes seen_mpidr=0x300 el=1 mmu=on ttbr0_match=yes stack_ok=yes parked=wfe
smp: cpus=4 started=4 checked_in=4 psci_errors=0 distinct_mpidrs=4 wait_us=0 result=ok
klog_card: slot verified by the kernel's own SD driver (lba=16392 sectors=4096); writing
```

pi5-sd1b:

```
klog_map: slot lba=20848 sectors=4096 on a disk of 250347520 sectors (firmware read back the header)
pi5_part: AIENOS partition first_lba=1050624 blocks=8388608 (4096 MiB) entries_used=2 index=1 via GPT (CRC32 primary+backup ok)
pi5_store_layer: reopened (payload identical to the pattern, generation bumped and read back) generation=2 region=64 sectors at partition block 8388544
timer_irq: 19 ticks in 200 ms
gic_cpu_interface: mmio gicc=0x107fffa000
timer_stats: intid=30 freq_hz=54000000 period_us=10000 min_us=10000 avg_us=10000 max_us=10000
smp: boot_mpidr=0x0 madt_cpus=4 conduit=smc psci_version=1.1
smp_cpu_on: target=0x100 psci_rc=0 (SUCCESS)
smp_cpu_on: target=0x200 psci_rc=0 (SUCCESS)
smp_cpu_on: target=0x300 psci_rc=0 (SUCCESS)
smp_cpu: target=0x100 checked_in=yes seen_mpidr=0x100 el=1 mmu=on ttbr0_match=yes stack_ok=yes parked=wfe
smp_cpu: target=0x200 checked_in=yes seen_mpidr=0x200 el=1 mmu=on ttbr0_match=yes stack_ok=yes parked=wfe
smp_cpu: target=0x300 checked_in=yes seen_mpidr=0x300 el=1 mmu=on ttbr0_match=yes stack_ok=yes parked=wfe
smp: cpus=4 started=4 checked_in=4 psci_errors=0 distinct_mpidrs=4 wait_us=0 result=ok
klog_card: slot verified by the kernel's own SD driver (lba=20848 sectors=4096); writing
```

## What each file is

| File | What it is |
| --- | --- |
| `<tag>/run.log` | The runner's log. Times are UTC. |
| `<tag>/kernel.log` | The kernel's console text, taken from the log slot (`KLOG.BIN`) on the SD card after the run. |
| `<tag>/block.txt` | The temporary block the runner added to the hub's `config.txt` so the Pi boots the AIENOS test image once (tryboot). |
| `<tag>/config.txt.before`, `.during`, `.after` | The hub's `config.txt` before the block, with it, and after it was removed. For all three runs `before` and `after` are byte-identical, and `during` is exactly `before` followed by `block.txt` (both checked with `cmp` when this folder was made). |
| `<tag>/KLOG.MAP` | The map the runner wrote to the card before the run: where the log slot is, plus a fresh random nonce. Byte-identical to the copy read back from the card after the run (`cmp`). |
| `<tag>/klog-hdr.bin` | The empty slot header the runner wrote at the start of the slot (512 bytes). |

Not copied: `AIENOS/KLOG.BIN`, the 2 MiB log slot (mostly empty). Its sha256 is in
`KLOG_BIN_SHA256.txt`; the originals are in the Spark's run folders.

## Checks made when this folder was made

- `kernel.log` equals `KLOG.BIN` (see limit a below).
- The nonce in each `KLOG.BIN` header equals the nonce in `klog-hdr.bin` and in `run.log`.
- The 64-bit commit field in each `KLOG.BIN` header holds the first 16 hex digits of the
  `aienos_commit` line (`8863d91d410ae705` for pi5-k1, `502d1682153b0314` for pi5-sd1a and pi5-sd1b).

## Limits (read these before relying on these runs)

a. **`kernel.log` is `KLOG.BIN` bytes 512 to 512+`log_len`.** Checked with `cmp` for all
   three: `log_len` (from the `KLOG.BIN` header) is 3809 for pi5-k1, 4075 for pi5-sd1a and
   4089 for pi5-sd1b, and `tail -c +513 KLOG.BIN | head -c <log_len>` is identical to `kernel.log`.
   The last line of each `kernel.log` (`klog_card: ... writing`) is printed before the log is
   written to the card, so the text cannot show that the write finished; the card copy with
   `state=1` (the `klog: state=1 log_len=...` line in `run.log`) is what shows it did.
   `KLOG.BIN` is not in the repo, so this check can only be repeated on the Spark.
   One more oddity: the pi5-k1 `run.log` says `kernel log NOT written (slot still empty or
   missing)` even though the line before it says `state=1 log_len=3809` and `kernel.log` is
   complete. `kernel.log` was written in the same instant as that line (file times 23:13:05.517 and
   23:13:05.520 -0500), and `klog-lib.sh` was last modified about 50 seconds later (23:13:56) and now
   carries the comment "head stops tail early (SIGPIPE under pipefail)". So the message was most
   likely a false alarm from the runner; that cause is an inference, not proven.

b. **pi5-k1 booted commit `8863d91`, which is not on GitHub.** `8863d91` ("native/disk: polled SD
   Host Controller driver for the Pi 5 microSD", 2026-10-12 22:38:42 -0500) exists only on a local
   branch (`pi5/target-backup`) on the Spark; `gh api repos/aien-dev/aienos/commits/8863d91...` finds
   no such commit. PR #345 landed on GitHub as the single commit `502d168`; the PR's own branch
   commits (`93ae032`, `db97e25`) are not `8863d91` either. The Pi image source of `502d168` builds to
   the same EFI as `8863d91` (see the rebuild experiment), so the work is in `502d168`, but the commit
   the stamp names is not on GitHub. Whether the tree was clean when the pi5-k1 EFI was built is not
   recorded (the stamp had no dirty flag then).

c. **pi5-sd1a and pi5-sd1b stamp `502d168`, but they were built from an uncommitted tree, so the
   stamp does not identify their source.** The strings `pi5_part` and `pi5_store_layer`, and the file
   `native/kernel/core/pi5_marker.c`, are not in the `502d168` tree (`git grep` finds none); they
   first appear in `e262a06` (PR #346). Both `kernel.log` files print them, so the EFI contained code
   that `502d168` does not.

d. **A rebuild from a GitHub commit is not shown to reproduce these EFI hashes as the stamps stand.**
   Before this folder, no record showed such a rebuild reproducing them, and building the commit that
   a stamp names does not: `502d168` builds to `34f3e4ef...`, which is neither run's EFI (see the
   rebuild experiment below). The experiment got matching hashes only by forcing the stamp, once,
   on the Spark; it is not a CI check.

e. **Out of scope here:** the Store runs `pi5-store1` and `pi5-store2` belong to the Pi Store work
   (branch `pi5/store-tier`, PR #348, which cites them), not to this folder. They are not recorded here.

From the PR that adds this folder on, a Pi build (`make -C native/kernel pi5`) made from a tree whose
tracked files differ from HEAD stamps `<HEAD>-dirty`, and `scripts/pi5/pi5-run.sh` logs the stamp it
finds in the EFI and says `NOT commit-bound (dirty build)` for such an image. The three runs here
predate that.

## Rebuild experiment (done once, 2026-10-13, on the Spark)

Toolchain: gcc 13.3.0 and binutils 2.42 (Ubuntu 24.04, aarch64 host, native build).
For each row: `git archive <source commit> | tar -x -C <empty dir>`, then
`make -s -C <dir>/native/kernel pi5 AIENOS_COMMIT=<stamp>`, then `sha256sum <dir>/target/native-kernel-pi5/BOOTAA64.EFI`.

| Source commit | On GitHub | `AIENOS_COMMIT` passed | EFI sha256 | Equals |
| --- | --- | --- | --- | --- |
| `502d168` | yes | `502d1682153b03146c421e5eba4555a9b1ba1c4b` | `34f3e4efa9101ac759cf57b1f9f6b394ee9e0abdb816b23dc388480abd799148` | neither run |
| `502d168` | yes | `8863d91d410ae70536954a0166b71a2a7a982181` | `cb25f3d3294e6b72b7cc773a8cbae2ff0718ada55cfa12c57d767369f9a69266` | pi5-k1 |
| `e262a06` | yes | `502d1682153b03146c421e5eba4555a9b1ba1c4b` | `b0ffdc61dc23a255af63723a2dc813952d4e069aa8e11e77383eedbbc01ec55a` | pi5-sd1a, pi5-sd1b |
| `8863d91` | no (local) | `8863d91d410ae70536954a0166b71a2a7a982181` | `cb25f3d3294e6b72b7cc773a8cbae2ff0718ada55cfa12c57d767369f9a69266` | pi5-k1 |

What this shows:

- The pi5-k1 EFI is what the source of `502d168` builds to when the stamp is forced to `8863d91`.
  The Pi image source of `502d168` and `8863d91` is the same: inside `native/` the two commits differ
  only in the PI5DIAG tool, one Makefile rule for it, README files and crumb files, and the other
  differences (Rust crates, a workflow, two scripts) did not change the image.
- The pi5-sd1a and pi5-sd1b EFI (the one that ran) is what the source of `e262a06` builds to when
  the stamp is forced to `502d168`. `e262a06` is the child of `502d168`, the commit the stamp names.

What it does not show: that the same holds on another machine or toolchain (UNVERIFIED), or how
the original images were built (the build commands were not recorded).
